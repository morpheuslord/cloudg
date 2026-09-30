"""Cross-service relationship linker.

Derives the edges that interlink an inventory — attachment, containment,
routing, and generic references — purely from collected asset metadata.
No cloud API calls and no scanners: given any list of CloudAssets (AWS,
Azure, GCP, or mixed), it produces the edges that turn a flat inventory
into a connected map.

Two passes:

1. Provider-aware rules: security-group attachment, subnet containment,
   route-table routes, ENI/volume attachment, VPC peering, Lambda VPC
   config, CloudFront origins, KMS references, Azure NIC wiring, GCP
   parent containment.
2. Generic reference scan: any identifier string found inside an asset's
   metadata/raw_data that resolves to another collected asset becomes a
   REFERENCES edge. This catches cross-service links no explicit rule
   knows about.
"""

from __future__ import annotations

import logging
import re
from typing import Any, Iterable

from cloudg.schema.models import AssetType, CloudAsset, EdgeType, NetworkEdge

logger = logging.getLogger(__name__)

# AWS-native short-ID shapes worth indexing (i-, vpc-, subnet-, sg-, ...)
_AWS_ID_RE = re.compile(
    r"^(i|vpc|subnet|sg|vol|eni|igw|nat|rtb|acl|pcx|tgw|eipalloc)-[0-9a-f]{8,17}$"
)

# Metadata keys whose values identify the asset itself (never link targets)
_SELF_ID_KEYS = {
    "group_id",
    "subnet_id_self",
    "route_table_id",
    "internet_gateway_id",
    "nat_gateway_id",
    "network_interface_id",
    "volume_id",
    "allocation_id",
    "network_acl_id",
    "peering_connection_id",
    "transit_gateway_id",
    "policy_id",
}

_MAX_SCAN_DEPTH = 6


class RelationshipLinker:
    """Builds interconnection edges between already-collected assets."""

    def __init__(self, assets: list[CloudAsset]) -> None:
        self._assets = assets
        self._index: dict[str, str] = {}  # identifier -> asset.id
        self._by_id: dict[str, CloudAsset] = {a.id: a for a in assets}
        self._edge_keys: set[tuple[str, str]] = set()
        self._build_index()

    # ------------------------------------------------------------------
    # Index
    # ------------------------------------------------------------------

    def _register(self, identifier: Any, asset_id: str) -> None:
        if isinstance(identifier, str) and identifier:
            self._index.setdefault(identifier, asset_id)

    def _build_index(self) -> None:
        for asset in self._assets:
            self._register(asset.arn, asset.id)
            self._register(asset.name, asset.id)

            # Native short IDs (last path/colon segment of the ARN / resource ID)
            if asset.arn:
                tail = asset.arn.rsplit("/", 1)[-1].rsplit(":", 1)[-1]
                if tail != asset.arn:
                    self._register(tail, asset.id)

            # Self-identifying metadata values
            md = asset.metadata
            for key in (
                "group_id",
                "route_table_id",
                "internet_gateway_id",
                "nat_gateway_id",
                "network_interface_id",
                "volume_id",
                "allocation_id",
                "network_acl_id",
                "peering_connection_id",
                "transit_gateway_id",
            ):
                self._register(md.get(key), asset.id)

            if asset.asset_type == AssetType.VPC:
                self._register(md.get("vpc_id"), asset.id)
            if asset.asset_type == AssetType.SUBNET:
                self._register(md.get("subnet_id"), asset.id)

            # Names that other services reference by domain
            if asset.asset_type == AssetType.S3_BUCKET:
                self._register(f"{asset.name}.s3.amazonaws.com", asset.id)
            if asset.asset_type == AssetType.LOAD_BALANCER:
                self._register(md.get("dns_name"), asset.id)

    def resolve(self, identifier: Any) -> str | None:
        """Resolve any known identifier to an internal asset ID."""
        if not isinstance(identifier, str):
            return None
        return self._index.get(identifier)

    # ------------------------------------------------------------------
    # Edge helpers
    # ------------------------------------------------------------------

    def _add(
        self,
        edges: list[NetworkEdge],
        source_id: str | None,
        target_id: str | None,
        edge_type: EdgeType,
        description: str | None = None,
    ) -> None:
        if not source_id or not target_id or source_id == target_id:
            return
        key = (source_id, target_id)
        if key in self._edge_keys:
            return
        self._edge_keys.add(key)
        edges.append(
            NetworkEdge(
                source_id=source_id,
                target_id=target_id,
                edge_type=edge_type,
                description=description,
            )
        )

    # ------------------------------------------------------------------
    # Provider-aware rules
    # ------------------------------------------------------------------

    def _link_rules(self, asset: CloudAsset, edges: list[NetworkEdge]) -> None:
        md = asset.metadata
        raw = asset.raw_data or {}

        # Security-group / NSG attachment (EC2, ELB, ENI, Lambda, RDS, Azure NIC)
        for sg_ref in md.get("security_groups", []) or []:
            self._add(
                edges,
                asset.id,
                self.resolve(sg_ref),
                EdgeType.ATTACHED_TO,
                f"{asset.name} uses security group {sg_ref}",
            )
        nsg_id = md.get("nsg_id")
        if nsg_id:
            self._add(edges, asset.id, self.resolve(nsg_id), EdgeType.ATTACHED_TO)

        # Subnet containment (everything with a subnet_id that isn't a subnet)
        subnet_ref = md.get("subnet_id")
        if subnet_ref and asset.asset_type != AssetType.SUBNET:
            self._add(
                edges,
                self.resolve(subnet_ref),
                asset.id,
                EdgeType.CONTAINS,
                f"Subnet {subnet_ref} contains {asset.name}",
            )

        # Lambda VPC config + execution role
        vpc_config = md.get("vpc_config") or {}
        if isinstance(vpc_config, dict):
            for sn in vpc_config.get("SubnetIds", []) or []:
                self._add(edges, self.resolve(sn), asset.id, EdgeType.CONTAINS)
            for sg in vpc_config.get("SecurityGroupIds", []) or []:
                self._add(edges, asset.id, self.resolve(sg), EdgeType.ATTACHED_TO)
        role_ref = raw.get("Role") or md.get("role_arn")
        if role_ref:
            self._add(
                edges,
                asset.id,
                self.resolve(role_ref),
                EdgeType.REFERENCES,
                f"{asset.name} executes as {role_ref}",
            )

        # EC2 instance profile
        profile_arn = (raw.get("IamInstanceProfile") or {}).get("Arn") if raw else None
        if profile_arn:
            self._add(edges, asset.id, self.resolve(profile_arn), EdgeType.REFERENCES)

        # KMS key references (secrets, volumes, tables, ...)
        kms_ref = md.get("kms_key_id")
        if kms_ref:
            self._add(
                edges,
                asset.id,
                self.resolve(kms_ref),
                EdgeType.REFERENCES,
                f"{asset.name} encrypted with {kms_ref}",
            )

        # CloudFront origins -> S3 buckets / load balancers
        for origin in md.get("origins", []) or []:
            target = self.resolve(origin)
            if target is None and isinstance(origin, str):
                # bucket origins look like <bucket>.s3.<region>.amazonaws.com
                target = self.resolve(origin.split(".s3", 1)[0]) if ".s3" in origin else None
            self._add(
                edges,
                asset.id,
                target,
                EdgeType.REFERENCES,
                f"{asset.name} origin {origin}",
            )

        # Route tables: routes -> gateways, associations -> subnets
        if asset.asset_type == AssetType.ROUTE_TABLE:
            for route in md.get("routes", []) or []:
                gw = route.get("GatewayId") or route.get("NatGatewayId")
                if gw and gw != "local":
                    self._add(
                        edges,
                        asset.id,
                        self.resolve(gw),
                        EdgeType.ROUTE,
                        f"route {route.get('DestinationCidrBlock', '')} via {gw}",
                    )
            for assoc in md.get("associations", []) or []:
                self._add(
                    edges, asset.id, self.resolve(assoc.get("SubnetId")), EdgeType.ATTACHED_TO
                )

        # Internet gateway attachments -> VPC
        for attachment in md.get("attachments", []) or []:
            if isinstance(attachment, dict):
                self._add(
                    edges, asset.id, self.resolve(attachment.get("VpcId")), EdgeType.ATTACHED_TO
                )

        # ENI / EBS / EIP attachment -> instance
        inst_ref = md.get("attached_instance_id")
        if inst_ref:
            self._add(edges, asset.id, self.resolve(inst_ref), EdgeType.ATTACHED_TO)
        for inst in md.get("attached_instance_ids", []) or []:
            self._add(edges, asset.id, self.resolve(inst), EdgeType.ATTACHED_TO)
        eni_ref = md.get("network_interface_id")
        if eni_ref and asset.asset_type != AssetType.NETWORK_INTERFACE:
            self._add(edges, asset.id, self.resolve(eni_ref), EdgeType.ATTACHED_TO)

        # VPC peering
        if asset.asset_type == AssetType.PEERING_CONNECTION:
            req = self.resolve(md.get("requester_vpc_id"))
            acc = self.resolve(md.get("accepter_vpc_id"))
            self._add(edges, req, asset.id, EdgeType.PEERING)
            self._add(edges, asset.id, acc, EdgeType.PEERING)

        # Azure VM -> NICs
        for nic_ref in md.get("network_interfaces", []) or []:
            self._add(edges, self.resolve(nic_ref), asset.id, EdgeType.ATTACHED_TO)

        # GCP: parent resource containment
        parent = md.get("parent_full_resource_name")
        if parent:
            self._add(edges, self.resolve(parent), asset.id, EdgeType.CONTAINS)

    # ------------------------------------------------------------------
    # Generic reference scan
    # ------------------------------------------------------------------

    def _iter_strings(self, value: Any, depth: int = 0) -> Iterable[str]:
        if depth > _MAX_SCAN_DEPTH:
            return
        if isinstance(value, str):
            yield value
        elif isinstance(value, dict):
            for v in value.values():
                yield from self._iter_strings(v, depth + 1)
        elif isinstance(value, (list, tuple)):
            for v in value:
                yield from self._iter_strings(v, depth + 1)

    def _looks_like_identifier(self, value: str) -> bool:
        if value.startswith("arn:") or value.startswith("/subscriptions/"):
            return True
        if value.startswith("//") and ".googleapis.com/" in value:
            return True
        return bool(_AWS_ID_RE.match(value))

    def _link_generic(self, asset: CloudAsset, edges: list[NetworkEdge]) -> None:
        own_ids = {asset.arn, asset.name}
        md = dict(asset.metadata)
        for key in _SELF_ID_KEYS:
            own_ids.add(md.pop(key, None))
        for value in self._iter_strings(md):
            if value in own_ids or not self._looks_like_identifier(value):
                continue
            target = self.resolve(value)
            if target and target != asset.id:
                self._add(
                    edges,
                    asset.id,
                    target,
                    EdgeType.REFERENCES,
                    f"{asset.name} references {value}",
                )

    # ------------------------------------------------------------------
    # Main interface
    # ------------------------------------------------------------------

    def link(self, include_generic: bool = True) -> list[NetworkEdge]:
        """Run all linking passes and return deduplicated edges.

        Args:
            include_generic: Also run the generic reference scan (pass 2).
        """
        edges: list[NetworkEdge] = []
        for asset in self._assets:
            try:
                self._link_rules(asset, edges)
            except Exception:
                logger.debug("Rule linking failed for %s", asset.name, exc_info=True)
        if include_generic:
            for asset in self._assets:
                try:
                    self._link_generic(asset, edges)
                except Exception:
                    logger.debug("Generic linking failed for %s", asset.name, exc_info=True)
        logger.info("Linker derived %d relationship edges", len(edges))
        return edges

    def seed_existing(self, edges: list[NetworkEdge]) -> None:
        """Register already-collected edges so the linker won't duplicate them."""
        for edge in edges:
            self._edge_keys.add((edge.source_id, edge.target_id))
