"""Cross-service relationship linker.

Derives the edges that interlink an inventory — attachment, containment,
routing, invocation, identity, protection, monitoring, governance and
generic references — purely from collected asset metadata. No cloud API
calls and no scanners: given any list of CloudAssets (AWS, Azure, GCP, or
mixed), it produces the edges that turn a flat inventory into a connected
map.

Three passes:

1. Declared relations: collectors record what an asset talks to in
   ``metadata["relations"]`` (target identifier, edge type, ontology
   relationship, direction, properties). The linker resolves each target
   and emits a typed edge.
2. Provider-aware rules: security-group attachment, subnet containment,
   route-table routes, ENI/volume attachment, VPC peering, Lambda VPC
   config, execution roles, CloudFront origins and WAF, KMS references,
   Azure NIC wiring, GCP parent containment.
3. Generic reference scan: any identifier string found inside an asset's
   metadata that resolves to another collected asset becomes a REFERENCES
   edge. This catches cross-service links no explicit rule knows about.

Identifier resolution is scope-aware: ambiguous identifiers (names such as
``default``) resolve to the candidate in the same account and region,
then the same account, and are left unresolved rather than guessed when
several accounts share them. References to resources in accounts that
were not collected become ``CLOUD_ACCOUNT`` placeholder nodes marked
``external``, so cross-account dependencies stay visible.
"""

from __future__ import annotations

import logging
import re
from typing import Any, Iterable

from cloudg.schema.models import AssetType, CloudAsset, CloudProvider, EdgeType, NetworkEdge

logger = logging.getLogger(__name__)

# AWS-native short-ID shapes worth indexing (i-, vpc-, subnet-, sg-, ...)
_AWS_ID_RE = re.compile(
    r"^(i|vpc|subnet|sg|vol|eni|igw|eigw|nat|rtb|acl|pcx|tgw|tgw-attach|tgw-rtb|eipalloc|lt|vpce|vpce-svc|fs|fsap|fl|pl|vgw|cgw|vpn|snap|ami)-[0-9a-f]{8,17}$"
)
_ARN_ACCOUNT_RE = re.compile(r"^arn:aws[a-zA-Z-]*:[a-z0-9-]+:[a-z0-9-]*:(\d{12}):")
_AZURE_SUB_RE = re.compile(r"^/subscriptions/([0-9a-fA-F-]{36})(?:/|$)")
_GCP_PROJECT_RE = re.compile(r"^//[a-z0-9.-]+\.googleapis\.com/projects/([a-z0-9-]+)(?:/|$)")
_ROLE_ARN_RE = re.compile(r"^arn:aws[a-zA-Z-]*:iam::(\d{12}):role/(.+)$")
_SSO_ROLE_HASH_RE = re.compile(r"[0-9a-f]{16}")
_ASSUMED_ROLE_RE = re.compile(r"^arn:aws[a-zA-Z-]*:sts::(\d{12}):assumed-role/([^/]+)/")
_LAMBDA_QUALIFIED_RE = re.compile(r"^(arn:aws[a-zA-Z-]*:lambda:[^:]+:\d{12}:function:[^:]+):.+$")

# GCP full resource names, anchored so ".googleapis.com" cannot match mid-string
_GCP_NAME_RE = re.compile(r"^//[a-z0-9-]+\.googleapis\.com/")

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
    "vpc_endpoint_id",
    "launch_template_id",
    "file_system_id",
    "flow_log_id",
    "cluster_arn",
}

# Metadata keys the generic pass never scans (already linked explicitly)
_SKIP_GENERIC_KEYS = {"relations", "aliases", "assume_role_policy"}

# Identifiers that are globally unique; ambiguity never needs scoping
_GLOBAL_PREFIXES = (
    "arn:", "/subscriptions/", "/providers/", "//", "k8s://", "cloudg:", "aws-security:",
    "azure-security:", "entra:", "loganalytics:", "gcp-principal:", "k8s-gke://",
)
# Synthetic identifier schemes whose last path segment is not a usable short ID
_NO_TAIL_PREFIXES = ("k8s://", "k8s-gke://", "gcp-principal:", "entra:", "loganalytics:")

_MAX_SCAN_DEPTH = 6
_MAX_UNRESOLVED = 2000


def _strip_image(ref: str) -> str:
    ref = ref.split("@", 1)[0]
    last = ref.rsplit("/", 1)[-1]
    if ":" in last:
        ref = ref[: len(ref) - len(last)] + last.split(":", 1)[0]
    return ref


class RelationshipLinker:
    """Builds interconnection edges between already-collected assets.

    Args:
        assets: The inventory to link.
        materialize_external: Create placeholder account nodes for
            references into accounts that were not collected.
    """

    def __init__(self, assets: list[CloudAsset], materialize_external: bool = True) -> None:
        self._assets = assets
        self._by_id: dict[str, CloudAsset] = {a.id: a for a in assets}
        self._index: dict[str, list[str]] = {}  # identifier -> asset ids
        self._edge_keys: set[tuple[str, str, str]] = set()
        self._pair_keys: set[tuple[str, str]] = set()
        self._materialize_external = materialize_external
        self.external_assets: list[CloudAsset] = []
        self._external_ids: set[str] = set()
        self.unresolved: list[dict[str, Any]] = []
        self._build_index()

    # ------------------------------------------------------------------
    # Index
    # ------------------------------------------------------------------

    def _register(self, identifier: Any, asset_id: str) -> None:
        if not isinstance(identifier, str) or not identifier:
            return
        ids = self._index.setdefault(identifier, [])
        if asset_id not in ids:
            ids.append(asset_id)
        lowered = identifier.lower()
        if lowered != identifier and (
            identifier.startswith(("/subscriptions/", "/providers/"))
            or "." in identifier and "/" not in identifier
        ):
            self._register(lowered, asset_id)

    def _index_asset(self, asset: CloudAsset) -> None:
        self._register(asset.arn, asset.id)
        self._register(asset.name, asset.id)

        # Native short IDs (last path/colon segment of the ARN / resource ID)
        if asset.arn and not asset.arn.startswith(_NO_TAIL_PREFIXES):
            tail = asset.arn.rsplit("/", 1)[-1].rsplit(":", 1)[-1]
            if tail != asset.arn:
                self._register(tail, asset.id)

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
            "vpc_endpoint_id",
            "launch_template_id",
            "file_system_id",
            "queue_url",
            "repository_uri",
            "zone_id",
        ):
            self._register(md.get(key), asset.id)
        for alias in md.get("aliases", []) or []:
            self._register(alias, asset.id)

        if asset.asset_type in (AssetType.VPC, AssetType.VNET):
            self._register(md.get("vpc_id"), asset.id)
        if asset.asset_type == AssetType.SUBNET:
            self._register(md.get("subnet_id"), asset.id)
        if asset.asset_type in (AssetType.ELASTIC_IP, AssetType.EC2):
            self._register(md.get("public_ip"), asset.id)
        if asset.asset_type == AssetType.CLOUD_ACCOUNT and md.get("account_id"):
            self._register(md["account_id"], asset.id)

        # Names that other services reference by domain
        if asset.asset_type == AssetType.S3_BUCKET:
            self._register(f"{asset.name}.s3.amazonaws.com", asset.id)
        if asset.asset_type == AssetType.LOAD_BALANCER and md.get("dns_name"):
            self._register(md["dns_name"], asset.id)
            self._register(str(md["dns_name"]).lower().rstrip("."), asset.id)
        if asset.asset_type == AssetType.CLOUDFRONT and md.get("domain_name"):
            self._register(str(md["domain_name"]).lower(), asset.id)

    def _build_index(self) -> None:
        for asset in self._assets:
            self._index_asset(asset)

    def _pick(self, candidates: list[str], identifier: str, context: CloudAsset | None) -> str | None:
        # Real assets win over placeholders (e.g. an Entra principal that is
        # a managed identity collected in another subscription).
        real = [c for c in candidates if not self._by_id[c].metadata.get("placeholder")]
        candidates = real or candidates
        if len(candidates) == 1:
            return candidates[0]
        if identifier.startswith(_GLOBAL_PREFIXES):
            return candidates[0]
        if context is None:
            return candidates[0]
        same_region = [
            c for c in candidates
            if self._by_id[c].account_id == context.account_id and self._by_id[c].region == context.region
        ]
        if same_region:
            return same_region[0]
        same_account = [c for c in candidates if self._by_id[c].account_id == context.account_id]
        if same_account:
            return same_account[0]
        global_scope = [c for c in candidates if self._by_id[c].region == "global"]
        if len(global_scope) == 1:
            return global_scope[0]
        return None  # ambiguous across accounts: do not guess

    def _lookup(self, identifier: str, context: CloudAsset | None) -> str | None:
        candidates = self._index.get(identifier)
        if candidates:
            return self._pick(candidates, identifier, context)
        return None

    def resolve(self, identifier: Any, context: CloudAsset | None = None) -> str | None:
        """Resolve any known identifier to an internal asset ID.

        Args:
            identifier: ARN, ID, name, URL, DNS name, image reference, ...
            context: The referencing asset, used to scope ambiguous names.
        """
        if not isinstance(identifier, str) or not identifier:
            return None
        found = self._lookup(identifier, context)
        if found:
            return found
        for candidate in self._variants(identifier):
            found = self._lookup(candidate, context)
            if found:
                return found
        # Role ARNs built from a bare name miss roles that have a path:
        # fall back to the role with that name in that account.
        m = _ROLE_ARN_RE.match(identifier)
        if m:
            acct, role_name = m.group(1), m.group(2).rsplit("/", 1)[-1]
            for cid in self._index.get(role_name, []):
                a = self._by_id[cid]
                if a.asset_type == AssetType.IAM_ROLE and a.account_id == acct:
                    return cid
        # Assumed-role sessions resolve to the role, scoped to its account
        m = _ASSUMED_ROLE_RE.match(identifier)
        if m:
            acct, role_name = m.groups()
            for cid in self._index.get(role_name, []):
                a = self._by_id[cid]
                if a.asset_type == AssetType.IAM_ROLE and a.account_id == acct:
                    return cid
        return None

    def _variants(self, identifier: str) -> Iterable[str]:
        """Normalised forms of an identifier to retry when the exact one misses."""
        stripped = identifier.strip().rstrip(".").rstrip("/")
        if stripped != identifier:
            yield stripped
        lowered = stripped.lower()
        if lowered != stripped:
            yield lowered
        if lowered.startswith("dualstack."):
            yield lowered[len("dualstack."):]
        if stripped.endswith(":*"):
            yield stripped[:-2]
        m = _LAMBDA_QUALIFIED_RE.match(stripped)
        if m:
            yield m.group(1)
        if stripped.startswith("arn:aws:s3:::") and "/" in stripped:
            yield stripped.split("/", 1)[0]
        if ".dkr.ecr." in stripped or ("/" in stripped and ":" in stripped.rsplit("/", 1)[-1]):
            yield _strip_image(stripped)
        if stripped.startswith("arn:aws:apigateway:") and "/stages/" in stripped:
            yield stripped.split("/stages/", 1)[0]
        if ".azurecr.io/" in lowered:
            yield lowered.split("/", 1)[0]  # image -> registry login server

    # ------------------------------------------------------------------
    # External placeholders and bookkeeping
    # ------------------------------------------------------------------

    @staticmethod
    def _foreign_account(identifier: str) -> tuple[CloudProvider, str, str] | None:
        """(provider, account id, account node identifier) an identifier lives in."""
        m = _ARN_ACCOUNT_RE.match(identifier) or re.match(r"^arn:aws[a-zA-Z-]*:iam::(\d{12}):", identifier)
        if m:
            return CloudProvider.AWS, m.group(1), f"arn:aws:iam::{m.group(1)}:root"
        if re.fullmatch(r"\d{12}", identifier):
            return CloudProvider.AWS, identifier, f"arn:aws:iam::{identifier}:root"
        m = _AZURE_SUB_RE.match(identifier)
        if m:
            sub = m.group(1).lower()
            return CloudProvider.AZURE, sub, f"/subscriptions/{sub}"
        m = _GCP_PROJECT_RE.match(identifier)
        if m:
            return CloudProvider.GCP, m.group(1), f"//cloudresourcemanager.googleapis.com/projects/{m.group(1)}"
        return None

    def _external_account(self, identifier: str, context: CloudAsset) -> str | None:
        """Account node (AWS account, Azure subscription, GCP project) for an
        identifier living in an account we did not map."""
        if not self._materialize_external or not isinstance(identifier, str):
            return None
        found = self._foreign_account(identifier)
        if found is None:
            return None
        provider, acct, ref = found
        if acct == "aws" or acct.lower() == (context.account_id or "").lower():
            return None
        existing = self._index.get(ref) or self._index.get(ref.lower())
        if existing:
            return existing[0]
        placeholder = CloudAsset(
            arn=ref,
            name=f"external account {acct}",
            asset_type=AssetType.CLOUD_ACCOUNT,
            provider=provider,
            region="global",
            account_id=acct,
            metadata={"account_id": acct, "external": True, "discovered_via": "cross-account reference"},
        )
        self.external_assets.append(placeholder)
        self._external_ids.add(placeholder.id)
        self._by_id[placeholder.id] = placeholder
        self._index_asset(placeholder)
        return placeholder.id

    def _note_unresolved(self, asset: CloudAsset, target: str, edge: str) -> None:
        if len(self.unresolved) < _MAX_UNRESOLVED:
            self.unresolved.append(
                {"source": asset.arn or asset.id, "source_name": asset.name, "target": target, "edge_type": edge}
            )

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
        relationship: str | None = None,
        properties: dict[str, Any] | None = None,
    ) -> None:
        if not source_id or not target_id or source_id == target_id:
            return
        key = (source_id, target_id, edge_type.value)
        if key in self._edge_keys:
            return
        self._edge_keys.add(key)
        self._pair_keys.add((source_id, target_id))
        edges.append(
            NetworkEdge(
                source_id=source_id,
                target_id=target_id,
                edge_type=edge_type,
                description=description,
                relationship=relationship,
                properties=properties or {},
            )
        )

    # ------------------------------------------------------------------
    # Pass 1: declared relations
    # ------------------------------------------------------------------

    def _link_declared(self, asset: CloudAsset, edges: list[NetworkEdge]) -> None:
        for r in asset.metadata.get("relations", []) or []:
            if not isinstance(r, dict):
                continue
            target_ref = r.get("target")
            try:
                edge_type = EdgeType(r.get("edge", EdgeType.REFERENCES.value))
            except ValueError:
                edge_type = EdgeType.REFERENCES
            target = self.resolve(target_ref, asset)
            if target is None and isinstance(target_ref, str):
                target = self._external_account(target_ref, asset)
            if target is None:
                self._note_unresolved(asset, str(target_ref), edge_type.value)
                continue
            src, dst = (target, asset.id) if r.get("reverse") else (asset.id, target)
            props = dict(r.get("properties") or {})
            if target in self._external_ids and target_ref:
                props.setdefault("external_reference", target_ref)
            self._add(
                edges,
                src,
                dst,
                edge_type,
                r.get("description"),
                r.get("relationship"),
                props,
            )

    # ------------------------------------------------------------------
    # Pass 2: provider-aware rules
    # ------------------------------------------------------------------

    def _link_rules(self, asset: CloudAsset, edges: list[NetworkEdge]) -> None:
        md = asset.metadata
        raw = asset.raw_data or {}

        def res(ref: Any) -> str | None:
            return self.resolve(ref, asset)

        # Security-group / NSG attachment (EC2, ELB, ENI, Lambda, RDS, Azure NIC)
        for sg_ref in md.get("security_groups", []) or []:
            self._add(
                edges,
                asset.id,
                res(sg_ref),
                EdgeType.ATTACHED_TO,
                f"{asset.name} uses security group {sg_ref}",
                "PROTECTED_BY_SG",
            )
        nsg_id = md.get("nsg_id")
        if nsg_id:
            self._add(edges, asset.id, res(nsg_id), EdgeType.ATTACHED_TO, relationship="PROTECTED_BY_SG")

        # Subnet containment (everything with a subnet_id that isn't a subnet)
        subnet_ref = md.get("subnet_id")
        if subnet_ref and asset.asset_type != AssetType.SUBNET:
            self._add(
                edges,
                res(subnet_ref),
                asset.id,
                EdgeType.CONTAINS,
                f"Subnet {subnet_ref} contains {asset.name}",
                "SUBNET_CONTAINS_INSTANCE",
            )

        # Lambda VPC config + execution role
        vpc_config = md.get("vpc_config") or {}
        if isinstance(vpc_config, dict):
            for sn in vpc_config.get("SubnetIds", []) or []:
                self._add(edges, res(sn), asset.id, EdgeType.CONTAINS, relationship="SUBNET_CONTAINS_INSTANCE")
            for sg in vpc_config.get("SecurityGroupIds", []) or []:
                self._add(edges, asset.id, res(sg), EdgeType.ATTACHED_TO, relationship="PROTECTED_BY_SG")
        role_ref = raw.get("Role") or md.get("role_arn")
        if role_ref and asset.asset_type in (
            AssetType.LAMBDA_FUNCTION,
            AssetType.STATE_MACHINE,
        ):
            self._add(
                edges,
                asset.id,
                res(role_ref),
                EdgeType.ASSUMES_ROLE,
                f"{asset.name} executes as {role_ref}",
                "RUNS_ON",
            )
        elif role_ref:
            self._add(edges, asset.id, res(role_ref), EdgeType.REFERENCES, f"{asset.name} references {role_ref}")

        # EC2 instance profile
        profile_arn = (raw.get("IamInstanceProfile") or {}).get("Arn") if raw else None
        if profile_arn:
            self._add(edges, asset.id, res(profile_arn), EdgeType.ASSUMES_ROLE, "instance profile", "RUNS_ON")

        # KMS key references (secrets, volumes, tables, ...)
        kms_ref = md.get("kms_key_id")
        if kms_ref:
            self._add(
                edges,
                asset.id,
                res(kms_ref),
                EdgeType.REFERENCES,
                f"{asset.name} encrypted with {kms_ref}",
                "ENCRYPTED_BY_KMS",
            )

        # CloudFront origins -> S3 buckets / load balancers, WAF -> distribution
        for origin in md.get("origins", []) or []:
            target = res(origin)
            if target is None and isinstance(origin, str):
                # bucket origins look like <bucket>.s3.<region>.amazonaws.com
                target = res(origin.split(".s3", 1)[0]) if ".s3" in origin else None
            if target and ((asset.id, target) in self._pair_keys or (target, asset.id) in self._pair_keys):
                continue  # already linked by a declared (typed) relation
            self._add(
                edges,
                asset.id,
                target,
                EdgeType.REFERENCES,
                f"{asset.name} origin {origin}",
                "SERVES_TRAFFIC_TO",
            )
        web_acl = md.get("web_acl_id")
        if web_acl:
            self._add(edges, res(web_acl), asset.id, EdgeType.PROTECTS, "WAF web ACL", "PROTECTED_BY_WAF")

        # Route tables: routes -> gateways, associations -> subnets
        if asset.asset_type == AssetType.ROUTE_TABLE:
            for route in md.get("routes", []) or []:
                gw = (
                    route.get("GatewayId")
                    or route.get("NatGatewayId")
                    or route.get("TransitGatewayId")
                    or route.get("VpcPeeringConnectionId")
                    or route.get("NetworkInterfaceId")
                )
                if gw and gw != "local":
                    self._add(
                        edges,
                        asset.id,
                        res(gw),
                        EdgeType.ROUTE,
                        f"route {route.get('DestinationCidrBlock', '')} via {gw}",
                        "NAT_TRANSLATED" if route.get("NatGatewayId") else "TRANSIT_ROUTED",
                    )
            for assoc in md.get("associations", []) or []:
                self._add(
                    edges, asset.id, res(assoc.get("SubnetId")), EdgeType.ATTACHED_TO
                )

        # Internet gateway attachments -> VPC
        for attachment in md.get("attachments", []) or []:
            if isinstance(attachment, dict) and attachment.get("VpcId"):
                self._add(
                    edges, asset.id, res(attachment.get("VpcId")), EdgeType.ATTACHED_TO
                )

        # ENI / EBS / EIP attachment -> instance
        inst_ref = md.get("attached_instance_id")
        if inst_ref:
            self._add(edges, asset.id, res(inst_ref), EdgeType.ATTACHED_TO)
        for inst in md.get("attached_instance_ids", []) or []:
            self._add(edges, asset.id, res(inst), EdgeType.ATTACHED_TO)
        eni_ref = md.get("network_interface_id")
        if eni_ref and asset.asset_type != AssetType.NETWORK_INTERFACE:
            self._add(edges, asset.id, res(eni_ref), EdgeType.ATTACHED_TO)

        # VPC peering
        if asset.asset_type == AssetType.PEERING_CONNECTION:
            req = res(md.get("requester_vpc_id"))
            acc = res(md.get("accepter_vpc_id"))
            self._add(edges, req, asset.id, EdgeType.PEERING, relationship="VPC_PEERED")
            self._add(edges, asset.id, acc, EdgeType.PEERING, relationship="VPC_PEERED")

        # Azure VM -> NICs
        for nic_ref in md.get("network_interfaces", []) or []:
            self._add(edges, res(nic_ref), asset.id, EdgeType.ATTACHED_TO)

        # GCP: parent resource containment
        parent = md.get("parent_full_resource_name")
        if parent:
            self._add(edges, res(parent), asset.id, EdgeType.CONTAINS)

    def _link_sso_roles(self, edges: list[NetworkEdge]) -> None:
        """Identity Center permission set -> the AWSReservedSSO_<name>_<hash>
        role it provisions in every assigned account."""
        sets = [a for a in self._assets if a.metadata.get("provisioned_role_prefix")]
        if not sets:
            return
        roles = [
            a for a in self._assets
            if a.asset_type == AssetType.IAM_ROLE
            and str(a.metadata.get("path") or "").startswith("/aws-reserved/sso.amazonaws.com/")
        ]
        for ps in sets:
            prefix = ps.metadata["provisioned_role_prefix"]
            for role in roles:
                if role.name.startswith(prefix) and _SSO_ROLE_HASH_RE.fullmatch(role.name[len(prefix):]):
                    self._add(edges, ps.id, role.id, EdgeType.MANAGES,
                              f"{ps.name} provisions {role.name}", "OWNED_BY")

    # ------------------------------------------------------------------
    # Pass 3: generic reference scan
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
        if _GCP_NAME_RE.match(value):
            return True
        return bool(_AWS_ID_RE.match(value))

    def _link_generic(self, asset: CloudAsset, edges: list[NetworkEdge]) -> None:
        own_ids = {asset.arn, asset.name}
        md = {k: v for k, v in asset.metadata.items() if k not in _SKIP_GENERIC_KEYS}
        for key in _SELF_ID_KEYS:
            own_ids.add(md.pop(key, None))
        for value in self._iter_strings(md):
            if value in own_ids or not self._looks_like_identifier(value):
                continue
            target = self.resolve(value, asset)
            if not target or target == asset.id:
                continue
            if (asset.id, target) in self._pair_keys or (target, asset.id) in self._pair_keys:
                continue
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

        External account placeholders created along the way are available
        on :attr:`external_assets`; unresolvable declared references on
        :attr:`unresolved`.

        Args:
            include_generic: Also run the generic reference scan (pass 3).
        """
        edges: list[NetworkEdge] = []
        for asset in self._assets:
            try:
                self._link_declared(asset, edges)
            except Exception:
                logger.debug("Declared linking failed for %s", asset.name, exc_info=True)
        for asset in self._assets:
            try:
                self._link_rules(asset, edges)
            except Exception:
                logger.debug("Rule linking failed for %s", asset.name, exc_info=True)
        try:
            self._link_sso_roles(edges)
        except Exception:
            logger.debug("SSO role linking failed", exc_info=True)
        if include_generic:
            for asset in self._assets:
                try:
                    self._link_generic(asset, edges)
                except Exception:
                    logger.debug("Generic linking failed for %s", asset.name, exc_info=True)
        logger.info(
            "Linker derived %d relationship edges (%d external accounts, %d unresolved references)",
            len(edges),
            len(self.external_assets),
            len(self.unresolved),
        )
        return edges

    def seed_existing(self, edges: list[NetworkEdge]) -> None:
        """Register already-collected edges so the linker won't duplicate them."""
        for edge in edges:
            self._edge_keys.add((edge.source_id, edge.target_id, edge.edge_type.value))
            self._pair_keys.add((edge.source_id, edge.target_id))
