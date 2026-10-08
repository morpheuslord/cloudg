"""Provider-aware linking rules (pass 2 of :class:`~cloudg.inventory.linker.RelationshipLinker`).

Each rule reads one family of metadata keys of an asset and emits the
typed edges it implies: security-group attachment, subnet containment,
Lambda VPC config and execution roles, instance profiles, KMS
references, CloudFront origins and WAF, route tables, gateway / ENI /
volume attachment, VPC peering, Azure NIC wiring and GCP parent
containment. The rules run in a fixed order because later ones (the
CloudFront origins) skip pairs that earlier ones already linked.
"""

from __future__ import annotations

from typing import Any, Callable

from cloudg.schema.models import AssetType, CloudAsset, EdgeType, NetworkEdge

__all__ = ["RuleLinksMixin"]

_ROUTE_TARGET_KEYS = (
    "GatewayId",
    "NatGatewayId",
    "TransitGatewayId",
    "VpcPeeringConnectionId",
    "NetworkInterfaceId",
)
_EXECUTION_ROLE_TYPES = (AssetType.LAMBDA_FUNCTION, AssetType.STATE_MACHINE)


class RuleLinksMixin:
    """The pass-2 rules; mixed into RelationshipLinker, which provides
    ``resolve``, ``_add`` and ``_pair_keys``."""

    _pair_keys: set[tuple[str, str]]
    resolve: Callable[..., str | None]
    _add: Callable[..., None]

    def _link_rules(self, asset: CloudAsset, edges: list[NetworkEdge]) -> None:
        for rule in (
            self._rule_security_groups,
            self._rule_subnet,
            self._rule_lambda_vpc,
            self._rule_roles,
            self._rule_kms,
            self._rule_origins,
            self._rule_route_table,
            self._rule_attachments,
            self._rule_peering,
            self._rule_parents,
        ):
            rule(asset, edges)

    def _res(self, ref: Any, asset: CloudAsset) -> str | None:
        return self.resolve(ref, asset)

    def _rule_security_groups(self, asset: CloudAsset, edges: list[NetworkEdge]) -> None:
        """Security-group / NSG attachment (EC2, ELB, ENI, Lambda, RDS, Azure NIC)."""
        md = asset.metadata
        for sg_ref in md.get("security_groups", []) or []:
            self._add(
                edges,
                asset.id,
                self._res(sg_ref, asset),
                EdgeType.ATTACHED_TO,
                f"{asset.name} uses security group {sg_ref}",
                "PROTECTED_BY_SG",
            )
        nsg_id = md.get("nsg_id")
        if nsg_id:
            self._add(
                edges,
                asset.id,
                self._res(nsg_id, asset),
                EdgeType.ATTACHED_TO,
                relationship="PROTECTED_BY_SG",
            )

    def _rule_subnet(self, asset: CloudAsset, edges: list[NetworkEdge]) -> None:
        """Subnet containment (everything with a subnet_id that isn't a subnet)."""
        subnet_ref = asset.metadata.get("subnet_id")
        if subnet_ref and asset.asset_type != AssetType.SUBNET:
            self._add(
                edges,
                self._res(subnet_ref, asset),
                asset.id,
                EdgeType.CONTAINS,
                f"Subnet {subnet_ref} contains {asset.name}",
                "SUBNET_CONTAINS_INSTANCE",
            )

    def _rule_lambda_vpc(self, asset: CloudAsset, edges: list[NetworkEdge]) -> None:
        """Lambda VPC config: subnets contain the function, its groups protect it."""
        vpc_config = asset.metadata.get("vpc_config") or {}
        if not isinstance(vpc_config, dict):
            return
        for sn in vpc_config.get("SubnetIds", []) or []:
            self._add(
                edges,
                self._res(sn, asset),
                asset.id,
                EdgeType.CONTAINS,
                relationship="SUBNET_CONTAINS_INSTANCE",
            )
        for sg in vpc_config.get("SecurityGroupIds", []) or []:
            self._add(
                edges,
                asset.id,
                self._res(sg, asset),
                EdgeType.ATTACHED_TO,
                relationship="PROTECTED_BY_SG",
            )

    def _rule_roles(self, asset: CloudAsset, edges: list[NetworkEdge]) -> None:
        """Execution roles (Lambda, Step Functions), other role references and
        EC2 instance profiles."""
        raw = asset.raw_data or {}
        role_ref = raw.get("Role") or asset.metadata.get("role_arn")
        if role_ref and asset.asset_type in _EXECUTION_ROLE_TYPES:
            self._add(
                edges,
                asset.id,
                self._res(role_ref, asset),
                EdgeType.ASSUMES_ROLE,
                f"{asset.name} executes as {role_ref}",
                "RUNS_ON",
            )
        elif role_ref:
            self._add(
                edges,
                asset.id,
                self._res(role_ref, asset),
                EdgeType.REFERENCES,
                f"{asset.name} references {role_ref}",
            )
        profile_arn = (raw.get("IamInstanceProfile") or {}).get("Arn") if raw else None
        if profile_arn:
            self._add(
                edges,
                asset.id,
                self._res(profile_arn, asset),
                EdgeType.ASSUMES_ROLE,
                "instance profile",
                "RUNS_ON",
            )

    def _rule_kms(self, asset: CloudAsset, edges: list[NetworkEdge]) -> None:
        """KMS key references (secrets, volumes, tables, ...)."""
        kms_ref = asset.metadata.get("kms_key_id")
        if kms_ref:
            self._add(
                edges,
                asset.id,
                self._res(kms_ref, asset),
                EdgeType.REFERENCES,
                f"{asset.name} encrypted with {kms_ref}",
                "ENCRYPTED_BY_KMS",
            )

    def _origin_target(self, origin: Any, asset: CloudAsset) -> str | None:
        target = self._res(origin, asset)
        if target is None and isinstance(origin, str) and ".s3" in origin:
            # bucket origins look like <bucket>.s3.<region>.amazonaws.com
            target = self._res(origin.split(".s3", 1)[0], asset)
        return target

    def _rule_origins(self, asset: CloudAsset, edges: list[NetworkEdge]) -> None:
        """CloudFront origins -> S3 buckets / load balancers, WAF -> distribution."""
        md = asset.metadata
        for origin in md.get("origins", []) or []:
            target = self._origin_target(origin, asset)
            if target and (
                (asset.id, target) in self._pair_keys or (target, asset.id) in self._pair_keys
            ):
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
            self._add(
                edges,
                self._res(web_acl, asset),
                asset.id,
                EdgeType.PROTECTS,
                "WAF web ACL",
                "PROTECTED_BY_WAF",
            )

    def _rule_route_table(self, asset: CloudAsset, edges: list[NetworkEdge]) -> None:
        """Route tables: routes -> gateways, associations -> subnets."""
        if asset.asset_type != AssetType.ROUTE_TABLE:
            return
        md = asset.metadata
        for route in md.get("routes", []) or []:
            gw = next((route.get(k) for k in _ROUTE_TARGET_KEYS if route.get(k)), None)
            if gw and gw != "local":
                self._add(
                    edges,
                    asset.id,
                    self._res(gw, asset),
                    EdgeType.ROUTE,
                    f"route {route.get('DestinationCidrBlock', '')} via {gw}",
                    "NAT_TRANSLATED" if route.get("NatGatewayId") else "TRANSIT_ROUTED",
                )
        for assoc in md.get("associations", []) or []:
            self._add(edges, asset.id, self._res(assoc.get("SubnetId"), asset), EdgeType.ATTACHED_TO)

    def _rule_attachments(self, asset: CloudAsset, edges: list[NetworkEdge]) -> None:
        """Internet gateway -> VPC, and ENI / EBS / EIP -> instance attachment."""
        md = asset.metadata
        targets: list[Any] = [
            attachment.get("VpcId")
            for attachment in md.get("attachments", []) or []
            if isinstance(attachment, dict) and attachment.get("VpcId")
        ]
        inst_ref = md.get("attached_instance_id")
        if inst_ref:
            targets.append(inst_ref)
        targets.extend(md.get("attached_instance_ids", []) or [])
        eni_ref = md.get("network_interface_id")
        if eni_ref and asset.asset_type != AssetType.NETWORK_INTERFACE:
            targets.append(eni_ref)
        for ref in targets:
            self._add(edges, asset.id, self._res(ref, asset), EdgeType.ATTACHED_TO)

    def _rule_peering(self, asset: CloudAsset, edges: list[NetworkEdge]) -> None:
        """VPC peering: requester VPC -> peering -> accepter VPC."""
        if asset.asset_type != AssetType.PEERING_CONNECTION:
            return
        md = asset.metadata
        req = self._res(md.get("requester_vpc_id"), asset)
        acc = self._res(md.get("accepter_vpc_id"), asset)
        self._add(edges, req, asset.id, EdgeType.PEERING, relationship="VPC_PEERED")
        self._add(edges, asset.id, acc, EdgeType.PEERING, relationship="VPC_PEERED")

    def _rule_parents(self, asset: CloudAsset, edges: list[NetworkEdge]) -> None:
        """Azure VM -> NICs, and GCP parent resource containment."""
        md = asset.metadata
        for nic_ref in md.get("network_interfaces", []) or []:
            self._add(edges, self._res(nic_ref, asset), asset.id, EdgeType.ATTACHED_TO)
        parent = md.get("parent_full_resource_name")
        if parent:
            self._add(edges, self._res(parent, asset), asset.id, EdgeType.CONTAINS)
