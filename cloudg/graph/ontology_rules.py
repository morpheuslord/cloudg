"""Relation taxonomy and inference rules for the cloud ontology.

Defines the ~63 typed semantic relations across 7 domain groups and the
inference layer that derives them from raw CloudG edges and asset metadata.
The OWL graph builder itself lives in :mod:`cloudg.graph.ontology`.
"""

from __future__ import annotations

from enum import Enum
from typing import Callable

from cloudg.schema.models import (
    AssetType,
    CloudAsset,
    EdgeType,
    NetworkEdge,
)

# ---------------------------------------------------------------------------
# Relation taxonomy: ~63 semantic relation types across 7 groups
# ---------------------------------------------------------------------------


class RelationGroup(str, Enum):
    """Top-level grouping of relation types."""

    NETWORK = "NETWORK"
    CONTAINMENT = "CONTAINMENT"
    IAM = "IAM"
    DATA_FLOW = "DATA_FLOW"
    SECURITY = "SECURITY"
    COMPUTE = "COMPUTE"
    GOVERNANCE = "GOVERNANCE"


class RelationType(str, Enum):
    """Fine-grained semantic relation types for cloud asset mapping."""

    # ── Network (15) ──
    INGRESS_ALLOWED = "INGRESS_ALLOWED"
    INGRESS_DENIED = "INGRESS_DENIED"
    EGRESS_ALLOWED = "EGRESS_ALLOWED"
    EGRESS_DENIED = "EGRESS_DENIED"
    ONLY_HTTP = "ONLY_HTTP"
    ONLY_HTTPS = "ONLY_HTTPS"
    ONLY_SSH = "ONLY_SSH"
    ONLY_RDP = "ONLY_RDP"
    ALL_TRAFFIC = "ALL_TRAFFIC"
    PORT_RESTRICTED = "PORT_RESTRICTED"
    CIDR_RESTRICTED = "CIDR_RESTRICTED"
    INTERNET_REACHABLE = "INTERNET_REACHABLE"
    VPC_PEERED = "VPC_PEERED"
    TRANSIT_ROUTED = "TRANSIT_ROUTED"
    NAT_TRANSLATED = "NAT_TRANSLATED"
    DNS_RESOLVED = "DNS_RESOLVED"

    # ── Containment (8) ──
    CONTAINS = "CONTAINS"
    VPC_CONTAINS_SUBNET = "VPC_CONTAINS_SUBNET"
    SUBNET_CONTAINS_INSTANCE = "SUBNET_CONTAINS_INSTANCE"
    REGION_CONTAINS_VPC = "REGION_CONTAINS_VPC"
    ACCOUNT_CONTAINS_REGION = "ACCOUNT_CONTAINS_REGION"
    ORG_CONTAINS_ACCOUNT = "ORG_CONTAINS_ACCOUNT"
    CLUSTER_CONTAINS_SERVICE = "CLUSTER_CONTAINS_SERVICE"
    LB_TARGETS_INSTANCE = "LB_TARGETS_INSTANCE"

    # ── IAM / Access (10) ──
    ROLE_ASSUMES_ROLE = "ROLE_ASSUMES_ROLE"
    USER_HAS_POLICY = "USER_HAS_POLICY"
    ROLE_HAS_POLICY = "ROLE_HAS_POLICY"
    GROUP_HAS_POLICY = "GROUP_HAS_POLICY"
    POLICY_ALLOWS_ACTION = "POLICY_ALLOWS_ACTION"
    POLICY_DENIES_ACTION = "POLICY_DENIES_ACTION"
    CROSS_ACCOUNT_TRUST = "CROSS_ACCOUNT_TRUST"
    SERVICE_LINKED_ROLE = "SERVICE_LINKED_ROLE"
    PERMISSION_BOUNDARY_LIMITS = "PERMISSION_BOUNDARY_LIMITS"
    SCP_RESTRICTS = "SCP_RESTRICTS"

    # ── Data Flow (9) ──
    READS_FROM = "READS_FROM"
    WRITES_TO = "WRITES_TO"
    ENCRYPTS_WITH = "ENCRYPTS_WITH"
    DECRYPTS_WITH = "DECRYPTS_WITH"
    LOGS_TO = "LOGS_TO"
    STREAMS_TO = "STREAMS_TO"
    REPLICATES_TO = "REPLICATES_TO"
    BACKUP_TO = "BACKUP_TO"
    CACHE_FOR = "CACHE_FOR"

    # ── Security (9) ──
    PROTECTED_BY_SG = "PROTECTED_BY_SG"
    PROTECTED_BY_NACL = "PROTECTED_BY_NACL"
    PROTECTED_BY_WAF = "PROTECTED_BY_WAF"
    ENCRYPTED_BY_KMS = "ENCRYPTED_BY_KMS"
    ROTATES_SECRET = "ROTATES_SECRET"  # nosec B105 # nosemgrep -- ontology relation name, not a credential
    CERTIFICATE_SECURES = "CERTIFICATE_SECURES"
    FINDING_AFFECTS = "FINDING_AFFECTS"
    VULNERABILITY_EXPLOITS = "VULNERABILITY_EXPLOITS"
    COMPLIANCE_GOVERNS = "COMPLIANCE_GOVERNS"

    # ── Compute (8) ──
    RUNS_ON = "RUNS_ON"
    TRIGGERED_BY = "TRIGGERED_BY"
    INVOKES = "INVOKES"
    SCALES_WITH = "SCALES_WITH"
    LOAD_BALANCED_BY = "LOAD_BALANCED_BY"
    SCHEDULED_BY = "SCHEDULED_BY"
    DEPENDS_ON = "DEPENDS_ON"
    SERVES_TRAFFIC_TO = "SERVES_TRAFFIC_TO"

    # ── Governance (4) ──
    TAGGED_WITH = "TAGGED_WITH"
    COST_ALLOCATED_TO = "COST_ALLOCATED_TO"
    OWNED_BY = "OWNED_BY"
    MONITORED_BY = "MONITORED_BY"


# Mapping from RelationType → RelationGroup
_RELATION_GROUPS: dict[RelationType, RelationGroup] = {}
_GROUP_RANGES = {
    RelationGroup.NETWORK: [
        RelationType.INGRESS_ALLOWED,
        RelationType.INGRESS_DENIED,
        RelationType.EGRESS_ALLOWED,
        RelationType.EGRESS_DENIED,
        RelationType.ONLY_HTTP,
        RelationType.ONLY_HTTPS,
        RelationType.ONLY_SSH,
        RelationType.ONLY_RDP,
        RelationType.ALL_TRAFFIC,
        RelationType.PORT_RESTRICTED,
        RelationType.CIDR_RESTRICTED,
        RelationType.INTERNET_REACHABLE,
        RelationType.VPC_PEERED,
        RelationType.TRANSIT_ROUTED,
        RelationType.NAT_TRANSLATED,
        RelationType.DNS_RESOLVED,
    ],
    RelationGroup.CONTAINMENT: [
        RelationType.CONTAINS,
        RelationType.VPC_CONTAINS_SUBNET,
        RelationType.SUBNET_CONTAINS_INSTANCE,
        RelationType.REGION_CONTAINS_VPC,
        RelationType.ACCOUNT_CONTAINS_REGION,
        RelationType.ORG_CONTAINS_ACCOUNT,
        RelationType.CLUSTER_CONTAINS_SERVICE,
        RelationType.LB_TARGETS_INSTANCE,
    ],
    RelationGroup.IAM: [
        RelationType.ROLE_ASSUMES_ROLE,
        RelationType.USER_HAS_POLICY,
        RelationType.ROLE_HAS_POLICY,
        RelationType.GROUP_HAS_POLICY,
        RelationType.POLICY_ALLOWS_ACTION,
        RelationType.POLICY_DENIES_ACTION,
        RelationType.CROSS_ACCOUNT_TRUST,
        RelationType.SERVICE_LINKED_ROLE,
        RelationType.PERMISSION_BOUNDARY_LIMITS,
        RelationType.SCP_RESTRICTS,
    ],
    RelationGroup.DATA_FLOW: [
        RelationType.READS_FROM,
        RelationType.WRITES_TO,
        RelationType.ENCRYPTS_WITH,
        RelationType.DECRYPTS_WITH,
        RelationType.LOGS_TO,
        RelationType.STREAMS_TO,
        RelationType.REPLICATES_TO,
        RelationType.BACKUP_TO,
        RelationType.CACHE_FOR,
    ],
    RelationGroup.SECURITY: [
        RelationType.PROTECTED_BY_SG,
        RelationType.PROTECTED_BY_NACL,
        RelationType.PROTECTED_BY_WAF,
        RelationType.ENCRYPTED_BY_KMS,
        RelationType.ROTATES_SECRET,
        RelationType.CERTIFICATE_SECURES,
        RelationType.FINDING_AFFECTS,
        RelationType.VULNERABILITY_EXPLOITS,
        RelationType.COMPLIANCE_GOVERNS,
    ],
    RelationGroup.COMPUTE: [
        RelationType.RUNS_ON,
        RelationType.TRIGGERED_BY,
        RelationType.INVOKES,
        RelationType.SCALES_WITH,
        RelationType.LOAD_BALANCED_BY,
        RelationType.SCHEDULED_BY,
        RelationType.DEPENDS_ON,
        RelationType.SERVES_TRAFFIC_TO,
    ],
    RelationGroup.GOVERNANCE: [
        RelationType.TAGGED_WITH,
        RelationType.COST_ALLOCATED_TO,
        RelationType.OWNED_BY,
        RelationType.MONITORED_BY,
    ],
}
for _group, _types in _GROUP_RANGES.items():
    for _rt in _types:
        _RELATION_GROUPS[_rt] = _group


def get_relation_group(rt: RelationType) -> RelationGroup:
    """Return the group a relation type belongs to."""
    return _RELATION_GROUPS[rt]


def get_relations_for_group(group: RelationGroup) -> list[RelationType]:
    """Return all relation types in a group."""
    return list(_GROUP_RANGES.get(group, []))


# ---------------------------------------------------------------------------
# Relation inference from raw CloudG edges
# ---------------------------------------------------------------------------

# Port → protocol-specific relation mapping
_PORT_RELATIONS: dict[int, RelationType] = {
    80: RelationType.ONLY_HTTP,
    443: RelationType.ONLY_HTTPS,
    22: RelationType.ONLY_SSH,
    3389: RelationType.ONLY_RDP,
}


def _infer_port_relations(edge: NetworkEdge) -> list[RelationType]:
    """Infer port-specific relations for a security-group rule."""
    relations: list[RelationType] = []
    ports = edge.ports or []
    protocol = (edge.protocol or "").upper()

    if len(ports) == 1:
        port_rel = _PORT_RELATIONS.get(ports[0])
        relations.append(port_rel if port_rel else RelationType.PORT_RESTRICTED)
    elif len(ports) > 1 and len(ports) <= 20:
        # Specific port set (not wide open)
        for p in ports:
            port_rel = _PORT_RELATIONS.get(p)
            if port_rel and port_rel not in relations:
                relations.append(port_rel)
        if not any(r in relations for r in _PORT_RELATIONS.values()):
            relations.append(RelationType.PORT_RESTRICTED)
    elif protocol == "ALL" or (edge.port_range and edge.port_range == "0-65535"):
        relations.append(RelationType.ALL_TRAFFIC)

    return relations


def _infer_sg_rule_relations(
    edge: NetworkEdge, assets_by_id: dict[str, CloudAsset]
) -> list[RelationType]:
    """Infer network relations for a SECURITY_GROUP_RULE edge."""
    relations: list[RelationType] = []
    cidr = edge.cidr or ""
    direction = (edge.direction or "ingress").lower()
    is_internet = cidr in ("0.0.0.0/0", "::/0")

    if direction == "ingress":
        relations.append(RelationType.INGRESS_ALLOWED)
    else:
        relations.append(RelationType.EGRESS_ALLOWED)

    if is_internet:
        relations.append(RelationType.INTERNET_REACHABLE)

    relations.extend(_infer_port_relations(edge))

    if not is_internet and cidr:
        relations.append(RelationType.CIDR_RESTRICTED)

    return relations


_CLUSTER_TYPES = {
    AssetType.ECS_CLUSTER,
    AssetType.EKS_CLUSTER,
    AssetType.AKS_CLUSTER,
    AssetType.GKE_CLUSTER,
    AssetType.K8S_NAMESPACE,
}
_ORG_TYPES = {AssetType.ORGANIZATION, AssetType.ORG_UNIT}


def _infer_containment_relations(
    edge: NetworkEdge, assets_by_id: dict[str, CloudAsset]
) -> list[RelationType]:
    """Infer the containment sub-type from the source and target asset types.

    A specific relation is used only when both ends match it: VPC / VNet to
    subnet, subnet to placed resource, cluster or namespace to workload,
    organization or OU to account. Anything else (organization to OU,
    account to VPC, VNet to VM, resource group to resource, unresolved
    endpoints) is plain ``CONTAINS``.
    """
    src = assets_by_id.get(edge.source_id)
    tgt = assets_by_id.get(edge.target_id)
    if not (src and tgt):
        return [RelationType.CONTAINS]
    if src.asset_type in (AssetType.VPC, AssetType.VNET) and tgt.asset_type == AssetType.SUBNET:
        return [RelationType.VPC_CONTAINS_SUBNET]
    if src.asset_type == AssetType.SUBNET:
        return [RelationType.SUBNET_CONTAINS_INSTANCE]
    if src.asset_type in _CLUSTER_TYPES:
        return [RelationType.CLUSTER_CONTAINS_SERVICE]
    if src.asset_type in _ORG_TYPES and tgt.asset_type == AssetType.CLOUD_ACCOUNT:
        return [RelationType.ORG_CONTAINS_ACCOUNT]
    return [RelationType.CONTAINS]


def _infer_iam_trust_relations(
    edge: NetworkEdge, assets_by_id: dict[str, CloudAsset]
) -> list[RelationType]:
    """Infer IAM trust relations, including cross-account trust."""
    relations = [RelationType.ROLE_ASSUMES_ROLE]
    src = assets_by_id.get(edge.source_id)
    tgt = assets_by_id.get(edge.target_id)
    if src and tgt and src.account_id and tgt.account_id:
        if src.account_id != tgt.account_id:
            relations.append(RelationType.CROSS_ACCOUNT_TRUST)
    return relations


# IAM policy attachment target type → relation
_POLICY_TARGET_RELATIONS: dict[AssetType, RelationType] = {
    AssetType.IAM_USER: RelationType.USER_HAS_POLICY,
    AssetType.IAM_ROLE: RelationType.ROLE_HAS_POLICY,
    AssetType.IAM_GROUP: RelationType.GROUP_HAS_POLICY,
}


def _infer_policy_attachment_relations(
    edge: NetworkEdge, assets_by_id: dict[str, CloudAsset]
) -> list[RelationType]:
    """Infer policy attachment relation from the target principal type."""
    tgt = assets_by_id.get(edge.target_id)
    rel = _POLICY_TARGET_RELATIONS.get(tgt.asset_type) if tgt else None
    return [rel] if rel else []


# Filter asset type -> relation for "resource ATTACHED_TO filter" edges
_FILTER_TARGET_RELATIONS: dict[AssetType, RelationType] = {
    AssetType.SECURITY_GROUP: RelationType.PROTECTED_BY_SG,
    AssetType.NSG: RelationType.PROTECTED_BY_SG,
    AssetType.NACL: RelationType.PROTECTED_BY_NACL,
}


def _infer_attachment_relations(
    edge: NetworkEdge, assets_by_id: dict[str, CloudAsset]
) -> list[RelationType]:
    """Infer the relation for an ATTACHED_TO edge from the target type.

    A resource attached to a security group, NSG or NACL is protected by
    it (``resource PROTECTED_BY_SG group``). Other attachments (ENI to
    instance, disk to VM, gateway to VPC) are dependencies.
    """
    tgt = assets_by_id.get(edge.target_id)
    rel = _FILTER_TARGET_RELATIONS.get(tgt.asset_type) if tgt else None
    return [rel] if rel else [RelationType.DEPENDS_ON]


def _infer_target_security_relations(
    edge: NetworkEdge, assets_by_id: dict[str, CloudAsset]
) -> list[RelationType]:
    """Infer security relations from the target asset's metadata.

    Rule edges (``SECURITY_GROUP_RULE``, ``NACL_RULE``) point from the
    traffic source to the filter, so they never yield ``PROTECTED_BY_SG`` /
    ``PROTECTED_BY_NACL``: those relations come from ATTACHED_TO edges,
    whose source is the protected resource.
    """
    tgt_asset = assets_by_id.get(edge.target_id)
    if not tgt_asset:
        return []
    relations: list[RelationType] = []

    # KMS encryption (from metadata)
    if tgt_asset.metadata.get("encryption") or tgt_asset.metadata.get("storage_encrypted"):
        if tgt_asset.metadata.get("kms_key_id", ""):
            relations.append(RelationType.ENCRYPTED_BY_KMS)

    return relations


# EdgeType → inference rule for edge types needing asset context
_EDGE_RELATION_RULES: dict[
    EdgeType, Callable[[NetworkEdge, dict[str, CloudAsset]], list[RelationType]]
] = {
    EdgeType.SECURITY_GROUP_RULE: _infer_sg_rule_relations,
    EdgeType.CONTAINS: _infer_containment_relations,
    EdgeType.IAM_TRUST: _infer_iam_trust_relations,
    EdgeType.IAM_POLICY_ATTACHMENT: _infer_policy_attachment_relations,
    EdgeType.ATTACHED_TO: _infer_attachment_relations,
}

# EdgeType → fixed relations for simple edge types
_SIMPLE_EDGE_RELATIONS: dict[EdgeType, list[RelationType]] = {
    EdgeType.LOAD_BALANCER_TARGET: [
        RelationType.LB_TARGETS_INSTANCE,
        RelationType.LOAD_BALANCED_BY,
    ],
    EdgeType.PEERING: [RelationType.VPC_PEERED],
    EdgeType.ROUTE: [RelationType.TRANSIT_ROUTED],
    EdgeType.INTERNET_EXPOSED: [RelationType.INTERNET_REACHABLE],
    # Typed inventory edges (used when the edge declares no relationship)
    EdgeType.INVOKES: [RelationType.INVOKES],
    EdgeType.USES_IMAGE: [RelationType.RUNS_ON],
    EdgeType.ASSUMES_ROLE: [RelationType.RUNS_ON],
    EdgeType.GRANTS_ACCESS: [RelationType.POLICY_ALLOWS_ACTION],
    EdgeType.LOGS_TO: [RelationType.LOGS_TO],
    EdgeType.PROTECTS: [RelationType.PROTECTED_BY_WAF],
    EdgeType.MONITORS: [RelationType.MONITORED_BY],
    EdgeType.MANAGES: [RelationType.OWNED_BY],
    EdgeType.GOVERNS: [RelationType.COMPLIANCE_GOVERNS],
    EdgeType.REFERENCES: [RelationType.DEPENDS_ON],
}

# Edge types whose default (or inferred) relation is only used when the edge
# carries no explicit ``relationship`` of its own.
_TYPED_EDGE_TYPES = {
    EdgeType.CONTAINS,
    EdgeType.INVOKES,
    EdgeType.USES_IMAGE,
    EdgeType.ASSUMES_ROLE,
    EdgeType.GRANTS_ACCESS,
    EdgeType.LOGS_TO,
    EdgeType.PROTECTS,
    EdgeType.MONITORS,
    EdgeType.MANAGES,
    EdgeType.GOVERNS,
    EdgeType.REFERENCES,
    EdgeType.ATTACHED_TO,
}


def infer_relations(edge: NetworkEdge, assets_by_id: dict[str, CloudAsset]) -> list[RelationType]:
    """Infer semantic relation types from a raw NetworkEdge.

    Analyses CIDR, ports, protocol, direction, and connected asset types
    to produce a list of semantic relations for the edge.
    """
    relations: list[RelationType] = []

    # An explicit relationship declared by the collector comes first
    declared = getattr(edge, "relationship", None)
    if declared and declared in RelationType.__members__:
        relations.append(RelationType[declared])

    # --- Network / containment / IAM relations by edge type ---
    rule = _EDGE_RELATION_RULES.get(edge.edge_type)
    if relations and edge.edge_type in _TYPED_EDGE_TYPES:
        pass  # the declared relationship replaces the default
    elif rule:
        relations.extend(r for r in rule(edge, assets_by_id) if r not in relations)
    else:
        relations.extend(
            r for r in _SIMPLE_EDGE_RELATIONS.get(edge.edge_type, []) if r not in relations
        )

    # --- Security relations from asset metadata ---
    relations.extend(_infer_target_security_relations(edge, assets_by_id))

    return relations


# Governance tag key (lower-cased) → relation
_TAG_KEY_RELATIONS: dict[str, RelationType] = {
    "owner": RelationType.OWNED_BY,
    "team": RelationType.OWNED_BY,
    "department": RelationType.OWNED_BY,
    "costcenter": RelationType.COST_ALLOCATED_TO,
    "cost-center": RelationType.COST_ALLOCATED_TO,
    "cost_center": RelationType.COST_ALLOCATED_TO,
    "monitoring": RelationType.MONITORED_BY,
    "monitored-by": RelationType.MONITORED_BY,
}


def _infer_tag_relations(asset: CloudAsset) -> list[tuple[RelationType, str]]:
    """Infer tag-based governance relations."""
    relations: list[tuple[RelationType, str]] = []
    for tag_key, tag_value in asset.tags.items():
        rel = _TAG_KEY_RELATIONS.get(tag_key.lower())
        if rel:
            relations.append((rel, f"tag:{tag_value}"))
    return relations


def _infer_vpc_containment(
    asset: CloudAsset, all_assets: list[CloudAsset]
) -> list[tuple[RelationType, str]]:
    """Infer VPC/Subnet containment from metadata."""
    vpc_id = asset.metadata.get("vpc_id")
    if not vpc_id or asset.asset_type == AssetType.VPC:
        return []
    for other in all_assets:
        if (
            other.asset_type in (AssetType.VPC, AssetType.VNET)
            and other.metadata.get("vpc_id") == vpc_id
        ):
            if asset.asset_type == AssetType.SUBNET:
                return [(RelationType.VPC_CONTAINS_SUBNET, other.id)]
            return [(RelationType.SUBNET_CONTAINS_INSTANCE, other.id)]
    return []


def _infer_metadata_relations(asset: CloudAsset) -> list[tuple[RelationType, str]]:
    """Infer relations from an asset's own metadata by asset type."""
    relations: list[tuple[RelationType, str]] = []

    # Lambda VPC config → DEPENDS_ON VPC
    if asset.asset_type == AssetType.LAMBDA_FUNCTION:
        vpc_config = asset.metadata.get("vpc_config")
        if vpc_config and isinstance(vpc_config, dict) and vpc_config.get("VpcId"):
            relations.append((RelationType.DEPENDS_ON, f"vpc:{vpc_config['VpcId']}"))

    # Secret / KMS key rotation
    if asset.asset_type in (AssetType.SECRET, AssetType.KMS_KEY):
        if asset.metadata.get("rotation_enabled"):
            relations.append((RelationType.ROTATES_SECRET, asset.id))

    # SG membership from EC2 metadata
    if asset.asset_type == AssetType.EC2:
        for sg_id in asset.metadata.get("security_groups", []):
            relations.append((RelationType.PROTECTED_BY_SG, f"sg:{sg_id}"))

    return relations


def infer_asset_relations(
    asset: CloudAsset, all_assets: list[CloudAsset]
) -> list[tuple[RelationType, str]]:
    """Infer additional semantic relations from asset metadata alone.

    Returns list of (RelationType, target_asset_id) tuples.
    """
    relations: list[tuple[RelationType, str]] = []
    relations.extend(_infer_tag_relations(asset))
    relations.extend(_infer_vpc_containment(asset, all_assets))
    relations.extend(_infer_metadata_relations(asset))
    return relations
