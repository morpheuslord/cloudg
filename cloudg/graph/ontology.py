"""Semantic ontology engine for cloud infrastructure.

Builds an RDF/OWL knowledge graph from CloudG assets, edges, and findings
using rdflib. Provides ~60 typed semantic relations across 7 domain groups,
SPARQL query interface, and multi-format export (Turtle, JSON-LD, RDF/XML).

The ontology is designed to be RAG-ready: every triple carries rich metadata
that downstream chunking and retrieval systems can exploit.
"""

from __future__ import annotations

import logging
from enum import Enum
from pathlib import Path
from typing import Any

from rdflib import BNode, Graph, Literal, Namespace, URIRef
from rdflib.namespace import OWL, RDF, RDFS, XSD

from cloudg.schema.models import (
    AssetType,
    CloudAsset,
    EdgeType,
    Finding,
    NetworkEdge,
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Namespaces
# ---------------------------------------------------------------------------

CM = Namespace("https://cloudg.io/ontology#")
CMR = Namespace("https://cloudg.io/resource/")
CMP = Namespace("https://cloudg.io/property/")

# ---------------------------------------------------------------------------
# Relation taxonomy — ~62 semantic relation types across 7 groups
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

    # ── Containment (7) ──
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

# AssetType → OWL class URI mapping
_ASSET_TYPE_CLASSES: dict[AssetType, str] = {
    AssetType.EC2: "ComputeInstance",
    AssetType.VIRTUAL_MACHINE: "ComputeInstance",
    AssetType.GCE_INSTANCE: "ComputeInstance",
    AssetType.LAMBDA_FUNCTION: "ServerlessFunction",
    AssetType.CLOUD_FUNCTION: "ServerlessFunction",
    AssetType.ECS_CLUSTER: "ContainerCluster",
    AssetType.EKS_CLUSTER: "ContainerCluster",
    AssetType.AKS_CLUSTER: "ContainerCluster",
    AssetType.GKE_CLUSTER: "ContainerCluster",
    AssetType.APP_SERVICE: "ManagedAppService",
    AssetType.VPC: "VirtualNetwork",
    AssetType.VNET: "VirtualNetwork",
    AssetType.SUBNET: "Subnet",
    AssetType.SECURITY_GROUP: "SecurityGroup",
    AssetType.NSG: "SecurityGroup",
    AssetType.NACL: "NetworkACL",
    AssetType.ROUTE_TABLE: "RouteTable",
    AssetType.INTERNET_GATEWAY: "InternetGateway",
    AssetType.NAT_GATEWAY: "NATGateway",
    AssetType.LOAD_BALANCER: "LoadBalancer",
    AssetType.CLOUDFRONT: "CDNDistribution",
    AssetType.CDN: "CDNDistribution",
    AssetType.TRANSIT_GATEWAY: "TransitGateway",
    AssetType.PEERING_CONNECTION: "PeeringConnection",
    AssetType.ELASTIC_IP: "ElasticIP",
    AssetType.S3_BUCKET: "ObjectStorage",
    AssetType.BLOB_STORAGE: "ObjectStorage",
    AssetType.GCS_BUCKET: "ObjectStorage",
    AssetType.EBS_VOLUME: "BlockStorage",
    AssetType.RDS_INSTANCE: "RelationalDatabase",
    AssetType.AURORA_CLUSTER: "RelationalDatabase",
    AssetType.AZURE_SQL: "RelationalDatabase",
    AssetType.CLOUD_SQL: "RelationalDatabase",
    AssetType.DYNAMODB_TABLE: "NoSQLDatabase",
    AssetType.IAM_USER: "IAMUser",
    AssetType.IAM_ROLE: "IAMRole",
    AssetType.IAM_POLICY: "IAMPolicy",
    AssetType.IAM_GROUP: "IAMGroup",
    AssetType.SERVICE_PRINCIPAL: "ServicePrincipal",
    AssetType.KMS_KEY: "EncryptionKey",
    AssetType.SECRET: "Secret",
    AssetType.CERTIFICATE: "Certificate",
    AssetType.KEY_VAULT: "KeyVault",
    AssetType.CLOUDTRAIL: "AuditLog",
    AssetType.FLOW_LOG: "FlowLog",
    AssetType.OTHER: "CloudResource",
}


def infer_relations(edge: NetworkEdge, assets_by_id: dict[str, CloudAsset]) -> list[RelationType]:
    """Infer semantic relation types from a raw NetworkEdge.

    Analyses CIDR, ports, protocol, direction, and connected asset types
    to produce a list of semantic relations for the edge.
    """
    relations: list[RelationType] = []
    cidr = edge.cidr or ""
    ports = edge.ports or []
    protocol = (edge.protocol or "").upper()
    direction = (edge.direction or "ingress").lower()
    edge_type = edge.edge_type

    # --- Network relations ---
    is_internet = cidr in ("0.0.0.0/0", "::/0")

    if edge_type == EdgeType.SECURITY_GROUP_RULE:
        if direction == "ingress":
            relations.append(RelationType.INGRESS_ALLOWED)
        else:
            relations.append(RelationType.EGRESS_ALLOWED)

        if is_internet:
            relations.append(RelationType.INTERNET_REACHABLE)

        # Port-specific relations
        if len(ports) == 1:
            port_rel = _PORT_RELATIONS.get(ports[0])
            if port_rel:
                relations.append(port_rel)
            else:
                relations.append(RelationType.PORT_RESTRICTED)
        elif len(ports) > 1 and len(ports) <= 20:
            # Specific port set (not wide open)
            for p in ports:
                port_rel = _PORT_RELATIONS.get(p)
                if port_rel and port_rel not in relations:
                    relations.append(port_rel)
            if not any(
                r in relations
                for r in [
                    RelationType.ONLY_HTTP,
                    RelationType.ONLY_HTTPS,
                    RelationType.ONLY_SSH,
                    RelationType.ONLY_RDP,
                ]
            ):
                relations.append(RelationType.PORT_RESTRICTED)
        elif protocol == "ALL" or (edge.port_range and edge.port_range == "0-65535"):
            relations.append(RelationType.ALL_TRAFFIC)

        if not is_internet and cidr:
            relations.append(RelationType.CIDR_RESTRICTED)

    elif edge_type == EdgeType.CONTAINS:
        # Infer containment sub-type from asset types
        src = assets_by_id.get(edge.source_id)
        tgt = assets_by_id.get(edge.target_id)
        if src and tgt:
            if (
                src.asset_type in (AssetType.VPC, AssetType.VNET)
                and tgt.asset_type == AssetType.SUBNET
            ):
                relations.append(RelationType.VPC_CONTAINS_SUBNET)
            elif src.asset_type == AssetType.SUBNET:
                relations.append(RelationType.SUBNET_CONTAINS_INSTANCE)
            elif src.asset_type in (
                AssetType.ECS_CLUSTER,
                AssetType.EKS_CLUSTER,
                AssetType.AKS_CLUSTER,
                AssetType.GKE_CLUSTER,
            ):
                relations.append(RelationType.CLUSTER_CONTAINS_SERVICE)
            else:
                relations.append(RelationType.VPC_CONTAINS_SUBNET)  # generic containment

    elif edge_type == EdgeType.IAM_TRUST:
        relations.append(RelationType.ROLE_ASSUMES_ROLE)
        # Check for cross-account trust
        src = assets_by_id.get(edge.source_id)
        tgt = assets_by_id.get(edge.target_id)
        if src and tgt and src.account_id and tgt.account_id:
            if src.account_id != tgt.account_id:
                relations.append(RelationType.CROSS_ACCOUNT_TRUST)

    elif edge_type == EdgeType.IAM_POLICY_ATTACHMENT:
        tgt = assets_by_id.get(edge.target_id)
        if tgt:
            if tgt.asset_type == AssetType.IAM_USER:
                relations.append(RelationType.USER_HAS_POLICY)
            elif tgt.asset_type == AssetType.IAM_ROLE:
                relations.append(RelationType.ROLE_HAS_POLICY)
            elif tgt.asset_type == AssetType.IAM_GROUP:
                relations.append(RelationType.GROUP_HAS_POLICY)

    elif edge_type == EdgeType.LOAD_BALANCER_TARGET:
        relations.append(RelationType.LB_TARGETS_INSTANCE)
        relations.append(RelationType.LOAD_BALANCED_BY)

    elif edge_type == EdgeType.PEERING:
        relations.append(RelationType.VPC_PEERED)

    elif edge_type == EdgeType.ROUTE:
        relations.append(RelationType.TRANSIT_ROUTED)

    elif edge_type == EdgeType.INTERNET_EXPOSED:
        relations.append(RelationType.INTERNET_REACHABLE)

    # --- Security relations from asset metadata ---
    tgt_asset = assets_by_id.get(edge.target_id)
    if tgt_asset:
        # SG protection
        if edge_type == EdgeType.SECURITY_GROUP_RULE:
            relations.append(RelationType.PROTECTED_BY_SG)
        elif edge_type == EdgeType.NACL_RULE:
            relations.append(RelationType.PROTECTED_BY_NACL)

        # KMS encryption (from metadata)
        if tgt_asset.metadata.get("encryption") or tgt_asset.metadata.get("storage_encrypted"):
            kms_key = tgt_asset.metadata.get("kms_key_id", "")
            if kms_key:
                relations.append(RelationType.ENCRYPTED_BY_KMS)

    return relations


def infer_asset_relations(
    asset: CloudAsset, all_assets: list[CloudAsset]
) -> list[tuple[RelationType, str]]:
    """Infer additional semantic relations from asset metadata alone.

    Returns list of (RelationType, target_asset_id) tuples.
    """
    relations: list[tuple[RelationType, str]] = []

    # Tag-based governance
    if asset.tags:
        for tag_key in asset.tags:
            tag_lower = tag_key.lower()
            if tag_lower in ("owner", "team", "department"):
                relations.append((RelationType.OWNED_BY, f"tag:{asset.tags[tag_key]}"))
            elif tag_lower in ("costcenter", "cost-center", "cost_center"):
                relations.append((RelationType.COST_ALLOCATED_TO, f"tag:{asset.tags[tag_key]}"))
            elif tag_lower in ("monitoring", "monitored-by"):
                relations.append((RelationType.MONITORED_BY, f"tag:{asset.tags[tag_key]}"))

    # VPC/Subnet containment from metadata
    vpc_id = asset.metadata.get("vpc_id")
    if vpc_id and asset.asset_type != AssetType.VPC:
        for other in all_assets:
            if (
                other.asset_type in (AssetType.VPC, AssetType.VNET)
                and other.metadata.get("vpc_id") == vpc_id
            ):
                if asset.asset_type == AssetType.SUBNET:
                    relations.append((RelationType.VPC_CONTAINS_SUBNET, other.id))
                else:
                    relations.append((RelationType.SUBNET_CONTAINS_INSTANCE, other.id))
                break

    # Lambda VPC config → DEPENDS_ON VPC
    if asset.asset_type == AssetType.LAMBDA_FUNCTION:
        vpc_config = asset.metadata.get("vpc_config")
        if vpc_config and isinstance(vpc_config, dict) and vpc_config.get("VpcId"):
            relations.append((RelationType.DEPENDS_ON, f"vpc:{vpc_config['VpcId']}"))

    # Secret rotation
    if asset.asset_type == AssetType.SECRET:
        if asset.metadata.get("rotation_enabled"):
            relations.append((RelationType.ROTATES_SECRET, asset.id))

    # KMS key rotation
    if asset.asset_type == AssetType.KMS_KEY:
        if asset.metadata.get("rotation_enabled"):
            relations.append((RelationType.ROTATES_SECRET, asset.id))

    # SG membership from EC2 metadata
    if asset.asset_type == AssetType.EC2:
        sg_ids = asset.metadata.get("security_groups", [])
        for sg_id in sg_ids:
            relations.append((RelationType.PROTECTED_BY_SG, f"sg:{sg_id}"))

    return relations


# ---------------------------------------------------------------------------
# OWL Ontology Builder
# ---------------------------------------------------------------------------


class CloudOntology:
    """Builds and queries a semantic RDF/OWL graph for cloud infrastructure.

    Constructs OWL class hierarchy, typed object/data properties, and
    individual instances from CloudG's Pydantic models.
    """

    def __init__(self) -> None:
        self._graph = Graph()
        self._graph.bind("cm", CM)
        self._graph.bind("cmr", CMR)
        self._graph.bind("cmp", CMP)
        self._graph.bind("owl", OWL)
        self._triple_count = 0

    @property
    def graph(self) -> Graph:
        """Access the underlying rdflib Graph."""
        return self._graph

    @property
    def triple_count(self) -> int:
        return len(self._graph)

    # ------------------------------------------------------------------
    # Schema definition (TBox)
    # ------------------------------------------------------------------

    def _define_schema(self) -> None:
        """Define the OWL class hierarchy and property declarations."""
        g = self._graph

        # Top-level classes
        for cls_name in [
            "CloudResource",
            "ComputeInstance",
            "ServerlessFunction",
            "ContainerCluster",
            "ManagedAppService",
            "VirtualNetwork",
            "Subnet",
            "SecurityGroup",
            "NetworkACL",
            "RouteTable",
            "InternetGateway",
            "NATGateway",
            "LoadBalancer",
            "CDNDistribution",
            "TransitGateway",
            "PeeringConnection",
            "ElasticIP",
            "ObjectStorage",
            "BlockStorage",
            "RelationalDatabase",
            "NoSQLDatabase",
            "IAMUser",
            "IAMRole",
            "IAMPolicy",
            "IAMGroup",
            "ServicePrincipal",
            "EncryptionKey",
            "Secret",
            "Certificate",
            "KeyVault",
            "AuditLog",
            "FlowLog",
            "SecurityFinding",
            "ComplianceControl",
            "Region",
            "Account",
            "Organization",
            "TagValue",
        ]:
            cls_uri = CM[cls_name]
            g.add((cls_uri, RDF.type, OWL.Class))
            g.add((cls_uri, RDFS.label, Literal(cls_name)))

        # Class hierarchy
        hierarchy = {
            "ComputeInstance": "CloudResource",
            "ServerlessFunction": "CloudResource",
            "ContainerCluster": "CloudResource",
            "ManagedAppService": "CloudResource",
            "VirtualNetwork": "CloudResource",
            "Subnet": "CloudResource",
            "SecurityGroup": "CloudResource",
            "NetworkACL": "CloudResource",
            "LoadBalancer": "CloudResource",
            "CDNDistribution": "CloudResource",
            "ObjectStorage": "CloudResource",
            "BlockStorage": "CloudResource",
            "RelationalDatabase": "CloudResource",
            "NoSQLDatabase": "CloudResource",
            "IAMUser": "CloudResource",
            "IAMRole": "CloudResource",
            "IAMPolicy": "CloudResource",
            "EncryptionKey": "CloudResource",
            "Secret": "CloudResource",  # nosec B105 - class hierarchy label, not a credential
        }
        for child, parent in hierarchy.items():
            g.add((CM[child], RDFS.subClassOf, CM[parent]))

        # Object properties (relations)
        for rt in RelationType:
            prop_uri = CMP[rt.value]
            g.add((prop_uri, RDF.type, OWL.ObjectProperty))
            g.add((prop_uri, RDFS.label, Literal(rt.value.replace("_", " ").title())))
            group = get_relation_group(rt)
            g.add((prop_uri, CM["relationGroup"], Literal(group.value)))

        # Data properties
        for dp_name in [
            "hasARN",
            "hasName",
            "hasRegion",
            "hasProvider",
            "hasAccountId",
            "hasCIDR",
            "hasPort",
            "hasProtocol",
            "hasSeverity",
            "hasRiskScore",
            "isInternetExposed",
        ]:
            dp_uri = CMP[dp_name]
            g.add((dp_uri, RDF.type, OWL.DatatypeProperty))

    # ------------------------------------------------------------------
    # Instance population (ABox)
    # ------------------------------------------------------------------

    def build(
        self,
        assets: list[CloudAsset],
        edges: list[NetworkEdge],
        findings: list[Finding] | None = None,
    ) -> Graph:
        """Build the full ontology graph from CloudG data.

        Args:
            assets: Collected cloud assets.
            edges: Network/relationship edges.
            findings: Optional security findings.

        Returns:
            Populated rdflib Graph.
        """
        logger.info("Building ontology from %d assets, %d edges", len(assets), len(edges))

        self._define_schema()
        assets_by_id = {a.id: a for a in assets}

        # Add asset individuals
        for asset in assets:
            self._add_asset(asset)

        # Add edges with inferred semantic relations
        for edge in edges:
            self._add_edge(edge, assets_by_id)

        # Add inferred asset-level relations
        for asset in assets:
            for rel_type, target_id in infer_asset_relations(asset, assets):
                src_uri = CMR[asset.id]
                tgt_uri = (
                    CMR[target_id]
                    if not target_id.startswith("tag:")
                    else CMR[target_id.replace(":", "_")]
                )
                self._graph.add((src_uri, CMP[rel_type.value], tgt_uri))

        # Add findings
        if findings:
            for finding in findings:
                self._add_finding(finding)

        logger.info("Ontology built: %d triples", len(self._graph))
        return self._graph

    def _add_asset(self, asset: CloudAsset) -> None:
        """Add a CloudAsset as an OWL individual."""
        uri = CMR[asset.id]
        owl_class = _ASSET_TYPE_CLASSES.get(asset.asset_type, "CloudResource")

        self._graph.add((uri, RDF.type, CM[owl_class]))
        self._graph.add((uri, CMP["hasName"], Literal(asset.name)))
        self._graph.add((uri, CMP["hasProvider"], Literal(asset.provider.value)))
        self._graph.add((uri, CMP["hasRegion"], Literal(asset.region)))
        self._graph.add(
            (
                uri,
                CMP["isInternetExposed"],
                Literal(asset.is_internet_exposed, datatype=XSD.boolean),
            )
        )

        if asset.arn:
            self._graph.add((uri, CMP["hasARN"], Literal(asset.arn)))
        if asset.account_id:
            self._graph.add((uri, CMP["hasAccountId"], Literal(asset.account_id)))

        # Tags as triples
        for key, value in asset.tags.items():
            tag_uri = CMR[f"tag_{key}_{value}".replace(" ", "_").replace("/", "_")]
            self._graph.add((uri, CMP[RelationType.TAGGED_WITH.value], tag_uri))
            self._graph.add((tag_uri, RDF.type, CM["TagValue"]))
            self._graph.add((tag_uri, RDFS.label, Literal(f"{key}={value}")))

    def _add_edge(self, edge: NetworkEdge, assets_by_id: dict[str, CloudAsset]) -> None:
        """Add a NetworkEdge as typed semantic triples with metadata."""
        src_uri = CMR[edge.source_id]
        tgt_uri = CMR[edge.target_id]

        # Ensure external nodes exist
        if edge.source_id not in assets_by_id:
            self._graph.add((src_uri, RDF.type, CM["CloudResource"]))
            self._graph.add((src_uri, CMP["hasName"], Literal(edge.source_id)))
        if edge.target_id not in assets_by_id:
            self._graph.add((tgt_uri, RDF.type, CM["CloudResource"]))
            self._graph.add((tgt_uri, CMP["hasName"], Literal(edge.target_id)))

        # Infer semantic relations
        inferred = infer_relations(edge, assets_by_id)

        for rel in inferred:
            self._graph.add((src_uri, CMP[rel.value], tgt_uri))

        # Add edge metadata as reified statement (blank node)
        if edge.cidr or edge.port_range or edge.protocol:
            stmt = BNode()
            self._graph.add((stmt, RDF.type, CM["EdgeMetadata"]))
            self._graph.add((stmt, CM["fromNode"], src_uri))
            self._graph.add((stmt, CM["toNode"], tgt_uri))
            if edge.cidr:
                self._graph.add((stmt, CMP["hasCIDR"], Literal(edge.cidr)))
            if edge.port_range:
                self._graph.add((stmt, CMP["hasPort"], Literal(edge.port_range)))
            if edge.protocol:
                self._graph.add((stmt, CMP["hasProtocol"], Literal(edge.protocol)))

    def _add_finding(self, finding: Finding) -> None:
        """Add a Finding as an OWL individual with relations."""
        uri = CMR[f"finding_{finding.id}"]
        self._graph.add((uri, RDF.type, CM["SecurityFinding"]))
        self._graph.add((uri, CMP["hasName"], Literal(finding.title)))
        self._graph.add((uri, CMP["hasSeverity"], Literal(finding.severity.value)))
        self._graph.add((uri, CMP["hasRiskScore"], Literal(finding.risk_score, datatype=XSD.float)))

        # Link to affected resource
        resource_uri = CMR[finding.resource_id]
        self._graph.add((uri, CMP[RelationType.FINDING_AFFECTS.value], resource_uri))

        # Link to compliance frameworks
        for fw in finding.compliance_frameworks:
            fw_uri = CMR[f"compliance_{fw}"]
            self._graph.add((fw_uri, RDF.type, CM["ComplianceControl"]))
            self._graph.add((fw_uri, RDFS.label, Literal(fw)))
            self._graph.add((fw_uri, CMP[RelationType.COMPLIANCE_GOVERNS.value], resource_uri))

    # ------------------------------------------------------------------
    # SPARQL queries
    # ------------------------------------------------------------------

    def query(self, sparql: str) -> list[dict[str, Any]]:
        """Execute a SPARQL query and return results as list of dicts."""
        results = []
        for row in self._graph.query(sparql):
            results.append({str(var): str(val) for var, val in zip(row.labels, row)})
        return results

    def query_internet_exposed(self) -> list[dict[str, str]]:
        """Find all internet-reachable resources."""
        sparql = """
        SELECT ?resource ?name ?type WHERE {
            ?source cmp:INTERNET_REACHABLE ?resource .
            ?resource cmp:hasName ?name .
            ?resource a ?type .
            FILTER(?type != owl:NamedIndividual)
        }
        """
        return self.query(sparql)

    def query_by_relation_group(self, group: RelationGroup) -> list[dict[str, str]]:
        """Find all triples belonging to a specific relation group."""
        relation_types = get_relations_for_group(group)
        if not relation_types:
            return []

        # Build UNION of all relation types in the group
        patterns = []
        for rt in relation_types:
            patterns.append(f"{{ ?src cmp:{rt.value} ?tgt }}")
        union = " UNION ".join(patterns)

        sparql = f"""
        SELECT ?src ?tgt ?srcName ?tgtName WHERE {{
            {union}
            OPTIONAL {{ ?src cmp:hasName ?srcName }}
            OPTIONAL {{ ?tgt cmp:hasName ?tgtName }}
        }}
        """
        return self.query(sparql)

    def query_asset_neighbourhood(self, asset_id: str, hops: int = 1) -> list[dict[str, str]]:
        """Find all resources within N hops of a given asset."""
        # For 1-hop we query direct predicates; for N-hop we use property paths
        if hops == 1:
            sparql = f"""
            SELECT ?predicate ?neighbour ?neighbourName WHERE {{
                {{
                    cmr:{asset_id} ?predicate ?neighbour .
                    FILTER(STRSTARTS(STR(?predicate), STR(cmp:)))
                }} UNION {{
                    ?neighbour ?predicate cmr:{asset_id} .
                    FILTER(STRSTARTS(STR(?predicate), STR(cmp:)))
                }}
                OPTIONAL {{ ?neighbour cmp:hasName ?neighbourName }}
            }}
            """
        else:
            # N-hop uses transitive path (up to hops length)
            sparql = f"""
            SELECT DISTINCT ?neighbour ?neighbourName WHERE {{
                cmr:{asset_id} (cmp:INGRESS_ALLOWED|cmp:EGRESS_ALLOWED|cmp:CONTAINS|cmp:VPC_CONTAINS_SUBNET|cmp:SUBNET_CONTAINS_INSTANCE|cmp:INTERNET_REACHABLE|cmp:PROTECTED_BY_SG|cmp:LB_TARGETS_INSTANCE){{1,{hops}}} ?neighbour .
                OPTIONAL {{ ?neighbour cmp:hasName ?neighbourName }}
            }}
            """
        return self.query(sparql)

    def query_compliance_gaps(self) -> list[dict[str, str]]:
        """Find resources affected by findings with compliance frameworks."""
        sparql = """
        SELECT ?finding ?severity ?resource ?resourceName ?framework WHERE {
            ?finding a cm:SecurityFinding .
            ?finding cmp:hasSeverity ?severity .
            ?finding cmp:FINDING_AFFECTS ?resource .
            ?framework cmp:COMPLIANCE_GOVERNS ?resource .
            ?framework rdfs:label ?frameworkName .
            OPTIONAL { ?resource cmp:hasName ?resourceName }
        }
        """
        return self.query(sparql)

    # ------------------------------------------------------------------
    # Export
    # ------------------------------------------------------------------

    def to_turtle(self) -> str:
        """Serialize graph to Turtle format."""
        return self._graph.serialize(format="turtle")

    def to_jsonld(self) -> str:
        """Serialize graph to JSON-LD format."""
        return self._graph.serialize(format="json-ld")

    def to_rdfxml(self) -> str:
        """Serialize graph to RDF/XML format."""
        return self._graph.serialize(format="xml")

    def to_ntriples(self) -> str:
        """Serialize graph to N-Triples format."""
        return self._graph.serialize(format="nt")

    def save(self, path: str | Path, fmt: str = "turtle") -> Path:
        """Save ontology to file.

        Args:
            path: Output file path.
            fmt: Serialization format (turtle, json-ld, xml, nt).

        Returns:
            Path to saved file.
        """
        output = Path(path)
        output.parent.mkdir(parents=True, exist_ok=True)

        format_map = {
            "turtle": "turtle",
            "ttl": "turtle",
            "json-ld": "json-ld",
            "jsonld": "json-ld",
            "xml": "xml",
            "rdfxml": "xml",
            "nt": "nt",
            "ntriples": "nt",
        }
        rdflib_fmt = format_map.get(fmt.lower(), "turtle")

        self._graph.serialize(destination=str(output), format=rdflib_fmt)
        logger.info("Saved ontology (%d triples) to %s as %s", len(self._graph), output, rdflib_fmt)
        return output

    # ------------------------------------------------------------------
    # Statistics
    # ------------------------------------------------------------------

    def stats(self) -> dict[str, Any]:
        """Return ontology statistics."""
        classes = set()
        individuals = set()
        relation_counts: dict[str, int] = {}

        for s, p, o in self._graph:
            if p == RDF.type and isinstance(o, URIRef) and str(o).startswith(str(CM)):
                cls_name = str(o).replace(str(CM), "")
                classes.add(cls_name)
                individuals.add(str(s))

            if isinstance(p, URIRef) and str(p).startswith(str(CMP)):
                prop_name = str(p).replace(str(CMP), "")
                relation_counts[prop_name] = relation_counts.get(prop_name, 0) + 1

        # Group relation counts
        group_counts: dict[str, int] = {}
        for rt_name, count in relation_counts.items():
            try:
                rt = RelationType(rt_name)
                grp = get_relation_group(rt).value
                group_counts[grp] = group_counts.get(grp, 0) + count
            except ValueError:
                pass  # Data properties, not relations

        return {
            "total_triples": len(self._graph),
            "classes_used": len(classes),
            "individuals": len(individuals),
            "relation_type_counts": relation_counts,
            "relation_group_counts": group_counts,
        }
