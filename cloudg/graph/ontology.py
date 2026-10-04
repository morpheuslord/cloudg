"""Semantic ontology engine for cloud infrastructure.

Builds an RDF/OWL knowledge graph from CloudG assets, edges, and findings
using rdflib. Provides ~60 typed semantic relations across 7 domain groups,
SPARQL query interface, and multi-format export (Turtle, JSON-LD, RDF/XML).

The ontology is designed to be RAG-ready: every triple carries rich metadata
that downstream chunking and retrieval systems can exploit.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from rdflib import BNode, Graph, Literal, Namespace, URIRef
from rdflib.namespace import OWL, RDF, RDFS, XSD

# Relation taxonomy and inference rules live in ontology_rules; they are
# re-exported here so `from cloudg.graph.ontology import ...` keeps working.
from cloudg.graph.ontology_rules import (
    RelationGroup,
    RelationType,
    get_relation_group,
    get_relations_for_group,
    infer_asset_relations,
    infer_relations,
)
from cloudg.schema.models import (
    AssetType,
    CloudAsset,
    Finding,
    NetworkEdge,
)

__all__ = [
    "CM",
    "CMP",
    "CMR",
    "CloudOntology",
    "RelationGroup",
    "RelationType",
    "get_relation_group",
    "get_relations_for_group",
    "infer_asset_relations",
    "infer_relations",
]

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Namespaces
# ---------------------------------------------------------------------------

CM = Namespace("https://cloudg.io/ontology#")
CMR = Namespace("https://cloudg.io/resource/")
CMP = Namespace("https://cloudg.io/property/")


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
    AssetType.NETWORK_INTERFACE: "NetworkInterface",
    AssetType.LOG_GROUP: "LogGroup",
    AssetType.CONTAINER_REGISTRY: "ContainerRegistry",
    AssetType.CONTAINER_SERVICE: "ContainerService",
    AssetType.TASK_DEFINITION: "TaskDefinition",
    AssetType.NODE_GROUP: "NodeGroup",
    AssetType.FARGATE_PROFILE: "FargateProfile",
    AssetType.CLUSTER_ADDON: "ClusterAddon",
    AssetType.K8S_NAMESPACE: "KubernetesNamespace",
    AssetType.K8S_WORKLOAD: "KubernetesWorkload",
    AssetType.K8S_SERVICE: "KubernetesService",
    AssetType.K8S_INGRESS: "KubernetesIngress",
    AssetType.K8S_SERVICE_ACCOUNT: "KubernetesServiceAccount",
    AssetType.AUTOSCALING_GROUP: "AutoScalingGroup",
    AssetType.LAUNCH_TEMPLATE: "LaunchTemplate",
    AssetType.TARGET_GROUP: "TargetGroup",
    AssetType.API_GATEWAY: "APIGateway",
    AssetType.VPC_ENDPOINT: "VPCEndpoint",
    AssetType.INSTANCE_PROFILE: "InstanceProfile",
    AssetType.IDENTITY_PROVIDER: "IdentityProvider",
    AssetType.MESSAGE_QUEUE: "MessageQueue",
    AssetType.NOTIFICATION_TOPIC: "NotificationTopic",
    AssetType.EVENT_BUS: "EventBus",
    AssetType.EVENT_RULE: "EventRule",
    AssetType.STATE_MACHINE: "StateMachine",
    AssetType.DATA_STREAM: "DataStream",
    AssetType.CACHE_CLUSTER: "CacheCluster",
    AssetType.SEARCH_DOMAIN: "SearchDomain",
    AssetType.DATA_WAREHOUSE: "DataWarehouse",
    AssetType.FILE_SYSTEM: "FileSystem",
    AssetType.DNS_ZONE: "DNSZone",
    AssetType.DNS_RECORD: "DNSRecord",
    AssetType.IAC_STACK: "IaCStack",
    AssetType.WAF_WEB_ACL: "WebApplicationFirewall",
    AssetType.NETWORK_FIREWALL: "NetworkFirewall",
    AssetType.DDOS_PROTECTION: "DDoSProtection",
    AssetType.THREAT_DETECTOR: "ThreatDetector",
    AssetType.SECURITY_HUB: "SecurityPostureHub",
    AssetType.VULNERABILITY_SCANNER: "VulnerabilityScanner",
    AssetType.DATA_SECURITY_SCANNER: "DataSecurityScanner",
    AssetType.CONFIG_RECORDER: "ConfigurationRecorder",
    AssetType.ACCESS_ANALYZER: "AccessAnalyzer",
    AssetType.ORGANIZATION: "Organization",
    AssetType.ORG_UNIT: "OrganizationalUnit",
    AssetType.CLOUD_ACCOUNT: "Account",
    AssetType.ORG_POLICY: "OrganizationPolicy",
    AssetType.LANDING_ZONE: "LandingZone",
    AssetType.GUARDRAIL: "Guardrail",
}


def _class_name(asset_type: AssetType) -> str:
    return "".join(part.capitalize() for part in asset_type.name.split("_"))


# Every AssetType gets an OWL class: explicit names above, CamelCase of the
# enum name otherwise, so new taxonomy values never fall back to CloudResource.
for _t in AssetType:
    _ASSET_TYPE_CLASSES.setdefault(_t, _class_name(_t))


# ---------------------------------------------------------------------------
# OWL Ontology Builder
# ---------------------------------------------------------------------------

# Top-level OWL classes declared in the schema (TBox)
_ONTOLOGY_CLASSES = [
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
]

# Class hierarchy: child → parent
_CLASS_HIERARCHY = {
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

# Data properties declared in the schema
_DATA_PROPERTIES = [
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
]


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
        for cls_name in _ONTOLOGY_CLASSES:
            cls_uri = CM[cls_name]
            g.add((cls_uri, RDF.type, OWL.Class))
            g.add((cls_uri, RDFS.label, Literal(cls_name)))

        # Class hierarchy
        for child, parent in _CLASS_HIERARCHY.items():
            g.add((CM[child], RDFS.subClassOf, CM[parent]))

        # Classes for every asset type (including ones not in the literal
        # list above), all under CloudResource.
        for cls_name in sorted(set(_ASSET_TYPE_CLASSES.values()) - {"CloudResource"}):
            cls_uri = CM[cls_name]
            if (cls_uri, RDF.type, OWL.Class) not in g:
                g.add((cls_uri, RDF.type, OWL.Class))
                g.add((cls_uri, RDFS.label, Literal(cls_name)))
            if cls_name not in _CLASS_HIERARCHY:
                g.add((cls_uri, RDFS.subClassOf, CM["CloudResource"]))

        # Object properties (relations)
        for rt in RelationType:
            prop_uri = CMP[rt.value]
            g.add((prop_uri, RDF.type, OWL.ObjectProperty))
            g.add((prop_uri, RDFS.label, Literal(rt.value.replace("_", " ").title())))
            group = get_relation_group(rt)
            g.add((prop_uri, CM["relationGroup"], Literal(group.value)))

        # Data properties
        for dp_name in _DATA_PROPERTIES:
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
