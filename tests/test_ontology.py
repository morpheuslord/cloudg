"""Tests for the semantic ontology engine."""

from __future__ import annotations


from cloudg.graph.ontology import (
    CloudOntology,
    RelationGroup,
    RelationType,
    get_relation_group,
    get_relations_for_group,
    infer_relations,
    infer_asset_relations,
)
from cloudg.schema.models import (
    AssetType,
    CloudAsset,
    CloudProvider,
    EdgeType,
    Finding,
    NetworkEdge,
    Severity,
)


# ── Helpers ──

def _make_assets() -> list[CloudAsset]:
    return [
        CloudAsset(
            id="vpc-1", name="prod-vpc",
            asset_type=AssetType.VPC, provider=CloudProvider.AWS,
            region="us-east-1", account_id="123456789012",
            metadata={"vpc_id": "vpc-1", "cidr_block": "10.0.0.0/16"},
            tags={"Name": "prod-vpc", "owner": "platform-team", "costcenter": "engineering"},
        ),
        CloudAsset(
            id="subnet-1", name="prod-subnet",
            asset_type=AssetType.SUBNET, provider=CloudProvider.AWS,
            region="us-east-1", account_id="123456789012",
            metadata={"vpc_id": "vpc-1", "subnet_id": "subnet-1", "cidr_block": "10.0.1.0/24"},
        ),
        CloudAsset(
            id="ec2-1", name="web-server",
            asset_type=AssetType.EC2, provider=CloudProvider.AWS,
            region="us-east-1", account_id="123456789012",
            metadata={"vpc_id": "vpc-1", "subnet_id": "subnet-1",
                       "security_groups": ["sg-1"], "instance_type": "t3.medium"},
        ),
        CloudAsset(
            id="rds-1", name="prod-db",
            asset_type=AssetType.RDS_INSTANCE, provider=CloudProvider.AWS,
            region="us-east-1", account_id="123456789012",
            metadata={"storage_encrypted": True, "kms_key_id": "kms-1"},
        ),
        CloudAsset(
            id="sg-1", name="web-sg",
            asset_type=AssetType.SECURITY_GROUP, provider=CloudProvider.AWS,
            region="us-east-1",
            metadata={"group_id": "sg-1", "vpc_id": "vpc-1"},
        ),
        CloudAsset(
            id="role-1", name="app-role",
            asset_type=AssetType.IAM_ROLE, provider=CloudProvider.AWS,
            region="global", account_id="123456789012",
            metadata={"assume_role_policy": {"Version": "2012-10-17", "Statement": []}},
        ),
        CloudAsset(
            id="kms-1", name="prod-key",
            asset_type=AssetType.KMS_KEY, provider=CloudProvider.AWS,
            region="us-east-1",
            metadata={"rotation_enabled": True, "key_usage": "ENCRYPT_DECRYPT"},
        ),
    ]


def _make_edges() -> list[NetworkEdge]:
    return [
        NetworkEdge(
            source_id="vpc-1", target_id="subnet-1",
            edge_type=EdgeType.CONTAINS,
        ),
        NetworkEdge(
            source_id="0.0.0.0/0", target_id="ec2-1",
            edge_type=EdgeType.SECURITY_GROUP_RULE,
            cidr="0.0.0.0/0", ports=[443], protocol="TCP",
            direction="ingress",
        ),
        NetworkEdge(
            source_id="ec2-1", target_id="rds-1",
            edge_type=EdgeType.SECURITY_GROUP_RULE,
            ports=[3306], protocol="TCP", cidr="10.0.0.0/8",
            direction="ingress",
        ),
        NetworkEdge(
            source_id="ec2-1", target_id="0.0.0.0/0",
            edge_type=EdgeType.SECURITY_GROUP_RULE,
            port_range="0-65535", protocol="ALL", cidr="0.0.0.0/0",
            direction="egress",
        ),
    ]


def _make_findings() -> list[Finding]:
    return [
        Finding(
            resource_id="ec2-1",
            resource_arn="arn:aws:ec2:::instance/ec2-1",
            severity=Severity.HIGH,
            title="Internet-exposed web server",
            description="EC2 instance is reachable from 0.0.0.0/0 on port 443",
            source_tool="cloudg-reachability",
            compliance_frameworks=["CIS", "NIST-800-53"],
        ),
        Finding(
            resource_id="rds-1",
            severity=Severity.CRITICAL,
            title="Database reachable from internet path",
            description="RDS instance reachable via web-server",
            source_tool="cloudg-reachability",
            compliance_frameworks=["CIS"],
        ),
    ]


# ── RelationType Tests ──


class TestRelationType:
    """Test the relation type taxonomy."""

    def test_total_relation_types(self):
        """Should have ~62 relation types."""
        assert len(RelationType) >= 60

    def test_all_types_have_groups(self):
        """Every relation type must belong to exactly one group."""
        for rt in RelationType:
            group = get_relation_group(rt)
            assert isinstance(group, RelationGroup)

    def test_seven_groups(self):
        """Should have exactly 7 groups."""
        assert len(RelationGroup) == 7

    def test_group_coverage(self):
        """All groups should have at least 4 relation types."""
        for group in RelationGroup:
            rels = get_relations_for_group(group)
            assert len(rels) >= 4, f"{group.value} has only {len(rels)} types"

    def test_network_group_relations(self):
        """Network group should include ingress/egress/internet relations."""
        network_rels = get_relations_for_group(RelationGroup.NETWORK)
        names = {r.value for r in network_rels}
        assert "INGRESS_ALLOWED" in names
        assert "EGRESS_ALLOWED" in names
        assert "INTERNET_REACHABLE" in names
        assert "ONLY_HTTPS" in names


# ── Relation Inference Tests ──


class TestRelationInference:
    """Test inference of semantic relations from raw edges."""

    def test_internet_sg_rule_infers_internet_reachable(self):
        """SG rule with 0.0.0.0/0 should infer INTERNET_REACHABLE."""
        edge = NetworkEdge(
            source_id="0.0.0.0/0", target_id="ec2-1",
            edge_type=EdgeType.SECURITY_GROUP_RULE,
            cidr="0.0.0.0/0", ports=[443], protocol="TCP",
            direction="ingress",
        )
        rels = infer_relations(edge, {})
        rel_names = {r.value for r in rels}
        assert "INTERNET_REACHABLE" in rel_names
        assert "INGRESS_ALLOWED" in rel_names
        assert "ONLY_HTTPS" in rel_names

    def test_ssh_port_infers_only_ssh(self):
        """SG rule with port 22 should infer ONLY_SSH."""
        edge = NetworkEdge(
            source_id="10.0.0.0/8", target_id="ec2-1",
            edge_type=EdgeType.SECURITY_GROUP_RULE,
            cidr="10.0.0.0/8", ports=[22], protocol="TCP",
            direction="ingress",
        )
        rels = infer_relations(edge, {})
        rel_names = {r.value for r in rels}
        assert "ONLY_SSH" in rel_names
        assert "CIDR_RESTRICTED" in rel_names

    def test_containment_edge_infers_vpc_contains(self):
        """CONTAINS edge between VPC and Subnet should infer VPC_CONTAINS_SUBNET."""
        assets_by_id = {a.id: a for a in _make_assets()}
        edge = NetworkEdge(
            source_id="vpc-1", target_id="subnet-1",
            edge_type=EdgeType.CONTAINS,
        )
        rels = infer_relations(edge, assets_by_id)
        rel_names = {r.value for r in rels}
        assert "VPC_CONTAINS_SUBNET" in rel_names

    def test_all_traffic_inferred(self):
        """Wide port range with ALL protocol should infer ALL_TRAFFIC."""
        edge = NetworkEdge(
            source_id="ec2-1", target_id="0.0.0.0/0",
            edge_type=EdgeType.SECURITY_GROUP_RULE,
            port_range="0-65535", protocol="ALL", cidr="0.0.0.0/0",
            direction="egress",
        )
        rels = infer_relations(edge, {})
        rel_names = {r.value for r in rels}
        assert "ALL_TRAFFIC" in rel_names
        assert "EGRESS_ALLOWED" in rel_names

    def test_lb_target_infers_load_balanced(self):
        """LOAD_BALANCER_TARGET edge should infer LB_TARGETS_INSTANCE."""
        edge = NetworkEdge(
            source_id="lb-1", target_id="ec2-1",
            edge_type=EdgeType.LOAD_BALANCER_TARGET,
        )
        rels = infer_relations(edge, {})
        rel_names = {r.value for r in rels}
        assert "LB_TARGETS_INSTANCE" in rel_names
        assert "LOAD_BALANCED_BY" in rel_names

    def test_peering_edge(self):
        """PEERING edge should infer VPC_PEERED."""
        edge = NetworkEdge(
            source_id="vpc-1", target_id="vpc-2",
            edge_type=EdgeType.PEERING,
        )
        rels = infer_relations(edge, {})
        assert RelationType.VPC_PEERED in rels

    def test_asset_relations_tags(self):
        """Asset with owner tag should infer OWNED_BY."""
        asset = _make_assets()[0]  # vpc with owner tag
        rels = infer_asset_relations(asset, _make_assets())
        rel_types = {r[0] for r in rels}
        assert RelationType.OWNED_BY in rel_types
        assert RelationType.COST_ALLOCATED_TO in rel_types

    def test_kms_rotation_infers_rotates_secret(self):
        """KMS key with rotation enabled should infer ROTATES_SECRET."""
        assets = _make_assets()
        kms = next(a for a in assets if a.asset_type == AssetType.KMS_KEY)
        rels = infer_asset_relations(kms, assets)
        rel_types = {r[0] for r in rels}
        assert RelationType.ROTATES_SECRET in rel_types


# ── Ontology Builder Tests ──


class TestCloudOntology:
    """Test the full ontology builder."""

    def test_build_creates_triples(self):
        """Building from assets/edges should produce triples."""
        onto = CloudOntology()
        onto.build(_make_assets(), _make_edges(), _make_findings())
        assert onto.triple_count > 0

    def test_build_creates_asset_individuals(self):
        """Each asset should become an RDF individual."""
        onto = CloudOntology()
        onto.build(_make_assets(), _make_edges())
        # Check that ec2-1 exists as ComputeInstance
        sparql = """
        SELECT ?type WHERE {
            <https://cloudg.io/resource/ec2-1> a ?type .
        }
        """
        results = onto.query(sparql)
        type_strs = [r.get("type", "") for r in results]
        assert any("ComputeInstance" in t for t in type_strs)

    def test_build_creates_relations(self):
        """Edges should produce typed relation triples."""
        onto = CloudOntology()
        onto.build(_make_assets(), _make_edges())
        stats = onto.stats()
        assert stats["total_triples"] > 50
        assert len(stats["relation_type_counts"]) > 0

    def test_all_relation_groups_have_triples(self):
        """All 7 groups should have at least some triples after build."""
        onto = CloudOntology()
        onto.build(_make_assets(), _make_edges(), _make_findings())
        stats = onto.stats()
        # At minimum network, containment, security, governance should be populated
        assert len(stats["relation_group_counts"]) >= 3

    def test_findings_added(self):
        """Findings should create SecurityFinding individuals."""
        onto = CloudOntology()
        onto.build(_make_assets(), _make_edges(), _make_findings())
        sparql = """
        SELECT ?finding WHERE {
            ?finding a <https://cloudg.io/ontology#SecurityFinding> .
        }
        """
        results = onto.query(sparql)
        assert len(results) >= 2

    def test_export_turtle(self):
        """Turtle export should produce valid non-empty string."""
        onto = CloudOntology()
        onto.build(_make_assets(), _make_edges())
        ttl = onto.to_turtle()
        assert len(ttl) > 100
        assert "@prefix" in ttl

    def test_export_jsonld(self):
        """JSON-LD export should produce valid JSON."""
        onto = CloudOntology()
        onto.build(_make_assets(), _make_edges())
        import json
        jsonld = onto.to_jsonld()
        parsed = json.loads(jsonld)
        assert isinstance(parsed, (dict, list))

    def test_save_and_load(self, tmp_path):
        """Save to file and verify it exists."""
        onto = CloudOntology()
        onto.build(_make_assets(), _make_edges())
        path = onto.save(tmp_path / "test.ttl", fmt="turtle")
        assert path.exists()
        assert path.stat().st_size > 100

    def test_stats(self):
        """Stats should return meaningful summary."""
        onto = CloudOntology()
        onto.build(_make_assets(), _make_edges(), _make_findings())
        stats = onto.stats()
        assert stats["total_triples"] > 0
        assert stats["classes_used"] > 0
        assert stats["individuals"] > 0
