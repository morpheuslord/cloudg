"""Tests for the semantic ontology engine."""

from __future__ import annotations

import asyncio

import pytest

from cloudg.collectors.aws import AsyncAWSCollector
from cloudg.collectors.azure import AzureCollector
from cloudg.graph.ontology import (
    CMP,
    CMR,
    CloudOntology,
    RelationGroup,
    RelationType,
    get_relation_group,
    get_relations_for_group,
    infer_relations,
    infer_asset_relations,
    iter_asset_relations,
)
from cloudg.graph.ontology_rules import kms_key_index
from cloudg.inventory.dependencies import AssetIndex
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
            id="vpc-1",
            name="prod-vpc",
            asset_type=AssetType.VPC,
            provider=CloudProvider.AWS,
            region="us-east-1",
            account_id="123456789012",
            metadata={"vpc_id": "vpc-1", "cidr_block": "10.0.0.0/16"},
            tags={"Name": "prod-vpc", "owner": "platform-team", "costcenter": "engineering"},
        ),
        CloudAsset(
            id="subnet-1",
            name="prod-subnet",
            asset_type=AssetType.SUBNET,
            provider=CloudProvider.AWS,
            region="us-east-1",
            account_id="123456789012",
            metadata={"vpc_id": "vpc-1", "subnet_id": "subnet-1", "cidr_block": "10.0.1.0/24"},
        ),
        CloudAsset(
            id="ec2-1",
            name="web-server",
            asset_type=AssetType.EC2,
            provider=CloudProvider.AWS,
            region="us-east-1",
            account_id="123456789012",
            metadata={
                "vpc_id": "vpc-1",
                "subnet_id": "subnet-1",
                "security_groups": ["sg-1"],
                "instance_type": "t3.medium",
            },
        ),
        CloudAsset(
            id="rds-1",
            name="prod-db",
            asset_type=AssetType.RDS_INSTANCE,
            provider=CloudProvider.AWS,
            region="us-east-1",
            account_id="123456789012",
            metadata={"storage_encrypted": True, "kms_key_id": "kms-1"},
        ),
        CloudAsset(
            id="sg-1",
            name="web-sg",
            asset_type=AssetType.SECURITY_GROUP,
            provider=CloudProvider.AWS,
            region="us-east-1",
            metadata={"group_id": "sg-1", "vpc_id": "vpc-1"},
        ),
        CloudAsset(
            id="role-1",
            name="app-role",
            asset_type=AssetType.IAM_ROLE,
            provider=CloudProvider.AWS,
            region="global",
            account_id="123456789012",
            metadata={"assume_role_policy": {"Version": "2012-10-17", "Statement": []}},
        ),
        CloudAsset(
            id="kms-1",
            name="prod-key",
            asset_type=AssetType.KMS_KEY,
            provider=CloudProvider.AWS,
            region="us-east-1",
            metadata={"rotation_enabled": True, "key_usage": "ENCRYPT_DECRYPT"},
        ),
    ]


def _make_edges() -> list[NetworkEdge]:
    return [
        NetworkEdge(
            source_id="vpc-1",
            target_id="subnet-1",
            edge_type=EdgeType.CONTAINS,
        ),
        NetworkEdge(
            source_id="0.0.0.0/0",
            target_id="ec2-1",
            edge_type=EdgeType.SECURITY_GROUP_RULE,
            cidr="0.0.0.0/0",
            ports=[443],
            protocol="TCP",
            direction="ingress",
        ),
        NetworkEdge(
            source_id="ec2-1",
            target_id="rds-1",
            edge_type=EdgeType.SECURITY_GROUP_RULE,
            ports=[3306],
            protocol="TCP",
            cidr="10.0.0.0/8",
            direction="ingress",
        ),
        NetworkEdge(
            source_id="ec2-1",
            target_id="0.0.0.0/0",
            edge_type=EdgeType.SECURITY_GROUP_RULE,
            port_range="0-65535",
            protocol="ALL",
            cidr="0.0.0.0/0",
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
        """64 relation types, as the module docstrings say."""
        assert len(RelationType) == 64

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
            source_id="0.0.0.0/0",
            target_id="ec2-1",
            edge_type=EdgeType.SECURITY_GROUP_RULE,
            cidr="0.0.0.0/0",
            ports=[443],
            protocol="TCP",
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
            source_id="10.0.0.0/8",
            target_id="ec2-1",
            edge_type=EdgeType.SECURITY_GROUP_RULE,
            cidr="10.0.0.0/8",
            ports=[22],
            protocol="TCP",
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
            source_id="vpc-1",
            target_id="subnet-1",
            edge_type=EdgeType.CONTAINS,
        )
        rels = infer_relations(edge, assets_by_id)
        rel_names = {r.value for r in rels}
        assert "VPC_CONTAINS_SUBNET" in rel_names

    def test_all_traffic_inferred(self):
        """Wide port range with ALL protocol should infer ALL_TRAFFIC."""
        edge = NetworkEdge(
            source_id="ec2-1",
            target_id="0.0.0.0/0",
            edge_type=EdgeType.SECURITY_GROUP_RULE,
            port_range="0-65535",
            protocol="ALL",
            cidr="0.0.0.0/0",
            direction="egress",
        )
        rels = infer_relations(edge, {})
        rel_names = {r.value for r in rels}
        assert "ALL_TRAFFIC" in rel_names
        assert "EGRESS_ALLOWED" in rel_names

    def test_lb_target_infers_load_balanced(self):
        """LOAD_BALANCER_TARGET edge should infer LB_TARGETS_INSTANCE."""
        edge = NetworkEdge(
            source_id="lb-1",
            target_id="ec2-1",
            edge_type=EdgeType.LOAD_BALANCER_TARGET,
        )
        rels = infer_relations(edge, {})
        rel_names = {r.value for r in rels}
        assert "LB_TARGETS_INSTANCE" in rel_names
        assert "LOAD_BALANCED_BY" in rel_names

    def test_peering_edge(self):
        """PEERING edge should infer VPC_PEERED."""
        edge = NetworkEdge(
            source_id="vpc-1",
            target_id="vpc-2",
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


# ── Containment and filter relation accuracy ──


def _typed(aid: str, asset_type: AssetType) -> CloudAsset:
    return CloudAsset(id=aid, name=aid, asset_type=asset_type, provider=CloudProvider.AWS)


def _rels(source: CloudAsset | str, target: CloudAsset | str, edge_type: EdgeType, **kw) -> set:
    assets = [a for a in (source, target) if isinstance(a, CloudAsset)]
    edge = NetworkEdge(
        source_id=source.id if isinstance(source, CloudAsset) else source,
        target_id=target.id if isinstance(target, CloudAsset) else target,
        edge_type=edge_type,
        **kw,
    )
    return set(infer_relations(edge, {a.id: a for a in assets}))


class TestContainmentRelations:
    """CONTAINS edges get a relation that matches both endpoint types."""

    def test_specific_relations(self):
        R = RelationType
        T = AssetType
        cases = [
            (T.VPC, T.SUBNET, R.VPC_CONTAINS_SUBNET),
            (T.VNET, T.SUBNET, R.VPC_CONTAINS_SUBNET),
            (T.SUBNET, T.EC2, R.SUBNET_CONTAINS_INSTANCE),
            (T.EKS_CLUSTER, T.K8S_NAMESPACE, R.CLUSTER_CONTAINS_SERVICE),
            (T.K8S_NAMESPACE, T.K8S_WORKLOAD, R.CLUSTER_CONTAINS_SERVICE),
            (T.ORGANIZATION, T.CLOUD_ACCOUNT, R.ORG_CONTAINS_ACCOUNT),
            (T.ORG_UNIT, T.CLOUD_ACCOUNT, R.ORG_CONTAINS_ACCOUNT),
        ]
        for src_type, tgt_type, expected in cases:
            rels = _rels(_typed("s", src_type), _typed("t", tgt_type), EdgeType.CONTAINS)
            assert rels == {expected}, (src_type, tgt_type, rels)

    def test_generic_containment_is_plain_contains(self):
        T = AssetType
        cases = [
            (T.ORGANIZATION, T.ORG_UNIT),
            (T.ORG_UNIT, T.ORG_UNIT),
            (T.CLOUD_ACCOUNT, T.VPC),
            (T.VNET, T.VIRTUAL_MACHINE),
            (T.VPC, T.INTERNET_GATEWAY),
            (T.RESOURCE_GROUP, T.KEY_VAULT),
        ]
        for src_type, tgt_type in cases:
            rels = _rels(_typed("s", src_type), _typed("t", tgt_type), EdgeType.CONTAINS)
            assert rels == {RelationType.CONTAINS}, (src_type, tgt_type, rels)

    def test_unresolved_endpoint_is_plain_contains(self):
        rels = _rels("subnet-unmapped", _typed("vm", AssetType.EC2), EdgeType.CONTAINS)
        assert rels == {RelationType.CONTAINS}

    def test_declared_relationship_replaces_inference(self):
        rels = _rels(
            "subnet-unmapped",
            _typed("vm", AssetType.EC2),
            EdgeType.CONTAINS,
            relationship="SUBNET_CONTAINS_INSTANCE",
        )
        assert rels == {RelationType.SUBNET_CONTAINS_INSTANCE}

    def test_contains_is_a_containment_relation(self):
        assert get_relation_group(RelationType.CONTAINS) == RelationGroup.CONTAINMENT


class TestFilterRelations:
    """PROTECTED_BY_SG / PROTECTED_BY_NACL point from the protected resource."""

    def test_internet_sg_rule_is_not_protected_by_sg(self):
        rels = _rels(
            "0.0.0.0/0",
            _typed("sg-web", AssetType.SECURITY_GROUP),
            EdgeType.SECURITY_GROUP_RULE,
            cidr="0.0.0.0/0",
            ports=[443],
            direction="ingress",
        )
        assert RelationType.PROTECTED_BY_SG not in rels
        assert {RelationType.INGRESS_ALLOWED, RelationType.INTERNET_REACHABLE} <= rels

    def test_group_to_group_rule_is_not_protected_by_sg(self):
        rels = _rels(
            _typed("sg-app", AssetType.SECURITY_GROUP),
            _typed("sg-db", AssetType.SECURITY_GROUP),
            EdgeType.SECURITY_GROUP_RULE,
            ports=[5432],
        )
        assert RelationType.PROTECTED_BY_SG not in rels

    def test_nacl_rule_is_not_protected_by_nacl(self):
        rels = _rels(
            "0.0.0.0/0", _typed("acl", AssetType.NACL), EdgeType.NACL_RULE, cidr="0.0.0.0/0"
        )
        assert RelationType.PROTECTED_BY_NACL not in rels

    def test_attachment_to_filter(self):
        T = AssetType
        R = RelationType
        for filter_type, expected in [
            (T.SECURITY_GROUP, R.PROTECTED_BY_SG),
            (T.NSG, R.PROTECTED_BY_SG),
            (T.NACL, R.PROTECTED_BY_NACL),
        ]:
            rels = _rels(_typed("vm", T.EC2), _typed("f", filter_type), EdgeType.ATTACHED_TO)
            assert rels == {expected}, filter_type

    def test_other_attachments_are_dependencies(self):
        rels = _rels(
            _typed("disk", AssetType.EBS_VOLUME), _typed("vm", AssetType.EC2), EdgeType.ATTACHED_TO
        )
        assert rels == {RelationType.DEPENDS_ON}

    def test_declared_attachment_relationship_wins(self):
        rels = _rels(
            _typed("vpn", AssetType.VPN_GATEWAY),
            _typed("tgw", AssetType.TRANSIT_GATEWAY),
            EdgeType.ATTACHED_TO,
            relationship="TRANSIT_ROUTED",
        )
        assert rels == {RelationType.TRANSIT_ROUTED}

    def test_ontology_triples(self):
        """End to end: the RDF graph carries the corrected triples."""
        from cloudg.graph.ontology import CMP, CMR

        assets = [
            _typed("org", AssetType.ORGANIZATION),
            _typed("ou", AssetType.ORG_UNIT),
            _typed("alb", AssetType.LOAD_BALANCER),
            _typed("sg-web", AssetType.SECURITY_GROUP),
        ]
        edges = [
            NetworkEdge(source_id="org", target_id="ou", edge_type=EdgeType.CONTAINS),
            NetworkEdge(
                source_id="0.0.0.0/0",
                target_id="sg-web",
                edge_type=EdgeType.SECURITY_GROUP_RULE,
                cidr="0.0.0.0/0",
                ports=[443],
            ),
            NetworkEdge(source_id="alb", target_id="sg-web", edge_type=EdgeType.ATTACHED_TO),
        ]
        g = CloudOntology().build(assets, edges)

        assert (CMR["org"], CMP["CONTAINS"], CMR["ou"]) in g
        assert (CMR["org"], CMP["VPC_CONTAINS_SUBNET"], CMR["ou"]) not in g
        assert (CMR["0.0.0.0/0"], CMP["PROTECTED_BY_SG"], CMR["sg-web"]) not in g
        assert (CMR["alb"], CMP["PROTECTED_BY_SG"], CMR["sg-web"]) in g


# ── Finding → asset resolution ──

_RDS_ARN = "arn:aws:rds:us-east-1:123456789012:db:prod-db"


def _assets_with_arns() -> list[CloudAsset]:
    assets = _make_assets()
    for a in assets:
        if a.id == "rds-1":
            a.arn = _RDS_ARN
        elif a.id == "ec2-1":
            a.arn = "arn:aws:ec2:us-east-1:123456789012:instance/i-0abc"
    return assets


def _scanner_finding(resource_id: str, resource_arn: str | None = None) -> Finding:
    return Finding(
        resource_id=resource_id,
        resource_arn=resource_arn,
        severity=Severity.HIGH,
        title=f"finding on {resource_id}",
        description="scanner output",
        source_tool="prowler",
        compliance_frameworks=["CIS"],
    )


def _affected(onto: CloudOntology, finding: Finding) -> list[str]:
    sparql = f"""
    SELECT ?res WHERE {{
        cmr:finding_{finding.id} cmp:{RelationType.FINDING_AFFECTS.value} ?res .
    }}
    """
    return [r["res"] for r in onto.query(sparql)]


class TestFindingResolution:
    """Findings attach to the asset by id, ARN or unique name, not raw resource_id."""

    def test_arn_resource_id_links_asset(self):
        finding = _scanner_finding(_RDS_ARN, _RDS_ARN)
        onto = CloudOntology()
        onto.build(_assets_with_arns(), _make_edges(), [finding])
        assert _affected(onto, finding) == ["https://cloudg.io/resource/rds-1"]
        # No dangling node named after the ARN
        assert not any("arn:aws:rds" in str(s) for s in onto.graph.subjects())

    def test_arn_only_in_resource_arn(self):
        finding = _scanner_finding("prod-db-scanner-label", _RDS_ARN)
        onto = CloudOntology()
        onto.build(_assets_with_arns(), _make_edges(), [finding])
        assert _affected(onto, finding) == ["https://cloudg.io/resource/rds-1"]

    def test_unique_name_links_asset(self):
        finding = _scanner_finding("prod-db")
        onto = CloudOntology()
        onto.build(_assets_with_arns(), _make_edges(), [finding])
        assert _affected(onto, finding) == ["https://cloudg.io/resource/rds-1"]

    def test_neighbourhood_includes_arn_finding(self):
        finding = _scanner_finding(_RDS_ARN)
        onto = CloudOntology()
        onto.build(_assets_with_arns(), _make_edges(), [finding])
        rows = onto.query_asset_neighbourhood("rds-1")
        assert any(
            r["predicate"].endswith(RelationType.FINDING_AFFECTS.value)
            and r["neighbour"].endswith(f"finding_{finding.id}")
            for r in rows
        )

    def test_compliance_governs_resolved_asset(self):
        finding = _scanner_finding(_RDS_ARN)
        onto = CloudOntology()
        onto.build(_assets_with_arns(), _make_edges(), [finding])
        sparql = f"""
        SELECT ?res WHERE {{
            cmr:compliance_CIS cmp:{RelationType.COMPLIANCE_GOVERNS.value} ?res .
        }}
        """
        assert [r["res"] for r in onto.query(sparql)] == ["https://cloudg.io/resource/rds-1"]

    def test_ambiguous_name_falls_back_to_raw_id(self):
        assets = _assets_with_arns()
        assets.append(
            CloudAsset(
                id="rds-2",
                name="prod-db",
                asset_type=AssetType.RDS_INSTANCE,
                provider=CloudProvider.AWS,
                region="eu-west-1",
            )
        )
        finding = _scanner_finding("prod-db")
        onto = CloudOntology()
        onto.build(assets, _make_edges(), [finding])
        assert _affected(onto, finding) == ["https://cloudg.io/resource/prod-db"]

    def test_internal_id_still_links(self):
        finding = _scanner_finding("ec2-1")
        onto = CloudOntology()
        onto.build(_assets_with_arns(), _make_edges(), [finding])
        assert _affected(onto, finding) == ["https://cloudg.io/resource/ec2-1"]


# ── Triple direction: KMS encryption and VPC containment ──


def _kms_key(key_id: str = "1234abcd-12ab-34cd-56ef-1234567890ab", **md) -> CloudAsset:
    return CloudAsset(
        arn=f"arn:aws:kms:us-east-1:123456789012:key/{key_id}",
        name=key_id,
        asset_type=AssetType.KMS_KEY,
        provider=CloudProvider.AWS,
        region="us-east-1",
        account_id="123456789012",
        metadata=md,
    )


def _encrypted_db(kms_key_id: str, **md) -> CloudAsset:
    return CloudAsset(
        id="orders-db",
        name="orders-db",
        asset_type=AssetType.RDS_INSTANCE,
        provider=CloudProvider.AWS,
        region="us-east-1",
        account_id="123456789012",
        metadata={"storage_encrypted": True, "kms_key_id": kms_key_id, **md},
    )


def _triples(onto: CloudOntology, rel: RelationType) -> set[tuple[str, str]]:
    prefix = str(CMR)
    return {
        (str(s).removeprefix(prefix), str(o).removeprefix(prefix))
        for s, o in onto.graph.subject_objects(CMP[rel.value])
    }


class TestKmsEncryptionDirection:
    """ENCRYPTED_BY_KMS links the encrypted asset to its key, never an edge's source."""

    def test_edge_into_encrypted_asset_has_no_kms_relation(self):
        assets_by_id = {a.id: a for a in _make_assets()}
        edge = NetworkEdge(
            source_id="ec2-1",
            target_id="rds-1",
            edge_type=EdgeType.SECURITY_GROUP_RULE,
            ports=[3306],
            protocol="TCP",
            cidr="10.0.0.0/8",
            direction="ingress",
        )
        assert RelationType.ENCRYPTED_BY_KMS not in infer_relations(edge, assets_by_id)

    def test_containment_edge_into_encrypted_asset_has_no_kms_relation(self):
        subnet = CloudAsset(
            id="subnet-private",
            name="subnet-private",
            asset_type=AssetType.SUBNET,
            provider=CloudProvider.AWS,
            region="us-east-1",
        )
        db = _encrypted_db("kms-1")
        edge = NetworkEdge(
            source_id="subnet-private", target_id="orders-db", edge_type=EdgeType.CONTAINS
        )
        rels = infer_relations(edge, {subnet.id: subnet, db.id: db})
        assert RelationType.ENCRYPTED_BY_KMS not in rels

    def test_asset_relation_points_at_key_asset(self):
        assets = _make_assets()
        rds = next(a for a in assets if a.id == "rds-1")
        assert (RelationType.ENCRYPTED_BY_KMS, "kms-1") in infer_asset_relations(rds, assets)

    def test_key_resolved_by_arn_key_id_and_alias(self):
        key = _kms_key(aliases=["alias/orders", "arn:aws:kms:us-east-1:123456789012:alias/orders"])
        for ref in (
            key.arn,
            "1234abcd-12ab-34cd-56ef-1234567890ab",
            "alias/orders",
            "arn:aws:kms:us-east-1:123456789012:alias/orders",
        ):
            db = _encrypted_db(ref)
            rels = infer_asset_relations(db, [db, key])
            assert rels == [(RelationType.ENCRYPTED_BY_KMS, key.id)], ref

    def test_uncollected_key_keeps_raw_reference(self):
        ref = "arn:aws:kms:us-east-1:123456789012:key/not-collected"
        db = _encrypted_db(ref)
        assert infer_asset_relations(db, [db, _kms_key()]) == [(RelationType.ENCRYPTED_BY_KMS, ref)]

    def test_unencrypted_asset_with_key_id_has_no_relation(self):
        db = _encrypted_db("kms-1", storage_encrypted=False)
        assert infer_asset_relations(db, [db]) == []

    def test_build_emits_only_asset_to_key_triples(self):
        subnet = CloudAsset(
            id="subnet-private",
            name="subnet-private",
            asset_type=AssetType.SUBNET,
            provider=CloudProvider.AWS,
            region="us-east-1",
        )
        assets = [*_make_assets(), subnet, _encrypted_db("kms-1")]
        edges = [
            *_make_edges(),
            NetworkEdge(
                source_id="subnet-private", target_id="orders-db", edge_type=EdgeType.CONTAINS
            ),
        ]
        onto = CloudOntology()
        onto.build(assets, edges)
        assert _triples(onto, RelationType.ENCRYPTED_BY_KMS) == {
            ("rds-1", "kms-1"),
            ("orders-db", "kms-1"),
        }


class TestVpcContainmentDirection:
    """Metadata containment runs from the VPC to its members."""

    def test_member_assets_emit_no_containment(self):
        assets = _make_assets()
        containment = set(get_relations_for_group(RelationGroup.CONTAINMENT))
        for asset in assets:
            if asset.asset_type == AssetType.VPC:
                continue
            rels = infer_asset_relations(asset, assets)
            assert not [r for r, _ in rels if r in containment], asset.id

    def test_vpc_emits_subnet_and_member_relations(self):
        assets = _make_assets()
        vpc = assets[0]
        group = set(get_relations_for_group(RelationGroup.CONTAINMENT))
        containment = {(r, o) for r, o in infer_asset_relations(vpc, assets) if r in group}
        assert containment == {
            (RelationType.VPC_CONTAINS_SUBNET, "subnet-1"),
            (RelationType.CONTAINS, "ec2-1"),
            (RelationType.CONTAINS, "sg-1"),
        }

    def test_build_emits_vpc_as_subject(self):
        onto = CloudOntology()
        onto.build(_make_assets(), _make_edges())
        assert _triples(onto, RelationType.VPC_CONTAINS_SUBNET) == {("vpc-1", "subnet-1")}
        assert _triples(onto, RelationType.CONTAINS) == {("vpc-1", "ec2-1"), ("vpc-1", "sg-1")}
        assert _triples(onto, RelationType.SUBNET_CONTAINS_INSTANCE) == set()

    def test_duplicate_vpc_records_claim_members_once(self):
        assets = _make_assets()
        dup = assets[0].model_copy(update={"id": "vpc-1-dup", "tags": {}})
        assets.append(dup)
        assert infer_asset_relations(dup, assets) == []
        rels = infer_asset_relations(assets[0], assets)
        assert (RelationType.CONTAINS, "vpc-1-dup") not in rels

    def test_vnet_contains_subnet(self):
        vnet = CloudAsset(
            id="vnet-1",
            name="hub",
            asset_type=AssetType.VNET,
            provider=CloudProvider.AZURE,
            region="westeurope",
            metadata={"vpc_id": "vnet-1"},
        )
        subnet = CloudAsset(
            id="vnet-1-default",
            name="default",
            asset_type=AssetType.SUBNET,
            provider=CloudProvider.AZURE,
            region="westeurope",
            metadata={"vpc_id": "vnet-1"},
        )
        assert infer_asset_relations(vnet, [vnet, subnet]) == [
            (RelationType.VPC_CONTAINS_SUBNET, "vnet-1-default")
        ]
        assert infer_asset_relations(subnet, [vnet, subnet]) == []


# ── Port relations agree with the reachability port parsing ──

_PORT_RELS = {
    RelationType.ALL_TRAFFIC,
    RelationType.ONLY_HTTP,
    RelationType.ONLY_HTTPS,
    RelationType.ONLY_SSH,
    RelationType.ONLY_RDP,
    RelationType.PORT_RESTRICTED,
}


def _aws_group(*ingress: dict) -> CloudAsset:
    return CloudAsset(
        id="sg-asset",
        arn="arn:aws:ec2:us-east-1:123456789012:security-group/sg-0abc",
        name="web-sg",
        asset_type=AssetType.SECURITY_GROUP,
        provider=CloudProvider.AWS,
        metadata={"group_id": "sg-0abc", "ingress_rules": list(ingress), "egress_rules": []},
    )


def _aws_rule(protocol: str, low: int | None = None, high: int | None = None) -> dict:
    rule = {"IpProtocol": protocol, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}
    if low is not None:
        rule.update(FromPort=low, ToPort=high if high is not None else low)
    return rule


def _aws_rule_edges(sg: CloudAsset) -> list[NetworkEdge]:
    collector = AsyncAWSCollector(session=None, region="us-east-1", account_id="123456789012")
    return asyncio.run(collector._collect_sg_edges([sg]))


def _port_rels(edge: NetworkEdge) -> set[RelationType]:
    return set(infer_relations(edge, {})) & _PORT_RELS


class TestPortRelations:
    @pytest.mark.parametrize(
        ("rule", "expected"),
        [
            (
                _aws_rule("tcp", 1, 1024),
                {RelationType.ONLY_SSH, RelationType.ONLY_HTTP, RelationType.ONLY_HTTPS},
            ),
            (_aws_rule("tcp", 22), {RelationType.ONLY_SSH}),
            (_aws_rule("tcp", 8000, 8100), {RelationType.PORT_RESTRICTED}),
            (_aws_rule("tcp", 0, 65535), {RelationType.ALL_TRAFFIC}),
            (_aws_rule("-1"), {RelationType.ALL_TRAFFIC}),
            (_aws_rule("icmp", 8, -1), set()),
        ],
        ids=["1-1024", "22", "8000-8100", "0-65535", "all", "icmp"],
    )
    def test_aws_collector_rules(self, rule, expected):
        (edge,) = _aws_rule_edges(_aws_group(rule))
        assert _port_rels(edge) == expected

    @pytest.mark.parametrize(
        ("protocol", "ports", "expected"),
        [
            ("Tcp", "*", {RelationType.ALL_TRAFFIC}),
            ("*", "*", {RelationType.ALL_TRAFFIC}),
            ("Tcp", "3389", {RelationType.ONLY_RDP}),
            ("Icmp", "*", set()),
        ],
    )
    def test_azure_collector_rules(self, protocol, ports, expected):
        nsg = CloudAsset(
            id="nsg", name="nsg", asset_type=AssetType.NSG, provider=CloudProvider.AZURE
        )
        rule = {
            "name": "r",
            "access": "Allow",
            "protocol": protocol,
            "source_address_prefix": "Internet",
            "destination_port_range": ports,
        }
        (edge,) = AzureCollector._rule_edges(nsg, rule, {})
        rels = set(infer_relations(edge, {nsg.id: nsg}))
        assert rels & _PORT_RELS == expected
        assert RelationType.INTERNET_REACHABLE in rels
        assert RelationType.CIDR_RESTRICTED not in rels

    def test_ports_list_without_port_range_is_used(self):
        edge = NetworkEdge(
            source_id="10.0.0.0/8",
            target_id="sg",
            edge_type=EdgeType.SECURITY_GROUP_RULE,
            cidr="10.0.0.0/8",
            ports=[22, 443],
        )
        assert _port_rels(edge) == {RelationType.ONLY_SSH, RelationType.ONLY_HTTPS}

    @pytest.mark.parametrize("source", ["Internet", "*", "Any", "::/0", "0.0.0.0/0"])
    def test_internet_sources_are_internet_reachable(self, source):
        edge = NetworkEdge(
            source_id=source,
            target_id="nsg",
            edge_type=EdgeType.SECURITY_GROUP_RULE,
            cidr=source,
            port_range="22",
            protocol="Tcp",
        )
        rels = set(infer_relations(edge, {}))
        assert RelationType.INTERNET_REACHABLE in rels
        assert RelationType.CIDR_RESTRICTED not in rels


class TestContainmentTargetTypes:
    """The specific containment relations check the target type as well."""

    @pytest.mark.parametrize(
        ("src_type", "tgt_type"),
        [
            (AssetType.EKS_CLUSTER, AssetType.SUBNET),
            (AssetType.ECS_CLUSTER, AssetType.SECURITY_GROUP),
            (AssetType.SUBNET, AssetType.ROUTE_TABLE),
            (AssetType.SUBNET, AssetType.NACL),
            (AssetType.SUBNET, AssetType.SUBNET),
        ],
    )
    def test_mismatched_target_is_plain_contains(self, src_type, tgt_type):
        rels = _rels(_typed("s", src_type), _typed("t", tgt_type), EdgeType.CONTAINS)
        assert rels == {RelationType.CONTAINS}

    @pytest.mark.parametrize(
        ("src_type", "tgt_type", "expected"),
        [
            (AssetType.EKS_CLUSTER, AssetType.NODE_GROUP, RelationType.CLUSTER_CONTAINS_SERVICE),
            (
                AssetType.ECS_CLUSTER,
                AssetType.CONTAINER_SERVICE,
                RelationType.CLUSTER_CONTAINS_SERVICE,
            ),
            (AssetType.SUBNET, AssetType.RDS_INSTANCE, RelationType.SUBNET_CONTAINS_INSTANCE),
            (AssetType.SUBNET, AssetType.NAT_GATEWAY, RelationType.SUBNET_CONTAINS_INSTANCE),
        ],
    )
    def test_matching_target_keeps_specific_relation(self, src_type, tgt_type, expected):
        rels = _rels(_typed("s", src_type), _typed("t", tgt_type), EdgeType.CONTAINS)
        assert rels == {expected}


class TestSecurityGroupAssetTriples:
    """AWS rule edges end on the security group asset (#25); the triples follow."""

    def test_rule_and_membership_triples_use_the_group_asset(self):
        sg = _aws_group(_aws_rule("tcp", 22), _aws_rule("tcp", 443))
        vm = CloudAsset(
            id="vm-asset", name="web-1", asset_type=AssetType.EC2, provider=CloudProvider.AWS
        )
        edges = [
            *_aws_rule_edges(sg),
            NetworkEdge(source_id=vm.id, target_id=sg.id, edge_type=EdgeType.ATTACHED_TO),
        ]
        g = CloudOntology().build([sg, vm], edges)
        internet = CMR["0.0.0.0/0"]
        assert (internet, CMP["INGRESS_ALLOWED"], CMR["sg-asset"]) in g
        assert (internet, CMP["INTERNET_REACHABLE"], CMR["sg-asset"]) in g
        assert (internet, CMP["ONLY_SSH"], CMR["sg-asset"]) in g
        assert (internet, CMP["ONLY_HTTPS"], CMR["sg-asset"]) in g
        assert (CMR["vm-asset"], CMP["PROTECTED_BY_SG"], CMR["sg-asset"]) in g
        assert not any("sg-0abc" in str(s) for s in g.subjects())


class TestKmsKeyIndex:
    def test_iter_asset_relations_matches_per_asset_inference(self):
        key = _kms_key(aliases=["alias/orders"])
        assets = [*_make_assets(), key, _encrypted_db("alias/orders")]
        expected = [(a.id, r, o) for a in assets for r, o in infer_asset_relations(a, assets)]
        assert [(a.id, r, o) for a, r, o in iter_asset_relations(assets)] == expected
        assert ("orders-db", RelationType.ENCRYPTED_BY_KMS, key.id) in expected

    def test_first_key_wins_a_shared_reference(self):
        first = _kms_key("key-a", aliases=["alias/shared"])
        second = _kms_key("key-b", aliases=["alias/shared"])
        index = kms_key_index([first, second, _encrypted_db("x")])
        assert index.find("alias/shared", tails=False) == first.id
        assert index.find("key-b", tails=False) == second.id
        assert index.find("orders-db", tails=False) is None


# ── AssetIndex: the shared asset matcher ──


def _indexed(*assets: CloudAsset) -> AssetIndex:
    return AssetIndex(assets)


def _named(aid: str, name: str, arn: str | None = None) -> CloudAsset:
    return CloudAsset(
        id=aid, name=name, arn=arn, asset_type=AssetType.OTHER, provider=CloudProvider.AWS
    )


class TestAssetIndex:
    def test_arn_resource_parts(self):
        index = _indexed(
            _named("db", "orders-prod", "arn:aws:rds:us-east-1:1:db:orders"),
            _named("fn", "handler", "arn:aws:lambda:us-east-1:1:function:api-handler"),
            _named("vm", "web", "arn:aws:ec2:us-east-1:1:instance/i-0web1"),
        )
        cases = {
            "db:orders": "db",
            "orders": "db",
            "function:api-handler": "fn",
            "api-handler": "fn",
            "instance/i-0web1": "vm",
            "i-0web1": "vm",
        }
        for ref, expected in cases.items():
            assert index.find(ref, arn_parts=True) == expected, ref
        # off by default, so resolve() and find() keep their old answers
        assert index.find("db:orders") is None
        assert index.resolve("api-handler") is None
        assert index.resolve("i-0web1") == "vm"

    def test_shared_arn_part_is_ambiguous(self):
        index = _indexed(
            _named("a", "a", "arn:aws:rds:us-east-1:1:db:orders"),
            _named("b", "b", "arn:aws:rds:eu-west-1:1:db:orders"),
        )
        assert index.find("orders", arn_parts=True) is None

    def test_casefold_name_tier(self):
        index = _indexed(_named("db", "Orders-DB"), _named("x", "dup"), _named("y", "DUP"))
        assert index.find("orders-db") is None
        assert index.find("orders-db", casefold=True) == "db"
        assert index.find("Dup", casefold=True) is None

    def test_ambiguous_name_is_not_rescued_by_the_opt_in_tiers(self):
        index = _indexed(
            _named("rds-1", "prod-db", "arn:aws:rds:us-east-1:1:db:prod-db"),
            _named("rds-2", "prod-db"),
        )
        assert index.find("prod-db", arn_parts=True, casefold=True) is None

    def test_exact_tiers_win_over_opt_in_tiers(self):
        index = _indexed(
            _named("named", "orders"),
            _named("db", "other", "arn:aws:rds:us-east-1:1:db:orders"),
        )
        assert index.find("orders", arn_parts=True) == "named"

    def test_resolve_finding_with_arn_parts(self):
        index = _indexed(_named("db", "orders-prod", "arn:aws:rds:us-east-1:1:db:orders"))
        finding = _scanner_finding("db:orders")
        assert index.resolve_finding(finding) is None
        assert index.resolve_finding(finding, arn_parts=True) == "db"

    def test_aliases_are_exact_references(self):
        index = AssetIndex()
        index.add("k1", "arn:aws:kms:us-east-1:1:key/k1", aliases=["alias/app"])
        index.add("k2", "arn:aws:kms:us-east-1:1:key/k2", aliases=["alias/app"])
        assert index.resolve("alias/app") == "k1"
