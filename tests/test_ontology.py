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
