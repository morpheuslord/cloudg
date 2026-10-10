"""Tests for RAG chunk export."""

from __future__ import annotations

import json

import networkx as nx

from cloudg.graph.rag_export import RAGChunk, RAGExporter
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
            account_id="111",
            metadata={"vpc_id": "vpc-1", "cidr_block": "10.0.0.0/16"},
        ),
        CloudAsset(
            id="ec2-1",
            name="web-server",
            asset_type=AssetType.EC2,
            provider=CloudProvider.AWS,
            region="us-east-1",
            account_id="111",
            is_internet_exposed=True,
            metadata={"vpc_id": "vpc-1", "instance_type": "t3.medium"},
        ),
        CloudAsset(
            id="rds-1",
            name="prod-db",
            asset_type=AssetType.RDS_INSTANCE,
            provider=CloudProvider.AWS,
            region="us-east-1",
            account_id="111",
        ),
        CloudAsset(
            id="sg-1",
            name="web-sg",
            asset_type=AssetType.SECURITY_GROUP,
            provider=CloudProvider.AWS,
            region="us-east-1",
        ),
    ]


def _make_edges() -> list[NetworkEdge]:
    return [
        NetworkEdge(
            source_id="vpc-1",
            target_id="ec2-1",
            edge_type=EdgeType.CONTAINS,
        ),
        NetworkEdge(
            source_id="0.0.0.0/0",
            target_id="ec2-1",
            edge_type=EdgeType.SECURITY_GROUP_RULE,
            cidr="0.0.0.0/0",
            ports=[443],
            protocol="TCP",
        ),
        NetworkEdge(
            source_id="ec2-1",
            target_id="rds-1",
            edge_type=EdgeType.SECURITY_GROUP_RULE,
            ports=[3306],
            protocol="TCP",
        ),
    ]


def _make_findings() -> list[Finding]:
    return [
        Finding(
            resource_id="ec2-1",
            severity=Severity.HIGH,
            title="Internet-exposed instance",
            description="desc",
            source_tool="test",
            compliance_frameworks=["CIS"],
        ),
    ]


def _build_graph() -> nx.DiGraph:
    """Build a test NetworkX graph matching our assets/edges."""
    from cloudg.graph.builder import GraphBuilder

    builder = GraphBuilder()
    return builder.build(_make_assets(), _make_edges())


# ── RAGChunk Tests ──


class TestRAGChunk:
    def test_to_dict(self):
        chunk = RAGChunk(
            chunk_id="test::1",
            chunk_type="entity",
            content="test content",
            metadata={"key": "value"},
            relations=[{"predicate": "TEST", "object": "x"}],
        )
        d = chunk.to_dict()
        assert d["chunk_id"] == "test::1"
        assert d["chunk_type"] == "entity"
        assert d["metadata"]["key"] == "value"


# ── Entity Chunk Tests ──


class TestEntityChunks:
    def test_one_chunk_per_asset(self):
        """Should generate one chunk per asset."""
        exporter = RAGExporter()
        chunks = exporter.export_entity_chunks(_make_assets(), _make_edges())
        assert len(chunks) == len(_make_assets())

    def test_chunk_has_correct_type(self):
        exporter = RAGExporter()
        chunks = exporter.export_entity_chunks(_make_assets(), _make_edges())
        assert all(c.chunk_type == "entity" for c in chunks)

    def test_chunk_id_format(self):
        exporter = RAGExporter()
        chunks = exporter.export_entity_chunks(_make_assets(), _make_edges())
        assert all(c.chunk_id.startswith("entity::") for c in chunks)

    def test_metadata_fields(self):
        """Each chunk should have required metadata fields."""
        exporter = RAGExporter()
        chunks = exporter.export_entity_chunks(_make_assets(), _make_edges())
        for chunk in chunks:
            assert "asset_type" in chunk.metadata
            assert "provider" in chunk.metadata
            assert "region" in chunk.metadata
            assert "relation_types" in chunk.metadata
            assert "severity_max" in chunk.metadata

    def test_internet_exposed_in_content(self):
        """Internet-exposed assets should have warning in content."""
        exporter = RAGExporter()
        chunks = exporter.export_entity_chunks(_make_assets(), _make_edges())
        ec2_chunk = next(c for c in chunks if "ec2-1" in c.chunk_id)
        assert "INTERNET EXPOSED" in ec2_chunk.content

    def test_findings_included(self):
        """Findings should appear in entity chunks."""
        exporter = RAGExporter()
        chunks = exporter.export_entity_chunks(_make_assets(), _make_edges(), _make_findings())
        ec2_chunk = next(c for c in chunks if "ec2-1" in c.chunk_id)
        assert ec2_chunk.metadata["finding_count"] == 1
        assert ec2_chunk.metadata["severity_max"] == "HIGH"

    def test_relations_populated(self):
        """Chunks should have inferred relations."""
        exporter = RAGExporter()
        chunks = exporter.export_entity_chunks(_make_assets(), _make_edges())
        ec2_chunk = next(c for c in chunks if "ec2-1" in c.chunk_id)
        assert len(ec2_chunk.relations) > 0


# ── Community Chunk Tests ──


class TestCommunityChunks:
    def test_produces_communities(self):
        """Connected graph should produce at least 1 community."""
        exporter = RAGExporter()
        graph = _build_graph()
        chunks = exporter.export_community_chunks(graph)
        assert len(chunks) >= 1

    def test_community_chunk_type(self):
        exporter = RAGExporter()
        graph = _build_graph()
        chunks = exporter.export_community_chunks(graph)
        assert all(c.chunk_type == "community" for c in chunks)

    def test_community_metadata(self):
        exporter = RAGExporter()
        graph = _build_graph()
        chunks = exporter.export_community_chunks(graph)
        for chunk in chunks:
            assert "community_id" in chunk.metadata
            assert "member_count" in chunk.metadata
            assert chunk.metadata["member_count"] >= 2

    def test_empty_graph_no_chunks(self):
        exporter = RAGExporter()
        graph = nx.DiGraph()
        chunks = exporter.export_community_chunks(graph)
        assert len(chunks) == 0


# ── Relation-Group Chunk Tests ──


class TestRelationGroupChunks:
    def test_produces_groups(self):
        """Should produce chunks for populated relation groups."""
        exporter = RAGExporter()
        assets_by_id = {a.id: a for a in _make_assets()}
        chunks = exporter.export_relation_chunks(_make_edges(), assets_by_id)
        assert len(chunks) >= 1

    def test_group_chunk_type(self):
        exporter = RAGExporter()
        assets_by_id = {a.id: a for a in _make_assets()}
        chunks = exporter.export_relation_chunks(_make_edges(), assets_by_id)
        assert all(c.chunk_type == "relation_group" for c in chunks)

    def test_network_group_present(self):
        """Network group should be in output for SG rules."""
        exporter = RAGExporter()
        assets_by_id = {a.id: a for a in _make_assets()}
        chunks = exporter.export_relation_chunks(_make_edges(), assets_by_id)
        group_names = {c.metadata.get("relation_group") for c in chunks}
        assert "NETWORK" in group_names

    def test_asset_level_relations_match_the_ontology(self):
        """KMS encryption and vpc_id containment reach RAG as they reach the ontology."""
        from cloudg.graph.ontology import CMP, CMR, CloudOntology

        assets = [
            *_make_assets(),
            CloudAsset(
                id="kms-1",
                name="orders-key",
                arn="arn:aws:kms:us-east-1:111:key/1234",
                asset_type=AssetType.KMS_KEY,
                provider=CloudProvider.AWS,
                metadata={"aliases": ["alias/orders"]},
            ),
            CloudAsset(
                id="orders-db",
                name="orders-db",
                asset_type=AssetType.RDS_INSTANCE,
                provider=CloudProvider.AWS,
                metadata={"storage_encrypted": True, "kms_key_id": "alias/orders"},
            ),
        ]
        assets_by_id = {a.id: a for a in assets}
        chunks = RAGExporter().export_relation_chunks(_make_edges(), assets_by_id)
        by_group = {c.metadata["relation_group"]: c for c in chunks}

        security = by_group["SECURITY"]
        assert {"predicate": "ENCRYPTED_BY_KMS", "object": "orders-key", "evidence": ""} in (
            security.relations
        )
        assert "orders-db → ENCRYPTED_BY_KMS → orders-key" in security.content
        containment = by_group["CONTAINMENT"]
        assert "prod-vpc → CONTAINS → web-server" in containment.content

        onto = CloudOntology().build(assets, _make_edges())
        assert (CMR["orders-db"], CMP["ENCRYPTED_BY_KMS"], CMR["kms-1"]) in onto
        assert (CMR["vpc-1"], CMP["CONTAINS"], CMR["ec2-1"]) in onto


# ── Combined Export Tests ──


class TestExportAll:
    def test_export_creates_files(self, tmp_path):
        """export_all should create JSONL and index files."""
        exporter = RAGExporter()
        graph = _build_graph()
        paths = exporter.export_all(
            _make_assets(),
            _make_edges(),
            graph,
            _make_findings(),
            output_dir=tmp_path,
        )
        assert paths["chunks"].exists()
        assert paths["index"].exists()

    def test_jsonl_valid(self, tmp_path):
        """Each line in JSONL should be valid JSON."""
        exporter = RAGExporter()
        graph = _build_graph()
        paths = exporter.export_all(
            _make_assets(),
            _make_edges(),
            graph,
            _make_findings(),
            output_dir=tmp_path,
        )
        with open(paths["chunks"]) as f:
            for line in f:
                parsed = json.loads(line.strip())
                assert "chunk_id" in parsed
                assert "chunk_type" in parsed
                assert "content" in parsed

    def test_index_counts(self, tmp_path):
        """Index should have correct chunk counts."""
        exporter = RAGExporter()
        graph = _build_graph()
        paths = exporter.export_all(
            _make_assets(),
            _make_edges(),
            graph,
            _make_findings(),
            output_dir=tmp_path,
        )
        with open(paths["index"]) as f:
            index = json.load(f)
        assert index["total_chunks"] > 0
        assert index["entity_chunks"] == len(_make_assets())
        assert "chunk_ids" in index


# ── Finding → asset resolution ──

_RDS_ARN = "arn:aws:rds:us-east-1:111:db:prod-db"


def _assets_with_arns() -> list[CloudAsset]:
    assets = _make_assets()
    for a in assets:
        if a.id == "rds-1":
            a.arn = _RDS_ARN
    return assets


def _scanner_finding(resource_id: str, resource_arn: str | None = None) -> Finding:
    return Finding(
        resource_id=resource_id,
        resource_arn=resource_arn,
        severity=Severity.CRITICAL,
        title=f"finding on {resource_id}",
        description="scanner output",
        source_tool="prowler",
        compliance_frameworks=["CIS"],
    )


def _entity(chunks: list[RAGChunk], asset_id: str) -> RAGChunk:
    return next(c for c in chunks if c.chunk_id == f"entity::{asset_id}")


class TestFindingResolution:
    """Findings attach to the asset by id, ARN or unique name, not raw resource_id."""

    def test_arn_resource_id_counts_on_entity(self):
        exporter = RAGExporter()
        chunks = exporter.export_entity_chunks(
            _assets_with_arns(), _make_edges(), [_scanner_finding(_RDS_ARN, _RDS_ARN)]
        )
        rds = _entity(chunks, "rds-1")
        assert rds.metadata["finding_count"] == 1
        assert rds.metadata["severity_max"] == "CRITICAL"
        assert rds.metadata["compliance_frameworks"] == ["CIS"]

    def test_arn_only_in_resource_arn(self):
        exporter = RAGExporter()
        chunks = exporter.export_entity_chunks(
            _assets_with_arns(), _make_edges(), [_scanner_finding("db-label", _RDS_ARN)]
        )
        assert _entity(chunks, "rds-1").metadata["finding_count"] == 1

    def test_unique_name_counts_on_entity(self):
        exporter = RAGExporter()
        chunks = exporter.export_entity_chunks(
            _assets_with_arns(), _make_edges(), [_scanner_finding("prod-db")]
        )
        assert _entity(chunks, "rds-1").metadata["finding_count"] == 1

    def test_ambiguous_name_not_attached(self):
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
        exporter = RAGExporter()
        chunks = exporter.export_entity_chunks(assets, _make_edges(), [_scanner_finding("prod-db")])
        assert _entity(chunks, "rds-1").metadata["finding_count"] == 0
        assert _entity(chunks, "rds-2").metadata["finding_count"] == 0

    def test_community_counts_arn_finding(self):
        from cloudg.graph.builder import GraphBuilder

        assets = _assets_with_arns()
        graph = GraphBuilder().build(assets, _make_edges())
        exporter = RAGExporter()
        chunks = exporter.export_community_chunks(graph, findings=[_scanner_finding(_RDS_ARN)])
        assert sum(c.metadata["finding_count"] for c in chunks) == 1

    def test_community_counts_arn_finding_with_assets(self):
        from cloudg.graph.builder import GraphBuilder

        assets = _assets_with_arns()
        graph = GraphBuilder().build(assets, _make_edges())
        exporter = RAGExporter()
        chunks = exporter.export_community_chunks(
            graph, {a.id: a for a in assets}, [_scanner_finding("prod-db")]
        )
        assert sum(c.metadata["finding_count"] for c in chunks) == 1


# ── Chunk size budget (rag.max_chunk_tokens) and strategy (rag.chunk_strategy) ──


def _hub(
    n_spokes: int, n_findings: int
) -> tuple[list[CloudAsset], list[NetworkEdge], list[Finding]]:
    """One security group with ``n_spokes`` attached instances and
    ``n_findings`` findings on the group."""
    sg = CloudAsset(
        id="sg-hub",
        name="hub-sg",
        asset_type=AssetType.SECURITY_GROUP,
        provider=CloudProvider.AWS,
        region="us-east-1",
    )
    spokes = [
        CloudAsset(
            id=f"i-{i:03d}",
            name=f"instance-{i:03d}",
            asset_type=AssetType.EC2,
            provider=CloudProvider.AWS,
            region="us-east-1",
        )
        for i in range(n_spokes)
    ]
    edges = [
        NetworkEdge(source_id=s.id, target_id=sg.id, edge_type=EdgeType.SECURITY_GROUP_RULE)
        for s in spokes
    ]
    findings = [
        Finding(
            resource_id=sg.id,
            severity=Severity.CRITICAL if i == n_findings - 1 else Severity.LOW,
            title=f"finding number {i:03d}",
            description="d",
            source_tool="test",
            compliance_frameworks=[f"FW{i}"],
        )
        for i in range(n_findings)
    ]
    return [sg, *spokes], edges, findings


class TestChunkBudget:
    def test_small_entity_chunk_keeps_every_line(self):
        assets, edges, findings = _hub(5, 3)
        chunk = _entity(RAGExporter().export_entity_chunks(assets, edges, findings), "sg-hub")
        assert chunk.content.count("instance-") == 5
        assert chunk.content.count("finding number") == 3
        assert "more" not in chunk.content
        # Most severe first
        assert chunk.content.index("finding number 002") < chunk.content.index("finding number 000")

    def test_default_budget_lifts_the_old_fixed_caps(self):
        # 40 relations and 20 findings used to be cut to 30 and 10
        assets, edges, findings = _hub(40, 20)
        chunk = _entity(RAGExporter().export_entity_chunks(assets, edges, findings), "sg-hub")
        assert chunk.content.count("instance-") == 40
        assert chunk.content.count("finding number") == 20
        assert chunk.metadata["compliance_frameworks"] == sorted(f"FW{i}" for i in range(20))

    def test_long_lists_are_cut_to_the_budget(self):
        assets, edges, findings = _hub(400, 200)
        exporter = RAGExporter(max_chunk_tokens=500)
        chunk = _entity(exporter.export_entity_chunks(assets, edges, findings), "sg-hub")
        assert len(chunk.content) <= 500 * 4
        shown_rel = chunk.content.count("instance-")
        shown_find = chunk.content.count("finding number")
        assert 0 < shown_rel < 400 and 0 < shown_find < 200
        # Both lists get a share, and each says how much was left out
        assert f"... and {400 - shown_rel} more" in chunk.content
        assert f"... and {200 - shown_find} more" in chunk.content
        assert "finding number 199" in chunk.content  # the CRITICAL one comes first
        # The structured relations and the counts still cover everything
        assert len(chunk.relations) == 400
        assert chunk.metadata["finding_count"] == 200

    def test_relation_group_chunk_is_cut_to_the_budget(self):
        assets, edges, _ = _hub(300, 0)
        by_id = {a.id: a for a in assets}
        small = RAGExporter(max_chunk_tokens=200).export_relation_chunks(edges, by_id)
        big = RAGExporter().export_relation_chunks(edges, by_id)
        for chunk in small:
            assert len(chunk.content) <= 200 * 4
        small_net = next(c for c in small if c.metadata["total_relations"] >= 300)
        shown = small_net.content.count("instance-")
        assert f"... and {small_net.metadata['total_relations'] - shown} more" in small_net.content
        assert len(small_net.relations) == shown
        big_net = next(c for c in big if c.chunk_id == small_net.chunk_id)
        assert big_net.content.count("instance-") > 50  # no fixed cap of 50 any more

    def test_community_member_list_is_cut_to_the_budget(self):
        from cloudg.graph.builder import GraphBuilder

        assets, edges, _ = _hub(300, 0)
        graph = GraphBuilder().build(assets, edges)
        chunks = RAGExporter(max_chunk_tokens=200).export_community_chunks(graph)
        big = max(chunks, key=lambda c: c.metadata["member_count"])
        assert len(big.content) <= 200 * 4
        assert "more" in big.content
        assert "Internal edges:" in big.content
        assert big.metadata["member_count"] == 301

    def test_invalid_arguments(self):
        import pytest

        with pytest.raises(ValueError):
            RAGExporter(max_chunk_tokens=0)
        with pytest.raises(ValueError):
            RAGExporter(chunk_strategy="everything")


class TestChunkStrategy:
    def _kinds(self, tmp_path, strategy: str) -> tuple[set[str], dict]:
        exporter = RAGExporter(chunk_strategy=strategy)
        paths = exporter.export_all(
            _make_assets(), _make_edges(), _build_graph(), _make_findings(), output_dir=tmp_path
        )
        lines = paths["chunks"].read_text().splitlines()
        index = json.loads(paths["index"].read_text())
        return {json.loads(line)["chunk_type"] for line in lines}, index

    def test_hybrid_writes_all_three(self, tmp_path):
        kinds, index = self._kinds(tmp_path, "hybrid")
        assert kinds == {"entity", "community", "relation_group"}
        assert index["entity_chunks"] and index["relation_group_chunks"]

    def test_single_strategies(self, tmp_path):
        for strategy in ("entity", "community", "relation_group"):
            kinds, index = self._kinds(tmp_path / strategy, strategy)
            assert kinds == {strategy}
            others = {"entity", "community", "relation_group"} - {strategy}
            assert all(index[f"{k}_chunks"] == 0 for k in others)
