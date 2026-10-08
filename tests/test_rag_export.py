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
