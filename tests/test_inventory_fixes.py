"""Regression tests: finding overlay matching, map_inventory(findings=...),
GraphML export of ARN-less assets, linker re-runs and saved coverage."""

from __future__ import annotations

import asyncio
import json

import networkx as nx

from cloudg.config import CloudGConfig
from cloudg.coverage import CollectionCoverage, ServiceStatus
from cloudg.graph.builder import GraphBuilder, graphml_safe
from cloudg.inventory.linker import RelationshipLinker
from cloudg.inventory.mapper import InventoryMapper, InventoryResult
from cloudg.schema.models import (
    AssetType,
    CloudAsset,
    CloudProvider,
    EdgeType,
    Finding,
    NetworkEdge,
    Severity,
)

TABLE_ARN = "arn:aws:dynamodb:us-east-1:111111111111:table/orders-table"
QUEUE_ARN = "arn:aws:sqs:us-east-1:111111111111:orders"


def _asset(name, asset_type, arn=None, metadata=None, **kw):
    return CloudAsset(
        name=name,
        asset_type=asset_type,
        provider=CloudProvider.AWS,
        arn=arn,
        metadata=metadata or {},
        **kw,
    )


def _finding(resource_id, resource_arn=None, frameworks=("CIS",)):
    return Finding(
        resource_id=resource_id,
        resource_arn=resource_arn,
        severity=Severity.HIGH,
        title="t",
        description="d",
        source_tool="test",
        compliance_frameworks=list(frameworks),
    )


def _orders_inventory() -> InventoryResult:
    table = _asset("orders", AssetType.DYNAMODB_TABLE, arn=TABLE_ARN)
    queue = _asset("orders", AssetType.OTHER, arn=QUEUE_ARN)
    return InventoryResult(assets=[table, queue], providers=["aws"])


# ── 18: findings resolve to one asset, by ARN before shared names ──


class TestFindingOverlayMatching:
    def test_resource_arn_beats_shared_name(self):
        result = _orders_inventory()
        table, queue = result.assets
        mapper = InventoryMapper(CloudGConfig())
        amap = mapper.build_asset_map(result, [_finding("orders", TABLE_ARN)])
        by_id = {e["id"]: e for e in amap["assets"]}
        assert by_id[table.id]["finding_count"] == 1
        assert by_id[queue.id]["finding_count"] == 0
        assert amap["assets_with_findings"] == 1

    def test_ambiguous_name_matches_nothing(self):
        result = _orders_inventory()
        mapper = InventoryMapper(CloudGConfig())
        amap = mapper.build_asset_map(result, [_finding("orders")])
        assert amap["assets_with_findings"] == 0

    def test_arn_in_resource_id_and_unique_tail(self):
        result = _orders_inventory()
        table, queue = result.assets
        mapper = InventoryMapper(CloudGConfig())
        amap = mapper.build_asset_map(result, [_finding(QUEUE_ARN), _finding("orders-table")])
        by_id = {e["id"]: e for e in amap["assets"]}
        # An ARN in resource_id, and the unique ARN tail after the last "/"
        assert by_id[queue.id]["finding_count"] == 1
        assert by_id[table.id]["finding_count"] == 1

    def test_compliance_map_uses_the_same_matching(self):
        result = _orders_inventory()
        mapper = InventoryMapper(CloudGConfig())
        cmap = mapper.build_compliance_map(result, [_finding("orders", TABLE_ARN)])
        assert cmap["frameworks"]["CIS"]["affected_assets"] == [TABLE_ARN]


# ── 26: map_inventory(findings=...) without output_dir ──


def test_map_inventory_overlays_findings_without_output_dir(monkeypatch, tmp_path):
    from cloudg.api import CloudGEngine
    from cloudg.inventory import InventoryMapper as Mapper

    inventory = _orders_inventory()

    async def fake_map(self):
        return inventory

    monkeypatch.setattr(Mapper, "map_inventory", fake_map)
    engine = CloudGEngine(CloudGConfig())
    findings = [_finding("orders", TABLE_ARN)]

    result = asyncio.run(engine.map_inventory(findings=findings))
    assert result.asset_map["assets_with_findings"] == 1
    assert result.compliance_map["frameworks"]["CIS"]["affected_asset_count"] == 1
    assert list(tmp_path.iterdir()) == []

    inventory.asset_map = inventory.compliance_map = None
    assert asyncio.run(engine.map_inventory()).asset_map is None  # no findings, no overlay

    out = tmp_path / "out"
    asyncio.run(engine.map_inventory(output_dir=out, findings=findings))
    assert (out / "asset-map.json").exists() and (out / "compliance-map.json").exists()


# ── 22: GraphML export of assets with no ARN ──


class TestGraphMLNoneAttributes:
    def test_save_graphml_with_arnless_asset(self, tmp_path):
        a = _asset("no-arn", AssetType.OTHER)
        b = _asset("with-arn", AssetType.S3_BUCKET, arn="arn:aws:s3:::b")
        builder = GraphBuilder()
        builder.build(
            [a, b], [NetworkEdge(source_id=a.id, target_id=b.id, edge_type=EdgeType.REFERENCES)]
        )
        path = builder.save_graphml(tmp_path / "g.graphml")
        loaded = nx.read_graphml(path)
        assert loaded.nodes[a.id].get("arn", "") == ""
        assert loaded.nodes[b.id]["arn"] == "arn:aws:s3:::b"

    def test_inventory_export_with_arnless_asset(self, tmp_path):
        result = InventoryResult(assets=[_asset("no-arn", AssetType.OTHER)], providers=["aws"])
        paths = result.export(tmp_path)
        assert paths["graphml"].exists()

    def test_graphml_safe_drops_none_and_encodes_containers(self):
        g = nx.DiGraph()
        g.add_node("n", arn=None, ports=[22, 443], props={"a": 1}, flag=True, count=3)
        g.add_edge("n", "m", cidr=None, kind="x")
        safe = graphml_safe(g)
        assert safe.nodes["n"] == {
            "ports": "[22, 443]",
            "props": '{"a": 1}',
            "flag": True,
            "count": 3,
        }
        assert safe.edges["n", "m"] == {"kind": "x"}
        assert g.nodes["n"]["arn"] is None  # the original is untouched
        "\n".join(nx.generate_graphml(safe))  # does not raise


# ── 23: RelationshipLinker.link() can run twice ──


def test_linker_link_twice_returns_same_edges():
    sg = _asset(
        "web-sg",
        AssetType.SECURITY_GROUP,
        arn="arn:aws:ec2:us-east-1:1:security-group/sg-0123456789abcdef0",
        metadata={"group_id": "sg-0123456789abcdef0"},
    )
    ec2 = _asset(
        "web-1",
        AssetType.EC2,
        arn="arn:aws:ec2:us-east-1:1:instance/i-0123456789abcdef0",
        metadata={
            "security_groups": ["sg-0123456789abcdef0"],
            "relations": [{"target": "arn:aws:iam::1:role/missing", "edge": "ASSUMES_ROLE"}],
        },
    )
    linker = RelationshipLinker([sg, ec2])
    first = linker.link()
    unresolved = list(linker.unresolved)
    second = linker.link()

    def keys(edges):
        return sorted((e.source_id, e.target_id, e.edge_type.value) for e in edges)

    assert first and keys(second) == keys(first)
    assert unresolved and linker.unresolved == unresolved


def test_linker_link_twice_still_skips_seeded_edges():
    sg = _asset(
        "web-sg",
        AssetType.SECURITY_GROUP,
        arn="arn:aws:ec2:us-east-1:1:security-group/sg-0123456789abcdef0",
        metadata={"group_id": "sg-0123456789abcdef0"},
    )
    ec2 = _asset(
        "web-1",
        AssetType.EC2,
        arn="arn:aws:ec2:us-east-1:1:instance/i-0123456789abcdef0",
        metadata={"security_groups": ["sg-0123456789abcdef0"]},
    )
    seeded = NetworkEdge(source_id=ec2.id, target_id=sg.id, edge_type=EdgeType.ATTACHED_TO)
    linker = RelationshipLinker([sg, ec2])
    linker.seed_existing([seeded])
    for _ in range(2):
        edges = linker.link()
        assert not any(
            (e.source_id, e.target_id, e.edge_type) == (ec2.id, sg.id, EdgeType.ATTACHED_TO)
            for e in edges
        )


# ── 31: coverage records are saved and loaded ──


def _coverage() -> CollectionCoverage:
    cov = CollectionCoverage(provider="aws", region="us-east-1", account_id="111111111111")
    cov.record("ec2", ServiceStatus.SUCCESS, asset_count=3, duration_ms=12)
    cov.record("rds", ServiceStatus.FAILED, error="AccessDenied")
    return cov


def test_inventory_export_and_load_keep_coverage(tmp_path):
    result = InventoryResult(
        assets=[_asset("web", AssetType.EC2, arn="arn:aws:ec2:us-east-1:1:instance/i-1")],
        coverage=[_coverage()],
        providers=["aws"],
    )
    paths = result.export(tmp_path)
    data = json.loads(paths["map"].read_text())
    assert data["coverage"][0]["services"][1]["error"] == "AccessDenied"

    loaded = InventoryResult.load(tmp_path)
    assert len(loaded.coverage) == 1
    cov = loaded.coverage[0]
    assert cov.account_id == "111111111111"
    assert cov.failed_services == 1 and cov.coverage_pct == 50.0
    assert cov.to_summary() == result.coverage[0].to_summary()


def test_inventory_load_without_coverage_key(tmp_path):
    result = InventoryResult(assets=[_asset("web", AssetType.EC2)], providers=["aws"])
    paths = result.export(tmp_path)
    data = json.loads(paths["map"].read_text())
    del data["coverage"]
    paths["map"].write_text(json.dumps(data))
    assert InventoryResult.load(tmp_path).coverage == []
