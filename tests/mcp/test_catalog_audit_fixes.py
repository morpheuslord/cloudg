"""Regression tests for the MCP catalog / workspace audit fixes: network
flow semantics, port and internet-source parsing, finding resolution,
lock scope, sandbox roots, error hygiene, cursors, scanner arguments and
SPARQL bounds."""

from __future__ import annotations

import json
import threading
import time
from pathlib import Path

import pytest

from cloudg.config import CloudGConfig
from cloudg.mcp.core import InvalidArgumentsError, Sensitivity
from cloudg.mcp.state import Dataset, Workspace
from cloudg.schema.models import (
    AssetType,
    CloudAsset,
    CloudProvider,
    EdgeType,
    Finding,
    NetworkEdge,
    Severity,
)


def _asset(i: str, t: AssetType, prov: CloudProvider = CloudProvider.AWS, **kw) -> CloudAsset:
    return CloudAsset(
        id=i,
        name=kw.pop("name", i),
        asset_type=t,
        provider=prov,
        region="us-east-1",
        account_id=kw.pop("account_id", "1"),
        **kw,
    )


def _rule(src: str, tgt: str, **kw) -> NetworkEdge:
    return NetworkEdge(source_id=src, target_id=tgt, edge_type=EdgeType.SECURITY_GROUP_RULE, **kw)


def _layer(tmp_path: Path, ds: Dataset):
    from cloudg.mcp.layer import CloudGMCPLayer

    ws = Workspace(CloudGConfig(), allowed_roots=[tmp_path], output_dir=tmp_path / "out")
    ws.add(ds)
    return CloudGMCPLayer(policy="open", workspace=ws), ws


async def _call(layer, tool: str, **args):
    res = await layer.call_tool(tool, args)
    assert not res.is_error, res.content[0].text
    return res.structured


# ---------------------------------------------------------------------------
# 1. attack / flow paths follow the reachability analysis
# ---------------------------------------------------------------------------


async def test_attack_paths_respect_network_flow(tmp_path):
    """igw ATTACHED_TO vpc CONTAINS db is not a traffic path when the db's
    security group only admits 10.0.0.0/8."""
    ds = Dataset(
        name="t",
        assets=[
            _asset("igw", AssetType.INTERNET_GATEWAY),
            _asset("vpc", AssetType.VPC),
            _asset("db", AssetType.RDS_INSTANCE),
            _asset("sg-db", AssetType.SECURITY_GROUP),
        ],
        edges=[
            NetworkEdge(
                source_id="0.0.0.0/0",
                target_id="igw",
                edge_type=EdgeType.INTERNET_EXPOSED,
                cidr="0.0.0.0/0",
            ),
            NetworkEdge(source_id="igw", target_id="vpc", edge_type=EdgeType.ATTACHED_TO),
            NetworkEdge(source_id="vpc", target_id="db", edge_type=EdgeType.CONTAINS),
            NetworkEdge(source_id="db", target_id="sg-db", edge_type=EdgeType.ATTACHED_TO),
            _rule("10.0.0.0/8", "sg-db", cidr="10.0.0.0/8", port_range="5432", protocol="TCP"),
            _rule(
                "sg-db",
                "0.0.0.0/0",
                cidr="0.0.0.0/0",
                port_range="0-65535",
                protocol="ALL",
                direction="egress",
            ),
        ],
    )
    layer, _ = _layer(tmp_path, ds)
    out = await _call(layer, "attack_paths")
    assert not [p for p in out["paths"] if p["nodes"][-1]["id"] == "db"]
    out = await _call(layer, "find_paths", source="internet", target="db")
    assert out["paths"] == []
    assert "db" not in ds.internet_reachable()


def test_flow_graph_marks_identity_pivots(sample_dataset):
    g = sample_dataset.flow_graph
    assert g["web-1"]["app-role"]["identity"] is True
    assert g["sg-admin"]["bastion"]["derived"] == "sg_admits"


# ---------------------------------------------------------------------------
# 3. ports and internet sources come from cloudg.graph.ports
# ---------------------------------------------------------------------------


def _multicloud() -> Dataset:
    az = CloudProvider.AZURE
    return Dataset(
        name="t",
        assets=[
            _asset("az-vm", AssetType.VIRTUAL_MACHINE, az, is_internet_exposed=True),
            _asset("az-nsg", AssetType.NSG, az),
            _asset(
                "gcp-vm", AssetType.VIRTUAL_MACHINE, CloudProvider.GCP, is_internet_exposed=True
            ),
            _asset("sg-1", AssetType.SECURITY_GROUP),
            _asset("icmp-sg", AssetType.SECURITY_GROUP),
        ],
        edges=[
            _rule("Internet", "az-nsg", cidr="Internet", port_range="*", protocol="*"),
            NetworkEdge(source_id="az-vm", target_id="az-nsg", edge_type=EdgeType.ATTACHED_TO),
            _rule("0.0.0.0/0", "gcp-vm", cidr="0.0.0.0/0", port_range=None, protocol="TCP"),
            _rule(
                "sg-1",
                "0.0.0.0/0",
                cidr="0.0.0.0/0",
                port_range="0-65535",
                protocol="ALL",
                direction="egress",
            ),
            _rule("0.0.0.0/0", "icmp-sg", cidr="0.0.0.0/0", port_range="8--1", protocol="ICMP"),
        ],
    )


async def test_exposure_reads_azure_and_gcp_rules(tmp_path):
    layer, _ = _layer(tmp_path, _multicloud())
    out = await _call(layer, "internet_exposure")
    items = {i["id"]: i for i in out["items"]}
    assert {22, 3389} <= set(items["az-vm"]["sensitive_ports_open"])
    assert items["az-vm"]["internet_rules"]
    assert 22 in items["gcp-vm"]["sensitive_ports_open"]


async def test_get_edges_ports_and_egress(tmp_path):
    layer, _ = _layer(tmp_path, _multicloud())
    out = await _call(layer, "get_edges", internet_only=True, port=22)
    assert {(e["source"], e["target"]) for e in out["items"]} == {
        ("Internet", "az-nsg"),
        ("0.0.0.0/0", "gcp-vm"),
    }
    out = await _call(layer, "get_edges", port=8)  # ICMP type 8 is not port 8
    assert "icmp-sg" not in {e["target"] for e in out["items"]}
    out = await _call(layer, "get_edges", source="internet")
    assert "0.0.0.0/0" not in {e["target"] for e in out["items"]}  # egress excluded


async def test_find_paths_from_internet_on_azure_only_dataset(tmp_path):
    ds = _multicloud()
    ds.edges = [e for e in ds.edges if e.source_id == "Internet" or e.target_id == "az-nsg"]
    layer, _ = _layer(tmp_path, ds)
    out = await _call(layer, "find_paths", source="internet", target="az-vm")
    assert out["paths"] and out["paths"][0]["summary"] == "Internet -> az-nsg -> az-vm"


# ---------------------------------------------------------------------------
# 2. finding -> asset resolution uses AssetIndex
# ---------------------------------------------------------------------------


def test_finding_resolution_matches_asset_index():
    from cloudg.inventory.dependencies import AssetIndex

    assets = [
        _asset("a1", AssetType.EC2, name="web", arn="arn:aws:ec2:us-east-1:111:instance/i-0aaa"),
        _asset("a2", AssetType.EC2, name="web", arn="arn:aws:ec2:us-east-1:222:instance/i-0bbb"),
    ]
    fs = [
        Finding(
            id="f-name",
            resource_id="web",
            severity=Severity.HIGH,
            title="t",
            source_tool="x",
            description="d",
        ),
        Finding(
            id="f-tail",
            resource_id="i-0bbb",
            severity=Severity.HIGH,
            title="t",
            source_tool="x",
            description="d",
        ),
    ]
    ds = Dataset(name="t", assets=assets, findings=fs)
    idx = AssetIndex(assets)
    for f in fs:
        assert ds.finding_asset_id(f) == idx.resolve_finding(f, arn_parts=True, casefold=True)
    assert ds.finding_asset_id(fs[0]) is None  # ambiguous name: not guessed
    assert ds.finding_asset_id(fs[1]) == "a2"
    assert ds.open_findings("a1") == []


# ---------------------------------------------------------------------------
# 5. a slow build never blocks other datasets or the workspace
# ---------------------------------------------------------------------------


def test_slow_build_does_not_block_workspace(tmp_path):
    ws = Workspace(CloudGConfig(), allowed_roots=[tmp_path])
    a = ws.add(Dataset(name="a"))
    ws.add(Dataset(name="b"))
    started = threading.Event()

    def slow():
        started.set()
        time.sleep(2)
        return "built"

    t = threading.Thread(target=lambda: a.cached("ontology", slow), daemon=True)
    t.start()
    started.wait(1)
    t0 = time.monotonic()
    ws.status()
    ws.get("b").summary()
    a.cached("other", lambda: 1)  # another key of the busy dataset
    assert a.cache_state()["ontology"] is False
    assert time.monotonic() - t0 < 1.0
    t.join(5)
    assert a.cached("ontology", lambda: "rebuilt") == "built"


def test_build_racing_a_mutation_is_not_cached():
    ds = Dataset(name="a")
    gate = threading.Event()

    def build():
        gate.wait(2)
        return "stale"

    t = threading.Thread(target=lambda: ds.cached("k", build), daemon=True)
    t.start()
    time.sleep(0.1)
    ds.invalidate()
    gate.set()
    t.join(3)
    assert ds.cached("k", lambda: "fresh") == "fresh"


# ---------------------------------------------------------------------------
# 4. sandbox roots, error hygiene, bounded scans
# ---------------------------------------------------------------------------


def test_implicit_root_refuses_filesystem_root_and_home(monkeypatch, tmp_path, caplog):
    monkeypatch.delenv("CLOUDG_MCP_ALLOWED_ROOTS", raising=False)
    cfg = CloudGConfig()
    cfg.report.output_dir = str(tmp_path / "reports")
    monkeypatch.chdir("/")
    ws = Workspace(cfg)
    assert Path("/") not in ws.allowed_roots
    assert ws.allowed_roots == [(tmp_path / "reports").resolve()]
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.chdir(tmp_path)
    ws = Workspace(cfg)
    assert tmp_path.resolve() not in ws.allowed_roots
    # Explicit roots are honoured as given
    monkeypatch.setenv("CLOUDG_MCP_ALLOWED_ROOTS", "/")
    assert Workspace(cfg).allowed_roots[0] == Path("/")


def test_schema_errors_do_not_echo_file_contents(tmp_path):
    from cloudg.mcp.state import load_dataset_file

    p = tmp_path / "bad.json"
    p.write_text(
        json.dumps(
            {
                "assets": [
                    {
                        "id": "x",
                        "name": "n",
                        "asset_type": "EC2",
                        "provider": "aws",
                        "tags": "AKIASECRETVALUE123",
                    }
                ]
            }
        )
    )
    with pytest.raises(InvalidArgumentsError) as exc:
        load_dataset_file(p, "x", kind="generic")
    assert "AKIASECRETVALUE123" not in exc.value.message
    assert "validation error" in exc.value.message


def test_directory_kind_detection_is_bounded(tmp_path):
    from cloudg.mcp.state.loading import iter_files

    deep = tmp_path
    for i in range(10):
        deep = deep / f"d{i}"
    deep.mkdir(parents=True)
    (deep / "results_json.json").write_text("{}")
    assert list(iter_files(tmp_path, "results_json.json", max_depth=6)) == []
    assert list(iter_files(tmp_path, "results_json.json", max_depth=12))
    many = tmp_path / "many"
    many.mkdir()
    for i in range(50):
        (many / f"f{i}.txt").write_text("")
    (many / "zz_results_json.json").write_text("{}")
    assert list(iter_files(many, "*.json", max_entries=10)) == [many / "zz_results_json.json"]


async def test_reference_errors_keep_values_out_of_the_text(call):
    msg, data = await call.error_data("get_finding", finding_id="f-ssh")
    assert "f-ssh" not in msg and data["value"] == "f-ssh"
    assert {"finding_id": "f-ssh-open", "dataset": "sample"} in data["suggestions"]
    msg, data = await call.error_data("get_asset", ref="orders")
    assert "orders" not in msg and "111111111111" not in msg
    assert all({"name", "arn", "type", "dataset"} <= set(s) for s in data["suggestions"])
    msg, data = await call.error_data("list_findings", min_severity="web-1")
    assert "web-1" not in msg and data["value"] == "web-1"


async def test_resource_errors_keep_values_out_of_the_text(layer):
    from cloudg.mcp.core import NotFoundError

    for uri in (
        "cloudg://findings/severity/web-1",
        "cloudg://docs/web-1",
        "cloudg://compliance/web-1",
        "cloudg://schema/asset-types/web-1",
        "cloudg://datasets/web-1/summary",
    ):
        with pytest.raises(NotFoundError) as exc:
            await layer.read_resource(uri)
        assert "web-1" not in exc.value.message, uri


# ---------------------------------------------------------------------------
# 7. cursors die with the dataset instance
# ---------------------------------------------------------------------------


async def test_cursor_rejected_after_dataset_replacement(call, workspace, sample_dataset):
    first = await call("find_assets", limit=5)
    workspace.add(sample_dataset.copy("sample"), replace=True)
    msg = await call.error("find_assets", limit=5, cursor=first["next_cursor"])
    assert "Stale cursor" in msg


# ---------------------------------------------------------------------------
# 8. scanner image references cannot become trivy options
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("image", ["--config=/etc/passwd", " -o/tmp/x", ""])
async def test_run_scanners_rejects_option_like_images(call, image):
    msg, data = await call.error_data(
        "run_scanners", scanners=["trivy"], images=[image], preflight=False
    )
    assert "must not start with '-'" in msg and data["value"] == [image]


# ---------------------------------------------------------------------------
# 9. SPARQL vetting is linear and results are bounded
# ---------------------------------------------------------------------------


def test_update_detection_is_linear():
    from cloudg.mcp.catalog._sparql import first_keyword, prepare_readonly

    t0 = time.monotonic()
    assert first_keyword("PREFIX a: <x> " * 20_000 + "INSERT DATA {}") == "INSERT"
    assert first_keyword("PREFIX " * 50_000) == ""
    assert first_keyword("BASE <" + "x" * 100_000) == ""
    assert time.monotonic() - t0 < 2.0
    with pytest.raises(InvalidArgumentsError, match="read-only"):
        prepare_readonly("PREFIX ex: <http://e/>\nBASE <http://b/>\n  delete WHERE { ?s ?p ?o }")


async def test_cartesian_sparql_stops_at_the_row_cap(call):
    t0 = time.monotonic()
    out = await call(
        "sparql_query", query="SELECT * WHERE { ?a ?b ?c . ?d ?e ?f . ?g ?h ?i }", limit=5
    )
    assert out["returned"] == 5 and out["truncated"]
    assert time.monotonic() - t0 < 30
    assert set(out["variable_kinds"]) >= {"a", "c"}


def test_sparql_rows_stop_at_the_deadline():
    from cloudg.mcp.catalog._sparql import collect

    rows, truncated, timed_out = collect(
        iter(range(100)), 50, lambda r: {"r": r}, time.monotonic() - 1
    )
    assert rows == [] and truncated and timed_out


# ---------------------------------------------------------------------------
# Text exports are RESTRICTED; structured exports stay structured
# ---------------------------------------------------------------------------


def test_textual_exports_are_restricted(layer):
    reg = layer.registry
    assert reg.tools["sparql_query"].sensitivity == Sensitivity.RESTRICTED
    assert reg.tools["subgraph_export"].sensitivity == Sensitivity.RESTRICTED
    assert reg.templates["cloudg://graph/{format}"].sensitivity == Sensitivity.RESTRICTED
    assert reg.templates["cloudg://ontology/{format}"].sensitivity == Sensitivity.RESTRICTED
    assert reg.resources["cloudg://ontology/turtle"].sensitivity == Sensitivity.RESTRICTED
    assert reg.resources["cloudg://graph/d3"].sensitivity == Sensitivity.CONFIDENTIAL


def test_graph_resource_handlers_return_objects(layer):
    ctx = layer.context()
    assert isinstance(layer.registry.resources["cloudg://graph/d3"].handler(ctx), dict)
    tpl = layer.registry.templates["cloudg://graph/{format}"].handler
    assert isinstance(tpl(ctx, format="cytoscape"), dict)


# ---------------------------------------------------------------------------
# Lead additions: rule-driven relations, deterministic blast radius
# ---------------------------------------------------------------------------


async def test_explain_edge_type_attachment_and_nacl(call):
    out = await call("explain_edge_type", edge_type="ATTACHED_TO")
    assert "PROTECTED_BY_SG" in out["ontology_relations"]
    out = await call("explain_edge_type", edge_type="NACL_RULE")
    assert out["ontology_relations"].startswith("none")
    out = await call("explain_edge_type", edge_type="CONTAINS")
    assert "ORG_CONTAINS_ACCOUNT" in out["ontology_relations"]


async def test_blast_radius_sensitive_reachable_is_sorted(call):
    out = await call("blast_radius", ref="web-1")
    ids = [n["id"] for n in out["network"]["sensitive_reachable"]]
    assert ids == sorted(ids)
