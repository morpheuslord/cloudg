"""Workspace / Dataset: loading, lookup, caches, mutation, diff, path safety."""

from __future__ import annotations

import json
import threading

import pytest

from cloudg.config import CloudGConfig
from cloudg.mcp.core import AccessDeniedError, InvalidArgumentsError, NotFoundError
from cloudg.mcp.state import (
    Dataset,
    NoDatasetError,
    ReferenceNotFoundError,
    Workspace,
    detect_kind,
    diff_datasets,
    load_dataset_file,
)
from cloudg.schema.models import AssetType, CloudAsset, CloudProvider, Finding, Severity
from tests.mcp.fixtures import sample_estate

# ---------------------------------------------------------------------------
# Dataset lookup
# ---------------------------------------------------------------------------


def test_find_asset_by_id_arn_name_tail_and_case(sample_dataset):
    ds = sample_dataset
    assert ds.find_asset("web-1").id == "web-1"
    assert ds.find_asset("arn:aws:rds:us-east-1:111111111111:db:orders-db").id == "orders-db"
    assert ds.find_asset("prod-main-key").id == "kms-main"  # unique name
    assert ds.find_asset("i-0bast").id == "bastion"  # ARN tail
    assert ds.find_asset("WEB-ALB").id == "alb-web"  # case-insensitive name
    assert ds.find_asset("nope") is None
    assert ds.find_asset("") is None


def test_resolve_asset_suggests_close_matches(sample_dataset):
    with pytest.raises(ReferenceNotFoundError) as exc:
        sample_dataset.resolve_asset("web-3")
    assert "close match" in exc.value.message and "web-3" not in exc.value.message
    assert "web-1" in {s["name"] for s in exc.value.data["suggestions"]}
    assert exc.value.data["value"] == "web-3"
    assert isinstance(exc.value, NotFoundError)


def test_resolve_asset_ambiguous_name(sample_dataset):
    ds = sample_dataset
    ds.assets.append(
        CloudAsset(
            id="dup",
            name="web-1",
            asset_type=AssetType.EC2,
            provider=CloudProvider.AWS,
            account_id="222222222222",
        )
    )
    ds.invalidate()
    assert ds.find_asset("web-1").id == "web-1"  # exact id still wins
    ds.assets[-1].name = "prod-vpc"  # clash with the VPC's name
    ds.invalidate()
    with pytest.raises(ReferenceNotFoundError, match="ambiguous"):
        ds.resolve_asset("prod-vpc")


def test_findings_matched_to_assets(sample_dataset):
    ds = sample_dataset
    by_asset = ds.findings_by_asset
    assert {f.id for f in by_asset["orders-db"]} == {"f-db-backup"}  # matched by ARN
    assert {f.id for f in by_asset["logs-bucket"]} == {"f-logs-public"}
    assert ds.finding_asset_id(ds.findings_by_id["f-ghost"]) is None
    assert [f.id for f in ds.open_findings("data-bucket")] == []  # suppressed
    assert ds.get_finding("prowler-aws-ec2_sg_open_22-1").id == "f-ssh-open"  # source id
    with pytest.raises(ReferenceNotFoundError, match="list_findings"):
        ds.get_finding("f-nope")


def test_cached_views_and_invalidation(sample_dataset):
    ds = sample_dataset
    g1 = ds.graph
    assert ds.graph is g1
    assert ds.cache_state()["graph"]
    assert ds.dependency_graph() is ds.dependency_graph()
    v = ds.version
    ds.add_findings(
        [
            Finding(
                id="f-new",
                resource_id="web-2",
                severity=Severity.LOW,
                title="t",
                description="d",
                source_tool="x",
            )
        ]
    )
    assert ds.version == v + 1
    assert not ds.cache_state()["graph"]
    assert ds.graph is not g1
    assert [f.id for f in ds.open_findings("web-2")] == ["f-new"]


def test_flow_graph_adds_sg_admits_edges(sample_dataset):
    g = sample_dataset.flow_graph
    assert g.has_edge("sg-admin", "bastion")
    assert g["sg-admin"]["bastion"]["derived"] == "sg_admits"
    assert not sample_dataset.graph.has_edge("sg-admin", "bastion")


def test_internet_reachable_and_centrality(sample_dataset):
    reach = sample_dataset.internet_reachable()
    assert {"alb-web", "sg-admin", "api-gw", "az-nsg"} <= reach
    c = sample_dataset.centrality()
    assert "web-1" in c and set(c["web-1"]) == {"degree", "betweenness", "in_degree", "out_degree"}


def test_ontology_and_rag_cached(sample_dataset):
    assert not sample_dataset.has_ontology()
    onto = sample_dataset.ontology()
    assert sample_dataset.has_ontology() and onto.triple_count > 0
    chunks = sample_dataset.rag_chunks("entity")
    assert len(chunks) == len(sample_dataset.assets)
    assert sample_dataset.rag_chunks("entity") is chunks
    assert sample_dataset.rag_chunks("relation_group")


def test_summary(sample_dataset):
    s = sample_dataset.summary()
    assert s["total_assets"] == len(sample_dataset.assets)
    assert s["suppressed_findings"] == 1
    assert s["open_findings"] == len(sample_dataset.findings) - 1
    assert list(s["severity_breakdown"])[0] == "CRITICAL"
    assert s["has_organization"] and s["organization"]["id"] == "o-sample"
    assert "CIS-AWS" in s["compliance_frameworks"]


def test_set_suppressed(sample_dataset):
    res = sample_dataset.set_suppressed(["f-web-cve", "f-versioning", "zzz"], True, "accepted")
    assert res == {"changed": ["f-web-cve"], "unchanged": ["f-versioning"], "not_found": ["zzz"]}
    assert sample_dataset.suppression_reasons["f-web-cve"] == "accepted"
    res = sample_dataset.set_suppressed(["f-web-cve"], False)
    assert res["changed"] == ["f-web-cve"] and "f-web-cve" not in sample_dataset.suppression_reasons


def test_copy_is_deep(sample_dataset):
    snap = sample_dataset.copy("snap")
    snap.assets[0].name = "changed"
    assert sample_dataset.assets[0].name != "changed"
    assert snap.kind == "snapshot" and snap.metadata["snapshot_of"] == "sample"


def test_constructors_from_engine_results(sample_dataset):
    from cloudg.api import CollectionResult, PipelineResult
    from cloudg.schema.models import ScanResult

    inv = sample_estate.build_inventory()
    ds = Dataset.from_inventory(inv, "inv")
    assert ds.organization["organization_id"] == "o-sample" and ds.coverage
    col = CollectionResult(
        assets=inv.assets,
        edges=inv.edges,
        providers_scanned=["aws"],
        regions_scanned={"aws": ["us-east-1"]},
        duration_ms=5,
    )
    assert len(Dataset.from_collection(col, "c").assets) == len(inv.assets)
    sr = ScanResult(
        assets=inv.assets, findings=sample_estate.findings(), compliance=sample_estate.compliance()
    )
    pr = PipelineResult(
        assets=inv.assets, edges=inv.edges, findings=sr.findings, scan_result=sr, errors=["x"]
    )
    p = Dataset.from_pipeline(pr, "p")
    assert len(p.compliance) == len(sr.compliance) and p.metadata["errors"] == ["x"]
    assert len(Dataset.from_scan_result(sr, "s").findings) == len(sr.findings)


# ---------------------------------------------------------------------------
# Loading
# ---------------------------------------------------------------------------


def test_detect_kind(sample_paths, tmp_path):
    assert detect_kind(sample_paths["inventory_dir"]) == "inventory"
    assert detect_kind(sample_paths["inventory_map"]) == "inventory"
    assert detect_kind(sample_paths["report"]) == "report"
    assert detect_kind(sample_paths["report_dir"]) == "report"
    generic = tmp_path / "g.json"
    generic.write_text(json.dumps({"assets": [], "findings": []}))
    assert detect_kind(generic) == "generic"
    trivy = tmp_path / "t.json"
    trivy.write_text(json.dumps({"SchemaVersion": 2, "ArtifactName": "x", "Results": []}))
    assert detect_kind(trivy) == "trivy"
    ck = tmp_path / "c.json"
    ck.write_text(json.dumps({"check_type": "terraform", "results": {}}))
    assert detect_kind(ck) == "checkov"
    jsonl = tmp_path / "p.jsonl"
    jsonl.write_text('{"a": 1}\n{"a": 2}\n')
    assert detect_kind(jsonl) == "prowler"
    (tmp_path / "s.js").write_text("scoutsuite_results = {}")
    assert detect_kind(tmp_path / "s.js") == "scoutsuite"
    bad = tmp_path / "bad.json"
    bad.write_text(json.dumps({"hello": 1}))
    with pytest.raises(InvalidArgumentsError, match="kind="):
        detect_kind(bad)
    (tmp_path / "empty").mkdir()
    with pytest.raises(InvalidArgumentsError):
        detect_kind(tmp_path / "empty")
    (tmp_path / "txt").write_text("not json")
    with pytest.raises(InvalidArgumentsError, match="not JSON"):
        detect_kind(tmp_path / "txt")


def test_load_inventory_merges_findings(sample_paths):
    ds = load_dataset_file(sample_paths["inventory_dir"], "x")
    assert ds.kind == "inventory"
    assert len(ds.assets) == len(sample_estate.assets())
    assert len(ds.edges) == len(sample_estate.edges())
    assert len(ds.findings) == len(sample_estate.findings())
    assert ds.organization["organization_id"] == "o-sample"
    assert ds.unresolved_references and ds.metadata["findings_source"].endswith("findings.json")
    assert ds.findings_by_id["f-versioning"].is_suppressed


def test_load_report_rebuilds_edges_from_graph(sample_paths):
    ds = load_dataset_file(sample_paths["report"], "r")
    assert ds.kind == "report"
    assert ds.edges, "edges should be rebuilt from the D3 graph block"
    assert len(ds.compliance) == len(sample_estate.compliance())
    assert ds.metadata.get("scan_id")


def test_load_generic_and_errors(tmp_path):
    p = tmp_path / "g.json"
    p.write_text(
        json.dumps(
            [
                {
                    "resource_id": "x",
                    "severity": "HIGH",
                    "title": "t",
                    "description": "d",
                    "source_tool": "manual",
                }
            ]
        )
    )
    ds = load_dataset_file(p, "g")
    assert len(ds.findings) == 1 and ds.kind == "generic"
    p.write_text(json.dumps({"assets": [{"name": "x"}]}))
    with pytest.raises(InvalidArgumentsError, match="cloudg schema"):
        load_dataset_file(p, "g", kind="generic")
    with pytest.raises(InvalidArgumentsError, match="Unknown kind"):
        load_dataset_file(p, "g", kind="excel")
    with pytest.raises(InvalidArgumentsError, match="does not exist"):
        load_dataset_file(tmp_path / "missing.json", "g")


def test_load_scanner_report_normalises(tmp_path):
    report = tmp_path / "trivy.json"
    report.write_text(
        json.dumps(
            {
                "SchemaVersion": 2,
                "ArtifactName": "nginx:1.0",
                "ArtifactType": "container_image",
                "Results": [
                    {
                        "Target": "nginx:1.0",
                        "Vulnerabilities": [
                            {
                                "VulnerabilityID": "CVE-2024-0001",
                                "PkgName": "openssl",
                                "InstalledVersion": "1",
                                "Severity": "CRITICAL",
                                "Title": "bad openssl",
                                "Description": "desc",
                            }
                        ],
                    }
                ],
            }
        )
    )
    ds = load_dataset_file(report, "t")
    assert ds.kind == "trivy" and ds.findings
    assert ds.findings[0].severity == Severity.CRITICAL


# ---------------------------------------------------------------------------
# Workspace
# ---------------------------------------------------------------------------


def test_workspace_load_select_remove_and_events(tmp_path, sample_paths):
    ws = Workspace(CloudGConfig(), allowed_roots=[tmp_path], output_dir=tmp_path / "out")
    events: list[tuple[str, str | None]] = []
    ws.on_change(lambda kind, uri: events.append((kind, uri)))
    with pytest.raises(NoDatasetError, match="load_dataset"):
        ws.get()
    a = ws.load(sample_paths["inventory_dir"])
    assert a.name == "inventory" and ws.active_name == "inventory"
    assert ("resources", None) in events
    assert ("resource", "cloudg://datasets/inventory/summary") in events
    b = ws.load(sample_paths["report"], activate=False)
    assert b.name == "findings" and ws.active_name == "inventory"
    c = ws.load(sample_paths["report"], activate=False)
    assert c.name == "findings-2"
    ws.select("findings")
    assert ws.get().name == "findings"
    with pytest.raises(NoDatasetError, match="dataset"):
        ws.get("nope")
    ws.remove("findings")
    assert ws.active_name in ("inventory", "findings-2")
    events.clear()
    ws.mutated(ws.get())
    assert events and all(k == "resource" for k, _ in events)
    st = ws.status()
    assert st["output_dir"] == str((tmp_path / "out").resolve())
    assert {d["name"] for d in st["datasets"]} == {"inventory", "findings-2"}


def test_workspace_listener_errors_are_swallowed(workspace, sample_dataset):
    workspace.on_change(lambda kind, uri: 1 / 0)
    workspace.add(sample_dataset.copy("other"))  # must not raise


def test_workspace_rejects_bad_names_and_duplicates(workspace, sample_dataset):
    with pytest.raises(InvalidArgumentsError, match="Invalid dataset name"):
        workspace.add(sample_dataset.copy("bad name!"))
    with pytest.raises(InvalidArgumentsError, match="already exists"):
        workspace.add(sample_dataset.copy("sample"), replace=False)


def test_workspace_eviction(tmp_path, sample_dataset):
    ws = Workspace(allowed_roots=[tmp_path], output_dir=tmp_path, max_datasets=2)
    for i in range(4):
        ws.add(sample_dataset.copy(f"d{i}"))
    assert ws.names() == ["d2", "d3"] and ws.active_name == "d3"


def test_snapshot_and_diff(workspace):
    workspace.snapshot(None, "before")
    ds = workspace.get("sample")
    ds.assets.append(
        CloudAsset(
            id="new-vm",
            name="new-vm",
            asset_type=AssetType.EC2,
            provider=CloudProvider.AWS,
            arn="arn:aws:ec2:x:1:instance/new",
            is_internet_exposed=True,
        )
    )
    ds.assets = [a for a in ds.assets if a.id != "web-2"]
    for a in ds.assets:
        if a.id == "orders-db":
            a.is_internet_exposed = True
            a.tags["new"] = "tag"
    ds.edges = [e for e in ds.edges if e.id != "e-waf-alb"]
    ds.findings = [f for f in ds.findings if f.id != "f-ssh-open"]
    ds.findings[0].severity = Severity.LOW
    ds.invalidate()
    d = workspace.diff("before", "sample")
    assert [a["id"] for a in d["assets"]["added"]["items"]] == ["new-vm"]
    assert [a["id"] for a in d["assets"]["removed"]["items"]] == ["web-2"]
    changed = {c["id"]: c for c in d["assets"]["changed"]["items"]}
    assert set(changed["orders-db"]["changed_fields"]) == {"internet_exposed", "tags"}
    assert changed["orders-db"]["internet_exposed"] == {"before": False, "after": True}
    assert d["edges"]["removed"]["count"] >= 1
    assert any(
        f["title"].startswith("Security group allows SSH")
        for f in d["findings"]["resolved"]["items"]
    )
    assert d["findings"]["severity_changed"]["count"] == 1
    exposed = {x["id"] for x in d["newly_internet_exposed"]["items"]}
    assert exposed == {"orders-db", "new-vm"}
    small = diff_datasets(workspace.get("before"), ds, limit=1)
    assert small["assets"]["changed"]["truncated"] or small["assets"]["changed"]["count"] <= 1


def test_path_safety(tmp_path, workspace):
    inside = tmp_path / "inventory"
    assert workspace.check_path(inside) == inside.resolve()
    assert workspace.check_path("inventory") == inside.resolve()  # relative to first root
    with pytest.raises(AccessDeniedError, match="outside the allowed roots"):
        workspace.check_path("/etc/passwd")
    with pytest.raises(AccessDeniedError):
        workspace.check_path(tmp_path / ".." / "..")
    link = tmp_path / "escape"
    link.symlink_to("/etc")
    with pytest.raises(AccessDeniedError):
        workspace.check_path(link / "hosts")
    with pytest.raises(InvalidArgumentsError, match="does not exist"):
        workspace.check_path(tmp_path / "missing")
    assert workspace.check_path(tmp_path / "missing", must_exist=False)
    with pytest.raises(AccessDeniedError):
        workspace.load("/etc/hosts")
    out = workspace.output_path("a/b")
    assert out == (tmp_path / "out" / "a" / "b").resolve()
    with pytest.raises(AccessDeniedError, match="escapes"):
        workspace.output_path("../x")
    with pytest.raises(AccessDeniedError):
        workspace.output_path("/tmp/elsewhere")


def test_default_roots_from_env(monkeypatch, tmp_path):
    monkeypatch.setenv("CLOUDG_MCP_ALLOWED_ROOTS", str(tmp_path))
    ws = Workspace(output_dir=tmp_path / "o")
    assert ws.allowed_roots == [tmp_path.resolve()]
    monkeypatch.delenv("CLOUDG_MCP_ALLOWED_ROOTS")
    monkeypatch.chdir(tmp_path)
    ws = Workspace()
    assert tmp_path.resolve() in ws.allowed_roots
    assert ws.output_root == (tmp_path / "reports").resolve()


def test_output_dir_outside_roots_is_added(tmp_path):
    other = tmp_path / "elsewhere"
    ws = Workspace(allowed_roots=[tmp_path / "a"], output_dir=other)
    assert other.resolve() in ws.allowed_roots


def test_concurrent_cache_builds(sample_dataset):
    results = []

    def work():
        results.append(id(sample_dataset.dependency_graph()))

    threads = [threading.Thread(target=work) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert len(set(results)) == 1
