"""Export, live (engine monkeypatched, no network) and meta tools."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

import pytest

from cloudg import api
from cloudg.schema.models import Finding, Severity
from tests.mcp.fixtures import sample_estate

# ---------------------------------------------------------------------------
# Export
# ---------------------------------------------------------------------------


async def test_terraform_preview(call):
    out = await call("terraform_preview")
    assert out["assets_considered"] > 40 and out["total_mapped"] > 0
    assert "aws_instance" in out["resource_types"]
    out = await call("terraform_preview", refs=["web-1", "orders-db"])
    assert out["assets_considered"] == 2
    out = await call("terraform_preview", asset_types=["S3_BUCKET"])
    assert out["assets_considered"] == 3
    assert "Did you mean" in await call.error("terraform_preview", refs=["web-11"])


async def test_export_terraform(call, workspace):
    out = await call("export_terraform", subdir="tf", asset_types=["EC2", "VPC"])
    assert out["resources"] == 4
    main = Path(out["files"]["main"])
    assert main.exists() and main.parent == workspace.output_root / "tf"
    assert "escapes" in await call.error("export_terraform", subdir="../../etc")


@pytest.mark.parametrize("fmt,key", [("json", "json"), ("html", "html"), ("graphml", "graphml"),
                                     ("inventory", "map"), ("asset_map", "asset_map")])
async def test_export_report(call, workspace, fmt, key):
    out = await call("export_report", format=fmt, subdir=f"r-{fmt}")
    path = Path(out["files"][key])
    assert path.exists() and path.stat().st_size > 50
    assert str(path).startswith(str(workspace.output_root))


async def test_export_report_json_roundtrip(call, workspace):
    out = await call("export_report", format="json")
    data = json.loads(Path(out["files"]["json"]).read_text())
    assert len(data["findings"]) == 12 and data["graph"]["nodes"]
    loaded = await call("load_dataset", path=out["files"]["json"], name="roundtrip")
    assert loaded["total_findings"] == 12 and loaded["total_edges"] > 0


# ---------------------------------------------------------------------------
# Live tools with a fake engine
# ---------------------------------------------------------------------------


class FakeEngine:
    instances: list["FakeEngine"] = []

    def __init__(self, config):
        self.config = config
        self.on_phase_start = None
        self.on_error = None
        self.calls: list[tuple] = []
        FakeEngine.instances.append(self)

    def _phase(self, name):
        if self.on_phase_start:
            self.on_phase_start(name)

    async def map_inventory(self, output_dir=None, findings=None, tagging_sweep=None):
        self.calls.append(("map_inventory", tagging_sweep))
        self._phase("inventory_mapping")
        if self.on_error:
            self.on_error("aws:rds", RuntimeError("AccessDenied"))
        return sample_estate.build_inventory()

    async def collect(self):
        self.calls.append(("collect",))
        self._phase("collection")
        inv = sample_estate.build_inventory()
        return api.CollectionResult(assets=inv.assets, edges=inv.edges, coverage=inv.coverage,
                                    providers_scanned=self.config.providers,
                                    regions_scanned={"aws": ["us-east-1"]}, duration_ms=3)

    async def scan(self, assets, edges, iac_dir=None, images=None, profile=None,
                   output_dir="./reports"):
        self.calls.append(("scan", iac_dir, images, str(output_dir)))
        self._phase("scanning")
        return [Finding(id="f-scan-1", resource_id="web-2", severity=Severity.HIGH,
                        title="Scanner says no", description="d", source_tool="prowler",
                        compliance_frameworks=["CIS-AWS"])]

    async def run_pipeline(self, output_dir="./reports"):
        self.calls.append(("run_pipeline", str(output_dir)))
        for p in ("collection", "scanning", "analysis", "normalisation", "reporting"):
            self._phase(p)
        from cloudg.schema.models import ScanResult

        inv = sample_estate.build_inventory()
        sr = ScanResult(assets=inv.assets, edges=inv.edges, findings=sample_estate.findings(),
                        compliance=sample_estate.compliance())
        return api.PipelineResult(assets=inv.assets, edges=inv.edges, findings=sr.findings,
                                  scan_result=sr, providers_scanned=["aws"],
                                  report_paths={"json": Path(output_dir) / "findings.json"},
                                  attack_paths=[["a", "b"]], errors=[])


@pytest.fixture
def fake_engine(monkeypatch):
    from cloudg.mcp.catalog import live

    FakeEngine.instances = []
    monkeypatch.setattr(api, "CloudGEngine", FakeEngine)
    # The engine is fake, so the credentials are irrelevant
    monkeypatch.setattr(live, "credential_problems", lambda cfg: {})
    return FakeEngine


@pytest.fixture
def no_credentials(monkeypatch):
    from cloudg.mcp.catalog import live

    seen: list = []

    def problems(cfg):
        seen.append(list(cfg.providers))
        return {p: "no credentials found" for p in cfg.providers}

    monkeypatch.setattr(live, "credential_problems", problems)
    return seen


@pytest.mark.parametrize("tool,args", [
    ("map_inventory", {}), ("collect_assets", {"providers": ["aws", "gcp"]}),
    ("run_pipeline", {}), ("run_scanners", {"scanners": ["prowler"]}),
])
async def test_live_tools_fail_fast_without_credentials(call, fake_engine, no_credentials,
                                                        tool, args):
    res = await call.raw(tool, **args)
    assert res.is_error
    text = res.content[0].text
    assert "Cannot collect live data" in text and "preflight=false" in text
    assert fake_engine.instances == []  # no engine, so no cloud API call was made
    assert no_credentials


async def test_preflight_can_be_skipped(call, fake_engine, no_credentials):
    out = await call("collect_assets", preflight=False)
    assert out["summary"]["total_assets"] > 40
    assert no_credentials == []


async def test_offline_scanners_skip_preflight(call, fake_engine, no_credentials):
    out = await call("run_scanners", scanners=["iam"])
    assert out["new_findings"] == 1 and no_credentials == []


async def test_preflight_timeout_is_reported(call, fake_engine, monkeypatch):
    import time as _time

    from cloudg.mcp.catalog import live

    monkeypatch.setattr(live, "PREFLIGHT_TIMEOUT_S", 0.05)
    monkeypatch.setattr(live, "credential_problems", lambda cfg: _time.sleep(0.5) or {})
    assert "did not finish" in await call.error("map_inventory")
    assert fake_engine.instances == []


def test_aws_check_reports_missing_profile_and_chain(monkeypatch, tmp_path):
    pytest.importorskip("boto3")
    from cloudg.config import AWSConfig
    from cloudg.mcp.catalog.live import _check_aws

    empty = tmp_path / "empty"
    empty.write_text("")
    for var in ("AWS_PROFILE", "AWS_DEFAULT_PROFILE", "AWS_ACCESS_KEY_ID",
                "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN", "AWS_WEB_IDENTITY_TOKEN_FILE",
                "AWS_ROLE_ARN", "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI",
                "AWS_CONTAINER_CREDENTIALS_FULL_URI"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("AWS_CONFIG_FILE", str(empty))
    monkeypatch.setenv("AWS_SHARED_CREDENTIALS_FILE", str(empty))
    monkeypatch.setenv("AWS_EC2_METADATA_DISABLED", "true")
    assert "could not be found" in _check_aws(AWSConfig(profile="nope"))
    assert "no credentials found" in _check_aws(AWSConfig())
    assert _check_aws(AWSConfig(access_key_id="AKIAEXAMPLE", secret_access_key="x")) is None
    missing = AWSConfig(role_arn="arn:aws:iam::111111111111:role/r",
                        web_identity_token_file=str(tmp_path / "missing"))
    assert "does not exist" in _check_aws(missing)


def _progress_ctx(layer):
    seen: list[tuple] = []
    ctx = layer.context()
    ctx.progress_callback = lambda p, t, m: seen.append((p, t, m))
    return ctx, seen


async def test_map_inventory(layer, fake_engine):
    ctx, seen = _progress_ctx(layer)
    res = await layer.call_tool("map_inventory", {"providers": ["AWS"], "regions": ["eu-west-1"],
                                                  "services": ["network"],
                                                  "tagging_sweep": False, "name": "live1"},
                                context=ctx)
    assert not res.is_error, res.content[0].text
    out = res.structured
    assert out["dataset"] == "live1" and out["active"] and out["summary"]["total_assets"] > 40
    assert out["collection_failures"][0]["service"] == "rds"
    assert out["errors"] == ["aws:rds: AccessDenied"]
    eng = fake_engine.instances[-1]
    assert eng.config.providers == ["aws"] and eng.config.aws.regions == ["eu-west-1"]
    assert eng.config.inventory.services == ["network"]
    assert eng.calls == [("map_inventory", False)]
    assert layer.workspace.active_name == "live1"
    await asyncio.sleep(0.01)
    assert any(m == "phase: inventory_mapping" for _, _, m in seen)
    assert seen[-1][0] == seen[-1][1] == 2
    assert any(getattr(c, "uri", "") == "cloudg://datasets/live1/summary" for c in res.content)
    # the workspace config itself was not mutated
    assert layer.workspace.config.aws.regions == ["us-east-1"]


async def test_map_inventory_bad_provider(call, fake_engine):
    assert "Unknown provider" in await call.error("map_inventory", providers=["oracle"])
    assert fake_engine.instances == []


async def test_collect_assets(call, fake_engine, layer):
    out = await call("collect_assets", providers=["aws", "gcp"])
    assert out["dataset"].startswith("collect-") and out["summary"]["total_assets"] > 40
    assert fake_engine.instances[-1].config.providers == ["aws", "gcp"]


async def test_run_scanners(call, fake_engine, workspace, sample_paths):
    iac = sample_paths["root"] / "iac"
    iac.mkdir()
    out = await call("run_scanners", scanners=["prowler", "iam"], iac_dir=str(iac),
                     images=["nginx:1"])
    assert out["new_findings"] == 1 and out["findings_after"] >= out["findings_before"]
    eng = fake_engine.instances[-1]
    assert eng.config.scanners.enabled == ["prowler", "iam"]
    _, iac_dir, images, outdir = eng.calls[0]
    assert iac_dir == str(iac.resolve()) and images == ["nginx:1"]
    assert outdir == str(workspace.output_root / "scans")
    assert "f-scan-1" in workspace.get().findings_by_id or any(
        f.title == "Scanner says no" for f in workspace.get().findings)
    # offline scanners have no cloud scope, so no cooldown applies
    out = await call("run_scanners", scanners=["iam"], normalise=False)
    assert out["findings_after"] == out["findings_before"] + 1


async def test_run_scanners_errors(call, fake_engine):
    assert "Unknown scanner" in await call.error("run_scanners", scanners=["nmap"])
    assert "outside the allowed roots" in await call.error("run_scanners", iac_dir="/etc")
    assert fake_engine.instances == []


async def test_run_pipeline(call, fake_engine, workspace):
    out = await call("run_pipeline", subdir="pipe", name="full")
    assert out["dataset"] == "full" and out["attack_paths_found"] == 1
    assert out["report_paths"]["json"].startswith(str(workspace.output_root / "pipe"))
    assert out["summary"]["total_findings"] == 12
    assert workspace.get("full").compliance
    assert "escapes" in await call.error("run_pipeline", subdir="../../x")


# ---------------------------------------------------------------------------
# Meta
# ---------------------------------------------------------------------------


async def test_list_capabilities(call, layer):
    out = await call("list_capabilities")
    assert out["tool_count"] == len(layer.list_tools())
    assert "find_assets" in {t["name"] for t in out["categories"]["inventory"]}
    assert "orient" in out["workflows"] and "security_posture_review" in out["prompts"]
    live = {t["name"]: t for t in out["categories"]["live"]}
    assert live["map_inventory"]["open_world"] and "cloud_access" in \
        live["map_inventory"]["capabilities"]


async def test_list_capabilities_respects_prefix_and_filters(workspace):
    from cloudg.mcp.layer import CloudGMCPLayer

    layer = CloudGMCPLayer(policy="open", workspace=workspace, prefix="cg_",
                           exclude_categories=["live"])
    res = await layer.call_tool("cg_list_capabilities", {})
    out = res.structured
    assert "live" not in out["categories"]
    assert all(t["name"].startswith("cg_") for ts in out["categories"].values() for t in ts)


@pytest.mark.parametrize("section", ["all", "asset_types", "edge_types", "severities",
                                     "relation_types", "relation_groups",
                                     "compliance_statuses", "providers"])
async def test_describe_schema(call, section):
    out = await call("describe_schema", section=section)
    assert out
    if section in ("all", "asset_types"):
        assert "EC2" in out["asset_types"]["Compute"]
        assert "S3_BUCKET" in out["asset_types"]["Storage"]
    if section == "edge_types":
        assert out["edge_types"]["ASSUMES_ROLE"] == "runs as"
    if section == "relation_groups":
        assert "IAM" in out["relation_groups"]
    if section == "relation_types":
        assert "CROSS_ACCOUNT_TRUST" in out["relation_groups"]["IAM"]


async def test_explain_asset_type(call):
    out = await call("explain_asset_type", asset_type="rds_instance")
    assert out["asset_type"] == "RDS_INSTANCE" and out["sensitive_data_store"]
    assert out["ontology_class"] == "cm:RelationalDatabase"
    assert out["terraform_type"] == "aws_db_instance" and out["in_active_dataset"] == 1
    out = await call("explain_asset_type", asset_type="LOAD_BALANCER")
    assert out["internet_exposure_expected"] is True
    out = await call("explain_asset_type", asset_type="CONTAINER_REGISTRY")
    assert out["note"] and "ECR" in out["note"]
    msg = await call.error("explain_asset_type", asset_type="LAMBDA")
    assert "Unknown asset type" in msg and "LAMBDA_FUNCTION" in msg


async def test_explain_edge_type(call):
    out = await call("explain_edge_type", edge_type="contains")
    assert out["dependency_direction"] == "reverse" and out["reads_as"] == "source contains target"
    out = await call("explain_edge_type", edge_type="SECURITY_GROUP_RULE")
    assert out["dependency_direction"] == "none"
    assert isinstance(out["ontology_relations"], str)
    out = await call("explain_edge_type", edge_type="ASSUMES_ROLE")
    assert out["ontology_relations"] == ["RUNS_ON"]
    assert "edge type" in await call.error("explain_edge_type", edge_type="LIKES")


async def test_meta_works_without_dataset(tmp_path):
    from cloudg.mcp.layer import CloudGMCPLayer
    from cloudg.mcp.state import Workspace

    layer = CloudGMCPLayer(policy="open", workspace=Workspace(allowed_roots=[tmp_path],
                                                              output_dir=tmp_path))
    for name, args in [("describe_schema", {}), ("explain_asset_type", {"asset_type": "EC2"}),
                       ("list_frameworks", {}), ("list_capabilities", {})]:
        res = await layer.call_tool(name, args)
        assert not res.is_error, name
    assert "in_active_dataset" not in (await layer.call_tool(
        "explain_asset_type", {"asset_type": "EC2"})).structured


# ---------------------------------------------------------------------------
# Live operation guard (cloudg.resilience)
# ---------------------------------------------------------------------------


class _Clock:
    def __init__(self) -> None:
        self.t = 1000.0

    def __call__(self) -> float:
        return self.t


@pytest.fixture
def clock(workspace):
    from cloudg.resilience import LiveOperationGuard

    c = _Clock()
    workspace.live_guard = LiveOperationGuard(cooldown_seconds=60, clock=c)
    return c


async def test_cooldown_rejects_repeat_collection(call, layer, fake_engine, clock):
    first = await call("collect_assets", name="c1")
    res = await call.raw("collect_assets", name="c2")
    assert res.is_error
    text = res.content[0].text
    assert "cooling down" in text and "'c1'" in text and "force=true" in text
    data = res.meta["cloudg/error_data"]
    assert data["reason"] == "cooldown" and data["retry_after_seconds"] == 60
    assert data["use_dataset"] == first["dataset"] and data["scopes"] == ["aws"]
    assert len(fake_engine.instances) == 1 and "c2" not in layer.workspace
    clock.t += 61
    assert (await call("collect_assets", name="c2"))["dataset"] == "c2"


async def test_cooldown_is_per_scope(call, fake_engine, clock):
    await call("collect_assets", providers=["aws"])
    out = await call("collect_assets", providers=["gcp"])
    assert out["summary"]["total_assets"] > 0


def test_live_scopes():
    from cloudg.config import CloudGConfig
    from cloudg.mcp.catalog.live import live_scopes

    cfg = CloudGConfig(providers=["aws", "azure", "gcp"])
    assert live_scopes(cfg) == ["aws", "azure", "gcp"]
    cfg.aws.accounts = ["111111111111", "222222222222"]
    cfg.azure.subscription_ids = ["sub-1"]
    cfg.gcp.organization_id = "42"
    assert live_scopes(cfg) == ["aws/111111111111", "aws/222222222222", "azure/sub-1",
                                "gcp/org:42"]
    cfg2 = CloudGConfig(providers=["aws"])
    cfg2.aws.profile = "prod"
    assert live_scopes(cfg2) == ["aws/profile:prod"]


async def test_single_flight_shares_one_run(layer, fake_engine, clock, monkeypatch):
    gate = asyncio.Event()
    orig = FakeEngine.map_inventory

    async def slow(self, *a, **kw):
        await gate.wait()
        return await orig(self, *a, **kw)

    monkeypatch.setattr(FakeEngine, "map_inventory", slow)
    t1 = asyncio.create_task(layer.call_tool("map_inventory", {"name": "shared"}))
    t2 = asyncio.create_task(layer.call_tool("map_inventory", {}))
    await asyncio.sleep(0.05)
    gate.set()
    r1, r2 = await t1, await t2
    assert not r1.is_error and not r2.is_error, (r1.content[0].text, r2.content[0].text)
    assert len(fake_engine.instances) == 1
    assert r1.structured["dataset"] == r2.structured["dataset"] == "shared"
    assert r2.structured.get("joined") is True and not r1.structured.get("joined")
    assert [d for d in layer.workspace.names() if d != "sample"] == ["shared"]
    assert layer.workspace.live_guard.status()["joined"] == 1


async def test_concurrent_different_operation_is_busy(layer, fake_engine, clock, monkeypatch):
    gate = asyncio.Event()
    orig = FakeEngine.map_inventory

    async def slow(self, *a, **kw):
        await gate.wait()
        return await orig(self, *a, **kw)

    monkeypatch.setattr(FakeEngine, "map_inventory", slow)
    t1 = asyncio.create_task(layer.call_tool("map_inventory", {}))
    await asyncio.sleep(0.05)
    r2 = await layer.call_tool("collect_assets", {})
    gate.set()
    await t1
    assert r2.is_error and r2.meta["cloudg/error_data"]["reason"] == "busy"


async def test_force_requires_admin_or_operator(layer, fake_engine, clock):
    from cloudg.mcp.context import Principal

    admin = Principal(id="alice", roles={"admin"})
    user = Principal(id="bob", roles={"default"})
    assert not (await layer.call_tool("collect_assets", {}, principal=admin)).is_error
    res = await layer.call_tool("collect_assets", {"force": True}, principal=user)
    assert res.is_error and "admin or operator" in res.content[0].text
    assert len(fake_engine.instances) == 1  # refused before any engine was built
    res = await layer.call_tool("collect_assets", {"force": True}, principal=admin)
    assert not res.is_error and len(fake_engine.instances) == 2
    op = Principal(id="ops", roles={"operator"})
    assert not (await layer.call_tool("collect_assets", {"force": True},
                                      principal=op)).is_error


async def test_name_validated_before_preflight_and_engine(call, fake_engine, no_credentials):
    for tool in ("map_inventory", "collect_assets", "run_pipeline"):
        msg = await call.error(tool, name="sample")
        assert "already exists" in msg and "replace=true" in msg
        msg = await call.error(tool, name="bad name")
        assert "Invalid dataset name" in msg
    assert fake_engine.instances == [] and no_credentials == []


async def test_live_replace_overwrites(call, fake_engine, workspace):
    out = await call("collect_assets", name="sample", replace=True)
    assert out["dataset"] == "sample" and workspace.get("sample").kind == "live"


async def test_throttling_summary_in_result(call, fake_engine, clock, monkeypatch):
    orig = FakeEngine.map_inventory

    async def throttled(self, *a, **kw):
        inv = await orig(self, *a, **kw)
        inv.throttling = {"totals": {"throttled": 7}, "messages": ["ec2 slowed"],
                          "skipped": {"aws/rds": "circuit open"}, "scopes": {"x": 1}}
        return inv

    monkeypatch.setattr(FakeEngine, "map_inventory", throttled)
    out = await call("map_inventory")
    assert out["throttling"] == {"totals": {"throttled": 7}, "messages": ["ec2 slowed"],
                                 "skipped": {"aws/rds": "circuit open"}}


async def test_rate_limit_status_tool_and_resource(call, layer, fake_engine, clock):
    out = await call("rate_limit_status")
    assert out["live_guard"]["cooling_down"] == {}
    assert out["live_guard"]["cooldown_seconds"] == 60
    assert "breakers" in out["throttling"] and "slowed_buckets" in out["throttling"]
    await call("collect_assets")
    out = await call("rate_limit_status")
    assert out["live_guard"]["cooling_down"] == {"aws": 60.0}
    import json as _json

    res = _json.loads((await layer.read_resource("cloudg://ratelimit"))[0].text)
    assert res["live_guard"]["started"] == 1
    spec = layer.registry.tools["rate_limit_status"]
    assert spec.annotations.read_only and spec.annotations.open_world is False


async def test_guard_built_lazily_from_config(workspace):
    workspace.config.ratelimit.live_cooldown_seconds = 5
    workspace._live_guard = None
    assert workspace.live_guard.cooldown_seconds == 5
    assert workspace.live_guard is workspace.live_guard
