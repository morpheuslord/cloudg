"""Regression tests for the cloudg CLI commands (collect, scan, report, map,
deps, run): machine-readable output, config wiring, exit codes."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from click.testing import CliRunner

import cloudg.api_scanners as api_scanners
from cloudg.cli import cli
from cloudg.coverage import CollectionCoverage, ServiceStatus
from cloudg.schema.models import (
    AssetType,
    CloudAsset,
    CloudProvider,
    ComplianceResult,
    ComplianceStatus,
    EdgeType,
    Finding,
    NetworkEdge,
    ScanResult,
    Severity,
)


def invoke(*args: str) -> Any:
    return CliRunner().invoke(cli, list(args), catch_exceptions=False)


def _assets() -> list[CloudAsset]:
    vpc = CloudAsset(
        id="vpc-1",
        arn="arn:aws:ec2:us-east-1:111111111111:vpc/vpc-1",
        name="main",
        asset_type=AssetType.VPC,
        provider=CloudProvider.AWS,
        region="us-east-1",
        account_id="111111111111",
    )
    ec2 = CloudAsset(
        id="i-1",
        arn="arn:aws:ec2:us-east-1:111111111111:instance/i-1",
        name="web",
        asset_type=AssetType.EC2,
        provider=CloudProvider.AWS,
        region="us-east-1",
        account_id="111111111111",
    )
    return [vpc, ec2]


def _finding(title: str = "Open port", tool: str = "prowler") -> Finding:
    return Finding(
        resource_id="i-1",
        resource_arn="arn:aws:ec2:us-east-1:111111111111:instance/i-1",
        severity=Severity.HIGH,
        title=title,
        description="d",
        source_tool=tool,
    )


def _write_config(path: Path, body: str) -> str:
    path.write_text(body)
    return str(path)


# ─────────────────────────────────────────────────────────────────────
# Bug 5: --json output is valid JSON on stdout
# ─────────────────────────────────────────────────────────────────────


class TestMachineReadableOutput:
    def _saved_map(self, tmp_path: Path) -> Path:
        from cloudg.inventory.mapper_result import InventoryResult

        edge = NetworkEdge(source_id="i-1", target_id="vpc-1", edge_type=EdgeType.CONTAINS)
        InventoryResult(assets=_assets(), edges=[edge], providers=["aws"]).export(tmp_path)
        return tmp_path

    def test_deps_json_overview_is_pure_json(self, tmp_path):
        result = invoke("deps", "--json", "-m", str(self._saved_map(tmp_path)))
        assert result.exit_code == 0, result.output
        data = json.loads(result.stdout)  # no banner in front of the document
        assert "shared_dependencies" in data
        assert "cloud graphing" in result.stderr  # the banner went to stderr

    def test_deps_json_for_one_asset(self, tmp_path):
        result = invoke("deps", "i-1", "--json", "-m", str(self._saved_map(tmp_path)))
        assert result.exit_code == 0, result.output
        assert json.loads(result.stdout)["asset"]["name"] == "web"

    def test_tables_still_go_to_stdout_without_json(self, tmp_path):
        result = invoke("deps", "-m", str(self._saved_map(tmp_path)))
        assert result.exit_code == 0
        assert "cloud graphing" in result.stdout

    def test_mcp_json_through_the_main_cli(self):
        result = invoke("mcp", "prompts", "--json")
        assert result.exit_code == 0, result.output
        assert isinstance(json.loads(result.stdout), list)
        assert "cloud graphing" in result.stderr

    def test_console_restored_after_json_command(self, tmp_path):
        from cloudg.ui import console

        invoke("deps", "--json", "-m", str(self._saved_map(tmp_path)))
        assert console.stderr is False


# ─────────────────────────────────────────────────────────────────────
# Bug 6: cloudg report -i
# ─────────────────────────────────────────────────────────────────────


def _findings_json(directory: Path, with_edges: bool = True) -> Path:
    from datetime import datetime

    from cloudg.graph.builder import GraphBuilder
    from cloudg.renderers.json_export import JSONExporter

    assets = _assets()
    edges = [NetworkEdge(source_id="i-1", target_id="vpc-1", edge_type=EdgeType.CONTAINS)]
    finding = _finding()
    result = ScanResult(
        scan_id="scan-1234",
        provider=CloudProvider.AWS,
        account_id="111111111111",
        region="us-east-1",
        started_at=datetime(2026, 10, 1, 12, 0, 0),
        completed_at=datetime(2026, 10, 1, 12, 5, 0),
        assets=assets,
        findings=[finding],
        edges=edges,
        compliance=[
            ComplianceResult(
                framework="CIS",
                control_id="CIS-5.2",
                status=ComplianceStatus.FAIL,
                finding_ids=[finding.id],
            )
        ],
    )
    builder = GraphBuilder()
    builder.build(assets, edges)
    path = JSONExporter(output_dir=str(directory)).export(result, graph_json=builder.to_d3_json())
    if not with_edges:  # a findings.json written before it carried edges
        data = json.loads(path.read_text())
        del data["edges"]
        path.write_text(json.dumps(data))
    return path


class TestReportCommand:
    def test_round_trip_keeps_metadata_compliance_and_edges(self, tmp_path):
        src = _findings_json(tmp_path / "in")
        out = tmp_path / "out"
        result = invoke("report", "-i", str(src), "-o", str(out), "--format", "json")
        assert result.exit_code == 0, result.output

        data = json.loads((out / "findings.json").read_text())
        assert data["metadata"]["scan_id"] == "scan-1234"
        assert data["metadata"]["completed_at"] not in (None, "None")
        assert data["metadata"]["account_id"] == "111111111111"
        assert len(data["compliance"]) == 1
        assert data["compliance"][0]["control_id"] == "CIS-5.2"
        assert len(data["edges"]) == 1
        assert data["summary"]["total_edges"] == 1

    def test_edges_rebuilt_from_graph_for_older_files(self, tmp_path):
        from cloudg.cli_helpers import _load_report_input

        src = _findings_json(tmp_path / "in", with_edges=False)
        scan_result, graph = _load_report_input(src)
        assert [(e.source_id, e.target_id) for e in scan_result.edges] == [("i-1", "vpc-1")]
        assert graph["links"]

    def test_raw_findings_list_is_normalised(self, tmp_path):
        raw = tmp_path / "raw-findings.json"
        raw.write_text(json.dumps([_finding().model_dump(mode="json")] * 2))
        out = tmp_path / "out"
        result = invoke("report", "-i", str(raw), "-o", str(out), "--format", "json")
        assert result.exit_code == 0, result.output
        data = json.loads((out / "findings.json").read_text())
        assert len(data["findings"]) == 1  # the duplicate was merged

    def test_refuses_to_overwrite_its_input(self, tmp_path):
        src = _findings_json(tmp_path)
        before = src.read_text()
        result = invoke("report", "-i", str(src), "-o", str(tmp_path))
        assert result.exit_code == 1
        assert "overwrite" in result.output
        assert src.read_text() == before

        allowed = invoke("report", "-i", str(src), "-o", str(tmp_path), "--overwrite")
        assert allowed.exit_code == 0, allowed.output
        assert json.loads(src.read_text())["metadata"]["scan_id"] == "scan-1234"

    def test_html_only_may_share_the_input_directory(self, tmp_path):
        src = _findings_json(tmp_path)
        result = invoke("report", "-i", str(src), "-o", str(tmp_path), "--format", "html")
        assert result.exit_code == 0, result.output

    def test_unknown_shape_is_an_error(self, tmp_path):
        bad = tmp_path / "bad.json"
        bad.write_text('"just a string"')
        result = invoke("report", "-i", str(bad), "-o", str(tmp_path / "out"))
        assert result.exit_code == 1


# ─────────────────────────────────────────────────────────────────────
# Bug 9: cloudg scan
# ─────────────────────────────────────────────────────────────────────


@pytest.fixture
def no_scanners_installed(monkeypatch):
    monkeypatch.setattr(api_scanners, "scanner_available", lambda name: name == "iam")


class TestScanCommand:
    def test_exits_non_zero_when_nothing_can_run(self, tmp_path, no_scanners_installed):
        result = invoke("scan", "-o", str(tmp_path), "--scanners", "prowler,checkov,iam")
        assert result.exit_code == 1
        assert "No scanner could run" in result.output
        assert not (tmp_path / "raw-findings.json").exists()

    def test_reads_config_and_has_no_dot_default(self, tmp_path, monkeypatch):
        monkeypatch.setattr(api_scanners, "scanner_available", lambda name: True)
        seen: dict[str, Any] = {}

        def fake_checkov(config, target_dir):
            seen.setdefault("dirs", []).append(target_dir)
            seen["timeout"] = config.scanners.timeout_seconds
            return [_finding(tool="checkov")]

        monkeypatch.setattr(api_scanners, "scan_checkov", fake_checkov)
        iac = tmp_path / "infra"
        iac.mkdir()
        cfg = _write_config(
            tmp_path / "config.yaml",
            f"scanners:\n  enabled: [checkov]\n  timeout_seconds: 120\n"
            f"  iac_directories: ['{iac}']\n",
        )
        result = invoke("-c", cfg, "scan", "-o", str(tmp_path / "out"))
        assert result.exit_code == 0, result.output
        assert seen == {"dirs": [str(iac)], "timeout": 120}
        raw = json.loads((tmp_path / "out" / "raw-findings.json").read_text())
        assert len(raw) == 1

        # Without --iac-dir and scanners.iac_directories, Checkov is skipped
        # instead of scanning "."
        seen.clear()
        result = invoke("scan", "-o", str(tmp_path / "out2"), "--scanners", "checkov")
        assert result.exit_code == 1
        assert seen == {}

    def test_iam_linter_runs_with_assets(self, tmp_path, monkeypatch):
        calls: list[int] = []

        def fake_iam(assets):
            calls.append(len(assets))
            return []

        monkeypatch.setattr(api_scanners, "scan_iam", fake_iam)
        inventory = tmp_path / "inventory-aws.json"
        inventory.write_text(json.dumps({"assets": [a.model_dump(mode="json") for a in _assets()]}))

        result = invoke("scan", "-o", str(tmp_path), "--scanners", "iam")
        assert result.exit_code == 1  # no assets: the linter cannot run
        assert "needs --assets" in result.output or "no collected assets" in result.output
        assert calls == []

        result = invoke(
            "scan", "-o", str(tmp_path), "--scanners", "iam", "--assets", str(inventory)
        )
        assert result.exit_code == 0, result.output
        assert calls == [2]

    def test_every_scanner_failing_is_non_zero(self, tmp_path, monkeypatch):
        monkeypatch.setattr(api_scanners, "scanner_available", lambda name: True)

        def boom(config, target_dir):
            raise api_scanners.ScannerFailed("Checkov", ["timed out after 60s"], [])

        monkeypatch.setattr(api_scanners, "scan_checkov", boom)
        result = invoke(
            "scan", "-o", str(tmp_path), "--scanners", "checkov", "--iac-dir", str(tmp_path)
        )
        assert result.exit_code == 1
        assert "timed out after 60s" in " ".join(result.output.split())


# ─────────────────────────────────────────────────────────────────────
# Bug 10: cloudg collect reads config.yaml auth
# ─────────────────────────────────────────────────────────────────────


class _FakeResolver:
    def __init__(self) -> None:
        self.calls: dict[str, Any] = {}

    def resolve_aws(self, profile=None, region=None, config=None):
        from cloudg.credentials import AWSCredentials

        self.calls["aws"] = {"profile": profile, "region": region, "config": config}
        return AWSCredentials(session=object(), account_id="111111111111", region=region)

    def resolve_azure(self, subscription_id=None, config=None):
        from cloudg.credentials import AzureCredentials

        self.calls["azure"] = {"subscription_id": subscription_id, "config": config}
        return AzureCredentials(credential=object(), subscription_id=subscription_id)

    def resolve_gcp(self, project_id=None, config=None):
        from cloudg.credentials import GCPCredentials

        self.calls["gcp"] = {"project_id": project_id, "config": config}
        return GCPCredentials(credentials=object(), project_id=project_id)


class TestCollectCredentials:
    def _cfg(self):
        from cloudg.config import CloudGConfig

        return CloudGConfig.model_validate(
            {
                "aws": {
                    "regions": ["eu-west-1"],
                    "access_key_id": "AKIAEXAMPLEEXAMPLE00",
                    "secret_access_key": "example-secret",
                    "session_token": "example-token",
                },
                "azure": {"subscription_ids": ["sub-1"], "tenant_id": "tenant-1"},
                "gcp": {"project_ids": ["proj-1"]},
            }
        )

    def test_aws_uses_config_auth_and_region(self):
        from cloudg.cli import _build_collector

        resolver, cfg = _FakeResolver(), self._cfg()
        _build_collector(
            "aws",
            resolver,
            cfg=cfg,
            profile=None,
            region=None,
            subscription_id=None,
            project_id=None,
        )
        call = resolver.calls["aws"]
        assert call["config"] is cfg.aws
        assert call["config"].session_token == "example-token"
        assert call["region"] == "eu-west-1"

    def test_flags_win_over_config(self):
        from cloudg.cli import _build_collector

        resolver, cfg = _FakeResolver(), self._cfg()
        _build_collector(
            "aws",
            resolver,
            cfg=cfg,
            profile="audit",
            region="us-west-2",
            subscription_id=None,
            project_id=None,
        )
        assert resolver.calls["aws"]["profile"] == "audit"
        assert resolver.calls["aws"]["region"] == "us-west-2"

    def test_azure_and_gcp_use_config(self):
        from cloudg.cli import _build_collector

        resolver, cfg = _FakeResolver(), self._cfg()
        kwargs = {"cfg": cfg, "profile": None, "region": None}
        _build_collector("azure", resolver, subscription_id=None, project_id=None, **kwargs)
        _build_collector("gcp", resolver, subscription_id=None, project_id=None, **kwargs)
        assert resolver.calls["azure"]["subscription_id"] == "sub-1"
        assert resolver.calls["azure"]["config"] is cfg.azure
        assert resolver.calls["gcp"]["project_id"] == "proj-1"

    def test_resolver_profile_flag_replaces_config_profile(self, monkeypatch):
        import cloudg.credentials as credentials
        from cloudg.config import AWSConfig

        seen = {}

        class _Session:
            def client(self, name):
                raise RuntimeError("no STS in this test")

        def fake_build(cfg, region, account_id=None):
            seen["profile"] = cfg.profile
            return _Session()

        monkeypatch.setattr(credentials, "build_aws_session", fake_build)
        credentials.CredentialResolver().resolve_aws(
            profile="flag", region="us-east-1", config=AWSConfig(profile="cfg")
        )
        assert seen["profile"] == "flag"


# ─────────────────────────────────────────────────────────────────────
# Bugs 11 and 15: cloudg map flags
# ─────────────────────────────────────────────────────────────────────


class _StopMapper:
    seen: dict[str, Any] = {}

    def __init__(self, cfg, tagging_sweep=None):
        _StopMapper.seen = {"sweep": tagging_sweep, "cfg": cfg}

    def map_inventory_sync(self):
        raise RuntimeError("stop here")


class TestMapCommand:
    @pytest.fixture(autouse=True)
    def fake_mapper(self, monkeypatch):
        import cloudg.inventory

        monkeypatch.setattr(cloudg.inventory, "InventoryMapper", _StopMapper)

    def test_sweep_follows_config_by_default(self, tmp_path):
        cfg = _write_config(tmp_path / "c.yaml", "inventory:\n  tagging_sweep: false\n")
        invoke("-c", cfg, "map", "-o", str(tmp_path))
        assert _StopMapper.seen["sweep"] is False

        invoke("-c", cfg, "map", "--sweep", "-o", str(tmp_path))
        assert _StopMapper.seen["sweep"] is True

        invoke("map", "-o", str(tmp_path))
        assert _StopMapper.seen["sweep"] is True  # the config default

    def test_accounts_need_a_role_name(self, tmp_path):
        result = invoke("map", "--accounts", "222222222222", "-o", str(tmp_path))
        assert result.exit_code == 2
        assert "--role-name" in result.output

        ok = invoke(
            "map", "--accounts", "222222222222", "--role-name", "Audit", "-o", str(tmp_path)
        )
        assert "--role-name" not in ok.output
        assert _StopMapper.seen["cfg"].aws.role_name == "Audit"

    def test_role_name_from_config_is_enough(self, tmp_path):
        cfg = _write_config(tmp_path / "c.yaml", "aws:\n  role_name: Audit\n")
        result = invoke("-c", cfg, "map", "--accounts", "222222222222", "-o", str(tmp_path))
        assert result.exit_code == 1  # reached the (stopped) mapper
        assert _StopMapper.seen["cfg"].aws.accounts == ["222222222222"]

    def test_org_does_not_need_a_role_name(self, tmp_path):
        result = invoke("map", "--org", "--accounts", "222222222222", "-o", str(tmp_path))
        assert result.exit_code == 1  # reached the (stopped) mapper

    def test_ou_help_mentions_arns(self):
        result = invoke("map", "--help")
        assert "ID, ARN or name" in " ".join(result.output.split())


# ─────────────────────────────────────────────────────────────────────
# Bug 14: cloudg run exit status
# ─────────────────────────────────────────────────────────────────────


class TestRunExitStatus:
    def _run(self, tmp_path, monkeypatch, assets, coverage):
        import cloudg.collectors.multi as multi

        async def fake_collect_all(self):
            return assets, [], coverage

        monkeypatch.setattr(multi.MultiAccountCollector, "collect_all", fake_collect_all)
        return invoke(
            "run",
            "-p",
            "aws",
            "--scanners",
            "",
            "--no-ontology",
            "--no-rag-export",
            "-o",
            str(tmp_path),
        )

    def test_total_collection_failure_exits_3(self, tmp_path, monkeypatch):
        cov = CollectionCoverage(provider="aws", region="us-east-1", account_id="111111111111")
        cov.record("aws_full", ServiceStatus.FAILED, error="AccessDenied")
        result = self._run(tmp_path, monkeypatch, [], [cov])
        assert result.exit_code == 3
        assert "Collection failed for every target" in result.output
        assert "AccessDenied" in result.output
        assert (tmp_path / "findings.json").exists()  # reports are still written

    def test_partial_collection_exits_0(self, tmp_path, monkeypatch):
        ok = CollectionCoverage(provider="aws", region="us-east-1", account_id="111111111111")
        ok.record("aws_full", ServiceStatus.SUCCESS, asset_count=2)
        bad = CollectionCoverage(provider="aws", region="eu-west-1", account_id="111111111111")
        bad.record("aws_full", ServiceStatus.FAILED, error="AccessDenied")
        result = self._run(tmp_path, monkeypatch, _assets(), [ok, bad])
        assert result.exit_code == 0, result.output
        assert "partial" in result.output

    def test_empty_but_readable_account_exits_0(self, tmp_path, monkeypatch):
        ok = CollectionCoverage(provider="aws", region="us-east-1", account_id="111111111111")
        ok.record("aws_full", ServiceStatus.SUCCESS)
        result = self._run(tmp_path, monkeypatch, [], [ok])
        assert result.exit_code == 0, result.output

    def test_accounts_in_config_need_a_role_name(self, tmp_path):
        cfg = _write_config(tmp_path / "c.yaml", "aws:\n  accounts: ['222222222222']\n")
        result = invoke("-c", cfg, "run", "-p", "aws", "-o", str(tmp_path))
        assert result.exit_code == 2
        assert "role_name" in result.output
