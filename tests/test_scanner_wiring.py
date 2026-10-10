"""Regression tests for scanner wiring in the engine and the CLI: timeouts,
credentials, regions, plugins, Terraform output, pipeline errors and hooks."""

from __future__ import annotations

import asyncio
import importlib.metadata
import subprocess
import threading
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

import cloudg.api_scanners as api_scanners
from cloudg.api import CloudGEngine, CollectionResult
from cloudg.config import AWSConfig, CloudGConfig
from cloudg.coverage import CollectionCoverage, ServiceStatus
from cloudg.schema.models import AssetType, CloudAsset, CloudProvider, Finding, Severity


def _finding(title: str, tool: str = "fake") -> Finding:
    return Finding(
        resource_id=f"r-{title}",
        resource_arn=f"arn:aws:s3:::{title}",
        severity=Severity.HIGH,
        title=title,
        description="d",
        source_tool=tool,
    )


def _asset() -> CloudAsset:
    return CloudAsset(
        id="role-1",
        arn="arn:aws:iam::111111111111:role/app",
        name="app",
        asset_type=AssetType.IAM_ROLE,
        provider=CloudProvider.AWS,
        account_id="111111111111",
    )


# ─────────────────────────────────────────────────────────────────────
# Plugin scanners used through fake entry points
# ─────────────────────────────────────────────────────────────────────

RELEASE_SLOW = threading.Event()


class FastPlugin:
    def __init__(self, timeout_seconds: int, assets: list[Any]) -> None:
        self.timeout_seconds = timeout_seconds
        self.assets = assets

    def run(self) -> list[Any]:
        return [_finding("fast", "fastscan")]


class SlowPlugin:
    """Finishes only after on_finding fired for FastPlugin (or after 5 s)."""

    def __init__(self, **kwargs: Any) -> None:
        self.kwargs = kwargs

    def run(self) -> list[Any]:
        released = RELEASE_SLOW.wait(timeout=5)
        return [_finding("slow-released" if released else "slow-timeout", "slowscan")]


class DictPlugin:
    def run(self) -> list[Any]:
        return [_finding("as-dict", "dictscan").model_dump(mode="json")]


class BrokenPlugin:
    def run(self) -> list[Any]:
        raise RuntimeError("plugin exploded")


class ImpostorProwler:
    def run(self) -> list[Any]:
        return [_finding("impostor")]


def _ep(name: str, value: str) -> importlib.metadata.EntryPoint:
    return importlib.metadata.EntryPoint(name=name, value=value, group="cloudg.scanners")


@pytest.fixture
def fake_plugins(monkeypatch):
    """cloudg's own built-in entry point, a third-party one reusing the
    built-in name "prowler", and four plugins with new names."""
    eps = importlib.metadata.EntryPoints(
        [
            _ep("prowler", "cloudg.scanners.prowler:ProwlerScanner"),
            _ep("prowler", "tests.test_scanner_wiring:ImpostorProwler"),
            _ep("fastscan", "tests.test_scanner_wiring:FastPlugin"),
            _ep("slowscan", "tests.test_scanner_wiring:SlowPlugin"),
            _ep("dictscan", "tests.test_scanner_wiring:DictPlugin"),
            _ep("brokenscan", "tests.test_scanner_wiring:BrokenPlugin"),
            _ep("fastscan", "tests.test_scanner_wiring:BrokenPlugin"),  # duplicate name
        ]
    )
    real_entry_points = importlib.metadata.entry_points

    def entry_points(**params: Any) -> Any:
        if str(params.get("group", "")).startswith("cloudg."):
            return eps.select(**params)
        return real_entry_points(**params)  # other libraries (networkx, ...)

    monkeypatch.setattr(importlib.metadata, "entry_points", entry_points)
    RELEASE_SLOW.clear()
    return eps


# ─────────────────────────────────────────────────────────────────────
# Bug 16: PluginRegistry drives scanner selection
# ─────────────────────────────────────────────────────────────────────


class TestPluginRegistry:
    def test_builtin_name_wins_over_a_plugin(self, fake_plugins, caplog):
        from cloudg.registry import PluginRegistry
        from cloudg.scanners.prowler import ProwlerScanner

        registry = PluginRegistry()
        with caplog.at_level("WARNING"):
            assert registry.get_scanner("prowler") is ProwlerScanner
        assert not registry.is_plugin_scanner("prowler")
        assert "built-in" in caplog.text and "ImpostorProwler" in caplog.text
        # The first plugin to claim a new name keeps it
        assert registry.get_scanner("fastscan") is FastPlugin
        assert "already uses the name" in caplog.text

    def test_select_scanners_splits_and_warns_on_unknown(self, fake_plugins, caplog):
        from cloudg.registry import select_scanners

        with caplog.at_level("WARNING"):
            selection = select_scanners(["Prowler", "fastscan", "nope", "iam", "fastscan"])
        assert selection.builtin == ["prowler", "iam"]
        assert list(selection.plugins) == ["fastscan"]
        assert selection.unknown == ["nope"]
        assert "Unknown scanner(s) ignored: nope" in caplog.text
        assert "fastscan" in caplog.text  # listed as available

    def test_run_plugin_scanner_passes_only_declared_arguments(self):
        from cloudg.registry import run_plugin_scanner

        context = {"timeout_seconds": 99, "assets": [], "config": object()}
        assert run_plugin_scanner(FastPlugin, **context)[0].title == "fast"
        assert run_plugin_scanner(DictPlugin, **context)[0].title == "as-dict"

    def test_engine_runs_plugins_from_scanners_enabled(self, fake_plugins, tmp_path):
        cfg = CloudGConfig()
        cfg.scanners.enabled = ["fastscan", "dictscan", "unknownscan"]
        engine = CloudGEngine(cfg)
        findings = asyncio.run(engine.scan([], [], output_dir=tmp_path))
        assert sorted(f.title for f in findings) == ["as-dict", "fast"]


# ─────────────────────────────────────────────────────────────────────
# Bug 17: pipeline errors, hooks, profile, sync wrapper
# ─────────────────────────────────────────────────────────────────────


def _engine_without_collection(cfg: CloudGConfig, coverage=None, assets=None) -> CloudGEngine:
    engine = CloudGEngine(cfg)

    async def fake_collect():
        return CollectionResult(assets=assets or [], coverage=coverage or [])

    engine.collect = fake_collect  # type: ignore[method-assign]
    return engine


class TestPipeline:
    def test_on_finding_fires_per_scanner_with_copies(self, fake_plugins, tmp_path):
        cfg = CloudGConfig()
        cfg.scanners.enabled = ["fastscan", "slowscan"]
        engine = CloudGEngine(cfg)
        received: list[Finding] = []

        def on_finding(f: Finding) -> None:
            received.append(f)
            if f.title == "fast":
                RELEASE_SLOW.set()  # only possible while slowscan still runs

        engine.on_finding = on_finding
        findings = asyncio.run(engine.scan([], [], output_dir=tmp_path))
        titles = [f.title for f in received]
        assert titles == ["fast", "slow-released"]
        # copies: changing what the hook got leaves the scan results alone
        received[0].title = "changed by the hook"
        assert sorted(f.title for f in findings) == ["fast", "slow-released"]

    def test_errors_record_collection_scanner_and_analysis_failures(
        self, fake_plugins, tmp_path, monkeypatch
    ):
        import cloudg.graph.ontology as ontology

        def broken_build(self, *args, **kwargs):
            raise RuntimeError("ontology broke")

        monkeypatch.setattr(ontology.CloudOntology, "build", broken_build)
        cov = CollectionCoverage(provider="aws", region="eu-west-1", account_id="111111111111")
        cov.record("aws_full", ServiceStatus.FAILED, error="AccessDenied")
        cfg = CloudGConfig()
        cfg.scanners.enabled = ["brokenscan"]
        cfg.rag.enabled = False
        engine = _engine_without_collection(cfg, coverage=[cov])
        seen: list[str] = []
        engine.on_error = lambda phase, exc: seen.append(phase)

        result = asyncio.run(engine.run_pipeline(tmp_path))
        joined = "\n".join(result.errors)
        assert "collection: aws 111111111111/eu-west-1: AccessDenied" in joined
        assert "brokenscan: plugin exploded" in joined
        assert "ontology: ontology broke" in joined
        assert "brokenscan" in seen and "ontology" in seen
        assert engine._error_sink is None  # cleared after the run

    def test_run_pipeline_passes_the_configured_profile(self, tmp_path):
        cfg = CloudGConfig()
        cfg.aws.profile = "audit"
        cfg.scanners.enabled = []
        engine = _engine_without_collection(cfg)
        seen = {}
        original = engine.scan

        async def spy_scan(*args, **kwargs):
            seen.update(kwargs)
            return await original(*args, **kwargs)

        engine.scan = spy_scan  # type: ignore[method-assign]
        asyncio.run(engine.run_pipeline(tmp_path))
        assert seen["profile"] == "audit"

    def test_run_pipeline_sync_inside_a_running_loop(self, tmp_path):
        engine = CloudGEngine(CloudGConfig())

        async def call_sync():
            engine.run_pipeline_sync(tmp_path)

        with pytest.raises(RuntimeError, match="await engine.run_pipeline"):
            asyncio.run(call_sync())
        assert "notebook" not in (CloudGEngine.run_pipeline_sync.__doc__ or "").lower()

    def test_iam_linter_follows_scanners_enabled(self, tmp_path, monkeypatch):
        calls: list[int] = []
        monkeypatch.setattr(api_scanners, "scan_iam", lambda assets: calls.append(1) or [])
        cfg = CloudGConfig()
        cfg.scanners.enabled = ["checkov"]  # iam not enabled
        asyncio.run(CloudGEngine(cfg).scan([_asset()], [], output_dir=tmp_path))
        assert calls == []
        cfg.scanners.enabled = ["iam"]
        asyncio.run(CloudGEngine(cfg).scan([_asset()], [], output_dir=tmp_path))
        assert calls == [1]

    def test_engine_trivy_falls_back_to_a_filesystem_scan(self, tmp_path, monkeypatch):
        monkeypatch.setattr(api_scanners, "scanner_available", lambda name: True)
        seen = {}

        def fake_fs(config, dirs):
            seen["dirs"] = dirs
            return [_finding("fs", "trivy")]

        monkeypatch.setattr(api_scanners, "scan_trivy_fs", fake_fs)
        cfg = CloudGConfig()
        cfg.scanners.enabled = ["trivy"]
        findings = asyncio.run(
            CloudGEngine(cfg).scan([], [], iac_dir=str(tmp_path), output_dir=tmp_path)
        )
        assert seen["dirs"] == [str(tmp_path)]
        assert [f.title for f in findings] == ["fs"]

    def test_scanner_timeout_is_reported_and_partial_findings_kept(self, tmp_path, monkeypatch):
        monkeypatch.setattr(api_scanners, "scanner_available", lambda name: True)

        def partial(config, images):
            raise api_scanners.ScannerFailed(
                "Trivy", ["timed out after 60s scanning b"], [_finding("a", "trivy")]
            )

        monkeypatch.setattr(api_scanners, "scan_trivy_images", partial)
        cfg = CloudGConfig()
        cfg.scanners.enabled = ["trivy"]
        engine = CloudGEngine(cfg)
        errors: list[str] = []
        engine.on_error = lambda phase, exc: errors.append(f"{phase}: {exc}")
        findings = asyncio.run(engine.scan([], [], images=["a", "b"], output_dir=tmp_path))
        assert [f.title for f in findings] == ["a"]
        assert errors == ["trivy: Trivy timed out after 60s scanning b"]


# ─────────────────────────────────────────────────────────────────────
# Bug 7: scanners.timeout_seconds reaches the subprocess
# ─────────────────────────────────────────────────────────────────────


class TestScannerTimeouts:
    @pytest.fixture
    def cfg(self) -> CloudGConfig:
        cfg = CloudGConfig()
        cfg.scanners.timeout_seconds = 77
        return cfg

    def test_checkov_and_trivy_use_the_configured_timeout(self, cfg, monkeypatch):
        import cloudg.scanners.checkov as checkov
        import cloudg.scanners.trivy as trivy

        timeouts: list[int] = []

        def fake_run(cmd, **kwargs):
            timeouts.append(kwargs["timeout"])
            return SimpleNamespace(stdout="{}", returncode=0, stderr="")

        for module in (checkov, trivy):
            monkeypatch.setattr(module.shutil, "which", lambda name: "/usr/bin/x")
            monkeypatch.setattr(module.subprocess, "run", fake_run)
        api_scanners.scan_checkov(cfg, "infra")
        api_scanners.scan_trivy_images(cfg, ["nginx:latest"])
        api_scanners.scan_trivy_fs(cfg, ["infra"])
        assert timeouts == [77, 77, 77]

    def test_a_timeout_raises_scanner_failed(self, cfg, monkeypatch):
        import cloudg.scanners.checkov as checkov

        def timed_out(cmd, **kwargs):
            raise subprocess.TimeoutExpired(cmd, kwargs["timeout"])

        monkeypatch.setattr(checkov.shutil, "which", lambda name: "/usr/bin/checkov")
        monkeypatch.setattr(checkov.subprocess, "run", timed_out)
        with pytest.raises(api_scanners.ScannerFailed, match="timed out after 77s"):
            api_scanners.scan_checkov(cfg, "infra")

    def test_prowler_and_scoutsuite_use_the_configured_timeout(self, cfg, tmp_path, monkeypatch):
        import cloudg.scanners.prowler as prowler
        import cloudg.scanners.scoutsuite as scoutsuite

        waits: list[int] = []

        class FakeProc:
            stdout: list[str] = []
            returncode = 0

            def wait(self, timeout):
                waits.append(timeout)

            def kill(self):
                pass

        monkeypatch.setattr(prowler.shutil, "which", lambda name: "/usr/bin/prowler")
        monkeypatch.setattr(prowler.subprocess, "Popen", lambda *a, **k: FakeProc())
        monkeypatch.setattr(scoutsuite.shutil, "which", lambda name: "/usr/bin/scout")

        def fake_run(cmd, **kwargs):
            waits.append(kwargs["timeout"])
            return SimpleNamespace(stdout="", returncode=0, stderr="")

        monkeypatch.setattr(scoutsuite.subprocess, "run", fake_run)
        auth = (None, {})
        api_scanners.scan_prowler(cfg, "aws", None, tmp_path, auth)
        api_scanners.scan_scoutsuite(cfg, "aws", None, tmp_path, auth)
        assert waits == [77, 77]


# ─────────────────────────────────────────────────────────────────────
# Bug 8: Terraform output directory
# ─────────────────────────────────────────────────────────────────────


class TestTerraformOutputDir:
    def test_follows_the_run_output_unless_set(self, tmp_path):
        from cloudg.config import TerraformConfig
        from cloudg.renderers.terraform_export import terraform_output_dir

        assert terraform_output_dir(TerraformConfig(), tmp_path) == tmp_path / "terraform"
        legacy = TerraformConfig(output_dir="./reports/terraform")  # shipped config.yaml
        assert terraform_output_dir(legacy, tmp_path) == tmp_path / "terraform"
        custom = TerraformConfig(output_dir=str(tmp_path / "tf"))
        assert terraform_output_dir(custom, "elsewhere") == tmp_path / "tf"

    def test_engine_analyze_writes_under_output_dir(self, tmp_path):
        cfg = CloudGConfig()
        cfg.terraform.enabled = True
        cfg.ontology.enabled = False
        cfg.rag.enabled = False
        result = asyncio.run(CloudGEngine(cfg).analyze([_asset()], [], [], output_dir=tmp_path))
        assert result.terraform_paths["import_commands"] == tmp_path / "terraform" / (
            "import_commands.sh"
        )
        assert (tmp_path / "terraform" / "main.tf.json").exists()

    def test_cli_terraform_phase_follows_output(self, tmp_path):
        from cloudg.cli_run_helpers import _terraform_phase

        cfg = CloudGConfig()
        tf_dir = _terraform_phase(cfg, True, [_asset()], [], tmp_path)
        assert Path(tf_dir) == tmp_path / "terraform"
        assert (tmp_path / "terraform" / "import_commands.sh").exists()


# ─────────────────────────────────────────────────────────────────────
# Bugs 10 to 13: credentials and regions for scanners and discovery
# ─────────────────────────────────────────────────────────────────────


class _FrozenSession:
    region_name = "us-east-1"

    def get_credentials(self):
        frozen = SimpleNamespace(
            access_key="ASIAROLE", secret_key="role-secret", token="role-token"
        )
        return SimpleNamespace(get_frozen_credentials=lambda: frozen)


class TestScannerCredentials:
    def test_direct_keys_with_session_token(self):
        from cloudg.credentials import aws_scanner_auth

        cfg = AWSConfig(
            access_key_id="AKIAEXAMPLE", secret_access_key="secret", session_token="token"
        )
        assert aws_scanner_auth(cfg) == (
            None,
            {
                "AWS_ACCESS_KEY_ID": "AKIAEXAMPLE",
                "AWS_SECRET_ACCESS_KEY": "secret",
                "AWS_SESSION_TOKEN": "token",
            },
        )

    def test_profile_from_config(self):
        from cloudg.credentials import aws_scanner_auth

        assert aws_scanner_auth(AWSConfig(profile="audit")) == ("audit", {})

    def test_role_arn_is_assumed_and_exported(self, monkeypatch):
        import cloudg.credentials as credentials

        seen = {}

        def fake_build(cfg, region, account_id=None):
            seen["region"] = region
            return _FrozenSession()

        monkeypatch.setattr(credentials, "build_aws_session", fake_build)
        cfg = AWSConfig(role_arn="arn:aws:iam::111111111111:role/audit", profile="base")
        profile, env = credentials.aws_scanner_auth(cfg, "ALL")
        assert profile is None
        assert env["AWS_SESSION_TOKEN"] == "role-token"
        assert seen["region"] == "us-east-1"  # never "ALL"

    def test_engine_scanners_get_config_profile(self, tmp_path, monkeypatch):
        monkeypatch.setattr(api_scanners, "scanner_available", lambda name: True)
        seen = {}

        def fake_prowler(config, prov, profile, out, auth=None):
            seen["auth"] = auth
            return []

        monkeypatch.setattr(api_scanners, "scan_prowler", fake_prowler)
        cfg = CloudGConfig()
        cfg.aws.profile = "from-config"
        cfg.scanners.enabled = ["prowler"]
        asyncio.run(CloudGEngine(cfg).scan([], [], output_dir=tmp_path))
        assert seen["auth"] == ("from-config", {})

    def test_auth_failure_skips_aws_scanners_and_is_reported(self, tmp_path, monkeypatch):
        monkeypatch.setattr(api_scanners, "scanner_available", lambda name: True)

        def fail(config, profile):
            raise RuntimeError("AssumeRole failed")

        monkeypatch.setattr(api_scanners, "resolve_aws_scanner_auth", fail)
        cfg = CloudGConfig()
        cfg.scanners.enabled = ["prowler", "scoutsuite"]
        plan = api_scanners.plan_scanner_jobs(
            cfg,
            cfg.scanners.enabled,
            providers=["aws"],
            profile=None,
            out=tmp_path,
            assets=[],
            iac_dirs=[],
            images=[],
        )
        assert plan.jobs == []
        assert [phase for phase, _ in plan.errors] == ["scanner_auth"]  # resolved once


class TestScannerRegions:
    def test_prowler_gets_region_flags_and_never_all(self, monkeypatch):
        from cloudg.scanners.prowler import ProwlerScanner

        monkeypatch.setenv("AWS_DEFAULT_REGION", "ALL")
        scanner = ProwlerScanner(aws_regions=["ALL"], aws_region="ALL")
        assert "-f" not in scanner._build_command()
        assert "AWS_DEFAULT_REGION" not in scanner._build_env()

        scanner = ProwlerScanner(aws_regions=["eu-west-1", "us-east-1"], aws_region="eu-west-1")
        cmd = scanner._build_command()
        assert cmd[cmd.index("-f") :][:3] == ["-f", "eu-west-1", "us-east-1"]
        assert scanner._build_env()["AWS_DEFAULT_REGION"] == "eu-west-1"

        own = ProwlerScanner(aws_regions=["eu-west-1"], extra_args=["--region", "us-east-2"])
        assert "-f" not in own._build_command()

    def test_prowler_keys_replace_a_profile_in_the_environment(self, monkeypatch):
        from cloudg.scanners.prowler import ProwlerScanner

        monkeypatch.setenv("AWS_PROFILE", "someone-else")
        monkeypatch.setenv("AWS_SESSION_TOKEN", "stale")
        env = ProwlerScanner(aws_access_key_id="AKIA", aws_secret_access_key="s")._build_env()
        assert "AWS_PROFILE" not in env and "AWS_SESSION_TOKEN" not in env
        env = ProwlerScanner(
            aws_access_key_id="ASIA", aws_secret_access_key="s", aws_session_token="t"
        )._build_env()
        assert env["AWS_SESSION_TOKEN"] == "t"

    def test_scoutsuite_gets_regions(self):
        from cloudg.scanners.scoutsuite import ScoutSuiteScanner

        cmd = ScoutSuiteScanner(regions=["eu-west-1"])._build_command()
        assert cmd[cmd.index("--regions") :][:2] == ["--regions", "eu-west-1"]
        assert "--regions" not in ScoutSuiteScanner(regions=["ALL"])._build_command()
        assert (
            "--regions" not in ScoutSuiteScanner(provider="azure", regions=["x"])._build_command()
        )

    def test_scanner_regions_from_config(self):
        cfg = CloudGConfig()
        cfg.aws.regions = ["ALL"]
        assert api_scanners.scanner_regions(cfg) == []
        cfg.aws.regions = ["eu-west-1", "us-east-1"]
        assert api_scanners.scanner_regions(cfg) == ["eu-west-1", "us-east-1"]


class TestRegionDiscoveryCredentials:
    def test_discovery_uses_the_resolved_session(self, monkeypatch):
        import cloudg.credentials as credentials
        from cloudg.collectors.multi import MultiAccountCollector

        cfg = CloudGConfig()
        cfg.aws.profile = "audit"
        built = {}
        session = object()

        def fake_build(aws_cfg, region, account_id=None):
            built["profile"] = aws_cfg.profile
            return session

        async def fake_discover(self, sess=None):
            built["session"] = sess
            return ["eu-west-1"]

        monkeypatch.setattr(credentials, "build_aws_session", fake_build)
        monkeypatch.setattr("cloudg.region_discovery.RegionDiscovery.discover_aws", fake_discover)
        regions = asyncio.run(MultiAccountCollector(cfg)._discover_aws_regions(cfg.aws))
        assert regions == ["eu-west-1"]
        assert built == {"profile": "audit", "session": session}

    def test_auth_failure_falls_back_to_default_regions(self, monkeypatch):
        import cloudg.credentials as credentials
        from cloudg.collectors.multi import MultiAccountCollector
        from cloudg.region_discovery import AWS_DEFAULT_ENABLED_REGIONS

        def fail(aws_cfg, region, account_id=None):
            raise RuntimeError("AssumeRole failed")

        monkeypatch.setattr(credentials, "build_aws_session", fail)
        cfg = CloudGConfig()
        regions = asyncio.run(MultiAccountCollector(cfg)._discover_aws_regions(cfg.aws))
        assert regions == AWS_DEFAULT_ENABLED_REGIONS


# ─────────────────────────────────────────────────────────────────────
# Bug 15: member roles and OU filters
# ─────────────────────────────────────────────────────────────────────


class TestMemberRoles:
    def test_role_arn_is_chained_before_the_member_role(self):
        from cloudg.credentials import _aws_target_roles

        cfg = SimpleNamespace(role_name="OrgAudit")
        hop = "arn:aws:iam::111111111111:role/hop"
        assert _aws_target_roles(cfg, hop, False, "222222222222") == [
            hop,
            "arn:aws:iam::222222222222:role/OrgAudit",
        ]
        # Through OIDC the base session already is role_arn
        assert _aws_target_roles(cfg, hop, True, "222222222222") == [
            "arn:aws:iam::222222222222:role/OrgAudit"
        ]
        assert _aws_target_roles(cfg, hop, False, None) == [hop]

    def test_an_account_without_a_role_name_is_an_error(self):
        from cloudg.credentials import _aws_target_roles

        with pytest.raises(RuntimeError, match="role_name"):
            _aws_target_roles(SimpleNamespace(role_name=None), None, False, "222222222222")

    def test_check_aws_account_scope(self):
        from cloudg.credentials import check_aws_account_scope

        with pytest.raises(ValueError, match="--role-name"):
            check_aws_account_scope(AWSConfig(accounts=["222222222222"]))
        check_aws_account_scope(AWSConfig(accounts=["222222222222"], role_name="Audit"))
        org = AWSConfig(accounts=["222222222222"])
        org.organization.enabled = True
        check_aws_account_scope(org)

    def test_caller_account_is_looked_up_even_with_role_arn(self, monkeypatch):
        from cloudg.collectors.multi import MultiAccountCollector

        cfg = CloudGConfig()
        cfg.aws.accounts = ["111111111111", "222222222222"]
        cfg.aws.role_name = "OrgAudit"
        cfg.aws.role_arn = "arn:aws:iam::111111111111:role/hop"
        collector = MultiAccountCollector(cfg)
        monkeypatch.setattr(collector, "_lookup_caller_account", lambda c, r: "111111111111")
        targets: list[str | None] = []

        async def fake_single(account_id, region, aws_cfg, is_primary=True):
            targets.append(account_id)
            return [], []

        monkeypatch.setattr(collector, "_collect_aws_single", fake_single)
        asyncio.run(collector._collect_aws_multi())
        assert collector._caller_account == "111111111111"
        assert sorted(targets) == ["111111111111", "222222222222"]


class TestOrganizationScope:
    def _topology(self):
        from cloudg.inventory.organization import OrgAccount, OrganizationTopology, OrgUnit

        topo = OrganizationTopology()
        topo.roots = [OrgUnit(id="r-1", name="Root", arn="arn:root", parent_id=None, is_root=True)]
        topo.ous = {
            "ou-1": OrgUnit(
                id="ou-1",
                name="Workloads",
                arn="arn:aws:organizations::1:ou/o-1/ou-1",
                parent_id="r-1",
            )
        }
        topo.accounts = {
            "2": OrgAccount(id="2", name="prod", arn="a", status="ACTIVE", parent_id="ou-1")
        }
        return topo

    def test_unmatched_ou_is_an_error_listing_known_ous(self):
        from cloudg.inventory.organization import OrganizationScopeError

        topo = self._topology()
        with pytest.raises(OrganizationScopeError, match=r"Workloads \(ou-1\)"):
            topo.target_accounts(include_ous=["Workload"])

    def test_ou_by_arn(self):
        topo = self._topology()
        assert topo.target_accounts(include_ous=["arn:aws:organizations::1:ou/o-1/ou-1"]) == ["2"]

    def test_mapper_does_not_fall_back_to_the_caller_account(self, monkeypatch):
        from cloudg.inventory import InventoryMapper
        from cloudg.inventory.organization import OrganizationScopeError

        cfg = CloudGConfig()
        cfg.aws.organization.enabled = True
        mapper = InventoryMapper(cfg)

        def scope_error(c):
            raise OrganizationScopeError("OU filter 'x' matched no OU")

        monkeypatch.setattr(mapper, "_discover_organization", scope_error)
        with pytest.raises(OrganizationScopeError):
            asyncio.run(mapper._discover_aws_organization(cfg, []))
