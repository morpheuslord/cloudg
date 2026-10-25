"""The public exception hierarchy and how the scanner wrappers use it."""

from __future__ import annotations

import subprocess

import pytest

import cloudg
from cloudg import exceptions as exc
from cloudg.scanners.checkov import CheckovScanner
from cloudg.scanners.iam_linter import IAMLinter
from cloudg.scanners.prowler import ProwlerScanner
from cloudg.scanners.scoutsuite import ScoutSuiteScanner
from cloudg.scanners.trivy import TrivyScanner


class TestHierarchy:
    def test_everything_derives_from_cloudg_error(self):
        for name in exc.__all__:
            assert issubclass(getattr(exc, name), exc.CloudGError), name

    def test_builtin_bases_are_kept(self):
        assert issubclass(exc.ConfigurationError, ValueError)
        assert issubclass(exc.ProviderSDKMissingError, ImportError)
        assert issubclass(exc.CollectionError, RuntimeError)
        assert issubclass(exc.CredentialError, RuntimeError)
        assert issubclass(exc.OrganizationScopeError, ValueError)
        assert issubclass(exc.ScannerFailed, RuntimeError)
        assert issubclass(exc.ReportParseError, exc.ScannerOutputError)

    def test_exported_from_the_package(self):
        assert cloudg.ScannerError is exc.ScannerError
        assert cloudg.CloudGError is exc.CloudGError

    def test_old_import_paths_still_work(self):
        from cloudg.api_scanners import ScannerFailed
        from cloudg.inventory.organization import OrganizationScopeError

        assert ScannerFailed is exc.ScannerFailed
        assert OrganizationScopeError is exc.OrganizationScopeError

    def test_resilience_errors_join_the_hierarchy(self):
        from cloudg.resilience import CircuitOpenError, LiveOperationRejected

        assert issubclass(CircuitOpenError, exc.CloudGError)
        assert issubclass(LiveOperationRejected, exc.CloudGError)

    def test_scanner_failed_keeps_its_message(self):
        failed = exc.ScannerFailed("trivy", ["a", "b"], ["partial"])
        assert str(failed) == "trivy a; b"
        assert failed.findings == ["partial"]
        assert failed.scanner == "trivy"

    def test_sdk_missing_message_names_the_extra(self):
        err = exc.ProviderSDKMissingError("gcp", missing="google-auth")
        assert "pip install 'cloudg[gcp]'" in str(err)
        assert err.missing == "google-auth"

    def test_timeout_detail_matches_the_recorded_text(self):
        err = exc.ScannerTimeoutError("checkov", 1800, target="infra")
        assert err.detail == "timed out after 1800s scanning infra"
        assert err.timeout_seconds == 1800


def _no_binary(monkeypatch):
    monkeypatch.setattr("shutil.which", lambda _name: None)


def _binary(monkeypatch):
    monkeypatch.setattr("shutil.which", lambda name: f"/usr/bin/{name}")


class TestScannerRecording:
    @pytest.mark.parametrize(
        "make, run",
        [
            (lambda **kw: CheckovScanner(**kw), lambda s: s.run()),
            (lambda **kw: ProwlerScanner(**kw), lambda s: s.run()),
            (lambda **kw: ScoutSuiteScanner(**kw), lambda s: s.run()),
            (lambda **kw: TrivyScanner(**kw), lambda s: s.scan_image("app:1")),
        ],
    )
    def test_missing_binary(self, monkeypatch, make, run):
        _no_binary(monkeypatch)
        lenient = make()
        assert run(lenient) == []
        assert lenient.errors == []
        lenient.raise_for_errors()  # nothing recorded, nothing raised

        with pytest.raises(exc.ScannerNotInstalledError) as info:
            run(make(strict=True))
        assert info.value.executable

    def test_timeout_is_recorded_then_raised(self, monkeypatch):
        _binary(monkeypatch)

        def boom(*_a, **_k):
            raise subprocess.TimeoutExpired("checkov", 5)

        monkeypatch.setattr(subprocess, "run", boom)
        scanner = CheckovScanner(target_dir="infra", timeout_seconds=5)
        assert scanner.run() == []
        assert scanner.errors == ["timed out after 5s scanning infra"]
        assert isinstance(scanner.failures[0], exc.ScannerTimeoutError)
        with pytest.raises(exc.ScannerTimeoutError):
            scanner.raise_for_errors()

        with pytest.raises(exc.ScannerTimeoutError):
            CheckovScanner(target_dir="infra", timeout_seconds=5, strict=True).run()

    def test_launch_failure(self, monkeypatch):
        _binary(monkeypatch)

        def boom(*_a, **_k):
            raise OSError("permission denied")

        monkeypatch.setattr(subprocess, "run", boom)
        scanner = TrivyScanner()
        scanner.scan_images(["a:1", "b:2"])
        assert len(scanner.errors) == 2
        with pytest.raises(exc.ScannerFailed) as info:
            scanner.raise_for_errors()
        assert all(isinstance(f, exc.ScannerExecutionError) for f in info.value.failures)

    def test_bad_output_is_a_failure_but_not_an_error(self):
        scanner = CheckovScanner()
        assert scanner._parse_output("{not json") == []
        assert scanner.errors == []
        assert isinstance(scanner.failures[0], exc.ScannerOutputError)
        with pytest.raises(exc.ScannerOutputError):
            scanner.raise_for_errors()

    def test_parliament_failure_is_recorded(self, monkeypatch):
        linter = IAMLinter()
        linter._parliament_available = True

        class Asset:
            name = "role/x"

        import sys
        import types

        fake = types.ModuleType("parliament")

        def analyze(_doc):
            raise RuntimeError("bad policy")

        fake.analyze_policy_string = analyze
        monkeypatch.setitem(sys.modules, "parliament", fake)
        linter._lint_with_parliament("{}", Asset())
        assert isinstance(linter.failures[0], exc.ScannerExecutionError)


class TestParseReport:
    @pytest.mark.parametrize(
        "scanner", [CheckovScanner, TrivyScanner, ProwlerScanner, ScoutSuiteScanner]
    )
    def test_strict_parse_report_raises_on_garbage(self, tmp_path, scanner):
        bad = tmp_path / ("scoutsuite_results_x.js" if scanner is ScoutSuiteScanner else "r.json")
        bad.write_text("this is not a report")
        assert scanner.parse_report(str(bad)) == []
        with pytest.raises(exc.ReportParseError):
            scanner.parse_report(str(bad), strict=True)

    def test_strict_parse_report_raises_on_empty_dir(self, tmp_path):
        with pytest.raises(exc.ReportParseError):
            CheckovScanner.parse_report(str(tmp_path), strict=True)
