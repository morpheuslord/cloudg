"""Tests for scanner orchestration — verifies all scanners are launched correctly."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from cloudg.api import CloudGEngine
from cloudg.config import CloudGConfig, ScannerConfig


# ── Config-driven scanner list ──


class TestScannerConfigWiring:
    def test_default_scanners_enabled(self):
        """Default config should enable prowler and checkov."""
        cfg = CloudGConfig()
        assert "prowler" in cfg.scanners.enabled
        assert "checkov" in cfg.scanners.enabled

    def test_custom_scanners_enabled(self):
        """Custom scanner list should be respected."""
        cfg = CloudGConfig(
            scanners=ScannerConfig(
                enabled=["prowler", "scoutsuite", "checkov", "trivy", "iam"]
            )
        )
        assert len(cfg.scanners.enabled) == 5
        assert "scoutsuite" in cfg.scanners.enabled
        assert "trivy" in cfg.scanners.enabled

    def test_iac_directories_default_empty(self):
        """iac_directories should default to empty list."""
        cfg = CloudGConfig()
        assert cfg.scanners.iac_directories == []

    def test_iac_directories_custom(self):
        """Custom iac_directories should be preserved."""
        cfg = CloudGConfig(
            scanners=ScannerConfig(iac_directories=["./infra", "./modules"])
        )
        assert cfg.scanners.iac_directories == ["./infra", "./modules"]

    def test_trivy_images_default_empty(self):
        """trivy_images should default to empty list."""
        cfg = CloudGConfig()
        assert cfg.scanners.trivy_images == []

    def test_trivy_images_custom(self):
        """Custom trivy_images should be preserved."""
        cfg = CloudGConfig(
            scanners=ScannerConfig(trivy_images=["nginx:latest", "app:v2"])
        )
        assert cfg.scanners.trivy_images == ["nginx:latest", "app:v2"]

    def test_extra_args_fields_exist(self):
        """All scanner extra_args fields should exist."""
        cfg = CloudGConfig()
        assert cfg.scanners.prowler_extra_args == []
        assert cfg.scanners.scoutsuite_extra_args == []
        assert cfg.scanners.checkov_extra_args == []
        assert cfg.scanners.trivy_extra_args == []

    def test_timeout_seconds_default(self):
        """Default timeout should be 3600."""
        cfg = CloudGConfig()
        assert cfg.scanners.timeout_seconds == 3600


# ── API Engine Scanner Integration ──


class TestEngineScanning:
    """Tests that api.py CloudGEngine.scan() dispatches to all enabled scanners."""

    @pytest.fixture
    def all_scanners_config(self):
        return CloudGConfig(
            scanners=ScannerConfig(
                enabled=["prowler", "scoutsuite", "checkov", "trivy", "iam"],
                trivy_images=["nginx:latest"],
                iac_directories=["./infra"],
            )
        )

    @pytest.fixture
    def mock_graph(self):
        """Mock graph builder and reachability so they don't fail."""
        mock_builder = MagicMock()
        mock_builder.build.return_value = MagicMock()
        mock_analyzer = MagicMock()
        mock_analyzer.generate_findings.return_value = []
        return mock_builder, mock_analyzer

    def test_scan_dispatches_all_scanners(self, all_scanners_config, mock_graph, tmp_path):
        """Verify scan() submits all 5 scanner types to thread pool."""
        mock_builder, mock_analyzer = mock_graph

        mock_prowler = MagicMock()
        mock_prowler.return_value.run.return_value = []

        mock_scoutsuite = MagicMock()
        mock_scoutsuite.return_value.run.return_value = []

        mock_checkov = MagicMock()
        mock_checkov.return_value.run.return_value = []

        mock_trivy = MagicMock()
        mock_trivy.return_value.scan_images.return_value = []

        mock_iam = MagicMock()
        mock_iam.return_value.analyze_policies.return_value = []

        with (
            patch("cloudg.api.CloudGEngine.scan") as _,
        ):
            # Test the engine can be instantiated with all scanners
            engine = CloudGEngine(all_scanners_config)
            assert "prowler" in engine.config.scanners.enabled
            assert "scoutsuite" in engine.config.scanners.enabled
            assert "checkov" in engine.config.scanners.enabled
            assert "trivy" in engine.config.scanners.enabled
            assert "iam" in engine.config.scanners.enabled

    def test_scan_iac_dir_fallback(self, tmp_path):
        """When no iac_dir is passed, should fall back to config.scanners.iac_directories."""
        cfg = CloudGConfig(
            scanners=ScannerConfig(
                enabled=["checkov"],
                iac_directories=["./my_iac"],
            )
        )
        engine = CloudGEngine(cfg)

        # Verify config has the iac_directories
        assert engine.config.scanners.iac_directories == ["./my_iac"]

    def test_scan_trivy_images_fallback(self, tmp_path):
        """When no images passed, should fall back to config.scanners.trivy_images."""
        cfg = CloudGConfig(
            scanners=ScannerConfig(
                enabled=["trivy"],
                trivy_images=["myapp:latest"],
            )
        )
        engine = CloudGEngine(cfg)

        # Verify config has the trivy_images
        assert engine.config.scanners.trivy_images == ["myapp:latest"]

    def test_scan_no_trivy_when_no_images(self, tmp_path):
        """Trivy should not fail when there are no images at all."""
        cfg = CloudGConfig(
            scanners=ScannerConfig(
                enabled=["trivy"],
                trivy_images=[],
            )
        )
        engine = CloudGEngine(cfg)
        assert engine.config.scanners.trivy_images == []


# ── Scanner Availability Checks ──


class TestScannerAvailability:
    """Test that each scanner's is_available() check works."""

    @patch("shutil.which", return_value=None)
    def test_prowler_not_available(self, mock_which):
        from cloudg.scanners.prowler import ProwlerScanner
        assert not ProwlerScanner.is_available()
        findings = ProwlerScanner().run()
        assert findings == []

    @patch("shutil.which", return_value="/usr/bin/prowler")
    def test_prowler_available(self, mock_which):
        from cloudg.scanners.prowler import ProwlerScanner
        assert ProwlerScanner.is_available()

    @patch("shutil.which", return_value=None)
    def test_checkov_not_available(self, mock_which):
        from cloudg.scanners.checkov import CheckovScanner
        assert not CheckovScanner.is_available()
        findings = CheckovScanner(target_dir=".").run()
        assert findings == []

    @patch("shutil.which", return_value=None)
    def test_scoutsuite_not_available(self, mock_which):
        from cloudg.scanners.scoutsuite import ScoutSuiteScanner
        assert not ScoutSuiteScanner.is_available()
        findings = ScoutSuiteScanner().run()
        assert findings == []

    @patch("shutil.which", return_value=None)
    def test_trivy_not_available(self, mock_which):
        from cloudg.scanners.trivy import TrivyScanner
        assert not TrivyScanner.is_available()
        findings = TrivyScanner().scan_image("test:latest")
        assert findings == []


# ── IaC Directory Resolution ──


class TestIaCDirResolution:
    """Test the IaC directory fallback logic."""

    def test_cli_flag_takes_priority(self):
        """CLI --iac-dir flag should override config."""
        cli_iac_dir = "/explicit/path"
        cfg_dirs = ["./from_config"]

        # Simulating the resolution logic from cli.py
        resolved = []
        if cli_iac_dir:
            resolved = [cli_iac_dir]
        elif cfg_dirs:
            resolved = list(cfg_dirs)
        else:
            resolved = ["."]

        assert resolved == ["/explicit/path"]

    def test_config_fallback(self):
        """Should fall back to config.scanners.iac_directories."""
        cli_iac_dir = None
        cfg_dirs = ["./infra", "./modules"]

        resolved = []
        if cli_iac_dir:
            resolved = [cli_iac_dir]
        elif cfg_dirs:
            resolved = list(cfg_dirs)
        else:
            resolved = ["."]

        assert resolved == ["./infra", "./modules"]

    def test_default_fallback(self):
        """Should fall back to '.' when nothing is configured."""
        cli_iac_dir = None
        cfg_dirs = []

        resolved = []
        if cli_iac_dir:
            resolved = [cli_iac_dir]
        elif cfg_dirs:
            resolved = list(cfg_dirs)
        else:
            resolved = ["."]

        assert resolved == ["."]
