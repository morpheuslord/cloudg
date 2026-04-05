"""Tests for the CloudMapper programmatic API."""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from cloudmapper.api import (
    AnalysisResult,
    CloudMapperEngine,
    CollectionResult,
    PipelineResult,
)
from cloudmapper.config import CloudMapperConfig


# ── Result Dataclass Tests ──


class TestPipelineResult:
    def test_empty_result(self):
        result = PipelineResult()
        assert result.total_assets == 0
        assert result.total_findings == 0

    def test_severity_breakdown_empty(self):
        result = PipelineResult()
        assert result.severity_breakdown == {}

    def test_to_summary_keys(self):
        result = PipelineResult(
            providers_scanned=["aws", "azure"],
            duration_ms=5000,
        )
        summary = result.to_summary()
        assert "total_assets" in summary
        assert "total_findings" in summary
        assert "providers_scanned" in summary
        assert summary["providers_scanned"] == ["aws", "azure"]
        assert summary["duration_ms"] == 5000


class TestCollectionResult:
    def test_defaults(self):
        result = CollectionResult()
        assert result.assets == []
        assert result.edges == []
        assert result.duration_ms == 0

    def test_with_data(self):
        result = CollectionResult(
            providers_scanned=["aws"],
            regions_scanned={"aws": ["us-east-1"]},
            duration_ms=1234,
        )
        assert result.providers_scanned == ["aws"]
        assert result.regions_scanned["aws"] == ["us-east-1"]


class TestAnalysisResult:
    def test_defaults(self):
        result = AnalysisResult()
        assert result.graph_nodes == 0
        assert result.ontology_triples == 0
        assert result.rag_chunks_path is None


# ── Engine Tests ──


class TestCloudMapperEngine:
    def test_engine_instantiation(self):
        """Engine should be instantiable with a config."""
        config = CloudMapperConfig()
        engine = CloudMapperEngine(config)
        assert engine.config is config

    def test_engine_default_hooks_are_none(self):
        config = CloudMapperConfig()
        engine = CloudMapperEngine(config)
        assert engine.on_collection_complete is None
        assert engine.on_scan_complete is None
        assert engine.on_finding is None
        assert engine.on_analysis_complete is None
        assert engine.on_phase_start is None
        assert engine.on_error is None

    def test_engine_hooks_settable(self):
        """Event hooks should be assignable."""
        config = CloudMapperConfig()
        engine = CloudMapperEngine(config)

        called = {"phase": None}

        def on_phase(name):
            called["phase"] = name

        engine.on_phase_start = on_phase
        engine._emit_phase_start("test_phase")
        assert called["phase"] == "test_phase"

    def test_engine_error_hook(self):
        """Error hook should capture exceptions."""
        config = CloudMapperConfig()
        engine = CloudMapperEngine(config)

        errors = []

        def on_err(phase, exc):
            errors.append((phase, str(exc)))

        engine.on_error = on_err
        engine._emit_error("test", ValueError("boom"))
        assert len(errors) == 1
        assert errors[0] == ("test", "boom")

    def test_multi_provider_config(self):
        """Engine with multi-provider config should preserve providers."""
        config = CloudMapperConfig(providers=["aws", "azure", "gcp"])
        engine = CloudMapperEngine(config)
        assert engine.config.providers == ["aws", "azure", "gcp"]


# ── Config Backward Compat Tests ──


class TestConfigBackwardCompat:
    def test_single_provider_string(self):
        """Old-style 'provider: azure' should auto-migrate to providers list."""
        config = CloudMapperConfig(provider="azure")
        assert config.providers == ["azure"]

    def test_providers_list_takes_precedence(self):
        """If providers list is explicitly set, it should be used."""
        config = CloudMapperConfig(providers=["aws", "gcp"])
        assert config.providers == ["aws", "gcp"]

    def test_default_is_aws(self):
        """Default provider should be aws."""
        config = CloudMapperConfig()
        assert config.providers == ["aws"]

    def test_all_regions_azure(self):
        """Azure config should default to ALL regions."""
        config = CloudMapperConfig()
        assert config.azure.regions == ["ALL"]

    def test_all_regions_gcp(self):
        """GCP config should default to ALL regions."""
        config = CloudMapperConfig()
        assert config.gcp.regions == ["ALL"]
