"""Tests for region auto-discovery and the ALL sentinel."""

from __future__ import annotations

import asyncio
from unittest.mock import MagicMock, patch


from cloudg.region_discovery import (
    AWS_DEFAULT_ENABLED_REGIONS,
    AWS_REGIONS_FALLBACK,
    AZURE_LOCATIONS_FALLBACK,
    GCP_REGIONS_FALLBACK,
    RegionDiscovery,
    is_all_regions,
)


def _run(coro):
    """Run async coroutine synchronously."""
    return asyncio.run(coro)


# ── Sentinel Tests ──


class TestIsAllRegions:
    def test_all_uppercase(self):
        assert is_all_regions(["ALL"]) is True

    def test_all_lowercase(self):
        assert is_all_regions(["all"]) is True

    def test_all_mixed_case(self):
        assert is_all_regions(["All"]) is True

    def test_specific_region(self):
        assert is_all_regions(["us-east-1"]) is False

    def test_multiple_regions(self):
        assert is_all_regions(["us-east-1", "eu-west-1"]) is False

    def test_empty_list(self):
        assert is_all_regions([]) is False

    def test_all_with_extras(self):
        assert is_all_regions(["ALL", "us-east-1"]) is False


# ── Fallback Tests ──


class TestFallbackLists:
    def test_aws_fallback_non_empty(self):
        assert len(AWS_REGIONS_FALLBACK) >= 25

    def test_aws_fallback_has_us_east_1(self):
        assert "us-east-1" in AWS_REGIONS_FALLBACK

    def test_azure_fallback_non_empty(self):
        assert len(AZURE_LOCATIONS_FALLBACK) >= 30

    def test_azure_fallback_has_eastus(self):
        assert "eastus" in AZURE_LOCATIONS_FALLBACK

    def test_gcp_fallback_non_empty(self):
        assert len(GCP_REGIONS_FALLBACK) >= 25

    def test_gcp_fallback_has_us_central1(self):
        assert "us-central1" in GCP_REGIONS_FALLBACK


# ── AWS Discovery Tests ──


class TestAWSDiscovery:
    def test_fallback_when_no_boto3(self):
        """Without boto3, should return fallback."""
        discovery = RegionDiscovery()
        with patch.dict("sys.modules", {"boto3": None}):
            regions = _run(discovery.discover_aws(session=None))
        # Falls back to the regions every account has enabled
        assert regions == AWS_DEFAULT_ENABLED_REGIONS

    def test_fallback_on_exception(self):
        """On API error, should return fallback."""
        discovery = RegionDiscovery()
        mock_session = MagicMock()
        mock_session.client.side_effect = Exception("Connection error")
        regions = _run(discovery.discover_aws(session=mock_session))
        assert regions == AWS_DEFAULT_ENABLED_REGIONS

    def test_fallback_has_no_opt_in_regions(self):
        """Opt-in regions (af-south-1, me-south-1, ...) fail in accounts
        that have not enabled them, so the fallback leaves them out."""
        assert "us-east-1" in AWS_DEFAULT_ENABLED_REGIONS
        for opt_in in ("af-south-1", "ap-east-1", "me-south-1", "il-central-1"):
            assert opt_in in AWS_REGIONS_FALLBACK
            assert opt_in not in AWS_DEFAULT_ENABLED_REGIONS

    def test_api_call_uses_the_session_and_its_region(self):
        """The given (resolved-credential) session is used, in its own region."""
        discovery = RegionDiscovery()
        mock_session = MagicMock()
        mock_session.region_name = "eu-west-1"
        mock_session.client.return_value.describe_regions.return_value = {
            "Regions": [{"RegionName": "eu-west-1"}]
        }
        assert _run(discovery.discover_aws(session=mock_session)) == ["eu-west-1"]
        mock_session.client.assert_called_once_with("ec2", region_name="eu-west-1")

    def test_api_success(self):
        """On successful API, should return discovered regions."""
        discovery = RegionDiscovery()
        mock_session = MagicMock()
        mock_ec2 = MagicMock()
        mock_session.client.return_value = mock_ec2
        mock_ec2.describe_regions.return_value = {
            "Regions": [
                {"RegionName": "us-east-1"},
                {"RegionName": "eu-west-1"},
                {"RegionName": "ap-southeast-1"},
            ]
        }
        regions = _run(discovery.discover_aws(session=mock_session))
        assert regions == ["ap-southeast-1", "eu-west-1", "us-east-1"]


# ── Azure Discovery Tests ──


class TestAzureDiscovery:
    def test_fallback_when_no_sdk(self):
        """Without azure SDK, should return fallback."""
        discovery = RegionDiscovery()
        regions = _run(discovery.discover_azure())
        # Should at least have fallback (SDK not installed in test env)
        assert len(regions) >= 20


# ── GCP Discovery Tests ──


class TestGCPDiscovery:
    def test_fallback_when_no_sdk(self):
        """Without GCP SDK, should return fallback."""
        discovery = RegionDiscovery()
        regions = _run(discovery.discover_gcp())
        assert len(regions) >= 20


# ── Multi-Provider Discovery Tests ──


class TestDiscoverAll:
    def test_discover_all_returns_dict(self):
        """discover_all should return dict mapping provider -> regions."""
        discovery = RegionDiscovery()
        result = _run(discovery.discover_all(["aws"]))
        assert "aws" in result
        assert len(result["aws"]) >= len(AWS_DEFAULT_ENABLED_REGIONS)

    def test_discover_all_multi_provider(self):
        """Multiple providers should all have entries."""
        discovery = RegionDiscovery()
        result = _run(discovery.discover_all(["aws", "azure", "gcp"]))
        assert "aws" in result
        assert "azure" in result
        assert "gcp" in result

    def test_discover_all_empty_providers(self):
        """Empty providers list should return empty dict."""
        discovery = RegionDiscovery()
        result = _run(discovery.discover_all([]))
        assert result == {}
