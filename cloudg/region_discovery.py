"""Auto-discovery of cloud provider regions.

Queries each provider's APIs to enumerate available regions/locations,
with static fallbacks for air-gapped or credential-less environments.

Usage:
    discovery = RegionDiscovery()
    aws_regions = await discovery.discover_aws(session)
    azure_regions = await discovery.discover_azure(credential, subscription_id)
    gcp_regions = await discovery.discover_gcp(credentials, project_id)
"""

from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Static fallback lists (updated periodically)
# ---------------------------------------------------------------------------

AWS_REGIONS_FALLBACK: list[str] = [
    "us-east-1",
    "us-east-2",
    "us-west-1",
    "us-west-2",
    "af-south-1",
    "ap-east-1",
    "ap-south-1",
    "ap-south-2",
    "ap-southeast-1",
    "ap-southeast-2",
    "ap-southeast-3",
    "ap-southeast-4",
    "ap-northeast-1",
    "ap-northeast-2",
    "ap-northeast-3",
    "ca-central-1",
    "ca-west-1",
    "eu-central-1",
    "eu-central-2",
    "eu-west-1",
    "eu-west-2",
    "eu-west-3",
    "eu-south-1",
    "eu-south-2",
    "eu-north-1",
    "il-central-1",
    "me-south-1",
    "me-central-1",
    "sa-east-1",
]

# Regions enabled in every AWS account (no opt-in needed). Region discovery
# falls back to these: opt-in regions in AWS_REGIONS_FALLBACK fail with auth
# errors in accounts that have not enabled them.
AWS_DEFAULT_ENABLED_REGIONS: list[str] = [
    "us-east-1",
    "us-east-2",
    "us-west-1",
    "us-west-2",
    "ap-south-1",
    "ap-southeast-1",
    "ap-southeast-2",
    "ap-northeast-1",
    "ap-northeast-2",
    "ap-northeast-3",
    "ca-central-1",
    "eu-central-1",
    "eu-west-1",
    "eu-west-2",
    "eu-west-3",
    "eu-north-1",
    "sa-east-1",
]

AZURE_LOCATIONS_FALLBACK: list[str] = [
    "eastus",
    "eastus2",
    "westus",
    "westus2",
    "westus3",
    "centralus",
    "northcentralus",
    "southcentralus",
    "westcentralus",
    "canadacentral",
    "canadaeast",
    "brazilsouth",
    "brazilsoutheast",
    "northeurope",
    "westeurope",
    "uksouth",
    "ukwest",
    "francecentral",
    "francesouth",
    "germanywestcentral",
    "germanynorth",
    "switzerlandnorth",
    "switzerlandwest",
    "norwayeast",
    "norwaywest",
    "swedencentral",
    "polandcentral",
    "italynorth",
    "spaincentral",
    "eastasia",
    "southeastasia",
    "japaneast",
    "japanwest",
    "koreacentral",
    "koreasouth",
    "centralindia",
    "southindia",
    "westindia",
    "australiaeast",
    "australiasoutheast",
    "australiacentral",
    "uaenorth",
    "uaecentral",
    "southafricanorth",
    "southafricawest",
    "qatarcentral",
    "israelcentral",
]

GCP_REGIONS_FALLBACK: list[str] = [
    "us-central1",
    "us-east1",
    "us-east4",
    "us-east5",
    "us-south1",
    "us-west1",
    "us-west2",
    "us-west3",
    "us-west4",
    "northamerica-northeast1",
    "northamerica-northeast2",
    "southamerica-east1",
    "southamerica-west1",
    "europe-central2",
    "europe-north1",
    "europe-southwest1",
    "europe-west1",
    "europe-west2",
    "europe-west3",
    "europe-west4",
    "europe-west6",
    "europe-west8",
    "europe-west9",
    "europe-west10",
    "europe-west12",
    "asia-east1",
    "asia-east2",
    "asia-northeast1",
    "asia-northeast2",
    "asia-northeast3",
    "asia-south1",
    "asia-south2",
    "asia-southeast1",
    "asia-southeast2",
    "australia-southeast1",
    "australia-southeast2",
    "me-central1",
    "me-central2",
    "me-west1",
    "africa-south1",
]


# ---------------------------------------------------------------------------
# Region Discovery
# ---------------------------------------------------------------------------


class RegionDiscovery:
    """Auto-discovers available regions for each cloud provider.

    Falls back to static lists when APIs are unavailable.
    """

    async def discover_aws(self, session: Any = None) -> list[str]:
        """Discover all enabled AWS regions.

        Args:
            session: boto3.Session built from the run's resolved credentials
                (see cloudg.credentials.build_aws_session). If None, a
                default-chain session is used. The call goes to the
                session's region (us-east-1 when it has none).

        Returns:
            List of region names (e.g. ['us-east-1', 'eu-west-1', ...]).
            When the API call fails: the regions enabled by default in every
            account (AWS_DEFAULT_ENABLED_REGIONS), never opt-in regions.
        """
        try:
            import boto3

            sess = session or boto3.Session()
            region = getattr(sess, "region_name", None)
            if not isinstance(region, str) or not region or region.upper() == "ALL":
                region = "us-east-1"
            ec2 = sess.client("ec2", region_name=region)
            response = ec2.describe_regions(
                Filters=[{"Name": "opt-in-status", "Values": ["opt-in-not-required", "opted-in"]}]
            )
            regions = [r["RegionName"] for r in response.get("Regions", [])]
            if regions:
                logger.info("Discovered %d AWS regions via API", len(regions))
                return sorted(regions)
        except ImportError:
            logger.warning("boto3 not installed, using fallback AWS regions")
        except Exception as exc:
            logger.warning(
                "AWS region discovery failed (%s); scanning the %d regions enabled by "
                "default in every account. Pass --regions to choose them yourself.",
                exc,
                len(AWS_DEFAULT_ENABLED_REGIONS),
            )

        logger.info("Using %d fallback AWS regions", len(AWS_DEFAULT_ENABLED_REGIONS))
        return list(AWS_DEFAULT_ENABLED_REGIONS)

    async def discover_azure(
        self,
        credential: Any = None,
        subscription_id: str | None = None,
    ) -> list[str]:
        """Discover all Azure locations for a subscription.

        Args:
            credential: Azure credential object (optional).
            subscription_id: Azure subscription ID (optional).

        Returns:
            List of location names (e.g. ['eastus', 'westeurope', ...]).
        """
        try:
            from azure.identity import DefaultAzureCredential
            from azure.mgmt.resource import SubscriptionClient

            cred = credential or DefaultAzureCredential()
            client = SubscriptionClient(cred)

            if subscription_id:
                locations = client.subscriptions.list_locations(subscription_id)
                locs = [loc.name for loc in locations if loc.name]
            else:
                # If no subscription, try to get the first one
                subs = list(client.subscriptions.list())
                if subs:
                    sub_id = subs[0].subscription_id
                    locations = client.subscriptions.list_locations(sub_id)
                    locs = [loc.name for loc in locations if loc.name]
                else:
                    locs = []

            if locs:
                logger.info("Discovered %d Azure locations via API", len(locs))
                return sorted(locs)
        except ImportError:
            logger.warning("azure-mgmt-resource not installed, using fallback Azure locations")
        except Exception as exc:
            logger.warning("Azure location discovery failed (%s), using fallback", exc)

        logger.info("Using %d fallback Azure locations", len(AZURE_LOCATIONS_FALLBACK))
        return AZURE_LOCATIONS_FALLBACK

    async def discover_gcp(
        self,
        credentials: Any = None,
        project_id: str | None = None,
    ) -> list[str]:
        """Discover all GCP regions for a project.

        Args:
            credentials: Google auth credentials (optional).
            project_id: GCP project ID (optional).

        Returns:
            List of region names (e.g. ['us-central1', 'europe-west1', ...]).
        """
        try:
            from googleapiclient import discovery as gcp_discovery
            import google.auth

            creds = credentials
            pid = project_id

            if not creds:
                creds, default_project = google.auth.default()
                pid = pid or default_project

            if not pid:
                raise ValueError("GCP project ID required for region discovery")

            service = gcp_discovery.build("compute", "v1", credentials=creds)
            request = service.regions().list(project=pid)
            response = request.execute()

            regions = [r["name"] for r in response.get("items", []) if r.get("status") == "UP"]

            if regions:
                logger.info("Discovered %d GCP regions via API", len(regions))
                return sorted(regions)
        except ImportError:
            logger.warning("google-api-python-client not installed, using fallback GCP regions")
        except Exception as exc:
            logger.warning("GCP region discovery failed (%s), using fallback", exc)

        logger.info("Using %d fallback GCP regions", len(GCP_REGIONS_FALLBACK))
        return GCP_REGIONS_FALLBACK

    async def discover_all(
        self,
        providers: list[str],
        aws_session: Any = None,
        azure_credential: Any = None,
        azure_subscription_id: str | None = None,
        gcp_credentials: Any = None,
        gcp_project_id: str | None = None,
    ) -> dict[str, list[str]]:
        """Discover regions for all specified providers.

        Args:
            providers: List of provider names ('aws', 'azure', 'gcp').

        Returns:
            Dict mapping provider name → list of regions.
        """
        import asyncio

        result: dict[str, list[str]] = {}
        tasks: dict[str, Any] = {}

        if "aws" in providers:
            tasks["aws"] = self.discover_aws(aws_session)
        if "azure" in providers:
            tasks["azure"] = self.discover_azure(azure_credential, azure_subscription_id)
        if "gcp" in providers:
            tasks["gcp"] = self.discover_gcp(gcp_credentials, gcp_project_id)

        if tasks:
            gathered = await asyncio.gather(*tasks.values(), return_exceptions=True)
            for provider, regions_or_exc in zip(tasks.keys(), gathered):
                if isinstance(regions_or_exc, Exception):
                    logger.error("Region discovery failed for %s: %s", provider, regions_or_exc)
                    # Use fallback
                    fallbacks = {
                        "aws": AWS_DEFAULT_ENABLED_REGIONS,
                        "azure": AZURE_LOCATIONS_FALLBACK,
                        "gcp": GCP_REGIONS_FALLBACK,
                    }
                    result[provider] = fallbacks.get(provider, [])
                else:
                    result[provider] = regions_or_exc

        return result


def is_all_regions(regions: list[str]) -> bool:
    """Check if the region list is the 'ALL' sentinel."""
    return len(regions) == 1 and regions[0].upper() == "ALL"
