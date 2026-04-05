"""Multi-provider, multi-account, multi-region collection orchestrator.

Supports simultaneous scanning of AWS + Azure + GCP with:
- Region auto-discovery via RegionDiscovery
- Parallel provider execution via asyncio.gather
- Per-region iteration for Azure and GCP
- Coverage tracking per provider/region/account
"""

from __future__ import annotations

import asyncio
import logging
import time
from typing import Any

from cloudmapper.config import CloudMapperConfig
from cloudmapper.coverage import CollectionCoverage, ServiceStatus
from cloudmapper.region_discovery import RegionDiscovery, is_all_regions
from cloudmapper.schema.models import CloudAsset, CloudProvider, NetworkEdge

logger = logging.getLogger(__name__)


class MultiAccountCollector:
    """Orchestrates collection across multiple providers, accounts, and regions.

    For AWS: assumes IAM roles in target accounts via STS, iterates regions.
    For Azure: iterates subscriptions × locations.
    For GCP: iterates projects × regions.

    Uses asyncio.Semaphore to limit concurrent API calls.
    """

    def __init__(self, config: CloudMapperConfig) -> None:
        self._config = config
        self._semaphore = asyncio.Semaphore(config.concurrency_limit)
        self._coverage: list[CollectionCoverage] = []
        self._region_discovery = RegionDiscovery()
        self._resolved_regions: dict[str, list[str]] = {}

    async def collect_all(self) -> tuple[list[CloudAsset], list[NetworkEdge], list[CollectionCoverage]]:
        """Collect assets and edges from ALL configured providers simultaneously.

        Returns:
            Tuple of (all_assets, all_edges, coverage_records).
        """
        providers = self._config.providers
        all_assets: list[CloudAsset] = []
        all_edges: list[NetworkEdge] = []

        # Build tasks for each provider
        tasks: list[asyncio.Task] = []
        task_labels: list[str] = []

        if "aws" in providers:
            tasks.append(asyncio.ensure_future(self._collect_aws_multi()))
            task_labels.append("aws")

        if "azure" in providers:
            tasks.append(asyncio.ensure_future(self._collect_azure_multi()))
            task_labels.append("azure")

        if "gcp" in providers:
            tasks.append(asyncio.ensure_future(self._collect_gcp_multi()))
            task_labels.append("gcp")

        if not tasks:
            logger.warning("No providers configured for collection")
            return all_assets, all_edges, self._coverage

        # Execute all providers in parallel
        logger.info("Starting multi-provider collection for: %s", ", ".join(task_labels))
        results = await asyncio.gather(*tasks, return_exceptions=True)

        for label, result in zip(task_labels, results):
            if isinstance(result, Exception):
                logger.error("Provider %s collection failed: %s", label, result)
                coverage = CollectionCoverage(provider=label)
                coverage.record(f"{label}_full", ServiceStatus.FAILED, error=str(result))
                self._coverage.append(coverage)
            elif isinstance(result, list):
                for assets, edges in result:
                    all_assets.extend(assets)
                    all_edges.extend(edges)

        logger.info(
            "Multi-provider collection complete: %d assets, %d edges across %d coverage records (%s)",
            len(all_assets), len(all_edges), len(self._coverage), ", ".join(task_labels),
        )
        return all_assets, all_edges, self._coverage

    # ------------------------------------------------------------------
    # AWS
    # ------------------------------------------------------------------

    async def _collect_aws_multi(self) -> list[tuple[list[CloudAsset], list[NetworkEdge]]]:
        """Iterate AWS accounts × regions."""
        cfg = self._config.aws
        accounts = cfg.accounts or [None]  # None = current account

        # Region resolution
        if is_all_regions(cfg.regions):
            logger.info("AWS: discovering all regions...")
            regions = await self._region_discovery.discover_aws()
        else:
            regions = cfg.regions

        self._resolved_regions["aws"] = regions
        logger.info("AWS: scanning %d regions × %d accounts", len(regions), len(accounts))

        tasks = []
        for account_id in accounts:
            for region in regions:
                tasks.append(self._collect_aws_single(account_id, region, cfg))

        return await asyncio.gather(*tasks, return_exceptions=False)

    async def _collect_aws_single(
        self,
        account_id: str | None,
        region: str,
        cfg: Any,
    ) -> tuple[list[CloudAsset], list[NetworkEdge]]:
        """Collect from a single AWS account/region.

        Credential priority:
        1. Direct access keys (access_key_id + secret_access_key) from config
        2. AWS profile from config
        3. Environment defaults (AWS_PROFILE, instance metadata, etc.)

        Role assumption is only used when role_name is set AND account_id is specified.
        """
        coverage = CollectionCoverage(
            provider="aws", region=region, account_id=account_id
        )
        self._coverage.append(coverage)

        async with self._semaphore:
            try:
                import boto3

                # Build session from credentials
                session_kwargs: dict[str, str] = {"region_name": region}

                if cfg.access_key_id and cfg.secret_access_key:
                    # Direct access keys provided — use them
                    session_kwargs["aws_access_key_id"] = cfg.access_key_id
                    session_kwargs["aws_secret_access_key"] = cfg.secret_access_key
                    if cfg.session_token:
                        session_kwargs["aws_session_token"] = cfg.session_token
                    logger.info("Using direct access keys for region %s", region)
                elif cfg.profile:
                    session_kwargs["profile_name"] = cfg.profile
                    logger.info("Using AWS profile '%s' for region %s", cfg.profile, region)
                else:
                    logger.info("Using default AWS credential chain for region %s", region)

                session = boto3.Session(**session_kwargs)

                # Optional cross-account role assumption
                if account_id and cfg.role_name:
                    sts = session.client("sts")
                    role_arn = f"arn:aws:iam::{account_id}:role/{cfg.role_name}"
                    logger.info("Assuming role %s in %s", role_arn, region)

                    try:
                        assumed = sts.assume_role(
                            RoleArn=role_arn,
                            RoleSessionName="cloudmapper-scan",
                            DurationSeconds=3600,
                        )
                        creds = assumed["Credentials"]
                        session = boto3.Session(
                            aws_access_key_id=creds["AccessKeyId"],
                            aws_secret_access_key=creds["SecretAccessKey"],
                            aws_session_token=creds["SessionToken"],
                            region_name=region,
                        )
                    except Exception as exc:
                        logger.error("Failed to assume role %s: %s", role_arn, exc)
                        coverage.record("sts_assume_role", ServiceStatus.FAILED, error=str(exc))
                        return [], []

                # Resolve account ID if not provided
                if not account_id:
                    try:
                        account_id = session.client("sts").get_caller_identity().get("Account")
                    except Exception:
                        account_id = "unknown"

                from cloudmapper.collectors.aws import AsyncAWSCollector

                collector = AsyncAWSCollector(
                    session=session, region=region, account_id=account_id
                )

                start = time.time()
                assets = await collector.collect()
                edges = await collector.collect_edges()
                duration_ms = int((time.time() - start) * 1000)

                coverage.record(
                    "aws_full", ServiceStatus.SUCCESS,
                    asset_count=len(assets), duration_ms=duration_ms,
                )
                return assets, edges

            except Exception as exc:
                logger.error("AWS collection failed for %s/%s: %s", account_id, region, exc)
                coverage.record("aws_full", ServiceStatus.FAILED, error=str(exc))
                return [], []

    # ------------------------------------------------------------------
    # Azure
    # ------------------------------------------------------------------

    async def _collect_azure_multi(self) -> list[tuple[list[CloudAsset], list[NetworkEdge]]]:
        """Iterate Azure subscriptions × locations."""
        sub_ids = self._config.azure.subscription_ids
        if not sub_ids:
            sub_ids = [None]

        # Region resolution
        azure_regions = self._config.azure.regions
        if is_all_regions(azure_regions):
            logger.info("Azure: discovering all locations...")
            first_sub = sub_ids[0] if sub_ids[0] else None
            try:
                from azure.identity import DefaultAzureCredential
                cred = DefaultAzureCredential()
            except ImportError:
                cred = None
            azure_regions = await self._region_discovery.discover_azure(cred, first_sub)
        
        self._resolved_regions["azure"] = azure_regions
        logger.info("Azure: scanning %d subscriptions (locations auto-handled by SDK)", len(sub_ids))

        # Azure SDKs already return resources across all locations within a subscription.
        # We pass the resolved regions as metadata but don't iterate per-region for Azure
        # since list_all() calls return resources from ALL locations.
        tasks = [self._collect_azure_single(sid) for sid in sub_ids]
        return await asyncio.gather(*tasks, return_exceptions=False)

    async def _collect_azure_single(
        self, subscription_id: str | None
    ) -> tuple[list[CloudAsset], list[NetworkEdge]]:
        """Collect from a single Azure subscription."""
        coverage = CollectionCoverage(
            provider="azure", account_id=subscription_id
        )
        self._coverage.append(coverage)

        async with self._semaphore:
            try:
                from azure.identity import DefaultAzureCredential
                from cloudmapper.collectors.azure import AzureCollector

                credential = DefaultAzureCredential()
                if not subscription_id:
                    from azure.mgmt.resource import SubscriptionClient
                    sub_client = SubscriptionClient(credential)
                    sub = next(sub_client.subscriptions.list(), None)
                    subscription_id = sub.subscription_id if sub else ""

                collector = AzureCollector(credential=credential, subscription_id=subscription_id)

                start = time.time()
                assets = await collector.collect()
                edges = await collector.collect_edges()
                duration_ms = int((time.time() - start) * 1000)

                coverage.record(
                    "azure_full", ServiceStatus.SUCCESS,
                    asset_count=len(assets), duration_ms=duration_ms,
                )
                return assets, edges

            except Exception as exc:
                logger.error("Azure collection failed for %s: %s", subscription_id, exc)
                coverage.record("azure_full", ServiceStatus.FAILED, error=str(exc))
                return [], []

    # ------------------------------------------------------------------
    # GCP
    # ------------------------------------------------------------------

    async def _collect_gcp_multi(self) -> list[tuple[list[CloudAsset], list[NetworkEdge]]]:
        """Iterate GCP projects × regions."""
        project_ids = self._config.gcp.project_ids
        if not project_ids:
            project_ids = [None]

        # Region resolution
        gcp_regions = self._config.gcp.regions
        if is_all_regions(gcp_regions):
            logger.info("GCP: discovering all regions...")
            try:
                import google.auth
                creds, default_project = google.auth.default()
                pid = project_ids[0] or default_project
            except Exception:
                creds, pid = None, None
            gcp_regions = await self._region_discovery.discover_gcp(creds, pid)

        self._resolved_regions["gcp"] = gcp_regions
        logger.info("GCP: scanning %d projects (Cloud Asset Inventory scans all regions)", len(project_ids))

        # GCP Cloud Asset Inventory API returns resources across ALL regions for a project.
        # No per-region iteration needed — the API is project-scoped.
        tasks = [self._collect_gcp_single(pid) for pid in project_ids]
        return await asyncio.gather(*tasks, return_exceptions=False)

    async def _collect_gcp_single(
        self, project_id: str | None
    ) -> tuple[list[CloudAsset], list[NetworkEdge]]:
        """Collect from a single GCP project."""
        coverage = CollectionCoverage(
            provider="gcp", account_id=project_id
        )
        self._coverage.append(coverage)

        async with self._semaphore:
            try:
                from cloudmapper.collectors.gcp import GCPCollector
                import google.auth

                credentials, default_project = google.auth.default()
                pid = project_id or default_project

                collector = GCPCollector(project_id=pid, credentials=credentials)

                start = time.time()
                assets = await collector.collect()
                edges = await collector.collect_edges()
                duration_ms = int((time.time() - start) * 1000)

                coverage.record(
                    "gcp_full", ServiceStatus.SUCCESS,
                    asset_count=len(assets), duration_ms=duration_ms,
                )
                return assets, edges

            except Exception as exc:
                logger.error("GCP collection failed for %s: %s", project_id, exc)
                coverage.record("gcp_full", ServiceStatus.FAILED, error=str(exc))
                return [], []
