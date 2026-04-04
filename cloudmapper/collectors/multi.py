"""Multi-account, multi-region collection orchestrator."""

from __future__ import annotations

import asyncio
import logging
import time
from typing import Any

from cloudmapper.config import CloudMapperConfig
from cloudmapper.coverage import CollectionCoverage, ServiceStatus
from cloudmapper.schema.models import CloudAsset, CloudProvider, NetworkEdge

logger = logging.getLogger(__name__)


class MultiAccountCollector:
    """Orchestrates collection across multiple accounts and regions.

    For AWS: assumes IAM roles in target accounts via STS.
    For Azure: iterates subscription IDs.
    For GCP: iterates project IDs.

    Uses asyncio.Semaphore to limit concurrent API calls.
    """

    def __init__(self, config: CloudMapperConfig) -> None:
        self._config = config
        self._semaphore = asyncio.Semaphore(config.concurrency_limit)
        self._coverage: list[CollectionCoverage] = []

    async def collect_all(self) -> tuple[list[CloudAsset], list[NetworkEdge], list[CollectionCoverage]]:
        """Collect assets and edges from all configured accounts/regions.

        Returns:
            Tuple of (all_assets, all_edges, coverage_records).
        """
        provider = self._config.provider
        all_assets: list[CloudAsset] = []
        all_edges: list[NetworkEdge] = []

        if provider == "aws":
            results = await self._collect_aws_multi()
        elif provider == "azure":
            results = await self._collect_azure_multi()
        elif provider == "gcp":
            results = await self._collect_gcp_multi()
        else:
            raise ValueError(f"Unknown provider: {provider}")

        for assets, edges in results:
            all_assets.extend(assets)
            all_edges.extend(edges)

        logger.info(
            "Multi-account collection complete: %d assets, %d edges across %d coverage records",
            len(all_assets), len(all_edges), len(self._coverage),
        )
        return all_assets, all_edges, self._coverage

    async def _collect_aws_multi(self) -> list[tuple[list[CloudAsset], list[NetworkEdge]]]:
        """Iterate AWS accounts × regions."""
        cfg = self._config.aws
        accounts = cfg.accounts or [None]  # None = current account
        regions = cfg.regions

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
        """Collect from a single AWS account/region, with STS role assumption."""
        coverage = CollectionCoverage(
            provider="aws", region=region, account_id=account_id
        )
        self._coverage.append(coverage)

        async with self._semaphore:
            try:
                import boto3

                if account_id:
                    # Assume role in target account
                    sts = boto3.client("sts", region_name=region)
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
                else:
                    session = boto3.Session(
                        profile_name=cfg.profile,
                        region_name=region,
                    )
                    account_id = session.client("sts").get_caller_identity().get("Account")

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

    async def _collect_azure_multi(self) -> list[tuple[list[CloudAsset], list[NetworkEdge]]]:
        """Iterate Azure subscriptions."""
        sub_ids = self._config.azure.subscription_ids
        if not sub_ids:
            sub_ids = [None]

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

    async def _collect_gcp_multi(self) -> list[tuple[list[CloudAsset], list[NetworkEdge]]]:
        """Iterate GCP projects."""
        project_ids = self._config.gcp.project_ids
        if not project_ids:
            project_ids = [None]

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
