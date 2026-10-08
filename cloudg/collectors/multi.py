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

from cloudg.config import CloudGConfig
from cloudg.coverage import CollectionCoverage, ServiceStatus
from cloudg.resilience.errors import describe_error
from cloudg.region_discovery import RegionDiscovery, is_all_regions
from cloudg.schema.models import CloudAsset, NetworkEdge

logger = logging.getLogger(__name__)


def primary_region(regions: list[str]) -> str:
    """Region where account-wide services are collected (us-east-1 if scanned)."""
    if "us-east-1" in regions:
        return "us-east-1"
    return regions[0] if regions else "us-east-1"


class MultiAccountCollector:
    """Orchestrates collection across multiple providers, accounts, and regions.

    For AWS: assumes IAM roles in target accounts via STS, iterates regions.
    For Azure: iterates subscriptions × locations.
    For GCP: iterates projects × regions.

    Uses asyncio.Semaphore to limit concurrent API calls.
    """

    def __init__(
        self,
        config: CloudGConfig,
        collector_overrides: dict[str, type] | None = None,
    ) -> None:
        self._config = config
        self._semaphore = asyncio.Semaphore(config.concurrency_limit)
        self._coverage: list[CollectionCoverage] = []
        self._region_discovery = RegionDiscovery()
        self._resolved_regions: dict[str, list[str]] = {}
        # Per-provider collector class overrides (e.g. the deep inventory
        # collectors used by `cloudg map`); constructor signatures must match
        # the standard collector for that provider.
        self._collector_overrides = collector_overrides or {}
        self._caller_account: str | None = None
        # Shared throttling resilience (rate limits, breakers, retries) from
        # config.ratelimit / aws.max_retries / aws.retry_mode
        from cloudg.resilience import configure

        configure(config)
        #: Throttling telemetry of the last collect_all() run
        self.resilience_stats: Any = None

    async def collect_all(
        self,
    ) -> tuple[list[CloudAsset], list[NetworkEdge], list[CollectionCoverage]]:
        """Collect assets and edges from ALL configured providers simultaneously.

        Returns:
            Tuple of (all_assets, all_edges, coverage_records).
        """
        from cloudg.resilience import current_stats, stats_scope

        bound = current_stats()
        if bound is not None:  # the caller (e.g. InventoryMapper) owns the run's stats
            self.resilience_stats = bound
            return await self._collect_all()
        with stats_scope() as stats:
            self.resilience_stats = stats
            return await self._collect_all()

    async def _collect_all(
        self,
    ) -> tuple[list[CloudAsset], list[NetworkEdge], list[CollectionCoverage]]:
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
                coverage.record(f"{label}_full", ServiceStatus.FAILED, error=describe_error(result))
                self._coverage.append(coverage)
            elif isinstance(result, list):
                for assets, edges in result:
                    all_assets.extend(assets)
                    all_edges.extend(edges)

        logger.info(
            "Multi-provider collection complete: %d assets, %d edges across %d coverage records (%s)",
            len(all_assets),
            len(all_edges),
            len(self._coverage),
            ", ".join(task_labels),
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

        # Account-wide services are collected once per account, here.
        primary = primary_region(regions)

        # The caller's own account (e.g. the Organizations management
        # account) is collected with the base credentials: member-account
        # roles such as AWSControlTowerExecution do not exist there.
        if cfg.accounts and cfg.role_name and not cfg.role_arn:
            self._caller_account = await asyncio.to_thread(
                self._lookup_caller_account, cfg, primary
            )

        tasks = []
        for account_id in accounts:
            for region in regions:
                tasks.append(
                    self._collect_aws_single(account_id, region, cfg, is_primary=region == primary)
                )

        return await asyncio.gather(*tasks, return_exceptions=False)

    @staticmethod
    def _lookup_caller_account(cfg: Any, region: str) -> str | None:
        try:
            from cloudg.credentials import build_aws_session

            session = build_aws_session(cfg, region, account_id=None)
            return session.client("sts").get_caller_identity().get("Account")
        except Exception as exc:
            logger.debug("Caller account lookup failed: %s", exc)
            return None

    async def _collect_aws_single(
        self,
        account_id: str | None,
        region: str,
        cfg: Any,
        is_primary: bool = True,
    ) -> tuple[list[CloudAsset], list[NetworkEdge]]:
        """Collect from a single AWS account/region.

        Credential priority:
        1. Direct access keys (access_key_id + secret_access_key) from config
        2. AWS profile from config
        3. Environment defaults (AWS_PROFILE, instance metadata, etc.)

        Role assumption is only used when role_name is set AND account_id is specified.
        """
        coverage = CollectionCoverage(provider="aws", region=region, account_id=account_id)
        self._coverage.append(coverage)

        async with self._semaphore:
            try:
                session = self._aws_session(account_id, region, cfg, coverage)
                if session is None:
                    return [], []

                # Resolve account ID if not provided
                if not account_id:
                    try:
                        account_id = session.client("sts").get_caller_identity().get("Account")
                    except Exception:
                        account_id = "unknown"

                collector = self._build_aws_collector(session, region, account_id, is_primary)
                assets, edges, duration_ms = await self._timed_collect(collector)
                self._record_aws_coverage(coverage, collector, len(assets), duration_ms)
                return assets, edges

            except Exception as exc:
                logger.error("AWS collection failed for %s/%s: %s", account_id, region, exc)
                coverage.record("aws_full", ServiceStatus.FAILED, error=describe_error(exc))
                return [], []

    @staticmethod
    async def _timed_collect(collector: Any) -> tuple[list[CloudAsset], list[NetworkEdge], int]:
        """Run a collector's asset and edge passes; returns their duration in ms too."""
        start = time.time()
        assets = await collector.collect()
        edges = await collector.collect_edges()
        return assets, edges, int((time.time() - start) * 1000)

    def _aws_session(
        self, account_id: str | None, region: str, cfg: Any, coverage: CollectionCoverage
    ) -> Any:
        """boto3 session for an account/region, or None when auth fails
        (recorded on ``coverage``)."""
        from cloudg.credentials import build_aws_session

        # Supports direct keys, OIDC web identity, profiles, the
        # default chain (instance/task roles), and AssumeRole with
        # optional ExternalId — see cloudg.credentials.
        assume_into = account_id
        if account_id and account_id == self._caller_account:
            assume_into = None
        try:
            return build_aws_session(cfg, region, account_id=assume_into)
        except RuntimeError as exc:
            logger.error("AWS auth failed for %s/%s: %s", account_id, region, exc)
            coverage.record("sts_assume_role", ServiceStatus.FAILED, error=describe_error(exc))
            return None

    def _build_aws_collector(
        self, session: Any, region: str, account_id: str | None, is_primary: bool
    ) -> Any:
        from cloudg.collectors.aws import AsyncAWSCollector

        collector_cls = self._collector_overrides.get("aws", AsyncAWSCollector)
        kwargs: dict[str, Any] = {}
        if getattr(collector_cls, "supports_region_scoping", False):
            kwargs["is_primary_region"] = is_primary
        return collector_cls(session=session, region=region, account_id=account_id, **kwargs)

    @staticmethod
    def _record_aws_coverage(
        coverage: CollectionCoverage, collector: Any, asset_count: int, duration_ms: int
    ) -> None:
        # Surface per-service results (a denied Inspector call is
        # otherwise invisible behind an overall SUCCESS).
        services = list(getattr(getattr(collector, "coverage", None), "services", []) or [])
        coverage.services.extend(services)
        degraded = any(
            sc.status in (ServiceStatus.FAILED, ServiceStatus.PARTIAL) for sc in services
        )
        coverage.record(
            "aws_full",
            ServiceStatus.PARTIAL if degraded else ServiceStatus.SUCCESS,
            asset_count=asset_count,
            duration_ms=duration_ms,
        )

    # ------------------------------------------------------------------
    # Azure
    # ------------------------------------------------------------------

    async def _collect_azure_multi(self) -> list[tuple[list[CloudAsset], list[NetworkEdge]]]:
        """Iterate Azure subscriptions (every Enabled one when none are configured)."""
        cfg = self._config.azure
        sub_ids: list[str | None] = list(cfg.subscription_ids)

        # One credential for the whole run (azure-identity credentials are thread-safe)
        cred: Any = None
        try:
            from cloudg.credentials import build_azure_credential

            cred = build_azure_credential(cfg)
        except Exception as exc:
            logger.warning("Azure authentication setup failed: %s", exc)

        if not sub_ids and getattr(cfg, "all_subscriptions", True) and cred is not None:
            try:
                from cloudg.collectors.azure import list_subscriptions

                subs = await asyncio.to_thread(list_subscriptions, cred)
                sub_ids = [s["subscription_id"] for s in subs]
                logger.info("Azure: discovered %d enabled subscriptions", len(sub_ids))
            except Exception as exc:
                logger.warning(
                    "Azure subscription enumeration failed (%s); using the first one", exc
                )
        if not sub_ids:
            sub_ids = [None]

        # Region resolution
        azure_regions = cfg.regions
        if is_all_regions(azure_regions):
            logger.info("Azure: discovering all locations...")
            first_sub = sub_ids[0] if sub_ids[0] else None
            azure_regions = await self._region_discovery.discover_azure(cred, first_sub)

        self._resolved_regions["azure"] = azure_regions
        logger.info(
            "Azure: scanning %d subscriptions (locations auto-handled by SDK)", len(sub_ids)
        )

        # Azure list/graph calls return resources from ALL locations of a
        # subscription, so there is no per-region iteration.
        tasks = [self._collect_azure_single(sid, credential=cred) for sid in sub_ids]
        return await asyncio.gather(*tasks, return_exceptions=False)

    async def _collect_azure_single(
        self, subscription_id: str | None, credential: Any = None
    ) -> tuple[list[CloudAsset], list[NetworkEdge]]:
        """Collect from a single Azure subscription.

        Assets and edges are collected separately: an edge failure never
        discards the subscription's assets, and per-service collector
        failures are recorded as coverage entries.
        """
        coverage = CollectionCoverage(provider="azure", account_id=subscription_id)
        self._coverage.append(coverage)

        async with self._semaphore:
            start = time.time()
            try:
                from cloudg.collectors.azure import AzureCollector, first_subscription_id

                if credential is None:
                    from cloudg.credentials import build_azure_credential

                    # Supports workload identity, service principal (secret or
                    # certificate), managed identity, and the default chain.
                    credential = build_azure_credential(self._config.azure)
                if not subscription_id:
                    subscription_id = (
                        await asyncio.to_thread(first_subscription_id, credential) or ""
                    )
                    coverage.account_id = subscription_id or None

                collector_cls = self._collector_overrides.get("azure", AzureCollector)
                collector = collector_cls(credential=credential, subscription_id=subscription_id)
                assets = await collector.collect()
            except Exception as exc:
                logger.error("Azure collection failed for %s: %s", subscription_id, exc)
                coverage.record("azure_full", ServiceStatus.FAILED, error=describe_error(exc))
                return [], []

            edges: list[NetworkEdge] = []
            try:
                edges = await collector.collect_edges()
            except Exception as exc:
                logger.error("Azure edge collection failed for %s: %s", subscription_id, exc)
                coverage.record("azure_edges", ServiceStatus.FAILED, error=describe_error(exc))

            duration_ms = int((time.time() - start) * 1000)
            service_errors = dict(getattr(collector, "service_errors", None) or {})
            for service, error in service_errors.items():
                coverage.record(f"azure_{service}", ServiceStatus.FAILED, error=error)
            coverage.record(
                "azure_full",
                ServiceStatus.PARTIAL if service_errors else ServiceStatus.SUCCESS,
                asset_count=len(assets),
                duration_ms=duration_ms,
            )
            return assets, edges

    # ------------------------------------------------------------------
    # GCP
    # ------------------------------------------------------------------

    async def _collect_gcp_multi(self) -> list[tuple[list[CloudAsset], list[NetworkEdge]]]:
        """Collect GCP once at organization scope, or once per project.

        Cloud Asset Inventory lists every region in one call, so regions are
        never iterated. With ``gcp.organization_id`` set (and
        ``collection_scope`` auto/organization) a single listing at
        ``organizations/<id>`` covers every project; ``project_ids`` then
        narrow it.
        """
        cfg = self._config.gcp
        org_id = str(cfg.organization_id or "").removeprefix("organizations/") or None
        scope_mode = getattr(cfg, "collection_scope", "auto")
        if scope_mode == "organization" and not org_id:
            logger.warning(
                "GCP: collection_scope=organization needs gcp.organization_id; collecting per project"
            )
        org_scope = bool(org_id) and scope_mode != "project"
        project_ids = cfg.project_ids
        if not project_ids:
            project_ids = [None]

        # Region resolution
        gcp_regions = self._config.gcp.regions
        if is_all_regions(gcp_regions):
            logger.info("GCP: discovering all regions...")
            try:
                from cloudg.credentials import build_gcp_credentials

                creds, default_project = build_gcp_credentials(self._config.gcp)
                pid = project_ids[0] or default_project
            except Exception:
                creds, pid = None, None
            gcp_regions = await self._region_discovery.discover_gcp(creds, pid)

        self._resolved_regions["gcp"] = gcp_regions

        # Cloud Asset Inventory returns resources across ALL regions, so no
        # per-region iteration is needed.
        if org_scope:
            logger.info(
                "GCP: scanning organizations/%s in one Cloud Asset Inventory listing", org_id
            )
            tasks = [
                self._collect_gcp_single(
                    project_ids[0], organization_id=org_id, project_filter=cfg.project_ids or None
                )
            ]
        else:
            logger.info("GCP: scanning %d projects (all regions per project)", len(project_ids))
            tasks = [self._collect_gcp_single(pid) for pid in project_ids]
        return await asyncio.gather(*tasks, return_exceptions=False)

    async def _collect_gcp_single(
        self,
        project_id: str | None,
        organization_id: str | None = None,
        project_filter: list[str] | None = None,
    ) -> tuple[list[CloudAsset], list[NetworkEdge]]:
        """Collect one GCP project, or a whole organization when
        ``organization_id`` is given (``project_filter`` narrows it)."""
        label = f"organizations/{organization_id}" if organization_id else project_id
        coverage = CollectionCoverage(provider="gcp", account_id=label)
        self._coverage.append(coverage)

        async with self._semaphore:
            try:
                from cloudg.collectors.gcp import GCPCollector
                from cloudg.credentials import build_gcp_credentials

                cfg = self._config.gcp
                # Supports key files, workload identity federation, ADC
                # (inherited GCE/GKE identity), and impersonation.
                credentials, default_project = build_gcp_credentials(cfg)
                pid = project_id or default_project
                if not pid and not organization_id:
                    raise RuntimeError(
                        "no GCP project to scan: set gcp.project_ids or gcp.organization_id, "
                        "or use credentials that carry a default project"
                    )
                if coverage.account_id is None:
                    coverage.account_id = pid

                collector_cls = self._collector_overrides.get("gcp", GCPCollector)
                kwargs = self._gcp_collector_kwargs(
                    collector_cls, cfg, organization_id, project_filter, coverage
                )
                collector = collector_cls(project_id=pid, credentials=credentials, **kwargs)

                assets, edges, duration_ms = await self._timed_collect(collector)
                self._record_gcp_coverage(coverage, len(assets), duration_ms)
                return assets, edges

            except Exception as exc:
                logger.error("GCP collection failed for %s: %s", label, exc)
                coverage.record("gcp_full", ServiceStatus.FAILED, error=describe_error(exc))
                return [], []

    @staticmethod
    def _gcp_collector_kwargs(
        collector_cls: Any,
        cfg: Any,
        organization_id: str | None,
        project_filter: list[str] | None,
        coverage: CollectionCoverage,
    ) -> dict[str, Any]:
        """Organization-scope options for collectors that support them."""
        if getattr(collector_cls, "supports_org_scope", False):
            return {
                "organization_id": organization_id,
                "project_filter": project_filter,
                "coverage": coverage,
                "skip_asset_types": getattr(cfg, "skip_asset_types", None),
                "page_size": getattr(cfg, "asset_page_size", 1000),
                "include_iam": getattr(cfg, "iam_policies", True),
                "timeout": getattr(cfg, "api_timeout_seconds", 600.0),
            }
        if organization_id:
            raise RuntimeError(f"{collector_cls.__name__} does not support organization scope")
        return {}

    @staticmethod
    def _record_gcp_coverage(
        coverage: CollectionCoverage, asset_count: int, duration_ms: int
    ) -> None:
        degraded = [
            s
            for s in coverage.services
            if s.status in (ServiceStatus.FAILED, ServiceStatus.PARTIAL)
        ]
        coverage.record(
            "gcp_full",
            ServiceStatus.PARTIAL if degraded else ServiceStatus.SUCCESS,
            asset_count=asset_count,
            duration_ms=duration_ms,
            error="; ".join(f"{s.service}: {s.error}" for s in degraded) or None,
        )
