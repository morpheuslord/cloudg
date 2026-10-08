"""Async AWS resource collector using aioboto3 with adaptive retries.

Every aioboto3 session is wired into :mod:`cloudg.resilience` (shared
adaptive rate limits, circuit breakers, throttle telemetry); a service whose
calls stay throttled after retries is recorded FAILED / PARTIAL with reason
"throttled" instead of failing the run.
"""

from __future__ import annotations

import asyncio
import logging
import time
from typing import Any

from cloudg.collectors.aws_services import CoreServiceCollectorsMixin
from cloudg.collectors.aws_services_extended import ExtendedServiceCollectorsMixin
from cloudg.collectors.base import BaseCollector
from cloudg.coverage import CollectionCoverage, ServiceStatus
from cloudg.resilience.errors import describe_error
from cloudg.resilience.stats import throttle_ledger
from cloudg.schema.models import (
    AssetType,
    CloudAsset,
    EdgeType,
    NetworkEdge,
)

logger = logging.getLogger(__name__)


def _retries(max_attempts: int | None = None, mode: str | None = None) -> dict[str, Any]:
    """botocore ``retries`` from ``aws.max_retries`` / ``aws.retry_mode``
    (applied to the resilience governor by the orchestrator; adaptive / 10)."""
    from cloudg.resilience.aws import botocore_retries

    retries = botocore_retries()
    if max_attempts is not None:
        retries["max_attempts"] = max_attempts
    if mode is not None:
        retries["mode"] = mode
    return retries


def _get_aio_config(max_attempts: int | None = None, mode: str | None = None) -> Any:
    """Return AioConfig with the configured retries (default: adaptive mode, 10 retries)."""
    retries = _retries(max_attempts, mode)
    try:
        from aiobotocore.config import AioConfig

        return AioConfig(
            retries=retries,
            connect_timeout=10,
            read_timeout=30,
        )
    except ImportError:
        from botocore.config import Config

        return Config(retries=retries)


def _default_client_config() -> Any:
    """Session-wide default for clients created without ``config=``: the
    configured retries only (botocore's default timeouts are kept)."""
    try:
        from aiobotocore.config import AioConfig

        return AioConfig(retries=_retries())
    except ImportError:  # pragma: no cover (aiobotocore always ships with aioboto3)
        return None


class AsyncAWSCollector(CoreServiceCollectorsMixin, ExtendedServiceCollectorsMixin, BaseCollector):
    """Collects AWS resources asynchronously using aioboto3.

    Enumerates: EC2, S3, RDS, VPC, Subnets, Security Groups,
    IAM Users/Roles/Policies, Lambda, ELBv2, ECS, DynamoDB,
    CloudFront, Secrets Manager, KMS.

    The per-service collector methods live in
    :class:`~cloudg.collectors.aws_services.CoreServiceCollectorsMixin` and
    :class:`~cloudg.collectors.aws_services_extended.ExtendedServiceCollectorsMixin`.
    """

    def __init__(
        self,
        session: Any,
        region: str = "us-east-1",
        account_id: str | None = None,
    ) -> None:
        self._boto3_session = session
        self._region = region
        self._account_id = account_id
        self._aioboto3_session: Any = None
        self._aio_config = _get_aio_config()
        self.coverage = CollectionCoverage(provider="aws", region=region, account_id=account_id)

    def _get_aio_session(self) -> Any:
        """Lazy-init aioboto3 session, propagating credentials from the boto3 session.

        Credential priority:
        1. Direct credentials extracted from the boto3 session (access key / secret)
        2. Profile name from the boto3 session
        3. Default credential chain (env vars, instance metadata, etc.)
        """
        if self._aioboto3_session is None:
            import aioboto3

            session_kwargs: dict[str, str | None] = {
                "region_name": self._region,
            }

            # Extract credentials from the boto3 session
            creds = self._boto3_session.get_credentials()
            if creds is not None:
                resolved = creds.get_frozen_credentials()
                session_kwargs["aws_access_key_id"] = resolved.access_key
                session_kwargs["aws_secret_access_key"] = resolved.secret_key
                if resolved.token:
                    session_kwargs["aws_session_token"] = resolved.token
            elif self._boto3_session.profile_name:
                # Fallback to profile if no direct credentials
                session_kwargs["profile_name"] = self._boto3_session.profile_name

            self._aioboto3_session = aioboto3.Session(**session_kwargs)
            # Every client of this session shares cloudg's adaptive rate
            # limiter, circuit breakers and throttle telemetry.
            from cloudg.resilience.aws import install_aws_hooks

            install_aws_hooks(
                self._aioboto3_session,
                account_id=self._account_id,
                region=self._region,
                default_config=_default_client_config(),
            )
        return self._aioboto3_session

    # ------------------------------------------------------------------
    # Edge collection
    # ------------------------------------------------------------------

    async def _collect_sg_edges(self, assets: list[CloudAsset]) -> list[NetworkEdge]:
        """Build edges from security group rules."""
        edges: list[NetworkEdge] = []
        sg_assets = [a for a in assets if a.asset_type == AssetType.SECURITY_GROUP]

        for sg in sg_assets:
            sg_id = sg.metadata.get("group_id", sg.id)

            # Ingress rules
            for rule in sg.metadata.get("ingress_rules", []):
                for ip_range in rule.get("IpRanges", []):
                    cidr = ip_range.get("CidrIp", "")
                    from_port = rule.get("FromPort", 0)
                    to_port = rule.get("ToPort", 65535)
                    protocol = rule.get("IpProtocol", "-1")

                    port_range = (
                        f"{from_port}-{to_port}" if from_port != to_port else str(from_port)
                    )

                    # Cap port list to avoid OOM on wide ranges (e.g., 0-65535)
                    port_count = min(to_port - from_port + 1, 100)
                    edges.append(
                        NetworkEdge(
                            source_id=cidr,
                            target_id=sg_id,
                            edge_type=EdgeType.SECURITY_GROUP_RULE,
                            ports=list(range(from_port, from_port + port_count)),
                            port_range=port_range,
                            protocol="ALL" if protocol == "-1" else protocol.upper(),
                            cidr=cidr,
                            direction="ingress",
                        )
                    )

            # Egress rules
            for rule in sg.metadata.get("egress_rules", []):
                for ip_range in rule.get("IpRanges", []):
                    cidr = ip_range.get("CidrIp", "")
                    from_port = rule.get("FromPort", 0)
                    to_port = rule.get("ToPort", 65535)
                    protocol = rule.get("IpProtocol", "-1")

                    edges.append(
                        NetworkEdge(
                            source_id=sg_id,
                            target_id=cidr,
                            edge_type=EdgeType.SECURITY_GROUP_RULE,
                            port_range=f"{from_port}-{to_port}",
                            protocol="ALL" if protocol == "-1" else protocol.upper(),
                            cidr=cidr,
                            direction="egress",
                        )
                    )

        return edges

    async def _collect_containment_edges(self, assets: list[CloudAsset]) -> list[NetworkEdge]:
        """Build VPC → Subnet → Resource containment edges."""
        edges: list[NetworkEdge] = []
        vpc_map = {
            a.metadata.get("vpc_id", a.id): a.id for a in assets if a.asset_type == AssetType.VPC
        }

        for asset in assets:
            vpc_id = asset.metadata.get("vpc_id")
            if vpc_id and vpc_id in vpc_map and asset.asset_type != AssetType.VPC:
                edges.append(
                    NetworkEdge(
                        source_id=vpc_map[vpc_id],
                        target_id=asset.id,
                        edge_type=EdgeType.CONTAINS,
                        description=f"VPC {vpc_id} contains {asset.name}",
                    )
                )
        return edges

    # ------------------------------------------------------------------
    # Main interface
    # ------------------------------------------------------------------

    async def _run_service_collector(self, name: str, coro: Any) -> list[CloudAsset]:
        """Run a service collector with coverage tracking."""
        start = time.time()
        # The ledger collects throttling that per-item error handling inside
        # the collector swallowed, so the service shows up PARTIAL
        # ("throttled: ...") instead of a silently incomplete SUCCESS.
        with throttle_ledger() as ledger:
            try:
                result = await coro
            except Exception as exc:
                duration_ms = int((time.time() - start) * 1000)
                logger.error("Collector %s failed: %s", name, exc)
                self.coverage.record(
                    name, ServiceStatus.FAILED, error=describe_error(exc), duration_ms=duration_ms
                )
                return []
        duration_ms = int((time.time() - start) * 1000)
        if ledger.degraded:
            logger.warning("Collector %s: %s", name, ledger.describe())
            self.coverage.record(
                name,
                ServiceStatus.PARTIAL,
                asset_count=len(result),
                error=ledger.describe(),
                duration_ms=duration_ms,
            )
        else:
            self.coverage.record(
                name, ServiceStatus.SUCCESS, asset_count=len(result), duration_ms=duration_ms
            )
        return result

    def _service_tasks(self) -> dict[str, Any]:
        """Collector callables per service, invoked lazily by :meth:`collect`.

        Values are zero-argument callables returning a coroutine (normally
        bound ``_collect_*`` methods). Subclasses extend or prune this dict
        to widen or narrow coverage without creating unawaited coroutines.
        """
        return {
            "ec2": self._collect_ec2,
            "s3": self._collect_s3,
            "rds": self._collect_rds,
            "vpc": self._collect_vpcs,
            "subnets": self._collect_subnets,
            "security_groups": self._collect_security_groups,
            "iam_users": self._collect_iam_users,
            "iam_roles": self._collect_iam_roles,
            "lambda": self._collect_lambda,
            "elbv2": self._collect_elbv2,
            "ecs": self._collect_ecs,
            "dynamodb": self._collect_dynamodb,
            "cloudfront": self._collect_cloudfront,
            "secretsmanager": self._collect_secrets_manager,
            "kms": self._collect_kms,
        }

    async def collect(self) -> list[CloudAsset]:
        """Collect all AWS assets concurrently."""
        logger.info("Starting AWS asset collection in %s", self._region)

        service_tasks = self._service_tasks()

        results = await asyncio.gather(
            *(
                self._run_service_collector(name, task() if callable(task) else task)
                for name, task in service_tasks.items()
            ),
            return_exceptions=True,
        )

        all_assets: list[CloudAsset] = []
        for result in results:
            if isinstance(result, Exception):
                logger.error("Collector task failed: %s", result)
            elif isinstance(result, list):
                all_assets.extend(result)

        logger.info(
            "Collected %d AWS assets (%s coverage)",
            len(all_assets),
            f"{self.coverage.coverage_pct}%",
        )
        self._cached_assets = all_assets
        return all_assets

    async def collect_edges(self) -> list[NetworkEdge]:
        """Collect all network/relationship edges."""
        assets = getattr(self, "_cached_assets", [])
        if not assets:
            assets = await self.collect()

        sg_edges, containment_edges = await asyncio.gather(
            self._collect_sg_edges(assets),
            self._collect_containment_edges(assets),
        )

        all_edges = sg_edges + containment_edges
        logger.info("Collected %d AWS edges", len(all_edges))
        return all_edges
