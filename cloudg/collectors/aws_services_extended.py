"""Extended AWS per-service collector methods, split out of ``aws.py``.

These mixin methods are consumed by
:class:`cloudg.collectors.aws.AsyncAWSCollector`.
"""

from __future__ import annotations

import logging
import time
from typing import TYPE_CHECKING, Any

from cloudg.coverage import ServiceStatus
from cloudg.schema.models import AssetType, CloudAsset, CloudProvider

if TYPE_CHECKING:
    from cloudg.coverage import CollectionCoverage

logger = logging.getLogger(__name__)


def secret_base_metadata(secret: dict[str, Any]) -> dict[str, Any]:
    """Secret metadata (never the value) shared with the deep inventory's
    richer Secrets Manager collector, which extends these keys."""
    return {
        "description": secret.get("Description", ""),
        "rotation_enabled": secret.get("RotationEnabled", False),
        "last_accessed": str(secret.get("LastAccessedDate", "")),
        "last_rotated": str(secret.get("LastRotatedDate", "")),
        "kms_key_id": secret.get("KmsKeyId", ""),
    }


class ExtendedServiceCollectorsMixin:
    """Collectors for ECS, DynamoDB, CloudFront, Secrets Manager and KMS.

    Expects the host class to provide ``self._get_aio_session()``,
    ``self._region``, ``self._account_id``, ``self._aio_config`` and
    ``self.coverage``.
    """

    if TYPE_CHECKING:
        _region: str
        _account_id: str | None
        _aio_config: Any
        coverage: CollectionCoverage

        def _get_aio_session(self) -> Any: ...

    async def _collect_ecs(self) -> list[CloudAsset]:
        """Collect ECS clusters and services."""
        assets: list[CloudAsset] = []
        session = self._get_aio_session()
        start = time.time()
        try:
            async with session.client(
                "ecs", region_name=self._region, config=self._aio_config
            ) as ecs:
                clusters_resp = await ecs.list_clusters()
                cluster_arns = clusters_resp.get("clusterArns", [])
                if cluster_arns:
                    desc = await ecs.describe_clusters(clusters=cluster_arns)
                    for cluster in desc.get("clusters", []):
                        assets.append(
                            CloudAsset(
                                arn=cluster.get("clusterArn", ""),
                                name=cluster.get("clusterName", ""),
                                asset_type=AssetType.ECS_CLUSTER,
                                provider=CloudProvider.AWS,
                                region=self._region,
                                account_id=self._account_id,
                                metadata={
                                    "status": cluster.get("status"),
                                    "running_tasks": cluster.get("runningTasksCount", 0),
                                    "active_services": cluster.get("activeServicesCount", 0),
                                    "capacity_providers": cluster.get("capacityProviders", []),
                                },
                                raw_data=cluster,
                            )
                        )
            self.coverage.record(
                "ecs",
                ServiceStatus.SUCCESS,
                asset_count=len(assets),
                duration_ms=int((time.time() - start) * 1000),
            )
        except Exception as exc:
            logger.error("Failed to collect ECS clusters: %s", exc)
            self.coverage.record("ecs", ServiceStatus.FAILED, error=str(exc))
        return assets

    def _dynamodb_asset(self, table_name: str, table: dict[str, Any]) -> CloudAsset:
        """Build a CloudAsset from a described DynamoDB table."""
        return CloudAsset(
            arn=table.get("TableArn", ""),
            name=table_name,
            asset_type=AssetType.DYNAMODB_TABLE,
            provider=CloudProvider.AWS,
            region=self._region,
            account_id=self._account_id,
            metadata={
                "status": table.get("TableStatus"),
                "item_count": table.get("ItemCount", 0),
                "size_bytes": table.get("TableSizeBytes", 0),
                "billing_mode": table.get("BillingModeSummary", {}).get(
                    "BillingMode", "PROVISIONED"
                ),
                "encryption": table.get("SSEDescription", {}).get("Status", "DISABLED"),
            },
            raw_data=table,
        )

    async def _collect_dynamodb(self) -> list[CloudAsset]:
        """Collect DynamoDB tables."""
        assets: list[CloudAsset] = []
        session = self._get_aio_session()
        start = time.time()
        try:
            async with session.client(
                "dynamodb", region_name=self._region, config=self._aio_config
            ) as ddb:
                paginator = ddb.get_paginator("list_tables")
                async for page in paginator.paginate():
                    for table_name in page.get("TableNames", []):
                        try:
                            desc = await ddb.describe_table(TableName=table_name)
                            assets.append(self._dynamodb_asset(table_name, desc.get("Table", {})))
                        except Exception as exc:
                            logger.warning(
                                "Failed to describe DynamoDB table %s: %s", table_name, exc
                            )
            self.coverage.record(
                "dynamodb",
                ServiceStatus.SUCCESS,
                asset_count=len(assets),
                duration_ms=int((time.time() - start) * 1000),
            )
        except Exception as exc:
            logger.error("Failed to collect DynamoDB tables: %s", exc)
            self.coverage.record("dynamodb", ServiceStatus.FAILED, error=str(exc))
        return assets

    async def _collect_cloudfront(self) -> list[CloudAsset]:
        """Collect CloudFront distributions."""
        assets: list[CloudAsset] = []
        session = self._get_aio_session()
        start = time.time()
        try:
            async with session.client(
                "cloudfront", region_name="us-east-1", config=self._aio_config
            ) as cf:
                paginator = cf.get_paginator("list_distributions")
                async for page in paginator.paginate():
                    dist_list = page.get("DistributionList", {})
                    for dist in dist_list.get("Items", []):
                        assets.append(
                            CloudAsset(
                                arn=dist.get("ARN", ""),
                                name=dist.get("DomainName", dist.get("Id", "")),
                                asset_type=AssetType.CLOUDFRONT,
                                provider=CloudProvider.AWS,
                                region="global",
                                account_id=self._account_id,
                                is_internet_exposed=True,
                                metadata={
                                    "status": dist.get("Status"),
                                    "domain_name": dist.get("DomainName"),
                                    "origins": [
                                        o.get("DomainName")
                                        for o in dist.get("Origins", {}).get("Items", [])
                                    ],
                                    "web_acl_id": dist.get("WebACLId", ""),
                                    "viewer_protocol_policy": dist.get(
                                        "DefaultCacheBehavior", {}
                                    ).get("ViewerProtocolPolicy"),
                                },
                                raw_data=dist,
                            )
                        )
            self.coverage.record(
                "cloudfront",
                ServiceStatus.SUCCESS,
                asset_count=len(assets),
                duration_ms=int((time.time() - start) * 1000),
            )
        except Exception as exc:
            logger.error("Failed to collect CloudFront distributions: %s", exc)
            self.coverage.record("cloudfront", ServiceStatus.FAILED, error=str(exc))
        return assets

    async def _collect_secrets_manager(self) -> list[CloudAsset]:
        """Collect Secrets Manager secrets (metadata only, not values)."""
        assets: list[CloudAsset] = []
        session = self._get_aio_session()
        start = time.time()
        try:
            async with session.client(
                "secretsmanager", region_name=self._region, config=self._aio_config
            ) as sm:
                paginator = sm.get_paginator("list_secrets")
                async for page in paginator.paginate():
                    for secret in page.get("SecretList", []):
                        tags = {t["Key"]: t["Value"] for t in secret.get("Tags", [])}
                        assets.append(
                            CloudAsset(
                                arn=secret.get("ARN", ""),
                                name=secret.get("Name", ""),
                                asset_type=AssetType.SECRET,
                                provider=CloudProvider.AWS,
                                region=self._region,
                                account_id=self._account_id,
                                tags=tags,
                                metadata=secret_base_metadata(secret),
                                raw_data=secret,
                            )
                        )
            self.coverage.record(
                "secretsmanager",
                ServiceStatus.SUCCESS,
                asset_count=len(assets),
                duration_ms=int((time.time() - start) * 1000),
            )
        except Exception as exc:
            # nosemgrep: the message names the AWS service, no credential is logged
            logger.error("secretsmanager service collection failed: %s", exc)
            self.coverage.record("secretsmanager", ServiceStatus.FAILED, error=str(exc))
        return assets

    def _kms_asset(self, key_meta: dict[str, Any]) -> CloudAsset:
        """Build a CloudAsset from described KMS key metadata."""
        return CloudAsset(
            arn=key_meta.get("Arn", ""),
            name=key_meta.get("KeyId", ""),
            asset_type=AssetType.KMS_KEY,
            provider=CloudProvider.AWS,
            region=self._region,
            account_id=self._account_id,
            metadata={
                "key_state": key_meta.get("KeyState"),
                "key_usage": key_meta.get("KeyUsage"),
                "key_manager": key_meta.get("KeyManager"),
                "origin": key_meta.get("Origin"),
                "rotation_enabled": key_meta.get("KeyRotationStatus", False),
            },
            raw_data=key_meta,
        )

    async def _collect_kms(self) -> list[CloudAsset]:
        """Collect KMS keys."""
        assets: list[CloudAsset] = []
        session = self._get_aio_session()
        start = time.time()
        try:
            async with session.client(
                "kms", region_name=self._region, config=self._aio_config
            ) as kms:
                paginator = kms.get_paginator("list_keys")
                async for page in paginator.paginate():
                    for key_entry in page.get("Keys", []):
                        try:
                            key_desc = await kms.describe_key(KeyId=key_entry["KeyId"])
                            key_meta = key_desc.get("KeyMetadata", {})
                            # Skip AWS-managed keys
                            if key_meta.get("KeyManager") == "AWS":
                                continue
                            assets.append(self._kms_asset(key_meta))
                        except Exception as exc:
                            logger.warning(
                                "Failed to describe KMS key %s: %s", key_entry["KeyId"], exc
                            )
            self.coverage.record(
                "kms",
                ServiceStatus.SUCCESS,
                asset_count=len(assets),
                duration_ms=int((time.time() - start) * 1000),
            )
        except Exception as exc:
            logger.error("Failed to collect KMS keys: %s", exc)
            self.coverage.record("kms", ServiceStatus.FAILED, error=str(exc))
        return assets
