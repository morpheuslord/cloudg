"""Storage: S3 (deep) and EFS.

S3 records the real bucket region, encryption key, event notifications
(-> Lambda / SQS / SNS), replication, access logging and policy grants.
EFS file systems carry their mount targets and access points.
"""

from __future__ import annotations

import logging
from typing import Any

from cloudg.inventory.aws_services._base import AWSServiceMixin, error_code, gather_limited, rel
from cloudg.inventory.aws_services import _policy_grants
from cloudg.schema.models import AssetType, CloudAsset, EdgeType

logger = logging.getLogger(__package__)  # the package logger, as before the split

_NOTIFICATION_TARGETS = (
    ("LambdaFunctionConfigurations", "LambdaFunctionArn"),
    ("QueueConfigurations", "QueueArn"),
    ("TopicConfigurations", "TopicArn"),
)


async def _s3_safe(call: Any, **kwargs: Any) -> dict:
    """A bucket sub-resource read; missing configuration reads as empty."""
    try:
        return await call(**kwargs)
    except Exception as exc:
        code = error_code(exc)
        if not code.startswith("NoSuch") and "NotFound" not in code:
            logger.debug("S3 %s failed: %s", getattr(call, "__name__", call), exc)
        return {}


async def _s3_bucket_region(s3: Any, bucket: dict) -> str:
    region = bucket.get("BucketRegion")
    if not region:
        loc = (await _s3_safe(s3.get_bucket_location, Bucket=bucket["Name"])).get(
            "LocationConstraint"
        )
        region = loc or "us-east-1"
    return "eu-west-1" if region == "EU" else region


async def _s3_bucket_config(s3: Any, name: str) -> dict[str, Any]:
    """Every bucket setting the map needs, read in one pass."""
    enc_rules = (
        (await _s3_safe(s3.get_bucket_encryption, Bucket=name)).get(
            "ServerSideEncryptionConfiguration"
        )
        or {}
    ).get("Rules", [])
    return {
        "sse": (enc_rules[0].get("ApplyServerSideEncryptionByDefault") or {}) if enc_rules else {},
        "pab": (await _s3_safe(s3.get_public_access_block, Bucket=name)).get(
            "PublicAccessBlockConfiguration"
        ),
        "acl": await _s3_safe(s3.get_bucket_acl, Bucket=name),
        "notif": await _s3_safe(s3.get_bucket_notification_configuration, Bucket=name),
        "repl": (await _s3_safe(s3.get_bucket_replication, Bucket=name)).get(
            "ReplicationConfiguration"
        )
        or {},
        "logging": (await _s3_safe(s3.get_bucket_logging, Bucket=name)).get("LoggingEnabled") or {},
        "policy": (await _s3_safe(s3.get_bucket_policy, Bucket=name)).get("Policy"),
    }


def _s3_wiring_relations(cfg: dict[str, Any]) -> list[dict | None]:
    """KMS key, event notifications, replication and access logging."""
    notif, repl, logging_cfg = cfg["notif"], cfg["repl"], cfg["logging"]
    relations: list[dict | None] = [
        rel(cfg["sse"].get("KMSMasterKeyID"), EdgeType.REFERENCES, "ENCRYPTED_BY_KMS"),
    ]
    for key, proto in _NOTIFICATION_TARGETS:
        for n in notif.get(key, []) or []:
            relations.append(
                rel(
                    n.get(proto),
                    EdgeType.INVOKES,
                    "INVOKES",
                    description="event notification",
                    events=n.get("Events"),
                )
            )
    for rule in repl.get("Rules", []) or []:
        dest = rule.get("Destination") or {}
        relations.append(
            rel(
                dest.get("Bucket"),
                EdgeType.REFERENCES,
                "REPLICATES_TO",
                destination_account=dest.get("Account"),
            )
        )
    relations.append(
        rel(repl.get("Role"), EdgeType.ASSUMES_ROLE, "RUNS_ON", description="replication role")
    )
    if logging_cfg.get("TargetBucket"):
        relations.append(
            rel(f"arn:aws:s3:::{logging_cfg['TargetBucket']}", EdgeType.LOGS_TO, "LOGS_TO")
        )
    return relations


def _s3_metadata(
    bucket: dict, cfg: dict[str, Any], account_pab: dict, public: bool
) -> dict[str, Any]:
    sse, acl, repl = cfg["sse"], cfg["acl"], cfg["repl"]
    return {
        "creation_date": str(bucket.get("CreationDate", "")),
        "acl_grants": len(acl.get("Grants", [])) if acl else None,
        "public_access_block": cfg["pab"],
        "account_public_access_block": account_pab or None,
        "encryption": bool(sse),
        "sse_algorithm": sse.get("SSEAlgorithm"),
        "kms_key_id": sse.get("KMSMasterKeyID"),
        "eventbridge_notifications": "EventBridgeConfiguration" in cfg["notif"],
        "replication_rules": len(repl.get("Rules", []) or []),
        "access_logging_target": cfg["logging"].get("TargetBucket"),
        "policy_allows_public": public,
    }


class StorageCollectorsMixin(AWSServiceMixin):
    # ------------------------------------------------------------------
    # S3 (overrides the shallow base collector)
    # ------------------------------------------------------------------

    async def _collect_s3(self) -> list[CloudAsset]:
        async with self._client("s3") as s3:
            buckets = [b async for b in self._paginate(s3, "list_buckets", "Buckets")]
            account_pab = await self._s3_account_public_access_block()
            results = await gather_limited(
                [lambda b=b: self._s3_bucket_asset(s3, b, account_pab) for b in buckets]
            )
            return [a for a in results if a]

    async def _s3_account_public_access_block(self) -> dict[str, Any]:
        """Account-level Block Public Access, which overrides bucket policies."""
        account_pab: dict[str, Any] = {}
        try:
            async with self._client("s3control") as s3c:
                resp = await s3c.get_public_access_block(AccountId=self._account_id)
                account_pab = resp.get("PublicAccessBlockConfiguration") or {}
        except Exception as exc:
            if "NoSuchPublicAccessBlockConfiguration" not in error_code(exc):
                logger.debug("Account public access block unavailable: %s", exc)
        return account_pab

    async def _s3_bucket_asset(self, s3: Any, bucket: dict, account_pab: dict) -> CloudAsset:
        name = bucket["Name"]
        region = await _s3_bucket_region(s3, bucket)
        cfg = await _s3_bucket_config(s3, name)
        relations = _s3_wiring_relations(cfg)
        grants, public_policy = _policy_grants.principal_grants(
            cfg["policy"], "bucket policy grant", conditioned_public=False
        )
        relations += grants
        blocked = any(
            bool(pab) and all(pab.get(k) for k in ("BlockPublicPolicy", "RestrictPublicBuckets"))
            for pab in (cfg["pab"], account_pab)
        )
        public = public_policy and not blocked
        return self._asset(
            arn=f"arn:aws:s3:::{name}",
            name=name,
            asset_type=AssetType.S3_BUCKET,
            region=region,
            metadata=_s3_metadata(bucket, cfg, account_pab, public),
            relations=relations,
            raw=bucket,
            exposed=public,
            aliases=[f"{name}.s3.amazonaws.com", f"{name}.s3.{region}.amazonaws.com"],
        )

    # ------------------------------------------------------------------
    # EFS
    # ------------------------------------------------------------------

    async def _collect_efs(self) -> list[CloudAsset]:
        assets: list[CloudAsset] = []
        async with self._client("efs") as efs:
            access_points = await self._efs_access_points(efs)
            async for fs in self._paginate(efs, "describe_file_systems", "FileSystems"):
                fs_id = fs["FileSystemId"]
                relations: list[dict | None] = [
                    rel(fs.get("KmsKeyId"), EdgeType.REFERENCES, "ENCRYPTED_BY_KMS")
                ]
                sgs = await self._efs_mount_targets(efs, fs_id, relations)
                assets.append(
                    self._asset(
                        arn=fs.get("FileSystemArn")
                        or self._arn("elasticfilesystem", f"file-system/{fs_id}"),
                        name=fs.get("Name") or fs_id,
                        asset_type=AssetType.FILE_SYSTEM,
                        tags=fs.get("Tags"),
                        metadata={
                            "file_system_id": fs_id,
                            "encrypted": fs.get("Encrypted"),
                            "kms_key_id": fs.get("KmsKeyId"),
                            "performance_mode": fs.get("PerformanceMode"),
                            "size_bytes": (fs.get("SizeInBytes") or {}).get("Value"),
                            "security_groups": sorted(set(sgs)),
                        },
                        relations=relations,
                        aliases=[fs_id, *access_points.get(fs_id, [])],
                    )
                )
        return assets

    async def _efs_access_points(self, efs: Any) -> dict[str, list[str]]:
        """Access point ARNs per file system, used as aliases."""
        access_points: dict[str, list[str]] = {}
        try:
            async for ap in self._paginate(efs, "describe_access_points", "AccessPoints"):
                access_points.setdefault(ap.get("FileSystemId", ""), []).append(
                    ap.get("AccessPointArn")
                )
        except Exception as exc:
            logger.debug("EFS access point listing failed: %s", exc)
        return access_points

    async def _efs_mount_targets(
        self, efs: Any, fs_id: str, relations: list[dict | None]
    ) -> list[str]:
        """Add a subnet relation per mount target; return their security groups."""
        sgs: list[str] = []
        try:
            async for mt in self._paginate(
                efs, "describe_mount_targets", "MountTargets", FileSystemId=fs_id
            ):
                relations.append(
                    rel(
                        mt.get("SubnetId"),
                        EdgeType.CONTAINS,
                        "SUBNET_CONTAINS_INSTANCE",
                        reverse=True,
                    )
                )
                try:
                    resp = await efs.describe_mount_target_security_groups(
                        MountTargetId=mt["MountTargetId"]
                    )
                    sgs.extend(resp.get("SecurityGroups", []))
                except Exception as exc:
                    logger.debug("Mount target SG lookup failed: %s", exc)
        except Exception as exc:
            logger.debug("Mount target listing failed for %s: %s", fs_id, exc)
        return sgs
