"""KMS (aliases, rotation, key policy and grant principals), Secrets
Manager (rotation function, KMS, resource policy, replicas) and DynamoDB
(KMS, streams, replicas, PITR, resource policy, Kinesis destinations).

These override the shallow base collectors and keep their metadata keys, so
the mixin must precede ``AsyncAWSCollector`` in the MRO.
"""

from __future__ import annotations

from typing import Any

from cloudg.collectors.aws_services_extended import secret_base_metadata
from cloudg.inventory.aws_services._base import gather_limited, rel
from cloudg.inventory.aws_services.governance._common import (
    _MAX_GRANTS,
    GovernanceHelpersMixin,
    _arn_account,
    _principal_target,
    _trust_kind,
    _ts,
    logger,
)
from cloudg.schema.models import AssetType, CloudAsset, EdgeType


def _kms_key_metadata(
    meta: dict[str, Any], rotation: dict[str, Any], mrc: dict[str, Any]
) -> dict[str, Any]:
    return {
        "key_state": meta.get("KeyState"),
        "key_usage": meta.get("KeyUsage"),
        "key_manager": meta.get("KeyManager"),
        "origin": meta.get("Origin"),
        "rotation_enabled": bool(rotation.get("KeyRotationEnabled", False)),
        "rotation_period_days": rotation.get("RotationPeriodInDays"),
        "next_rotation": _ts(rotation.get("NextRotationDate")),
        "key_spec": meta.get("KeySpec"),
        "description": meta.get("Description"),
        "enabled": meta.get("Enabled"),
        "created": _ts(meta.get("CreationDate")),
        "deletion_date": _ts(meta.get("DeletionDate")),
        "pending_deletion": meta.get("KeyState") == "PendingDeletion",
        "multi_region": meta.get("MultiRegion", False),
        "multi_region_type": mrc.get("MultiRegionKeyType"),
        "custom_key_store_id": meta.get("CustomKeyStoreId"),
    }


def _kms_replica_relations(mrc: dict[str, Any]) -> list[dict | None]:
    primary = (mrc.get("PrimaryKey") or {}).get("Arn")
    if mrc.get("MultiRegionKeyType") != "REPLICA" or not primary:
        return []
    return [
        rel(
            primary,
            EdgeType.REFERENCES,
            "REPLICATES_TO",
            reverse=True,
            description="multi-Region primary key",
        )
    ]


def _dynamodb_metadata(
    table: dict[str, Any],
    pitr: dict[str, Any],
    replicas: list[str],
    destinations: list[dict],
    index_arns: list[str],
) -> dict[str, Any]:
    sse = table.get("SSEDescription") or {}
    stream = table.get("StreamSpecification") or {}
    return {
        "status": table.get("TableStatus"),
        "item_count": table.get("ItemCount", 0),
        "size_bytes": table.get("TableSizeBytes", 0),
        "billing_mode": (table.get("BillingModeSummary") or {}).get("BillingMode", "PROVISIONED"),
        "encryption": sse.get("Status", "DISABLED"),
        "sse_type": sse.get("SSEType"),
        "kms_key_id": sse.get("KMSMasterKeyArn"),
        "stream_enabled": bool(stream.get("StreamEnabled")),
        "stream_view_type": stream.get("StreamViewType"),
        "stream_arn": table.get("LatestStreamArn"),
        "global_table_version": table.get("GlobalTableVersion"),
        "replica_regions": replicas,
        "pitr_enabled": pitr.get("PointInTimeRecoveryStatus") == "ENABLED",
        "pitr_recovery_days": pitr.get("RecoveryPeriodInDays"),
        "deletion_protection": table.get("DeletionProtectionEnabled", False),
        "table_class": (table.get("TableClassSummary") or {}).get("TableClass"),
        "indexes": [i.rsplit("/", 1)[-1] for i in index_arns],
        "kinesis_destinations": [d.get("StreamArn") for d in destinations if d.get("StreamArn")],
    }


class DataProtectionCollectorsMixin(GovernanceHelpersMixin):
    """Deep KMS, Secrets Manager and DynamoDB collectors."""

    def _replica_relation(
        self, arn: str, region: str, reverse: bool = False, **attrs: Any
    ) -> dict | None:
        """REPLICATES_TO a copy of ``arn`` in another region."""
        return rel(
            arn.replace(f":{self._region}:", f":{region}:", 1),
            EdgeType.REFERENCES,
            "REPLICATES_TO",
            reverse=reverse,
            **attrs,
        )

    # -- KMS ------------------------------------------------------------

    async def _collect_kms(self) -> list[CloudAsset]:  # type: ignore[override]
        async with self._client("kms") as kms:
            keys = [k async for k in self._paginate(kms, "list_keys", "Keys")]
            aliases: dict[str, list[dict]] = {}
            try:
                async for a in self._paginate(kms, "list_aliases", "Aliases"):
                    if a.get("TargetKeyId"):
                        aliases.setdefault(a["TargetKeyId"], []).append(a)
            except Exception as exc:
                logger.debug("KMS alias listing failed: %s", exc)
            results = await gather_limited(
                [lambda k=k: self._kms_key_asset(kms, k, aliases) for k in keys]
            )
        return [a for a in results if a]

    async def _kms_rotation(self, kms: Any, key_id: str, meta: dict[str, Any]) -> dict[str, Any]:
        """Rotation status; only symmetric keys with AWS key material rotate."""
        if (
            meta.get("KeySpec", "SYMMETRIC_DEFAULT") != "SYMMETRIC_DEFAULT"
            or meta.get("Origin") == "EXTERNAL"
        ):
            return {}
        try:
            return await kms.get_key_rotation_status(KeyId=key_id)
        except Exception as exc:
            logger.debug("KMS rotation status for %s failed: %s", key_id, exc)
            return {}

    async def _kms_grants(self, kms: Any, key_id: str) -> tuple[dict[str, dict[str, Any]], int]:
        """Grantee -> operations / grant names (capped), plus the grant count."""
        grants: dict[str, dict[str, Any]] = {}
        grant_count = 0
        try:
            async for g in self._paginate(kms, "list_grants", "Grants", KeyId=key_id):
                grant_count += 1
                target = _principal_target(str(g.get("GranteePrincipal") or ""))
                if target and len(grants) < _MAX_GRANTS:
                    entry_g = grants.setdefault(target, {"ops": set(), "names": set()})
                    entry_g["ops"].update(g.get("Operations") or [])
                    if g.get("Name"):
                        entry_g["names"].add(g["Name"])
        except Exception as exc:
            logger.debug("KMS grants for %s failed: %s", key_id, exc)
        return grants, grant_count

    async def _kms_tags(self, kms: Any, key_id: str) -> list[dict]:
        try:
            return [
                {"Key": t.get("TagKey"), "Value": t.get("TagValue")}
                async for t in self._paginate(kms, "list_resource_tags", "Tags", KeyId=key_id)
            ]
        except Exception as exc:
            logger.debug("KMS tags for %s failed: %s", key_id, exc)
            return []

    def _kms_grant_relations(self, grants: dict[str, dict[str, Any]]) -> list[dict | None]:
        return [
            rel(
                target,
                EdgeType.GRANTS_ACCESS,
                _trust_kind(_arn_account(target) not in (None, self._account_id)),
                reverse=True,
                description="KMS grant",
                operations=sorted(g["ops"]),
                grant_names=sorted(g["names"])[:10],
            )
            for target, g in grants.items()
        ]

    async def _kms_key_asset(
        self, kms: Any, entry: dict, aliases: dict[str, list[dict]]
    ) -> CloudAsset | None:
        key_id = entry["KeyId"]
        meta = (await kms.describe_key(KeyId=key_id)).get("KeyMetadata", {})
        if meta.get("KeyManager") == "AWS":
            return None
        rotation = await self._kms_rotation(kms, key_id, meta)
        policy_rels, policy_info = await self._policy_access(
            lambda: kms.get_key_policy(KeyId=key_id, PolicyName="default"),
            "Policy",
            "KMS key policy",
            skip_empty=False,
        )
        grants, grant_count = await self._kms_grants(kms, key_id)
        tags = await self._kms_tags(kms, key_id)
        key_aliases = aliases.get(key_id, [])
        mrc = meta.get("MultiRegionConfiguration") or {}
        return self._asset(
            arn=meta.get("Arn", ""),
            name=meta.get("KeyId", key_id),
            asset_type=AssetType.KMS_KEY,
            tags=tags,
            metadata={
                **_kms_key_metadata(meta, rotation, mrc),
                "aliases": [a.get("AliasName") for a in key_aliases],
                "grant_count": grant_count,
                "grantees": sorted(grants)[:_MAX_GRANTS],
                **policy_info,
            },
            relations=[
                *policy_rels,
                *self._kms_grant_relations(grants),
                *_kms_replica_relations(mrc),
            ],
            raw=meta,
            exposed=bool(policy_info.get("public_policy")),
            aliases=[a.get("AliasName") for a in key_aliases]
            + [a.get("AliasArn") for a in key_aliases],
        )

    # -- Secrets Manager -------------------------------------------------

    async def _collect_secrets_manager(self) -> list[CloudAsset]:  # type: ignore[override]
        async with self._client("secretsmanager") as sm:
            secrets = [s async for s in self._paginate(sm, "list_secrets", "SecretList")]
            results = await gather_limited([lambda s=s: self._secret_asset(sm, s) for s in secrets])
        return [a for a in results if a]

    def _secret_relations(
        self, secret: dict[str, Any], replicas: list[dict], policy_rels: list[dict]
    ) -> list[dict | None]:
        arn = secret.get("ARN", "")
        primary_region = secret.get("PrimaryRegion")
        relations: list[dict | None] = [
            rel(secret.get("KmsKeyId", ""), EdgeType.REFERENCES, "ENCRYPTED_BY_KMS"),
            rel(
                secret.get("RotationLambdaARN"),
                EdgeType.INVOKES,
                "ROTATES_SECRET",
                description="rotation function",
            ),
            *policy_rels,
        ]
        relations += [
            self._replica_relation(
                arn, rep["Region"], description="secret replica", status=rep.get("Status")
            )
            for rep in replicas
            if rep.get("Region") and rep.get("Region") != self._region
        ]
        if primary_region and primary_region != self._region:
            relations.append(
                self._replica_relation(
                    arn, primary_region, reverse=True, description="primary secret"
                )
            )
        return relations

    async def _secret_asset(self, sm: Any, secret: dict) -> CloudAsset:
        arn = secret.get("ARN", "")
        replicas: list[dict] = []
        try:
            replicas = (await sm.describe_secret(SecretId=arn)).get("ReplicationStatus") or []
        except Exception as exc:
            logger.debug("Replication status lookup failed: %s", exc)
        policy_rels, policy_info = await self._policy_access(
            lambda: sm.get_resource_policy(SecretId=arn),
            "ResourcePolicy",
            "Resource policy lookup",
        )
        rules = secret.get("RotationRules") or {}
        return self._asset(
            arn=arn,
            name=secret.get("Name", ""),
            asset_type=AssetType.SECRET,
            tags=secret.get("Tags"),
            metadata={
                **secret_base_metadata(secret),
                "rotation_lambda": secret.get("RotationLambdaARN"),
                "rotation_days": rules.get("AutomaticallyAfterDays"),
                "rotation_schedule": rules.get("ScheduleExpression"),
                "next_rotation": _ts(secret.get("NextRotationDate")),
                "owning_service": secret.get("OwningService"),
                "primary_region": secret.get("PrimaryRegion"),
                "replica_regions": sorted(r.get("Region") for r in replicas if r.get("Region")),
                "created": _ts(secret.get("CreatedDate")),
                "deleted_date": _ts(secret.get("DeletedDate")),
                **policy_info,
            },
            relations=self._secret_relations(secret, replicas, policy_rels),
            raw={k: v for k, v in secret.items() if k != "SecretVersionsToStages"},
            exposed=bool(policy_info.get("public_policy")),
        )

    # -- DynamoDB --------------------------------------------------------

    async def _collect_dynamodb(self) -> list[CloudAsset]:  # type: ignore[override]
        async with self._client("dynamodb") as ddb:
            names = [n async for n in self._paginate(ddb, "list_tables", "TableNames")]
            results = await gather_limited(
                [lambda n=n: self._dynamodb_table_asset(ddb, n) for n in names]
            )
        return [a for a in results if a]

    async def _dynamodb_pitr(self, ddb: Any, table_name: str) -> dict[str, Any]:
        try:
            return (
                (await ddb.describe_continuous_backups(TableName=table_name)).get(
                    "ContinuousBackupsDescription"
                )
                or {}
            ).get("PointInTimeRecoveryDescription") or {}
        except Exception as exc:
            logger.debug("PITR status for %s failed: %s", table_name, exc)
            return {}

    async def _dynamodb_destinations_and_tags(
        self, ddb: Any, table_name: str, arn: str
    ) -> tuple[list[dict], list[dict]]:
        destinations: list[dict] = []
        try:
            destinations = (
                await ddb.describe_kinesis_streaming_destination(TableName=table_name)
            ).get("KinesisDataStreamDestinations") or []
        except Exception as exc:
            logger.debug("Kinesis destinations for %s failed: %s", table_name, exc)
        tags: list[dict] = []
        try:
            tags = [
                t
                async for t in self._paginate(ddb, "list_tags_of_resource", "Tags", ResourceArn=arn)
            ]
        except Exception as exc:
            logger.debug("Tags for %s failed: %s", table_name, exc)
        return destinations, tags

    def _dynamodb_relations(
        self,
        table: dict[str, Any],
        replicas: list[str],
        destinations: list[dict],
        policy_rels: list[dict],
    ) -> list[dict | None]:
        arn = table.get("TableArn", "")
        sse = table.get("SSEDescription") or {}
        relations: list[dict | None] = [
            rel(sse.get("KMSMasterKeyArn"), EdgeType.REFERENCES, "ENCRYPTED_BY_KMS"),
            *policy_rels,
        ]
        relations += [
            self._replica_relation(arn, region, description="global table replica")
            for region in replicas
            if region != self._region
        ]
        relations += [
            rel(
                dest.get("StreamArn"),
                EdgeType.REFERENCES,
                "STREAMS_TO",
                description="Kinesis streaming destination",
                status=dest.get("DestinationStatus"),
            )
            for dest in destinations
        ]
        relations.append(
            rel(
                (table.get("RestoreSummary") or {}).get("SourceTableArn"),
                EdgeType.REFERENCES,
                "DEPENDS_ON",
                description="restored from table",
            )
        )
        return relations

    async def _dynamodb_table_asset(self, ddb: Any, table_name: str) -> CloudAsset:
        table = (await ddb.describe_table(TableName=table_name)).get("Table", {})
        arn = table.get("TableArn", "")
        pitr = await self._dynamodb_pitr(ddb, table_name)
        policy_rels, policy_info = await self._policy_access(
            lambda: ddb.get_resource_policy(ResourceArn=arn),
            "Policy",
            f"DynamoDB resource policy for {table_name}",
            quiet_code="PolicyNotFoundException",
        )
        destinations, tags = await self._dynamodb_destinations_and_tags(ddb, table_name, arn)
        replicas = [r.get("RegionName") for r in table.get("Replicas") or [] if r.get("RegionName")]
        index_arns = [
            i.get("IndexArn")
            for i in (table.get("GlobalSecondaryIndexes") or [])
            + (table.get("LocalSecondaryIndexes") or [])
            if i.get("IndexArn")
        ]
        return self._asset(
            arn=arn,
            name=table_name,
            asset_type=AssetType.DYNAMODB_TABLE,
            tags=tags,
            metadata={
                **_dynamodb_metadata(table, pitr, replicas, destinations, index_arns),
                **policy_info,
            },
            relations=self._dynamodb_relations(table, replicas, destinations, policy_rels),
            raw=table,
            exposed=bool(policy_info.get("public_policy")),
            aliases=[table.get("LatestStreamArn"), *index_arns[:20]],
        )
