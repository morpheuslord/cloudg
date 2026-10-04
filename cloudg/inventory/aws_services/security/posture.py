"""Posture and audit: AWS Config (recorder + delivery channel), IAM Access
Analyzer and CloudTrail trails (-> LOGS_TO S3 / CloudWatch Logs)."""

from __future__ import annotations

from typing import Any

from cloudg.inventory.aws_services._base import rel
from cloudg.inventory.aws_services.security._common import SecurityServiceMixin, logger
from cloudg.schema.models import AssetType, CloudAsset, EdgeType


def _config_channel_relations(channels: list[dict]) -> list[dict | None]:
    """Where the delivery channels send configuration snapshots."""
    relations: list[dict | None] = []
    for ch in channels:
        if ch.get("s3BucketName"):
            relations.append(rel(f"arn:aws:s3:::{ch['s3BucketName']}", EdgeType.LOGS_TO, "LOGS_TO"))
        relations.append(rel(ch.get("snsTopicARN"), EdgeType.LOGS_TO, "STREAMS_TO"))
        relations.append(rel(ch.get("s3KmsKeyArn"), EdgeType.REFERENCES, "ENCRYPTED_BY_KMS"))
    return relations


def _trail_delivery_relations(t: dict) -> list[dict | None]:
    return [
        rel(
            f"arn:aws:s3:::{t['S3BucketName']}" if t.get("S3BucketName") else None,
            EdgeType.LOGS_TO,
            "LOGS_TO",
        ),
        rel(
            (t.get("CloudWatchLogsLogGroupArn") or "").removesuffix(":*"),
            EdgeType.LOGS_TO,
            "LOGS_TO",
        ),
        rel(t.get("CloudWatchLogsRoleArn"), EdgeType.ASSUMES_ROLE, "RUNS_ON"),
        rel(t.get("KmsKeyId"), EdgeType.REFERENCES, "ENCRYPTED_BY_KMS"),
        rel(t.get("SnsTopicARN"), EdgeType.LOGS_TO, "STREAMS_TO"),
    ]


class PostureCollectorsMixin(SecurityServiceMixin):
    async def _collect_config(self) -> list[CloudAsset]:
        async with self._client("config") as cfg:
            recorders = (await cfg.describe_configuration_recorders()).get(
                "ConfigurationRecorders", []
            )
            if not recorders:
                return [self._disabled_asset("config", AssetType.CONFIG_RECORDER, "AWS Config")]
            statuses = {
                s.get("name"): s
                for s in (await cfg.describe_configuration_recorder_status()).get(
                    "ConfigurationRecordersStatus", []
                )
            }
            channels = (await cfg.describe_delivery_channels()).get("DeliveryChannels", [])
            rule_names = [
                r.get("ConfigRuleName", "")
                for r in await self._security_listing(
                    cfg, "describe_config_rules", "ConfigRules", "Config rule listing failed: %s"
                )
            ]
            aggregators = [
                a.get("ConfigurationAggregatorName", "")
                for a in await self._security_listing(
                    cfg,
                    "describe_configuration_aggregators",
                    "ConfigurationAggregators",
                    "Config aggregator listing failed: %s",
                )
            ]
            shared = {"rules": rule_names, "aggregators": aggregators}
            return [
                self._config_recorder_asset(rec, statuses, channels, shared) for rec in recorders
            ]

    def _config_recorder_asset(
        self,
        rec: dict,
        statuses: dict[str, dict],
        channels: list[dict],
        shared: dict[str, Any],
    ) -> CloudAsset:
        name = rec.get("name", "default")
        group = rec.get("recordingGroup") or {}
        status = statuses.get(name, {})
        relations: list[dict | None] = [
            self._monitors_account("configuration recording"),
            rel(rec.get("roleARN"), EdgeType.ASSUMES_ROLE, "RUNS_ON"),
        ]
        relations += _config_channel_relations(channels)
        return self._asset(
            arn=rec.get("arn") or self._arn("config", f"config-recorder/{name}"),
            name=f"config-{name}",
            asset_type=AssetType.CONFIG_RECORDER,
            metadata={
                "security_service": "config",
                "enabled": bool(status.get("recording")),
                "recording": status.get("recording"),
                "last_status": status.get("lastStatus"),
                "all_supported": group.get("allSupported"),
                "include_global_resources": group.get("includeGlobalResourceTypes"),
                "rule_count": len(shared["rules"]),
                "rules": shared["rules"][:100],
                "aggregators": shared["aggregators"],
            },
            relations=relations,
            aliases=[self._security_alias("config")],
        )

    async def _collect_access_analyzer(self) -> list[CloudAsset]:
        async with self._client("accessanalyzer") as aa:
            analyzers = [a async for a in self._paginate(aa, "list_analyzers", "analyzers")]
            if not analyzers:
                return [
                    self._disabled_asset(
                        "accessanalyzer", AssetType.ACCESS_ANALYZER, "IAM Access Analyzer"
                    )
                ]
            return [
                self._asset(
                    arn=a["arn"],
                    name=a.get("name", ""),
                    asset_type=AssetType.ACCESS_ANALYZER,
                    tags=a.get("tags"),
                    metadata={
                        "security_service": "accessanalyzer",
                        "enabled": a.get("status") == "ACTIVE",
                        "type": a.get("type"),
                        "status": a.get("status"),
                    },
                    relations=[self._monitors_account(f"{a.get('type')} analyzer")],
                    aliases=[self._security_alias("accessanalyzer")],
                )
                for a in analyzers
            ]

    async def _collect_cloudtrail(self) -> list[CloudAsset]:
        assets: list[CloudAsset] = []
        async with self._client("cloudtrail") as ct:
            # Shadow trails include multi-region trails homed elsewhere and the
            # organization trail of the management account, so member
            # accounts are not reported as unaudited. The same trail seen
            # from several regions is merged by ARN in the mapper.
            trails = (await ct.describe_trails(includeShadowTrails=True)).get("trailList", [])
            if not trails:
                return [
                    self._disabled_asset(
                        "cloudtrail",
                        AssetType.CLOUDTRAIL,
                        "CloudTrail",
                        "no trail covers this region",
                    )
                ]
            for t in trails:
                home = t.get("HomeRegion", self._region)
                if (
                    home != self._region
                    and not t.get("IsMultiRegionTrail")
                    and not t.get("IsOrganizationTrail")
                ):
                    continue
                logging_on = await self._trail_logging(ct, t, home)
                assets.append(self._trail_asset(t, home, logging_on))
        return assets

    async def _trail_logging(self, ct: Any, t: dict, home: str) -> bool | None:
        if home != self._region:
            return True  # visible as a shadow trail: it is delivering here
        try:
            return (await ct.get_trail_status(Name=t["TrailARN"])).get("IsLogging")
        except Exception as exc:
            logger.debug("Trail status failed: %s", exc)
            return None

    def _trail_asset(self, t: dict, home: str, logging_on: bool | None) -> CloudAsset:
        relations = [
            self._monitors_account(
                "API audit logging", organization_trail=t.get("IsOrganizationTrail")
            ),
            *_trail_delivery_relations(t),
        ]
        return self._asset(
            arn=t["TrailARN"],
            name=t.get("Name", ""),
            asset_type=AssetType.CLOUDTRAIL,
            region=home,
            metadata={
                "security_service": "cloudtrail",
                "enabled": bool(logging_on),
                "is_logging": logging_on,
                "multi_region": t.get("IsMultiRegionTrail"),
                "organization_trail": t.get("IsOrganizationTrail"),
                "log_file_validation": t.get("LogFileValidationEnabled"),
                "s3_bucket": t.get("S3BucketName"),
                "kms_key_id": t.get("KmsKeyId"),
            },
            relations=relations,
            aliases=[self._security_alias("cloudtrail")],
        )
