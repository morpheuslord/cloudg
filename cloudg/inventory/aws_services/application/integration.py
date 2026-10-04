"""EventBridge Scheduler, Pipes, API destinations / connections and
archives. Connection auth parameters are never collected."""

from __future__ import annotations

from typing import Any

from cloudg.inventory.aws_services._base import arns_in, gather_limited, rel
from cloudg.inventory.aws_services.application._common import (
    ApplicationBase,
    _bucket_arn,
    _host,
    _role_rel,
    _vpc_config,
    logger,
)
from cloudg.schema.models import AssetType, CloudAsset, EdgeType


def _schedule_relations(full: dict, target: dict, universal: bool) -> list[dict | None]:
    ecs = target.get("EcsParameters") or {}
    relations: list[dict | None] = [
        _role_rel(target.get("RoleArn"), "schedule execution role"),
        rel(
            (target.get("DeadLetterConfig") or {}).get("Arn"),
            EdgeType.REFERENCES,
            "WRITES_TO",
            description="dead-letter queue",
        ),
        rel(full.get("KmsKeyArn"), EdgeType.REFERENCES, "ENCRYPTED_BY_KMS"),
    ]
    if not universal:
        relations.append(
            rel(target.get("Arn", ""), EdgeType.INVOKES, "INVOKES", description="schedule target")
        )
    if ecs.get("TaskDefinitionArn"):
        relations.append(
            rel(
                ecs["TaskDefinitionArn"],
                EdgeType.INVOKES,
                "INVOKES",
                description="runs ECS task",
            )
        )
    return relations


def _pipe_source_relations(src_params: dict) -> list[dict | None]:
    """Dead-letter targets and credential secrets of the pipe's source."""
    relations: list[dict | None] = []
    for block in src_params.values():
        if not isinstance(block, dict):
            continue
        dlq = (block.get("DeadLetterConfig") or {}).get("Arn")
        relations.append(
            rel(dlq, EdgeType.REFERENCES, "WRITES_TO", description="pipe dead-letter target")
        )
        relations.extend(
            rel(secret, EdgeType.REFERENCES, "READS_FROM", description="source credentials")
            for secret in arns_in(block.get("Credentials") or {})
        )
    return relations


def _pipe_log_relations(logcfg: dict) -> list[dict | None]:
    group = (logcfg.get("CloudwatchLogsLogDestination") or {}).get("LogGroupArn") or ""
    return [
        rel(group.removesuffix(":*"), EdgeType.LOGS_TO, "LOGS_TO"),
        rel(
            (logcfg.get("FirehoseLogDestination") or {}).get("DeliveryStreamArn"),
            EdgeType.LOGS_TO,
            "LOGS_TO",
        ),
        rel(
            _bucket_arn((logcfg.get("S3LogDestination") or {}).get("BucketName")),
            EdgeType.LOGS_TO,
            "LOGS_TO",
        ),
    ]


class IntegrationCollectorsMixin(ApplicationBase):
    """EventBridge Scheduler, Pipes, API destination and archive collectors."""

    def _scheduler_asset(self, s: dict, group: str, full: dict) -> CloudAsset:
        target = full.get("Target") or {}
        tarn = target.get("Arn", "")
        universal = tarn.startswith("arn:aws:scheduler:::aws-sdk:")
        ecs = target.get("EcsParameters") or {}
        awsvpc = (ecs.get("NetworkConfiguration") or {}).get("awsvpcConfiguration") or {}
        return self._asset(
            arn=full.get("Arn") or s.get("Arn", ""),
            name=s["Name"],
            asset_type=AssetType.SCHEDULE,
            metadata={
                "service": "scheduler",
                "group": group,
                "state": full.get("State"),
                "expression": full.get("ScheduleExpression"),
                "timezone": full.get("ScheduleExpressionTimezone"),
                "flexible_window": (full.get("FlexibleTimeWindow") or {}).get("Mode"),
                "action_after_completion": full.get("ActionAfterCompletion"),
                "target_arn": tarn,
                "target_api": tarn.split("aws-sdk:", 1)[1] if universal else None,
                "retry_attempts": (target.get("RetryPolicy") or {}).get("MaximumRetryAttempts"),
                "vpc_config": _vpc_config(awsvpc, "Subnets", "SecurityGroups"),
            },
            relations=_schedule_relations(full, target, universal),
            aliases=[f"{group}/{s['Name']}"],
        )

    async def _collect_scheduler(self) -> list[CloudAsset]:
        async with self._client("scheduler") as sch:
            schedules = [s async for s in self._paginate(sch, "list_schedules", "Schedules")]

            async def detail(s: dict) -> CloudAsset:
                group = s.get("GroupName") or "default"
                full = await sch.get_schedule(Name=s["Name"], GroupName=group)
                return self._scheduler_asset(s, group, full)

            results = await gather_limited([lambda s=s: detail(s) for s in schedules])
        return [a for a in results if a]

    def _event_pipe_asset(self, p: dict, summary: dict) -> CloudAsset:
        src_params = p.get("SourceParameters") or {}
        relations: list[dict | None] = [
            rel(
                p.get("Source"),
                EdgeType.INVOKES,
                "TRIGGERED_BY",
                reverse=True,
                description="pipe source",
            ),
            rel(p.get("Enrichment"), EdgeType.INVOKES, "INVOKES", description="pipe enrichment"),
            rel(p.get("Target"), EdgeType.INVOKES, "INVOKES", description="pipe target"),
            _role_rel(p.get("RoleArn"), "pipe execution role"),
            rel(p.get("KmsKeyIdentifier"), EdgeType.REFERENCES, "ENCRYPTED_BY_KMS"),
        ]
        relations += _pipe_source_relations(src_params)
        logcfg = p.get("LogConfiguration") or {}
        relations += _pipe_log_relations(logcfg)
        kafka_vpc = (src_params.get("SelfManagedKafkaParameters") or {}).get("Vpc") or {}
        return self._asset(
            arn=p.get("Arn") or summary.get("Arn", ""),
            name=p.get("Name") or summary["Name"],
            asset_type=AssetType.EVENT_PIPE,
            tags=p.get("Tags"),
            metadata={
                "service": "pipes",
                "desired_state": p.get("DesiredState"),
                "current_state": p.get("CurrentState"),
                "source": p.get("Source"),
                "enrichment": p.get("Enrichment"),
                "target": p.get("Target"),
                "source_type": next(
                    (k for k, v in src_params.items() if isinstance(v, dict)), None
                ),
                "has_filter": bool(src_params.get("FilterCriteria")),
                "log_level": logcfg.get("Level"),
                "vpc_config": _vpc_config(kafka_vpc, "Subnets", "SecurityGroup"),
            },
            relations=relations,
        )

    async def _collect_pipes(self) -> list[CloudAsset]:
        async with self._client("pipes") as pipes:
            summaries = [p async for p in self._paginate(pipes, "list_pipes", "Pipes")]

            async def detail(summary: dict) -> CloudAsset:
                p = await pipes.describe_pipe(Name=summary["Name"])
                return self._event_pipe_asset(p, summary)

            results = await gather_limited([lambda s=s: detail(s) for s in summaries])
        return [a for a in results if a]

    async def _event_connection_asset(self, events: Any, c: dict) -> CloudAsset:
        secret = kms = None
        private_cfg = None
        try:
            # describe_connection returns AuthParameters; only the
            # secret ARN / KMS key / connectivity config are kept.
            d = await events.describe_connection(Name=c["Name"])
            secret, kms = d.get("SecretArn"), d.get("KmsKeyIdentifier")
            res = (d.get("InvocationConnectivityParameters") or {}).get("ResourceParameters") or {}
            private_cfg = res.get("ResourceConfigurationArn")
        except Exception as exc:
            logger.debug("describe_connection failed for %s: %s", c.get("Name"), exc)
        relations: list[dict | None] = [
            rel(
                secret,
                EdgeType.REFERENCES,
                "READS_FROM",
                description="connection credentials secret",
            ),
            rel(kms, EdgeType.REFERENCES, "ENCRYPTED_BY_KMS"),
            rel(
                private_cfg,
                EdgeType.REFERENCES,
                "DEPENDS_ON",
                description="private connectivity resource configuration",
            ),
        ]
        return self._asset(
            arn=c["ConnectionArn"],
            name=c.get("Name", ""),
            asset_type=AssetType.API_DESTINATION,
            metadata={
                "service": "events",
                "kind": "connection",
                "state": c.get("ConnectionState"),
                "authorization_type": c.get("AuthorizationType"),
                "secret_arn": secret,
                "private": bool(private_cfg),
            },
            relations=relations,
        )

    def _api_destination_asset(self, d: dict) -> CloudAsset:
        return self._asset(
            arn=d["ApiDestinationArn"],
            name=d.get("Name", ""),
            asset_type=AssetType.API_DESTINATION,
            metadata={
                "service": "events",
                "kind": "api_destination",
                "state": d.get("ApiDestinationState"),
                "endpoint_host": _host(d.get("InvocationEndpoint")),
                "http_method": d.get("HttpMethod"),
                "rate_limit_per_second": d.get("InvocationRateLimitPerSecond"),
            },
            relations=[
                rel(
                    d.get("ConnectionArn"),
                    EdgeType.REFERENCES,
                    "DEPENDS_ON",
                    description="connection",
                )
            ],
        )

    async def _collect_eventbridge_api_destinations(self) -> list[CloudAsset]:
        assets: list[CloudAsset] = []
        async with self._client("events") as events:
            connections = [c async for c in self._pages(events.list_connections, "Connections")]
            destinations = [
                d async for d in self._pages(events.list_api_destinations, "ApiDestinations")
            ]
            conn_assets = await gather_limited(
                [lambda c=c: self._event_connection_asset(events, c) for c in connections]
            )
            assets.extend(a for a in conn_assets if a)
        assets.extend(self._api_destination_asset(d) for d in destinations)
        return assets

    def _event_archive_asset(self, a: dict) -> CloudAsset:
        name = a.get("ArchiveName", "")
        return self._asset(
            arn=self._arn("events", f"archive/{name}"),
            name=name,
            asset_type=AssetType.EVENT_ARCHIVE,
            metadata={
                "service": "events",
                "kind": "event_archive",
                "event_source": a.get("EventSourceArn"),
                "state": a.get("State"),
                "retention_days": a.get("RetentionDays"),
                "size_bytes": a.get("SizeBytes"),
                "event_count": a.get("EventCount"),
            },
            relations=[
                rel(
                    a.get("EventSourceArn"),
                    EdgeType.REFERENCES,
                    "READS_FROM",
                    description="archived event bus",
                )
            ],
        )

    async def _collect_eventbridge_archives(self) -> list[CloudAsset]:
        assets: list[CloudAsset] = []
        async with self._client("events") as events:
            async for a in self._pages(events.list_archives, "Archives"):
                assets.append(self._event_archive_asset(a))
        return assets
