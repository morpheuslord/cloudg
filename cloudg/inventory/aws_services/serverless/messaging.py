"""Messaging and orchestration: SQS queues (DLQ redrive, encryption,
cross-account grants), SNS topics -> subscriptions, EventBridge buses and
rules -> targets (+ target roles), Step Functions state machines -> every
resource their definition calls, Kinesis data streams."""

from __future__ import annotations

import json
import logging
from typing import Any

from cloudg.inventory.aws_services._base import (
    AWSServiceMixin,
    arns_in,
    gather_limited,
    rel,
    resource_policy_relations,
)
from cloudg.schema.models import AssetType, CloudAsset, EdgeType

logger = logging.getLogger(__package__)  # the package logger, as before the split

_SNS_FANOUT_PROTOCOLS = ("sqs", "lambda", "firehose", "application")


def _rule_target_relations(t: dict) -> list[dict | None]:
    """An EventBridge target, the role it runs with and its DLQ."""
    return [
        rel(t.get("Arn"), EdgeType.INVOKES, "INVOKES", description=f"target {t.get('Id')}"),
        rel(t.get("RoleArn"), EdgeType.ASSUMES_ROLE, "RUNS_ON", description="target role"),
        rel(
            (t.get("DeadLetterConfig") or {}).get("Arn"),
            EdgeType.REFERENCES,
            "WRITES_TO",
            description="target DLQ",
        ),
    ]


def _state_machine_relations(desc: dict, parsed: dict) -> list[dict | None]:
    called = [a for a in arns_in(parsed) if not a.startswith("arn:aws:states:::")]
    relations: list[dict | None] = [rel(desc.get("roleArn"), EdgeType.ASSUMES_ROLE, "RUNS_ON")]
    relations += [
        rel(a, EdgeType.INVOKES, "INVOKES", description="called by definition") for a in called
    ]
    for dest in (desc.get("loggingConfiguration") or {}).get("destinations", []) or []:
        group = ((dest.get("cloudWatchLogsLogGroup") or {}).get("logGroupArn") or "").removesuffix(
            ":*"
        )
        relations.append(rel(group, EdgeType.LOGS_TO, "LOGS_TO"))
    return relations


class MessagingCollectorsMixin(AWSServiceMixin):
    def _policy_guarded_asset(
        self,
        *,
        arn: str,
        asset_type: Any,
        policy: Any,
        relations: list[dict | None],
        metadata: dict[str, Any],
        aliases: list[str] | tuple = (),
    ) -> CloudAsset:
        """A queue or topic whose resource policy adds grants and decides
        whether it is public."""
        pol_rels, public = resource_policy_relations(policy, self._account_id)
        relations.extend(pol_rels)
        return self._asset(
            arn=arn,
            name=arn.rsplit(":", 1)[-1],
            asset_type=asset_type,
            metadata={**metadata, "policy_allows_public": public},
            relations=relations,
            exposed=public,
            aliases=aliases,
        )

    async def _collect_sqs(self) -> list[CloudAsset]:
        assets: list[CloudAsset] = []
        async with self._client("sqs") as sqs:
            # ListQueues only returns a NextToken when MaxResults is set.
            urls = [
                u
                async for u in self._paginate(
                    sqs, "list_queues", "QueueUrls", PaginationConfig={"PageSize": 1000}
                )
            ]
            results = await gather_limited(
                [lambda u=u: self._sqs_queue_asset(sqs, u) for u in urls]
            )
            assets.extend(a for a in results if a)
        return assets

    async def _sqs_queue_asset(self, sqs: Any, url: str) -> CloudAsset:
        attrs = (await sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["All"])).get(
            "Attributes", {}
        )
        redrive = json.loads(attrs["RedrivePolicy"]) if attrs.get("RedrivePolicy") else {}
        relations: list[dict | None] = [
            rel(attrs.get("KmsMasterKeyId"), EdgeType.REFERENCES, "ENCRYPTED_BY_KMS"),
            rel(
                redrive.get("deadLetterTargetArn"),
                EdgeType.REFERENCES,
                "WRITES_TO",
                description="dead-letter queue",
            ),
        ]
        return self._policy_guarded_asset(
            arn=attrs.get("QueueArn", url),
            asset_type=AssetType.MESSAGE_QUEUE,
            policy=attrs.get("Policy"),
            relations=relations,
            metadata={
                "queue_url": url,
                "fifo": attrs.get("FifoQueue") == "true",
                "kms_key_id": attrs.get("KmsMasterKeyId"),
                "sse_sqs": attrs.get("SqsManagedSseEnabled") == "true",
                "visibility_timeout": attrs.get("VisibilityTimeout"),
                "dead_letter_target": redrive.get("deadLetterTargetArn"),
            },
            aliases=[url],
        )

    async def _collect_sns(self) -> list[CloudAsset]:
        assets: list[CloudAsset] = []
        async with self._client("sns") as sns:
            topics = [t["TopicArn"] async for t in self._paginate(sns, "list_topics", "Topics")]
            subs: dict[str, list[dict]] = {}
            try:
                async for s in self._paginate(sns, "list_subscriptions", "Subscriptions"):
                    subs.setdefault(s.get("TopicArn", ""), []).append(s)
            except Exception as exc:
                logger.debug("SNS subscription listing failed: %s", exc)
            results = await gather_limited(
                [lambda t=t: self._sns_topic_asset(sns, t, subs.get(t, [])) for t in topics]
            )
            assets.extend(a for a in results if a)
        return assets

    async def _sns_topic_asset(self, sns: Any, arn: str, subs: list[dict]) -> CloudAsset:
        attrs = (await sns.get_topic_attributes(TopicArn=arn)).get("Attributes", {})
        relations: list[dict | None] = [
            rel(attrs.get("KmsMasterKeyId"), EdgeType.REFERENCES, "ENCRYPTED_BY_KMS")
        ]
        protocols: dict[str, int] = {}
        for s in subs:
            proto = s.get("Protocol", "")
            protocols[proto] = protocols.get(proto, 0) + 1
            if proto in _SNS_FANOUT_PROTOCOLS:
                relations.append(
                    rel(
                        s.get("Endpoint"),
                        EdgeType.INVOKES,
                        "STREAMS_TO",
                        description=f"{proto} subscription",
                    )
                )
        return self._policy_guarded_asset(
            arn=arn,
            asset_type=AssetType.NOTIFICATION_TOPIC,
            policy=attrs.get("Policy"),
            relations=relations,
            metadata={
                "kms_key_id": attrs.get("KmsMasterKeyId"),
                "subscriptions_by_protocol": protocols,
                "fifo": attrs.get("FifoTopic") == "true",
            },
        )

    async def _collect_eventbridge(self) -> list[CloudAsset]:
        assets: list[CloudAsset] = []
        async with self._client("events") as events:
            buses = [b async for b in self._pages(events.list_event_buses, "EventBuses")]
            for bus in buses:
                bus_name = bus.get("Name", "default")
                pol_rels, public = resource_policy_relations(bus.get("Policy"), self._account_id)
                assets.append(
                    self._asset(
                        arn=bus["Arn"],
                        name=bus_name,
                        asset_type=AssetType.EVENT_BUS,
                        metadata={"policy_allows_public": public},
                        relations=pol_rels,
                        exposed=public,
                    )
                )
                async for rule in self._paginate(
                    events, "list_rules", "Rules", EventBusName=bus_name
                ):
                    assets.append(await self._event_rule_asset(events, bus, rule))
        return assets

    async def _event_rule_asset(self, events: Any, bus: dict, rule: dict) -> CloudAsset:
        bus_name = bus.get("Name", "default")
        relations: list[dict | None] = [
            rel(bus["Arn"], EdgeType.CONTAINS, reverse=True),
            rel(rule.get("RoleArn"), EdgeType.ASSUMES_ROLE, "RUNS_ON"),
        ]
        targets: list[str] = []
        try:
            async for t in self._paginate(
                events,
                "list_targets_by_rule",
                "Targets",
                Rule=rule["Name"],
                EventBusName=bus_name,
            ):
                targets.append(t.get("Arn", ""))
                relations.extend(_rule_target_relations(t))
        except Exception as exc:
            logger.debug("Target listing failed for %s: %s", rule.get("Name"), exc)
        return self._asset(
            arn=rule["Arn"],
            name=rule["Name"],
            asset_type=AssetType.EVENT_RULE,
            metadata={
                "event_bus": bus_name,
                "state": rule.get("State"),
                "schedule": rule.get("ScheduleExpression"),
                "event_pattern": rule.get("EventPattern"),
                "managed_by": rule.get("ManagedBy"),
                "targets": targets,
            },
            relations=relations,
        )

    async def _collect_stepfunctions(self) -> list[CloudAsset]:
        assets: list[CloudAsset] = []
        async with self._client("stepfunctions") as sfn:
            machines = [
                m async for m in self._paginate(sfn, "list_state_machines", "stateMachines")
            ]
            results = await gather_limited(
                [lambda m=m: self._state_machine_asset(sfn, m) for m in machines]
            )
            assets.extend(a for a in results if a)
        return assets

    async def _state_machine_asset(self, sfn: Any, sm: dict) -> CloudAsset:
        desc = await sfn.describe_state_machine(stateMachineArn=sm["stateMachineArn"])
        definition = desc.get("definition") or "{}"
        try:
            parsed = json.loads(definition)
        except ValueError:
            parsed = {}
        integrations = sorted(
            {
                a.split(":::", 1)[1].split(".", 1)[0]
                for a in arns_in(parsed)
                if a.startswith("arn:aws:states:::")
            }
        )
        return self._asset(
            arn=sm["stateMachineArn"],
            name=sm.get("name", ""),
            asset_type=AssetType.STATE_MACHINE,
            metadata={
                "type": desc.get("type"),
                "status": desc.get("status"),
                "service_integrations": integrations,
                "states": len((parsed.get("States") or {})),
                "role_arn": desc.get("roleArn"),
            },
            relations=_state_machine_relations(desc, parsed),
        )

    async def _collect_kinesis(self) -> list[CloudAsset]:
        assets: list[CloudAsset] = []
        async with self._client("kinesis") as kinesis:
            names = [n async for n in self._paginate(kinesis, "list_streams", "StreamNames")]
            results = await gather_limited(
                [lambda n=n: self._kinesis_stream_asset(kinesis, n) for n in names]
            )
            assets.extend(a for a in results if a)
        return assets

    async def _kinesis_stream_asset(self, kinesis: Any, name: str) -> CloudAsset:
        s = (await kinesis.describe_stream_summary(StreamName=name))["StreamDescriptionSummary"]
        return self._asset(
            arn=s["StreamARN"],
            name=name,
            asset_type=AssetType.DATA_STREAM,
            metadata={
                "status": s.get("StreamStatus"),
                "mode": (s.get("StreamModeDetails") or {}).get("StreamMode"),
                "shards": s.get("OpenShardCount"),
                "encryption": s.get("EncryptionType"),
                "kms_key_id": s.get("KeyId"),
                "consumers": s.get("ConsumerCount"),
            },
            relations=[rel(s.get("KeyId"), EdgeType.REFERENCES, "ENCRYPTED_BY_KMS")],
        )
