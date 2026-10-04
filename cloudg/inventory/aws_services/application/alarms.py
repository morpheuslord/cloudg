"""CloudWatch metric and composite alarms: actions, scaling policies,
composite children and the resources a metric alarm monitors."""

from __future__ import annotations

from typing import Any

from cloudg.inventory.aws_services._base import rel
from cloudg.inventory.aws_services.application._common import (
    _ALARM_RULE_RE,
    _ASG_POLICY_RE,
    ApplicationBase,
)
from cloudg.schema.models import AssetType, CloudAsset, EdgeType

_ALARM_ACTION_FIELDS = (
    ("AlarmActions", "ALARM"),
    ("OKActions", "OK"),
    ("InsufficientDataActions", "INSUFFICIENT_DATA"),
)


def _alarm_action_relations(alarm: dict) -> tuple[list[dict | None], list[str]]:
    """Alarm action targets, plus EC2 automate actions (by name only)."""
    relations: list[dict | None] = []
    ec2_actions: list[str] = []
    for field, state in _ALARM_ACTION_FIELDS:
        for action in alarm.get(field, []) or []:
            if action.startswith("arn:aws:automate:"):
                ec2_actions.append(action.rsplit(":", 1)[-1])
                continue
            if ":autoscaling:" in action and "scalingPolicy" in action:
                m = _ASG_POLICY_RE.search(action)
                if m:
                    relations.append(
                        rel(
                            m.group(1),
                            EdgeType.INVOKES,
                            "SCALES_WITH",
                            description=f"{state} scaling policy",
                        )
                    )
                continue
            relations.append(
                rel(action, EdgeType.INVOKES, "INVOKES", description=f"{state} action")
            )
    return relations, ec2_actions


class AlarmCollectorsMixin(ApplicationBase):
    """CloudWatch alarm collector."""

    def _alarm_dimension_targets(self, namespace: str, dims: list[dict]) -> list[str]:
        d = {x.get("Name"): x.get("Value") for x in dims or [] if x.get("Name") and x.get("Value")}
        out: list[str] = []
        for rule in _DIMENSION_RULES:
            target = rule(self, namespace, d)
            if target:
                out.append(target)
        return out

    def _alarm_target_relations(
        self, alarm: dict, composite: bool
    ) -> tuple[list[dict | None], list[str]]:
        """Composite children, or the resources a metric alarm monitors."""
        if composite:
            children = [
                rel(
                    child.strip(),
                    EdgeType.REFERENCES,
                    "DEPENDS_ON",
                    description="composite alarm child",
                )
                for child in _ALARM_RULE_RE.findall(alarm.get("AlarmRule") or "")
            ]
            return children, []
        monitored = self._alarm_dimension_targets(
            alarm.get("Namespace", ""), alarm.get("Dimensions") or []
        )
        for q in alarm.get("Metrics", []) or []:
            metric = (q.get("MetricStat") or {}).get("Metric") or {}
            monitored += self._alarm_dimension_targets(
                metric.get("Namespace", ""), metric.get("Dimensions") or []
            )
        # EC2 actions act on the instance in the dimensions
        description = f"{alarm.get('Namespace')} {alarm.get('MetricName') or ''}".strip()
        relations = [
            rel(target, EdgeType.MONITORS, "MONITORED_BY", description=description)
            for target in dict.fromkeys(monitored)
        ]
        return relations, monitored

    def _alarm_asset(self, alarm: dict, composite: bool) -> CloudAsset:
        name = alarm.get("AlarmName", "")
        relations, ec2_actions = _alarm_action_relations(alarm)
        target_rels, monitored = self._alarm_target_relations(alarm, composite)
        relations += target_rels
        return self._asset(
            arn=alarm.get("AlarmArn") or self._arn("cloudwatch", f"alarm:{name}"),
            name=name,
            asset_type=AssetType.ALARM,
            metadata={
                "service": "cloudwatch",
                "alarm_type": "composite" if composite else "metric",
                "state": alarm.get("StateValue"),
                "actions_enabled": alarm.get("ActionsEnabled"),
                "namespace": alarm.get("Namespace"),
                "metric": alarm.get("MetricName"),
                "statistic": alarm.get("Statistic") or alarm.get("ExtendedStatistic"),
                "threshold": alarm.get("Threshold"),
                "comparison": alarm.get("ComparisonOperator"),
                "evaluation_periods": alarm.get("EvaluationPeriods"),
                "dimensions": {
                    x.get("Name"): x.get("Value") for x in alarm.get("Dimensions", []) or []
                },
                "alarm_rule": alarm.get("AlarmRule"),
                "ec2_actions": ec2_actions,
                "monitored_identifiers": list(dict.fromkeys(monitored)),
            },
            relations=relations,
        )

    async def _collect_cloudwatch_alarms(self) -> list[CloudAsset]:
        assets: list[CloudAsset] = []
        async with self._client("cloudwatch") as cw:
            paginator = cw.get_paginator("describe_alarms")
            async for page in paginator.paginate(AlarmTypes=["MetricAlarm", "CompositeAlarm"]):
                for alarm in page.get("MetricAlarms", []) or []:
                    assets.append(self._alarm_asset(alarm, composite=False))
                for alarm in page.get("CompositeAlarms", []) or []:
                    assets.append(self._alarm_asset(alarm, composite=True))
        return assets


# Alarm dimension -> monitored resource identifier. Each rule takes
# (collector, namespace, dimensions) and returns an identifier or None;
# evaluated in order, which fixes the order of the resulting relations.
def _raw(key: str) -> Any:
    return lambda c, ns, d: d.get(key)


def _arn_of(key: str, service: str, fmt: str, namespace: str | None = None) -> Any:
    def rule(c: Any, ns: str, d: dict) -> str | None:
        if not d.get(key) or (namespace and ns != namespace):
            return None
        return c._arn(service, fmt.format(d[key]))

    return rule


def _lambda_target(c: Any, ns: str, d: dict) -> str | None:
    if ns != "AWS/Lambda" or not d.get("FunctionName"):
        return None
    return c._arn("lambda", f"function:{d.get('Resource') or d['FunctionName']}")


def _elb_target(c: Any, ns: str, d: dict) -> str | None:
    if d.get("TargetGroup"):
        return c._arn("elasticloadbalancing", d["TargetGroup"])
    if d.get("LoadBalancer"):
        return c._arn("elasticloadbalancing", f"loadbalancer/{d['LoadBalancer']}")
    return None


def _ecs_target(c: Any, ns: str, d: dict) -> str | None:
    if ns != "AWS/ECS" or not d.get("ClusterName"):
        return None
    if d.get("ServiceName"):
        return c._arn("ecs", f"service/{d['ClusterName']}/{d['ServiceName']}")
    return c._arn("ecs", f"cluster/{d['ClusterName']}")


def _s3_target(c: Any, ns: str, d: dict) -> str | None:
    return f"arn:aws:s3:::{d['BucketName']}" if ns == "AWS/S3" and d.get("BucketName") else None


def _api_name_target(c: Any, ns: str, d: dict) -> str | None:
    return d.get("ApiName") if ns == "AWS/ApiGateway" else None


_DIMENSION_RULES = (
    _raw("InstanceId"),
    _raw("AutoScalingGroupName"),
    _lambda_target,
    _arn_of("QueueName", "sqs", "{}"),
    _arn_of("TopicName", "sns", "{}"),
    _arn_of("TableName", "dynamodb", "table/{}"),
    _arn_of("DBInstanceIdentifier", "rds", "db:{}"),
    _arn_of("DBClusterIdentifier", "rds", "cluster:{}"),
    _elb_target,
    _raw("LoadBalancerName"),
    _ecs_target,
    _raw("StateMachineArn"),
    _arn_of("StreamName", "kinesis", "stream/{}", "AWS/Kinesis"),
    _arn_of("DeliveryStreamName", "firehose", "deliverystream/{}"),
    _s3_target,
    *(_raw(k) for k in ("CacheClusterId", "VolumeId", "NatGatewayId", "ApiId", "FileSystemId")),
    _api_name_target,
)
