"""CloudWatch metric and composite alarms: actions, scaling policies,
composite children and the resources a metric alarm monitors."""

from __future__ import annotations

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
        if d.get("InstanceId"):
            out.append(d["InstanceId"])
        if d.get("AutoScalingGroupName"):
            out.append(d["AutoScalingGroupName"])
        if namespace == "AWS/Lambda" and d.get("FunctionName"):
            res = d.get("Resource") or d["FunctionName"]
            out.append(self._arn("lambda", f"function:{res}"))
        if d.get("QueueName"):
            out.append(self._arn("sqs", d["QueueName"]))
        if d.get("TopicName"):
            out.append(self._arn("sns", d["TopicName"]))
        if d.get("TableName"):
            out.append(self._arn("dynamodb", f"table/{d['TableName']}"))
        if d.get("DBInstanceIdentifier"):
            out.append(self._arn("rds", f"db:{d['DBInstanceIdentifier']}"))
        if d.get("DBClusterIdentifier"):
            out.append(self._arn("rds", f"cluster:{d['DBClusterIdentifier']}"))
        if d.get("TargetGroup"):
            out.append(self._arn("elasticloadbalancing", d["TargetGroup"]))
        elif d.get("LoadBalancer"):
            out.append(self._arn("elasticloadbalancing", f"loadbalancer/{d['LoadBalancer']}"))
        if d.get("LoadBalancerName"):
            out.append(d["LoadBalancerName"])
        if namespace == "AWS/ECS" and d.get("ClusterName"):
            if d.get("ServiceName"):
                out.append(self._arn("ecs", f"service/{d['ClusterName']}/{d['ServiceName']}"))
            else:
                out.append(self._arn("ecs", f"cluster/{d['ClusterName']}"))
        if d.get("StateMachineArn"):
            out.append(d["StateMachineArn"])
        if namespace == "AWS/Kinesis" and d.get("StreamName"):
            out.append(self._arn("kinesis", f"stream/{d['StreamName']}"))
        if d.get("DeliveryStreamName"):
            out.append(self._arn("firehose", f"deliverystream/{d['DeliveryStreamName']}"))
        if namespace == "AWS/S3" and d.get("BucketName"):
            out.append(f"arn:aws:s3:::{d['BucketName']}")
        for key in ("CacheClusterId", "VolumeId", "NatGatewayId", "ApiId", "FileSystemId"):
            if d.get(key):
                out.append(d[key])
        if namespace == "AWS/ApiGateway" and d.get("ApiName"):
            out.append(d["ApiName"])
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
