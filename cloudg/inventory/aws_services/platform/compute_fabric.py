"""Compute fabric: Auto Scaling groups -> instances / launch templates /
target groups, launch templates (AMI, instance profile, SGs), VPC endpoints
and VPC flow logs."""

from __future__ import annotations

import logging
from typing import Any

from cloudg.inventory.aws_services._base import AWSServiceMixin, gather_limited, rel
from cloudg.schema.models import AssetType, CloudAsset, EdgeType

logger = logging.getLogger(__package__)  # the package logger, as before the split


def _asg_launch_template(g: dict) -> dict[str, Any]:
    """The group's launch template, direct or via a mixed instances policy."""
    return (
        g.get("LaunchTemplate")
        or ((g.get("MixedInstancesPolicy") or {}).get("LaunchTemplate") or {}).get(
            "LaunchTemplateSpecification"
        )
        or {}
    )


def _asg_relations(g: dict, lt: dict[str, Any]) -> list[dict | None]:
    relations: list[dict | None] = [
        rel(
            lt.get("LaunchTemplateId"),
            EdgeType.REFERENCES,
            "DEPENDS_ON",
            description="launch template",
        ),
        rel(g.get("ServiceLinkedRoleARN"), EdgeType.ASSUMES_ROLE, "RUNS_ON"),
    ]
    relations += [
        rel(i.get("InstanceId"), EdgeType.MANAGES, "SCALES_WITH")
        for i in g.get("Instances", []) or []
    ]
    relations += [
        rel(tg, EdgeType.LOAD_BALANCER_TARGET, "LOAD_BALANCED_BY", reverse=True)
        for tg in g.get("TargetGroupARNs", []) or []
    ]
    subnets = [s.strip() for s in (g.get("VPCZoneIdentifier") or "").split(",") if s.strip()]
    relations += [
        rel(s, EdgeType.CONTAINS, "SUBNET_CONTAINS_INSTANCE", reverse=True) for s in subnets
    ]
    return relations


class ComputeFabricCollectorsMixin(AWSServiceMixin):
    async def _collect_autoscaling(self) -> list[CloudAsset]:
        assets: list[CloudAsset] = []
        async with self._client("autoscaling") as asg_client:
            async for g in self._paginate(
                asg_client, "describe_auto_scaling_groups", "AutoScalingGroups"
            ):
                lt = _asg_launch_template(g)
                assets.append(
                    self._asset(
                        arn=g["AutoScalingGroupARN"],
                        name=g["AutoScalingGroupName"],
                        asset_type=AssetType.AUTOSCALING_GROUP,
                        tags=g.get("Tags"),
                        metadata={
                            "min_size": g.get("MinSize"),
                            "max_size": g.get("MaxSize"),
                            "desired_capacity": g.get("DesiredCapacity"),
                            "instance_count": len(g.get("Instances", []) or []),
                            "launch_template": lt.get("LaunchTemplateName")
                            or lt.get("LaunchTemplateId"),
                            "launch_configuration": g.get("LaunchConfigurationName"),
                            "health_check_type": g.get("HealthCheckType"),
                        },
                        relations=_asg_relations(g, lt),
                    )
                )
        return assets

    async def _collect_launch_templates(self) -> list[CloudAsset]:
        async with self._client("ec2") as ec2:
            templates = [
                t async for t in self._paginate(ec2, "describe_launch_templates", "LaunchTemplates")
            ]
            results = await gather_limited(
                [lambda t=t: self._launch_template_asset(ec2, t) for t in templates]
            )
            return [a for a in results if a]

    async def _launch_template_asset(self, ec2: Any, t: dict) -> CloudAsset:
        data: dict[str, Any] = {}
        try:
            resp = await ec2.describe_launch_template_versions(
                LaunchTemplateId=t["LaunchTemplateId"], Versions=["$Latest"]
            )
            versions = resp.get("LaunchTemplateVersions", [])
            data = versions[0].get("LaunchTemplateData", {}) if versions else {}
        except Exception as exc:
            logger.debug("Launch template version lookup failed: %s", exc)
        profile = data.get("IamInstanceProfile") or {}
        sgs = list(data.get("SecurityGroupIds", []) or [])
        for ni in data.get("NetworkInterfaces", []) or []:
            sgs.extend(ni.get("Groups", []) or [])
        return self._asset(
            arn=self._arn("ec2", f"launch-template/{t['LaunchTemplateId']}"),
            name=t.get("LaunchTemplateName", t["LaunchTemplateId"]),
            asset_type=AssetType.LAUNCH_TEMPLATE,
            tags=t.get("Tags"),
            metadata={
                "launch_template_id": t["LaunchTemplateId"],
                "latest_version": t.get("LatestVersionNumber"),
                "image_id": data.get("ImageId"),
                "instance_type": data.get("InstanceType"),
                "security_groups": sgs,
                "imdsv2_required": (data.get("MetadataOptions") or {}).get("HttpTokens")
                == "required",
            },
            relations=[
                rel(
                    profile.get("Arn") or profile.get("Name"),
                    EdgeType.ASSUMES_ROLE,
                    "RUNS_ON",
                    description="instance profile",
                )
            ],
            aliases=[t["LaunchTemplateId"]],
        )

    async def _collect_vpc_endpoints(self) -> list[CloudAsset]:
        assets: list[CloudAsset] = []
        async with self._client("ec2") as ec2:
            async for ep in self._paginate(ec2, "describe_vpc_endpoints", "VpcEndpoints"):
                relations: list[dict | None] = [
                    rel(ep.get("VpcId"), EdgeType.CONTAINS, reverse=True),
                    rel(
                        ep.get("ServiceName"),
                        EdgeType.ROUTE,
                        "SERVES_TRAFFIC_TO",
                        description="consumes endpoint service",
                    ),
                ]
                relations += [
                    rel(s, EdgeType.CONTAINS, "SUBNET_CONTAINS_INSTANCE", reverse=True)
                    for s in ep.get("SubnetIds", []) or []
                ]
                relations += [
                    rel(r, EdgeType.ROUTE, "TRANSIT_ROUTED", reverse=True)
                    for r in ep.get("RouteTableIds", []) or []
                ]
                assets.append(
                    self._asset(
                        arn=self._arn("ec2", f"vpc-endpoint/{ep['VpcEndpointId']}"),
                        name=ep.get("ServiceName", ep["VpcEndpointId"]),
                        asset_type=AssetType.VPC_ENDPOINT,
                        tags=ep.get("Tags"),
                        metadata={
                            "vpc_endpoint_id": ep["VpcEndpointId"],
                            "service_name": ep.get("ServiceName"),
                            "endpoint_type": ep.get("VpcEndpointType"),
                            "state": ep.get("State"),
                            "private_dns": ep.get("PrivateDnsEnabled"),
                            "security_groups": [
                                g.get("GroupId") for g in ep.get("Groups", []) or []
                            ],
                        },
                        relations=relations,
                        aliases=[ep["VpcEndpointId"]],
                    )
                )
        return assets

    async def _collect_flow_logs(self) -> list[CloudAsset]:
        assets: list[CloudAsset] = []
        async with self._client("ec2") as ec2:
            async for fl in self._paginate(ec2, "describe_flow_logs", "FlowLogs"):
                dest = fl.get("LogDestination")
                if not dest and fl.get("LogGroupName"):
                    dest = self._arn("logs", f"log-group:{fl['LogGroupName']}")
                if dest and dest.startswith("arn:aws:s3:::"):
                    dest = dest.split("/", 1)[0]
                assets.append(
                    self._asset(
                        arn=self._arn("ec2", f"vpc-flow-log/{fl['FlowLogId']}"),
                        name=fl["FlowLogId"],
                        asset_type=AssetType.FLOW_LOG,
                        tags=fl.get("Tags"),
                        metadata={
                            "flow_log_id": fl["FlowLogId"],
                            "monitored_resource": fl.get("ResourceId"),
                            "traffic_type": fl.get("TrafficType"),
                            "destination_type": fl.get("LogDestinationType"),
                            "status": fl.get("FlowLogStatus"),
                        },
                        relations=[
                            rel(
                                fl.get("ResourceId"),
                                EdgeType.MONITORS,
                                "MONITORED_BY",
                                description="flow logging",
                            ),
                            rel(dest, EdgeType.LOGS_TO, "LOGS_TO"),
                            rel(
                                fl.get("DeliverLogsPermissionArn"), EdgeType.ASSUMES_ROLE, "RUNS_ON"
                            ),
                        ],
                    )
                )
        return assets
