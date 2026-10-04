"""Deep AWS inventory collector — full-account resource enumeration.

Extends the standard :class:`AsyncAWSCollector` with:

- The network fabric that connects everything: route tables, internet
  gateways, NAT gateways, network interfaces, EBS volumes, Elastic IPs,
  NACLs, VPC peering connections, transit gateways and their attachments,
  VPC endpoints and flow logs.
- The service collectors in :mod:`cloudg.inventory.aws_services`:
  identity (the full IAM graph), containers (ECR, ECS, EKS and in-cluster
  Kubernetes workloads), serverless and integration (Lambda, API Gateway,
  SQS, SNS, EventBridge, Step Functions, Kinesis), security services and
  scanners (GuardDuty, Security Hub, Inspector, Macie, Config, Access
  Analyzer, WAF, Network Firewall, Shield, CloudTrail, Detective), and
  platform/data/DNS/deployment services.
- A catch-all sweep over the Resource Groups Tagging API, which returns
  every taggable resource in the region — so services without a dedicated
  collector still appear on the map instead of silently missing.

Global services (IAM, S3, CloudFront, Route 53, Shield, CloudFront-scope
WAF) are collected once per account, in the primary region only.

Every collector is assigned to a service family (see
:data:`SERVICE_FAMILIES`) so a run can be narrowed with
``inventory.services`` / ``inventory.exclude_services``.

This collector is used by the inventory mapper (``cloudg map``) and never
runs a security scanner.
"""

from __future__ import annotations

import logging
from typing import Any

from cloudg.collectors.aws import AsyncAWSCollector
from cloudg.inventory.aws_services import (
    ApplicationCollectorsMixin,
    CloudControlCollectorsMixin,
    ContainerCollectorsMixin,
    DataMLCollectorsMixin,
    GovernanceCollectorsMixin,
    IdentityCollectorsMixin,
    NetworkExtCollectorsMixin,
    PlatformCollectorsMixin,
    SecurityCollectorsMixin,
    ServerlessCollectorsMixin,
)
from cloudg.inventory.aws_services._base import rel
from cloudg.inventory.catalogs import asset_type_map, load_catalog
from cloudg.schema.models import AssetType, CloudAsset, CloudProvider, EdgeType

logger = logging.getLogger(__name__)

# Maps "service" or "service:resource-type" (from an ARN) to an AssetType,
# used to classify resources found only by the breadth sweeps. The table
# lives in catalogs/aws_arn_types.yaml.
_ARN_TYPE_MAP: dict[str, AssetType] = asset_type_map(
    load_catalog("aws_arn_types").get("arn_types"), "aws_arn_types"
)

# Collector task name -> service family, used by inventory.services filtering.
SERVICE_FAMILIES: dict[str, str] = {
    "ec2": "compute",
    "autoscaling": "compute",
    "launch_templates": "compute",
    "vpc": "network",
    "subnets": "network",
    "security_groups": "network",
    "route_tables": "network",
    "internet_gateways": "network",
    "nat_gateways": "network",
    "network_interfaces": "network",
    "elastic_ips": "network",
    "nacls": "network",
    "vpc_peering": "network",
    "transit_gateways": "network",
    "vpc_endpoints": "network",
    "elbv2": "network",
    "elb_classic": "network",
    "cloudfront": "network",
    "ebs_volumes": "storage",
    "s3": "storage",
    "efs": "storage",
    "rds": "data",
    "dynamodb": "data",
    "elasticache": "data",
    "opensearch": "data",
    "redshift": "data",
    "iam": "identity",
    "kms": "identity",
    "secretsmanager": "identity",
    "acm": "identity",
    "ecr": "containers",
    "ecs": "containers",
    "eks": "containers",
    "lambda": "serverless",
    "apigateway": "serverless",
    "apigatewayv2": "serverless",
    "stepfunctions": "serverless",
    "sqs": "integration",
    "sns": "integration",
    "eventbridge": "integration",
    "kinesis": "integration",
    "guardduty": "security",
    "securityhub": "security",
    "inspector2": "security",
    "macie": "security",
    "config": "security",
    "access_analyzer": "security",
    "detective": "security",
    "wafv2": "security",
    "network_firewall": "security",
    "shield": "security",
    "cloudtrail": "logging",
    "flow_logs": "logging",
    "log_groups": "logging",
    "route53": "dns",
    "cloudformation": "iac",
    "tagging_sweep": "sweep",
    "cloud_control": "sweep",
}

# Account-wide services: collected once per account, in the primary region.
GLOBAL_TASKS = {"iam", "s3", "cloudfront", "route53", "shield"}


def _arn_resource_type(service: str, resource: str) -> str:
    path = resource.lstrip("/")
    if service == "wafv2":
        parts = path.split("/")
        return parts[1] if len(parts) > 1 else parts[0]
    if service == "apigateway":
        parts = path.split("/")
        return f"{parts[0]}/{parts[2]}" if len(parts) > 2 else parts[0]
    return path.split("/", 1)[0].split(":", 1)[0] if path else ""


def asset_type_from_arn(arn: str) -> AssetType:
    """Best-effort AssetType classification from an ARN (see
    catalogs/aws_arn_types.yaml for the table and matching rules)."""
    parts = arn.split(":", 5)
    if len(parts) < 6:
        return AssetType.OTHER
    service, region, account, resource = parts[2], parts[3], parts[4], parts[5]
    rtype = _arn_resource_type(service, resource)
    found = _ARN_TYPE_MAP.get(f"{service}:{rtype}")
    if found is not None:
        return found
    if service == "s3" and (region or account or "/" in resource):
        return AssetType.OTHER  # access points, jobs, ... are not buckets
    return _ARN_TYPE_MAP.get(service, AssetType.OTHER)


def select_tasks(
    names: list[str], include: list[str] | None = None, exclude: list[str] | None = None
) -> list[str]:
    """Filter collector task names by family or task name.

    ``include`` defaults to everything (``["all"]``); ``exclude`` always wins.
    "kubernetes" is a pseudo-family that only toggles in-cluster mapping.
    """
    inc = {i.lower() for i in (include or ["all"])}
    exc = {e.lower() for e in (exclude or [])}
    selected = []
    for name in names:
        family = SERVICE_FAMILIES.get(name, "other")
        if name in exc or family in exc:
            continue
        if "all" in inc or name in inc or family in inc or (name == "eks" and "kubernetes" in inc):
            selected.append(name)
    return selected


class AWSDeepInventoryCollector(
    GovernanceCollectorsMixin,
    NetworkExtCollectorsMixin,
    ApplicationCollectorsMixin,
    DataMLCollectorsMixin,
    IdentityCollectorsMixin,
    ContainerCollectorsMixin,
    ServerlessCollectorsMixin,
    SecurityCollectorsMixin,
    PlatformCollectorsMixin,
    CloudControlCollectorsMixin,
    AsyncAWSCollector,
):
    """AWS collector with full network-fabric and service coverage plus a
    tagging-API sweep that catches every taggable resource the dedicated
    collectors miss.

    Args:
        session: boto3 session for the target account.
        region: Region to collect.
        account_id: Account the session belongs to.
        tagging_sweep: Run the Resource Groups Tagging API sweep.
        is_primary_region: Collect account-wide (global) services here.
            The orchestrator sets this for exactly one region per account.
        services: Families / task names to include (default: all).
        exclude_services: Families / task names to skip.
        kubernetes: Map workloads inside EKS clusters via the k8s API.
        kubernetes_timeout: Kubernetes API timeout in seconds.
        iam_resource_edges: Link principals to resources their policies grant.
        max_images_per_repository: ECR images sampled per repository.
        stack_resources: Link CloudFormation stacks to managed resources.
        cloud_control: Run the Cloud Control API breadth sweep.
        cloud_control_types: Only these CloudFormation types / prefixes.
        cloud_control_exclude: Skip these CloudFormation types / prefixes.
        cloud_control_concurrency: Types listed in parallel per region.
    """

    supports_region_scoping = True

    def __init__(
        self,
        session: Any,
        region: str = "us-east-1",
        account_id: str | None = None,
        tagging_sweep: bool = True,
        is_primary_region: bool = True,
        services: list[str] | None = None,
        exclude_services: list[str] | None = None,
        kubernetes: bool = True,
        kubernetes_timeout: int = 10,
        iam_resource_edges: bool = True,
        max_images_per_repository: int = 20,
        stack_resources: bool = True,
        cloud_control: bool = True,
        cloud_control_types: list[str] | None = None,
        cloud_control_exclude: list[str] | None = None,
        cloud_control_concurrency: int = 6,
    ) -> None:
        super().__init__(session=session, region=region, account_id=account_id)
        self._tagging_sweep = tagging_sweep
        self._is_primary_region = is_primary_region
        self._services = services or ["all"]
        self._exclude_services = list(exclude_services or [])
        inc = {s.lower() for s in self._services}
        self._kubernetes_enabled = kubernetes and "kubernetes" not in {
            e.lower() for e in self._exclude_services
        } and ("all" in inc or "kubernetes" in inc or "containers" in inc or "eks" in inc)
        self._kubernetes_timeout = kubernetes_timeout
        self._iam_resource_edges = iam_resource_edges
        self._max_images = max_images_per_repository
        self._stack_resources = stack_resources
        self._cloud_control = cloud_control
        self._cloud_control_types = list(cloud_control_types or [])
        self._cloud_control_exclude = list(cloud_control_exclude or [])
        self._cloud_control_concurrency = cloud_control_concurrency

    # ------------------------------------------------------------------
    # Network fabric collectors
    # ------------------------------------------------------------------

    async def _collect_route_tables(self) -> list[CloudAsset]:
        assets: list[CloudAsset] = []
        session = self._get_aio_session()
        async with session.client("ec2", region_name=self._region) as ec2:
            response = await ec2.describe_route_tables()
            for rt in response.get("RouteTables", []):
                tags = {t["Key"]: t["Value"] for t in rt.get("Tags", [])}
                assets.append(
                    CloudAsset(
                        arn=f"arn:aws:ec2:{self._region}:{self._account_id}:route-table/{rt['RouteTableId']}",
                        name=tags.get("Name", rt["RouteTableId"]),
                        asset_type=AssetType.ROUTE_TABLE,
                        provider=CloudProvider.AWS,
                        region=self._region,
                        account_id=self._account_id,
                        tags=tags,
                        metadata={
                            "route_table_id": rt["RouteTableId"],
                            "vpc_id": rt.get("VpcId"),
                            "routes": rt.get("Routes", []),
                            "associations": rt.get("Associations", []),
                        },
                        raw_data=rt,
                    )
                )
        return assets

    async def _collect_internet_gateways(self) -> list[CloudAsset]:
        assets: list[CloudAsset] = []
        session = self._get_aio_session()
        async with session.client("ec2", region_name=self._region) as ec2:
            response = await ec2.describe_internet_gateways()
            for igw in response.get("InternetGateways", []):
                tags = {t["Key"]: t["Value"] for t in igw.get("Tags", [])}
                assets.append(
                    CloudAsset(
                        arn=f"arn:aws:ec2:{self._region}:{self._account_id}:internet-gateway/{igw['InternetGatewayId']}",
                        name=tags.get("Name", igw["InternetGatewayId"]),
                        asset_type=AssetType.INTERNET_GATEWAY,
                        provider=CloudProvider.AWS,
                        region=self._region,
                        account_id=self._account_id,
                        tags=tags,
                        is_internet_exposed=True,
                        metadata={
                            "internet_gateway_id": igw["InternetGatewayId"],
                            "attachments": igw.get("Attachments", []),
                        },
                        raw_data=igw,
                    )
                )
        return assets

    async def _collect_nat_gateways(self) -> list[CloudAsset]:
        assets: list[CloudAsset] = []
        session = self._get_aio_session()
        async with session.client("ec2", region_name=self._region) as ec2:
            paginator = ec2.get_paginator("describe_nat_gateways")
            async for page in paginator.paginate():
                for nat in page.get("NatGateways", []):
                    tags = {t["Key"]: t["Value"] for t in nat.get("Tags", [])}
                    assets.append(
                        CloudAsset(
                            arn=f"arn:aws:ec2:{self._region}:{self._account_id}:natgateway/{nat['NatGatewayId']}",
                            name=tags.get("Name", nat["NatGatewayId"]),
                            asset_type=AssetType.NAT_GATEWAY,
                            provider=CloudProvider.AWS,
                            region=self._region,
                            account_id=self._account_id,
                            tags=tags,
                            metadata={
                                "nat_gateway_id": nat["NatGatewayId"],
                                "vpc_id": nat.get("VpcId"),
                                "subnet_id": nat.get("SubnetId"),
                                "state": nat.get("State"),
                                "connectivity_type": nat.get("ConnectivityType"),
                            },
                            raw_data=nat,
                        )
                    )
        return assets

    async def _collect_network_interfaces(self) -> list[CloudAsset]:
        assets: list[CloudAsset] = []
        session = self._get_aio_session()
        async with session.client("ec2", region_name=self._region) as ec2:
            paginator = ec2.get_paginator("describe_network_interfaces")
            async for page in paginator.paginate():
                for eni in page.get("NetworkInterfaces", []):
                    assets.append(
                        CloudAsset(
                            arn=f"arn:aws:ec2:{self._region}:{self._account_id}:network-interface/{eni['NetworkInterfaceId']}",
                            name=eni["NetworkInterfaceId"],
                            asset_type=AssetType.NETWORK_INTERFACE,
                            provider=CloudProvider.AWS,
                            region=self._region,
                            account_id=self._account_id,
                            metadata={
                                "network_interface_id": eni["NetworkInterfaceId"],
                                "vpc_id": eni.get("VpcId"),
                                "subnet_id": eni.get("SubnetId"),
                                "security_groups": [g["GroupId"] for g in eni.get("Groups", [])],
                                "private_ip": eni.get("PrivateIpAddress"),
                                "public_ip": eni.get("Association", {}).get("PublicIp"),
                                "attached_instance_id": eni.get("Attachment", {}).get("InstanceId"),
                                "interface_type": eni.get("InterfaceType"),
                                "description": eni.get("Description", ""),
                            },
                            raw_data=eni,
                        )
                    )
        return assets

    async def _collect_ebs_volumes(self) -> list[CloudAsset]:
        assets: list[CloudAsset] = []
        session = self._get_aio_session()
        async with session.client("ec2", region_name=self._region) as ec2:
            paginator = ec2.get_paginator("describe_volumes")
            async for page in paginator.paginate():
                for vol in page.get("Volumes", []):
                    tags = {t["Key"]: t["Value"] for t in vol.get("Tags", [])}
                    assets.append(
                        CloudAsset(
                            arn=f"arn:aws:ec2:{self._region}:{self._account_id}:volume/{vol['VolumeId']}",
                            name=tags.get("Name", vol["VolumeId"]),
                            asset_type=AssetType.EBS_VOLUME,
                            provider=CloudProvider.AWS,
                            region=self._region,
                            account_id=self._account_id,
                            tags=tags,
                            metadata={
                                "volume_id": vol["VolumeId"],
                                "size_gb": vol.get("Size"),
                                "state": vol.get("State"),
                                "encrypted": vol.get("Encrypted", False),
                                "volume_type": vol.get("VolumeType"),
                                "attached_instance_ids": [
                                    a.get("InstanceId")
                                    for a in vol.get("Attachments", [])
                                    if a.get("InstanceId")
                                ],
                            },
                            raw_data=vol,
                        )
                    )
        return assets

    async def _collect_elastic_ips(self) -> list[CloudAsset]:
        assets: list[CloudAsset] = []
        session = self._get_aio_session()
        async with session.client("ec2", region_name=self._region) as ec2:
            response = await ec2.describe_addresses()
            for addr in response.get("Addresses", []):
                tags = {t["Key"]: t["Value"] for t in addr.get("Tags", [])}
                alloc = addr.get("AllocationId", addr.get("PublicIp", ""))
                assets.append(
                    CloudAsset(
                        arn=f"arn:aws:ec2:{self._region}:{self._account_id}:elastic-ip/{alloc}",
                        name=tags.get("Name", addr.get("PublicIp", alloc)),
                        asset_type=AssetType.ELASTIC_IP,
                        provider=CloudProvider.AWS,
                        region=self._region,
                        account_id=self._account_id,
                        tags=tags,
                        is_internet_exposed=True,
                        metadata={
                            "allocation_id": addr.get("AllocationId"),
                            "public_ip": addr.get("PublicIp"),
                            "attached_instance_id": addr.get("InstanceId"),
                            "network_interface_id": addr.get("NetworkInterfaceId"),
                        },
                        raw_data=addr,
                    )
                )
        return assets

    async def _collect_nacls(self) -> list[CloudAsset]:
        assets: list[CloudAsset] = []
        session = self._get_aio_session()
        async with session.client("ec2", region_name=self._region) as ec2:
            response = await ec2.describe_network_acls()
            for nacl in response.get("NetworkAcls", []):
                tags = {t["Key"]: t["Value"] for t in nacl.get("Tags", [])}
                assets.append(
                    CloudAsset(
                        arn=f"arn:aws:ec2:{self._region}:{self._account_id}:network-acl/{nacl['NetworkAclId']}",
                        name=tags.get("Name", nacl["NetworkAclId"]),
                        asset_type=AssetType.NACL,
                        provider=CloudProvider.AWS,
                        region=self._region,
                        account_id=self._account_id,
                        tags=tags,
                        metadata={
                            "network_acl_id": nacl["NetworkAclId"],
                            "vpc_id": nacl.get("VpcId"),
                            "is_default": nacl.get("IsDefault", False),
                            "entries": nacl.get("Entries", []),
                            "associations": nacl.get("Associations", []),
                        },
                        raw_data=nacl,
                    )
                )
        return assets

    async def _collect_vpc_peering(self) -> list[CloudAsset]:
        assets: list[CloudAsset] = []
        session = self._get_aio_session()
        async with session.client("ec2", region_name=self._region) as ec2:
            response = await ec2.describe_vpc_peering_connections()
            for pcx in response.get("VpcPeeringConnections", []):
                tags = {t["Key"]: t["Value"] for t in pcx.get("Tags", [])}
                assets.append(
                    CloudAsset(
                        arn=f"arn:aws:ec2:{self._region}:{self._account_id}:vpc-peering-connection/{pcx['VpcPeeringConnectionId']}",
                        name=tags.get("Name", pcx["VpcPeeringConnectionId"]),
                        asset_type=AssetType.PEERING_CONNECTION,
                        provider=CloudProvider.AWS,
                        region=self._region,
                        account_id=self._account_id,
                        tags=tags,
                        metadata={
                            "peering_connection_id": pcx["VpcPeeringConnectionId"],
                            "requester_vpc_id": pcx.get("RequesterVpcInfo", {}).get("VpcId"),
                            "accepter_vpc_id": pcx.get("AccepterVpcInfo", {}).get("VpcId"),
                            "status": pcx.get("Status", {}).get("Code"),
                        },
                        raw_data=pcx,
                    )
                )
        return assets

    async def _collect_transit_gateways(self) -> list[CloudAsset]:
        assets: list[CloudAsset] = []
        session = self._get_aio_session()
        async with session.client("ec2", region_name=self._region) as ec2:
            paginator = ec2.get_paginator("describe_transit_gateways")
            async for page in paginator.paginate():
                for tgw in page.get("TransitGateways", []):
                    tags = {t["Key"]: t["Value"] for t in tgw.get("Tags", [])}
                    assets.append(
                        CloudAsset(
                            arn=tgw.get("TransitGatewayArn", ""),
                            name=tags.get("Name", tgw.get("TransitGatewayId", "")),
                            asset_type=AssetType.TRANSIT_GATEWAY,
                            provider=CloudProvider.AWS,
                            region=self._region,
                            account_id=self._account_id,
                            tags=tags,
                            metadata={
                                "transit_gateway_id": tgw.get("TransitGatewayId"),
                                "state": tgw.get("State"),
                                "owner_id": tgw.get("OwnerId"),
                            },
                            raw_data=tgw,
                        )
                    )

            # Attachments (VPCs, VPNs, peerings — possibly in other accounts)
            by_tgw = {a.metadata["transit_gateway_id"]: a for a in assets}
            try:
                paginator = ec2.get_paginator("describe_transit_gateway_attachments")
                async for page in paginator.paginate():
                    for att in page.get("TransitGatewayAttachments", []):
                        owner = by_tgw.get(att.get("TransitGatewayId"))
                        if owner is None:
                            continue
                        r = rel(
                            att.get("ResourceId"),
                            EdgeType.ROUTE,
                            "TRANSIT_ROUTED",
                            description=f"{att.get('ResourceType')} attachment",
                            resource_owner=att.get("ResourceOwnerId"),
                            state=att.get("State"),
                        )
                        if r:
                            owner.metadata.setdefault("relations", []).append(r)
                            owner.metadata.setdefault("attachments", []).append(
                                {
                                    "resource_id": att.get("ResourceId"),
                                    "resource_type": att.get("ResourceType"),
                                    "resource_owner": att.get("ResourceOwnerId"),
                                }
                            )
            except Exception as exc:
                logger.debug("Transit gateway attachment listing failed: %s", exc)
        return assets

    # ------------------------------------------------------------------
    # Catch-all tagging-API sweep
    # ------------------------------------------------------------------

    async def _collect_tagging_sweep(self) -> list[CloudAsset]:
        """Enumerate every taggable resource in the region via the Resource
        Groups Tagging API. Duplicates of dedicated collectors are dropped
        later (dedupe by ARN in :meth:`collect`)."""
        assets: list[CloudAsset] = []
        session = self._get_aio_session()
        async with session.client("resourcegroupstaggingapi", region_name=self._region) as tagging:
            paginator = tagging.get_paginator("get_resources")
            async for page in paginator.paginate():
                for res in page.get("ResourceTagMappingList", []):
                    arn = res.get("ResourceARN", "")
                    if not arn:
                        continue
                    tags = {t["Key"]: t["Value"] for t in res.get("Tags", [])}
                    name = arn.rsplit("/", 1)[-1].rsplit(":", 1)[-1]
                    assets.append(
                        CloudAsset(
                            arn=arn,
                            name=tags.get("Name", name),
                            asset_type=asset_type_from_arn(arn),
                            provider=CloudProvider.AWS,
                            region=self._region,
                            account_id=self._account_id,
                            tags=tags,
                            metadata={
                                "discovered_via": "tagging-api",
                                "service": arn.split(":")[2] if arn.count(":") >= 2 else "",
                            },
                        )
                    )
        return assets

    # ------------------------------------------------------------------
    # Main interface
    # ------------------------------------------------------------------

    def _service_tasks(self) -> dict[str, Any]:
        tasks = super()._service_tasks()
        # The identity mixin maps users, roles, groups, policies and
        # instance profiles in one call; drop the shallow per-type tasks.
        tasks.pop("iam_users", None)
        tasks.pop("iam_roles", None)
        tasks.update(
            {
                "iam": self._collect_iam,
                "route_tables": self._collect_route_tables,
                "internet_gateways": self._collect_internet_gateways,
                "nat_gateways": self._collect_nat_gateways,
                "network_interfaces": self._collect_network_interfaces,
                "ebs_volumes": self._collect_ebs_volumes,
                "elastic_ips": self._collect_elastic_ips,
                "nacls": self._collect_nacls,
                "vpc_peering": self._collect_vpc_peering,
                "transit_gateways": self._collect_transit_gateways,
                "vpc_endpoints": self._collect_vpc_endpoints,
                "flow_logs": self._collect_flow_logs,
                "elb_classic": self._collect_elb_classic,
                "autoscaling": self._collect_autoscaling,
                "launch_templates": self._collect_launch_templates,
                "efs": self._collect_efs,
                "elasticache": self._collect_elasticache,
                "opensearch": self._collect_opensearch,
                "redshift": self._collect_redshift,
                "route53": self._collect_route53,
                "cloudformation": self._collect_cloudformation,
                "log_groups": self._collect_log_groups,
                "acm": self._collect_acm,
                "ecr": self._collect_ecr,
                "eks": self._collect_eks,
                "apigateway": self._collect_apigateway,
                "apigatewayv2": self._collect_apigatewayv2,
                "sqs": self._collect_sqs,
                "sns": self._collect_sns,
                "eventbridge": self._collect_eventbridge,
                "stepfunctions": self._collect_stepfunctions,
                "kinesis": self._collect_kinesis,
                "guardduty": self._collect_guardduty,
                "securityhub": self._collect_securityhub,
                "inspector2": self._collect_inspector2,
                "macie": self._collect_macie,
                "config": self._collect_config,
                "access_analyzer": self._collect_access_analyzer,
                "detective": self._collect_detective,
                "wafv2": self._collect_wafv2,
                "network_firewall": self._collect_network_firewall,
                "shield": self._collect_shield,
                "cloudtrail": self._collect_cloudtrail,
            }
        )
        global_tasks = set(GLOBAL_TASKS)
        for registry in (self._governance_tasks(),
            self._network_ext_tasks(),
            self._application_tasks(),
            self._data_ml_tasks(),
            self._cloudcontrol_tasks(),):
            for name, (task, family, is_global) in registry.items():
                tasks[name] = task
                SERVICE_FAMILIES.setdefault(name, family)
                if is_global:
                    global_tasks.add(name)
        if self._tagging_sweep:
            tasks["tagging_sweep"] = self._collect_tagging_sweep
        if not self._is_primary_region:
            for name in global_tasks:
                tasks.pop(name, None)
        selected = set(select_tasks(list(tasks), self._services, self._exclude_services))
        return {name: task for name, task in tasks.items() if name in selected}

    async def collect(self) -> list[CloudAsset]:
        """Collect all assets, deduplicating breadth-sweep hits against the
        richer assets produced by the dedicated collectors.

        Precedence: dedicated collector > Cloud Control > tagging API. A
        sweep hit is dropped when its ARN or identifier matches an asset
        that ranks higher."""
        assets = await super().collect()

        def tier(a: CloudAsset) -> int:
            via = a.metadata.get("discovered_via")
            return {"cloud-control": 1, "tagging-api": 2}.get(via, 0)

        merged: list[CloudAsset] = []
        known: set[str] = set()
        for rank in (0, 1, 2):
            for a in assets:
                if tier(a) != rank:
                    continue
                keys = {a.arn} if a.arn else set()
                if rank:
                    keys |= set(a.metadata.get("aliases") or [])
                    if keys & known:
                        continue
                merged.append(a)
                known.update(k for k in ({a.arn} | set(a.metadata.get("aliases") or [])) if k)

        dropped = len(assets) - len(merged)
        if dropped:
            logger.debug("Breadth sweeps: %d duplicates dropped, kept detailed assets", dropped)
        self._cached_assets = merged
        return merged
