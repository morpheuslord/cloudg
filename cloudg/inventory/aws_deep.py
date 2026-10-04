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
from dataclasses import dataclass
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

# The task catalog lives in aws_deep_tasks; re-exported here
from cloudg.inventory.aws_deep_tasks import (
    _ARN_TYPE_MAP,
    DEEP_TASK_METHODS,
    GLOBAL_TASKS,
    SERVICE_FAMILIES,
    _arn_resource_type,
    asset_type_from_arn,
    select_tasks,
)
from cloudg.schema.models import AssetType, CloudAsset, CloudProvider, EdgeType

logger = logging.getLogger(__name__)


@dataclass
class DeepInventoryOptions:
    """Mapping options of :class:`AWSDeepInventoryCollector` (see its Args)."""

    tagging_sweep: bool = True
    is_primary_region: bool = True
    services: list[str] | None = None
    exclude_services: list[str] | None = None
    kubernetes: bool = True
    kubernetes_timeout: int = 10
    iam_resource_edges: bool = True
    max_images_per_repository: int = 20
    stack_resources: bool = True
    cloud_control: bool = True
    cloud_control_types: list[str] | None = None
    cloud_control_exclude: list[str] | None = None
    cloud_control_concurrency: int = 6


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
        **options: Any,
    ) -> None:
        super().__init__(session=session, region=region, account_id=account_id)
        # tagging_sweep stays the 4th positional parameter (0.5.0 public API);
        # unknown option names raise TypeError, as keyword parameters did
        opts = DeepInventoryOptions(tagging_sweep=tagging_sweep, **options)
        self._tagging_sweep = opts.tagging_sweep
        self._is_primary_region = opts.is_primary_region
        self._services = opts.services or ["all"]
        self._exclude_services = list(opts.exclude_services or [])
        inc = {s.lower() for s in self._services}
        self._kubernetes_enabled = (
            opts.kubernetes
            and "kubernetes" not in {e.lower() for e in self._exclude_services}
            and ("all" in inc or "kubernetes" in inc or "containers" in inc or "eks" in inc)
        )
        self._kubernetes_timeout = opts.kubernetes_timeout
        self._iam_resource_edges = opts.iam_resource_edges
        self._max_images = opts.max_images_per_repository
        self._stack_resources = opts.stack_resources
        self._cloud_control = opts.cloud_control
        self._cloud_control_types = list(opts.cloud_control_types or [])
        self._cloud_control_exclude = list(opts.cloud_control_exclude or [])
        self._cloud_control_concurrency = opts.cloud_control_concurrency

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
            try:
                await self._link_tgw_attachments(ec2, assets)
            except Exception as exc:
                logger.debug("Transit gateway attachment listing failed: %s", exc)
        return assets

    @staticmethod
    async def _link_tgw_attachments(ec2: Any, assets: list[CloudAsset]) -> None:
        """Record each transit gateway attachment as a routed relation."""
        by_tgw = {a.metadata["transit_gateway_id"]: a for a in assets}
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

    def _merge_registries(self, tasks: dict[str, Any]) -> set[str]:
        """Add the service-mixin task registries; returns the global tasks."""
        global_tasks = set(GLOBAL_TASKS)
        for registry in (
            self._governance_tasks(),
            self._network_ext_tasks(),
            self._application_tasks(),
            self._data_ml_tasks(),
            self._cloudcontrol_tasks(),
        ):
            for name, (task, family, is_global) in registry.items():
                tasks[name] = task
                SERVICE_FAMILIES.setdefault(name, family)
                if is_global:
                    global_tasks.add(name)
        return global_tasks

    def _service_tasks(self) -> dict[str, Any]:
        tasks = super()._service_tasks()
        # The identity mixin maps users, roles, groups, policies and
        # instance profiles in one call; drop the shallow per-type tasks.
        tasks.pop("iam_users", None)
        tasks.pop("iam_roles", None)
        tasks.update({name: getattr(self, method) for name, method in DEEP_TASK_METHODS})
        global_tasks = self._merge_registries(tasks)
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


# Public API, including names re-exported from the split-out modules
__all__ = [
    "asset_type_from_arn",
    "AWSDeepInventoryCollector",
    "DEEP_TASK_METHODS",
    "DeepInventoryOptions",
    "GLOBAL_TASKS",
    "select_tasks",
    "SERVICE_FAMILIES",
    "_arn_resource_type",
    "_ARN_TYPE_MAP",
]
