"""Deep AWS inventory collector — full-account resource enumeration.

Extends the standard :class:`AsyncAWSCollector` with:

- The network fabric that connects everything: route tables, internet
  gateways, NAT gateways, network interfaces, EBS volumes, Elastic IPs,
  NACLs, VPC peering connections, and transit gateways.
- Customer-managed IAM policies (the glue of most cross-service access).
- A catch-all sweep over the Resource Groups Tagging API, which returns
  every taggable resource in the region — so services without a dedicated
  collector still appear on the map instead of silently missing.

This collector is used by the inventory mapper (``cloudg map``) and never
runs a security scanner.
"""

from __future__ import annotations

import logging
from typing import Any

from cloudg.collectors.aws import AsyncAWSCollector
from cloudg.schema.models import AssetType, CloudAsset, CloudProvider

logger = logging.getLogger(__name__)

# Maps "service" or "service:resource-type" (from an ARN) to an AssetType,
# used to classify resources found only by the tagging-API sweep.
_ARN_TYPE_MAP: dict[str, AssetType] = {
    "ec2:instance": AssetType.EC2,
    "ec2:volume": AssetType.EBS_VOLUME,
    "ec2:vpc": AssetType.VPC,
    "ec2:subnet": AssetType.SUBNET,
    "ec2:security-group": AssetType.SECURITY_GROUP,
    "ec2:route-table": AssetType.ROUTE_TABLE,
    "ec2:internet-gateway": AssetType.INTERNET_GATEWAY,
    "ec2:natgateway": AssetType.NAT_GATEWAY,
    "ec2:network-interface": AssetType.NETWORK_INTERFACE,
    "ec2:network-acl": AssetType.NACL,
    "ec2:elastic-ip": AssetType.ELASTIC_IP,
    "ec2:vpc-peering-connection": AssetType.PEERING_CONNECTION,
    "ec2:transit-gateway": AssetType.TRANSIT_GATEWAY,
    "s3": AssetType.S3_BUCKET,
    "rds:db": AssetType.RDS_INSTANCE,
    "rds:cluster": AssetType.AURORA_CLUSTER,
    "lambda:function": AssetType.LAMBDA_FUNCTION,
    "elasticloadbalancing:loadbalancer": AssetType.LOAD_BALANCER,
    "cloudfront:distribution": AssetType.CLOUDFRONT,
    "dynamodb:table": AssetType.DYNAMODB_TABLE,
    "ecs:cluster": AssetType.ECS_CLUSTER,
    "eks:cluster": AssetType.EKS_CLUSTER,
    "iam:user": AssetType.IAM_USER,
    "iam:role": AssetType.IAM_ROLE,
    "iam:policy": AssetType.IAM_POLICY,
    "iam:group": AssetType.IAM_GROUP,
    "kms:key": AssetType.KMS_KEY,
    "secretsmanager:secret": AssetType.SECRET,
    "acm:certificate": AssetType.CERTIFICATE,
    "cloudtrail:trail": AssetType.CLOUDTRAIL,
}


def asset_type_from_arn(arn: str) -> AssetType:
    """Best-effort AssetType classification from an ARN."""
    parts = arn.split(":", 5)
    if len(parts) < 6:
        return AssetType.OTHER
    service = parts[2]
    resource = parts[5]
    rtype = resource.split("/", 1)[0].split(":", 1)[0] if resource else ""
    return _ARN_TYPE_MAP.get(f"{service}:{rtype}", _ARN_TYPE_MAP.get(service, AssetType.OTHER))


class AWSDeepInventoryCollector(AsyncAWSCollector):
    """AWS collector with full network-fabric coverage plus a tagging-API
    sweep that catches every taggable resource the dedicated collectors miss."""

    def __init__(
        self,
        session: Any,
        region: str = "us-east-1",
        account_id: str | None = None,
        tagging_sweep: bool = True,
    ) -> None:
        super().__init__(session=session, region=region, account_id=account_id)
        self._tagging_sweep = tagging_sweep

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
                            },
                            raw_data=tgw,
                        )
                    )
        return assets

    async def _collect_iam_policies(self) -> list[CloudAsset]:
        """Customer-managed IAM policies (AWS-managed ones are noise)."""
        assets: list[CloudAsset] = []
        session = self._get_aio_session()
        async with session.client("iam", region_name="us-east-1") as iam:
            paginator = iam.get_paginator("list_policies")
            async for page in paginator.paginate(Scope="Local"):
                for pol in page.get("Policies", []):
                    assets.append(
                        CloudAsset(
                            arn=pol.get("Arn", ""),
                            name=pol.get("PolicyName", ""),
                            asset_type=AssetType.IAM_POLICY,
                            provider=CloudProvider.AWS,
                            region="global",
                            account_id=self._account_id,
                            metadata={
                                "policy_id": pol.get("PolicyId"),
                                "attachment_count": pol.get("AttachmentCount", 0),
                                "default_version": pol.get("DefaultVersionId"),
                            },
                            raw_data=pol,
                        )
                    )
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
        tasks.update(
            {
                "route_tables": self._collect_route_tables(),
                "internet_gateways": self._collect_internet_gateways(),
                "nat_gateways": self._collect_nat_gateways(),
                "network_interfaces": self._collect_network_interfaces(),
                "ebs_volumes": self._collect_ebs_volumes(),
                "elastic_ips": self._collect_elastic_ips(),
                "nacls": self._collect_nacls(),
                "vpc_peering": self._collect_vpc_peering(),
                "transit_gateways": self._collect_transit_gateways(),
                "iam_policies": self._collect_iam_policies(),
            }
        )
        if self._tagging_sweep:
            tasks["tagging_sweep"] = self._collect_tagging_sweep()
        return tasks

    async def collect(self) -> list[CloudAsset]:
        """Collect all assets, deduplicating tagging-sweep hits against the
        richer assets produced by the dedicated collectors."""
        assets = await super().collect()

        detailed = [a for a in assets if a.metadata.get("discovered_via") != "tagging-api"]
        swept = [a for a in assets if a.metadata.get("discovered_via") == "tagging-api"]

        known_arns = {a.arn for a in detailed if a.arn}
        merged = detailed + [a for a in swept if a.arn not in known_arns]

        dropped = len(assets) - len(merged)
        if dropped:
            logger.debug("Tagging sweep: %d duplicates dropped, kept detailed assets", dropped)
        self._cached_assets = merged
        return merged
