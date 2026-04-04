"""Async AWS resource collector using aioboto3."""

from __future__ import annotations

import asyncio
import logging
from typing import Any

from cloudmapper.collectors.base import BaseCollector
from cloudmapper.schema.models import (
    AssetType,
    CloudAsset,
    CloudProvider,
    EdgeType,
    NetworkEdge,
)

logger = logging.getLogger(__name__)


class AsyncAWSCollector(BaseCollector):
    """Collects AWS resources asynchronously using aioboto3.

    Enumerates: EC2, S3, RDS, VPC, Subnets, Security Groups,
    IAM Users/Roles/Policies, Lambda, ELBv2, EBS, NAT/Internet Gateways.
    """

    def __init__(
        self,
        session: Any,
        region: str = "us-east-1",
        account_id: str | None = None,
    ) -> None:
        self._boto3_session = session
        self._region = region
        self._account_id = account_id
        self._aioboto3_session: Any = None

    def _get_aio_session(self) -> Any:
        """Lazy-init aioboto3 session."""
        if self._aioboto3_session is None:
            import aioboto3

            self._aioboto3_session = aioboto3.Session(
                region_name=self._region,
                profile_name=self._boto3_session.profile_name,
            )
        return self._aioboto3_session

    # ------------------------------------------------------------------
    # Individual service collectors
    # ------------------------------------------------------------------

    async def _collect_ec2(self) -> list[CloudAsset]:
        """Collect EC2 instances."""
        assets: list[CloudAsset] = []
        session = self._get_aio_session()
        try:
            async with session.client("ec2", region_name=self._region) as ec2:
                paginator = ec2.get_paginator("describe_instances")
                async for page in paginator.paginate():
                    for reservation in page.get("Reservations", []):
                        for inst in reservation.get("Instances", []):
                            tags = {
                                t["Key"]: t["Value"]
                                for t in inst.get("Tags", [])
                            }
                            assets.append(
                                CloudAsset(
                                    arn=f"arn:aws:ec2:{self._region}:{self._account_id}:instance/{inst['InstanceId']}",
                                    name=tags.get("Name", inst["InstanceId"]),
                                    asset_type=AssetType.EC2,
                                    provider=CloudProvider.AWS,
                                    region=self._region,
                                    account_id=self._account_id,
                                    tags=tags,
                                    metadata={
                                        "instance_type": inst.get("InstanceType"),
                                        "state": inst.get("State", {}).get("Name"),
                                        "vpc_id": inst.get("VpcId"),
                                        "subnet_id": inst.get("SubnetId"),
                                        "public_ip": inst.get("PublicIpAddress"),
                                        "private_ip": inst.get("PrivateIpAddress"),
                                        "image_id": inst.get("ImageId"),
                                        "security_groups": [
                                            sg["GroupId"]
                                            for sg in inst.get("SecurityGroups", [])
                                        ],
                                    },
                                    raw_data=inst,
                                )
                            )
        except Exception as exc:
            logger.error("Failed to collect EC2 instances: %s", exc)
        return assets

    async def _collect_s3(self) -> list[CloudAsset]:
        """Collect S3 buckets."""
        assets: list[CloudAsset] = []
        session = self._get_aio_session()
        try:
            async with session.client("s3", region_name=self._region) as s3:
                response = await s3.list_buckets()
                for bucket in response.get("Buckets", []):
                    bucket_name = bucket["Name"]
                    # Get bucket details
                    metadata: dict[str, Any] = {"creation_date": str(bucket.get("CreationDate", ""))}
                    try:
                        acl = await s3.get_bucket_acl(Bucket=bucket_name)
                        metadata["acl_grants"] = len(acl.get("Grants", []))
                    except Exception:
                        pass
                    try:
                        pub = await s3.get_public_access_block(Bucket=bucket_name)
                        metadata["public_access_block"] = pub.get(
                            "PublicAccessBlockConfiguration", {}
                        )
                    except Exception:
                        metadata["public_access_block"] = None
                    try:
                        enc = await s3.get_bucket_encryption(Bucket=bucket_name)
                        metadata["encryption"] = True
                    except Exception:
                        metadata["encryption"] = False

                    assets.append(
                        CloudAsset(
                            arn=f"arn:aws:s3:::{bucket_name}",
                            name=bucket_name,
                            asset_type=AssetType.S3_BUCKET,
                            provider=CloudProvider.AWS,
                            region="global",
                            account_id=self._account_id,
                            metadata=metadata,
                            raw_data=bucket,
                        )
                    )
        except Exception as exc:
            logger.error("Failed to collect S3 buckets: %s", exc)
        return assets

    async def _collect_rds(self) -> list[CloudAsset]:
        """Collect RDS instances."""
        assets: list[CloudAsset] = []
        session = self._get_aio_session()
        try:
            async with session.client("rds", region_name=self._region) as rds:
                paginator = rds.get_paginator("describe_db_instances")
                async for page in paginator.paginate():
                    for db in page.get("DBInstances", []):
                        assets.append(
                            CloudAsset(
                                arn=db.get("DBInstanceArn", ""),
                                name=db.get("DBInstanceIdentifier", ""),
                                asset_type=AssetType.RDS_INSTANCE,
                                provider=CloudProvider.AWS,
                                region=self._region,
                                account_id=self._account_id,
                                metadata={
                                    "engine": db.get("Engine"),
                                    "engine_version": db.get("EngineVersion"),
                                    "instance_class": db.get("DBInstanceClass"),
                                    "multi_az": db.get("MultiAZ", False),
                                    "publicly_accessible": db.get(
                                        "PubliclyAccessible", False
                                    ),
                                    "storage_encrypted": db.get(
                                        "StorageEncrypted", False
                                    ),
                                    "vpc_id": db.get("DBSubnetGroup", {}).get(
                                        "VpcId"
                                    ),
                                },
                                raw_data=db,
                            )
                        )
        except Exception as exc:
            logger.error("Failed to collect RDS instances: %s", exc)
        return assets

    async def _collect_vpcs(self) -> list[CloudAsset]:
        """Collect VPCs."""
        assets: list[CloudAsset] = []
        session = self._get_aio_session()
        try:
            async with session.client("ec2", region_name=self._region) as ec2:
                response = await ec2.describe_vpcs()
                for vpc in response.get("Vpcs", []):
                    tags = {t["Key"]: t["Value"] for t in vpc.get("Tags", [])}
                    assets.append(
                        CloudAsset(
                            arn=f"arn:aws:ec2:{self._region}:{self._account_id}:vpc/{vpc['VpcId']}",
                            name=tags.get("Name", vpc["VpcId"]),
                            asset_type=AssetType.VPC,
                            provider=CloudProvider.AWS,
                            region=self._region,
                            account_id=self._account_id,
                            tags=tags,
                            metadata={
                                "vpc_id": vpc["VpcId"],
                                "cidr_block": vpc.get("CidrBlock"),
                                "is_default": vpc.get("IsDefault", False),
                                "state": vpc.get("State"),
                            },
                            raw_data=vpc,
                        )
                    )
        except Exception as exc:
            logger.error("Failed to collect VPCs: %s", exc)
        return assets

    async def _collect_subnets(self) -> list[CloudAsset]:
        """Collect subnets."""
        assets: list[CloudAsset] = []
        session = self._get_aio_session()
        try:
            async with session.client("ec2", region_name=self._region) as ec2:
                response = await ec2.describe_subnets()
                for subnet in response.get("Subnets", []):
                    tags = {t["Key"]: t["Value"] for t in subnet.get("Tags", [])}
                    assets.append(
                        CloudAsset(
                            arn=subnet.get("SubnetArn", ""),
                            name=tags.get("Name", subnet["SubnetId"]),
                            asset_type=AssetType.SUBNET,
                            provider=CloudProvider.AWS,
                            region=self._region,
                            account_id=self._account_id,
                            tags=tags,
                            metadata={
                                "subnet_id": subnet["SubnetId"],
                                "vpc_id": subnet.get("VpcId"),
                                "cidr_block": subnet.get("CidrBlock"),
                                "availability_zone": subnet.get("AvailabilityZone"),
                                "map_public_ip": subnet.get(
                                    "MapPublicIpOnLaunch", False
                                ),
                            },
                            raw_data=subnet,
                        )
                    )
        except Exception as exc:
            logger.error("Failed to collect subnets: %s", exc)
        return assets

    async def _collect_security_groups(self) -> list[CloudAsset]:
        """Collect security groups."""
        assets: list[CloudAsset] = []
        session = self._get_aio_session()
        try:
            async with session.client("ec2", region_name=self._region) as ec2:
                response = await ec2.describe_security_groups()
                for sg in response.get("SecurityGroups", []):
                    assets.append(
                        CloudAsset(
                            arn=f"arn:aws:ec2:{self._region}:{self._account_id}:security-group/{sg['GroupId']}",
                            name=sg.get("GroupName", sg["GroupId"]),
                            asset_type=AssetType.SECURITY_GROUP,
                            provider=CloudProvider.AWS,
                            region=self._region,
                            account_id=self._account_id,
                            metadata={
                                "group_id": sg["GroupId"],
                                "vpc_id": sg.get("VpcId"),
                                "description": sg.get("Description"),
                                "ingress_rules": sg.get("IpPermissions", []),
                                "egress_rules": sg.get("IpPermissionsEgress", []),
                            },
                            raw_data=sg,
                        )
                    )
        except Exception as exc:
            logger.error("Failed to collect security groups: %s", exc)
        return assets

    async def _collect_iam_users(self) -> list[CloudAsset]:
        """Collect IAM users."""
        assets: list[CloudAsset] = []
        session = self._get_aio_session()
        try:
            async with session.client("iam", region_name="us-east-1") as iam:
                paginator = iam.get_paginator("list_users")
                async for page in paginator.paginate():
                    for user in page.get("Users", []):
                        assets.append(
                            CloudAsset(
                                arn=user.get("Arn", ""),
                                name=user.get("UserName", ""),
                                asset_type=AssetType.IAM_USER,
                                provider=CloudProvider.AWS,
                                region="global",
                                account_id=self._account_id,
                                metadata={
                                    "user_id": user.get("UserId"),
                                    "create_date": str(user.get("CreateDate", "")),
                                    "password_last_used": str(
                                        user.get("PasswordLastUsed", "")
                                    ),
                                },
                                raw_data=user,
                            )
                        )
        except Exception as exc:
            logger.error("Failed to collect IAM users: %s", exc)
        return assets

    async def _collect_iam_roles(self) -> list[CloudAsset]:
        """Collect IAM roles."""
        assets: list[CloudAsset] = []
        session = self._get_aio_session()
        try:
            async with session.client("iam", region_name="us-east-1") as iam:
                paginator = iam.get_paginator("list_roles")
                async for page in paginator.paginate():
                    for role in page.get("Roles", []):
                        assets.append(
                            CloudAsset(
                                arn=role.get("Arn", ""),
                                name=role.get("RoleName", ""),
                                asset_type=AssetType.IAM_ROLE,
                                provider=CloudProvider.AWS,
                                region="global",
                                account_id=self._account_id,
                                metadata={
                                    "role_id": role.get("RoleId"),
                                    "assume_role_policy": role.get(
                                        "AssumeRolePolicyDocument"
                                    ),
                                    "max_session_duration": role.get(
                                        "MaxSessionDuration"
                                    ),
                                },
                                raw_data=role,
                            )
                        )
        except Exception as exc:
            logger.error("Failed to collect IAM roles: %s", exc)
        return assets

    async def _collect_lambda(self) -> list[CloudAsset]:
        """Collect Lambda functions."""
        assets: list[CloudAsset] = []
        session = self._get_aio_session()
        try:
            async with session.client("lambda", region_name=self._region) as lam:
                paginator = lam.get_paginator("list_functions")
                async for page in paginator.paginate():
                    for fn in page.get("Functions", []):
                        assets.append(
                            CloudAsset(
                                arn=fn.get("FunctionArn", ""),
                                name=fn.get("FunctionName", ""),
                                asset_type=AssetType.LAMBDA_FUNCTION,
                                provider=CloudProvider.AWS,
                                region=self._region,
                                account_id=self._account_id,
                                metadata={
                                    "runtime": fn.get("Runtime"),
                                    "handler": fn.get("Handler"),
                                    "memory_size": fn.get("MemorySize"),
                                    "timeout": fn.get("Timeout"),
                                    "last_modified": fn.get("LastModified"),
                                    "vpc_config": fn.get("VpcConfig"),
                                },
                                raw_data=fn,
                            )
                        )
        except Exception as exc:
            logger.error("Failed to collect Lambda functions: %s", exc)
        return assets

    async def _collect_elbv2(self) -> list[CloudAsset]:
        """Collect ELBv2 load balancers."""
        assets: list[CloudAsset] = []
        session = self._get_aio_session()
        try:
            async with session.client("elbv2", region_name=self._region) as elbv2:
                response = await elbv2.describe_load_balancers()
                for lb in response.get("LoadBalancers", []):
                    assets.append(
                        CloudAsset(
                            arn=lb.get("LoadBalancerArn", ""),
                            name=lb.get("LoadBalancerName", ""),
                            asset_type=AssetType.LOAD_BALANCER,
                            provider=CloudProvider.AWS,
                            region=self._region,
                            account_id=self._account_id,
                            metadata={
                                "type": lb.get("Type"),
                                "scheme": lb.get("Scheme"),
                                "vpc_id": lb.get("VpcId"),
                                "state": lb.get("State", {}).get("Code"),
                                "dns_name": lb.get("DNSName"),
                                "security_groups": lb.get("SecurityGroups", []),
                            },
                            raw_data=lb,
                        )
                    )
        except Exception as exc:
            logger.error("Failed to collect ELBv2 load balancers: %s", exc)
        return assets

    # ------------------------------------------------------------------
    # Edge collection
    # ------------------------------------------------------------------

    async def _collect_sg_edges(self, assets: list[CloudAsset]) -> list[NetworkEdge]:
        """Build edges from security group rules."""
        edges: list[NetworkEdge] = []
        sg_assets = [a for a in assets if a.asset_type == AssetType.SECURITY_GROUP]

        for sg in sg_assets:
            sg_id = sg.metadata.get("group_id", sg.id)

            # Ingress rules
            for rule in sg.metadata.get("ingress_rules", []):
                for ip_range in rule.get("IpRanges", []):
                    cidr = ip_range.get("CidrIp", "")
                    from_port = rule.get("FromPort", 0)
                    to_port = rule.get("ToPort", 65535)
                    protocol = rule.get("IpProtocol", "-1")

                    port_range = (
                        f"{from_port}-{to_port}"
                        if from_port != to_port
                        else str(from_port)
                    )

                    edges.append(
                        NetworkEdge(
                            source_id=cidr,
                            target_id=sg_id,
                            edge_type=EdgeType.SECURITY_GROUP_RULE,
                            ports=list(range(from_port, min(to_port + 1, from_port + 100))),
                            port_range=port_range,
                            protocol="ALL" if protocol == "-1" else protocol.upper(),
                            cidr=cidr,
                            direction="ingress",
                        )
                    )

            # Egress rules
            for rule in sg.metadata.get("egress_rules", []):
                for ip_range in rule.get("IpRanges", []):
                    cidr = ip_range.get("CidrIp", "")
                    from_port = rule.get("FromPort", 0)
                    to_port = rule.get("ToPort", 65535)
                    protocol = rule.get("IpProtocol", "-1")

                    edges.append(
                        NetworkEdge(
                            source_id=sg_id,
                            target_id=cidr,
                            edge_type=EdgeType.SECURITY_GROUP_RULE,
                            port_range=f"{from_port}-{to_port}",
                            protocol="ALL" if protocol == "-1" else protocol.upper(),
                            cidr=cidr,
                            direction="egress",
                        )
                    )

        return edges

    async def _collect_containment_edges(
        self, assets: list[CloudAsset]
    ) -> list[NetworkEdge]:
        """Build VPC → Subnet → Resource containment edges."""
        edges: list[NetworkEdge] = []
        vpc_map = {
            a.metadata.get("vpc_id", a.id): a.id
            for a in assets
            if a.asset_type == AssetType.VPC
        }

        for asset in assets:
            vpc_id = asset.metadata.get("vpc_id")
            if vpc_id and vpc_id in vpc_map and asset.asset_type != AssetType.VPC:
                edges.append(
                    NetworkEdge(
                        source_id=vpc_map[vpc_id],
                        target_id=asset.id,
                        edge_type=EdgeType.CONTAINS,
                        description=f"VPC {vpc_id} contains {asset.name}",
                    )
                )
        return edges

    # ------------------------------------------------------------------
    # Main interface
    # ------------------------------------------------------------------

    async def collect(self) -> list[CloudAsset]:
        """Collect all AWS assets concurrently."""
        logger.info("Starting AWS asset collection in %s", self._region)

        results = await asyncio.gather(
            self._collect_ec2(),
            self._collect_s3(),
            self._collect_rds(),
            self._collect_vpcs(),
            self._collect_subnets(),
            self._collect_security_groups(),
            self._collect_iam_users(),
            self._collect_iam_roles(),
            self._collect_lambda(),
            self._collect_elbv2(),
            return_exceptions=True,
        )

        all_assets: list[CloudAsset] = []
        for result in results:
            if isinstance(result, Exception):
                logger.error("Collector task failed: %s", result)
            elif isinstance(result, list):
                all_assets.extend(result)

        logger.info("Collected %d AWS assets", len(all_assets))
        self._cached_assets = all_assets
        return all_assets

    async def collect_edges(self) -> list[NetworkEdge]:
        """Collect all network/relationship edges."""
        assets = getattr(self, "_cached_assets", [])
        if not assets:
            assets = await self.collect()

        sg_edges, containment_edges = await asyncio.gather(
            self._collect_sg_edges(assets),
            self._collect_containment_edges(assets),
        )

        all_edges = sg_edges + containment_edges
        logger.info("Collected %d AWS edges", len(all_edges))
        return all_edges
