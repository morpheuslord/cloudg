"""Tests for AWS collector using moto mocking."""

from __future__ import annotations

import asyncio
import json

import boto3
import pytest
from moto import mock_aws

from cloudg.collectors.aws import AsyncAWSCollector
from cloudg.schema.models import AssetType, CloudProvider


@pytest.fixture
def aws_credentials():
    """Mock AWS credentials for moto."""
    import os
    os.environ["AWS_ACCESS_KEY_ID"] = "testing"
    os.environ["AWS_SECRET_ACCESS_KEY"] = "testing"
    os.environ["AWS_SECURITY_TOKEN"] = "testing"
    os.environ["AWS_SESSION_TOKEN"] = "testing"
    os.environ["AWS_DEFAULT_REGION"] = "us-east-1"


@pytest.fixture
def boto3_session(aws_credentials):
    """Create a test boto3 session."""
    return boto3.Session(region_name="us-east-1")


# ── Schema Tests ──


class TestSchemaModels:
    """Test Pydantic v2 schema models."""

    def test_cloud_asset_creation(self):
        from cloudg.schema.models import CloudAsset

        asset = CloudAsset(
            name="test-instance",
            asset_type=AssetType.EC2,
            provider=CloudProvider.AWS,
            region="us-east-1",
            tags={"Name": "test"},
        )
        assert asset.name == "test-instance"
        assert asset.asset_type == AssetType.EC2
        assert asset.provider == CloudProvider.AWS
        assert asset.id  # Should have auto-generated UUID

    def test_cloud_asset_display_id_with_arn(self):
        from cloudg.schema.models import CloudAsset

        asset = CloudAsset(
            arn="arn:aws:ec2:us-east-1:123456:instance/i-123",
            name="test",
            asset_type=AssetType.EC2,
            provider=CloudProvider.AWS,
        )
        assert asset.display_id == "arn:aws:ec2:us-east-1:123456:instance/i-123"

    def test_cloud_asset_display_id_without_arn(self):
        from cloudg.schema.models import CloudAsset

        asset = CloudAsset(
            name="test",
            asset_type=AssetType.EC2,
            provider=CloudProvider.AWS,
        )
        assert asset.display_id == asset.id

    def test_finding_risk_score(self):
        from cloudg.schema.models import Finding, Severity

        finding = Finding(
            resource_id="test",
            severity=Severity.CRITICAL,
            title="Test",
            description="Test finding",
            source_tool="test",
        )
        assert finding.risk_score == 9.5

    def test_finding_risk_score_with_cvss(self):
        from cloudg.schema.models import Finding, Severity

        finding = Finding(
            resource_id="test",
            severity=Severity.HIGH,
            title="Test",
            description="Test",
            source_tool="test",
            cvss_score=9.0,
        )
        # (7.5 + 9.0) / 2 = 8.25 -> 8.2
        assert finding.risk_score == 8.2

    def test_scan_result_summary(self):
        from cloudg.schema.models import Finding, ScanResult, Severity

        result = ScanResult(
            findings=[
                Finding(resource_id="r1", severity=Severity.CRITICAL, title="A", description="", source_tool="t"),
                Finding(resource_id="r2", severity=Severity.HIGH, title="B", description="", source_tool="t"),
                Finding(resource_id="r3", severity=Severity.CRITICAL, title="C", description="", source_tool="t"),
            ]
        )
        summary = result.summary
        assert summary["total_findings"] == 3
        assert summary["severity_breakdown"]["CRITICAL"] == 2
        assert summary["severity_breakdown"]["HIGH"] == 1

    def test_network_edge_creation(self):
        from cloudg.schema.models import EdgeType, NetworkEdge

        edge = NetworkEdge(
            source_id="0.0.0.0/0",
            target_id="sg-123",
            edge_type=EdgeType.SECURITY_GROUP_RULE,
            ports=[22, 80, 443],
            protocol="TCP",
            cidr="0.0.0.0/0",
        )
        assert edge.source_id == "0.0.0.0/0"
        assert 22 in edge.ports


# ── AWS Collector Tests ──


@mock_aws
class TestAsyncAWSCollector:
    """Test AWS asset collector with moto mocking."""

    def _setup_ec2(self, session):
        """Create mock EC2 instances."""
        ec2 = session.client("ec2", region_name="us-east-1")
        # Create VPC
        vpc = ec2.create_vpc(CidrBlock="10.0.0.0/16")
        vpc_id = vpc["Vpc"]["VpcId"]
        ec2.create_tags(Resources=[vpc_id], Tags=[{"Key": "Name", "Value": "test-vpc"}])

        # Create subnet
        subnet = ec2.create_subnet(VpcId=vpc_id, CidrBlock="10.0.1.0/24")
        subnet_id = subnet["Subnet"]["SubnetId"]

        # Create security group
        sg = ec2.create_security_group(
            GroupName="test-sg",
            Description="Test SG",
            VpcId=vpc_id,
        )
        sg_id = sg["GroupId"]
        ec2.authorize_security_group_ingress(
            GroupId=sg_id,
            IpPermissions=[{
                "IpProtocol": "tcp",
                "FromPort": 22,
                "ToPort": 22,
                "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
            }],
        )

        # Create instance
        ec2.run_instances(
            ImageId="ami-12345678",
            InstanceType="t2.micro",
            MinCount=1,
            MaxCount=1,
            SubnetId=subnet_id,
            SecurityGroupIds=[sg_id],
            TagSpecifications=[{
                "ResourceType": "instance",
                "Tags": [{"Key": "Name", "Value": "test-instance"}],
            }],
        )
        return vpc_id, subnet_id, sg_id

    def _setup_s3(self, session):
        """Create mock S3 bucket."""
        s3 = session.client("s3", region_name="us-east-1")
        s3.create_bucket(Bucket="test-bucket-cloudg")

    def _setup_iam(self, session):
        """Create mock IAM user."""
        iam = session.client("iam", region_name="us-east-1")
        iam.create_user(UserName="test-user")
        iam.create_role(
            RoleName="test-role",
            AssumeRolePolicyDocument=json.dumps({
                "Version": "2012-10-17",
                "Statement": [{
                    "Effect": "Allow",
                    "Principal": {"Service": "ec2.amazonaws.com"},
                    "Action": "sts:AssumeRole",
                }],
            }),
        )

    def test_collect_ec2_instances(self, boto3_session):
        """Test EC2 instance collection."""
        self._setup_ec2(boto3_session)
        collector = AsyncAWSCollector(
            session=boto3_session, region="us-east-1", account_id="123456789012"
        )
        assets = asyncio.run(collector._collect_ec2())
        assert len(assets) >= 1
        ec2_asset = assets[0]
        assert ec2_asset.asset_type == AssetType.EC2
        assert ec2_asset.provider == CloudProvider.AWS
        assert ec2_asset.name == "test-instance"

    def test_collect_s3_buckets(self, boto3_session):
        """Test S3 bucket collection."""
        self._setup_s3(boto3_session)
        collector = AsyncAWSCollector(
            session=boto3_session, region="us-east-1", account_id="123456789012"
        )
        assets = asyncio.run(collector._collect_s3())
        assert len(assets) >= 1
        bucket = next(a for a in assets if a.name == "test-bucket-cloudg")
        assert bucket.asset_type == AssetType.S3_BUCKET

    def test_collect_vpcs(self, boto3_session):
        """Test VPC collection."""
        self._setup_ec2(boto3_session)
        collector = AsyncAWSCollector(
            session=boto3_session, region="us-east-1", account_id="123456789012"
        )
        assets = asyncio.run(collector._collect_vpcs())
        # At minimum the default VPC + test VPC
        assert len(assets) >= 1
        vpc_names = [a.name for a in assets]
        assert any("test-vpc" in name for name in vpc_names)

    def test_collect_security_groups(self, boto3_session):
        """Test security group collection with rules."""
        self._setup_ec2(boto3_session)
        collector = AsyncAWSCollector(
            session=boto3_session, region="us-east-1", account_id="123456789012"
        )
        assets = asyncio.run(collector._collect_security_groups())
        assert len(assets) >= 1
        sg = next((a for a in assets if a.name == "test-sg"), None)
        assert sg is not None
        assert sg.asset_type == AssetType.SECURITY_GROUP

    def test_collect_iam_users(self, boto3_session):
        """Test IAM user collection."""
        self._setup_iam(boto3_session)
        collector = AsyncAWSCollector(
            session=boto3_session, region="us-east-1", account_id="123456789012"
        )
        assets = asyncio.run(collector._collect_iam_users())
        assert len(assets) >= 1
        user = next(a for a in assets if a.name == "test-user")
        assert user.asset_type == AssetType.IAM_USER

    def test_collect_iam_roles(self, boto3_session):
        """Test IAM role collection."""
        self._setup_iam(boto3_session)
        collector = AsyncAWSCollector(
            session=boto3_session, region="us-east-1", account_id="123456789012"
        )
        assets = asyncio.run(collector._collect_iam_roles())
        role = next((a for a in assets if a.name == "test-role"), None)
        assert role is not None
        assert role.asset_type == AssetType.IAM_ROLE

    def test_full_collect(self, boto3_session):
        """Test the full collect() method."""
        self._setup_ec2(boto3_session)
        self._setup_s3(boto3_session)
        self._setup_iam(boto3_session)

        collector = AsyncAWSCollector(
            session=boto3_session, region="us-east-1", account_id="123456789012"
        )
        assets = asyncio.run(collector.collect())
        assert len(assets) > 0

        # Should have multiple asset types
        types = {a.asset_type for a in assets}
        assert AssetType.EC2 in types
        assert AssetType.S3_BUCKET in types
        assert AssetType.VPC in types

    def test_collect_edges(self, boto3_session):
        """Test edge collection from security groups."""
        self._setup_ec2(boto3_session)

        collector = AsyncAWSCollector(
            session=boto3_session, region="us-east-1", account_id="123456789012"
        )
        asyncio.run(collector.collect())
        edges = asyncio.run(collector.collect_edges())

        # Should have at least SG edges
        assert len(edges) >= 1
