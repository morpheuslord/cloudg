"""Tests for scanner-independent inventory mapping (cloudg.inventory)."""

from __future__ import annotations

import asyncio
import json

import boto3
import pytest
from moto import mock_aws

from cloudg.inventory.aws_deep import AWSDeepInventoryCollector, asset_type_from_arn
from cloudg.inventory.azure_deep import asset_type_from_arm
from cloudg.inventory.linker import RelationshipLinker
from cloudg.inventory.mapper import InventoryMapper, InventoryResult, _service_of
from cloudg.config import CloudGConfig
from cloudg.schema.models import (
    AssetType,
    CloudAsset,
    CloudProvider,
    EdgeType,
    Finding,
    NetworkEdge,
    Severity,
)


@pytest.fixture
def aws_credentials():
    import os

    os.environ["AWS_ACCESS_KEY_ID"] = "testing"
    os.environ["AWS_SECRET_ACCESS_KEY"] = "testing"
    os.environ["AWS_SECURITY_TOKEN"] = "testing"
    os.environ["AWS_SESSION_TOKEN"] = "testing"
    os.environ["AWS_DEFAULT_REGION"] = "us-east-1"


@pytest.fixture
def boto3_session(aws_credentials):
    return boto3.Session(region_name="us-east-1")


def _asset(name, asset_type, arn=None, metadata=None, raw_data=None, provider=CloudProvider.AWS):
    return CloudAsset(
        name=name,
        asset_type=asset_type,
        provider=provider,
        arn=arn,
        metadata=metadata or {},
        raw_data=raw_data or {},
    )


# ── ARN / ARM classification ──


class TestTypeClassification:
    def test_asset_type_from_arn(self):
        assert asset_type_from_arn("arn:aws:ec2:us-east-1:1:instance/i-0abc") == AssetType.EC2
        assert asset_type_from_arn("arn:aws:s3:::my-bucket") == AssetType.S3_BUCKET
        assert (
            asset_type_from_arn("arn:aws:lambda:us-east-1:1:function:fn")
            == AssetType.LAMBDA_FUNCTION
        )
        assert asset_type_from_arn("arn:aws:sns:us-east-1:1:topic") == AssetType.NOTIFICATION_TOPIC
        assert (
            asset_type_from_arn("arn:aws:ecr:us-east-1:1:repository/app")
            == AssetType.CONTAINER_REGISTRY
        )
        assert asset_type_from_arn("arn:aws:braket:us-east-1:1:quantum-task/x") == AssetType.OTHER
        assert asset_type_from_arn("not-an-arn") == AssetType.OTHER

    def test_asset_type_from_arm(self):
        assert asset_type_from_arm("Microsoft.Compute/virtualMachines") == AssetType.VIRTUAL_MACHINE
        assert (
            asset_type_from_arm("Microsoft.Network/networkInterfaces")
            == AssetType.NETWORK_INTERFACE
        )
        assert asset_type_from_arm("Microsoft.Weird/thing") == AssetType.OTHER
        assert asset_type_from_arm(None) == AssetType.OTHER


# ── Relationship linker ──


class TestRelationshipLinker:
    def test_security_group_attachment(self):
        sg = _asset(
            "web-sg",
            AssetType.SECURITY_GROUP,
            arn="arn:aws:ec2:us-east-1:1:security-group/sg-0123456789abcdef0",
            metadata={"group_id": "sg-0123456789abcdef0"},
        )
        ec2 = _asset(
            "web-1",
            AssetType.EC2,
            arn="arn:aws:ec2:us-east-1:1:instance/i-0123456789abcdef0",
            metadata={"security_groups": ["sg-0123456789abcdef0"]},
        )
        edges = RelationshipLinker([sg, ec2]).link()
        attached = [e for e in edges if e.edge_type == EdgeType.ATTACHED_TO]
        assert any(e.source_id == ec2.id and e.target_id == sg.id for e in attached)

    def test_subnet_containment(self):
        subnet = _asset(
            "app-subnet",
            AssetType.SUBNET,
            arn="arn:aws:ec2:us-east-1:1:subnet/subnet-0123456789abcdef0",
            metadata={"subnet_id": "subnet-0123456789abcdef0"},
        )
        rds = _asset(
            "db-1",
            AssetType.RDS_INSTANCE,
            arn="arn:aws:rds:us-east-1:1:db:db-1",
            metadata={"subnet_id": "subnet-0123456789abcdef0"},
        )
        edges = RelationshipLinker([subnet, rds]).link()
        assert any(
            e.source_id == subnet.id and e.target_id == rds.id and e.edge_type == EdgeType.CONTAINS
            for e in edges
        )

    def test_route_table_to_gateway(self):
        igw = _asset(
            "igw",
            AssetType.INTERNET_GATEWAY,
            arn="arn:aws:ec2:us-east-1:1:internet-gateway/igw-0123456789abcdef0",
            metadata={"internet_gateway_id": "igw-0123456789abcdef0"},
        )
        rtb = _asset(
            "public-rt",
            AssetType.ROUTE_TABLE,
            arn="arn:aws:ec2:us-east-1:1:route-table/rtb-0123456789abcdef0",
            metadata={
                "route_table_id": "rtb-0123456789abcdef0",
                "routes": [
                    {"DestinationCidrBlock": "0.0.0.0/0", "GatewayId": "igw-0123456789abcdef0"},
                    {"DestinationCidrBlock": "10.0.0.0/16", "GatewayId": "local"},
                ],
            },
        )
        edges = RelationshipLinker([igw, rtb]).link()
        routes = [e for e in edges if e.edge_type == EdgeType.ROUTE]
        assert len(routes) == 1
        assert routes[0].source_id == rtb.id and routes[0].target_id == igw.id

    def test_lambda_role_reference(self):
        role = _asset(
            "app-role",
            AssetType.IAM_ROLE,
            arn="arn:aws:iam::1:role/app-role",
        )
        fn = _asset(
            "fn",
            AssetType.LAMBDA_FUNCTION,
            arn="arn:aws:lambda:us-east-1:1:function:fn",
            raw_data={"Role": "arn:aws:iam::1:role/app-role"},
        )
        edges = RelationshipLinker([role, fn]).link()
        assert any(
            e.source_id == fn.id
            and e.target_id == role.id
            and e.edge_type == EdgeType.ASSUMES_ROLE
            and e.relationship == "RUNS_ON"
            for e in edges
        )

    def test_kms_reference(self):
        key = _asset(
            "key-1",
            AssetType.KMS_KEY,
            arn="arn:aws:kms:us-east-1:1:key/abcd-1234",
        )
        secret = _asset(
            "db-password",
            AssetType.SECRET,
            arn="arn:aws:secretsmanager:us-east-1:1:secret:db-password",
            metadata={"kms_key_id": "arn:aws:kms:us-east-1:1:key/abcd-1234"},
        )
        edges = RelationshipLinker([key, secret]).link()
        assert any(e.source_id == secret.id and e.target_id == key.id for e in edges)

    def test_vpc_peering(self):
        vpc_a = _asset(
            "vpc-a",
            AssetType.VPC,
            arn="arn:aws:ec2:us-east-1:1:vpc/vpc-0123456789abcdef0",
            metadata={"vpc_id": "vpc-0123456789abcdef0"},
        )
        vpc_b = _asset(
            "vpc-b",
            AssetType.VPC,
            arn="arn:aws:ec2:us-east-1:1:vpc/vpc-0123456789abcdef1",
            metadata={"vpc_id": "vpc-0123456789abcdef1"},
        )
        pcx = _asset(
            "peer",
            AssetType.PEERING_CONNECTION,
            arn="arn:aws:ec2:us-east-1:1:vpc-peering-connection/pcx-0123456789abcdef0",
            metadata={
                "peering_connection_id": "pcx-0123456789abcdef0",
                "requester_vpc_id": "vpc-0123456789abcdef0",
                "accepter_vpc_id": "vpc-0123456789abcdef1",
            },
        )
        edges = RelationshipLinker([vpc_a, vpc_b, pcx]).link()
        peering = [e for e in edges if e.edge_type == EdgeType.PEERING]
        assert len(peering) == 2

    def test_azure_nic_wiring(self):
        sub_id = "/subscriptions/s1/resourceGroups/rg/providers/Microsoft.Network/virtualNetworks/vnet/subnets/sn"
        nsg_id = "/subscriptions/s1/resourceGroups/rg/providers/Microsoft.Network/networkSecurityGroups/nsg"
        nic_id = (
            "/subscriptions/s1/resourceGroups/rg/providers/Microsoft.Network/networkInterfaces/nic"
        )
        vm_id = "/subscriptions/s1/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm"

        subnet = _asset("sn", AssetType.SUBNET, arn=sub_id, provider=CloudProvider.AZURE)
        nsg = _asset("nsg", AssetType.NSG, arn=nsg_id, provider=CloudProvider.AZURE)
        nic = _asset(
            "nic",
            AssetType.NETWORK_INTERFACE,
            arn=nic_id,
            provider=CloudProvider.AZURE,
            metadata={
                "nsg_id": nsg_id,
                "subnet_id": sub_id,
                "attached_instance_id": vm_id,
            },
        )
        vm = _asset(
            "vm",
            AssetType.VIRTUAL_MACHINE,
            arn=vm_id,
            provider=CloudProvider.AZURE,
            metadata={"network_interfaces": [nic_id]},
        )
        edges = RelationshipLinker([subnet, nsg, nic, vm]).link()
        assert any(e.source_id == nic.id and e.target_id == nsg.id for e in edges)
        assert any(e.source_id == subnet.id and e.target_id == nic.id for e in edges)
        assert any(e.source_id == nic.id and e.target_id == vm.id for e in edges)

    def test_gcp_parent_containment(self):
        vpc = _asset(
            "net",
            AssetType.VPC,
            arn="//compute.googleapis.com/projects/p/global/networks/net",
            provider=CloudProvider.GCP,
        )
        subnet = _asset(
            "sn",
            AssetType.SUBNET,
            arn="//compute.googleapis.com/projects/p/regions/r/subnetworks/sn",
            provider=CloudProvider.GCP,
            metadata={
                "parent_full_resource_name": "//compute.googleapis.com/projects/p/global/networks/net"
            },
        )
        edges = RelationshipLinker([vpc, subnet]).link()
        assert any(
            e.source_id == vpc.id and e.target_id == subnet.id and e.edge_type == EdgeType.CONTAINS
            for e in edges
        )

    def test_generic_reference_scan(self):
        bucket = _asset(
            "logs-bucket",
            AssetType.S3_BUCKET,
            arn="arn:aws:s3:::logs-bucket",
        )
        trail = _asset(
            "trail",
            AssetType.CLOUDTRAIL,
            arn="arn:aws:cloudtrail:us-east-1:1:trail/trail",
            metadata={"log_destination": "arn:aws:s3:::logs-bucket"},
        )
        edges = RelationshipLinker([bucket, trail]).link()
        assert any(
            e.source_id == trail.id
            and e.target_id == bucket.id
            and e.edge_type == EdgeType.REFERENCES
            for e in edges
        )

    def test_generic_scan_can_be_disabled(self):
        bucket = _asset("b", AssetType.S3_BUCKET, arn="arn:aws:s3:::b")
        trail = _asset(
            "t",
            AssetType.CLOUDTRAIL,
            arn="arn:aws:cloudtrail:us-east-1:1:trail/t",
            metadata={"log_destination": "arn:aws:s3:::b"},
        )
        edges = RelationshipLinker([bucket, trail]).link(include_generic=False)
        assert not edges

    def test_no_duplicate_or_self_edges(self):
        sg = _asset(
            "sg",
            AssetType.SECURITY_GROUP,
            arn="arn:aws:ec2:us-east-1:1:security-group/sg-0123456789abcdef0",
            metadata={"group_id": "sg-0123456789abcdef0"},
        )
        ec2 = _asset(
            "i",
            AssetType.EC2,
            arn="arn:aws:ec2:us-east-1:1:instance/i-0123456789abcdef0",
            metadata={
                "security_groups": ["sg-0123456789abcdef0", "sg-0123456789abcdef0"],
            },
        )
        edges = RelationshipLinker([sg, ec2]).link()
        keys = [(e.source_id, e.target_id) for e in edges]
        assert len(keys) == len(set(keys))
        assert all(s != t for s, t in keys)

    def test_seed_existing_prevents_duplicates(self):
        sg = _asset(
            "sg",
            AssetType.SECURITY_GROUP,
            arn="arn:aws:ec2:us-east-1:1:security-group/sg-0123456789abcdef0",
            metadata={"group_id": "sg-0123456789abcdef0"},
        )
        ec2 = _asset(
            "i",
            AssetType.EC2,
            arn="arn:aws:ec2:us-east-1:1:instance/i-0123456789abcdef0",
            metadata={"security_groups": ["sg-0123456789abcdef0"]},
        )
        linker = RelationshipLinker([sg, ec2])
        linker.seed_existing(
            [
                NetworkEdge(
                    source_id=ec2.id,
                    target_id=sg.id,
                    edge_type=EdgeType.ATTACHED_TO,
                )
            ]
        )
        assert linker.link() == []


# ── Deep AWS collector (moto) ──


@mock_aws
class TestAWSDeepInventoryCollector:
    def _setup_network(self, session):
        ec2 = session.client("ec2", region_name="us-east-1")
        vpc_id = ec2.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]["VpcId"]
        subnet_id = ec2.create_subnet(VpcId=vpc_id, CidrBlock="10.0.1.0/24")["Subnet"]["SubnetId"]
        igw_id = ec2.create_internet_gateway()["InternetGateway"]["InternetGatewayId"]
        ec2.attach_internet_gateway(InternetGatewayId=igw_id, VpcId=vpc_id)
        rtb_id = ec2.create_route_table(VpcId=vpc_id)["RouteTable"]["RouteTableId"]
        ec2.create_route(RouteTableId=rtb_id, DestinationCidrBlock="0.0.0.0/0", GatewayId=igw_id)
        ec2.run_instances(
            ImageId="ami-12345678",
            InstanceType="t2.micro",
            MinCount=1,
            MaxCount=1,
            SubnetId=subnet_id,
            TagSpecifications=[
                {
                    "ResourceType": "instance",
                    "Tags": [{"Key": "Name", "Value": "deep-test"}],
                }
            ],
        )
        ec2.create_volume(AvailabilityZone="us-east-1a", Size=8)
        ec2.allocate_address(Domain="vpc")
        return vpc_id, subnet_id, igw_id, rtb_id

    def test_deep_collect_network_fabric(self, boto3_session):
        self._setup_network(boto3_session)
        collector = AWSDeepInventoryCollector(
            session=boto3_session, region="us-east-1", account_id="123456789012"
        )
        assets = asyncio.run(collector.collect())
        types = {a.asset_type for a in assets}

        assert AssetType.ROUTE_TABLE in types
        assert AssetType.INTERNET_GATEWAY in types
        assert AssetType.EBS_VOLUME in types
        assert AssetType.NETWORK_INTERFACE in types
        assert AssetType.NACL in types
        assert AssetType.ELASTIC_IP in types

    def test_deep_collect_dedupes_sweep_hits(self, boto3_session):
        self._setup_network(boto3_session)
        collector = AWSDeepInventoryCollector(
            session=boto3_session, region="us-east-1", account_id="123456789012"
        )
        assets = asyncio.run(collector.collect())
        arns = [a.arn for a in assets if a.arn]
        assert len(arns) == len(set(arns))

    def test_sweep_can_be_disabled(self, boto3_session):
        self._setup_network(boto3_session)
        collector = AWSDeepInventoryCollector(
            session=boto3_session,
            region="us-east-1",
            account_id="123456789012",
            tagging_sweep=False,
        )
        assets = asyncio.run(collector.collect())
        assert all(a.metadata.get("discovered_via") != "tagging-api" for a in assets)


# ── Mapper: summary, export, findings merge ──


class TestInventoryMapper:
    def _result(self):
        sg = _asset(
            "sg",
            AssetType.SECURITY_GROUP,
            arn="arn:aws:ec2:us-east-1:1:security-group/sg-0123456789abcdef0",
            metadata={"group_id": "sg-0123456789abcdef0"},
        )
        ec2 = _asset(
            "web",
            AssetType.EC2,
            arn="arn:aws:ec2:us-east-1:1:instance/i-0123456789abcdef0",
            metadata={"security_groups": ["sg-0123456789abcdef0"]},
        )
        edges = RelationshipLinker([sg, ec2]).link()
        return InventoryResult(assets=[sg, ec2], edges=edges, providers=["aws"])

    def test_summary(self):
        result = self._result()
        summary = result.summary
        assert summary["total_assets"] == 2
        assert summary["total_edges"] == 1
        assert summary["assets_by_type"]["EC2"] == 1
        assert summary["assets_by_service"]["ec2"] == 2
        assert summary["unlinked_assets"] == 0

    def test_export(self, tmp_path):
        result = self._result()
        paths = result.export(tmp_path)
        assert paths["map"].exists()
        assert paths["graphml"].exists()
        assert paths["graph"].exists()
        data = json.loads(paths["map"].read_text())
        assert data["summary"]["total_assets"] == 2
        assert len(data["assets"]) == 2

    def test_asset_map_merge(self):
        result = self._result()
        ec2 = next(a for a in result.assets if a.asset_type == AssetType.EC2)
        findings = [
            Finding(
                resource_id=ec2.id,
                resource_arn=ec2.arn,
                severity=Severity.HIGH,
                title="Open SSH",
                description="SSH open to the world",
                source_tool="test",
                compliance_frameworks=["CIS", "NIST-800-53"],
            )
        ]
        mapper = InventoryMapper(CloudGConfig())
        asset_map = mapper.build_asset_map(result, findings)
        assert asset_map["assets_with_findings"] == 1
        top = asset_map["assets"][0]
        assert top["name"] == "web"
        assert top["severity_breakdown"] == {"HIGH": 1}

    def test_compliance_map_merge(self):
        result = self._result()
        ec2 = next(a for a in result.assets if a.asset_type == AssetType.EC2)
        findings = [
            Finding(
                resource_id=ec2.id,
                resource_arn=ec2.arn,
                severity=Severity.HIGH,
                title="Open SSH",
                description="d",
                source_tool="test",
                compliance_frameworks=["CIS"],
            ),
            Finding(
                resource_id="unmatched",
                severity=Severity.LOW,
                title="Other",
                description="d",
                source_tool="test",
                compliance_frameworks=["CIS"],
            ),
        ]
        mapper = InventoryMapper(CloudGConfig())
        cmap = mapper.build_compliance_map(result, findings)
        assert cmap["total_frameworks"] == 1
        cis = cmap["frameworks"]["CIS"]
        assert cis["findings"] == 2
        assert cis["affected_asset_count"] == 1
        assert ec2.arn in cis["affected_assets"]

    def test_export_merged(self, tmp_path):
        result = self._result()
        mapper = InventoryMapper(CloudGConfig())
        paths = mapper.export_merged(result, [], tmp_path)
        assert paths["asset_map"].exists()
        assert paths["compliance_map"].exists()

    def test_service_of(self):
        aws = _asset("a", AssetType.EC2, arn="arn:aws:ec2:us-east-1:1:instance/i-1")
        azure = _asset(
            "b",
            AssetType.VIRTUAL_MACHINE,
            arn="/subscriptions/s/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm",
            provider=CloudProvider.AZURE,
        )
        gcp = _asset(
            "c",
            AssetType.GCE_INSTANCE,
            arn="//compute.googleapis.com/projects/p/zones/z/instances/i",
            provider=CloudProvider.GCP,
        )
        assert _service_of(aws) == "ec2"
        assert _service_of(azure) == "microsoft.compute"
        assert _service_of(gcp) == "compute"

    def test_service_of_ignores_googleapis_mid_string(self):
        # ".googleapis.com/" anywhere but the identifier's own host must not
        # classify the asset as GCP (CodeQL py/incomplete-url-substring-sanitization)
        fake = _asset(
            "b",
            AssetType.S3_BUCKET,
            arn="arn:aws:s3:::backup.googleapis.com/evil",
        )
        assert _service_of(fake) == "s3"

    def test_linker_ignores_googleapis_mid_string(self):
        bucket = _asset(
            "x.googleapis.com/path",
            AssetType.S3_BUCKET,
            arn="arn:aws:s3:::real-bucket",
        )
        trail = _asset(
            "t",
            AssetType.CLOUDTRAIL,
            arn="arn:aws:cloudtrail:us-east-1:1:trail/t",
            metadata={"note": "x.googleapis.com/path"},
        )
        linker = RelationshipLinker([bucket, trail])
        # the value is indexed by name, but it is not identifier-shaped, so the
        # generic scan must not produce an edge from it
        edges = linker.link()
        assert all(e.description != "t references x.googleapis.com/path" for e in edges)
        assert not linker._looks_like_identifier("x.googleapis.com/path")
        assert linker._looks_like_identifier("//compute.googleapis.com/projects/p")
