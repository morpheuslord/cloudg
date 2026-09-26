"""Tests for Terraform .tf.json export."""

from __future__ import annotations

import json


from cloudg.renderers.terraform_export import (
    TerraformExporter,
    _sanitise_tf_name,
    _TF_RESOURCE_MAP,
)
from cloudg.schema.models import (
    AssetType,
    CloudAsset,
    CloudProvider,
    EdgeType,
    NetworkEdge,
)


# ── Helpers ──

def _make_assets() -> list[CloudAsset]:
    return [
        CloudAsset(
            id="vpc-1", name="prod-vpc",
            asset_type=AssetType.VPC, provider=CloudProvider.AWS,
            region="us-east-1", account_id="123456789012",
            arn="arn:aws:ec2:us-east-1:123456789012:vpc/vpc-1",
            metadata={"vpc_id": "vpc-1", "cidr_block": "10.0.0.0/16"},
            tags={"Name": "prod-vpc", "Environment": "production"},
        ),
        CloudAsset(
            id="subnet-1", name="prod-subnet",
            asset_type=AssetType.SUBNET, provider=CloudProvider.AWS,
            region="us-east-1", account_id="123456789012",
            arn="arn:aws:ec2:us-east-1:123456789012:subnet/subnet-1",
            metadata={"vpc_id": "vpc-1", "subnet_id": "subnet-1",
                       "cidr_block": "10.0.1.0/24", "availability_zone": "us-east-1a",
                       "map_public_ip": False},
        ),
        CloudAsset(
            id="ec2-1", name="web-server-01",
            asset_type=AssetType.EC2, provider=CloudProvider.AWS,
            region="us-east-1", account_id="123456789012",
            arn="arn:aws:ec2:us-east-1:123456789012:instance/i-1234567890",
            metadata={"instance_type": "t3.medium", "image_id": "ami-12345",
                       "subnet_id": "subnet-1", "security_groups": ["sg-1"]},
            tags={"Name": "web-server-01"},
        ),
        CloudAsset(
            id="sg-1", name="web-sg",
            asset_type=AssetType.SECURITY_GROUP, provider=CloudProvider.AWS,
            region="us-east-1", account_id="123456789012",
            arn="arn:aws:ec2:us-east-1:123456789012:security-group/sg-1",
            metadata={
                "group_id": "sg-1", "vpc_id": "vpc-1",
                "description": "Web security group",
                "ingress_rules": [
                    {"IpProtocol": "tcp", "FromPort": 443, "ToPort": 443,
                     "IpRanges": [{"CidrIp": "0.0.0.0/0"}]},
                    {"IpProtocol": "tcp", "FromPort": 80, "ToPort": 80,
                     "IpRanges": [{"CidrIp": "0.0.0.0/0"}]},
                ],
                "egress_rules": [
                    {"IpProtocol": "-1", "FromPort": 0, "ToPort": 0,
                     "IpRanges": [{"CidrIp": "0.0.0.0/0"}]},
                ],
            },
        ),
        CloudAsset(
            id="rds-1", name="prod-db",
            asset_type=AssetType.RDS_INSTANCE, provider=CloudProvider.AWS,
            region="us-east-1", account_id="123456789012",
            arn="arn:aws:rds:us-east-1:123456789012:db/prod-db",
            metadata={"engine": "postgres", "engine_version": "15.4",
                       "instance_class": "db.r6g.large", "storage_encrypted": True,
                       "multi_az": True, "publicly_accessible": False},
        ),
        CloudAsset(
            id="role-1", name="app-role",
            asset_type=AssetType.IAM_ROLE, provider=CloudProvider.AWS,
            region="global", account_id="123456789012",
            arn="arn:aws:iam::123456789012:role/app-role",
            metadata={"assume_role_policy": {
                "Version": "2012-10-17",
                "Statement": [{"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"},
                               "Action": "sts:AssumeRole"}],
            }},
        ),
        CloudAsset(
            id="s3-1", name="my-data-bucket",
            asset_type=AssetType.S3_BUCKET, provider=CloudProvider.AWS,
            region="global",
            arn="arn:aws:s3:::my-data-bucket",
            tags={"Environment": "production"},
        ),
    ]


def _make_edges() -> list[NetworkEdge]:
    return [
        NetworkEdge(
            source_id="vpc-1", target_id="subnet-1",
            edge_type=EdgeType.CONTAINS,
        ),
    ]


# ── Sanitisation Tests ──


class TestSanitiseTfName:
    def test_simple_name(self):
        assert _sanitise_tf_name("my-server") == "my_server"

    def test_leading_digits(self):
        assert _sanitise_tf_name("123server") == "server"

    def test_special_chars(self):
        assert _sanitise_tf_name("my.server/prod") == "my_server_prod"

    def test_empty_fallback(self):
        assert _sanitise_tf_name("123") == "resource"

    def test_max_length(self):
        long_name = "a" * 100
        result = _sanitise_tf_name(long_name)
        assert len(result) <= 64


# ── Resource Mapping Tests ──


class TestResourceMapping:
    def test_aws_mappings_exist(self):
        """All main AWS asset types should have Terraform mappings."""
        aws_types = [
            AssetType.EC2, AssetType.VPC, AssetType.SUBNET,
            AssetType.SECURITY_GROUP, AssetType.S3_BUCKET,
            AssetType.RDS_INSTANCE, AssetType.LAMBDA_FUNCTION,
            AssetType.LOAD_BALANCER, AssetType.IAM_ROLE,
        ]
        for at in aws_types:
            assert at in _TF_RESOURCE_MAP, f"{at.value} missing from TF map"

    def test_azure_mappings_exist(self):
        azure_types = [AssetType.VIRTUAL_MACHINE, AssetType.VNET, AssetType.NSG]
        for at in azure_types:
            assert at in _TF_RESOURCE_MAP

    def test_gcp_mappings_exist(self):
        gcp_types = [AssetType.GCE_INSTANCE, AssetType.GCS_BUCKET, AssetType.CLOUD_SQL]
        for at in gcp_types:
            assert at in _TF_RESOURCE_MAP


# ── Exporter Tests ──


class TestTerraformExporter:
    def test_export_creates_all_files(self, tmp_path):
        """Should create provider, variables, main, and import files."""
        exporter = TerraformExporter(output_dir=tmp_path)
        paths = exporter.export(_make_assets(), _make_edges())
        assert paths["provider"].exists()
        assert paths["variables"].exists()
        assert paths["main"].exists()
        assert paths["import_commands"].exists()

    def test_main_is_valid_json(self, tmp_path):
        """main.tf.json should be valid JSON."""
        exporter = TerraformExporter(output_dir=tmp_path)
        paths = exporter.export(_make_assets(), _make_edges())
        with open(paths["main"]) as f:
            data = json.load(f)
        assert "resource" in data

    def test_provider_has_aws(self, tmp_path):
        """Provider file should have AWS config."""
        exporter = TerraformExporter(output_dir=tmp_path)
        paths = exporter.export(_make_assets(), _make_edges())
        with open(paths["provider"]) as f:
            data = json.load(f)
        assert "aws" in data.get("provider", {})

    def test_variables_has_region(self, tmp_path):
        """Variables should include aws_region."""
        exporter = TerraformExporter(output_dir=tmp_path)
        paths = exporter.export(_make_assets(), _make_edges())
        with open(paths["variables"]) as f:
            data = json.load(f)
        assert "aws_region" in data.get("variable", {})

    def test_ec2_resource_generated(self, tmp_path):
        """EC2 instance should produce aws_instance resource."""
        exporter = TerraformExporter(output_dir=tmp_path)
        paths = exporter.export(_make_assets(), _make_edges())
        with open(paths["main"]) as f:
            data = json.load(f)
        resources = data.get("resource", {})
        assert "aws_instance" in resources
        instances = resources["aws_instance"]
        assert len(instances) >= 1

    def test_ec2_attributes(self, tmp_path):
        """EC2 resource should have instance_type and ami."""
        exporter = TerraformExporter(output_dir=tmp_path)
        paths = exporter.export(_make_assets(), _make_edges())
        with open(paths["main"]) as f:
            data = json.load(f)
        instances = data["resource"]["aws_instance"]
        instance = next(iter(instances.values()))
        assert instance.get("instance_type") == "t3.medium"
        assert instance.get("ami") == "ami-12345"

    def test_sg_ingress_expanded(self, tmp_path):
        """SG resource should have expanded ingress/egress blocks."""
        exporter = TerraformExporter(output_dir=tmp_path)
        paths = exporter.export(_make_assets(), _make_edges())
        with open(paths["main"]) as f:
            data = json.load(f)
        sgs = data["resource"].get("aws_security_group", {})
        sg = next(iter(sgs.values()))
        assert "ingress" in sg
        assert len(sg["ingress"]) == 2  # port 443 and 80
        assert sg["ingress"][0]["from_port"] == 443
        assert "egress" in sg

    def test_rds_attributes(self, tmp_path):
        """RDS resource should have engine and encryption attrs."""
        exporter = TerraformExporter(output_dir=tmp_path)
        paths = exporter.export(_make_assets(), _make_edges())
        with open(paths["main"]) as f:
            data = json.load(f)
        rds = data["resource"].get("aws_db_instance", {})
        db = next(iter(rds.values()))
        assert db["engine"] == "postgres"
        assert db["storage_encrypted"] is True
        assert db["multi_az"] is True

    def test_iam_role_has_policy(self, tmp_path):
        """IAM role should have assume_role_policy as JSON string."""
        exporter = TerraformExporter(output_dir=tmp_path)
        paths = exporter.export(_make_assets(), _make_edges())
        with open(paths["main"]) as f:
            data = json.load(f)
        roles = data["resource"].get("aws_iam_role", {})
        role = next(iter(roles.values()))
        assert "assume_role_policy" in role
        # Should be a JSON string, parseable
        parsed = json.loads(role["assume_role_policy"])
        assert parsed["Version"] == "2012-10-17"

    def test_computed_fields_stripped(self, tmp_path):
        """Computed/read-only fields should NOT appear in output."""
        exporter = TerraformExporter(output_dir=tmp_path)
        paths = exporter.export(_make_assets(), _make_edges())
        with open(paths["main"]) as f:
            data = json.load(f)
        # Check that no resource has 'arn' or 'state' as a direct attribute
        for res_type, resources in data["resource"].items():
            for name, attrs in resources.items():
                assert "arn" not in attrs, f"{res_type}.{name} has computed 'arn'"
                assert "state" not in attrs, f"{res_type}.{name} has computed 'state'"

    def test_import_commands_valid(self, tmp_path):
        """import_commands.sh should contain terraform import lines."""
        exporter = TerraformExporter(output_dir=tmp_path)
        paths = exporter.export(_make_assets(), _make_edges())
        content = paths["import_commands"].read_text()
        assert "terraform import" in content
        # Should reference ARNs
        assert "arn:aws" in content
        assert content.startswith("#!/usr/bin/env bash")

    def test_import_script_executable(self, tmp_path):
        """Import script should be executable."""
        exporter = TerraformExporter(output_dir=tmp_path)
        paths = exporter.export(_make_assets(), _make_edges())
        import os
        assert os.access(paths["import_commands"], os.X_OK)

    def test_s3_bucket_resource(self, tmp_path):
        """S3 bucket should produce aws_s3_bucket resource."""
        exporter = TerraformExporter(output_dir=tmp_path)
        paths = exporter.export(_make_assets(), _make_edges())
        with open(paths["main"]) as f:
            data = json.load(f)
        assert "aws_s3_bucket" in data["resource"]

    def test_preview(self):
        """Preview should return correct counts without writing files."""
        exporter = TerraformExporter()
        preview = exporter.preview(_make_assets())
        assert preview["total_mapped"] == len(_make_assets())
        assert preview["total_unmapped"] == 0
        assert "aws_instance" in preview["resource_types"]
        assert "aws_vpc" in preview["resource_types"]

    def test_provider_required_providers(self, tmp_path):
        """Provider file should have required_providers block."""
        exporter = TerraformExporter(output_dir=tmp_path)
        paths = exporter.export(_make_assets())
        with open(paths["provider"]) as f:
            data = json.load(f)
        req = data["terraform"]["required_providers"]
        assert "aws" in req
        assert req["aws"]["source"] == "hashicorp/aws"
