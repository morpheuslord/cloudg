"""Terraform .tf.json recreation support.

Generates Terraform-native JSON configuration from collected CloudG
assets, enabling infrastructure recreation and state import.

Output structure:
    reports/terraform/
    ├── provider.tf.json
    ├── variables.tf.json
    ├── main.tf.json
    └── import_commands.sh

Uses .tf.json format (not HCL) because Terraform natively reads JSON
and it's trivially safe to generate from Python dicts.
"""

from __future__ import annotations

import json
import logging
import re
from pathlib import Path
from typing import Any

from cloudg.schema.models import (
    AssetType,
    CloudAsset,
    CloudProvider,
    NetworkEdge,
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Asset Type → Terraform resource mapping
# ---------------------------------------------------------------------------

# Each entry: (terraform_resource_type, attribute_transformer_function_name)
_TF_RESOURCE_MAP: dict[AssetType, str] = {
    # AWS
    AssetType.EC2: "aws_instance",
    AssetType.VPC: "aws_vpc",
    AssetType.SUBNET: "aws_subnet",
    AssetType.SECURITY_GROUP: "aws_security_group",
    AssetType.S3_BUCKET: "aws_s3_bucket",
    AssetType.RDS_INSTANCE: "aws_db_instance",
    AssetType.LAMBDA_FUNCTION: "aws_lambda_function",
    AssetType.LOAD_BALANCER: "aws_lb",
    AssetType.IAM_ROLE: "aws_iam_role",
    AssetType.IAM_USER: "aws_iam_user",
    AssetType.IAM_POLICY: "aws_iam_policy",
    AssetType.ECS_CLUSTER: "aws_ecs_cluster",
    AssetType.DYNAMODB_TABLE: "aws_dynamodb_table",
    AssetType.KMS_KEY: "aws_kms_key",
    AssetType.SECRET: "aws_secretsmanager_secret",
    AssetType.CLOUDFRONT: "aws_cloudfront_distribution",
    AssetType.NAT_GATEWAY: "aws_nat_gateway",
    AssetType.INTERNET_GATEWAY: "aws_internet_gateway",
    AssetType.ELASTIC_IP: "aws_eip",
    AssetType.ROUTE_TABLE: "aws_route_table",
    AssetType.NACL: "aws_network_acl",
    AssetType.CLOUDTRAIL: "aws_cloudtrail",
    # Azure
    AssetType.VIRTUAL_MACHINE: "azurerm_linux_virtual_machine",
    AssetType.VNET: "azurerm_virtual_network",
    AssetType.NSG: "azurerm_network_security_group",
    AssetType.BLOB_STORAGE: "azurerm_storage_account",
    AssetType.AZURE_SQL: "azurerm_mssql_database",
    AssetType.KEY_VAULT: "azurerm_key_vault",
    AssetType.AKS_CLUSTER: "azurerm_kubernetes_cluster",
    AssetType.APP_SERVICE: "azurerm_linux_web_app",
    # GCP
    AssetType.GCE_INSTANCE: "google_compute_instance",
    AssetType.GCS_BUCKET: "google_storage_bucket",
    AssetType.CLOUD_SQL: "google_sql_database_instance",
    AssetType.CLOUD_FUNCTION: "google_cloudfunctions_function",
    AssetType.GKE_CLUSTER: "google_container_cluster",
}

# Read-only / computed fields to strip from Terraform output
_COMPUTED_FIELDS = {
    "arn",
    "id",
    "state",
    "status",
    "create_date",
    "creation_date",
    "public_ip",
    "private_ip",
    "dns_name",
    "domain_name",
    "last_modified",
    "last_accessed",
    "last_rotated",
    "running_tasks",
    "active_services",
    "item_count",
    "size_bytes",
    "acl_grants",
    "public_access_block",
    "key_state",
    "origin",
    "image_id",
    "password_last_used",
    "user_id",
    "role_id",
    "web_acl_id",
    "capacity_providers",
}


def _sanitise_tf_name(name: str) -> str:
    """Convert a resource name to a valid Terraform resource label."""
    # Replace non-alphanumeric with underscore, strip leading digits
    clean = re.sub(r"[^a-zA-Z0-9_]", "_", name)
    clean = re.sub(r"^[0-9]+", "", clean)
    clean = re.sub(r"_+", "_", clean).strip("_")
    return clean[:64] or "resource"


def _get_import_id(asset: CloudAsset) -> str:
    """Determine the best ID for `terraform import` command."""
    if asset.arn:
        return asset.arn
    # Fallback to provider-specific IDs from metadata
    for key in ("vpc_id", "subnet_id", "group_id", "instance_id"):
        val = asset.metadata.get(key)
        if val:
            return val
    return asset.id


# ---------------------------------------------------------------------------
# Per-resource attribute transformers
# ---------------------------------------------------------------------------


def _transform_ec2(asset: CloudAsset) -> dict[str, Any]:
    """Transform EC2 instance to aws_instance attributes."""
    m = asset.metadata
    attrs: dict[str, Any] = {}
    if m.get("instance_type"):
        attrs["instance_type"] = m["instance_type"]
    if m.get("image_id"):
        attrs["ami"] = m["image_id"]
    if m.get("subnet_id"):
        attrs["subnet_id"] = m["subnet_id"]
    if m.get("security_groups"):
        attrs["vpc_security_group_ids"] = m["security_groups"]
    if asset.tags:
        attrs["tags"] = asset.tags
    return attrs


def _transform_vpc(asset: CloudAsset) -> dict[str, Any]:
    m = asset.metadata
    attrs: dict[str, Any] = {}
    if m.get("cidr_block"):
        attrs["cidr_block"] = m["cidr_block"]
    attrs["enable_dns_support"] = True
    attrs["enable_dns_hostnames"] = True
    if asset.tags:
        attrs["tags"] = asset.tags
    return attrs


def _transform_subnet(asset: CloudAsset) -> dict[str, Any]:
    m = asset.metadata
    attrs: dict[str, Any] = {}
    if m.get("vpc_id"):
        attrs["vpc_id"] = m["vpc_id"]
    if m.get("cidr_block"):
        attrs["cidr_block"] = m["cidr_block"]
    if m.get("availability_zone"):
        attrs["availability_zone"] = m["availability_zone"]
    if m.get("map_public_ip"):
        attrs["map_public_ip_on_launch"] = m["map_public_ip"]
    if asset.tags:
        attrs["tags"] = asset.tags
    return attrs


def _transform_security_group(asset: CloudAsset) -> dict[str, Any]:
    m = asset.metadata
    attrs: dict[str, Any] = {
        "name": asset.name,
    }
    if m.get("description"):
        attrs["description"] = m["description"]
    if m.get("vpc_id"):
        attrs["vpc_id"] = m["vpc_id"]

    # Expand ingress rules
    ingress_rules = []
    for rule in m.get("ingress_rules", []):
        for ip_range in rule.get("IpRanges", []):
            proto = rule.get("IpProtocol", "-1")
            ingress_rules.append(
                {
                    "from_port": rule.get("FromPort", 0),
                    "to_port": rule.get("ToPort", 0),
                    "protocol": "all" if proto == "-1" else proto,
                    "cidr_blocks": [ip_range.get("CidrIp", "")],
                    "description": ip_range.get("Description", ""),
                }
            )
    if ingress_rules:
        attrs["ingress"] = ingress_rules

    # Expand egress rules
    egress_rules = []
    for rule in m.get("egress_rules", []):
        for ip_range in rule.get("IpRanges", []):
            proto = rule.get("IpProtocol", "-1")
            egress_rules.append(
                {
                    "from_port": rule.get("FromPort", 0),
                    "to_port": rule.get("ToPort", 0),
                    "protocol": "all" if proto == "-1" else proto,
                    "cidr_blocks": [ip_range.get("CidrIp", "")],
                    "description": ip_range.get("Description", ""),
                }
            )
    if egress_rules:
        attrs["egress"] = egress_rules

    if asset.tags:
        attrs["tags"] = asset.tags
    return attrs


def _transform_s3(asset: CloudAsset) -> dict[str, Any]:
    attrs: dict[str, Any] = {
        "bucket": asset.name,
    }
    if asset.tags:
        attrs["tags"] = asset.tags
    return attrs


def _transform_rds(asset: CloudAsset) -> dict[str, Any]:
    m = asset.metadata
    attrs: dict[str, Any] = {
        "identifier": asset.name,
    }
    if m.get("engine"):
        attrs["engine"] = m["engine"]
    if m.get("engine_version"):
        attrs["engine_version"] = m["engine_version"]
    if m.get("instance_class"):
        attrs["instance_class"] = m["instance_class"]
    if m.get("storage_encrypted") is not None:
        attrs["storage_encrypted"] = m["storage_encrypted"]
    if m.get("multi_az") is not None:
        attrs["multi_az"] = m["multi_az"]
    if m.get("publicly_accessible") is not None:
        attrs["publicly_accessible"] = m["publicly_accessible"]
    return attrs


def _transform_lambda(asset: CloudAsset) -> dict[str, Any]:
    m = asset.metadata
    attrs: dict[str, Any] = {
        "function_name": asset.name,
    }
    if m.get("runtime"):
        attrs["runtime"] = m["runtime"]
    if m.get("handler"):
        attrs["handler"] = m["handler"]
    if m.get("memory_size"):
        attrs["memory_size"] = m["memory_size"]
    if m.get("timeout"):
        attrs["timeout"] = m["timeout"]
    # Lambda needs a deployment package placeholder
    attrs["filename"] = "lambda_placeholder.zip"
    attrs["source_code_hash"] = ""
    return attrs


def _transform_lb(asset: CloudAsset) -> dict[str, Any]:
    m = asset.metadata
    attrs: dict[str, Any] = {
        "name": asset.name,
    }
    if m.get("type"):
        attrs["load_balancer_type"] = m["type"].lower()
    if m.get("scheme"):
        attrs["internal"] = m["scheme"] == "internal"
    if m.get("security_groups"):
        attrs["security_groups"] = m["security_groups"]
    if asset.tags:
        attrs["tags"] = asset.tags
    return attrs


def _transform_iam_role(asset: CloudAsset) -> dict[str, Any]:
    m = asset.metadata
    attrs: dict[str, Any] = {
        "name": asset.name,
    }
    if m.get("assume_role_policy"):
        policy = m["assume_role_policy"]
        if isinstance(policy, dict):
            attrs["assume_role_policy"] = json.dumps(policy)
        else:
            attrs["assume_role_policy"] = str(policy)
    if m.get("max_session_duration"):
        attrs["max_session_duration"] = m["max_session_duration"]
    if asset.tags:
        attrs["tags"] = asset.tags
    return attrs


def _transform_iam_user(asset: CloudAsset) -> dict[str, Any]:
    return {"name": asset.name}


def _transform_ecs_cluster(asset: CloudAsset) -> dict[str, Any]:
    return {"name": asset.name}


def _transform_dynamodb(asset: CloudAsset) -> dict[str, Any]:
    m = asset.metadata
    attrs: dict[str, Any] = {
        "name": asset.name,
    }
    if m.get("billing_mode"):
        attrs["billing_mode"] = m["billing_mode"]
    # DynamoDB needs at least a hash key — use placeholder if not known
    attrs["hash_key"] = "id"
    attrs["attribute"] = [{"name": "id", "type": "S"}]
    return attrs


def _transform_kms(asset: CloudAsset) -> dict[str, Any]:
    m = asset.metadata
    attrs: dict[str, Any] = {}
    if m.get("key_usage"):
        attrs["key_usage"] = m["key_usage"]
    if m.get("rotation_enabled"):
        attrs["enable_key_rotation"] = m["rotation_enabled"]
    attrs["description"] = f"KMS key {asset.name}"
    return attrs


def _transform_secret(asset: CloudAsset) -> dict[str, Any]:
    m = asset.metadata
    attrs: dict[str, Any] = {
        "name": asset.name,
    }
    if m.get("description"):
        attrs["description"] = m["description"]
    if m.get("kms_key_id"):
        attrs["kms_key_id"] = m["kms_key_id"]
    return attrs


def _transform_generic(asset: CloudAsset) -> dict[str, Any]:
    """Fallback transformer: strips computed fields from metadata."""
    attrs: dict[str, Any] = {}
    for key, value in asset.metadata.items():
        if key.lower() not in _COMPUTED_FIELDS and value is not None:
            attrs[key] = value
    if asset.tags:
        attrs["tags"] = asset.tags
    return attrs


# Transformer registry
_TRANSFORMERS: dict[AssetType, Any] = {
    AssetType.EC2: _transform_ec2,
    AssetType.VPC: _transform_vpc,
    AssetType.SUBNET: _transform_subnet,
    AssetType.SECURITY_GROUP: _transform_security_group,
    AssetType.S3_BUCKET: _transform_s3,
    AssetType.RDS_INSTANCE: _transform_rds,
    AssetType.LAMBDA_FUNCTION: _transform_lambda,
    AssetType.LOAD_BALANCER: _transform_lb,
    AssetType.IAM_ROLE: _transform_iam_role,
    AssetType.IAM_USER: _transform_iam_user,
    AssetType.ECS_CLUSTER: _transform_ecs_cluster,
    AssetType.DYNAMODB_TABLE: _transform_dynamodb,
    AssetType.KMS_KEY: _transform_kms,
    AssetType.SECRET: _transform_secret,
}


# ---------------------------------------------------------------------------
# Terraform Exporter
# ---------------------------------------------------------------------------


class TerraformExporter:
    """Generates Terraform .tf.json from collected CloudG assets.

    Produces:
    - provider.tf.json — provider configuration
    - variables.tf.json — parameterised values
    - main.tf.json — all resource definitions
    - import_commands.sh — terraform import commands for each resource
    """

    def __init__(self, output_dir: str | Path = "./reports/terraform") -> None:
        self._output_dir = Path(output_dir)

    def export(
        self,
        assets: list[CloudAsset],
        edges: list[NetworkEdge] | None = None,
    ) -> dict[str, Path]:
        """Generate all Terraform files from assets.

        Args:
            assets: Collected cloud assets.
            edges: Optional edges for cross-reference resolution.

        Returns:
            Dict mapping file type → Path.
        """
        self._output_dir.mkdir(parents=True, exist_ok=True)

        # Determine providers used
        providers_used = {a.provider for a in assets}

        # Build cross-reference maps from edges
        containment_map = self._build_containment_map(edges or [])

        # Generate files
        provider_path = self._generate_provider(providers_used, assets)
        variables_path = self._generate_variables(assets)
        main_path = self._generate_main(assets, containment_map)
        import_path = self._generate_import_commands(assets)

        paths = {
            "provider": provider_path,
            "variables": variables_path,
            "main": main_path,
            "import_commands": import_path,
        }

        logger.info(
            "Terraform export complete: %d resources → %s",
            len(assets),
            self._output_dir,
        )
        return paths

    def _build_containment_map(self, edges: list[NetworkEdge]) -> dict[str, str]:
        """Build a map of resource_id → container_id from CONTAINS edges."""
        containment: dict[str, str] = {}
        for edge in edges:
            if edge.edge_type.value == "CONTAINS":
                containment[edge.target_id] = edge.source_id
        return containment

    def _generate_provider(
        self,
        providers: set[CloudProvider],
        assets: list[CloudAsset],
    ) -> Path:
        """Generate provider.tf.json."""
        provider_blocks: dict[str, Any] = {}

        if CloudProvider.AWS in providers:
            provider_blocks["aws"] = {
                "region": "${var.aws_region}",
            }

        if CloudProvider.AZURE in providers:
            provider_blocks["azurerm"] = {
                "features": {},
            }

        if CloudProvider.GCP in providers:
            provider_blocks["google"] = {
                "project": "${var.gcp_project_id}",
                "region": "${var.gcp_region}",
            }

        tf_json = {
            "terraform": {
                "required_version": ">= 1.5.0",
                "required_providers": {},
            },
            "provider": provider_blocks,
        }

        # Add required provider sources
        if CloudProvider.AWS in providers:
            tf_json["terraform"]["required_providers"]["aws"] = {
                "source": "hashicorp/aws",
                "version": "~> 5.0",
            }
        if CloudProvider.AZURE in providers:
            tf_json["terraform"]["required_providers"]["azurerm"] = {
                "source": "hashicorp/azurerm",
                "version": "~> 3.0",
            }
        if CloudProvider.GCP in providers:
            tf_json["terraform"]["required_providers"]["google"] = {
                "source": "hashicorp/google",
                "version": "~> 5.0",
            }

        path = self._output_dir / "provider.tf.json"
        with open(path, "w") as f:
            json.dump(tf_json, f, indent=2)
        return path

    def _generate_variables(self, assets: list[CloudAsset]) -> Path:
        """Generate variables.tf.json with parameterised values."""
        regions = {a.region for a in assets if a.region and a.region != "global"}
        accounts = {a.account_id for a in assets if a.account_id}
        providers = {a.provider for a in assets}

        variables: dict[str, Any] = {}

        if CloudProvider.AWS in providers:
            variables["aws_region"] = {
                "description": "AWS region for resource deployment",
                "type": "string",
                "default": next(iter(regions), "us-east-1"),
            }
            if accounts:
                variables["aws_account_id"] = {
                    "description": "AWS account ID",
                    "type": "string",
                    "default": next(iter(accounts), ""),
                }

        if CloudProvider.GCP in providers:
            gcp_projects = {
                a.account_id for a in assets if a.provider == CloudProvider.GCP and a.account_id
            }
            variables["gcp_project_id"] = {
                "description": "GCP project ID",
                "type": "string",
                "default": next(iter(gcp_projects), ""),
            }
            variables["gcp_region"] = {
                "description": "GCP region",
                "type": "string",
                "default": next(iter(regions), "us-central1"),
            }

        if CloudProvider.AZURE in providers:
            azure_subs = {
                a.account_id for a in assets if a.provider == CloudProvider.AZURE and a.account_id
            }
            variables["azure_subscription_id"] = {
                "description": "Azure subscription ID",
                "type": "string",
                "default": next(iter(azure_subs), ""),
            }

        path = self._output_dir / "variables.tf.json"
        with open(path, "w") as f:
            json.dump({"variable": variables}, f, indent=2)
        return path

    def _generate_main(
        self,
        assets: list[CloudAsset],
        containment_map: dict[str, str],
    ) -> Path:
        """Generate main.tf.json with all resource definitions."""
        resources: dict[str, dict[str, dict[str, Any]]] = {}

        for asset in assets:
            tf_type = _TF_RESOURCE_MAP.get(asset.asset_type)
            if not tf_type:
                logger.debug("No Terraform mapping for asset type: %s", asset.asset_type.value)
                continue

            # Get transformer
            transformer = _TRANSFORMERS.get(asset.asset_type, _transform_generic)
            attrs = transformer(asset)

            # Sanitise resource name for Terraform
            tf_name = _sanitise_tf_name(asset.name)

            # Ensure unique names within same resource type
            if tf_type not in resources:
                resources[tf_type] = {}

            counter = 0
            original_name = tf_name
            while tf_name in resources[tf_type]:
                counter += 1
                tf_name = f"{original_name}_{counter}"

            # Add comment-like metadata as lifecycle ignore
            attrs["lifecycle"] = {"ignore_changes": ["tags"]}

            resources[tf_type][tf_name] = attrs

        # Structure as Terraform JSON
        tf_json: dict[str, Any] = {"resource": resources}

        path = self._output_dir / "main.tf.json"
        with open(path, "w") as f:
            json.dump(tf_json, f, indent=2, default=str)
        return path

    def _generate_import_commands(self, assets: list[CloudAsset]) -> Path:
        """Generate import_commands.sh with terraform import commands."""
        lines = [
            "#!/usr/bin/env bash",
            "# CloudG — Terraform Import Commands",
            "# Generated from collected cloud assets",
            "# Run: chmod +x import_commands.sh && ./import_commands.sh",
            "",
            "set -euo pipefail",
            "",
        ]

        for asset in assets:
            tf_type = _TF_RESOURCE_MAP.get(asset.asset_type)
            if not tf_type:
                continue

            tf_name = _sanitise_tf_name(asset.name)
            import_id = _get_import_id(asset)

            lines.append(f'echo "Importing {tf_type}.{tf_name}..."')
            lines.append(f"terraform import {tf_type}.{tf_name} {import_id}")
            lines.append("")

        lines.append('echo "✓ All imports complete"')

        path = self._output_dir / "import_commands.sh"
        with open(path, "w") as f:
            f.write("\n".join(lines))

        # Make executable
        path.chmod(0o755)

        return path

    # ------------------------------------------------------------------
    # Utility: summary of what would be generated
    # ------------------------------------------------------------------

    def preview(self, assets: list[CloudAsset]) -> dict[str, Any]:
        """Preview what Terraform resources would be generated without writing files.

        Returns:
            Summary dict with resource counts by type.
        """
        type_counts: dict[str, int] = {}
        unmapped: dict[str, int] = {}

        for asset in assets:
            tf_type = _TF_RESOURCE_MAP.get(asset.asset_type)
            if tf_type:
                type_counts[tf_type] = type_counts.get(tf_type, 0) + 1
            else:
                key = asset.asset_type.value
                unmapped[key] = unmapped.get(key, 0) + 1

        return {
            "total_mapped": sum(type_counts.values()),
            "total_unmapped": sum(unmapped.values()),
            "resource_types": type_counts,
            "unmapped_asset_types": unmapped,
        }
