"""Task catalog of the deep AWS inventory collector.

Service families, account-wide (global) tasks, task selection and ARN-based
asset classification used by
:class:`~cloudg.inventory.aws_deep.AWSDeepInventoryCollector`; all names are
re-exported from :mod:`cloudg.inventory.aws_deep`.
"""

from __future__ import annotations

from cloudg.inventory.catalogs import asset_type_map, load_catalog
from cloudg.schema.models import AssetType

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


# Collector task name -> collector method, added on top of the base
# collector's tasks (order is the scheduling order).
DEEP_TASK_METHODS: tuple[tuple[str, str], ...] = (
    ("iam", "_collect_iam"),
    ("route_tables", "_collect_route_tables"),
    ("internet_gateways", "_collect_internet_gateways"),
    ("nat_gateways", "_collect_nat_gateways"),
    ("network_interfaces", "_collect_network_interfaces"),
    ("ebs_volumes", "_collect_ebs_volumes"),
    ("elastic_ips", "_collect_elastic_ips"),
    ("nacls", "_collect_nacls"),
    ("vpc_peering", "_collect_vpc_peering"),
    ("transit_gateways", "_collect_transit_gateways"),
    ("vpc_endpoints", "_collect_vpc_endpoints"),
    ("flow_logs", "_collect_flow_logs"),
    ("elb_classic", "_collect_elb_classic"),
    ("autoscaling", "_collect_autoscaling"),
    ("launch_templates", "_collect_launch_templates"),
    ("efs", "_collect_efs"),
    ("elasticache", "_collect_elasticache"),
    ("opensearch", "_collect_opensearch"),
    ("redshift", "_collect_redshift"),
    ("route53", "_collect_route53"),
    ("cloudformation", "_collect_cloudformation"),
    ("log_groups", "_collect_log_groups"),
    ("acm", "_collect_acm"),
    ("ecr", "_collect_ecr"),
    ("eks", "_collect_eks"),
    ("apigateway", "_collect_apigateway"),
    ("apigatewayv2", "_collect_apigatewayv2"),
    ("sqs", "_collect_sqs"),
    ("sns", "_collect_sns"),
    ("eventbridge", "_collect_eventbridge"),
    ("stepfunctions", "_collect_stepfunctions"),
    ("kinesis", "_collect_kinesis"),
    ("guardduty", "_collect_guardduty"),
    ("securityhub", "_collect_securityhub"),
    ("inspector2", "_collect_inspector2"),
    ("macie", "_collect_macie"),
    ("config", "_collect_config"),
    ("access_analyzer", "_collect_access_analyzer"),
    ("detective", "_collect_detective"),
    ("wafv2", "_collect_wafv2"),
    ("network_firewall", "_collect_network_firewall"),
    ("shield", "_collect_shield"),
    ("cloudtrail", "_collect_cloudtrail"),
)
