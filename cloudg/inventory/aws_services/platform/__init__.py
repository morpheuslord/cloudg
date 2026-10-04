"""Platform, data, DNS and deployment services.

- S3 (deep): real bucket region, encryption key, event notifications
  (-> Lambda / SQS / SNS), replication, access logging, policy grants.
- Load balancing: ALB/NLB listeners + certificates + access logs, target
  groups -> registered targets, classic ELBs -> instances.
- Auto Scaling groups -> instances / launch templates / target groups,
  launch templates (AMI, instance profile, SGs).
- Data: RDS instances + Aurora clusters (deep), EFS (+ mount targets and
  access points), ElastiCache, OpenSearch, Redshift.
- DNS: Route 53 zones and alias / CNAME / A records -> what they resolve to.
- Deployment: CloudFormation stacks -> every resource they manage.
- Operations: CloudWatch log groups, ACM certificates -> what uses them,
  VPC endpoints, VPC flow logs.

Each area lives in its own module; :class:`PlatformCollectorsMixin`
composes them so the S3 / ELBv2 / RDS overrides still precede
``AsyncAWSCollector`` in the deep collector's MRO.
"""

from __future__ import annotations

from cloudg.inventory.aws_services.platform.compute_fabric import ComputeFabricCollectorsMixin
from cloudg.inventory.aws_services.platform.data import DataCollectorsMixin
from cloudg.inventory.aws_services.platform.dns_iac_ops import (
    _ACM_KEY_TYPES,
    _DNS_RECORD_TYPES,
    _MAX_RECORDS_PER_ZONE,
    DnsIacOpsCollectorsMixin,
    _dns,
)
from cloudg.inventory.aws_services.platform.load_balancing import LoadBalancingCollectorsMixin
from cloudg.inventory.aws_services.platform.storage import StorageCollectorsMixin


class PlatformCollectorsMixin(
    StorageCollectorsMixin,
    LoadBalancingCollectorsMixin,
    ComputeFabricCollectorsMixin,
    DataCollectorsMixin,
    DnsIacOpsCollectorsMixin,
):
    """Every platform, data, DNS and deployment collector."""


__all__ = [
    "_ACM_KEY_TYPES",
    "_DNS_RECORD_TYPES",
    "_MAX_RECORDS_PER_ZONE",
    "ComputeFabricCollectorsMixin",
    "DataCollectorsMixin",
    "DnsIacOpsCollectorsMixin",
    "LoadBalancingCollectorsMixin",
    "PlatformCollectorsMixin",
    "StorageCollectorsMixin",
    "_dns",
]
