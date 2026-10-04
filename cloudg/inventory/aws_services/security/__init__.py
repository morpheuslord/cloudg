"""Security services and scanners: what protects and watches the estate.

Each service is mapped per account and region. When a service is not
deployed, a placeholder asset with ``metadata.enabled = False`` is emitted
so detection and scanning gaps are visible on the map and in the summary.

- GuardDuty detectors (features, delegated admin) -> MONITORS account
- Security Hub (standards, product integrations, admin) -> aggregates the
  GuardDuty/Inspector/Macie deployments it ingests from
- Inspector2 (per resource type) -> MONITORS every covered EC2 instance,
  ECR repository and Lambda function, with scan status
- Macie, AWS Config (recorder + delivery channel), IAM Access Analyzer,
  Detective
- WAFv2 web ACLs -> PROTECTS ALBs, API Gateway stages, CloudFront
- Network Firewall -> PROTECTS VPC / subnets
- Shield Advanced protections -> PROTECTS resources
- CloudTrail trails -> LOGS_TO S3 / CloudWatch Logs, MONITORS account
"""

from __future__ import annotations

from cloudg.inventory.aws_services.security._common import (
    _NOT_ENABLED_CODES,
    SecurityServiceMixin,
    _disabled_reason,
    _not_enabled,
)
from cloudg.inventory.aws_services.security.detection import (
    _MAX_COVERAGE,
    DetectionCollectorsMixin,
    _coverage_target,
)
from cloudg.inventory.aws_services.security.network_protection import (
    _WAF_RESOURCE_TYPES,
    NetworkProtectionCollectorsMixin,
)
from cloudg.inventory.aws_services.security.posture import PostureCollectorsMixin


class SecurityCollectorsMixin(
    DetectionCollectorsMixin,
    PostureCollectorsMixin,
    NetworkProtectionCollectorsMixin,
):
    """Every security service and scanner collector."""


__all__ = [
    "_MAX_COVERAGE",
    "_NOT_ENABLED_CODES",
    "_WAF_RESOURCE_TYPES",
    "DetectionCollectorsMixin",
    "NetworkProtectionCollectorsMixin",
    "PostureCollectorsMixin",
    "SecurityCollectorsMixin",
    "SecurityServiceMixin",
    "_coverage_target",
    "_disabled_reason",
    "_not_enabled",
]
