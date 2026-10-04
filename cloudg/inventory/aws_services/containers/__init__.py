"""Containers: ECR, ECS and EKS, down to the workloads inside clusters.

- ECR repositories with image inventory, scan findings summary, scan
  configuration, encryption and cross-account pull grants.
- ECS clusters -> services -> task definitions -> container images, task
  and execution roles, secrets, log groups, target groups, subnets, SGs.
- EKS clusters -> nodegroups (ASGs, node roles), Fargate profiles, addons
  (IRSA roles), access entries (which IAM principals hold which cluster
  access policies), pod identity associations, OIDC provider; plus the
  in-cluster Kubernetes workloads via :mod:`cloudg.inventory.kubernetes`.
"""

from __future__ import annotations

from cloudg.inventory._util import image_repository
from cloudg.inventory.aws_services.containers.ecr import EcrCollectorsMixin
from cloudg.inventory.aws_services.containers.ecs import EcsCollectorsMixin, _chunks
from cloudg.inventory.aws_services.containers.eks import (
    EksCollectorsMixin,
    _status,
    k8s_identifier,
)


class ContainerCollectorsMixin(EcrCollectorsMixin, EcsCollectorsMixin, EksCollectorsMixin):
    """Every container collector; the ECS override precedes AsyncAWSCollector."""


__all__ = [
    "ContainerCollectorsMixin",
    "EcrCollectorsMixin",
    "EcsCollectorsMixin",
    "EksCollectorsMixin",
    "_chunks",
    "_status",
    "image_repository",
    "k8s_identifier",
]
