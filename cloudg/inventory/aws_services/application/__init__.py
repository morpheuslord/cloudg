"""Application delivery, operations and integration services.

- CI/CD: CodePipeline (stages/actions -> roles, CodeBuild, CloudFormation,
  ECS, CodeDeploy, Lambda, artifact buckets/KMS, source connections),
  CodeBuild (service role, VPC, source, ECR image, parameter/secret
  references), CodeDeploy deployment groups (ASGs, ECS services, target
  groups, triggers, alarms), CodeConnections.
- Systems Manager: parameter *metadata* (never values), managed instances
  and hybrid nodes, self-owned documents and their shares, associations,
  maintenance windows.
- AWS Backup: plans, rules, copy actions, selections, vaults (KMS, access
  policy, lock), protected resources.
- ECS extras: capacity providers, container instances, Cloud Map.
- Lambda aliases (routing, function URLs, alias-scoped invokers).
- EventBridge Scheduler, Pipes, API destinations/connections, archives.
- CloudWatch Logs subscription filters, log destinations, resource
  policies, cross-account observability (OAM), CloudWatch alarms.
- Kinesis Data Firehose, AWS Batch, App Runner, Elastic Beanstalk.

Secret material is never collected: no parameter values, no environment
variable values (only names and unmistakable resource identifiers), no
connection auth parameters, no Splunk HEC tokens, no webhook secrets.

Each service area lives in its own module; :class:`ApplicationCollectorsMixin`
composes them, so the mixin keeps its place in the deep collector's MRO.
"""

from __future__ import annotations

from typing import Any

from cloudg.inventory.aws_services.application.alarms import AlarmCollectorsMixin
from cloudg.inventory.aws_services.application.backup import BackupCollectorsMixin
from cloudg.inventory.aws_services.application.batch import BatchCollectorsMixin
from cloudg.inventory.aws_services.application.build_deploy import BuildDeployCollectorsMixin
from cloudg.inventory.aws_services.application.cicd import CicdCollectorsMixin
from cloudg.inventory.aws_services.application.compute import ComputeCollectorsMixin
from cloudg.inventory.aws_services.application.containers_ext import (
    ContainersExtCollectorsMixin,
)
from cloudg.inventory.aws_services.application.firehose import FirehoseCollectorsMixin
from cloudg.inventory.aws_services.application.integration import IntegrationCollectorsMixin
from cloudg.inventory.aws_services.application.logs import LogsCollectorsMixin
from cloudg.inventory.aws_services.application.operations import OperationsCollectorsMixin
from cloudg.inventory.aws_services.application.serverless_ext import (
    LambdaAliasCollectorsMixin,
)

__all__ = ["ApplicationCollectorsMixin"]


class ApplicationCollectorsMixin(
    CicdCollectorsMixin,
    BuildDeployCollectorsMixin,
    OperationsCollectorsMixin,
    AlarmCollectorsMixin,
    BackupCollectorsMixin,
    ContainersExtCollectorsMixin,
    LambdaAliasCollectorsMixin,
    IntegrationCollectorsMixin,
    FirehoseCollectorsMixin,
    LogsCollectorsMixin,
    BatchCollectorsMixin,
    ComputeCollectorsMixin,
):
    """CI/CD, operations, backup, integration, logging and app-platform
    collectors."""

    def _application_tasks(self) -> dict[str, tuple[Any, str, bool]]:
        """name -> (collector callable, service family, is_global)."""
        return {
            "codepipeline": (self._collect_codepipeline, "cicd", False),
            "codebuild": (self._collect_codebuild, "cicd", False),
            "codedeploy": (self._collect_codedeploy, "cicd", False),
            "codeconnections": (self._collect_codeconnections, "cicd", False),
            "ssm_parameters": (self._collect_ssm_parameters, "operations", False),
            "ssm_managed_instances": (self._collect_ssm_managed_instances, "operations", False),
            "ssm_documents": (self._collect_ssm_documents, "operations", False),
            "ssm_associations": (self._collect_ssm_associations, "operations", False),
            "ssm_maintenance_windows": (self._collect_ssm_maintenance_windows, "operations", False),
            "cloudwatch_alarms": (self._collect_cloudwatch_alarms, "operations", False),
            "backup_plans": (self._collect_backup_plans, "backup", False),
            "backup_vaults": (self._collect_backup_vaults, "backup", False),
            "ecs_capacity_providers": (self._collect_ecs_capacity_providers, "containers", False),
            "ecs_container_instances": (self._collect_ecs_container_instances, "containers", False),
            "cloudmap": (self._collect_cloudmap, "containers", False),
            "lambda_aliases": (self._collect_lambda_aliases, "serverless", False),
            "scheduler": (self._collect_scheduler, "integration", False),
            "pipes": (self._collect_pipes, "integration", False),
            "eventbridge_api_destinations": (
                self._collect_eventbridge_api_destinations,
                "integration",
                False,
            ),
            "eventbridge_archives": (self._collect_eventbridge_archives, "integration", False),
            "firehose": (self._collect_firehose, "integration", False),
            "log_subscriptions": (self._collect_log_subscriptions, "logging", False),
            "log_destinations": (self._collect_log_destinations, "logging", False),
            "oam": (self._collect_oam, "logging", False),
            "batch": (self._collect_batch, "compute", False),
            "apprunner": (self._collect_apprunner, "compute", False),
            "elasticbeanstalk": (self._collect_elasticbeanstalk, "compute", False),
        }
