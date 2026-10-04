"""Data, analytics, messaging and machine-learning services.

- Messaging: MSK (provisioned + serverless, cluster policies), Amazon MQ.
- Machine learning: SageMaker domains, notebook instances, endpoints
  (-> endpoint config -> models) and models; Bedrock agents (action group
  Lambdas, knowledge bases, guardrails), knowledge bases (vector stores,
  data sources), guardrails and model invocation logging.
- Serverless data: OpenSearch Serverless collections (network, encryption
  and data access policies), Redshift Serverless workgroups / namespaces.
- Analytics: Glue Data Catalog (databases, jobs, crawlers, connections,
  triggers), Lake Formation (admins, registered locations, grants), EMR
  clusters, EMR Serverless applications, Athena workgroups.
- Data movement: Transfer Family servers / users, DataSync tasks and
  locations.
- Data stores: RDS Proxy, Aurora global clusters, MemoryDB, DAX, FSx.
- Public registries: ECR Public repositories.

Secret material is never collected: connection passwords, environment and
argument values, Kerberos attributes and similar fields are dropped; only
identifiers (ARNs, names, hosts, S3 locations) are kept.

Each area lives in its own sub-module; :class:`DataMLCollectorsMixin`
composes them and owns the task registry.
"""

from __future__ import annotations

from typing import Any

from cloudg.inventory.aws_services.data_ml._common import (
    _AGENT_VERSION,
    _EMR_ACTIVE_STATES,
    _EXECUTE_API_HOST_RE,
    _FS_ID_RE,
    _GLUE_ARG_LOGS,
    _GLUE_ARG_READS,
    _GLUE_ARG_WRITES,
    _MAX_LF_PERMISSIONS,
    _MAX_TABLES_COUNTED,
    _MAX_TRANSFER_USERS,
    _S3_URI_RE,
    _UUID_RE,
    DataMLHelpersMixin,
    _aoss_match,
    _bucket_arn,
    _document,
    _host,
    _kms_ref,
    logger,
)
from cloudg.inventory.aws_services.data_ml.analytics import AnalyticsCollectorsMixin
from cloudg.inventory.aws_services.data_ml.bedrock import BedrockCollectorsMixin
from cloudg.inventory.aws_services.data_ml.databases import DatabaseCollectorsMixin
from cloudg.inventory.aws_services.data_ml.glue import GlueCollectorsMixin
from cloudg.inventory.aws_services.data_ml.lakeformation import LakeFormationCollectorsMixin
from cloudg.inventory.aws_services.data_ml.messaging import MessagingCollectorsMixin
from cloudg.inventory.aws_services.data_ml.registry import RegistryCollectorsMixin
from cloudg.inventory.aws_services.data_ml.sagemaker import SageMakerCollectorsMixin
from cloudg.inventory.aws_services.data_ml.serverless_data import ServerlessDataCollectorsMixin
from cloudg.inventory.aws_services.data_ml.transfer import TransferCollectorsMixin

__all__ = [
    "DataMLCollectorsMixin",
    "DataMLHelpersMixin",
    "_AGENT_VERSION",
    "_EMR_ACTIVE_STATES",
    "_EXECUTE_API_HOST_RE",
    "_FS_ID_RE",
    "_GLUE_ARG_LOGS",
    "_GLUE_ARG_READS",
    "_GLUE_ARG_WRITES",
    "_MAX_LF_PERMISSIONS",
    "_MAX_TABLES_COUNTED",
    "_MAX_TRANSFER_USERS",
    "_S3_URI_RE",
    "_UUID_RE",
    "_aoss_match",
    "_bucket_arn",
    "_document",
    "_host",
    "_kms_ref",
    "logger",
]


class DataMLCollectorsMixin(
    MessagingCollectorsMixin,
    SageMakerCollectorsMixin,
    BedrockCollectorsMixin,
    ServerlessDataCollectorsMixin,
    GlueCollectorsMixin,
    LakeFormationCollectorsMixin,
    AnalyticsCollectorsMixin,
    TransferCollectorsMixin,
    DatabaseCollectorsMixin,
    RegistryCollectorsMixin,
):
    """Collectors for data, analytics, messaging and ML services."""

    def _data_ml_tasks(self) -> dict[str, tuple[Any, str, bool]]:
        """name -> (collector callable, service family, is_global)."""
        return {
            "msk": (self._collect_msk, "integration", False),
            "amazon_mq": (self._collect_amazon_mq, "integration", False),
            "sagemaker": (self._collect_sagemaker, "ml", False),
            "bedrock": (self._collect_bedrock, "ml", False),
            "opensearch_serverless": (self._collect_opensearch_serverless, "data", False),
            "redshift_serverless": (self._collect_redshift_serverless, "data", False),
            "glue": (self._collect_glue, "analytics", False),
            "lakeformation": (self._collect_lakeformation, "analytics", False),
            "emr": (self._collect_emr, "analytics", False),
            "emr_serverless": (self._collect_emr_serverless, "analytics", False),
            "athena": (self._collect_athena, "analytics", False),
            "transfer_family": (self._collect_transfer_family, "storage", False),
            "datasync": (self._collect_datasync, "storage", False),
            "fsx": (self._collect_fsx, "storage", False),
            "rds_proxies": (self._collect_rds_proxies, "data", False),
            "rds_global_clusters": (self._collect_rds_global_clusters, "data", True),
            "memorydb": (self._collect_memorydb, "data", False),
            "dax": (self._collect_dax, "data", False),
            "ecr_public": (self._collect_ecr_public, "containers", True),
        }
