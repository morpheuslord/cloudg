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
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
from fnmatch import fnmatchcase
from typing import Any, Awaitable, Callable
from urllib.parse import urlparse

from cloudg.inventory.aws_services._base import (
    AWSServiceMixin,
    arns_in,
    as_list,
    error_code,
    gather_limited,
    identifier_refs,
    policy_principals,
    policy_statements,
    principal_ref,
    rel,
)
from cloudg.schema.models import AssetType, CloudAsset, EdgeType

logger = logging.getLogger(__name__)

_MAX_TRANSFER_USERS = 200  # per server
_MAX_LF_PERMISSIONS = 2000  # per region
_MAX_TABLES_COUNTED = 1000  # per Glue database
_AGENT_VERSION = "DRAFT"  # working copy of a Bedrock agent

_UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I)
_S3_URI_RE = re.compile(r"^s3[an]?://([^/]+)", re.I)
_FS_ID_RE = re.compile(r"\b(fs-[0-9a-f]{8,17})\b")
_EMR_ACTIVE_STATES = ["STARTING", "BOOTSTRAPPING", "RUNNING", "WAITING"]

# Glue job arguments that carry S3 locations (values are never stored)
_GLUE_ARG_READS = ("--extra-py-files", "--extra-jars", "--extra-files")
_GLUE_ARG_WRITES = ("--TempDir",)
_GLUE_ARG_LOGS = ("--spark-event-logs-path",)


def _kms_ref(key: Any) -> str | None:
    """A KMS key identifier worth linking (drops 'auto', AWS-owned markers)."""
    if not isinstance(key, str) or not key:
        return None
    if key.startswith("arn:") or key.startswith("alias/") or _UUID_RE.match(key):
        return key
    return None


def _bucket_arn(uri: Any) -> str | None:
    """Bucket ARN for an ``s3://bucket/key`` URI or S3 ARN."""
    if not isinstance(uri, str) or not uri:
        return None
    m = _S3_URI_RE.match(uri.strip())
    if m:
        return f"arn:aws:s3:::{m.group(1)}"
    if uri.startswith("arn:aws:s3:::"):
        return uri.split("/", 1)[0]
    return None


def _host(url: Any) -> str | None:
    """Hostname of a URL (never user-info, path or query)."""
    if not isinstance(url, str) or not url:
        return None
    candidate = url[len("jdbc:") :] if url.startswith("jdbc:") else url
    if "://" not in candidate:
        candidate = f"//{candidate}"
    try:
        host = urlparse(candidate).hostname
    except ValueError:
        return None
    return host.lower() if host else None


def _document(doc: Any) -> Any:
    """Parse a JSON document that may already be decoded."""
    if isinstance(doc, str):
        try:
            return json.loads(doc)
        except ValueError:
            return None
    return doc


def _aoss_match(resources: Any, name: str, kinds: tuple[str, ...]) -> bool:
    """Whether OpenSearch Serverless resource patterns cover a collection."""
    for res in as_list(resources):
        if not isinstance(res, str):
            continue
        kind, _, rest = res.partition("/")
        if kind not in kinds:
            continue
        if fnmatchcase(name, rest.split("/", 1)[0]):
            return True
    return False


class DataMLCollectorsMixin(AWSServiceMixin):
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

    # ------------------------------------------------------------------
    # Shared helpers
    # ------------------------------------------------------------------

    def _role_ref(self, role: Any) -> str | None:
        if not isinstance(role, str) or not role:
            return None
        return role if role.startswith("arn:") else f"arn:aws:iam::{self._account_id}:role/{role}"

    def _profile_ref(self, profile: Any) -> str | None:
        if not isinstance(profile, str) or not profile:
            return None
        if profile.startswith("arn:"):
            return profile
        return f"arn:aws:iam::{self._account_id}:instance-profile/{profile}"

    def _log_group_ref(self, group: Any, region: str | None = None) -> str | None:
        if not isinstance(group, str) or not group:
            return None
        if group.startswith("arn:"):
            return group.removesuffix(":*")
        return self._arn("logs", f"log-group:{group}", region)

    @staticmethod
    def _subnet_rels(subnets: Any) -> list[dict[str, Any] | None]:
        return [
            rel(s, EdgeType.CONTAINS, "SUBNET_CONTAINS_INSTANCE", reverse=True)
            for s in as_list(subnets)
        ]

    @staticmethod
    def _grant_rels(policy: Any, description: str) -> tuple[list[dict[str, Any] | None], bool]:
        """GRANTS_ACCESS relations (principal -> resource) from a resource
        policy, plus whether it allows any principal unconditionally."""
        relations: list[dict[str, Any] | None] = []
        public = False
        seen: set[str] = set()
        for st in policy_statements(policy):
            if st.get("Effect") != "Allow":
                continue
            for p in policy_principals(st).get("AWS", []):
                if p == "*":
                    public = public or not st.get("Condition")
                    continue
                ref = principal_ref(p)
                if ref in seen:
                    continue
                seen.add(ref)
                relations.append(
                    rel(
                        ref,
                        EdgeType.GRANTS_ACCESS,
                        "POLICY_ALLOWS_ACTION",
                        reverse=True,
                        description=description,
                        actions=as_list(st.get("Action"))[:20],
                    )
                )
        return relations, public

    async def _gather_parts(
        self, label: str, parts: dict[str, Callable[[], Awaitable[list[CloudAsset]]]]
    ) -> list[CloudAsset]:
        """Run independent sub-collectors; raise only when all of them fail."""
        names = list(parts)
        results = await asyncio.gather(*(parts[n]() for n in names), return_exceptions=True)
        assets: list[CloudAsset] = []
        failures: dict[str, Exception] = {}
        for name, result in zip(names, results):
            if isinstance(result, Exception):
                failures[name] = result
            elif isinstance(result, BaseException):
                raise result
            else:
                assets.extend(result)
        if failures and len(failures) == len(names):
            raise next(iter(failures.values()))
        for name, exc in failures.items():
            logger.info("%s: %s collection failed (%s): %s", label, name, error_code(exc), exc)
        return assets

    # ------------------------------------------------------------------
    # MSK
    # ------------------------------------------------------------------

    async def _collect_msk(self) -> list[CloudAsset]:
        async with self._client("kafka") as kafka:
            clusters = [
                c async for c in self._paginate(kafka, "list_clusters_v2", "ClusterInfoList")
            ]

            async def detail(c: dict) -> CloudAsset:
                arn = c["ClusterArn"]
                relations: list[dict[str, Any] | None] = []
                sgs: list[str] = []
                md: dict[str, Any] = {
                    "service": "msk",
                    "cluster_type": c.get("ClusterType"),
                    "state": c.get("State"),
                    "kafka_version": c.get("CurrentVersion"),
                }
                exposed = False
                prov = c.get("Provisioned") or {}
                if prov:
                    nodes = prov.get("BrokerNodeGroupInfo") or {}
                    relations += self._subnet_rels(nodes.get("ClientSubnets"))
                    sgs += nodes.get("SecurityGroups") or []
                    public = ((nodes.get("ConnectivityInfo") or {}).get("PublicAccess") or {}).get(
                        "Type"
                    )
                    exposed = bool(public) and public != "DISABLED"
                    kms = ((prov.get("EncryptionInfo") or {}).get("EncryptionAtRest") or {}).get(
                        "DataVolumeKMSKeyId"
                    )
                    relations.append(rel(_kms_ref(kms), EdgeType.REFERENCES, "ENCRYPTED_BY_KMS"))
                    logs = (prov.get("LoggingInfo") or {}).get("BrokerLogs") or {}
                    cw, fh, s3 = (
                        logs.get("CloudWatchLogs") or {},
                        logs.get("Firehose") or {},
                        logs.get("S3") or {},
                    )
                    if cw.get("Enabled"):
                        relations.append(
                            rel(
                                self._log_group_ref(cw.get("LogGroup")), EdgeType.LOGS_TO, "LOGS_TO"
                            )
                        )
                    if fh.get("Enabled") and fh.get("DeliveryStream"):
                        relations.append(
                            rel(
                                self._arn("firehose", f"deliverystream/{fh['DeliveryStream']}"),
                                EdgeType.LOGS_TO,
                                "LOGS_TO",
                            )
                        )
                    if s3.get("Enabled") and s3.get("Bucket"):
                        relations.append(
                            rel(f"arn:aws:s3:::{s3['Bucket']}", EdgeType.LOGS_TO, "LOGS_TO")
                        )
                    auth = prov.get("ClientAuthentication") or {}
                    sasl = auth.get("Sasl") or {}
                    md.update(
                        {
                            "instance_type": nodes.get("InstanceType"),
                            "broker_nodes": prov.get("NumberOfBrokerNodes"),
                            "public_access": public or "DISABLED",
                            "kms_key_id": _kms_ref(kms),
                            "encryption_in_transit": (
                                (prov.get("EncryptionInfo") or {}).get("EncryptionInTransit") or {}
                            ).get("ClientBroker"),
                            "auth_iam": bool((sasl.get("Iam") or {}).get("Enabled")),
                            "auth_scram": bool((sasl.get("Scram") or {}).get("Enabled")),
                            "auth_tls": bool((auth.get("Tls") or {}).get("Enabled")),
                            "unauthenticated_access": bool(
                                (auth.get("Unauthenticated") or {}).get("Enabled")
                            ),
                            "configuration_arn": (prov.get("CurrentBrokerSoftwareInfo") or {}).get(
                                "ConfigurationArn"
                            ),
                        }
                    )
                for vc in (c.get("Serverless") or {}).get("VpcConfigs") or []:
                    relations += self._subnet_rels(vc.get("SubnetIds"))
                    sgs += vc.get("SecurityGroupIds") or []
                policy = None
                try:
                    policy = (await kafka.get_cluster_policy(ClusterArn=arn)).get("Policy")
                except Exception as exc:
                    if "NotFound" not in error_code(exc):
                        logger.debug("MSK policy lookup failed for %s: %s", arn, exc)
                grants, public_policy = self._grant_rels(policy, "MSK cluster policy grant")
                relations += grants
                md["security_groups"] = sorted(set(sgs))
                md["policy_allows_public"] = public_policy
                return self._asset(
                    arn=arn,
                    name=c.get("ClusterName") or arn,
                    asset_type=AssetType.MESSAGE_BROKER,
                    tags=c.get("Tags"),
                    metadata=md,
                    relations=relations,
                    exposed=exposed,
                )

            results = await gather_limited([lambda c=c: detail(c) for c in clusters])
        return [a for a in results if a]

    # ------------------------------------------------------------------
    # Amazon MQ
    # ------------------------------------------------------------------

    async def _collect_amazon_mq(self) -> list[CloudAsset]:
        async with self._client("mq") as mq:
            brokers = [b async for b in self._paginate(mq, "list_brokers", "BrokerSummaries")]

            async def detail(summary: dict) -> CloudAsset:
                broker_id = summary["BrokerId"]
                b = await mq.describe_broker(BrokerId=broker_id)
                enc = b.get("EncryptionOptions") or {}
                kms = None if enc.get("UseAwsOwnedKey", True) else _kms_ref(enc.get("KmsKeyId"))
                relations: list[dict[str, Any] | None] = self._subnet_rels(b.get("SubnetIds"))
                relations.append(rel(kms, EdgeType.REFERENCES, "ENCRYPTED_BY_KMS"))
                logs = b.get("Logs") or {}
                for kind, key in (("General", "GeneralLogGroup"), ("Audit", "AuditLogGroup")):
                    if logs.get(kind):
                        group = logs.get(key) or f"/aws/amazonmq/broker/{broker_id}/{kind.lower()}"
                        relations.append(
                            rel(
                                self._log_group_ref(group),
                                EdgeType.LOGS_TO,
                                "LOGS_TO",
                                log_type=kind,
                            )
                        )
                replica = b.get("DataReplicationMetadata") or {}
                counterpart = (replica.get("DataReplicationCounterpart") or {}).get("BrokerId")
                if counterpart:
                    relations.append(
                        rel(
                            counterpart,
                            EdgeType.REFERENCES,
                            "REPLICATES_TO",
                            reverse=replica.get("DataReplicationRole") != "PRIMARY",
                        )
                    )
                hosts = []
                for inst in b.get("BrokerInstances") or []:
                    hosts += [_host(e) for e in inst.get("Endpoints") or []]
                    hosts.append(_host(inst.get("ConsoleURL")))
                hosts = sorted({h for h in hosts if h})
                return self._asset(
                    arn=b.get("BrokerArn") or summary.get("BrokerArn", ""),
                    name=b.get("BrokerName") or broker_id,
                    asset_type=AssetType.MESSAGE_BROKER,
                    tags=b.get("Tags"),
                    metadata={
                        "service": "amazon-mq",
                        "broker_id": broker_id,
                        "engine": b.get("EngineType"),
                        "engine_version": b.get("EngineVersion"),
                        "deployment_mode": b.get("DeploymentMode"),
                        "state": b.get("BrokerState"),
                        "publicly_accessible": bool(b.get("PubliclyAccessible")),
                        "authentication_strategy": b.get("AuthenticationStrategy"),
                        "security_groups": b.get("SecurityGroups") or [],
                        "kms_key_id": kms,
                        "aws_owned_key": enc.get("UseAwsOwnedKey"),
                        "general_logs": bool(logs.get("General")),
                        "audit_logs": bool(logs.get("Audit")),
                        "user_count": len(b.get("Users") or []),
                        "ldap_hosts": (b.get("LdapServerMetadata") or {}).get("Hosts") or [],
                        "endpoints": hosts,
                    },
                    relations=relations,
                    exposed=bool(b.get("PubliclyAccessible")),
                    aliases=[broker_id, *hosts],
                )

            results = await gather_limited([lambda b=b: detail(b) for b in brokers])
        return [a for a in results if a]

    # ------------------------------------------------------------------
    # SageMaker
    # ------------------------------------------------------------------

    async def _collect_sagemaker(self) -> list[CloudAsset]:
        async with self._client("sagemaker") as sm:
            return await self._gather_parts(
                "sagemaker",
                {
                    "domains": lambda: self._sagemaker_domains(sm),
                    "notebooks": lambda: self._sagemaker_notebooks(sm),
                    "endpoints": lambda: self._sagemaker_endpoints(sm),
                    "models": lambda: self._sagemaker_models(sm),
                },
            )

    async def _sagemaker_domains(self, sm: Any) -> list[CloudAsset]:
        domains = [d async for d in self._paginate(sm, "list_domains", "Domains")]

        async def detail(summary: dict) -> CloudAsset:
            d = await sm.describe_domain(DomainId=summary["DomainId"])
            settings = d.get("DefaultUserSettings") or {}
            sgs = list(settings.get("SecurityGroups") or [])
            if d.get("SecurityGroupIdForDomainBoundary"):
                sgs.append(d["SecurityGroupIdForDomainBoundary"])
            sharing = settings.get("SharingSettings") or {}
            relations: list[dict[str, Any] | None] = self._subnet_rels(d.get("SubnetIds"))
            relations += [
                rel(
                    settings.get("ExecutionRole"),
                    EdgeType.ASSUMES_ROLE,
                    "RUNS_ON",
                    description="default execution role",
                ),
                rel(_kms_ref(d.get("KmsKeyId")), EdgeType.REFERENCES, "ENCRYPTED_BY_KMS"),
                rel(
                    d.get("HomeEfsFileSystemId"),
                    EdgeType.REFERENCES,
                    "WRITES_TO",
                    description="home directories",
                ),
                rel(
                    _bucket_arn(sharing.get("S3OutputPath")),
                    EdgeType.REFERENCES,
                    "WRITES_TO",
                    description="notebook sharing output",
                ),
            ]
            public = d.get("AppNetworkAccessType") == "PublicInternetOnly"
            return self._asset(
                arn=d.get("DomainArn") or summary.get("DomainArn", ""),
                name=d.get("DomainName") or summary["DomainId"],
                asset_type=AssetType.ML_WORKSPACE,
                metadata={
                    "service": "sagemaker",
                    "kind": "domain",
                    "domain_id": d.get("DomainId"),
                    "status": d.get("Status"),
                    "auth_mode": d.get("AuthMode"),
                    "app_network_access": d.get("AppNetworkAccessType"),
                    "vpc_id": d.get("VpcId"),
                    "security_groups": sorted(set(sgs)),
                    "kms_key_id": _kms_ref(d.get("KmsKeyId")),
                    "url": d.get("Url"),
                },
                relations=relations,
                exposed=public,
                aliases=[d.get("DomainId")],
            )

        results = await gather_limited([lambda x=x: detail(x) for x in domains])
        return [a for a in results if a]

    async def _sagemaker_notebooks(self, sm: Any) -> list[CloudAsset]:
        notebooks = [
            n async for n in self._paginate(sm, "list_notebook_instances", "NotebookInstances")
        ]

        async def detail(summary: dict) -> CloudAsset:
            n = await sm.describe_notebook_instance(
                NotebookInstanceName=summary["NotebookInstanceName"]
            )
            kms = _kms_ref(n.get("KmsKeyId"))
            relations: list[dict[str, Any] | None] = self._subnet_rels(n.get("SubnetId"))
            relations += [
                rel(n.get("RoleArn"), EdgeType.ASSUMES_ROLE, "RUNS_ON"),
                rel(kms, EdgeType.REFERENCES, "ENCRYPTED_BY_KMS"),
                rel(n.get("NetworkInterfaceId"), EdgeType.ATTACHED_TO, reverse=True),
            ]
            direct = n.get("DirectInternetAccess") == "Enabled"
            return self._asset(
                arn=n.get("NotebookInstanceArn") or summary.get("NotebookInstanceArn", ""),
                name=n.get("NotebookInstanceName") or summary["NotebookInstanceName"],
                asset_type=AssetType.ML_WORKSPACE,
                metadata={
                    "service": "sagemaker",
                    "kind": "notebook_instance",
                    "status": n.get("NotebookInstanceStatus"),
                    "instance_type": n.get("InstanceType"),
                    "direct_internet_access": direct,
                    "root_access": n.get("RootAccess"),
                    "security_groups": n.get("SecurityGroups") or [],
                    "kms_key_id": kms,
                    "lifecycle_config": n.get("NotebookInstanceLifecycleConfigName"),
                    "imds_min_version": (n.get("InstanceMetadataServiceConfiguration") or {}).get(
                        "MinimumInstanceMetadataServiceVersion"
                    ),
                    "url": n.get("Url"),
                },
                relations=relations,
                exposed=direct,
            )

        results = await gather_limited([lambda x=x: detail(x) for x in notebooks])
        return [a for a in results if a]

    async def _sagemaker_endpoints(self, sm: Any) -> list[CloudAsset]:
        endpoints = [e async for e in self._paginate(sm, "list_endpoints", "Endpoints")]
        configs: dict[str, dict] = {}

        async def endpoint_config(name: str) -> dict:
            if name not in configs:
                try:
                    configs[name] = await sm.describe_endpoint_config(EndpointConfigName=name)
                except Exception as exc:
                    logger.debug("Endpoint config %s lookup failed: %s", name, exc)
                    configs[name] = {}
            return configs[name]

        async def detail(summary: dict) -> CloudAsset:
            e = await sm.describe_endpoint(EndpointName=summary["EndpointName"])
            cfg = (
                await endpoint_config(e.get("EndpointConfigName", ""))
                if e.get("EndpointConfigName")
                else {}
            )
            variants = (cfg.get("ProductionVariants") or []) + (
                cfg.get("ShadowProductionVariants") or []
            )
            relations: list[dict[str, Any] | None] = [
                # SageMaker lower-cases resource names in ARNs; a bare name
                # could collide with the endpoint's own name.
                rel(
                    self._arn("sagemaker", f"model/{v['ModelName'].lower()}")
                    if v.get("ModelName")
                    else None,
                    EdgeType.REFERENCES,
                    "DEPENDS_ON",
                    description="serves model",
                    variant=v.get("VariantName"),
                )
                for v in variants
            ]
            kms = _kms_ref(cfg.get("KmsKeyId"))
            capture = cfg.get("DataCaptureConfig") or {}
            output = (cfg.get("AsyncInferenceConfig") or {}).get("OutputConfig") or {}
            relations += [
                rel(kms, EdgeType.REFERENCES, "ENCRYPTED_BY_KMS"),
                rel(cfg.get("ExecutionRoleArn"), EdgeType.ASSUMES_ROLE, "RUNS_ON"),
                rel(
                    _bucket_arn(capture.get("DestinationS3Uri"))
                    if capture.get("EnableCapture")
                    else None,
                    EdgeType.REFERENCES,
                    "WRITES_TO",
                    description="data capture",
                ),
                rel(
                    _bucket_arn(output.get("S3OutputPath")),
                    EdgeType.REFERENCES,
                    "WRITES_TO",
                    description="async inference output",
                ),
                rel(
                    _bucket_arn(output.get("S3FailurePath")),
                    EdgeType.REFERENCES,
                    "WRITES_TO",
                    description="async inference failures",
                ),
            ]
            vpc = cfg.get("VpcConfig") or {}
            relations += self._subnet_rels(vpc.get("Subnets"))
            return self._asset(
                arn=e.get("EndpointArn") or summary.get("EndpointArn", ""),
                name=e.get("EndpointName") or summary["EndpointName"],
                asset_type=AssetType.ML_ENDPOINT,
                metadata={
                    "service": "sagemaker",
                    "status": e.get("EndpointStatus"),
                    "endpoint_config": e.get("EndpointConfigName"),
                    "models": [v.get("ModelName") for v in variants if v.get("ModelName")],
                    "instance_types": sorted(
                        {v["InstanceType"] for v in variants if v.get("InstanceType")}
                    ),
                    "serverless": any(v.get("ServerlessConfig") for v in variants),
                    "data_capture": bool(capture.get("EnableCapture")),
                    "kms_key_id": kms,
                    "security_groups": vpc.get("SecurityGroupIds") or [],
                    "network_isolation": cfg.get("EnableNetworkIsolation"),
                },
                relations=relations,
            )

        results = await gather_limited([lambda x=x: detail(x) for x in endpoints])
        return [a for a in results if a]

    async def _sagemaker_models(self, sm: Any) -> list[CloudAsset]:
        models = [m async for m in self._paginate(sm, "list_models", "Models")]

        async def detail(summary: dict) -> CloudAsset:
            m = await sm.describe_model(ModelName=summary["ModelName"])
            containers = ([m["PrimaryContainer"]] if m.get("PrimaryContainer") else []) + (
                m.get("Containers") or []
            )
            relations: list[dict[str, Any] | None] = [
                rel(m.get("ExecutionRoleArn"), EdgeType.ASSUMES_ROLE, "RUNS_ON"),
            ]
            images: list[str] = []
            for c in containers:
                if c.get("Image"):
                    images.append(c["Image"])
                    relations.append(rel(c["Image"], EdgeType.USES_IMAGE, "RUNS_ON"))
                source = ((c.get("ModelDataSource") or {}).get("S3DataSource") or {}).get("S3Uri")
                for uri in (c.get("ModelDataUrl"), source):
                    relations.append(
                        rel(
                            _bucket_arn(uri),
                            EdgeType.REFERENCES,
                            "READS_FROM",
                            description="model artifacts",
                        )
                    )
                relations.append(rel(c.get("ModelPackageName"), EdgeType.REFERENCES, "DEPENDS_ON"))
                relations += [
                    rel(r, EdgeType.REFERENCES, "DEPENDS_ON", description="container environment")
                    for r in identifier_refs(c.get("Environment"))
                ]
            vpc = m.get("VpcConfig") or {}
            relations += self._subnet_rels(vpc.get("Subnets"))
            arn = m.get("ModelArn") or summary.get("ModelArn", "")
            return self._asset(
                arn=arn,
                name=m.get("ModelName") or summary["ModelName"],
                asset_type=AssetType.ML_MODEL,
                metadata={
                    "service": "sagemaker",
                    "images": images,
                    "network_isolation": m.get("EnableNetworkIsolation"),
                    "security_groups": vpc.get("SecurityGroupIds") or [],
                    "in_vpc": bool(vpc),
                },
                relations=relations,
                aliases=[arn.lower() if arn.lower() != arn else None],
            )

        results = await gather_limited([lambda x=x: detail(x) for x in models])
        return [a for a in results if a]

    # ------------------------------------------------------------------
    # Bedrock
    # ------------------------------------------------------------------

    async def _collect_bedrock(self) -> list[CloudAsset]:
        async with (
            self._client("bedrock-agent") as agent_client,
            self._client("bedrock") as bedrock,
        ):
            return await self._gather_parts(
                "bedrock",
                {
                    "agents": lambda: self._bedrock_agents(agent_client),
                    "knowledge_bases": lambda: self._bedrock_knowledge_bases(agent_client),
                    "guardrails": lambda: self._bedrock_guardrails(bedrock),
                    "invocation_logging": lambda: self._bedrock_invocation_logging(bedrock),
                },
            )

    async def _bedrock_agents(self, ba: Any) -> list[CloudAsset]:
        summaries = [s async for s in self._paginate(ba, "list_agents", "agentSummaries")]

        async def action_groups(agent_id: str) -> list[dict]:
            out: list[dict] = []
            try:
                async for ag in self._paginate(
                    ba,
                    "list_agent_action_groups",
                    "actionGroupSummaries",
                    agentId=agent_id,
                    agentVersion=_AGENT_VERSION,
                ):
                    try:
                        resp = await ba.get_agent_action_group(
                            agentId=agent_id,
                            agentVersion=_AGENT_VERSION,
                            actionGroupId=ag["actionGroupId"],
                        )
                        out.append(resp.get("agentActionGroup") or {})
                    except Exception as exc:
                        logger.debug("Action group lookup failed: %s", exc)
            except Exception as exc:
                logger.debug("Action group listing failed for agent %s: %s", agent_id, exc)
            return out

        async def knowledge_bases(agent_id: str) -> list[dict]:
            try:
                return [
                    kb
                    async for kb in self._paginate(
                        ba,
                        "list_agent_knowledge_bases",
                        "agentKnowledgeBaseSummaries",
                        agentId=agent_id,
                        agentVersion=_AGENT_VERSION,
                    )
                ]
            except Exception as exc:
                logger.debug("Agent knowledge base listing failed for %s: %s", agent_id, exc)
                return []

        async def detail(summary: dict) -> CloudAsset:
            agent_id = summary["agentId"]
            a = (await ba.get_agent(agentId=agent_id)).get("agent") or {}
            kms = _kms_ref(a.get("customerEncryptionKeyArn"))
            guardrail = (
                a.get("guardrailConfiguration") or summary.get("guardrailConfiguration") or {}
            )
            relations: list[dict[str, Any] | None] = [
                rel(a.get("agentResourceRoleArn"), EdgeType.ASSUMES_ROLE, "RUNS_ON"),
                rel(kms, EdgeType.REFERENCES, "ENCRYPTED_BY_KMS"),
                rel(
                    guardrail.get("guardrailIdentifier"),
                    EdgeType.PROTECTS,
                    reverse=True,
                    description="Bedrock guardrail",
                    version=guardrail.get("guardrailVersion"),
                ),
            ]
            groups = await action_groups(agent_id)
            for g in groups:
                executor = g.get("actionGroupExecutor") or {}
                relations.append(
                    rel(
                        executor.get("lambda"),
                        EdgeType.INVOKES,
                        "INVOKES",
                        description="action group executor",
                        action_group=g.get("actionGroupName"),
                    )
                )
                schema_s3 = (g.get("apiSchema") or {}).get("s3") or {}
                if schema_s3.get("s3BucketName"):
                    relations.append(
                        rel(
                            f"arn:aws:s3:::{schema_s3['s3BucketName']}",
                            EdgeType.REFERENCES,
                            "READS_FROM",
                            description="action group API schema",
                        )
                    )
            kbs = await knowledge_bases(agent_id)
            relations += [
                rel(
                    self._arn("bedrock", f"knowledge-base/{kb['knowledgeBaseId']}"),
                    EdgeType.REFERENCES,
                    "READS_FROM",
                    description="agent knowledge base",
                    state=kb.get("knowledgeBaseState"),
                )
                for kb in kbs
                if kb.get("knowledgeBaseId")
            ]
            return self._asset(
                arn=a.get("agentArn") or self._arn("bedrock", f"agent/{agent_id}"),
                name=a.get("agentName") or summary.get("agentName") or agent_id,
                asset_type=AssetType.AI_AGENT,
                metadata={
                    "service": "bedrock",
                    "agent_id": agent_id,
                    "status": a.get("agentStatus") or summary.get("agentStatus"),
                    "foundation_model": a.get("foundationModel"),
                    "orchestration": a.get("orchestrationType"),
                    "collaboration": a.get("agentCollaboration"),
                    "kms_key_id": kms,
                    "guardrail": guardrail.get("guardrailIdentifier"),
                    "action_groups": [g.get("actionGroupName") for g in groups],
                    "action_group_lambdas": [
                        (g.get("actionGroupExecutor") or {}).get("lambda")
                        for g in groups
                        if (g.get("actionGroupExecutor") or {}).get("lambda")
                    ],
                    "knowledge_bases": [kb.get("knowledgeBaseId") for kb in kbs],
                },
                relations=relations,
                aliases=[agent_id],
            )

        results = await gather_limited([lambda s=s: detail(s) for s in summaries])
        return [a for a in results if a]

    async def _bedrock_knowledge_bases(self, ba: Any) -> list[CloudAsset]:
        summaries = [
            s async for s in self._paginate(ba, "list_knowledge_bases", "knowledgeBaseSummaries")
        ]

        async def data_sources(kb_id: str) -> list[dict]:
            out: list[dict] = []
            try:
                async for ds in self._paginate(
                    ba, "list_data_sources", "dataSourceSummaries", knowledgeBaseId=kb_id
                ):
                    try:
                        resp = await ba.get_data_source(
                            knowledgeBaseId=kb_id, dataSourceId=ds["dataSourceId"]
                        )
                        out.append(resp.get("dataSource") or {})
                    except Exception as exc:
                        logger.debug("Data source lookup failed: %s", exc)
                        out.append(ds)
            except Exception as exc:
                logger.debug("Data source listing failed for %s: %s", kb_id, exc)
            return out

        async def detail(summary: dict) -> CloudAsset:
            kb_id = summary["knowledgeBaseId"]
            kb = (await ba.get_knowledge_base(knowledgeBaseId=kb_id)).get("knowledgeBase") or {}
            storage = kb.get("storageConfiguration") or {}
            config = kb.get("knowledgeBaseConfiguration") or {}
            vector = config.get("vectorKnowledgeBaseConfiguration") or {}
            relations: list[dict[str, Any] | None] = [
                rel(kb.get("roleArn"), EdgeType.ASSUMES_ROLE, "RUNS_ON")
            ]
            store_targets = {
                "opensearchServerlessConfiguration": "collectionArn",
                "opensearchManagedClusterConfiguration": "domainArn",
                "rdsConfiguration": "resourceArn",
                "neptuneAnalyticsConfiguration": "graphArn",
                "s3VectorsConfiguration": "vectorBucketArn",
            }
            endpoints: list[str] = []
            for key, field in store_targets.items():
                block = storage.get(key) or {}
                relations.append(
                    rel(
                        block.get(field),
                        EdgeType.REFERENCES,
                        "READS_FROM",
                        description="vector store",
                        store_type=storage.get("type"),
                    )
                )
            for block in storage.values():
                if not isinstance(block, dict):
                    continue
                relations.append(
                    rel(
                        block.get("credentialsSecretArn"),
                        EdgeType.REFERENCES,
                        "READS_FROM",
                        description="vector store credentials",
                    )
                )
                for field in ("connectionString", "endpoint", "domainEndpoint"):
                    host = _host(block.get(field))
                    if host:
                        endpoints.append(host)
            relations.append(
                rel(
                    (config.get("kendraKnowledgeBaseConfiguration") or {}).get("kendraIndexArn"),
                    EdgeType.REFERENCES,
                    "READS_FROM",
                    description="Kendra index",
                )
            )
            for loc in (vector.get("supplementalDataStorageConfiguration") or {}).get(
                "storageLocations"
            ) or []:
                relations.append(
                    rel(
                        _bucket_arn((loc.get("s3Location") or {}).get("uri")),
                        EdgeType.REFERENCES,
                        "WRITES_TO",
                        description="supplemental data storage",
                    )
                )
            sources = await data_sources(kb_id)
            source_meta = []
            for ds in sources:
                cfg = ds.get("dataSourceConfiguration") or {}
                s3cfg = cfg.get("s3Configuration") or {}
                relations.append(
                    rel(
                        s3cfg.get("bucketArn"),
                        EdgeType.REFERENCES,
                        "READS_FROM",
                        description="knowledge base data source",
                        data_source=ds.get("name"),
                    )
                )
                relations.append(
                    rel(
                        _kms_ref(
                            (ds.get("serverSideEncryptionConfiguration") or {}).get("kmsKeyArn")
                        ),
                        EdgeType.REFERENCES,
                        "ENCRYPTED_BY_KMS",
                    )
                )
                hosts = []
                for block in cfg.values():
                    if isinstance(block, dict):
                        src = block.get("sourceConfiguration") or {}
                        relations.append(
                            rel(
                                src.get("credentialsSecretArn"),
                                EdgeType.REFERENCES,
                                "READS_FROM",
                                description="data source credentials",
                            )
                        )
                        hosts.append(_host(src.get("hostUrl")))
                source_meta.append(
                    {
                        "name": ds.get("name"),
                        "type": cfg.get("type"),
                        "status": ds.get("status"),
                        "hosts": [h for h in hosts if h],
                    }
                )
            return self._asset(
                arn=kb.get("knowledgeBaseArn") or self._arn("bedrock", f"knowledge-base/{kb_id}"),
                name=kb.get("name") or summary.get("name") or kb_id,
                asset_type=AssetType.KNOWLEDGE_BASE,
                metadata={
                    "service": "bedrock",
                    "knowledge_base_id": kb_id,
                    "status": kb.get("status"),
                    "type": config.get("type"),
                    "storage_type": storage.get("type"),
                    "embedding_model": vector.get("embeddingModelArn"),
                    "vector_store_endpoints": sorted(set(endpoints)),
                    "data_sources": source_meta,
                },
                relations=relations,
                aliases=[kb_id],
            )

        results = await gather_limited([lambda s=s: detail(s) for s in summaries])
        return [a for a in results if a]

    async def _bedrock_guardrails(self, bedrock: Any) -> list[CloudAsset]:
        guardrails = [g async for g in self._paginate(bedrock, "list_guardrails", "guardrails")]

        async def detail(g: dict) -> CloudAsset:
            full: dict = {}
            try:
                full = await bedrock.get_guardrail(guardrailIdentifier=g["id"])
            except Exception as exc:
                logger.debug("Guardrail lookup failed for %s: %s", g.get("id"), exc)
            kms = _kms_ref(full.get("kmsKeyArn"))
            return self._asset(
                arn=g.get("arn") or self._arn("bedrock", f"guardrail/{g['id']}"),
                name=g.get("name") or g["id"],
                asset_type=AssetType.AI_GUARDRAIL,
                metadata={
                    "service": "bedrock",
                    "guardrail_id": g.get("id"),
                    "status": g.get("status"),
                    "version": g.get("version"),
                    "kms_key_id": kms,
                    "topic_policy": bool(full.get("topicPolicy")),
                    "content_policy": bool(full.get("contentPolicy")),
                    "word_policy": bool(full.get("wordPolicy")),
                    "sensitive_information_policy": bool(full.get("sensitiveInformationPolicy")),
                    "contextual_grounding_policy": bool(full.get("contextualGroundingPolicy")),
                    "cross_region_profile": (g.get("crossRegionDetails") or {}).get(
                        "guardrailProfileArn"
                    ),
                },
                relations=[rel(kms, EdgeType.REFERENCES, "ENCRYPTED_BY_KMS")],
                aliases=[g.get("id")],
            )

        results = await gather_limited([lambda g=g: detail(g) for g in guardrails])
        return [a for a in results if a]

    async def _bedrock_invocation_logging(self, bedrock: Any) -> list[CloudAsset]:
        """Model invocation logging is a region-wide setting, so it becomes
        one LOG_SINK asset per region (only when configured)."""
        cfg = (await bedrock.get_model_invocation_logging_configuration()).get(
            "loggingConfig"
        ) or {}
        if not cfg:
            return []
        cw = cfg.get("cloudWatchConfig") or {}
        s3 = cfg.get("s3Config") or {}
        large = cw.get("largeDataDeliveryS3Config") or {}
        relations: list[dict[str, Any] | None] = [
            rel(self._log_group_ref(cw.get("logGroupName")), EdgeType.LOGS_TO, "LOGS_TO"),
            rel(cw.get("roleArn"), EdgeType.ASSUMES_ROLE, "RUNS_ON"),
        ]
        for bucket in (s3.get("bucketName"), large.get("bucketName")):
            if bucket:
                relations.append(rel(f"arn:aws:s3:::{bucket}", EdgeType.LOGS_TO, "LOGS_TO"))
        return [
            self._asset(
                arn=f"cloudg:aws:bedrock:{self._region}:{self._account_id}:model-invocation-logging",
                name=f"Bedrock model invocation logging ({self._region})",
                asset_type=AssetType.LOG_SINK,
                metadata={
                    "service": "bedrock",
                    "kind": "model_invocation_logging",
                    "log_group": cw.get("logGroupName"),
                    "s3_bucket": s3.get("bucketName"),
                    "text": cfg.get("textDataDeliveryEnabled"),
                    "image": cfg.get("imageDataDeliveryEnabled"),
                    "embedding": cfg.get("embeddingDataDeliveryEnabled"),
                    "video": cfg.get("videoDataDeliveryEnabled"),
                },
                relations=relations,
            )
        ]

    # ------------------------------------------------------------------
    # OpenSearch Serverless
    # ------------------------------------------------------------------

    async def _aoss_policies(self, aoss: Any, family: str, policy_type: str) -> list[dict]:
        """Every security ('security') or access ('access') policy document of a type."""
        lister = aoss.list_security_policies if family == "security" else aoss.list_access_policies
        getter = aoss.get_security_policy if family == "security" else aoss.get_access_policy
        summary_key = "securityPolicySummaries" if family == "security" else "accessPolicySummaries"
        detail_key = "securityPolicyDetail" if family == "security" else "accessPolicyDetail"
        out: list[dict] = []
        try:
            async for p in self._pages(lister, summary_key, token_in="nextToken", type=policy_type):
                try:
                    detail = (await getter(type=policy_type, name=p["name"])).get(detail_key) or {}
                    out.append({"name": p["name"], "policy": _document(detail.get("policy"))})
                except Exception as exc:
                    logger.debug(
                        "AOSS %s policy %s lookup failed: %s", policy_type, p.get("name"), exc
                    )
        except Exception as exc:
            logger.debug("AOSS %s policy listing failed: %s", policy_type, exc)
        return out

    async def _collect_opensearch_serverless(self) -> list[CloudAsset]:
        async with self._client("opensearchserverless") as aoss:
            summaries = [
                c
                async for c in self._pages(
                    aoss.list_collections, "collectionSummaries", token_in="nextToken"
                )
            ]
            details: dict[str, dict] = {c["id"]: c for c in summaries if c.get("id")}
            ids = list(details)
            for i in range(0, len(ids), 100):
                try:
                    resp = await aoss.batch_get_collection(ids=ids[i : i + 100])
                    for d in resp.get("collectionDetails", []) or []:
                        details[d["id"]] = {**details.get(d["id"], {}), **d}
                except Exception as exc:
                    logger.debug("AOSS batch_get_collection failed: %s", exc)
            network, encryption, access = await asyncio.gather(
                self._aoss_policies(aoss, "security", "network"),
                self._aoss_policies(aoss, "security", "encryption"),
                self._aoss_policies(aoss, "access", "data"),
            )

        assets: list[CloudAsset] = []
        for c in details.values():
            name = c.get("name") or c["id"]
            relations: list[dict[str, Any] | None] = []
            public_types: set[str] = set()
            source_vpces: set[str] = set()
            network_policies: list[str] = []
            for p in network:
                for block in as_list(p["policy"]):
                    if not isinstance(block, dict):
                        continue
                    for rule in as_list(block.get("Rules")):
                        if not isinstance(rule, dict) or not _aoss_match(
                            rule.get("Resource"), name, ("collection", "dashboard")
                        ):
                            continue
                        network_policies.append(p["name"])
                        if block.get("AllowFromPublic"):
                            public_types.add(str(rule.get("ResourceType", "collection")))
                        source_vpces.update(block.get("SourceVPCEs") or [])
            kms = _kms_ref(c.get("kmsKeyArn"))
            aws_owned = None
            for p in encryption:
                doc = p["policy"]
                if not isinstance(doc, dict):
                    continue
                if any(
                    isinstance(r, dict) and _aoss_match(r.get("Resource"), name, ("collection",))
                    for r in as_list(doc.get("Rules"))
                ):
                    aws_owned = bool(doc.get("AWSOwnedKey"))
                    kms = kms or _kms_ref(doc.get("KmsARN"))
                    break
            relations.append(rel(kms, EdgeType.REFERENCES, "ENCRYPTED_BY_KMS"))
            grants: dict[str, set[str]] = {}
            for p in access:
                for block in as_list(p["policy"]):
                    if not isinstance(block, dict):
                        continue
                    perms: set[str] = set()
                    for rule in as_list(block.get("Rules")):
                        if isinstance(rule, dict) and _aoss_match(
                            rule.get("Resource"), name, ("collection", "index")
                        ):
                            perms.update(str(x) for x in as_list(rule.get("Permission")))
                    if not perms:
                        continue
                    for principal in as_list(block.get("Principal")):
                        if isinstance(principal, str) and (
                            principal.startswith("arn:") or principal.isdigit()
                        ):
                            grants.setdefault(principal_ref(principal), set()).update(perms)
            relations += [
                rel(
                    principal,
                    EdgeType.GRANTS_ACCESS,
                    "POLICY_ALLOWS_ACTION",
                    reverse=True,
                    description="data access policy",
                    permissions=sorted(perms)[:20],
                )
                for principal, perms in grants.items()
            ]
            endpoint = c.get("collectionEndpoint")
            assets.append(
                self._asset(
                    arn=c.get("arn") or self._arn("aoss", f"collection/{c['id']}"),
                    name=name,
                    asset_type=AssetType.SEARCH_DOMAIN,
                    metadata={
                        "service": "opensearch-serverless",
                        "collection_id": c.get("id"),
                        "type": c.get("type"),
                        "status": c.get("status"),
                        "standby_replicas": c.get("standbyReplicas"),
                        "endpoint": endpoint,
                        "dashboard_endpoint": c.get("dashboardEndpoint"),
                        "public_access": sorted(public_types),
                        "source_vpc_endpoints": sorted(source_vpces),
                        "network_policies": sorted(set(network_policies)),
                        "kms_key_id": kms,
                        "aws_owned_key": aws_owned,
                    },
                    relations=relations,
                    exposed=bool(public_types),
                    aliases=[c.get("id"), _host(endpoint)],
                )
            )
        return assets

    # ------------------------------------------------------------------
    # Redshift Serverless
    # ------------------------------------------------------------------

    async def _collect_redshift_serverless(self) -> list[CloudAsset]:
        async with self._client("redshift-serverless") as rs:
            namespaces: list[CloudAsset] = []
            ns_error: Exception | None = None
            try:
                namespaces = await self._redshift_namespaces(rs)
            except Exception as exc:
                ns_error = exc
            # Workgroups name their namespace; resolve it to the namespace ARN
            # (workgroups and namespaces commonly share a name such as "default").
            ns_arns = {a.name: a.arn for a in namespaces}
            try:
                workgroups = await self._redshift_workgroups(rs, ns_arns)
            except Exception as exc:
                if ns_error is not None:
                    raise
                logger.info("redshift_serverless: workgroup collection failed: %s", exc)
                workgroups = []
            if ns_error is not None:
                logger.info("redshift_serverless: namespace collection failed: %s", ns_error)
        return namespaces + workgroups

    async def _redshift_namespaces(self, rs: Any) -> list[CloudAsset]:
        assets: list[CloudAsset] = []
        async for ns in self._paginate(rs, "list_namespaces", "namespaces"):
            kms = _kms_ref(ns.get("kmsKeyId"))
            # iamRoles entries look like "IamRole(applyStatus=in-sync, iamRoleArn=arn:...)"
            roles = [r.rstrip(")") for r in arns_in(ns.get("iamRoles")) if ":role/" in r]
            relations: list[dict[str, Any] | None] = [
                rel(kms, EdgeType.REFERENCES, "ENCRYPTED_BY_KMS"),
                rel(
                    ns.get("adminPasswordSecretArn"),
                    EdgeType.REFERENCES,
                    "READS_FROM",
                    description="managed admin credentials",
                ),
                rel(
                    _kms_ref(ns.get("adminPasswordSecretKmsKeyId")),
                    EdgeType.REFERENCES,
                    "ENCRYPTED_BY_KMS",
                ),
            ]
            relations += [rel(r, EdgeType.ASSUMES_ROLE, "RUNS_ON") for r in roles]
            if ns.get("defaultIamRoleArn") not in roles:
                relations.append(rel(ns.get("defaultIamRoleArn"), EdgeType.ASSUMES_ROLE, "RUNS_ON"))
            assets.append(
                self._asset(
                    arn=ns.get("namespaceArn")
                    or self._arn("redshift-serverless", f"namespace/{ns.get('namespaceId')}"),
                    name=ns.get("namespaceName") or ns.get("namespaceId", ""),
                    asset_type=AssetType.DATA_WAREHOUSE,
                    metadata={
                        "service": "redshift-serverless",
                        "kind": "namespace",
                        "namespace_id": ns.get("namespaceId"),
                        "status": ns.get("status"),
                        "db_name": ns.get("dbName"),
                        "kms_key_id": kms,
                        "log_exports": ns.get("logExports") or [],
                        "iam_roles": roles,
                    },
                    relations=relations,
                    aliases=[ns.get("namespaceId")],
                )
            )
        return assets

    async def _redshift_workgroups(
        self, rs: Any, ns_arns: dict[str, str | None]
    ) -> list[CloudAsset]:
        assets: list[CloudAsset] = []
        async for wg in self._paginate(rs, "list_workgroups", "workgroups"):
            endpoint = wg.get("endpoint") or {}
            vpces = [
                v.get("vpcEndpointId")
                for v in endpoint.get("vpcEndpoints") or []
                if v.get("vpcEndpointId")
            ]
            relations: list[dict[str, Any] | None] = self._subnet_rels(wg.get("subnetIds"))
            ns = wg.get("namespaceName")
            relations.append(
                rel(
                    ns_arns.get(ns) or ns,
                    EdgeType.REFERENCES,
                    "DEPENDS_ON",
                    description="workgroup compute for namespace",
                )
            )
            relations.append(
                rel(
                    wg.get("customDomainCertificateArn"),
                    EdgeType.REFERENCES,
                    "CERTIFICATE_SECURES",
                    reverse=True,
                )
            )
            assets.append(
                self._asset(
                    arn=wg.get("workgroupArn")
                    or self._arn("redshift-serverless", f"workgroup/{wg.get('workgroupId')}"),
                    name=wg.get("workgroupName") or wg.get("workgroupId", ""),
                    asset_type=AssetType.DATA_WAREHOUSE,
                    metadata={
                        "service": "redshift-serverless",
                        "kind": "workgroup",
                        "workgroup_id": wg.get("workgroupId"),
                        "namespace": wg.get("namespaceName"),
                        "status": wg.get("status"),
                        "base_capacity": wg.get("baseCapacity"),
                        "publicly_accessible": bool(wg.get("publiclyAccessible")),
                        "enhanced_vpc_routing": wg.get("enhancedVpcRouting"),
                        "security_groups": wg.get("securityGroupIds") or [],
                        "endpoint": endpoint.get("address"),
                        "vpc_endpoints": vpces,
                        "custom_domain": wg.get("customDomainName"),
                    },
                    relations=relations,
                    exposed=bool(wg.get("publiclyAccessible")),
                    aliases=[
                        wg.get("workgroupId"),
                        endpoint.get("address"),
                        wg.get("customDomainName"),
                    ],
                )
            )
        return assets

    # ------------------------------------------------------------------
    # Glue Data Catalog + Lake Formation
    # ------------------------------------------------------------------

    def _glue_arn(self, kind: str, name: str) -> str:
        return self._arn("glue", f"{kind}/{name}")

    async def _lf_permissions(self, lf: Any) -> list[dict]:
        out: list[dict] = []
        async for p in self._pages(
            lf.list_permissions,
            "PrincipalResourcePermissions",
            max_pages=_MAX_LF_PERMISSIONS // 100 + 1,
            MaxResults=100,
        ):
            out.append(p)
            if len(out) >= _MAX_LF_PERMISSIONS:
                break
        return out

    async def _collect_glue(self) -> list[CloudAsset]:
        async with self._client("glue") as glue:
            security_keys: dict[str, list[str]] = {}
            try:
                async for sc in self._paginate(
                    glue, "get_security_configurations", "SecurityConfigurations"
                ):
                    enc = sc.get("EncryptionConfiguration") or {}
                    keys = [s.get("KmsKeyArn") for s in enc.get("S3Encryption") or []]
                    for block in (
                        "CloudWatchEncryption",
                        "JobBookmarksEncryption",
                        "DataQualityEncryption",
                    ):
                        keys.append((enc.get(block) or {}).get("KmsKeyArn"))
                    security_keys[sc["Name"]] = sorted({k for k in keys if _kms_ref(k)})
            except Exception as exc:
                logger.debug("Glue security configuration listing failed: %s", exc)

            def security_rels(name: Any) -> list[dict[str, Any] | None]:
                return [
                    rel(k, EdgeType.REFERENCES, "ENCRYPTED_BY_KMS", security_configuration=name)
                    for k in security_keys.get(name, [])
                    if isinstance(name, str)
                ]

            return await self._gather_parts(
                "glue",
                {
                    "catalog": lambda: self._glue_databases(glue),
                    "jobs": lambda: self._glue_jobs(glue, security_rels),
                    "crawlers": lambda: self._glue_crawlers(glue, security_rels),
                    "connections": lambda: self._glue_connections(glue),
                    "triggers": lambda: self._glue_triggers(glue),
                },
            )

    async def _glue_databases(self, glue: Any) -> list[CloudAsset]:
        databases = [d async for d in self._paginate(glue, "get_databases", "DatabaseList")]
        catalog_arn = self._arn("glue", "catalog")

        grants: dict[str, dict[str, set[str]]] = {}
        try:
            async with self._client("lakeformation") as lf:
                for p in await self._lf_permissions(lf):
                    res = p.get("Resource") or {}
                    db = (
                        (res.get("Database") or {}).get("Name")
                        or (res.get("Table") or {}).get("DatabaseName")
                        or (res.get("TableWithColumns") or {}).get("DatabaseName")
                    )
                    principal = (p.get("Principal") or {}).get("DataLakePrincipalIdentifier")
                    if not db or not isinstance(principal, str):
                        continue
                    if not (principal.startswith("arn:") or principal.isdigit()):
                        continue
                    grants.setdefault(db, {}).setdefault(principal_ref(principal), set()).update(
                        p.get("Permissions") or []
                    )
        except Exception as exc:
            logger.debug("Lake Formation permission listing failed: %s", exc)

        async def table_count(name: str) -> int | None:
            count = 0
            try:
                async for _ in self._paginate(glue, "get_tables", "TableList", DatabaseName=name):
                    count += 1
                    if count >= _MAX_TABLES_COUNTED:
                        break
            except Exception as exc:
                logger.debug("Glue table listing failed for %s: %s", name, exc)
                return None
            return count

        counts = await gather_limited([lambda n=d["Name"]: table_count(n) for d in databases])
        assets: list[CloudAsset] = []
        for d, tables in zip(databases, counts):
            name = d["Name"]
            target = d.get("TargetDatabase") or {}
            relations: list[dict[str, Any] | None] = [
                rel(catalog_arn, EdgeType.CONTAINS, reverse=True),
                rel(
                    _bucket_arn(d.get("LocationUri")),
                    EdgeType.REFERENCES,
                    "DEPENDS_ON",
                    description="database location",
                ),
            ]
            if target.get("DatabaseName"):
                relations.append(
                    rel(
                        f"arn:aws:glue:{target.get('Region') or self._region}:{target.get('CatalogId') or self._account_id}"
                        f":database/{target['DatabaseName']}",
                        EdgeType.REFERENCES,
                        "DEPENDS_ON",
                        description="resource link",
                    )
                )
            relations += [
                rel(
                    principal,
                    EdgeType.GRANTS_ACCESS,
                    "POLICY_ALLOWS_ACTION",
                    reverse=True,
                    description="Lake Formation grant",
                    permissions=sorted(perms),
                )
                for principal, perms in grants.get(name, {}).items()
            ]
            assets.append(
                self._asset(
                    arn=self._glue_arn("database", name),
                    name=name,
                    asset_type=AssetType.DATA_CATALOG,
                    metadata={
                        "service": "glue",
                        "kind": "database",
                        "location": d.get("LocationUri"),
                        "table_count": tables,
                        "table_count_capped": tables is not None and tables >= _MAX_TABLES_COUNTED,
                        "resource_link": bool(target),
                        "federated": (d.get("FederatedDatabase") or {}).get("ConnectionName"),
                        "iam_allowed_principals_default": any(
                            (p.get("Principal") or {}).get("DataLakePrincipalIdentifier")
                            == "IAM_ALLOWED_PRINCIPALS"
                            for p in d.get("CreateTableDefaultPermissions") or []
                        ),
                    },
                    relations=relations,
                )
            )

        kms: str | None = None
        encryption: dict = {}
        try:
            encryption = (await glue.get_data_catalog_encryption_settings()).get(
                "DataCatalogEncryptionSettings"
            ) or {}
            kms = _kms_ref((encryption.get("EncryptionAtRest") or {}).get("SseAwsKmsKeyId"))
        except Exception as exc:
            logger.debug("Glue catalog encryption lookup failed: %s", exc)
        pw = encryption.get("ConnectionPasswordEncryption") or {}
        pw_kms = _kms_ref(pw.get("AwsKmsKeyId"))
        assets.append(
            self._asset(
                arn=catalog_arn,
                name=f"Glue Data Catalog ({self._region})",
                asset_type=AssetType.DATA_CATALOG,
                metadata={
                    "service": "glue",
                    "kind": "catalog",
                    "database_count": len(databases),
                    "encryption_mode": (encryption.get("EncryptionAtRest") or {}).get(
                        "CatalogEncryptionMode"
                    ),
                    "kms_key_id": kms,
                    "connection_password_encryption": pw.get("ReturnConnectionPasswordEncrypted"),
                },
                relations=[
                    rel(kms, EdgeType.REFERENCES, "ENCRYPTED_BY_KMS"),
                    rel(pw_kms, EdgeType.REFERENCES, "ENCRYPTED_BY_KMS"),
                ],
            )
        )
        return assets

    async def _glue_jobs(self, glue: Any, security_rels: Callable[[Any], list]) -> list[CloudAsset]:
        assets: list[CloudAsset] = []
        async for j in self._paginate(glue, "get_jobs", "Jobs"):
            name = j["Name"]
            command = j.get("Command") or {}
            args = j.get("DefaultArguments") or {}
            relations: list[dict[str, Any] | None] = [
                rel(self._role_ref(j.get("Role")), EdgeType.ASSUMES_ROLE, "RUNS_ON"),
                rel(
                    _bucket_arn(command.get("ScriptLocation")),
                    EdgeType.REFERENCES,
                    "READS_FROM",
                    description="job script",
                ),
            ]
            relations += [
                rel(self._glue_arn("connection", c), EdgeType.REFERENCES, "DEPENDS_ON")
                for c in (j.get("Connections") or {}).get("Connections") or []
            ]
            relations += security_rels(j.get("SecurityConfiguration"))
            for key in _GLUE_ARG_READS:
                for part in str(args.get(key, "")).split(","):
                    relations.append(
                        rel(
                            _bucket_arn(part.strip()),
                            EdgeType.REFERENCES,
                            "READS_FROM",
                            argument=key,
                        )
                    )
            for key in _GLUE_ARG_WRITES:
                relations.append(
                    rel(_bucket_arn(args.get(key)), EdgeType.REFERENCES, "WRITES_TO", argument=key)
                )
            for key in _GLUE_ARG_LOGS:
                relations.append(
                    rel(_bucket_arn(args.get(key)), EdgeType.LOGS_TO, "LOGS_TO", argument=key)
                )
            relations += [
                rel(r, EdgeType.REFERENCES, "DEPENDS_ON", description="job argument")
                for r in identifier_refs(args)
            ]
            source = j.get("SourceControlDetails") or {}
            assets.append(
                self._asset(
                    arn=self._glue_arn("job", name),
                    name=name,
                    asset_type=AssetType.ETL_JOB,
                    metadata={
                        "service": "glue",
                        "kind": "job",
                        "command": command.get("Name"),
                        "script_location": command.get("ScriptLocation"),
                        "glue_version": j.get("GlueVersion"),
                        "worker_type": j.get("WorkerType"),
                        "workers": j.get("NumberOfWorkers"),
                        "security_configuration": j.get("SecurityConfiguration"),
                        "connections": (j.get("Connections") or {}).get("Connections") or [],
                        "source_control": {
                            "provider": source.get("Provider"),
                            "repository": source.get("Repository"),
                        }
                        if source
                        else None,
                    },
                    relations=relations,
                )
            )
        return assets

    async def _glue_crawlers(
        self, glue: Any, security_rels: Callable[[Any], list]
    ) -> list[CloudAsset]:
        assets: list[CloudAsset] = []
        async for c in self._paginate(glue, "get_crawlers", "Crawlers"):
            name = c["Name"]
            targets = c.get("Targets") or {}
            relations: list[dict[str, Any] | None] = [
                rel(self._role_ref(c.get("Role")), EdgeType.ASSUMES_ROLE, "RUNS_ON"),
                rel(
                    self._glue_arn("database", c["DatabaseName"])
                    if c.get("DatabaseName")
                    else None,
                    EdgeType.REFERENCES,
                    "WRITES_TO",
                    description="crawler output database",
                ),
            ]
            relations += security_rels(c.get("CrawlerSecurityConfiguration"))
            connections: set[str] = set()
            for t in targets.get("S3Targets") or []:
                relations.append(
                    rel(
                        _bucket_arn(t.get("Path")),
                        EdgeType.REFERENCES,
                        "READS_FROM",
                        source_type="s3",
                    )
                )
                relations.append(
                    rel(
                        t.get("EventQueueArn"),
                        EdgeType.REFERENCES,
                        "READS_FROM",
                        source_type="events",
                    )
                )
                connections.add(t.get("ConnectionName") or "")
            for key in ("JdbcTargets", "MongoDBTargets"):
                for t in targets.get(key) or []:
                    connections.add(t.get("ConnectionName") or "")
            for t in targets.get("DynamoDBTargets") or []:
                if t.get("Path"):
                    table = (
                        t["Path"]
                        if t["Path"].startswith("arn:")
                        else self._arn("dynamodb", f"table/{t['Path']}")
                    )
                    relations.append(
                        rel(table, EdgeType.REFERENCES, "READS_FROM", source_type="dynamodb")
                    )
            for t in targets.get("CatalogTargets") or []:
                if t.get("DatabaseName"):
                    relations.append(
                        rel(
                            self._glue_arn("database", t["DatabaseName"]),
                            EdgeType.REFERENCES,
                            "READS_FROM",
                            source_type="catalog",
                        )
                    )
                relations.append(
                    rel(
                        t.get("EventQueueArn"),
                        EdgeType.REFERENCES,
                        "READS_FROM",
                        source_type="events",
                    )
                )
                connections.add(t.get("ConnectionName") or "")
            for key, field in (
                ("DeltaTargets", "DeltaTables"),
                ("IcebergTargets", "Paths"),
                ("HudiTargets", "Paths"),
            ):
                for t in targets.get(key) or []:
                    relations += [
                        rel(_bucket_arn(p), EdgeType.REFERENCES, "READS_FROM", source_type=key)
                        for p in t.get(field) or []
                    ]
                    connections.add(t.get("ConnectionName") or "")
            relations += [
                rel(
                    self._glue_arn("connection", n),
                    EdgeType.REFERENCES,
                    "READS_FROM",
                    source_type="connection",
                )
                for n in sorted(connections)
                if n
            ]
            assets.append(
                self._asset(
                    arn=self._glue_arn("crawler", name),
                    name=name,
                    asset_type=AssetType.ETL_JOB,
                    metadata={
                        "service": "glue",
                        "kind": "crawler",
                        "state": c.get("State"),
                        "database": c.get("DatabaseName"),
                        "schedule": (c.get("Schedule") or {}).get("ScheduleExpression"),
                        "target_types": sorted(k for k, v in targets.items() if v),
                        "security_configuration": c.get("CrawlerSecurityConfiguration"),
                        "lake_formation_credentials": (
                            c.get("LakeFormationConfiguration") or {}
                        ).get("UseLakeFormationCredentials"),
                    },
                    relations=relations,
                )
            )
        return assets

    async def _glue_connections(self, glue: Any) -> list[CloudAsset]:
        assets: list[CloudAsset] = []
        async for c in self._paginate(glue, "get_connections", "ConnectionList", HidePassword=True):
            name = c["Name"]
            props = c.get("ConnectionProperties") or {}
            physical = c.get("PhysicalConnectionRequirements") or {}
            auth = c.get("AuthenticationConfiguration") or {}
            hosts: list[str] = []
            for key in ("JDBC_CONNECTION_URL", "CONNECTION_URL", "HOST"):
                host = _host(props.get(key))
                if host:
                    hosts.append(host)
            for broker in str(props.get("KAFKA_BOOTSTRAP_SERVERS", "")).split(","):
                host = _host(broker.strip())
                if host:
                    hosts.append(host)
            relations: list[dict[str, Any] | None] = self._subnet_rels(physical.get("SubnetId"))
            relations += [
                rel(
                    auth.get("SecretArn"),
                    EdgeType.REFERENCES,
                    "READS_FROM",
                    description="connection credentials",
                ),
                rel(
                    props.get("SECRET_ID"),
                    EdgeType.REFERENCES,
                    "READS_FROM",
                    description="connection credentials",
                ),
                rel(_kms_ref(auth.get("KmsKeyArn")), EdgeType.REFERENCES, "ENCRYPTED_BY_KMS"),
            ]
            relations += [
                rel(h, EdgeType.REFERENCES, "READS_FROM", description="connection endpoint")
                for h in sorted(set(hosts))
            ]
            assets.append(
                self._asset(
                    arn=self._glue_arn("connection", name),
                    name=name,
                    asset_type=AssetType.DATA_CATALOG,
                    metadata={
                        "service": "glue",
                        "kind": "connection",
                        "connection_type": c.get("ConnectionType"),
                        "hosts": sorted(set(hosts)),
                        "security_groups": physical.get("SecurityGroupIdList") or [],
                        "availability_zone": physical.get("AvailabilityZone"),
                        "authentication_type": auth.get("AuthenticationType"),
                        "enforce_ssl": props.get("JDBC_ENFORCE_SSL"),
                        "status": c.get("Status"),
                    },
                    relations=relations,
                )
            )
        return assets

    async def _glue_triggers(self, glue: Any) -> list[CloudAsset]:
        assets: list[CloudAsset] = []
        async for t in self._paginate(glue, "get_triggers", "Triggers"):
            name = t["Name"]
            relations: list[dict[str, Any] | None] = []
            for action in t.get("Actions") or []:
                if action.get("JobName"):
                    relations.append(
                        rel(self._glue_arn("job", action["JobName"]), EdgeType.INVOKES, "INVOKES")
                    )
                if action.get("CrawlerName"):
                    relations.append(
                        rel(
                            self._glue_arn("crawler", action["CrawlerName"]),
                            EdgeType.INVOKES,
                            "INVOKES",
                        )
                    )
            for cond in (t.get("Predicate") or {}).get("Conditions") or []:
                if cond.get("JobName"):
                    relations.append(
                        rel(
                            self._glue_arn("job", cond["JobName"]),
                            EdgeType.INVOKES,
                            "TRIGGERED_BY",
                            reverse=True,
                            state=cond.get("State"),
                        )
                    )
                if cond.get("CrawlerName"):
                    relations.append(
                        rel(
                            self._glue_arn("crawler", cond["CrawlerName"]),
                            EdgeType.INVOKES,
                            "TRIGGERED_BY",
                            reverse=True,
                            state=cond.get("CrawlState"),
                        )
                    )
            assets.append(
                self._asset(
                    arn=self._glue_arn("trigger", name),
                    name=name,
                    asset_type=AssetType.EVENT_RULE,
                    metadata={
                        "service": "glue",
                        "kind": "trigger",
                        "trigger_type": t.get("Type"),
                        "state": t.get("State"),
                        "schedule": t.get("Schedule"),
                        "workflow": t.get("WorkflowName"),
                    },
                    relations=relations,
                )
            )
        return assets

    async def _collect_lakeformation(self) -> list[CloudAsset]:
        async with self._client("lakeformation") as lf:
            settings = (await lf.get_data_lake_settings()).get("DataLakeSettings") or {}
            resources: list[dict] = []
            try:
                resources = [r async for r in self._pages(lf.list_resources, "ResourceInfoList")]
            except Exception as exc:
                logger.debug("Lake Formation resource listing failed: %s", exc)
            permissions: list[dict] = []
            try:
                permissions = await self._lf_permissions(lf)
            except Exception as exc:
                logger.debug("Lake Formation permission listing failed: %s", exc)

        relations: list[dict[str, Any] | None] = [
            rel(self._arn("glue", "catalog"), EdgeType.GOVERNS, "COMPLIANCE_GOVERNS"),
        ]

        def principals(entries: Any) -> list[str]:
            ids = [(e or {}).get("DataLakePrincipalIdentifier") for e in as_list(entries)]
            return [
                principal_ref(i)
                for i in ids
                if isinstance(i, str) and (i.startswith("arn:") or i.isdigit())
            ]

        admins = principals(settings.get("DataLakeAdmins"))
        readonly = principals(settings.get("ReadOnlyAdmins"))
        relations += [
            rel(
                p,
                EdgeType.GRANTS_ACCESS,
                "POLICY_ALLOWS_ACTION",
                reverse=True,
                description="data lake administrator",
            )
            for p in admins
        ]
        relations += [
            rel(
                p,
                EdgeType.GRANTS_ACCESS,
                "POLICY_ALLOWS_ACTION",
                reverse=True,
                description="read-only data lake administrator",
            )
            for p in readonly
        ]
        locations = []
        for r in resources:
            arn = r.get("ResourceArn")
            locations.append(arn)
            relations.append(
                rel(
                    _bucket_arn(arn) or arn,
                    EdgeType.GOVERNS,
                    "COMPLIANCE_GOVERNS",
                    description="registered data location",
                )
            )
            relations.append(
                rel(
                    r.get("RoleArn"),
                    EdgeType.ASSUMES_ROLE,
                    "RUNS_ON",
                    description="location registration role",
                )
            )
        grants: dict[str, set[str]] = {}
        location_grants: list[dict[str, Any]] = []
        for p in permissions:
            res = p.get("Resource") or {}
            if not (res.get("Catalog") is not None or res.get("DataLocation")):
                continue
            principal = (p.get("Principal") or {}).get("DataLakePrincipalIdentifier")
            if not isinstance(principal, str) or not (
                principal.startswith("arn:") or principal.isdigit()
            ):
                continue
            grants.setdefault(principal_ref(principal), set()).update(p.get("Permissions") or [])
            if res.get("DataLocation"):
                location_grants.append(
                    {
                        "principal": principal,
                        "location": res["DataLocation"].get("ResourceArn"),
                        "permissions": p.get("Permissions") or [],
                    }
                )
        relations += [
            rel(
                pr,
                EdgeType.GRANTS_ACCESS,
                "POLICY_ALLOWS_ACTION",
                reverse=True,
                description="Lake Formation catalog / location grant",
                permissions=sorted(perms),
            )
            for pr, perms in grants.items()
        ]
        defaults = (settings.get("CreateDatabaseDefaultPermissions") or []) + (
            settings.get("CreateTableDefaultPermissions") or []
        )
        return [
            self._asset(
                arn=f"cloudg:aws:lakeformation:{self._region}:{self._account_id}:data-lake",
                name=f"Lake Formation data lake ({self._region})",
                asset_type=AssetType.DATA_CATALOG,
                metadata={
                    "service": "lakeformation",
                    "kind": "data_lake_settings",
                    "admins": admins,
                    "read_only_admins": readonly,
                    "registered_locations": locations,
                    "iam_allowed_principals_default": any(
                        (d.get("Principal") or {}).get("DataLakePrincipalIdentifier")
                        == "IAM_ALLOWED_PRINCIPALS"
                        for d in defaults
                    ),
                    "trusted_resource_owners": settings.get("TrustedResourceOwners") or [],
                    "external_data_filtering": settings.get("AllowExternalDataFiltering"),
                    "permission_count": len(permissions),
                    "permissions_capped": len(permissions) >= _MAX_LF_PERMISSIONS,
                    "data_location_grants": location_grants[:100],
                },
                relations=relations,
            )
        ]

    # ------------------------------------------------------------------
    # EMR / EMR Serverless / Athena
    # ------------------------------------------------------------------

    async def _collect_emr(self) -> list[CloudAsset]:
        async with self._client("emr") as emr:
            clusters = [
                c
                async for c in self._paginate(
                    emr, "list_clusters", "Clusters", ClusterStates=_EMR_ACTIVE_STATES
                )
            ]

            async def detail(summary: dict) -> CloudAsset:
                c = (await emr.describe_cluster(ClusterId=summary["Id"])).get("Cluster") or {}
                ec2 = c.get("Ec2InstanceAttributes") or {}
                subnets = ec2.get("RequestedEc2SubnetIds") or (
                    [ec2["Ec2SubnetId"]] if ec2.get("Ec2SubnetId") else []
                )
                sgs = [
                    ec2.get("EmrManagedMasterSecurityGroup"),
                    ec2.get("EmrManagedSlaveSecurityGroup"),
                    ec2.get("ServiceAccessSecurityGroup"),
                    *(ec2.get("AdditionalMasterSecurityGroups") or []),
                    *(ec2.get("AdditionalSlaveSecurityGroups") or []),
                ]
                kms = _kms_ref(c.get("LogEncryptionKmsKeyId"))
                relations: list[dict[str, Any] | None] = self._subnet_rels(subnets)
                relations += [
                    rel(
                        self._role_ref(c.get("ServiceRole")),
                        EdgeType.ASSUMES_ROLE,
                        "RUNS_ON",
                        description="service role",
                    ),
                    rel(
                        self._role_ref(c.get("AutoScalingRole")),
                        EdgeType.ASSUMES_ROLE,
                        "RUNS_ON",
                        description="auto scaling role",
                    ),
                    rel(
                        self._profile_ref(ec2.get("IamInstanceProfile")),
                        EdgeType.ASSUMES_ROLE,
                        "RUNS_ON",
                        description="EC2 instance profile",
                    ),
                    rel(_bucket_arn(c.get("LogUri")), EdgeType.LOGS_TO, "LOGS_TO"),
                    rel(kms, EdgeType.REFERENCES, "ENCRYPTED_BY_KMS"),
                    rel(c.get("OutpostArn"), EdgeType.REFERENCES, "RUNS_ON"),
                ]
                master_dns = c.get("MasterPublicDnsName") or ""
                public = master_dns.startswith("ec2-")
                return self._asset(
                    arn=c.get("ClusterArn")
                    or summary.get("ClusterArn")
                    or self._arn("elasticmapreduce", f"cluster/{summary['Id']}"),
                    name=c.get("Name") or summary.get("Name") or summary["Id"],
                    asset_type=AssetType.BIG_DATA_CLUSTER,
                    tags=c.get("Tags"),
                    metadata={
                        "service": "emr",
                        "cluster_id": summary["Id"],
                        "state": (c.get("Status") or {}).get("State"),
                        "release_label": c.get("ReleaseLabel"),
                        "applications": [a.get("Name") for a in c.get("Applications") or []],
                        "security_groups": sorted({g for g in sgs if g}),
                        "security_configuration": c.get("SecurityConfiguration"),
                        "log_uri": c.get("LogUri"),
                        "kms_key_id": kms,
                        "master_public_dns": master_dns or None,
                        "key_name": ec2.get("Ec2KeyName"),
                        "kerberos": bool(c.get("KerberosAttributes")),
                        "termination_protected": c.get("TerminationProtected"),
                    },
                    relations=relations,
                    exposed=public,
                    aliases=[summary["Id"], master_dns or None],
                )

            results = await gather_limited([lambda c=c: detail(c) for c in clusters])
        return [a for a in results if a]

    async def _collect_emr_serverless(self) -> list[CloudAsset]:
        async with self._client("emr-serverless") as emrs:
            apps = [a async for a in self._paginate(emrs, "list_applications", "applications")]

            async def detail(summary: dict) -> CloudAsset:
                a = (await emrs.get_application(applicationId=summary["id"])).get(
                    "application"
                ) or {}
                net = a.get("networkConfiguration") or {}
                mon = a.get("monitoringConfiguration") or {}
                s3mon = mon.get("s3MonitoringConfiguration") or {}
                cw = mon.get("cloudWatchLoggingConfiguration") or {}
                relations: list[dict[str, Any] | None] = self._subnet_rels(net.get("subnetIds"))
                image = (a.get("imageConfiguration") or {}).get("imageUri")
                relations += [
                    rel(image, EdgeType.USES_IMAGE, "RUNS_ON"),
                    rel(_bucket_arn(s3mon.get("logUri")), EdgeType.LOGS_TO, "LOGS_TO"),
                    rel(
                        self._log_group_ref(cw.get("logGroupName")) if cw.get("enabled") else None,
                        EdgeType.LOGS_TO,
                        "LOGS_TO",
                    ),
                ]
                for key in {
                    _kms_ref(s3mon.get("encryptionKeyArn")),
                    _kms_ref(cw.get("encryptionKeyArn")),
                }:
                    relations.append(rel(key, EdgeType.REFERENCES, "ENCRYPTED_BY_KMS"))
                for spec in (a.get("workerTypeSpecifications") or {}).values():
                    relations.append(
                        rel(
                            (spec.get("imageConfiguration") or {}).get("imageUri"),
                            EdgeType.USES_IMAGE,
                            "RUNS_ON",
                        )
                    )
                return self._asset(
                    arn=a.get("arn") or summary.get("arn", ""),
                    name=a.get("name") or summary.get("name") or summary["id"],
                    asset_type=AssetType.BIG_DATA_CLUSTER,
                    tags=a.get("tags"),
                    metadata={
                        "service": "emr-serverless",
                        "application_id": summary["id"],
                        "type": a.get("type") or summary.get("type"),
                        "state": a.get("state") or summary.get("state"),
                        "release_label": a.get("releaseLabel"),
                        "security_groups": net.get("securityGroupIds") or [],
                        "in_vpc": bool(net.get("subnetIds")),
                        "image": image,
                    },
                    relations=relations,
                    aliases=[summary["id"]],
                )

            results = await gather_limited([lambda x=x: detail(x) for x in apps])
        return [a for a in results if a]

    async def _collect_athena(self) -> list[CloudAsset]:
        async with self._client("athena") as athena:
            groups = [g async for g in self._pages(athena.list_work_groups, "WorkGroups")]

            async def detail(summary: dict) -> CloudAsset:
                name = summary["Name"]
                wg = (await athena.get_work_group(WorkGroup=name)).get("WorkGroup") or {}
                cfg = wg.get("Configuration") or {}
                result = cfg.get("ResultConfiguration") or {}
                enc = result.get("EncryptionConfiguration") or {}
                managed = cfg.get("ManagedQueryResultsConfiguration") or {}
                keys = {
                    _kms_ref(enc.get("KmsKey")),
                    _kms_ref(((managed.get("EncryptionConfiguration") or {}).get("KmsKey"))),
                    _kms_ref(
                        (cfg.get("CustomerContentEncryptionConfiguration") or {}).get("KmsKey")
                    ),
                }
                relations: list[dict[str, Any] | None] = [
                    rel(
                        _bucket_arn(result.get("OutputLocation")),
                        EdgeType.REFERENCES,
                        "WRITES_TO",
                        description="query results",
                    ),
                    rel(cfg.get("ExecutionRole"), EdgeType.ASSUMES_ROLE, "RUNS_ON"),
                ]
                relations += [
                    rel(k, EdgeType.REFERENCES, "ENCRYPTED_BY_KMS")
                    for k in sorted(k for k in keys if k)
                ]
                return self._asset(
                    arn=self._arn("athena", f"workgroup/{name}"),
                    name=name,
                    asset_type=AssetType.QUERY_WORKGROUP,
                    metadata={
                        "service": "athena",
                        "state": wg.get("State") or summary.get("State"),
                        "output_location": result.get("OutputLocation"),
                        "encryption": enc.get("EncryptionOption"),
                        "kms_key_id": _kms_ref(enc.get("KmsKey")),
                        "enforce_workgroup_configuration": cfg.get("EnforceWorkGroupConfiguration"),
                        "managed_query_results": managed.get("Enabled"),
                        "bytes_scanned_cutoff": cfg.get("BytesScannedCutoffPerQuery"),
                        "engine_version": (cfg.get("EngineVersion") or {}).get(
                            "EffectiveEngineVersion"
                        ),
                        "identity_center": (cfg.get("IdentityCenterConfiguration") or {}).get(
                            "EnableIdentityCenter"
                        ),
                    },
                    relations=relations,
                )

            results = await gather_limited([lambda g=g: detail(g) for g in groups])
        return [a for a in results if a]

    # ------------------------------------------------------------------
    # Transfer Family / DataSync / FSx
    # ------------------------------------------------------------------

    def _home_rels(self, domain: Any, path: Any, description: str) -> list[dict[str, Any] | None]:
        """READS_FROM the bucket / EFS file system behind a Transfer home path."""
        if not isinstance(path, str) or not path.strip("/"):
            return []
        head = path.strip("/").split("/", 1)[0]
        if domain == "EFS" or head.startswith("fs-"):
            return [rel(head, EdgeType.REFERENCES, "READS_FROM", description=description)]
        return [
            rel(f"arn:aws:s3:::{head}", EdgeType.REFERENCES, "READS_FROM", description=description)
        ]

    async def _collect_transfer_family(self) -> list[CloudAsset]:
        async with self._client("transfer") as transfer:
            servers = [s async for s in self._paginate(transfer, "list_servers", "Servers")]

            async def users(server_id: str, domain: Any, server_arn: str) -> list[CloudAsset]:
                out: list[CloudAsset] = []
                try:
                    names = []
                    async for u in self._paginate(
                        transfer, "list_users", "Users", ServerId=server_id
                    ):
                        names.append(u)
                        if len(names) >= _MAX_TRANSFER_USERS:
                            break
                except Exception as exc:
                    logger.debug("Transfer user listing failed for %s: %s", server_id, exc)
                    return out

                async def user_detail(summary: dict) -> CloudAsset:
                    u = summary
                    try:
                        u = (
                            await transfer.describe_user(
                                ServerId=server_id, UserName=summary["UserName"]
                            )
                        ).get("User") or summary
                    except Exception as exc:
                        logger.debug("Transfer user lookup failed: %s", exc)
                    relations: list[dict[str, Any] | None] = [
                        rel(server_arn, EdgeType.CONTAINS, reverse=True),
                        rel(u.get("Role"), EdgeType.ASSUMES_ROLE, "RUNS_ON"),
                    ]
                    relations += self._home_rels(domain, u.get("HomeDirectory"), "home directory")
                    for m in u.get("HomeDirectoryMappings") or []:
                        relations += self._home_rels(
                            domain, m.get("Target"), "home directory mapping"
                        )
                    return self._asset(
                        arn=u.get("Arn")
                        or summary.get("Arn")
                        or self._arn("transfer", f"user/{server_id}/{summary['UserName']}"),
                        name=f"{server_id}/{summary['UserName']}",
                        asset_type=AssetType.IDENTITY_USER,
                        tags=u.get("Tags"),
                        metadata={
                            "service": "transfer",
                            "server_id": server_id,
                            "user_name": summary["UserName"],
                            "home_directory": u.get("HomeDirectory"),
                            "home_directory_type": u.get("HomeDirectoryType"),
                            "ssh_key_count": len(u.get("SshPublicKeys") or [])
                            or summary.get("SshPublicKeyCount"),
                            "has_session_policy": bool(u.get("Policy")),
                        },
                        relations=relations,
                    )

                results = await gather_limited([lambda x=x: user_detail(x) for x in names])
                return [a for a in results if a]

            async def detail(summary: dict) -> list[CloudAsset]:
                server_id = summary["ServerId"]
                s = (await transfer.describe_server(ServerId=server_id)).get("Server") or summary
                ep = s.get("EndpointDetails") or {}
                idp = s.get("IdentityProviderDetails") or {}
                endpoint_type = s.get("EndpointType")
                exposed = endpoint_type == "PUBLIC" or (
                    endpoint_type == "VPC" and bool(ep.get("AddressAllocationIds"))
                )
                relations: list[dict[str, Any] | None] = self._subnet_rels(ep.get("SubnetIds"))
                relations += [
                    rel(ep.get("VpcEndpointId"), EdgeType.ATTACHED_TO),
                    rel(
                        s.get("LoggingRole"),
                        EdgeType.ASSUMES_ROLE,
                        "RUNS_ON",
                        description="logging role",
                    ),
                    rel(
                        idp.get("Function"),
                        EdgeType.INVOKES,
                        "INVOKES",
                        description="custom identity provider",
                    ),
                    rel(
                        idp.get("InvocationRole"),
                        EdgeType.ASSUMES_ROLE,
                        "RUNS_ON",
                        description="identity provider invocation role",
                    ),
                    rel(
                        s.get("Certificate"),
                        EdgeType.REFERENCES,
                        "CERTIFICATE_SECURES",
                        reverse=True,
                    ),
                ]
                relations += [
                    rel(a, EdgeType.ATTACHED_TO, reverse=True)
                    for a in ep.get("AddressAllocationIds") or []
                ]
                api_host = _host(idp.get("Url"))
                if api_host and ".execute-api." in api_host:
                    relations.append(
                        rel(
                            api_host.split(".", 1)[0],
                            EdgeType.INVOKES,
                            "INVOKES",
                            description="API Gateway identity provider",
                        )
                    )
                relations += [
                    rel(self._log_group_ref(d), EdgeType.LOGS_TO, "LOGS_TO")
                    for d in s.get("StructuredLogDestinations") or []
                ]
                workflows = s.get("WorkflowDetails") or {}
                wf_ids: list[str] = []
                for key in ("OnUpload", "OnPartialUpload"):
                    for wf in workflows.get(key) or []:
                        wf_ids.append(wf.get("WorkflowId"))
                        relations.append(
                            rel(
                                wf.get("ExecutionRole"),
                                EdgeType.ASSUMES_ROLE,
                                "RUNS_ON",
                                description=f"{key} workflow role",
                            )
                        )
                arn = (
                    s.get("Arn")
                    or summary.get("Arn")
                    or self._arn("transfer", f"server/{server_id}")
                )
                tags = s.get("Tags")
                server = self._asset(
                    arn=arn,
                    name=next((t.get("Value") for t in tags or [] if t.get("Key") == "Name"), None)
                    or server_id,
                    asset_type=AssetType.DATA_TRANSFER,
                    tags=tags,
                    metadata={
                        "service": "transfer",
                        "kind": "server",
                        "server_id": server_id,
                        "endpoint_type": endpoint_type,
                        "identity_provider_type": s.get("IdentityProviderType"),
                        "directory_id": idp.get("DirectoryId"),
                        "domain": s.get("Domain"),
                        "protocols": s.get("Protocols") or [],
                        "state": s.get("State"),
                        "security_policy": s.get("SecurityPolicyName"),
                        "vpc_id": ep.get("VpcId"),
                        "security_groups": ep.get("SecurityGroupIds") or [],
                        "workflows": [w for w in wf_ids if w],
                        "user_count": s.get("UserCount"),
                    },
                    relations=relations,
                    exposed=exposed,
                    aliases=[
                        server_id,
                        f"{server_id}.server.transfer.{self._region}.amazonaws.com",
                    ],
                )
                return [server, *await users(server_id, s.get("Domain"), arn)]

            results = await gather_limited([lambda x=x: detail(x) for x in servers])
        return [a for r in results if r for a in r]

    def _location_target(self, uri: Any) -> str | None:
        """Underlying resource of a DataSync location URI (S3 bucket / EFS / FSx)."""
        bucket = _bucket_arn(uri)
        if bucket:
            return bucket
        if isinstance(uri, str) and uri.split("://", 1)[0] in (
            "efs",
            "fsxw",
            "fsxl",
            "fsxz",
            "fsxn",
        ):
            m = _FS_ID_RE.search(uri)
            return m.group(1) if m else None
        return None

    async def _collect_datasync(self) -> list[CloudAsset]:
        async with self._client("datasync") as ds:
            locations = [loc async for loc in self._paginate(ds, "list_locations", "Locations")]
            tasks = [t async for t in self._paginate(ds, "list_tasks", "Tasks")]

            async def location_detail(loc: dict) -> CloudAsset:
                arn = loc["LocationArn"]
                uri = loc.get("LocationUri") or ""
                scheme = uri.split("://", 1)[0] if "://" in uri else None
                relations: list[dict[str, Any] | None] = [
                    rel(
                        self._location_target(uri),
                        EdgeType.REFERENCES,
                        "DEPENDS_ON",
                        description="location storage",
                    ),
                ]
                if scheme == "s3":
                    try:
                        s3 = await ds.describe_location_s3(LocationArn=arn)
                        relations.append(
                            rel(
                                (s3.get("S3Config") or {}).get("BucketAccessRoleArn"),
                                EdgeType.ASSUMES_ROLE,
                                "RUNS_ON",
                                description="bucket access role",
                            )
                        )
                    except Exception as exc:
                        logger.debug("DataSync S3 location lookup failed: %s", exc)
                host = (
                    None
                    if scheme in ("s3", "efs") or (scheme or "").startswith("fsx")
                    else _host(uri)
                )
                return self._asset(
                    arn=arn,
                    name=uri or arn,
                    asset_type=AssetType.DATA_TRANSFER,
                    metadata={
                        "service": "datasync",
                        "kind": "location",
                        "location_uri": uri,
                        "location_type": scheme,
                        "host": host,
                    },
                    relations=relations,
                )

            uris = {loc["LocationArn"]: loc.get("LocationUri") for loc in locations}

            async def task_detail(summary: dict) -> CloudAsset:
                t = await ds.describe_task(TaskArn=summary["TaskArn"])
                src, dst = t.get("SourceLocationArn"), t.get("DestinationLocationArn")
                relations: list[dict[str, Any] | None] = [
                    rel(src, EdgeType.REFERENCES, "READS_FROM", description="source location"),
                    rel(dst, EdgeType.REFERENCES, "WRITES_TO", description="destination location"),
                    rel(
                        self._location_target(uris.get(src)),
                        EdgeType.REFERENCES,
                        "READS_FROM",
                        description="source storage",
                    ),
                    rel(
                        self._location_target(uris.get(dst)),
                        EdgeType.REFERENCES,
                        "WRITES_TO",
                        description="destination storage",
                    ),
                    rel(
                        self._log_group_ref(t.get("CloudWatchLogGroupArn")),
                        EdgeType.LOGS_TO,
                        "LOGS_TO",
                    ),
                ]
                report = ((t.get("TaskReportConfig") or {}).get("Destination") or {}).get(
                    "S3"
                ) or {}
                relations.append(
                    rel(
                        report.get("S3BucketArn"),
                        EdgeType.REFERENCES,
                        "WRITES_TO",
                        description="task report",
                    )
                )
                relations.append(
                    rel(report.get("BucketAccessRoleArn"), EdgeType.ASSUMES_ROLE, "RUNS_ON")
                )
                return self._asset(
                    arn=summary["TaskArn"],
                    name=t.get("Name")
                    or summary.get("Name")
                    or summary["TaskArn"].rsplit("/", 1)[-1],
                    asset_type=AssetType.DATA_TRANSFER,
                    metadata={
                        "service": "datasync",
                        "kind": "task",
                        "status": t.get("Status"),
                        "task_mode": t.get("TaskMode"),
                        "source": uris.get(src) or src,
                        "destination": uris.get(dst) or dst,
                        "schedule": (t.get("Schedule") or {}).get("ScheduleExpression"),
                        "verify_mode": (t.get("Options") or {}).get("VerifyMode"),
                    },
                    relations=relations,
                )

            loc_assets = await gather_limited([lambda x=x: location_detail(x) for x in locations])
            task_assets = await gather_limited([lambda x=x: task_detail(x) for x in tasks])
        return [a for a in loc_assets + task_assets if a]

    async def _collect_fsx(self) -> list[CloudAsset]:
        async with self._client("fsx") as fsx:
            systems = [f async for f in self._paginate(fsx, "describe_file_systems", "FileSystems")]
        eni_sgs: dict[str, list[str]] = {}
        enis = sorted({e for f in systems for e in f.get("NetworkInterfaceIds") or []})
        if enis:
            try:
                async with self._client("ec2") as ec2:
                    for i in range(0, len(enis), 200):
                        async for eni in self._paginate(
                            ec2,
                            "describe_network_interfaces",
                            "NetworkInterfaces",
                            NetworkInterfaceIds=enis[i : i + 200],
                        ):
                            eni_sgs[eni["NetworkInterfaceId"]] = [
                                g["GroupId"] for g in eni.get("Groups") or []
                            ]
            except Exception as exc:
                logger.debug("FSx ENI security group lookup failed: %s", exc)

        assets: list[CloudAsset] = []
        for f in systems:
            fs_id = f["FileSystemId"]
            kms = _kms_ref(f.get("KmsKeyId"))
            windows = f.get("WindowsConfiguration") or {}
            lustre = f.get("LustreConfiguration") or {}
            ontap = f.get("OntapConfiguration") or {}
            repo = lustre.get("DataRepositoryConfiguration") or {}
            relations: list[dict[str, Any] | None] = self._subnet_rels(f.get("SubnetIds"))
            relations += [
                rel(kms, EdgeType.REFERENCES, "ENCRYPTED_BY_KMS"),
                rel(
                    _bucket_arn(repo.get("ImportPath")),
                    EdgeType.REFERENCES,
                    "READS_FROM",
                    description="import path",
                ),
                rel(
                    _bucket_arn(repo.get("ExportPath")),
                    EdgeType.REFERENCES,
                    "WRITES_TO",
                    description="export path",
                ),
                rel(
                    (windows.get("AuditLogConfiguration") or {}).get("AuditLogDestination"),
                    EdgeType.LOGS_TO,
                    "LOGS_TO",
                ),
                rel(
                    (lustre.get("LogConfiguration") or {}).get("Destination"),
                    EdgeType.LOGS_TO,
                    "LOGS_TO",
                ),
            ]
            relations += [
                rel(e, EdgeType.ATTACHED_TO, reverse=True)
                for e in f.get("NetworkInterfaceIds") or []
            ]
            sgs = sorted(
                {g for e in f.get("NetworkInterfaceIds") or [] for g in eni_sgs.get(e, [])}
            )
            self_managed = windows.get("SelfManagedActiveDirectoryConfiguration") or {}
            aliases = [
                fs_id,
                f.get("DNSName"),
                *[a.get("Name") for a in windows.get("Aliases") or []],
            ]
            assets.append(
                self._asset(
                    arn=f.get("ResourceARN") or self._arn("fsx", f"file-system/{fs_id}"),
                    name=next(
                        (t.get("Value") for t in f.get("Tags") or [] if t.get("Key") == "Name"),
                        None,
                    )
                    or fs_id,
                    asset_type=AssetType.FILE_SYSTEM,
                    tags=f.get("Tags"),
                    metadata={
                        "service": "fsx",
                        "file_system_id": fs_id,
                        "file_system_type": f.get("FileSystemType"),
                        "lifecycle": f.get("Lifecycle"),
                        "storage_capacity_gb": f.get("StorageCapacity"),
                        "vpc_id": f.get("VpcId"),
                        "dns_name": f.get("DNSName"),
                        "kms_key_id": kms,
                        "security_groups": sgs,
                        "active_directory_id": windows.get("ActiveDirectoryId"),
                        "self_managed_ad_domain": self_managed.get("DomainName"),
                        "deployment_type": windows.get("DeploymentType")
                        or lustre.get("DeploymentType")
                        or ontap.get("DeploymentType"),
                    },
                    relations=relations,
                    aliases=aliases,
                )
            )
        return assets

    # ------------------------------------------------------------------
    # RDS extras, MemoryDB, DAX
    # ------------------------------------------------------------------

    async def _collect_rds_proxies(self) -> list[CloudAsset]:
        async with self._client("rds") as rds:
            proxies = [p async for p in self._paginate(rds, "describe_db_proxies", "DBProxies")]

            async def detail(p: dict) -> CloudAsset:
                name = p["DBProxyName"]
                relations: list[dict[str, Any] | None] = self._subnet_rels(p.get("VpcSubnetIds"))
                relations.append(rel(p.get("RoleArn"), EdgeType.ASSUMES_ROLE, "RUNS_ON"))
                relations += [
                    rel(
                        a.get("SecretArn"),
                        EdgeType.REFERENCES,
                        "READS_FROM",
                        description="proxy authentication secret",
                    )
                    for a in p.get("Auth") or []
                ]
                targets: list[dict] = []
                try:
                    targets = [
                        t
                        async for t in self._paginate(
                            rds, "describe_db_proxy_targets", "Targets", DBProxyName=name
                        )
                    ]
                except Exception as exc:
                    logger.debug("Proxy target lookup failed for %s: %s", name, exc)
                for t in targets:
                    ref = t.get("TargetArn")
                    if not ref and t.get("Type") == "TRACKED_CLUSTER" and t.get("TrackedClusterId"):
                        ref = self._arn("rds", f"cluster:{t['TrackedClusterId']}")
                    elif not ref and t.get("RdsResourceId"):
                        ref = self._arn("rds", f"db:{t['RdsResourceId']}")
                    ref = ref or t.get("Endpoint")
                    relations.append(
                        rel(
                            ref,
                            EdgeType.LOAD_BALANCER_TARGET,
                            "SERVES_TRAFFIC_TO",
                            target_type=t.get("Type"),
                            role=t.get("Role"),
                        )
                    )
                return self._asset(
                    arn=p.get("DBProxyArn") or self._arn("rds", f"db-proxy:{name}"),
                    name=name,
                    asset_type=AssetType.DATABASE_PROXY,
                    metadata={
                        "service": "rds-proxy",
                        "engine_family": p.get("EngineFamily"),
                        "status": p.get("Status"),
                        "vpc_id": p.get("VpcId"),
                        "security_groups": p.get("VpcSecurityGroupIds") or [],
                        "endpoint": p.get("Endpoint"),
                        "require_tls": p.get("RequireTLS"),
                        "iam_auth": sorted(
                            {a.get("IAMAuth") for a in p.get("Auth") or [] if a.get("IAMAuth")}
                        ),
                        "targets": [
                            t.get("RdsResourceId") or t.get("TrackedClusterId") for t in targets
                        ],
                    },
                    relations=relations,
                    aliases=[p.get("Endpoint")],
                )

            results = await gather_limited([lambda x=x: detail(x) for x in proxies])
        return [a for a in results if a]

    async def _collect_rds_global_clusters(self) -> list[CloudAsset]:
        assets: list[CloudAsset] = []
        async with self._client("rds") as rds:
            async for g in self._paginate(rds, "describe_global_clusters", "GlobalClusters"):
                members = g.get("GlobalClusterMembers") or []
                relations: list[dict[str, Any] | None] = []
                for m in members:
                    arn = m.get("DBClusterArn")
                    relations.append(rel(arn, EdgeType.CONTAINS, writer=m.get("IsWriter")))
                    relations.append(
                        rel(
                            arn,
                            EdgeType.REFERENCES,
                            "REPLICATES_TO",
                            reverse=bool(m.get("IsWriter")),
                            description="global database replication",
                            sync_status=m.get("SynchronizationStatus"),
                        )
                    )
                writer = next((m.get("DBClusterArn") for m in members if m.get("IsWriter")), None)
                gid = g.get("GlobalClusterIdentifier", "")
                assets.append(
                    self._asset(
                        arn=g.get("GlobalClusterArn")
                        or f"arn:aws:rds::{self._account_id}:global-cluster:{gid}",
                        name=gid,
                        asset_type=AssetType.AURORA_CLUSTER,
                        region="global",
                        tags=g.get("TagList"),
                        metadata={
                            "service": "rds",
                            "kind": "global_cluster",
                            "engine": g.get("Engine"),
                            "engine_version": g.get("EngineVersion"),
                            "status": g.get("Status"),
                            "storage_encrypted": g.get("StorageEncrypted"),
                            "deletion_protection": g.get("DeletionProtection"),
                            "writer": writer,
                            "members": [m.get("DBClusterArn") for m in members],
                            "endpoint": g.get("Endpoint"),
                        },
                        relations=relations,
                        aliases=[g.get("GlobalClusterResourceId"), g.get("Endpoint")],
                    )
                )
        return assets

    async def _collect_memorydb(self) -> list[CloudAsset]:
        async with self._client("memorydb") as mdb:
            subnet_groups: dict[str, dict] = {}
            try:
                async for sg in self._paginate(mdb, "describe_subnet_groups", "SubnetGroups"):
                    subnet_groups[sg["Name"]] = sg
            except Exception as exc:
                logger.debug("MemoryDB subnet group listing failed: %s", exc)
            assets: list[CloudAsset] = []
            async for c in self._paginate(mdb, "describe_clusters", "Clusters"):
                group = subnet_groups.get(c.get("SubnetGroupName") or "", {})
                kms = _kms_ref(c.get("KmsKeyId"))
                relations: list[dict[str, Any] | None] = self._subnet_rels(
                    [s.get("Identifier") for s in group.get("Subnets") or []]
                )
                relations += [
                    rel(kms, EdgeType.REFERENCES, "ENCRYPTED_BY_KMS"),
                    rel(
                        c.get("SnsTopicArn"),
                        EdgeType.REFERENCES,
                        "WRITES_TO",
                        description="event notifications",
                    ),
                ]
                endpoint = (c.get("ClusterEndpoint") or {}).get("Address")
                assets.append(
                    self._asset(
                        arn=c.get("ARN") or self._arn("memorydb", f"cluster/{c['Name']}"),
                        name=c["Name"],
                        asset_type=AssetType.CACHE_CLUSTER,
                        metadata={
                            "service": "memorydb",
                            "engine": c.get("Engine"),
                            "engine_version": c.get("EngineVersion"),
                            "node_type": c.get("NodeType"),
                            "status": c.get("Status"),
                            "shards": c.get("NumberOfShards"),
                            "tls_enabled": c.get("TLSEnabled"),
                            "acl": c.get("ACLName"),
                            "kms_key_id": kms,
                            "vpc_id": group.get("VpcId"),
                            "subnet_group": c.get("SubnetGroupName"),
                            "security_groups": [
                                g.get("SecurityGroupId") for g in c.get("SecurityGroups") or []
                            ],
                            "endpoint": endpoint,
                        },
                        relations=relations,
                        aliases=[endpoint],
                    )
                )
        return assets

    async def _collect_dax(self) -> list[CloudAsset]:
        async with self._client("dax") as dax:
            subnet_groups: dict[str, dict] = {}
            try:
                async for sg in self._paginate(dax, "describe_subnet_groups", "SubnetGroups"):
                    subnet_groups[sg["SubnetGroupName"]] = sg
            except Exception as exc:
                logger.debug("DAX subnet group listing failed: %s", exc)
            assets: list[CloudAsset] = []
            async for c in self._paginate(dax, "describe_clusters", "Clusters"):
                group = subnet_groups.get(c.get("SubnetGroup") or "", {})
                relations: list[dict[str, Any] | None] = self._subnet_rels(
                    [s.get("SubnetIdentifier") for s in group.get("Subnets") or []]
                )
                relations += [
                    rel(c.get("IamRoleArn"), EdgeType.ASSUMES_ROLE, "RUNS_ON"),
                    rel(
                        (c.get("NotificationConfiguration") or {}).get("TopicArn"),
                        EdgeType.REFERENCES,
                        "WRITES_TO",
                        description="event notifications",
                    ),
                ]
                endpoint = (c.get("ClusterDiscoveryEndpoint") or {}).get("Address")
                assets.append(
                    self._asset(
                        arn=c.get("ClusterArn") or self._arn("dax", f"cache/{c['ClusterName']}"),
                        name=c["ClusterName"],
                        asset_type=AssetType.CACHE_CLUSTER,
                        metadata={
                            "service": "dax",
                            "node_type": c.get("NodeType"),
                            "status": c.get("Status"),
                            "nodes": c.get("TotalNodes"),
                            "sse": (c.get("SSEDescription") or {}).get("Status"),
                            "endpoint_encryption": c.get("ClusterEndpointEncryptionType"),
                            "vpc_id": group.get("VpcId"),
                            "subnet_group": c.get("SubnetGroup"),
                            "security_groups": [
                                g.get("SecurityGroupIdentifier")
                                for g in c.get("SecurityGroups") or []
                            ],
                            "endpoint": endpoint,
                        },
                        relations=relations,
                        aliases=[endpoint],
                    )
                )
        return assets

    # ------------------------------------------------------------------
    # ECR Public (global, us-east-1 only)
    # ------------------------------------------------------------------

    async def _collect_ecr_public(self) -> list[CloudAsset]:
        assets: list[CloudAsset] = []
        async with self._client("ecr-public", region="us-east-1") as ecr:
            async for r in self._paginate(ecr, "describe_repositories", "repositories"):
                uri = r.get("repositoryUri")
                assets.append(
                    self._asset(
                        arn=r["repositoryArn"],
                        name=r.get("repositoryName", ""),
                        asset_type=AssetType.CONTAINER_REGISTRY,
                        region="global",
                        metadata={
                            "service": "ecr-public",
                            "public": True,
                            "registry_id": r.get("registryId"),
                            "repository_uri": uri,
                            "created_at": str(r.get("createdAt", "")),
                        },
                        exposed=True,
                        aliases=[uri],
                    )
                )
        return assets
