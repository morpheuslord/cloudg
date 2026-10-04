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
"""

from __future__ import annotations

import json
import logging
import re
from typing import Any, Iterable
from urllib.parse import urlparse

from cloudg.inventory.aws_services._base import (
    AWSServiceMixin,
    arns_in,
    condition_values,
    error_code,
    gather_limited,
    identifier_refs,
    policy_principals,
    policy_statements,
    principal_ref,
    rel,
)
from cloudg.inventory.aws_services.containers import image_repository
from cloudg.inventory.aws_services._base import resource_policy_relations as _resource_policy_relations
from cloudg.schema.models import AssetType, CloudAsset, EdgeType

logger = logging.getLogger(__name__)

_MAX_PARAMETERS = 10000
_MAX_LOG_GROUPS_FOR_FILTERS = 2000
_MAX_PROTECTED_RESOURCES = 5000

_ARN_ACCOUNT_RE = re.compile(r"^arn:aws[a-zA-Z-]*:[a-z0-9-]+:[a-z0-9-]*:(\d{12}):")
_ALARM_RULE_RE = re.compile(r"(?:ALARM|OK|INSUFFICIENT_DATA)\(\s*\"?([^\")]+?)\"?\s*\)")
_ASG_POLICY_RE = re.compile(r"autoScalingGroupName/([^:]+)")
_AWS_OWNED_DOC_PREFIXES = ("AWS-", "AWSEC2-", "AWSSupport-", "AWSConfigRemediation-", "Amazon", "AWSFIS-")


# ----------------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------------


def _chunks(items: list[Any], size: int) -> Iterable[list[Any]]:
    for i in range(0, len(items), size):
        yield items[i : i + size]


def _arn_account(arn: Any) -> str | None:
    if not isinstance(arn, str):
        return None
    m = _ARN_ACCOUNT_RE.match(arn)
    return m.group(1) if m else None


def _host(url: Any) -> str | None:
    """Host part of an endpoint URL; paths, queries and credentials dropped."""
    if not isinstance(url, str) or not url:
        return None
    parsed = urlparse(url if "://" in url else f"https://{url}")
    return parsed.hostname


def _clean_url(url: Any) -> str | None:
    """Repository URL without embedded credentials or query string."""
    if not isinstance(url, str) or not url:
        return None
    if "://" not in url:
        return url.split("?", 1)[0]
    p = urlparse(url)
    host = p.hostname or ""
    if p.port:
        host = f"{host}:{p.port}"
    return f"{p.scheme}://{host}{p.path}"


def _bucket_arn(location: Any) -> str | None:
    """S3 bucket ARN from 'bucket/prefix', 's3://bucket/...', or an S3 ARN."""
    if not isinstance(location, str) or not location:
        return None
    loc = location.strip()
    if loc.startswith("arn:aws:s3:::"):
        return "arn:aws:s3:::" + loc[len("arn:aws:s3:::"):].split("/", 1)[0]
    if loc.startswith("s3://"):
        loc = loc[5:]
    bucket = loc.split("/", 1)[0]
    return f"arn:aws:s3:::{bucket}" if bucket else None


def _ecr_repo(image: Any) -> str | None:
    """Repository reference for ECR images; None for public registries."""
    if not isinstance(image, str) or ".dkr.ecr." not in image:
        return None
    return image_repository(image)


def _is_aws_owned_document(name: str) -> bool:
    return name.startswith(_AWS_OWNED_DOC_PREFIXES)


def _env_names(variables: Any) -> list[str]:
    """Names from [{name|Name: ...}] or {name: value} env shapes."""
    if isinstance(variables, dict):
        return sorted(str(k) for k in variables)
    out = []
    for v in variables or []:
        if isinstance(v, dict):
            n = v.get("name", v.get("Name"))
            if n:
                out.append(str(n))
    return sorted(out)


def _env_values(variables: Any) -> dict[str, Any]:
    if isinstance(variables, dict):
        return variables
    out: dict[str, Any] = {}
    for v in variables or []:
        if isinstance(v, dict):
            out[str(v.get("name", v.get("Name", "")))] = v.get("value", v.get("Value"))
    return out


def _resource_list(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return [str(v) for v in value]
    return []


class ApplicationCollectorsMixin(AWSServiceMixin):

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
            "eventbridge_api_destinations": (self._collect_eventbridge_api_destinations, "integration", False),
            "eventbridge_archives": (self._collect_eventbridge_archives, "integration", False),
            "firehose": (self._collect_firehose, "integration", False),
            "log_subscriptions": (self._collect_log_subscriptions, "logging", False),
            "log_destinations": (self._collect_log_destinations, "logging", False),
            "oam": (self._collect_oam, "logging", False),
            "batch": (self._collect_batch, "compute", False),
            "apprunner": (self._collect_apprunner, "compute", False),
            "elasticbeanstalk": (self._collect_elasticbeanstalk, "compute", False),
        }

    # ------------------------------------------------------------------
    # Shared identifier builders
    # ------------------------------------------------------------------

    def _cross_account(self, arn: Any) -> bool:
        acct = _arn_account(arn)
        return bool(acct and self._account_id and acct != self._account_id)

    def _role_ref(self, value: Any) -> str | None:
        if not isinstance(value, str) or not value:
            return None
        return value if value.startswith("arn:") else f"arn:aws:iam::{self._account_id}:role/{value.lstrip('/')}"

    def _instance_profile_ref(self, value: Any) -> str | None:
        if not isinstance(value, str) or not value:
            return None
        return value if value.startswith("arn:") else f"arn:aws:iam::{self._account_id}:instance-profile/{value}"

    def _param_arn(self, name: str, region: str | None = None) -> str:
        if name.startswith("arn:"):
            return name
        return self._arn("ssm", "parameter/" + name.lstrip("/"), region)

    def _secret_or_param_ref(self, value: Any, kind: str = "auto") -> str | None:
        """Reference for a secret/parameter pointer (never its value).

        Secrets Manager ARNs may carry ``:json-key:stage:version`` suffixes;
        bare names are SSM parameter names (``kind='parameter'``) or secret
        names (``kind='secret'``).
        """
        if not isinstance(value, str) or not value:
            return None
        if value.startswith("arn:"):
            parts = value.split(":")
            if len(parts) > 7 and parts[2] == "secretsmanager":
                return ":".join(parts[:7])
            return value
        if kind == "secret":
            return value.split(":", 1)[0]
        return self._param_arn(value)

    def _log_group_arn(self, name: str, region: str | None = None) -> str:
        return self._arn("logs", f"log-group:{name}", region)

    def _env_relations(self, variables: Any, description: str) -> list[dict | None]:
        """Identifier-only references from plain environment values."""
        return [
            rel(ref, EdgeType.REFERENCES, "DEPENDS_ON", description=description)
            for ref in identifier_refs(_env_values(variables))
        ]

    # ------------------------------------------------------------------
    # CodePipeline
    # ------------------------------------------------------------------

    def _pipeline_action_relations(self, action: dict) -> tuple[list[dict | None], dict[str, Any]]:
        type_id = action.get("actionTypeId") or {}
        category = type_id.get("category", "")
        provider = type_id.get("provider", "")
        cfg = {k: v for k, v in (action.get("configuration") or {}).items()
               if isinstance(v, str) and "#{" not in v}
        region = action.get("region") or self._region
        name = action.get("name", "")
        desc = f"{category} action {name} ({provider})"
        relations: list[dict | None] = []
        summary: dict[str, Any] = {
            "name": name, "category": category, "provider": provider, "owner": type_id.get("owner"),
            "region": region, "run_order": action.get("runOrder"),
        }
        role = action.get("roleArn")
        if role:
            summary["cross_account_role"] = self._cross_account(role)
            relations.append(rel(role, EdgeType.ASSUMES_ROLE, "RUNS_ON", description=f"{desc} role",
                                 cross_account=self._cross_account(role) or None))
        if region != self._region:
            summary["cross_region"] = True

        def arn(service: str, resource: str) -> str:
            return self._arn(service, resource, region)

        if provider == "CodeBuild" and cfg.get("ProjectName"):
            relations.append(rel(arn("codebuild", f"project/{cfg['ProjectName']}"), EdgeType.INVOKES, "INVOKES", description=desc))
        elif provider == "CloudFormation" and cfg.get("StackName"):
            relations.append(rel(cfg["StackName"], EdgeType.MANAGES, description=f"{desc} deploys stack"))
            relations.append(rel(cfg.get("RoleArn"), EdgeType.REFERENCES, "DEPENDS_ON", description="CloudFormation deployment role"))
        elif provider == "CloudFormationStackSet" and cfg.get("StackSetName"):
            relations.append(rel(cfg["StackSetName"], EdgeType.MANAGES, description=f"{desc} deploys stack set"))
        elif provider == "ECS" and cfg.get("ClusterName") and cfg.get("ServiceName"):
            relations.append(rel(arn("ecs", f"service/{cfg['ClusterName']}/{cfg['ServiceName']}"), EdgeType.MANAGES, description=desc))
        elif provider in ("CodeDeploy", "CodeDeployToECS") and cfg.get("ApplicationName") and cfg.get("DeploymentGroupName"):
            relations.append(rel(arn("codedeploy", f"deploymentgroup:{cfg['ApplicationName']}/{cfg['DeploymentGroupName']}"),
                                 EdgeType.INVOKES, "INVOKES", description=desc))
        elif provider == "Lambda" and cfg.get("FunctionName"):
            fn = cfg["FunctionName"]
            relations.append(rel(fn if fn.startswith("arn:") else arn("lambda", f"function:{fn}"), EdgeType.INVOKES, "INVOKES", description=desc))
        elif provider == "StepFunctions" and cfg.get("StateMachineArn"):
            relations.append(rel(cfg["StateMachineArn"], EdgeType.INVOKES, "INVOKES", description=desc))
        elif provider == "ElasticBeanstalk" and cfg.get("ApplicationName") and cfg.get("EnvironmentName"):
            relations.append(rel(arn("elasticbeanstalk", f"environment/{cfg['ApplicationName']}/{cfg['EnvironmentName']}"),
                                 EdgeType.MANAGES, description=desc))
        elif provider == "EKS" and cfg.get("ClusterName"):
            relations.append(rel(arn("eks", f"cluster/{cfg['ClusterName']}"), EdgeType.MANAGES, description=desc))
        elif provider == "CodeStarSourceConnection":
            relations.append(rel(cfg.get("ConnectionArn"), EdgeType.REFERENCES, "READS_FROM", description=desc))
            summary["repository"] = cfg.get("FullRepositoryId")
            summary["branch"] = cfg.get("BranchName")
        elif provider == "CodeCommit" and cfg.get("RepositoryName"):
            relations.append(rel(arn("codecommit", cfg["RepositoryName"]), EdgeType.REFERENCES, "READS_FROM", description=desc))
            summary["repository"] = cfg["RepositoryName"]
            summary["branch"] = cfg.get("BranchName")
        elif provider == "ECR" and cfg.get("RepositoryName"):
            relations.append(rel(arn("ecr", f"repository/{cfg['RepositoryName']}"), EdgeType.REFERENCES, "READS_FROM", description=desc))
        elif provider == "S3":
            bucket = cfg.get("S3Bucket") or cfg.get("BucketName")
            verb = "READS_FROM" if category == "Source" else "WRITES_TO"
            relations.append(rel(_bucket_arn(bucket), EdgeType.REFERENCES, verb, description=desc))
            relations.append(rel(cfg.get("KMSEncryptionKeyARN"), EdgeType.REFERENCES, "ENCRYPTED_BY_KMS"))
        elif provider == "GitHub":
            summary["repository"] = f"{cfg.get('Owner', '')}/{cfg.get('Repo', '')}".strip("/") or None
            summary["branch"] = cfg.get("Branch")
        # ARNs anywhere else in the configuration (deliberately not the raw
        # configuration itself, which may carry tokens or user parameters)
        known = {r["target"] for r in relations if r}
        for value in cfg.values():
            if value.startswith("arn:") and value not in known:
                relations.append(rel(value, EdgeType.REFERENCES, "DEPENDS_ON", description=desc))
        summary["environment_variable_names"] = _env_names(action.get("environmentVariables")) or None
        return relations, {k: v for k, v in summary.items() if v not in (None, "", [])}

    async def _collect_codepipeline(self) -> list[CloudAsset]:
        async with self._client("codepipeline") as cp:
            summaries = [p async for p in self._paginate(cp, "list_pipelines", "pipelines")]

            async def detail(summary: dict) -> CloudAsset:
                resp = await cp.get_pipeline(name=summary["name"])
                p = resp.get("pipeline") or {}
                name = p.get("name", summary["name"])
                arn = (resp.get("metadata") or {}).get("pipelineArn") or self._arn("codepipeline", name)
                relations: list[dict | None] = [rel(p.get("roleArn"), EdgeType.ASSUMES_ROLE, "RUNS_ON", description="pipeline service role")]
                stores = list((p.get("artifactStores") or {}).items())
                if p.get("artifactStore"):
                    stores.append((self._region, p["artifactStore"]))
                buckets = []
                for store_region, store in stores:
                    if store.get("type") == "S3" and store.get("location"):
                        buckets.append(store["location"])
                        relations.append(rel(_bucket_arn(store["location"]), EdgeType.REFERENCES, "WRITES_TO",
                                             description=f"artifact store ({store_region})"))
                    key = (store.get("encryptionKey") or {}).get("id")
                    relations.append(rel(key, EdgeType.REFERENCES, "ENCRYPTED_BY_KMS", description="artifact encryption"))
                stages = []
                for stage in p.get("stages", []) or []:
                    actions = []
                    for action in stage.get("actions", []) or []:
                        a_rels, a_summary = self._pipeline_action_relations(action)
                        relations.extend(a_rels)
                        actions.append(a_summary)
                    stages.append({"name": stage.get("name"), "actions": actions})
                all_actions = [a for s in stages for a in s["actions"]]
                return self._asset(
                    arn=arn,
                    name=name,
                    asset_type=AssetType.CI_PIPELINE,
                    metadata={
                        "service": "codepipeline",
                        "pipeline_type": p.get("pipelineType"),
                        "execution_mode": p.get("executionMode"),
                        "version": p.get("version"),
                        "stages": stages,
                        "artifact_buckets": buckets,
                        "providers": sorted({a.get("provider", "") for a in all_actions}),
                        "cross_account_actions": sum(1 for a in all_actions if a.get("cross_account_role")),
                        "trigger_providers": [t.get("providerType") for t in p.get("triggers", []) or []],
                        "variable_names": [v.get("name") for v in p.get("variables", []) or []],
                        "updated": str((resp.get("metadata") or {}).get("updated") or "") or None,
                    },
                    relations=relations,
                )

            results = await gather_limited([lambda s=s: detail(s) for s in summaries])
        return [a for a in results if a]

    # ------------------------------------------------------------------
    # CodeBuild
    # ------------------------------------------------------------------

    def _codebuild_source_relations(self, source: dict, label: str) -> list[dict | None]:
        stype = source.get("type")
        loc = source.get("location") or ""
        out: list[dict | None] = []
        if stype == "S3":
            out.append(rel(_bucket_arn(loc), EdgeType.REFERENCES, "READS_FROM", description=label))
        elif stype == "CODECOMMIT" and "/repos/" in loc:
            out.append(rel(self._arn("codecommit", loc.rsplit("/repos/", 1)[1].strip("/")), EdgeType.REFERENCES, "READS_FROM", description=label))
        auth_res = (source.get("auth") or {}).get("resource")
        if isinstance(auth_res, str) and auth_res.startswith("arn:"):
            out.append(rel(auth_res, EdgeType.REFERENCES, "READS_FROM", description=f"{label} credentials"))
        return out

    def _codebuild_asset(self, proj: dict) -> CloudAsset:
        name = proj.get("name", "")
        env = proj.get("environment") or {}
        vpc = proj.get("vpcConfig") or {}
        relations: list[dict | None] = [
            rel(proj.get("serviceRole"), EdgeType.ASSUMES_ROLE, "RUNS_ON", description="build service role"),
            rel((proj.get("buildBatchConfig") or {}).get("serviceRole"), EdgeType.ASSUMES_ROLE, "RUNS_ON", description="batch build role"),
            rel(proj.get("resourceAccessRole"), EdgeType.ASSUMES_ROLE, "RUNS_ON", description="resource access role"),
            rel(proj.get("encryptionKey"), EdgeType.REFERENCES, "ENCRYPTED_BY_KMS"),
        ]
        relations += self._codebuild_source_relations(proj.get("source") or {}, "primary source")
        for i, src in enumerate(proj.get("secondarySources", []) or []):
            relations += self._codebuild_source_relations(src, f"secondary source {src.get('sourceIdentifier') or i}")

        image = env.get("image")
        repo = _ecr_repo(image)
        if repo:
            relations.append(rel(repo, EdgeType.USES_IMAGE, "RUNS_ON", description=f"build image {image}"))
        cred = (env.get("registryCredential") or {}).get("credential")
        relations.append(rel(self._secret_or_param_ref(cred, "secret"), EdgeType.REFERENCES, "READS_FROM", description="registry credential"))

        env_vars = env.get("environmentVariables") or []
        var_types: dict[str, str] = {}
        for var in env_vars:
            vname, vtype, value = var.get("name"), var.get("type", "PLAINTEXT"), var.get("value")
            var_types[str(vname)] = vtype
            # Parameter-store / secrets-manager variable values are names or
            # ARNs of the secret, not the secret itself.
            if vtype == "PARAMETER_STORE":
                relations.append(rel(self._secret_or_param_ref(value, "parameter"), EdgeType.REFERENCES, "READS_FROM",
                                     description=f"env {vname} from Parameter Store"))
            elif vtype == "SECRETS_MANAGER":
                relations.append(rel(self._secret_or_param_ref(value, "secret"), EdgeType.REFERENCES, "READS_FROM",
                                     description=f"env {vname} from Secrets Manager"))
        relations += self._env_relations({v.get("name"): v.get("value") for v in env_vars if v.get("type", "PLAINTEXT") == "PLAINTEXT"},
                                         "environment reference")

        for art in [proj.get("artifacts") or {}, *(proj.get("secondaryArtifacts") or [])]:
            if art.get("type") == "S3":
                relations.append(rel(_bucket_arn(art.get("location")), EdgeType.REFERENCES, "WRITES_TO", description="build artifacts"))
        cache = proj.get("cache") or {}
        if cache.get("type") == "S3":
            relations.append(rel(_bucket_arn(cache.get("location")), EdgeType.REFERENCES, "READS_FROM", description="build cache"))
        for fs in proj.get("fileSystemLocations", []) or []:
            fs_id = (fs.get("location") or "").split(".", 1)[0]
            if fs_id.startswith("fs-"):
                relations.append(rel(fs_id, EdgeType.REFERENCES, "READS_FROM", description=f"EFS mount {fs.get('mountPoint')}"))

        logs = proj.get("logsConfig") or {}
        cw = logs.get("cloudWatchLogs") or {}
        if cw.get("status", "ENABLED") == "ENABLED":
            relations.append(rel(self._log_group_arn(cw.get("groupName") or f"/aws/codebuild/{name}"), EdgeType.LOGS_TO, "LOGS_TO"))
        s3logs = logs.get("s3Logs") or {}
        if s3logs.get("status") == "ENABLED":
            relations.append(rel(_bucket_arn(s3logs.get("location")), EdgeType.LOGS_TO, "LOGS_TO"))

        source = proj.get("source") or {}
        public = proj.get("projectVisibility") == "PUBLIC_READ"
        webhook = proj.get("webhook") or {}
        return self._asset(
            arn=proj.get("arn") or self._arn("codebuild", f"project/{name}"),
            name=name,
            asset_type=AssetType.BUILD_PROJECT,
            tags=proj.get("tags"),
            metadata={
                "service": "codebuild",
                "source_type": source.get("type"),
                "source_location": _clean_url(source.get("location")),
                "secondary_sources": [
                    {"type": s.get("type"), "location": _clean_url(s.get("location"))}
                    for s in proj.get("secondarySources", []) or []
                ],
                "environment_type": env.get("type"),
                "compute_type": env.get("computeType"),
                "image": image,
                "image_pull_credentials": env.get("imagePullCredentialsType"),
                "privileged_mode": env.get("privilegedMode", False),
                "environment_variable_names": sorted(var_types),
                "environment_variable_types": var_types,
                "service_role": proj.get("serviceRole"),
                "encryption_key": proj.get("encryptionKey"),
                "vpc_id": vpc.get("vpcId"),
                "vpc_config": {"SubnetIds": vpc.get("subnets", []) or [], "SecurityGroupIds": vpc.get("securityGroupIds", []) or []}
                if vpc else None,
                "webhook_enabled": bool(webhook),
                "webhook_filter_groups": len(webhook.get("filterGroups", []) or []),
                "visibility": proj.get("projectVisibility"),
                "badge_enabled": (proj.get("badge") or {}).get("badgeEnabled", False),
                "concurrent_build_limit": proj.get("concurrentBuildLimit"),
                "timeout_minutes": proj.get("timeoutInMinutes"),
            },
            relations=relations,
            exposed=public,
        )

    async def _collect_codebuild(self) -> list[CloudAsset]:
        assets: list[CloudAsset] = []
        async with self._client("codebuild") as cb:
            names = [n async for n in self._paginate(cb, "list_projects", "projects")]
            for chunk in _chunks(names, 100):
                try:
                    resp = await cb.batch_get_projects(names=chunk)
                except Exception as exc:
                    logger.debug("CodeBuild batch_get_projects failed: %s", exc)
                    continue
                for proj in resp.get("projects", []) or []:
                    try:
                        assets.append(self._codebuild_asset(proj))
                    except Exception as exc:
                        logger.debug("CodeBuild project mapping failed for %s: %s", proj.get("name"), exc)
        return assets

    # ------------------------------------------------------------------
    # CodeDeploy
    # ------------------------------------------------------------------

    async def _collect_codedeploy(self) -> list[CloudAsset]:
        assets: list[CloudAsset] = []
        async with self._client("codedeploy") as cd:
            apps = [a async for a in self._paginate(cd, "list_applications", "applications")]
            platforms: dict[str, str] = {}
            for chunk in _chunks(apps, 100):
                try:
                    resp = await cd.batch_get_applications(applicationNames=chunk)
                    for info in resp.get("applicationsInfo", []) or []:
                        platforms[info.get("applicationName", "")] = info.get("computePlatform", "")
                except Exception as exc:
                    logger.debug("CodeDeploy batch_get_applications failed: %s", exc)

            async def groups_for(app: str) -> list[CloudAsset]:
                names = [g async for g in self._paginate(cd, "list_deployment_groups", "deploymentGroups", applicationName=app)]
                out: list[CloudAsset] = []
                for chunk in _chunks(names, 100):
                    resp = await cd.batch_get_deployment_groups(applicationName=app, deploymentGroupNames=chunk)
                    out.extend(self._deployment_group_asset(g, platforms.get(app)) for g in resp.get("deploymentGroupsInfo", []) or [])
                return out

            results = await gather_limited([lambda a=a: groups_for(a) for a in apps])
            for r in results:
                assets.extend(r or [])
        return assets

    def _deployment_group_asset(self, g: dict, app_platform: str | None) -> CloudAsset:
        app, name = g.get("applicationName", ""), g.get("deploymentGroupName", "")
        relations: list[dict | None] = [
            rel(g.get("serviceRoleArn"), EdgeType.ASSUMES_ROLE, "RUNS_ON", description="CodeDeploy service role"),
        ]
        for asg in g.get("autoScalingGroups", []) or []:
            relations.append(rel(asg.get("name"), EdgeType.MANAGES, description="deploys to ASG"))
        for svc in g.get("ecsServices", []) or []:
            if svc.get("clusterName") and svc.get("serviceName"):
                relations.append(rel(self._arn("ecs", f"service/{svc['clusterName']}/{svc['serviceName']}"),
                                     EdgeType.MANAGES, description="blue/green ECS deployment"))
        lb = g.get("loadBalancerInfo") or {}
        for elb in lb.get("elbInfoList", []) or []:
            relations.append(rel(elb.get("name"), EdgeType.MANAGES, description="classic ELB traffic control"))
        tgs = list(lb.get("targetGroupInfoList", []) or [])
        listeners: list[str] = []
        for pair in lb.get("targetGroupPairInfoList", []) or []:
            tgs.extend(pair.get("targetGroups", []) or [])
            for route in ("prodTrafficRoute", "testTrafficRoute"):
                listeners.extend((pair.get(route) or {}).get("listenerArns", []) or [])
        for tg in tgs:
            relations.append(rel(tg.get("name"), EdgeType.MANAGES, description="traffic shifting target group"))
        for listener in listeners:
            relations.append(rel(listener, EdgeType.REFERENCES, "SERVES_TRAFFIC_TO", description="traffic route listener"))
        for trig in g.get("triggerConfigurations", []) or []:
            relations.append(rel(trig.get("triggerTargetArn"), EdgeType.INVOKES, "INVOKES", description=f"trigger {trig.get('triggerName')}"))
        for alarm in (g.get("alarmConfiguration") or {}).get("alarms", []) or []:
            relations.append(rel(alarm.get("name"), EdgeType.REFERENCES, "MONITORED_BY", description="rollback alarm"))
        rev = g.get("targetRevision") or {}
        s3loc = rev.get("s3Location") or {}
        relations.append(rel(_bucket_arn(s3loc.get("bucket")), EdgeType.REFERENCES, "READS_FROM", description="revision bundle"))
        tag_filters = [
            {"key": f.get("Key"), "value": f.get("Value"), "type": f.get("Type")}
            for f in (g.get("ec2TagFilters") or []) + (g.get("onPremisesInstanceTagFilters") or [])
        ]
        for tag_set in ((g.get("ec2TagSet") or {}).get("ec2TagSetList") or []):
            for group in tag_set or []:
                tag_filters.append({"key": group.get("Key"), "value": group.get("Value"), "type": group.get("Type")})
        return self._asset(
            arn=self._arn("codedeploy", f"deploymentgroup:{app}/{name}"),
            name=f"{app}/{name}",
            asset_type=AssetType.DEPLOYMENT_GROUP,
            metadata={
                "service": "codedeploy",
                "application_name": app,
                "deployment_group_id": g.get("deploymentGroupId"),
                "compute_platform": g.get("computePlatform") or app_platform,
                "deployment_config": g.get("deploymentConfigName"),
                "deployment_style": g.get("deploymentStyle"),
                "tag_filters": tag_filters,
                "auto_scaling_groups": [a.get("name") for a in g.get("autoScalingGroups", []) or []],
                "ecs_services": g.get("ecsServices", []) or [],
                "revision_type": rev.get("revisionType"),
                "github_repository": (rev.get("gitHubLocation") or {}).get("repository"),
                "auto_rollback": (g.get("autoRollbackConfiguration") or {}).get("enabled", False),
                "last_successful_deployment": (g.get("lastSuccessfulDeployment") or {}).get("deploymentId"),
            },
            relations=relations,
            aliases=[g.get("deploymentGroupId")],
        )

    # ------------------------------------------------------------------
    # CodeConnections / CodeStar connections
    # ------------------------------------------------------------------

    async def _collect_codeconnections(self) -> list[CloudAsset]:
        connections: list[dict] = []
        last_exc: Exception | None = None
        for service in ("codeconnections", "codestar-connections"):
            try:
                async with self._client(service) as cc:
                    connections = [c async for c in self._pages(cc.list_connections, "Connections")]
                last_exc = None
                break
            except Exception as exc:
                last_exc = exc
                logger.debug("%s list_connections failed: %s", service, exc)
        if last_exc is not None:
            raise last_exc
        assets: list[CloudAsset] = []
        for c in connections:
            arn = c.get("ConnectionArn", "")
            # Pipelines may reference either service prefix for the same connection
            other = (arn.replace(":codeconnections:", ":codestar-connections:") if ":codeconnections:" in arn
                     else arn.replace(":codestar-connections:", ":codeconnections:"))
            owner = c.get("OwnerAccountId")
            assets.append(
                self._asset(
                    arn=arn,
                    name=c.get("ConnectionName", arn),
                    asset_type=AssetType.SOURCE_CONNECTION,
                    tags=c.get("Tags"),
                    metadata={
                        "service": "codeconnections",
                        "kind": "source_connection",
                        "provider_type": c.get("ProviderType"),
                        "status": c.get("ConnectionStatus"),
                        "owner_account_id": owner,
                        "cross_account": bool(owner and self._account_id and owner != self._account_id),
                    },
                    relations=[rel(c.get("HostArn"), EdgeType.REFERENCES, "DEPENDS_ON", description="connection host")],
                    aliases=[other if other != arn else None],
                )
            )
        return assets

    # ------------------------------------------------------------------
    # Systems Manager
    # ------------------------------------------------------------------

    async def _collect_ssm_parameters(self) -> list[CloudAsset]:
        """Parameter metadata only: get_parameter(s) is never called."""
        assets: list[CloudAsset] = []
        async with self._client("ssm") as ssm:
            async for p in self._paginate(ssm, "describe_parameters", "Parameters",
                                          PaginationConfig={"MaxItems": _MAX_PARAMETERS}):
                if len(assets) >= _MAX_PARAMETERS:
                    break
                name = p.get("Name", "")
                arn = p.get("ARN") or self._param_arn(name)
                key = p.get("KeyId")
                assets.append(
                    self._asset(
                        arn=arn,
                        name=name,
                        asset_type=AssetType.PARAMETER,
                        metadata={
                            "service": "ssm",
                            "type": p.get("Type"),
                            "tier": p.get("Tier"),
                            "data_type": p.get("DataType"),
                            "version": p.get("Version"),
                            "kms_key_id": key,
                            "last_modified": str(p.get("LastModifiedDate") or "") or None,
                            "last_modified_user": p.get("LastModifiedUser"),
                            "description": p.get("Description"),
                            "has_policies": bool(p.get("Policies")),
                            "secure": p.get("Type") == "SecureString",
                        },
                        relations=[rel(key, EdgeType.REFERENCES, "ENCRYPTED_BY_KMS")] if key else [],
                        aliases=[self._param_arn(name)] if self._param_arn(name) != arn else [],
                    )
                )
        return assets

    async def _collect_ssm_managed_instances(self) -> list[CloudAsset]:
        assets: list[CloudAsset] = []
        fleet_relations: list[dict | None] = []
        ping: dict[str, int] = {}
        platforms: dict[str, int] = {}
        outdated = 0
        async with self._client("ssm") as ssm:
            async for info in self._paginate(ssm, "describe_instance_information", "InstanceInformationList"):
                iid = info.get("InstanceId", "")
                status = info.get("PingStatus", "")
                ping[status] = ping.get(status, 0) + 1
                plat = info.get("PlatformType", "")
                platforms[plat] = platforms.get(plat, 0) + 1
                if info.get("IsLatestVersion") is False:
                    outdated += 1
                props = {"ping_status": status, "agent_version": info.get("AgentVersion"),
                         "platform": info.get("PlatformName"), "association_status": info.get("AssociationStatus")}
                if iid.startswith("mi-"):
                    arn = self._arn("ssm", f"managed-instance/{iid}")
                    assets.append(
                        self._asset(
                            arn=arn,
                            name=info.get("Name") or info.get("ComputerName") or iid,
                            asset_type=AssetType.VIRTUAL_MACHINE,
                            metadata={
                                "service": "ssm",
                                "hybrid": True,
                                "instance_id": iid,
                                "resource_type": info.get("ResourceType"),
                                "platform_type": plat,
                                "platform_name": info.get("PlatformName"),
                                "platform_version": info.get("PlatformVersion"),
                                "computer_name": info.get("ComputerName"),
                                "private_ip": info.get("IPAddress"),
                                "ping_status": status,
                                "agent_version": info.get("AgentVersion"),
                                "activation_id": info.get("ActivationId"),
                                "source_id": info.get("SourceId"),
                                "source_type": info.get("SourceType"),
                            },
                            relations=[rel(self._role_ref(info.get("IamRole")), EdgeType.ASSUMES_ROLE, "RUNS_ON",
                                           description="hybrid activation role")],
                            aliases=[iid],
                        )
                    )
                    fleet_relations.append(rel(arn, EdgeType.MANAGES, description="SSM hybrid node", **props))
                else:
                    fleet_relations.append(rel(iid, EdgeType.MANAGES, description="SSM managed instance", **props))
        if fleet_relations:
            assets.append(
                self._asset(
                    arn=f"cloudg:aws:ssm:{self._region}:{self._account_id}:fleet",
                    name=f"Systems Manager fleet ({self._region})",
                    asset_type=AssetType.OTHER,
                    metadata={
                        "service": "ssm",
                        "kind": "managed_fleet",
                        "managed_instances": len(fleet_relations),
                        "hybrid_nodes": sum(1 for a in assets if a.metadata.get("hybrid")),
                        "ping_status": ping,
                        "platforms": platforms,
                        "outdated_agents": outdated,
                    },
                    relations=fleet_relations,
                    aliases=[self._security_alias("ssm")],
                )
            )
        return assets

    async def _collect_ssm_documents(self) -> list[CloudAsset]:
        async with self._client("ssm") as ssm:
            docs = [d async for d in self._paginate(ssm, "list_documents", "DocumentIdentifiers",
                                                    Filters=[{"Key": "Owner", "Values": ["Self"]}])]

            async def detail(doc: dict) -> CloudAsset:
                name = doc.get("Name", "")
                accounts: list[str] = []
                try:
                    perm = await ssm.describe_document_permission(Name=name, PermissionType="Share")
                    accounts = [str(a) for a in perm.get("AccountIds", []) or []]
                except Exception as exc:
                    logger.debug("Document permission lookup failed for %s: %s", name, exc)
                public = any(a.lower() == "all" for a in accounts)
                shared = [a for a in accounts if a.lower() != "all"]
                relations = [
                    rel(principal_ref(a), EdgeType.GRANTS_ACCESS, "POLICY_ALLOWS_ACTION", reverse=True,
                        description="document shared with account", cross_account=a != self._account_id)
                    for a in shared
                ]
                return self._asset(
                    arn=name if name.startswith("arn:") else self._arn("ssm", f"document/{name}"),
                    name=name,
                    asset_type=AssetType.RUNBOOK,
                    tags=doc.get("Tags"),
                    metadata={
                        "service": "ssm",
                        "kind": "ssm_document",
                        "document_type": doc.get("DocumentType"),
                        "document_format": doc.get("DocumentFormat"),
                        "document_version": doc.get("DocumentVersion"),
                        "platform_types": doc.get("PlatformTypes", []),
                        "target_type": doc.get("TargetType"),
                        "public": public,
                        "shared_with_accounts": shared,
                    },
                    relations=relations,
                    exposed=public,
                )

            results = await gather_limited([lambda d=d: detail(d) for d in docs])
        return [a for a in results if a]

    def _ssm_target_relations(self, targets: Any, description: str) -> tuple[list[dict | None], list[dict]]:
        relations: list[dict | None] = []
        summary: list[dict] = []
        for t in targets or []:
            key, values = t.get("Key", ""), t.get("Values", []) or []
            summary.append({"key": key, "values": values[:50]})
            if key in ("InstanceIds", "ResourceId"):
                for v in values:
                    if v != "*":
                        relations.append(rel(v, EdgeType.MANAGES, "SCHEDULED_BY", description=description))
            elif key in ("resource-groups:Name", "ResourceGroup"):
                for v in values:
                    relations.append(rel(v, EdgeType.MANAGES, "SCHEDULED_BY", description=f"{description} (resource group)"))
        return relations, summary

    def _ssm_document_ref(self, name: Any) -> str | None:
        if not isinstance(name, str) or not name:
            return None
        if name.startswith("arn:"):
            return name
        if _is_aws_owned_document(name):
            return None
        return self._arn("ssm", f"document/{name}")

    async def _collect_ssm_associations(self) -> list[CloudAsset]:
        assets: list[CloudAsset] = []
        async with self._client("ssm") as ssm:
            async for a in self._paginate(ssm, "list_associations", "Associations"):
                aid = a.get("AssociationId", "")
                doc = a.get("Name", "")
                relations, targets = self._ssm_target_relations(a.get("Targets"), f"association applies {doc}")
                if a.get("InstanceId"):
                    relations.append(rel(a["InstanceId"], EdgeType.MANAGES, "SCHEDULED_BY", description=f"association applies {doc}"))
                relations.append(rel(self._ssm_document_ref(doc), EdgeType.REFERENCES, "DEPENDS_ON", description="association document"))
                assets.append(
                    self._asset(
                        arn=self._arn("ssm", f"association/{aid}"),
                        name=a.get("AssociationName") or f"{doc} ({aid})",
                        asset_type=AssetType.SCHEDULE,
                        metadata={
                            "service": "ssm",
                            "kind": "ssm_association",
                            "association_id": aid,
                            "document": doc,
                            "document_version": a.get("DocumentVersion"),
                            "schedule": a.get("ScheduleExpression"),
                            "targets": targets,
                            "status": (a.get("Overview") or {}).get("Status"),
                            "last_execution": str(a.get("LastExecutionDate") or "") or None,
                        },
                        relations=relations,
                        aliases=[aid],
                    )
                )
        return assets

    async def _collect_ssm_maintenance_windows(self) -> list[CloudAsset]:
        async with self._client("ssm") as ssm:
            windows = [w async for w in self._paginate(ssm, "describe_maintenance_windows", "WindowIdentities")]

            async def detail(w: dict) -> CloudAsset:
                wid = w.get("WindowId", "")
                relations: list[dict | None] = []
                targets: list[dict] = []
                tasks: list[dict] = []
                try:
                    async for t in self._paginate(ssm, "describe_maintenance_window_targets", "Targets", WindowId=wid):
                        t_rels, t_summary = self._ssm_target_relations(t.get("Targets"), "maintenance window target")
                        relations.extend(t_rels)
                        targets.append({"name": t.get("Name"), "resource_type": t.get("ResourceType"), "targets": t_summary})
                except Exception as exc:
                    logger.debug("Maintenance window targets failed for %s: %s", wid, exc)
                try:
                    async for task in self._paginate(ssm, "describe_maintenance_window_tasks", "Tasks", WindowId=wid):
                        task_arn = task.get("TaskArn", "")
                        ttype = task.get("Type")
                        if task_arn.startswith("arn:"):
                            relations.append(rel(task_arn, EdgeType.INVOKES, "INVOKES", description=f"{ttype} task"))
                        else:
                            relations.append(rel(self._ssm_document_ref(task_arn), EdgeType.REFERENCES, "DEPENDS_ON",
                                                 description=f"{ttype} task document"))
                        relations.append(rel(task.get("ServiceRoleArn"), EdgeType.ASSUMES_ROLE, "RUNS_ON", description="task role"))
                        log_bucket = (task.get("LoggingInfo") or {}).get("S3BucketName")
                        relations.append(rel(_bucket_arn(log_bucket), EdgeType.LOGS_TO, "LOGS_TO"))
                        t_rels, _ = self._ssm_target_relations(task.get("Targets"), "maintenance window task target")
                        relations.extend(t_rels)
                        tasks.append({"name": task.get("Name"), "type": ttype, "task": task_arn, "priority": task.get("Priority")})
                except Exception as exc:
                    logger.debug("Maintenance window tasks failed for %s: %s", wid, exc)
                return self._asset(
                    arn=self._arn("ssm", f"maintenancewindow/{wid}"),
                    name=w.get("Name") or wid,
                    asset_type=AssetType.SCHEDULE,
                    metadata={
                        "service": "ssm",
                        "kind": "maintenance_window",
                        "window_id": wid,
                        "enabled": w.get("Enabled"),
                        "schedule": w.get("Schedule"),
                        "timezone": w.get("ScheduleTimezone"),
                        "duration_hours": w.get("Duration"),
                        "cutoff_hours": w.get("Cutoff"),
                        "next_execution": w.get("NextExecutionTime"),
                        "targets": targets,
                        "tasks": tasks,
                    },
                    relations=relations,
                    aliases=[wid],
                )

            results = await gather_limited([lambda w=w: detail(w) for w in windows])
        return [a for a in results if a]

    # ------------------------------------------------------------------
    # CloudWatch alarms
    # ------------------------------------------------------------------

    def _alarm_dimension_targets(self, namespace: str, dims: list[dict]) -> list[str]:
        d = {x.get("Name"): x.get("Value") for x in dims or [] if x.get("Name") and x.get("Value")}
        out: list[str] = []
        if d.get("InstanceId"):
            out.append(d["InstanceId"])
        if d.get("AutoScalingGroupName"):
            out.append(d["AutoScalingGroupName"])
        if namespace == "AWS/Lambda" and d.get("FunctionName"):
            res = d.get("Resource") or d["FunctionName"]
            out.append(self._arn("lambda", f"function:{res}"))
        if d.get("QueueName"):
            out.append(self._arn("sqs", d["QueueName"]))
        if d.get("TopicName"):
            out.append(self._arn("sns", d["TopicName"]))
        if d.get("TableName"):
            out.append(self._arn("dynamodb", f"table/{d['TableName']}"))
        if d.get("DBInstanceIdentifier"):
            out.append(self._arn("rds", f"db:{d['DBInstanceIdentifier']}"))
        if d.get("DBClusterIdentifier"):
            out.append(self._arn("rds", f"cluster:{d['DBClusterIdentifier']}"))
        if d.get("TargetGroup"):
            out.append(self._arn("elasticloadbalancing", d["TargetGroup"]))
        elif d.get("LoadBalancer"):
            out.append(self._arn("elasticloadbalancing", f"loadbalancer/{d['LoadBalancer']}"))
        if d.get("LoadBalancerName"):
            out.append(d["LoadBalancerName"])
        if namespace == "AWS/ECS" and d.get("ClusterName"):
            if d.get("ServiceName"):
                out.append(self._arn("ecs", f"service/{d['ClusterName']}/{d['ServiceName']}"))
            else:
                out.append(self._arn("ecs", f"cluster/{d['ClusterName']}"))
        if d.get("StateMachineArn"):
            out.append(d["StateMachineArn"])
        if namespace == "AWS/Kinesis" and d.get("StreamName"):
            out.append(self._arn("kinesis", f"stream/{d['StreamName']}"))
        if d.get("DeliveryStreamName"):
            out.append(self._arn("firehose", f"deliverystream/{d['DeliveryStreamName']}"))
        if namespace == "AWS/S3" and d.get("BucketName"):
            out.append(f"arn:aws:s3:::{d['BucketName']}")
        for key in ("CacheClusterId", "VolumeId", "NatGatewayId", "ApiId", "FileSystemId"):
            if d.get(key):
                out.append(d[key])
        if namespace == "AWS/ApiGateway" and d.get("ApiName"):
            out.append(d["ApiName"])
        return out

    def _alarm_asset(self, alarm: dict, composite: bool) -> CloudAsset:
        name = alarm.get("AlarmName", "")
        relations: list[dict | None] = []
        ec2_actions: list[str] = []
        for field, state in (("AlarmActions", "ALARM"), ("OKActions", "OK"), ("InsufficientDataActions", "INSUFFICIENT_DATA")):
            for action in alarm.get(field, []) or []:
                if action.startswith("arn:aws:automate:"):
                    ec2_actions.append(action.rsplit(":", 1)[-1])
                    continue
                if ":autoscaling:" in action and "scalingPolicy" in action:
                    m = _ASG_POLICY_RE.search(action)
                    if m:
                        relations.append(rel(m.group(1), EdgeType.INVOKES, "SCALES_WITH", description=f"{state} scaling policy"))
                    continue
                relations.append(rel(action, EdgeType.INVOKES, "INVOKES", description=f"{state} action"))
        monitored: list[str] = []
        if composite:
            for child in _ALARM_RULE_RE.findall(alarm.get("AlarmRule") or ""):
                relations.append(rel(child.strip(), EdgeType.REFERENCES, "DEPENDS_ON", description="composite alarm child"))
        else:
            monitored = self._alarm_dimension_targets(alarm.get("Namespace", ""), alarm.get("Dimensions") or [])
            for q in alarm.get("Metrics", []) or []:
                metric = ((q.get("MetricStat") or {}).get("Metric") or {})
                monitored += self._alarm_dimension_targets(metric.get("Namespace", ""), metric.get("Dimensions") or [])
            # EC2 actions act on the instance in the dimensions
            for target in dict.fromkeys(monitored):
                relations.append(rel(target, EdgeType.MONITORS, "MONITORED_BY", description=f"{alarm.get('Namespace')} {alarm.get('MetricName') or ''}".strip()))
        return self._asset(
            arn=alarm.get("AlarmArn") or self._arn("cloudwatch", f"alarm:{name}"),
            name=name,
            asset_type=AssetType.ALARM,
            metadata={
                "service": "cloudwatch",
                "alarm_type": "composite" if composite else "metric",
                "state": alarm.get("StateValue"),
                "actions_enabled": alarm.get("ActionsEnabled"),
                "namespace": alarm.get("Namespace"),
                "metric": alarm.get("MetricName"),
                "statistic": alarm.get("Statistic") or alarm.get("ExtendedStatistic"),
                "threshold": alarm.get("Threshold"),
                "comparison": alarm.get("ComparisonOperator"),
                "evaluation_periods": alarm.get("EvaluationPeriods"),
                "dimensions": {x.get("Name"): x.get("Value") for x in alarm.get("Dimensions", []) or []},
                "alarm_rule": alarm.get("AlarmRule"),
                "ec2_actions": ec2_actions,
                "monitored_identifiers": list(dict.fromkeys(monitored)),
            },
            relations=relations,
        )

    async def _collect_cloudwatch_alarms(self) -> list[CloudAsset]:
        assets: list[CloudAsset] = []
        async with self._client("cloudwatch") as cw:
            paginator = cw.get_paginator("describe_alarms")
            async for page in paginator.paginate(AlarmTypes=["MetricAlarm", "CompositeAlarm"]):
                for alarm in page.get("MetricAlarms", []) or []:
                    assets.append(self._alarm_asset(alarm, composite=False))
                for alarm in page.get("CompositeAlarms", []) or []:
                    assets.append(self._alarm_asset(alarm, composite=True))
        return assets

    # ------------------------------------------------------------------
    # AWS Backup
    # ------------------------------------------------------------------

    def _vault_ref(self, name: Any) -> str | None:
        if not isinstance(name, str) or not name:
            return None
        return name if name.startswith("arn:") else self._arn("backup", f"backup-vault:{name}")

    async def _collect_backup_plans(self) -> list[CloudAsset]:
        async with self._client("backup") as bk:
            plans = [p async for p in self._paginate(bk, "list_backup_plans", "BackupPlansList")]

            async def detail(summary: dict) -> CloudAsset:
                pid = summary["BackupPlanId"]
                resp = await bk.get_backup_plan(BackupPlanId=pid)
                plan = resp.get("BackupPlan") or {}
                relations: list[dict | None] = []
                rules = []
                for r in plan.get("Rules", []) or []:
                    vault = r.get("TargetBackupVaultName")
                    relations.append(rel(self._vault_ref(vault), EdgeType.REFERENCES, "BACKUP_TO",
                                         description=f"rule {r.get('RuleName')} target vault"))
                    copies = []
                    for c in r.get("CopyActions", []) or []:
                        dest = c.get("DestinationBackupVaultArn")
                        cross_acct = self._cross_account(dest)
                        cross_region = bool(dest and dest.split(":")[3:4] != [self._region])
                        copies.append({"destination": dest, "cross_account": cross_acct, "cross_region": cross_region})
                        relations.append(rel(dest, EdgeType.REFERENCES, "BACKUP_TO", description=f"rule {r.get('RuleName')} copy action",
                                             cross_account=cross_acct or None, cross_region=cross_region or None))
                    rules.append({
                        "name": r.get("RuleName"),
                        "vault": vault,
                        "schedule": r.get("ScheduleExpression"),
                        "continuous": r.get("EnableContinuousBackup", False),
                        "delete_after_days": (r.get("Lifecycle") or {}).get("DeleteAfterDays"),
                        "cold_storage_after_days": (r.get("Lifecycle") or {}).get("MoveToColdStorageAfterDays"),
                        "copy_actions": copies,
                    })
                selections = []
                try:
                    async for s in self._paginate(bk, "list_backup_selections", "BackupSelectionsList", BackupPlanId=pid):
                        sel_meta: dict[str, Any] = {"name": s.get("SelectionName"), "iam_role": s.get("IamRoleArn")}
                        relations.append(rel(s.get("IamRoleArn"), EdgeType.ASSUMES_ROLE, "RUNS_ON", description="backup selection role"))
                        try:
                            full = (await bk.get_backup_selection(BackupPlanId=pid, SelectionId=s["SelectionId"])).get("BackupSelection") or {}
                        except Exception as exc:
                            logger.debug("get_backup_selection failed for %s: %s", s.get("SelectionId"), exc)
                            full = {}
                        resources = full.get("Resources", []) or []
                        sel_meta["resources"] = resources[:200]
                        sel_meta["not_resources"] = (full.get("NotResources", []) or [])[:200]
                        sel_meta["tag_conditions"] = [
                            {"type": t.get("ConditionType"), "key": t.get("ConditionKey"), "value": t.get("ConditionValue")}
                            for t in full.get("ListOfTags", []) or []
                        ]
                        sel_meta["conditions"] = full.get("Conditions") or {}
                        for res in resources:
                            if "*" not in res:
                                relations.append(rel(res, EdgeType.MANAGES, "BACKUP_TO", description=f"selection {s.get('SelectionName')}"))
                        selections.append(sel_meta)
                except Exception as exc:
                    logger.debug("Backup selections failed for %s: %s", pid, exc)
                return self._asset(
                    arn=resp.get("BackupPlanArn") or summary.get("BackupPlanArn") or self._arn("backup", f"backup-plan:{pid}"),
                    name=plan.get("BackupPlanName") or summary.get("BackupPlanName") or pid,
                    asset_type=AssetType.BACKUP_PLAN,
                    metadata={
                        "service": "backup",
                        "plan_id": pid,
                        "version_id": resp.get("VersionId"),
                        "rules": rules,
                        "selections": selections,
                        "last_execution": str(summary.get("LastExecutionDate") or "") or None,
                        "advanced_settings": [a.get("ResourceType") for a in plan.get("AdvancedBackupSettings", []) or []],
                    },
                    relations=relations,
                    aliases=[pid],
                )

            results = await gather_limited([lambda p=p: detail(p) for p in plans])
        return [a for a in results if a]

    async def _collect_backup_vaults(self) -> list[CloudAsset]:
        async with self._client("backup") as bk:
            vaults = [v async for v in self._paginate(bk, "list_backup_vaults", "BackupVaultList")]

            protected: dict[str, list[dict]] = {}
            try:
                count = 0
                async for r in self._paginate(bk, "list_protected_resources", "Results"):
                    count += 1
                    if count > _MAX_PROTECTED_RESOURCES:
                        break
                    protected.setdefault(r.get("LastBackupVaultArn") or "", []).append(r)
            except Exception as exc:
                logger.debug("list_protected_resources failed: %s", exc)

            async def detail(v: dict) -> CloudAsset:
                name, arn = v.get("BackupVaultName", ""), v.get("BackupVaultArn", "")
                relations: list[dict | None] = [rel(v.get("EncryptionKeyArn"), EdgeType.REFERENCES, "ENCRYPTED_BY_KMS")]
                public = False
                has_policy = False
                try:
                    pol = await bk.get_backup_vault_access_policy(BackupVaultName=name)
                    has_policy = bool(pol.get("Policy"))
                    for st in policy_statements(pol.get("Policy")):
                        if st.get("Effect") != "Allow":
                            continue
                        for p in policy_principals(st).get("AWS", []):
                            if p == "*":
                                public = public or not st.get("Condition")
                                continue
                            ref = principal_ref(p)
                            relations.append(rel(ref, EdgeType.GRANTS_ACCESS, "POLICY_ALLOWS_ACTION", reverse=True,
                                                 description="vault access policy", cross_account=self._cross_account(ref) or None))
                except Exception as exc:
                    if error_code(exc) not in ("ResourceNotFoundException",):
                        logger.debug("Vault policy read failed for %s: %s", name, exc)
                prot = protected.get(arn, [])
                for r in prot:
                    relations.append(rel(r.get("ResourceArn"), EdgeType.REFERENCES, "BACKUP_TO", reverse=True,
                                         description="protected resource last backed up here"))
                return self._asset(
                    arn=arn,
                    name=name,
                    asset_type=AssetType.BACKUP_VAULT,
                    metadata={
                        "service": "backup",
                        "vault_type": v.get("VaultType"),
                        "state": v.get("VaultState"),
                        "kms_key_id": v.get("EncryptionKeyArn"),
                        "recovery_points": v.get("NumberOfRecoveryPoints"),
                        "locked": v.get("Locked", False),
                        "min_retention_days": v.get("MinRetentionDays"),
                        "max_retention_days": v.get("MaxRetentionDays"),
                        "lock_date": str(v.get("LockDate") or "") or None,
                        "has_access_policy": has_policy,
                        "policy_allows_public": public,
                        "protected_resources": len(prot),
                        "protected_resource_types": sorted({r.get("ResourceType", "") for r in prot}),
                    },
                    relations=relations,
                    exposed=public,
                    aliases=[self._vault_ref(name) if self._vault_ref(name) != arn else None],
                )

            results = await gather_limited([lambda v=v: detail(v) for v in vaults])
        return [a for a in results if a]

    # ------------------------------------------------------------------
    # ECS capacity providers, container instances, Cloud Map
    # ------------------------------------------------------------------

    async def _ecs_clusters(self, ecs: Any) -> list[dict]:
        arns = [c async for c in self._paginate(ecs, "list_clusters", "clusterArns")]
        clusters: list[dict] = []
        for chunk in _chunks(arns, 100):
            clusters.extend((await ecs.describe_clusters(clusters=chunk)).get("clusters", []) or [])
        return clusters

    async def _collect_ecs_capacity_providers(self) -> list[CloudAsset]:
        assets: list[CloudAsset] = []
        async with self._client("ecs") as ecs:
            providers = [p async for p in self._pages(ecs.describe_capacity_providers, "capacityProviders",
                                                       token_in="nextToken", include=["TAGS"])]
            users: dict[str, list[str]] = {}
            try:
                for c in await self._ecs_clusters(ecs):
                    for name in c.get("capacityProviders", []) or []:
                        users.setdefault(name, []).append(c["clusterArn"])
            except Exception as exc:
                logger.debug("ECS cluster lookup for capacity providers failed: %s", exc)
        for p in providers:
            name = p.get("name", "")
            asg = p.get("autoScalingGroupProvider") or {}
            mip = p.get("managedInstancesProvider") or {}
            if not asg and not mip and name in ("FARGATE", "FARGATE_SPOT"):
                continue
            lt = mip.get("instanceLaunchTemplate") or {}
            net = lt.get("networkConfiguration") or {}
            relations: list[dict | None] = [
                rel(asg.get("autoScalingGroupArn"), EdgeType.MANAGES, "SCALES_WITH", description="managed scaling"),
                rel(mip.get("infrastructureRoleArn"), EdgeType.ASSUMES_ROLE, "RUNS_ON", description="infrastructure role"),
                rel(lt.get("ec2InstanceProfileArn"), EdgeType.REFERENCES, "RUNS_ON", description="instance profile"),
                rel(p.get("cluster"), EdgeType.CONTAINS, reverse=True),
            ]
            for carn in users.get(name, []):
                relations.append(rel(carn, EdgeType.REFERENCES, "SCALES_WITH", reverse=True, description="cluster capacity provider"))
            assets.append(
                self._asset(
                    arn=p.get("capacityProviderArn") or self._arn("ecs", f"capacity-provider/{name}"),
                    name=name,
                    asset_type=AssetType.CAPACITY_PROVIDER,
                    tags=p.get("tags"),
                    metadata={
                        "service": "ecs",
                        "status": p.get("status"),
                        "type": p.get("type"),
                        "managed_scaling": (asg.get("managedScaling") or {}).get("status"),
                        "target_capacity": (asg.get("managedScaling") or {}).get("targetCapacity"),
                        "managed_termination_protection": asg.get("managedTerminationProtection"),
                        "managed_draining": asg.get("managedDraining"),
                        "clusters": users.get(name, []),
                        "vpc_config": {"SubnetIds": net.get("subnets", []) or [], "SecurityGroupIds": net.get("securityGroups", []) or []}
                        if net else None,
                    },
                    relations=relations,
                )
            )
        return assets

    async def _collect_ecs_container_instances(self) -> list[CloudAsset]:
        """Cluster -> EC2 instance containment.

        Emitted as a relation-carrying stub of the cluster (same ARN,
        ``discovered_via`` set) so :func:`cloudg.inventory.mapper.deduplicate`
        merges the relations into the cluster asset from the ``ecs`` task.
        Container instance ARNs become aliases of the cluster.
        """
        assets: list[CloudAsset] = []
        async with self._client("ecs") as ecs:
            cluster_arns = [c async for c in self._paginate(ecs, "list_clusters", "clusterArns")]

            async def per_cluster(carn: str) -> CloudAsset | None:
                ci_arns = [c async for c in self._paginate(ecs, "list_container_instances", "containerInstanceArns", cluster=carn)]
                if not ci_arns:
                    return None
                instances: list[dict] = []
                for chunk in _chunks(ci_arns, 100):
                    instances.extend((await ecs.describe_container_instances(cluster=carn, containerInstances=chunk))
                                     .get("containerInstances", []) or [])
                relations = [
                    rel(ci.get("ec2InstanceId"), EdgeType.CONTAINS, description="ECS container instance",
                        status=ci.get("status"), agent_connected=ci.get("agentConnected"),
                        capacity_provider=ci.get("capacityProviderName"), running_tasks=ci.get("runningTasksCount"))
                    for ci in instances
                ]
                return self._asset(
                    arn=carn,
                    name=carn.rsplit("/", 1)[-1],
                    asset_type=AssetType.ECS_CLUSTER,
                    metadata={
                        "discovered_via": "ecs container instances",
                        "container_instance_ids": [ci.get("ec2InstanceId") for ci in instances],
                    },
                    relations=relations,
                    aliases=ci_arns,
                )

            results = await gather_limited([lambda c=c: per_cluster(c) for c in cluster_arns])
            assets.extend(a for a in results if a)
        return assets

    async def _collect_cloudmap(self) -> list[CloudAsset]:
        assets: list[CloudAsset] = []
        async with self._client("servicediscovery") as sd:
            namespaces = [n async for n in self._paginate(sd, "list_namespaces", "Namespaces")]
            services = [s async for s in self._paginate(sd, "list_services", "Services")]

            async def namespace_of(svc: dict) -> str | None:
                ns = (svc.get("DnsConfig") or {}).get("NamespaceId")
                if ns:
                    return ns
                return ((await sd.get_service(Id=svc["Id"])).get("Service") or {}).get("NamespaceId")

            ns_ids = await gather_limited([lambda s=s: namespace_of(s) for s in services])

        ns_arns = {n.get("Id"): n.get("Arn") for n in namespaces}
        for n in namespaces:
            ntype = n.get("Type", "")
            props = n.get("Properties") or {}
            zone = (props.get("DnsProperties") or {}).get("HostedZoneId")
            assets.append(
                self._asset(
                    arn=n.get("Arn") or self._arn("servicediscovery", f"namespace/{n.get('Id')}"),
                    name=n.get("Name", ""),
                    asset_type=AssetType.DNS_ZONE if ntype.startswith("DNS") else AssetType.SERVICE_REGISTRY,
                    metadata={
                        "service": "servicediscovery",
                        "kind": "cloudmap_namespace",
                        "namespace_id": n.get("Id"),
                        "namespace_type": ntype,
                        "hosted_zone_id": zone,
                        "http_name": (props.get("HttpProperties") or {}).get("HttpName"),
                        "service_count": n.get("ServiceCount"),
                        "owner": n.get("ResourceOwner"),
                    },
                    relations=[rel(zone, EdgeType.REFERENCES, "DNS_RESOLVED", description="Route 53 hosted zone")],
                    exposed=ntype == "DNS_PUBLIC",
                    aliases=[n.get("Id")],
                )
            )
        for svc, ns_id in zip(services, ns_ids):
            dns = svc.get("DnsConfig") or {}
            assets.append(
                self._asset(
                    arn=svc.get("Arn") or self._arn("servicediscovery", f"service/{svc.get('Id')}"),
                    name=svc.get("Name", ""),
                    asset_type=AssetType.DNS_RECORD if dns else AssetType.SERVICE_REGISTRY,
                    metadata={
                        "service": "servicediscovery",
                        "kind": "cloudmap_service",
                        "service_id": svc.get("Id"),
                        "namespace_id": ns_id,
                        "service_type": svc.get("Type"),
                        "instance_count": svc.get("InstanceCount"),
                        "dns_records": [r.get("Type") for r in dns.get("DnsRecords", []) or []],
                        "routing_policy": dns.get("RoutingPolicy"),
                        "health_check": (svc.get("HealthCheckConfig") or {}).get("Type")
                        or ("CUSTOM" if svc.get("HealthCheckCustomConfig") else None),
                    },
                    relations=[rel(ns_arns.get(ns_id) or ns_id, EdgeType.CONTAINS, reverse=True)],
                    aliases=[svc.get("Id")],
                )
            )
        return assets

    # ------------------------------------------------------------------
    # Lambda aliases
    # ------------------------------------------------------------------

    async def _collect_lambda_aliases(self) -> list[CloudAsset]:
        async with self._client("lambda") as lam:
            functions = [f async for f in self._paginate(lam, "list_functions", "Functions")]

            async def per_function(fn: dict) -> list[CloudAsset]:
                fname, farn = fn.get("FunctionName", ""), fn.get("FunctionArn", "")
                aliases = [a async for a in self._paginate(lam, "list_aliases", "Aliases", FunctionName=fname)]
                if not aliases:
                    return []
                urls: dict[str, dict] = {}
                try:
                    async for u in self._paginate(lam, "list_function_url_configs", "FunctionUrlConfigs", FunctionName=fname):
                        urls[u.get("FunctionArn", "")] = u
                except Exception as exc:
                    logger.debug("list_function_url_configs failed for %s: %s", fname, exc)
                    for a in aliases:
                        try:
                            u = await lam.get_function_url_config(FunctionName=fname, Qualifier=a["Name"])
                            urls[a.get("AliasArn", "")] = u
                        except Exception as inner:
                            if error_code(inner) != "ResourceNotFoundException":
                                logger.debug("Alias URL lookup failed for %s:%s: %s", fname, a.get("Name"), inner)
                out: list[CloudAsset] = []
                for a in aliases:
                    aname, aarn = a.get("Name", ""), a.get("AliasArn") or f"{farn}:{a.get('Name', '')}"
                    relations: list[dict | None] = [rel(farn, EdgeType.REFERENCES, "DEPENDS_ON", description=f"alias of {fname}")]
                    public_policy = False
                    try:
                        pol = await lam.get_policy(FunctionName=fname, Qualifier=aname)
                        pol_rels, public_policy = _resource_policy_relations(pol.get("Policy"), self._account_id)
                        relations.extend(pol_rels)
                    except Exception as exc:
                        if error_code(exc) != "ResourceNotFoundException":
                            logger.debug("Alias policy read failed for %s:%s: %s", fname, aname, exc)
                    url = urls.get(aarn) or {}
                    weights = (a.get("RoutingConfig") or {}).get("AdditionalVersionWeights") or {}
                    out.append(
                        self._asset(
                            arn=aarn,
                            name=f"{fname}:{aname}",
                            asset_type=AssetType.LAMBDA_FUNCTION,
                            metadata={
                                "alias": True,
                                "alias_name": aname,
                                "function_name": fname,
                                "function_arn": farn,
                                "function_version": a.get("FunctionVersion"),
                                "routing_weights": {str(k): v for k, v in weights.items()},
                                "versions": sorted({a.get("FunctionVersion", ""), *(str(k) for k in weights)} - {""}),
                                "description": a.get("Description"),
                                "function_url": url.get("FunctionUrl"),
                                "function_url_auth": url.get("AuthType"),
                                "policy_allows_public": public_policy,
                            },
                            relations=relations,
                            exposed=url.get("AuthType") == "NONE" or public_policy,
                            aliases=[url.get("FunctionUrl")],
                        )
                    )
                return out

            results = await gather_limited([lambda f=f: per_function(f) for f in functions])
        return [a for r in results for a in (r or [])]

    # ------------------------------------------------------------------
    # EventBridge Scheduler, Pipes, API destinations, archives
    # ------------------------------------------------------------------

    async def _collect_scheduler(self) -> list[CloudAsset]:
        async with self._client("scheduler") as sch:
            schedules = [s async for s in self._paginate(sch, "list_schedules", "Schedules")]

            async def detail(s: dict) -> CloudAsset:
                group = s.get("GroupName") or "default"
                full = await sch.get_schedule(Name=s["Name"], GroupName=group)
                target = full.get("Target") or {}
                tarn = target.get("Arn", "")
                ecs = target.get("EcsParameters") or {}
                universal = tarn.startswith("arn:aws:scheduler:::aws-sdk:")
                relations: list[dict | None] = [
                    rel(target.get("RoleArn"), EdgeType.ASSUMES_ROLE, "RUNS_ON", description="schedule execution role"),
                    rel((target.get("DeadLetterConfig") or {}).get("Arn"), EdgeType.REFERENCES, "WRITES_TO", description="dead-letter queue"),
                    rel(full.get("KmsKeyArn"), EdgeType.REFERENCES, "ENCRYPTED_BY_KMS"),
                ]
                if not universal:
                    relations.append(rel(tarn, EdgeType.INVOKES, "INVOKES", description="schedule target"))
                if ecs.get("TaskDefinitionArn"):
                    relations.append(rel(ecs["TaskDefinitionArn"], EdgeType.INVOKES, "INVOKES", description="runs ECS task"))
                awsvpc = (ecs.get("NetworkConfiguration") or {}).get("awsvpcConfiguration") or {}
                return self._asset(
                    arn=full.get("Arn") or s.get("Arn", ""),
                    name=s["Name"],
                    asset_type=AssetType.SCHEDULE,
                    metadata={
                        "service": "scheduler",
                        "group": group,
                        "state": full.get("State"),
                        "expression": full.get("ScheduleExpression"),
                        "timezone": full.get("ScheduleExpressionTimezone"),
                        "flexible_window": (full.get("FlexibleTimeWindow") or {}).get("Mode"),
                        "action_after_completion": full.get("ActionAfterCompletion"),
                        "target_arn": tarn,
                        "target_api": tarn.split("aws-sdk:", 1)[1] if universal else None,
                        "retry_attempts": (target.get("RetryPolicy") or {}).get("MaximumRetryAttempts"),
                        "vpc_config": {"SubnetIds": awsvpc.get("Subnets", []) or [], "SecurityGroupIds": awsvpc.get("SecurityGroups", []) or []}
                        if awsvpc else None,
                    },
                    relations=relations,
                    aliases=[f"{group}/{s['Name']}"],
                )

            results = await gather_limited([lambda s=s: detail(s) for s in schedules])
        return [a for a in results if a]

    async def _collect_pipes(self) -> list[CloudAsset]:
        async with self._client("pipes") as pipes:
            summaries = [p async for p in self._paginate(pipes, "list_pipes", "Pipes")]

            async def detail(summary: dict) -> CloudAsset:
                p = await pipes.describe_pipe(Name=summary["Name"])
                src_params = p.get("SourceParameters") or {}
                relations: list[dict | None] = [
                    rel(p.get("Source"), EdgeType.INVOKES, "TRIGGERED_BY", reverse=True, description="pipe source"),
                    rel(p.get("Enrichment"), EdgeType.INVOKES, "INVOKES", description="pipe enrichment"),
                    rel(p.get("Target"), EdgeType.INVOKES, "INVOKES", description="pipe target"),
                    rel(p.get("RoleArn"), EdgeType.ASSUMES_ROLE, "RUNS_ON", description="pipe execution role"),
                    rel(p.get("KmsKeyIdentifier"), EdgeType.REFERENCES, "ENCRYPTED_BY_KMS"),
                ]
                for block in src_params.values():
                    if not isinstance(block, dict):
                        continue
                    dlq = (block.get("DeadLetterConfig") or {}).get("Arn")
                    relations.append(rel(dlq, EdgeType.REFERENCES, "WRITES_TO", description="pipe dead-letter target"))
                    for secret in arns_in(block.get("Credentials") or {}):
                        relations.append(rel(secret, EdgeType.REFERENCES, "READS_FROM", description="source credentials"))
                logcfg = p.get("LogConfiguration") or {}
                relations.append(rel(((logcfg.get("CloudwatchLogsLogDestination") or {}).get("LogGroupArn") or "").removesuffix(":*"),
                                     EdgeType.LOGS_TO, "LOGS_TO"))
                relations.append(rel((logcfg.get("FirehoseLogDestination") or {}).get("DeliveryStreamArn"), EdgeType.LOGS_TO, "LOGS_TO"))
                relations.append(rel(_bucket_arn((logcfg.get("S3LogDestination") or {}).get("BucketName")), EdgeType.LOGS_TO, "LOGS_TO"))
                kafka_vpc = (src_params.get("SelfManagedKafkaParameters") or {}).get("Vpc") or {}
                return self._asset(
                    arn=p.get("Arn") or summary.get("Arn", ""),
                    name=p.get("Name") or summary["Name"],
                    asset_type=AssetType.EVENT_PIPE,
                    tags=p.get("Tags"),
                    metadata={
                        "service": "pipes",
                        "desired_state": p.get("DesiredState"),
                        "current_state": p.get("CurrentState"),
                        "source": p.get("Source"),
                        "enrichment": p.get("Enrichment"),
                        "target": p.get("Target"),
                        "source_type": next((k for k, v in src_params.items() if isinstance(v, dict)), None),
                        "has_filter": bool(src_params.get("FilterCriteria")),
                        "log_level": logcfg.get("Level"),
                        "vpc_config": {"SubnetIds": kafka_vpc.get("Subnets", []) or [], "SecurityGroupIds": kafka_vpc.get("SecurityGroup", []) or []}
                        if kafka_vpc else None,
                    },
                    relations=relations,
                )

            results = await gather_limited([lambda s=s: detail(s) for s in summaries])
        return [a for a in results if a]

    async def _collect_eventbridge_api_destinations(self) -> list[CloudAsset]:
        assets: list[CloudAsset] = []
        async with self._client("events") as events:
            connections = [c async for c in self._pages(events.list_connections, "Connections")]
            destinations = [d async for d in self._pages(events.list_api_destinations, "ApiDestinations")]

            async def connection(c: dict) -> CloudAsset:
                relations: list[dict | None] = []
                secret = kms = None
                private_cfg = None
                try:
                    # describe_connection returns AuthParameters; only the
                    # secret ARN / KMS key / connectivity config are kept.
                    d = await events.describe_connection(Name=c["Name"])
                    secret, kms = d.get("SecretArn"), d.get("KmsKeyIdentifier")
                    res = (d.get("InvocationConnectivityParameters") or {}).get("ResourceParameters") or {}
                    private_cfg = res.get("ResourceConfigurationArn")
                except Exception as exc:
                    logger.debug("describe_connection failed for %s: %s", c.get("Name"), exc)
                relations += [
                    rel(secret, EdgeType.REFERENCES, "READS_FROM", description="connection credentials secret"),
                    rel(kms, EdgeType.REFERENCES, "ENCRYPTED_BY_KMS"),
                    rel(private_cfg, EdgeType.REFERENCES, "DEPENDS_ON", description="private connectivity resource configuration"),
                ]
                return self._asset(
                    arn=c["ConnectionArn"],
                    name=c.get("Name", ""),
                    asset_type=AssetType.API_DESTINATION,
                    metadata={
                        "service": "events",
                        "kind": "connection",
                        "state": c.get("ConnectionState"),
                        "authorization_type": c.get("AuthorizationType"),
                        "secret_arn": secret,
                        "private": bool(private_cfg),
                    },
                    relations=relations,
                )

            conn_assets = await gather_limited([lambda c=c: connection(c) for c in connections])
            assets.extend(a for a in conn_assets if a)
        for d in destinations:
            assets.append(
                self._asset(
                    arn=d["ApiDestinationArn"],
                    name=d.get("Name", ""),
                    asset_type=AssetType.API_DESTINATION,
                    metadata={
                        "service": "events",
                        "kind": "api_destination",
                        "state": d.get("ApiDestinationState"),
                        "endpoint_host": _host(d.get("InvocationEndpoint")),
                        "http_method": d.get("HttpMethod"),
                        "rate_limit_per_second": d.get("InvocationRateLimitPerSecond"),
                    },
                    relations=[rel(d.get("ConnectionArn"), EdgeType.REFERENCES, "DEPENDS_ON", description="connection")],
                )
            )
        return assets

    async def _collect_eventbridge_archives(self) -> list[CloudAsset]:
        assets: list[CloudAsset] = []
        async with self._client("events") as events:
            async for a in self._pages(events.list_archives, "Archives"):
                name = a.get("ArchiveName", "")
                assets.append(
                    self._asset(
                        arn=self._arn("events", f"archive/{name}"),
                        name=name,
                        asset_type=AssetType.EVENT_ARCHIVE,
                        metadata={
                            "service": "events",
                            "kind": "event_archive",
                            "event_source": a.get("EventSourceArn"),
                            "state": a.get("State"),
                            "retention_days": a.get("RetentionDays"),
                            "size_bytes": a.get("SizeBytes"),
                            "event_count": a.get("EventCount"),
                        },
                        relations=[rel(a.get("EventSourceArn"), EdgeType.REFERENCES, "READS_FROM", description="archived event bus")],
                    )
                )
        return assets

    # ------------------------------------------------------------------
    # Kinesis Data Firehose
    # ------------------------------------------------------------------

    def _firehose_destination(self, dest: dict) -> tuple[list[dict | None], dict[str, Any]]:
        relations: list[dict | None] = []
        for dtype, d in dest.items():
            if not isinstance(d, dict):
                continue
            label = dtype.removesuffix("DestinationDescription") or dtype
            summary: dict[str, Any] = {"type": label}

            def common(block: dict, backup: bool = False) -> None:
                relations.append(rel(block.get("RoleARN"), EdgeType.ASSUMES_ROLE, "RUNS_ON", description=f"{label} delivery role"))
                kms = ((block.get("EncryptionConfiguration") or {}).get("KMSEncryptionConfig") or {}).get("AWSKMSKeyARN")
                relations.append(rel(kms, EdgeType.REFERENCES, "ENCRYPTED_BY_KMS"))
                logs = block.get("CloudWatchLoggingOptions") or {}
                if logs.get("Enabled") and logs.get("LogGroupName"):
                    relations.append(rel(self._log_group_arn(logs["LogGroupName"]), EdgeType.LOGS_TO, "LOGS_TO"))
                for proc in (block.get("ProcessingConfiguration") or {}).get("Processors", []) or []:
                    for param in proc.get("Parameters", []) or []:
                        if param.get("ParameterName") == "LambdaArn":
                            relations.append(rel(param.get("ParameterValue"), EdgeType.INVOKES, "INVOKES", description="record transformation"))
                secret = (block.get("SecretsManagerConfiguration") or {}).get("SecretARN")
                relations.append(rel(secret, EdgeType.REFERENCES, "READS_FROM", description=f"{label} credentials secret"))
                if block.get("BucketARN"):
                    if backup:
                        relations.append(rel(block["BucketARN"], EdgeType.REFERENCES, "BACKUP_TO", description="S3 backup / failed records"))
                    else:
                        relations.append(rel(block["BucketARN"], EdgeType.INVOKES, "STREAMS_TO", description=f"{label} destination"))
                for nested in ("S3DestinationDescription", "S3BackupDescription"):
                    if isinstance(block.get(nested), dict):
                        common(block[nested], backup=True)

            common(d)
            for key in ("DomainARN", "ClusterARN"):
                if d.get(key):
                    relations.append(rel(d[key], EdgeType.INVOKES, "STREAMS_TO", description=f"{label} destination"))
            catalog = (d.get("CatalogConfiguration") or {}).get("CatalogARN")
            relations.append(rel(catalog, EdgeType.INVOKES, "STREAMS_TO", description="Iceberg catalog"))
            if d.get("ClusterJDBCURL"):
                host = _host(d["ClusterJDBCURL"].replace("jdbc:redshift://", "https://"))
                summary["endpoint_host"] = host
                if host and ".redshift." in host:
                    relations.append(rel(host.split(".", 1)[0], EdgeType.INVOKES, "STREAMS_TO", description="Redshift destination"))
            if d.get("CollectionEndpoint"):
                host = _host(d["CollectionEndpoint"])
                summary["endpoint_host"] = host
                if host:
                    relations.append(rel(self._arn("aoss", f"collection/{host.split('.', 1)[0]}"), EdgeType.INVOKES, "STREAMS_TO",
                                         description="OpenSearch Serverless destination"))
            if d.get("ClusterEndpoint"):
                summary["endpoint_host"] = _host(d["ClusterEndpoint"])
            # Splunk: endpoint host only, never the HEC token
            if d.get("HECEndpoint"):
                summary["endpoint_host"] = _host(d["HECEndpoint"])
            endpoint = d.get("EndpointConfiguration") or {}
            if endpoint.get("Url"):
                summary["endpoint_host"] = _host(endpoint["Url"])
                summary["endpoint_name"] = endpoint.get("Name")
            if d.get("AccountUrl"):
                summary["endpoint_host"] = _host(d["AccountUrl"])
            vpc = d.get("VpcConfigurationDescription") or {}
            if vpc:
                summary["vpc_config"] = {"SubnetIds": vpc.get("SubnetIds", []) or [], "SecurityGroupIds": vpc.get("SecurityGroupIds", []) or []}
            summary["backup_mode"] = d.get("S3BackupMode")
            return relations, {k: v for k, v in summary.items() if v is not None}
        return relations, {}

    async def _collect_firehose(self) -> list[CloudAsset]:
        async with self._client("firehose") as fh:
            # No botocore paginator: list_delivery_streams pages by name
            names: list[str] = []
            start: str | None = None
            for _ in range(1000):
                kwargs: dict[str, Any] = {"Limit": 100}
                if start:
                    kwargs["ExclusiveStartDeliveryStreamName"] = start
                resp = await fh.list_delivery_streams(**kwargs)
                page = resp.get("DeliveryStreamNames", []) or []
                names.extend(page)
                if not resp.get("HasMoreDeliveryStreams") or not page:
                    break
                start = page[-1]

            async def detail(name: str) -> CloudAsset:
                desc = (await fh.describe_delivery_stream(DeliveryStreamName=name))["DeliveryStreamDescription"]
                relations: list[dict | None] = []
                source = desc.get("Source") or {}
                kin = source.get("KinesisStreamSourceDescription") or {}
                msk = source.get("MSKSourceDescription") or {}
                db = source.get("DatabaseSourceDescription") or {}
                relations += [
                    rel(kin.get("KinesisStreamARN"), EdgeType.INVOKES, "TRIGGERED_BY", reverse=True, description="Kinesis source"),
                    rel(kin.get("RoleARN"), EdgeType.ASSUMES_ROLE, "RUNS_ON", description="source read role"),
                    rel(msk.get("MSKClusterARN"), EdgeType.INVOKES, "TRIGGERED_BY", reverse=True, description=f"MSK source {msk.get('TopicName') or ''}".strip()),
                    rel((msk.get("AuthenticationConfiguration") or {}).get("RoleARN"), EdgeType.ASSUMES_ROLE, "RUNS_ON", description="MSK connectivity role"),
                    rel((((db.get("DatabaseSourceAuthenticationConfiguration") or {}).get("SecretsManagerConfiguration")) or {}).get("SecretARN"),
                        EdgeType.REFERENCES, "READS_FROM", description="database source credentials"),
                ]
                enc = desc.get("DeliveryStreamEncryptionConfiguration") or {}
                relations.append(rel(enc.get("KeyARN"), EdgeType.REFERENCES, "ENCRYPTED_BY_KMS"))
                destinations = []
                vpc_config = None
                for dest in desc.get("Destinations", []) or []:
                    d_rels, d_summary = self._firehose_destination(dest)
                    relations.extend(d_rels)
                    vpc_config = vpc_config or d_summary.pop("vpc_config", None)
                    destinations.append(d_summary)
                source_type = desc.get("DeliveryStreamType")
                return self._asset(
                    arn=desc.get("DeliveryStreamARN") or self._arn("firehose", f"deliverystream/{name}"),
                    name=name,
                    asset_type=AssetType.DELIVERY_STREAM,
                    metadata={
                        "service": "firehose",
                        "status": desc.get("DeliveryStreamStatus"),
                        "source_type": source_type,
                        "source_database_host": _host(db.get("Endpoint")) if db else None,
                        "destinations": destinations,
                        "encryption": enc.get("Status"),
                        "encryption_key_type": enc.get("KeyType"),
                        "vpc_config": vpc_config,
                    },
                    relations=relations,
                )

            results = await gather_limited([lambda n=n: detail(n) for n in names])
        return [a for a in results if a]

    # ------------------------------------------------------------------
    # CloudWatch Logs: subscriptions, destinations, resource policies, OAM
    # ------------------------------------------------------------------

    def _subscription_relations(self, destination: Any, role: Any, label: str) -> list[dict | None]:
        return [
            rel(destination, EdgeType.INVOKES, "STREAMS_TO", description=label,
                cross_account=self._cross_account(destination) or None),
            rel(role, EdgeType.ASSUMES_ROLE, "RUNS_ON", description="subscription delivery role"),
        ]

    async def _collect_log_subscriptions(self) -> list[CloudAsset]:
        assets: list[CloudAsset] = []
        async with self._client("logs") as logs:
            try:
                async for pol in self._pages(logs.describe_account_policies, "accountPolicies",
                                             token_in="nextToken", policyType="SUBSCRIPTION_FILTER_POLICY"):
                    doc: dict[str, Any] = {}
                    try:
                        doc = json.loads(pol.get("policyDocument") or "{}")
                    except ValueError:
                        pass
                    name = pol.get("policyName", "")
                    assets.append(
                        self._asset(
                            arn=f"cloudg:aws:logs:{self._region}:{pol.get('accountId') or self._account_id}:account-policy/subscription/{name}",
                            name=f"account subscription policy {name}",
                            asset_type=AssetType.LOG_SINK,
                            metadata={
                                "service": "logs",
                                "kind": "account_subscription_policy",
                                "scope": pol.get("scope"),
                                "selection_criteria": pol.get("selectionCriteria"),
                                "destination_arn": doc.get("DestinationArn"),
                                "filter_pattern": doc.get("FilterPattern"),
                                "distribution": doc.get("Distribution"),
                            },
                            relations=self._subscription_relations(doc.get("DestinationArn"), doc.get("RoleArn"), "account-wide subscription"),
                        )
                    )
            except Exception as exc:
                logger.debug("describe_account_policies failed: %s", exc)

            groups: list[str] = []
            async for g in self._paginate(logs, "describe_log_groups", "logGroups"):
                groups.append(g["logGroupName"])
                if len(groups) >= _MAX_LOG_GROUPS_FOR_FILTERS:
                    break

            async def filters_for(group: str) -> list[CloudAsset]:
                out: list[CloudAsset] = []
                group_arn = self._log_group_arn(group)
                async for f in self._paginate(logs, "describe_subscription_filters", "subscriptionFilters", logGroupName=group):
                    fname = f.get("filterName", "")
                    out.append(
                        self._asset(
                            arn=f"{group_arn}:subscription-filter:{fname}",
                            name=f"{group} -> {fname}",
                            asset_type=AssetType.LOG_SINK,
                            metadata={
                                "service": "logs",
                                "kind": "subscription_filter",
                                "log_group": group,
                                "destination_arn": f.get("destinationArn"),
                                "filter_pattern": f.get("filterPattern"),
                                "distribution": f.get("distribution"),
                            },
                            relations=[
                                rel(group_arn, EdgeType.INVOKES, "STREAMS_TO", reverse=True, description="subscribed log group"),
                                *self._subscription_relations(f.get("destinationArn"), f.get("roleArn"), "subscription destination"),
                            ],
                        )
                    )
                return out

            results = await gather_limited([lambda g=g: filters_for(g) for g in groups])
            for r in results:
                assets.extend(r or [])
        return assets

    async def _collect_log_destinations(self) -> list[CloudAsset]:
        assets: list[CloudAsset] = []
        async with self._client("logs") as logs:
            async for d in self._paginate(logs, "describe_destinations", "destinations"):
                pol_relations: list[dict | None] = []
                public = False
                for st in policy_statements(d.get("accessPolicy")):
                    if st.get("Effect") != "Allow":
                        continue
                    for p in policy_principals(st).get("AWS", []):
                        if p == "*":
                            public = public or not st.get("Condition")
                            continue
                        ref = principal_ref(p)
                        pol_relations.append(rel(ref, EdgeType.GRANTS_ACCESS, "POLICY_ALLOWS_ACTION", reverse=True,
                                                 description="may subscribe log groups", cross_account=self._cross_account(ref) or None))
                assets.append(
                    self._asset(
                        arn=d.get("arn") or self._arn("logs", f"destination:{d.get('destinationName')}"),
                        name=d.get("destinationName", ""),
                        asset_type=AssetType.LOG_SINK,
                        metadata={
                            "service": "logs",
                            "kind": "log_destination",
                            "target_arn": d.get("targetArn"),
                            "policy_allows_public": public,
                            "org_condition": condition_values(
                                next(iter(policy_statements(d.get("accessPolicy"))), {}), "aws:PrincipalOrgID"),
                        },
                        relations=[
                            *self._subscription_relations(d.get("targetArn"), d.get("roleArn"), "destination target"),
                            *pol_relations,
                        ],
                        exposed=public,
                    )
                )
            try:
                async for p in self._paginate(logs, "describe_resource_policies", "resourcePolicies"):
                    name = p.get("policyName", "")
                    services: set[str] = set()
                    relations: list[dict | None] = []
                    for st in policy_statements(p.get("policyDocument")):
                        if st.get("Effect") != "Allow":
                            continue
                        principals = policy_principals(st)
                        services.update(principals.get("Service", []))
                        for p_ref in principals.get("AWS", []):
                            if p_ref != "*":
                                relations.append(rel(principal_ref(p_ref), EdgeType.GRANTS_ACCESS, "POLICY_ALLOWS_ACTION", reverse=True,
                                                     cross_account=self._cross_account(principal_ref(p_ref)) or None))
                        for res in _resource_list(st.get("Resource")):
                            if res.startswith("arn:") and "*" not in res.split("log-group:", 1)[-1]:
                                relations.append(rel(res.removesuffix(":*"), EdgeType.REFERENCES, "WRITES_TO", description="policy resource"))
                    relations.append(rel(p.get("resourceArn"), EdgeType.REFERENCES, "DEPENDS_ON", description="policy attached to"))
                    assets.append(
                        self._asset(
                            arn=f"cloudg:aws:logs:{self._region}:{self._account_id}:resource-policy/{name}",
                            name=f"logs resource policy {name}",
                            asset_type=AssetType.IAM_POLICY,
                            metadata={
                                "service": "logs",
                                "kind": "logs_resource_policy",
                                "scope": p.get("policyScope"),
                                "service_principals": sorted(services),
                            },
                            relations=relations,
                        )
                    )
            except Exception as exc:
                logger.debug("describe_resource_policies failed: %s", exc)
        return assets

    async def _collect_oam(self) -> list[CloudAsset]:
        assets: list[CloudAsset] = []
        async with self._client("oam") as oam:
            sinks = [s async for s in self._paginate(oam, "list_sinks", "Items")]
            links = [link async for link in self._paginate(oam, "list_links", "Items")]

            async def sink(s: dict) -> CloudAsset:
                relations: list[dict | None] = []
                orgs: list[str] = []
                try:
                    pol = await oam.get_sink_policy(SinkIdentifier=s["Arn"])
                    for st in policy_statements(pol.get("Policy")):
                        if st.get("Effect") != "Allow":
                            continue
                        orgs += condition_values(st, "aws:PrincipalOrgID", "aws:PrincipalOrgPaths")
                        for p in policy_principals(st).get("AWS", []):
                            if p != "*":
                                ref = principal_ref(p)
                                relations.append(rel(ref, EdgeType.GRANTS_ACCESS, "POLICY_ALLOWS_ACTION", reverse=True,
                                                     description="source account may link", cross_account=self._cross_account(ref) or None))
                except Exception as exc:
                    if error_code(exc) != "ResourceNotFoundException":
                        logger.debug("OAM sink policy read failed for %s: %s", s.get("Arn"), exc)
                return self._asset(
                    arn=s["Arn"],
                    name=s.get("Name") or s.get("Id", ""),
                    asset_type=AssetType.LOG_SINK,
                    metadata={"service": "oam", "kind": "oam_sink", "monitoring_account": True, "allowed_org_ids": orgs},
                    relations=relations,
                    aliases=[s.get("Id")],
                )

            sink_assets = await gather_limited([lambda s=s: sink(s) for s in sinks])
            assets.extend(a for a in sink_assets if a)
        for link in links:
            sink_arn = link.get("SinkArn")
            assets.append(
                self._asset(
                    arn=link["Arn"],
                    name=link.get("Label") or link.get("Id", ""),
                    asset_type=AssetType.LOG_SINK,
                    metadata={
                        "service": "oam",
                        "kind": "oam_link",
                        "sink_arn": sink_arn,
                        "monitoring_account_id": _arn_account(sink_arn),
                        "resource_types": link.get("ResourceTypes", []),
                    },
                    relations=[rel(sink_arn, EdgeType.INVOKES, "STREAMS_TO", description="shares telemetry with monitoring account",
                                   cross_account=self._cross_account(sink_arn) or None)],
                )
            )
        return assets

    # ------------------------------------------------------------------
    # AWS Batch
    # ------------------------------------------------------------------

    def _batch_container_relations(self, c: dict, label: str) -> tuple[list[dict | None], dict[str, Any]]:
        relations: list[dict | None] = []
        image = c.get("image")
        repo = _ecr_repo(image)
        if repo:
            relations.append(rel(repo, EdgeType.USES_IMAGE, "RUNS_ON", description=f"{label} image {image}"))
        relations.append(rel(c.get("jobRoleArn"), EdgeType.ASSUMES_ROLE, "RUNS_ON", description="job role"))
        relations.append(rel(c.get("executionRoleArn"), EdgeType.ASSUMES_ROLE, "RUNS_ON", description="execution role"))
        secrets = list(c.get("secrets", []) or []) + list(((c.get("logConfiguration") or {}).get("secretOptions")) or [])
        for s in secrets:
            relations.append(rel(self._secret_or_param_ref(s.get("valueFrom"), "parameter"), EdgeType.REFERENCES, "READS_FROM",
                                 description=f"secret {s.get('name')}"))
        cred = (c.get("repositoryCredentials") or {}).get("credentialsParameter")
        relations.append(rel(self._secret_or_param_ref(cred, "secret"), EdgeType.REFERENCES, "READS_FROM", description="registry credentials"))
        relations += self._env_relations(c.get("environment") or c.get("env"), "environment reference")
        log_cfg = c.get("logConfiguration") or {}
        group = (log_cfg.get("options") or {}).get("awslogs-group")
        if log_cfg.get("logDriver") == "awslogs" and group:
            relations.append(rel(self._log_group_arn(group, (log_cfg.get("options") or {}).get("awslogs-region")), EdgeType.LOGS_TO, "LOGS_TO"))
        for vol in c.get("volumes", []) or []:
            fs = (vol.get("efsVolumeConfiguration") or {}).get("fileSystemId")
            relations.append(rel(fs, EdgeType.REFERENCES, "READS_FROM", description=f"EFS volume {vol.get('name')}"))
        summary = {
            "image": image,
            "environment_variable_names": _env_names(c.get("environment") or c.get("env")),
            "secret_names": sorted(str(s.get("name")) for s in c.get("secrets", []) or []),
            "privileged": c.get("privileged") or ((c.get("securityContext") or {}).get("privileged")),
        }
        return relations, summary

    async def _collect_batch(self) -> list[CloudAsset]:
        assets: list[CloudAsset] = []
        async with self._client("batch") as batch:
            envs = [e async for e in self._paginate(batch, "describe_compute_environments", "computeEnvironments")]
            queues = [q async for q in self._paginate(batch, "describe_job_queues", "jobQueues")]
            latest: dict[str, dict] = {}
            revisions: dict[str, int] = {}
            try:
                async for jd in self._paginate(batch, "describe_job_definitions", "jobDefinitions", status="ACTIVE"):
                    name = jd.get("jobDefinitionName", "")
                    revisions[name] = revisions.get(name, 0) + 1
                    if name not in latest or jd.get("revision", 0) > latest[name].get("revision", 0):
                        latest[name] = jd
            except Exception as exc:
                logger.debug("describe_job_definitions failed: %s", exc)

        for ce in envs:
            cr = ce.get("computeResources") or {}
            lt = cr.get("launchTemplate") or {}
            relations: list[dict | None] = [
                rel(ce.get("ecsClusterArn"), EdgeType.MANAGES, description="managed ECS cluster"),
                rel((ce.get("eksConfiguration") or {}).get("eksClusterArn"), EdgeType.REFERENCES, "RUNS_ON", description="EKS cluster"),
                rel(self._role_ref(ce.get("serviceRole")), EdgeType.ASSUMES_ROLE, "RUNS_ON", description="Batch service role"),
                rel(self._instance_profile_ref(cr.get("instanceRole")), EdgeType.REFERENCES, "RUNS_ON", description="instance profile"),
                rel(self._role_ref(cr.get("spotIamFleetRole")), EdgeType.ASSUMES_ROLE, "RUNS_ON", description="spot fleet role"),
                rel(lt.get("launchTemplateId") or lt.get("launchTemplateName"), EdgeType.REFERENCES, "DEPENDS_ON", description="launch template"),
            ]
            assets.append(
                self._asset(
                    arn=ce["computeEnvironmentArn"],
                    name=ce.get("computeEnvironmentName", ""),
                    asset_type=AssetType.BATCH_ENVIRONMENT,
                    tags=ce.get("tags"),
                    metadata={
                        "service": "batch",
                        "type": ce.get("type"),
                        "state": ce.get("state"),
                        "status": ce.get("status"),
                        "orchestration": ce.get("containerOrchestrationType"),
                        "resource_type": cr.get("type"),
                        "allocation_strategy": cr.get("allocationStrategy"),
                        "max_vcpus": cr.get("maxvCpus"),
                        "instance_types": cr.get("instanceTypes", []),
                        "image_id": cr.get("imageId"),
                        "ec2_key_pair": cr.get("ec2KeyPair"),
                        "vpc_config": {"SubnetIds": cr.get("subnets", []) or [], "SecurityGroupIds": cr.get("securityGroupIds", []) or []}
                        if cr else None,
                    },
                    relations=relations,
                )
            )
        for q in queues:
            relations = [
                rel(o.get("computeEnvironment"), EdgeType.REFERENCES, "RUNS_ON", description=f"compute environment order {o.get('order')}")
                for o in q.get("computeEnvironmentOrder", []) or []
            ]
            relations += [
                rel(o.get("serviceEnvironment"), EdgeType.REFERENCES, "RUNS_ON", description="service environment")
                for o in q.get("serviceEnvironmentOrder", []) or []
            ]
            relations.append(rel(q.get("schedulingPolicyArn"), EdgeType.REFERENCES, "DEPENDS_ON", description="scheduling policy"))
            assets.append(
                self._asset(
                    arn=q["jobQueueArn"],
                    name=q.get("jobQueueName", ""),
                    asset_type=AssetType.JOB_QUEUE,
                    tags=q.get("tags"),
                    metadata={
                        "service": "batch",
                        "state": q.get("state"),
                        "status": q.get("status"),
                        "priority": q.get("priority"),
                        "queue_type": q.get("jobQueueType"),
                    },
                    relations=relations,
                )
            )
        for name, jd in latest.items():
            relations = []
            containers: list[dict] = []
            blocks: list[tuple[dict, str]] = []
            if jd.get("containerProperties"):
                blocks.append((jd["containerProperties"], "container"))
            for nr in ((jd.get("nodeProperties") or {}).get("nodeRangeProperties") or []):
                if nr.get("container"):
                    blocks.append((nr["container"], f"node {nr.get('targetNodes')}"))
                for tp in ((nr.get("ecsProperties") or {}).get("taskProperties") or []):
                    blocks.extend((c, f"node container {c.get('name')}") for c in tp.get("containers", []) or [])
            for tp in ((jd.get("ecsProperties") or {}).get("taskProperties") or []):
                relations.append(rel(tp.get("taskRoleArn"), EdgeType.ASSUMES_ROLE, "RUNS_ON", description="task role"))
                relations.append(rel(tp.get("executionRoleArn"), EdgeType.ASSUMES_ROLE, "RUNS_ON", description="execution role"))
                for vol in tp.get("volumes", []) or []:
                    fs = (vol.get("efsVolumeConfiguration") or {}).get("fileSystemId")
                    relations.append(rel(fs, EdgeType.REFERENCES, "READS_FROM", description=f"EFS volume {vol.get('name')}"))
                blocks.extend((c, f"container {c.get('name')}") for c in tp.get("containers", []) or [])
            pod = (jd.get("eksProperties") or {}).get("podProperties") or {}
            blocks.extend((c, f"pod container {c.get('name')}") for c in (pod.get("containers") or []) + (pod.get("initContainers") or []))
            for block, label in blocks:
                c_rels, c_summary = self._batch_container_relations(block, label)
                relations.extend(c_rels)
                containers.append({"name": block.get("name") or label, **{k: v for k, v in c_summary.items() if v}})
            arn = jd["jobDefinitionArn"]
            assets.append(
                self._asset(
                    arn=arn,
                    name=name,
                    asset_type=AssetType.JOB_DEFINITION,
                    tags=jd.get("tags"),
                    metadata={
                        "service": "batch",
                        "type": jd.get("type"),
                        "revision": jd.get("revision"),
                        "active_revisions": revisions.get(name, 1),
                        "platform_capabilities": jd.get("platformCapabilities", []),
                        "orchestration": jd.get("containerOrchestrationType"),
                        "containers": containers,
                        "service_account": pod.get("serviceAccountName"),
                        "parameter_names": sorted(jd.get("parameters") or {}),
                    },
                    relations=relations,
                    aliases=[arn.rsplit(":", 1)[0] if arn.rsplit(":", 1)[-1].isdigit() else None],
                )
            )
        return assets

    # ------------------------------------------------------------------
    # App Runner
    # ------------------------------------------------------------------

    async def _collect_apprunner(self) -> list[CloudAsset]:
        assets: list[CloudAsset] = []
        async with self._client("apprunner") as ar:
            summaries = [s async for s in self._pages(ar.list_services, "ServiceSummaryList")]
            connectors: dict[str, dict] = {}
            try:
                async for c in self._pages(ar.list_vpc_connectors, "VpcConnectors"):
                    connectors[c["VpcConnectorArn"]] = c
            except Exception as exc:
                logger.debug("list_vpc_connectors failed: %s", exc)

            async def detail(s: dict) -> CloudAsset:
                svc = (await ar.describe_service(ServiceArn=s["ServiceArn"]))["Service"]
                src = svc.get("SourceConfiguration") or {}
                img = src.get("ImageRepository") or {}
                code = src.get("CodeRepository") or {}
                auth = src.get("AuthenticationConfiguration") or {}
                net = svc.get("NetworkConfiguration") or {}
                egress = net.get("EgressConfiguration") or {}
                relations: list[dict | None] = [
                    rel((svc.get("InstanceConfiguration") or {}).get("InstanceRoleArn"), EdgeType.ASSUMES_ROLE, "RUNS_ON", description="instance role"),
                    rel(auth.get("AccessRoleArn"), EdgeType.ASSUMES_ROLE, "RUNS_ON", description="ECR access role"),
                    rel(auth.get("ConnectionArn"), EdgeType.REFERENCES, "READS_FROM", description="source connection"),
                    rel((svc.get("EncryptionConfiguration") or {}).get("KmsKey"), EdgeType.REFERENCES, "ENCRYPTED_BY_KMS"),
                    rel(egress.get("VpcConnectorArn"), EdgeType.REFERENCES, "DEPENDS_ON", description="VPC connector"),
                    rel(self._log_group_arn(f"/aws/apprunner/{svc.get('ServiceName')}/{svc.get('ServiceId')}/application"),
                        EdgeType.LOGS_TO, "LOGS_TO"),
                ]
                image = img.get("ImageIdentifier")
                if image and img.get("ImageRepositoryType") == "ECR":
                    relations.append(rel(image_repository(image), EdgeType.USES_IMAGE, "RUNS_ON", description=f"runs {image}"))
                env_names: list[str] = []
                secret_names: list[str] = []
                cfgs = [img.get("ImageConfiguration") or {},
                        ((code.get("CodeConfiguration") or {}).get("CodeConfigurationValues")) or {}]
                for cfg in cfgs:
                    env = cfg.get("RuntimeEnvironmentVariables") or {}
                    env_names += sorted(env)
                    relations += self._env_relations(env, "environment reference")
                    for sname, ref in (cfg.get("RuntimeEnvironmentSecrets") or {}).items():
                        secret_names.append(sname)
                        relations.append(rel(self._secret_or_param_ref(ref, "parameter"), EdgeType.REFERENCES, "READS_FROM",
                                             description=f"secret {sname}"))
                connector = connectors.get(egress.get("VpcConnectorArn") or "") or {}
                public = (net.get("IngressConfiguration") or {}).get("IsPubliclyAccessible", True)
                return self._asset(
                    arn=svc["ServiceArn"],
                    name=svc.get("ServiceName", ""),
                    asset_type=AssetType.APP_SERVICE,
                    metadata={
                        "service": "apprunner",
                        "platform": "apprunner",
                        "status": svc.get("Status"),
                        "service_url": svc.get("ServiceUrl"),
                        "source_type": "image" if img else "code",
                        "image": image,
                        "image_repository_type": img.get("ImageRepositoryType"),
                        "repository_url": _clean_url(code.get("RepositoryUrl")),
                        "auto_deployments": src.get("AutoDeploymentsEnabled"),
                        "cpu": (svc.get("InstanceConfiguration") or {}).get("Cpu"),
                        "memory": (svc.get("InstanceConfiguration") or {}).get("Memory"),
                        "egress_type": egress.get("EgressType"),
                        "publicly_accessible": public,
                        "environment_variable_names": env_names,
                        "secret_names": sorted(secret_names),
                        "vpc_config": {"SubnetIds": connector.get("Subnets", []) or [], "SecurityGroupIds": connector.get("SecurityGroups", []) or []}
                        if connector else None,
                    },
                    relations=relations,
                    exposed=bool(public),
                    aliases=[svc.get("ServiceUrl"), svc.get("ServiceId")],
                )

            results = await gather_limited([lambda s=s: detail(s) for s in summaries])
            assets.extend(a for a in results if a)
        for c in connectors.values():
            assets.append(
                self._asset(
                    arn=c["VpcConnectorArn"],
                    name=c.get("VpcConnectorName", ""),
                    asset_type=AssetType.VPC_LINK,
                    metadata={
                        "service": "apprunner",
                        "kind": "vpc_connector",
                        "status": c.get("Status"),
                        "revision": c.get("VpcConnectorRevision"),
                        "vpc_config": {"SubnetIds": c.get("Subnets", []) or [], "SecurityGroupIds": c.get("SecurityGroups", []) or []},
                    },
                )
            )
        return assets

    # ------------------------------------------------------------------
    # Elastic Beanstalk
    # ------------------------------------------------------------------

    async def _collect_elasticbeanstalk(self) -> list[CloudAsset]:
        assets: list[CloudAsset] = []
        async with self._client("elasticbeanstalk") as eb:
            apps = (await eb.describe_applications()).get("Applications", []) or []
            envs = [e async for e in self._paginate(eb, "describe_environments", "Environments", IncludeDeleted=False)]

            async def detail(env: dict) -> CloudAsset:
                name, app = env.get("EnvironmentName", ""), env.get("ApplicationName", "")
                relations: list[dict | None] = [
                    rel(self._arn("elasticbeanstalk", f"application/{app}"), EdgeType.CONTAINS, reverse=True),
                    rel(env.get("OperationsRole"), EdgeType.ASSUMES_ROLE, "RUNS_ON", description="operations role"),
                ]
                resources: dict[str, Any] = {}
                try:
                    ident = {"EnvironmentId": env["EnvironmentId"]} if env.get("EnvironmentId") else {"EnvironmentName": name}
                    res = (await eb.describe_environment_resources(**ident)).get("EnvironmentResources") or {}
                    for key, field, label in (
                        ("AutoScalingGroups", "Name", "auto scaling group"),
                        ("Instances", "Id", "instance"),
                        ("LaunchTemplates", "Id", "launch template"),
                        ("LaunchConfigurations", "Name", "launch configuration"),
                        ("LoadBalancers", "Name", "load balancer"),
                        ("Queues", "URL", "worker queue"),
                    ):
                        ids = [r.get(field) for r in res.get(key, []) or [] if r.get(field)]
                        resources[key] = ids
                        relations.extend(rel(i, EdgeType.MANAGES, description=f"environment {label}") for i in ids)
                except Exception as exc:
                    logger.debug("describe_environment_resources failed for %s: %s", name, exc)
                options: dict[tuple[str, str], str] = {}
                env_var_names: list[str] = []
                try:
                    cfg = await eb.describe_configuration_settings(ApplicationName=app, EnvironmentName=name)
                    for setting in (cfg.get("ConfigurationSettings") or [{}])[0].get("OptionSettings", []) or []:
                        ns, opt = setting.get("Namespace", ""), setting.get("OptionName", "")
                        if ns == "aws:elasticbeanstalk:application:environment":
                            env_var_names.append(opt)  # never the value
                            continue
                        if setting.get("Value") is not None:
                            options[(ns, opt)] = str(setting["Value"])
                except Exception as exc:
                    logger.debug("describe_configuration_settings failed for %s: %s", name, exc)
                service_role = options.get(("aws:elasticbeanstalk:environment", "ServiceRole"))
                profile = options.get(("aws:autoscaling:launchconfiguration", "IamInstanceProfile"))
                relations.append(rel(self._role_ref(service_role), EdgeType.ASSUMES_ROLE, "RUNS_ON", description="service role"))
                relations.append(rel(self._instance_profile_ref(profile), EdgeType.REFERENCES, "RUNS_ON", description="instance profile"))

                def split(value: str | None) -> list[str]:
                    return [v.strip() for v in (value or "").split(",") if v.strip()]

                sgs = [s for s in split(options.get(("aws:autoscaling:launchconfiguration", "SecurityGroups"))) if s.startswith("sg-")]
                subnets = split(options.get(("aws:ec2:vpc", "Subnets")))
                elb_subnets = split(options.get(("aws:ec2:vpc", "ELBSubnets")))
                scheme = options.get(("aws:ec2:vpc", "ELBScheme"), "public")
                env_type = options.get(("aws:elasticbeanstalk:environment", "EnvironmentType"))
                tier = (env.get("Tier") or {}).get("Name")
                exposed = tier == "WebServer" and scheme != "internal" and (
                    env_type != "SingleInstance" or options.get(("aws:ec2:vpc", "AssociatePublicIpAddress"), "true") != "false"
                )
                for link in env.get("EnvironmentLinks", []) or []:
                    relations.append(rel(self._arn("elasticbeanstalk", f"environment/{app}/{link.get('EnvironmentName')}"),
                                         EdgeType.REFERENCES, "DEPENDS_ON", description=f"environment link {link.get('LinkName')}"))
                return self._asset(
                    arn=env.get("EnvironmentArn") or self._arn("elasticbeanstalk", f"environment/{app}/{name}"),
                    name=name,
                    asset_type=AssetType.APP_SERVICE,
                    metadata={
                        "service": "elasticbeanstalk",
                        "kind": "environment",
                        "application": app,
                        "environment_id": env.get("EnvironmentId"),
                        "platform": env.get("PlatformArn") or env.get("SolutionStackName"),
                        "solution_stack": env.get("SolutionStackName"),
                        "tier": tier,
                        "environment_type": env_type,
                        "status": env.get("Status"),
                        "health": env.get("Health"),
                        "version_label": env.get("VersionLabel"),
                        "cname": env.get("CNAME"),
                        "endpoint": env.get("EndpointURL"),
                        "load_balancer_type": options.get(("aws:elasticbeanstalk:environment", "LoadBalancerType")),
                        "elb_scheme": scheme,
                        "vpc_id": options.get(("aws:ec2:vpc", "VPCId")),
                        "security_groups": sgs,
                        "vpc_config": {"SubnetIds": sorted(set(subnets + elb_subnets)), "SecurityGroupIds": []} if subnets or elb_subnets else None,
                        "service_role": service_role,
                        "instance_profile": profile,
                        "environment_variable_names": sorted(env_var_names),
                        "managed_resources": resources,
                    },
                    relations=relations,
                    exposed=exposed,
                    aliases=[env.get("EnvironmentId"), env.get("CNAME"), env.get("EndpointURL")],
                )

            results = await gather_limited([lambda e=e: detail(e) for e in envs])
            assets.extend(a for a in results if a)
        for app in apps:
            aname = app.get("ApplicationName", "")
            assets.append(
                self._asset(
                    arn=app.get("ApplicationArn") or self._arn("elasticbeanstalk", f"application/{aname}"),
                    name=aname,
                    asset_type=AssetType.APP_SERVICE,
                    metadata={
                        "service": "elasticbeanstalk",
                        "kind": "application",
                        "platform": "elasticbeanstalk",
                        "versions": len(app.get("Versions", []) or []),
                        "configuration_templates": app.get("ConfigurationTemplates", []),
                        "service_role": ((app.get("ResourceLifecycleConfig") or {}).get("ServiceRole")),
                    },
                    relations=[rel((app.get("ResourceLifecycleConfig") or {}).get("ServiceRole"), EdgeType.ASSUMES_ROLE, "RUNS_ON",
                                   description="version lifecycle role")],
                )
            )
        return assets

