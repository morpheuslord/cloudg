"""CodeBuild (service role, VPC, source, ECR image, parameter/secret
references) and CodeDeploy deployment groups (ASGs, ECS services, target
groups, triggers, alarms)."""

from __future__ import annotations

from typing import Any

from cloudg.inventory.aws_services._base import gather_limited, rel
from cloudg.inventory.aws_services.application._common import (
    ApplicationBase,
    _bucket_arn,
    _chunks,
    _clean_url,
    _ecr_repo,
    _role_rel,
    _vpc_config,
    logger,
)
from cloudg.schema.models import AssetType, CloudAsset, EdgeType

# CodeBuild environment variable type -> (reference kind, store label)
_CODEBUILD_SECRET_TYPES = {
    "PARAMETER_STORE": ("parameter", "Parameter Store"),
    "SECRETS_MANAGER": ("secret", "Secrets Manager"),
}


def _tag_filter(f: dict) -> dict[str, Any]:
    return {"key": f.get("Key"), "value": f.get("Value"), "type": f.get("Type")}


class BuildDeployCollectorsMixin(ApplicationBase):
    """CodeBuild and CodeDeploy collectors."""

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
            out.append(
                rel(
                    self._arn("codecommit", loc.rsplit("/repos/", 1)[1].strip("/")),
                    EdgeType.REFERENCES,
                    "READS_FROM",
                    description=label,
                )
            )
        auth_res = (source.get("auth") or {}).get("resource")
        if isinstance(auth_res, str) and auth_res.startswith("arn:"):
            out.append(
                rel(auth_res, EdgeType.REFERENCES, "READS_FROM", description=f"{label} credentials")
            )
        return out

    def _codebuild_role_relations(self, proj: dict) -> list[dict | None]:
        """Roles, KMS key and every source of a build project."""
        relations: list[dict | None] = [
            _role_rel(proj.get("serviceRole"), "build service role"),
            _role_rel((proj.get("buildBatchConfig") or {}).get("serviceRole"), "batch build role"),
            _role_rel(proj.get("resourceAccessRole"), "resource access role"),
            rel(proj.get("encryptionKey"), EdgeType.REFERENCES, "ENCRYPTED_BY_KMS"),
        ]
        relations += self._codebuild_source_relations(proj.get("source") or {}, "primary source")
        for i, src in enumerate(proj.get("secondarySources", []) or []):
            relations += self._codebuild_source_relations(
                src, f"secondary source {src.get('sourceIdentifier') or i}"
            )
        return relations

    def _codebuild_env_relations(self, env: dict) -> tuple[list[dict | None], dict[str, str]]:
        """Build image, registry credential and environment variable refs."""
        relations: list[dict | None] = []
        image = env.get("image")
        repo = _ecr_repo(image)
        if repo:
            relations.append(
                rel(repo, EdgeType.USES_IMAGE, "RUNS_ON", description=f"build image {image}")
            )
        cred = (env.get("registryCredential") or {}).get("credential")
        relations.append(self._app_secret_rel(cred, "secret", "registry credential"))
        env_vars = env.get("environmentVariables") or []
        var_types: dict[str, str] = {}
        for var in env_vars:
            vname, vtype, value = var.get("name"), var.get("type", "PLAINTEXT"), var.get("value")
            var_types[str(vname)] = vtype
            # Parameter-store / secrets-manager variable values are names or
            # ARNs of the secret, not the secret itself.
            if vtype in _CODEBUILD_SECRET_TYPES:
                kind, store = _CODEBUILD_SECRET_TYPES[vtype]
                relations.append(self._app_secret_rel(value, kind, f"env {vname} from {store}"))
        relations += self._env_relations(
            {
                v.get("name"): v.get("value")
                for v in env_vars
                if v.get("type", "PLAINTEXT") == "PLAINTEXT"
            },
            "environment reference",
        )
        return relations, var_types

    def _codebuild_output_relations(self, proj: dict, name: str) -> list[dict | None]:
        """Artifact / cache buckets, EFS mounts and log destinations."""
        relations: list[dict | None] = []
        for art in [proj.get("artifacts") or {}, *(proj.get("secondaryArtifacts") or [])]:
            if art.get("type") == "S3":
                relations.append(
                    rel(
                        _bucket_arn(art.get("location")),
                        EdgeType.REFERENCES,
                        "WRITES_TO",
                        description="build artifacts",
                    )
                )
        cache = proj.get("cache") or {}
        if cache.get("type") == "S3":
            relations.append(
                rel(
                    _bucket_arn(cache.get("location")),
                    EdgeType.REFERENCES,
                    "READS_FROM",
                    description="build cache",
                )
            )
        for fs in proj.get("fileSystemLocations", []) or []:
            fs_id = (fs.get("location") or "").split(".", 1)[0]
            if fs_id.startswith("fs-"):
                relations.append(
                    rel(
                        fs_id,
                        EdgeType.REFERENCES,
                        "READS_FROM",
                        description=f"EFS mount {fs.get('mountPoint')}",
                    )
                )
        logs = proj.get("logsConfig") or {}
        cw = logs.get("cloudWatchLogs") or {}
        if cw.get("status", "ENABLED") == "ENABLED":
            group = cw.get("groupName") or f"/aws/codebuild/{name}"
            relations.append(rel(self._log_group_arn(group), EdgeType.LOGS_TO, "LOGS_TO"))
        s3logs = logs.get("s3Logs") or {}
        if s3logs.get("status") == "ENABLED":
            relations.append(rel(_bucket_arn(s3logs.get("location")), EdgeType.LOGS_TO, "LOGS_TO"))
        return relations

    def _codebuild_metadata(self, proj: dict, var_types: dict[str, str]) -> dict[str, Any]:
        env = proj.get("environment") or {}
        vpc = proj.get("vpcConfig") or {}
        source = proj.get("source") or {}
        webhook = proj.get("webhook") or {}
        return {
            "service": "codebuild",
            "source_type": source.get("type"),
            "source_location": _clean_url(source.get("location")),
            "secondary_sources": [
                {"type": s.get("type"), "location": _clean_url(s.get("location"))}
                for s in proj.get("secondarySources", []) or []
            ],
            "environment_type": env.get("type"),
            "compute_type": env.get("computeType"),
            "image": env.get("image"),
            "image_pull_credentials": env.get("imagePullCredentialsType"),
            "privileged_mode": env.get("privilegedMode", False),
            "environment_variable_names": sorted(var_types),
            "environment_variable_types": var_types,
            "service_role": proj.get("serviceRole"),
            "encryption_key": proj.get("encryptionKey"),
            "vpc_id": vpc.get("vpcId"),
            "vpc_config": _vpc_config(vpc, "subnets", "securityGroupIds"),
            "webhook_enabled": bool(webhook),
            "webhook_filter_groups": len(webhook.get("filterGroups", []) or []),
            "visibility": proj.get("projectVisibility"),
            "badge_enabled": (proj.get("badge") or {}).get("badgeEnabled", False),
            "concurrent_build_limit": proj.get("concurrentBuildLimit"),
            "timeout_minutes": proj.get("timeoutInMinutes"),
        }

    def _codebuild_asset(self, proj: dict) -> CloudAsset:
        name = proj.get("name", "")
        relations = self._codebuild_role_relations(proj)
        env_rels, var_types = self._codebuild_env_relations(proj.get("environment") or {})
        relations += env_rels
        relations += self._codebuild_output_relations(proj, name)
        return self._asset(
            arn=proj.get("arn") or self._arn("codebuild", f"project/{name}"),
            name=name,
            asset_type=AssetType.BUILD_PROJECT,
            tags=proj.get("tags"),
            metadata=self._codebuild_metadata(proj, var_types),
            relations=relations,
            exposed=proj.get("projectVisibility") == "PUBLIC_READ",
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
                        logger.debug(
                            "CodeBuild project mapping failed for %s: %s", proj.get("name"), exc
                        )
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
                names = [
                    g
                    async for g in self._paginate(
                        cd, "list_deployment_groups", "deploymentGroups", applicationName=app
                    )
                ]
                out: list[CloudAsset] = []
                for chunk in _chunks(names, 100):
                    resp = await cd.batch_get_deployment_groups(
                        applicationName=app, deploymentGroupNames=chunk
                    )
                    out.extend(
                        self._deployment_group_asset(g, platforms.get(app))
                        for g in resp.get("deploymentGroupsInfo", []) or []
                    )
                return out

            results = await gather_limited([lambda a=a: groups_for(a) for a in apps])
            for r in results:
                assets.extend(r or [])
        return assets

    def _deployment_target_relations(self, g: dict) -> list[dict | None]:
        """Service role, ASGs, ECS services and load-balancer traffic control."""
        relations: list[dict | None] = [
            _role_rel(g.get("serviceRoleArn"), "CodeDeploy service role"),
        ]
        for asg in g.get("autoScalingGroups", []) or []:
            relations.append(rel(asg.get("name"), EdgeType.MANAGES, description="deploys to ASG"))
        for svc in g.get("ecsServices", []) or []:
            if svc.get("clusterName") and svc.get("serviceName"):
                relations.append(
                    rel(
                        self._arn("ecs", f"service/{svc['clusterName']}/{svc['serviceName']}"),
                        EdgeType.MANAGES,
                        description="blue/green ECS deployment",
                    )
                )
        lb = g.get("loadBalancerInfo") or {}
        for elb in lb.get("elbInfoList", []) or []:
            relations.append(
                rel(elb.get("name"), EdgeType.MANAGES, description="classic ELB traffic control")
            )
        tgs = list(lb.get("targetGroupInfoList", []) or [])
        listeners: list[str] = []
        for pair in lb.get("targetGroupPairInfoList", []) or []:
            tgs.extend(pair.get("targetGroups", []) or [])
            for route in ("prodTrafficRoute", "testTrafficRoute"):
                listeners.extend((pair.get(route) or {}).get("listenerArns", []) or [])
        for tg in tgs:
            relations.append(
                rel(tg.get("name"), EdgeType.MANAGES, description="traffic shifting target group")
            )
        for listener in listeners:
            relations.append(
                rel(
                    listener,
                    EdgeType.REFERENCES,
                    "SERVES_TRAFFIC_TO",
                    description="traffic route listener",
                )
            )
        return relations

    def _deployment_signal_relations(self, g: dict) -> list[dict | None]:
        """Triggers, rollback alarms and the revision bundle bucket."""
        relations: list[dict | None] = [
            rel(
                trig.get("triggerTargetArn"),
                EdgeType.INVOKES,
                "INVOKES",
                description=f"trigger {trig.get('triggerName')}",
            )
            for trig in g.get("triggerConfigurations", []) or []
        ]
        for alarm in (g.get("alarmConfiguration") or {}).get("alarms", []) or []:
            relations.append(
                rel(
                    alarm.get("name"),
                    EdgeType.REFERENCES,
                    "MONITORED_BY",
                    description="rollback alarm",
                )
            )
        s3loc = (g.get("targetRevision") or {}).get("s3Location") or {}
        relations.append(
            rel(
                _bucket_arn(s3loc.get("bucket")),
                EdgeType.REFERENCES,
                "READS_FROM",
                description="revision bundle",
            )
        )
        return relations

    def _deployment_group_asset(self, g: dict, app_platform: str | None) -> CloudAsset:
        app, name = g.get("applicationName", ""), g.get("deploymentGroupName", "")
        relations = self._deployment_target_relations(g) + self._deployment_signal_relations(g)
        rev = g.get("targetRevision") or {}
        tag_filters = [
            _tag_filter(f)
            for f in (g.get("ec2TagFilters") or []) + (g.get("onPremisesInstanceTagFilters") or [])
        ]
        for tag_set in (g.get("ec2TagSet") or {}).get("ec2TagSetList") or []:
            tag_filters.extend(_tag_filter(group) for group in tag_set or [])
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
                "auto_scaling_groups": [
                    a.get("name") for a in g.get("autoScalingGroups", []) or []
                ],
                "ecs_services": g.get("ecsServices", []) or [],
                "revision_type": rev.get("revisionType"),
                "github_repository": (rev.get("gitHubLocation") or {}).get("repository"),
                "auto_rollback": (g.get("autoRollbackConfiguration") or {}).get("enabled", False),
                "last_successful_deployment": (g.get("lastSuccessfulDeployment") or {}).get(
                    "deploymentId"
                ),
            },
            relations=relations,
            aliases=[g.get("deploymentGroupId")],
        )
