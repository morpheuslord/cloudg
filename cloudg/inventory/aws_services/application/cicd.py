"""CodePipeline (stages/actions -> roles, CodeBuild, CloudFormation, ECS,
CodeDeploy, Lambda, artifact buckets/KMS, source connections) and
CodeConnections / CodeStar connections."""

from __future__ import annotations

from typing import Any

from cloudg.inventory.aws_services._base import gather_limited, rel
from cloudg.inventory.aws_services.application._common import (
    ApplicationBase,
    _env_names,
    _bucket_arn,
    _role_rel,
    logger,
)
from cloudg.schema.models import AssetType, CloudAsset, EdgeType

# provider -> (required configuration keys, ARN service, resource template,
# edge, relationship) for actions whose target ARN is built from config.
_PIPELINE_TARGETS: dict[str, tuple[tuple[str, ...], str, str, EdgeType, str | None]] = {
    "CodeBuild": (
        ("ProjectName",),
        "codebuild",
        "project/{ProjectName}",
        EdgeType.INVOKES,
        "INVOKES",
    ),
    "ECS": (
        ("ClusterName", "ServiceName"),
        "ecs",
        "service/{ClusterName}/{ServiceName}",
        EdgeType.MANAGES,
        None,
    ),
    "CodeDeploy": (
        ("ApplicationName", "DeploymentGroupName"),
        "codedeploy",
        "deploymentgroup:{ApplicationName}/{DeploymentGroupName}",
        EdgeType.INVOKES,
        "INVOKES",
    ),
    "ElasticBeanstalk": (
        ("ApplicationName", "EnvironmentName"),
        "elasticbeanstalk",
        "environment/{ApplicationName}/{EnvironmentName}",
        EdgeType.MANAGES,
        None,
    ),
    "EKS": (("ClusterName",), "eks", "cluster/{ClusterName}", EdgeType.MANAGES, None),
    "ECR": (
        ("RepositoryName",),
        "ecr",
        "repository/{RepositoryName}",
        EdgeType.REFERENCES,
        "READS_FROM",
    ),
}
_PIPELINE_TARGETS["CodeDeployToECS"] = _PIPELINE_TARGETS["CodeDeploy"]


def _pipeline_misc_relations(
    provider: str, category: str, cfg: dict[str, str], desc: str
) -> tuple[list[dict | None], dict[str, Any]]:
    """Relations / summary extras for providers referenced by name or ARN."""
    if provider == "CloudFormation" and cfg.get("StackName"):
        return [
            rel(cfg["StackName"], EdgeType.MANAGES, description=f"{desc} deploys stack"),
            rel(
                cfg.get("RoleArn"),
                EdgeType.REFERENCES,
                "DEPENDS_ON",
                description="CloudFormation deployment role",
            ),
        ], {}
    if provider == "CloudFormationStackSet" and cfg.get("StackSetName"):
        stack_set = cfg["StackSetName"]
        return [rel(stack_set, EdgeType.MANAGES, description=f"{desc} deploys stack set")], {}
    if provider == "StepFunctions" and cfg.get("StateMachineArn"):
        return [rel(cfg["StateMachineArn"], EdgeType.INVOKES, "INVOKES", description=desc)], {}
    if provider == "CodeStarSourceConnection":
        connection = rel(
            cfg.get("ConnectionArn"), EdgeType.REFERENCES, "READS_FROM", description=desc
        )
        return [connection], {
            "repository": cfg.get("FullRepositoryId"),
            "branch": cfg.get("BranchName"),
        }
    if provider == "S3":
        bucket = cfg.get("S3Bucket") or cfg.get("BucketName")
        verb = "READS_FROM" if category == "Source" else "WRITES_TO"
        return [
            rel(_bucket_arn(bucket), EdgeType.REFERENCES, verb, description=desc),
            rel(cfg.get("KMSEncryptionKeyARN"), EdgeType.REFERENCES, "ENCRYPTED_BY_KMS"),
        ], {}
    if provider == "GitHub":
        return [], {
            "repository": f"{cfg.get('Owner', '')}/{cfg.get('Repo', '')}".strip("/") or None,
            "branch": cfg.get("Branch"),
        }
    return [], {}


class CicdCollectorsMixin(ApplicationBase):
    """CodePipeline and CodeConnections collectors."""

    # ------------------------------------------------------------------
    # CodePipeline
    # ------------------------------------------------------------------

    def _pipeline_provider_relations(
        self, provider: str, category: str, cfg: dict[str, str], region: str, desc: str
    ) -> tuple[list[dict | None], dict[str, Any]]:
        """Relations (and summary extras) for one action's provider config."""
        spec = _PIPELINE_TARGETS.get(provider)
        if spec:
            keys, service, template, edge, relationship = spec
            if not all(cfg.get(k) for k in keys):
                return [], {}
            target = self._arn(service, template.format(**cfg), region)
            return [rel(target, edge, relationship, description=desc)], {}
        if provider == "Lambda" and cfg.get("FunctionName"):
            fn = cfg["FunctionName"]
            target = fn if fn.startswith("arn:") else self._arn("lambda", f"function:{fn}", region)
            return [rel(target, EdgeType.INVOKES, "INVOKES", description=desc)], {}
        if provider == "CodeCommit" and cfg.get("RepositoryName"):
            repo = cfg["RepositoryName"]
            target = self._arn("codecommit", repo, region)
            return [rel(target, EdgeType.REFERENCES, "READS_FROM", description=desc)], {
                "repository": repo,
                "branch": cfg.get("BranchName"),
            }
        return _pipeline_misc_relations(provider, category, cfg, desc)

    def _pipeline_action_relations(self, action: dict) -> tuple[list[dict | None], dict[str, Any]]:
        type_id = action.get("actionTypeId") or {}
        category = type_id.get("category", "")
        provider = type_id.get("provider", "")
        cfg = {
            k: v
            for k, v in (action.get("configuration") or {}).items()
            if isinstance(v, str) and "#{" not in v
        }
        region = action.get("region") or self._region
        name = action.get("name", "")
        desc = f"{category} action {name} ({provider})"
        relations: list[dict | None] = []
        summary: dict[str, Any] = {
            "name": name,
            "category": category,
            "provider": provider,
            "owner": type_id.get("owner"),
            "region": region,
            "run_order": action.get("runOrder"),
        }
        role = action.get("roleArn")
        if role:
            summary["cross_account_role"] = self._cross_account(role)
            relations.append(
                rel(
                    role,
                    EdgeType.ASSUMES_ROLE,
                    "RUNS_ON",
                    description=f"{desc} role",
                    cross_account=self._cross_account(role) or None,
                )
            )
        if region != self._region:
            summary["cross_region"] = True
        p_rels, extras = self._pipeline_provider_relations(provider, category, cfg, region, desc)
        relations += p_rels
        summary.update(extras)
        # ARNs anywhere else in the configuration (deliberately not the raw
        # configuration itself, which may carry tokens or user parameters)
        known = {r["target"] for r in relations if r}
        for value in cfg.values():
            if value.startswith("arn:") and value not in known:
                relations.append(rel(value, EdgeType.REFERENCES, "DEPENDS_ON", description=desc))
        summary["environment_variable_names"] = (
            _env_names(action.get("environmentVariables")) or None
        )
        return relations, {k: v for k, v in summary.items() if v not in (None, "", [])}

    def _pipeline_store_relations(self, p: dict) -> tuple[list[dict | None], list[str]]:
        """Artifact store buckets and their KMS keys."""
        relations: list[dict | None] = []
        stores = list((p.get("artifactStores") or {}).items())
        if p.get("artifactStore"):
            stores.append((self._region, p["artifactStore"]))
        buckets = []
        for store_region, store in stores:
            if store.get("type") == "S3" and store.get("location"):
                buckets.append(store["location"])
                relations.append(
                    rel(
                        _bucket_arn(store["location"]),
                        EdgeType.REFERENCES,
                        "WRITES_TO",
                        description=f"artifact store ({store_region})",
                    )
                )
            key = (store.get("encryptionKey") or {}).get("id")
            relations.append(
                rel(key, EdgeType.REFERENCES, "ENCRYPTED_BY_KMS", description="artifact encryption")
            )
        return relations, buckets

    def _pipeline_asset(self, resp: dict, summary_name: str) -> CloudAsset:
        p = resp.get("pipeline") or {}
        name = p.get("name", summary_name)
        arn = (resp.get("metadata") or {}).get("pipelineArn") or self._arn("codepipeline", name)
        relations: list[dict | None] = [_role_rel(p.get("roleArn"), "pipeline service role")]
        store_rels, buckets = self._pipeline_store_relations(p)
        relations += store_rels
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

    async def _collect_codepipeline(self) -> list[CloudAsset]:
        async with self._client("codepipeline") as cp:
            summaries = [p async for p in self._paginate(cp, "list_pipelines", "pipelines")]

            async def detail(summary: dict) -> CloudAsset:
                resp = await cp.get_pipeline(name=summary["name"])
                return self._pipeline_asset(resp, summary["name"])

            results = await gather_limited([lambda s=s: detail(s) for s in summaries])
        return [a for a in results if a]

    # ------------------------------------------------------------------
    # CodeConnections / CodeStar connections
    # ------------------------------------------------------------------

    def _codeconnection_asset(self, c: dict) -> CloudAsset:
        arn = c.get("ConnectionArn", "")
        # Pipelines may reference either service prefix for the same connection
        other = (
            arn.replace(":codeconnections:", ":codestar-connections:")
            if ":codeconnections:" in arn
            else arn.replace(":codestar-connections:", ":codeconnections:")
        )
        owner = c.get("OwnerAccountId")
        return self._asset(
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
            relations=[
                rel(
                    c.get("HostArn"),
                    EdgeType.REFERENCES,
                    "DEPENDS_ON",
                    description="connection host",
                )
            ],
            aliases=[other if other != arn else None],
        )

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
        return [self._codeconnection_asset(c) for c in connections]
