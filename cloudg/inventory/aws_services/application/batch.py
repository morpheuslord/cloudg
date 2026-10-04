"""AWS Batch: compute environments, job queues and the latest revision of
each active job definition (container / multi-node / ECS / EKS shapes)."""

from __future__ import annotations

from typing import Any

from cloudg.inventory.aws_services._base import rel
from cloudg.inventory.aws_services.application._common import (
    ApplicationBase,
    _ecr_repo,
    _efs_volume_relations,
    _env_names,
    _role_rel,
    _vpc_config,
    logger,
)
from cloudg.schema.models import AssetType, CloudAsset, EdgeType


def _definition_blocks(jd: dict, relations: list) -> list[tuple[dict, str]]:
    """Every container block of a job definition with its label; ECS task
    roles and volumes go into ``relations``."""
    blocks: list[tuple[dict, str]] = []
    if jd.get("containerProperties"):
        blocks.append((jd["containerProperties"], "container"))
    for nr in (jd.get("nodeProperties") or {}).get("nodeRangeProperties") or []:
        if nr.get("container"):
            blocks.append((nr["container"], f"node {nr.get('targetNodes')}"))
        for tp in (nr.get("ecsProperties") or {}).get("taskProperties") or []:
            blocks.extend(
                (c, f"node container {c.get('name')}") for c in tp.get("containers", []) or []
            )
    for tp in (jd.get("ecsProperties") or {}).get("taskProperties") or []:
        relations.append(_role_rel(tp.get("taskRoleArn"), "task role"))
        relations.append(_role_rel(tp.get("executionRoleArn"), "execution role"))
        relations += _efs_volume_relations(tp.get("volumes"))
        blocks.extend((c, f"container {c.get('name')}") for c in tp.get("containers", []) or [])
    pod = (jd.get("eksProperties") or {}).get("podProperties") or {}
    blocks.extend(
        (c, f"pod container {c.get('name')}")
        for c in (pod.get("containers") or []) + (pod.get("initContainers") or [])
    )
    return blocks


class BatchCollectorsMixin(ApplicationBase):
    """AWS Batch collector."""

    def _batch_container_relations(
        self, c: dict, label: str
    ) -> tuple[list[dict | None], dict[str, Any]]:
        relations: list[dict | None] = []
        image = c.get("image")
        repo = _ecr_repo(image)
        if repo:
            relations.append(
                rel(repo, EdgeType.USES_IMAGE, "RUNS_ON", description=f"{label} image {image}")
            )
        relations.append(_role_rel(c.get("jobRoleArn"), "job role"))
        relations.append(_role_rel(c.get("executionRoleArn"), "execution role"))
        log_cfg = c.get("logConfiguration") or {}
        secrets = list(c.get("secrets", []) or []) + list(log_cfg.get("secretOptions") or [])
        relations.extend(
            self._app_secret_rel(s.get("valueFrom"), "parameter", f"secret {s.get('name')}")
            for s in secrets
        )
        cred = (c.get("repositoryCredentials") or {}).get("credentialsParameter")
        relations.append(self._app_secret_rel(cred, "secret", "registry credentials"))
        relations += self._env_relations(
            c.get("environment") or c.get("env"), "environment reference"
        )
        options = log_cfg.get("options") or {}
        group = options.get("awslogs-group")
        if log_cfg.get("logDriver") == "awslogs" and group:
            group_arn = self._log_group_arn(group, options.get("awslogs-region"))
            relations.append(rel(group_arn, EdgeType.LOGS_TO, "LOGS_TO"))
        relations += _efs_volume_relations(c.get("volumes"))
        summary = {
            "image": image,
            "environment_variable_names": _env_names(c.get("environment") or c.get("env")),
            "secret_names": sorted(str(s.get("name")) for s in c.get("secrets", []) or []),
            "privileged": c.get("privileged")
            or ((c.get("securityContext") or {}).get("privileged")),
        }
        return relations, summary

    async def _batch_job_definitions(self, batch: Any) -> tuple[dict[str, dict], dict[str, int]]:
        """Latest active revision per job definition name, and revision counts."""
        latest: dict[str, dict] = {}
        revisions: dict[str, int] = {}
        try:
            async for jd in self._paginate(
                batch, "describe_job_definitions", "jobDefinitions", status="ACTIVE"
            ):
                name = jd.get("jobDefinitionName", "")
                revisions[name] = revisions.get(name, 0) + 1
                if name not in latest or jd.get("revision", 0) > latest[name].get("revision", 0):
                    latest[name] = jd
        except Exception as exc:
            logger.debug("describe_job_definitions failed: %s", exc)
        return latest, revisions

    def _batch_environment_relations(self, ce: dict) -> list[dict | None]:
        cr = ce.get("computeResources") or {}
        lt = cr.get("launchTemplate") or {}
        return [
            rel(ce.get("ecsClusterArn"), EdgeType.MANAGES, description="managed ECS cluster"),
            rel(
                (ce.get("eksConfiguration") or {}).get("eksClusterArn"),
                EdgeType.REFERENCES,
                "RUNS_ON",
                description="EKS cluster",
            ),
            _role_rel(self._role_ref(ce.get("serviceRole")), "Batch service role"),
            rel(
                self._instance_profile_ref(cr.get("instanceRole")),
                EdgeType.REFERENCES,
                "RUNS_ON",
                description="instance profile",
            ),
            _role_rel(self._role_ref(cr.get("spotIamFleetRole")), "spot fleet role"),
            rel(
                lt.get("launchTemplateId") or lt.get("launchTemplateName"),
                EdgeType.REFERENCES,
                "DEPENDS_ON",
                description="launch template",
            ),
        ]

    def _batch_environment_asset(self, ce: dict) -> CloudAsset:
        cr = ce.get("computeResources") or {}
        return self._asset(
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
                "vpc_config": _vpc_config(cr, "subnets", "securityGroupIds"),
            },
            relations=self._batch_environment_relations(ce),
        )

    def _batch_queue_asset(self, q: dict) -> CloudAsset:
        relations = [
            rel(
                o.get("computeEnvironment"),
                EdgeType.REFERENCES,
                "RUNS_ON",
                description=f"compute environment order {o.get('order')}",
            )
            for o in q.get("computeEnvironmentOrder", []) or []
        ]
        relations += [
            rel(
                o.get("serviceEnvironment"),
                EdgeType.REFERENCES,
                "RUNS_ON",
                description="service environment",
            )
            for o in q.get("serviceEnvironmentOrder", []) or []
        ]
        relations.append(
            rel(
                q.get("schedulingPolicyArn"),
                EdgeType.REFERENCES,
                "DEPENDS_ON",
                description="scheduling policy",
            )
        )
        return self._asset(
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

    def _batch_job_definition_asset(self, name: str, jd: dict, revision_count: int) -> CloudAsset:
        relations: list[dict | None] = []
        containers: list[dict] = []
        for block, label in _definition_blocks(jd, relations):
            c_rels, c_summary = self._batch_container_relations(block, label)
            relations.extend(c_rels)
            containers.append(
                {"name": block.get("name") or label, **{k: v for k, v in c_summary.items() if v}}
            )
        pod = (jd.get("eksProperties") or {}).get("podProperties") or {}
        arn = jd["jobDefinitionArn"]
        return self._asset(
            arn=arn,
            name=name,
            asset_type=AssetType.JOB_DEFINITION,
            tags=jd.get("tags"),
            metadata={
                "service": "batch",
                "type": jd.get("type"),
                "revision": jd.get("revision"),
                "active_revisions": revision_count,
                "platform_capabilities": jd.get("platformCapabilities", []),
                "orchestration": jd.get("containerOrchestrationType"),
                "containers": containers,
                "service_account": pod.get("serviceAccountName"),
                "parameter_names": sorted(jd.get("parameters") or {}),
            },
            relations=relations,
            aliases=[arn.rsplit(":", 1)[0] if arn.rsplit(":", 1)[-1].isdigit() else None],
        )

    async def _collect_batch(self) -> list[CloudAsset]:
        async with self._client("batch") as batch:
            envs = [
                e
                async for e in self._paginate(
                    batch, "describe_compute_environments", "computeEnvironments"
                )
            ]
            queues = [q async for q in self._paginate(batch, "describe_job_queues", "jobQueues")]
            latest, revisions = await self._batch_job_definitions(batch)
        assets = [self._batch_environment_asset(ce) for ce in envs]
        assets.extend(self._batch_queue_asset(q) for q in queues)
        assets.extend(
            self._batch_job_definition_asset(name, jd, revisions.get(name, 1))
            for name, jd in latest.items()
        )
        return assets
