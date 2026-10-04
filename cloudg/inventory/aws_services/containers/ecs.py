"""ECS clusters -> services -> task definitions -> container images, task and
execution roles, secrets, log groups, target groups, subnets, SGs."""

from __future__ import annotations

import logging
from typing import Any

from cloudg.inventory._util import image_repository
from cloudg.inventory.aws_services._base import (
    AWSServiceMixin,
    gather_limited,
    identifier_refs,
    rel,
)
from cloudg.schema.models import AssetType, CloudAsset, EdgeType

logger = logging.getLogger(__package__)  # the package logger, as before the split


def _chunks(items: list[Any], size: int) -> list[list[Any]]:
    return [items[i : i + size] for i in range(0, len(items), size)]


def _container_summary(c: dict, env: dict[str, Any]) -> dict[str, Any]:
    return {
        "name": c.get("name"),
        "image": c.get("image", ""),
        "essential": c.get("essential", True),
        "privileged": c.get("privileged", False),
        "ports": [p.get("containerPort") for p in c.get("portMappings", []) or []],
        "environment_keys": sorted(env),
        "secrets": [s.get("name") for s in c.get("secrets", []) or []],
        "log_driver": (c.get("logConfiguration") or {}).get("logDriver"),
    }


def _task_role_relations(td: dict) -> list[dict | None]:
    """Task and execution roles, and EFS volumes."""
    relations: list[dict | None] = [
        rel(td.get("taskRoleArn"), EdgeType.ASSUMES_ROLE, "RUNS_ON", description="task role"),
        rel(
            td.get("executionRoleArn"),
            EdgeType.ASSUMES_ROLE,
            "DEPENDS_ON",
            description="execution role",
            purpose="execution",
        ),
    ]
    for vol in td.get("volumes", []) or []:
        efs = (vol.get("efsVolumeConfiguration") or {}).get("fileSystemId")
        relations.append(
            rel(efs, EdgeType.REFERENCES, "READS_FROM", description=f"volume {vol.get('name')}")
        )
    return relations


def _service_relations(carn: str, svc: dict, net: dict) -> list[dict | None]:
    relations: list[dict | None] = [
        rel(carn, EdgeType.CONTAINS, "CLUSTER_CONTAINS_SERVICE", reverse=True),
        rel(
            svc.get("taskDefinition", ""),
            EdgeType.REFERENCES,
            "DEPENDS_ON",
            description="runs task definition",
        ),
        rel(svc.get("roleArn"), EdgeType.ASSUMES_ROLE, "DEPENDS_ON", description="service role"),
    ]
    relations += [
        rel(sn, EdgeType.CONTAINS, "SUBNET_CONTAINS_INSTANCE", reverse=True)
        for sn in net.get("subnets", []) or []
    ]
    relations += [
        rel(
            lb.get("targetGroupArn"),
            EdgeType.LOAD_BALANCER_TARGET,
            "LOAD_BALANCED_BY",
            reverse=True,
            container=lb.get("containerName"),
            port=lb.get("containerPort"),
        )
        for lb in svc.get("loadBalancers", []) or []
    ]
    relations += [
        rel(reg.get("registryArn"), EdgeType.REFERENCES, "DNS_RESOLVED")
        for reg in svc.get("serviceRegistries", []) or []
    ]
    return relations


def _cluster_metadata(cluster: dict, running_defs: set[str]) -> dict[str, Any]:
    return {
        "status": cluster.get("status"),
        "running_tasks": cluster.get("runningTasksCount", 0),
        "pending_tasks": cluster.get("pendingTasksCount", 0),
        "active_services": cluster.get("activeServicesCount", 0),
        "container_instances": cluster.get("registeredContainerInstancesCount", 0),
        "capacity_providers": cluster.get("capacityProviders", []),
        "container_insights": any(
            s.get("name") == "containerInsights" and s.get("value") == "enabled"
            for s in cluster.get("settings", []) or []
        ),
        "standalone_task_definitions": sorted(d for d in running_defs if d),
    }


class EcsCollectorsMixin(AWSServiceMixin):
    # ------------------------------------------------------------------
    # ECS (overrides the shallow base collector)
    # ------------------------------------------------------------------

    def _ecs_container_relations(self, c: dict, env: dict[str, Any]) -> list[dict | None]:
        """Image, secrets, environment references and log group of one container."""
        image = c.get("image", "")
        relations: list[dict | None] = [
            rel(
                image_repository(image),
                EdgeType.USES_IMAGE,
                "RUNS_ON",
                description=f"container {c.get('name')} runs {image}",
            )
        ]
        relations += [
            rel(
                secret.get("valueFrom"),
                EdgeType.REFERENCES,
                "READS_FROM",
                description=f"secret {secret.get('name')}",
            )
            for secret in c.get("secrets", []) or []
        ]
        relations += [
            rel(ref, EdgeType.REFERENCES, "DEPENDS_ON", description="environment reference")
            for ref in identifier_refs(env)
        ]
        log_opts = (c.get("logConfiguration") or {}).get("options") or {}
        group = log_opts.get("awslogs-group")
        if group:
            region = log_opts.get("awslogs-region", self._region)
            relations.append(
                rel(
                    f"arn:aws:logs:{region}:{self._account_id}:log-group:{group}",
                    EdgeType.LOGS_TO,
                    "LOGS_TO",
                )
            )
        return relations

    def _task_definition_asset(self, td: dict, tags: Any = None) -> CloudAsset:
        relations: list[dict | None] = []
        containers = []
        for c in td.get("containerDefinitions", []):
            env = {e.get("name"): e.get("value") for e in c.get("environment", []) or []}
            relations += self._ecs_container_relations(c, env)
            containers.append(_container_summary(c, env))
        relations += _task_role_relations(td)
        return self._asset(
            arn=td["taskDefinitionArn"],
            name=f"{td.get('family')}:{td.get('revision')}",
            asset_type=AssetType.TASK_DEFINITION,
            tags=tags,
            metadata={
                "family": td.get("family"),
                "revision": td.get("revision"),
                "status": td.get("status"),
                "network_mode": td.get("networkMode"),
                "compatibilities": td.get("requiresCompatibilities", []),
                "cpu": td.get("cpu"),
                "memory": td.get("memory"),
                "containers": containers,
                "images": [c["image"] for c in containers],
                "task_role_arn": td.get("taskRoleArn"),
                "execution_role_arn": td.get("executionRoleArn"),
            },
            relations=relations,
        )

    async def _collect_ecs(self) -> list[CloudAsset]:
        assets: list[CloudAsset] = []
        async with self._client("ecs") as ecs:
            task_def_arns: dict[str, int] = {}
            for cluster in await self._ecs_describe_clusters(ecs):
                carn = cluster["clusterArn"]
                services = await self._ecs_services(ecs, carn)
                running_defs = await self._ecs_running_task_definitions(ecs, carn)
                for svc in services:
                    td = svc.get("taskDefinition", "")
                    task_def_arns[td] = task_def_arns.get(td, 0) + 1
                    assets.append(self._ecs_service_asset(carn, svc))
                for td in running_defs:
                    task_def_arns.setdefault(td, 0)
                assets.append(self._ecs_cluster_asset(cluster, running_defs, services))

            results = await gather_limited(
                [lambda a=a: self._ecs_task_definition(ecs, a) for a in task_def_arns if a]
            )
            assets.extend(a for a in results if a)
        return assets

    async def _ecs_describe_clusters(self, ecs: Any) -> list[dict]:
        cluster_arns = [c async for c in self._paginate(ecs, "list_clusters", "clusterArns")]
        clusters: list[dict] = []
        for chunk in _chunks(cluster_arns, 100):
            resp = await ecs.describe_clusters(clusters=chunk, include=["SETTINGS", "TAGS"])
            clusters.extend(resp.get("clusters", []))
        return clusters

    async def _ecs_services(self, ecs: Any, carn: str) -> list[dict]:
        service_arns = [
            s async for s in self._paginate(ecs, "list_services", "serviceArns", cluster=carn)
        ]
        services: list[dict] = []
        for chunk in _chunks(service_arns, 10):
            resp = await ecs.describe_services(cluster=carn, services=chunk, include=["TAGS"])
            services.extend(resp.get("services", []))
        return services

    async def _ecs_running_task_definitions(self, ecs: Any, carn: str) -> set[str]:
        """Task definitions of running tasks, including ones no service runs."""
        running_defs: set[str] = set()
        try:
            task_arns = [
                t
                async for t in self._paginate(
                    ecs, "list_tasks", "taskArns", cluster=carn, desiredStatus="RUNNING"
                )
            ]
            for chunk in _chunks(task_arns, 100):
                resp = await ecs.describe_tasks(cluster=carn, tasks=chunk)
                for t in resp.get("tasks", []):
                    running_defs.add(t.get("taskDefinitionArn", ""))
        except Exception as exc:
            logger.debug("ECS task listing failed for %s: %s", carn, exc)
        return running_defs

    def _ecs_service_asset(self, carn: str, svc: dict) -> CloudAsset:
        net = (svc.get("networkConfiguration") or {}).get("awsvpcConfiguration") or {}
        return self._asset(
            arn=svc["serviceArn"],
            name=svc.get("serviceName", ""),
            asset_type=AssetType.CONTAINER_SERVICE,
            tags=svc.get("tags"),
            metadata={
                "platform": "ecs",
                "cluster_arn": carn,
                "task_definition": svc.get("taskDefinition", ""),
                "launch_type": svc.get("launchType") or "capacity-provider",
                "status": svc.get("status"),
                "desired_count": svc.get("desiredCount"),
                "running_count": svc.get("runningCount"),
                "scheduling_strategy": svc.get("schedulingStrategy"),
                "assign_public_ip": net.get("assignPublicIp") == "ENABLED",
                "security_groups": net.get("securityGroups", []) or [],
                "subnets": net.get("subnets", []) or [],
            },
            relations=_service_relations(carn, svc, net),
            exposed=net.get("assignPublicIp") == "ENABLED",
        )

    def _ecs_cluster_asset(
        self, cluster: dict, running_defs: set[str], services: list[dict]
    ) -> CloudAsset:
        service_defs = {s.get("taskDefinition") for s in services}
        return self._asset(
            arn=cluster["clusterArn"],
            name=cluster.get("clusterName", ""),
            asset_type=AssetType.ECS_CLUSTER,
            tags=cluster.get("tags"),
            metadata=_cluster_metadata(cluster, running_defs),
            relations=[
                rel(d, EdgeType.MANAGES, "SCHEDULED_BY", description="runs standalone tasks")
                for d in running_defs
                if d and d not in service_defs
            ],
            raw=cluster,
        )

    async def _ecs_task_definition(self, ecs: Any, td_arn: str) -> CloudAsset | None:
        resp = await ecs.describe_task_definition(taskDefinition=td_arn, include=["TAGS"])
        return self._task_definition_asset(resp["taskDefinition"], resp.get("tags"))
