"""ECS extras: capacity providers, container instances (cluster -> EC2
instance containment) and Cloud Map namespaces / services."""

from __future__ import annotations

from typing import Any

from cloudg.inventory.aws_services._base import gather_limited, rel
from cloudg.inventory.aws_services.application._common import (
    ApplicationBase,
    _chunks,
    _vpc_config,
    logger,
)
from cloudg.schema.models import AssetType, CloudAsset, EdgeType


class ContainersExtCollectorsMixin(ApplicationBase):
    """ECS capacity provider, container instance and Cloud Map collectors."""

    async def _ecs_clusters(self, ecs: Any) -> list[dict]:
        arns = [c async for c in self._paginate(ecs, "list_clusters", "clusterArns")]
        clusters: list[dict] = []
        for chunk in _chunks(arns, 100):
            clusters.extend((await ecs.describe_clusters(clusters=chunk)).get("clusters", []) or [])
        return clusters

    async def _ecs_capacity_provider_users(self, ecs: Any) -> dict[str, list[str]]:
        """Capacity provider name -> ARNs of the clusters using it."""
        users: dict[str, list[str]] = {}
        try:
            for c in await self._ecs_clusters(ecs):
                for name in c.get("capacityProviders", []) or []:
                    users.setdefault(name, []).append(c["clusterArn"])
        except Exception as exc:
            logger.debug("ECS cluster lookup for capacity providers failed: %s", exc)
        return users

    def _ecs_capacity_provider_relations(self, p: dict, clusters: list[str]) -> list[dict | None]:
        asg = p.get("autoScalingGroupProvider") or {}
        mip = p.get("managedInstancesProvider") or {}
        lt = mip.get("instanceLaunchTemplate") or {}
        relations: list[dict | None] = [
            rel(
                asg.get("autoScalingGroupArn"),
                EdgeType.MANAGES,
                "SCALES_WITH",
                description="managed scaling",
            ),
            rel(
                mip.get("infrastructureRoleArn"),
                EdgeType.ASSUMES_ROLE,
                "RUNS_ON",
                description="infrastructure role",
            ),
            rel(
                lt.get("ec2InstanceProfileArn"),
                EdgeType.REFERENCES,
                "RUNS_ON",
                description="instance profile",
            ),
            rel(p.get("cluster"), EdgeType.CONTAINS, reverse=True),
        ]
        relations.extend(
            rel(
                carn,
                EdgeType.REFERENCES,
                "SCALES_WITH",
                reverse=True,
                description="cluster capacity provider",
            )
            for carn in clusters
        )
        return relations

    def _ecs_capacity_provider_asset(self, p: dict, clusters: list[str]) -> CloudAsset:
        name = p.get("name", "")
        asg = p.get("autoScalingGroupProvider") or {}
        lt = (p.get("managedInstancesProvider") or {}).get("instanceLaunchTemplate") or {}
        scaling = asg.get("managedScaling") or {}
        return self._asset(
            arn=p.get("capacityProviderArn") or self._arn("ecs", f"capacity-provider/{name}"),
            name=name,
            asset_type=AssetType.CAPACITY_PROVIDER,
            tags=p.get("tags"),
            metadata={
                "service": "ecs",
                "status": p.get("status"),
                "type": p.get("type"),
                "managed_scaling": scaling.get("status"),
                "target_capacity": scaling.get("targetCapacity"),
                "managed_termination_protection": asg.get("managedTerminationProtection"),
                "managed_draining": asg.get("managedDraining"),
                "clusters": clusters,
                "vpc_config": _vpc_config(
                    lt.get("networkConfiguration") or {}, "subnets", "securityGroups"
                ),
            },
            relations=self._ecs_capacity_provider_relations(p, clusters),
        )

    async def _collect_ecs_capacity_providers(self) -> list[CloudAsset]:
        async with self._client("ecs") as ecs:
            providers = [
                p
                async for p in self._pages(
                    ecs.describe_capacity_providers,
                    "capacityProviders",
                    token_in="nextToken",
                    include=["TAGS"],
                )
            ]
            users = await self._ecs_capacity_provider_users(ecs)
        assets: list[CloudAsset] = []
        for p in providers:
            name = p.get("name", "")
            asg = p.get("autoScalingGroupProvider") or {}
            mip = p.get("managedInstancesProvider") or {}
            if not asg and not mip and name in ("FARGATE", "FARGATE_SPOT"):
                continue
            assets.append(self._ecs_capacity_provider_asset(p, users.get(name, [])))
        return assets

    async def _ecs_cluster_container_instances(self, ecs: Any, carn: str) -> CloudAsset | None:
        ci_arns = [
            c
            async for c in self._paginate(
                ecs, "list_container_instances", "containerInstanceArns", cluster=carn
            )
        ]
        if not ci_arns:
            return None
        instances: list[dict] = []
        for chunk in _chunks(ci_arns, 100):
            resp = await ecs.describe_container_instances(cluster=carn, containerInstances=chunk)
            instances.extend(resp.get("containerInstances", []) or [])
        relations = [
            rel(
                ci.get("ec2InstanceId"),
                EdgeType.CONTAINS,
                description="ECS container instance",
                status=ci.get("status"),
                agent_connected=ci.get("agentConnected"),
                capacity_provider=ci.get("capacityProviderName"),
                running_tasks=ci.get("runningTasksCount"),
            )
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
            results = await gather_limited(
                [lambda c=c: self._ecs_cluster_container_instances(ecs, c) for c in cluster_arns]
            )
            assets.extend(a for a in results if a)
        return assets

    # ------------------------------------------------------------------
    # Cloud Map
    # ------------------------------------------------------------------

    def _cloudmap_namespace_asset(self, n: dict) -> CloudAsset:
        ntype = n.get("Type", "")
        props = n.get("Properties") or {}
        zone = (props.get("DnsProperties") or {}).get("HostedZoneId")
        return self._asset(
            arn=n.get("Arn") or self._arn("servicediscovery", f"namespace/{n.get('Id')}"),
            name=n.get("Name", ""),
            asset_type=AssetType.DNS_ZONE
            if ntype.startswith("DNS")
            else AssetType.SERVICE_REGISTRY,
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
            relations=[
                rel(zone, EdgeType.REFERENCES, "DNS_RESOLVED", description="Route 53 hosted zone")
            ],
            exposed=ntype == "DNS_PUBLIC",
            aliases=[n.get("Id")],
        )

    def _cloudmap_service_asset(self, svc: dict, ns_id: Any, ns_arn: Any) -> CloudAsset:
        dns = svc.get("DnsConfig") or {}
        return self._asset(
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
            relations=[rel(ns_arn or ns_id, EdgeType.CONTAINS, reverse=True)],
            aliases=[svc.get("Id")],
        )

    async def _collect_cloudmap(self) -> list[CloudAsset]:
        async with self._client("servicediscovery") as sd:
            namespaces = [n async for n in self._paginate(sd, "list_namespaces", "Namespaces")]
            services = [s async for s in self._paginate(sd, "list_services", "Services")]

            async def namespace_of(svc: dict) -> str | None:
                ns = (svc.get("DnsConfig") or {}).get("NamespaceId")
                if ns:
                    return ns
                return ((await sd.get_service(Id=svc["Id"])).get("Service") or {}).get(
                    "NamespaceId"
                )

            ns_ids = await gather_limited([lambda s=s: namespace_of(s) for s in services])

        ns_arns = {n.get("Id"): n.get("Arn") for n in namespaces}
        assets = [self._cloudmap_namespace_asset(n) for n in namespaces]
        assets.extend(
            self._cloudmap_service_asset(svc, ns_id, ns_arns.get(ns_id))
            for svc, ns_id in zip(services, ns_ids)
        )
        return assets
