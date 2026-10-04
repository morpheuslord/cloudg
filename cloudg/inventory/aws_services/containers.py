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

import asyncio
import logging
from typing import Any

from cloudg.inventory.aws_services._base import (
    AWSServiceMixin,
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


def _chunks(items: list[Any], size: int) -> list[list[Any]]:
    return [items[i : i + size] for i in range(0, len(items), size)]


def image_repository(image: str) -> str:
    """Strip tag/digest from an image reference: repo URI used for linking."""
    ref = image.split("@", 1)[0]
    last = ref.rsplit("/", 1)[-1]
    if ":" in last:
        ref = ref[: len(ref) - len(last)] + last.split(":", 1)[0]
    return ref


class ContainerCollectorsMixin(AWSServiceMixin):
    _max_images: int = 20
    _kubernetes_enabled: bool = True
    _kubernetes_timeout: int = 10
    _boto3_session: Any
    coverage: Any

    # ------------------------------------------------------------------
    # ECR
    # ------------------------------------------------------------------

    async def _collect_ecr(self) -> list[CloudAsset]:
        assets: list[CloudAsset] = []
        async with self._client("ecr") as ecr:
            registry: dict[str, Any] = {}
            try:
                scan_cfg = await ecr.get_registry_scanning_configuration()
                registry["scan_type"] = (scan_cfg.get("scanningConfiguration") or {}).get(
                    "scanType"
                )
            except Exception as exc:
                logger.debug("ECR registry scanning config unavailable: %s", exc)
            try:
                reg = await ecr.describe_registry()
                rules = (reg.get("replicationConfiguration") or {}).get("rules", [])
                registry["replication_destinations"] = [
                    d for r in rules for d in r.get("destinations", [])
                ]
            except Exception as exc:
                logger.debug("ECR describe_registry unavailable: %s", exc)

            repos = [r async for r in self._paginate(ecr, "describe_repositories", "repositories")]

            async def detail(repo: dict) -> CloudAsset:
                name = repo["repositoryName"]
                images: list[dict] = []
                if self._max_images:
                    try:
                        paginator = ecr.get_paginator("describe_images")
                        async for page in paginator.paginate(
                            repositoryName=name,
                            PaginationConfig={"MaxItems": self._max_images},
                        ):
                            images.extend(page.get("imageDetails", []))
                    except Exception as exc:
                        logger.debug("describe_images failed for %s: %s", name, exc)
                images.sort(key=lambda i: str(i.get("imagePushedAt", "")), reverse=True)
                severities: dict[str, int] = {}
                for img in images:
                    counts = (img.get("imageScanFindingsSummary") or {}).get(
                        "findingSeverityCounts", {}
                    )
                    for sev, n in counts.items():
                        severities[sev] = severities.get(sev, 0) + int(n)

                relations: list[dict | None] = []
                policy_public = False
                try:
                    pol = await ecr.get_repository_policy(repositoryName=name)
                    for st in policy_statements(pol.get("policyText")):
                        if st.get("Effect") != "Allow":
                            continue
                        for p in policy_principals(st).get("AWS", []):
                            if p == "*":
                                policy_public = True
                                continue
                            relations.append(
                                rel(
                                    principal_ref(p),
                                    EdgeType.GRANTS_ACCESS,
                                    "READS_FROM",
                                    reverse=True,
                                    description="repository policy grant",
                                )
                            )
                except Exception as exc:
                    if error_code(exc) != "RepositoryPolicyNotFoundException":
                        logger.debug("ECR policy read failed for %s: %s", name, exc)

                enc = repo.get("encryptionConfiguration") or {}
                relations.append(rel(enc.get("kmsKey"), EdgeType.REFERENCES, "ENCRYPTED_BY_KMS"))
                return self._asset(
                    arn=repo["repositoryArn"],
                    name=name,
                    asset_type=AssetType.CONTAINER_REGISTRY,
                    metadata={
                        "registry": "ecr",
                        "repository_uri": repo.get("repositoryUri"),
                        "image_tag_mutability": repo.get("imageTagMutability"),
                        "scan_on_push": (repo.get("imageScanningConfiguration") or {}).get(
                            "scanOnPush"
                        ),
                        "registry_scan_type": registry.get("scan_type"),
                        "replication_destinations": registry.get("replication_destinations", []),
                        "encryption_type": enc.get("encryptionType"),
                        "kms_key_id": enc.get("kmsKey"),
                        "image_count_sampled": len(images),
                        "latest_images": [
                            {
                                "digest": i.get("imageDigest"),
                                "tags": i.get("imageTags", []),
                                "pushed_at": str(i.get("imagePushedAt", "")),
                                "scan_status": (i.get("imageScanStatus") or {}).get("status"),
                                "size_bytes": i.get("imageSizeInBytes"),
                            }
                            for i in images[:5]
                        ],
                        "image_findings": severities,
                        "policy_allows_public": policy_public,
                    },
                    relations=relations,
                    raw=repo,
                    exposed=policy_public,
                    aliases=[repo.get("repositoryUri")],
                )

            results = await gather_limited([lambda r=r: detail(r) for r in repos])
            assets.extend(a for a in results if a)
        return assets

    # ------------------------------------------------------------------
    # ECS (overrides the shallow base collector)
    # ------------------------------------------------------------------

    def _task_definition_asset(self, td: dict, tags: Any = None) -> CloudAsset:
        relations: list[dict | None] = []
        containers = []
        for c in td.get("containerDefinitions", []):
            image = c.get("image", "")
            relations.append(
                rel(
                    image_repository(image),
                    EdgeType.USES_IMAGE,
                    "RUNS_ON",
                    description=f"container {c.get('name')} runs {image}",
                )
            )
            for secret in c.get("secrets", []) or []:
                relations.append(
                    rel(
                        secret.get("valueFrom"),
                        EdgeType.REFERENCES,
                        "READS_FROM",
                        description=f"secret {secret.get('name')}",
                    )
                )
            env = {e.get("name"): e.get("value") for e in c.get("environment", []) or []}
            for ref in identifier_refs(env):
                relations.append(
                    rel(ref, EdgeType.REFERENCES, "DEPENDS_ON", description="environment reference")
                )
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
            containers.append(
                {
                    "name": c.get("name"),
                    "image": image,
                    "essential": c.get("essential", True),
                    "privileged": c.get("privileged", False),
                    "ports": [p.get("containerPort") for p in c.get("portMappings", []) or []],
                    "environment_keys": sorted(env),
                    "secrets": [s.get("name") for s in c.get("secrets", []) or []],
                    "log_driver": (c.get("logConfiguration") or {}).get("logDriver"),
                }
            )
        relations.append(
            rel(td.get("taskRoleArn"), EdgeType.ASSUMES_ROLE, "RUNS_ON", description="task role")
        )
        relations.append(
            rel(
                td.get("executionRoleArn"),
                EdgeType.ASSUMES_ROLE,
                "DEPENDS_ON",
                description="execution role",
                purpose="execution",
            )
        )
        for vol in td.get("volumes", []) or []:
            efs = (vol.get("efsVolumeConfiguration") or {}).get("fileSystemId")
            relations.append(
                rel(efs, EdgeType.REFERENCES, "READS_FROM", description=f"volume {vol.get('name')}")
            )
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
            cluster_arns = [c async for c in self._paginate(ecs, "list_clusters", "clusterArns")]
            clusters: list[dict] = []
            for chunk in _chunks(cluster_arns, 100):
                resp = await ecs.describe_clusters(clusters=chunk, include=["SETTINGS", "TAGS"])
                clusters.extend(resp.get("clusters", []))

            task_def_arns: dict[str, int] = {}
            for cluster in clusters:
                carn = cluster["clusterArn"]
                service_arns = [
                    s
                    async for s in self._paginate(ecs, "list_services", "serviceArns", cluster=carn)
                ]
                services: list[dict] = []
                for chunk in _chunks(service_arns, 10):
                    resp = await ecs.describe_services(
                        cluster=carn, services=chunk, include=["TAGS"]
                    )
                    services.extend(resp.get("services", []))

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

                for svc in services:
                    td = svc.get("taskDefinition", "")
                    task_def_arns[td] = task_def_arns.get(td, 0) + 1
                    net = (svc.get("networkConfiguration") or {}).get("awsvpcConfiguration") or {}
                    relations: list[dict | None] = [
                        rel(carn, EdgeType.CONTAINS, "CLUSTER_CONTAINS_SERVICE", reverse=True),
                        rel(
                            td,
                            EdgeType.REFERENCES,
                            "DEPENDS_ON",
                            description="runs task definition",
                        ),
                        rel(
                            svc.get("roleArn"),
                            EdgeType.ASSUMES_ROLE,
                            "DEPENDS_ON",
                            description="service role",
                        ),
                    ]
                    for sn in net.get("subnets", []) or []:
                        relations.append(
                            rel(sn, EdgeType.CONTAINS, "SUBNET_CONTAINS_INSTANCE", reverse=True)
                        )
                    for lb in svc.get("loadBalancers", []) or []:
                        relations.append(
                            rel(
                                lb.get("targetGroupArn"),
                                EdgeType.LOAD_BALANCER_TARGET,
                                "LOAD_BALANCED_BY",
                                reverse=True,
                                container=lb.get("containerName"),
                                port=lb.get("containerPort"),
                            )
                        )
                    for reg in svc.get("serviceRegistries", []) or []:
                        relations.append(
                            rel(reg.get("registryArn"), EdgeType.REFERENCES, "DNS_RESOLVED")
                        )
                    assets.append(
                        self._asset(
                            arn=svc["serviceArn"],
                            name=svc.get("serviceName", ""),
                            asset_type=AssetType.CONTAINER_SERVICE,
                            tags=svc.get("tags"),
                            metadata={
                                "platform": "ecs",
                                "cluster_arn": carn,
                                "task_definition": td,
                                "launch_type": svc.get("launchType") or "capacity-provider",
                                "status": svc.get("status"),
                                "desired_count": svc.get("desiredCount"),
                                "running_count": svc.get("runningCount"),
                                "scheduling_strategy": svc.get("schedulingStrategy"),
                                "assign_public_ip": net.get("assignPublicIp") == "ENABLED",
                                "security_groups": net.get("securityGroups", []) or [],
                                "subnets": net.get("subnets", []) or [],
                            },
                            relations=relations,
                            exposed=net.get("assignPublicIp") == "ENABLED",
                        )
                    )

                for td in running_defs:
                    task_def_arns.setdefault(td, 0)

                assets.append(
                    self._asset(
                        arn=carn,
                        name=cluster.get("clusterName", ""),
                        asset_type=AssetType.ECS_CLUSTER,
                        tags=cluster.get("tags"),
                        metadata={
                            "status": cluster.get("status"),
                            "running_tasks": cluster.get("runningTasksCount", 0),
                            "pending_tasks": cluster.get("pendingTasksCount", 0),
                            "active_services": cluster.get("activeServicesCount", 0),
                            "container_instances": cluster.get(
                                "registeredContainerInstancesCount", 0
                            ),
                            "capacity_providers": cluster.get("capacityProviders", []),
                            "container_insights": any(
                                s.get("name") == "containerInsights" and s.get("value") == "enabled"
                                for s in cluster.get("settings", []) or []
                            ),
                            "standalone_task_definitions": sorted(d for d in running_defs if d),
                        },
                        relations=[
                            rel(
                                d,
                                EdgeType.MANAGES,
                                "SCHEDULED_BY",
                                description="runs standalone tasks",
                            )
                            for d in running_defs
                            if d and d not in {s.get("taskDefinition") for s in services}
                        ],
                        raw=cluster,
                    )
                )

            async def describe(td_arn: str) -> CloudAsset | None:
                resp = await ecs.describe_task_definition(taskDefinition=td_arn, include=["TAGS"])
                return self._task_definition_asset(resp["taskDefinition"], resp.get("tags"))

            results = await gather_limited([lambda a=a: describe(a) for a in task_def_arns if a])
            assets.extend(a for a in results if a)
        return assets

    # ------------------------------------------------------------------
    # EKS
    # ------------------------------------------------------------------

    async def _collect_eks(self) -> list[CloudAsset]:
        assets: list[CloudAsset] = []
        async with self._client("eks") as eks:
            names = [n async for n in self._paginate(eks, "list_clusters", "clusters")]
            for name in names:
                try:
                    assets.extend(await self._collect_eks_cluster(eks, name))
                except Exception as exc:
                    logger.error("EKS cluster %s collection failed: %s", name, exc)
        return assets

    async def _eks_list(self, eks: Any, operation: str, key: str, **kwargs: Any) -> list[Any]:
        """A cluster sub-listing; failure (permissions, API gaps) skips only it."""
        try:
            return [item async for item in self._paginate(eks, operation, key, **kwargs)]
        except Exception as exc:
            logger.debug("EKS %s unavailable: %s", operation, exc)
            return []

    async def _collect_eks_cluster(self, eks: Any, name: str) -> list[CloudAsset]:
        cluster = (await eks.describe_cluster(name=name))["cluster"]
        carn = cluster["arn"]
        vpc = cluster.get("resourcesVpcConfig") or {}
        assets: list[CloudAsset] = []

        relations: list[dict | None] = [
            rel(
                cluster.get("roleArn"),
                EdgeType.ASSUMES_ROLE,
                "RUNS_ON",
                description="cluster service role",
            ),
            rel(vpc.get("vpcId"), EdgeType.CONTAINS, reverse=True, description="cluster VPC"),
        ]
        for sn in vpc.get("subnetIds", []) or []:
            relations.append(rel(sn, EdgeType.CONTAINS, "SUBNET_CONTAINS_INSTANCE", reverse=True))
        for enc in cluster.get("encryptionConfig", []) or []:
            relations.append(
                rel(
                    (enc.get("provider") or {}).get("keyArn"),
                    EdgeType.REFERENCES,
                    "ENCRYPTED_BY_KMS",
                )
            )
        issuer = ((cluster.get("identity") or {}).get("oidc") or {}).get("issuer")
        if issuer:
            relations.append(
                rel(issuer, EdgeType.REFERENCES, "DEPENDS_ON", description="IRSA OIDC issuer")
            )

        # Access entries: which IAM principals can reach the Kubernetes API
        access_entries: list[dict] = []
        try:
            principals = [
                p
                async for p in self._paginate(
                    eks, "list_access_entries", "accessEntries", clusterName=name
                )
            ]

            async def entry(principal: str) -> dict:
                detail = (
                    await eks.describe_access_entry(clusterName=name, principalArn=principal)
                )["accessEntry"]
                pols = [
                    p
                    async for p in self._paginate(
                        eks,
                        "list_associated_access_policies",
                        "associatedAccessPolicies",
                        clusterName=name,
                        principalArn=principal,
                    )
                ]
                return {
                    "principal_arn": principal,
                    "type": detail.get("type"),
                    "username": detail.get("username"),
                    "kubernetes_groups": detail.get("kubernetesGroups", []),
                    "access_policies": [
                        {
                            "policy": p.get("policyArn", "").rsplit("/", 1)[-1],
                            "scope": (p.get("accessScope") or {}).get("type"),
                            "namespaces": (p.get("accessScope") or {}).get("namespaces", []),
                        }
                        for p in pols
                    ],
                }

            for e in await gather_limited([lambda p=p: entry(p) for p in principals]):
                if not e:
                    continue
                access_entries.append(e)
                is_admin = (
                    any(p["policy"] == "AmazonEKSClusterAdminPolicy" for p in e["access_policies"])
                    or "system:masters" in e["kubernetes_groups"]
                )
                relations.append(
                    rel(
                        e["principal_arn"],
                        EdgeType.GRANTS_ACCESS,
                        "POLICY_ALLOWS_ACTION",
                        reverse=True,
                        description="EKS access entry" + (" (cluster admin)" if is_admin else ""),
                        kubernetes_groups=e["kubernetes_groups"],
                        access_policies=[p["policy"] for p in e["access_policies"]],
                        cluster_admin=is_admin,
                    )
                )
        except Exception as exc:
            logger.debug("EKS access entries unavailable for %s: %s", name, exc)

        # Pod identity associations: service account -> IAM role
        try:
            assocs = [
                a
                async for a in self._paginate(
                    eks, "list_pod_identity_associations", "associations", clusterName=name
                )
            ]
            for a in await gather_limited(
                [
                    lambda a=a: eks.describe_pod_identity_association(
                        clusterName=name, associationId=a["associationId"]
                    )
                    for a in assocs
                ]
            ):
                if not a:
                    continue
                assoc = a["association"]
                sa_id = k8s_identifier(
                    carn,
                    assoc.get("namespace", ""),
                    "ServiceAccount",
                    assoc.get("serviceAccount", ""),
                )
                assets.append(
                    self._asset(
                        arn=sa_id,
                        name=f"{assoc.get('namespace')}/{assoc.get('serviceAccount')}",
                        asset_type=AssetType.K8S_SERVICE_ACCOUNT,
                        metadata={
                            "cluster_arn": carn,
                            "namespace": assoc.get("namespace"),
                            "discovered_via": "eks-pod-identity",
                        },
                        relations=[
                            rel(
                                assoc.get("roleArn"),
                                EdgeType.ASSUMES_ROLE,
                                "RUNS_ON",
                                description="EKS Pod Identity",
                            ),
                            rel(
                                assoc.get("targetRoleArn"),
                                EdgeType.ASSUMES_ROLE,
                                "ROLE_ASSUMES_ROLE",
                                description="pod identity target role",
                            ),
                            rel(carn, EdgeType.CONTAINS, "CLUSTER_CONTAINS_SERVICE", reverse=True),
                        ],
                    )
                )
        except Exception as exc:
            logger.debug("EKS pod identity unavailable for %s: %s", name, exc)

        public = bool(vpc.get("endpointPublicAccess"))
        open_cidrs = vpc.get("publicAccessCidrs", []) or []
        exposed = public and ("0.0.0.0/0" in open_cidrs or not open_cidrs)
        cluster_asset = self._asset(
            arn=carn,
            name=name,
            asset_type=AssetType.EKS_CLUSTER,
            tags=cluster.get("tags"),
            metadata={
                "version": cluster.get("version"),
                "platform_version": cluster.get("platformVersion"),
                "status": cluster.get("status"),
                "endpoint": cluster.get("endpoint"),
                "endpoint_public_access": public,
                "endpoint_private_access": bool(vpc.get("endpointPrivateAccess")),
                "public_access_cidrs": open_cidrs,
                "vpc_id": vpc.get("vpcId"),
                "subnets": vpc.get("subnetIds", []),
                "security_groups": list(
                    dict.fromkeys(
                        (vpc.get("securityGroupIds") or [])
                        + (
                            [vpc["clusterSecurityGroupId"]]
                            if vpc.get("clusterSecurityGroupId")
                            else []
                        )
                    )
                ),
                "oidc_issuer": issuer,
                "authentication_mode": (cluster.get("accessConfig") or {}).get(
                    "authenticationMode"
                ),
                "secrets_encrypted": bool(cluster.get("encryptionConfig")),
                "logging_enabled": [
                    t
                    for lg in (cluster.get("logging") or {}).get("clusterLogging", [])
                    if lg.get("enabled")
                    for t in lg.get("types", [])
                ],
                "access_entries": access_entries,
            },
            relations=relations,
            raw={k: v for k, v in cluster.items() if k != "certificateAuthority"},
            exposed=exposed,
        )
        assets.append(cluster_asset)

        # Nodegroups
        for ng_name in await self._eks_list(eks, "list_nodegroups", "nodegroups", clusterName=name):
            try:
                ng = (await eks.describe_nodegroup(clusterName=name, nodegroupName=ng_name))[
                    "nodegroup"
                ]
            except Exception as exc:
                logger.debug("describe_nodegroup %s/%s failed: %s", name, ng_name, exc)
                continue
            res = ng.get("resources") or {}
            lt = ng.get("launchTemplate") or {}
            ng_rel: list[dict | None] = [
                rel(carn, EdgeType.CONTAINS, "CLUSTER_CONTAINS_SERVICE", reverse=True),
                rel(ng.get("nodeRole"), EdgeType.ASSUMES_ROLE, "RUNS_ON", description="node role"),
                rel(lt.get("id"), EdgeType.REFERENCES, "DEPENDS_ON", description="launch template"),
                rel(res.get("remoteAccessSecurityGroup"), EdgeType.ATTACHED_TO, "PROTECTED_BY_SG"),
            ]
            for sn in ng.get("subnets", []) or []:
                ng_rel.append(rel(sn, EdgeType.CONTAINS, "SUBNET_CONTAINS_INSTANCE", reverse=True))
            for asg in res.get("autoScalingGroups", []) or []:
                ng_rel.append(rel(asg.get("name"), EdgeType.MANAGES, "SCALES_WITH"))
            assets.append(
                self._asset(
                    arn=ng["nodegroupArn"],
                    name=f"{name}/{ng_name}",
                    asset_type=AssetType.NODE_GROUP,
                    tags=ng.get("tags"),
                    metadata={
                        "cluster_arn": carn,
                        "status": ng.get("status"),
                        "capacity_type": ng.get("capacityType"),
                        "instance_types": ng.get("instanceTypes", []),
                        "ami_type": ng.get("amiType"),
                        "release_version": ng.get("releaseVersion"),
                        "scaling": ng.get("scalingConfig"),
                        "node_role": ng.get("nodeRole"),
                        "auto_scaling_groups": [
                            a.get("name") for a in res.get("autoScalingGroups", []) or []
                        ],
                    },
                    relations=ng_rel,
                )
            )

        # Fargate profiles
        for fp_name in await self._eks_list(
            eks, "list_fargate_profiles", "fargateProfileNames", clusterName=name
        ):
            try:
                fp = (
                    await eks.describe_fargate_profile(clusterName=name, fargateProfileName=fp_name)
                )["fargateProfile"]
            except Exception as exc:
                logger.debug("describe_fargate_profile failed: %s", exc)
                continue
            fp_rel: list[dict | None] = [
                rel(carn, EdgeType.CONTAINS, "CLUSTER_CONTAINS_SERVICE", reverse=True),
                rel(
                    fp.get("podExecutionRoleArn"),
                    EdgeType.ASSUMES_ROLE,
                    "RUNS_ON",
                    description="pod execution role",
                ),
            ]
            for sn in fp.get("subnets", []) or []:
                fp_rel.append(rel(sn, EdgeType.CONTAINS, "SUBNET_CONTAINS_INSTANCE", reverse=True))
            assets.append(
                self._asset(
                    arn=fp["fargateProfileArn"],
                    name=f"{name}/{fp_name}",
                    asset_type=AssetType.FARGATE_PROFILE,
                    tags=fp.get("tags"),
                    metadata={
                        "cluster_arn": carn,
                        "status": fp.get("status"),
                        "selectors": fp.get("selectors", []),
                    },
                    relations=fp_rel,
                )
            )

        # Addons
        for addon_name in await self._eks_list(eks, "list_addons", "addons", clusterName=name):
            try:
                addon = (await eks.describe_addon(clusterName=name, addonName=addon_name))["addon"]
            except Exception as exc:
                logger.debug("describe_addon failed: %s", exc)
                continue
            assets.append(
                self._asset(
                    arn=addon["addonArn"],
                    name=f"{name}/{addon_name}",
                    asset_type=AssetType.CLUSTER_ADDON,
                    tags=addon.get("tags"),
                    metadata={
                        "cluster_arn": carn,
                        "addon_version": addon.get("addonVersion"),
                        "status": addon.get("status"),
                        "service_account_role": addon.get("serviceAccountRoleArn"),
                    },
                    relations=[
                        rel(carn, EdgeType.CONTAINS, "CLUSTER_CONTAINS_SERVICE", reverse=True),
                        rel(
                            addon.get("serviceAccountRoleArn"),
                            EdgeType.ASSUMES_ROLE,
                            "RUNS_ON",
                            description="addon IRSA role",
                        ),
                    ],
                )
            )

        # In-cluster workloads through the Kubernetes API
        if (
            self._kubernetes_enabled
            and cluster.get("endpoint")
            and cluster.get("status") == "ACTIVE"
        ):
            from cloudg.inventory.kubernetes import collect_eks_workloads

            try:
                k8s_assets = await asyncio.to_thread(
                    collect_eks_workloads,
                    self._boto3_session,
                    cluster,
                    self._region,
                    self._account_id,
                    self._kubernetes_timeout,
                )
                assets.extend(k8s_assets)
                self.coverage.record(
                    f"kubernetes:{name}", _status("SUCCESS"), asset_count=len(k8s_assets)
                )
            except Exception as exc:
                logger.warning("Kubernetes API mapping skipped for %s: %s", name, exc)
                self.coverage.record(f"kubernetes:{name}", _status("FAILED"), error=str(exc))
        return assets


def k8s_identifier(cluster_arn: str, namespace: str, kind: str, name: str) -> str:
    """Synthetic, stable identifier for a Kubernetes object."""
    ns = namespace or "_cluster"
    return f"k8s://{cluster_arn}/{ns}/{kind}/{name}"


def _status(name: str) -> Any:
    from cloudg.coverage import ServiceStatus

    return ServiceStatus(name)
