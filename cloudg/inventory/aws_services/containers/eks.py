"""EKS clusters -> nodegroups (ASGs, node roles), Fargate profiles, addons
(IRSA roles), access entries (which IAM principals hold which cluster
access policies), pod identity associations, OIDC provider; plus the
in-cluster Kubernetes workloads via :mod:`cloudg.inventory.kubernetes`."""

from __future__ import annotations

import asyncio
import logging
from typing import Any

from cloudg.inventory.aws_services._base import AWSServiceMixin, gather_limited, rel
from cloudg.schema.models import AssetType, CloudAsset, EdgeType

_CLUSTER_ADMIN_POLICY = "AmazonEKSClusterAdminPolicy"

logger = logging.getLogger(__package__)  # the package logger, as before the split


def k8s_identifier(cluster_arn: str, namespace: str, kind: str, name: str) -> str:
    """Synthetic, stable identifier for a Kubernetes object."""
    ns = namespace or "_cluster"
    return f"k8s://{cluster_arn}/{ns}/{kind}/{name}"


def _status(name: str) -> Any:
    from cloudg.coverage import ServiceStatus

    return ServiceStatus(name)


def _in_cluster(carn: str) -> dict[str, Any] | None:
    """The child resource belongs to the cluster."""
    return rel(carn, EdgeType.CONTAINS, "CLUSTER_CONTAINS_SERVICE", reverse=True)


def _subnet_rels(subnets: list[str] | None) -> list[dict | None]:
    return [
        rel(sn, EdgeType.CONTAINS, "SUBNET_CONTAINS_INSTANCE", reverse=True) for sn in subnets or []
    ]


def _cluster_relations(cluster: dict, vpc: dict, issuer: str | None) -> list[dict | None]:
    """Service role, VPC, subnets, secrets KMS keys and the IRSA OIDC issuer."""
    relations: list[dict | None] = [
        rel(
            cluster.get("roleArn"),
            EdgeType.ASSUMES_ROLE,
            "RUNS_ON",
            description="cluster service role",
        ),
        rel(vpc.get("vpcId"), EdgeType.CONTAINS, reverse=True, description="cluster VPC"),
    ]
    relations += _subnet_rels(vpc.get("subnetIds"))
    relations += [
        rel((enc.get("provider") or {}).get("keyArn"), EdgeType.REFERENCES, "ENCRYPTED_BY_KMS")
        for enc in cluster.get("encryptionConfig", []) or []
    ]
    if issuer:
        relations.append(
            rel(issuer, EdgeType.REFERENCES, "DEPENDS_ON", description="IRSA OIDC issuer")
        )
    return relations


def _access_entry_rel(e: dict) -> dict[str, Any] | None:
    is_admin = (
        any(p["policy"] == _CLUSTER_ADMIN_POLICY for p in e["access_policies"])
        or "system:masters" in e["kubernetes_groups"]
    )
    return rel(
        e["principal_arn"],
        EdgeType.GRANTS_ACCESS,
        "POLICY_ALLOWS_ACTION",
        reverse=True,
        description="EKS access entry" + (" (cluster admin)" if is_admin else ""),
        kubernetes_groups=e["kubernetes_groups"],
        access_policies=[p["policy"] for p in e["access_policies"]],
        cluster_admin=is_admin,
    )


def _cluster_security_groups(vpc: dict) -> list[str]:
    extra = [vpc["clusterSecurityGroupId"]] if vpc.get("clusterSecurityGroupId") else []
    return list(dict.fromkeys((vpc.get("securityGroupIds") or []) + extra))


def _cluster_metadata(cluster: dict, vpc: dict, issuer: str | None) -> dict[str, Any]:
    return {
        "version": cluster.get("version"),
        "platform_version": cluster.get("platformVersion"),
        "status": cluster.get("status"),
        "endpoint": cluster.get("endpoint"),
        "endpoint_public_access": bool(vpc.get("endpointPublicAccess")),
        "endpoint_private_access": bool(vpc.get("endpointPrivateAccess")),
        "public_access_cidrs": vpc.get("publicAccessCidrs", []) or [],
        "vpc_id": vpc.get("vpcId"),
        "subnets": vpc.get("subnetIds", []),
        "security_groups": _cluster_security_groups(vpc),
        "oidc_issuer": issuer,
        "authentication_mode": (cluster.get("accessConfig") or {}).get("authenticationMode"),
        "secrets_encrypted": bool(cluster.get("encryptionConfig")),
        "logging_enabled": [
            t
            for lg in (cluster.get("logging") or {}).get("clusterLogging", [])
            if lg.get("enabled")
            for t in lg.get("types", [])
        ],
    }


class EksCollectorsMixin(AWSServiceMixin):
    _kubernetes_enabled: bool = True
    _kubernetes_timeout: int = 10
    _boto3_session: Any
    coverage: Any

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
        issuer = ((cluster.get("identity") or {}).get("oidc") or {}).get("issuer")
        relations = _cluster_relations(cluster, cluster.get("resourcesVpcConfig") or {}, issuer)
        access_entries = await self._eks_access_entries(eks, name, relations)
        assets = await self._eks_pod_identities(eks, name, carn)
        assets.append(self._eks_cluster_asset(cluster, name, relations, access_entries, issuer))
        assets += await self._eks_nodegroups(eks, name, carn)
        assets += await self._eks_fargate_profiles(eks, name, carn)
        assets += await self._eks_addons(eks, name, carn)
        if (
            self._kubernetes_enabled
            and cluster.get("endpoint")
            and cluster.get("status") == "ACTIVE"
        ):
            await self._eks_kubernetes_workloads(cluster, name, assets)
        return assets

    def _eks_cluster_asset(
        self,
        cluster: dict,
        name: str,
        relations: list[dict | None],
        access_entries: list[dict],
        issuer: str | None,
    ) -> CloudAsset:
        vpc = cluster.get("resourcesVpcConfig") or {}
        public = bool(vpc.get("endpointPublicAccess"))
        open_cidrs = vpc.get("publicAccessCidrs", []) or []
        return self._asset(
            arn=cluster["arn"],
            name=name,
            asset_type=AssetType.EKS_CLUSTER,
            tags=cluster.get("tags"),
            metadata={
                **_cluster_metadata(cluster, vpc, issuer),
                "access_entries": access_entries,
            },
            relations=relations,
            raw={k: v for k, v in cluster.items() if k != "certificateAuthority"},
            exposed=public and ("0.0.0.0/0" in open_cidrs or not open_cidrs),
        )

    # ------------------------------------------------------------------
    # Who can reach the cluster
    # ------------------------------------------------------------------

    async def _eks_access_entries(
        self, eks: Any, name: str, relations: list[dict | None]
    ) -> list[dict]:
        """Which IAM principals can reach the Kubernetes API, and with what."""
        access_entries: list[dict] = []
        try:
            principals = [
                p
                async for p in self._paginate(
                    eks, "list_access_entries", "accessEntries", clusterName=name
                )
            ]
            for e in await gather_limited(
                [lambda p=p: self._eks_access_entry(eks, name, p) for p in principals]
            ):
                if not e:
                    continue
                access_entries.append(e)
                relations.append(_access_entry_rel(e))
        except Exception as exc:
            logger.debug("EKS access entries unavailable for %s: %s", name, exc)
        return access_entries

    async def _eks_access_entry(self, eks: Any, name: str, principal: str) -> dict:
        detail = (await eks.describe_access_entry(clusterName=name, principalArn=principal))[
            "accessEntry"
        ]
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

    async def _eks_pod_identities(self, eks: Any, name: str, carn: str) -> list[CloudAsset]:
        """Pod identity associations: service account -> IAM role."""
        assets: list[CloudAsset] = []
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
                if a:
                    assets.append(self._eks_pod_identity_asset(carn, a["association"]))
        except Exception as exc:
            logger.debug("EKS pod identity unavailable for %s: %s", name, exc)
        return assets

    def _eks_pod_identity_asset(self, carn: str, assoc: dict) -> CloudAsset:
        return self._asset(
            arn=k8s_identifier(
                carn, assoc.get("namespace", ""), "ServiceAccount", assoc.get("serviceAccount", "")
            ),
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
                _in_cluster(carn),
            ],
        )

    # ------------------------------------------------------------------
    # Compute and addons
    # ------------------------------------------------------------------

    async def _eks_nodegroups(self, eks: Any, name: str, carn: str) -> list[CloudAsset]:
        assets: list[CloudAsset] = []
        for ng_name in await self._eks_list(eks, "list_nodegroups", "nodegroups", clusterName=name):
            try:
                ng = (await eks.describe_nodegroup(clusterName=name, nodegroupName=ng_name))[
                    "nodegroup"
                ]
            except Exception as exc:
                logger.debug("describe_nodegroup %s/%s failed: %s", name, ng_name, exc)
                continue
            assets.append(self._eks_nodegroup_asset(f"{name}/{ng_name}", carn, ng))
        return assets

    def _eks_nodegroup_asset(self, label: str, carn: str, ng: dict) -> CloudAsset:
        res = ng.get("resources") or {}
        lt = ng.get("launchTemplate") or {}
        ng_rel: list[dict | None] = [
            _in_cluster(carn),
            rel(ng.get("nodeRole"), EdgeType.ASSUMES_ROLE, "RUNS_ON", description="node role"),
            rel(lt.get("id"), EdgeType.REFERENCES, "DEPENDS_ON", description="launch template"),
            rel(res.get("remoteAccessSecurityGroup"), EdgeType.ATTACHED_TO, "PROTECTED_BY_SG"),
        ]
        ng_rel += _subnet_rels(ng.get("subnets"))
        ng_rel += [
            rel(asg.get("name"), EdgeType.MANAGES, "SCALES_WITH")
            for asg in res.get("autoScalingGroups", []) or []
        ]
        return self._asset(
            arn=ng["nodegroupArn"],
            name=label,
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

    async def _eks_fargate_profiles(self, eks: Any, name: str, carn: str) -> list[CloudAsset]:
        assets: list[CloudAsset] = []
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
                _in_cluster(carn),
                rel(
                    fp.get("podExecutionRoleArn"),
                    EdgeType.ASSUMES_ROLE,
                    "RUNS_ON",
                    description="pod execution role",
                ),
            ]
            fp_rel += _subnet_rels(fp.get("subnets"))
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
        return assets

    async def _eks_addons(self, eks: Any, name: str, carn: str) -> list[CloudAsset]:
        assets: list[CloudAsset] = []
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
                        _in_cluster(carn),
                        rel(
                            addon.get("serviceAccountRoleArn"),
                            EdgeType.ASSUMES_ROLE,
                            "RUNS_ON",
                            description="addon IRSA role",
                        ),
                    ],
                )
            )
        return assets

    async def _eks_kubernetes_workloads(
        self, cluster: dict, name: str, assets: list[CloudAsset]
    ) -> None:
        """Add the in-cluster workloads, read through the Kubernetes API."""
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
