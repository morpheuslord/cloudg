"""Serverless data: OpenSearch Serverless collections (network, encryption
and data access policies), Redshift Serverless workgroups / namespaces."""

from __future__ import annotations

import asyncio
from typing import Any

from cloudg.inventory.aws_services._base import arns_in, as_list, principal_ref, rel
from cloudg.inventory.aws_services.data_ml._common import (
    DataMLHelpersMixin,
    Relations,
    _aoss_match,
    _document,
    _host,
    _kms_ref,
    _linkable_principal,
    _permission_grant_rels,
    logger,
)
from cloudg.schema.models import AssetType, CloudAsset, EdgeType


def _aoss_rules(policies: list[dict], name: str, kinds: tuple[str, ...]) -> list[tuple]:
    """(policy name, block, rule) for every policy rule covering a collection."""
    out: list[tuple] = []
    for p in policies:
        for block in as_list(p["policy"]):
            if not isinstance(block, dict):
                continue
            for rule in as_list(block.get("Rules")):
                if isinstance(rule, dict) and _aoss_match(rule.get("Resource"), name, kinds):
                    out.append((p["name"], block, rule))
    return out


def _aoss_network(network: list[dict], name: str) -> tuple[set[str], set[str], list[str]]:
    """(public resource types, source VPC endpoints, policy names) of the
    network policies covering a collection."""
    public_types: set[str] = set()
    source_vpces: set[str] = set()
    network_policies: list[str] = []
    for policy_name, block, rule in _aoss_rules(network, name, ("collection", "dashboard")):
        network_policies.append(policy_name)
        if block.get("AllowFromPublic"):
            public_types.add(str(rule.get("ResourceType", "collection")))
        source_vpces.update(block.get("SourceVPCEs") or [])
    return public_types, source_vpces, network_policies


def _aoss_encryption(
    encryption: list[dict], name: str, kms: str | None
) -> tuple[str | None, bool | None]:
    """(KMS key, AWS-owned key) from the first encryption policy covering a
    collection."""
    for p in encryption:
        doc = p["policy"]
        if not isinstance(doc, dict):
            continue
        if any(
            isinstance(r, dict) and _aoss_match(r.get("Resource"), name, ("collection",))
            for r in as_list(doc.get("Rules"))
        ):
            return kms or _kms_ref(doc.get("KmsARN")), bool(doc.get("AWSOwnedKey"))
    return kms, None


def _aoss_grants(access: list[dict], name: str) -> dict[str, set[str]]:
    """principal -> data access permissions on a collection or its indexes."""
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
                if _linkable_principal(principal):
                    grants.setdefault(principal_ref(principal), set()).update(perms)
    return grants


class ServerlessDataCollectorsMixin(DataMLHelpersMixin):
    """OpenSearch Serverless and Redshift Serverless collectors."""

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

    async def _aoss_collections(self, aoss: Any) -> dict[str, dict]:
        """Collection summaries merged with their batch_get_collection detail."""
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
        return details

    async def _collect_opensearch_serverless(self) -> list[CloudAsset]:
        async with self._client("opensearchserverless") as aoss:
            details = await self._aoss_collections(aoss)
            policies = await asyncio.gather(
                self._aoss_policies(aoss, "security", "network"),
                self._aoss_policies(aoss, "security", "encryption"),
                self._aoss_policies(aoss, "access", "data"),
            )
        return [self._aoss_asset(c, *policies) for c in details.values()]

    def _aoss_asset(
        self, c: dict, network: list[dict], encryption: list[dict], access: list[dict]
    ) -> CloudAsset:
        name = c.get("name") or c["id"]
        public_types, source_vpces, network_policies = _aoss_network(network, name)
        kms, aws_owned = _aoss_encryption(encryption, name, _kms_ref(c.get("kmsKeyArn")))
        relations: Relations = [rel(kms, EdgeType.REFERENCES, "ENCRYPTED_BY_KMS")]
        relations += _permission_grant_rels(
            _aoss_grants(access, name), "data access policy", limit=20
        )
        endpoint = c.get("collectionEndpoint")
        return self._asset(
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
            relations: Relations = [
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
        return [
            self._redshift_workgroup(wg, ns_arns)
            async for wg in self._paginate(rs, "list_workgroups", "workgroups")
        ]

    def _redshift_workgroup_rels(self, wg: dict, ns_arns: dict[str, str | None]) -> Relations:
        relations: Relations = self._subnet_rels(wg.get("subnetIds"))
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
        return relations

    def _redshift_workgroup(self, wg: dict, ns_arns: dict[str, str | None]) -> CloudAsset:
        endpoint = wg.get("endpoint") or {}
        vpces = [
            v.get("vpcEndpointId")
            for v in endpoint.get("vpcEndpoints") or []
            if v.get("vpcEndpointId")
        ]
        relations = self._redshift_workgroup_rels(wg, ns_arns)
        return self._asset(
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
