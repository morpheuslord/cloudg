"""Data stores: RDS Proxy, Aurora global clusters, MemoryDB, DAX."""

from __future__ import annotations

from typing import Any

from cloudg.inventory.aws_services._base import rel
from cloudg.inventory.aws_services.data_ml._common import (
    DataMLHelpersMixin,
    Relations,
    _gather_details,
    _kms_ref,
    logger,
)
from cloudg.schema.models import AssetType, CloudAsset, EdgeType


def _notification_rel(topic: Any) -> dict[str, Any] | None:
    return rel(topic, EdgeType.REFERENCES, "WRITES_TO", description="event notifications")


class DatabaseCollectorsMixin(DataMLHelpersMixin):
    """RDS Proxy, Aurora global cluster, MemoryDB and DAX collectors."""

    # ------------------------------------------------------------------
    # RDS Proxy
    # ------------------------------------------------------------------

    async def _collect_rds_proxies(self) -> list[CloudAsset]:
        async with self._client("rds") as rds:
            proxies = [p async for p in self._paginate(rds, "describe_db_proxies", "DBProxies")]
            return await _gather_details(proxies, lambda x: self._rds_proxy(rds, x))

    async def _rds_proxy_targets(self, rds: Any, name: str) -> list[dict]:
        try:
            return [
                t
                async for t in self._paginate(
                    rds, "describe_db_proxy_targets", "Targets", DBProxyName=name
                )
            ]
        except Exception as exc:
            logger.debug("Proxy target lookup failed for %s: %s", name, exc)
            return []

    def _proxy_target_rel(self, t: dict) -> dict[str, Any] | None:
        ref = t.get("TargetArn")
        if not ref and t.get("Type") == "TRACKED_CLUSTER" and t.get("TrackedClusterId"):
            ref = self._arn("rds", f"cluster:{t['TrackedClusterId']}")
        elif not ref and t.get("RdsResourceId"):
            ref = self._arn("rds", f"db:{t['RdsResourceId']}")
        return rel(
            ref or t.get("Endpoint"),
            EdgeType.LOAD_BALANCER_TARGET,
            "SERVES_TRAFFIC_TO",
            target_type=t.get("Type"),
            role=t.get("Role"),
        )

    async def _rds_proxy(self, rds: Any, p: dict) -> CloudAsset:
        name = p["DBProxyName"]
        relations: Relations = self._subnet_rels(p.get("VpcSubnetIds"))
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
        targets = await self._rds_proxy_targets(rds, name)
        relations += [self._proxy_target_rel(t) for t in targets]
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
                "targets": [t.get("RdsResourceId") or t.get("TrackedClusterId") for t in targets],
            },
            relations=relations,
            aliases=[p.get("Endpoint")],
        )

    # ------------------------------------------------------------------
    # Aurora global clusters
    # ------------------------------------------------------------------

    async def _collect_rds_global_clusters(self) -> list[CloudAsset]:
        assets: list[CloudAsset] = []
        async with self._client("rds") as rds:
            async for g in self._paginate(rds, "describe_global_clusters", "GlobalClusters"):
                members = g.get("GlobalClusterMembers") or []
                relations: Relations = []
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

    # ------------------------------------------------------------------
    # MemoryDB / DAX
    # ------------------------------------------------------------------

    async def _subnet_groups(self, client: Any, name_key: str, label: str) -> dict[str, dict]:
        """Subnet groups by name (clusters only name theirs)."""
        groups: dict[str, dict] = {}
        try:
            async for sg in self._paginate(client, "describe_subnet_groups", "SubnetGroups"):
                groups[sg[name_key]] = sg
        except Exception as exc:
            logger.debug("%s subnet group listing failed: %s", label, exc)
        return groups

    async def _collect_memorydb(self) -> list[CloudAsset]:
        async with self._client("memorydb") as mdb:
            subnet_groups = await self._subnet_groups(mdb, "Name", "MemoryDB")
            return [
                self._memorydb_cluster(c, subnet_groups.get(c.get("SubnetGroupName") or "", {}))
                async for c in self._paginate(mdb, "describe_clusters", "Clusters")
            ]

    def _memorydb_cluster(self, c: dict, group: dict) -> CloudAsset:
        kms = _kms_ref(c.get("KmsKeyId"))
        relations: Relations = self._subnet_rels(
            [s.get("Identifier") for s in group.get("Subnets") or []]
        )
        relations += [
            rel(kms, EdgeType.REFERENCES, "ENCRYPTED_BY_KMS"),
            _notification_rel(c.get("SnsTopicArn")),
        ]
        endpoint = (c.get("ClusterEndpoint") or {}).get("Address")
        return self._asset(
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

    async def _collect_dax(self) -> list[CloudAsset]:
        async with self._client("dax") as dax:
            subnet_groups = await self._subnet_groups(dax, "SubnetGroupName", "DAX")
            return [
                self._dax_cluster(c, subnet_groups.get(c.get("SubnetGroup") or "", {}))
                async for c in self._paginate(dax, "describe_clusters", "Clusters")
            ]

    def _dax_cluster(self, c: dict, group: dict) -> CloudAsset:
        relations: Relations = self._subnet_rels(
            [s.get("SubnetIdentifier") for s in group.get("Subnets") or []]
        )
        relations += [
            rel(c.get("IamRoleArn"), EdgeType.ASSUMES_ROLE, "RUNS_ON"),
            _notification_rel((c.get("NotificationConfiguration") or {}).get("TopicArn")),
        ]
        endpoint = (c.get("ClusterDiscoveryEndpoint") or {}).get("Address")
        return self._asset(
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
                    g.get("SecurityGroupIdentifier") for g in c.get("SecurityGroups") or []
                ],
                "endpoint": endpoint,
            },
            relations=relations,
            aliases=[endpoint],
        )
