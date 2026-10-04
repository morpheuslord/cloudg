"""Data services: RDS instances + Aurora clusters (deep), ElastiCache,
OpenSearch and Redshift."""

from __future__ import annotations

import logging
from typing import Any

from cloudg.collectors.aws_services import rds_instance_metadata
from cloudg.inventory.aws_services._base import AWSServiceMixin, rel
from cloudg.schema.models import AssetType, CloudAsset, EdgeType

logger = logging.getLogger(__package__)  # the package logger, as before the split


def _vpc_security_groups(resource: dict) -> list[str]:
    return [g.get("VpcSecurityGroupId") for g in resource.get("VpcSecurityGroups", []) or []]


def _cache_node_sgs(cc: dict) -> list[str]:
    return [g.get("SecurityGroupId") for g in cc.get("SecurityGroups", []) or []]


def _rds_instance_relations(db: dict, group: dict) -> list[dict | None]:
    relations: list[dict | None] = [
        rel(db.get("KmsKeyId"), EdgeType.REFERENCES, "ENCRYPTED_BY_KMS"),
        rel(
            db.get("DBClusterIdentifier"),
            EdgeType.CONTAINS,
            reverse=True,
            description="cluster member",
        ),
        rel(db.get("MonitoringRoleArn"), EdgeType.ASSUMES_ROLE, "RUNS_ON"),
        rel(
            db.get("ReadReplicaSourceDBInstanceIdentifier"),
            EdgeType.REFERENCES,
            "REPLICATES_TO",
            reverse=True,
        ),
    ]
    relations += [
        rel(s.get("SubnetIdentifier"), EdgeType.CONTAINS, "SUBNET_CONTAINS_INSTANCE", reverse=True)
        for s in group.get("Subnets", []) or []
    ]
    relations += [
        rel(r.get("RoleArn"), EdgeType.ASSUMES_ROLE, "RUNS_ON", feature=r.get("FeatureName"))
        for r in db.get("AssociatedRoles", []) or []
    ]
    secret = (db.get("MasterUserSecret") or {}).get("SecretArn")
    relations.append(
        rel(secret, EdgeType.REFERENCES, "READS_FROM", description="managed master secret")
    )
    return relations


def _opensearch_relations(d: dict, vpc: dict) -> list[dict | None]:
    relations: list[dict | None] = [
        rel(
            (d.get("EncryptionAtRestOptions") or {}).get("KmsKeyId"),
            EdgeType.REFERENCES,
            "ENCRYPTED_BY_KMS",
        ),
    ]
    relations += [
        rel(s, EdgeType.CONTAINS, "SUBNET_CONTAINS_INSTANCE", reverse=True)
        for s in vpc.get("SubnetIds", []) or []
    ]
    for opt in (d.get("LogPublishingOptions") or {}).values():
        if opt.get("Enabled"):
            relations.append(
                rel(
                    (opt.get("CloudWatchLogsLogGroupArn") or "").removesuffix(":*"),
                    EdgeType.LOGS_TO,
                    "LOGS_TO",
                )
            )
    return relations


class DataCollectorsMixin(AWSServiceMixin):
    # ------------------------------------------------------------------
    # RDS (overrides the shallow base collector)
    # ------------------------------------------------------------------

    async def _collect_rds(self) -> list[CloudAsset]:
        assets: list[CloudAsset] = []
        async with self._client("rds") as rds:
            async for db in self._paginate(rds, "describe_db_instances", "DBInstances"):
                assets.append(self._rds_instance_asset(db))
            try:
                async for c in self._paginate(rds, "describe_db_clusters", "DBClusters"):
                    assets.append(self._rds_cluster_asset(c))
            except Exception as exc:
                logger.debug("RDS cluster listing failed: %s", exc)
        return assets

    def _rds_instance_asset(self, db: dict) -> CloudAsset:
        group = db.get("DBSubnetGroup") or {}
        return self._asset(
            arn=db.get("DBInstanceArn", ""),
            name=db.get("DBInstanceIdentifier", ""),
            asset_type=AssetType.RDS_INSTANCE,
            tags=db.get("TagList"),
            metadata={
                **rds_instance_metadata(db),
                "kms_key_id": db.get("KmsKeyId"),
                "vpc_id": group.get("VpcId"),
                "security_groups": _vpc_security_groups(db),
                "endpoint": (db.get("Endpoint") or {}).get("Address"),
                "cluster": db.get("DBClusterIdentifier"),
                "deletion_protection": db.get("DeletionProtection"),
            },
            relations=_rds_instance_relations(db, group),
            raw=db,
            exposed=bool(db.get("PubliclyAccessible")),
            aliases=[(db.get("Endpoint") or {}).get("Address")],
        )

    def _rds_cluster_asset(self, c: dict) -> CloudAsset:
        relations = [
            rel(c.get("KmsKeyId"), EdgeType.REFERENCES, "ENCRYPTED_BY_KMS"),
            rel(
                (c.get("MasterUserSecret") or {}).get("SecretArn"),
                EdgeType.REFERENCES,
                "READS_FROM",
            ),
        ]
        relations += [
            rel(r.get("RoleArn"), EdgeType.ASSUMES_ROLE, "RUNS_ON")
            for r in c.get("AssociatedRoles", []) or []
        ]
        return self._asset(
            arn=c["DBClusterArn"],
            name=c.get("DBClusterIdentifier", ""),
            asset_type=AssetType.AURORA_CLUSTER,
            tags=c.get("TagList"),
            metadata={
                "engine": c.get("Engine"),
                "engine_version": c.get("EngineVersion"),
                "status": c.get("Status"),
                "storage_encrypted": c.get("StorageEncrypted"),
                "kms_key_id": c.get("KmsKeyId"),
                "security_groups": _vpc_security_groups(c),
                "members": [
                    m.get("DBInstanceIdentifier") for m in c.get("DBClusterMembers", []) or []
                ],
                "endpoint": c.get("Endpoint"),
            },
            relations=relations,
            exposed=bool(c.get("PubliclyAccessible")),
            aliases=[c.get("DBClusterIdentifier"), c.get("Endpoint"), c.get("ReaderEndpoint")],
        )

    # ------------------------------------------------------------------
    # ElastiCache
    # ------------------------------------------------------------------

    async def _collect_elasticache(self) -> list[CloudAsset]:
        assets: list[CloudAsset] = []
        async with self._client("elasticache") as ec:
            nodes = {
                cc["CacheClusterId"]: cc
                async for cc in self._paginate(ec, "describe_cache_clusters", "CacheClusters")
            }
            grouped: set[str] = set()
            async for rg in self._paginate(ec, "describe_replication_groups", "ReplicationGroups"):
                grouped.update(rg.get("MemberClusters", []) or [])
                assets.append(self._cache_group_asset(rg, nodes))
            for cid, cc in nodes.items():
                if cid in grouped:
                    continue
                assets.append(self._cache_node_asset(cid, cc))
        return assets

    def _cache_group_asset(self, rg: dict, nodes: dict[str, dict]) -> CloudAsset:
        """A replication group, aliased by its member nodes so they resolve to it."""
        members = rg.get("MemberClusters", []) or []
        sgs = sorted({sg for m in members for sg in _cache_node_sgs(nodes.get(m, {})) if sg})
        return self._asset(
            arn=rg.get("ARN")
            or self._arn("elasticache", f"replicationgroup:{rg['ReplicationGroupId']}"),
            name=rg["ReplicationGroupId"],
            asset_type=AssetType.CACHE_CLUSTER,
            metadata={
                "engine": rg.get("Engine", "redis"),
                "status": rg.get("Status"),
                "members": members,
                "security_groups": sgs,
                "transit_encryption": rg.get("TransitEncryptionEnabled"),
                "at_rest_encryption": rg.get("AtRestEncryptionEnabled"),
                "auth_token_enabled": rg.get("AuthTokenEnabled"),
                "kms_key_id": rg.get("KmsKeyId"),
            },
            relations=[rel(rg.get("KmsKeyId"), EdgeType.REFERENCES, "ENCRYPTED_BY_KMS")],
            aliases=[
                rg["ReplicationGroupId"],
                *members,
                *(
                    nodes.get(m, {}).get("ARN") or self._arn("elasticache", f"cluster:{m}")
                    for m in members
                ),
            ],
        )

    def _cache_node_asset(self, cid: str, cc: dict) -> CloudAsset:
        return self._asset(
            arn=cc.get("ARN") or self._arn("elasticache", f"cluster:{cid}"),
            name=cid,
            asset_type=AssetType.CACHE_CLUSTER,
            metadata={
                "engine": cc.get("Engine"),
                "engine_version": cc.get("EngineVersion"),
                "node_type": cc.get("CacheNodeType"),
                "status": cc.get("CacheClusterStatus"),
                "security_groups": _cache_node_sgs(cc),
                "subnet_group": cc.get("CacheSubnetGroupName"),
            },
            aliases=[cid],
        )

    # ------------------------------------------------------------------
    # OpenSearch and Redshift
    # ------------------------------------------------------------------

    async def _collect_opensearch(self) -> list[CloudAsset]:
        async with self._client("opensearch") as os_client:
            names = [
                d["DomainName"]
                for d in (await os_client.list_domain_names()).get("DomainNames", [])
            ]
            assets = []
            for i in range(0, len(names), 5):
                resp = await os_client.describe_domains(DomainNames=names[i : i + 5])
                assets.extend(self._opensearch_asset(d) for d in resp.get("DomainStatusList", []))
            return assets

    def _opensearch_asset(self, d: dict) -> CloudAsset:
        vpc = d.get("VPCOptions") or {}
        return self._asset(
            arn=d["ARN"],
            name=d["DomainName"],
            asset_type=AssetType.SEARCH_DOMAIN,
            metadata={
                "engine_version": d.get("EngineVersion"),
                "in_vpc": bool(vpc),
                "vpc_id": vpc.get("VPCId"),
                "security_groups": vpc.get("SecurityGroupIds", []) or [],
                "endpoint": d.get("Endpoint") or (d.get("Endpoints") or {}).get("vpc"),
                "fine_grained_access": (d.get("AdvancedSecurityOptions") or {}).get("Enabled"),
                "node_to_node_encryption": (d.get("NodeToNodeEncryptionOptions") or {}).get(
                    "Enabled"
                ),
            },
            relations=_opensearch_relations(d, vpc),
            exposed=not vpc,
        )

    async def _collect_redshift(self) -> list[CloudAsset]:
        assets: list[CloudAsset] = []
        async with self._client("redshift") as rs:
            async for c in self._paginate(rs, "describe_clusters", "Clusters"):
                cid = c["ClusterIdentifier"]
                relations: list[dict | None] = [
                    rel(c.get("KmsKeyId"), EdgeType.REFERENCES, "ENCRYPTED_BY_KMS")
                ]
                relations += [
                    rel(r.get("IamRoleArn"), EdgeType.ASSUMES_ROLE, "RUNS_ON")
                    for r in c.get("IamRoles", []) or []
                ]
                assets.append(
                    self._asset(
                        arn=c.get("ClusterNamespaceArn") or self._arn("redshift", f"cluster:{cid}"),
                        name=cid,
                        asset_type=AssetType.DATA_WAREHOUSE,
                        tags=c.get("Tags"),
                        metadata=self._redshift_metadata(c),
                        relations=relations,
                        exposed=bool(c.get("PubliclyAccessible")),
                        aliases=[cid, self._arn("redshift", f"cluster:{cid}")],
                    )
                )
        return assets

    @staticmethod
    def _redshift_metadata(c: dict) -> dict[str, Any]:
        return {
            "node_type": c.get("NodeType"),
            "nodes": c.get("NumberOfNodes"),
            "encrypted": c.get("Encrypted"),
            "publicly_accessible": c.get("PubliclyAccessible"),
            "vpc_id": c.get("VpcId"),
            "security_groups": _vpc_security_groups(c),
            "endpoint": (c.get("Endpoint") or {}).get("Address"),
        }
