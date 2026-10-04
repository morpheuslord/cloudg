"""Messaging: MSK (provisioned + serverless, cluster policies), Amazon MQ."""

from __future__ import annotations

from typing import Any

from cloudg.inventory.aws_services._base import error_code, rel
from cloudg.inventory.aws_services.data_ml._common import (
    DataMLHelpersMixin,
    Relations,
    _gather_details,
    _host,
    _kms_ref,
    logger,
)
from cloudg.schema.models import AssetType, CloudAsset, EdgeType


def _msk_provisioned_metadata(prov: dict, nodes: dict, public: Any, kms: Any) -> dict[str, Any]:
    """Broker, encryption and client-auth settings of a provisioned cluster."""
    auth = prov.get("ClientAuthentication") or {}
    sasl = auth.get("Sasl") or {}
    return {
        "instance_type": nodes.get("InstanceType"),
        "broker_nodes": prov.get("NumberOfBrokerNodes"),
        "public_access": public or "DISABLED",
        "kms_key_id": _kms_ref(kms),
        "encryption_in_transit": (
            (prov.get("EncryptionInfo") or {}).get("EncryptionInTransit") or {}
        ).get("ClientBroker"),
        "auth_iam": bool((sasl.get("Iam") or {}).get("Enabled")),
        "auth_scram": bool((sasl.get("Scram") or {}).get("Enabled")),
        "auth_tls": bool((auth.get("Tls") or {}).get("Enabled")),
        "unauthenticated_access": bool((auth.get("Unauthenticated") or {}).get("Enabled")),
        "configuration_arn": (prov.get("CurrentBrokerSoftwareInfo") or {}).get("ConfigurationArn"),
    }


class MessagingCollectorsMixin(DataMLHelpersMixin):
    """MSK and Amazon MQ collectors."""

    # ------------------------------------------------------------------
    # MSK
    # ------------------------------------------------------------------

    async def _collect_msk(self) -> list[CloudAsset]:
        async with self._client("kafka") as kafka:
            clusters = [
                c async for c in self._paginate(kafka, "list_clusters_v2", "ClusterInfoList")
            ]
            return await _gather_details(clusters, lambda c: self._msk_detail(kafka, c))

    def _msk_log_rels(self, logs: dict) -> Relations:
        """LOGS_TO relations for the enabled broker log destinations."""
        cw, fh, s3 = (
            logs.get("CloudWatchLogs") or {},
            logs.get("Firehose") or {},
            logs.get("S3") or {},
        )
        relations: Relations = []
        if cw.get("Enabled"):
            relations.append(
                rel(self._log_group_ref(cw.get("LogGroup")), EdgeType.LOGS_TO, "LOGS_TO")
            )
        if fh.get("Enabled") and fh.get("DeliveryStream"):
            relations.append(
                rel(
                    self._arn("firehose", f"deliverystream/{fh['DeliveryStream']}"),
                    EdgeType.LOGS_TO,
                    "LOGS_TO",
                )
            )
        if s3.get("Enabled") and s3.get("Bucket"):
            relations.append(rel(f"arn:aws:s3:::{s3['Bucket']}", EdgeType.LOGS_TO, "LOGS_TO"))
        return relations

    def _msk_provisioned(self, prov: dict) -> tuple[Relations, list[str], dict[str, Any], bool]:
        """(relations, security groups, metadata, exposed) of a provisioned
        cluster; empty for serverless clusters."""
        if not prov:
            return [], [], {}, False
        nodes = prov.get("BrokerNodeGroupInfo") or {}
        relations = self._subnet_rels(nodes.get("ClientSubnets"))
        sgs = list(nodes.get("SecurityGroups") or [])
        public = ((nodes.get("ConnectivityInfo") or {}).get("PublicAccess") or {}).get("Type")
        kms = ((prov.get("EncryptionInfo") or {}).get("EncryptionAtRest") or {}).get(
            "DataVolumeKMSKeyId"
        )
        relations.append(rel(_kms_ref(kms), EdgeType.REFERENCES, "ENCRYPTED_BY_KMS"))
        relations += self._msk_log_rels((prov.get("LoggingInfo") or {}).get("BrokerLogs") or {})
        metadata = _msk_provisioned_metadata(prov, nodes, public, kms)
        return relations, sgs, metadata, bool(public) and public != "DISABLED"

    async def _msk_policy(self, kafka: Any, arn: str) -> Any:
        try:
            return (await kafka.get_cluster_policy(ClusterArn=arn)).get("Policy")
        except Exception as exc:
            if "NotFound" not in error_code(exc):
                logger.debug("MSK policy lookup failed for %s: %s", arn, exc)
        return None

    async def _msk_detail(self, kafka: Any, c: dict) -> CloudAsset:
        arn = c["ClusterArn"]
        md: dict[str, Any] = {
            "service": "msk",
            "cluster_type": c.get("ClusterType"),
            "state": c.get("State"),
            "kafka_version": c.get("CurrentVersion"),
        }
        relations, sgs, provisioned, exposed = self._msk_provisioned(c.get("Provisioned") or {})
        md.update(provisioned)
        for vc in (c.get("Serverless") or {}).get("VpcConfigs") or []:
            relations += self._subnet_rels(vc.get("SubnetIds"))
            sgs += vc.get("SecurityGroupIds") or []
        policy = await self._msk_policy(kafka, arn)
        grants, public_policy = self._grant_rels(policy, "MSK cluster policy grant")
        relations += grants
        md["security_groups"] = sorted(set(sgs))
        md["policy_allows_public"] = public_policy
        return self._asset(
            arn=arn,
            name=c.get("ClusterName") or arn,
            asset_type=AssetType.MESSAGE_BROKER,
            tags=c.get("Tags"),
            metadata=md,
            relations=relations,
            exposed=exposed,
        )

    # ------------------------------------------------------------------
    # Amazon MQ
    # ------------------------------------------------------------------

    async def _collect_amazon_mq(self) -> list[CloudAsset]:
        async with self._client("mq") as mq:
            brokers = [b async for b in self._paginate(mq, "list_brokers", "BrokerSummaries")]
            return await _gather_details(brokers, lambda b: self._amazon_mq_detail(mq, b))

    def _amazon_mq_relations(self, b: dict, broker_id: str, kms: str | None) -> Relations:
        relations: Relations = self._subnet_rels(b.get("SubnetIds"))
        relations.append(rel(kms, EdgeType.REFERENCES, "ENCRYPTED_BY_KMS"))
        logs = b.get("Logs") or {}
        for kind, key in (("General", "GeneralLogGroup"), ("Audit", "AuditLogGroup")):
            if logs.get(kind):
                group = logs.get(key) or f"/aws/amazonmq/broker/{broker_id}/{kind.lower()}"
                relations.append(
                    rel(self._log_group_ref(group), EdgeType.LOGS_TO, "LOGS_TO", log_type=kind)
                )
        replica = b.get("DataReplicationMetadata") or {}
        counterpart = (replica.get("DataReplicationCounterpart") or {}).get("BrokerId")
        if counterpart:
            relations.append(
                rel(
                    counterpart,
                    EdgeType.REFERENCES,
                    "REPLICATES_TO",
                    reverse=replica.get("DataReplicationRole") != "PRIMARY",
                )
            )
        return relations

    @staticmethod
    def _amazon_mq_hosts(b: dict) -> list[str]:
        hosts = []
        for inst in b.get("BrokerInstances") or []:
            hosts += [_host(e) for e in inst.get("Endpoints") or []]
            hosts.append(_host(inst.get("ConsoleURL")))
        return sorted({h for h in hosts if h})

    async def _amazon_mq_detail(self, mq: Any, summary: dict) -> CloudAsset:
        broker_id = summary["BrokerId"]
        b = await mq.describe_broker(BrokerId=broker_id)
        enc = b.get("EncryptionOptions") or {}
        kms = None if enc.get("UseAwsOwnedKey", True) else _kms_ref(enc.get("KmsKeyId"))
        relations = self._amazon_mq_relations(b, broker_id, kms)
        logs = b.get("Logs") or {}
        hosts = self._amazon_mq_hosts(b)
        return self._asset(
            arn=b.get("BrokerArn") or summary.get("BrokerArn", ""),
            name=b.get("BrokerName") or broker_id,
            asset_type=AssetType.MESSAGE_BROKER,
            tags=b.get("Tags"),
            metadata={
                "service": "amazon-mq",
                "broker_id": broker_id,
                "engine": b.get("EngineType"),
                "engine_version": b.get("EngineVersion"),
                "deployment_mode": b.get("DeploymentMode"),
                "state": b.get("BrokerState"),
                "publicly_accessible": bool(b.get("PubliclyAccessible")),
                "authentication_strategy": b.get("AuthenticationStrategy"),
                "security_groups": b.get("SecurityGroups") or [],
                "kms_key_id": kms,
                "aws_owned_key": enc.get("UseAwsOwnedKey"),
                "general_logs": bool(logs.get("General")),
                "audit_logs": bool(logs.get("Audit")),
                "user_count": len(b.get("Users") or []),
                "ldap_hosts": (b.get("LdapServerMetadata") or {}).get("Hosts") or [],
                "endpoints": hosts,
            },
            relations=relations,
            exposed=bool(b.get("PubliclyAccessible")),
            aliases=[broker_id, *hosts],
        )
