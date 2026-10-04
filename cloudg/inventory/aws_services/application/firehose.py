"""Kinesis Data Firehose delivery streams: sources, delivery roles, record
transformation, destinations (endpoint hosts only, never Splunk HEC tokens)
and S3 backup."""

from __future__ import annotations

from typing import Any

from cloudg.inventory.aws_services._base import gather_limited, rel
from cloudg.inventory.aws_services.application._common import (
    ApplicationBase,
    _host,
    _role_rel,
    _vpc_config,
)
from cloudg.schema.models import AssetType, CloudAsset, EdgeType

# Destination fields whose host is recorded as ``endpoint_host``, in the
# order they override one another.
_ENDPOINT_HOST_FIELDS = ("ClusterEndpoint", "HECEndpoint")


def _firehose_redshift_relations(d: dict, summary: dict[str, Any]) -> list[dict | None]:
    """Redshift cluster found by its JDBC endpoint host; the host itself
    (never credentials) goes into ``summary``."""
    relations: list[dict | None] = []
    if d.get("ClusterJDBCURL"):
        host = _host(d["ClusterJDBCURL"].replace("jdbc:redshift://", "https://"))
        summary["endpoint_host"] = host
        if host and ".redshift." in host:
            relations.append(
                rel(
                    host.split(".", 1)[0],
                    EdgeType.INVOKES,
                    "STREAMS_TO",
                    description="Redshift destination",
                )
            )
    return relations


def _firehose_endpoint_summary(d: dict, summary: dict[str, Any]) -> None:
    # Splunk: endpoint host only, never the HEC token
    for field in _ENDPOINT_HOST_FIELDS:
        if d.get(field):
            summary["endpoint_host"] = _host(d[field])
    endpoint = d.get("EndpointConfiguration") or {}
    if endpoint.get("Url"):
        summary["endpoint_host"] = _host(endpoint["Url"])
        summary["endpoint_name"] = endpoint.get("Name")
    if d.get("AccountUrl"):
        summary["endpoint_host"] = _host(d["AccountUrl"])
    vpc = d.get("VpcConfigurationDescription") or {}
    if vpc:
        summary["vpc_config"] = _vpc_config(vpc, "SubnetIds", "SecurityGroupIds")
    summary["backup_mode"] = d.get("S3BackupMode")


class FirehoseCollectorsMixin(ApplicationBase):
    """Kinesis Data Firehose collector."""

    def _firehose_block_relations(
        self, block: dict, label: str, relations: list, backup: bool = False
    ) -> None:
        """Role, KMS, logging, transformation, secret and bucket relations of
        one destination block and (recursively) its S3 backup blocks."""
        relations.append(_role_rel(block.get("RoleARN"), f"{label} delivery role"))
        kms = ((block.get("EncryptionConfiguration") or {}).get("KMSEncryptionConfig") or {}).get(
            "AWSKMSKeyARN"
        )
        relations.append(rel(kms, EdgeType.REFERENCES, "ENCRYPTED_BY_KMS"))
        logs = block.get("CloudWatchLoggingOptions") or {}
        if logs.get("Enabled") and logs.get("LogGroupName"):
            relations.append(
                rel(self._log_group_arn(logs["LogGroupName"]), EdgeType.LOGS_TO, "LOGS_TO")
            )
        for proc in (block.get("ProcessingConfiguration") or {}).get("Processors", []) or []:
            relations.extend(
                rel(
                    param.get("ParameterValue"),
                    EdgeType.INVOKES,
                    "INVOKES",
                    description="record transformation",
                )
                for param in proc.get("Parameters", []) or []
                if param.get("ParameterName") == "LambdaArn"
            )
        secret = (block.get("SecretsManagerConfiguration") or {}).get("SecretARN")
        relations.append(
            rel(
                secret, EdgeType.REFERENCES, "READS_FROM", description=f"{label} credentials secret"
            )
        )
        if block.get("BucketARN"):
            if backup:
                bucket_rel = rel(
                    block["BucketARN"],
                    EdgeType.REFERENCES,
                    "BACKUP_TO",
                    description="S3 backup / failed records",
                )
            else:
                bucket_rel = rel(
                    block["BucketARN"],
                    EdgeType.INVOKES,
                    "STREAMS_TO",
                    description=f"{label} destination",
                )
            relations.append(bucket_rel)
        for nested in ("S3DestinationDescription", "S3BackupDescription"):
            if isinstance(block.get(nested), dict):
                self._firehose_block_relations(block[nested], label, relations, backup=True)

    def _firehose_target_relations(self, d: dict, label: str) -> list[dict | None]:
        """Domain / cluster / Iceberg catalog destination targets."""
        relations: list[dict | None] = [
            rel(d[key], EdgeType.INVOKES, "STREAMS_TO", description=f"{label} destination")
            for key in ("DomainARN", "ClusterARN")
            if d.get(key)
        ]
        catalog = (d.get("CatalogConfiguration") or {}).get("CatalogARN")
        relations.append(
            rel(catalog, EdgeType.INVOKES, "STREAMS_TO", description="Iceberg catalog")
        )
        return relations

    def _firehose_collection_relations(self, d: dict, summary: dict[str, Any]) -> list[dict | None]:
        if not d.get("CollectionEndpoint"):
            return []
        host = _host(d["CollectionEndpoint"])
        summary["endpoint_host"] = host
        if not host:
            return []
        return [
            rel(
                self._arn("aoss", f"collection/{host.split('.', 1)[0]}"),
                EdgeType.INVOKES,
                "STREAMS_TO",
                description="OpenSearch Serverless destination",
            )
        ]

    def _firehose_destination(self, dest: dict) -> tuple[list[dict | None], dict[str, Any]]:
        relations: list[dict | None] = []
        for dtype, d in dest.items():
            if not isinstance(d, dict):
                continue
            label = dtype.removesuffix("DestinationDescription") or dtype
            summary: dict[str, Any] = {"type": label}
            self._firehose_block_relations(d, label, relations)
            relations += self._firehose_target_relations(d, label)
            relations += _firehose_redshift_relations(d, summary)
            relations += self._firehose_collection_relations(d, summary)
            _firehose_endpoint_summary(d, summary)
            return relations, {k: v for k, v in summary.items() if v is not None}
        return relations, {}

    def _firehose_source_relations(self, source: dict) -> list[dict | None]:
        kin = source.get("KinesisStreamSourceDescription") or {}
        msk = source.get("MSKSourceDescription") or {}
        db = source.get("DatabaseSourceDescription") or {}
        db_auth = db.get("DatabaseSourceAuthenticationConfiguration") or {}
        return [
            rel(
                kin.get("KinesisStreamARN"),
                EdgeType.INVOKES,
                "TRIGGERED_BY",
                reverse=True,
                description="Kinesis source",
            ),
            _role_rel(kin.get("RoleARN"), "source read role"),
            rel(
                msk.get("MSKClusterARN"),
                EdgeType.INVOKES,
                "TRIGGERED_BY",
                reverse=True,
                description=f"MSK source {msk.get('TopicName') or ''}".strip(),
            ),
            _role_rel(
                (msk.get("AuthenticationConfiguration") or {}).get("RoleARN"),
                "MSK connectivity role",
            ),
            rel(
                (db_auth.get("SecretsManagerConfiguration") or {}).get("SecretARN"),
                EdgeType.REFERENCES,
                "READS_FROM",
                description="database source credentials",
            ),
        ]

    def _firehose_stream_asset(self, name: str, desc: dict) -> CloudAsset:
        source = desc.get("Source") or {}
        db = source.get("DatabaseSourceDescription") or {}
        relations = self._firehose_source_relations(source)
        enc = desc.get("DeliveryStreamEncryptionConfiguration") or {}
        relations.append(rel(enc.get("KeyARN"), EdgeType.REFERENCES, "ENCRYPTED_BY_KMS"))
        destinations = []
        vpc_config = None
        for dest in desc.get("Destinations", []) or []:
            d_rels, d_summary = self._firehose_destination(dest)
            relations.extend(d_rels)
            vpc_config = vpc_config or d_summary.pop("vpc_config", None)
            destinations.append(d_summary)
        return self._asset(
            arn=desc.get("DeliveryStreamARN") or self._arn("firehose", f"deliverystream/{name}"),
            name=name,
            asset_type=AssetType.DELIVERY_STREAM,
            metadata={
                "service": "firehose",
                "status": desc.get("DeliveryStreamStatus"),
                "source_type": desc.get("DeliveryStreamType"),
                "source_database_host": _host(db.get("Endpoint")) if db else None,
                "destinations": destinations,
                "encryption": enc.get("Status"),
                "encryption_key_type": enc.get("KeyType"),
                "vpc_config": vpc_config,
            },
            relations=relations,
        )

    async def _firehose_names(self, fh: Any) -> list[str]:
        # No botocore paginator: list_delivery_streams pages by name
        names: list[str] = []
        start: str | None = None
        for _ in range(1000):
            kwargs: dict[str, Any] = {"Limit": 100}
            if start:
                kwargs["ExclusiveStartDeliveryStreamName"] = start
            resp = await fh.list_delivery_streams(**kwargs)
            page = resp.get("DeliveryStreamNames", []) or []
            names.extend(page)
            if not resp.get("HasMoreDeliveryStreams") or not page:
                break
            start = page[-1]
        return names

    async def _collect_firehose(self) -> list[CloudAsset]:
        async with self._client("firehose") as fh:
            names = await self._firehose_names(fh)

            async def detail(name: str) -> CloudAsset:
                resp = await fh.describe_delivery_stream(DeliveryStreamName=name)
                return self._firehose_stream_asset(name, resp["DeliveryStreamDescription"])

            results = await gather_limited([lambda n=n: detail(n) for n in names])
        return [a for a in results if a]
