"""Data services: Spanner, Bigtable, Firestore, BigQuery tables, connections
and transfers, Dataplex and Data Catalog, Data Fusion, Datastream, Storage
Transfer, NetApp Volumes, Filestore backups, Dataproc Metastore, Secret
Manager rotation and Parameter Manager."""

from __future__ import annotations

import re
from typing import Any

from cloudg.inventory.gcp_relations._refs import (
    bq_dataset_ref,
    gcs_ref,
    host_target,
    parent_of,
    secret_version_ref,
)
from cloudg.inventory.gcp_relations.context import Extracted, GCPContext, _extractor
from cloudg.inventory.gcp_relations.names import (
    _list,
    _num,
    dig,
    full_name,
    network_ref,
)
from cloudg.schema.models import EdgeType

# ---------------------------------------------------------------------------
# Spanner
# ---------------------------------------------------------------------------


@_extractor("spanner.googleapis.com/Instance")
def _spanner_instance(ctx: GCPContext, out: Extracted) -> None:
    d = ctx.data
    out.metadata.update(
        instance_config=str(d.get("config") or "").rsplit("/", 1)[-1] or None,
        node_count=_num(d.get("nodeCount")),
        processing_units=_num(d.get("processingUnits")),
        autoscaling=bool(d.get("autoscalingConfig")),
        edition=d.get("edition"),
    )


@_extractor("spanner.googleapis.com/Database")
def _spanner_database(ctx: GCPContext, out: Extracted) -> None:
    d = ctx.data
    out.add(
        parent_of(ctx.name, "databases"),
        EdgeType.CONTAINS,
        "CLUSTER_CONTAINS_SERVICE",
        reverse=True,
    )
    out.add(
        full_name(dig(d, "restoreInfo", "backupInfo", "backup"), "spanner"),
        EdgeType.REFERENCES,
        "DEPENDS_ON",
        description="restored from backup",
    )
    out.metadata.update(
        dialect=d.get("databaseDialect"),
        drop_protection=bool(d.get("enableDropProtection")),
        version_retention_period=d.get("versionRetentionPeriod"),
    )


@_extractor("spanner.googleapis.com/Backup")
def _spanner_backup(ctx: GCPContext, out: Extracted) -> None:
    d = ctx.data
    out.add(
        full_name(d.get("database"), "spanner"),
        EdgeType.REFERENCES,
        "BACKUP_TO",
        reverse=True,
        description="database backup",
    )
    out.metadata.update(expire_time=d.get("expireTime"), size_bytes=_num(d.get("sizeBytes")))


@_extractor("spanner.googleapis.com/InstancePartition")
def _spanner_partition(ctx: GCPContext, out: Extracted) -> None:
    out.add(parent_of(ctx.name, "instancePartitions"), EdgeType.CONTAINS, reverse=True)


# ---------------------------------------------------------------------------
# Bigtable
# ---------------------------------------------------------------------------


@_extractor("bigtableadmin.googleapis.com/Instance")
def _bigtable_instance(ctx: GCPContext, out: Extracted) -> None:
    out.metadata.update(instance_type=ctx.data.get("type"), edition=ctx.data.get("edition"))


@_extractor("bigtableadmin.googleapis.com/Cluster")
def _bigtable_cluster(ctx: GCPContext, out: Extracted) -> None:
    d = ctx.data
    out.add(
        parent_of(ctx.name, "clusters"), EdgeType.CONTAINS, "CLUSTER_CONTAINS_SERVICE", reverse=True
    )
    out.metadata.update(
        serve_nodes=_num(d.get("serveNodes")),
        storage_type=d.get("defaultStorageType"),
        autoscaling=bool(dig(d, "clusterConfig", "clusterAutoscalingConfig")),
    )


@_extractor(
    "bigtableadmin.googleapis.com/Table",
    "bigtableadmin.googleapis.com/LogicalView",
    "bigtableadmin.googleapis.com/MaterializedView",
)
def _bigtable_table(ctx: GCPContext, out: Extracted) -> None:
    d = ctx.data
    parent = (
        parent_of(ctx.name, "tables")
        or parent_of(ctx.name, "logicalViews")
        or parent_of(ctx.name, "materializedViews")
    )
    out.add(parent, EdgeType.CONTAINS, reverse=True)
    out.metadata.update(
        deletion_protection=d.get("deletionProtection"),
        change_stream=bool(d.get("changeStreamConfig")),
    )


@_extractor("bigtableadmin.googleapis.com/AuthorizedView")
def _bigtable_authorized_view(ctx: GCPContext, out: Extracted) -> None:
    out.add(parent_of(ctx.name, "authorizedViews"), EdgeType.CONTAINS, reverse=True)


@_extractor("bigtableadmin.googleapis.com/Backup")
def _bigtable_backup(ctx: GCPContext, out: Extracted) -> None:
    d = ctx.data
    out.add(
        full_name(d.get("sourceTable"), "bigtableadmin"),
        EdgeType.REFERENCES,
        "BACKUP_TO",
        reverse=True,
        description="table backup",
    )
    out.metadata.update(expire_time=d.get("expireTime"), backup_type=d.get("backupType"))


@_extractor("bigtableadmin.googleapis.com/AppProfile")
def _bigtable_app_profile(ctx: GCPContext, out: Extracted) -> None:
    d = ctx.data
    instance = parent_of(ctx.name, "appProfiles")
    out.add(instance, EdgeType.CONTAINS, reverse=True)
    clusters = []
    single = dig(d, "singleClusterRouting", "clusterId")
    if single:
        clusters.append(single)
    clusters += list(dig(d, "multiClusterRoutingUseAny", "clusterIds", default=[]) or [])
    for cluster in clusters:
        if instance:
            out.add(f"{instance}/clusters/{cluster}", EdgeType.ROUTE, "SERVES_TRAFFIC_TO")
    out.metadata["routing"] = "single" if single else "multi"


# ---------------------------------------------------------------------------
# Firestore
# ---------------------------------------------------------------------------


@_extractor("firestore.googleapis.com/Database")
def _firestore_database(ctx: GCPContext, out: Extracted) -> None:
    d = ctx.data
    out.metadata.update(
        database_type=d.get("type"),
        concurrency_mode=d.get("concurrencyMode"),
        point_in_time_recovery=d.get("pointInTimeRecoveryEnablement"),
        delete_protection=d.get("deleteProtectionState"),
        edition=d.get("databaseEdition"),
    )


@_extractor("firestore.googleapis.com/Backup")
def _firestore_backup(ctx: GCPContext, out: Extracted) -> None:
    d = ctx.data
    out.add(
        full_name(d.get("database"), "firestore"),
        EdgeType.REFERENCES,
        "BACKUP_TO",
        reverse=True,
        description="database backup",
    )
    out.metadata.update(expire_time=d.get("expireTime"), backup_state=d.get("state"))


@_extractor("firestore.googleapis.com/BackupSchedule")
def _firestore_backup_schedule(ctx: GCPContext, out: Extracted) -> None:
    """Backup schedules come from the Firestore API (not Cloud Asset Inventory)."""
    d = ctx.data
    out.add(
        parent_of(ctx.name, "backupSchedules"),
        EdgeType.MANAGES,
        "BACKUP_TO",
        description="scheduled database backups",
    )
    out.metadata.update(
        retention=d.get("retention"),
        recurrence="weekly" if d.get("weeklyRecurrence") else "daily",
    )


# ---------------------------------------------------------------------------
# BigQuery tables, connections and transfers
# ---------------------------------------------------------------------------

_SQL_REF_RE = re.compile(r"`([A-Za-z0-9_-]+(?:[.:][A-Za-z0-9_$-]+){1,2})`")
_SQL_FROM_RE = re.compile(
    r"\b(?:FROM|JOIN)\s+([A-Za-z0-9_-]+\.[A-Za-z0-9_]+(?:\.[A-Za-z0-9_$]+)?)\b", re.IGNORECASE
)


def sql_table_refs(query: Any, default_project: str | None) -> list[str]:
    """BigQuery tables a SQL query reads (backticked or after FROM / JOIN)."""
    if not isinstance(query, str) or not query:
        return []
    refs: list[str] = []
    for raw in _SQL_REF_RE.findall(query) + _SQL_FROM_RE.findall(query):
        parts = re.split(r"[.:]", raw)
        if len(parts) == 2:
            parts = [default_project or "", *parts]
        if len(parts) != 3 or not parts[0]:
            continue
        ref = f"//bigquery.googleapis.com/projects/{parts[0]}/datasets/{parts[1]}/tables/{parts[2]}"
        if ref not in refs:
            refs.append(ref)
    return refs


def _bq_connection_ref(value: Any) -> str | None:
    """``projects/p/locations/l/connections/c`` or ``p.l.c`` as a full name."""
    if not isinstance(value, str) or not value:
        return None
    if "/connections/" in value:
        return full_name(value, "bigqueryconnection")
    parts = value.split(".")
    if len(parts) == 3:
        return (
            f"//bigqueryconnection.googleapis.com/projects/{parts[0]}"
            f"/locations/{parts[1]}/connections/{parts[2]}"
        )
    return None


def _table_reference(ref: Any) -> str | None:
    if not isinstance(ref, dict):
        return None
    pid, ds, tbl = ref.get("projectId"), ref.get("datasetId"), ref.get("tableId")
    if pid and ds and tbl:
        return f"//bigquery.googleapis.com/projects/{pid}/datasets/{ds}/tables/{tbl}"
    return None


@_extractor("bigquery.googleapis.com/Table")
def _bq_table(ctx: GCPContext, out: Extracted) -> None:
    d = ctx.data
    out.add(parent_of(ctx.name, "tables"), EdgeType.CONTAINS, reverse=True)
    project = dig(d, "tableReference", "projectId") or ctx.project_id
    query = dig(d, "view", "query") or dig(d, "materializedView", "query")
    for ref in sql_table_refs(query, project):
        if ref != ctx.name:
            out.add(ref, EdgeType.REFERENCES, "READS_FROM", description="view query source")
    ext = d.get("externalDataConfiguration") or {}
    for uri in _list(ext.get("sourceUris")):
        out.add(gcs_ref(str(uri).split("*", 1)[0]), EdgeType.REFERENCES, "READS_FROM")
    biglake = d.get("biglakeConfiguration") or {}
    out.add(gcs_ref(biglake.get("storageUri")), EdgeType.REFERENCES, "READS_FROM")
    for conn in (ext.get("connectionId"), biglake.get("connectionId")):
        out.add(_bq_connection_ref(conn), EdgeType.REFERENCES, "DEPENDS_ON")
    for key in ("snapshotDefinition", "cloneDefinition"):
        out.add(
            _table_reference(dig(d, key, "baseTableReference")),
            EdgeType.REFERENCES,
            "BACKUP_TO" if key == "snapshotDefinition" else "REPLICATES_TO",
            reverse=True,
        )
    out.metadata.update(
        table_type=d.get("type"),
        num_rows=_num(d.get("numRows")),
        num_bytes=_num(d.get("numBytes")),
        partitioned=bool(d.get("timePartitioning") or d.get("rangePartitioning")),
        require_partition_filter=d.get("requirePartitionFilter"),
        expiration_time=_num(d.get("expirationTime")),
    )


@_extractor("bigquery.googleapis.com/Routine")
def _bq_routine(ctx: GCPContext, out: Extracted) -> None:
    d = ctx.data
    out.add(parent_of(ctx.name, "routines"), EdgeType.CONTAINS, reverse=True)
    project = dig(d, "routineReference", "projectId") or ctx.project_id
    for ref in sql_table_refs(d.get("definitionBody"), project):
        out.add(ref, EdgeType.REFERENCES, "READS_FROM")
    out.add(
        _bq_connection_ref(dig(d, "remoteFunctionOptions", "connection")),
        EdgeType.REFERENCES,
        "DEPENDS_ON",
    )
    out.metadata.update(routine_type=d.get("routineType"), language=d.get("language"))


@_extractor("bigquery.googleapis.com/Model")
def _bq_model(ctx: GCPContext, out: Extracted) -> None:
    out.add(parent_of(ctx.name, "models"), EdgeType.CONTAINS, reverse=True)
    out.metadata["model_type"] = ctx.data.get("modelType")


@_extractor("bigquery.googleapis.com/RowAccessPolicy")
def _bq_row_access(ctx: GCPContext, out: Extracted) -> None:
    out.add(
        parent_of(ctx.name, "rowAccessPolicies"),
        EdgeType.GOVERNS,
        "COMPLIANCE_GOVERNS",
        description="row-level security",
    )
    out.metadata["filter_predicate"] = ctx.data.get("filterPredicate")


@_extractor("bigqueryconnection.googleapis.com/Connection")
def _bq_connection(ctx: GCPContext, out: Extracted) -> None:
    d = ctx.data
    sql = d.get("cloudSql") or {}
    parts = str(sql.get("instanceId") or "").split(":")
    if len(parts) == 3:
        out.add(
            f"//cloudsql.googleapis.com/projects/{parts[0]}/instances/{parts[2]}",
            EdgeType.REFERENCES,
            "READS_FROM",
            database=sql.get("database"),
        )
    out.add(
        full_name(dig(d, "cloudSpanner", "database"), "spanner"),
        EdgeType.REFERENCES,
        "READS_FROM",
    )
    role = dig(d, "aws", "accessRole", "iamRoleId")
    out.add(
        role,
        EdgeType.ASSUMES_ROLE,
        "CROSS_ACCOUNT_TRUST",
        description="BigQuery Omni assumes the AWS role",
    )
    for key in ("cloudSql", "cloudResource", "spark"):
        out.sa(dig(d, key, "serviceAccountId"), ctx, "connection identity")
    out.add(
        full_name(dig(d, "spark", "metastoreService"), "metastore"),
        EdgeType.REFERENCES,
        "DEPENDS_ON",
    )
    kind = next(
        (
            k
            for k in ("cloudSql", "aws", "azure", "cloudSpanner", "cloudResource", "spark")
            if d.get(k)
        ),
        None,
    )
    out.metadata.update(
        connection_type=kind,
        azure_tenant=dig(d, "azure", "customerTenantId"),
        aws_role=role,
    )


@_extractor("bigquerydatatransfer.googleapis.com/TransferConfig")
def _bq_transfer(ctx: GCPContext, out: Extracted) -> None:
    d = ctx.data
    out.add(
        bq_dataset_ref(ctx.project_id, d.get("destinationDatasetId")),
        EdgeType.REFERENCES,
        "WRITES_TO",
        description="transfer destination dataset",
    )
    params = d.get("params") or {}
    for key in ("data_path_template", "data_path"):
        value = params.get(key)
        if isinstance(value, str) and value.startswith("gs://"):
            out.add(gcs_ref(value.split("*", 1)[0]), EdgeType.REFERENCES, "READS_FROM")
        elif isinstance(value, str) and value.startswith("s3://"):
            out.add(f"arn:aws:s3:::{value[5:].split('/', 1)[0]}", EdgeType.REFERENCES, "READS_FROM")
    for ref in sql_table_refs(params.get("query"), ctx.project_id):
        out.add(ref, EdgeType.REFERENCES, "READS_FROM", description="scheduled query source")
    out.add(
        full_name(d.get("notificationPubsubTopic"), "pubsub"),
        EdgeType.INVOKES,
        "INVOKES",
        description="run notifications",
    )
    out.metadata.update(
        data_source=d.get("dataSourceId"),
        schedule=d.get("schedule"),
        disabled=d.get("disabled"),
    )


# ---------------------------------------------------------------------------
# Dataplex, Data Catalog, Dataproc Metastore
# ---------------------------------------------------------------------------


def _dataplex_resource(spec: Any) -> str | None:
    """A Dataplex asset's bucket or dataset."""
    if not isinstance(spec, dict):
        return None
    name = spec.get("name")
    if not isinstance(name, str):
        return None
    if "/buckets/" in name:
        return f"//storage.googleapis.com/{name.rsplit('/buckets/', 1)[1]}"
    if "/datasets/" in name:
        return full_name(name, "bigquery")
    return full_name(name)


@_extractor("dataplex.googleapis.com/Lake")
def _dataplex_lake(ctx: GCPContext, out: Extracted) -> None:
    d = ctx.data
    out.add(
        full_name(dig(d, "metastore", "service"), "metastore"), EdgeType.REFERENCES, "DEPENDS_ON"
    )
    out.sa(d.get("serviceAccount"), ctx, "lake service agent")


@_extractor("dataplex.googleapis.com/Zone")
def _dataplex_zone(ctx: GCPContext, out: Extracted) -> None:
    out.add(parent_of(ctx.name, "zones"), EdgeType.CONTAINS, reverse=True)
    out.metadata["zone_type"] = ctx.data.get("type")


@_extractor("dataplex.googleapis.com/Asset")
def _dataplex_asset(ctx: GCPContext, out: Extracted) -> None:
    d = ctx.data
    out.add(parent_of(ctx.name, "assets"), EdgeType.CONTAINS, reverse=True)
    out.add(
        _dataplex_resource(d.get("resourceSpec")),
        EdgeType.GOVERNS,
        "COMPLIANCE_GOVERNS",
        description="Dataplex governs the resource",
    )
    out.metadata["resource_type"] = dig(d, "resourceSpec", "type")


@_extractor("dataplex.googleapis.com/Task")
def _dataplex_task(ctx: GCPContext, out: Extracted) -> None:
    d = ctx.data
    out.add(parent_of(ctx.name, "tasks"), EdgeType.CONTAINS, reverse=True)
    out.sa(dig(d, "executionSpec", "serviceAccount"), ctx, "task identity")
    spark = d.get("spark") or {}
    for key in ("mainJarFileUri", "pythonScriptFile", "sqlScriptFile"):
        uri = spark.get(key)
        if isinstance(uri, str) and uri.startswith("gs://"):
            out.add(gcs_ref(uri), EdgeType.REFERENCES, "READS_FROM")
    out.metadata["trigger"] = dig(d, "triggerSpec", "type")


@_extractor("dataplex.googleapis.com/DataScan")
def _dataplex_scan(ctx: GCPContext, out: Extracted) -> None:
    d = ctx.data
    target = full_name(dig(d, "data", "resource")) or full_name(
        dig(d, "data", "entity"), "dataplex"
    )
    out.add(
        target,
        EdgeType.MONITORS,
        "MONITORED_BY",
        description=f"{d.get('type') or 'data'} scan",
    )
    out.metadata.update(
        scan_type=d.get("type"), trigger=list((dig(d, "executionSpec", "trigger") or {}).keys())
    )


@_extractor(
    "dataplex.googleapis.com/EntryGroup",
    "datacatalog.googleapis.com/EntryGroup",
    "datacatalog.googleapis.com/TagTemplate",
    "datacatalog.googleapis.com/Taxonomy",
)
def _catalog_container(ctx: GCPContext, out: Extracted) -> None:
    d = ctx.data
    out.metadata.update(
        activated_policy_types=list(d.get("activatedPolicyTypes") or []) or None,
        field_count=len(d.get("fields") or {}) or None,
        publicly_readable=d.get("isPubliclyReadable"),
    )


@_extractor("metastore.googleapis.com/Service")
def _metastore(ctx: GCPContext, out: Extracted) -> None:
    d = ctx.data
    out.add(full_name(d.get("network"), "compute"), EdgeType.ATTACHED_TO)
    for consumer in _list(dig(d, "networkConfig", "consumers")):
        if isinstance(consumer, dict):
            out.in_subnet(full_name(consumer.get("subnetwork"), "compute"))
    out.add(gcs_ref(d.get("artifactGcsUri")), EdgeType.REFERENCES, "WRITES_TO")
    out.metadata.update(
        tier=d.get("tier"), database_type=d.get("databaseType"), endpoint=d.get("endpointUri")
    )


# ---------------------------------------------------------------------------
# Data Fusion, Datastream, Storage Transfer
# ---------------------------------------------------------------------------


@_extractor("datafusion.googleapis.com/Instance")
def _datafusion(ctx: GCPContext, out: Extracted) -> None:
    d = ctx.data
    nc = d.get("networkConfig") or {}
    out.add(network_ref(nc.get("network"), ctx.project_id), EdgeType.ATTACHED_TO)
    for key in ("dataprocServiceAccount", "p4ServiceAccount", "serviceAccount"):
        out.sa(d.get(key), ctx, f"Data Fusion {key}")
    for url in (d.get("apiEndpoint"), d.get("serviceEndpoint")):
        out.alias(host_target(url))
    private = bool(d.get("privateInstance"))
    if not private:
        out.expose("Data Fusion public instance endpoint", protocol="tcp", ports=["443"])
    out.metadata.update(
        private_instance=private,
        edition=d.get("type"),
        version=d.get("version"),
        enable_rbac=d.get("enableRbac"),
    )


@_extractor("datafusion.googleapis.com/DnsPeering")
def _datafusion_dns_peering(ctx: GCPContext, out: Extracted) -> None:
    d = ctx.data
    out.add(parent_of(ctx.name, "dnsPeerings"), EdgeType.CONTAINS, reverse=True)
    out.add(
        network_ref(d.get("targetNetwork"), d.get("targetProject")), EdgeType.ROUTE, "DNS_RESOLVED"
    )


@_extractor("datastream.googleapis.com/Stream")
def _datastream_stream(ctx: GCPContext, out: Extracted) -> None:
    d = ctx.data
    out.add(
        full_name(dig(d, "sourceConfig", "sourceConnectionProfile"), "datastream"),
        EdgeType.REFERENCES,
        "READS_FROM",
        description="change data capture source",
    )
    out.add(
        full_name(dig(d, "destinationConfig", "destinationConnectionProfile"), "datastream"),
        EdgeType.INVOKES,
        "STREAMS_TO",
        description="stream destination",
    )
    out.metadata.update(stream_state=d.get("state"), backfill_all=bool(d.get("backfillAll")))


@_extractor("datastream.googleapis.com/ConnectionProfile")
def _datastream_profile(ctx: GCPContext, out: Extracted) -> None:
    d = ctx.data
    out.add(gcs_ref(dig(d, "gcsProfile", "bucket")), EdgeType.REFERENCES, "DEPENDS_ON")
    kind = None
    for key in ("mysqlProfile", "postgresqlProfile", "oracleProfile", "sqlServerProfile"):
        prof = d.get(key)
        if isinstance(prof, dict):
            kind = key.removesuffix("Profile")
            out.add(prof.get("hostname"), EdgeType.REFERENCES, "DEPENDS_ON", port=prof.get("port"))
    out.add(
        full_name(dig(d, "privateConnectivity", "privateConnection"), "datastream"),
        EdgeType.REFERENCES,
        "DEPENDS_ON",
    )
    out.metadata.update(
        profile_type=kind
        or next(
            (k.removesuffix("Profile") for k in ("gcsProfile", "bigqueryProfile") if k in d), None
        ),
        connectivity=next(
            (
                k
                for k in (
                    "privateConnectivity",
                    "staticServiceIpConnectivity",
                    "forwardSshConnectivity",
                )
                if k in d
            ),
            None,
        ),
    )


@_extractor("datastream.googleapis.com/PrivateConnection")
def _datastream_private_connection(ctx: GCPContext, out: Extracted) -> None:
    cfg = ctx.data.get("vpcPeeringConfig") or {}
    out.add(full_name(cfg.get("vpc"), "compute"), EdgeType.PEERING, "VPC_PEERED")
    out.metadata["subnet"] = cfg.get("subnet")


@_extractor("storagetransfer.googleapis.com/TransferJob")
def _transfer_job(ctx: GCPContext, out: Extracted) -> None:
    d = ctx.data
    spec = d.get("transferSpec") or d.get("replicationSpec") or {}
    out.add(gcs_ref(dig(spec, "gcsDataSource", "bucketName")), EdgeType.REFERENCES, "READS_FROM")
    out.add(gcs_ref(dig(spec, "gcsDataSink", "bucketName")), EdgeType.REFERENCES, "WRITES_TO")
    s3 = spec.get("awsS3DataSource") or {}
    if s3.get("bucketName"):
        out.add(f"arn:aws:s3:::{s3['bucketName']}", EdgeType.REFERENCES, "READS_FROM")
    out.add(
        s3.get("roleArn"),
        EdgeType.ASSUMES_ROLE,
        "CROSS_ACCOUNT_TRUST",
        description="Storage Transfer assumes the AWS role",
    )
    azure = spec.get("azureBlobStorageDataSource") or {}
    if azure.get("storageAccount"):
        out.add(
            host_target(f"{azure['storageAccount']}.blob.core.windows.net"),
            EdgeType.REFERENCES,
            "READS_FROM",
            container=azure.get("container"),
        )
    for src in (s3, azure):
        out.add(secret_version_ref(src.get("credentialsSecret")), EdgeType.REFERENCES, "READS_FROM")
    out.add(
        full_name(dig(d, "notificationConfig", "pubsubTopic"), "pubsub"),
        EdgeType.INVOKES,
        "INVOKES",
    )
    stream = dig(d, "eventStream", "name")
    out.add(full_name(stream, "pubsub") or stream, EdgeType.REFERENCES, "READS_FROM")
    out.metadata.update(
        transfer_status=d.get("status"),
        source_type=next((k for k in spec if k.endswith("DataSource")), None),
        schedule_start=dig(d, "schedule", "scheduleStartDate"),
        repeat_interval=dig(d, "schedule", "repeatInterval"),
    )


# ---------------------------------------------------------------------------
# NetApp Volumes, Filestore backups
# ---------------------------------------------------------------------------


@_extractor("netapp.googleapis.com/StoragePool")
def _netapp_pool(ctx: GCPContext, out: Extracted) -> None:
    d = ctx.data
    out.add(network_ref(d.get("network"), ctx.project_id), EdgeType.ATTACHED_TO)
    out.add(full_name(d.get("activeDirectory"), "netapp"), EdgeType.REFERENCES, "DEPENDS_ON")
    out.add(full_name(d.get("kmsConfig"), "netapp"), EdgeType.REFERENCES, "DEPENDS_ON")
    out.metadata.update(
        service_level=d.get("serviceLevel"), capacity_gib=_num(d.get("capacityGib"))
    )


@_extractor("netapp.googleapis.com/Volume")
def _netapp_volume(ctx: GCPContext, out: Extracted) -> None:
    d = ctx.data
    out.add(full_name(d.get("storagePool"), "netapp"), EdgeType.CONTAINS, reverse=True)
    out.add(network_ref(d.get("network"), ctx.project_id), EdgeType.ATTACHED_TO)
    backup = d.get("backupConfig") or {}
    out.add(full_name(backup.get("backupVault"), "netapp"), EdgeType.REFERENCES, "BACKUP_TO")
    for policy in _list(backup.get("backupPolicies")):
        out.add(full_name(policy, "netapp"), EdgeType.REFERENCES, "DEPENDS_ON")
    clients = sorted(
        {
            c.strip()
            for r in _list(dig(d, "exportPolicy", "rules"))
            if isinstance(r, dict)
            for c in str(r.get("allowedClients") or "").split(",")
            if c.strip()
        }
    )
    out.metadata.update(
        protocols=list(d.get("protocols") or []),
        capacity_gib=_num(d.get("capacityGib")),
        allowed_clients=clients,
        snapshot_policy=bool(dig(d, "snapshotPolicy", "enabled")),
    )


@_extractor("netapp.googleapis.com/Replication")
def _netapp_replication(ctx: GCPContext, out: Extracted) -> None:
    d = ctx.data
    out.add(parent_of(ctx.name, "replications"), EdgeType.CONTAINS, reverse=True)
    out.add(
        full_name(d.get("destinationVolume"), "netapp"),
        EdgeType.REFERENCES,
        "REPLICATES_TO",
        description="volume replication",
    )
    out.metadata.update(replication_schedule=d.get("replicationSchedule"), role=d.get("role"))


@_extractor("netapp.googleapis.com/Backup", "netapp.googleapis.com/Snapshot")
def _netapp_backup(ctx: GCPContext, out: Extracted) -> None:
    d = ctx.data
    parent = parent_of(ctx.name, "backups") or parent_of(ctx.name, "snapshots")
    source = full_name(d.get("sourceVolume"), "netapp")
    if "/snapshots/" in ctx.name:
        source = source or parent
    else:
        out.add(parent, EdgeType.CONTAINS, reverse=True)
    out.add(source, EdgeType.REFERENCES, "BACKUP_TO", reverse=True, description="volume backup")


@_extractor(
    "netapp.googleapis.com/BackupVault",
    "netapp.googleapis.com/BackupPolicy",
    "netapp.googleapis.com/ActiveDirectory",
    "netapp.googleapis.com/KmsConfig",
)
def _netapp_misc(ctx: GCPContext, out: Extracted) -> None:
    d = ctx.data
    out.metadata.update(
        domain=d.get("domain"),
        enabled=d.get("enabled"),
        daily_backup_limit=_num(d.get("dailyBackupLimit")),
        vault_type=d.get("backupVaultType"),
    )


@_extractor("file.googleapis.com/Backup")
def _filestore_backup(ctx: GCPContext, out: Extracted) -> None:
    d = ctx.data
    out.add(
        full_name(d.get("sourceInstance"), "file"),
        EdgeType.REFERENCES,
        "BACKUP_TO",
        reverse=True,
        description="file share backup",
    )
    out.metadata.update(
        source_file_share=d.get("sourceFileShare"), storage_bytes=_num(d.get("storageBytes"))
    )


# ---------------------------------------------------------------------------
# Secret Manager rotation, Parameter Manager
# ---------------------------------------------------------------------------


@_extractor("secretmanager.googleapis.com/Secret")
def _secret_rotation(ctx: GCPContext, out: Extracted) -> None:
    """Rotation schedule and notification topics (the rotator subscribes to them)."""
    d = ctx.data
    rotation = d.get("rotation") or {}
    topics = [
        full_name(t.get("name"), "pubsub") for t in _list(d.get("topics")) if isinstance(t, dict)
    ]
    out.metadata.update(
        rotation_period=rotation.get("rotationPeriod"),
        next_rotation_time=rotation.get("nextRotationTime"),
        rotation_topics=[t for t in topics if t] if rotation else [],
        expire_time=d.get("expireTime"),
        version_destroy_ttl=d.get("versionDestroyTtl"),
    )


@_extractor("parametermanager.googleapis.com/Parameter")
def _parameter(ctx: GCPContext, out: Extracted) -> None:
    d = ctx.data
    out.metadata.update(
        format=d.get("format"),
        principal=dig(d, "policyMember", "iamPolicyUidPrincipal"),
    )


@_extractor("parametermanager.googleapis.com/ParameterVersion")
def _parameter_version(ctx: GCPContext, out: Extracted) -> None:
    out.add(parent_of(ctx.name, "versions"), EdgeType.CONTAINS, reverse=True)
    out.metadata["disabled"] = ctx.data.get("disabled")


__all__ = ["sql_table_refs"]


@_extractor("cloudkms.googleapis.com/KeyRing")
def _key_ring(ctx: GCPContext, out: Extracted) -> None:
    out.metadata["key_ring"] = ctx.name.rsplit("/", 1)[-1]
