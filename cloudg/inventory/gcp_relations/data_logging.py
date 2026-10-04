"""Logging sinks, data stores, CMEK keys, secrets and registries."""

from __future__ import annotations

from cloudg.inventory.gcp_relations.context import Extracted, GCPContext, _extractor
from cloudg.inventory.gcp_relations.names import (
    INTERNET_CIDRS,
    PUBLIC_MEMBERS,
    _list,
    _num,
    dig,
    full_name,
    network_ref,
)
from cloudg.schema.models import EdgeType


@_extractor("logging.googleapis.com/LogSink")
def _log_sink(ctx: GCPContext, out: Extracted) -> None:
    d = ctx.data
    dest = full_name(d.get("destination"))
    out.add(dest, EdgeType.LOGS_TO, "LOGS_TO", description="log sink destination")
    flt = d.get("filter")
    out.metadata.update(
        destination=dest,
        filter=flt[:500] if isinstance(flt, str) else flt,
        include_children=bool(d.get("includeChildren")),
        disabled=bool(d.get("disabled")),
        writer_identity=d.get("writerIdentity"),
        exclusion_count=len(_list(d.get("exclusions"))),
    )


@_extractor("logging.googleapis.com/LogBucket")
def _log_bucket(ctx: GCPContext, out: Extracted) -> None:
    d = ctx.data
    out.metadata.update(
        retention_days=_num(d.get("retentionDays")),
        locked=bool(d.get("locked")),
        analytics_enabled=bool(d.get("analyticsEnabled")),
    )


# ---------------------------------------------------------------------------
# Data stores
# ---------------------------------------------------------------------------


@_extractor("sqladmin.googleapis.com/Instance")
def _cloud_sql(ctx: GCPContext, out: Extracted) -> None:
    d = ctx.data
    ipc = dig(d, "settings", "ipConfiguration", default={}) or {}
    out.add(
        full_name(ipc.get("privateNetwork"), "compute"),
        EdgeType.ATTACHED_TO,
        description="private services access network",
    )
    nets = [n.get("value") for n in _list(ipc.get("authorizedNetworks")) if isinstance(n, dict)]
    ipv4 = ipc.get("ipv4Enabled", True)
    public_ips = [
        i.get("ipAddress")
        for i in _list(d.get("ipAddresses"))
        if isinstance(i, dict) and i.get("type") == "PRIMARY"
    ]
    if ipv4 and any(n in INTERNET_CIDRS for n in nets):
        out.expose(
            "Cloud SQL authorized network 0.0.0.0/0",
            protocol="tcp",
            ports=[_SQL_PORTS.get(str(d.get("databaseVersion", "")).split("_")[0], "")],
        )
    master = d.get("masterInstanceName")
    if isinstance(master, str) and master:
        pid = master.split(":", 1)[0] if ":" in master else ctx.project_id
        out.add(
            f"//cloudsql.googleapis.com/projects/{pid}/instances/{master.rsplit(':', 1)[-1]}",
            EdgeType.REFERENCES,
            "REPLICATES_TO",
            reverse=True,
        )
    for ip in public_ips:
        out.alias(ip)
    out.metadata.update(
        database_version=d.get("databaseVersion"),
        tier=dig(d, "settings", "tier"),
        public_ip_enabled=bool(ipv4),
        public_ips=public_ips,
        authorized_networks=nets,
        ssl_mode=ipc.get("sslMode") or ("ENCRYPTED_ONLY" if ipc.get("requireSsl") else None),
        backups_enabled=bool(dig(d, "settings", "backupConfiguration", "enabled")),
        availability_type=dig(d, "settings", "availabilityType"),
    )


_SQL_PORTS = {"POSTGRES": "5432", "MYSQL": "3306", "SQLSERVER": "1433"}


@_extractor("redis.googleapis.com/Instance", "memcache.googleapis.com/Instance")
def _redis(ctx: GCPContext, out: Extracted) -> None:
    d = ctx.data
    out.add(network_ref(d.get("authorizedNetwork"), ctx.project_id), EdgeType.ATTACHED_TO)
    out.metadata.update(
        connect_mode=d.get("connectMode"),
        auth_enabled=d.get("authEnabled"),
        transit_encryption=d.get("transitEncryptionMode"),
    )


@_extractor("redis.googleapis.com/Cluster")
def _redis_cluster(ctx: GCPContext, out: Extracted) -> None:
    for psc in _list(ctx.data.get("pscConfigs")):
        if isinstance(psc, dict):
            out.add(network_ref(psc.get("network"), ctx.project_id), EdgeType.ATTACHED_TO)


@_extractor("file.googleapis.com/Instance")
def _filestore(ctx: GCPContext, out: Extracted) -> None:
    for net in _list(ctx.data.get("networks")):
        if isinstance(net, dict):
            out.add(
                network_ref(net.get("network"), ctx.project_id),
                EdgeType.ATTACHED_TO,
                connect_mode=net.get("connectMode"),
            )


@_extractor("alloydb.googleapis.com/Cluster")
def _alloydb_cluster(ctx: GCPContext, out: Extracted) -> None:
    d = ctx.data
    out.add(
        network_ref(dig(d, "networkConfig", "network") or d.get("network"), ctx.project_id),
        EdgeType.ATTACHED_TO,
    )


@_extractor("alloydb.googleapis.com/Instance")
def _alloydb_instance(ctx: GCPContext, out: Extracted) -> None:
    d = ctx.data
    out.add(
        ctx.name.split("/instances/", 1)[0],
        EdgeType.CONTAINS,
        "CLUSTER_CONTAINS_SERVICE",
        reverse=True,
    )
    nc = d.get("networkConfig") or {}
    nets = [
        n.get("cidrRange")
        for n in _list(nc.get("authorizedExternalNetworks"))
        if isinstance(n, dict)
    ]
    if nc.get("enablePublicIp") and (not nets or any(n in INTERNET_CIDRS for n in nets)):
        out.expose("AlloyDB public IP", protocol="tcp", ports=["5432"])
    out.metadata.update(public_ip_enabled=bool(nc.get("enablePublicIp")), authorized_networks=nets)


@_extractor("bigquery.googleapis.com/Dataset")
def _bq_dataset(ctx: GCPContext, out: Extracted) -> None:
    public = []
    for entry in _list(ctx.data.get("access")):
        if not isinstance(entry, dict):
            continue
        member = entry.get("iamMember") or entry.get("specialGroup")
        if member in PUBLIC_MEMBERS:
            public.append({"member": member, "role": entry.get("role")})
        view = entry.get("view") or (entry.get("dataset") or {}).get("dataset")
        if isinstance(view, dict) and view.get("projectId") and view.get("datasetId"):
            out.add(
                f"//bigquery.googleapis.com/projects/{view['projectId']}/datasets/{view['datasetId']}",
                EdgeType.GRANTS_ACCESS,
                "READS_FROM",
                reverse=True,
                description="authorized view/dataset",
            )
    if public:
        out.expose(
            "BigQuery dataset access granted to " + ", ".join(sorted({p["member"] for p in public}))
        )
        out.metadata["public_access"] = public
    out.metadata["access_entry_count"] = len(_list(ctx.data.get("access")))


@_extractor("storage.googleapis.com/Bucket")
def _bucket(ctx: GCPContext, out: Extracted) -> None:
    d = ctx.data
    iam_cfg = d.get("iamConfiguration") or {}
    log_bucket = dig(d, "logging", "logBucket")
    if log_bucket:
        out.add(
            f"//storage.googleapis.com/{log_bucket}",
            EdgeType.LOGS_TO,
            "LOGS_TO",
            description="access logs",
        )
    public_acl = sorted(
        {
            a.get("entity")
            for a in _list(d.get("acl")) + _list(d.get("defaultObjectAcl"))
            if isinstance(a, dict) and a.get("entity") in PUBLIC_MEMBERS
        }
    )
    if public_acl:
        out.expose("bucket ACL grants " + ", ".join(public_acl))
    out.metadata.update(
        uniform_bucket_level_access=bool(
            dig(iam_cfg, "uniformBucketLevelAccess", "enabled")
            or dig(iam_cfg, "bucketPolicyOnly", "enabled")
        ),
        public_access_prevention=iam_cfg.get("publicAccessPrevention"),
        versioning=bool(dig(d, "versioning", "enabled")),
        retention_locked=bool(dig(d, "retentionPolicy", "isLocked")),
        website=bool(d.get("website")),
        storage_class=d.get("storageClass"),
        location_type=d.get("locationType"),
        public_acl=public_acl,
    )


@_extractor("cloudkms.googleapis.com/CryptoKey")
def _crypto_key(ctx: GCPContext, out: Extracted) -> None:
    d = ctx.data
    out.add(
        ctx.name.split("/cryptoKeys/", 1)[0],
        EdgeType.CONTAINS,
        reverse=True,
        description="key ring contains key",
    )
    out.metadata.update(
        purpose=d.get("purpose"),
        rotation_period=d.get("rotationPeriod"),
        protection_level=dig(d, "versionTemplate", "protectionLevel"),
        primary_state=dig(d, "primary", "state"),
    )


@_extractor("secretmanager.googleapis.com/Secret")
def _secret(ctx: GCPContext, out: Extracted) -> None:
    d = ctx.data
    for t in _list(d.get("topics")):
        if isinstance(t, dict):
            out.add(
                full_name(t.get("name"), "pubsub"),
                EdgeType.INVOKES,
                "INVOKES",
                description="secret event notifications",
            )
    out.metadata.update(
        rotation=bool(d.get("rotation")),
        replication="user_managed" if dig(d, "replication", "userManaged") else "automatic",
    )


@_extractor("artifactregistry.googleapis.com/Repository")
def _ar_repo(ctx: GCPContext, out: Extracted) -> None:
    d = ctx.data
    out.metadata.update(
        format=d.get("format"),
        mode=d.get("mode"),
        immutable_tags=bool(dig(d, "dockerConfig", "immutableTags")),
    )
