"""Operations: Cloud Monitoring alert policies, notification channels and
uptime checks, OS Config (VM Manager) patch deployments, OS policies and
vulnerability reports, and Backup and DR Service vaults, plans and
associations.

The same extractors serve Cloud Asset Inventory records and resources read
from the service APIs by :mod:`cloudg.inventory.gcp_sources`.
"""

from __future__ import annotations

import re
from typing import Any

from cloudg.inventory.gcp_relations._refs import crm_ref, host_target, parent_of
from cloudg.inventory.gcp_relations.context import Extracted, GCPContext, _extractor
from cloudg.inventory.gcp_relations.names import (
    _list,
    _num,
    asset_type_service,
    dig,
    full_name,
    url_alias,
)
from cloudg.schema.models import EdgeType

# ---------------------------------------------------------------------------
# Cloud Monitoring
# ---------------------------------------------------------------------------

_LABEL_RE = re.compile(r"resource\.labels?\.\"?([a-z_]+)\"?\s*(?:==|=|:)\s*\"([^\"]+)\"")
_TYPE_RE = re.compile(r"resource\.type\s*(?:==|=)\s*\"([a-z0-9_.]+)\"")


def _monitored(rtype: str, labels: dict[str, str], project: str | None) -> str | None:
    """Full name of the one resource a monitored-resource type + labels pin down."""
    p = labels.get("project_id") or project
    loc = labels.get("location") or labels.get("region") or labels.get("zone")
    if rtype == "gce_instance" and labels.get("instance_id") and p:
        zone = labels.get("zone")
        if zone:
            return f"//compute.googleapis.com/projects/{p}/zones/{zone}/instances/{labels['instance_id']}"
        return f"gcp-instance-id:{p}/{labels['instance_id']}"
    simple = {
        "gcs_bucket": ("bucket_name", lambda v: f"//storage.googleapis.com/{v}"),
        "pubsub_topic": ("topic_id", lambda v: f"//pubsub.googleapis.com/projects/{p}/topics/{v}"),
        "pubsub_subscription": (
            "subscription_id",
            lambda v: f"//pubsub.googleapis.com/projects/{p}/subscriptions/{v}",
        ),
        "bigquery_dataset": (
            "dataset_id",
            lambda v: f"//bigquery.googleapis.com/projects/{p}/datasets/{v}",
        ),
        "spanner_instance": (
            "instance_id",
            lambda v: f"//spanner.googleapis.com/projects/{p}/instances/{v}",
        ),
        "https_lb_rule": (
            "forwarding_rule_name",
            lambda v: f"//compute.googleapis.com/projects/{p}/global/forwardingRules/{v}",
        ),
    }
    if rtype in simple:
        key, build = simple[rtype]
        return build(labels[key]) if labels.get(key) and p else None
    if rtype == "cloudsql_database" and ":" in labels.get("database_id", ""):
        proj, inst = labels["database_id"].split(":", 1)
        return f"//cloudsql.googleapis.com/projects/{proj}/instances/{inst}"
    if rtype in ("cloud_run_revision", "cloud_run_job") and p and loc:
        if labels.get("service_name"):
            return f"//run.googleapis.com/projects/{p}/locations/{loc}/services/{labels['service_name']}"
        if labels.get("job_name"):
            return f"//run.googleapis.com/projects/{p}/locations/{loc}/jobs/{labels['job_name']}"
    if (
        rtype in ("cloud_function", "cloud_run_function")
        and p
        and loc
        and labels.get("function_name")
    ):
        return f"//cloudfunctions.googleapis.com/projects/{p}/locations/{loc}/functions/{labels['function_name']}"
    if rtype.startswith("k8s_") and p and loc and labels.get("cluster_name"):
        return f"//container.googleapis.com/projects/{p}/locations/{loc}/clusters/{labels['cluster_name']}"
    if rtype == "redis_instance" and labels.get("instance_id"):
        return full_name(labels["instance_id"], "redis")
    return None


def filter_targets(text: Any, project: str | None) -> list[str]:
    """Resources a Monitoring filter (``resource.type = ... AND resource.labels.x = ...``) names."""
    if not isinstance(text, str) or not text:
        return []
    m = _TYPE_RE.search(text)
    labels = {k: v for k, v in _LABEL_RE.findall(text)}
    target = _monitored(m.group(1), labels, project) if m else None
    return [target] if target else []


def _condition_filters(cond: dict[str, Any]) -> list[str]:
    out = []
    for key in ("conditionThreshold", "conditionAbsent", "conditionMatchedLog"):
        flt = dig(cond, key, "filter")
        if isinstance(flt, str):
            out.append(flt)
    for key, field in (
        ("conditionMonitoringQueryLanguage", "query"),
        ("conditionPrometheusQueryLanguage", "query"),
        ("conditionSql", "query"),
    ):
        q = dig(cond, key, field)
        if isinstance(q, str):
            out.append(q)
    return out


@_extractor("monitoring.googleapis.com/AlertPolicy")
def _alert_policy(ctx: GCPContext, out: Extracted) -> None:
    """MONITORS / MONITORED_BY the resources its conditions pin; INVOKES its channels."""
    d = ctx.data
    pid = ctx.project_id
    monitored: list[str] = []
    conditions = [c for c in _list(d.get("conditions")) if isinstance(c, dict)]
    for cond in conditions:
        for flt in _condition_filters(cond):
            monitored += filter_targets(flt, pid)
    for target in dict.fromkeys(monitored):
        out.add(target, EdgeType.MONITORS, "MONITORED_BY", description="alert condition")
    if conditions and not monitored and pid:
        out.add(
            crm_ref(f"projects/{pid}"),
            EdgeType.MONITORS,
            "MONITORED_BY",
            description="project-wide alert condition",
        )
    for channel in _list(d.get("notificationChannels")):
        out.add(
            full_name(channel, "monitoring"),
            EdgeType.INVOKES,
            "INVOKES",
            description="alert notification",
        )
    out.metadata.update(
        enabled=d.get("enabled", True),
        combiner=d.get("combiner"),
        condition_count=len(conditions),
        severity=d.get("severity"),
        notification_channel_count=len(_list(d.get("notificationChannels"))),
    )


@_extractor("monitoring.googleapis.com/NotificationChannel")
def _notification_channel(ctx: GCPContext, out: Extracted) -> None:
    d = ctx.data
    labels = d.get("labels") or {}
    pid = ctx.project_id
    topic = labels.get("topic")
    if topic:
        out.add(
            full_name(topic, "pubsub"), EdgeType.INVOKES, "INVOKES", description="Pub/Sub channel"
        )
    url = labels.get("url")
    if isinstance(url, str) and url.startswith("https://") and "REDACTED" not in url:
        out.add(url_alias(url), EdgeType.INVOKES, "INVOKES", description="webhook channel")
    out.metadata.update(
        channel_type=d.get("type"),
        enabled=d.get("enabled", True),
        verification=d.get("verificationStatus"),
        label_keys=sorted(labels.keys()),
        project_id=pid,
    )


@_extractor("monitoring.googleapis.com/UptimeCheckConfig")
def _uptime_check(ctx: GCPContext, out: Extracted) -> None:
    d = ctx.data
    res = d.get("monitoredResource") or {}
    labels = res.get("labels") or {}
    targets = []
    if res.get("type") == "uptime_url":
        targets.append(host_target(labels.get("host")))
    elif res.get("type"):
        targets.append(_monitored(res["type"], labels, ctx.project_id))
    targets.append(
        full_name(dig(d, "syntheticMonitor", "cloudFunctionV2", "name"), "cloudfunctions")
    )
    for target in targets:
        out.add(target, EdgeType.MONITORS, "MONITORED_BY", description="uptime check")
    out.metadata.update(
        checker_type=d.get("checkerType"),
        period=d.get("period"),
        protocol="http" if d.get("httpCheck") else "tcp" if d.get("tcpCheck") else None,
        regions=list(d.get("selectedRegions") or []),
    )


# ---------------------------------------------------------------------------
# OS Config / VM Manager
# ---------------------------------------------------------------------------


def _instance_ref(value: Any, project: str | None) -> str | None:
    """``zones/z/instances/i``, ``projects/p/zones/z/instances/i`` or a URL."""
    if not isinstance(value, str) or not value:
        return None
    if value.startswith("zones/") and project:
        value = f"projects/{project}/{value}"
    return full_name(value, "compute")


def instance_filter(f: Any, zone: str | None = None) -> dict[str, Any]:
    """Normalised OS Config instance filter (both patch and OS policy shapes)."""
    if not isinstance(f, dict):
        return {}
    labels = [g.get("labels") or {} for g in _list(f.get("groupLabels")) if isinstance(g, dict)]
    labels += [
        g.get("labels") or {} for g in _list(f.get("inclusionLabels")) if isinstance(g, dict)
    ]
    zones = list(f.get("zones") or [])
    if zone and not zones:
        zones = [zone]
    return {
        "all": bool(f.get("all")),
        "labels": labels,
        "exclusion_labels": [
            g.get("labels") or {} for g in _list(f.get("exclusionLabels")) if isinstance(g, dict)
        ],
        "zones": zones,
        "name_prefixes": list(f.get("instanceNamePrefixes") or []),
        "os_short_names": [
            i.get("osShortName") for i in _list(f.get("inventories")) if isinstance(i, dict)
        ],
    }


@_extractor("osconfig.googleapis.com/PatchDeployment")
def _patch_deployment(ctx: GCPContext, out: Extracted) -> None:
    """Explicit instances are linked here; label / zone filters by the deep collector."""
    d = ctx.data
    flt = d.get("instanceFilter") or {}
    for inst in _list(flt.get("instances")):
        out.add(
            _instance_ref(inst, ctx.project_id),
            EdgeType.MANAGES,
            "SCHEDULED_BY",
            description="patch deployment target",
        )
    if flt.get("all") and ctx.project_id:
        out.add(
            crm_ref(f"projects/{ctx.project_id}"),
            EdgeType.MANAGES,
            "SCHEDULED_BY",
            description="patches every VM in the project",
        )
    sched = d.get("recurringSchedule") or {}
    out.metadata.update(
        instance_filter=instance_filter(flt),
        frequency=sched.get("frequency"),
        time_zone=dig(sched, "timeZone", "id"),
        one_time=bool(d.get("oneTimeSchedule")),
        reboot=dig(d, "patchConfig", "rebootConfig"),
        last_execute_time=d.get("lastExecuteTime"),
    )


@_extractor("osconfig.googleapis.com/OSPolicyAssignment")
def _os_policy_assignment(ctx: GCPContext, out: Extracted) -> None:
    d = ctx.data
    flt = d.get("instanceFilter") or {}
    zone = ctx.location if ctx.location and ctx.location.count("-") == 2 else None
    if flt.get("all") and not flt.get("inclusionLabels") and ctx.project_id and not zone:
        out.add(crm_ref(f"projects/{ctx.project_id}"), EdgeType.MANAGES, "SCHEDULED_BY")
    out.metadata.update(
        instance_filter=instance_filter(flt, zone),
        os_policies=[
            {"id": p.get("id"), "mode": p.get("mode")}
            for p in _list(d.get("osPolicies"))
            if isinstance(p, dict)
        ],
        rollout_state=d.get("rolloutState"),
        baseline=d.get("baseline"),
    )


_VULN_REPORT_RE = re.compile(
    r"projects/([^/]+)/locations/([^/]+)/instances/([^/]+)/vulnerabilityReport"
)


@_extractor("osconfig.googleapis.com/VulnerabilityReport")
def _vm_vulnerability_report(ctx: GCPContext, out: Extracted) -> None:
    d = ctx.data
    m = _VULN_REPORT_RE.search(ctx.name)
    counts: dict[str, int] = {}
    cves = []
    for v in _list(d.get("vulnerabilities")):
        details = v.get("details") if isinstance(v, dict) else None
        if not isinstance(details, dict):
            continue
        sev = str(details.get("severity") or "UNKNOWN").upper()
        counts[sev] = counts.get(sev, 0) + 1
        if details.get("cve"):
            cves.append(details["cve"])
    if m:
        project, zone, inst = m.groups()
        out.add(
            f"//compute.googleapis.com/projects/{project}/zones/{zone}/instances/{inst}",
            EdgeType.MONITORS,
            "MONITORED_BY",
            description="VM Manager vulnerability report",
            severity_counts=counts,
        )
    out.metadata.update(
        severity_counts=counts, cves=cves[:50], vulnerability_count=sum(counts.values())
    )


# ---------------------------------------------------------------------------
# Backup and DR Service
# ---------------------------------------------------------------------------


@_extractor("backupdr.googleapis.com/BackupVault")
def _backup_vault(ctx: GCPContext, out: Extracted) -> None:
    d = ctx.data
    out.sa(d.get("serviceAccount"), ctx, "backup vault service agent")
    out.metadata.update(
        min_retention=d.get("backupMinimumEnforcedRetentionDuration"),
        access_restriction=d.get("accessRestriction"),
        backup_count=_num(d.get("backupCount")),
        locked_until=d.get("effectiveTime"),
        vault_state=d.get("state"),
        deletable=d.get("deletable"),
    )


@_extractor("backupdr.googleapis.com/BackupPlan")
def _backup_plan(ctx: GCPContext, out: Extracted) -> None:
    d = ctx.data
    out.add(
        full_name(d.get("backupVault"), "backupdr"),
        EdgeType.REFERENCES,
        "BACKUP_TO",
        description="plan target vault",
    )
    rules = [
        {
            "id": r.get("ruleId"),
            "retention_days": _num(r.get("backupRetentionDays")),
            "recurrence": dig(r, "standardSchedule", "recurrenceType"),
        }
        for r in _list(d.get("backupRules"))
        if isinstance(r, dict)
    ]
    out.metadata.update(
        resource_type=d.get("resourceType"),
        rules=rules,
        vault_service_account=d.get("backupVaultServiceAccount"),
        plan_state=d.get("state"),
    )


@_extractor("backupdr.googleapis.com/BackupPlanAssociation")
def _backup_plan_association(ctx: GCPContext, out: Extracted) -> None:
    d = ctx.data
    rtype = d.get("resourceType")
    resource = full_name(d.get("resource"), asset_type_service(rtype))
    out.add(
        resource,
        EdgeType.MANAGES,
        "BACKUP_TO",
        description="resource protected by the backup plan",
    )
    out.add(full_name(d.get("backupPlan"), "backupdr"), EdgeType.REFERENCES, "DEPENDS_ON")
    out.add(full_name(d.get("dataSource"), "backupdr"), EdgeType.REFERENCES, "BACKUP_TO")
    out.metadata.update(resource=resource, resource_type=rtype, association_state=d.get("state"))


@_extractor("backupdr.googleapis.com/DataSource")
def _backup_data_source(ctx: GCPContext, out: Extracted) -> None:
    d = ctx.data
    out.add(parent_of(ctx.name, "dataSources"), EdgeType.CONTAINS, reverse=True)
    res = d.get("dataSourceGcpResource") or {}
    out.add(
        full_name(res.get("gcpResourcename"), asset_type_service(res.get("type"))),
        EdgeType.REFERENCES,
        "BACKUP_TO",
        reverse=True,
        description="resource backed up into the vault",
    )
    out.metadata.update(backup_count=_num(d.get("backupCount")), config_state=d.get("configState"))


@_extractor("backupdr.googleapis.com/Backup")
def _backupdr_backup(ctx: GCPContext, out: Extracted) -> None:
    d = ctx.data
    out.add(parent_of(ctx.name, "backups"), EdgeType.CONTAINS, reverse=True)
    out.metadata.update(
        backup_type=d.get("backupType"),
        expire_time=d.get("expireTime"),
        enforced_retention_end=d.get("enforcedRetentionEndTime"),
    )


@_extractor("backupdr.googleapis.com/ManagementServer")
def _backup_management_server(ctx: GCPContext, out: Extracted) -> None:
    d = ctx.data
    for net in _list(d.get("networks")):
        if isinstance(net, dict):
            out.add(full_name(net.get("network"), "compute"), EdgeType.ATTACHED_TO)
    uri = dig(d, "managementUri", "webUi")
    out.alias(url_alias(uri))
    out.metadata.update(server_type=d.get("type"), server_state=d.get("state"))
