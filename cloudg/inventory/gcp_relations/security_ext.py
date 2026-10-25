"""Security services: Security Command Center (activation, services, sources,
notification and BigQuery exports, mute rules, per-service settings),
Sensitive Data Protection, Data Access audit logs, the IAM recommender and
Artifact Analysis vulnerability summaries.

Security services carry a ``gcp-security:<service>:<parent>`` alias, the
GCP counterpart of the AWS ``aws-security:`` alias, so placeholders for
services that are not enabled and the configs that depend on them link
up.
"""

from __future__ import annotations

import re
from typing import Any

from cloudg.inventory.gcp_relations._refs import bq_ref, crm_ref, gcs_ref
from cloudg.inventory.gcp_relations.context import Extracted, GCPContext, _extractor
from cloudg.inventory.gcp_relations.identity_ext import principal_target
from cloudg.inventory.gcp_relations.names import (
    _list,
    dig,
    full_name,
    image_repository,
    relative_name,
)
from cloudg.schema.models import EdgeType

SECURITY_ALIAS = "gcp-security:"
_PARENT_RE = re.compile(r"^((?:organizations|folders|projects)/[^/]+)")
# Settings resource type -> SCC service id
_SETTINGS = {
    "securitycenter.googleapis.com/EventThreatDetectionSettings": "event-threat-detection",
    "securitycenter.googleapis.com/ContainerThreatDetectionSettings": "container-threat-detection",
    "securitycenter.googleapis.com/SecurityHealthAnalyticsSettings": "security-health-analytics",
    "securitycenter.googleapis.com/VirtualMachineThreatDetectionSettings": "vm-threat-detection",
    "securitycenter.googleapis.com/WebSecurityScannerSettings": "web-security-scanner",
}


def security_alias(service: str, parent: str | None) -> str | None:
    """``gcp-security:<service>:<projects/x | folders/y | organizations/z>``."""
    return f"{SECURITY_ALIAS}{service}:{parent}" if parent else None


def parent_resource(name: str) -> str | None:
    """The project / folder / organization a resource name lives under."""
    m = _PARENT_RE.match(relative_name(name))
    return m.group(1) if m else None


# ---------------------------------------------------------------------------
# Security Command Center
# ---------------------------------------------------------------------------


@_extractor("securitycenter.googleapis.com/SecurityCenter")
def _scc(ctx: GCPContext, out: Extracted) -> None:
    """SCC activation at a parent (built from the SCC API by the deep collector)."""
    d = ctx.data
    parent = d.get("parent") or parent_resource(ctx.name)
    out.alias(security_alias("scc", parent))
    if d.get("enabled", True):
        out.add(
            crm_ref(parent),
            EdgeType.MONITORS,
            "MONITORED_BY",
            description=f"Security Command Center {d.get('tier') or ''}".strip(),
        )
    out.metadata.update(
        security_service="scc",
        enabled=bool(d.get("enabled", True)),
        tier=d.get("tier"),
        parent=parent,
    )


@_extractor("securitycentermanagement.googleapis.com/SecurityCenterService")
def _scc_service(ctx: GCPContext, out: Extracted) -> None:
    """One SCC service (ETD, CTD, SHA, VMTD, WSS, ...) at a parent."""
    d = ctx.data
    parent = parent_resource(ctx.name)
    service = ctx.name.rsplit("/", 1)[-1]
    effective = d.get("effectiveEnablementState") or d.get("intendedEnablementState")
    enabled = effective == "ENABLED"
    out.alias(security_alias(service, parent))
    if enabled:
        out.add(crm_ref(parent), EdgeType.MONITORS, "MONITORED_BY", description=service)
    out.add(security_alias("scc", parent), EdgeType.REFERENCES, "DEPENDS_ON")
    modules = d.get("modules") or {}
    out.metadata.update(
        security_service=service,
        enabled=enabled,
        intended_state=d.get("intendedEnablementState"),
        effective_state=effective,
        module_count=len(modules),
        disabled_modules=sorted(
            k
            for k, v in modules.items()
            if isinstance(v, dict) and v.get("effectiveEnablementState") == "DISABLED"
        ),
    )


@_extractor(*_SETTINGS)
def _scc_settings(ctx: GCPContext, out: Extracted) -> None:
    d = ctx.data
    parent = parent_resource(ctx.name)
    service = _SETTINGS.get(ctx.asset_type, "scc")
    state = d.get("serviceEnablementState")
    out.alias(security_alias(service, parent))
    if state in ("ENABLED", "INHERITED", None):
        out.add(crm_ref(parent), EdgeType.MONITORS, "MONITORED_BY", description=service)
    out.metadata.update(
        security_service=service, enablement_state=state, enabled=state != "DISABLED"
    )


@_extractor("securitycenter.googleapis.com/Source")
def _scc_source(ctx: GCPContext, out: Extracted) -> None:
    d = ctx.data
    parent = parent_resource(ctx.name)
    out.add(
        security_alias("scc", parent),
        EdgeType.INVOKES,
        "STREAMS_TO",
        description="finding source",
    )
    out.metadata.update(security_service="scc-source", canonical_name=d.get("canonicalName"))


@_extractor("securitycenter.googleapis.com/NotificationConfig")
def _scc_notification(ctx: GCPContext, out: Extracted) -> None:
    d = ctx.data
    parent = parent_resource(ctx.name)
    out.add(
        full_name(d.get("pubsubTopic"), "pubsub"),
        EdgeType.INVOKES,
        "STREAMS_TO",
        description="findings exported to Pub/Sub",
    )
    out.sa(d.get("serviceAccount"), ctx, "notification publisher")
    out.add(security_alias("scc", parent), EdgeType.REFERENCES, "DEPENDS_ON")
    out.metadata["filter"] = dig(d, "streamingConfig", "filter")


@_extractor("securitycenter.googleapis.com/BigQueryExport")
def _scc_bq_export(ctx: GCPContext, out: Extracted) -> None:
    d = ctx.data
    out.add(
        bq_ref(d.get("dataset")),
        EdgeType.INVOKES,
        "STREAMS_TO",
        description="findings exported to BigQuery",
    )
    out.sa(d.get("principal"), ctx, "export writer")
    out.add(security_alias("scc", parent_resource(ctx.name)), EdgeType.REFERENCES, "DEPENDS_ON")
    out.metadata["filter"] = d.get("filter")


@_extractor(
    "securitycenter.googleapis.com/MuteConfig", "securitycenter.googleapis.com/ResourceValueConfig"
)
def _scc_config(ctx: GCPContext, out: Extracted) -> None:
    d = ctx.data
    out.add(security_alias("scc", parent_resource(ctx.name)), EdgeType.REFERENCES, "DEPENDS_ON")
    out.metadata.update(
        filter=d.get("filter"), config_type=d.get("type"), resource_value=d.get("resourceValue")
    )


# ---------------------------------------------------------------------------
# Sensitive Data Protection (Cloud DLP)
# ---------------------------------------------------------------------------


def _discovery_scope(ctx: GCPContext, d: dict[str, Any]) -> str | None:
    loc = dig(d, "orgConfig", "location", default={}) or {}
    if loc.get("folderId"):
        return f"folders/{loc['folderId']}"
    if loc.get("organizationId"):
        return f"organizations/{loc['organizationId']}"
    return parent_resource(ctx.name)


@_extractor("dlp.googleapis.com/DiscoveryConfig")
def _dlp_discovery(ctx: GCPContext, out: Extracted) -> None:
    d = ctx.data
    scope = _discovery_scope(ctx, d)
    active = d.get("status") in (None, "RUNNING")
    if active:
        out.add(
            crm_ref(scope),
            EdgeType.MONITORS,
            "MONITORED_BY",
            description="sensitive data discovery",
        )
    out.alias(security_alias("dlp-discovery", parent_resource(ctx.name)))
    for action in _list(d.get("actions")):
        if not isinstance(action, dict):
            continue
        table = dig(action, "exportData", "profileTable", default={}) or {}
        if table.get("projectId") and table.get("datasetId"):
            out.add(
                bq_ref(f"{table['projectId']}.{table['datasetId']}"),
                EdgeType.REFERENCES,
                "WRITES_TO",
                description="data profiles export",
            )
        out.add(
            full_name(dig(action, "pubSubNotification", "topic"), "pubsub"),
            EdgeType.INVOKES,
            "INVOKES",
        )
    for tmpl in _list(d.get("inspectTemplates")):
        out.add(full_name(tmpl, "dlp"), EdgeType.REFERENCES, "DEPENDS_ON")
    targets = sorted({k for t in _list(d.get("targets")) if isinstance(t, dict) for k in t})
    out.metadata.update(
        security_service="dlp-discovery",
        enabled=active,
        discovery_status=d.get("status"),
        targets=targets,
        scope=scope,
    )


@_extractor("dlp.googleapis.com/JobTrigger")
def _dlp_job_trigger(ctx: GCPContext, out: Extracted) -> None:
    d = ctx.data
    job = d.get("inspectJob") or {}
    storage = job.get("storageConfig") or {}
    url = dig(storage, "cloudStorageOptions", "fileSet", "url")
    if isinstance(url, str):
        out.add(
            gcs_ref(url.removeprefix("gs://").split("/", 1)[0]), EdgeType.MONITORS, "MONITORED_BY"
        )
    ref = dig(storage, "bigQueryOptions", "tableReference", default={}) or {}
    if ref.get("projectId") and ref.get("datasetId"):
        table = ref.get("tableId")
        out.add(
            bq_ref(f"{ref['projectId']}.{ref['datasetId']}" + (f".{table}" if table else "")),
            EdgeType.MONITORS,
            "MONITORED_BY",
        )
    for action in _list(job.get("actions")):
        if not isinstance(action, dict):
            continue
        out_table = dig(action, "saveFindings", "outputConfig", "table", default={}) or {}
        if out_table.get("projectId") and out_table.get("datasetId"):
            out.add(
                bq_ref(f"{out_table['projectId']}.{out_table['datasetId']}"),
                EdgeType.REFERENCES,
                "WRITES_TO",
            )
        out.add(full_name(dig(action, "pubSub", "topic"), "pubsub"), EdgeType.INVOKES, "INVOKES")
    out.add(full_name(job.get("inspectTemplateName"), "dlp"), EdgeType.REFERENCES, "DEPENDS_ON")
    out.metadata.update(trigger_status=d.get("status"), security_service="dlp-inspection")


@_extractor(
    "dlp.googleapis.com/InspectTemplate",
    "dlp.googleapis.com/DeidentifyTemplate",
    "dlp.googleapis.com/StoredInfoType",
)
def _dlp_template(ctx: GCPContext, out: Extracted) -> None:
    info_types = dig(ctx.data, "inspectConfig", "infoTypes", default=[]) or []
    out.metadata["info_type_count"] = len(_list(info_types)) or None


# ---------------------------------------------------------------------------
# Data Access audit logs (from IAM policies), IAM recommender, Artifact Analysis
# ---------------------------------------------------------------------------


@_extractor("logging.googleapis.com/AuditConfig")
def _audit_config(ctx: GCPContext, out: Extracted) -> None:
    """Data Access audit logging configured on a project, folder or organization."""
    d = ctx.data
    resource = d.get("resource")
    out.add(resource, EdgeType.MONITORS, "MONITORED_BY", description="Data Access audit logs")
    rel_res = relative_name(resource or "")
    if rel_res.startswith("projects/") and d.get("enabled"):
        out.add(
            f"//logging.googleapis.com/{rel_res}/locations/global/buckets/_Default",
            EdgeType.LOGS_TO,
            "LOGS_TO",
            description="Data Access logs land in the _Default bucket",
        )
    out.alias(security_alias("audit-logs", rel_res or None))
    out.metadata.update(
        security_service="audit-logs",
        enabled=bool(d.get("enabled")),
        services=d.get("services") or [],
        all_services=d.get("allServices"),
        exempted_members=d.get("exemptedMembers") or [],
    )


@_extractor("recommender.googleapis.com/IamPolicyRecommender")
def _iam_recommender(ctx: GCPContext, out: Extracted) -> None:
    """IAM policy recommendations: over-granted roles, per principal (FINDING_AFFECTS)."""
    d = ctx.data
    out.add(
        crm_ref(d.get("parent")),
        EdgeType.MONITORS,
        "MONITORED_BY",
        description="IAM role recommendations",
    )
    for rec in _list(d.get("recommendations")):
        if not isinstance(rec, dict):
            continue
        out.add(
            principal_target(rec.get("member")),
            EdgeType.MONITORS,
            "FINDING_AFFECTS",
            description=rec.get("description"),
            role=rec.get("role"),
            action=rec.get("action"),
            priority=rec.get("priority"),
            resource=rec.get("resource"),
        )
    out.metadata.update(
        security_service="iam-recommender",
        recommendation_count=len(_list(d.get("recommendations"))),
    )


@_extractor("containeranalysis.googleapis.com/VulnerabilitySummary")
def _vulnerability_summary(ctx: GCPContext, out: Extracted) -> None:
    """Artifact Analysis findings per image (MONITORS / MONITORED_BY with counts)."""
    d = ctx.data
    parent = d.get("parent")
    out.alias(security_alias("artifact-analysis", parent))
    for uri, summary in (d.get("images") or {}).items():
        if not isinstance(summary, dict):
            continue
        target = summary.get("target") or uri
        out.add(
            target,
            EdgeType.MONITORS,
            "MONITORED_BY",
            description="Artifact Analysis vulnerability scan",
            severity_counts=summary.get("severity_counts"),
            fixable=summary.get("fixable"),
            cves=(summary.get("cves") or [])[:20],
        )
        repo = image_repository(str(uri).removeprefix("https://"))
        if repo and repo != target:
            out.add(repo, EdgeType.MONITORS, "MONITORED_BY", description="repository scanned")
    out.metadata.update(
        security_service="artifact-analysis",
        enabled=d.get("enabled", True),
        image_count=len(d.get("images") or {}),
        occurrence_count=d.get("occurrence_count"),
        truncated=d.get("truncated") or None,
    )
