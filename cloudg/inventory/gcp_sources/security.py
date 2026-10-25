"""Security sources: Security Command Center, Artifact Analysis
vulnerability occurrences, Data Access audit log configs, the IAM
recommender and Sensitive Data Protection discovery coverage."""

from __future__ import annotations

from typing import Any

from cloudg.inventory.gcp_relations.names import image_repository
from cloudg.inventory.gcp_sources.base import SourceContext, SourceRun, source
from cloudg.schema.models import AssetType, CloudAsset

_SCC = "https://securitycenter.googleapis.com"
_SCCM = "https://securitycentermanagement.googleapis.com/v1"
_CA = "https://containeranalysis.googleapis.com/v1"
_SU = "https://serviceusage.googleapis.com/v1"
_REC = "https://recommender.googleapis.com/v1"

# SCC service id -> (asset type, label); the core services get placeholders
SCC_SERVICES: dict[str, tuple[AssetType, str]] = {
    "event-threat-detection": (AssetType.THREAT_DETECTOR, "Event Threat Detection"),
    "container-threat-detection": (AssetType.THREAT_DETECTOR, "Container Threat Detection"),
    "vm-threat-detection": (AssetType.THREAT_DETECTOR, "Virtual Machine Threat Detection"),
    "security-health-analytics": (AssetType.CONFIG_RECORDER, "Security Health Analytics"),
    "web-security-scanner": (AssetType.VULNERABILITY_SCANNER, "Web Security Scanner"),
}
_SCC_TYPE = "securitycenter.googleapis.com/SecurityCenter"
_SVC_TYPE = "securitycentermanagement.googleapis.com/SecurityCenterService"


def _project(parent: str) -> str | None:
    return parent.split("/", 1)[1] if parent.startswith("projects/") else None


def _scc_parent(ctx: SourceContext, run: SourceRun, parent: str) -> list[CloudAsset]:
    """SCC activation, services, sources and exports at one parent."""
    project = _project(parent)
    services_url = f"{_SCCM}/{parent}/locations/global/securityCenterServices"
    before = (len(run.disabled), len(run.errors))
    services = ctx.items(run, services_url, "securityCenterServices", tolerate=False)
    unreachable = (len(run.disabled), len(run.errors)) != before
    active = [s for s in services if s.get("effectiveEnablementState") == "ENABLED"]
    out: list[CloudAsset] = []
    if unreachable or not active:
        if len(run.errors) > before[1]:
            return out  # permission problem: unknown, not "not enabled"
        out.append(
            ctx.placeholder(
                "scc", parent, AssetType.SECURITY_HUB, "Security Command Center", gcp_type=_SCC_TYPE
            )
        )
        for sid, (atype, label) in SCC_SERVICES.items():
            out.append(ctx.placeholder(sid, parent, atype, label, gcp_type=_SVC_TYPE))
        return out
    tier = None
    if parent.startswith("organizations/"):
        sub = ctx.get(run, f"{_SCC}/v1beta2/{parent}/subscription", tolerate=True) or {}
        tier = sub.get("tier")
    hub = ctx.build(
        f"//securitycenter.googleapis.com/{parent}/securityCenter",
        _SCC_TYPE,
        {"parent": parent, "tier": tier, "enabled": True, "displayName": "Security Command Center"},
        project=project,
        source_name="scc",
        global_resource=project is None,
    )
    out.append(hub)
    for svc in services:
        name = svc.get("name")
        if not isinstance(name, str):
            continue
        sid = name.rsplit("/", 1)[-1]
        atype, label = SCC_SERVICES.get(sid, (AssetType.SECURITY_HUB, sid))
        enabled = svc.get("effectiveEnablementState") == "ENABLED"
        asset = ctx.build(
            f"//securitycentermanagement.googleapis.com/{name}",
            _SVC_TYPE,
            {**svc, "displayName": label if enabled else f"{label} (not enabled)"},
            project=project,
            source_name="scc",
            global_resource=project is None,
        )
        if asset is not None:
            asset.asset_type = atype
            out.append(asset)
    for key, kind in (
        ("sources", "securitycenter.googleapis.com/Source"),
        ("notificationConfigs", "securitycenter.googleapis.com/NotificationConfig"),
        ("bigQueryExports", "securitycenter.googleapis.com/BigQueryExport"),
    ):
        for item in ctx.items(run, f"{_SCC}/v1/{parent}/{key}", key, tolerate=key != "sources"):
            name = item.get("name")
            if isinstance(name, str):
                out.append(
                    ctx.build(
                        f"//securitycenter.googleapis.com/{name}",
                        kind,
                        item,
                        project=project,
                        source_name="scc",
                        global_resource=project is None,
                    )
                )
    return [a for a in out if a is not None]


@source("scc", "security")
def security_command_center(ctx: SourceContext, run: SourceRun) -> list[CloudAsset]:
    """Security Command Center: tier, services (ETD, CTD, SHA, VMTD, WSS), sources, exports.

    Parents where SCC is not activated get "not enabled" placeholders.
    """
    out: list[CloudAsset] = []
    for parent in ctx.parents(folders=False):
        out += _scc_parent(ctx, run, parent)
    return out


# ---------------------------------------------------------------------------
# Artifact Analysis
# ---------------------------------------------------------------------------


def _occurrence_summary(ctx: SourceContext, occurrences: list[dict[str, Any]]) -> dict[str, Any]:
    images: dict[str, dict[str, Any]] = {}
    for occ in occurrences:
        uri = occ.get("resourceUri")
        vuln = occ.get("vulnerability") or {}
        if not isinstance(uri, str) or not uri:
            continue
        entry = images.setdefault(uri, {"severity_counts": {}, "fixable": 0, "cves": []})
        sev = str(vuln.get("effectiveSeverity") or vuln.get("severity") or "UNKNOWN").upper()
        entry["severity_counts"][sev] = entry["severity_counts"].get(sev, 0) + 1
        if vuln.get("fixAvailable"):
            entry["fixable"] += 1
        cve = vuln.get("shortDescription") or str(occ.get("noteName") or "").rsplit("/", 1)[-1]
        if cve and cve not in entry["cves"] and len(entry["cves"]) < 50:
            entry["cves"].append(cve)
    for uri, entry in images.items():
        image = ctx.lookup(uri) or ctx.lookup(uri.removeprefix("https://"))
        if image is not None:
            entry["target"] = image.arn
            image.metadata["vulnerabilities"] = dict(entry["severity_counts"])
        else:
            entry["target"] = image_repository(uri.removeprefix("https://")) or uri
    return images


@source("artifact_analysis", "security")
def artifact_analysis(ctx: SourceContext, run: SourceRun) -> list[CloudAsset]:
    """Artifact Analysis vulnerability occurrences per image, per project with registries."""
    registry_projects = {
        a.account_id
        for a in ctx.by_type(
            "artifactregistry.googleapis.com/Repository",
            "artifactregistry.googleapis.com/DockerImage",
        )
        if a.account_id
    }
    out: list[CloudAsset] = []
    for project, _number in ctx.projects():
        if project not in registry_projects:
            continue
        svc = ctx.get(
            run,
            f"{_SU}/projects/{project}/services/containerscanning.googleapis.com",
            tolerate=True,
        )
        if svc and svc.get("state") == "DISABLED":
            out.append(
                ctx.placeholder(
                    "artifact-analysis",
                    f"projects/{project}",
                    AssetType.VULNERABILITY_SCANNER,
                    "Artifact Analysis vulnerability scanning",
                    gcp_type="containeranalysis.googleapis.com/VulnerabilitySummary",
                )
            )
            continue
        res = run.call(
            ctx.rest.list,
            f"{_CA}/projects/{project}/occurrences",
            "occurrences",
            {"filter": 'kind="VULNERABILITY"'},
            page_size=1000,
            max_items=ctx.options.max_vulnerability_occurrences,
        )
        if res is None:
            continue
        occurrences, truncated = res
        data = {
            "parent": f"projects/{project}",
            "images": _occurrence_summary(ctx, occurrences),
            "occurrence_count": len(occurrences),
            "truncated": truncated,
            "enabled": True,
            "displayName": "Artifact Analysis vulnerabilities",
        }
        out.append(
            ctx.build(
                f"//containeranalysis.googleapis.com/projects/{project}/vulnerabilitySummary",
                "containeranalysis.googleapis.com/VulnerabilitySummary",
                data,
                project=project,
                source_name="artifact_analysis",
            )
        )
    return [a for a in out if a is not None]


# ---------------------------------------------------------------------------
# Data Access audit logs (IAM policy auditConfigs, Resource Manager API)
# ---------------------------------------------------------------------------

_LOG_TYPES = {0: "LOG_TYPE_UNSPECIFIED", 1: "ADMIN_READ", 2: "DATA_WRITE", 3: "DATA_READ"}
_CRM_V3 = "https://cloudresourcemanager.googleapis.com/v3"


def _g(d: Any, snake: str, camel: str) -> Any:
    return d.get(snake, d.get(camel)) if isinstance(d, dict) else None


def audit_summary(policy: Any) -> dict[str, Any]:
    """Services with Data Access logging, exemptions and whether ``allServices`` is on."""
    services: list[dict[str, Any]] = []
    exempt: set[str] = set()
    for cfg in _g(policy, "audit_configs", "auditConfigs") or []:
        if not isinstance(cfg, dict):
            continue
        types = []
        for lc in _g(cfg, "audit_log_configs", "auditLogConfigs") or []:
            lt = _g(lc, "log_type", "logType")
            lt = _LOG_TYPES.get(lt, str(lt)) if isinstance(lt, int) else str(lt)
            types.append(lt)
            exempt |= set(_g(lc, "exempted_members", "exemptedMembers") or [])
        services.append({"service": cfg.get("service"), "log_types": types})
    data_access = [s for s in services if {"DATA_READ", "DATA_WRITE"} & set(s["log_types"])]
    return {
        "services": services,
        "allServices": any(s["service"] == "allServices" for s in data_access),
        "enabled": bool(data_access),
        "exemptedMembers": sorted(exempt),
    }


@source("audit_configs", "logging")
def audit_configs(ctx: SourceContext, run: SourceRun) -> list[CloudAsset]:
    """Data Access audit log configuration of the organization, folders and projects.

    Admin Activity logs are always on; Data Access logs only where an IAM
    policy ``auditConfigs`` entry turns them on. Parents without one get a
    "not enabled" asset, like an AWS account without a CloudTrail trail.
    """
    out: list[CloudAsset] = []
    for parent in ctx.parents():
        policy = run.call(
            ctx.rest.post,
            f"{_CRM_V3}/{parent}:getIamPolicy",
            {"options": {"requestedPolicyVersion": 3}},
        )
        if policy is None:
            continue
        summary = audit_summary(policy)
        name = f"//cloudresourcemanager.googleapis.com/{parent}"
        target = ctx.lookup(name)
        if target is not None:
            target.metadata["data_access_audit_logs"] = summary["enabled"]
        project = parent.split("/", 1)[1] if parent.startswith("projects/") else None
        label = "Data Access audit logs"
        data = {
            **summary,
            "resource": name,
            "displayName": f"{label} @ {parent}" + ("" if summary["enabled"] else " (not enabled)"),
        }
        asset = ctx.build(
            f"//logging.googleapis.com/{parent}/auditConfig",
            "logging.googleapis.com/AuditConfig",
            data,
            project=project,
            source_name="audit_configs",
            global_resource=project is None,
        )
        if asset is None:
            continue
        if not summary["enabled"]:
            asset.arn = f"cloudg:gcp:audit-logs:{parent}:not-enabled"
            asset.metadata["status"] = "not enabled"
        out.append(asset)
    return out


# ---------------------------------------------------------------------------
# IAM recommender
# ---------------------------------------------------------------------------


def _recommendation(rec: dict[str, Any]) -> list[dict[str, Any]]:
    """(member, role, resource, action) of each operation of an IAM recommendation."""
    out = []
    for group in (rec.get("content") or {}).get("operationGroups") or []:
        for op in (group or {}).get("operations") or []:
            filters = op.get("pathFilters") or {}
            member = filters.get("/iamPolicy/bindings/*/members/*")
            role = filters.get("/iamPolicy/bindings/*/role")
            if member or role:
                out.append(
                    {
                        "member": member,
                        "role": role,
                        "resource": op.get("resource"),
                        "action": op.get("action"),
                        "priority": rec.get("priority"),
                        "description": rec.get("description"),
                    }
                )
    return out


@source("iam_recommender", "security")
def iam_recommender(ctx: SourceContext, run: SourceRun) -> list[CloudAsset]:
    """IAM role recommendations (excess permissions) per project."""
    out: list[CloudAsset] = []
    for project, _number in ctx.projects():
        recs = ctx.items(
            run,
            f"{_REC}/projects/{project}/locations/global/recommenders/google.iam.policy.Recommender/recommendations",
            "recommendations",
            page_size=500,
        )
        active = [r for r in recs if (r.get("stateInfo") or {}).get("state") in (None, "ACTIVE")]
        ops = [op for r in active for op in _recommendation(r)]
        if not ops:
            continue
        out.append(
            ctx.build(
                f"//recommender.googleapis.com/projects/{project}/iamPolicyRecommender",
                "recommender.googleapis.com/IamPolicyRecommender",
                {
                    "parent": f"projects/{project}",
                    "recommendations": ops,
                    "displayName": "IAM recommender",
                },
                project=project,
                source_name="iam_recommender",
            )
        )
    return [a for a in out if a is not None]


# ---------------------------------------------------------------------------
# Sensitive Data Protection discovery coverage
# ---------------------------------------------------------------------------


@source("dlp_discovery", "security", phase=3, needs_rest=False)
def dlp_discovery_coverage(ctx: SourceContext, run: SourceRun) -> list[CloudAsset]:
    """A "not enabled" placeholder per project no Sensitive Data Protection discovery covers."""
    configs = ctx.by_type("dlp.googleapis.com/DiscoveryConfig")
    covered: set[str] = set()
    org_wide = False
    for cfg in configs:
        if not cfg.metadata.get("enabled", True):
            continue
        scope = str(cfg.metadata.get("scope") or "")
        if scope.startswith(("organizations/", "folders/")):
            org_wide = True
        if cfg.account_id:
            covered.add(cfg.account_id)
    run.ok += 1
    if org_wide:
        return []
    return [
        ctx.placeholder(
            "dlp-discovery",
            f"projects/{project}",
            AssetType.DATA_SECURITY_SCANNER,
            "Sensitive Data Protection discovery",
            gcp_type="dlp.googleapis.com/DiscoveryConfig",
        )
        for project, _ in ctx.projects()
        if project not in covered
    ]
