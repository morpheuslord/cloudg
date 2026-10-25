"""Defender for Cloud and Microsoft Sentinel: coverage, findings and placeholders.

- Defender plans (``microsoft.security/pricings``): an enabled plan
  ``MONITORS / MONITORED_BY`` the subscription (as before) and every
  resource of the types it covers, unless a resource-level pricing turns it
  off. Plans the subscription does not list become "not enabled"
  placeholders, like the AWS ``_disabled_asset`` ones.
- Assessments and sub-assessments (``securityresources``): one
  ``SECURITY_HUB`` asset per subscription ("Defender for Cloud
  recommendations", with the secure score) ``MONITORS`` each assessed
  resource, ``FINDING_AFFECTS`` when it has unhealthy recommendations or
  vulnerabilities (container image findings included).
- Alerts: one ``THREAT_DETECTOR`` asset ``MONITORS / FINDING_AFFECTS`` each
  resource an active alert names.
- Sentinel: onboarded workspaces (``microsoft.securityinsights``), their
  data connectors (``LOGS_TO`` the workspace, ``MONITORS`` their source,
  AWS connectors ``ASSUMES_ROLE / CROSS_ACCOUNT_TRUST`` the AWS role),
  analytics rules and automation rules (``INVOKES`` playbooks); a "not
  enabled" placeholder when no workspace of the subscription has Sentinel.
- Guest configuration assignments ``GOVERNS`` their machine.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from cloudg.inventory.aws_services._base import rel
from cloudg.inventory.azure_graph.helpers import (
    _get,
    _list,
    _lower,
    _path,
    host_of,
    subscription_ref,
)
from cloudg.inventory.azure_graph.registry import _Draft, extractor
from cloudg.schema.models import AssetType, CloudAsset, CloudProvider, EdgeType

if TYPE_CHECKING:
    from cloudg.inventory.azure_graph.builder import AzureAssetBuilder

# Defender plan (lowercase pricing name) -> resource types it protects
PLAN_RESOURCE_TYPES: dict[str, tuple[str, ...]] = {
    "virtualmachines": (
        "microsoft.compute/virtualmachines",
        "microsoft.compute/virtualmachinescalesets",
        "microsoft.hybridcompute/machines",
    ),
    "sqlservers": ("microsoft.sql/servers", "microsoft.sql/managedinstances"),
    "sqlservervirtualmachines": ("microsoft.sqlvirtualmachine/sqlvirtualmachines",),
    "appservices": ("microsoft.web/sites",),
    "storageaccounts": ("microsoft.storage/storageaccounts",),
    "keyvaults": ("microsoft.keyvault/vaults", "microsoft.keyvault/managedhsms"),
    "containers": (
        "microsoft.containerservice/managedclusters",
        "microsoft.containerregistry/registries",
        "microsoft.kubernetes/connectedclusters",
    ),
    "kubernetesservice": ("microsoft.containerservice/managedclusters",),
    "containerregistry": ("microsoft.containerregistry/registries",),
    "opensourcerelationaldatabases": (
        "microsoft.dbforpostgresql/flexibleservers",
        "microsoft.dbforpostgresql/servers",
        "microsoft.dbformysql/flexibleservers",
        "microsoft.dbformysql/servers",
        "microsoft.dbformariadb/servers",
    ),
    "cosmosdbs": ("microsoft.documentdb/databaseaccounts",),
    "api": ("microsoft.apimanagement/service",),
    "ai": ("microsoft.cognitiveservices/accounts",),
}

# Plans every subscription can turn on; missing ones get a placeholder
STANDARD_PLANS: tuple[str, ...] = (
    "VirtualMachines",
    "SqlServers",
    "SqlServerVirtualMachines",
    "AppServices",
    "StorageAccounts",
    "KeyVaults",
    "Arm",
    "OpenSourceRelationalDatabases",
    "Containers",
    "CosmosDbs",
    "CloudPosture",
    "Api",
    "AI",
)
_MAX_COVERED = 5000
_MAX_TITLES = 20


def _security_alias(service: str, subscription_id: str) -> str:
    return f"azure-security:{service}:{subscription_id}"


def _disabled_asset(
    subscription_id: str,
    service: str,
    asset_type: AssetType,
    label: str,
    reason: str = "not enabled",
) -> CloudAsset:
    """Placeholder for a security service that is not on in this subscription."""
    return CloudAsset(
        arn=f"cloudg:azure:{service}:{subscription_id}:not-enabled",
        name=f"{label} ({reason})",
        asset_type=asset_type,
        provider=CloudProvider.AZURE,
        region="global",
        account_id=subscription_id,
        metadata={
            "security_service": service,
            "enabled": False,
            "status": reason,
            "aliases": [_security_alias(service, subscription_id)],
        },
    )


def defender_coverage(
    b: "AzureAssetBuilder", overrides: dict[str, bool], pricings_seen: bool
) -> None:
    """Per-resource MONITORS of enabled plans; placeholders for plans not listed."""
    present: set[str] = set()
    for asset in b.extras:
        md = asset.metadata
        if md.get("resource_type") != "microsoft.security/pricings":
            continue
        plan = str(md.get("security_service", "")).removeprefix("defender-")
        present.add(plan)
        if not md.get("enabled"):
            continue
        relations = md.setdefault("relations", [])
        covered = 0
        for d in b.drafts_of(*PLAN_RESOURCE_TYPES.get(plan, ())):
            if overrides.get(f"{d.id.lower()}|{plan}") is False or covered >= _MAX_COVERED:
                continue
            covered += 1
            relations.append(
                rel(d.id, EdgeType.MONITORS, "MONITORED_BY", description=f"Defender plan {plan}")
            )
        md["covered_resources"] = covered
    if not pricings_seen:
        return
    for plan in STANDARD_PLANS:
        if plan.lower() not in present:
            b.add_extra(
                _disabled_asset(
                    b.subscription_id,
                    f"defender-{plan.lower()}",
                    AssetType.THREAT_DETECTOR,
                    f"Defender for Cloud: {plan}",
                )
            )


# ── assessments, secure score, alerts ──


def _cspm_asset(b: "AzureAssetBuilder") -> CloudAsset:
    asset = b.state.get("defender_cspm_asset")
    if asset is None:
        sub = b.subscription_id
        asset = CloudAsset(
            arn=f"cloudg:azure:defender-cspm:{sub}",
            name="Defender for Cloud recommendations",
            asset_type=AssetType.SECURITY_HUB,
            provider=CloudProvider.AZURE,
            region="global",
            account_id=sub,
            metadata={
                "security_service": "defender-cspm",
                "enabled": True,
                "resource_type": "microsoft.security/assessments",
                "aliases": [_security_alias("defender-cspm", sub)],
                "relations": [
                    rel(subscription_ref(sub), EdgeType.MONITORS, "MONITORED_BY"),
                ],
            },
        )
        b.state["defender_cspm_asset"] = asset
        b.add_extra(asset)
    return asset


def _bucket(agg: dict[str, dict[str, Any]], rid: str) -> dict[str, Any]:
    return agg.setdefault(
        rid,
        {
            "healthy": 0,
            "unhealthy": 0,
            "not_applicable": 0,
            "high": 0,
            "vulnerabilities": 0,
            "high_vulnerabilities": 0,
            "titles": [],
            "images": [],
        },
    )


def _count_assessment(entry: dict[str, Any], row: dict[str, Any]) -> None:
    code = _lower(row.get("code"))
    severity = _lower(row.get("severity"))
    title = row.get("title")
    if _lower(row.get("type")).endswith("/subassessments"):
        if code == "unhealthy":
            entry["vulnerabilities"] += 1
            entry["high_vulnerabilities"] += severity in ("high", "critical")
            extra = row.get("additionalData") or {}
            image = _get(extra, "repositoryName") or _path(
                extra, "artifactDetails", "repositoryName"
            )
            if image and image not in entry["images"] and len(entry["images"]) < _MAX_TITLES:
                entry["images"].append(image)
        return
    if code == "healthy":
        entry["healthy"] += 1
    elif code == "unhealthy":
        entry["unhealthy"] += 1
        entry["high"] += severity == "high"
        if title and title not in entry["titles"] and len(entry["titles"]) < _MAX_TITLES:
            entry["titles"].append(title)
    else:
        entry["not_applicable"] += 1


def add_assessments(b: "AzureAssetBuilder", rows: list[dict[str, Any]]) -> int:
    """Aggregate assessments / sub-assessments into per-resource relations."""
    agg: dict[str, dict[str, Any]] = {}
    for row in rows:
        if not isinstance(row, dict):
            continue
        if _lower(row.get("type")) not in (
            "microsoft.security/assessments",
            "microsoft.security/assessments/subassessments",
        ):
            continue
        rid = row.get("resourceId") or _path(row.get("properties") or {}, "resourceDetails", "Id")
        if not isinstance(rid, str) or not rid.startswith("/"):
            continue
        _count_assessment(_bucket(agg, rid.rstrip("/")), row)
    if not agg:
        return 0
    asset = _cspm_asset(b)
    relations = asset.metadata.setdefault("relations", [])
    totals = {"healthy": 0, "unhealthy": 0, "vulnerabilities": 0}
    for rid, entry in list(agg.items())[:_MAX_COVERED]:
        for key in totals:
            totals[key] += entry[key]
        finding = entry["unhealthy"] or entry["vulnerabilities"]
        relations.append(
            rel(
                rid,
                EdgeType.MONITORS,
                "FINDING_AFFECTS" if finding else "MONITORED_BY",
                description="Defender for Cloud assessment",
                **{k: v for k, v in entry.items() if v},
            )
        )
    asset.metadata.update(
        {
            "assessed_resources": len(agg),
            "healthy_assessments": totals["healthy"],
            "unhealthy_assessments": totals["unhealthy"],
            "vulnerability_findings": totals["vulnerabilities"],
        }
    )
    return len(rows)


def add_secure_score(b: "AzureAssetBuilder", rows: list[dict[str, Any]]) -> int:
    score: dict[str, Any] | None = None
    controls: list[dict[str, Any]] = []
    for row in rows:
        rtype = _lower(row.get("type"))
        props = row.get("properties") or {}
        sc = _get(props, "score") or {}
        if rtype == "microsoft.security/securescores":
            score = {
                "current": _get(sc, "current"),
                "max": _get(sc, "max"),
                "percentage": _get(sc, "percentage"),
            }
        elif rtype == "microsoft.security/securescores/securescorecontrols":
            controls.append(
                {
                    "control": _get(props, "displayName"),
                    "current": _get(sc, "current"),
                    "max": _get(sc, "max"),
                    "unhealthy_resources": _get(props, "unhealthyResourceCount"),
                }
            )
    if score is None and not controls:
        return 0
    md = _cspm_asset(b).metadata
    if score is not None:
        md["secure_score"] = score
    if controls:
        controls.sort(key=lambda c: -(c.get("unhealthy_resources") or 0))
        md["secure_score_controls"] = controls[:30]
    return len(rows)


def _alert_resources(props: dict[str, Any]) -> list[str]:
    out: list[str] = []
    for ident in _list(_get(props, "resourceIdentifiers")):
        rid = _get(ident, "azureResourceId") or _get(ident, "AzureResourceId")
        if isinstance(rid, str) and rid.startswith("/") and rid not in out:
            out.append(rid.rstrip("/"))
    entity = _get(props, "compromisedEntity")
    if not out and isinstance(entity, str) and entity.startswith("/subscriptions/"):
        out.append(entity)
    return out


def add_security_alerts(b: "AzureAssetBuilder", rows: list[dict[str, Any]]) -> int:
    """Active alerts: one THREAT_DETECTOR asset FINDING_AFFECTS each named resource."""
    agg: dict[str, dict[str, Any]] = {}
    severities: dict[str, int] = {}
    rows = [r for r in rows if _lower(r.get("type")) == "microsoft.security/locations/alerts"]
    for row in rows:
        props = row.get("properties") or {}
        sev = str(_get(props, "severity") or _get(props, "Severity") or "Unknown")
        severities[sev] = severities.get(sev, 0) + 1
        name = _get(props, "alertDisplayName") or _get(props, "AlertDisplayName") or row.get("name")
        for rid in _alert_resources(props):
            entry = agg.setdefault(rid, {"alerts": 0, "high": 0, "names": []})
            entry["alerts"] += 1
            entry["high"] += _lower(sev) == "high"
            if name and name not in entry["names"] and len(entry["names"]) < _MAX_TITLES:
                entry["names"].append(name)
    if not rows:
        return 0
    sub = b.subscription_id
    relations = [rel(subscription_ref(sub), EdgeType.MONITORS, "MONITORED_BY")]
    relations += [
        rel(rid, EdgeType.MONITORS, "FINDING_AFFECTS", description="Defender alert", **entry)
        for rid, entry in list(agg.items())[:_MAX_COVERED]
    ]
    b.add_extra(
        CloudAsset(
            arn=f"cloudg:azure:defender-alerts:{sub}",
            name="Defender for Cloud alerts",
            asset_type=AssetType.THREAT_DETECTOR,
            provider=CloudProvider.AZURE,
            region="global",
            account_id=sub,
            metadata={
                "security_service": "defender-alerts",
                "enabled": True,
                "active_alerts": sum(severities.values()),
                "alerts_by_severity": severities,
                "affected_resources": len(agg),
                "aliases": [_security_alias("defender-alerts", sub)],
                "relations": [r for r in relations if r],
            },
        )
    )
    return len(rows)


# ── Microsoft Sentinel ──


def _sentinel_row(workspace: str, subscription_id: str, region: str) -> dict[str, Any]:
    return {
        "id": f"{workspace}/providers/Microsoft.SecurityInsights/onboardingStates/default",
        "name": "default",
        "type": "microsoft.securityinsights/onboardingstates",
        "location": region,
        "subscriptionId": subscription_id,
        "properties": {},
    }


@extractor("microsoft.operationsmanagement/solutions")
def _x_solution(d: _Draft, b: "AzureAssetBuilder") -> None:
    ws = _get(d.props, "workspaceResourceId")
    product = _lower(_get(d.row.get("plan") or {}, "product"))
    d.md["workspace_id"] = ws
    d.add(rel(ws, EdgeType.REFERENCES, "DEPENDS_ON", description="solution workspace"))
    if isinstance(ws, str) and (
        d.name.lower().startswith("securityinsights(") or product.endswith("/securityinsights")
    ):
        b.add_row(_sentinel_row(ws, d.account_id, d.region), synthetic=True)


@extractor("microsoft.securityinsights/onboardingstates")
def _x_sentinel(d: _Draft, b: "AzureAssetBuilder") -> None:
    from cloudg.inventory.azure_graph.governance import extension_owner

    ws = extension_owner(d.id)
    d.name = f"Microsoft Sentinel ({(ws or '').rsplit('/', 1)[-1]})"
    d.md.update({"security_service": "sentinel", "enabled": True, "workspace_id": ws})
    d.alias(_security_alias("sentinel", d.account_id))
    d.add(rel(ws, EdgeType.REFERENCES, "DEPENDS_ON", description="Sentinel workspace"))
    d.add(rel(subscription_ref(d.account_id), EdgeType.MONITORS, "MONITORED_BY"))


def sentinel_placeholder(b: "AzureAssetBuilder") -> None:
    """ "Microsoft Sentinel (not enabled)" when no workspace has Sentinel."""
    if not b.drafts_of("microsoft.securityinsights/onboardingstates"):
        b.add_extra(
            _disabled_asset(
                b.subscription_id, "sentinel", AssetType.THREAT_DETECTOR, "Microsoft Sentinel"
            )
        )


def _connector_relations(d: _Draft, ws: str | None) -> None:
    p = d.props
    kind = _lower(d.row.get("kind"))
    d.md["connector_kind"] = d.row.get("kind")
    d.add(rel(ws, EdgeType.LOGS_TO, "LOGS_TO", description="Sentinel data connector"))
    sub = _get(p, "subscriptionId")
    if sub:
        d.add(rel(subscription_ref(sub), EdgeType.MONITORS, "MONITORED_BY"))
    tenant = _get(p, "tenantId")
    if tenant and kind in ("azureactivedirectory", "office365", "microsoftthreatprotection"):
        d.add(rel(f"entra:tenant/{tenant}", EdgeType.MONITORS, "MONITORED_BY"))
    role = _get(p, "awsRoleArn") or _get(p, "roleArn")
    if isinstance(role, str) and role.startswith("arn:aws"):
        d.add(
            rel(
                role,
                EdgeType.ASSUMES_ROLE,
                "CROSS_ACCOUNT_TRUST",
                description="Sentinel AWS connector role",
            )
        )
    for url in _list(_get(p, "sqsUrls")):
        d.add(rel(url, EdgeType.REFERENCES, "READS_FROM", description="S3 notification queue"))


@extractor("microsoft.securityinsights/dataconnectors")
def _x_sentinel_connector(d: _Draft, b: "AzureAssetBuilder") -> None:
    from cloudg.inventory.azure_graph.governance import extension_owner

    _connector_relations(d, extension_owner(d.id))


@extractor("microsoft.securityinsights/alertrules")
def _x_sentinel_rule(d: _Draft, b: "AzureAssetBuilder") -> None:
    from cloudg.inventory.azure_graph.governance import extension_owner

    p = d.props
    d.name = _get(p, "displayName") or d.name
    d.md.update(
        {
            "rule_kind": d.row.get("kind"),
            "enabled": _get(p, "enabled"),
            "severity": _get(p, "severity"),
            "tactics": _list(_get(p, "tactics")),
            "query_frequency": _get(p, "queryFrequency"),
        }
    )
    d.add(
        rel(extension_owner(d.id), EdgeType.MONITORS, "MONITORED_BY", description="analytics rule")
    )


@extractor("microsoft.securityinsights/automationrules")
def _x_sentinel_automation(d: _Draft, b: "AzureAssetBuilder") -> None:
    p = d.props
    d.name = _get(p, "displayName") or d.name
    d.md["order"] = _get(p, "order")
    for action in _list(_get(p, "actions")):
        app = _path(action, "actionConfiguration", "logicAppResourceId")
        d.add(rel(app, EdgeType.INVOKES, "INVOKES", description="playbook"))


# ── guest configuration ──


@extractor("microsoft.guestconfiguration/guestconfigurationassignments")
def _x_guest_configuration(d: _Draft, b: "AzureAssetBuilder") -> None:
    from cloudg.inventory.azure_graph.governance import extension_owner

    p = d.props
    status = _get(p, "complianceStatus")
    machine = _get(p, "targetResourceId") or extension_owner(d.id)
    d.md.update(
        {
            "guardrail_kind": "guest-configuration",
            "compliance_status": status,
            "configuration": _path(p, "guestConfiguration", "name"),
            "assignment_type": _path(p, "guestConfiguration", "assignmentType"),
            "last_checked": _get(p, "lastComplianceStatusChecked"),
        }
    )
    d.add(
        rel(
            machine,
            EdgeType.GOVERNS,
            "FINDING_AFFECTS" if _lower(status) == "noncompliant" else "COMPLIANCE_GOVERNS",
            description="guest configuration",
            compliance_status=status,
        )
    )


# ── Defender for Cloud automations (export to Event Hubs / Log Analytics / Logic Apps) ──


@extractor("microsoft.security/automations")
def _x_security_automation(d: _Draft, b: "AzureAssetBuilder") -> None:
    for action in _list(_get(d.props, "actions")):
        kind = _lower(_get(action, "actionType"))
        target = (
            _get(action, "logicAppResourceId")
            or _get(action, "eventHubResourceId")
            or _get(action, "workspaceResourceId")
        )
        if kind == "logicapp":
            d.add(rel(target, EdgeType.INVOKES, "INVOKES", description="workflow automation"))
        elif kind == "eventhub":
            d.add(rel(target, EdgeType.LOGS_TO, "STREAMS_TO", description="continuous export"))
        elif kind == "workspace":
            d.add(rel(target, EdgeType.LOGS_TO, "LOGS_TO", description="continuous export"))
        else:
            d.add(rel(host_of(_get(action, "uri")), EdgeType.INVOKES, "INVOKES"))


__all__ = [
    "PLAN_RESOURCE_TYPES",
    "STANDARD_PLANS",
    "add_assessments",
    "add_secure_score",
    "add_security_alerts",
    "defender_coverage",
    "sentinel_placeholder",
]
