"""Extractors for operations, monitoring, backup, containers and identity depth.

- Metric, log-search, activity-log and smart-detector alerts
  (``MONITORS / MONITORED_BY`` their scopes, ``INVOKES`` action groups);
  action groups (``INVOKES`` webhooks, functions, Logic Apps, runbooks,
  Event Hubs; e-mail addresses and phone numbers are dropped).
- Diagnostic settings (the resource and the setting ``LOGS_TO`` the
  workspace / storage, ``STREAMS_TO`` Event Hubs), data collection rules
  and associations, maintenance configurations and their assignments
  (``SCHEDULED_BY``), Automation runbooks, schedules, job schedules,
  hybrid worker groups and update deployments, Arc machines and
  extensions, App Configuration replicas.
- Backup: Recovery Services protected items and policies, Azure Backup
  instances and policies (``BACKUP_TO``), Site Recovery replicated items
  (``REPLICATES_TO``), vault immutability, soft delete and CMK.
- Containers: ACR replications (``REPLICATES_TO``), webhooks (``INVOKES``),
  tasks (``READS_FROM`` source repos, ``WRITES_TO`` the registry, timer
  ``SCHEDULED_BY``), scope maps and tokens (``GRANTS_ACCESS``); AKS Entra
  admin groups, OIDC issuer, trusted access, cluster extensions and Flux
  configurations (``READS_FROM`` Git).
- Identity: user-assigned identity federated credentials (``IAM_TRUST``
  from the AKS issuer or an external issuer), Key Vault keys and secrets
  (metadata only: no values) with rotation policies.
- Compute: Batch pools, Spring Apps, availability sets, proximity
  placement and host groups; Azure Deployment Environments (dev centers,
  projects, catalogs, environment types).
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from cloudg.inventory.aws_services._base import rel
from cloudg.inventory.azure_graph.helpers import (
    LOG_ANALYTICS_PREFIX,
    _get,
    _list,
    _lower,
    _path,
    _rid,
    _rids,
    host_of,
    issuer_kind,
    parent_resource_id,
    principal_ref,
    subscription_ref,
)
from cloudg.inventory.azure_graph.registry import _Draft, _keyvault_key_ref, extractor, relation_row
from cloudg.schema.models import EdgeType

if TYPE_CHECKING:
    from cloudg.inventory.azure_graph.builder import AzureAssetBuilder

_MODEL_LOG_CATEGORIES = {"requestresponse", "audit", "trace", "allmetrics"}


def _owner_of(extension_id: Any) -> str | None:
    rid = str(extension_id or "")
    cut = rid.lower().rfind("/providers/")
    return rid[:cut] if cut > 0 else None


# ── alerts and action groups ──


def _alert_common(d: _Draft, scopes: list[Any], groups: list[Any], description: str) -> None:
    for scope in scopes:
        d.add(rel(scope, EdgeType.MONITORS, "MONITORED_BY", description=description))
    for group in groups:
        d.add(rel(group, EdgeType.INVOKES, "INVOKES", description="action group"))
    d.md["enabled"] = _get(d.props, "enabled")
    d.md["severity"] = _get(d.props, "severity")
    d.md["scopes"] = scopes[:50]


@extractor("microsoft.insights/metricalerts")
def _x_metric_alert(d: _Draft, b: "AzureAssetBuilder") -> None:
    p = d.props
    groups = [_get(a, "actionGroupId") for a in _list(_get(p, "actions"))]
    d.md["criteria"] = [_get(c, "metricName") for c in _list(_path(p, "criteria", "allOf"))]
    _alert_common(d, _list(_get(p, "scopes")), groups, "metric alert")


@extractor("microsoft.insights/scheduledqueryrules")
def _x_log_alert(d: _Draft, b: "AzureAssetBuilder") -> None:
    p = d.props
    actions = _get(p, "actions") or {}
    groups = _list(_get(actions, "actionGroups")) if isinstance(actions, dict) else []
    groups += [_get(a, "actionGroupId") for a in _list(actions) if isinstance(a, dict)]
    _alert_common(d, _list(_get(p, "scopes")), groups, "log search alert")


@extractor("microsoft.insights/activitylogalerts")
def _x_activity_alert(d: _Draft, b: "AzureAssetBuilder") -> None:
    p = d.props
    groups = [_get(a, "actionGroupId") for a in _list(_path(p, "actions", "actionGroups"))]
    d.md["conditions"] = [
        f"{_get(c, 'field')}={_get(c, 'equals')}" for c in _list(_path(p, "condition", "allOf"))
    ][:20]
    _alert_common(d, _list(_get(p, "scopes")), groups, "activity log alert")


@extractor("microsoft.alertsmanagement/smartdetectoralertrules")
def _x_smart_alert(d: _Draft, b: "AzureAssetBuilder") -> None:
    p = d.props
    groups = _list(_path(p, "actionGroups", "groupIds"))
    _alert_common(d, _list(_get(p, "scope")), groups, "smart detector")


_RECEIVERS = (
    ("webhookReceivers", "serviceUri", True),
    ("azureFunctionReceivers", "functionAppResourceId", False),
    ("logicAppReceivers", "resourceId", False),
    ("automationRunbookReceivers", "automationAccountId", False),
    ("armRoleReceivers", None, False),
)


@extractor("microsoft.insights/actiongroups")
def _x_action_group(d: _Draft, b: "AzureAssetBuilder") -> None:
    p = d.props
    counts: dict[str, int] = {}
    for key, field, is_url in _RECEIVERS:
        receivers = _list(_get(p, key))
        counts[key] = len(receivers)
        if not field:
            continue
        for r in receivers:
            target = _get(r, field)
            d.add(
                rel(
                    host_of(target) if is_url else target,
                    EdgeType.INVOKES,
                    "INVOKES",
                    description=key.removesuffix("Receivers"),
                )
            )
    for r in _list(_get(p, "eventHubReceivers")):
        ns, hub = _lower(_get(r, "eventHubNameSpace")), _lower(_get(r, "eventHubName"))
        d.add(
            rel(
                f"{ns}.servicebus.windows.net/{hub}" if ns and hub else None,
                EdgeType.INVOKES,
                "STREAMS_TO",
                description="Event Hubs receiver",
            )
        )
    for key in ("emailReceivers", "smsReceivers", "voiceReceivers", "azureAppPushReceivers"):
        counts[key] = len(_list(_get(p, key)))
    d.md["receiver_counts"] = {k: v for k, v in counts.items() if v}
    d.md["enabled"] = _get(p, "enabled")
    # contact details are personal data, not inventory
    d.props = {
        k: v
        for k, v in p.items()
        if _lower(k)
        not in ("emailreceivers", "smsreceivers", "voicereceivers", "azureapppushreceivers")
    }


# ── diagnostic settings, data collection ──


@extractor("microsoft.insights/diagnosticsettings")
def _x_diagnostic_setting(d: _Draft, b: "AzureAssetBuilder") -> None:
    from cloudg.inventory.azure_graph.integration import _set_md_later

    p = d.props
    source = _owner_of(d.id)
    categories = [
        str(_get(x, "category") or _get(x, "categoryGroup") or "")
        for x in _list(_get(p, "logs"))
        if _get(x, "enabled")
    ]
    d.md.update(
        {
            "source_resource": source,
            "log_categories": categories,
            "metrics": any(_get(m, "enabled") for m in _list(_get(p, "metrics"))),
        }
    )
    targets = [
        (_get(p, "workspaceId"), "LOGS_TO", EdgeType.LOGS_TO),
        (_get(p, "storageAccountId"), "LOGS_TO", EdgeType.LOGS_TO),
        (_get(p, "marketplacePartnerId"), "LOGS_TO", EdgeType.LOGS_TO),
    ]
    rule = _get(p, "eventHubAuthorizationRuleId")
    hub_ns = None
    if isinstance(rule, str) and rule:
        cut = rule.lower().find("/authorizationrules/")
        hub_ns = rule[:cut] if cut > 0 else rule
    hub = _get(p, "eventHubName")
    hub_target = f"{hub_ns}/eventhubs/{hub}" if hub_ns and hub else hub_ns
    targets.append((hub_target, "STREAMS_TO", EdgeType.LOGS_TO))
    for target, relationship, edge in targets:
        if not target:
            continue
        d.add(rel(target, edge, relationship, description="diagnostic setting"))
        if source:
            b.defer(
                source, rel(target, edge, relationship, description=f"diagnostic setting {d.name}")
            )
    if source and "/microsoft.cognitiveservices/accounts/" in source.lower():
        logged = {c.lower() for c in categories} & _MODEL_LOG_CATEGORIES
        _set_md_later(b, source, {"model_request_logging": bool(logged) or None})
    if source:
        _set_md_later(b, source, {"diagnostic_settings": True})


@extractor("microsoft.insights/datacollectionrules")
def _x_dcr(d: _Draft, b: "AzureAssetBuilder") -> None:
    p = d.props
    dest = _get(p, "destinations") or {}
    for ws in _list(_get(dest, "logAnalytics")):
        d.add(rel(_get(ws, "workspaceResourceId"), EdgeType.LOGS_TO, "LOGS_TO"))
    for acct in _list(_get(dest, "storageBlobsDirect")) + _list(_get(dest, "storageAccounts")):
        d.add(rel(_get(acct, "storageAccountResourceId"), EdgeType.LOGS_TO, "LOGS_TO"))
    for hub in _list(_get(dest, "eventHubsDirect")) + _list(_get(dest, "eventHubs")):
        d.add(rel(_get(hub, "eventHubResourceId"), EdgeType.LOGS_TO, "STREAMS_TO"))
    for mon in _list(_get(dest, "monitoringAccounts")):
        d.add(rel(_get(mon, "accountResourceId"), EdgeType.LOGS_TO, "LOGS_TO"))
    d.add(rel(_get(p, "dataCollectionEndpointId"), EdgeType.REFERENCES, "DEPENDS_ON"))
    d.md["streams"] = sorted(
        {s for f in _list(_get(p, "dataFlows")) for s in _list(_get(f, "streams"))}
    )


@relation_row("microsoft.insights/datacollectionruleassociations")
def _dcr_association(row: dict[str, Any], b: "AzureAssetBuilder") -> None:
    p = row.get("properties") or {}
    resource = _owner_of(row.get("id"))
    rule = _get(p, "dataCollectionRuleId")
    if not resource:
        return
    b.defer(resource, rel(rule, EdgeType.LOGS_TO, "LOGS_TO", description="data collection rule"))
    b.defer(resource, rel(_get(p, "dataCollectionEndpointId"), EdgeType.REFERENCES, "DEPENDS_ON"))
    b.defer(rule, rel(resource, EdgeType.MONITORS, "MONITORED_BY", description="collects from"))


@extractor("microsoft.maintenance/maintenanceconfigurations")
def _x_maintenance_config(d: _Draft, b: "AzureAssetBuilder") -> None:
    p = d.props
    window = _get(p, "maintenanceWindow") or {}
    d.md.update(
        {
            "maintenance_scope": _get(p, "maintenanceScope"),
            "recur_every": _get(window, "recurEvery"),
            "start": _get(window, "startDateTime"),
            "duration": _get(window, "duration"),
        }
    )


@relation_row("microsoft.maintenance/configurationassignments")
def _maintenance_assignment(row: dict[str, Any], b: "AzureAssetBuilder") -> None:
    p = row.get("properties") or {}
    config = _get(p, "maintenanceConfigurationId")
    target = _get(p, "resourceId") or _owner_of(row.get("id"))
    b.defer(
        config, rel(target, EdgeType.MANAGES, "SCHEDULED_BY", description="maintenance assignment")
    )


# ── Automation ──


def _account_of(child_id: str | None) -> str | None:
    return parent_resource_id(child_id)


@extractor("microsoft.automation/automationaccounts/runbooks")
def _x_runbook(d: _Draft, b: "AzureAssetBuilder") -> None:
    p = d.props
    d.md.update(
        {
            "runbook_type": _get(p, "runbookType"),
            "state": _get(p, "state"),
            "log_verbose": _get(p, "logVerbose"),
        }
    )


@extractor("microsoft.automation/automationaccounts/schedules")
def _x_automation_schedule(d: _Draft, b: "AzureAssetBuilder") -> None:
    p = d.props
    d.md.update(
        {
            "frequency": _get(p, "frequency"),
            "interval": _get(p, "interval"),
            "enabled": _get(p, "isEnabled"),
            "next_run": _get(p, "nextRun"),
        }
    )


@relation_row("microsoft.automation/automationaccounts/jobschedules")
def _job_schedule(row: dict[str, Any], b: "AzureAssetBuilder") -> None:
    p = row.get("properties") or {}
    account = _account_of(row.get("id"))
    runbook = _get(_get(p, "runbook") or {}, "name")
    schedule = _get(_get(p, "schedule") or {}, "name")
    if not account or not runbook:
        return
    runbook_id = f"{account}/runbooks/{runbook}"
    if schedule:
        b.defer(
            f"{account}/schedules/{schedule}",
            rel(runbook_id, EdgeType.MANAGES, "SCHEDULED_BY", description="job schedule"),
        )
    worker = _get(p, "runOn")
    if worker:
        b.defer(
            runbook_id,
            rel(
                f"{account}/hybridRunbookWorkerGroups/{worker}",
                EdgeType.REFERENCES,
                "RUNS_ON",
                description="hybrid worker group",
            ),
        )


@extractor("microsoft.automation/automationaccounts/hybridrunbookworkergroups")
def _x_worker_group(d: _Draft, b: "AzureAssetBuilder") -> None:
    d.md["group_type"] = _get(d.props, "groupType")
    d.md["credential"] = _path(d.props, "credential", "name")


@relation_row(
    "microsoft.automation/automationaccounts/hybridrunbookworkergroups/hybridrunbookworkers"
)
def _hybrid_worker(row: dict[str, Any], b: "AzureAssetBuilder") -> None:
    p = row.get("properties") or {}
    b.defer(
        parent_resource_id(row.get("id")),
        rel(
            _get(p, "vmResourceId"),
            EdgeType.CONTAINS,
            "CLUSTER_CONTAINS_SERVICE",
            description="hybrid worker",
        ),
    )


@extractor("microsoft.automation/automationaccounts/softwareupdateconfigurations")
def _x_update_configuration(d: _Draft, b: "AzureAssetBuilder") -> None:
    p = d.props
    cfg = _get(p, "updateConfiguration") or {}
    d.md["schedule"] = _path(p, "scheduleInfo", "frequency")
    for vm in _list(_get(cfg, "azureVirtualMachines")) + _list(_get(cfg, "nonAzureComputerNames")):
        d.add(rel(vm, EdgeType.MANAGES, "SCHEDULED_BY", description="update deployment"))
    for query in _list(_path(cfg, "targets", "azureQueries")):
        for scope in _list(_get(query, "scope")):
            d.add(
                rel(scope, EdgeType.MANAGES, "SCHEDULED_BY", description="update deployment scope")
            )


@relation_row("microsoft.automation/automationaccounts/webhooks")
def _automation_webhook(row: dict[str, Any], b: "AzureAssetBuilder") -> None:
    p = row.get("properties") or {}
    account = _account_of(row.get("id"))
    runbook = _path(p, "runbook", "name")
    if account and runbook:
        from cloudg.inventory.azure_graph.integration import _set_md_later

        _set_md_later(
            b,
            f"{account}/runbooks/{runbook}",
            {"webhook_trigger": True, "webhook_expiry": _get(p, "expiryTime")},
        )


@extractor("microsoft.automation/automationaccounts")
def _x_automation_account(d: _Draft, b: "AzureAssetBuilder") -> None:
    p = d.props
    d.md["local_auth_disabled"] = _get(p, "disableLocalAuth")
    _keyvault_key_ref(d, _path(p, "encryption", "keyVaultProperties", "keyvaultUri"))


# ── Arc, App Configuration ──


@extractor("microsoft.hybridcompute/machines")
def _x_arc_machine(d: _Draft, b: "AzureAssetBuilder") -> None:
    p = d.props
    d.md.update(
        {
            "arc": True,
            "os_name": _get(p, "osName"),
            "agent_version": _get(p, "agentVersion"),
            "status": _get(p, "status"),
            "machine_fqdn": _get(p, "machineFqdn"),
        }
    )
    d.add(
        rel(
            _get(p, "privateLinkScopeResourceId"),
            EdgeType.REFERENCES,
            "DEPENDS_ON",
            description="Arc private link scope",
        )
    )


@extractor(
    "microsoft.hybridcompute/machines/extensions", "microsoft.compute/virtualmachines/extensions"
)
def _x_machine_extension(d: _Draft, b: "AzureAssetBuilder") -> None:
    p = d.props
    d.md.update(
        {
            "publisher": _get(p, "publisher"),
            "extension_type": _get(p, "type"),
            "version": _get(p, "typeHandlerVersion"),
        }
    )
    ws = _path(p, "settings", "workspaceId")
    if ws:
        d.add(rel(f"{LOG_ANALYTICS_PREFIX}{str(ws).lower()}", EdgeType.LOGS_TO, "LOGS_TO"))


@extractor("microsoft.appconfiguration/configurationstores/replicas")
def _x_appconfig_replica(d: _Draft, b: "AzureAssetBuilder") -> None:
    d.alias(host_of(_get(d.props, "endpoint")))
    store = parent_resource_id(d.id)
    if store:
        b.defer(
            store,
            rel(
                d.id, EdgeType.REFERENCES, "REPLICATES_TO", description="App Configuration replica"
            ),
        )


# ── backup and disaster recovery ──


@extractor("microsoft.recoveryservices/vaults", "microsoft.dataprotection/backupvaults")
def _x_vault_protection(d: _Draft, b: "AzureAssetBuilder") -> None:
    p = d.props
    security = _get(p, "securitySettings") or {}
    redundancy = _get(p, "redundancySettings") or {}
    d.md.update(
        {
            "immutability": _path(security, "immutabilitySettings", "state"),
            "soft_delete": _path(security, "softDeleteSettings", "softDeleteState")
            or _path(security, "softDeleteSettings", "state"),
            "cross_region_restore": _get(redundancy, "crossRegionRestore"),
            "storage_redundancy": _get(redundancy, "standardTierStorageRedundancy"),
            "multi_user_authorization": _get(security, "multiUserAuthorization"),
        }
    )
    _keyvault_key_ref(d, _path(p, "encryption", "keyVaultProperties", "keyUri"), "vault CMK")


def _vault_of(child_id: str | None) -> str | None:
    rid = str(child_id or "")
    for marker in (
        "/backupfabrics/",
        "/replicationfabrics/",
        "/backuppolicies/",
        "/backupinstances/",
        "/replicationpolicies/",
    ):
        cut = rid.lower().find(marker)
        if cut > 0:
            return rid[:cut]
    return parent_resource_id(rid)


@relation_row(
    "microsoft.recoveryservices/vaults/backupfabrics/protectioncontainers/protecteditems",
    "microsoft.dataprotection/backupvaults/backupinstances",
)
def _protected_item(row: dict[str, Any], b: "AzureAssetBuilder") -> None:
    p = row.get("properties") or {}
    source = (
        _get(p, "sourceResourceId")
        or _path(p, "dataSourceInfo", "resourceID")
        or _path(p, "dataSourceInfo", "resourceId")
    )
    policy = _get(p, "policyId") or _path(p, "policyInfo", "policyId")
    vault = _vault_of(row.get("id"))
    state = (
        _get(p, "protectionState")
        or _path(p, "currentProtectionState")
        or _get(p, "protectionStatus")
    )
    if not source:
        return
    details = {
        "workload": _get(p, "workloadType") or _path(p, "dataSourceInfo", "datasourceType"),
        "state": state,
        "last_backup": _get(p, "lastBackupTime"),
    }
    b.defer(
        source,
        rel(
            vault,
            EdgeType.REFERENCES,
            "BACKUP_TO",
            description="protected by Azure Backup",
            **details,
        ),
    )
    b.defer(
        policy or vault,
        rel(source, EdgeType.MANAGES, "BACKUP_TO", description="backup protection", **details),
    )
    b.state.setdefault("backup_items", {}).setdefault(str(vault).lower(), 0)
    b.state["backup_items"][str(vault).lower()] += 1


@extractor(
    "microsoft.recoveryservices/vaults/backuppolicies",
    "microsoft.dataprotection/backupvaults/backuppolicies",
)
def _x_backup_policy(d: _Draft, b: "AzureAssetBuilder") -> None:
    p = d.props
    vault = _vault_of(d.id)
    retention = _get(p, "retentionPolicy") or {}
    d.md.update(
        {
            "management_type": _get(p, "backupManagementType") or _get(p, "objectType"),
            "schedule": _path(p, "schedulePolicy", "scheduleRunFrequency"),
            "daily_retention_days": _path(retention, "dailySchedule", "retentionDuration", "count"),
            "protected_items": _get(p, "protectedItemsCount"),
            "datasource_types": _list(_get(p, "datasourceTypes")),
        }
    )
    d.add(rel(vault, EdgeType.REFERENCES, "BACKUP_TO", description="policy target vault"))


@relation_row(
    "microsoft.recoveryservices/vaults/replicationfabrics/replicationprotectioncontainers/replicationprotecteditems"
)
def _asr_item(row: dict[str, Any], b: "AzureAssetBuilder") -> None:
    p = row.get("properties") or {}
    details = _get(p, "providerSpecificDetails") or {}
    source = _get(details, "fabricObjectId") or _get(details, "vmId") or _get(p, "fabricObjectId")
    target = (
        _get(details, "recoveryAzureVMId")
        or _get(details, "selectedRecoveryAzureNetworkId")
        or _get(details, "recoveryAzureResourceGroupId")
    )
    vault = _vault_of(row.get("id"))
    if not isinstance(source, str) or not source.startswith("/"):
        return
    b.defer(
        source,
        rel(
            target or vault,
            EdgeType.REFERENCES,
            "REPLICATES_TO",
            description="Site Recovery replication",
            health=_get(p, "replicationHealth"),
            recovery_location=_get(details, "recoveryAzureLocation") or _get(p, "recoveryFabricId"),
        ),
    )
    b.defer(
        vault,
        rel(source, EdgeType.MANAGES, "REPLICATES_TO", description="Site Recovery protected item"),
    )


@extractor("microsoft.recoveryservices/vaults/replicationpolicies")
def _x_asr_policy(d: _Draft, b: "AzureAssetBuilder") -> None:
    d.md["recovery_point_history_minutes"] = _path(
        d.props, "providerSpecificDetails", "recoveryPointHistory"
    )


# ── containers ──


@extractor("microsoft.containerregistry/registries/replications")
def _x_acr_replication(d: _Draft, b: "AzureAssetBuilder") -> None:
    registry = parent_resource_id(d.id)
    d.md["zone_redundancy"] = _get(d.props, "zoneRedundancy")
    d.md["region_endpoint_enabled"] = _get(d.props, "regionEndpointEnabled")
    if registry:
        b.defer(
            registry,
            rel(
                d.id,
                EdgeType.REFERENCES,
                "REPLICATES_TO",
                description="geo-replication",
                location=d.region,
            ),
        )


@extractor("microsoft.containerregistry/registries/webhooks")
def _x_acr_webhook(d: _Draft, b: "AzureAssetBuilder") -> None:
    p = d.props
    d.md.update(
        {
            "actions": _list(_get(p, "actions")),
            "scope": _get(p, "scope"),
            "status": _get(p, "status"),
        }
    )
    uri = _get(p, "serviceUri")
    d.add(rel(host_of(uri), EdgeType.INVOKES, "INVOKES", description="registry webhook"))
    d.props = {k: v for k, v in p.items() if _lower(k) not in ("serviceuri", "customheaders")}


@extractor("microsoft.containerregistry/registries/tasks")
def _x_acr_task(d: _Draft, b: "AzureAssetBuilder") -> None:
    from cloudg.inventory.azure_graph.integration import repository_ref

    p = d.props
    registry = parent_resource_id(d.id)
    step = _get(p, "step") or {}
    trigger = _get(p, "trigger") or {}
    repos = [_get(step, "contextPath")] + [
        _path(t, "sourceRepository", "repositoryUrl")
        for t in _list(_get(trigger, "sourceTriggers"))
    ]
    for url in dict.fromkeys(r for r in repos if isinstance(r, str) and "://" in r):
        d.add(
            rel(
                repository_ref(b, url), EdgeType.REFERENCES, "READS_FROM", description="task source"
            )
        )
    d.add(rel(registry, EdgeType.REFERENCES, "WRITES_TO", description="pushes images"))
    timers = [_get(t, "schedule") for t in _list(_get(trigger, "timerTriggers"))]
    d.md.update(
        {
            "status": _get(p, "status"),
            "timer_schedules": timers,
            "base_image_trigger": bool(_get(trigger, "baseImageTrigger")),
            "agent_pool": _get(p, "agentPoolName"),
        }
    )
    if timers and registry:
        d.md["scheduled"] = True


@extractor("microsoft.containerregistry/registries/scopemaps")
def _x_acr_scope_map(d: _Draft, b: "AzureAssetBuilder") -> None:
    d.md["actions"] = _list(_get(d.props, "actions"))[:200]


@extractor("microsoft.containerregistry/registries/tokens")
def _x_acr_token(d: _Draft, b: "AzureAssetBuilder") -> None:
    p = d.props
    registry = parent_resource_id(d.id)
    d.md["status"] = _get(p, "status")
    d.add(rel(_get(p, "scopeMapId"), EdgeType.REFERENCES, "DEPENDS_ON", description="scope map"))
    d.add(
        rel(
            registry,
            EdgeType.GRANTS_ACCESS,
            "POLICY_ALLOWS_ACTION",
            description="repository-scoped token",
        )
    )
    d.props = {k: v for k, v in p.items() if _lower(k) != "credentials"}


@extractor("microsoft.containerservice/managedclusters")
def _x_aks_access(d: _Draft, b: "AzureAssetBuilder") -> None:
    p = d.props
    issuer = _path(p, "oidcIssuerProfile", "issuerURL")
    if isinstance(issuer, str) and issuer:
        d.alias(issuer.rstrip("/"), issuer.rstrip("/") + "/")
    d.md.update(
        {
            "oidc_issuer": issuer,
            "workload_identity": _path(p, "securityProfile", "workloadIdentity", "enabled"),
            "entra_integration": bool(_get(p, "aadProfile")),
            "image_cleaner": _path(p, "securityProfile", "imageCleaner", "enabled"),
            "defender_enabled": _path(
                p, "securityProfile", "defender", "securityMonitoring", "enabled"
            ),
            "sku_tier": _get(d.row.get("sku") or {}, "tier"),
        }
    )
    for group in _list(_path(p, "aadProfile", "adminGroupObjectIDs")):
        b.note_principal(group, "Group")
        d.add(
            rel(
                principal_ref(group),
                EdgeType.GRANTS_ACCESS,
                "POLICY_ALLOWS_ACTION",
                reverse=True,
                description="AKS cluster admin group",
                role="cluster-admin",
                privileged=True,
            )
        )


@relation_row("microsoft.containerservice/managedclusters/trustedaccessrolebindings")
def _aks_trusted_access(row: dict[str, Any], b: "AzureAssetBuilder") -> None:
    p = row.get("properties") or {}
    b.defer(
        parent_resource_id(row.get("id")),
        rel(
            _get(p, "sourceResourceId"),
            EdgeType.GRANTS_ACCESS,
            "POLICY_ALLOWS_ACTION",
            reverse=True,
            description="trusted access",
            roles=_list(_get(p, "roles")),
        ),
    )


@extractor("microsoft.kubernetesconfiguration/extensions")
def _x_cluster_extension(d: _Draft, b: "AzureAssetBuilder") -> None:
    p = d.props
    d.md.update(
        {
            "extension_type": _get(p, "extensionType"),
            "version": _get(p, "version") or _get(p, "currentVersion"),
            "release_train": _get(p, "releaseTrain"),
            "state": _get(p, "provisioningState"),
            "cluster_id": _owner_of(d.id),
        }
    )


@extractor(
    "microsoft.kubernetesconfiguration/fluxconfigurations",
    "microsoft.kubernetesconfiguration/sourcecontrolconfigurations",
)
def _x_flux(d: _Draft, b: "AzureAssetBuilder") -> None:
    from cloudg.inventory.azure_graph.integration import repository_ref

    p = d.props
    cluster = _owner_of(d.id)
    git = _get(p, "gitRepository") or {}
    url = (
        _get(git, "url")
        or _get(p, "repositoryUrl")
        or _path(p, "bucket", "url")
        or _path(p, "ociRepository", "url")
    )
    d.md.update(
        {
            "source_kind": _get(p, "sourceKind"),
            "repository_url": url,
            "branch": _path(git, "repositoryRef", "branch"),
            "kustomizations": sorted((_get(p, "kustomizations") or {}).keys()),
            "compliance_state": _get(p, "complianceState"),
        }
    )
    d.add(
        rel(repository_ref(b, url), EdgeType.REFERENCES, "READS_FROM", description="GitOps source")
    )
    d.add(rel(cluster, EdgeType.MANAGES, "OWNED_BY", description="GitOps deploys to"))
    d.props = {k: v for k, v in p.items() if _lower(k) not in ("configurationprotectedsettings",)}


# ── identity depth ──


@extractor("microsoft.managedidentity/userassignedidentities")
def _x_uami_client(d: _Draft, b: "AzureAssetBuilder") -> None:
    client = _get(d.props, "clientId")
    if isinstance(client, str) and client:
        d.alias(f"azure-client-id:{client.lower()}")


@extractor("microsoft.managedidentity/userassignedidentities/federatedidentitycredentials")
def _x_federated_credential(d: _Draft, b: "AzureAssetBuilder") -> None:
    p = d.props
    identity = parent_resource_id(d.id)
    issuer = str(_get(p, "issuer") or "").rstrip("/")
    subject = _get(p, "subject")
    kind = issuer_kind(issuer)
    aks = kind == "aks"
    d.md.update(
        {
            "issuer": issuer,
            "subject": subject,
            "audiences": _list(_get(p, "audiences")),
            "issuer_kind": kind,
        }
    )
    d.add(
        rel(
            identity,
            EdgeType.IAM_TRUST,
            "ROLE_ASSUMES_ROLE" if aks else "CROSS_ACCOUNT_TRUST",
            description=f"tokens from {issuer} for {subject}",
            subject=subject,
        )
    )
    if identity and issuer:
        b.defer(
            identity,
            rel(
                issuer,
                EdgeType.IAM_TRUST,
                "ROLE_ASSUMES_ROLE",
                reverse=True,
                description="workload identity federation",
                subject=subject,
            ),
        )


@extractor("microsoft.keyvault/vaults/keys")
def _x_kv_key(d: _Draft, b: "AzureAssetBuilder") -> None:
    p = d.props
    policy = _get(p, "rotationPolicy") or {}
    actions = [_lower(_path(a, "action", "type")) for a in _list(_get(policy, "lifetimeActions"))]
    d.md.update(
        {
            "key_type": _get(p, "kty"),
            "key_size": _get(p, "keySize"),
            "enabled": _path(p, "attributes", "enabled"),
            "expires": _path(p, "attributes", "exp"),
            "auto_rotation": "rotate" in actions,
            "rotation_expiry": _path(policy, "attributes", "expiryTime"),
            "exportable": _path(p, "attributes", "exportable"),
        }
    )
    uri = _get(p, "keyUri")
    d.alias(uri, _get(p, "keyUriWithVersion"))


@extractor("microsoft.keyvault/vaults/secrets")
def _x_kv_secret(d: _Draft, b: "AzureAssetBuilder") -> None:
    p = d.props
    d.md.update(
        {
            "content_type": _get(p, "contentType"),
            "enabled": _path(p, "attributes", "enabled"),
            "expires": _path(p, "attributes", "exp"),
            "has_expiry": _path(p, "attributes", "exp") is not None,
        }
    )
    d.alias(_get(p, "secretUri"))
    # values are never inventory, even if a response carried one
    d.props = {k: v for k, v in p.items() if _lower(k) != "value"}


# ── compute ──


@extractor("microsoft.batch/batchaccounts")
def _x_batch_account(d: _Draft, b: "AzureAssetBuilder") -> None:
    p = d.props
    d.add(
        rel(
            _path(p, "autoStorage", "storageAccountId"),
            EdgeType.REFERENCES,
            "DEPENDS_ON",
            description="auto storage",
        )
    )
    d.add(
        rel(
            _path(p, "keyVaultReference", "id"),
            EdgeType.REFERENCES,
            "DEPENDS_ON",
            description="Key Vault",
        )
    )
    d.alias(host_of(_get(p, "accountEndpoint")))
    d.md["pool_allocation_mode"] = _get(p, "poolAllocationMode")


@extractor("microsoft.batch/batchaccounts/pools")
def _x_batch_pool(d: _Draft, b: "AzureAssetBuilder") -> None:
    p = d.props
    net = _get(p, "networkConfiguration") or {}
    d.add(rel(_get(net, "subnetId"), EdgeType.CONTAINS, "SUBNET_CONTAINS_INSTANCE", reverse=True))
    public = _path(net, "publicIPAddressConfiguration", "provision")
    d.md.update(
        {
            "vm_size": _get(p, "vmSize"),
            "public_ip": public,
            "current_nodes": _get(p, "currentDedicatedNodes"),
        }
    )
    d.exposed = _lower(public) not in ("", "nopublicipaddresses")


@extractor("microsoft.appplatform/spring")
def _x_spring(d: _Draft, b: "AzureAssetBuilder") -> None:
    net = _get(d.props, "networkProfile") or {}
    for key in ("serviceRuntimeSubnetId", "appSubnetId"):
        d.add(rel(_get(net, key), EdgeType.CONTAINS, "SUBNET_CONTAINS_INSTANCE", reverse=True))


@extractor("microsoft.appplatform/spring/apps")
def _x_spring_app(d: _Draft, b: "AzureAssetBuilder") -> None:
    p = d.props
    d.alias(host_of(_get(p, "url")), str(_get(p, "fqdn") or "").lower() or None)
    d.md["public"] = _get(p, "public")
    d.exposed = bool(_get(p, "public"))


@extractor(
    "microsoft.compute/availabilitysets",
    "microsoft.compute/proximityplacementgroups",
    "microsoft.compute/hostgroups",
)
def _x_placement_group(d: _Draft, b: "AzureAssetBuilder") -> None:
    p = d.props
    members = _rids(_get(p, "virtualMachines")) + _rids(_get(p, "virtualMachineScaleSets"))
    d.md.update(
        {
            "member_count": len(members),
            "fault_domains": _get(p, "platformFaultDomainCount"),
            "update_domains": _get(p, "platformUpdateDomainCount"),
        }
    )
    for member in members:
        d.add(rel(member, EdgeType.CONTAINS, description="placement member"))
    d.add(rel(_rid(_get(p, "proximityPlacementGroup")), EdgeType.CONTAINS, reverse=True))
    for host in _rids(_get(p, "hosts")):
        d.add(rel(host, EdgeType.CONTAINS, description="dedicated host"))


# ── Azure Deployment Environments ──


@extractor("microsoft.devcenter/projects")
def _x_devcenter_project(d: _Draft, b: "AzureAssetBuilder") -> None:
    d.add(
        rel(_get(d.props, "devCenterId"), EdgeType.CONTAINS, reverse=True, description="dev center")
    )
    d.md["max_dev_boxes_per_user"] = _get(d.props, "maxDevBoxesPerUser")


@extractor("microsoft.devcenter/devcenters/catalogs", "microsoft.devcenter/projects/catalogs")
def _x_devcenter_catalog(d: _Draft, b: "AzureAssetBuilder") -> None:
    from cloudg.inventory.azure_graph.integration import repository_ref

    p = d.props
    source = _get(p, "gitHub") or _get(p, "adoGit") or {}
    url = _get(source, "uri")
    d.md.update(
        {"repository_url": url, "branch": _get(source, "branch"), "path": _get(source, "path")}
    )
    d.add(
        rel(
            repository_ref(b, url),
            EdgeType.REFERENCES,
            "READS_FROM",
            description="environment catalog",
        )
    )
    d.add(
        rel(
            host_of(_get(source, "secretIdentifier")),
            EdgeType.REFERENCES,
            "READS_FROM",
            description="Git token",
        )
    )


@extractor("microsoft.devcenter/projects/environmenttypes")
def _x_environment_type(d: _Draft, b: "AzureAssetBuilder") -> None:
    p = d.props
    target = _get(p, "deploymentTargetId")
    d.md["status"] = _get(p, "status")
    d.add(rel(target, EdgeType.MANAGES, "OWNED_BY", description="deployment target"))
    role_map = _path(p, "creatorRoleAssignment", "roles") or {}
    d.md["creator_roles"] = sorted(role_map.keys()) if isinstance(role_map, dict) else []
    for oid in (_get(p, "userRoleAssignments") or {}).keys():
        b.note_principal(oid, None)
        d.add(
            rel(
                principal_ref(oid),
                EdgeType.GRANTS_ACCESS,
                "POLICY_ALLOWS_ACTION",
                reverse=True,
                description="environment type user role",
            )
        )


@extractor("microsoft.devcenter/devcenters")
def _x_devcenter(d: _Draft, b: "AzureAssetBuilder") -> None:
    d.md["dev_center_uri"] = _get(d.props, "devCenterUri")
    d.alias(host_of(_get(d.props, "devCenterUri")))


# ── subscription-level activity log export ──


@extractor("microsoft.insights/diagnosticsettings")
def _x_activity_log(d: _Draft, b: "AzureAssetBuilder") -> None:
    owner = _owner_of(d.id)
    if owner and owner.rstrip("/").count("/") == 2 and owner.lower().startswith("/subscriptions/"):
        d.md["activity_log_export"] = True
        d.add(
            rel(
                subscription_ref(owner.rsplit("/", 1)[-1]),
                EdgeType.MONITORS,
                "MONITORED_BY",
                description="activity log export",
            )
        )


__all__: list[str] = []
