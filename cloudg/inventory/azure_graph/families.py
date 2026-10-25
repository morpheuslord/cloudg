"""Azure collection tasks, their service families, and ``--services`` filtering.

The Azure inventory is split into named *tasks* the same way the AWS deep
collector is: one per Resource Graph table, per ARM REST child-resource
kind, per subscription-level REST listing, plus Entra ID and in-cluster
AKS mapping. Every task belongs to a service family (the AWS family names
where one fits: ``network``, ``compute``, ``containers``, ``identity``,
...), and ``inventory.services`` / ``inventory.exclude_services`` select
tasks by task or family name exactly like
:func:`cloudg.inventory.aws_deep_tasks.select_tasks`.

The breadth query (``resources``) always runs, but when a filter is set its
rows are kept only for the selected families (resource groups and the
subscription are always kept), so ``--services network`` maps the network
and nothing else.
"""

from __future__ import annotations

import time
from typing import Any, Iterable

# Task name -> service family. Order is the order tasks run in.
AZURE_TASK_FAMILIES: dict[str, str] = {
    # Resource Graph tables
    "resources": "sweep",
    "resource_containers": "governance",
    "role_assignments": "identity",
    "management_group_role_assignments": "identity",
    "role_definitions": "identity",
    "defender_pricings": "security",
    "policy": "governance",
    "policy_states": "governance",
    "security_assessments": "security",
    "security_alerts": "security",
    "secure_score": "security",
    "backup_items": "backup",
    "kubernetes_configuration": "containers",
    "network_resources": "network",
    "guest_configuration": "operations",
    "maintenance": "operations",
    "insights": "logging",
    # Subscription-level ARM REST listings
    "deny_assignments": "identity",
    "pim_eligibility": "identity",
    "lighthouse": "identity",
    "locks": "governance",
    "deployments": "iac",
    "deployment_stacks": "iac",
    "activity_log": "logging",
    # ARM REST child resources
    "managed_identity_credentials": "identity",
    "key_vault_items": "identity",
    "apim": "serverless",
    "functions": "serverless",
    "web_apps": "serverless",
    "static_sites": "serverless",
    "service_bus": "integration",
    "event_hubs": "integration",
    "stream_analytics": "analytics",
    "data_factory": "analytics",
    "synapse": "analytics",
    "kusto": "analytics",
    "sql": "data",
    "cosmos": "data",
    "storage": "storage",
    "dns_records": "dns",
    "dns_resolver": "dns",
    "virtual_wan": "hybrid",
    "network_manager": "network",
    "front_door": "network",
    "acr": "containers",
    "aks": "containers",
    "cognitive_services": "ml",
    "machine_learning": "ml",
    "search": "ml",
    "automation": "operations",
    "app_configuration": "operations",
    "monitor_private_link": "logging",
    "batch": "compute",
    "spring_apps": "compute",
    "data_protection": "backup",
    "dev_center": "cicd",
    "diagnostic_settings": "logging",
    "sentinel": "security",
    # Data planes
    "search_data_plane": "ml",
    "synapse_data_plane": "analytics",
    # In-cluster
    "aks_kubernetes": "kubernetes",
    # Entra ID (Microsoft Graph), collected once per tenant
    "entra": "identity",
}

# Tasks that always run when their source is reachable: they carry the
# subscription, its resource groups and the relations every family uses.
CORE_TASKS = frozenset({"resources", "resource_containers"})

# ARM namespace (or full type) -> family of the rows of the breadth query.
_TYPE_FAMILIES: dict[str, str] = {
    "microsoft.compute/disks": "storage",
    "microsoft.compute/snapshots": "storage",
    "microsoft.compute/diskencryptionsets": "identity",
    "microsoft.compute/diskaccesses": "storage",
    "microsoft.network/dnszones": "dns",
    "microsoft.network/privatednszones": "dns",
    "microsoft.network/dnsresolvers": "dns",
    "microsoft.network/dnsforwardingrulesets": "dns",
    "microsoft.network/trafficmanagerprofiles": "dns",
    "microsoft.network/virtualwans": "hybrid",
    "microsoft.network/virtualhubs": "hybrid",
    "microsoft.network/vpngateways": "hybrid",
    "microsoft.network/vpnsites": "hybrid",
    "microsoft.network/p2svpngateways": "hybrid",
    "microsoft.network/expressroutecircuits": "hybrid",
    "microsoft.network/expressroutegateways": "hybrid",
    "microsoft.network/expressrouteports": "hybrid",
    "microsoft.network/localnetworkgateways": "hybrid",
    "microsoft.network/connections": "hybrid",
    "microsoft.network/virtualnetworkgateways": "hybrid",
    "microsoft.network/azurefirewalls": "security",
    "microsoft.network/firewallpolicies": "security",
    "microsoft.network/ddosprotectionplans": "security",
    "microsoft.network/frontdoorwebapplicationfirewallpolicies": "security",
    "microsoft.network/applicationgatewaywebapplicationfirewallpolicies": "security",
    "microsoft.cdn/cdnwebapplicationfirewallpolicies": "security",
    "microsoft.network/networkwatchers": "logging",
    "microsoft.network/networkwatchers/flowlogs": "logging",
    "microsoft.web/connections": "integration",
    "microsoft.web/certificates": "identity",
    "microsoft.authorization/policyassignments": "governance",
    "microsoft.authorization/policyexemptions": "governance",
    "microsoft.authorization/policydefinitions": "governance",
    "microsoft.authorization/policysetdefinitions": "governance",
    "microsoft.authorization/locks": "governance",
    "microsoft.authorization/roleassignments": "identity",
    "microsoft.authorization/roledefinitions": "identity",
    "microsoft.authorization/denyassignments": "identity",
    "microsoft.insights/components": "logging",
    "microsoft.operationsmanagement/solutions": "security",
}

_NAMESPACE_FAMILIES: dict[str, str] = {
    "microsoft.compute": "compute",
    "microsoft.hybridcompute": "hybrid",
    "microsoft.batch": "compute",
    "microsoft.appplatform": "compute",
    "microsoft.avs": "compute",
    "microsoft.network": "network",
    "microsoft.cdn": "network",
    "microsoft.storage": "storage",
    "microsoft.storagesync": "storage",
    "microsoft.netapp": "storage",
    "microsoft.elasticsan": "storage",
    "microsoft.sql": "data",
    "microsoft.dbforpostgresql": "data",
    "microsoft.dbformysql": "data",
    "microsoft.dbformariadb": "data",
    "microsoft.documentdb": "data",
    "microsoft.cache": "data",
    "microsoft.kusto": "analytics",
    "microsoft.synapse": "analytics",
    "microsoft.databricks": "analytics",
    "microsoft.hdinsight": "analytics",
    "microsoft.datafactory": "analytics",
    "microsoft.streamanalytics": "analytics",
    "microsoft.purview": "analytics",
    "microsoft.machinelearningservices": "ml",
    "microsoft.cognitiveservices": "ml",
    "microsoft.search": "ml",
    "microsoft.botservice": "ml",
    "microsoft.keyvault": "identity",
    "microsoft.managedidentity": "identity",
    "microsoft.azureactivedirectory": "identity",
    "microsoft.managedservices": "identity",
    "microsoft.authorization": "governance",
    "microsoft.resources": "iac",
    "microsoft.solutions": "iac",
    "microsoft.blueprint": "governance",
    "microsoft.management": "governance",
    "microsoft.containerservice": "containers",
    "microsoft.containerregistry": "containers",
    "microsoft.app": "containers",
    "microsoft.containerinstance": "containers",
    "microsoft.kubernetes": "containers",
    "microsoft.kubernetesconfiguration": "containers",
    "microsoft.redhatopenshift": "containers",
    "microsoft.web": "serverless",
    "microsoft.apimanagement": "serverless",
    "microsoft.servicebus": "integration",
    "microsoft.eventhub": "integration",
    "microsoft.eventgrid": "integration",
    "microsoft.logic": "integration",
    "microsoft.relay": "integration",
    "microsoft.notificationhubs": "integration",
    "microsoft.signalrservice": "integration",
    "microsoft.devices": "integration",
    "microsoft.insights": "logging",
    "microsoft.operationalinsights": "logging",
    "microsoft.alertsmanagement": "logging",
    "microsoft.monitor": "logging",
    "microsoft.dashboard": "logging",
    "microsoft.automation": "operations",
    "microsoft.maintenance": "operations",
    "microsoft.appconfiguration": "operations",
    "microsoft.guestconfiguration": "operations",
    "microsoft.security": "security",
    "microsoft.securityinsights": "security",
    "microsoft.operationsmanagement": "security",
    "microsoft.recoveryservices": "backup",
    "microsoft.dataprotection": "backup",
    "microsoft.devcenter": "cicd",
    "microsoft.devtestlab": "cicd",
}

_ALWAYS_KEPT = (
    "microsoft.resources/subscriptions",
    "microsoft.resources/subscriptions/resourcegroups",
    "microsoft.resources/resourcegroups",
)


def family_of_task(task: str) -> str:
    return AZURE_TASK_FAMILIES.get(task, "other")


def family_of_type(arm_type: str | None) -> str:
    """Service family of an ARM resource type (``other`` when unknown)."""
    rtype = (arm_type or "").lower()
    if rtype in _TYPE_FAMILIES:
        return _TYPE_FAMILIES[rtype]
    for full, fam in _TYPE_FAMILIES.items():
        if rtype.startswith(full + "/"):
            return fam
    return _NAMESPACE_FAMILIES.get(rtype.split("/", 1)[0], "other")


def _wanted(name: str, family: str, inc: set[str], exc: set[str]) -> bool:
    if name in exc or family in exc:
        return False
    if "all" in inc or name in inc or family in inc:
        return True
    # in-cluster mapping rides on the containers family, like EKS
    return name == "aks_kubernetes" and "containers" in inc


def select_azure_tasks(
    names: Iterable[str] | None = None,
    include: list[str] | None = None,
    exclude: list[str] | None = None,
) -> list[str]:
    """Filter Azure task names by task or family name.

    ``include`` defaults to everything (``["all"]``); ``exclude`` always
    wins, except for :data:`CORE_TASKS`, which always run. "kubernetes" is
    a pseudo-family that only toggles in-cluster AKS mapping.
    """
    inc = {i.lower() for i in (include or ["all"])}
    exc = {e.lower() for e in (exclude or [])}
    out: list[str] = []
    for name in names if names is not None else AZURE_TASK_FAMILIES:
        if name in CORE_TASKS or _wanted(name, family_of_task(name), inc, exc):
            out.append(name)
    return out


def row_filter(include: list[str] | None, exclude: list[str] | None):
    """Predicate keeping the breadth rows of selected families, or None for all."""
    inc = {i.lower() for i in (include or ["all"])}
    exc = {e.lower() for e in (exclude or [])}
    if "all" in inc and not exc:
        return None

    def keep(row: dict) -> bool:
        rtype = str((row or {}).get("type") or "").lower()
        if rtype in _ALWAYS_KEPT:
            return True
        family = family_of_type(rtype)
        return _wanted(rtype, family, inc, exc)

    return keep


class TaskRecorder:
    """Per-task coverage records (SUCCESS / FAILED / PARTIAL / SKIPPED).

    Args:
        coverage: CollectionCoverage receiving the records (None: count only).
    """

    def __init__(self, coverage: Any = None) -> None:
        self.coverage = coverage
        self.records: dict[str, tuple[str, int, str | None]] = {}

    def record(
        self,
        task: str,
        status: str,
        count: int = 0,
        error: str | None = None,
        started: float | None = None,
    ) -> None:
        from cloudg.coverage import ServiceStatus

        self.records[task] = (status, count, error)
        if self.coverage is not None:
            self.coverage.record(
                task,
                ServiceStatus(status),
                asset_count=count,
                error=error,
                duration_ms=int((time.time() - started) * 1000) if started else None,
            )

    def skip(self, task: str, reason: str) -> None:
        self.record(task, "SKIPPED", error=reason)

    def outcome(
        self, task: str, count: int, failures: list[str], calls: int, started: float | None
    ) -> None:
        """SUCCESS, PARTIAL (some calls failed) or FAILED (every call failed)."""
        if not failures:
            self.record(task, "SUCCESS", count, None, started)
            return
        status = "FAILED" if calls and len(failures) >= calls and not count else "PARTIAL"
        shown = "; ".join(dict.fromkeys(failures))[:500]
        self.record(task, status, count, shown, started)


__all__ = [
    "AZURE_TASK_FAMILIES",
    "CORE_TASKS",
    "TaskRecorder",
    "family_of_task",
    "family_of_type",
    "row_filter",
    "select_azure_tasks",
]
