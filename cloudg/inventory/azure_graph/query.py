"""Azure Resource Graph querying: paginated KQL with 429 back-off.

Resource Graph allows ~15 queries per 5-second window per user. Every page
takes a token from the shared ``azure/*/*/resourcegraph`` bucket (3 rps,
burst 15: cloudg.resilience), throttled pages wait for the server's
``Retry-After`` / ``x-ms-user-quota-resets-after`` (or exponential back-off
when there is none), and clients built by
:func:`default_graph_client_factory` also read the quota headers of every
response to pause before the quota runs out.
"""

from __future__ import annotations

import re
import time
from dataclasses import dataclass
from types import SimpleNamespace
from typing import Any, Callable

from cloudg.inventory.azure_graph.helpers import _kql, to_rest
from cloudg.resilience.errors import retry_after
from cloudg.resilience.governor import get_governor
from cloudg.resilience.limiter import Scope


def default_graph_client_factory(credential: Any) -> Any:
    """Build a real ``ResourceGraphClient`` (raises ImportError when absent)."""
    from azure.mgmt.resourcegraph import ResourceGraphClient  # type: ignore[import-not-found]

    from cloudg.resilience.azure import build_azure_client

    return build_azure_client(ResourceGraphClient, credential)


def _make_request(
    query: str,
    subscriptions: list[str] | None,
    management_groups: list[str] | None,
    top: int,
    skip_token: str | None,
) -> Any:
    try:
        from azure.mgmt.resourcegraph.models import (  # type: ignore[import-not-found]
            QueryRequest,
            QueryRequestOptions,
        )

        options = QueryRequestOptions(top=top, skip_token=skip_token, result_format="objectArray")
        kwargs: dict[str, Any] = {"query": query, "options": options}
        if subscriptions:
            kwargs["subscriptions"] = subscriptions
        if management_groups:
            kwargs["management_groups"] = management_groups
        return QueryRequest(**kwargs)
    except ImportError:
        return SimpleNamespace(
            query=query,
            subscriptions=subscriptions,
            management_groups=management_groups,
            options=SimpleNamespace(top=top, skip_token=skip_token, result_format="objectArray"),
        )


def _rows_of(data: Any) -> list[dict[str, Any]]:
    if data is None:
        return []
    if isinstance(data, list):
        return [to_rest(r) if not isinstance(r, dict) else r for r in data]
    if isinstance(data, dict) and "rows" in data and "columns" in data:  # table format
        names = [c.get("name") for c in data.get("columns") or []]
        return [dict(zip(names, row)) for row in data.get("rows") or []]
    return []


def _status_code(exc: BaseException) -> int | None:
    code = getattr(exc, "status_code", None)
    if code is None:
        code = getattr(getattr(exc, "response", None), "status_code", None)
    return code if isinstance(code, int) else None


@dataclass(frozen=True)
class QueryLimits:
    """Paging / retry bounds of :func:`run_query`."""

    page_size: int = 1000
    max_pages: int = 5000
    max_retries: int = 5


_GRAPH_SCOPE = Scope("azure", None, None, "resourcegraph")


def _fetch_page(client: Any, request: Any, max_retries: int, sleep: Callable[[float], None]) -> Any:
    """One ``resources`` call, retrying throttled (429) responses.

    Waits at least the server's Retry-After / quota-reset hint, otherwise
    exponential back-off (2s, 4s, ... capped at 30s). Clients built by
    :func:`default_graph_client_factory` already retry 429 in their
    azure-core pipeline (and report every attempt), so a 429 that reaches
    this function from them is final and is not retried again.
    """
    gov = get_governor()
    # Clients from default_graph_client_factory pace every HTTP attempt in
    # their pipeline; others (custom factories) are paced here per page.
    paced_by_client = bool(getattr(client, "_cloudg_throttle_policy", False))
    attempt = 0
    while True:
        if not paced_by_client and gov.provider_enabled("azure"):
            gov.check(_GRAPH_SCOPE)
            gov.limiter.acquire_sync(_GRAPH_SCOPE, sleep=sleep)
        try:
            response = client.resources(request)
        except Exception as exc:
            if not paced_by_client and _status_code(exc) == 429:
                hint = retry_after(exc)
                gov.on_throttle(_GRAPH_SCOPE, hint, str(exc)[:200])
                if attempt < max_retries:
                    attempt += 1
                    gov.record_retry(_GRAPH_SCOPE)
                    # The limiter, paused for the hint, waits it out when enabled
                    delay = min(2.0**attempt, 30.0)
                    if not gov.provider_enabled("azure"):
                        delay = max(delay, min(hint or 0.0, 300.0))
                    sleep(delay)
                    continue
            gov.on_final_error(_GRAPH_SCOPE, exc, "Resource Graph query")
            raise
        gov.on_success(_GRAPH_SCOPE)
        return response


def run_query(
    client: Any,
    query: str,
    *,
    subscriptions: list[str] | None = None,
    management_groups: list[str] | None = None,
    sleep: Callable[[float], None] = time.sleep,
    **limits: int,
) -> list[dict[str, Any]]:
    """Run an ARG query across every page (``skip_token``).

    Retries throttled (HTTP 429) pages with exponential back-off. Blocking:
    call it from a worker thread inside async code.

    Args:
        limits: ``page_size`` (1000), ``max_pages`` (5000) and
            ``max_retries`` (5) overrides; see :class:`QueryLimits`.
    """
    bounds = QueryLimits(**limits)
    rows: list[dict[str, Any]] = []
    skip: str | None = None
    for _ in range(bounds.max_pages):
        request = _make_request(query, subscriptions, management_groups, bounds.page_size, skip)
        response = _fetch_page(client, request, bounds.max_retries, sleep)
        rows.extend(_rows_of(getattr(response, "data", None)))
        skip = getattr(response, "skip_token", None)
        if not skip:
            break
    return rows


def resources_query(subscription_id: str) -> str:
    return (
        f"resources | where subscriptionId =~ '{_kql(subscription_id)}' "
        "| project id, name, type, kind, location, resourceGroup, subscriptionId, tags, sku, "
        "identity, managedBy, zones, plan, properties | order by id asc"
    )


def containers_query(subscription_id: str) -> str:
    return (
        f"resourcecontainers | where subscriptionId =~ '{_kql(subscription_id)}' "
        "| project id, name, type, location, resourceGroup, subscriptionId, tags, managedBy, properties "
        "| order by id asc"
    )


def role_assignments_query(subscription_id: str) -> str:
    return _role_assignments_query(f"| where subscriptionId =~ '{_kql(subscription_id)}' ")


def management_group_role_assignments_query() -> str:
    """Role assignments made at management group or tenant root scope (run tenant-wide)."""
    return _role_assignments_query(
        "| where isempty(subscriptionId) "
        "| where tostring(properties.scope) startswith '/providers/Microsoft.Management/' "
        "or tostring(properties.scope) == '/' "
    )


def _role_assignments_query(where: str) -> str:
    guid = r"@'([0-9a-fA-F-]{36})$'"
    return (
        "authorizationresources "
        "| where type =~ 'microsoft.authorization/roleassignments' "
        f"{where}"
        "| extend roleDefinitionId = tostring(properties.roleDefinitionId), "
        "principalId = tostring(properties.principalId), "
        "principalType = tostring(properties.principalType), scope = tostring(properties.scope) "
        f"| extend roleGuid = tolower(extract({guid}, 1, roleDefinitionId)) "
        "| join kind=leftouter (authorizationresources "
        "| where type =~ 'microsoft.authorization/roledefinitions' "
        f"| extend roleGuid = tolower(extract({guid}, 1, id)), roleName = tostring(properties.roleName) "
        "| summarize roleName = any(roleName) by roleGuid) on roleGuid "
        "| project id, name, roleDefinitionId, roleGuid, roleName, principalId, principalType, scope, "
        "properties | order by id asc"
    )


def defender_query(subscription_id: str) -> str:
    return (
        "securityresources | where type =~ 'microsoft.security/pricings' "
        f"| where subscriptionId =~ '{_kql(subscription_id)}' "
        "| project id, name, type, subscriptionId, properties | order by id asc"
    )


# ── Azure parity: extra Resource Graph tables ──

_ROW_COLUMNS = (
    "id, name, type, kind, location, resourceGroup, subscriptionId, tags, identity, properties"
)


def _kql_type(value: str) -> str:
    """An ARM type literal for KQL: letters, digits, ``.``, ``_``, ``-`` and ``/`` only."""
    return re.sub(r"[^A-Za-z0-9._/\-]", "", value or "")


def _types_clause(types: tuple[str, ...]) -> str:
    if not types:
        return ""
    quoted = ", ".join(f"'{_kql_type(t)}'" for t in types)
    return f"| where type in~ ({quoted}) "


def table_query(table: str, subscription_id: str, types: tuple[str, ...] = ()) -> str:
    """ARM-shaped rows of one Resource Graph table for one subscription."""
    return (
        f"{_kql(table)} | where subscriptionId =~ '{_kql(subscription_id)}' "
        f"{_types_clause(types)}| project {_ROW_COLUMNS} | order by id asc"
    )


def role_definitions_query() -> str:
    """Every role definition visible to the caller (built-in and custom)."""
    guid = r"@'([0-9a-fA-F-]{36})$'"
    return (
        "authorizationresources | where type =~ 'microsoft.authorization/roledefinitions' "
        f"| extend roleGuid = tolower(extract({guid}, 1, id)) "
        "| project id, name, type, roleGuid, properties | order by id asc"
    )


POLICY_TYPES = (
    "microsoft.authorization/policyassignments",
    "microsoft.authorization/policyexemptions",
)
POLICY_DEFINITION_TYPES = (
    "microsoft.authorization/policydefinitions",
    "microsoft.authorization/policysetdefinitions",
)


def policy_definitions_query(names: list[str]) -> str:
    """Custom policy definitions / initiatives, plus the built-in ones named in ``names``."""
    named = ", ".join(f"'{_kql(n)}'" for n in names[:800] if _kql(n))
    builtin = f" or name in~ ({named})" if named else ""
    return (
        f"policyresources {_types_clause(POLICY_DEFINITION_TYPES)}"
        f"| where tostring(properties.policyType) !~ 'BuiltIn'{builtin} "
        "| project id, name, type, subscriptionId, properties | order by id asc"
    )


def policy_states_query(subscription_id: str) -> str:
    """Non-compliant policy states of one subscription (latest evaluation)."""
    return (
        "policyresources | where type =~ 'microsoft.policyinsights/policystates' "
        f"| where subscriptionId =~ '{_kql(subscription_id)}' "
        "| where tostring(properties.complianceState) =~ 'NonCompliant' "
        "| project id, type, subscriptionId, resourceId = tostring(properties.resourceId), "
        "policyAssignmentId = tostring(properties.policyAssignmentId), "
        "policyDefinitionId = tostring(properties.policyDefinitionId), "
        "policyDefinitionAction = tostring(properties.policyDefinitionAction), "
        "complianceState = tostring(properties.complianceState) | order by id asc"
    )


def security_assessments_query(subscription_id: str) -> str:
    """Defender for Cloud assessments and sub-assessments, one lean row each."""
    return (
        "securityresources "
        "| where type in~ ('microsoft.security/assessments', "
        "'microsoft.security/assessments/subassessments') "
        f"| where subscriptionId =~ '{_kql(subscription_id)}' "
        "| extend resourceId = tostring(coalesce(properties.resourceDetails.Id, "
        "properties.resourceDetails.id, properties.resourceDetails.ResourceId)), "
        "code = tostring(properties.status.code), "
        "severity = tostring(coalesce(properties.metadata.severity, properties.status.severity)), "
        "title = tostring(properties.displayName) "
        "| project id, type, subscriptionId, resourceId, code, severity, title, "
        "additionalData = properties.additionalData | order by id asc"
    )


def secure_score_query(subscription_id: str) -> str:
    return (
        "securityresources "
        "| where type in~ ('microsoft.security/securescores', "
        "'microsoft.security/securescores/securescorecontrols') "
        f"| where subscriptionId =~ '{_kql(subscription_id)}' "
        "| project id, name, type, subscriptionId, properties | order by id asc"
    )


def security_alerts_query(subscription_id: str) -> str:
    """Active (not dismissed or resolved) Defender for Cloud alerts."""
    return (
        "securityresources | where type =~ 'microsoft.security/locations/alerts' "
        f"| where subscriptionId =~ '{_kql(subscription_id)}' "
        "| where tostring(properties.Status) !in~ ('Dismissed', 'Resolved') "
        "| project id, name, type, subscriptionId, properties | order by id asc"
    )


BACKUP_TYPES = (
    "microsoft.recoveryservices/vaults/backupfabrics/protectioncontainers/protecteditems",
    "microsoft.recoveryservices/vaults/backuppolicies",
    "microsoft.recoveryservices/vaults/replicationfabrics/replicationprotectioncontainers/"
    "replicationprotecteditems",
    "microsoft.recoveryservices/vaults/replicationpolicies",
    "microsoft.dataprotection/backupvaults/backupinstances",
    "microsoft.dataprotection/backupvaults/backuppolicies",
)

# (task, table, types) of the best-effort ARM-shaped tables
ARG_TABLE_TASKS: tuple[tuple[str, str, tuple[str, ...]], ...] = (
    ("policy", "policyresources", POLICY_TYPES),
    ("backup_items", "recoveryservicesresources", BACKUP_TYPES),
    ("kubernetes_configuration", "kubernetesconfigurationresources", ()),
    ("network_resources", "networkresources", ()),
    (
        "guest_configuration",
        "guestconfigurationresources",
        ("microsoft.guestconfiguration/guestconfigurationassignments",),
    ),
    ("maintenance", "maintenanceresources", ("microsoft.maintenance/configurationassignments",)),
    ("insights", "insightsresources", ("microsoft.insights/datacollectionruleassociations",)),
)
