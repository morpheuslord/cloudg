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
    guid = r"@'([0-9a-fA-F-]{36})$'"
    return (
        "authorizationresources "
        "| where type =~ 'microsoft.authorization/roleassignments' "
        f"| where subscriptionId =~ '{_kql(subscription_id)}' "
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
