"""Best-effort Resource Graph tables beyond ``resources``.

Each table is one task (:mod:`.families`); a failing query is recorded as a
FAILED coverage record and never stops the subscription. ARM-shaped rows
go through the normal builder pipeline, so through the extractors (and
relation-only row handlers, such as maintenance and data collection rule
associations) registered for their types. The aggregate tables (policy
states, Defender assessments, alerts, secure score) have handlers that
attach relations to existing assets instead of creating one asset per row.
"""

from __future__ import annotations

import logging
import time
from typing import TYPE_CHECKING, Any, Callable

from cloudg.inventory.azure_graph.helpers import _get, _lower, management_group_ref, normalize_scope
from cloudg.inventory.azure_graph.query import (
    ARG_TABLE_TASKS,
    management_group_role_assignments_query,
    policy_definitions_query,
    policy_states_query,
    role_definitions_query,
    run_query,
    secure_score_query,
    security_alerts_query,
    security_assessments_query,
    table_query,
)

if TYPE_CHECKING:
    from cloudg.inventory.azure_graph.builder import AzureAssetBuilder

logger = logging.getLogger("cloudg.inventory.azure_graph")

# Aggregate tables are capped: they can hold one row per CVE per image
_AGGREGATE_PAGES = 20


def _ancestors(container_rows: list[dict[str, Any]], subscription_id: str) -> list[str]:
    """Management group names above the subscription, nearest first."""
    for row in container_rows:
        if _lower(row.get("type")) != "microsoft.resources/subscriptions":
            continue
        chain = _get(row.get("properties") or {}, "managementGroupAncestorsChain") or []
        return [str(_get(a, "name")) for a in chain if isinstance(a, dict) and _get(a, "name")]
    return []


def _inherited_rows(rows: list[dict[str, Any]], ancestors: list[str]) -> list[dict[str, Any]]:
    """Management-group / root role assignments that apply to this subscription."""
    wanted = {management_group_ref(a).lower() for a in ancestors}
    out = []
    for row in rows:
        scope = normalize_scope(row.get("scope") or _get(row.get("properties") or {}, "scope"))
        if not scope:
            continue
        above = scope == "/" or scope.lower().startswith(
            "/providers/microsoft.management/managementgroups/"
        )
        # without the ancestor chain only root assignments are known to apply
        if above and (scope == "/" or scope.lower() in wanted):
            out.append(row)
    return out


def _referenced_definition_names(builder: "AzureAssetBuilder") -> list[str]:
    names: list[str] = []
    for d in builder.drafts_of("microsoft.authorization/policyassignments"):
        ref = _get(d.props, "policyDefinitionId")
        if isinstance(ref, str) and ref:
            names.append(ref.rstrip("/").rsplit("/", 1)[-1])
    return list(dict.fromkeys(names))


class _TableRun:
    """Runs one subscription's best-effort tables and records each as a task."""

    def __init__(
        self,
        client: Any,
        builder: "AzureAssetBuilder",
        subscription_id: str,
        on: Callable[[str], bool],
        recorder: Any,
    ) -> None:
        self.client = client
        self.b = builder
        self.sub = subscription_id
        self.on = on
        self.rec = recorder

    def query(self, query: str, *, tenant: bool = False, max_pages: int | None = None) -> list:
        kwargs: dict[str, Any] = {} if tenant else {"subscriptions": [self.sub]}
        if max_pages:
            kwargs["max_pages"] = max_pages
        return run_query(self.client, query, **kwargs)

    def task(self, name: str, fn: Callable[[], int]) -> None:
        if not self.on(name):
            return
        started = time.time()
        try:
            count = fn()
        except Exception as exc:
            logger.warning("Azure Resource Graph task %s failed for %s: %s", name, self.sub, exc)
            self.rec.record(name, "FAILED", error=str(exc)[:500], started=started)
            return
        self.rec.record(name, "SUCCESS", count, started=started)

    # ── tasks ──

    def arm_table(self, table: str, types: tuple[str, ...]) -> int:
        rows = self.query(table_query(table, self.sub, types))
        if types:
            wanted = set(types)
            rows = [r for r in rows if _lower(r.get("type")) in wanted]
        self.b.add_rows(rows, discovered_via="resource-graph")
        return len(rows)

    def policy_definitions(self) -> int:
        rows = self.query(
            policy_definitions_query(_referenced_definition_names(self.b)), tenant=True
        )
        before = len(self.b.drafts)
        self.b.add_rows(rows, discovered_via="resource-graph")
        return len(self.b.drafts) - before

    def policy_states(self) -> int:
        from cloudg.inventory.azure_graph.governance import add_policy_states

        rows = self.query(policy_states_query(self.sub), max_pages=_AGGREGATE_PAGES)
        return add_policy_states(self.b, rows)

    def assessments(self) -> int:
        from cloudg.inventory.azure_graph.security import add_assessments

        rows = self.query(security_assessments_query(self.sub), max_pages=_AGGREGATE_PAGES)
        return add_assessments(self.b, rows)

    def secure_score(self) -> int:
        from cloudg.inventory.azure_graph.security import add_secure_score

        return add_secure_score(self.b, self.query(secure_score_query(self.sub)))

    def alerts(self) -> int:
        from cloudg.inventory.azure_graph.security import add_security_alerts

        rows = self.query(security_alerts_query(self.sub), max_pages=_AGGREGATE_PAGES)
        return add_security_alerts(self.b, rows)

    def inherited_roles(self, container_rows: list[dict[str, Any]]) -> int:
        rows = self.query(management_group_role_assignments_query(), tenant=True)
        rows = _inherited_rows(
            [r for r in rows if _get(r, "principalId")], _ancestors(container_rows, self.sub)
        )
        self.b.add_role_assignments(rows, inherited_from="management group")
        return len(rows)

    def role_definitions(self) -> int:
        rows = self.query(role_definitions_query(), tenant=True)
        self.b.add_role_definitions(rows)
        return len(rows)


def collect_tables(
    client: Any,
    builder: "AzureAssetBuilder",
    subscription_id: str,
    *,
    on: Callable[[str], bool],
    recorder: Any,
    container_rows: list[dict[str, Any]],
    role_assignments: bool = True,
) -> None:
    """Run every best-effort Resource Graph task selected by ``on``."""
    run = _TableRun(client, builder, subscription_id, on, recorder)
    if role_assignments:
        run.task("management_group_role_assignments", lambda: run.inherited_roles(container_rows))
        run.task("role_definitions", run.role_definitions)
    for task, table, types in ARG_TABLE_TASKS:
        if task == "policy":
            run.task(
                "policy",
                lambda t=table, ty=types: run.arm_table(t, ty) + run.policy_definitions(),
            )
            run.task("policy_states", run.policy_states)
            continue
        run.task(task, lambda t=table, ty=types: run.arm_table(t, ty))
    run.task("security_assessments", run.assessments)
    run.task("secure_score", run.secure_score)
    run.task("security_alerts", run.alerts)


__all__ = ["collect_tables"]
