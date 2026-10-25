"""Fakes for the Azure inventory tests: Resource Graph, ARM REST, Microsoft Graph."""

from __future__ import annotations

import asyncio
import re
from types import SimpleNamespace
from typing import Any

from cloudg.inventory.azure_deep import AzureDeepInventoryCollector
from cloudg.inventory.azure_graph.rest import AzureRestError
from cloudg.inventory.linker import RelationshipLinker
from tests.test_azure_inventory import SUB, _Graph

_TYPE_RE = re.compile(r"type\s*(?:=~|in~)\s*\(?([^|]*)", re.I)
_SUB_RE = re.compile(r"subscriptionId =~ '([^']+)'", re.I)


class TypedFakeGraph:
    """Resource Graph stand-in: table from the first token, rows filtered by the
    ``type =~`` / ``type in~ (...)`` clauses of the query (like real ARG)."""

    def __init__(self, tables: dict[str, list[dict[str, Any]]], fail: set[str] | None = None):
        self.tables = tables
        self.fail = fail or set()
        self.requests: list[Any] = []

    def resources(self, request: Any) -> Any:
        self.requests.append(request)
        query = request.query.strip()
        table = query.split("|", 1)[0].strip()
        if table in self.fail:
            raise RuntimeError(f"{table} is not available")
        rows = self.tables.get(table, [])
        wanted: set[str] = set()
        for clause in _TYPE_RE.findall(query.split("join", 1)[0]):
            wanted.update(t.lower() for t in re.findall(r"'([^']+)'", clause))
        if wanted:
            rows = [r for r in rows if str(r.get("type", "")).lower() in wanted]
        sub = _SUB_RE.search(query)
        if sub:  # rows that carry a subscriptionId must match it
            rows = [
                r
                for r in rows
                if "subscriptionId" not in r or str(r["subscriptionId"]).lower() == sub.group(1)
            ]
        return SimpleNamespace(data=list(rows), skip_token=None)


class FakeArm:
    """ARM REST stand-in serving ``path -> rows`` (lists) or objects (single GETs)."""

    def __init__(self, routes: dict[str, Any], forbidden: set[str] | None = None):
        self.routes = {k.lower().rstrip("/"): v for k, v in routes.items()}
        self.forbidden = {f.lower() for f in forbidden or set()}
        self.calls: list[tuple[str, str, dict[str, Any]]] = []

    def _lookup(self, path: str) -> Any:
        key = path.lower().split("?", 1)[0].rstrip("/")
        if any(key.endswith(f) for f in self.forbidden):
            raise AzureRestError(403, path, "AuthorizationFailed")
        if key not in self.routes:
            raise AzureRestError(404, path, "ResourceNotFound")
        return self.routes[key]

    def list(self, path: str, api_version: str | None = None, **params: Any) -> list[dict]:
        params.pop("max_items", None)
        self.calls.append(("list", path, params))
        value = self._lookup(path)
        return list(value) if isinstance(value, list) else [value]

    def get(self, path: str, api_version: str | None = None, **params: Any) -> dict:
        self.calls.append(("get", path, params))
        value = self._lookup(path)
        return value if isinstance(value, dict) else {}

    def post(self, path: str, api_version: str | None = None, body: Any = None) -> dict:
        self.calls.append(("post", path, {}))
        return self._lookup(path)


def arm_row(rid: str, rtype: str, properties: dict | None = None, **extra: Any) -> dict:
    """An ARM REST child object (no subscriptionId / resourceGroup columns)."""
    row = {"id": rid, "name": rid.rsplit("/", 1)[-1], "type": rtype, "properties": properties or {}}
    row.update(extra)
    return row


def collect_linked(
    tables: dict[str, list[dict[str, Any]]],
    arm_routes: dict[str, Any] | None = None,
    *,
    credential: Any = None,
    dataplane: Any = None,
    **options: Any,
) -> SimpleNamespace:
    """Run the deep collector against fakes and link the result."""
    fake = TypedFakeGraph(tables)
    arm = FakeArm(arm_routes or {})
    collector = AzureDeepInventoryCollector(
        credential if credential is not None else object(),
        SUB,
        graph_client_factory=lambda cred: fake,
        arm_client_factory=lambda cred: arm,
        dataplane_client_factory=dataplane or (lambda cred, base, scope: FakeArm({})),
        **options,
    )
    assets = asyncio.run(collector.collect())
    linker = RelationshipLinker(assets)
    edges = linker.link()
    return SimpleNamespace(
        collector=collector,
        fake=fake,
        arm=arm,
        assets=assets,
        graph=_Graph(assets + linker.external_assets, edges),
        linker=linker,
        coverage={s.service: s for s in collector.coverage.services},
    )


__all__ = ["FakeArm", "TypedFakeGraph", "arm_row", "collect_linked"]
