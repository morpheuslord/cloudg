"""Read-only data-plane metadata: AI Search and Synapse artifacts.

AI Search data sources, indexers, indexes and skillsets, and Synapse
pipelines, linked services, datasets and triggers, live behind each
service's own endpoint, not ARM. They are read with an Entra token for the
service's data-plane audience (``https://search.azure.com/.default``,
``https://dev.azuresynapse.net/.default``), which needs a data-plane
reader role (Search Index Data Reader / Search Service Contributor,
Synapse Artifact User). Connection strings in the responses are scanned
for endpoints and then dropped; nothing secret is kept.
"""

from __future__ import annotations

import time
from typing import TYPE_CHECKING, Any, Callable

from cloudg.exceptions import CredentialError
from cloudg.inventory.azure_graph.helpers import _get, host_of
from cloudg.inventory.azure_graph.rest import AzureRestError

if TYPE_CHECKING:
    from cloudg.inventory.azure_graph.builder import AzureAssetBuilder

SEARCH_SCOPE = "https://search.azure.com/.default"
SYNAPSE_SCOPE = "https://dev.azuresynapse.net/.default"
SEARCH_API = "2024-07-01"
SYNAPSE_API = "2020-12-01"
_SEARCH_KINDS = ("datasources", "indexers", "indexes", "skillsets")
_SYNAPSE_KINDS = ("linkedservices", "datasets", "pipelines", "triggers")


def _search_rows(svc_id: str, kind: str, items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rows = []
    for item in items:
        name = item.get("name")
        if not name:
            continue
        rows.append(
            {
                "id": f"{svc_id}/{kind}/{name}",
                "name": name,
                "type": f"microsoft.search/searchservices/{kind}",
                "properties": {k: v for k, v in item.items() if not k.startswith("@odata.etag")},
            }
        )
    return rows


def _synapse_rows(ws_id: str, kind: str, items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rows = []
    for item in items:
        name = item.get("name")
        if not name:
            continue
        row = dict(item)
        row["id"] = item.get("id") or f"{ws_id}/{kind}/{name}"
        row["type"] = f"microsoft.synapse/workspaces/{kind}"
        rows.append(row)
    return rows


class _PlaneRun:
    def __init__(self, task: str) -> None:
        self.task = task
        self.calls = 0
        self.rows = 0
        self.failures: list[str] = []
        self.started = time.time()
        self.skipped: str | None = None

    def call(self, fn: Callable[[], list[dict[str, Any]]]) -> list[dict[str, Any]]:
        self.calls += 1
        try:
            rows = fn()
        except CredentialError as exc:
            self.skipped = str(exc)
            return []
        except AzureRestError as exc:
            if not exc.not_applicable:
                self.failures.append(str(exc)[:300])
            return []
        except Exception as exc:  # unreachable endpoint (private), malformed JSON
            self.failures.append(f"{type(exc).__name__}: {str(exc)[:200]}")
            return []
        self.rows += len(rows)
        return rows

    def record(self, recorder: Any) -> None:
        if self.skipped and not self.rows:
            recorder.record(self.task, "SKIPPED", error=self.skipped[:300], started=self.started)
        else:
            recorder.outcome(self.task, self.rows, self.failures, self.calls, self.started)


def fetch_data_planes(
    credential: Any,
    factory: Callable[[Any, str, str], Any],
    builder: "AzureAssetBuilder",
    tasks: set[str],
    recorder: Any,
    *,
    max_parents: int = 500,
) -> None:
    """Read AI Search and Synapse data-plane objects into ``builder``."""
    if "search_data_plane" in tasks:
        run = _PlaneRun("search_data_plane")
        for d in builder.drafts_of("microsoft.search/searchservices")[:max_parents]:
            if run.skipped:
                break
            client = factory(
                credential, f"https://{d.name.lower()}.search.windows.net", SEARCH_SCOPE
            )
            for kind in _SEARCH_KINDS:
                items = run.call(lambda k=kind: client.list(f"/{k}", SEARCH_API))
                builder.add_rows(_search_rows(d.id, kind, items), discovered_via="data-plane")
        run.record(recorder)
    if "synapse_data_plane" in tasks:
        run = _PlaneRun("synapse_data_plane")
        for d in builder.drafts_of("microsoft.synapse/workspaces")[:max_parents]:
            dev = host_of(_get(_get(d.props, "connectivityEndpoints") or {}, "dev"))
            if run.skipped or not dev:
                continue
            client = factory(credential, f"https://{dev}", SYNAPSE_SCOPE)
            for kind in _SYNAPSE_KINDS:
                items = run.call(lambda k=kind: client.list(f"/{k}", SYNAPSE_API))
                builder.add_rows(_synapse_rows(d.id, kind, items), discovered_via="data-plane")
        run.record(recorder)


__all__ = ["fetch_data_planes"]
