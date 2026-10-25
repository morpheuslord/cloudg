"""Framework of the API-backed GCP sources: registry, run context, coverage.

A source maps one family of resources that Cloud Asset Inventory does not
return (or returns without the detail AWS-depth mapping needs). It is a
function ``fn(ctx, run) -> list[CloudAsset]`` registered with
:func:`source`. Sources run in phases (identity first, so later phases see
the groups; roles last, so every bound role is known) and, inside a phase,
concurrently in worker threads.

Each source is best-effort and gets its own coverage record
``gcp_<name>``:

- SUCCESS: every call answered (APIs that are not enabled in a project
  count as "not in use");
- PARTIAL: some calls failed, some answered;
- FAILED: nothing answered, or the source raised;
- SKIPPED: a prerequisite is missing (no REST transport, no organization,
  no customer ID) or the API is not enabled anywhere it was asked.

Resources a source reads go through the collector's own record pipeline
(:meth:`GCPCollector._build_asset`), so they get the same identifiers,
aliases, scrubbing and ``@_extractor`` relations as listed resources.
"""

from __future__ import annotations

import asyncio
import logging
import threading
import time
from dataclasses import dataclass
from typing import Any, Callable, Iterable

from cloudg.coverage import ServiceStatus
from cloudg.exceptions import CredentialError
from cloudg.inventory.gcp_sources.rest import GCPApiError
from cloudg.inventory.gcp_tasks import is_selected
from cloudg.resilience.errors import describe_error
from cloudg.schema.models import AssetType, CloudAsset, CloudProvider

logger = logging.getLogger(__name__)

_CRM = "//cloudresourcemanager.googleapis.com/"


@dataclass
class GCPSourceOptions:
    """Limits and inputs of the API-backed sources (``gcp.*`` config keys)."""

    customer_id: str | None = None
    max_dns_records_per_zone: int = 5000
    max_vulnerability_occurrences: int = 5000
    max_groups: int = 2000
    max_group_members: int = 5000
    expand_predefined_roles: bool = True
    max_role_expansions: int = 500
    max_scheduler_locations: int = 25
    concurrency: int = 4


SourceFn = Callable[["SourceContext", "SourceRun"], list[CloudAsset]]


@dataclass(frozen=True)
class Source:
    name: str
    family: str
    fn: SourceFn
    phase: int = 2
    needs_rest: bool = True
    description: str = ""


SOURCES: dict[str, Source] = {}


def source(
    name: str, family: str, *, phase: int = 2, needs_rest: bool = True, description: str = ""
) -> Callable[[SourceFn], SourceFn]:
    """Register an API-backed source (coverage record ``gcp_<name>``)."""

    def register(fn: SourceFn) -> SourceFn:
        SOURCES[name] = Source(
            name,
            family,
            fn,
            phase,
            needs_rest,
            description or (fn.__doc__ or "").strip().split("\n")[0],
        )
        return fn

    return register


class SourceSkipped(Exception):
    """A prerequisite of the source is missing (recorded as SKIPPED)."""


class SourceRun:
    """Outcome book-keeping of one source run."""

    def __init__(self, name: str) -> None:
        self.name = name
        self.ok = 0
        self.errors: list[str] = []
        self.disabled: list[str] = []
        self.notes: list[str] = []

    def call(
        self, fn: Callable[..., Any], *args: Any, tolerate: bool = False, **kwargs: Any
    ) -> Any:
        """Run one API call; errors are recorded (not raised) and None returned.

        ``tolerate``: an error is expected for some setups and is not a failure.
        API-not-enabled answers are recorded in ``disabled``; 404 counts as
        an empty answer.
        """
        try:
            result = fn(*args, **kwargs)
        except CredentialError:
            raise
        except GCPApiError as exc:
            if exc.disabled or exc.precondition:
                self.disabled.append(exc.url)
            elif exc.not_found or tolerate:
                self.ok += 1
            else:
                self.errors.append(describe_error(exc))
            return None
        except Exception as exc:
            if not tolerate:
                self.errors.append(f"{type(exc).__name__}: {describe_error(exc)}")
            return None
        self.ok += 1
        return result

    def status(self, produced: int) -> tuple[ServiceStatus, str | None]:
        if self.errors:
            status = ServiceStatus.PARTIAL if (produced or self.ok) else ServiceStatus.FAILED
            more = f" (+{len(self.errors) - 1} more)" if len(self.errors) > 1 else ""
            return status, self.errors[0][:400] + more
        if not self.ok and self.disabled and not produced:
            return ServiceStatus.SKIPPED, f"API not enabled ({len(self.disabled)} calls)"
        return ServiceStatus.SUCCESS, "; ".join(self.notes) or None


class SourceContext:
    """What a source sees: the collector, the assets so far and the REST client."""

    def __init__(
        self,
        collector: Any,
        assets: list[CloudAsset],
        rest: Any,
        options: GCPSourceOptions,
    ) -> None:
        self.collector = collector
        self.rest = rest
        self.options = options
        self.state: dict[str, Any] = {}
        self._assets = list(assets)
        self._lock = threading.Lock()
        self._index: dict[str, CloudAsset] | None = None

    # -- assets -----------------------------------------------------------

    @property
    def assets(self) -> list[CloudAsset]:
        with self._lock:
            return list(self._assets)

    def add(self, assets: Iterable[CloudAsset]) -> None:
        with self._lock:
            for a in assets:
                self._assets.append(a)
                if self._index is not None:
                    self._index_one(self._index, a)

    def _index_one(self, idx: dict[str, CloudAsset], a: CloudAsset) -> None:
        for ident in [a.arn, *(a.metadata.get("aliases") or [])]:
            if isinstance(ident, str) and ident:
                idx.setdefault(ident, a)
                idx.setdefault(ident.lower(), a)

    def lookup(self, identifier: Any) -> CloudAsset | None:
        """Asset with this arn or alias (case-insensitive fallback)."""
        if not isinstance(identifier, str) or not identifier:
            return None
        with self._lock:
            if self._index is None:
                self._index = {}
                for a in self._assets:
                    self._index_one(self._index, a)
            return self._index.get(identifier) or self._index.get(identifier.lower())

    def by_type(self, *gcp_types: str) -> list[CloudAsset]:
        wanted = set(gcp_types)
        return [a for a in self.assets if a.metadata.get("gcp_asset_type") in wanted]

    # -- scope ------------------------------------------------------------

    def projects(self) -> list[tuple[str, str | None]]:
        """(project id, number) of every project in scope."""
        c = self.collector
        if c._project_scope and c._project_id:
            return [(c._project_id, c._id_to_number.get(c._project_id))]
        out: dict[str, str | None] = {}
        for a in self.assets:
            if a.asset_type == AssetType.CLOUD_ACCOUNT and a.provider == CloudProvider.GCP:
                pid = a.metadata.get("project_id") or a.account_id
                if pid and not a.metadata.get("external"):
                    out.setdefault(pid, a.metadata.get("project_number"))
        if c._project_filter:
            out = {p: n for p, n in out.items() if {p, n} & c._project_filter}
        return sorted(out.items())

    def organization(self) -> str | None:
        """Numeric organization ID (configured, scope, or the assets' ancestry)."""
        c = self.collector
        if c._organization_id:
            return c._organization_id
        if c._scope.startswith("organizations/"):
            return c._scope.split("/", 1)[1]
        for a in self.assets:
            org = a.metadata.get("organization")
            if isinstance(org, str) and org.startswith("organizations/"):
                return org.split("/", 1)[1]
        return None

    def folders(self) -> list[str]:
        found: set[str] = set()
        for a in self.assets:
            for f in a.metadata.get("folders") or []:
                if isinstance(f, str) and f.startswith("folders/"):
                    found.add(f)
            if a.metadata.get("gcp_asset_type") == "cloudresourcemanager.googleapis.com/Folder":
                found.add("folders/" + a.arn.rsplit("/", 1)[-1])
        return sorted(found)

    def parents(self, folders: bool = True) -> list[str]:
        """Organization, folders and projects in scope (``organizations/1`` ...)."""
        out = [f"projects/{p}" for p, _ in self.projects()]
        if folders:
            out = self.folders() + out
        org = self.organization()
        return ([f"organizations/{org}"] if org else []) + out

    def project_ancestors(self, project: str | None) -> list[str]:
        """Ancestry of ``project`` as other assets in it record it."""
        if not project:
            return []
        number = self.collector._id_to_number.get(project)
        for a in self.assets:
            if a.account_id == project and a.metadata.get("project_number"):
                number = number or a.metadata.get("project_number")
                rest = list(a.metadata.get("folders") or [])
                if a.metadata.get("organization"):
                    rest.append(a.metadata["organization"])
                return [f"projects/{number}", *rest]
        return [f"projects/{number or project}"]

    # -- REST helpers -----------------------------------------------------

    def items(
        self, run: "SourceRun", url: str, key: str, tolerate: bool = False, **kwargs: Any
    ) -> list[dict[str, Any]]:
        """Paged list through ``run.call`` (errors recorded, [] on failure)."""
        res = run.call(self.rest.list, url, key, tolerate=tolerate, **kwargs)
        if not res:
            return []
        found, truncated = res
        if truncated:
            run.notes.append(f"{key} truncated at {len(found)}")
        return found

    def get(
        self,
        run: "SourceRun",
        url: str,
        params: dict[str, Any] | None = None,
        tolerate: bool = False,
    ) -> dict[str, Any] | None:
        return run.call(self.rest.get, url, params, tolerate=tolerate)

    # -- building ---------------------------------------------------------

    def build(
        self,
        name: str,
        asset_type: str,
        data: dict[str, Any],
        *,
        project: str | None = None,
        location: str | None = None,
        source_name: str = "",
        global_resource: bool = False,
    ) -> CloudAsset | None:
        """A CloudAsset for an API resource, through the collector's record pipeline.

        Returns None when the resource is already in the inventory (listed
        by Cloud Asset Inventory or built by another source).
        """
        if not name.startswith("//"):
            raise ValueError(f"full resource name expected, got {name!r}")
        if self.lookup(name) is not None:
            return None
        parent = f"{_CRM}projects/{project}" if project else ""
        rec = {
            "name": name,
            "asset_type": asset_type,
            "data": data,
            "location": location or "",
            "parent": parent,
            "ancestors": [] if global_resource else self.project_ancestors(project),
        }
        asset = self.collector._build_asset(rec)
        if asset is None:
            return None
        for alias in asset.metadata.get("aliases") or []:
            if self.lookup(alias) is not None and alias.startswith("//"):
                return None
        if global_resource:
            asset.account_id = None
            for key in ("project", "project_id", "project_number"):
                asset.metadata[key] = None
        asset.metadata["discovered_via"] = f"gcp-api:{source_name}" if source_name else "gcp-api"
        return asset

    def placeholder(
        self,
        service: str,
        parent: str,
        asset_type: AssetType,
        label: str,
        reason: str = "not enabled",
        gcp_type: str | None = None,
    ) -> CloudAsset:
        """A "not enabled" placeholder, like the AWS ``_disabled_asset``.

        ``arn`` is ``cloudg:gcp:<service>:<parent>:not-enabled`` and the
        asset carries the service's ``gcp-security:`` alias, so configs
        that depend on the service link to the gap.
        """
        project = parent.split("/", 1)[1] if parent.startswith("projects/") else None
        md: dict[str, Any] = {
            "security_service": service,
            "enabled": False,
            "status": reason,
            "parent": parent,
            "gcp_asset_type": gcp_type,
            "project_id": project,
            "placeholder_for": "service",
            "discovered_via": "gcp-api",
            "aliases": [f"gcp-security:{service}:{parent}"],
        }
        if not project:
            md["relations"] = [
                {
                    "target": f"{_CRM}{parent}",
                    "edge": "CONTAINS",
                    "reverse": True,
                    "description": f"{label} {reason}",
                }
            ]
        return CloudAsset(
            arn=f"cloudg:gcp:{service}:{parent}:not-enabled",
            name=f"{label} ({reason})",
            asset_type=asset_type,
            provider=CloudProvider.GCP,
            region="global",
            account_id=project,
            metadata=md,
        )


def _run_one(src: Source, ctx: SourceContext) -> list[CloudAsset]:
    start = time.time()
    record = ctx.collector._record
    key = f"gcp_{src.name}"
    if src.needs_rest and ctx.rest is None:
        record(key, ServiceStatus.SKIPPED, 0, "no REST transport (no GCP credentials)", start=start)
        return []
    run = SourceRun(src.name)
    try:
        assets = [a for a in (src.fn(ctx, run) or []) if a is not None]
    except SourceSkipped as exc:
        record(key, ServiceStatus.SKIPPED, 0, str(exc), start=start)
        return []
    except Exception as exc:
        logger.warning("GCP source %s failed: %s", src.name, exc)
        logger.debug("GCP source %s failed", src.name, exc_info=True)
        record(key, ServiceStatus.FAILED, 0, describe_error(exc), start=start)
        return []
    status, error = run.status(len(assets))
    record(key, status, len(assets), error, start=start)
    return assets


async def run_sources(
    ctx: SourceContext,
    include: Iterable[str] | None = None,
    exclude: Iterable[str] | None = None,
    phases: Iterable[int] | None = None,
) -> list[CloudAsset]:
    """Run the selected sources phase by phase; returns every asset they built."""
    selected = [s for s in SOURCES.values() if is_selected(s.name, s.family, include, exclude)]
    wanted = set(phases) if phases is not None else {s.phase for s in selected}
    created: list[CloudAsset] = []
    sem = asyncio.Semaphore(max(1, ctx.options.concurrency))

    async def one(src: Source) -> list[CloudAsset]:
        async with sem:
            return await asyncio.to_thread(_run_one, src, ctx)

    for phase in sorted(wanted):
        batch = [s for s in selected if s.phase == phase]
        results = await asyncio.gather(*(one(s) for s in batch))
        for assets in results:
            ctx.add(assets)
            created.extend(assets)
    return created


__all__ = [
    "GCPSourceOptions",
    "SOURCES",
    "Source",
    "SourceContext",
    "SourceRun",
    "SourceSkipped",
    "run_sources",
    "source",
]
