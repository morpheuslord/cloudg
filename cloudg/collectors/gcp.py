"""GCP resource collector built on the Cloud Asset Inventory API.

Enumeration uses ``AssetService.ListAssets`` with ``content_type=RESOURCE``
at project scope, or once at organization scope (``organizations/<id>``),
which returns the full resource JSON (``resource.data``) plus the resource
hierarchy (``ancestors``) for every supported asset type. Per-type
extractors in :mod:`cloudg.inventory.gcp_relations` turn that JSON into
typed relations, exposure flags and metadata.

If ``ListAssets`` is denied, the collector falls back to
``SearchAllResources`` (summary fields only) and records the run as
PARTIAL; if both fail it raises so the orchestrator records FAILED.
Blocking gRPC calls run in worker threads, with retries on quota and
availability errors.
"""

from __future__ import annotations

import asyncio
import logging
import re
import time
from contextlib import nullcontext
from dataclasses import dataclass
from typing import Any, Iterable

from cloudg.collectors.base import BaseCollector
from cloudg.collectors.gcp_assets import (
    _INTERNET,
    MappedRecord,
    _num,
    _project_segment,
    apply_firewalls,
    asset_location,
    build_cloud_asset,
    display_name,
    extract_location,
    internet_edges,
    record_from_asset,
    record_from_search,
    state_str,
    to_plain,
)
from cloudg.coverage import CollectionCoverage, ServiceStatus
from cloudg.resilience.errors import ErrorKind, classify, describe_error, is_throttle
from cloudg.resilience.gcp import RetryCounter, gcp_retry, gcp_scope, paced
from cloudg.resilience.governor import get_governor
from cloudg.inventory.catalogs import asset_type_map, load_catalog
from cloudg.schema.models import (
    AssetType,
    CloudAsset,
    CloudProvider,
    NetworkEdge,
)

logger = logging.getLogger(__name__)

# Mapping from GCP asset types to our normalised AssetType
# Asset type -> AssetType; the table lives in catalogs/gcp_asset_types.yaml.
_GCP_ASSET_TYPE_MAP: dict[str, AssetType] = asset_type_map(
    load_catalog("gcp_asset_types").get("base"), "gcp_asset_types"
)

# High-churn types skipped unless configured otherwise (GCPConfig.skip_asset_types)
DEFAULT_SKIP_ASSET_TYPES: tuple[str, ...] = (
    "k8s.io/Pod",
    "k8s.io/Node",
    "k8s.io/Event",
    "events.k8s.io/Event",
    "k8s.io/Endpoints",
    "discovery.k8s.io/EndpointSlice",
    "apps.k8s.io/ReplicaSet",
    "apps.k8s.io/ControllerRevision",
    "run.googleapis.com/Revision",
    "cloudkms.googleapis.com/CryptoKeyVersion",
    "secretmanager.googleapis.com/SecretVersion",
    "serviceusage.googleapis.com/Service",
)

_RESOURCE_MANAGER = "//cloudresourcemanager.googleapis.com/"


def _content_type(name: str) -> Any:
    try:
        from google.cloud import asset_v1

        return asset_v1.ContentType[name]
    except Exception:  # SDK missing (injected test client)
        return name


def _retry(scope: Any = None, counter: Any = None) -> Any:
    """api_core Retry on quota / availability errors (initial 1s, x2, capped
    at ratelimit.gcp.max_backoff_seconds (60), overall deadline_seconds
    (900), at most max_retries consecutive retries, retry budget); retried
    errors feed cloudg's adaptive rate limiter for ``scope``."""
    return gcp_retry(scope, counter=counter)


@dataclass
class GCPCollectorOptions:
    """Keyword options of :class:`GCPCollector` (documented there)."""

    organization_id: str | None = None
    scope: str | None = None
    project_filter: Iterable[str] | None = None
    skip_asset_types: Iterable[str] | None = None
    page_size: int = 1000
    include_iam: bool = True
    client: Any = None
    coverage: CollectionCoverage | None = None
    timeout: float = 600.0
    link_locally: bool | None = None


class GCPCollector(BaseCollector):
    """Collects GCP resources using the Cloud Asset Inventory API.

    Args:
        project_id: Project to collect (also the fallback account id).
        credentials: google-auth credentials.
        organization_id: Collect once at ``organizations/<id>`` scope instead
            of the project (covers every project in the org).
        scope: Explicit CAI scope (``projects/x``, ``folders/y``, ...).
        project_filter: At org/folder scope, keep only these projects (IDs
            or numbers); org- and folder-level resources are always kept.
        skip_asset_types: CAI types to drop (high-churn Kubernetes objects...).
        page_size: ListAssets page size (max 1000).
        include_iam: Collect IAM policy bindings (deep collector).
        client: Injected ``AssetServiceClient`` (tests).
        coverage: Coverage record that receives per-API status.
        timeout: Per-call timeout in seconds.
        link_locally: Resolve relations into edges in :meth:`collect_edges`
            (for pipelines that do not run the inventory linker).
    """

    supports_org_scope = True
    _link_locally_default = True

    def __init__(self, project_id: str | None, credentials: Any = None, **options: Any) -> None:
        # Keyword-only options are validated by the dataclass (unknown -> TypeError)
        opts = GCPCollectorOptions(**options)
        self._project_id = project_id
        self._credentials = credentials
        org = (
            str(opts.organization_id).removeprefix("organizations/")
            if opts.organization_id
            else None
        )
        self._organization_id = org
        if opts.scope:
            self._scope = opts.scope
        elif org:
            self._scope = f"organizations/{org}"
        else:
            self._scope = f"projects/{project_id}"
        self._project_scope = self._scope.startswith("projects/")
        self._project_filter = {str(p) for p in opts.project_filter or []}
        skip = opts.skip_asset_types
        self._skip_types = set(DEFAULT_SKIP_ASSET_TYPES if skip is None else skip)
        self._page_size = max(1, min(int(opts.page_size), 1000))
        self._include_iam = opts.include_iam
        self._client = opts.client
        self.coverage = opts.coverage or CollectionCoverage(provider="gcp", account_id=self._scope)
        self._timeout = opts.timeout
        link = opts.link_locally
        self._link_locally = self._link_locally_default if link is None else link
        self._cached_assets: list[CloudAsset] = []
        self._collected = False
        self._number_to_id: dict[str, str] = {}
        self._id_to_number: dict[str, str] = {}

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _resolve_asset_type(self, gcp_type: str) -> AssetType:
        """Map GCP asset type string to normalised AssetType."""
        return _GCP_ASSET_TYPE_MAP.get(gcp_type, AssetType.OTHER)

    def _extract_location(self, name: str) -> str:
        """Extract region/zone from resource name."""
        return extract_location(name)

    def _record(
        self,
        service: str,
        status: ServiceStatus,
        count: int = 0,
        error: str | None = None,
        start: float | None = None,
    ) -> None:
        duration = int((time.time() - start) * 1000) if start else None
        self.coverage.record(service, status, asset_count=count, error=error, duration_ms=duration)

    def _get_client(self) -> Any:
        if self._client is None:
            try:
                from google.cloud import asset_v1
            except ImportError as exc:
                raise RuntimeError(
                    "google-cloud-asset is not installed; install cloudg[gcp] to collect GCP"
                ) from exc
            self._client = asset_v1.AssetServiceClient(credentials=self._credentials)
        return self._client

    def _call_kwargs(self, scope: Any = None, counter: Any = None) -> dict[str, Any]:
        kwargs: dict[str, Any] = {"timeout": self._timeout}
        retry = _retry(scope, counter)
        if retry is not None:
            kwargs["retry"] = retry
        return kwargs

    def _iterate(
        self, method: Any, request: dict[str, Any]
    ) -> tuple[list[dict[str, Any]], Exception | None]:
        """Drain a paged CAI call in the calling (worker) thread.

        Each page takes a token from the shared limiter of this scope x RPC
        (Cloud Asset Inventory quotas are per minute per project / org), an
        open circuit fails fast, and throttling that outlasts the retries
        is reported as such (the caller records it in coverage).
        """
        gov = get_governor()
        scope = gcp_scope(self._scope, "cloudasset", method)
        items: list[dict[str, Any]] = []
        counter = RetryCounter()
        enabled = gov.provider_enabled("gcp")
        try:
            if enabled:
                gov.check(scope)
                gov.limiter.acquire_sync(scope)
                gov.record_call(scope)
            # Concurrent listings per project / org (ratelimit.gcp.max_concurrency)
            with gov.limiter.bulkhead(scope).hold_sync() if enabled else nullcontext():
                result = method(request=request, **self._call_kwargs(scope, counter))
                for item in paced(result, scope, request.get("page_size"), counter=counter):
                    items.append(to_plain(item))
        except Exception as exc:
            if is_throttle(exc):
                gov.on_gave_up(scope, f"throttled: {scope.operation}: {str(exc)[:150]}")
            elif classify(exc) is ErrorKind.TRANSIENT:
                gov.on_failure(scope)
            return items, exc
        gov.on_success(scope)
        return items, None

    # ------------------------------------------------------------------
    # Enumeration
    # ------------------------------------------------------------------

    def _list_assets(
        self, content_type: str, asset_types: list[str] | None = None
    ) -> tuple[list[dict[str, Any]], Exception | None]:
        client = self._get_client()
        request: dict[str, Any] = {
            "parent": self._scope,
            "content_type": _content_type(content_type),
            "page_size": self._page_size,
        }
        if asset_types:
            request["asset_types"] = asset_types
        return self._iterate(client.list_assets, request)

    def _search_resources(self) -> tuple[list[dict[str, Any]], Exception | None]:
        client = self._get_client()
        request = {"scope": self._scope, "page_size": 500, "read_mask": "*"}
        return self._iterate(client.search_all_resources, request)

    @staticmethod
    def _record_from_asset(d: dict[str, Any]) -> dict[str, Any]:
        return record_from_asset(d)

    @staticmethod
    def _record_from_search(d: dict[str, Any]) -> dict[str, Any]:
        """A SearchAllResources result in the ListAssets record shape (summary only)."""
        return record_from_search(d)

    async def _collect_records(self) -> list[dict[str, Any]]:
        start = time.time()
        raw, error = await asyncio.to_thread(self._list_assets, "RESOURCE")
        if error is None:
            self._record("gcp_list_assets", ServiceStatus.SUCCESS, len(raw), start=start)
            return [self._record_from_asset(r) for r in raw]
        if raw:
            logger.error(
                "GCP ListAssets for %s stopped after %d assets: %s", self._scope, len(raw), error
            )
            self._record(
                "gcp_list_assets",
                ServiceStatus.PARTIAL,
                len(raw),
                f"listing truncated: {describe_error(error)}",
                start=start,
            )
            return [self._record_from_asset(r) for r in raw]

        logger.warning(
            "GCP ListAssets failed for %s (%s); falling back to SearchAllResources",
            self._scope,
            error,
        )
        return await self._collect_from_search(error, start)

    async def _collect_from_search(self, error: Exception, start: float) -> list[dict[str, Any]]:
        """Summary records from SearchAllResources after ListAssets failed with ``error``."""
        search_start = time.time()
        found, search_error = await asyncio.to_thread(self._search_resources)
        self._record(
            "gcp_list_assets", ServiceStatus.FAILED, error=describe_error(error), start=start
        )
        if search_error is not None and not found:
            self._record(
                "gcp_search_resources",
                ServiceStatus.FAILED,
                error=describe_error(search_error),
                start=search_start,
            )
            raise RuntimeError(
                f"GCP asset enumeration failed for {self._scope}: "
                f"ListAssets: {describe_error(error)}; "
                f"SearchAllResources: {describe_error(search_error)}"
            )
        self._record(
            "gcp_search_resources",
            ServiceStatus.PARTIAL,
            len(found),
            "summary data only (ListAssets unavailable)"
            + (f"; listing truncated: {describe_error(search_error)}" if search_error else ""),
            start=search_start,
        )
        return [self._record_from_search(r) for r in found]

    # ------------------------------------------------------------------
    # Project number <-> id
    # ------------------------------------------------------------------

    def _learn_projects(self, records: list[dict[str, Any]]) -> None:
        for rec in records:
            if rec["asset_type"] == "cloudresourcemanager.googleapis.com/Project":
                self._learn_project_asset(rec)
        for rec in records:
            number = self._ancestor_number(rec)
            if not number or number in self._number_to_id:
                continue
            seg = _project_segment(rec["name"])
            if seg and not seg.isdigit():
                self._number_to_id[number] = seg
        if self._project_scope and self._project_id:
            numbers = {self._ancestor_number(r) for r in records} - {None}
            if len(numbers) == 1:
                self._number_to_id.setdefault(numbers.pop(), self._project_id)
        self._id_to_number = {v: k for k, v in self._number_to_id.items()}

    def _learn_project_asset(self, rec: dict[str, Any]) -> None:
        """Project number -> id from a cloudresourcemanager Project asset."""
        data = rec.get("data") or {}
        number = _num(data.get("projectNumber"))
        if not number and str(data.get("name", "")).startswith("projects/"):
            number = data["name"].split("/", 1)[1]
        if not number:
            number = rec["name"].rsplit("/", 1)[-1]
        pid = data.get("projectId")
        if number and pid:
            self._number_to_id.setdefault(number, pid)

    @staticmethod
    def _ancestor_number(rec: dict[str, Any]) -> str | None:
        for a in rec.get("ancestors") or []:
            if isinstance(a, str) and a.startswith("projects/"):
                return a.split("/", 1)[1]
        return None

    def _project_of(self, rec: dict[str, Any]) -> tuple[str | None, str | None]:
        """(project id, project number) of a record."""
        number = self._ancestor_number(rec)
        pid = self._number_to_id.get(number) if number else None
        if not pid:
            seg = _project_segment(rec["name"])
            if seg and not seg.isdigit():
                pid = seg
            elif seg:
                number = number or seg
                pid = self._number_to_id.get(seg)
        if not pid and self._project_scope:
            pid = self._project_id
        if pid and not number:
            number = self._id_to_number.get(pid)
        return pid, number

    def _keep(self, rec: dict[str, Any], pid: str | None, number: str | None) -> bool:
        if rec["asset_type"] in self._skip_types:
            return False
        if self._project_filter and (pid or number):
            return bool({pid, number} & self._project_filter)
        return True

    # ------------------------------------------------------------------
    # Asset building
    # ------------------------------------------------------------------

    @staticmethod
    def _display_name(rec: dict[str, Any], data: dict[str, Any]) -> str:
        return display_name(rec, data)

    def _number_id_aliases(self, name: str) -> list[str]:
        out = []
        m = re.search(r"/projects/([^/]+)(/|$)", name)
        if not m:
            return out
        seg = m.group(1)
        other = self._number_to_id.get(seg) if seg.isdigit() else self._id_to_number.get(seg)
        if other:
            out.append(name[: m.start(1)] + other + name[m.end(1) :])
        return out

    def _build_asset(self, rec: dict[str, Any]) -> CloudAsset | None:
        from cloudg.inventory.gcp_relations import GCPContext, extract, scrub

        pid, number = self._project_of(rec)
        if not self._keep(rec, pid, number):
            return None
        data = scrub(rec.get("data") or {})
        m = MappedRecord(rec, data, pid, number, asset_location(rec, data))
        ctx = GCPContext(
            name=m.name,
            asset_type=m.asset_type,
            data=data,
            project_id=pid,
            project_number=number,
            location=m.location if m.location != "global" else None,
            ancestors=list(m.ancestors),
        )
        return build_cloud_asset(
            m,
            extract(ctx),
            name=self._display_name(rec, data),
            asset_type=self._resolve_asset_type(m.asset_type),
            extra_aliases=self._number_id_aliases(m.name),
        )

    def _build_assets(self, records: list[dict[str, Any]]) -> list[CloudAsset]:
        self._learn_projects(records)
        assets: list[CloudAsset] = []
        failures: list[str] = []
        for rec in records:
            try:
                asset = self._build_asset(rec)
            except Exception as exc:
                failures.append(f"{rec.get('name')}: {type(exc).__name__}: {exc}")
                logger.debug("Failed to map GCP asset %s", rec.get("name"), exc_info=True)
                continue
            if asset is not None:
                assets.append(asset)
        if failures:
            self._record(
                "gcp_asset_mapping",
                ServiceStatus.PARTIAL,
                len(assets),
                f"{len(failures)} assets could not be mapped; first: {failures[0]}",
            )
        return assets

    # ------------------------------------------------------------------
    # Cross-asset passes
    # ------------------------------------------------------------------

    def _apply_firewalls(self, assets: list[CloudAsset]) -> None:
        """Attach VPC firewall rules to the instances they target and derive
        instance exposure (external IP + enabled 0.0.0.0/0 ingress allow)."""
        apply_firewalls(assets)

    def _ensure_project_asset(self, assets: list[CloudAsset]) -> list[CloudAsset]:
        """Project scope: make sure the project itself is an asset (IAM
        bindings and parent containment point at it)."""
        if not self._project_scope or not self._project_id:
            return []
        for a in assets:
            if a.asset_type == AssetType.CLOUD_ACCOUNT and a.account_id == self._project_id:
                return []
        number = self._id_to_number.get(self._project_id)
        ident = number or self._project_id
        aliases = [
            f"projects/{self._project_id}",
            f"{_RESOURCE_MANAGER}projects/{self._project_id}",
            self._project_id,
        ]
        if number:
            aliases += [f"projects/{number}", number]
        return [
            CloudAsset(
                arn=f"{_RESOURCE_MANAGER}projects/{ident}",
                name=self._project_id,
                asset_type=AssetType.CLOUD_ACCOUNT,
                provider=CloudProvider.GCP,
                region="global",
                account_id=self._project_id,
                metadata={
                    "gcp_asset_type": "cloudresourcemanager.googleapis.com/Project",
                    "account_id": self._project_id,
                    "project_id": self._project_id,
                    "project_number": number,
                    "aliases": [a for a in aliases if a != f"{_RESOURCE_MANAGER}projects/{ident}"],
                    "discovered_via": "collection scope",
                },
            )
        ]

    async def _enrich(self, assets: list[CloudAsset]) -> list[CloudAsset]:
        """Hook for subclasses: return extra assets (e.g. IAM principals)."""
        return []

    def _finalize(self, assets: list[CloudAsset]) -> list[CloudAsset]:
        from cloudg.inventory.gcp_relations import (
            ensure_service_account_principals,
            merge_gcp_principals,
        )

        self._apply_firewalls(assets)
        assets = assets + self._ensure_project_asset(assets)
        assets = assets + ensure_service_account_principals(assets)
        assets, _ = merge_gcp_principals(assets)
        return assets

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    async def collect(self) -> list[CloudAsset]:
        """Collect all GCP assets via Cloud Asset Inventory.

        Raises:
            RuntimeError: If the SDK is missing or enumeration failed entirely.
        """
        logger.info("Starting GCP asset collection for %s", self._scope)
        records = await self._collect_records()
        assets = self._build_assets(records)
        assets = assets + await self._enrich(assets)
        assets = self._finalize(assets)
        logger.info("Collected %d GCP assets from %s", len(assets), self._scope)
        self._cached_assets = assets
        self._collected = True
        return assets

    async def collect_edges(self) -> list[NetworkEdge]:
        """Internet ingress edges (``0.0.0.0/0`` -> exposed asset), plus the
        locally resolved relation edges when ``link_locally`` is set."""
        assets = self._cached_assets if self._collected else await self.collect()
        edges: list[NetworkEdge] = internet_edges(assets)
        if self._link_locally:
            from cloudg.inventory.linker import RelationshipLinker

            linker = RelationshipLinker(assets, materialize_external=False)
            linker.seed_existing(edges)
            edges.extend(linker.link(include_generic=False))
        logger.info("Collected %d GCP edges", len(edges))
        return edges


# Public API, including names re-exported from the split-out modules
__all__ = [
    "apply_firewalls",
    "asset_location",
    "build_cloud_asset",
    "display_name",
    "extract_location",
    "GCPCollector",
    "GCPCollectorOptions",
    "internet_edges",
    "MappedRecord",
    "record_from_asset",
    "record_from_search",
    "state_str",
    "to_plain",
    "_INTERNET",
    "_num",
    "_project_segment",
]
