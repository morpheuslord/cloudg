"""Deep GCP inventory collector.

The base :class:`GCPCollector` enumerates every resource with Cloud Asset
Inventory ``ListAssets`` (full resource JSON) and declares typed relations
through :mod:`cloudg.inventory.gcp_relations`. This subclass deepens the map
to the level of the AWS deep collector:

- A much richer GCP-type -> normalised AssetType mapping, so resources
  classify as real asset types instead of OTHER.
- IAM policy bindings via ``SearchAllIamPolicies``: every member becomes a
  principal asset (the collected service account, or a non-external
  ``gcp-principal:<member>`` placeholder) carrying GRANTS_ACCESS /
  ASSUMES_ROLE relations to the bound resource and USER / GROUP /
  ROLE_HAS_POLICY relations to the bound role. ``allUsers`` and
  ``allAuthenticatedUsers`` mark the resource internet-exposed.
- API-backed sources (:mod:`cloudg.inventory.gcp_sources`) for what Cloud
  Asset Inventory does not return: Cloud DNS records, Security Command
  Center, Cloud Identity groups, deny and Principal Access Boundary
  policies, PAM, audit-log configs, Cloud Monitoring, OS Config, Artifact
  Analysis, Backup and DR and more. Each one is best-effort with its own
  coverage record.
- Cross-asset passes (:mod:`cloudg.inventory.gcp_sources.derived`): tag
  bindings, secret rotation handlers, resource-policy schedules, labels of
  Deployment Manager / Config Connector resources, API Gateway authorizers.
- Per-family coverage (``gcp_assets_<family>``) and ``inventory.services``
  / ``inventory.exclude_services`` filtering (:mod:`cloudg.inventory.gcp_tasks`).

Edges are resolved by the inventory mapper's linker, so this collector
does not link locally.
"""

from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass, field, fields
from typing import Any

from cloudg.collectors.gcp import _GCP_ASSET_TYPE_MAP, GCPCollector
from cloudg.coverage import ServiceStatus
from cloudg.inventory.catalogs import asset_type_map, load_catalog
from cloudg.inventory.gcp_relations import apply_iam_policies, merge_gcp_principals
from cloudg.inventory.gcp_sources import GCPRestClient, GCPSourceOptions, SourceContext, run_sources
from cloudg.inventory.gcp_sources import derived
from cloudg.inventory.gcp_tasks import gcp_family, is_selected, type_selected
from cloudg.resilience.errors import describe_error
from cloudg.schema.models import AssetType, CloudAsset

logger = logging.getLogger(__name__)

__all__ = [
    "GCPDeepInventoryCollector",
    "GCPDeepOptions",
    "_DEEP_GCP_TYPE_MAP",
    "deep_options_from_config",
    "merge_gcp_principals",
]

_C = "compute.googleapis.com/"

# Deep mapping adds to the base table (catalogs/gcp_asset_types.yaml, "deep").
_DEEP_GCP_TYPE_MAP: dict[str, AssetType] = {
    **_GCP_ASSET_TYPE_MAP,
    **asset_type_map(load_catalog("gcp_asset_types").get("deep"), "gcp_asset_types"),
}


@dataclass
class GCPDeepOptions:
    """Keyword options the deep collector adds to :class:`GCPCollectorOptions`.

    Attributes:
        services: Families / services / sources to map (default: all).
        exclude_services: Families / services / sources to skip (wins over ``services``).
        rest_client: Injected REST client for the API-backed sources (tests);
            otherwise one is built from ``credentials``.
        deep_sources: Run the API-backed sources at all.
        rest_timeout: Per-request timeout of the REST client, in seconds.
        max_images_per_repository: Newest Docker images kept per repository.
        source_options: :class:`GCPSourceOptions` (or a dict of its fields).
    """

    services: list[str] | None = None
    exclude_services: list[str] | None = None
    rest_client: Any = None
    deep_sources: bool = True
    rest_timeout: float = 60.0
    max_images_per_repository: int | None = 100
    source_options: Any = field(default=None)


def deep_options_from_config(inventory: Any = None, gcp: Any = None) -> dict[str, Any]:
    """Deep collector keyword options from ``inventory.*`` and ``gcp.*`` config."""
    out: dict[str, Any] = {}
    if inventory is not None:
        out.update(
            services=list(getattr(inventory, "services", None) or ["all"]),
            exclude_services=list(getattr(inventory, "exclude_services", None) or []),
            max_images_per_repository=getattr(inventory, "max_images_per_repository", 100),
        )
    if gcp is not None:
        out.update(
            deep_sources=getattr(gcp, "deep_sources", True),
            rest_timeout=getattr(gcp, "rest_timeout_seconds", 60.0),
            source_options={
                "customer_id": getattr(gcp, "cloud_identity_customer_id", None),
                "max_dns_records_per_zone": getattr(gcp, "max_dns_records_per_zone", 5000),
                "max_vulnerability_occurrences": getattr(
                    gcp, "max_vulnerability_occurrences", 5000
                ),
                "max_groups": getattr(gcp, "max_groups", 2000),
                "max_group_members": getattr(gcp, "max_group_members", 5000),
                "expand_predefined_roles": getattr(gcp, "expand_predefined_roles", True),
                "max_role_expansions": getattr(gcp, "max_role_expansions", 500),
                "max_scheduler_locations": getattr(gcp, "max_scheduler_locations", 25),
                "concurrency": getattr(gcp, "source_concurrency", 4),
            },
        )
    return out


class GCPDeepInventoryCollector(GCPCollector):
    """GCP collector with a deeper type taxonomy, IAM bindings and API-backed sources."""

    _link_locally_default = False

    def __init__(self, project_id: str | None, credentials: Any = None, **options: Any) -> None:
        names = {f.name for f in fields(GCPDeepOptions)}
        deep = GCPDeepOptions(**{k: options.pop(k) for k in list(options) if k in names})
        super().__init__(project_id, credentials, **options)
        self._services = list(deep.services or ["all"])
        self._exclude_services = list(deep.exclude_services or [])
        self._deep_sources = deep.deep_sources
        self._max_images = deep.max_images_per_repository
        opts = deep.source_options
        if isinstance(opts, dict):
            opts = GCPSourceOptions(**opts)
        self._source_options = opts or GCPSourceOptions()
        rest = deep.rest_client
        if rest is None and credentials is not None and deep.deep_sources:
            rest = GCPRestClient(credentials, timeout=deep.rest_timeout)
        self._rest = rest

    def _resolve_asset_type(self, gcp_type: str) -> AssetType:
        return _DEEP_GCP_TYPE_MAP.get(gcp_type, AssetType.OTHER)

    # ------------------------------------------------------------------
    # Service filtering and per-family coverage
    # ------------------------------------------------------------------

    def _selected(self, name: str, family: str) -> bool:
        return is_selected(name, family, self._services, self._exclude_services)

    def _keep(self, rec: dict[str, Any], pid: str | None, number: str | None) -> bool:
        if not type_selected(rec["asset_type"], self._services, self._exclude_services):
            return False
        return super()._keep(rec, pid, number)

    def _listing_status(self) -> tuple[ServiceStatus, str | None]:
        """Status of this run's asset listing, for the per-family records."""
        by_service = {s.service: s for s in self.coverage.services}
        if "gcp_search_resources" in by_service:
            return ServiceStatus.PARTIAL, "summary data only (ListAssets unavailable)"
        listing = by_service.get("gcp_list_assets")
        if listing is not None and listing.status != ServiceStatus.SUCCESS:
            return ServiceStatus.PARTIAL, listing.error
        return ServiceStatus.SUCCESS, None

    def _record_families(self, assets: list[CloudAsset]) -> None:
        counts: dict[str, int] = {}
        for a in assets:
            fam = gcp_family(str(a.metadata.get("gcp_asset_type") or ""))
            counts[fam] = counts.get(fam, 0) + 1
        known = {gcp_family(t) for t in _DEEP_GCP_TYPE_MAP} | set(counts)
        status, error = self._listing_status()
        for fam in sorted(known):
            if not self._selected(fam, fam):
                continue
            self._record(f"gcp_assets_{fam}", status, counts.get(fam, 0), error)

    def _build_assets(self, records: list[dict[str, Any]]) -> list[CloudAsset]:
        records = derived.cap_images(records, self._max_images)
        assets = super()._build_assets(records)
        self._record_families(assets)
        return assets

    # ------------------------------------------------------------------
    # IAM policies (SearchAllIamPolicies)
    # ------------------------------------------------------------------

    def _search_iam(self) -> tuple[list[dict[str, Any]], Exception | None]:
        client = self._get_client()
        request = {"scope": self._scope, "page_size": 500}
        return self._iterate(client.search_all_iam_policies, request)

    def _keep_policy(self, pol: dict[str, Any]) -> bool:
        if not self._project_filter:
            return True
        project = str(pol.get("project") or "")
        if not project:
            return True
        number = project.removeprefix("projects/")
        return bool({number, self._number_to_id.get(number)} & self._project_filter)

    async def _enrich_iam(self, assets: list[CloudAsset], ctx: SourceContext) -> list[CloudAsset]:
        start = time.time()
        policies, error = await asyncio.to_thread(self._search_iam)
        policies = [p for p in policies if isinstance(p, dict) and self._keep_policy(p)]
        if error is not None:
            logger.error("GCP IAM policy search failed for %s: %s", self._scope, error)
            status = ServiceStatus.PARTIAL if policies else ServiceStatus.FAILED
            self._record(
                "gcp_iam_policies", status, len(policies), describe_error(error), start=start
            )
        else:
            self._record("gcp_iam_policies", ServiceStatus.SUCCESS, len(policies), start=start)
        created = apply_iam_policies(assets, policies)
        ctx.state["iam_roles"] = sorted(
            {
                b.get("role")
                for p in policies
                for b in (p.get("policy") or {}).get("bindings") or []
                if isinstance(b, dict) and isinstance(b.get("role"), str)
            }
        )
        logger.info("GCP IAM: %d policies, %d new principal assets", len(policies), len(created))
        return created

    # ------------------------------------------------------------------
    # Enrichment and cross-asset passes
    # ------------------------------------------------------------------

    async def _enrich(self, assets: list[CloudAsset]) -> list[CloudAsset]:
        ctx = SourceContext(self, assets, self._rest, self._source_options)
        inc, exc = self._services, self._exclude_services
        created: list[CloudAsset] = []
        if self._deep_sources:
            created += await run_sources(ctx, inc, exc, phases=[0])
        if self._include_iam and self._selected("iam_policies", "identity"):
            found = await self._enrich_iam(assets + created, ctx)
            ctx.add(found)
            created += found
        if self._deep_sources:
            created += await run_sources(ctx, inc, exc, phases=[1, 2, 3])
        return created

    def _finalize(self, assets: list[CloudAsset]) -> list[CloudAsset]:
        assets = self._derived("tag_bindings", derived.fold_tag_bindings, assets) or assets
        for name, fn in derived.PASSES:
            self._derived(name, fn, assets)
        assets = assets + (self._derived("authorizers", derived.authorizer_assets, assets) or [])
        assets = assets + (
            self._derived("principals", derived.ensure_principal_placeholders, assets) or []
        )
        return super()._finalize(assets)

    def _derived(self, name: str, fn: Any, assets: list[CloudAsset]) -> Any:
        """Run one cross-asset pass; a failure is recorded, not raised."""
        try:
            return fn(assets)
        except Exception as exc:
            logger.warning("GCP pass %s failed: %s", name, exc)
            logger.debug("GCP pass %s failed", name, exc_info=True)
            self._record(f"gcp_derived_{name}", ServiceStatus.FAILED, error=describe_error(exc))
            return None
