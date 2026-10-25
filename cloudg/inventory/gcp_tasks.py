"""Service families of the deep GCP inventory collector.

GCP has no per-service collectors to pick from: Cloud Asset Inventory
returns every type in one listing. ``inventory.services`` /
``inventory.exclude_services`` (``--services`` / ``--exclude-services``)
therefore filter at two levels, the same way
:func:`cloudg.inventory.aws_deep_tasks.select_tasks` filters AWS tasks:

- listed asset types, by their API service (``compute``, ``pubsub``, ...)
  or by family (``network``, ``data``, ...; ``catalogs/gcp_asset_types.yaml``
  ``families`` and ``type_families``);
- the API-backed sources of :mod:`cloudg.inventory.gcp_sources`, by source
  name (``dns_records``, ``scc``, ...) or by family.

``include`` defaults to everything; ``exclude`` always wins. The
``hierarchy`` family (organization, folders, projects) is kept unless it is
excluded by name, so a filtered map still has its projects.
"""

from __future__ import annotations

from typing import Iterable

from cloudg.inventory.catalogs import load_catalog

_CATALOG = load_catalog("gcp_asset_types")
GCP_SERVICE_FAMILIES: dict[str, str] = {
    str(k): str(v) for k, v in (_CATALOG.get("families") or {}).items()
}
GCP_TYPE_FAMILIES: dict[str, str] = {
    str(k): str(v) for k, v in (_CATALOG.get("type_families") or {}).items()
}
ALWAYS_KEPT = frozenset({"hierarchy"})


def gcp_service(asset_type: str) -> str:
    """API service of a CAI asset type: ``compute.googleapis.com/Disk`` -> ``compute``,
    ``k8s.io/Pod`` -> ``k8s.io``."""
    service = asset_type.split("/", 1)[0]
    return service.removesuffix(".googleapis.com")


def gcp_family(asset_type: str) -> str:
    """Service family of a CAI asset type (``other`` when the catalog has none)."""
    return GCP_TYPE_FAMILIES.get(asset_type) or GCP_SERVICE_FAMILIES.get(
        gcp_service(asset_type), "other"
    )


def is_selected(
    name: str,
    family: str,
    include: Iterable[str] | None = None,
    exclude: Iterable[str] | None = None,
) -> bool:
    """True when ``name`` (a service or source) of ``family`` passes the filters."""
    inc = {i.lower() for i in (include or ["all"])}
    exc = {e.lower() for e in (exclude or [])}
    name, family = name.lower(), family.lower()
    if name in exc or family in exc:
        return False
    return "all" in inc or name in inc or family in inc or family in ALWAYS_KEPT


def type_selected(
    asset_type: str, include: Iterable[str] | None = None, exclude: Iterable[str] | None = None
) -> bool:
    """Filter for one CAI asset type (by its service, family or the full type name)."""
    exc = {e.lower() for e in (exclude or [])}
    if asset_type.lower() in exc:
        return False
    inc = {i.lower() for i in (include or ["all"])}
    if asset_type.lower() in inc:
        return True
    return is_selected(gcp_service(asset_type), gcp_family(asset_type), include, exclude)


def families() -> list[str]:
    """Every family name the catalog and the API sources use."""
    from cloudg.inventory.gcp_sources import SOURCES

    names = set(GCP_SERVICE_FAMILIES.values()) | set(GCP_TYPE_FAMILIES.values())
    names |= {s.family for s in SOURCES.values()}
    return sorted(names | {"other"})


__all__ = [
    "ALWAYS_KEPT",
    "GCP_SERVICE_FAMILIES",
    "GCP_TYPE_FAMILIES",
    "families",
    "gcp_family",
    "gcp_service",
    "is_selected",
    "type_selected",
]
