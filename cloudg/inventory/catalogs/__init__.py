"""Reference catalogs for the inventory mapper.

Type maps, skip lists and other reference data live in YAML files next to
this module, so coverage grows by editing data rather than code. Each
catalog is loaded once and cached.

Overlays: every ``*.yaml`` file in ``$CLOUDG_CATALOG_DIR`` whose name
matches a packaged catalog (``aws_cloudcontrol.yaml``,
``aws_arn_types.yaml``, ...) is merged on top of it: mappings are updated
key by key, lists are extended. That lets a deployment add resource types
or reclassify them without touching cloudg.
"""

from __future__ import annotations

import logging
import os
from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml

from cloudg.schema.models import AssetType

logger = logging.getLogger(__name__)

_HERE = Path(__file__).parent


def _merge(base: Any, extra: Any) -> Any:
    if isinstance(base, dict) and isinstance(extra, dict):
        out = dict(base)
        for key, value in extra.items():
            out[key] = _merge(base.get(key), value) if key in base else value
        return out
    if isinstance(base, list) and isinstance(extra, list):
        return base + [v for v in extra if v not in base]
    return extra if extra is not None else base


@lru_cache(maxsize=None)
def load_catalog(name: str) -> dict[str, Any]:
    """Load ``<name>.yaml`` plus any overlay from ``$CLOUDG_CATALOG_DIR``."""
    with open(_HERE / f"{name}.yaml") as f:
        data: dict[str, Any] = yaml.safe_load(f) or {}
    overlay_dir = os.environ.get("CLOUDG_CATALOG_DIR")
    if overlay_dir:
        overlay = Path(overlay_dir) / f"{name}.yaml"
        if overlay.is_file():
            with open(overlay) as f:
                data = _merge(data, yaml.safe_load(f) or {})
            logger.info("Catalog %s: merged overlay %s", name, overlay)
    return data


def asset_type_map(mapping: dict[str, str] | None, catalog: str = "") -> dict[str, AssetType]:
    """Validate a ``key -> AssetType name`` mapping from a catalog.

    Raises:
        ValueError: An entry names an AssetType that does not exist.
    """
    out: dict[str, AssetType] = {}
    for key, value in (mapping or {}).items():
        try:
            out[str(key)] = AssetType[str(value)]
        except KeyError as exc:
            raise ValueError(f"Catalog {catalog}: unknown AssetType {value!r} for {key!r}") from exc
    return out


def flatten(groups: Any) -> list[str]:
    """A list, or a mapping of group -> list, as one flat list."""
    if isinstance(groups, dict):
        return [item for items in groups.values() for item in (items or [])]
    return list(groups or [])


__all__ = ["asset_type_map", "flatten", "load_catalog"]
