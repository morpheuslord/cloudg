"""Plugin registry — discovers collectors and scanners via entry_points."""

from __future__ import annotations

import importlib
import logging
from importlib.metadata import entry_points
from typing import Any, Type

logger = logging.getLogger(__name__)

# Entry point group names
COLLECTOR_GROUP = "cloudg.collectors"
SCANNER_GROUP = "cloudg.scanners"

# Built-in fallback mappings (used when no entry_points are registered)
_BUILTIN_COLLECTORS: dict[str, str] = {
    "aws": "cloudg.collectors.aws:AsyncAWSCollector",
    "azure": "cloudg.collectors.azure:AzureCollector",
    "gcp": "cloudg.collectors.gcp:GCPCollector",
}

_BUILTIN_SCANNERS: dict[str, str] = {
    "prowler": "cloudg.scanners.prowler:ProwlerScanner",
    "scoutsuite": "cloudg.scanners.scoutsuite:ScoutSuiteScanner",
    "checkov": "cloudg.scanners.checkov:CheckovScanner",
    "trivy": "cloudg.scanners.trivy:TrivyScanner",
    "iam": "cloudg.scanners.iam_linter:IAMLinter",
}


def _load_class(dotted_path: str) -> Type[Any]:
    """Import a class from a 'module.path:ClassName' string."""
    module_path, class_name = dotted_path.rsplit(":", 1)
    module = importlib.import_module(module_path)
    return getattr(module, class_name)


class PluginRegistry:
    """Discovers and loads plugins via setuptools entry_points.

    Falls back to built-in mappings when no entry_points are found.

    Usage:
        registry = PluginRegistry()
        collector_cls = registry.get_collector("aws")
        scanner_cls = registry.get_scanner("prowler")
    """

    def __init__(self) -> None:
        self._collectors: dict[str, Type[Any]] = {}
        self._scanners: dict[str, Type[Any]] = {}
        self._discovered = False

    def _discover(self) -> None:
        """Discover plugins from entry_points (lazy, runs once)."""
        if self._discovered:
            return
        self._discovered = True

        # Discover collectors
        try:
            eps = entry_points()
            collector_eps = (
                eps.select(group=COLLECTOR_GROUP)
                if hasattr(eps, "select")
                else eps.get(COLLECTOR_GROUP, [])
            )
            for ep in collector_eps:
                try:
                    self._collectors[ep.name] = ep.load()
                    logger.debug("Loaded collector plugin: %s", ep.name)
                except Exception as exc:
                    logger.warning("Failed to load collector plugin %s: %s", ep.name, exc)
        except Exception:
            pass

        # Discover scanners
        try:
            eps = entry_points()
            scanner_eps = (
                eps.select(group=SCANNER_GROUP)
                if hasattr(eps, "select")
                else eps.get(SCANNER_GROUP, [])
            )
            for ep in scanner_eps:
                try:
                    self._scanners[ep.name] = ep.load()
                    logger.debug("Loaded scanner plugin: %s", ep.name)
                except Exception as exc:
                    logger.warning("Failed to load scanner plugin %s: %s", ep.name, exc)
        except Exception:
            pass

        # Fill in built-in defaults for any not discovered
        for name, path in _BUILTIN_COLLECTORS.items():
            if name not in self._collectors:
                try:
                    self._collectors[name] = _load_class(path)
                except Exception as exc:
                    logger.debug("Built-in collector %s not available: %s", name, exc)

        for name, path in _BUILTIN_SCANNERS.items():
            if name not in self._scanners:
                try:
                    self._scanners[name] = _load_class(path)
                except Exception as exc:
                    logger.debug("Built-in scanner %s not available: %s", name, exc)

        logger.info(
            "Plugin registry: %d collectors, %d scanners",
            len(self._collectors),
            len(self._scanners),
        )

    def get_collector(self, name: str) -> Type[Any]:
        """Get a collector class by name."""
        self._discover()
        if name not in self._collectors:
            raise KeyError(
                f"No collector registered for '{name}'. Available: {list(self._collectors.keys())}"
            )
        return self._collectors[name]

    def get_scanner(self, name: str) -> Type[Any]:
        """Get a scanner class by name."""
        self._discover()
        if name not in self._scanners:
            raise KeyError(
                f"No scanner registered for '{name}'. Available: {list(self._scanners.keys())}"
            )
        return self._scanners[name]

    def list_collectors(self) -> list[str]:
        """List registered collector names."""
        self._discover()
        return list(self._collectors.keys())

    def list_scanners(self) -> list[str]:
        """List registered scanner names."""
        self._discover()
        return list(self._scanners.keys())
