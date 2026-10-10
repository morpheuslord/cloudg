"""Plugin registry: discovers collectors and scanners via entry_points."""

from __future__ import annotations

import importlib
import importlib.metadata
import logging
import re
from dataclasses import dataclass, field
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


def _dist_label(ep: Any) -> str:
    """ " (from <distribution>)" for log messages, when the entry point knows it."""
    dist = getattr(ep, "dist", None)
    name = getattr(dist, "name", None) if dist is not None else None
    return f" (from {name})" if name else ""


# Shape of a valid "module.path:ClassName" plugin path
_DOTTED_PATH_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_.]*:[A-Za-z_][A-Za-z0-9_]*$")


def _load_class(dotted_path: str) -> Type[Any]:
    """Import a class from a 'module.path:ClassName' string.

    Paths come from the built-in mapping above or from installed
    entry points, never from remote input; the shape check rejects
    anything that is not a plain dotted module path.
    """
    if not _DOTTED_PATH_RE.match(dotted_path):
        raise ValueError(f"Invalid plugin path: {dotted_path!r}")
    module_path, class_name = dotted_path.rsplit(":", 1)
    module = importlib.import_module(  # nosemgrep: python.lang.security.audit.non-literal-import.non-literal-import
        module_path
    )
    return getattr(module, class_name)


class PluginRegistry:
    """Discovers and loads plugins via setuptools entry_points.

    Falls back to built-in mappings when no entry_points are found.

    Precedence: the built-in collectors and scanners always win. cloudg
    registers them as entry points itself; an entry point from any other
    package that reuses a built-in name (for example ``prowler``) is
    ignored with a warning, so installing a package can never silently
    swap out a built-in scanner. Register a plugin under a name of its own
    instead. When two packages register the same new name, the first one
    found is kept and the others are ignored with a warning.

    Usage:
        registry = PluginRegistry()
        collector_cls = registry.get_collector("aws")
        scanner_cls = registry.get_scanner("prowler")
    """

    def __init__(self) -> None:
        self._collectors: dict[str, Type[Any]] = {}
        self._scanners: dict[str, Type[Any]] = {}
        # Names served by a third-party plugin (never a built-in name)
        self._plugin_collectors: set[str] = set()
        self._plugin_scanners: set[str] = set()
        self._discovered = False

    def _discover(self) -> None:
        """Discover plugins from entry_points (lazy, runs once)."""
        if self._discovered:
            return
        self._discovered = True

        self._discover_group(
            COLLECTOR_GROUP, _BUILTIN_COLLECTORS, self._collectors, self._plugin_collectors
        )
        self._discover_group(
            SCANNER_GROUP, _BUILTIN_SCANNERS, self._scanners, self._plugin_scanners
        )
        self._apply_builtin_fallbacks()

        logger.debug(
            "Plugin registry: %d collectors, %d scanners",
            len(self._collectors),
            len(self._scanners),
        )

    @staticmethod
    def _group_entry_points(group: str) -> list[Any]:
        return list(importlib.metadata.entry_points(group=group))

    def _discover_group(
        self,
        group: str,
        builtins: dict[str, str],
        target: dict[str, Type[Any]],
        plugin_names: set[str],
    ) -> None:
        """Load the third-party entry points of ``group`` (built-ins load later)."""
        kind = group.rsplit(".", 1)[-1][:-1]  # "collector" / "scanner"
        try:
            group_eps = self._group_entry_points(group)
        except Exception:
            logger.debug("%s entry point discovery failed", group, exc_info=True)
            return
        for ep in group_eps:
            if ep.name in builtins:
                if ep.value != builtins[ep.name]:
                    logger.warning(
                        "Ignoring %s plugin %s = %s%s: %r is a built-in %s name, and "
                        "built-ins take precedence. Register the plugin under another name.",
                        kind,
                        ep.name,
                        ep.value,
                        _dist_label(ep),
                        ep.name,
                        kind,
                    )
                continue  # cloudg's own entry point: loaded with the built-ins
            if ep.name in plugin_names:
                logger.warning(
                    "Ignoring %s plugin %s = %s%s: another plugin already uses the name",
                    kind,
                    ep.name,
                    ep.value,
                    _dist_label(ep),
                )
                continue
            try:
                loaded = ep.load()
            except Exception as exc:
                logger.warning("Failed to load %s plugin %s: %s", kind, ep.name, exc)
                continue
            plugin_names.add(ep.name)
            target[ep.name] = loaded
            logger.debug("Loaded %s plugin: %s", kind, ep.name)

    def _apply_builtin_fallbacks(self) -> None:
        """Fill in built-in defaults for any plugin not discovered."""
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

    def is_plugin_scanner(self, name: str) -> bool:
        """True when ``name`` is served by a third-party plugin (never a
        built-in name; see the precedence rules above)."""
        self._discover()
        return name in self._plugin_scanners


@dataclass
class ScannerSelection:
    """Requested scanner names, split by who runs them.

    ``builtin`` names are run by cloudg's own orchestration (with each
    scanner's specific settings); ``plugins`` maps the remaining names to
    their plugin classes; ``unknown`` lists names nothing provides.
    """

    builtin: list[str] = field(default_factory=list)
    plugins: dict[str, Type[Any]] = field(default_factory=dict)
    unknown: list[str] = field(default_factory=list)

    def __contains__(self, name: str) -> bool:
        return name in self.builtin

    @property
    def names(self) -> list[str]:
        """Every scanner that will run: built-ins, then plugins."""
        return self.builtin + list(self.plugins)


def select_scanners(names: list[str], registry: PluginRegistry | None = None) -> ScannerSelection:
    """Resolve ``scanners.enabled`` / ``--scanners`` names against the registry.

    Built-in names (prowler, scoutsuite, checkov, trivy, iam) run the
    built-in scanner. Other names run the plugin registered under them in
    the ``cloudg.scanners`` entry point group (matched case-insensitively).
    Names nothing provides are logged as a warning and reported in
    ``unknown`` instead of being dropped silently.
    """
    registry = registry or PluginRegistry()
    plugin_names = {n.lower(): n for n in registry.list_scanners() if registry.is_plugin_scanner(n)}
    selection = ScannerSelection()
    for raw in names:
        name = raw.strip().lower()
        if not name or name in selection.builtin or name in selection.plugins:
            continue
        if name in _BUILTIN_SCANNERS:
            selection.builtin.append(name)
        elif name in plugin_names:
            selection.plugins[name] = registry.get_scanner(plugin_names[name])
        elif name not in selection.unknown:
            selection.unknown.append(name)
    if selection.unknown:
        logger.warning(
            "Unknown scanner(s) ignored: %s. Available: %s",
            ", ".join(selection.unknown),
            ", ".join(available_scanners(registry)),
        )
    return selection


def available_scanners(registry: PluginRegistry | None = None) -> list[str]:
    """Built-in scanner names, then the installed plugin scanners."""
    registry = registry or PluginRegistry()
    plugins = sorted(n for n in registry.list_scanners() if registry.is_plugin_scanner(n))
    return list(_BUILTIN_SCANNERS) + plugins


def run_plugin_scanner(scanner_cls: Type[Any], **context: Any) -> list[Any]:
    """Instantiate a plugin scanner and run it.

    The constructor receives the keyword arguments it declares out of
    ``config``, ``provider``, ``profile``, ``output_dir``, ``assets``,
    ``iac_dirs``, ``images`` and ``timeout_seconds`` (all of them when it
    takes ``**kwargs``). ``run()`` must return a list of
    :class:`cloudg.schema.models.Finding` objects or dicts in that shape.

    Raises:
        TypeError: ``run()`` returned something that is not a finding.
    """
    import inspect

    from cloudg.schema.models import Finding

    try:
        params = inspect.signature(scanner_cls).parameters.values()
    except (TypeError, ValueError):
        params = []
    if any(p.kind is inspect.Parameter.VAR_KEYWORD for p in params):
        kwargs = dict(context)
    else:
        accepted = {p.name for p in params}
        kwargs = {k: v for k, v in context.items() if k in accepted}
    scanner = scanner_cls(**kwargs)

    findings: list[Any] = []
    for item in scanner.run() or []:
        if isinstance(item, Finding):
            findings.append(item)
        elif isinstance(item, dict):
            findings.append(Finding.model_validate(item))
        else:
            raise TypeError(
                f"{scanner_cls.__name__}.run() returned a {type(item).__name__}, "
                "expected Finding objects or dicts"
            )
    return findings
