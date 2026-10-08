"""The :class:`Workspace`: named datasets, the active one, path safety and
change hooks."""

from __future__ import annotations

import logging
import os
import re
import threading
from pathlib import Path
from typing import Any, Callable, Iterable

from cloudg.mcp.core import AccessDeniedError, InvalidArgumentsError
from cloudg.mcp.state.base import NAME_RE, NoDatasetError
from cloudg.mcp.state.dataset import Dataset
from cloudg.mcp.state.diff import diff_datasets
from cloudg.mcp.state.loading import load_dataset_file

logger = logging.getLogger("cloudg.mcp")

ALLOWED_ROOTS_ENV = "CLOUDG_MCP_ALLOWED_ROOTS"


def _too_broad(p: Path) -> bool:
    """Whether ``p`` is the filesystem root or the user's home directory,
    which are never used as an implicit sandbox root."""
    if p == Path(p.anchor):
        return True
    try:
        return p == Path.home().resolve()
    except (RuntimeError, OSError):  # no resolvable home directory
        return False


def default_roots(report_dir: Path) -> list[Path]:
    """Allowed roots when none are configured: ``$CLOUDG_MCP_ALLOWED_ROOTS``
    (explicit, used as given), else the current directory plus the report
    directory. The current directory is dropped (with a warning) when it is
    ``/`` or the home directory, so starting the server from there does not
    expose the whole filesystem or home."""
    env = os.environ.get(ALLOWED_ROOTS_ENV)
    if env:
        return [Path(p) for p in env.split(os.pathsep) if p]
    roots = []
    for candidate in (Path.cwd(), report_dir):
        resolved = candidate.expanduser().resolve()
        if _too_broad(resolved):
            logger.warning(
                "Not using %s as an implicit allowed root (it is the filesystem root or the "
                "home directory). Set %s or pass allowed_roots to widen the sandbox.",
                resolved,
                ALLOWED_ROOTS_ENV,
            )
            continue
        roots.append(resolved)
    if not roots:
        raise ValueError(
            "No safe default allowed root: the current directory and the report directory "
            f"are / or the home directory. Set {ALLOWED_ROOTS_ENV} or pass allowed_roots."
        )
    return roots


class Workspace:
    """Named datasets, the active selection, path safety and change hooks.

    Args:
        config: cloudg configuration used by live tools (collection,
            scanners) and for default directories. ``CloudGConfig()`` when
            omitted.
        allowed_roots: Directories tools may read from / write to. Default:
            ``$CLOUDG_MCP_ALLOWED_ROOTS`` (``os.pathsep``-separated) or the
            current directory plus ``config.report.output_dir``. An implicit
            current directory that is ``/`` or the home directory is left
            out (see :func:`default_roots`).
        output_dir: Where write tools put files (must be inside an allowed
            root). Default: ``config.report.output_dir``.
        max_datasets: Oldest non-active dataset is evicted beyond this.
    """

    def __init__(
        self,
        config: Any = None,
        *,
        allowed_roots: Iterable[str | Path] | None = None,
        output_dir: str | Path | None = None,
        max_datasets: int = 16,
    ) -> None:
        if config is None:
            from cloudg.config import CloudGConfig

            config = CloudGConfig()
        self.config = config
        report_dir = Path(getattr(getattr(config, "report", None), "output_dir", "./reports"))
        if allowed_roots is None:
            allowed_roots = default_roots(report_dir)
        self.allowed_roots: list[Path] = []
        for r in allowed_roots:
            p = Path(r).expanduser().resolve()
            if p not in self.allowed_roots:
                self.allowed_roots.append(p)
        if not self.allowed_roots:
            raise ValueError("Workspace needs at least one allowed root")
        out = Path(output_dir).expanduser() if output_dir else report_dir
        if not out.is_absolute():
            out = Path.cwd() / out
        self.output_root = out.resolve()
        if not self._inside_roots(self.output_root):
            self.allowed_roots.append(self.output_root)
        self.max_datasets = max_datasets
        self._datasets: dict[str, Dataset] = {}
        self._active: str | None = None
        self._lock = threading.RLock()
        self._listeners: list[Callable[[str, str | None], Any]] = []
        self._live_guard: Any = None

    # -- live operation guard ----------------------------------------------

    @property
    def live_guard(self) -> Any:
        """The :class:`cloudg.resilience.LiveOperationGuard` shared by every
        live tool of this workspace (single-flight, cooldowns, concurrency
        caps), built from ``config.ratelimit`` on first use."""
        if self._live_guard is None:
            with self._lock:
                if self._live_guard is None:
                    from cloudg.resilience import LiveOperationGuard

                    self._live_guard = LiveOperationGuard.from_config(self.config)
        return self._live_guard

    @live_guard.setter
    def live_guard(self, guard: Any) -> None:
        self._live_guard = guard

    # -- change notification ---------------------------------------------

    def on_change(self, listener: Callable[[str, str | None], Any]) -> None:
        """Register ``listener(kind, uri)``. Kinds: ``"resources"`` (the
        resource list changed: dataset added / removed) and ``"resource"``
        (one URI's content changed)."""
        self._listeners.append(listener)

    def notify(self, kind: str, uri: str | None = None) -> None:
        for fn in list(self._listeners):
            try:
                fn(kind, uri)
            except Exception:  # a broken listener must not break the tool call
                logger.debug("workspace listener failed", exc_info=True)

    def _changed(self, dataset: str | None, list_changed: bool) -> None:
        if list_changed:
            self.notify("resources", None)
        self.notify("resource", "cloudg://workspace")
        self.notify("resource", "cloudg://datasets")
        if dataset:
            self.notify("resource", f"cloudg://datasets/{dataset}/summary")

    # -- datasets ---------------------------------------------------------

    @property
    def active_name(self) -> str | None:
        return self._active

    def names(self) -> list[str]:
        with self._lock:
            return list(self._datasets)

    def datasets(self) -> list[Dataset]:
        with self._lock:
            return list(self._datasets.values())

    def __contains__(self, name: object) -> bool:
        return name in self._datasets

    def __len__(self) -> int:
        return len(self._datasets)

    def get(self, name: str | None = None) -> Dataset:
        """The named dataset, or the active one when ``name`` is empty."""
        with self._lock:
            if not name:
                if self._active is None:
                    raise NoDatasetError(
                        "No dataset is loaded. Call load_dataset(path=...) with an "
                        "inventory-map.json / findings.json / scanner report, or "
                        "map_inventory to collect live data."
                    )
                return self._datasets[self._active]
            ds = self._datasets.get(name)
            if ds is None:
                raise NoDatasetError(
                    f"No such dataset. {len(self._datasets)} dataset(s) are loaded: see "
                    "datasets in the error data, or call list_datasets.",
                    data={"value": name, "datasets": [{"dataset": n} for n in self._datasets]},
                )
            return ds

    def unique_name(self, base: str) -> str:
        base = re.sub(r"[^A-Za-z0-9_.\-]+", "-", base).strip("-")[:48] or "dataset"
        with self._lock:
            if base not in self._datasets:
                return base
            i = 2
            while f"{base}-{i}" in self._datasets:
                i += 1
            return f"{base}-{i}"

    def check_name(self, name: str, *, replace: bool = False) -> str:
        """Validate a name for a new dataset before doing any work: the
        format, and (unless ``replace``) that no dataset already uses it."""
        if not NAME_RE.match(name or ""):
            raise InvalidArgumentsError(
                "Invalid dataset name: use 1-64 letters, digits, '.', '_' or '-'.",
                data={"value": name},
            )
        if not replace and name in self._datasets:
            suggested = self.unique_name(name)
            raise InvalidArgumentsError(
                "A dataset with that name already exists. Choose another name (the error "
                "data suggests a free one), or pass replace=true to overwrite it.",
                data={"existing": name, "suggested": suggested},
            )
        return name

    def add(self, dataset: Dataset, *, activate: bool = True, replace: bool = False) -> Dataset:
        """Add ``dataset``. An existing dataset of the same name is only
        overwritten with ``replace=True``."""
        with self._lock:
            self.check_name(dataset.name, replace=replace)
            existed = dataset.name in self._datasets
            self._datasets[dataset.name] = dataset
            if activate or self._active is None:
                self._active = dataset.name
            self._evict()
        self._changed(dataset.name, list_changed=not existed)
        return dataset

    def _evict(self) -> None:
        while len(self._datasets) > self.max_datasets:
            victim = next(n for n in self._datasets if n != self._active)
            logger.info("Evicting dataset %s (max_datasets=%d)", victim, self.max_datasets)
            del self._datasets[victim]

    def select(self, name: str) -> Dataset:
        ds = self.get(name)
        with self._lock:
            self._active = name
        self._changed(name, list_changed=False)
        return ds

    def remove(self, name: str) -> Dataset:
        with self._lock:
            ds = self.get(name)
            del self._datasets[name]
            if self._active == name:
                self._active = next(reversed(self._datasets), None) if self._datasets else None
        self._changed(None, list_changed=True)
        return ds

    def mutated(self, dataset: Dataset) -> None:
        """Tell listeners a dataset's contents changed (after a mutation)."""
        self._changed(dataset.name, list_changed=False)

    def snapshot(self, name: str | None, new_name: str, *, replace: bool = False) -> Dataset:
        src = self.get(name)
        self.check_name(new_name, replace=replace)
        return self.add(src.copy(new_name), activate=False, replace=replace)

    def diff(self, base: str, target: str | None = None, limit: int = 50) -> dict[str, Any]:
        return diff_datasets(self.get(base), self.get(target), limit=limit)

    # -- loading ----------------------------------------------------------

    def load(
        self,
        path: str | Path,
        name: str | None = None,
        *,
        kind: str = "auto",
        activate: bool = True,
        normalise: bool = True,
        replace: bool = False,
    ) -> Dataset:
        """Load a file / directory (path-checked) as a dataset. An explicit
        ``name`` that is already taken is refused unless ``replace``."""
        p = self.check_path(path)
        if name:
            self.check_name(name, replace=replace)
        base = name or (p.parent.name if p.name == "inventory-map.json" else p.stem) or "dataset"
        ds = load_dataset_file(p, name or self.unique_name(base), kind=kind, normalise=normalise)
        return self.add(ds, activate=activate, replace=replace)

    def add_inventory(self, result: Any, name: str | None = None, **kw: Any) -> Dataset:
        return self.add(Dataset.from_inventory(result, name or self.unique_name("live")), **kw)

    # -- path safety ------------------------------------------------------

    def _inside_roots(self, p: Path) -> bool:
        return any(p == r or p.is_relative_to(r) for r in self.allowed_roots)

    def check_path(self, path: str | Path, *, must_exist: bool = True) -> Path:
        """Resolve ``path`` (relative to the first allowed root) and make
        sure it stays inside the allowed roots, symlinks included."""
        raw = Path(str(path)).expanduser()
        if not raw.is_absolute():
            raw = self.allowed_roots[0] / raw
        resolved = raw.resolve()
        if not self._inside_roots(resolved):
            roots = ", ".join(str(r) for r in self.allowed_roots)
            raise AccessDeniedError(
                f"Path {path} is outside the allowed roots ({roots}). "
                "Ask the operator to add its directory to the workspace's allowed roots."
            )
        if must_exist and not resolved.exists():
            raise InvalidArgumentsError(f"Path does not exist: {path}")
        return resolved

    def output_path(self, subpath: str | Path = "") -> Path:
        """A location under :attr:`output_root` (``..`` escapes rejected)."""
        sub = Path(str(subpath or ""))
        if sub.is_absolute():
            target = sub.resolve()
        else:
            target = (self.output_root / sub).resolve()
        if not (target == self.output_root or target.is_relative_to(self.output_root)):
            raise AccessDeniedError(
                f"Output path {subpath} escapes the output directory {self.output_root}."
            )
        return target

    # -- status -----------------------------------------------------------

    def status(self) -> dict[str, Any]:
        """Workspace overview. Datasets are listed from a snapshot taken
        under the lock and described after releasing it, so a dataset busy
        building an analysis never blocks the rest of the workspace."""
        with self._lock:
            active = self._active
            datasets = list(self._datasets.values())
        return {
            "active_dataset": active,
            "datasets": [d.describe() for d in datasets],
            "allowed_roots": [str(r) for r in self.allowed_roots],
            "output_dir": str(self.output_root),
            "providers_configured": list(getattr(self.config, "providers", []) or []),
        }
