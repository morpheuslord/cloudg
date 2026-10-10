"""Loading files and directories into a :class:`Dataset`."""

from __future__ import annotations

import fnmatch
import json
import logging
import os
from pathlib import Path
from typing import Any, Iterable, Iterator

from pydantic import ValidationError

from cloudg.mcp.core import InvalidArgumentsError
from cloudg.mcp.state.base import DATASET_KINDS
from cloudg.mcp.state.dataset import Dataset
from cloudg.schema.models import CloudAsset, ComplianceResult, EdgeType, Finding, NetworkEdge

logger = logging.getLogger("cloudg.mcp")

# Bounds on directory scans (kind detection): a directory with a huge tree,
# or a symlink loop, must not stall a tool call.
SCAN_MAX_DEPTH = 6
SCAN_MAX_ENTRIES = 10_000


# ---------------------------------------------------------------------------
# Bounded directory walk
# ---------------------------------------------------------------------------


def iter_files(
    root: Path,
    pattern: str,
    *,
    max_depth: int = SCAN_MAX_DEPTH,
    max_entries: int = SCAN_MAX_ENTRIES,
) -> Iterator[Path]:
    """Files under ``root`` whose name matches the glob ``pattern``, walking
    at most ``max_depth`` levels and ``max_entries`` directory entries.
    Symlinked directories are not followed."""
    seen = 0
    base_depth = len(root.parts)
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        here = Path(dirpath)
        seen += len(dirnames) + len(filenames)
        if len(here.parts) - base_depth >= max_depth:
            dirnames[:] = []
        dirnames.sort()
        for name in sorted(filenames):
            if fnmatch.fnmatch(name, pattern):
                yield here / name
        if seen >= max_entries:
            logger.debug("Stopped scanning %s after %d entries", root, seen)
            return


def _has_file(root: Path, pattern: str) -> bool:
    return next(iter_files(root, pattern), None) is not None


# ---------------------------------------------------------------------------
# Parsing
# ---------------------------------------------------------------------------


def _parse_assets(raw: Iterable[dict[str, Any]]) -> list[CloudAsset]:
    return [
        CloudAsset.model_validate({k: v for k, v in a.items() if k != "display_id"}) for a in raw
    ]


def _parse_findings(raw: Iterable[dict[str, Any]]) -> list[Finding]:
    return [Finding.model_validate({k: v for k, v in f.items() if k != "risk_score"}) for f in raw]


def _edges_from_d3(graph: dict[str, Any]) -> list[NetworkEdge]:
    """Rebuild edges from a findings.json ``graph`` block (D3 links)."""
    valid = {e.value for e in EdgeType}
    out = []
    for link in graph.get("links", []) or []:
        etype = link.get("type")
        if etype not in valid or not link.get("source") or not link.get("target"):
            continue
        out.append(
            NetworkEdge(
                source_id=str(link["source"]),
                target_id=str(link["target"]),
                edge_type=EdgeType(etype),
                port_range=link.get("port_range") or None,
                protocol=link.get("protocol") or None,
                cidr=link.get("cidr") or None,
                direction=link.get("direction") or "ingress",
                description=link.get("description") or None,
                relationship=link.get("relationship") or None,
            )
        )
    return out


# ---------------------------------------------------------------------------
# Kind detection
# ---------------------------------------------------------------------------


def _detect_dir_kind(path: Path) -> str:
    if (path / "inventory-map.json").exists():
        return "inventory"
    if (path / "findings.json").exists():
        return "report"
    if _has_file(path, "scoutsuite_results*.js"):
        return "scoutsuite"
    if _has_file(path, "results_json.json"):
        return "checkov"
    raise InvalidArgumentsError(
        f"Cannot tell what {path} contains (no inventory-map.json or findings.json). "
        f"Pass kind= one of {', '.join(DATASET_KINDS[1:])}."
    )


def detect_kind(path: Path) -> str:
    """Best-effort detection of what a file / directory holds."""
    if path.is_dir():
        return _detect_dir_kind(path)
    if path.suffix == ".js" or path.name.startswith("scoutsuite_results"):
        return "scoutsuite"
    try:
        text = path.read_text()
    except OSError as exc:
        raise InvalidArgumentsError(f"Cannot read {path}: {exc.strerror or 'I/O error'}") from None
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        # JSON Lines: Prowler ASFF / OCSF output
        first = text.strip().splitlines()[0] if text.strip() else ""
        try:
            json.loads(first)
        except (json.JSONDecodeError, IndexError):
            raise InvalidArgumentsError(f"{path} is not JSON.") from None
        # Prowler ASFF or OCSF JSON Lines; the Prowler parser reads both
        return "prowler"
    return _detect_json_kind(data, path)


def is_ocsf(data: Any) -> bool:
    """Whether ``data`` (a record, or a list / wrapper of records) is OCSF
    (Prowler 4+ default output) rather than AWS Security Finding Format."""
    from cloudg.scanners.prowler_ocsf import is_ocsf_record

    if isinstance(data, list):
        data = data[0] if data else None
    return is_ocsf_record(data)


def _detect_dict_kind(data: dict[str, Any]) -> str | None:
    keys = set(data)
    if "findings" in keys and ("metadata" in keys or "summary" in keys):
        return "report"
    if {"assets", "edges"} <= keys and keys & {"unresolved_references", "regions"}:
        return "inventory"
    if keys & {"assets", "edges", "findings"}:
        return "generic"
    if "Results" in keys and keys & {"ArtifactName", "SchemaVersion", "ArtifactType"}:
        return "trivy"
    if "check_type" in keys or isinstance(data.get("results"), dict):
        return "checkov"
    if "Findings" in keys:
        return "prowler"
    return None


def _detect_list_kind(first: dict[str, Any], path: Path) -> str | None:
    if "check_type" in first:
        return "checkov"
    if is_ocsf(first) or first.keys() & {"ProductArn", "SchemaVersion"}:
        return "prowler"
    if first.keys() & {"severity", "title", "resource_id"}:
        return "generic"
    return None


def _detect_json_kind(data: Any, path: Path) -> str:
    kind = None
    if isinstance(data, dict):
        kind = _detect_dict_kind(data)
    elif isinstance(data, list) and data and isinstance(data[0], dict):
        kind = _detect_list_kind(data[0], path)
    if kind is None:
        raise InvalidArgumentsError(
            f"Unrecognised content in {path}. Pass kind= one of {', '.join(DATASET_KINDS[1:])}."
        )
    return kind


# ---------------------------------------------------------------------------
# Loading
# ---------------------------------------------------------------------------


def _load_inventory(path: Path, name: str) -> Dataset:
    from cloudg.inventory.mapper_result import InventoryResult

    try:
        inv = InventoryResult.load(path)
    except ValidationError as exc:
        raise InvalidArgumentsError(_schema_error(path, exc)) from None
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        raise InvalidArgumentsError(
            f"Cannot load inventory map {path}: {type(exc).__name__}"
        ) from None
    ds = Dataset.from_inventory(inv, name, source=str(path), kind="inventory")
    report = (path if path.is_dir() else path.parent) / "findings.json"
    if report.exists():
        other = _load_json_dataset(report, name, "report")
        ds.findings, ds.compliance = other.findings, other.compliance
        ds.metadata["findings_source"] = str(report)
    return ds


def _load_scanner_output(path: Path, name: str, kind: str, normalise: bool) -> Dataset:
    from cloudg.ingest import parse_report

    try:
        findings = parse_report(kind, path)
    except (ValueError, FileNotFoundError) as exc:
        raise InvalidArgumentsError(str(exc)) from None
    ds = Dataset(name=name, findings=list(findings), source=str(path), kind=kind)
    if normalise and (findings or getattr(findings, "passed_checks", None)):
        from cloudg.normaliser import FindingsNormaliser

        # A Prowler FindingList carries its passed checks into the normaliser
        sr = FindingsNormaliser().normalise(findings)
        ds.findings, ds.compliance = sr.findings, sr.compliance
    return ds


def load_dataset_file(path: Path, name: str, kind: str = "auto", normalise: bool = True) -> Dataset:
    """Load ``path`` into a :class:`Dataset` (no path-safety checks here;
    :meth:`Workspace.load` does those)."""
    if kind not in DATASET_KINDS:
        raise InvalidArgumentsError(
            f"Unknown kind {kind!r}. Use one of: {', '.join(DATASET_KINDS)}"
        )
    if not path.exists():
        raise InvalidArgumentsError(f"Path does not exist: {path}")
    kind = detect_kind(path) if kind == "auto" else kind
    if kind == "inventory":
        return _load_inventory(path, name)
    if kind in ("report", "generic"):
        target = path / "findings.json" if path.is_dir() else path
        return _load_json_dataset(target, name, kind)
    return _load_scanner_output(path, name, kind, normalise)


def _schema_error(path: Path, exc: ValidationError) -> str:
    """Describe a validation failure by location and error type only: the
    input values (file contents, possibly secrets) stay out of the message."""
    errors = exc.errors(include_input=False, include_url=False, include_context=False)
    first = errors[0] if errors else {}
    loc = ".".join(str(p) for p in first.get("loc", ()))
    where = f"; first at {loc or '(root)'} ({first.get('type', 'invalid')})" if first else ""
    return f"{path} does not match the cloudg schema: {len(errors)} validation error(s){where}."


def _parse_json_payload(data: dict[str, Any], path: Path) -> dict[str, Any]:
    try:
        edges = [NetworkEdge.model_validate(e) for e in data.get("edges", []) or []]
        if not edges and isinstance(data.get("graph"), dict):
            edges = _edges_from_d3(data["graph"])
        return {
            "assets": _parse_assets(data.get("assets", []) or []),
            "edges": edges,
            "findings": _parse_findings(data.get("findings", []) or []),
            "compliance": [
                ComplianceResult.model_validate(c) for c in data.get("compliance", []) or []
            ],
        }
    except ValidationError as exc:
        raise InvalidArgumentsError(_schema_error(path, exc)) from None
    except (TypeError, ValueError, AttributeError, KeyError) as exc:
        raise InvalidArgumentsError(
            f"{path} does not match the cloudg schema ({type(exc).__name__})."
        ) from None


def _load_json_dataset(path: Path, name: str, kind: str) -> Dataset:
    try:
        data = json.loads(path.read_text())
    except OSError as exc:
        raise InvalidArgumentsError(
            f"Cannot read JSON from {path}: {exc.strerror or 'I/O error'}"
        ) from None
    except json.JSONDecodeError as exc:
        raise InvalidArgumentsError(
            f"Cannot read JSON from {path}: invalid JSON at line {exc.lineno} column {exc.colno}"
        ) from None
    if isinstance(data, list):
        data = {"findings": data}
    if not isinstance(data, dict):
        raise InvalidArgumentsError(f"{path} does not hold a JSON object or list.")
    parsed = _parse_json_payload(data, path)
    meta = data.get("metadata") if isinstance(data.get("metadata"), dict) else {}
    return Dataset(
        name=name,
        **parsed,
        unresolved_references=list(data.get("unresolved_references", []) or []),
        providers=list(data.get("providers", []) or []),
        regions=dict(data.get("regions", {}) or {}),
        organization=data.get("organization"),
        source=str(path),
        kind=kind,
        metadata=dict(meta),
    )
