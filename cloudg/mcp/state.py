"""In-memory workspace of named datasets shared by every MCP request.

A :class:`Dataset` is one loaded view of cloud infrastructure: assets,
edges, findings, compliance mappings, collection coverage, the
organization topology and unresolved references, plus where it came from
(a file path, a live collection, or inline data). Derived structures
(lookup indexes, the NetworkX graph, the :class:`DependencyGraph`, the
reachability analyser, centrality metrics and the RDF ontology) are
built lazily on first use, cached, and invalidated whenever the dataset
is mutated (findings ingested, suppressed, normalised...).

The :class:`Workspace` holds several datasets by name with one marked
active, so an agent can load a baseline and a fresh collection side by
side and diff them. It also owns filesystem safety: every path a tool
reads or writes must resolve inside one of the configured allowed roots
(default: the current directory and the configured report directory), and
writes land under a single output root.

Usage::

    ws = Workspace(CloudGConfig(), allowed_roots=["./reports"])
    ds = ws.load("./reports/inventory-map.json")       # auto-detected
    ws.get().resolve_asset("arn:aws:lambda:...:function:api")
    ws.on_change(lambda kind, uri: print(kind, uri))  # list_changed hooks

Everything here is thread-safe: tool handlers run in worker threads.
"""

from __future__ import annotations

import copy
import difflib
import hashlib
import json
import logging
import os
import re
import threading
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Any, Callable, Iterable

from cloudg.mcp.core import AccessDeniedError, InvalidArgumentsError, NotFoundError
from cloudg.schema.models import (
    AssetType,
    CloudAsset,
    ComplianceResult,
    EdgeType,
    Finding,
    NetworkEdge,
    Severity,
)

if TYPE_CHECKING:  # pragma: no cover
    import networkx as nx

    from cloudg.coverage import CollectionCoverage
    from cloudg.inventory.dependencies import DependencyGraph
    from cloudg.inventory.mapper_result import InventoryResult

logger = logging.getLogger("cloudg.mcp")

INTERNET_NODES = ("0.0.0.0/0", "::/0")
SEVERITY_RANK = {
    Severity.CRITICAL.value: 4,
    Severity.HIGH.value: 3,
    Severity.MEDIUM.value: 2,
    Severity.LOW.value: 1,
    Severity.INFO.value: 0,
}
SCANNER_KINDS = ("prowler", "scoutsuite", "checkov", "trivy")
DATASET_KINDS = ("auto", "inventory", "report", "generic", *SCANNER_KINDS)
_NAME_RE = re.compile(r"^[A-Za-z0-9_.\-]{1,64}$")


# ---------------------------------------------------------------------------
# Errors. Both are NotFoundError subclasses: raised from a tool handler the
# layer returns them as an isError result the model can read (message with
# suggestions + ``data``); raised from a resource handler they become a
# JSON-RPC "resource not found" error.
# ---------------------------------------------------------------------------


class NoDatasetError(NotFoundError):
    """No dataset is loaded / the named dataset does not exist."""


class ReferenceNotFoundError(NotFoundError):
    """An asset / finding / control reference matched nothing."""


def ref_tails(identifier: str) -> set[str]:
    """Short forms an asset can be referred to by, derived from its ARN or
    resource id: the resource part of an ARN (``function:api``,
    ``db:orders``, ``instance/i-0abc``), the last ``/`` segment
    (``i-0abc``) and the last ``:`` segment (``api``). Azure / GCP paths
    contribute their last ``/`` segment."""
    out: set[str] = set()
    if identifier.startswith("arn:"):
        parts = identifier.split(":", 5)
        if len(parts) == 6 and parts[5]:
            out.add(parts[5])
    slash = identifier.rsplit("/", 1)[-1]
    colon = identifier.rsplit(":", 1)[-1]
    for t in (slash, colon):
        if t and t != identifier:
            out.add(t)
    return out


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


# ---------------------------------------------------------------------------
# Dataset
# ---------------------------------------------------------------------------


@dataclass
class Dataset:
    """One loaded inventory / findings view plus lazily-built analyses."""

    name: str
    assets: list[CloudAsset] = field(default_factory=list)
    edges: list[NetworkEdge] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    compliance: list[ComplianceResult] = field(default_factory=list)
    coverage: list["CollectionCoverage"] = field(default_factory=list)
    organization: dict[str, Any] | None = None
    unresolved_references: list[dict[str, Any]] = field(default_factory=list)
    providers: list[str] = field(default_factory=list)
    regions: dict[str, list[str]] = field(default_factory=dict)
    source: str = "inline"  # file path, "live" or "inline"
    kind: str = "generic"  # inventory | report | generic | live | <scanner> | snapshot
    loaded_at: str = field(default_factory=_now)
    metadata: dict[str, Any] = field(default_factory=dict)
    suppression_reasons: dict[str, str] = field(default_factory=dict)
    version: int = 0

    def __post_init__(self) -> None:
        self._lock = threading.RLock()
        self._cache: dict[str, Any] = {}
        if not self.providers:
            self.providers = sorted({a.provider.value.lower() for a in self.assets})

    # -- cache plumbing -------------------------------------------------

    def _cached(self, key: str, factory: Callable[[], Any]) -> Any:
        with self._lock:
            if key not in self._cache:
                self._cache[key] = factory()
            return self._cache[key]

    def cached(self, key: str, factory: Callable[[], Any]) -> Any:
        """Memoise ``factory()`` under ``key`` until the next mutation."""
        return self._cached(key, factory)

    @property
    def adjacency(self) -> dict[str, list[tuple[NetworkEdge, str, str]]]:
        """node id -> [(edge, other node id, "out" | "in")] over every edge
        (parallel edges kept, unlike the NetworkX DiGraph)."""

        def build() -> dict[str, list[tuple[NetworkEdge, str, str]]]:
            adj: dict[str, list[tuple[NetworkEdge, str, str]]] = {}
            for e in self.edges:
                adj.setdefault(e.source_id, []).append((e, e.target_id, "out"))
                adj.setdefault(e.target_id, []).append((e, e.source_id, "in"))
            return adj

        return self._cached("adjacency", build)

    def invalidate(self) -> None:
        """Drop every derived index and bump :attr:`version`."""
        with self._lock:
            self._cache.clear()
            self.version += 1

    def cache_state(self) -> dict[str, bool]:
        with self._lock:
            keys = ("graph", "dependency_graph", "ontology", "centrality", "rag_entity")
            return {k: any(c == k or c.startswith(k + ":") for c in self._cache) for k in keys}

    # -- indexes ----------------------------------------------------------

    @property
    def by_id(self) -> dict[str, CloudAsset]:
        return self._cached("by_id", lambda: {a.id: a for a in self.assets})

    def _key_index(self) -> dict[str, str]:
        """Any identifier (id / ARN / name) -> asset id (first wins)."""

        def build() -> dict[str, str]:
            idx: dict[str, str] = {}
            for a in self.assets:
                for k in (a.id, a.arn, a.name):
                    if k:
                        idx.setdefault(k, a.id)
            return idx

        return self._cached("key_index", build)

    def find_asset(self, ref: str) -> CloudAsset | None:
        """Find by internal ID, ARN / resource ID, unique name, unique ARN
        tail (``DependencyGraph.find`` semantics), then case-insensitive
        unique name."""
        if not ref:
            return None
        by_id = self.by_id
        if ref in by_id:
            return by_id[ref]

        def build_lookup() -> dict[str, Any]:
            arn: dict[str, CloudAsset] = {}
            names: dict[str, list[CloudAsset]] = {}
            lower: dict[str, list[CloudAsset]] = {}
            tails: dict[str, list[CloudAsset]] = {}
            for a in self.assets:
                if a.arn:
                    arn.setdefault(a.arn, a)
                    for tail in ref_tails(a.arn):
                        tails.setdefault(tail, []).append(a)
                names.setdefault(a.name, []).append(a)
                lower.setdefault(a.name.lower(), []).append(a)
            return {"arn": arn, "names": names, "lower": lower, "tails": tails}

        lk = self._cached("lookup", build_lookup)
        if ref in lk["arn"]:
            return lk["arn"][ref]
        for table, key in (("names", ref), ("tails", ref), ("lower", ref.lower())):
            hits = lk[table].get(key, [])
            if len(hits) == 1:
                return hits[0]
        return None

    def suggest(self, ref: str, n: int = 5) -> list[str]:
        """Close matches for a reference that resolved to nothing."""
        if not ref:
            return []
        ref_l = ref.lower()
        sub = [a.name for a in self.assets if ref_l in a.name.lower()]
        sub += [a.arn for a in self.assets if a.arn and ref_l in a.arn.lower()]
        candidates = list(dict.fromkeys(a.name for a in self.assets))
        close = difflib.get_close_matches(ref, candidates, n=n, cutoff=0.5)
        out = list(dict.fromkeys([*sub[:n], *close]))
        return out[:n]

    def resolve_asset(self, ref: str) -> CloudAsset:
        """:meth:`find_asset` or raise a helpful :class:`ReferenceNotFoundError`."""
        asset = self.find_asset(ref)
        if asset is not None:
            return asset
        ref_l = (ref or "").lower()
        ambiguous = [a for a in self.assets if a.name == ref or a.name.lower() == ref_l]
        if len(ambiguous) > 1:
            ids = ", ".join(f"{a.id} ({a.asset_type.value}, {a.account_id})" for a in ambiguous[:5])
            raise ReferenceNotFoundError(
                f"Asset reference {ref!r} is ambiguous ({len(ambiguous)} assets share that name). "
                f"Use the id or ARN instead: {ids}",
                data={"ambiguous": [a.id for a in ambiguous[:20]]},
            )
        hints = self.suggest(ref)
        msg = f"No asset matches {ref!r} in dataset {self.name!r}."
        if hints:
            msg += " Did you mean: " + ", ".join(repr(h) for h in hints) + "?"
        msg += " Use find_assets(query=...) to search by name, ARN or tag."
        raise ReferenceNotFoundError(msg, data={"suggestions": hints})

    def asset_key(self, asset_id: str) -> str:
        """Stable identity of an asset across loads: its ARN, else its id."""
        a = self.by_id.get(asset_id)
        return (a.arn or a.id) if a else asset_id

    # -- findings ---------------------------------------------------------

    @property
    def findings_by_id(self) -> dict[str, Finding]:
        return self._cached("findings_by_id", lambda: {f.id: f for f in self.findings})

    def finding_asset_id(self, finding: Finding) -> str | None:
        idx = self._key_index()
        for k in (finding.resource_arn, finding.resource_id):
            if k and k in idx:
                return idx[k]
        return None

    @property
    def findings_by_asset(self) -> dict[str, list[Finding]]:
        """Asset id -> findings (matched on id / ARN / name like the mapper)."""

        def build() -> dict[str, list[Finding]]:
            out: dict[str, list[Finding]] = {}
            for f in self.findings:
                aid = self.finding_asset_id(f)
                if aid:
                    out.setdefault(aid, []).append(f)
            return out

        return self._cached("findings_by_asset", build)

    def open_findings(self, asset_id: str | None = None) -> list[Finding]:
        src = self.findings if asset_id is None else self.findings_by_asset.get(asset_id, [])
        return [f for f in src if not f.is_suppressed]

    def get_finding(self, finding_id: str) -> Finding:
        f = self.findings_by_id.get(finding_id)
        if f is not None:
            return f
        by_src = [x for x in self.findings if x.source_finding_id == finding_id]
        if len(by_src) == 1:
            return by_src[0]
        hints = [x.id for x in self.findings if finding_id and finding_id in x.id][:5]
        msg = f"No finding with id {finding_id!r} in dataset {self.name!r}."
        if hints:
            msg += " Did you mean: " + ", ".join(hints) + "?"
        msg += " Use list_findings to browse finding ids."
        raise ReferenceNotFoundError(msg, data={"suggestions": hints})

    # -- graph views ------------------------------------------------------

    @property
    def builder(self) -> Any:
        def build() -> Any:
            from cloudg.graph.builder import GraphBuilder

            b = GraphBuilder()
            b.build(self.assets, self.edges)
            return b

        return self._cached("graph", build)

    @property
    def graph(self) -> "nx.DiGraph":
        """NetworkX graph from :class:`GraphBuilder` (placeholders included)."""
        return self.builder.graph

    @property
    def flow_graph(self) -> "nx.DiGraph":
        """Directed graph for traffic / attack-path questions: the builder
        graph plus a reversed copy of every ``resource ATTACHED_TO
        security-group`` edge, because traffic a security group admits
        flows on to the resources attached to it."""

        def build() -> Any:
            g = self.graph.copy()
            sg_types = {AssetType.SECURITY_GROUP.value, AssetType.NSG.value}
            for u, v, d in list(self.graph.edges(data=True)):
                if d.get("edge_type") == EdgeType.ATTACHED_TO.value:
                    if self.graph.nodes[v].get("asset_type") in sg_types and not g.has_edge(v, u):
                        g.add_edge(v, u, **{**d, "derived": "sg_admits"})
            return g

        return self._cached("flow_graph", build)

    def dependency_graph(self, include_hierarchy: bool = False) -> "DependencyGraph":
        def build() -> Any:
            from cloudg.inventory.dependencies import DependencyGraph

            return DependencyGraph(self.assets, self.edges, include_hierarchy=include_hierarchy)

        return self._cached(f"dependency_graph:{include_hierarchy}", build)

    @property
    def reachability(self) -> Any:
        """:class:`ReachabilityAnalyzer` over a private copy of the graph
        (the analyser marks nodes in place)."""

        def build() -> Any:
            from cloudg.graph.reachability import ReachabilityAnalyzer

            return ReachabilityAnalyzer(self.graph.copy())

        return self._cached("reachability", build)

    def internet_reachable(self) -> set[str]:
        return self._cached(
            "internet_reachable", lambda: set(self.reachability.find_internet_exposed())
        )

    def centrality(self) -> dict[str, dict[str, float]]:
        return self._cached("centrality", lambda: self.builder.compute_centrality())

    def ontology(self) -> Any:
        """The RDF ontology, built on first use. Building it can be slow on big maps."""

        def build() -> Any:
            from cloudg.graph.ontology import CloudOntology

            onto = CloudOntology()
            onto.build(self.assets, self.edges, self.findings)
            return onto

        return self._cached("ontology", build)

    def has_ontology(self) -> bool:
        with self._lock:
            return "ontology" in self._cache

    def inventory_view(self) -> "InventoryResult":
        def build() -> Any:
            from cloudg.inventory.mapper_result import InventoryResult

            return InventoryResult(
                assets=self.assets,
                edges=self.edges,
                coverage=self.coverage,
                providers=self.providers,
                regions=self.regions,
                organization=self.organization,
                unresolved_references=self.unresolved_references,
            )

        return self._cached("inventory_view", build)

    def rag_chunks(self, chunk_type: str) -> list[Any]:
        def build() -> list[Any]:
            from cloudg.graph.rag_export import RAGExporter

            rag = RAGExporter()
            if chunk_type == "entity":
                return rag.export_entity_chunks(self.assets, self.edges, self.findings)
            if chunk_type == "community":
                return rag.export_community_chunks(self.graph, self.by_id, self.findings)
            return rag.export_relation_chunks(self.edges, self.by_id)

        return self._cached(f"rag_{chunk_type}", build)

    # -- summaries --------------------------------------------------------

    def summary(self) -> dict[str, Any]:
        def build() -> dict[str, Any]:
            inv = self.inventory_view().summary
            sev: dict[str, int] = {}
            for f in self.findings:
                if not f.is_suppressed:
                    sev[f.severity.value] = sev.get(f.severity.value, 0) + 1
            sev = dict(sorted(sev.items(), key=lambda kv: -SEVERITY_RANK.get(kv[0], -1)))
            out = {
                "dataset": self.name,
                "kind": self.kind,
                "source": self.source,
                "loaded_at": self.loaded_at,
                "version": self.version,
                "providers": self.providers,
                "total_assets": inv["total_assets"],
                "total_edges": inv["total_edges"],
                "total_findings": len(self.findings),
                "open_findings": sum(sev.values()),
                "suppressed_findings": sum(1 for f in self.findings if f.is_suppressed),
                "severity_breakdown": sev,
                "accounts": inv["accounts"],
                "regions": len(inv["assets_by_region"]),
                "internet_exposed": inv["internet_exposed"],
                "cross_account_edges": inv["cross_account_edges"],
                "unlinked_assets": inv["unlinked_assets"],
                "unresolved_references": inv["unresolved_references"],
                "compliance_frameworks": sorted({c.framework for c in self.compliance}),
                "assets_by_type": dict(list(inv["assets_by_type"].items())[:15]),
                "assets_by_provider": _count_by(self.assets, lambda a: a.provider.value),
                "edges_by_type": inv["edges_by_type"],
                "has_organization": bool(self.organization),
                "coverage_records": len(self.coverage),
            }
            if "organization" in inv:
                out["organization"] = inv["organization"]
            return out

        return self._cached("summary", build)

    # -- mutation ---------------------------------------------------------

    def add_findings(
        self, findings: Iterable[Finding], compliance: Iterable[ComplianceResult] = ()
    ) -> int:
        with self._lock:
            new = list(findings)
            self.findings.extend(new)
            self.compliance.extend(compliance)
            self.invalidate()
            return len(new)

    def replace_findings(
        self, findings: list[Finding], compliance: list[ComplianceResult] | None = None
    ) -> None:
        with self._lock:
            self.findings = list(findings)
            if compliance is not None:
                self.compliance = list(compliance)
            self.invalidate()

    def set_suppressed(
        self, finding_ids: Iterable[str], suppressed: bool, reason: str = ""
    ) -> dict[str, list[str]]:
        changed, unchanged, missing = [], [], []
        with self._lock:
            for fid in finding_ids:
                f = self.findings_by_id.get(fid)
                if f is None:
                    missing.append(fid)
                    continue
                if f.is_suppressed == suppressed:
                    unchanged.append(fid)
                else:
                    f.is_suppressed = suppressed
                    changed.append(fid)
                if suppressed:
                    self.suppression_reasons[fid] = reason
                else:
                    self.suppression_reasons.pop(fid, None)
            if changed:
                self.invalidate()
        return {"changed": changed, "unchanged": unchanged, "not_found": missing}

    def copy(self, name: str, kind: str = "snapshot") -> "Dataset":
        """Deep copy (models included) under a new name."""
        with self._lock:
            return Dataset(
                name=name,
                assets=[a.model_copy(deep=True) for a in self.assets],
                edges=[e.model_copy(deep=True) for e in self.edges],
                findings=[f.model_copy(deep=True) for f in self.findings],
                compliance=[c.model_copy(deep=True) for c in self.compliance],
                coverage=[c.model_copy(deep=True) for c in self.coverage],
                organization=copy.deepcopy(self.organization),
                unresolved_references=copy.deepcopy(self.unresolved_references),
                providers=list(self.providers),
                regions=copy.deepcopy(self.regions),
                source=f"snapshot of {self.name}",
                kind=kind,
                metadata={**copy.deepcopy(self.metadata), "snapshot_of": self.name},
                suppression_reasons=dict(self.suppression_reasons),
            )

    def describe(self) -> dict[str, Any]:
        """Compact listing entry."""
        return {
            "name": self.name,
            "kind": self.kind,
            "source": self.source,
            "loaded_at": self.loaded_at,
            "version": self.version,
            "providers": self.providers,
            "assets": len(self.assets),
            "edges": len(self.edges),
            "findings": len(self.findings),
            "compliance_results": len(self.compliance),
            "cached": self.cache_state(),
        }

    # -- constructors -----------------------------------------------------

    @classmethod
    def from_inventory(
        cls, result: "InventoryResult", name: str, source: str = "live", kind: str = "inventory"
    ) -> "Dataset":
        return cls(
            name=name,
            assets=list(result.assets),
            edges=list(result.edges),
            coverage=list(result.coverage),
            organization=result.organization,
            unresolved_references=list(result.unresolved_references),
            providers=list(result.providers),
            regions=dict(result.regions),
            source=source,
            kind=kind,
            metadata={"duration_ms": getattr(result, "duration_ms", 0)},
        )

    @classmethod
    def from_collection(cls, result: Any, name: str, source: str = "live") -> "Dataset":
        """From :class:`cloudg.api.CollectionResult`."""
        return cls(
            name=name,
            assets=list(result.assets),
            edges=list(result.edges),
            coverage=list(result.coverage),
            providers=list(result.providers_scanned),
            regions=dict(result.regions_scanned),
            source=source,
            kind="live",
            metadata={"duration_ms": result.duration_ms},
        )

    @classmethod
    def from_pipeline(cls, result: Any, name: str, source: str = "live") -> "Dataset":
        """From :class:`cloudg.api.PipelineResult` (``run_pipeline`` /
        ``run_from_reports``)."""
        sr = result.scan_result
        return cls(
            name=name,
            assets=list(result.assets or (sr.assets if sr else [])),
            edges=list(result.edges or (sr.edges if sr else [])),
            findings=list(result.findings),
            compliance=list(sr.compliance) if sr else [],
            coverage=list(result.coverage),
            providers=list(result.providers_scanned),
            regions=dict(result.regions_scanned),
            source=source,
            kind="live",
            metadata={
                "duration_ms": result.duration_ms,
                "errors": list(result.errors),
                "report_paths": {k: str(v) for k, v in result.report_paths.items()},
            },
        )

    @classmethod
    def from_scan_result(cls, sr: Any, name: str, source: str = "inline") -> "Dataset":
        return cls(
            name=name,
            assets=list(sr.assets),
            edges=list(sr.edges),
            findings=list(sr.findings),
            compliance=list(sr.compliance),
            source=source,
            kind="report",
        )


def _count_by(items: Iterable[Any], key: Callable[[Any], str]) -> dict[str, int]:
    out: dict[str, int] = {}
    for it in items:
        k = key(it)
        out[k] = out.get(k, 0) + 1
    return dict(sorted(out.items(), key=lambda kv: -kv[1]))


# ---------------------------------------------------------------------------
# Loading files
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


def detect_kind(path: Path) -> str:
    """Best-effort detection of what a file / directory holds."""
    if path.is_dir():
        if (path / "inventory-map.json").exists():
            return "inventory"
        if (path / "findings.json").exists():
            return "report"
        if list(path.rglob("scoutsuite_results*.js")):
            return "scoutsuite"
        if list(path.rglob("results_json.json")):
            return "checkov"
        raise InvalidArgumentsError(
            f"Cannot tell what {path} contains (no inventory-map.json or findings.json). "
            f"Pass kind= one of {', '.join(DATASET_KINDS[1:])}."
        )
    if path.suffix == ".js" or path.name.startswith("scoutsuite_results"):
        return "scoutsuite"
    try:
        text = path.read_text()
    except OSError as exc:
        raise InvalidArgumentsError(f"Cannot read {path}: {exc}") from None
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        # JSON Lines: Prowler ASFF / OCSF output
        first = text.strip().splitlines()[0] if text.strip() else ""
        try:
            record = json.loads(first)
        except (json.JSONDecodeError, IndexError):
            raise InvalidArgumentsError(f"{path} is not JSON.") from None
        if is_ocsf(record):
            raise _ocsf_error(path)
        return "prowler"
    return _detect_json_kind(data, path)


_OCSF_KEYS = {"finding_info", "class_uid", "category_uid", "type_uid", "severity_id"}


def is_ocsf(data: Any) -> bool:
    """Whether ``data`` (a record, or a list / wrapper of records) is OCSF
    (Prowler 4+ default output) rather than AWS Security Finding Format."""
    if isinstance(data, list):
        data = data[0] if data else None
    if not isinstance(data, dict):
        return False
    if "ProductArn" in data or "Findings" in data:
        return False
    return bool(_OCSF_KEYS & set(data))


def _ocsf_error(path: Path) -> InvalidArgumentsError:
    return InvalidArgumentsError(
        f"{path} is Prowler OCSF output, which cloudg cannot parse yet (its records would "
        "become placeholder findings). Re-run prowler with -M json-asff and load the ASFF "
        "file instead.",
        data={"format": "ocsf", "hint": "prowler <provider> -M json-asff"},
    )


def check_prowler_input(path: Path) -> None:
    """Refuse Prowler OCSF output (file, or the JSON files of a directory)
    before cloudg's ASFF-only parser turns it into junk findings."""
    files = sorted(path.rglob("*.json"))[:20] if path.is_dir() else [path]
    for f in files:
        try:
            text = f.read_text()
        except OSError:
            continue
        stripped = text.strip()
        if not stripped:
            continue
        try:
            data = json.loads(stripped)
        except json.JSONDecodeError:
            try:
                data = json.loads(stripped.splitlines()[0])
            except json.JSONDecodeError:
                continue
        if is_ocsf(data):
            raise _ocsf_error(f)


def _detect_json_kind(data: Any, path: Path) -> str:
    if isinstance(data, dict):
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
    if isinstance(data, list) and data and isinstance(data[0], dict):
        first = data[0]
        if "check_type" in first:
            return "checkov"
        if is_ocsf(first):
            raise _ocsf_error(path)
        if first.keys() & {"ProductArn", "SchemaVersion"}:
            return "prowler"
        if first.keys() & {"severity", "title", "resource_id"}:
            return "generic"
    raise InvalidArgumentsError(
        f"Unrecognised content in {path}. Pass kind= one of {', '.join(DATASET_KINDS[1:])}."
    )


def load_dataset_file(path: Path, name: str, kind: str = "auto", normalise: bool = True) -> Dataset:
    """Load ``path`` into a :class:`Dataset` (no path-safety checks here;
    :meth:`Workspace.load` does those)."""
    if kind not in DATASET_KINDS:
        raise InvalidArgumentsError(
            f"Unknown kind {kind!r}. Use one of: {', '.join(DATASET_KINDS)}")
    if not path.exists():
        raise InvalidArgumentsError(f"Path does not exist: {path}")
    kind = detect_kind(path) if kind == "auto" else kind

    if kind == "inventory":
        from cloudg.inventory.mapper_result import InventoryResult

        try:
            inv = InventoryResult.load(path)
        except (OSError, json.JSONDecodeError, ValueError) as exc:
            raise InvalidArgumentsError(f"Cannot load inventory map {path}: {exc}") from None
        ds = Dataset.from_inventory(inv, name, source=str(path), kind="inventory")
        report = (path if path.is_dir() else path.parent) / "findings.json"
        if report.exists():
            other = _load_json_dataset(report, name, "report")
            ds.findings, ds.compliance = other.findings, other.compliance
            ds.metadata["findings_source"] = str(report)
        return ds
    if kind in ("report", "generic"):
        target = path / "findings.json" if path.is_dir() else path
        return _load_json_dataset(target, name, kind)

    # Native scanner output
    from cloudg.ingest import parse_report

    if kind == "prowler":
        check_prowler_input(path)
    try:
        findings = parse_report(kind, path)
    except (ValueError, FileNotFoundError) as exc:
        raise InvalidArgumentsError(str(exc)) from None
    ds = Dataset(name=name, findings=findings, source=str(path), kind=kind)
    if normalise and findings:
        from cloudg.normaliser import FindingsNormaliser

        sr = FindingsNormaliser().normalise(findings)
        ds.findings, ds.compliance = sr.findings, sr.compliance
    return ds


def _load_json_dataset(path: Path, name: str, kind: str) -> Dataset:
    try:
        data = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        raise InvalidArgumentsError(f"Cannot read JSON from {path}: {exc}") from None
    if isinstance(data, list):
        data = {"findings": data}
    if not isinstance(data, dict):
        raise InvalidArgumentsError(f"{path} does not hold a JSON object or list.")
    try:
        assets = _parse_assets(data.get("assets", []) or [])
        edges = [NetworkEdge.model_validate(e) for e in data.get("edges", []) or []]
        if not edges and isinstance(data.get("graph"), dict):
            edges = _edges_from_d3(data["graph"])
        findings = _parse_findings(data.get("findings", []) or [])
        compliance = [ComplianceResult.model_validate(c) for c in data.get("compliance", []) or []]
    except Exception as exc:  # pydantic ValidationError and friends
        raise InvalidArgumentsError(f"{path} does not match the cloudg schema: {exc}") from None
    meta = data.get("metadata") if isinstance(data.get("metadata"), dict) else {}
    return Dataset(
        name=name,
        assets=assets,
        edges=edges,
        findings=findings,
        compliance=compliance,
        unresolved_references=list(data.get("unresolved_references", []) or []),
        providers=list(data.get("providers", []) or []),
        regions=dict(data.get("regions", {}) or {}),
        organization=data.get("organization"),
        source=str(path),
        kind=kind,
        metadata=dict(meta),
    )


# ---------------------------------------------------------------------------
# Diff
# ---------------------------------------------------------------------------


def _asset_fingerprint(a: CloudAsset) -> dict[str, Any]:
    return {
        "name": a.name,
        "type": a.asset_type.value,
        "region": a.region,
        "account_id": a.account_id,
        "tags": a.tags,
        "internet_exposed": a.is_internet_exposed,
        "metadata_hash": hashlib.sha256(
            json.dumps(a.metadata, sort_keys=True, default=str).encode()
        ).hexdigest()[:16],
    }


def diff_datasets(base: Dataset, target: Dataset, limit: int = 50) -> dict[str, Any]:
    """What changed from ``base`` to ``target``. Assets are matched on ARN
    (else id), edges on (source, target, type, relationship) over those
    keys, findings on (source tool, check / title, resource)."""

    def asset_map(ds: Dataset) -> dict[str, CloudAsset]:
        return {(a.arn or a.id): a for a in ds.assets}

    def brief(a: CloudAsset) -> dict[str, Any]:
        return {
            "id": a.id,
            "key": a.arn or a.id,
            "name": a.name,
            "type": a.asset_type.value,
            "account_id": a.account_id,
            "region": a.region,
        }

    ba, ta = asset_map(base), asset_map(target)
    added = [brief(ta[k]) for k in sorted(ta.keys() - ba.keys())]
    removed = [brief(ba[k]) for k in sorted(ba.keys() - ta.keys())]
    changed = []
    for k in sorted(ba.keys() & ta.keys()):
        fb, ft = _asset_fingerprint(ba[k]), _asset_fingerprint(ta[k])
        if fb != ft:
            fields = sorted(f for f in fb if fb[f] != ft[f])
            entry = {**brief(ta[k]), "changed_fields": fields}
            if "internet_exposed" in fields:
                entry["internet_exposed"] = {
                    "before": fb["internet_exposed"],
                    "after": ft["internet_exposed"],
                }
            changed.append(entry)

    def edge_keys(ds: Dataset) -> dict[tuple, dict[str, Any]]:
        out = {}
        for e in ds.edges:
            key = (ds.asset_key(e.source_id), ds.asset_key(e.target_id), e.edge_type.value,
                   e.relationship or "")
            out[key] = {"source": key[0], "target": key[1], "edge_type": key[2],
                        "relationship": e.relationship}
        return out

    be, te = edge_keys(base), edge_keys(target)

    def finding_keys(ds: Dataset) -> dict[tuple, dict[str, Any]]:
        out = {}
        for f in ds.findings:
            aid = ds.finding_asset_id(f)
            res = ds.asset_key(aid) if aid else (f.resource_arn or f.resource_id)
            key = (f.source_tool, f.source_finding_id or f.title, res)
            out[key] = {"id": f.id, "title": f.title, "severity": f.severity.value,
                        "resource": res, "source_tool": f.source_tool}
        return out

    bf, tf = finding_keys(base), finding_keys(target)
    new_f = [tf[k] for k in sorted(tf.keys() - bf.keys(), key=str)]
    resolved_f = [bf[k] for k in sorted(bf.keys() - tf.keys(), key=str)]
    sev_changed = [
        {**tf[k], "severity_before": bf[k]["severity"]}
        for k in sorted(bf.keys() & tf.keys(), key=str)
        if bf[k]["severity"] != tf[k]["severity"]
    ]

    def section(items: list[Any]) -> dict[str, Any]:
        return {"count": len(items), "items": items[:limit], "truncated": len(items) > limit}

    newly_exposed = [
        c for c in changed if isinstance(c.get("internet_exposed"), dict)
        and c["internet_exposed"]["after"]
    ] + [a for a in added if ta[a["key"]].is_internet_exposed]

    return {
        "base": base.name,
        "target": target.name,
        "assets": {
            "added": section(added),
            "removed": section(removed),
            "changed": section(changed),
            "unchanged": len(ba.keys() & ta.keys()) - len(changed),
        },
        "edges": {
            "added": section([te[k] for k in sorted(te.keys() - be.keys())]),
            "removed": section([be[k] for k in sorted(be.keys() - te.keys())]),
        },
        "findings": {
            "new": section(new_f),
            "resolved": section(resolved_f),
            "severity_changed": section(sev_changed),
        },
        "newly_internet_exposed": section(newly_exposed),
    }


# ---------------------------------------------------------------------------
# Workspace
# ---------------------------------------------------------------------------


class Workspace:
    """Named datasets, the active selection, path safety and change hooks.

    Args:
        config: cloudg configuration used by live tools (collection,
            scanners) and for default directories. ``CloudGConfig()`` when
            omitted.
        allowed_roots: Directories tools may read from / write to. Default:
            ``$CLOUDG_MCP_ALLOWED_ROOTS`` (``os.pathsep``-separated) or the
            current directory plus ``config.report.output_dir``.
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
            env = os.environ.get("CLOUDG_MCP_ALLOWED_ROOTS")
            allowed_roots = (
                [p for p in env.split(os.pathsep) if p] if env else [Path.cwd(), report_dir]
            )
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
            except Exception:
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
                known = ", ".join(self._datasets) or "none"
                raise NoDatasetError(f"No dataset named {name!r}. Loaded datasets: {known}.")
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
        if not _NAME_RE.match(name or ""):
            raise InvalidArgumentsError(
                f"Invalid dataset name {name!r}: use 1-64 letters, digits, '.', '_' or '-'."
            )
        if not replace and name in self._datasets:
            raise InvalidArgumentsError(
                f"A dataset named {name!r} already exists. Choose another name (for example "
                f"{self.unique_name(name)!r}), or pass replace=true to overwrite it.",
                data={"existing": name, "suggested": self.unique_name(name)},
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
        with self._lock:
            return {
                "active_dataset": self._active,
                "datasets": [d.describe() for d in self._datasets.values()],
                "allowed_roots": [str(r) for r in self.allowed_roots],
                "output_dir": str(self.output_root),
                "providers_configured": list(getattr(self.config, "providers", []) or []),
            }
