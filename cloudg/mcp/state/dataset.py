"""The :class:`Dataset`: one loaded view of cloud infrastructure plus its
lazily built, cached analyses."""

from __future__ import annotations

import copy
import difflib
import threading
import uuid
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Callable, Iterable

from cloudg.mcp.state.base import (
    SEVERITY_RANK,
    ReferenceNotFoundError,
    count_by,
    matches_note,
    now_iso,
    ref_tails,
)
from cloudg.schema.models import (
    AssetType,
    CloudAsset,
    ComplianceResult,
    EdgeType,
    Finding,
    NetworkEdge,
)

if TYPE_CHECKING:  # pragma: no cover
    import networkx as nx

    from cloudg.coverage import CollectionCoverage
    from cloudg.inventory.dependencies import DependencyGraph
    from cloudg.inventory.mapper_result import InventoryResult

_CACHE_STATE_KEYS = ("graph", "dependency_graph", "ontology", "centrality", "rag_entity")


def _asset_hint(a: CloudAsset, dataset: str) -> dict[str, Any]:
    """A suggestion entry: keys tell the output pipeline what each value is."""
    return {
        "id": a.id,
        "name": a.name,
        "arn": a.arn,
        "type": a.asset_type.value,
        "account_id": a.account_id,
        "dataset": dataset,
    }


@dataclass
class Dataset:
    """One loaded inventory / findings view plus lazily-built analyses.

    Derived views are built outside the dataset lock: each cache key has its
    own build lock, so a slow build (the ontology of a big map) only makes
    callers of that same key wait. A build that races a mutation is
    returned to its caller but not cached.
    """

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
    loaded_at: str = field(default_factory=now_iso)
    metadata: dict[str, Any] = field(default_factory=dict)
    suppression_reasons: dict[str, str] = field(default_factory=dict)
    version: int = 0

    def __post_init__(self) -> None:
        self._lock = threading.RLock()
        self._build_locks: dict[str, threading.RLock] = {}
        self._cache: dict[str, Any] = {}
        # Distinguishes two datasets loaded under the same name, so cursors
        # issued for one are refused by its replacement.
        self.instance_id = uuid.uuid4().hex
        if not self.providers:
            self.providers = sorted({a.provider.value.lower() for a in self.assets})

    # -- cache plumbing -------------------------------------------------

    def _cached(self, key: str, factory: Callable[[], Any]) -> Any:
        with self._lock:
            if key in self._cache:
                return self._cache[key]
            build_lock = self._build_locks.setdefault(key, threading.RLock())
        with build_lock:
            with self._lock:
                if key in self._cache:
                    return self._cache[key]
                version = self.version
            value = factory()
            with self._lock:
                if self.version == version:
                    self._cache[key] = value
            return value

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
            keys = list(self._cache)
        return {k: any(c == k or c.startswith(k + ":") for c in keys) for k in _CACHE_STATE_KEYS}

    # -- indexes ----------------------------------------------------------

    @property
    def by_id(self) -> dict[str, CloudAsset]:
        return self._cached("by_id", lambda: {a.id: a for a in self.assets})

    def _lookup_tables(self) -> dict[str, Any]:
        def build() -> dict[str, Any]:
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

        return self._cached("lookup", build)

    def find_asset(self, ref: str) -> CloudAsset | None:
        """Find by internal ID, ARN / resource ID (first asset wins), unique
        name, unique ARN tail (see :func:`ref_tails`), then unique
        case-insensitive name. Shared names and tails never match."""
        if not ref:
            return None
        hit = self.by_id.get(ref)
        if hit is not None:
            return hit
        lk = self._lookup_tables()
        if ref in lk["arn"]:
            return lk["arn"][ref]
        for table, key in (("names", ref), ("tails", ref), ("lower", ref.lower())):
            hits = lk[table].get(key, [])
            if len(hits) == 1:
                return hits[0]
        return None

    def suggest_assets(self, ref: str, n: int = 5) -> list[CloudAsset]:
        """Assets whose name or ARN contains ``ref``, then close name matches."""
        if not ref:
            return []
        ref_l = ref.lower()
        out: dict[str, CloudAsset] = {}
        for a in self.assets:
            if ref_l in a.name.lower() or (a.arn and ref_l in a.arn.lower()):
                out.setdefault(a.id, a)
            if len(out) >= n:
                return list(out.values())
        first_by_name: dict[str, CloudAsset] = {}
        for a in self.assets:
            first_by_name.setdefault(a.name, a)
        for name in difflib.get_close_matches(ref, list(first_by_name), n=n, cutoff=0.5):
            a = first_by_name[name]
            out.setdefault(a.id, a)
        return list(out.values())[:n]

    def suggest(self, ref: str, n: int = 5) -> list[str]:
        """Close matches (names / ARNs) for a reference that resolved to nothing."""
        ref_l = (ref or "").lower()
        return [
            a.arn if (a.arn and ref_l in a.arn.lower() and ref_l not in a.name.lower()) else a.name
            for a in self.suggest_assets(ref, n)
        ]

    def resolve_asset(self, ref: str) -> CloudAsset:
        """:meth:`find_asset` or raise a helpful :class:`ReferenceNotFoundError`
        whose ``data`` carries the reference and the candidate assets."""
        asset = self.find_asset(ref)
        if asset is not None:
            return asset
        ref_l = (ref or "").lower()
        ambiguous = [a for a in self.assets if a.name == ref or a.name.lower() == ref_l]
        if len(ambiguous) > 1:
            raise ReferenceNotFoundError(
                f"The asset reference is ambiguous: {len(ambiguous)} assets share that name. "
                "Use the id or ARN of one of the candidates in the error data instead.",
                data={
                    "value": ref,
                    "dataset": self.name,
                    "ambiguous": [a.id for a in ambiguous[:20]],
                    "candidates": [_asset_hint(a, self.name) for a in ambiguous[:5]],
                },
            )
        hints = [_asset_hint(a, self.name) for a in self.suggest_assets(ref)]
        msg = "No asset matches the reference in this dataset." + matches_note(len(hints))
        msg += " Use find_assets(query=...) to search by name, ARN or tag."
        raise ReferenceNotFoundError(
            msg, data={"value": ref, "dataset": self.name, "suggestions": hints}
        )

    def asset_key(self, asset_id: str) -> str:
        """Stable identity of an asset across loads: its ARN, else its id."""
        a = self.by_id.get(asset_id)
        return (a.arn or a.id) if a else asset_id

    # -- findings ---------------------------------------------------------

    @property
    def findings_by_id(self) -> dict[str, Finding]:
        return self._cached("findings_by_id", lambda: {f.id: f for f in self.findings})

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
        hints = [
            {"finding_id": x.id, "dataset": self.name}
            for x in self.findings
            if finding_id and finding_id in x.id
        ][:5]
        msg = "No finding with that id in this dataset." + matches_note(len(hints))
        msg += " Use list_findings to browse finding ids."
        raise ReferenceNotFoundError(
            msg, data={"value": finding_id, "dataset": self.name, "suggestions": hints}
        )

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

    def _build_summary(self) -> dict[str, Any]:
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
            "assets_by_provider": count_by(self.assets, lambda a: a.provider.value),
            "edges_by_type": inv["edges_by_type"],
            "has_organization": bool(self.organization),
            "coverage_records": len(self.coverage),
        }
        if "organization" in inv:
            out["organization"] = inv["organization"]
        return out

    def summary(self) -> dict[str, Any]:
        return self._cached("summary", self._build_summary)

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

    def _set_one_suppressed(self, fid: str, suppressed: bool, reason: str) -> str:
        f = self.findings_by_id.get(fid)
        if f is None:
            return "not_found"
        state = "unchanged" if f.is_suppressed == suppressed else "changed"
        f.is_suppressed = suppressed
        if suppressed:
            self.suppression_reasons[fid] = reason
        else:
            self.suppression_reasons.pop(fid, None)
        return state

    def set_suppressed(
        self, finding_ids: Iterable[str], suppressed: bool, reason: str = ""
    ) -> dict[str, list[str]]:
        out: dict[str, list[str]] = {"changed": [], "unchanged": [], "not_found": []}
        with self._lock:
            for fid in finding_ids:
                out[self._set_one_suppressed(fid, suppressed, reason)].append(fid)
            if out["changed"]:
                self.invalidate()
        return out

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
