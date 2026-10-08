"""The inventory map produced by :class:`~cloudg.inventory.mapper.InventoryMapper`.

:class:`InventoryResult` holds the linked assets and edges, summarises them,
runs the interdependency analysis, and persists / reloads the map. It is
re-exported from :mod:`cloudg.inventory.mapper`.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from cloudg.coverage import CollectionCoverage
from cloudg.schema.models import AssetType, CloudAsset, NetworkEdge

_HIERARCHY_TYPES = {AssetType.ORGANIZATION, AssetType.ORG_UNIT, AssetType.CLOUD_ACCOUNT}

# GCP identifiers, anchored so ".googleapis.com" cannot match mid-string:
# full resource name "//compute.googleapis.com/projects/..." and
# asset type "compute.googleapis.com/Instance"
_GCP_RESOURCE_NAME_RE = re.compile(r"^//([a-z0-9-]+)\.googleapis\.com/")
_GCP_ASSET_TYPE_RE = re.compile(r"^([a-z0-9-]+)\.googleapis\.com/")


def _count(counter: dict[str, int], key: str) -> None:
    counter[key] = counter.get(key, 0) + 1


def _by_count(counter: dict[str, int]) -> dict[str, int]:
    """Counter sorted by descending count (ties keep insertion order)."""
    return dict(sorted(counter.items(), key=lambda x: -x[1]))


def _asset_counts(assets: list[CloudAsset]) -> tuple[dict[str, int], ...]:
    """Asset counts by type, region, account and service."""
    by_type: dict[str, int] = {}
    by_region: dict[str, int] = {}
    by_account: dict[str, int] = {}
    by_service: dict[str, int] = {}
    for a in assets:
        _count(by_type, a.asset_type.value)
        _count(by_region, a.region)
        _count(by_account, a.account_id or "unknown")
        _count(by_service, _service_of(a))
    return by_type, by_region, by_account, by_service


def _is_cross_account(s: CloudAsset | None, t: CloudAsset | None) -> bool:
    """Whether an edge joins two accounts (hierarchy-to-hierarchy excluded)."""
    if not (s and t and s.account_id and t.account_id and s.account_id != t.account_id):
        return False
    return not (s.asset_type in _HIERARCHY_TYPES and t.asset_type in _HIERARCHY_TYPES)


def _edge_stats(
    assets: list[CloudAsset], edges: list[NetworkEdge]
) -> tuple[dict[str, int], dict[str, int], set[str], int]:
    """Edge counts by type / relationship, linked asset ids and the number
    of cross-account edges (hierarchy edges count by type only)."""
    by_id = {a.id: a for a in assets}
    edge_types: dict[str, int] = {}
    relationships: dict[str, int] = {}
    linked_ids: set[str] = set()
    cross_account = 0
    for e in edges:
        _count(edge_types, e.edge_type.value)
        if e.relationship:
            _count(relationships, e.relationship)
        if (e.properties or {}).get("hierarchy"):
            continue
        linked_ids.add(e.source_id)
        linked_ids.add(e.target_id)
        if _is_cross_account(by_id.get(e.source_id), by_id.get(e.target_id)):
            cross_account += 1
    return edge_types, relationships, linked_ids, cross_account


def _organization_summary(org: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": org.get("organization_id"),
        "accounts": len(org.get("accounts", {})),
        "ous": len(org.get("ous", {})),
        "control_tower": org.get("control_tower_enabled", False),
        "governed_regions": org.get("governed_regions", []),
    }


def _write_json(path: Path, data: Any) -> Path:
    with open(path, "w") as f:
        json.dump(data, f, indent=2, default=str)
    return path


@dataclass
class InventoryResult:
    """Complete inventory map — assets, interconnections, and summary."""

    assets: list[CloudAsset] = field(default_factory=list)
    edges: list[NetworkEdge] = field(default_factory=list)
    coverage: list[CollectionCoverage] = field(default_factory=list)
    providers: list[str] = field(default_factory=list)
    regions: dict[str, list[str]] = field(default_factory=dict)
    duration_ms: int = 0
    organization: dict[str, Any] | None = None
    unresolved_references: list[dict[str, Any]] = field(default_factory=list)
    #: Throttling telemetry of the run (``cloudg.resilience`` summary: totals,
    #: per-scope counters, human-readable messages, skipped scopes); None when
    #: no API pushed back
    throttling: dict[str, Any] | None = None

    @property
    def summary(self) -> dict[str, Any]:
        by_type, by_region, by_account, by_service = _asset_counts(self.assets)
        edge_types, relationships, linked_ids, cross_account = _edge_stats(self.assets, self.edges)
        orphans = sum(
            1
            for a in self.assets
            if a.id not in linked_ids and a.asset_type not in _HIERARCHY_TYPES
        )
        security_gaps = sum(
            1
            for a in self.assets
            if a.metadata.get("security_service") and a.metadata.get("enabled") is False
        )

        out = {
            "total_assets": len(self.assets),
            "total_edges": len(self.edges),
            "providers": self.providers,
            "assets_by_type": _by_count(by_type),
            "assets_by_service": _by_count(by_service),
            "assets_by_region": by_region,
            "assets_by_account": by_account,
            "edges_by_type": edge_types,
            "edges_by_relationship": _by_count(relationships),
            "unlinked_assets": orphans,
            "internet_exposed": sum(1 for a in self.assets if a.is_internet_exposed),
            "accounts": len([k for k in by_account if k != "unknown"]),
            "cross_account_edges": cross_account,
            "external_accounts": sum(
                1
                for a in self.assets
                if a.asset_type == AssetType.CLOUD_ACCOUNT and a.metadata.get("external")
            ),
            "security_service_gaps": security_gaps,
            "unresolved_references": len(self.unresolved_references),
        }
        if self.organization:
            out["organization"] = _organization_summary(self.organization)
        if self.throttling:
            out["throttling"] = {
                "totals": self.throttling.get("totals", {}),
                "messages": self.throttling.get("messages", []),
                "skipped": self.throttling.get("skipped", {}),
            }
        return out

    # ------------------------------------------------------------------
    # Analysis
    # ------------------------------------------------------------------

    def dependency_graph(self, include_hierarchy: bool = False) -> Any:
        """A :class:`~cloudg.inventory.dependencies.DependencyGraph` view."""
        from cloudg.inventory.dependencies import DependencyGraph

        return DependencyGraph(self.assets, self.edges, include_hierarchy=include_hierarchy)

    def analysis(self, top: int = 25) -> dict[str, Any]:
        """Interdependency and coverage analysis of the whole map."""
        from cloudg.inventory.dependencies import cross_account_edges, security_coverage

        graph = self.dependency_graph()
        return {
            "shared_dependencies": graph.shared_dependencies(top),
            "largest_blast_radius": graph.blast_radius(top=top),
            "cross_account_edges": cross_account_edges(self.assets, self.edges),
            "security_coverage": security_coverage(self.assets, self.edges),
            "unresolved_references": self.unresolved_references,
        }

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------

    def export(self, output_dir: str | Path) -> dict[str, Path]:
        """Write the inventory map to disk.

        Produces:
        - ``inventory-map.json``: assets + edges + summary (self-contained)
        - ``inventory-map.graphml``: the interconnection graph
        - ``inventory-graph.json``: D3-compatible graph for viewers
        - ``inventory-dependencies.json``: shared dependencies, blast radius,
          cross-account edges, security coverage
        - ``inventory-organization.json``: the org / Control Tower topology
          (only when the organization was mapped)
        """
        out = Path(output_dir)
        out.mkdir(parents=True, exist_ok=True)
        paths: dict[str, Path] = {}

        paths["map"] = _write_json(
            out / "inventory-map.json",
            {
                "summary": self.summary,
                "providers": self.providers,
                "regions": self.regions,
                "assets": [a.model_dump(mode="json") for a in self.assets],
                "edges": [e.model_dump(mode="json") for e in self.edges],
                "unresolved_references": self.unresolved_references,
                **({"throttling": self.throttling} if self.throttling else {}),
            },
        )

        from cloudg.graph.builder import GraphBuilder

        builder = GraphBuilder()
        builder.build(self.assets, self.edges)
        paths["graphml"] = builder.save_graphml(out / "inventory-map.graphml")
        paths["graph"] = _write_json(out / "inventory-graph.json", builder.to_d3_json())
        paths["dependencies"] = _write_json(out / "inventory-dependencies.json", self.analysis())
        if self.organization:
            paths["organization"] = _write_json(
                out / "inventory-organization.json", self.organization
            )
        return paths

    @classmethod
    def load(cls, path: str | Path) -> "InventoryResult":
        """Load an ``inventory-map.json`` written by :meth:`export`
        (or the directory containing it)."""
        p = Path(path)
        if p.is_dir():
            p = p / "inventory-map.json"
        with open(p) as f:
            data = json.load(f)
        assets = []
        for raw in data.get("assets", []):
            raw = {k: v for k, v in raw.items() if k != "display_id"}
            assets.append(CloudAsset.model_validate(raw))
        edges = [NetworkEdge.model_validate(e) for e in data.get("edges", [])]
        org = None
        org_path = p.parent / "inventory-organization.json"
        if org_path.exists():
            with open(org_path) as f:
                org = json.load(f)
        return cls(
            assets=assets,
            edges=edges,
            providers=data.get("providers") or data.get("summary", {}).get("providers", []),
            regions=data.get("regions", {}),
            organization=org,
            unresolved_references=data.get("unresolved_references", []),
            throttling=data.get("throttling"),
        )


def _azure_service(asset: CloudAsset, arn: str) -> str:
    """Service of an Azure resource: its provider namespace, lower-cased."""
    rtype = asset.metadata.get("resource_type") or ""
    if rtype:
        return rtype.split("/")[0].lower()
    lowered = arn.lower()
    if "/providers/" in lowered:
        return lowered.split("/providers/", 1)[1].split("/", 1)[0]
    return "microsoft.resources"


def _service_of(asset: CloudAsset) -> str:
    """Cloud service an asset belongs to, derived from its identifier."""
    arn = asset.arn or ""
    if arn.startswith("arn:"):
        parts = arn.split(":", 3)
        return parts[2] if len(parts) > 2 else "unknown"
    if arn.startswith(("k8s://", "k8s-gke://")):
        return "kubernetes"
    if arn.startswith("gcp-principal:"):
        return "iam"
    if arn.startswith("entra:"):
        return "entra"
    if arn.startswith("cloudg:"):
        parts = arn.split(":")
        return parts[2] if len(parts) > 2 else "unknown"
    if arn.startswith("/subscriptions/"):
        return _azure_service(asset, arn)
    gcp_name = _GCP_RESOURCE_NAME_RE.match(arn)
    if gcp_name:
        return gcp_name.group(1)
    gcp_type = _GCP_ASSET_TYPE_RE.match(asset.metadata.get("gcp_asset_type", ""))
    if gcp_type:
        return gcp_type.group(1)
    return "unknown"
