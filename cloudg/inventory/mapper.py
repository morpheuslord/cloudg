"""Inventory mapper — scanner-independent infrastructure mapping.

Orchestrates deep collection across providers, accounts and regions, links
every asset into an interconnected map, and produces exportable artifacts.
Runs **no** security scanner: this is a pure inventory function of cloudg.

A mapping run:

1. AWS Organizations / Control Tower discovery (``aws.organization``):
   the OU tree, every member account, SCPs, the landing zone, governed
   regions and enabled controls; collection then fans out to every
   selected account by assuming the member role there.
2. Deep collection per account x region (global services once per
   account), including containers, Kubernetes workloads, serverless,
   integration, data, DNS, deployment and security services.
3. Deduplication of anything seen twice (same ARN from several regions or
   collectors), merging the relationships each copy declared.
4. Linking: typed relationship edges, scoped identifier resolution, and
   placeholder nodes for accounts referenced but not mapped.
5. Account hierarchy: account nodes containing their top-level resources,
   under the OU tree when the organization was mapped.
6. Analysis: shared dependencies, blast radius, cross-account edges,
   security service coverage.

Scanner findings produced elsewhere (a `cloudg run`, `cloudg ingest`, or
any `CloudGEngine.scan()`) can be merged in afterwards to overlay the
inventory with risk — producing an asset map (asset → findings) and a
compliance map (framework → affected assets).

Usage (programmatic):

    from cloudg.config import CloudGConfig
    from cloudg.inventory import InventoryMapper

    mapper = InventoryMapper(CloudGConfig(providers=["aws"]))
    result = await mapper.map_inventory()
    result.export("./reports")

    # interdependency questions
    graph = result.dependency_graph()
    role = graph.find("arn:aws:iam::123456789012:role/app")
    impact = graph.dependents(role.id)

    # later, overlay scanner findings
    asset_map = mapper.build_asset_map(result, findings)
    compliance_map = mapper.build_compliance_map(result, findings)
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from cloudg.config import CloudGConfig
from cloudg.coverage import CollectionCoverage, ServiceStatus
from cloudg.schema.models import (
    AssetType,
    CloudAsset,
    CloudProvider,
    EdgeType,
    Finding,
    NetworkEdge,
)

logger = logging.getLogger(__name__)

_HIERARCHY_TYPES = {AssetType.ORGANIZATION, AssetType.ORG_UNIT, AssetType.CLOUD_ACCOUNT}


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

    @property
    def summary(self) -> dict[str, Any]:
        by_type: dict[str, int] = {}
        by_region: dict[str, int] = {}
        by_account: dict[str, int] = {}
        by_service: dict[str, int] = {}
        by_id = {a.id: a for a in self.assets}
        for a in self.assets:
            by_type[a.asset_type.value] = by_type.get(a.asset_type.value, 0) + 1
            by_region[a.region] = by_region.get(a.region, 0) + 1
            acct = a.account_id or "unknown"
            by_account[acct] = by_account.get(acct, 0) + 1
            svc = _service_of(a)
            by_service[svc] = by_service.get(svc, 0) + 1

        edge_types: dict[str, int] = {}
        relationships: dict[str, int] = {}
        linked_ids: set[str] = set()
        cross_account = 0
        for e in self.edges:
            edge_types[e.edge_type.value] = edge_types.get(e.edge_type.value, 0) + 1
            if e.relationship:
                relationships[e.relationship] = relationships.get(e.relationship, 0) + 1
            if (e.properties or {}).get("hierarchy"):
                continue
            linked_ids.add(e.source_id)
            linked_ids.add(e.target_id)
            s, t = by_id.get(e.source_id), by_id.get(e.target_id)
            if s and t and s.account_id and t.account_id and s.account_id != t.account_id:
                if not (s.asset_type in _HIERARCHY_TYPES and t.asset_type in _HIERARCHY_TYPES):
                    cross_account += 1
        orphans = [
            a for a in self.assets if a.id not in linked_ids and a.asset_type not in _HIERARCHY_TYPES
        ]
        security_gaps = sum(
            1 for a in self.assets
            if a.metadata.get("security_service") and a.metadata.get("enabled") is False
        )

        out = {
            "total_assets": len(self.assets),
            "total_edges": len(self.edges),
            "providers": self.providers,
            "assets_by_type": dict(sorted(by_type.items(), key=lambda x: -x[1])),
            "assets_by_service": dict(sorted(by_service.items(), key=lambda x: -x[1])),
            "assets_by_region": by_region,
            "assets_by_account": by_account,
            "edges_by_type": edge_types,
            "edges_by_relationship": dict(sorted(relationships.items(), key=lambda x: -x[1])),
            "unlinked_assets": len(orphans),
            "internet_exposed": sum(1 for a in self.assets if a.is_internet_exposed),
            "accounts": len([k for k in by_account if k != "unknown"]),
            "cross_account_edges": cross_account,
            "external_accounts": sum(
                1 for a in self.assets
                if a.asset_type == AssetType.CLOUD_ACCOUNT and a.metadata.get("external")
            ),
            "security_service_gaps": security_gaps,
            "unresolved_references": len(self.unresolved_references),
        }
        if self.organization:
            out["organization"] = {
                "id": self.organization.get("organization_id"),
                "accounts": len(self.organization.get("accounts", {})),
                "ous": len(self.organization.get("ous", {})),
                "control_tower": self.organization.get("control_tower_enabled", False),
                "governed_regions": self.organization.get("governed_regions", []),
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

        map_path = out / "inventory-map.json"
        with open(map_path, "w") as f:
            json.dump(
                {
                    "summary": self.summary,
                    "providers": self.providers,
                    "regions": self.regions,
                    "assets": [a.model_dump(mode="json") for a in self.assets],
                    "edges": [e.model_dump(mode="json") for e in self.edges],
                    "unresolved_references": self.unresolved_references,
                },
                f,
                indent=2,
                default=str,
            )
        paths["map"] = map_path

        from cloudg.graph.builder import GraphBuilder

        builder = GraphBuilder()
        builder.build(self.assets, self.edges)
        paths["graphml"] = builder.save_graphml(out / "inventory-map.graphml")

        graph_path = out / "inventory-graph.json"
        with open(graph_path, "w") as f:
            json.dump(builder.to_d3_json(), f, indent=2, default=str)
        paths["graph"] = graph_path

        deps_path = out / "inventory-dependencies.json"
        with open(deps_path, "w") as f:
            json.dump(self.analysis(), f, indent=2, default=str)
        paths["dependencies"] = deps_path

        if self.organization:
            org_path = out / "inventory-organization.json"
            with open(org_path, "w") as f:
                json.dump(self.organization, f, indent=2, default=str)
            paths["organization"] = org_path

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
        )


def _service_of(asset: CloudAsset) -> str:
    """Cloud service an asset belongs to, derived from its identifier."""
    arn = asset.arn or ""
    if arn.startswith("arn:"):
        parts = arn.split(":", 3)
        return parts[2] if len(parts) > 2 else "unknown"
    if arn.startswith("k8s://"):
        return "kubernetes"
    if arn.startswith("cloudg:"):
        parts = arn.split(":")
        return parts[2] if len(parts) > 2 else "unknown"
    if arn.startswith("/subscriptions/"):
        rtype = asset.metadata.get("resource_type") or ""
        if rtype:
            return rtype.split("/")[0].lower()
        lowered = arn.lower()
        if "/providers/" in lowered:
            return lowered.split("/providers/", 1)[1].split("/", 1)[0]
        return "microsoft.resources"
    if ".googleapis.com/" in arn:
        return arn.lstrip("/").split(".googleapis.com", 1)[0].split("/")[-1]
    gcp_type = asset.metadata.get("gcp_asset_type", "")
    if ".googleapis.com/" in gcp_type:
        return gcp_type.split(".googleapis.com", 1)[0]
    return "unknown"


def deduplicate(
    assets: list[CloudAsset], edges: list[NetworkEdge]
) -> tuple[list[CloudAsset], list[NetworkEdge]]:
    """Collapse assets that share an identifier (the same resource seen from
    several regions or collectors). The richest copy is kept, declared
    relations and aliases are merged, and edges are re-pointed to it."""
    kept: dict[str, CloudAsset] = {}
    position: dict[str, int] = {}
    remap: dict[str, str] = {}
    out: list[CloudAsset] = []
    for asset in assets:
        key = asset.arn
        if not key:
            out.append(asset)
            continue
        current = kept.get(key)
        if current is None:
            kept[key] = asset
            position[key] = len(out)
            out.append(asset)
            continue
        # Prefer the detailed copy over sweep / placeholder discoveries
        if current.metadata.get("discovered_via") and not asset.metadata.get("discovered_via"):
            asset, current = current, asset
            kept[key] = current
            out[position[key]] = current
        for list_key in ("relations", "aliases"):
            extra = asset.metadata.get(list_key) or []
            if extra:
                merged = list(current.metadata.get(list_key) or [])
                merged.extend(x for x in extra if x not in merged)
                current.metadata[list_key] = merged
        current.is_internet_exposed = current.is_internet_exposed or asset.is_internet_exposed
        remap[asset.id] = current.id

    if not remap:
        return out, edges
    new_edges = []
    seen: set[tuple[str, str, str]] = set()
    for e in edges:
        s = remap.get(e.source_id, e.source_id)
        t = remap.get(e.target_id, e.target_id)
        key3 = (s, t, e.edge_type.value)
        if s == t or key3 in seen:
            continue
        seen.add(key3)
        if s != e.source_id or t != e.target_id:
            e = e.model_copy(update={"source_id": s, "target_id": t})
        new_edges.append(e)
    logger.info("Deduplicated %d repeated assets", len(remap))
    return out, new_edges


def _account_identifier(provider: CloudProvider, account_id: str) -> str:
    if provider == CloudProvider.AZURE:
        return f"/subscriptions/{account_id}"
    if provider == CloudProvider.GCP:
        return f"//cloudresourcemanager.googleapis.com/projects/{account_id}"
    return f"arn:aws:iam::{account_id}:root"


def add_account_hierarchy(
    assets: list[CloudAsset], edges: list[NetworkEdge]
) -> tuple[list[CloudAsset], list[NetworkEdge]]:
    """Ensure an account node per account and make it contain every
    top-level resource (anything not already contained by something)."""
    by_arn = {a.arn: a for a in assets if a.arn}
    accounts: dict[tuple[CloudProvider, str], CloudAsset] = {}
    for a in assets:
        if a.asset_type == AssetType.CLOUD_ACCOUNT and a.account_id:
            accounts[(a.provider, a.account_id)] = a
    new_assets: list[CloudAsset] = []
    for a in assets:
        if not a.account_id or a.account_id == "unknown" or a.asset_type in _HIERARCHY_TYPES:
            continue
        key = (a.provider, a.account_id)
        if key in accounts:
            continue
        ident = _account_identifier(a.provider, a.account_id)
        existing = by_arn.get(ident)
        if existing is not None:
            accounts[key] = existing
            continue
        node = CloudAsset(
            arn=ident,
            name=f"account {a.account_id}",
            asset_type=AssetType.CLOUD_ACCOUNT,
            provider=a.provider,
            region="global",
            account_id=a.account_id,
            metadata={"account_id": a.account_id, "external": False},
        )
        accounts[key] = node
        new_assets.append(node)

    contained = {e.target_id for e in edges if e.edge_type == EdgeType.CONTAINS}
    new_edges = list(edges)
    for a in assets:
        if a.id in contained or a.asset_type in _HIERARCHY_TYPES or not a.account_id:
            continue
        acct = accounts.get((a.provider, a.account_id))
        if acct is None or acct.id == a.id:
            continue
        new_edges.append(
            NetworkEdge(
                source_id=acct.id,
                target_id=a.id,
                edge_type=EdgeType.CONTAINS,
                relationship="ACCOUNT_CONTAINS_REGION",
                description=f"account {a.account_id} contains {a.name}",
                properties={"hierarchy": True},
            )
        )
    return assets + new_assets, new_edges


class InventoryMapper:
    """Maps complete cloud infrastructure without running any scanner.

    Args:
        config: cloudg configuration (not mutated).
        tagging_sweep: Override ``config.inventory.tagging_sweep``.
    """

    def __init__(self, config: CloudGConfig, tagging_sweep: bool | None = None) -> None:
        self._config = config
        inv_cfg = getattr(config, "inventory", None)
        self._inventory = inv_cfg
        self._tagging_sweep = (
            tagging_sweep
            if tagging_sweep is not None
            else (inv_cfg.tagging_sweep if inv_cfg else True)
        )
        self._link_references = inv_cfg.link_references if inv_cfg else True
        self.organization: Any = None

    def _collector_overrides(self) -> dict[str, type]:
        from cloudg.inventory.aws_deep import AWSDeepInventoryCollector
        from cloudg.inventory.azure_deep import AzureDeepInventoryCollector
        from cloudg.inventory.gcp_deep import GCPDeepInventoryCollector

        inv = self._inventory
        options: dict[str, Any] = {"tagging_sweep": self._tagging_sweep}
        if inv is not None:
            options.update(
                services=list(inv.services),
                exclude_services=list(inv.exclude_services),
                kubernetes=inv.kubernetes,
                kubernetes_timeout=inv.kubernetes_timeout,
                iam_resource_edges=inv.iam_resource_edges,
                max_images_per_repository=inv.max_images_per_repository,
                stack_resources=inv.stack_resources,
            )

        # Subclass keeping the (session, region, account_id) signature that
        # MultiAccountCollector expects, with the mapping options bound.
        class _ConfiguredAWS(AWSDeepInventoryCollector):
            def __init__(
                self,
                session: Any,
                region: str = "us-east-1",
                account_id: str | None = None,
                is_primary_region: bool = True,
            ) -> None:
                super().__init__(
                    session, region, account_id, is_primary_region=is_primary_region, **options
                )

        return {
            "aws": _ConfiguredAWS,
            "azure": AzureDeepInventoryCollector,
            "gcp": GCPDeepInventoryCollector,
        }

    # ------------------------------------------------------------------
    # Organizations / Control Tower
    # ------------------------------------------------------------------

    def _discover_organization(self, cfg: CloudGConfig) -> Any:
        """Discover the org and point ``cfg.aws`` at its accounts (blocking)."""
        from cloudg.collectors.multi import primary_region
        from cloudg.credentials import build_aws_session
        from cloudg.inventory.organization import DEFAULT_MEMBER_ROLE, discover_organization
        from cloudg.region_discovery import is_all_regions

        org_cfg = cfg.aws.organization
        regions = [] if is_all_regions(cfg.aws.regions) else list(cfg.aws.regions)
        region = org_cfg.home_region or primary_region(regions)
        session = build_aws_session(cfg.aws, region, account_id=None)
        topology = discover_organization(
            session, control_tower=org_cfg.control_tower, home_region=org_cfg.home_region
        )

        accounts = topology.target_accounts(
            include_ous=org_cfg.include_ous,
            exclude_accounts=org_cfg.exclude_accounts,
            include_management_account=org_cfg.include_management_account,
            include_suspended=org_cfg.include_suspended,
        )
        if cfg.aws.accounts:
            wanted = set(cfg.aws.accounts)
            accounts = [a for a in accounts if a in wanted]
        cfg.aws.accounts = accounts
        cfg.aws.role_name = org_cfg.role_name or cfg.aws.role_name or DEFAULT_MEMBER_ROLE
        if org_cfg.use_governed_regions and topology.governed_regions and is_all_regions(cfg.aws.regions):
            cfg.aws.regions = list(topology.governed_regions)
            logger.info("Using %d Control Tower governed regions", len(cfg.aws.regions))
        logger.info(
            "Organization mapping: %d accounts selected, member role %s",
            len(accounts),
            cfg.aws.role_name,
        )
        return topology

    # ------------------------------------------------------------------
    # Mapping
    # ------------------------------------------------------------------

    async def map_inventory(self) -> InventoryResult:
        """Deep-collect every provider and link the assets into a map."""
        start = time.time()
        cfg = self._config.model_copy(deep=True)
        org_coverage: list[CollectionCoverage] = []

        topology = None
        if "aws" in cfg.providers and cfg.aws.organization.enabled:
            cov = CollectionCoverage(provider="aws", region="global")
            org_coverage.append(cov)
            t0 = time.time()
            try:
                topology = await asyncio.to_thread(self._discover_organization, cfg)
                cov.record(
                    "organizations",
                    ServiceStatus.SUCCESS,
                    asset_count=len(topology.accounts),
                    duration_ms=int((time.time() - t0) * 1000),
                )
                if topology.errors:
                    cov.record("controltower", ServiceStatus.PARTIAL, error="; ".join(topology.errors))
            except Exception as exc:
                logger.error("Organization discovery failed; mapping the caller account only: %s", exc)
                cov.record("organizations", ServiceStatus.FAILED, error=str(exc))
        self.organization = topology

        from cloudg.collectors.multi import MultiAccountCollector

        collector = MultiAccountCollector(cfg, collector_overrides=self._collector_overrides())
        assets, edges, coverage = await collector.collect_all()

        if topology is not None and cfg.aws.organization.map_structure:
            assets = topology.to_assets() + assets

        assets, edges = deduplicate(assets, edges)

        # Link: derive cross-service relationships from asset metadata
        from cloudg.inventory.linker import RelationshipLinker

        linker = RelationshipLinker(assets)
        linker.seed_existing(edges)
        edges = edges + linker.link(include_generic=self._link_references)
        assets = assets + linker.external_assets

        if self._inventory is None or self._inventory.account_hierarchy:
            assets, edges = add_account_hierarchy(assets, edges)

        return InventoryResult(
            assets=assets,
            edges=edges,
            coverage=org_coverage + coverage,
            providers=list(cfg.providers),
            regions=getattr(collector, "_resolved_regions", {}),
            duration_ms=int((time.time() - start) * 1000),
            organization=topology.to_dict() if topology is not None else None,
            unresolved_references=linker.unresolved,
        )

    def map_inventory_sync(self) -> InventoryResult:
        """Synchronous wrapper for :meth:`map_inventory`."""
        return asyncio.run(self.map_inventory())

    # ------------------------------------------------------------------
    # Merging with scanner results (produced elsewhere)
    # ------------------------------------------------------------------

    @staticmethod
    def _findings_for(asset: CloudAsset, findings: list[Finding]) -> list[Finding]:
        ids = {asset.id, asset.arn, asset.name}
        matched = []
        for f in findings:
            if f.resource_arn and f.resource_arn in ids:
                matched.append(f)
            elif f.resource_id in ids:
                matched.append(f)
        return matched

    def build_asset_map(
        self, result: InventoryResult, findings: list[Finding]
    ) -> dict[str, Any]:
        """Overlay scanner findings onto the inventory: asset → risk view."""
        entries = []
        for asset in result.assets:
            matched = self._findings_for(asset, findings)
            severity: dict[str, int] = {}
            for f in matched:
                severity[f.severity.value] = severity.get(f.severity.value, 0) + 1
            entries.append(
                {
                    "id": asset.id,
                    "arn": asset.arn,
                    "name": asset.name,
                    "type": asset.asset_type.value,
                    "provider": asset.provider.value,
                    "region": asset.region,
                    "account_id": asset.account_id,
                    "internet_exposed": asset.is_internet_exposed,
                    "finding_count": len(matched),
                    "severity_breakdown": severity,
                    "finding_ids": [f.id for f in matched],
                }
            )
        entries.sort(key=lambda e: -e["finding_count"])
        return {
            "total_assets": len(entries),
            "assets_with_findings": sum(1 for e in entries if e["finding_count"]),
            "assets": entries,
        }

    def build_compliance_map(
        self, result: InventoryResult, findings: list[Finding]
    ) -> dict[str, Any]:
        """Compliance framework → affected assets, from finding mappings."""
        arn_index = {a.arn: a for a in result.assets if a.arn}
        id_index = {a.id: a for a in result.assets}

        frameworks: dict[str, dict[str, Any]] = {}
        for f in findings:
            asset = arn_index.get(f.resource_arn or "") or id_index.get(f.resource_id)
            for fw in f.compliance_frameworks:
                entry = frameworks.setdefault(
                    fw,
                    {"findings": 0, "severity_breakdown": {}, "affected_assets": set()},
                )
                entry["findings"] += 1
                sev = f.severity.value
                entry["severity_breakdown"][sev] = entry["severity_breakdown"].get(sev, 0) + 1
                if asset:
                    entry["affected_assets"].add(asset.arn or asset.id)
                elif f.resource_arn:
                    entry["affected_assets"].add(f.resource_arn)

        serialised = {
            fw: {
                "findings": e["findings"],
                "severity_breakdown": e["severity_breakdown"],
                "affected_assets": sorted(e["affected_assets"]),
                "affected_asset_count": len(e["affected_assets"]),
            }
            for fw, e in sorted(frameworks.items())
        }
        return {
            "frameworks": serialised,
            "total_frameworks": len(serialised),
            "total_inventory_assets": len(result.assets),
        }

    def export_merged(
        self,
        result: InventoryResult,
        findings: list[Finding],
        output_dir: str | Path,
    ) -> dict[str, Path]:
        """Export asset and compliance maps that merge inventory + findings."""
        out = Path(output_dir)
        out.mkdir(parents=True, exist_ok=True)
        paths: dict[str, Path] = {}

        asset_map_path = out / "asset-map.json"
        with open(asset_map_path, "w") as f:
            json.dump(self.build_asset_map(result, findings), f, indent=2, default=str)
        paths["asset_map"] = asset_map_path

        compliance_path = out / "compliance-map.json"
        with open(compliance_path, "w") as f:
            json.dump(self.build_compliance_map(result, findings), f, indent=2, default=str)
        paths["compliance_map"] = compliance_path

        return paths
