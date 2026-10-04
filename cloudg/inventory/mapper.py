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
from pathlib import Path
from typing import Any

from cloudg.config import CloudGConfig
from cloudg.coverage import CollectionCoverage, ServiceStatus

# InventoryResult and _service_of live in mapper_result; re-exported here
from cloudg.inventory.mapper_result import (  # noqa: F401
    _HIERARCHY_TYPES,
    InventoryResult,
    _service_of,
)
from cloudg.schema.models import (
    AssetType,
    CloudAsset,
    CloudProvider,
    EdgeType,
    Finding,
    NetworkEdge,
)

logger = logging.getLogger(__name__)


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
                cloud_control=inv.cloud_control,
                cloud_control_types=list(inv.cloud_control_types),
                cloud_control_exclude=list(inv.cloud_control_exclude),
                cloud_control_concurrency=inv.cloud_control_concurrency,
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
        if (
            org_cfg.use_governed_regions
            and topology.governed_regions
            and is_all_regions(cfg.aws.regions)
        ):
            cfg.aws.regions = list(topology.governed_regions)
            logger.info("Using %d Control Tower governed regions", len(cfg.aws.regions))
        logger.info(
            "Organization mapping: %d accounts selected, member role %s",
            len(accounts),
            cfg.aws.role_name,
        )
        return topology

    async def _discover_azure_hierarchy(
        self, cfg: CloudGConfig, coverage: list[CollectionCoverage]
    ) -> list[CloudAsset]:
        """Azure management groups and policy assignments."""
        cov = CollectionCoverage(provider="azure", region="global")
        coverage.append(cov)
        t0 = time.time()
        errors: list[str] = []
        try:
            from cloudg.credentials import build_azure_credential
            from cloudg.inventory.azure_hierarchy import discover_azure_hierarchy

            credential = build_azure_credential(cfg.azure)
            found = await asyncio.to_thread(
                discover_azure_hierarchy, credential, None, include_policies=True, errors=errors
            )
            cov.record(
                "management_groups",
                ServiceStatus.PARTIAL if errors else ServiceStatus.SUCCESS,
                asset_count=len(found),
                error="; ".join(errors) or None,
                duration_ms=int((time.time() - t0) * 1000),
            )
            return found
        except ImportError as exc:
            cov.record("management_groups", ServiceStatus.SKIPPED, error=str(exc))
        except Exception as exc:
            logger.error("Azure hierarchy discovery failed: %s", exc)
            cov.record("management_groups", ServiceStatus.FAILED, error=str(exc))
        return []

    async def _discover_gcp_hierarchy(
        self, cfg: CloudGConfig, coverage: list[CollectionCoverage]
    ) -> list[CloudAsset]:
        """GCP organization, folders, org policies and access policies."""
        gcp = cfg.gcp
        cov = CollectionCoverage(provider="gcp", region="global", account_id=gcp.organization_id)
        coverage.append(cov)
        t0 = time.time()
        try:
            from cloudg.credentials import build_gcp_credentials
            from cloudg.inventory.gcp_hierarchy import discover_gcp_hierarchy

            credentials = build_gcp_credentials(gcp)[0]
            found = await asyncio.to_thread(
                discover_gcp_hierarchy,
                credentials,
                gcp.organization_id,
                None,
                coverage=cov,
                org_policies=getattr(gcp, "org_policies", True),
                access_policies=getattr(gcp, "vpc_service_controls", True),
            )
            cov.record(
                "organization_hierarchy",
                ServiceStatus.SUCCESS,
                asset_count=len(found),
                duration_ms=int((time.time() - t0) * 1000),
            )
            return found
        except ImportError as exc:
            cov.record("organization_hierarchy", ServiceStatus.SKIPPED, error=str(exc))
        except Exception as exc:
            logger.error("GCP hierarchy discovery failed: %s", exc)
            cov.record("organization_hierarchy", ServiceStatus.FAILED, error=str(exc))
        return []

    async def _discover_hierarchies(
        self, cfg: CloudGConfig, coverage: list[CollectionCoverage]
    ) -> list[CloudAsset]:
        """Azure management groups / policy and GCP org / folders / policy."""
        out: list[CloudAsset] = []
        if "azure" in cfg.providers and getattr(cfg.azure, "map_management_groups", False):
            out.extend(await self._discover_azure_hierarchy(cfg, coverage))
        gcp = cfg.gcp
        if "gcp" in cfg.providers and gcp.organization_id and getattr(gcp, "map_hierarchy", False):
            out.extend(await self._discover_gcp_hierarchy(cfg, coverage))
        return out

    async def _discover_aws_organization(
        self, cfg: CloudGConfig, coverage: list[CollectionCoverage]
    ) -> Any:
        """AWS Organizations / Control Tower discovery, recorded as coverage.

        Returns the topology, or None when discovery is off or failed (the
        caller account alone is then mapped).
        """
        if not ("aws" in cfg.providers and cfg.aws.organization.enabled):
            return None
        cov = CollectionCoverage(provider="aws", region="global")
        coverage.append(cov)
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
            return topology
        except Exception as exc:
            logger.error("Organization discovery failed; mapping the caller account only: %s", exc)
            cov.record("organizations", ServiceStatus.FAILED, error=str(exc))
            return None

    def _link(
        self, cfg: CloudGConfig, assets: list[CloudAsset], edges: list[NetworkEdge]
    ) -> tuple[list[CloudAsset], list[NetworkEdge], list[dict[str, Any]]]:
        """Deduplicate, link and add the account hierarchy.

        Returns the final assets, edges and the linker's unresolved references.
        """
        assets, edges = deduplicate(assets, edges)
        if "gcp" in cfg.providers:
            from cloudg.inventory.gcp_relations import merge_gcp_principals

            # Fold per-project service-account placeholders into the real SAs
            assets, edges = merge_gcp_principals(assets, edges)

        # Link: derive cross-service relationships from asset metadata
        from cloudg.inventory.linker import RelationshipLinker

        linker = RelationshipLinker(assets)
        linker.seed_existing(edges)
        edges = edges + linker.link(include_generic=self._link_references)
        assets = assets + linker.external_assets

        if self._inventory is None or self._inventory.account_hierarchy:
            assets, edges = add_account_hierarchy(assets, edges)
        return assets, edges, linker.unresolved

    # ------------------------------------------------------------------
    # Mapping
    # ------------------------------------------------------------------

    async def map_inventory(self) -> InventoryResult:
        """Deep-collect every provider and link the assets into a map."""
        start = time.time()
        cfg = self._config.model_copy(deep=True)
        org_coverage: list[CollectionCoverage] = []

        topology = await self._discover_aws_organization(cfg, org_coverage)
        self.organization = topology

        # Cloud hierarchies beyond AWS (management groups / org folders);
        # merged into the map like the AWS organization structure.
        hierarchy_assets = await self._discover_hierarchies(cfg, org_coverage)

        from cloudg.collectors.multi import MultiAccountCollector

        collector = MultiAccountCollector(cfg, collector_overrides=self._collector_overrides())
        assets, edges, coverage = await collector.collect_all()

        if topology is not None and cfg.aws.organization.map_structure:
            assets = topology.to_assets() + assets
        assets = hierarchy_assets + assets
        assets, edges, unresolved = self._link(cfg, assets, edges)

        return InventoryResult(
            assets=assets,
            edges=edges,
            coverage=org_coverage + coverage,
            providers=list(cfg.providers),
            regions=getattr(collector, "_resolved_regions", {}),
            duration_ms=int((time.time() - start) * 1000),
            organization=topology.to_dict() if topology is not None else None,
            unresolved_references=unresolved,
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

    def build_asset_map(self, result: InventoryResult, findings: list[Finding]) -> dict[str, Any]:
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
