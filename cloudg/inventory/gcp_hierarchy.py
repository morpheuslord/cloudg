"""GCP resource hierarchy, organization policies and VPC Service Controls.

:func:`discover_gcp_hierarchy` maps, from Cloud Asset Inventory at
organization scope:

- the Organization (ORGANIZATION), Folders (ORG_UNIT) and Projects
  (CLOUD_ACCOUNT, ``account_id`` = project ID, aliases ``projects/<number>``,
  ``<number>``, ``projects/<id>``) with parent CONTAINS child relations;
- organization policies (``ContentType.ORG_POLICY`` plus
  ``orgpolicy.googleapis.com/Policy`` resources) as ORG_POLICY assets that
  GOVERN the organization, folder or project they are set on;
- VPC Service Controls perimeters (``ContentType.ACCESS_POLICY``) as
  GUARDRAIL assets that GOVERN their member projects and networks.

Asset identifiers match what :class:`~cloudg.collectors.gcp.GCPCollector`
produces for the same resources, so the inventory mapper's deduplication
merges the two views.
"""

from __future__ import annotations

import asyncio
import logging
import time
from typing import Any

from cloudg.collectors.gcp import GCPCollector
from cloudg.coverage import CollectionCoverage, ServiceStatus
from cloudg.inventory.aws_services._base import rel
from cloudg.inventory.gcp_relations import full_name, perimeter_metadata, relative_name
from cloudg.schema.models import AssetType, CloudAsset, CloudProvider, EdgeType

logger = logging.getLogger(__name__)

HIERARCHY_TYPES = [
    "cloudresourcemanager.googleapis.com/Organization",
    "cloudresourcemanager.googleapis.com/Folder",
    "cloudresourcemanager.googleapis.com/Project",
    "orgpolicy.googleapis.com/Policy",
]


def _bool_policy(p: dict[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    bp = p.get("boolean_policy") or p.get("booleanPolicy")
    if isinstance(bp, dict):
        out["enforced"] = bool(bp.get("enforced"))
    lp = p.get("list_policy") or p.get("listPolicy")
    if isinstance(lp, dict):
        def g(snake: str, camel: str) -> Any:
            return lp.get(snake, lp.get(camel))

        all_values = g("all_values", "allValues")
        if isinstance(all_values, (int, float)):
            all_values = {0: None, 1: "ALLOW", 2: "DENY"}.get(int(all_values))
        out.update(
            allowed_values=list(g("allowed_values", "allowedValues") or []),
            denied_values=list(g("denied_values", "deniedValues") or []),
            all_values=all_values or None,
            inherit_from_parent=g("inherit_from_parent", "inheritFromParent"),
        )
    if p.get("restore_default") or p.get("restoreDefault"):
        out["restore_default"] = True
    return {k: v for k, v in out.items() if v not in (None, [], "")}


def org_policy_assets(results: list[dict[str, Any]], number_to_id: dict[str, str]) -> list[CloudAsset]:
    """ORG_POLICY assets from ``ContentType.ORG_POLICY`` listing results."""
    assets: list[CloudAsset] = []
    for res in results:
        attached = res.get("name") or ""
        policies = res.get("org_policy") or res.get("orgPolicy") or []
        rel_attached = relative_name(attached)
        project = rel_attached.split("/", 1)[1] if rel_attached.startswith("projects/") else None
        account = number_to_id.get(project or "", project) if project else None
        for p in policies:
            if not isinstance(p, dict) or not p.get("constraint"):
                continue
            constraint = str(p["constraint"])
            short = constraint.removeprefix("constraints/")
            arn = f"//orgpolicy.googleapis.com/{rel_attached}/policies/{short}"
            md = {
                "gcp_asset_type": "orgpolicy.googleapis.com/Policy",
                "constraint": constraint,
                "attached_to": attached,
                **_bool_policy(p),
                "relations": [rel(attached, EdgeType.GOVERNS, "SCP_RESTRICTS", description=f"{constraint} on {rel_attached}")],
            }
            assets.append(
                CloudAsset(
                    arn=arn,
                    name=f"{short} @ {rel_attached}",
                    asset_type=AssetType.ORG_POLICY,
                    provider=CloudProvider.GCP,
                    region="global",
                    account_id=account,
                    metadata=md,
                )
            )
    return assets


def perimeter_assets(results: list[dict[str, Any]]) -> list[CloudAsset]:
    """GUARDRAIL assets for VPC-SC service perimeters (``ContentType.ACCESS_POLICY``)."""
    assets: list[CloudAsset] = []
    for res in results:
        perimeter = res.get("service_perimeter") or res.get("servicePerimeter")
        if not isinstance(perimeter, dict) or not perimeter:
            continue
        name = res.get("name") or full_name(perimeter.get("name"), "accesscontextmanager") or ""
        md, governed = perimeter_metadata(perimeter)
        relations = [
            rel(ref, EdgeType.GOVERNS, "COMPLIANCE_GOVERNS", description="VPC Service Controls perimeter", dry_run=dry or None)
            for ref, dry in governed
        ]
        md.update(
            gcp_asset_type="accesscontextmanager.googleapis.com/ServicePerimeter",
            access_policy=relative_name(name).split("/servicePerimeters/", 1)[0],
            relations=[r for r in relations if r],
            member_count=len(governed),
        )
        assets.append(
            CloudAsset(
                arn=name,
                name=md.get("title") or name.rsplit("/", 1)[-1],
                asset_type=AssetType.GUARDRAIL,
                provider=CloudProvider.GCP,
                region="global",
                metadata=md,
            )
        )
    return assets


def discover_gcp_hierarchy(
    credentials: Any,
    organization_id: str,
    client: Any = None,
    *,
    coverage: CollectionCoverage | None = None,
    org_policies: bool = True,
    access_policies: bool = True,
) -> list[CloudAsset]:
    """Map the organization -> folder -> project tree, org policies and VPC-SC.

    Blocking (run it with ``asyncio.to_thread`` or use
    :func:`discover_gcp_hierarchy_async`).

    Args:
        credentials: google-auth credentials.
        organization_id: Numeric org ID (``organizations/`` prefix optional).
        client: Injected ``AssetServiceClient`` (tests).
        coverage: Receives per-part status (hierarchy, org policies, VPC-SC).
        org_policies: Map organization policies.
        access_policies: Map VPC Service Controls perimeters.

    Raises:
        RuntimeError: When the hierarchy itself cannot be listed.
    """
    org = str(organization_id).removeprefix("organizations/")
    collector = GCPCollector(
        project_id=None,
        credentials=credentials,
        organization_id=org,
        client=client,
        skip_asset_types=[],
        include_iam=False,
        coverage=coverage,
    )
    cov = collector.coverage

    start = time.time()
    types = HIERARCHY_TYPES if org_policies else HIERARCHY_TYPES[:3]
    raw, error = collector._list_assets("RESOURCE", asset_types=types)
    if error is not None and not raw:
        cov.record("gcp_hierarchy", ServiceStatus.FAILED, error=str(error))
        raise RuntimeError(f"GCP hierarchy discovery failed for organizations/{org}: {error}")
    records = [collector._record_from_asset(r) for r in raw]
    assets = collector._build_assets(records)
    cov.record(
        "gcp_hierarchy",
        ServiceStatus.PARTIAL if error else ServiceStatus.SUCCESS,
        asset_count=len(assets),
        error=str(error) if error else None,
        duration_ms=int((time.time() - start) * 1000),
    )
    org_arn = f"//cloudresourcemanager.googleapis.com/organizations/{org}"
    if not any(a.arn == org_arn for a in assets):
        assets.insert(
            0,
            CloudAsset(
                arn=org_arn,
                name=f"organization {org}",
                asset_type=AssetType.ORGANIZATION,
                provider=CloudProvider.GCP,
                region="global",
                metadata={
                    "gcp_asset_type": "cloudresourcemanager.googleapis.com/Organization",
                    "aliases": [f"organizations/{org}"],
                    "discovered_via": "configured organization_id",
                },
            ),
        )

    if org_policies:
        start = time.time()
        results, error = collector._list_assets("ORG_POLICY")
        policies = org_policy_assets(results, collector._number_to_id)
        known = {a.arn for a in assets}
        assets.extend(p for p in policies if p.arn not in known)
        cov.record(
            "gcp_org_policies",
            ServiceStatus.SUCCESS if error is None else (ServiceStatus.PARTIAL if results else ServiceStatus.FAILED),
            asset_count=len(policies),
            error=str(error) if error else None,
            duration_ms=int((time.time() - start) * 1000),
        )

    if access_policies:
        start = time.time()
        results, error = collector._list_assets("ACCESS_POLICY")
        perimeters = perimeter_assets(results)
        assets.extend(perimeters)
        cov.record(
            "gcp_vpc_service_controls",
            ServiceStatus.SUCCESS if error is None else (ServiceStatus.PARTIAL if results else ServiceStatus.FAILED),
            asset_count=len(perimeters),
            error=str(error) if error else None,
            duration_ms=int((time.time() - start) * 1000),
        )

    logger.info("GCP hierarchy for organizations/%s: %d assets", org, len(assets))
    return assets


async def discover_gcp_hierarchy_async(
    credentials: Any, organization_id: str, client: Any = None, **kwargs: Any
) -> list[CloudAsset]:
    """Async wrapper running :func:`discover_gcp_hierarchy` in a worker thread."""
    return await asyncio.to_thread(discover_gcp_hierarchy, credentials, organization_id, client, **kwargs)
