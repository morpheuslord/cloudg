"""Inventory tools: search, inspect and aggregate the assets of a dataset.

These answer "what do we have": filtered / sorted / paginated asset
search, one asset in detail, counts by any dimension, accounts, regions,
tags, collection coverage, unresolved references and the organization
(AWS Organizations / Control Tower, Azure management groups, GCP folders)
topology.
"""

from __future__ import annotations

from typing import Annotated, Any, Literal

from pydantic import BaseModel, Field

from cloudg.inventory.mapper_result import _service_of
from cloudg.mcp.catalog._common import (
    ASSET_FIELDS,
    DEFAULT_LIMIT,
    AssetDetailOut,
    AssetPageOut,
    Catalog,
    CountOut,
    Cursor,
    DatasetArg,
    Limit,
    RefArg,
    asset_brief,
    asset_uri,
    bounded,
    check_fields,
    finding_brief,
    fingerprint,
    paginate,
    project,
    schema,
    ws_dataset,
)
from cloudg.mcp.catalog._inventory import (
    AssetFilter,
    account_rows,
    filter_assets,
    group_key,
    org_from_assets,
    org_from_discovery,
    relation_view,
    sort_assets,
    truncate_metadata,
)
from cloudg.mcp.core import Capability, Registry, Sensitivity

CATEGORY = "inventory"
R = Capability.READ_STATE

SortKey = Literal["name", "type", "region", "account", "risk", "findings"]
GroupBy = Literal["type", "provider", "region", "account", "service", "exposure", "severity"]

QueryArg = Annotated[
    str, Field(description="Case-insensitive substring of name, ARN, id or a tag value.")
]
ProviderArg = Annotated[str, Field(description="aws, azure or gcp.")]
AssetTypesArg = Annotated[
    list[str] | None,
    Field(description="AssetType values, e.g. ['EC2','S3_BUCKET'] (describe_schema)."),
]
RegionArg = Annotated[str, Field(description="Exact region, e.g. us-east-1.")]
AccountArg = Annotated[str, Field(description="Exact account / subscription / project.")]
TagArg = Annotated[str, Field(description="Tag filter: 'key' or 'key=value'.")]
ExposedArg = Annotated[bool | None, Field(description="Only exposed (true) / not exposed (false).")]
HasFindingsArg = Annotated[
    bool | None, Field(description="Only assets with (true) / without (false) open findings.")
]
MinSeverityArg = Annotated[
    str, Field(description="Only assets with an open finding at or above this severity.")
]
SortArg = Annotated[SortKey, Field(description="'risk' ranks by worst finding + exposure.")]
FieldsArg = Annotated[
    list[str] | None,
    Field(description=f"Project each item to these fields. Valid: {', '.join(ASSET_FIELDS)}"),
]


class FindAssetsArgs(BaseModel):
    """find_assets arguments (the MCP wire schema)."""

    query: QueryArg = ""
    provider: ProviderArg = ""
    asset_types: AssetTypesArg = None
    region: RegionArg = ""
    account_id: AccountArg = ""
    tag: TagArg = ""
    internet_exposed: ExposedArg = None
    has_findings: HasFindingsArg = None
    min_severity: MinSeverityArg = ""
    sort_by: SortArg = "name"
    descending: bool = False
    fields: FieldsArg = None
    limit: Limit = DEFAULT_LIMIT
    cursor: Cursor = ""
    dataset: DatasetArg = ""


class CountAssetsArgs(BaseModel):
    """count_assets arguments (the MCP wire schema)."""

    group_by: GroupBy = "type"
    provider: str = ""
    asset_types: list[str] | None = None
    region: str = ""
    account_id: str = ""
    internet_exposed: bool | None = None
    top: Annotated[int, Field(ge=1, le=500)] = 50
    dataset: DatasetArg = ""


_RO = dict(category=CATEGORY, read_only=True, idempotent=True, open_world=False)

CATALOG = Catalog()


@CATALOG.tool(
    title="Find assets",
    sensitivity=Sensitivity.CONFIDENTIAL,
    output_schema=schema(AssetPageOut),
    tags={"start-here"},
    **_RO,
)
def find_assets(ctx: Any, args: FindAssetsArgs) -> dict:
    """Search assets with filters (provider, type, region, account, tag,
    exposure, findings, severity, free text), sorting and cursor
    pagination. Returns compact briefs; call get_asset (or read the
    item's uri) for details. Example: find internet-exposed EC2 with
    HIGH findings: asset_types=['EC2'], internet_exposed=true,
    min_severity='HIGH'."""
    ds = ws_dataset(ctx, args.dataset)
    proj = check_fields(args.fields, ASSET_FIELDS)
    flt = AssetFilter.from_args(dict(args))
    matched = filter_assets(ds, flt)
    sort_assets(ds, matched, args.sort_by, args.descending)
    fp = fingerprint(ds, f=flt.key(), s=args.sort_by, d=args.descending)
    page, env = paginate(matched, args.limit, args.cursor, fp)
    items = [project(asset_brief(ds, a, tags="tags" in (proj or [])), proj) for a in page]
    out = {"dataset": ds.name, **env, "items": items}
    if not matched and ds.assets:
        out["hint"] = (
            "No assets matched. Loosen the filters, or use list_asset_types / "
            "list_accounts / list_regions to see valid values."
        )
    return out


@CATALOG.tool(
    title="Get asset",
    sensitivity=Sensitivity.CONFIDENTIAL,
    output_schema=schema(AssetDetailOut),
    **_RO,
)
def get_asset(
    ctx: Any,
    ref: RefArg,
    include_findings: bool = True,
    max_relations: Annotated[int, Field(ge=0, le=200)] = 20,
    dataset: DatasetArg = "",
) -> dict:
    """One asset in detail: identity, tags, exposure, relation counts by
    edge type with the first neighbours in / out, direct dependency
    counts, its open findings, and the metadata keys available via
    get_asset_metadata. Use neighbors / dependency_tree to go further."""
    ds = ws_dataset(ctx, dataset)
    a = ds.resolve_asset(ref)
    out = asset_brief(ds, a, tags=True)
    out["dataset"] = ds.name
    out["service"] = _service_of(a)
    g = ds.graph
    out["relations"] = relation_view(ds, a, max_relations)
    needs, needed_by = ds.dependency_graph().direct_counts(a.id)
    out["dependencies"] = {"direct_depends_on": needs, "direct_dependents": needed_by}
    out["degree"] = {"in": g.in_degree(a.id), "out": g.out_degree(a.id)} if a.id in g else {}
    if include_findings:
        fs = sorted(ds.open_findings(a.id), key=lambda f: -f.risk_score)
        out["findings"] = [finding_brief(ds, f) for f in fs[:25]]
    out["metadata_keys"] = sorted(a.metadata)[:100]
    out["collected_at"] = a.collected_at.isoformat() if a.collected_at else None
    ctx.link(asset_uri(a.id), a.name, title=f"{a.asset_type.value} {a.name}")
    ctx.link(asset_uri(a.id) + "/neighbors", f"{a.name} neighbors")
    return out


@CATALOG.tool(title="Get asset metadata", sensitivity=Sensitivity.RESTRICTED, **_RO)
def get_asset_metadata(
    ctx: Any,
    ref: RefArg,
    keys: Annotated[
        list[str] | None,
        Field(description="Only these metadata keys (see get_asset.metadata_keys)."),
    ] = None,
    max_chars: Annotated[int, Field(ge=1000, le=200_000)] = 40_000,
    dataset: DatasetArg = "",
) -> dict:
    """Raw collector metadata of one asset (configuration, policies,
    rules, declared relations). May hold sensitive values such as policy
    documents or environment settings, so it is RESTRICTED. Ask for
    specific keys to keep the result small."""
    ds = ws_dataset(ctx, dataset)
    a = ds.resolve_asset(ref)
    meta = a.metadata
    missing: list[str] = []
    if keys:
        missing = [k for k in keys if k not in meta]
        meta = {k: meta[k] for k in keys if k in meta}
    out: dict[str, Any] = {"id": a.id, "name": a.name, "type": a.asset_type.value}
    out.update(truncate_metadata(meta, max_chars))
    if missing:
        out["missing_keys"] = missing
    return out


@CATALOG.tool(
    title="Count assets",
    sensitivity=Sensitivity.INTERNAL,
    output_schema=schema(CountOut),
    **_RO,
)
def count_assets(ctx: Any, args: CountAssetsArgs) -> dict:
    """Count assets grouped by type, provider, region, account, cloud
    service, exposure or worst open-finding severity, with optional
    filters. A cheap aggregate view with no identifiers beyond group keys."""
    ds = ws_dataset(ctx, args.dataset)
    flt = AssetFilter.from_args(dict(args))
    matched = filter_assets(ds, flt)
    groups: dict[str, int] = {}
    for a in matched:
        k = group_key(ds, a, args.group_by)
        groups[k] = groups.get(k, 0) + 1
    ordered = sorted(groups.items(), key=lambda kv: (-kv[1], kv[0]))
    return {
        "dataset": ds.name,
        "group_by": args.group_by,
        "total": len(matched),
        "group_count": len(groups),
        "groups": dict(ordered[: args.top]),
        "truncated": len(groups) > args.top,
    }


@CATALOG.tool(title="List asset types", sensitivity=Sensitivity.INTERNAL, **_RO)
def list_asset_types(ctx: Any, dataset: DatasetArg = "") -> dict:
    """Asset types present in the dataset with counts, exposed counts
    and open-finding counts. These are the valid values for asset_types filters."""
    ds = ws_dataset(ctx, dataset)
    stats: dict[str, dict[str, int]] = {}
    for a in ds.assets:
        s = stats.setdefault(
            a.asset_type.value, {"count": 0, "internet_exposed": 0, "open_findings": 0}
        )
        s["count"] += 1
        s["internet_exposed"] += int(a.is_internet_exposed)
        s["open_findings"] += len(ds.open_findings(a.id))
    items = [{"type": t, **s} for t, s in sorted(stats.items(), key=lambda kv: -kv[1]["count"])]
    return {"dataset": ds.name, "total_types": len(items), "items": items}


@CATALOG.tool(title="List accounts", sensitivity=Sensitivity.CONFIDENTIAL, **_RO)
def list_accounts(
    ctx: Any, limit: Limit = 100, cursor: Cursor = "", dataset: DatasetArg = ""
) -> dict:
    """Accounts / subscriptions / projects in the dataset with provider,
    display name, asset count, regions, exposed assets, open findings
    and whether the account is external (only referenced, not mapped)."""
    ds = ws_dataset(ctx, dataset)
    page, env = paginate(account_rows(ds), limit, cursor, fingerprint(ds, t="accounts"))
    return {"dataset": ds.name, **env, "items": page}


@CATALOG.tool(title="List regions", sensitivity=Sensitivity.INTERNAL, **_RO)
def list_regions(ctx: Any, dataset: DatasetArg = "") -> dict:
    """Regions in the dataset with providers, asset and account counts,
    plus the regions each provider was configured / scanned for."""
    ds = ws_dataset(ctx, dataset)
    regions: dict[str, dict[str, Any]] = {}
    for a in ds.assets:
        r = regions.setdefault(
            a.region, {"region": a.region, "providers": set(), "assets": 0, "accounts": set()}
        )
        r["providers"].add(a.provider.value)
        r["assets"] += 1
        if a.account_id:
            r["accounts"].add(a.account_id)
    items = [
        {**r, "providers": sorted(r["providers"]), "accounts": len(r["accounts"])}
        for r in sorted(regions.values(), key=lambda r: -r["assets"])
    ]
    return {"dataset": ds.name, "total": len(items), "items": items, "scanned_regions": ds.regions}


@CATALOG.tool(title="List tags", sensitivity=Sensitivity.CONFIDENTIAL, **_RO)
def list_tags(
    ctx: Any,
    key: Annotated[str, Field(description="Only this tag key (shows its values).")] = "",
    top: Annotated[int, Field(ge=1, le=200)] = 30,
    dataset: DatasetArg = "",
) -> dict:
    """Tag keys used across assets with how many assets carry each and
    their most common values. Pass key= to list one key's values. Use
    the result with find_assets(tag='key=value')."""
    ds = ws_dataset(ctx, dataset)
    keys: dict[str, dict[str, int]] = {}
    for a in ds.assets:
        for k, v in a.tags.items():
            if key and k != key:
                continue
            vals = keys.setdefault(k, {})
            vals[v] = vals.get(v, 0) + 1
    items = []
    for k, vals in sorted(keys.items(), key=lambda kv: -sum(kv[1].values())):
        top_vals = sorted(vals.items(), key=lambda kv: -kv[1])[: (top if key else 5)]
        items.append(
            {
                "key": k,
                "assets": sum(vals.values()),
                "distinct_values": len(vals),
                "top_values": dict(top_vals),
            }
        )
    page, env = bounded(items, top)
    return {"dataset": ds.name, **env, "items": page}


@CATALOG.tool(title="Coverage report", sensitivity=Sensitivity.INTERNAL, **_RO)
def coverage_report(ctx: Any, dataset: DatasetArg = "") -> dict:
    """Which collectors / services succeeded or failed per provider,
    account and region during collection, with error messages for
    failures. Explains gaps (e.g. AccessDenied) before trusting the map.
    Only live collections carry coverage records."""
    ds = ws_dataset(ctx, dataset)
    if not ds.coverage:
        return {
            "dataset": ds.name,
            "records": [],
            "note": "This dataset has no coverage records (they exist only for live "
            "collections via map_inventory / collect_assets).",
        }
    records = [c.to_summary() for c in ds.coverage]
    total = sum(r["total_services"] for r in records)
    ok = sum(r["successful"] for r in records)
    return {
        "dataset": ds.name,
        "records": records,
        "total_services": total,
        "successful": ok,
        "failed": sum(r["failed"] for r in records),
        "coverage_pct": round(ok / total * 100, 1) if total else 0.0,
    }


@CATALOG.tool(title="Unresolved references", sensitivity=Sensitivity.CONFIDENTIAL, **_RO)
def unresolved_references(
    ctx: Any, limit: Limit = DEFAULT_LIMIT, cursor: Cursor = "", dataset: DatasetArg = ""
) -> dict:
    """Relations the linker could not resolve to a mapped asset (e.g. a
    role ARN in a service that was not collected). They are blind spots in
    the relationship graph."""
    ds = ws_dataset(ctx, dataset)
    page, env = paginate(ds.unresolved_references, limit, cursor, fingerprint(ds, t="unres"))
    return {"dataset": ds.name, **env, "items": page}


@CATALOG.tool(title="Organization topology", sensitivity=Sensitivity.CONFIDENTIAL, **_RO)
def organization_topology(
    ctx: Any,
    include_policies: bool = False,
    max_accounts: Annotated[int, Field(ge=1, le=1000)] = 200,
    dataset: DatasetArg = "",
) -> dict:
    """The organization hierarchy: organization, OUs / management groups
    / folders, member accounts with their OU path, Control Tower landing
    zone and governed regions, and (optionally) the SCPs / org policies
    and what they target."""
    ds = ws_dataset(ctx, dataset)
    if ds.organization:
        return org_from_discovery(ds, ds.organization, include_policies, max_accounts)
    return org_from_assets(ds, include_policies, max_accounts)


def register(reg: Registry) -> None:
    """Add this module's tools to ``reg``."""
    CATALOG.register(reg)
