"""Inventory tools: search, inspect and aggregate the assets of a dataset.

These answer "what do we have": filtered / sorted / paginated asset
search, one asset in detail, counts by any dimension, accounts, regions,
tags, collection coverage, unresolved references and the organization
(AWS Organizations / Control Tower, Azure management groups, GCP folders)
topology.
"""

from __future__ import annotations

import json
from typing import Annotated, Any, Literal

from pydantic import Field

from cloudg.inventory.mapper_result import _service_of
from cloudg.mcp.catalog._common import (
    ASSET_FIELDS,
    DEFAULT_LIMIT,
    AssetDetailOut,
    AssetPageOut,
    CountOut,
    Cursor,
    DatasetArg,
    Limit,
    RefArg,
    asset_brief,
    asset_uri,
    bounded,
    check_fields,
    edge_brief,
    finding_brief,
    fingerprint,
    paginate,
    parse_enum,
    parse_enums,
    parse_severity,
    project,
    schema,
    ws_dataset,
)
from cloudg.mcp.core import Capability, Registry, Sensitivity
from cloudg.mcp.state import SEVERITY_RANK, Dataset
from cloudg.schema.models import AssetType, CloudAsset, CloudProvider

CATEGORY = "inventory"
R = Capability.READ_STATE
_HIERARCHY = {AssetType.ORGANIZATION, AssetType.ORG_UNIT, AssetType.CLOUD_ACCOUNT}

SortKey = Literal["name", "type", "region", "account", "risk", "findings"]
GroupBy = Literal["type", "provider", "region", "account", "service", "exposure", "severity"]


def filter_assets(
    ds: Dataset,
    *,
    query: str = "",
    provider: str = "",
    asset_types: list[str] | None = None,
    region: str = "",
    account_id: str = "",
    tag: str = "",
    internet_exposed: bool | None = None,
    has_findings: bool | None = None,
    min_severity: str = "",
) -> list[CloudAsset]:
    """Shared asset filter used by find_assets / count_assets."""
    prov = parse_enum(provider, CloudProvider, "provider") if provider else None
    types = parse_enums(asset_types, AssetType, "asset type")
    min_rank = SEVERITY_RANK[parse_severity(min_severity).value] if min_severity else None
    tag_key, _, tag_val = tag.partition("=")
    has_val = "=" in tag
    q = query.lower().strip()
    out = []
    for a in ds.assets:
        if prov and a.provider != prov:
            continue
        if types and a.asset_type not in types:
            continue
        if region and a.region.lower() != region.lower():
            continue
        if account_id and (a.account_id or "") != account_id:
            continue
        if tag:
            if tag_key not in a.tags:
                continue
            if has_val and a.tags[tag_key] != tag_val:
                continue
        if internet_exposed is not None and a.is_internet_exposed != internet_exposed:
            continue
        if has_findings is not None or min_rank is not None:
            open_f = ds.open_findings(a.id)
            if has_findings is not None and bool(open_f) != has_findings:
                continue
            if min_rank is not None and not any(
                SEVERITY_RANK[f.severity.value] >= min_rank for f in open_f
            ):
                continue
        if q and not (
            q in a.name.lower() or q in (a.arn or "").lower() or q in a.id.lower()
            or any(q in str(v).lower() for v in a.tags.values())
        ):
            continue
        out.append(a)
    return out


def _risk_key(ds: Dataset, a: CloudAsset) -> tuple:
    open_f = ds.open_findings(a.id)
    best = max((f.risk_score for f in open_f), default=0.0)
    return (best + (2.0 if a.is_internet_exposed else 0.0), len(open_f))


def register(reg: Registry) -> None:
    @reg.tool(
        title="Find assets",
        category=CATEGORY,
        sensitivity=Sensitivity.CONFIDENTIAL,
        read_only=True,
        idempotent=True,
        open_world=False,
        output_schema=schema(AssetPageOut),
        tags={"start-here"},
    )
    def find_assets(
        ctx: Any,
        query: Annotated[
            str, Field(description="Case-insensitive substring of name, ARN, id or a tag value.")
        ] = "",
        provider: Annotated[str, Field(description="aws, azure or gcp.")] = "",
        asset_types: Annotated[
            list[str] | None,
            Field(description="AssetType values, e.g. ['EC2','S3_BUCKET'] (describe_schema)."),
        ] = None,
        region: Annotated[str, Field(description="Exact region, e.g. us-east-1.")] = "",
        account_id: Annotated[str, Field(description="Exact account / subscription / project.")]
        = "",
        tag: Annotated[str, Field(description="Tag filter: 'key' or 'key=value'.")] = "",
        internet_exposed: Annotated[
            bool | None, Field(description="Only exposed (true) / not exposed (false).")
        ] = None,
        has_findings: Annotated[
            bool | None,
            Field(description="Only assets with (true) / without (false) open findings."),
        ] = None,
        min_severity: Annotated[
            str, Field(description="Only assets with an open finding at or above this severity.")
        ] = "",
        sort_by: Annotated[
            SortKey, Field(description="'risk' ranks by worst finding + exposure.")
        ] = "name",
        descending: bool = False,
        fields: Annotated[
            list[str] | None,
            Field(description="Project each item to these fields. Valid: "
                  f"{', '.join(ASSET_FIELDS)}"),
        ] = None,
        limit: Limit = DEFAULT_LIMIT,
        cursor: Cursor = "",
        dataset: DatasetArg = "",
    ) -> dict:
        """Search assets with filters (provider, type, region, account, tag,
        exposure, findings, severity, free text), sorting and cursor
        pagination. Returns compact briefs; call get_asset (or read the
        item's uri) for details. Example: find internet-exposed EC2 with
        HIGH findings: asset_types=['EC2'], internet_exposed=true,
        min_severity='HIGH'."""
        ds = ws_dataset(ctx, dataset)
        proj = check_fields(fields, ASSET_FIELDS)
        matched = filter_assets(
            ds, query=query, provider=provider, asset_types=asset_types, region=region,
            account_id=account_id, tag=tag, internet_exposed=internet_exposed,
            has_findings=has_findings, min_severity=min_severity,
        )
        keys = {
            "name": lambda a: (a.name.lower(), a.id),
            "type": lambda a: (a.asset_type.value, a.name.lower()),
            "region": lambda a: (a.region, a.name.lower()),
            "account": lambda a: (a.account_id or "", a.name.lower()),
            "risk": lambda a: _risk_key(ds, a),
            "findings": lambda a: (len(ds.open_findings(a.id)), a.name.lower()),
        }
        reverse = descending if sort_by not in ("risk", "findings") else not descending
        matched.sort(key=keys[sort_by], reverse=reverse)
        fp = fingerprint(
            ds, q=query, p=provider, t=asset_types, r=region, a=account_id, tag=tag,
            ie=internet_exposed, hf=has_findings, ms=min_severity, s=sort_by, d=descending,
        )
        page, env = paginate(matched, limit, cursor, fp)
        items = [project(asset_brief(ds, a, tags="tags" in (proj or [])), proj) for a in page]
        out = {"dataset": ds.name, **env, "items": items}
        if not matched and ds.assets:
            out["hint"] = (
                "No assets matched. Loosen the filters, or use list_asset_types / "
                "list_accounts / list_regions to see valid values."
            )
        return out

    @reg.tool(
        title="Get asset",
        category=CATEGORY,
        sensitivity=Sensitivity.CONFIDENTIAL,
        read_only=True,
        idempotent=True,
        open_world=False,
        output_schema=schema(AssetDetailOut),
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
        rel: dict[str, Any] = {"outgoing": {}, "incoming": {}}
        out_edges = [e for e in ds.edges if e.source_id == a.id]
        in_edges = [e for e in ds.edges if e.target_id == a.id]
        for e in out_edges:
            rel["outgoing"][e.edge_type.value] = rel["outgoing"].get(e.edge_type.value, 0) + 1
        for e in in_edges:
            rel["incoming"][e.edge_type.value] = rel["incoming"].get(e.edge_type.value, 0) + 1
        rel["sample"] = [edge_brief(ds, e) for e in (out_edges + in_edges)[:max_relations]]
        rel["total"] = len(out_edges) + len(in_edges)
        rel["truncated"] = rel["total"] > max_relations
        out["relations"] = rel
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

    @reg.tool(
        title="Get asset metadata",
        category=CATEGORY,
        sensitivity=Sensitivity.RESTRICTED,
        read_only=True,
        idempotent=True,
        open_world=False,
    )
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
        if keys:
            missing = [k for k in keys if k not in meta]
            meta = {k: meta[k] for k in keys if k in meta}
        else:
            missing = []
        text = json.dumps(meta, default=str)
        out: dict[str, Any] = {"id": a.id, "name": a.name, "type": a.asset_type.value}
        if len(text) > max_chars:
            sizes = {k: len(json.dumps(v, default=str)) for k, v in meta.items()}
            out["truncated"] = True
            out["key_sizes"] = dict(sorted(sizes.items(), key=lambda kv: -kv[1])[:50])
            out["hint"] = "Metadata exceeds max_chars; request specific keys."
            kept, total = {}, 0
            for k, v in meta.items():
                if total + sizes[k] > max_chars:
                    continue
                kept[k] = v
                total += sizes[k]
            out["metadata"] = kept
        else:
            out["truncated"] = False
            out["metadata"] = meta
        if missing:
            out["missing_keys"] = missing
        return out

    @reg.tool(
        title="Count assets",
        category=CATEGORY,
        sensitivity=Sensitivity.INTERNAL,
        read_only=True,
        idempotent=True,
        open_world=False,
        output_schema=schema(CountOut),
    )
    def count_assets(
        ctx: Any,
        group_by: GroupBy = "type",
        provider: str = "",
        asset_types: list[str] | None = None,
        region: str = "",
        account_id: str = "",
        internet_exposed: bool | None = None,
        top: Annotated[int, Field(ge=1, le=500)] = 50,
        dataset: DatasetArg = "",
    ) -> dict:
        """Count assets grouped by type, provider, region, account, cloud
        service, exposure or worst open-finding severity, with optional
        filters. A cheap aggregate view with no identifiers beyond group keys."""
        ds = ws_dataset(ctx, dataset)
        matched = filter_assets(
            ds, provider=provider, asset_types=asset_types, region=region,
            account_id=account_id, internet_exposed=internet_exposed,
        )

        def key(a: CloudAsset) -> str:
            if group_by == "type":
                return a.asset_type.value
            if group_by == "provider":
                return a.provider.value
            if group_by == "region":
                return a.region
            if group_by == "account":
                return a.account_id or "unknown"
            if group_by == "service":
                return _service_of(a)
            if group_by == "exposure":
                return "internet_exposed" if a.is_internet_exposed else "internal"
            fs = ds.open_findings(a.id)
            return max((f.severity.value for f in fs), key=lambda s: SEVERITY_RANK[s],
                       default="NONE")

        groups: dict[str, int] = {}
        for a in matched:
            k = key(a)
            groups[k] = groups.get(k, 0) + 1
        ordered = sorted(groups.items(), key=lambda kv: (-kv[1], kv[0]))
        return {
            "dataset": ds.name,
            "group_by": group_by,
            "total": len(matched),
            "group_count": len(groups),
            "groups": dict(ordered[:top]),
            "truncated": len(groups) > top,
        }

    @reg.tool(
        title="List asset types",
        category=CATEGORY,
        sensitivity=Sensitivity.INTERNAL,
        read_only=True,
        idempotent=True,
        open_world=False,
    )
    def list_asset_types(ctx: Any, dataset: DatasetArg = "") -> dict:
        """Asset types present in the dataset with counts, exposed counts
        and open-finding counts. These are the valid values for asset_types filters."""
        ds = ws_dataset(ctx, dataset)
        stats: dict[str, dict[str, int]] = {}
        for a in ds.assets:
            s = stats.setdefault(a.asset_type.value, {"count": 0, "internet_exposed": 0,
                                                      "open_findings": 0})
            s["count"] += 1
            s["internet_exposed"] += int(a.is_internet_exposed)
            s["open_findings"] += len(ds.open_findings(a.id))
        items = [{"type": t, **s} for t, s in sorted(stats.items(), key=lambda kv: -kv[1]["count"])]
        return {"dataset": ds.name, "total_types": len(items), "items": items}

    @reg.tool(
        title="List accounts",
        category=CATEGORY,
        sensitivity=Sensitivity.CONFIDENTIAL,
        read_only=True,
        idempotent=True,
        open_world=False,
    )
    def list_accounts(
        ctx: Any, limit: Limit = 100, cursor: Cursor = "", dataset: DatasetArg = ""
    ) -> dict:
        """Accounts / subscriptions / projects in the dataset with provider,
        display name, asset count, regions, exposed assets, open findings
        and whether the account is external (only referenced, not mapped)."""
        ds = ws_dataset(ctx, dataset)
        accts: dict[str, dict[str, Any]] = {}
        names: dict[str, tuple[str, bool]] = {}
        for a in ds.assets:
            if a.asset_type == AssetType.CLOUD_ACCOUNT and a.account_id:
                names[a.account_id] = (a.name, bool(a.metadata.get("external")))
            acct = a.account_id or "unknown"
            e = accts.setdefault(acct, {"account_id": acct, "provider": a.provider.value,
                                        "assets": 0, "regions": set(), "internet_exposed": 0,
                                        "open_findings": 0})
            e["assets"] += 1
            e["regions"].add(a.region)
            e["internet_exposed"] += int(a.is_internet_exposed)
            e["open_findings"] += len(ds.open_findings(a.id))
        items = []
        for acct, e in sorted(accts.items(), key=lambda kv: -kv[1]["assets"]):
            name, external = names.get(acct, (None, False))
            items.append({**e, "regions": sorted(e["regions"]), "name": name,
                          "external": external})
        page, env = paginate(items, limit, cursor, fingerprint(ds, t="accounts"))
        return {"dataset": ds.name, **env, "items": page}

    @reg.tool(
        title="List regions",
        category=CATEGORY,
        sensitivity=Sensitivity.INTERNAL,
        read_only=True,
        idempotent=True,
        open_world=False,
    )
    def list_regions(ctx: Any, dataset: DatasetArg = "") -> dict:
        """Regions in the dataset with providers, asset and account counts,
        plus the regions each provider was configured / scanned for."""
        ds = ws_dataset(ctx, dataset)
        regions: dict[str, dict[str, Any]] = {}
        for a in ds.assets:
            r = regions.setdefault(a.region, {"region": a.region, "providers": set(),
                                              "assets": 0, "accounts": set()})
            r["providers"].add(a.provider.value)
            r["assets"] += 1
            if a.account_id:
                r["accounts"].add(a.account_id)
        items = [
            {**r, "providers": sorted(r["providers"]), "accounts": len(r["accounts"])}
            for r in sorted(regions.values(), key=lambda r: -r["assets"])
        ]
        return {"dataset": ds.name, "total": len(items), "items": items,
                "scanned_regions": ds.regions}

    @reg.tool(
        title="List tags",
        category=CATEGORY,
        sensitivity=Sensitivity.CONFIDENTIAL,
        read_only=True,
        idempotent=True,
        open_world=False,
    )
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
            items.append({"key": k, "assets": sum(vals.values()), "distinct_values": len(vals),
                          "top_values": dict(top_vals)})
        page, env = bounded(items, top)
        return {"dataset": ds.name, **env, "items": page}

    @reg.tool(
        title="Coverage report",
        category=CATEGORY,
        sensitivity=Sensitivity.INTERNAL,
        read_only=True,
        idempotent=True,
        open_world=False,
    )
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

    @reg.tool(
        title="Unresolved references",
        category=CATEGORY,
        sensitivity=Sensitivity.CONFIDENTIAL,
        read_only=True,
        idempotent=True,
        open_world=False,
    )
    def unresolved_references(
        ctx: Any, limit: Limit = DEFAULT_LIMIT, cursor: Cursor = "", dataset: DatasetArg = ""
    ) -> dict:
        """Relations the linker could not resolve to a mapped asset (e.g. a
        role ARN in a service that was not collected). They are blind spots in
        the relationship graph."""
        ds = ws_dataset(ctx, dataset)
        page, env = paginate(ds.unresolved_references, limit, cursor, fingerprint(ds, t="unres"))
        return {"dataset": ds.name, **env, "items": page}

    @reg.tool(
        title="Organization topology",
        category=CATEGORY,
        sensitivity=Sensitivity.CONFIDENTIAL,
        read_only=True,
        idempotent=True,
        open_world=False,
    )
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
        org = ds.organization
        if org:
            accounts = list((org.get("accounts") or {}).values())
            ous = list((org.get("ous") or {}).values())
            out: dict[str, Any] = {
                "dataset": ds.name,
                "source": "organization_discovery",
                "organization_id": org.get("organization_id"),
                "management_account_id": org.get("management_account_id"),
                "feature_set": org.get("feature_set"),
                "control_tower_enabled": bool(
                    org.get("control_tower_enabled", org.get("landing_zone"))
                ),
                "governed_regions": org.get("governed_regions", []),
                "shared_accounts": org.get("shared_accounts", {}),
                "ous": [
                    {"id": o.get("id"), "name": o.get("name"), "path": o.get("path"),
                     "parent_id": o.get("parent_id")}
                    for o in ous
                ],
                "accounts": [
                    {"id": a.get("id"), "name": a.get("name"), "status": a.get("status"),
                     "ou_path": a.get("ou_path"), "parent_id": a.get("parent_id")}
                    for a in accounts[:max_accounts]
                ],
                "total_accounts": len(accounts),
                "truncated": len(accounts) > max_accounts,
            }
            if include_policies:
                out["policies"] = [
                    {"id": p.get("id"), "name": p.get("name"), "type": p.get("type"),
                     "aws_managed": p.get("aws_managed"), "targets": p.get("targets", [])}
                    for p in org.get("policies", [])
                ]
            return out
        # Fall back to the hierarchy assets on the map
        hier = [a for a in ds.assets if a.asset_type in _HIERARCHY]
        if not hier:
            return {"dataset": ds.name, "source": None, "note": "No organization data in this "
                    "dataset. Map with organization discovery enabled to get it."}
        ids = {a.id for a in hier}
        parents = {
            e.target_id: e.source_id
            for e in ds.edges
            if e.edge_type.value == "CONTAINS" and e.source_id in ids and e.target_id in ids
        }
        nodes = [
            {"id": a.id, "name": a.name, "type": a.asset_type.value, "account_id": a.account_id,
             "parent_id": parents.get(a.id), "external": bool(a.metadata.get("external"))}
            for a in hier
        ]
        out = {"dataset": ds.name, "source": "map_assets", "nodes": nodes[:max_accounts],
               "total": len(nodes), "truncated": len(nodes) > max_accounts}
        if include_policies:
            pols = [a for a in ds.assets if a.asset_type == AssetType.ORG_POLICY]
            targets: dict[str, list[str]] = {}
            for e in ds.edges:
                if e.edge_type.value == "GOVERNS" and e.source_id in {p.id for p in pols}:
                    targets.setdefault(e.source_id, []).append(e.target_id)
            out["policies"] = [{"id": p.id, "name": p.name, "targets": targets.get(p.id, [])}
                               for p in pols]
        return out
