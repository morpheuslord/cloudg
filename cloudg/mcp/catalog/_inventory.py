"""Helpers behind the inventory tools: the asset filter, sort and group
keys, metadata truncation and the organization topology views."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Callable, Sequence

from cloudg.inventory.mapper_result import _service_of
from cloudg.mcp.catalog._common import parse_enum, parse_enums, parse_severity
from cloudg.mcp.state import SEVERITY_RANK, Dataset
from cloudg.schema.models import AssetType, CloudAsset, CloudProvider

_HIERARCHY = {AssetType.ORGANIZATION, AssetType.ORG_UNIT, AssetType.CLOUD_ACCOUNT}

Predicate = Callable[[CloudAsset], bool]


@dataclass(frozen=True)
class AssetFilter:
    """The filters find_assets / count_assets accept (empty = no filter)."""

    query: str = ""
    provider: str = ""
    asset_types: Sequence[str] | None = None
    region: str = ""
    account_id: str = ""
    tag: str = ""
    internet_exposed: bool | None = None
    has_findings: bool | None = None
    min_severity: str = ""


def _tag_predicate(tag: str) -> Predicate:
    key, has_val, val = tag.partition("=")
    if has_val:
        return lambda a: key in a.tags and a.tags[key] == val
    return lambda a: key in a.tags


def _query_predicate(query: str) -> Predicate:
    q = query.lower().strip()

    def match(a: CloudAsset) -> bool:
        return (
            q in a.name.lower()
            or q in (a.arn or "").lower()
            or q in a.id.lower()
            or any(q in str(v).lower() for v in a.tags.values())
        )

    return match


def _finding_predicate(ds: Dataset, flt: AssetFilter) -> Predicate | None:
    min_rank = SEVERITY_RANK[parse_severity(flt.min_severity).value] if flt.min_severity else None
    if flt.has_findings is None and min_rank is None:
        return None

    def match(a: CloudAsset) -> bool:
        open_f = ds.open_findings(a.id)
        if flt.has_findings is not None and bool(open_f) != flt.has_findings:
            return False
        return min_rank is None or any(SEVERITY_RANK[f.severity.value] >= min_rank for f in open_f)

    return match


def _predicates(ds: Dataset, flt: AssetFilter) -> list[Predicate]:
    preds: list[Predicate] = []
    if flt.provider:
        prov = parse_enum(flt.provider, CloudProvider, "provider")
        preds.append(lambda a: a.provider == prov)
    types = parse_enums(flt.asset_types, AssetType, "asset type")
    if types:
        preds.append(lambda a: a.asset_type in types)
    if flt.region:
        region = flt.region.lower()
        preds.append(lambda a: a.region.lower() == region)
    if flt.account_id:
        preds.append(lambda a: (a.account_id or "") == flt.account_id)
    if flt.tag:
        preds.append(_tag_predicate(flt.tag))
    if flt.internet_exposed is not None:
        preds.append(lambda a: a.is_internet_exposed == flt.internet_exposed)
    by_findings = _finding_predicate(ds, flt)
    if by_findings is not None:
        preds.append(by_findings)
    if flt.query.strip():
        preds.append(_query_predicate(flt.query))
    return preds


def filter_assets(ds: Dataset, flt: AssetFilter | None = None) -> list[CloudAsset]:
    """Assets of ``ds`` matching every filter of ``flt``."""
    preds = _predicates(ds, flt or AssetFilter())
    return [a for a in ds.assets if all(p(a) for p in preds)]


def risk_key(ds: Dataset, a: CloudAsset) -> tuple:
    open_f = ds.open_findings(a.id)
    best = max((f.risk_score for f in open_f), default=0.0)
    return (best + (2.0 if a.is_internet_exposed else 0.0), len(open_f))


def sort_assets(ds: Dataset, assets: list[CloudAsset], sort_by: str, descending: bool) -> None:
    """Sort in place; 'risk' and 'findings' put the highest first unless
    ``descending`` flips them."""
    keys: dict[str, Callable[[CloudAsset], Any]] = {
        "name": lambda a: (a.name.lower(), a.id),
        "type": lambda a: (a.asset_type.value, a.name.lower()),
        "region": lambda a: (a.region, a.name.lower()),
        "account": lambda a: (a.account_id or "", a.name.lower()),
        "risk": lambda a: risk_key(ds, a),
        "findings": lambda a: (len(ds.open_findings(a.id)), a.name.lower()),
    }
    reverse = descending if sort_by not in ("risk", "findings") else not descending
    assets.sort(key=keys[sort_by], reverse=reverse)


def _worst_severity(ds: Dataset, a: CloudAsset) -> str:
    fs = ds.open_findings(a.id)
    return max((f.severity.value for f in fs), key=lambda s: SEVERITY_RANK[s], default="NONE")


def group_key(ds: Dataset, a: CloudAsset, group_by: str) -> str:
    """The count_assets group an asset falls in."""
    keys: dict[str, Callable[[CloudAsset], str]] = {
        "type": lambda x: x.asset_type.value,
        "provider": lambda x: x.provider.value,
        "region": lambda x: x.region,
        "account": lambda x: x.account_id or "unknown",
        "service": _service_of,
        "exposure": lambda x: "internet_exposed" if x.is_internet_exposed else "internal",
    }
    fn = keys.get(group_by)
    return fn(a) if fn else _worst_severity(ds, a)


def relation_view(ds: Dataset, a: CloudAsset, max_relations: int) -> dict[str, Any]:
    """get_asset's relation counts by edge type plus the first edges."""
    from cloudg.mcp.catalog._common import edge_brief

    rel: dict[str, Any] = {"outgoing": {}, "incoming": {}}
    out_edges = [e for e in ds.edges if e.source_id == a.id]
    in_edges = [e for e in ds.edges if e.target_id == a.id]
    for side, edges in (("outgoing", out_edges), ("incoming", in_edges)):
        for e in edges:
            rel[side][e.edge_type.value] = rel[side].get(e.edge_type.value, 0) + 1
    rel["sample"] = [edge_brief(ds, e) for e in (out_edges + in_edges)[:max_relations]]
    rel["total"] = len(out_edges) + len(in_edges)
    rel["truncated"] = rel["total"] > max_relations
    return rel


def truncate_metadata(meta: dict[str, Any], max_chars: int) -> dict[str, Any]:
    """Fit ``meta`` into ``max_chars`` of JSON, largest keys dropped first."""
    if len(json.dumps(meta, default=str)) <= max_chars:
        return {"truncated": False, "metadata": meta}
    sizes = {k: len(json.dumps(v, default=str)) for k, v in meta.items()}
    kept, total = {}, 0
    for k, v in meta.items():
        if total + sizes[k] > max_chars:
            continue
        kept[k] = v
        total += sizes[k]
    return {
        "truncated": True,
        "key_sizes": dict(sorted(sizes.items(), key=lambda kv: -kv[1])[:50]),
        "hint": "Metadata exceeds max_chars; request specific keys.",
        "metadata": kept,
    }


def account_rows(ds: Dataset) -> list[dict[str, Any]]:
    """One row per account / subscription / project, most assets first."""
    accts: dict[str, dict[str, Any]] = {}
    names: dict[str, tuple[str, bool]] = {}
    for a in ds.assets:
        if a.asset_type == AssetType.CLOUD_ACCOUNT and a.account_id:
            names[a.account_id] = (a.name, bool(a.metadata.get("external")))
        acct = a.account_id or "unknown"
        e = accts.setdefault(
            acct,
            {"account_id": acct, "provider": a.provider.value, "assets": 0, "regions": set(),
             "internet_exposed": 0, "open_findings": 0},
        )
        e["assets"] += 1
        e["regions"].add(a.region)
        e["internet_exposed"] += int(a.is_internet_exposed)
        e["open_findings"] += len(ds.open_findings(a.id))
    items = []
    for acct, e in sorted(accts.items(), key=lambda kv: -kv[1]["assets"]):
        name, external = names.get(acct, (None, False))
        items.append({**e, "regions": sorted(e["regions"]), "name": name, "external": external})
    return items


# ---------------------------------------------------------------------------
# Organization topology
# ---------------------------------------------------------------------------


def _pick(d: dict[str, Any], keys: Sequence[str]) -> dict[str, Any]:
    return {k: d.get(k) for k in keys}


def org_from_discovery(
    ds: Dataset, org: dict[str, Any], include_policies: bool, max_accounts: int
) -> dict[str, Any]:
    """Topology from organization discovery (``Dataset.organization``)."""
    accounts = list((org.get("accounts") or {}).values())
    ous = list((org.get("ous") or {}).values())
    out: dict[str, Any] = {
        "dataset": ds.name,
        "source": "organization_discovery",
        "organization_id": org.get("organization_id"),
        "management_account_id": org.get("management_account_id"),
        "feature_set": org.get("feature_set"),
        "control_tower_enabled": bool(org.get("control_tower_enabled", org.get("landing_zone"))),
        "governed_regions": org.get("governed_regions", []),
        "shared_accounts": org.get("shared_accounts", {}),
        "ous": [_pick(o, ("id", "name", "path", "parent_id")) for o in ous],
        "accounts": [
            _pick(a, ("id", "name", "status", "ou_path", "parent_id"))
            for a in accounts[:max_accounts]
        ],
        "total_accounts": len(accounts),
        "truncated": len(accounts) > max_accounts,
    }
    if include_policies:
        out["policies"] = [
            {**_pick(p, ("id", "name", "type", "aws_managed")), "targets": p.get("targets", [])}
            for p in org.get("policies", [])
        ]
    return out


def _org_policies(ds: Dataset) -> list[dict[str, Any]]:
    pols = [a for a in ds.assets if a.asset_type == AssetType.ORG_POLICY]
    pol_ids = {p.id for p in pols}
    targets: dict[str, list[str]] = {}
    for e in ds.edges:
        if e.edge_type.value == "GOVERNS" and e.source_id in pol_ids:
            targets.setdefault(e.source_id, []).append(e.target_id)
    return [{"id": p.id, "name": p.name, "targets": targets.get(p.id, [])} for p in pols]


def org_from_assets(ds: Dataset, include_policies: bool, max_accounts: int) -> dict[str, Any]:
    """Topology rebuilt from the hierarchy assets on the map."""
    hier = [a for a in ds.assets if a.asset_type in _HIERARCHY]
    if not hier:
        return {
            "dataset": ds.name,
            "source": None,
            "note": "No organization data in this dataset. Map with organization discovery "
            "enabled to get it.",
        }
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
        out["policies"] = _org_policies(ds)
    return out
