"""Completions and content builders shared by the resources and prompts."""

from __future__ import annotations

from typing import Any

from cloudg.mcp.catalog._common import asset_brief, finding_brief, max_severity
from cloudg.mcp.state import SEVERITY_RANK, Dataset, ReferenceNotFoundError
from cloudg.schema.models import AssetType, Severity

GRAPH_FORMATS = ("d3", "cytoscape", "graphml")
ONTOLOGY_FORMATS = {
    "turtle": "text/turtle",
    "json-ld": "application/ld+json",
    "xml": "application/rdf+xml",
    "nt": "application/n-triples",
}


# ---------------------------------------------------------------------------
# Completions (fn(ctx, partial) -> list[str])
# ---------------------------------------------------------------------------


def _ctx_dataset(ctx: Any) -> Dataset | None:
    name = (getattr(ctx, "meta", {}) or {}).get("arguments", {}).get("dataset") or None
    try:
        return ctx.workspace.get(name)
    except Exception:
        return None


def complete_dataset(ctx: Any, partial: str = "") -> list[str]:
    return [n for n in ctx.workspace.names() if n.lower().startswith(partial.lower())]


def complete_asset(ctx: Any, partial: str = "") -> list[str]:
    ds = _ctx_dataset(ctx)
    if ds is None:
        return []
    p = partial.lower()
    names: dict[str, int] = {}
    for a in ds.assets:
        names[a.name] = names.get(a.name, 0) + 1
    starts, contains = [], []
    for a in ds.assets:
        # Unique names complete to the name; shared names to the ARN / id
        label = a.name if names[a.name] == 1 else (a.arn or a.id)
        keys = [k.lower() for k in (a.name, a.arn or "", a.id)]
        if not p or any(k.startswith(p) for k in keys):
            starts.append(label)
        elif any(p in k for k in keys):
            contains.append(label)
    # The full list: the layer caps what it sends and computes hasMore
    return list(dict.fromkeys(sorted(starts) + sorted(contains)))


def complete_finding(ctx: Any, partial: str = "") -> list[str]:
    ds = _ctx_dataset(ctx)
    if ds is None:
        return []
    ranked = sorted(ds.findings, key=lambda f: -f.risk_score)
    return [f.id for f in ranked if f.id.startswith(partial)]


def complete_severity(ctx: Any, partial: str = "") -> list[str]:
    return [s.value for s in Severity if s.value.startswith(partial.upper())]


def complete_framework(ctx: Any, partial: str = "") -> list[str]:
    names: set[str] = set()
    ds = _ctx_dataset(ctx)
    if ds is not None:
        names |= {c.framework for c in ds.compliance}
        names |= {fw for f in ds.findings for fw in f.compliance_frameworks}
    if not names:
        from cloudg.mcp.catalog.compliance import _rules_dir, ruleset_catalog

        names = set(ruleset_catalog(_rules_dir(ctx)))
    return sorted(n for n in names if partial.lower() in n.lower())


def complete_asset_type(ctx: Any, partial: str = "") -> list[str]:
    return [t.value for t in AssetType if t.value.startswith(partial.upper())]


def complete_graph_format(ctx: Any, partial: str = "") -> list[str]:
    return [f for f in GRAPH_FORMATS if f.startswith(partial.lower())]


def complete_ontology_format(ctx: Any, partial: str = "") -> list[str]:
    return [f for f in ONTOLOGY_FORMATS if f.startswith(partial.lower())]


# ---------------------------------------------------------------------------
# Content builders shared with prompts
# ---------------------------------------------------------------------------


def asset_detail(ds: Dataset, ref: str) -> dict[str, Any]:
    if ref in ds.graph and ref not in ds.by_id:
        return {
            "id": ref,
            "external": True,
            "name": ds.graph.nodes[ref].get("name", ref),
            "degree": ds.graph.degree(ref),
        }
    a = ds.resolve_asset(ref)
    out = asset_brief(ds, a, tags=True)
    rel: dict[str, dict[str, int]] = {"outgoing": {}, "incoming": {}}
    for e, _, d in ds.adjacency.get(a.id, []):
        side = rel["outgoing" if d == "out" else "incoming"]
        side[e.edge_type.value] = side.get(e.edge_type.value, 0) + 1
    out["relations"] = rel
    out["findings"] = [
        finding_brief(ds, f)
        for f in sorted(ds.open_findings(a.id), key=lambda f: -f.risk_score)[:10]
    ]
    out["metadata_keys"] = sorted(a.metadata)[:100]
    needs, needed_by = ds.dependency_graph().direct_counts(a.id)
    out["dependencies"] = {"direct_depends_on": needs, "direct_dependents": needed_by}
    return out


def finding_detail(ds: Dataset, f: Any) -> dict[str, Any]:
    """Content of ``cloudg://findings/{finding_id}``."""
    return {
        **finding_brief(ds, f),
        "description": f.description,
        "evidence": f.evidence,
        "remediation": f.remediation,
    }


def framework_detail(ds: Dataset, framework: str) -> dict[str, Any]:
    """Content of ``cloudg://compliance/{framework}``."""
    from cloudg.mcp.catalog._compliance import framework_rollup, open_control_findings

    rows = [
        r for r in framework_rollup(ds, framework) if r["framework"].lower() == framework.lower()
    ] or framework_rollup(ds, framework)
    if not rows:
        raise ReferenceNotFoundError(
            "No compliance data for that framework.", data={"value": framework}
        )
    fw_names = {r["framework"] for r in rows}
    failing = []
    for c in ds.compliance:
        if c.framework in fw_names and c.status.value == "FAIL":
            open_f = open_control_findings(ds, c)
            failing.append(
                {
                    "framework": c.framework,
                    "control_id": c.control_id,
                    "control_title": c.control_title,
                    "open_findings": len(open_f),
                    "max_severity": max_severity(open_f),
                }
            )
    failing.sort(key=lambda r: (-SEVERITY_RANK.get(r["max_severity"] or "", -1), r["control_id"]))
    return {"dataset": ds.name, "posture": rows, "failing_controls": failing[:300]}
