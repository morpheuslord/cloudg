"""Graph tools about impact and structure: blast radius, dependencies,
shared dependencies, cross-account edges, centrality, sub-graph export,
security-service coverage and graph statistics. Registered by
:func:`cloudg.mcp.catalog.graph.register` after the path and exposure
tools, so the tool order is unchanged."""

from __future__ import annotations

from typing import Annotated, Any, Callable, Literal

import networkx as nx
from pydantic import Field

from cloudg.mcp.catalog._common import (
    DEFAULT_LIMIT,
    Catalog,
    Cursor,
    DatasetArg,
    DependencyOut,
    Limit,
    RefArg,
    asset_brief,
    asset_uri,
    bounded,
    fingerprint,
    node_brief,
    paginate,
    parse_enums,
    schema,
    ws_dataset,
)
from cloudg.mcp.catalog._graph import (
    CROWN_JEWELS,
    Walk,
    bfs,
    dep_items,
    prune_tree,
    resolve_node,
)
from cloudg.mcp.core import Sensitivity
from cloudg.mcp.state import Dataset
from cloudg.schema.models import AssetType, EdgeType

CATEGORY = "graph"

GraphFormat = Literal["d3", "cytoscape", "graphml"]
Metric = Literal["degree", "in_degree", "out_degree", "betweenness"]
DepthArg = Annotated[int, Field(ge=1, le=15)]
DepLimit = Annotated[int, Field(ge=1, le=500)]

_RO = dict(read_only=True, idempotent=True, open_world=False, category=CATEGORY)

CATALOG = Catalog()


def _edge_types(values: list[str] | None) -> set[str]:
    return {t.value for t in parse_enums(values, EdgeType, "edge type")}


@CATALOG.tool(title="Blast radius", sensitivity=Sensitivity.CONFIDENTIAL, **_RO)
def blast_radius(
    ctx: Any,
    ref: RefArg,
    max_depth: DepthArg = 10,
    limit: DepLimit = 50,
    dataset: DatasetArg = "",
) -> dict:
    """What is affected if this asset breaks, is deleted, changed or
    compromised: (1) dependency blast radius, meaning everything that
    transitively depends on it, with accounts and exposed assets
    affected; (2) network / graph reach: everything reachable from it,
    with the sensitive data stores among them and a 0-10 risk score."""
    ds = ws_dataset(ctx, dataset)
    a = ds.resolve_asset(ref)
    items = dep_items(ds, ds.dependency_graph().dependents(a.id, max_depth))
    net = ds.reachability.compute_blast_radius(a.id)
    reach = sorted(n for n in net["reachable_nodes"] if n in ds.by_id)
    sensitive = [n for n in reach if ds.by_id[n].asset_type in CROWN_JEWELS]
    by_depth: dict[str, int] = {}
    for i in items:
        by_depth[str(i["depth"])] = by_depth.get(str(i["depth"]), 0) + 1
    ctx.link(asset_uri(a.id), a.name)
    return {
        "dataset": ds.name,
        "asset": asset_brief(ds, a),
        "dependency": {
            "transitive_dependents": len(items),
            "by_depth": by_depth,
            "accounts_affected": sorted({i["account_id"] for i in items if i["account_id"]}),
            "internet_exposed_dependents": sum(1 for i in items if i["internet_exposed"]),
            "items": items[:limit],
            "truncated": len(items) > limit,
        },
        "network": {
            "reachable_assets": len(reach),
            "max_depth": net["depth"],
            "risk_score": net["risk_score"],
            "sensitive_reachable": [node_brief(ds, n) for n in sensitive[:limit]],
        },
    }


def _dependency_result(
    ctx: Any, ref: str, dataset: str, limit: int, walk: Callable[[Dataset, str], list]
) -> dict:
    """Shared body of depends_on / dependents."""
    ds = ws_dataset(ctx, dataset)
    a = ds.resolve_asset(ref)
    page, env = bounded(dep_items(ds, walk(ds, a.id)), limit)
    return {"dataset": ds.name, "asset": asset_brief(ds, a), **env, "items": page}


@CATALOG.tool(
    title="Depends on",
    sensitivity=Sensitivity.CONFIDENTIAL,
    output_schema=schema(DependencyOut),
    **_RO,
)
def depends_on(
    ctx: Any,
    ref: RefArg,
    max_depth: DepthArg = 3,
    limit: DepLimit = 100,
    dataset: DatasetArg = "",
) -> dict:
    """Everything this asset needs (upstream), breadth-first: its role,
    keys, image, subnet, log group, the queue that triggers it... Each
    item says which edge it came through and at what depth."""
    return _dependency_result(
        ctx, ref, dataset, limit, lambda ds, aid: ds.dependency_graph().depends_on(aid, max_depth)
    )


@CATALOG.tool(
    title="Dependents",
    sensitivity=Sensitivity.CONFIDENTIAL,
    output_schema=schema(DependencyOut),
    **_RO,
)
def dependents(
    ctx: Any,
    ref: RefArg,
    max_depth: DepthArg = 3,
    limit: DepLimit = 100,
    dataset: DatasetArg = "",
) -> dict:
    """Everything that needs this asset (downstream), i.e. what breaks if it
    is deleted or changed. Breadth-first, with the edge and depth of each."""
    return _dependency_result(
        ctx, ref, dataset, limit, lambda ds, aid: ds.dependency_graph().dependents(aid, max_depth)
    )


@CATALOG.tool(title="Dependency tree", sensitivity=Sensitivity.CONFIDENTIAL, **_RO)
def dependency_tree(
    ctx: Any,
    ref: RefArg,
    direction: Annotated[
        Literal["up", "down", "both"],
        Field(description="up = what it depends on, down = what depends on it."),
    ] = "both",
    max_depth: Annotated[int, Field(ge=1, le=6)] = 3,
    include_hierarchy: Annotated[
        bool, Field(description="Include org / account containment edges.")
    ] = False,
    max_nodes: Annotated[int, Field(ge=1, le=1000)] = 200,
    dataset: DatasetArg = "",
) -> dict:
    """Nested upstream / downstream dependency tree of one asset (the
    same view as `cloudg deps`), pruned to max_nodes."""
    ds = ws_dataset(ctx, dataset)
    a = ds.resolve_asset(ref)
    tree = ds.dependency_graph(include_hierarchy).tree(a.id, direction, max_depth)
    budget = [max_nodes, 0]
    out: dict[str, Any] = {"dataset": ds.name, "asset": tree["asset"]}
    for key in ("depends_on", "dependents"):
        if key in tree:
            out[key] = prune_tree(tree[key], budget)
    out["truncated"] = bool(budget[1])
    return out


@CATALOG.tool(title="Shared dependencies", sensitivity=Sensitivity.CONFIDENTIAL, **_RO)
def shared_dependencies(
    ctx: Any, top: Annotated[int, Field(ge=1, le=200)] = 25, dataset: DatasetArg = ""
) -> dict:
    """Single points of failure: assets the most other assets directly
    depend on (one KMS key behind forty resources, one role behind every
    function), excluding pure containment."""
    ds = ws_dataset(ctx, dataset)
    items = ds.dependency_graph().shared_dependencies(top)
    return {"dataset": ds.name, "items": items, "returned": len(items)}


@CATALOG.tool(title="Largest blast radius", sensitivity=Sensitivity.CONFIDENTIAL, **_RO)
def largest_blast_radius(
    ctx: Any, top: Annotated[int, Field(ge=1, le=100)] = 15, dataset: DatasetArg = ""
) -> dict:
    """Assets whose failure or change affects the most others
    (transitive dependents), with accounts and internet-exposed assets
    affected. Use blast_radius(ref) for the detail of one."""
    ds = ws_dataset(ctx, dataset)
    items = ds.dependency_graph().blast_radius(top=top)
    return {"dataset": ds.name, "items": items, "returned": len(items)}


@CATALOG.tool(title="Cross-account edges", sensitivity=Sensitivity.CONFIDENTIAL, **_RO)
def cross_account_edges(
    ctx: Any,
    account_id: Annotated[str, Field(description="Only edges touching this account.")] = "",
    external_only: Annotated[
        bool, Field(description="Only edges to accounts outside the mapped estate.")
    ] = False,
    edge_types: list[str] | None = None,
    limit: Limit = DEFAULT_LIMIT,
    cursor: Cursor = "",
    dataset: DatasetArg = "",
) -> dict:
    """Relationships that cross account / subscription / project
    boundaries (trust, grants, peering, shared resources), flagging
    external accounts. Summarised by account pair."""
    from cloudg.inventory.dependencies import cross_account_edges as _xa

    ds = ws_dataset(ctx, dataset)
    types = _edge_types(edge_types)
    rows = [
        r
        for r in ds.cached("cross_account", lambda: _xa(ds.assets, ds.edges))
        if (not account_id or account_id in (r["source_account"], r["target_account"]))
        and (not external_only or r["external"])
        and (not types or r["edge_type"] in types)
    ]
    pairs: dict[str, int] = {}
    for r in rows:
        k = f"{r['source_account']} -> {r['target_account']}"
        pairs[k] = pairs.get(k, 0) + 1
    page, env = paginate(
        rows, limit, cursor, fingerprint(ds, a=account_id, x=external_only, t=sorted(types))
    )
    return {"dataset": ds.name, **env, "by_account_pair": pairs, "items": page}


def _centrality(g: nx.DiGraph, metric: str) -> dict[str, float]:
    if metric == "degree":
        return nx.degree_centrality(g)
    if metric == "in_degree":
        return nx.in_degree_centrality(g)
    if metric == "out_degree":
        return nx.out_degree_centrality(g)
    n = g.number_of_nodes()
    k = None if n <= 1500 else min(n, 300)
    return nx.betweenness_centrality(g, k=k, seed=7)


@CATALOG.tool(title="Most central assets", sensitivity=Sensitivity.CONFIDENTIAL, **_RO)
def centrality_top(
    ctx: Any,
    metric: Metric = "degree",
    top: Annotated[int, Field(ge=1, le=200)] = 20,
    asset_types: list[str] | None = None,
    dataset: DatasetArg = "",
) -> dict:
    """Most connected / most "in the middle" assets by graph centrality.
    High betweenness marks chokepoints that many paths cross. They are good
    places for controls and bad places for compromise. Betweenness is
    sampled on large graphs."""
    ds = ws_dataset(ctx, dataset)
    types = parse_enums(asset_types, AssetType, "asset type")
    g = ds.graph
    scores = ds.cached(f"centrality:{metric}", lambda: _centrality(g, metric))
    ranked = [
        (n, s)
        for n, s in sorted(scores.items(), key=lambda kv: -kv[1])
        if n in ds.by_id and (not types or ds.by_id[n].asset_type in types)
    ][:top]
    return {
        "dataset": ds.name,
        "metric": metric,
        "sampled": metric == "betweenness" and g.number_of_nodes() > 1500,
        "items": [
            {**asset_brief(ds, ds.by_id[n]), "score": round(s, 5), "degree": g.degree(n)}
            for n, s in ranked
        ],
    }


def _subgraph_nodes(ds: Dataset, seeds: list[str], walk: Walk) -> tuple[list[str], bool]:
    keep: list[str] = []
    truncated = False
    for ref in seeds:
        sid = resolve_node(ds, ref)
        nodes, _, tr = bfs(ds, sid, walk)
        truncated = truncated or tr
        for n in [sid, *nodes]:
            if n not in keep:
                keep.append(n)
    if len(keep) > walk.cap:
        return keep[: walk.cap], True
    return keep, truncated


def _render_subgraph(ds: Dataset, keep: list[str], types: set[str] | None, fmt: str) -> Any:
    from cloudg.graph.builder import GraphBuilder

    sub = GraphBuilder()
    keep_set = set(keep)
    sub.build(
        [ds.by_id[n] for n in keep if n in ds.by_id],
        [
            e
            for e in ds.edges
            if e.source_id in keep_set
            and e.target_id in keep_set
            and (types is None or e.edge_type.value in types)
        ],
    )
    if fmt == "d3":
        return sub, sub.to_d3_json()
    if fmt == "cytoscape":
        return sub, sub.to_cytoscape_json()
    return sub, "\n".join(nx.generate_graphml(sub.graph))


# RESTRICTED: the GraphML form is one opaque string the privacy layer can
# only scan as free text, so strict ceilings hide the whole tool.
@CATALOG.tool(title="Export sub-graph", sensitivity=Sensitivity.RESTRICTED, **_RO)
def subgraph_export(
    ctx: Any,
    seeds: Annotated[
        list[str], Field(min_length=1, max_length=50, description="Asset refs to start from.")
    ],
    depth: Annotated[int, Field(ge=0, le=4)] = 1,
    format: GraphFormat = "d3",  # pylint: disable=redefined-builtin  # MCP argument name
    max_nodes: Annotated[int, Field(ge=1, le=2000)] = 300,
    edge_types: list[str] | None = None,
    dataset: DatasetArg = "",
) -> dict:
    """The neighbourhood of a few assets as a self-contained graph in
    D3 ({nodes, links}), Cytoscape ({elements}) or GraphML (string), for
    visualisation or handing to another tool. Use the
    cloudg://graph/{format} resources for the whole graph."""
    ds = ws_dataset(ctx, dataset)
    types = _edge_types(edge_types) or None
    keep, truncated = _subgraph_nodes(ds, seeds, Walk("both", types, depth, max_nodes))
    sub, data = _render_subgraph(ds, keep, types, format)
    return {
        "dataset": ds.name,
        "format": format,
        "nodes": sub.graph.number_of_nodes(),
        "edges": sub.graph.number_of_edges(),
        "truncated": truncated,
        "graph": data,
    }


@CATALOG.tool(title="Security service coverage", sensitivity=Sensitivity.CONFIDENTIAL, **_RO)
def security_coverage(
    ctx: Any, limit: Annotated[int, Field(ge=1, le=500)] = 50, dataset: DatasetArg = ""
) -> dict:
    """Which security services (GuardDuty, Security Hub, Inspector,
    Config, Access Analyzer, Macie...) are enabled per account / region,
    the gaps, workloads without vulnerability scanning, and
    internet-facing entry points without a WAF."""
    from cloudg.inventory.dependencies import security_coverage as _cov

    ds = ws_dataset(ctx, dataset)
    cov = ds.cached("security_coverage", lambda: _cov(ds.assets, ds.edges))
    out: dict[str, Any] = {
        "dataset": ds.name,
        "services_by_account_region": cov["services_by_account_region"],
    }
    for key in ("gaps", "workloads_without_vulnerability_scanning", "internet_facing_without_waf"):
        items, env = bounded(cov[key], limit)
        out[key] = {**env, "items": items}
    return out


@CATALOG.tool(title="Graph statistics", sensitivity=Sensitivity.INTERNAL, **_RO)
def graph_stats(ctx: Any, dataset: DatasetArg = "") -> dict:
    """Shape of the relationship graph: nodes (assets vs placeholders),
    edges by type and relationship, connected components, the largest
    component, isolated assets and density."""
    ds = ws_dataset(ctx, dataset)
    g = ds.graph
    n_nodes = g.number_of_nodes()
    comps = sorted((len(c) for c in nx.weakly_connected_components(g)), reverse=True)
    rels: dict[str, int] = {}
    for e in ds.edges:
        if e.relationship:
            rels[e.relationship] = rels.get(e.relationship, 0) + 1
    return {
        "dataset": ds.name,
        "nodes": n_nodes,
        "asset_nodes": len(ds.by_id),
        "placeholder_nodes": n_nodes - sum(1 for n in g if n in ds.by_id),
        "edges": len(ds.edges),
        "graph_edges": g.number_of_edges(),
        "edges_by_type": ds.summary()["edges_by_type"],
        "edges_by_relationship": dict(sorted(rels.items(), key=lambda kv: -kv[1])[:30]),
        "components": len(comps),
        "largest_component": comps[0] if comps else 0,
        "isolated_assets": sum(1 for n in ds.by_id if n in g and g.degree(n) == 0),
        "density": round(nx.density(g), 6) if n_nodes > 1 else 0.0,
        "mean_degree": round(sum(d for _, d in g.degree()) / n_nodes, 3) if n_nodes else 0.0,
    }
