"""Graph and relationship tools: neighbours, paths, exposure, attack and
lateral-movement paths, dependency / blast-radius analysis, cross-account
edges, centrality, sub-graph export and security-service coverage.

Three views of the same edges are used, each for the question it answers:

- the relationship graph (``GraphBuilder``): edges as collected, read
  "source verb target";
- the flow graph (:attr:`Dataset.flow_graph`): the network-flow hops of
  :func:`cloudg.graph.reachability.network_flow_graph` (the same rules as
  the internet-exposure analysis) plus the identity edges ASSUMES_ROLE,
  IAM_TRUST and GRANTS_ACCESS, so a path may continue from a compromised
  workload through its role to what the role can reach;
- the dependency graph (``DependencyGraph``): every edge turned into a
  "dependent -> dependency" arrow, which depends_on / dependents / blast
  radius walk (availability and change impact).
"""

from __future__ import annotations

from typing import Annotated, Any, Literal

from pydantic import BaseModel, Field

from cloudg.mcp.catalog._common import (
    DEFAULT_LIMIT,
    Catalog,
    Cursor,
    DatasetArg,
    EdgePageOut,
    Limit,
    NeighborsOut,
    PathsOut,
    RefArg,
    asset_brief,
    asset_uri,
    bounded,
    edge_brief,
    fingerprint,
    node_brief,
    paginate,
    parse_enums,
    schema,
    ws_dataset,
)
from cloudg.mcp.catalog._graph import (
    GRAPH_RO,
    edge_type_values,
    CROWN_JEWELS,
    IDENTITY_EDGES,
    INTERNET,
    SENSITIVE_PORTS,
    AttackSearch,
    EdgeQuery,
    Walk,
    allows_port,
    attack_graph,
    attack_paths_found,
    bfs,
    brief,
    describe_path,
    exposure_evidence,
    identity_graph,
    lateral_chains,
    lateral_starts,
    path_graph,
    resolve_node,
    simple_paths,
    with_internet,
)
from cloudg.mcp.catalog._graph_impact import CATALOG as IMPACT_CATALOG
from cloudg.mcp.core import Capability, Registry, Sensitivity
from cloudg.schema.models import AssetType

__all__ = [
    "CATALOG",
    "CROWN_JEWELS",
    "IDENTITY_EDGES",
    "SENSITIVE_PORTS",
    "allows_port",
    "register",
]

R = Capability.READ_STATE

Direction = Literal["out", "in", "both"]
PathMode = Literal["flow", "directed", "undirected"]

EdgeTypesArg = Annotated[
    list[str] | None,
    Field(description="Only these EdgeType values, e.g. ['ASSUMES_ROLE','GRANTS_ACCESS']."),
]

SourceArg = Annotated[str, Field(description="Source asset ref (or 'internet').")]
TargetArg = Annotated[str, Field(description="Target asset ref.")]
RelationshipArg = Annotated[str, Field(description="Exact relationship / RelationType.")]
InternetOnlyArg = Annotated[
    bool,
    Field(
        description="Only ingress edges from the internet (0.0.0.0/0, ::/0, or the Azure "
        "Internet / Any / * sources)."
    ),
]
PortArg = Annotated[int | None, Field(ge=0, le=65535, description="Edges allowing this port.")]


class GetEdgesArgs(BaseModel):
    """get_edges arguments (the MCP wire schema)."""

    source: SourceArg = ""
    target: TargetArg = ""
    edge_types: list[str] | None = None
    relationship: RelationshipArg = ""
    cross_account_only: bool = False
    internet_only: InternetOnlyArg = False
    port: PortArg = None
    limit: Limit = DEFAULT_LIMIT
    cursor: Cursor = ""
    dataset: DatasetArg = ""


CATALOG = Catalog()


@CATALOG.tool(
    title="Neighbors",
    sensitivity=Sensitivity.CONFIDENTIAL,
    output_schema=schema(NeighborsOut),
    **GRAPH_RO,
)
def neighbors(
    ctx: Any,
    ref: RefArg,
    direction: Annotated[
        Direction, Field(description="out = edges from the asset, in = edges to it.")
    ] = "both",
    edge_types: EdgeTypesArg = None,
    depth: Annotated[int, Field(ge=1, le=4)] = 1,
    limit: Annotated[int, Field(ge=1, le=500)] = 100,
    dataset: DatasetArg = "",
) -> dict:
    """Assets connected to one asset, up to `depth` hops, with the edges
    between them (type, relationship, ports, CIDR). Filter by direction
    and edge types. Example: what a Lambda can reach through its role:
    ref='api-handler', direction='out', edge_types=['ASSUMES_ROLE',
    'GRANTS_ACCESS'], depth=2."""
    ds = ws_dataset(ctx, dataset)
    start = resolve_node(ds, ref)
    walk = Walk(direction, edge_type_values(edge_types) or None, depth, limit)
    nodes, edges, truncated = bfs(ds, start, walk)
    ctx.link(asset_uri(start) + "/neighbors", "neighbors")
    return {
        "dataset": ds.name,
        "asset": node_brief(ds, start),
        "nodes": [node_brief(ds, n) for n in nodes],
        "edges": [edge_brief(ds, e) for e in edges],
        "node_count": len(nodes),
        "edge_count": len(edges),
        "truncated": truncated,
    }


@CATALOG.tool(
    title="Get edges",
    sensitivity=Sensitivity.CONFIDENTIAL,
    output_schema=schema(EdgePageOut),
    **GRAPH_RO,
)
def get_edges(ctx: Any, args: GetEdgesArgs) -> dict:
    """Search edges by endpoint, edge type, relationship, cross-account,
    internet origin or port, with pagination. Egress rules never count as
    internet-sourced. Example: every rule that opens SSH to the internet:
    internet_only=true, port=22."""
    ds = ws_dataset(ctx, args.dataset)
    q = EdgeQuery(
        source=resolve_node(ds, args.source, virtual_internet=True) if args.source else None,
        target=resolve_node(ds, args.target) if args.target else None,
        edge_types=edge_type_values(args.edge_types),
        relationship=args.relationship,
        internet_only=args.internet_only,
        port=args.port,
    )
    xa = args.cross_account_only
    out = [
        b
        for b in (edge_brief(ds, e) for e in ds.edges if q.matches(e))
        if not xa or b.get("cross_account")
    ]
    fp = fingerprint(ds, q=vars(q) | {"edge_types": sorted(q.edge_types or ())}, x=xa)
    page, env = paginate(out, args.limit, args.cursor, fp)
    return {"dataset": ds.name, **env, "items": page}


@CATALOG.tool(
    title="Find paths",
    sensitivity=Sensitivity.CONFIDENTIAL,
    output_schema=schema(PathsOut),
    **GRAPH_RO,
)
def find_paths(
    ctx: Any,
    source: Annotated[str, Field(min_length=1, description="Start asset ref, or 'internet'.")],
    target: Annotated[str, Field(min_length=1, description="End asset ref.")],
    max_depth: Annotated[int, Field(ge=1, le=12)] = 6,
    max_paths: Annotated[int, Field(ge=1, le=50)] = 5,
    mode: Annotated[
        PathMode,
        Field(
            description="flow: network-flow hops (as the reachability analysis walks them: "
            "security groups admit traffic to attached resources) plus identity pivots "
            "(ASSUMES_ROLE, IAM_TRUST, GRANTS_ACCESS); directed: edges as collected; "
            "undirected: any connection."
        ),
    ] = "flow",
    dataset: DatasetArg = "",
) -> dict:
    """Shortest connection paths between two assets (shortest first),
    each with the node briefs and the edge type of every hop. Use
    source='internet' to see how something is reachable from any internet
    entry point (0.0.0.0/0, ::/0, Azure Internet sources)."""
    ds = ws_dataset(ctx, dataset)
    s = resolve_node(ds, source, virtual_internet=True)
    t = resolve_node(ds, target)
    g = path_graph(ds, mode)
    if s == INTERNET:
        g = with_internet(ds, g)
    paths = simple_paths(g, s, t, max_depth, max_paths)
    out = {
        "dataset": ds.name,
        "source": brief(ds, s),
        "target": node_brief(ds, t),
        "mode": mode,
        "paths": [describe_path(ds, g, p) for p in paths[:max_paths]],
        "total_found": min(len(paths), max_paths),
        "truncated": len(paths) > max_paths,
    }
    if not paths:
        out["hint"] = (
            f"No path within {max_depth} hops in '{mode}' mode. Try mode='undirected' or a "
            "larger max_depth, or check neighbors() of each end."
        )
    return out


@CATALOG.tool(
    title="Attack paths",
    sensitivity=Sensitivity.CONFIDENTIAL,
    output_schema=schema(PathsOut),
    **GRAPH_RO,
)
def attack_paths(
    ctx: Any,
    target: Annotated[
        str,
        Field(
            description="Asset to reach; empty = every crown-jewel "
            "asset (databases, buckets, secrets, keys, roles)."
        ),
    ] = "",
    max_depth: Annotated[int, Field(ge=1, le=12)] = 8,
    max_paths: Annotated[int, Field(ge=1, le=100)] = 20,
    dataset: DatasetArg = "",
) -> dict:
    """Shortest routes from the internet (internet-sourced ingress rules
    and internet-exposed assets) to sensitive assets over the flow graph:
    network-flow hops as the reachability analysis walks them, plus
    identity pivots (ASSUMES_ROLE, IAM_TRUST, GRANTS_ACCESS) from a reached
    workload. Ranked by target sensitivity, open findings along the path
    and length. Each path lists every hop and edge type; investigate the
    entry point and each hop with get_asset / findings_for_asset."""
    ds = ws_dataset(ctx, dataset)
    g = attack_graph(ds)
    if g.out_degree(INTERNET) == 0:
        return {
            "dataset": ds.name,
            "paths": [],
            "total_found": 0,
            "truncated": False,
            "hint": "Nothing in this dataset is internet-exposed.",
        }
    if target:
        targets = {resolve_node(ds, target): 10}
    else:
        targets = {
            a.id: CROWN_JEWELS[a.asset_type] for a in ds.assets if a.asset_type in CROWN_JEWELS
        }
    found = attack_paths_found(AttackSearch(ds, targets, max_depth), g)
    page, env = bounded(found, max_paths)
    return {
        "dataset": ds.name,
        "paths": page,
        "total_found": env["total"],
        "truncated": env["truncated"],
        "targets_considered": len(targets),
    }


@CATALOG.tool(
    title="Lateral movement paths",
    sensitivity=Sensitivity.CONFIDENTIAL,
    output_schema=schema(PathsOut),
    **GRAPH_RO,
)
def lateral_movement_paths(
    ctx: Any,
    start: Annotated[
        str,
        Field(
            description="Start from this asset; empty = every "
            "internet-exposed asset and external account."
        ),
    ] = "",
    max_depth: Annotated[int, Field(ge=1, le=8)] = 4,
    max_paths: Annotated[int, Field(ge=1, le=100)] = 25,
    dataset: DatasetArg = "",
) -> dict:
    """Identity pivot chains: from a foothold (internet-exposed compute
    or an external / cross-account principal) along ASSUMES_ROLE,
    IAM_TRUST and GRANTS_ACCESS edges to the roles and resources it can
    reach. Shows how a compromise propagates through IAM."""
    ds = ws_dataset(ctx, dataset)
    starts = [resolve_node(ds, start)] if start else lateral_starts(ds)
    g = identity_graph(ds)
    chains = lateral_chains(ds, g, starts, max_depth)
    page, env = bounded(chains, max_paths)
    return {
        "dataset": ds.name,
        "paths": [describe_path(ds, g, p) for p in page],
        "total_found": env["total"],
        "truncated": env["truncated"],
        "starting_points": len(set(starts)),
    }


@CATALOG.tool(title="Internet exposure", sensitivity=Sensitivity.CONFIDENTIAL, **GRAPH_RO)
def internet_exposure(
    ctx: Any,
    asset_types: list[str] | None = None,
    include_reachable: Annotated[
        bool,
        Field(
            description="Also list assets transitively reachable from the internet in the graph."
        ),
    ] = False,
    limit: Limit = DEFAULT_LIMIT,
    cursor: Cursor = "",
    dataset: DatasetArg = "",
) -> dict:
    """Internet-exposed assets with the evidence: the internet-sourced
    rules / INTERNET_EXPOSED edges reaching them, sensitive ports open
    (SSH, RDP, databases...), whether a WAF protects them, and their open
    findings. Sorted with unprotected sensitive-port exposures first."""
    ds = ws_dataset(ctx, dataset)
    types = parse_enums(asset_types, AssetType, "asset type")
    items = [
        {**asset_brief(ds, a), **exposure_evidence(ds, a.id)}
        for a in ds.assets
        if a.is_internet_exposed and (not types or a.asset_type in types)
    ]
    items.sort(
        key=lambda i: (
            -len(i["sensitive_ports_open"]),
            i["protected_by_waf"],
            -(i["open_findings"] or 0),
            i["name"],
        )
    )
    page, env = paginate(items, limit, cursor, fingerprint(ds, t=sorted(x.value for x in types)))
    out: dict[str, Any] = {"dataset": ds.name, **env, "items": page}
    if include_reachable:
        reach = sorted(n for n in ds.internet_reachable() if n in ds.by_id)
        sample, renv = bounded(reach, limit)
        out["graph_reachable"] = {
            "total": renv["total"],
            "truncated": renv["truncated"],
            "items": [node_brief(ds, n) for n in sample],
        }
    return out


def register(reg: Registry) -> None:
    """Add this module's tools to ``reg``."""
    CATALOG.register(reg)
    IMPACT_CATALOG.register(reg)
