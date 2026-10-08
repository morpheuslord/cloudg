"""Graph and relationship tools: neighbours, paths, exposure, attack and
lateral-movement paths, dependency / blast-radius analysis, cross-account
edges, centrality, sub-graph export and security-service coverage.

Three views of the same edges are used, each for the question it answers:

- the relationship graph (``GraphBuilder``): edges as collected, read
  "source verb target";
- the flow graph: the relationship graph plus "security group admits
  traffic to the resources attached to it", used for internet exposure
  and attack paths;
- the dependency graph (``DependencyGraph``): every edge turned into a
  "dependent -> dependency" arrow, which depends_on / dependents / blast
  radius walk (availability and change impact).
"""

from __future__ import annotations

from collections import deque
from typing import Annotated, Any, Literal

import networkx as nx
from pydantic import Field

from cloudg.mcp.catalog._common import (
    DEFAULT_LIMIT,
    Catalog,
    Cursor,
    DatasetArg,
    DependencyOut,
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
from cloudg.mcp.core import Capability, InvalidArgumentsError, Registry, Sensitivity
from cloudg.mcp.state import INTERNET_NODES, Dataset
from cloudg.schema.models import AssetType, EdgeType

CATEGORY = "graph"
R = Capability.READ_STATE

CROWN_JEWELS = {
    AssetType.RDS_INSTANCE: 10,
    AssetType.AURORA_CLUSTER: 10,
    AssetType.AZURE_SQL: 10,
    AssetType.CLOUD_SQL: 10,
    AssetType.DYNAMODB_TABLE: 9,
    AssetType.DATA_WAREHOUSE: 9,
    AssetType.SECRET: 9,
    AssetType.KEY_VAULT: 9,
    AssetType.KMS_KEY: 8,
    AssetType.S3_BUCKET: 8,
    AssetType.BLOB_STORAGE: 8,
    AssetType.GCS_BUCKET: 8,
    AssetType.FILE_SYSTEM: 7,
    AssetType.CACHE_CLUSTER: 6,
    AssetType.SEARCH_DOMAIN: 7,
    AssetType.IAM_ROLE: 5,
    AssetType.IAM_USER: 5,
    AssetType.ACCESS_KEY: 6,
}
IDENTITY_EDGES = {
    EdgeType.IAM_TRUST.value,
    EdgeType.ASSUMES_ROLE.value,
    EdgeType.GRANTS_ACCESS.value,
}
SENSITIVE_PORTS = {22, 3389, 3306, 5432, 1433, 27017, 6379, 9200, 5601, 8080, 8443}

Direction = Literal["out", "in", "both"]
PathMode = Literal["flow", "directed", "undirected"]
GraphFormat = Literal["d3", "cytoscape", "graphml"]
Metric = Literal["degree", "in_degree", "out_degree", "betweenness"]


def _internet_alias(ref: str) -> bool:
    return ref.strip().lower() in ("internet", "0.0.0.0/0", "::/0", "public")


def _resolve_node(ds: Dataset, ref: str) -> str:
    if _internet_alias(ref):
        for n in INTERNET_NODES:
            if n in ds.graph:
                return n
        raise InvalidArgumentsError(
            "This dataset has no internet node (no 0.0.0.0/0 rules or INTERNET_EXPOSED edges). "
            "Use internet_exposure to see assets flagged as exposed."
        )
    if ref in ds.graph and ref not in ds.by_id:
        return ref  # placeholder node (CIDR / external id)
    return ds.resolve_asset(ref).id


def _path_graph(ds: Dataset, mode: str) -> nx.DiGraph | nx.Graph:
    if mode == "flow":
        return ds.flow_graph
    if mode == "undirected":
        return ds.cached("undirected", lambda: ds.graph.to_undirected(as_view=False))
    return ds.graph


def _describe_path(ds: Dataset, g: Any, path: list[str]) -> dict[str, Any]:
    edge_types = []
    for u, v in zip(path, path[1:]):
        data = g.get_edge_data(u, v) or {}
        et = data.get("edge_type", "?")
        if data.get("derived") == "sg_admits":
            et = "SG_ADMITS"
        edge_types.append(et)
    return {
        "length": len(path) - 1,
        "nodes": [_compact(node_brief(ds, n)) for n in path],
        "edge_types": edge_types,
        "summary": " -> ".join(node_brief(ds, n)["name"] for n in path),
    }


_COMPACT_KEYS = ("id", "name", "type", "account_id", "internet_exposed", "open_findings",
                 "max_severity", "external")


def _compact(brief: dict[str, Any]) -> dict[str, Any]:
    """Path hops repeat a lot: keep only what explains the hop."""
    return {k: brief[k] for k in _COMPACT_KEYS if brief.get(k) is not None}


def _exposure_evidence(ds: Dataset, asset_id: str) -> dict[str, Any]:
    """0.0.0.0/0 rules reaching an asset directly or through a security
    group / NSG attached to it, sensitive ports among them, WAF coverage."""
    rules = []
    ports: set[int] = set()
    protected = False
    sg_types = {"SECURITY_GROUP", "NSG"}
    via_nodes = [(asset_id, None)]
    for e, other, d in ds.adjacency.get(asset_id, []):
        if d == "in" and e.edge_type == EdgeType.PROTECTS:
            protected = True
        if d == "out" and e.edge_type == EdgeType.ATTACHED_TO and other in ds.by_id \
                and ds.by_id[other].asset_type.value in sg_types:
            via_nodes.append((other, ds.by_id[other].name))
    for node, via in via_nodes:
        for e, other, d in ds.adjacency.get(node, []):
            if d != "in" or not (e.cidr in INTERNET_NODES or other in INTERNET_NODES):
                continue
            rules.append({
                "edge_type": e.edge_type.value,
                "ports": e.port_range or ",".join(str(p) for p in e.ports[:10]) or "all",
                "protocol": e.protocol,
                "via": via or e.description,
            })
            ports.update(e.ports)
            for part in (e.port_range or "").split(","):
                lo, _, hi = part.strip().partition("-")
                if lo.isdigit():
                    end = int(hi) if hi.isdigit() else int(lo)
                    ports.update(p for p in SENSITIVE_PORTS if int(lo) <= p <= end)
    return {
        "internet_rules": rules[:10],
        "sensitive_ports_open": sorted(ports & SENSITIVE_PORTS),
        "protected_by_waf": protected,
    }


def _bfs(
    ds: Dataset, start: str, direction: str, edge_types: set[str] | None, depth: int, cap: int
) -> tuple[list[str], list[Any], bool]:
    seen = {start}
    nodes: list[str] = []
    edges: list[Any] = []
    seen_edges: set[str] = set()
    queue: deque[tuple[str, int]] = deque([(start, 0)])
    truncated = False
    while queue:
        node, d = queue.popleft()
        if d >= depth:
            continue
        for e, other, dirn in ds.adjacency.get(node, []):
            if direction != "both" and dirn != direction:
                continue
            if edge_types and e.edge_type.value not in edge_types:
                continue
            if e.id not in seen_edges:
                if len(edges) >= cap * 2:
                    truncated = True
                    continue
                seen_edges.add(e.id)
                edges.append(e)
            if other not in seen:
                if len(nodes) >= cap:
                    truncated = True
                    continue
                seen.add(other)
                nodes.append(other)
                queue.append((other, d + 1))
    return nodes, edges, truncated


def _dep_items(ds: Dataset, links: list[Any]) -> list[dict[str, Any]]:
    out = []
    for link in links:
        a = ds.by_id.get(link.asset_id)
        if a is None:
            continue
        out.append({**asset_brief(ds, a), "via": link.via_edge, "relationship": link.relationship,
                    "depth": link.depth, "parent_id": link.parent_id})
    return out


def _prune_tree(nodes: list[dict[str, Any]], budget: list[int]) -> list[dict[str, Any]]:
    """Keep at most ``budget[0]`` nodes; ``budget[1]`` becomes 1 when a node
    had to be dropped."""
    out = []
    for n in nodes:
        if budget[0] <= 0:
            budget[1] = 1
            break
        budget[0] -= 1
        children = n.get("children") or []
        out.append({**n, "children": _prune_tree(children, budget)})
    return out

CATALOG = Catalog()

_RO = dict(read_only=True, idempotent=True, open_world=False, category=CATEGORY)

@CATALOG.tool(title="Neighbors", sensitivity=Sensitivity.CONFIDENTIAL,
          output_schema=schema(NeighborsOut), **_RO)
def neighbors(
    ctx: Any,
    ref: RefArg,
    direction: Annotated[Direction, Field(description="out = edges from the asset, "
                                          "in = edges to it.")] = "both",
    edge_types: Annotated[list[str] | None, Field(
        description="Only these EdgeType values, e.g. ['ASSUMES_ROLE','GRANTS_ACCESS'].")]
    = None,
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
    start = _resolve_node(ds, ref)
    types = {t.value for t in parse_enums(edge_types, EdgeType, "edge type")} or None
    nodes, edges, truncated = _bfs(ds, start, direction, types, depth, limit)
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

@CATALOG.tool(title="Get edges", sensitivity=Sensitivity.CONFIDENTIAL,
          output_schema=schema(EdgePageOut), **_RO)
def get_edges(
    ctx: Any,
    source: Annotated[str, Field(description="Source asset ref (or 'internet').")] = "",
    target: Annotated[str, Field(description="Target asset ref.")] = "",
    edge_types: list[str] | None = None,
    relationship: Annotated[str, Field(description="Exact relationship / RelationType.")]
    = "",
    cross_account_only: bool = False,
    internet_only: Annotated[bool, Field(description="Only edges from 0.0.0.0/0 / ::/0.")]
    = False,
    port: Annotated[int | None, Field(ge=0, le=65535, description="Edges allowing this "
                                      "port.")] = None,
    limit: Limit = DEFAULT_LIMIT,
    cursor: Cursor = "",
    dataset: DatasetArg = "",
) -> dict:
    """Search edges by endpoint, edge type, relationship, cross-account,
    internet origin or port, with pagination. Example: every rule that
    opens SSH to the internet: internet_only=true, port=22."""
    ds = ws_dataset(ctx, dataset)
    src = _resolve_node(ds, source) if source else None
    tgt = _resolve_node(ds, target) if target else None
    types = {t.value for t in parse_enums(edge_types, EdgeType, "edge type")}
    out = []
    for e in ds.edges:
        if src and e.source_id != src:
            continue
        if tgt and e.target_id != tgt:
            continue
        if types and e.edge_type.value not in types:
            continue
        if relationship and (e.relationship or "") != relationship:
            continue
        if internet_only and not (e.source_id in INTERNET_NODES or e.cidr in INTERNET_NODES):
            continue
        if port is not None and not _allows_port(e, port):
            continue
        b = edge_brief(ds, e)
        if cross_account_only and not b.get("cross_account"):
            continue
        out.append(b)
    fp = fingerprint(ds, s=src, t=tgt, et=sorted(types), r=relationship, x=cross_account_only,
                     i=internet_only, p=port)
    page, env = paginate(out, limit, cursor, fp)
    return {"dataset": ds.name, **env, "items": page}

@CATALOG.tool(title="Find paths", sensitivity=Sensitivity.CONFIDENTIAL,
          output_schema=schema(PathsOut), **_RO)
def find_paths(
    ctx: Any,
    source: Annotated[str, Field(min_length=1, description="Start asset ref, or "
                                 "'internet'.")],
    target: Annotated[str, Field(min_length=1, description="End asset ref.")],
    max_depth: Annotated[int, Field(ge=1, le=12)] = 6,
    max_paths: Annotated[int, Field(ge=1, le=50)] = 5,
    mode: Annotated[PathMode, Field(
        description="flow: directed + security groups admit traffic to attached resources "
        "(best for reachability); directed: edges as collected; undirected: any "
        "connection.")] = "flow",
    dataset: DatasetArg = "",
) -> dict:
    """Shortest connection paths between two assets (shortest first),
    each with the node briefs and the edge type of every hop. Use
    source='internet' to see how something is reachable from 0.0.0.0/0."""
    ds = ws_dataset(ctx, dataset)
    s, t = _resolve_node(ds, source), _resolve_node(ds, target)
    g = _path_graph(ds, mode)
    paths: list[list[str]] = []
    try:
        # Look for one path beyond max_paths so `truncated` means more exist
        for p in nx.shortest_simple_paths(g, s, t):
            if len(p) - 1 > max_depth or len(paths) > max_paths:
                break
            paths.append(p)
    except nx.NetworkXNoPath:
        pass
    except nx.NodeNotFound:
        pass
    out = {
        "dataset": ds.name,
        "source": node_brief(ds, s),
        "target": node_brief(ds, t),
        "mode": mode,
        "paths": [_describe_path(ds, g, p) for p in paths[:max_paths]],
        "total_found": min(len(paths), max_paths),
        "truncated": len(paths) > max_paths,
    }
    if not paths:
        out["hint"] = (
            f"No path within {max_depth} hops in '{mode}' mode. Try mode='undirected' or a "
            "larger max_depth, or check neighbors() of each end."
        )
    return out

@CATALOG.tool(title="Attack paths", sensitivity=Sensitivity.CONFIDENTIAL,
          output_schema=schema(PathsOut), **_RO)
def attack_paths(
    ctx: Any,
    target: Annotated[str, Field(description="Asset to reach; empty = every crown-jewel "
                                 "asset (databases, buckets, secrets, keys, roles).")] = "",
    max_depth: Annotated[int, Field(ge=1, le=12)] = 8,
    max_paths: Annotated[int, Field(ge=1, le=100)] = 20,
    dataset: DatasetArg = "",
) -> dict:
    """Shortest routes from the internet (0.0.0.0/0 rules and
    internet-exposed assets) to sensitive assets over the flow graph,
    ranked by target sensitivity, open findings along the path and
    length. Each path lists every hop and edge type; investigate the
    entry point and each hop with get_asset / findings_for_asset."""
    ds = ws_dataset(ctx, dataset)
    g = ds.flow_graph.copy()
    entry = "__internet__"
    g.add_node(entry)
    for n in INTERNET_NODES:
        if n in g:
            g.add_edge(entry, n, edge_type="INTERNET")
    for a in ds.assets:
        if a.is_internet_exposed:
            g.add_edge(entry, a.id, edge_type="INTERNET_EXPOSED")
    if g.out_degree(entry) == 0:
        return {"dataset": ds.name, "paths": [], "total_found": 0, "truncated": False,
                "hint": "Nothing in this dataset is internet-exposed."}
    if target:
        targets = {_resolve_node(ds, target): 10}
    else:
        targets = {a.id: CROWN_JEWELS[a.asset_type] for a in ds.assets
                   if a.asset_type in CROWN_JEWELS}
    lengths, paths = nx.single_source_dijkstra(g, entry, cutoff=max_depth + 1)
    found = []
    for tid, weight in targets.items():
        if tid not in paths:
            continue
        p = paths[tid][1:]  # drop the virtual entry
        if not p:
            continue
        on_path = sum(len(ds.open_findings(n)) for n in p if n in ds.by_id)
        score = round(weight * 1.0 + min(on_path, 10) * 0.5 - (len(p) - 1) * 0.3, 2)
        first = g.get_edge_data(entry, p[0]) or {}
        desc = _describe_path(ds, g, p)
        desc["entry"] = "internet-exposed asset" if first.get("edge_type") == \
            "INTERNET_EXPOSED" else "0.0.0.0/0 rule"
        desc["target_weight"] = weight
        desc["findings_on_path"] = on_path
        desc["score"] = score
        found.append(desc)
    found.sort(key=lambda d: (-d["score"], d["length"]))
    page, env = bounded(found, max_paths)
    return {"dataset": ds.name, "paths": page, "total_found": env["total"],
            "truncated": env["truncated"], "targets_considered": len(targets)}

@CATALOG.tool(title="Lateral movement paths", sensitivity=Sensitivity.CONFIDENTIAL,
          output_schema=schema(PathsOut), **_RO)
def lateral_movement_paths(
    ctx: Any,
    start: Annotated[str, Field(description="Start from this asset; empty = every "
                                "internet-exposed asset and external account.")] = "",
    max_depth: Annotated[int, Field(ge=1, le=8)] = 4,
    max_paths: Annotated[int, Field(ge=1, le=100)] = 25,
    dataset: DatasetArg = "",
) -> dict:
    """Identity pivot chains: from a foothold (internet-exposed compute
    or an external / cross-account principal) along ASSUMES_ROLE,
    IAM_TRUST and GRANTS_ACCESS edges to the roles and resources it can
    reach. Shows how a compromise propagates through IAM."""
    ds = ws_dataset(ctx, dataset)
    if start:
        starts = [_resolve_node(ds, start)]
    else:
        starts = [a.id for a in ds.assets if a.is_internet_exposed]
        starts += [a.id for a in ds.assets if a.asset_type == AssetType.CLOUD_ACCOUNT
                   and a.metadata.get("external")]
    g = nx.DiGraph()
    for e in ds.edges:
        if e.edge_type.value in IDENTITY_EDGES:
            g.add_edge(e.source_id, e.target_id, edge_type=e.edge_type.value,
                       relationship=e.relationship)
    chains: list[list[str]] = []
    for s in dict.fromkeys(starts):
        if s not in g:
            continue
        for tgt, p in nx.single_source_shortest_path(g, s, cutoff=max_depth).items():
            if tgt != s and g.out_degree(tgt) == 0:
                chains.append(p)
    chains.sort(key=lambda p: (-max((CROWN_JEWELS.get(ds.by_id[n].asset_type, 0)
                                      for n in p if n in ds.by_id), default=0), len(p)))
    page, env = bounded(chains, max_paths)
    return {"dataset": ds.name, "paths": [_describe_path(ds, g, p) for p in page],
            "total_found": env["total"], "truncated": env["truncated"],
            "starting_points": len(set(starts))}

@CATALOG.tool(title="Internet exposure", sensitivity=Sensitivity.CONFIDENTIAL, **_RO)
def internet_exposure(
    ctx: Any,
    asset_types: list[str] | None = None,
    include_reachable: Annotated[bool, Field(
        description="Also list assets transitively reachable from 0.0.0.0/0 in the graph.")]
    = False,
    limit: Limit = DEFAULT_LIMIT,
    cursor: Cursor = "",
    dataset: DatasetArg = "",
) -> dict:
    """Internet-exposed assets with the evidence: the 0.0.0.0/0 rules /
    INTERNET_EXPOSED edges reaching them, sensitive ports open
    (SSH, RDP, databases...), whether a WAF protects them, and their open
    findings. Sorted with unprotected sensitive-port exposures first."""
    ds = ws_dataset(ctx, dataset)
    types = parse_enums(asset_types, AssetType, "asset type")
    items = []
    for a in ds.assets:
        if not a.is_internet_exposed or (types and a.asset_type not in types):
            continue
        ev = _exposure_evidence(ds, a.id)
        items.append({**asset_brief(ds, a), **ev})
    items.sort(key=lambda i: (-len(i["sensitive_ports_open"]), i["protected_by_waf"],
                              -(i["open_findings"] or 0), i["name"]))
    page, env = paginate(items, limit, cursor,
                         fingerprint(ds, t=sorted(x.value for x in types)))
    out: dict[str, Any] = {"dataset": ds.name, **env, "items": page}
    if include_reachable:
        reach = sorted(n for n in ds.internet_reachable() if n in ds.by_id)
        sample, renv = bounded(reach, limit)
        out["graph_reachable"] = {"total": renv["total"], "truncated": renv["truncated"],
                                  "items": [node_brief(ds, n) for n in sample]}
    return out

@CATALOG.tool(title="Blast radius", sensitivity=Sensitivity.CONFIDENTIAL, **_RO)
def blast_radius(
    ctx: Any,
    ref: RefArg,
    max_depth: Annotated[int, Field(ge=1, le=15)] = 10,
    limit: Annotated[int, Field(ge=1, le=500)] = 50,
    dataset: DatasetArg = "",
) -> dict:
    """What is affected if this asset breaks, is deleted, changed or
    compromised: (1) dependency blast radius, meaning everything that
    transitively depends on it, with accounts and exposed assets
    affected; (2) network / graph reach: everything reachable from it,
    with the sensitive data stores among them and a 0-10 risk score."""
    ds = ws_dataset(ctx, dataset)
    a = ds.resolve_asset(ref)
    deps = ds.dependency_graph().dependents(a.id, max_depth)
    dep_items = _dep_items(ds, deps)
    accounts = sorted({i["account_id"] for i in dep_items if i["account_id"]})
    net = ds.reachability.compute_blast_radius(a.id)
    reach = [n for n in net["reachable_nodes"] if n in ds.by_id]
    sensitive = [n for n in reach if ds.by_id[n].asset_type in CROWN_JEWELS]
    by_depth: dict[str, int] = {}
    for i in dep_items:
        by_depth[str(i["depth"])] = by_depth.get(str(i["depth"]), 0) + 1
    ctx.link(asset_uri(a.id), a.name)
    return {
        "dataset": ds.name,
        "asset": asset_brief(ds, a),
        "dependency": {
            "transitive_dependents": len(dep_items),
            "by_depth": by_depth,
            "accounts_affected": accounts,
            "internet_exposed_dependents": sum(1 for i in dep_items if i["internet_exposed"]),
            "items": dep_items[:limit],
            "truncated": len(dep_items) > limit,
        },
        "network": {
            "reachable_assets": len(reach),
            "max_depth": net["depth"],
            "risk_score": net["risk_score"],
            "sensitive_reachable": [node_brief(ds, n) for n in sensitive[:limit]],
        },
    }

@CATALOG.tool(title="Depends on", sensitivity=Sensitivity.CONFIDENTIAL,
          output_schema=schema(DependencyOut), **_RO)
def depends_on(
    ctx: Any,
    ref: RefArg,
    max_depth: Annotated[int, Field(ge=1, le=15)] = 3,
    limit: Annotated[int, Field(ge=1, le=500)] = 100,
    dataset: DatasetArg = "",
) -> dict:
    """Everything this asset needs (upstream), breadth-first: its role,
    keys, image, subnet, log group, the queue that triggers it... Each
    item says which edge it came through and at what depth."""
    ds = ws_dataset(ctx, dataset)
    a = ds.resolve_asset(ref)
    items = _dep_items(ds, ds.dependency_graph().depends_on(a.id, max_depth))
    page, env = bounded(items, limit)
    return {"dataset": ds.name, "asset": asset_brief(ds, a), **env, "items": page}

@CATALOG.tool(title="Dependents", sensitivity=Sensitivity.CONFIDENTIAL,
          output_schema=schema(DependencyOut), **_RO)
def dependents(
    ctx: Any,
    ref: RefArg,
    max_depth: Annotated[int, Field(ge=1, le=15)] = 3,
    limit: Annotated[int, Field(ge=1, le=500)] = 100,
    dataset: DatasetArg = "",
) -> dict:
    """Everything that needs this asset (downstream), i.e. what breaks if it
    is deleted or changed. Breadth-first, with the edge and depth of each."""
    ds = ws_dataset(ctx, dataset)
    a = ds.resolve_asset(ref)
    items = _dep_items(ds, ds.dependency_graph().dependents(a.id, max_depth))
    page, env = bounded(items, limit)
    return {"dataset": ds.name, "asset": asset_brief(ds, a), **env, "items": page}

@CATALOG.tool(title="Dependency tree", sensitivity=Sensitivity.CONFIDENTIAL, **_RO)
def dependency_tree(
    ctx: Any,
    ref: RefArg,
    direction: Annotated[Literal["up", "down", "both"], Field(
        description="up = what it depends on, down = what depends on it.")] = "both",
    max_depth: Annotated[int, Field(ge=1, le=6)] = 3,
    include_hierarchy: Annotated[bool, Field(
        description="Include org / account containment edges.")] = False,
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
            out[key] = _prune_tree(tree[key], budget)
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
    external_only: Annotated[bool, Field(
        description="Only edges to accounts outside the mapped estate.")] = False,
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
    types = {t.value for t in parse_enums(edge_types, EdgeType, "edge type")}
    rows = ds.cached("cross_account", lambda: _xa(ds.assets, ds.edges))
    rows = [
        r for r in rows
        if (not account_id or account_id in (r["source_account"], r["target_account"]))
        and (not external_only or r["external"])
        and (not types or r["edge_type"] in types)
    ]
    pairs: dict[str, int] = {}
    for r in rows:
        k = f"{r['source_account']} -> {r['target_account']}"
        pairs[k] = pairs.get(k, 0) + 1
    page, env = paginate(rows, limit, cursor,
                         fingerprint(ds, a=account_id, x=external_only, t=sorted(types)))
    return {"dataset": ds.name, **env, "by_account_pair": pairs, "items": page}

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

    def compute() -> dict[str, float]:
        if metric == "degree":
            return nx.degree_centrality(g)
        if metric == "in_degree":
            return nx.in_degree_centrality(g)
        if metric == "out_degree":
            return nx.out_degree_centrality(g)
        n = g.number_of_nodes()
        k = None if n <= 1500 else min(n, 300)
        return nx.betweenness_centrality(g, k=k, seed=7)

    scores = ds.cached(f"centrality:{metric}", compute)
    ranked = [
        (n, s) for n, s in sorted(scores.items(), key=lambda kv: -kv[1])
        if n in ds.by_id and (not types or ds.by_id[n].asset_type in types)
    ][:top]
    return {
        "dataset": ds.name,
        "metric": metric,
        "sampled": metric == "betweenness" and g.number_of_nodes() > 1500,
        "items": [{**asset_brief(ds, ds.by_id[n]), "score": round(s, 5),
                   "degree": g.degree(n)} for n, s in ranked],
    }

@CATALOG.tool(title="Export sub-graph", sensitivity=Sensitivity.CONFIDENTIAL, **_RO)
def subgraph_export(
    ctx: Any,
    seeds: Annotated[list[str], Field(min_length=1, max_length=50,
                                      description="Asset refs to start from.")],
    depth: Annotated[int, Field(ge=0, le=4)] = 1,
    format: GraphFormat = "d3",
    max_nodes: Annotated[int, Field(ge=1, le=2000)] = 300,
    edge_types: list[str] | None = None,
    dataset: DatasetArg = "",
) -> dict:
    """The neighbourhood of a few assets as a self-contained graph in
    D3 ({nodes, links}), Cytoscape ({elements}) or GraphML (string), for
    visualisation or handing to another tool. Use the
    cloudg://graph/{format} resources for the whole graph."""
    ds = ws_dataset(ctx, dataset)
    types = {t.value for t in parse_enums(edge_types, EdgeType, "edge type")} or None
    keep: list[str] = []
    truncated = False
    for ref in seeds:
        sid = _resolve_node(ds, ref)
        if sid not in keep:
            keep.append(sid)
        nodes, _, tr = _bfs(ds, sid, "both", types, depth, max_nodes)
        truncated = truncated or tr
        for n in nodes:
            if n not in keep:
                keep.append(n)
    if len(keep) > max_nodes:
        keep, truncated = keep[:max_nodes], True
    from cloudg.graph.builder import GraphBuilder

    sub = GraphBuilder()
    keep_set = set(keep)
    sub.build([ds.by_id[n] for n in keep if n in ds.by_id],
              [e for e in ds.edges if e.source_id in keep_set and e.target_id in keep_set
               and (types is None or e.edge_type.value in types)])
    if format == "d3":
        data: Any = sub.to_d3_json()
    elif format == "cytoscape":
        data = sub.to_cytoscape_json()
    else:
        data = "\n".join(nx.generate_graphml(sub.graph))
    return {"dataset": ds.name, "format": format, "nodes": sub.graph.number_of_nodes(),
            "edges": sub.graph.number_of_edges(), "truncated": truncated, "graph": data}

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
    out: dict[str, Any] = {"dataset": ds.name,
                           "services_by_account_region": cov["services_by_account_region"]}
    for key in ("gaps", "workloads_without_vulnerability_scanning",
                "internet_facing_without_waf"):
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
    comps = sorted((len(c) for c in nx.weakly_connected_components(g)), reverse=True)
    isolated = sum(1 for n in ds.by_id if n in g and g.degree(n) == 0)
    summary = ds.summary()
    rels: dict[str, int] = {}
    for e in ds.edges:
        if e.relationship:
            rels[e.relationship] = rels.get(e.relationship, 0) + 1
    return {
        "dataset": ds.name,
        "nodes": g.number_of_nodes(),
        "asset_nodes": len(ds.by_id),
        "placeholder_nodes": g.number_of_nodes() - sum(1 for n in g if n in ds.by_id),
        "edges": len(ds.edges),
        "graph_edges": g.number_of_edges(),
        "edges_by_type": summary["edges_by_type"],
        "edges_by_relationship": dict(sorted(rels.items(), key=lambda kv: -kv[1])[:30]),
        "components": len(comps),
        "largest_component": comps[0] if comps else 0,
        "isolated_assets": isolated,
        "density": round(nx.density(g), 6) if g.number_of_nodes() > 1 else 0.0,
        "mean_degree": round(
            sum(d for _, d in g.degree()) / g.number_of_nodes(), 3
        ) if g.number_of_nodes() else 0.0,
    }


def _allows_port(e: Any, port: int) -> bool:
    if port in e.ports:
        return True
    if e.port_range:
        for part in str(e.port_range).split(","):
            lo, _, hi = part.strip().partition("-")
            if lo.isdigit() and int(lo) <= port <= (int(hi) if hi.isdigit() else int(lo)):
                return True
    return not e.ports and not e.port_range and (e.protocol or "").upper() in ("ALL", "-1")


def register(reg: Registry) -> None:
    """Add this module's tools to ``reg``."""
    CATALOG.register(reg)
