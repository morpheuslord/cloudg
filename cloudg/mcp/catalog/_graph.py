"""Helpers behind the graph tools: node resolution (including the virtual
internet source), path description, exposure evidence, edge filters, the
breadth-first neighbourhood walk and the attack / lateral path searches.

Port and internet-source parsing is delegated to :mod:`cloudg.graph.ports`
so the MCP tools read rules exactly like the reachability analysis: Azure
``*`` ports and ``Internet`` / ``Any`` / ``*`` sources, GCP rules with no
ports (every port of the protocol), AWS ICMP type / code pairs (no ports)
and egress rules (never an internet entry).
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass
from typing import Any, Iterable

import networkx as nx

from cloudg.graph.ports import edge_port_ranges, is_egress, is_internet_source, port_in_ranges
from cloudg.mcp.catalog._common import asset_brief, node_brief, parse_enums
from cloudg.mcp.core import InvalidArgumentsError
from cloudg.mcp.state import Dataset
from cloudg.schema.models import AssetType, EdgeType, NetworkEdge

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

CATEGORY = "graph"
#: Tool options shared by every read-only graph tool.
GRAPH_RO = dict(read_only=True, idempotent=True, open_world=False, category=CATEGORY)

# Virtual node standing for "the internet" when a tool is asked for
# source='internet': linked to every internet entry point of the dataset.
INTERNET = "__internet__"
_INTERNET_ALIASES = ("internet", "0.0.0.0/0", "::/0", "public")
_COMPACT_KEYS = (
    "id",
    "name",
    "type",
    "account_id",
    "internet_exposed",
    "open_findings",
    "max_severity",
    "external",
)


# ---------------------------------------------------------------------------
# Edges
# ---------------------------------------------------------------------------


def edge_type_values(values: list[str] | None) -> set[str]:
    """The EdgeType values named in a tool's ``edge_types`` argument."""
    return {t.value for t in parse_enums(values, EdgeType, "edge type")}


def edge_data(e: NetworkEdge) -> dict[str, Any]:
    """The attributes :mod:`cloudg.graph.ports` reads from a graph edge."""
    return {
        "edge_type": e.edge_type.value,
        "port_range": e.port_range,
        "protocol": e.protocol,
        "cidr": e.cidr,
        "direction": e.direction,
    }


def allows_port(e: NetworkEdge, port: int) -> bool:
    """Whether a rule edge opens ``port`` (explicit port list or port range)."""
    if port in e.ports:
        return True
    return port_in_ranges(port, edge_port_ranges(edge_data(e)))


def open_ports(e: NetworkEdge, wanted: Iterable[int]) -> set[int]:
    """The ports of ``wanted`` a rule edge opens."""
    ranges = edge_port_ranges(edge_data(e))
    return {p for p in wanted if p in e.ports or port_in_ranges(p, ranges)}


def from_internet(e: NetworkEdge) -> bool:
    """An ingress edge whose source or CIDR stands for the whole internet."""
    if is_egress(edge_data(e)):
        return False
    return is_internet_source(e.source_id) or is_internet_source(e.cidr)


# ---------------------------------------------------------------------------
# Nodes
# ---------------------------------------------------------------------------


def internet_alias(ref: str) -> bool:
    return ref.strip().lower() in _INTERNET_ALIASES


def internet_nodes(ds: Dataset) -> list[str]:
    """Internet entry points of the dataset (same rule as the reachability
    analysis), sorted with the 0.0.0.0/0 and ::/0 nodes first."""

    def build() -> list[str]:
        from cloudg.graph.reachability import ReachabilityAnalyzer

        found = ReachabilityAnalyzer(ds.graph).internet_entry_points()
        return sorted(found, key=lambda n: (n not in ("0.0.0.0/0", "::/0"), n))

    return ds.cached("internet_nodes", build)


def resolve_node(ds: Dataset, ref: str, *, virtual_internet: bool = False) -> str:
    """Graph node for a reference: an asset, a placeholder node, or for
    'internet' the first internet entry point (or :data:`INTERNET` when
    ``virtual_internet``)."""
    if internet_alias(ref):
        nodes = internet_nodes(ds)
        if not nodes:
            raise InvalidArgumentsError(
                "This dataset has no internet node (no internet-sourced ingress rules or "
                "INTERNET_EXPOSED edges). Use internet_exposure to see assets flagged as exposed."
            )
        return INTERNET if virtual_internet else nodes[0]
    if ref in ds.graph and ref not in ds.by_id:
        return ref  # placeholder node (CIDR / external id)
    return ds.resolve_asset(ref).id


def brief(ds: Dataset, node: str) -> dict[str, Any]:
    if node == INTERNET:
        return {"id": INTERNET, "name": "internet", "type": "EXTERNAL", "external": True}
    return node_brief(ds, node)


def compact(b: dict[str, Any]) -> dict[str, Any]:
    """Path hops repeat a lot: keep only what explains the hop."""
    return {k: b[k] for k in _COMPACT_KEYS if b.get(k) is not None}


# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------


def path_graph(ds: Dataset, mode: str) -> nx.DiGraph | nx.Graph:
    if mode == "flow":
        return ds.flow_graph
    if mode == "undirected":
        return ds.cached("undirected", lambda: ds.graph.to_undirected(as_view=False))
    return ds.graph


def with_internet(ds: Dataset, g: Any) -> Any:
    """Copy of ``g`` with :data:`INTERNET` linked to every entry point."""
    g = g.copy()
    g.add_node(INTERNET)
    for n in internet_nodes(ds):
        if n in g:
            g.add_edge(INTERNET, n, edge_type="INTERNET")
    return g


def hop_type(data: dict[str, Any]) -> str:
    if data.get("derived") == "sg_admits" or data.get("reversed"):
        return "SG_ADMITS"
    return data.get("edge_type", "?")


def describe_path(ds: Dataset, g: Any, path: list[str]) -> dict[str, Any]:
    edge_types = [hop_type(g.get_edge_data(u, v) or {}) for u, v in zip(path, path[1:])]
    briefs = [brief(ds, n) for n in path]
    return {
        "length": len(path) - 1,
        "nodes": [compact(b) for b in briefs],
        "edge_types": edge_types,
        "summary": " -> ".join(b["name"] for b in briefs),
    }


def simple_paths(g: Any, s: str, t: str, max_depth: int, max_paths: int) -> list[list[str]]:
    """Shortest simple paths from ``s`` to ``t`` (one beyond ``max_paths`` so
    the caller can tell more exist). Paths from :data:`INTERNET` are
    returned without the virtual first node."""
    skip = 1 if s == INTERNET else 0
    paths: list[list[str]] = []
    try:
        for p in nx.shortest_simple_paths(g, s, t):
            if len(p) - 1 - skip > max_depth or len(paths) > max_paths:
                break
            paths.append(p[skip:])
    except (nx.NetworkXNoPath, nx.NodeNotFound):
        return paths  # no (further) path: what was found so far is the answer
    return paths


@dataclass
class AttackSearch:
    """Inputs of the attack-path search."""

    ds: Dataset
    targets: dict[str, int]
    max_depth: int


def attack_graph(ds: Dataset) -> nx.DiGraph:
    """The flow graph plus a virtual entry linked to every internet entry
    point and every asset flagged internet-exposed."""
    g = with_internet(ds, ds.flow_graph)
    for a in ds.assets:
        if a.is_internet_exposed:
            g.add_edge(INTERNET, a.id, edge_type="INTERNET_EXPOSED")
    return g


def attack_paths_found(search: AttackSearch, g: nx.DiGraph) -> list[dict[str, Any]]:
    ds = search.ds
    _, paths = nx.single_source_dijkstra(g, INTERNET, cutoff=search.max_depth + 1)
    found = []
    for tid, weight in search.targets.items():
        p = paths.get(tid, [INTERNET])[1:]  # drop the virtual entry
        if not p:
            continue
        on_path = sum(len(ds.open_findings(n)) for n in p if n in ds.by_id)
        first = g.get_edge_data(INTERNET, p[0]) or {}
        desc = describe_path(ds, g, p)
        desc["entry"] = (
            "internet-exposed asset"
            if first.get("edge_type") == "INTERNET_EXPOSED"
            else "internet-sourced rule"
        )
        desc["target_weight"] = weight
        desc["findings_on_path"] = on_path
        desc["score"] = round(weight * 1.0 + min(on_path, 10) * 0.5 - (len(p) - 1) * 0.3, 2)
        found.append(desc)
    found.sort(key=lambda d: (-d["score"], d["length"]))
    return found


def identity_graph(ds: Dataset) -> nx.DiGraph:
    def build() -> nx.DiGraph:
        g = nx.DiGraph()
        for e in ds.edges:
            if e.edge_type.value in IDENTITY_EDGES:
                g.add_edge(
                    e.source_id,
                    e.target_id,
                    edge_type=e.edge_type.value,
                    relationship=e.relationship,
                )
        return g

    return ds.cached("identity_graph", build)


def lateral_starts(ds: Dataset) -> list[str]:
    starts = [a.id for a in ds.assets if a.is_internet_exposed]
    starts += [
        a.id
        for a in ds.assets
        if a.asset_type == AssetType.CLOUD_ACCOUNT and a.metadata.get("external")
    ]
    return starts


def lateral_chains(ds: Dataset, g: nx.DiGraph, starts: list[str], max_depth: int) -> list:
    chains: list[list[str]] = []
    for s in dict.fromkeys(starts):
        if s not in g:
            continue
        for tgt, p in nx.single_source_shortest_path(g, s, cutoff=max_depth).items():
            if tgt != s and g.out_degree(tgt) == 0:
                chains.append(p)

    def weight(p: list[str]) -> int:
        return max(
            (CROWN_JEWELS.get(ds.by_id[n].asset_type, 0) for n in p if n in ds.by_id), default=0
        )

    chains.sort(key=lambda p: (-weight(p), len(p)))
    return chains


# ---------------------------------------------------------------------------
# Exposure
# ---------------------------------------------------------------------------


def _filter_nodes(ds: Dataset, asset_id: str) -> tuple[list[tuple[str, str | None]], bool]:
    """The asset plus the security groups / NSGs attached to it, and
    whether a PROTECTS edge (WAF) points at it."""
    via_nodes: list[tuple[str, str | None]] = [(asset_id, None)]
    protected = False
    for e, other, d in ds.adjacency.get(asset_id, []):
        if d == "in" and e.edge_type == EdgeType.PROTECTS:
            protected = True
        a = ds.by_id.get(other)
        if (
            d == "out"
            and e.edge_type == EdgeType.ATTACHED_TO
            and a is not None
            and a.asset_type in (AssetType.SECURITY_GROUP, AssetType.NSG)
        ):
            via_nodes.append((other, a.name))
    return via_nodes, protected


def exposure_evidence(ds: Dataset, asset_id: str) -> dict[str, Any]:
    """Internet-sourced ingress rules reaching an asset directly or through
    a security group / NSG attached to it, sensitive ports among them, WAF
    coverage."""
    via_nodes, protected = _filter_nodes(ds, asset_id)
    rules = []
    ports: set[int] = set()
    for node, via in via_nodes:
        for e, other, d in ds.adjacency.get(node, []):
            if d != "in" or is_egress(edge_data(e)):
                continue
            if not (is_internet_source(e.cidr) or is_internet_source(other)):
                continue
            rules.append(
                {
                    "edge_type": e.edge_type.value,
                    "ports": e.port_range or ",".join(str(p) for p in e.ports[:10]) or "all",
                    "protocol": e.protocol,
                    "via": via or e.description,
                }
            )
            ports |= open_ports(e, SENSITIVE_PORTS)
    return {
        "internet_rules": rules[:10],
        "sensitive_ports_open": sorted(ports),
        "protected_by_waf": protected,
    }


# ---------------------------------------------------------------------------
# Neighbourhood walk and dependency helpers
# ---------------------------------------------------------------------------


@dataclass
class Walk:
    """Options of the breadth-first neighbourhood walk."""

    direction: str = "both"
    edge_types: set[str] | None = None
    depth: int = 1
    cap: int = 100


def _hops(ds: Dataset, node: str, walk: Walk) -> Iterable[tuple[NetworkEdge, str]]:
    for e, other, dirn in ds.adjacency.get(node, []):
        if walk.direction != "both" and dirn != walk.direction:
            continue
        if walk.edge_types and e.edge_type.value not in walk.edge_types:
            continue
        yield e, other


def bfs(ds: Dataset, start: str, walk: Walk) -> tuple[list[str], list[Any], bool]:
    """Nodes and edges within ``walk.depth`` hops of ``start``; at most
    ``cap`` nodes and ``2 * cap`` edges."""
    seen = {start}
    nodes: list[str] = []
    edges: list[Any] = []
    seen_edges: set[str] = set()
    queue: deque[tuple[str, int]] = deque([(start, 0)])
    truncated = False
    while queue:
        node, d = queue.popleft()
        if d >= walk.depth:
            continue
        for e, other in _hops(ds, node, walk):
            if e.id not in seen_edges:
                if len(edges) >= walk.cap * 2:
                    truncated = True
                    continue
                seen_edges.add(e.id)
                edges.append(e)
            if other in seen:
                continue
            if len(nodes) >= walk.cap:
                truncated = True
                continue
            seen.add(other)
            nodes.append(other)
            queue.append((other, d + 1))
    return nodes, edges, truncated


def dep_items(ds: Dataset, links: list[Any]) -> list[dict[str, Any]]:
    out = []
    for link in links:
        a = ds.by_id.get(link.asset_id)
        if a is None:
            continue
        out.append(
            {
                **asset_brief(ds, a),
                "via": link.via_edge,
                "relationship": link.relationship,
                "depth": link.depth,
                "parent_id": link.parent_id,
            }
        )
    return out


def prune_tree(nodes: list[dict[str, Any]], budget: list[int]) -> list[dict[str, Any]]:
    """Keep at most ``budget[0]`` nodes; ``budget[1]`` becomes 1 when a node
    had to be dropped."""
    out = []
    for n in nodes:
        if budget[0] <= 0:
            budget[1] = 1
            break
        budget[0] -= 1
        children = n.get("children") or []
        out.append({**n, "children": prune_tree(children, budget)})
    return out


# ---------------------------------------------------------------------------
# Edge search
# ---------------------------------------------------------------------------


@dataclass
class EdgeQuery:
    """get_edges filters, with endpoints already resolved to node ids."""

    source: str | None = None
    target: str | None = None
    edge_types: set[str] | None = None
    relationship: str = ""
    internet_only: bool = False
    port: int | None = None

    def _endpoint_ok(self, e: NetworkEdge) -> bool:
        if self.source == INTERNET:
            if not from_internet(e):
                return False
        elif self.source and e.source_id != self.source:
            return False
        return not self.target or e.target_id == self.target

    def matches(self, e: NetworkEdge) -> bool:
        if not self._endpoint_ok(e):
            return False
        if self.edge_types and e.edge_type.value not in self.edge_types:
            return False
        if self.relationship and (e.relationship or "") != self.relationship:
            return False
        if self.internet_only and not from_internet(e):
            return False
        return self.port is None or allows_port(e, self.port)
