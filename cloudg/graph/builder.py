"""NetworkX graph construction from cloud assets and edges."""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

import networkx as nx

from cloudg.graph.ports import (
    ALL_PORTS_RANGE,
    ALL_PROTOCOLS,
    FILTER_RULE_EDGES,
    PORTED_PROTOCOLS,
    PORTLESS_PROTOCOLS,
)
from cloudg.schema.models import CloudAsset, EdgeType, NetworkEdge

logger = logging.getLogger(__name__)

# Edge types that carry ports. When two of them share a source and target
# they are merged into one graph edge (see GraphBuilder._add_edge).
_MERGEABLE_EDGES = FILTER_RULE_EDGES | {EdgeType.INTERNET_EXPOSED.value}

# Protocols whose empty port list on a filter rule allows every port: the
# port-carrying protocols plus the spellings of "every protocol". The
# port-less protocols (ICMP and the like, see cloudg.graph.ports) add no
# ports when such a rule is merged with a rule for another protocol: AWS
# stores the ICMP type and code in the port fields and Azure writes "*".
_EMPTY_MEANS_ALL_PROTOCOLS = PORTED_PROTOCOLS | ALL_PROTOCOLS


def _split(value: str) -> list[str]:
    return [part.strip() for part in value.split(",") if part.strip()]


def _join_unique(values: list[str], *, ignore_case: bool = False) -> list[str]:
    """``values`` without repeats, first spelling kept, in order."""
    seen: dict[str, str] = {}
    for value in values:
        seen.setdefault(value.upper() if ignore_case else value, value)
    return list(seen.values())


def _can_merge(existing: dict[str, Any], new: dict[str, Any]) -> bool:
    """Whether two edges on the same source and target can be merged.

    They must be the same port-carrying edge type with the same CIDR and
    direction. Protocols may differ (see :func:`_merge_edge_attrs`).
    """
    return (
        existing.get("edge_type") == new["edge_type"]
        and new["edge_type"] in _MERGEABLE_EDGES
        and existing.get("cidr", "") == new["cidr"]
        and str(existing.get("direction", "")).lower() == new["direction"].lower()
    )


def _rule_ports(attrs: dict[str, Any], mixed_protocols: bool) -> list[str]:
    """The ``port_range`` tokens one edge contributes to a merged edge."""
    protocols = {p.upper() for p in _split(str(attrs.get("protocol", "")))}
    if mixed_protocols and protocols and protocols <= PORTLESS_PROTOCOLS:
        return []
    tokens = _split(str(attrs.get("port_range", "")))
    if tokens:
        return tokens
    # An empty port list on a TCP / UDP / all-protocol filter rule allows
    # every port (the GCP collector writes it that way). Spell it out so the
    # other rule's ports do not narrow it.
    if attrs.get("edge_type") in FILTER_RULE_EDGES and protocols & _EMPTY_MEANS_ALL_PROTOCOLS:
        return [ALL_PORTS_RANGE]
    return []


def _merge_edge_attrs(existing: dict[str, Any], new: dict[str, Any]) -> None:
    """Fold the attributes of ``new`` into the graph edge ``existing``.

    ``port_range`` becomes the comma-separated union of both edges' ports.
    When the protocols match it is the two strings joined as written. When
    they differ, ``protocol`` lists both (``"TCP,ICMP"``), ICMP and other
    port-less rules add no ports, and an empty TCP / UDP / all-protocol rule
    adds ``0-65535``. The ports are then a union across protocols: the edge
    still says which ports are open from the source, but not which protocol
    each port is open for. Descriptions are joined with ``"; "``.
    """
    protocols = _join_unique(
        _split(str(existing.get("protocol", ""))) + _split(new["protocol"]), ignore_case=True
    )
    mixed = len(protocols) > 1
    if not mixed and not existing.get("port_range") and not new["port_range"]:
        port_range = ""
    else:
        port_range = ",".join(_join_unique(_rule_ports(existing, mixed) + _rule_ports(new, mixed)))
    descriptions = _join_unique(
        [d for d in str(existing.get("description", "")).split("; ") if d]
        + ([new["description"]] if new["description"] else [])
    )
    existing["protocol"] = ",".join(protocols)
    existing["port_range"] = port_range
    existing["description"] = "; ".join(descriptions)
    if not existing.get("relationship"):
        existing["relationship"] = new["relationship"]


class GraphBuilder:
    """Builds a NetworkX directed graph from collected cloud assets and edges.

    Nodes represent cloud resources with full CloudAsset data as attributes.
    Edges represent network connectivity, IAM trust, or containment relationships.

    The graph is a ``nx.DiGraph``, so it holds one edge per source and target.
    Collectors often emit several rules for one pair, for example two
    security group ingress rules from ``0.0.0.0/0`` for ports 22 and 443.
    Such ``SECURITY_GROUP_RULE``, ``NACL_RULE`` and ``INTERNET_EXPOSED`` edges
    are merged into one graph edge whose ``port_range`` lists the ports of
    all of them (``"22,443"``), as long as their CIDR and direction match.
    Any other edge sharing a source and target with an earlier one replaces
    its attributes, as NetworkX does.
    """

    def __init__(self) -> None:
        self._graph = nx.DiGraph()

    @property
    def graph(self) -> nx.DiGraph:
        """Access the underlying NetworkX graph."""
        return self._graph

    def build(
        self,
        assets: list[CloudAsset],
        edges: list[NetworkEdge],
    ) -> nx.DiGraph:
        """Build the graph from assets and edges.

        Args:
            assets: List of normalised cloud assets (nodes).
            edges: List of network/IAM edges.

        Returns:
            Populated NetworkX DiGraph.
        """
        self._graph.clear()

        if len(assets) > 10000:
            logger.warning(
                "Large graph: %d assets. Consider filtering by region or service "
                "to reduce memory usage.",
                len(assets),
            )

        # Add asset nodes
        for asset in assets:
            self._add_asset_node(asset)

        # Add edges
        for edge in edges:
            self._add_edge(edge)

        logger.info(
            "Built graph with %d nodes and %d edges",
            self._graph.number_of_nodes(),
            self._graph.number_of_edges(),
        )
        return self._graph

    def _add_asset_node(self, asset: CloudAsset) -> None:
        """Add a cloud asset as a node with its attributes."""
        self._graph.add_node(
            asset.id,
            name=asset.name,
            asset_type=asset.asset_type.value,
            provider=asset.provider.value,
            region=asset.region,
            arn=asset.arn,
            account_id=asset.account_id or "",
            tags=json.dumps(asset.tags) if asset.tags else "{}",
            is_internet_exposed=asset.is_internet_exposed,
        )

    def _ensure_node(self, node_id: str) -> None:
        """Create an external placeholder node if it does not exist yet."""
        if node_id not in self._graph:
            self._graph.add_node(
                node_id,
                name=node_id,
                asset_type="EXTERNAL",
                provider="EXTERNAL",
                is_external=True,
            )

    def _add_edge(self, edge: NetworkEdge) -> None:
        """Add an edge, creating placeholder endpoints as needed.

        A rule edge whose source and target already have a compatible rule
        edge is merged into it instead of overwriting it; see the class
        docstring.
        """
        # Ensure source/target nodes exist (create placeholder if needed)
        self._ensure_node(edge.source_id)
        self._ensure_node(edge.target_id)

        attrs = {
            "edge_type": edge.edge_type.value,
            "port_range": edge.port_range or "",
            "protocol": edge.protocol or "",
            "cidr": edge.cidr or "",
            "direction": edge.direction or "",
            "description": edge.description or "",
            "relationship": edge.relationship or "",
        }
        existing = self._graph.get_edge_data(edge.source_id, edge.target_id)
        if existing is not None:
            if _can_merge(existing, attrs):
                _merge_edge_attrs(existing, attrs)
                return
            logger.debug(
                "Edge %s -> %s (%s) replaces a %s edge on the same pair",
                edge.source_id,
                edge.target_id,
                attrs["edge_type"],
                existing.get("edge_type"),
            )
        self._graph.add_edge(edge.source_id, edge.target_id, **attrs)

    def compute_centrality(self) -> dict[str, dict[str, float]]:
        """Compute graph centrality metrics for blast-radius scoring.

        Returns:
            Dict mapping node_id -> {degree, betweenness, in_degree, out_degree}
        """
        metrics: dict[str, dict[str, float]] = {}

        degree_centrality = nx.degree_centrality(self._graph)
        in_degree = nx.in_degree_centrality(self._graph)
        out_degree = nx.out_degree_centrality(self._graph)

        # Betweenness only makes sense for connected graphs
        try:
            betweenness = nx.betweenness_centrality(self._graph)
        except Exception:
            betweenness = {n: 0.0 for n in self._graph.nodes()}

        for node in self._graph.nodes():
            metrics[node] = {
                "degree": degree_centrality.get(node, 0.0),
                "betweenness": betweenness.get(node, 0.0),
                "in_degree": in_degree.get(node, 0.0),
                "out_degree": out_degree.get(node, 0.0),
            }

        return metrics

    # ------------------------------------------------------------------
    # Graph persistence
    # ------------------------------------------------------------------

    def save_graphml(self, path: str | Path) -> Path:
        """Save graph to GraphML format for persistence/offline analysis.

        Args:
            path: Output file path.

        Returns:
            Path to saved file.
        """
        output = Path(path)
        output.parent.mkdir(parents=True, exist_ok=True)

        # Patch numpy 2.0 compatibility (np.float_ removed)
        try:
            import numpy as np

            if not hasattr(np, "float_"):
                np.float_ = np.float64  # type: ignore[attr-defined]
        except ImportError:
            pass

        nx.write_graphml_xml(self._graph, str(output))
        logger.info("Saved graph to %s", output)
        return output

    def load_graphml(self, path: str | Path) -> nx.DiGraph:
        """Load graph from GraphML file.

        Args:
            path: Path to GraphML file.

        Returns:
            Loaded DiGraph.
        """
        self._graph = nx.read_graphml(str(path))
        logger.info(
            "Loaded graph from %s (%d nodes, %d edges)",
            path,
            self._graph.number_of_nodes(),
            self._graph.number_of_edges(),
        )
        return self._graph

    def subgraph(self, node_ids: set[str]) -> nx.DiGraph:
        """Extract a subgraph containing only the specified nodes.

        Args:
            node_ids: Set of node IDs to include.

        Returns:
            Subgraph as new DiGraph.
        """
        return self._graph.subgraph(node_ids).copy()

    # ------------------------------------------------------------------
    # Attack path analysis
    # ------------------------------------------------------------------

    def find_attack_paths(self, source: str, target: str, max_depth: int = 10) -> list[list[str]]:
        """Find all simple paths between source and target nodes.

        Args:
            source: Source node ID (e.g., internet entry point).
            target: Target node ID (e.g., database).
            max_depth: Maximum path length.

        Returns:
            List of paths (each path is a list of node IDs).
        """
        if source not in self._graph or target not in self._graph:
            return []

        try:
            paths = list(nx.all_simple_paths(self._graph, source, target, cutoff=max_depth))
            logger.info("Found %d attack paths from %s to %s", len(paths), source, target)
            return paths
        except nx.NetworkXError as exc:
            logger.warning("Attack path search failed: %s", exc)
            return []

    def find_lateral_movement_paths(self) -> list[list[str]]:
        """Find paths that traverse IAM trust edges.

        Returns:
            List of paths that include at least one IAM_TRUST edge.
        """
        # Find IAM trust edges
        iam_edges = [
            (u, v) for u, v, d in self._graph.edges(data=True) if d.get("edge_type") == "IAM_TRUST"
        ]

        if not iam_edges:
            return []

        paths: list[list[str]] = []
        # Find internet-exposed entry points
        entry_points = [
            n
            for n, d in self._graph.nodes(data=True)
            if d.get("is_internet_exposed") or d.get("is_external")
        ]

        # For each IAM trust target, check if reachable from internet
        for _, trust_target in iam_edges:
            for entry in entry_points:
                try:
                    for path in nx.all_simple_paths(self._graph, entry, trust_target, cutoff=8):
                        paths.append(path)
                        if len(paths) > 100:  # Cap to prevent combinatorial explosion
                            break
                except nx.NetworkXError:
                    continue
                if len(paths) > 100:
                    break

        logger.info("Found %d lateral movement paths", len(paths))
        return paths

    # ------------------------------------------------------------------
    # Export formats
    # ------------------------------------------------------------------

    def to_d3_json(self) -> dict[str, Any]:
        """Export graph to D3.js-compatible JSON format.

        Returns:
            Dict with 'nodes' and 'links' arrays for D3.js force-directed graph.
        """
        nodes = []
        for node_id, data in self._graph.nodes(data=True):
            nodes.append(
                {
                    "id": node_id,
                    "name": data.get("name", node_id),
                    "type": data.get("asset_type", "UNKNOWN"),
                    "provider": data.get("provider", "UNKNOWN"),
                    "region": data.get("region", ""),
                    "arn": data.get("arn", ""),
                    "account_id": data.get("account_id", ""),
                    "is_internet_exposed": data.get("is_internet_exposed", False),
                    "is_external": data.get("is_external", False),
                }
            )

        links = []
        for source, target, data in self._graph.edges(data=True):
            links.append(
                {
                    "source": source,
                    "target": target,
                    "type": data.get("edge_type", "UNKNOWN"),
                    "port_range": data.get("port_range"),
                    "protocol": data.get("protocol"),
                    "cidr": data.get("cidr"),
                    "direction": data.get("direction"),
                    "relationship": data.get("relationship", ""),
                    "description": data.get("description", ""),
                }
            )

        return {"nodes": nodes, "links": links}

    def to_cytoscape_json(self) -> dict[str, Any]:
        """Export graph to Cytoscape.js-compatible JSON format.

        Returns:
            Dict with 'elements' containing 'nodes' and 'edges' arrays.
        """
        elements: dict[str, list[dict[str, Any]]] = {"nodes": [], "edges": []}

        for node_id, data in self._graph.nodes(data=True):
            elements["nodes"].append(
                {
                    "data": {
                        "id": node_id,
                        "label": data.get("name", node_id),
                        "type": data.get("asset_type", "UNKNOWN"),
                        "provider": data.get("provider", "UNKNOWN"),
                        "region": data.get("region", ""),
                        "internet_exposed": data.get("is_internet_exposed", False),
                    }
                }
            )

        for source, target, data in self._graph.edges(data=True):
            elements["edges"].append(
                {
                    "data": {
                        "source": source,
                        "target": target,
                        "type": data.get("edge_type", "UNKNOWN"),
                        "port_range": data.get("port_range", ""),
                        "protocol": data.get("protocol", ""),
                    }
                }
            )

        return {"elements": elements}

    def to_json_str(self, indent: int = 2) -> str:
        """Serialize graph to JSON string."""
        return json.dumps(self.to_d3_json(), indent=indent, default=str)
