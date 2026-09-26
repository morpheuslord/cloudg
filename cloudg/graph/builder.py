"""NetworkX graph construction from cloud assets and edges."""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

import networkx as nx

from cloudg.schema.models import CloudAsset, NetworkEdge

logger = logging.getLogger(__name__)


class GraphBuilder:
    """Builds a NetworkX directed graph from collected cloud assets and edges.

    Nodes represent cloud resources with full CloudAsset data as attributes.
    Edges represent network connectivity, IAM trust, or containment relationships.
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
            self._graph.add_node(
                asset.id,
                name=asset.name,
                asset_type=asset.asset_type.value,
                provider=asset.provider.value,
                region=asset.region,
                arn=asset.arn,
                tags=json.dumps(asset.tags) if asset.tags else "{}",
                is_internet_exposed=asset.is_internet_exposed,
            )

        # Add edges
        for edge in edges:
            # Ensure source/target nodes exist (create placeholder if needed)
            if edge.source_id not in self._graph:
                self._graph.add_node(
                    edge.source_id,
                    name=edge.source_id,
                    asset_type="EXTERNAL",
                    provider="EXTERNAL",
                    is_external=True,
                )
            if edge.target_id not in self._graph:
                self._graph.add_node(
                    edge.target_id,
                    name=edge.target_id,
                    asset_type="EXTERNAL",
                    provider="EXTERNAL",
                    is_external=True,
                )

            self._graph.add_edge(
                edge.source_id,
                edge.target_id,
                edge_type=edge.edge_type.value,
                port_range=edge.port_range or "",
                protocol=edge.protocol or "",
                cidr=edge.cidr or "",
                direction=edge.direction or "",
                description=edge.description or "",
            )

        logger.info(
            "Built graph with %d nodes and %d edges",
            self._graph.number_of_nodes(),
            self._graph.number_of_edges(),
        )
        return self._graph

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
