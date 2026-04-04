"""NetworkX graph construction from cloud assets and edges."""

from __future__ import annotations

import json
import logging
from typing import Any

import networkx as nx

from cloudmapper.schema.models import CloudAsset, NetworkEdge

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

        # Add asset nodes
        for asset in assets:
            self._graph.add_node(
                asset.id,
                name=asset.name,
                asset_type=asset.asset_type.value,
                provider=asset.provider.value,
                region=asset.region,
                arn=asset.arn,
                tags=asset.tags,
                metadata=asset.metadata,
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
                ports=edge.ports,
                port_range=edge.port_range,
                protocol=edge.protocol,
                cidr=edge.cidr,
                direction=edge.direction,
                description=edge.description,
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
                    "metadata": data.get("metadata", {}),
                }
            )

        links = []
        for source, target, data in self._graph.edges(data=True):
            links.append(
                {
                    "source": source,
                    "target": target,
                    "type": data.get("edge_type", "UNKNOWN"),
                    "ports": data.get("ports", []),
                    "port_range": data.get("port_range"),
                    "protocol": data.get("protocol"),
                    "cidr": data.get("cidr"),
                    "direction": data.get("direction"),
                }
            )

        return {"nodes": nodes, "links": links}

    def to_json_str(self, indent: int = 2) -> str:
        """Serialize graph to JSON string."""
        return json.dumps(self.to_d3_json(), indent=indent, default=str)
