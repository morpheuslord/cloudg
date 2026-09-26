"""BFS-based network reachability analysis."""

from __future__ import annotations

import logging
from typing import Any

import networkx as nx

from cloudg.schema.models import AssetType, Finding, Severity

logger = logging.getLogger(__name__)

# Ports that are considered sensitive when exposed to the internet
SENSITIVE_PORTS = {
    22: "SSH",
    3389: "RDP",
    3306: "MySQL",
    5432: "PostgreSQL",
    1433: "MSSQL",
    27017: "MongoDB",
    6379: "Redis",
    9200: "Elasticsearch",
    5601: "Kibana",
    8080: "HTTP-Alt",
    8443: "HTTPS-Alt",
}

# Asset types that should NOT be internet-exposed
SENSITIVE_ASSET_TYPES = {
    AssetType.RDS_INSTANCE,
    AssetType.AURORA_CLUSTER,
    AssetType.AZURE_SQL,
    AssetType.CLOUD_SQL,
    AssetType.DYNAMODB_TABLE,
}

# Asset types where internet exposure is expected
EXPECTED_EXPOSED_TYPES = {
    AssetType.LOAD_BALANCER,
    AssetType.CLOUDFRONT,
    AssetType.CDN,
    AssetType.INTERNET_GATEWAY,
}


class ReachabilityAnalyzer:
    """Analyses network reachability via BFS on the infrastructure graph.

    1. Find all nodes reachable from 0.0.0.0/0 → "internet-exposed"
    2. From each exposed node, BFS to find internally-reachable resources → "blast radius"
    3. Cross-reference with asset type to generate severity-scored findings.
    """

    def __init__(self, graph: nx.DiGraph) -> None:
        self._graph = graph

    def find_internet_exposed(self) -> set[str]:
        """Find all nodes reachable from internet-facing entry points (0.0.0.0/0).

        Returns:
            Set of node IDs that are internet-exposed.
        """
        internet_nodes = set()

        # Find all nodes that represent internet CIDR sources
        for node_id, data in self._graph.nodes(data=True):
            name = data.get("name", node_id)
            if name in ("0.0.0.0/0", "::/0") or data.get("is_external"):
                internet_nodes.add(node_id)

        # Also find edges with internet CIDRs
        for source, target, data in self._graph.edges(data=True):
            cidr = data.get("cidr", "")
            if cidr in ("0.0.0.0/0", "::/0"):
                internet_nodes.add(source)

        # BFS from all internet entry points
        exposed: set[str] = set()
        for entry_point in internet_nodes:
            reachable = nx.descendants(self._graph, entry_point)
            exposed.update(reachable)

        # Mark nodes in graph
        for node_id in exposed:
            if node_id in self._graph:
                self._graph.nodes[node_id]["is_internet_exposed"] = True

        logger.info("Found %d internet-exposed nodes", len(exposed))
        return exposed

    def compute_blast_radius(self, node_id: str) -> dict[str, Any]:
        """Compute blast radius: all nodes reachable from a given node.

        Args:
            node_id: Starting node for BFS.

        Returns:
            Dict with 'reachable_nodes', 'depth', and 'risk_score'.
        """
        if node_id not in self._graph:
            return {"reachable_nodes": [], "depth": 0, "risk_score": 0.0}

        reachable = nx.descendants(self._graph, node_id)
        bfs_tree = nx.bfs_tree(self._graph, node_id)

        # Calculate max depth
        if len(bfs_tree) > 1:
            lengths = nx.single_source_shortest_path_length(bfs_tree, node_id)
            max_depth = max(lengths.values()) if lengths else 0
        else:
            max_depth = 0

        # Risk score based on number of reachable nodes and their types
        risk_score = min(10.0, len(reachable) * 0.5)

        # Increase risk if sensitive assets are reachable
        for r_node in reachable:
            node_data = self._graph.nodes.get(r_node, {})
            asset_type_str = node_data.get("asset_type", "")
            try:
                asset_type = AssetType(asset_type_str)
                if asset_type in SENSITIVE_ASSET_TYPES:
                    risk_score = min(10.0, risk_score + 2.0)
            except ValueError:
                pass

        return {
            "reachable_nodes": list(reachable),
            "depth": max_depth,
            "risk_score": round(risk_score, 1),
        }

    def generate_findings(self) -> list[Finding]:
        """Generate security findings based on reachability analysis.

        Returns:
            List of Finding objects for reachability-related security issues.
        """
        findings: list[Finding] = []
        exposed_nodes = self.find_internet_exposed()

        for node_id in exposed_nodes:
            node_data = self._graph.nodes.get(node_id, {})
            asset_type_str = node_data.get("asset_type", "")
            name = node_data.get("name", node_id)
            arn = node_data.get("arn", "")

            # Skip external/placeholder nodes
            if node_data.get("is_external"):
                continue

            try:
                asset_type = AssetType(asset_type_str)
            except ValueError:
                continue

            # Check for sensitive asset types exposed to internet
            if asset_type in SENSITIVE_ASSET_TYPES:
                findings.append(
                    Finding(
                        resource_id=node_id,
                        resource_arn=arn,
                        severity=Severity.CRITICAL,
                        title=f"Internet-exposed {asset_type.value}: {name}",
                        description=(
                            f"The {asset_type.value} resource '{name}' is reachable "
                            f"from the internet (0.0.0.0/0). Database and data-store "
                            f"resources should never be directly internet-accessible."
                        ),
                        evidence=f"BFS reachability from 0.0.0.0/0 reaches node {node_id}",
                        remediation=(
                            "Restrict security group / NSG / firewall rules to remove "
                            "internet access. Place behind a private subnet with NAT "
                            "gateway or VPN."
                        ),
                        source_tool="cloudg-reachability",
                        compliance_frameworks=["CIS", "NIST-800-53"],
                    )
                )
            elif asset_type not in EXPECTED_EXPOSED_TYPES:
                # Non-database but unexpected exposure
                findings.append(
                    Finding(
                        resource_id=node_id,
                        resource_arn=arn,
                        severity=Severity.HIGH,
                        title=f"Unexpected internet-exposed resource: {name}",
                        description=(
                            f"The {asset_type.value} resource '{name}' is reachable "
                            f"from the internet. Verify this exposure is intentional."
                        ),
                        evidence=f"BFS reachability from 0.0.0.0/0 reaches node {node_id}",
                        remediation=(
                            "Review security group / NSG rules. If exposure is not "
                            "required, restrict to specific CIDR ranges or VPN."
                        ),
                        source_tool="cloudg-reachability",
                    )
                )

        # Check for sensitive port exposure on security group edges
        for source, target, data in self._graph.edges(data=True):
            cidr = data.get("cidr", "")
            if cidr not in ("0.0.0.0/0", "::/0"):
                continue

            ports = data.get("ports", [])
            port_range = data.get("port_range", "")

            for port, service in SENSITIVE_PORTS.items():
                if port in ports or str(port) in port_range:
                    target_data = self._graph.nodes.get(target, {})
                    findings.append(
                        Finding(
                            resource_id=target,
                            resource_arn=target_data.get("arn", ""),
                            severity=Severity.CRITICAL,
                            title=f"Security group allows {service} (port {port}) from 0.0.0.0/0",
                            description=(
                                f"A security group rule allows inbound traffic on "
                                f"port {port} ({service}) from 0.0.0.0/0. This is a "
                                f"common attack vector."
                            ),
                            evidence=f"Edge from {source} to {target}, port {port}, cidr {cidr}",
                            remediation=(
                                f"Restrict port {port} ({service}) access to specific "
                                f"IP ranges. Use a bastion host or VPN for "
                                f"administrative access."
                            ),
                            source_tool="cloudg-reachability",
                            compliance_frameworks=["CIS", "NIST-800-53", "PCI-DSS"],
                        )
                    )

        logger.info("Generated %d reachability findings", len(findings))
        return findings
