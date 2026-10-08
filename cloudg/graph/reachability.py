"""BFS-based network reachability analysis.

Internet exposure follows network-flow edges only. Starting from the
internet sources (``0.0.0.0/0``, ``::/0`` and edges that carry an internet
CIDR), the walk moves along an edge only when traffic can travel that way:

- ``INTERNET_EXPOSED``, ``LOAD_BALANCER_TARGET``, ``ROUTE`` and ``PEERING``:
  source to target, as the edge points.
- ``SECURITY_GROUP_RULE`` and ``NACL_RULE``: source to target for ingress
  rules. Egress rules (``direction == "egress"``) point from a group to the
  destination it may send to and carry no inbound traffic.
- ``ATTACHED_TO``: reversed when the target is a traffic filter (security
  group, NSG, NACL, or any edge declaring ``PROTECTED_BY_SG`` /
  ``PROTECTED_BY_NACL``), since traffic admitted by a group reaches the
  resources attached to it. Forward when the source is a network interface
  or public IP, which hand their traffic to the resource they are attached
  to. Other attachments (disks, route tables, VNet integration, gateways
  attached to a VPC) are not traffic paths.
- ``CONTAINS``: parent to child when the parent is a VPC, VNet or subnet,
  so traffic admitted into a network reaches what is placed in it.
  Hierarchy containment (organization, OU, account, cluster, namespace,
  resource group) is not traversed.

Identity edges (``GRANTS_ACCESS``, ``ASSUMES_ROLE``, ``IAM_TRUST``,
``IAM_POLICY_ATTACHMENT``) and the other typed inventory edges
(``INVOKES``, ``REFERENCES``, ``LOGS_TO`` and so on) never make a resource
internet-exposed: a role granted access to a database does not open a
network path to it. Those edges still count for
:meth:`ReachabilityAnalyzer.compute_blast_radius`, which models what a
compromised resource can reach, identity included.

The walk is an over-approximation: it does not intersect ports across
hops, and a rule whose source is another group or a workload is followed
like any other ingress rule.
"""

from __future__ import annotations

import logging
import uuid
from collections import deque
from typing import Any, Iterator

import networkx as nx

from cloudg.schema.models import AssetType, EdgeType, Finding, Severity

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

# Rule containers sit on SG/NSG rule edges but are not reachable workloads;
# their open rules are reported by the sensitive-port findings instead.
RULE_CONTAINER_TYPES = {
    AssetType.SECURITY_GROUP,
    AssetType.NSG,
}

# Source / CIDR values that stand for the whole internet. Azure NSG rules
# use the service tags ``Internet``, ``Any`` and ``*`` instead of a CIDR.
INTERNET_CIDRS = frozenset({"0.0.0.0/0", "::/0"})
_INTERNET_EDGE_CIDRS = frozenset({"0.0.0.0/0", "::/0", "*", "internet", "any"})

# Edges that carry traffic from source to target as they point
_FORWARD_FLOW_EDGES = frozenset(
    {
        EdgeType.INTERNET_EXPOSED.value,
        EdgeType.LOAD_BALANCER_TARGET.value,
        EdgeType.ROUTE.value,
        EdgeType.PEERING.value,
    }
)

# Filter rules: followed source to target unless they are egress rules
_RULE_EDGES = frozenset({EdgeType.SECURITY_GROUP_RULE.value, EdgeType.NACL_RULE.value})

# ATTACHED_TO targets that filter traffic for the resource attached to them
_TRAFFIC_FILTER_TYPES = frozenset(
    {AssetType.SECURITY_GROUP.value, AssetType.NSG.value, AssetType.NACL.value}
)
_FILTER_RELATIONSHIPS = frozenset({"PROTECTED_BY_SG", "PROTECTED_BY_NACL"})

# ATTACHED_TO sources that pass their traffic on to the resource they attach to
_INTERFACE_TYPES = frozenset({AssetType.NETWORK_INTERFACE.value, AssetType.ELASTIC_IP.value})

# CONTAINS parents whose containment is network placement
_NETWORK_PLACEMENT_TYPES = frozenset(
    {AssetType.VPC.value, AssetType.VNET.value, AssetType.SUBNET.value}
)

# Namespace for deterministic finding ids (uuid5 of rule + asset)
_FINDING_ID_NAMESPACE = uuid.uuid5(
    uuid.NAMESPACE_URL, "https://github.com/morpheuslord/cloudg/reachability"
)

# Rule names hashed into the finding ids
RULE_SENSITIVE_EXPOSURE = "internet-exposed-sensitive-asset"
RULE_UNEXPECTED_EXPOSURE = "internet-exposed-unexpected-asset"
RULE_OPEN_PORT = "internet-open-sensitive-port"


def finding_id(rule: str, asset: str) -> str:
    """Deterministic finding id: a UUID5 hash of the rule and the asset key.

    The same rule firing on the same asset gets the same id on every run,
    so reachability findings can be deduplicated and tracked across scans.
    """
    return str(uuid.uuid5(_FINDING_ID_NAMESPACE, f"{rule}|{asset}"))


def _is_egress(edge_data: dict[str, Any]) -> bool:
    """Whether a graph edge is an egress filter rule."""
    return str(edge_data.get("direction") or "").lower() == "egress"


class ReachabilityAnalyzer:
    """Analyses network reachability via BFS on the infrastructure graph.

    1. Find all nodes reachable from the internet over network-flow edges
       ("internet-exposed"); see the module docstring for the traversal rules.
    2. From any node, BFS over every edge type to find what it can reach
       ("blast radius").
    3. Cross-reference with asset type to generate severity-scored findings.
    """

    def __init__(self, graph: nx.DiGraph) -> None:
        self._graph = graph

    def find_internet_exposed(self) -> set[str]:
        """Find all nodes reachable from the internet over network-flow edges.

        Entry points are nodes named ``0.0.0.0/0`` or ``::/0`` and the source
        of every non-egress edge whose CIDR stands for the internet. The walk
        follows only the network-flow hops described in the module docstring,
        so resources reached only through IAM or other non-network edges are
        not reported.

        Returns:
            Set of node IDs that are internet-exposed.
        """
        exposed: set[str] = set()
        queue = deque(self._internet_entry_points())
        seen = set(queue)
        while queue:
            node_id = queue.popleft()
            for nxt in self._flow_successors(node_id):
                exposed.add(nxt)
                if nxt not in seen:
                    seen.add(nxt)
                    queue.append(nxt)

        # Mark nodes in graph
        for node_id in exposed:
            self._graph.nodes[node_id]["is_internet_exposed"] = True

        logger.info("Found %d internet-exposed nodes", len(exposed))
        return exposed

    def _internet_entry_points(self) -> set[str]:
        """Nodes that represent the internet as a traffic source."""
        entry_points = {
            node_id
            for node_id, data in self._graph.nodes(data=True)
            if data.get("name", node_id) in INTERNET_CIDRS
        }
        for source, _target, data in self._graph.edges(data=True):
            if str(data.get("cidr") or "").lower() in _INTERNET_EDGE_CIDRS and not _is_egress(data):
                entry_points.add(source)
        return entry_points

    def _flow_successors(self, node_id: str) -> Iterator[str]:
        """Nodes that traffic arriving at ``node_id`` can travel on to."""
        node_type = self._graph.nodes[node_id].get("asset_type", "")
        for _source, target, data in self._graph.out_edges(node_id, data=True):
            edge_type = data.get("edge_type", "")
            if (
                edge_type in _FORWARD_FLOW_EDGES
                or (edge_type in _RULE_EDGES and not _is_egress(data))
                or (edge_type == EdgeType.ATTACHED_TO.value and node_type in _INTERFACE_TYPES)
                or (edge_type == EdgeType.CONTAINS.value and node_type in _NETWORK_PLACEMENT_TYPES)
            ):
                yield target
        # Traffic admitted by a security group / NSG / NACL reaches the
        # resources attached to it: walk those ATTACHED_TO edges backwards.
        is_filter = node_type in _TRAFFIC_FILTER_TYPES
        for source, _target, data in self._graph.in_edges(node_id, data=True):
            if data.get("edge_type") == EdgeType.ATTACHED_TO.value and (
                is_filter or data.get("relationship") in _FILTER_RELATIONSHIPS
            ):
                yield source

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

        # Findings for internet-exposed resources, in a stable order
        for node_id in sorted(self.find_internet_exposed()):
            finding = self._exposure_finding(node_id)
            if finding:
                findings.append(finding)

        # Findings for sensitive port exposure on security group edges
        findings.extend(self._sensitive_port_findings())

        logger.info("Generated %d reachability findings", len(findings))
        return findings

    def _exposure_finding(self, node_id: str) -> Finding | None:
        """Build a finding for one internet-exposed node, if warranted."""
        node_data = self._graph.nodes.get(node_id, {})

        # Skip external/placeholder nodes
        if node_data.get("is_external"):
            return None

        try:
            asset_type = AssetType(node_data.get("asset_type", ""))
        except ValueError:
            return None

        # Check for sensitive asset types exposed to internet
        if asset_type in SENSITIVE_ASSET_TYPES:
            return self._sensitive_exposure_finding(node_id, node_data, asset_type)
        if asset_type not in EXPECTED_EXPOSED_TYPES | RULE_CONTAINER_TYPES:
            # Non-database but unexpected exposure
            return self._unexpected_exposure_finding(node_id, node_data, asset_type)
        return None

    def _sensitive_exposure_finding(
        self, node_id: str, node_data: dict[str, Any], asset_type: AssetType
    ) -> Finding:
        """Critical finding for an internet-exposed sensitive data store."""
        name = node_data.get("name", node_id)
        return Finding(
            id=finding_id(RULE_SENSITIVE_EXPOSURE, node_id),
            resource_id=node_id,
            resource_arn=node_data.get("arn", ""),
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

    def _unexpected_exposure_finding(
        self, node_id: str, node_data: dict[str, Any], asset_type: AssetType
    ) -> Finding:
        """High finding for an unexpectedly internet-exposed resource."""
        name = node_data.get("name", node_id)
        return Finding(
            id=finding_id(RULE_UNEXPECTED_EXPOSURE, node_id),
            resource_id=node_id,
            resource_arn=node_data.get("arn", ""),
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

    def _sensitive_port_findings(self) -> list[Finding]:
        """Findings for sensitive ports open to the internet on edges."""
        findings: list[Finding] = []
        for source, target, data in self._graph.edges(data=True):
            cidr = data.get("cidr", "")
            if cidr not in ("0.0.0.0/0", "::/0"):
                continue

            ports = data.get("ports", [])
            port_range = data.get("port_range", "")

            for port, service in SENSITIVE_PORTS.items():
                if port in ports or str(port) in port_range:
                    findings.append(self._open_port_finding(source, target, cidr, port, service))
        return findings

    def _open_port_finding(
        self, source: str, target: str, cidr: str, port: int, service: str
    ) -> Finding:
        """Critical finding for one sensitive port open from 0.0.0.0/0."""
        target_data = self._graph.nodes.get(target, {})
        return Finding(
            # One finding per rule edge and port: the asset key is the edge
            id=finding_id(f"{RULE_OPEN_PORT}:{port}", f"{source}->{target}"),
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
