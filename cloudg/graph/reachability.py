"""BFS-based network reachability analysis.

Internet exposure follows network-flow edges only. Starting from the
internet sources (``0.0.0.0/0``, ``::/0`` and edges whose CIDR stands for
the internet, see :func:`cloudg.graph.ports.is_internet_source`), the walk
moves along an edge only when traffic can travel that way:

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

These rules are available on their own through
:meth:`ReachabilityAnalyzer.flow_successors` (the hops out of one node) and
:func:`network_flow_graph` (every hop as a directed graph), so other
consumers walk the network exactly the way the exposure analysis does.

Identity edges (``GRANTS_ACCESS``, ``ASSUMES_ROLE``, ``IAM_TRUST``,
``IAM_POLICY_ATTACHMENT``) and the other typed inventory edges
(``INVOKES``, ``REFERENCES``, ``LOGS_TO`` and so on) never make a resource
internet-exposed: a role granted access to a database does not open a
network path to it. In particular ``INVOKES`` is not followed, so a Lambda
function behind a public API Gateway is not reported as internet-exposed:
the gateway is the exposed resource and the function is only invoked by
it. Those edges still count for
:meth:`ReachabilityAnalyzer.compute_blast_radius`, which models what a
compromised resource can reach, identity included.

Rule containers (security groups, NSGs, NACLs) and routing constructs
(target groups) are hops on the walk and are marked ``is_internet_exposed``
like any reached node, since internet traffic does reach them, but they do
not get an exposure finding of their own: a group's open rules are
reported by the sensitive-port findings, and a target group's exposure is
reported on the targets behind it.

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

from cloudg.graph.ports import (
    FILTER_RULE_EDGES,
    INTERNET_CIDRS,
    edge_port_ranges,
    is_egress,
    is_internet_source,
    port_in_ranges,
)
from cloudg.schema.models import AssetType, EdgeType, Finding, Severity

__all__ = [
    "EXPECTED_EXPOSED_TYPES",
    "INTERNET_CIDRS",
    "NON_RESOURCE_TYPES",
    "ROUTING_CONSTRUCT_TYPES",
    "RULE_CONTAINER_TYPES",
    "RULE_OPEN_PORT",
    "RULE_SENSITIVE_EXPOSURE",
    "RULE_UNEXPECTED_EXPOSURE",
    "SENSITIVE_ASSET_TYPES",
    "SENSITIVE_PORTS",
    "FlowHop",
    "ReachabilityAnalyzer",
    "asset_key",
    "finding_id",
    "is_internet_source",
    "network_flow_graph",
]

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

# Rule containers sit on SG / NSG / NACL rule edges but are not reachable
# workloads; their open rules are reported by the sensitive-port findings.
# The same types are the traffic filters whose ATTACHED_TO edges the walk
# follows backwards.
RULE_CONTAINER_TYPES = {
    AssetType.SECURITY_GROUP,
    AssetType.NSG,
    AssetType.NACL,
}

# Load-balancer routing constructs: traffic passes through them to the
# targets, which get the exposure findings.
ROUTING_CONSTRUCT_TYPES = {AssetType.TARGET_GROUP}

# Reached by the walk but never reported as an exposed resource
NON_RESOURCE_TYPES = RULE_CONTAINER_TYPES | ROUTING_CONSTRUCT_TYPES

# Edges that carry traffic from source to target as they point
_FORWARD_FLOW_EDGES = frozenset(
    {
        EdgeType.INTERNET_EXPOSED.value,
        EdgeType.LOAD_BALANCER_TARGET.value,
        EdgeType.ROUTE.value,
        EdgeType.PEERING.value,
    }
)

# ATTACHED_TO targets that filter traffic for the resource attached to them
_TRAFFIC_FILTER_TYPES = frozenset(t.value for t in RULE_CONTAINER_TYPES)
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

# One network-flow hop: (next node, attributes of the graph edge used, and
# whether the edge was walked against its direction)
FlowHop = tuple[str, dict[str, Any], bool]


def finding_id(rule: str, asset: str) -> str:
    """Deterministic finding id: a UUID5 hash of the rule and the asset key.

    The same rule firing on the same asset gets the same id on every run,
    so reachability findings can be deduplicated and tracked across scans.
    Pass :func:`asset_key` of the node, not the graph node id: collectors
    give assets a fresh random id on every collection.
    """
    return str(uuid.uuid5(_FINDING_ID_NAMESPACE, f"{rule}|{asset}"))


def asset_key(graph: nx.DiGraph, node_id: str) -> str:
    """Key of a graph node that stays the same across collections.

    The node's ARN (cloud resource id) when it has one, else the node id.
    CIDR and other external placeholder nodes have no ARN; their id is
    already stable.
    """
    return str(graph.nodes.get(node_id, {}).get("arn") or node_id)


def _is_forward_hop(data: dict[str, Any], node_type: str) -> bool:
    """Whether traffic at a node of ``node_type`` follows this out-edge."""
    edge_type = data.get("edge_type", "")
    if edge_type in _FORWARD_FLOW_EDGES:
        return True
    if edge_type in FILTER_RULE_EDGES:
        return not is_egress(data)
    if edge_type == EdgeType.ATTACHED_TO.value:
        return node_type in _INTERFACE_TYPES
    if edge_type == EdgeType.CONTAINS.value:
        return node_type in _NETWORK_PLACEMENT_TYPES
    return False


def _is_reverse_hop(data: dict[str, Any], node_is_filter: bool) -> bool:
    """Whether traffic at a filter node follows this in-edge backwards."""
    return data.get("edge_type") == EdgeType.ATTACHED_TO.value and (
        node_is_filter or data.get("relationship") in _FILTER_RELATIONSHIPS
    )


def network_flow_graph(graph: nx.DiGraph) -> nx.DiGraph:
    """The network-flow hops of ``graph`` as a new directed graph.

    Every node of ``graph`` is copied with its attributes. There is an edge
    ``u -> v`` exactly when :meth:`ReachabilityAnalyzer.flow_successors`
    yields ``v`` for ``u``, so walking this graph forward follows the same
    rules as the internet-exposure analysis (see the module docstring).
    Each edge carries ``edge_type`` (the type of the underlying edge) and
    ``reversed`` (True for an ``ATTACHED_TO`` edge walked from the filter
    back to the resource attached to it). ``graph`` is not modified.
    """
    analyzer = ReachabilityAnalyzer(graph)
    flow = nx.DiGraph()
    flow.add_nodes_from(graph.nodes(data=True))
    for node_id in graph.nodes:
        for nxt, data, walked_back in analyzer.flow_hops(node_id):
            if not flow.has_edge(node_id, nxt):
                flow.add_edge(
                    node_id, nxt, edge_type=data.get("edge_type", ""), reversed=walked_back
                )
    return flow


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
        not reported. Every node returned is marked ``is_internet_exposed``
        in the graph, rule containers and target groups included.

        Returns:
            Set of node IDs that are internet-exposed.
        """
        exposed: set[str] = set()
        queue = deque(self.internet_entry_points())
        seen = set(queue)
        while queue:
            node_id = queue.popleft()
            for nxt in self.flow_successors(node_id):
                exposed.add(nxt)
                if nxt not in seen:
                    seen.add(nxt)
                    queue.append(nxt)

        # Mark nodes in graph
        for node_id in exposed:
            self._graph.nodes[node_id]["is_internet_exposed"] = True

        logger.info("Found %d internet-exposed nodes", len(exposed))
        return exposed

    def internet_entry_points(self) -> set[str]:
        """Nodes that represent the internet as a traffic source.

        Nodes named ``0.0.0.0/0`` or ``::/0``, plus the source of every
        non-egress edge whose ``cidr`` passes
        :func:`~cloudg.graph.ports.is_internet_source` (which adds the Azure
        service tags ``Internet``, ``Any`` and ``*``).
        """
        entry_points = {
            node_id
            for node_id, data in self._graph.nodes(data=True)
            if data.get("name", node_id) in INTERNET_CIDRS
        }
        for source, _target, data in self._graph.edges(data=True):
            if is_internet_source(data.get("cidr")) and not is_egress(data):
                entry_points.add(source)
        return entry_points

    def flow_hops(self, node_id: str) -> Iterator[FlowHop]:
        """The network-flow hops out of ``node_id``, with the edge each uses.

        Yields ``(next_node, edge_data, reversed)``: out-edges that carry
        traffic forward (``reversed`` False) and ``ATTACHED_TO`` in-edges
        walked back from a traffic filter to the resource attached to it
        (``reversed`` True). A node may appear more than once when several
        edges lead to it. Unknown nodes yield nothing.
        """
        if node_id not in self._graph:
            return
        node_type = self._graph.nodes[node_id].get("asset_type", "")
        for _source, target, data in self._graph.out_edges(node_id, data=True):
            if _is_forward_hop(data, node_type):
                yield target, data, False
        # Traffic admitted by a security group / NSG / NACL reaches the
        # resources attached to it: walk those ATTACHED_TO edges backwards.
        is_filter = node_type in _TRAFFIC_FILTER_TYPES
        for source, _target, data in self._graph.in_edges(node_id, data=True):
            if _is_reverse_hop(data, is_filter):
                yield source, data, True

    def flow_successors(self, node_id: str) -> Iterator[str]:
        """Nodes that traffic arriving at ``node_id`` can travel on to.

        This is the single-step form of the exposure walk; the rules are in
        the module docstring. See :meth:`flow_hops` for the edges used and
        :func:`network_flow_graph` for the whole flow graph at once.
        """
        for nxt, _data, _reversed in self.flow_hops(node_id):
            yield nxt

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
        if asset_type not in EXPECTED_EXPOSED_TYPES | NON_RESOURCE_TYPES:
            # Non-database but unexpected exposure
            return self._unexpected_exposure_finding(node_id, node_data, asset_type)
        return None

    def _sensitive_exposure_finding(
        self, node_id: str, node_data: dict[str, Any], asset_type: AssetType
    ) -> Finding:
        """Critical finding for an internet-exposed sensitive data store."""
        name = node_data.get("name", node_id)
        return Finding(
            id=finding_id(RULE_SENSITIVE_EXPOSURE, asset_key(self._graph, node_id)),
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
            id=finding_id(RULE_UNEXPECTED_EXPOSURE, asset_key(self._graph, node_id)),
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
        """Findings for sensitive ports open to the internet on edges.

        An edge qualifies when its ``cidr`` stands for the internet
        (:func:`~cloudg.graph.ports.is_internet_source`: ``0.0.0.0/0``,
        ``::/0`` or the Azure tags ``Internet``, ``Any`` and ``*``). Ports are
        compared as numbers against the ranges parsed from the edge's
        ``port_range`` and ``protocol`` (see :mod:`cloudg.graph.ports`), plus
        any ``ports`` list on the edge (graphs built by hand rather than by
        :class:`~cloudg.graph.builder.GraphBuilder` may carry one). Egress
        rules are skipped: they point from a group to the internet and open
        nothing inbound. Each edge yields at most one finding per sensitive
        port.
        """
        findings: list[Finding] = []
        for source, target, data in self._graph.edges(data=True):
            cidr = str(data.get("cidr") or "")
            if not is_internet_source(cidr) or is_egress(data):
                continue

            ports = data.get("ports") or []
            ranges = edge_port_ranges(data)

            for port, service in SENSITIVE_PORTS.items():
                if port in ports or port_in_ranges(port, ranges):
                    findings.append(self._open_port_finding(source, target, cidr, port, service))
        return findings

    def _open_port_finding(
        self, source: str, target: str, cidr: str, port: int, service: str
    ) -> Finding:
        """Critical finding for one sensitive port open from the internet."""
        target_data = self._graph.nodes.get(target, {})
        # The IPv4 and IPv6 "any" CIDRs keep the historical 0.0.0.0/0 wording;
        # an Azure service tag is named as written.
        origin = "0.0.0.0/0" if cidr in INTERNET_CIDRS else cidr
        edge_key = f"{asset_key(self._graph, source)}->{asset_key(self._graph, target)}"
        return Finding(
            # One finding per rule edge and port, keyed by the stable asset keys
            id=finding_id(f"{RULE_OPEN_PORT}:{port}", edge_key),
            resource_id=target,
            resource_arn=target_data.get("arn", ""),
            severity=Severity.CRITICAL,
            title=f"Security group allows {service} (port {port}) from {origin}",
            description=(
                f"A security group rule allows inbound traffic on "
                f"port {port} ({service}) from {origin}. This is a "
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
