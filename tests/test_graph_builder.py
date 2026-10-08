"""Tests for GraphBuilder's handling of several edges on one source and target."""

from __future__ import annotations

import asyncio

import pytest

from cloudg.collectors.aws import AsyncAWSCollector
from cloudg.collectors.azure import AzureCollector
from cloudg.graph.builder import GraphBuilder
from cloudg.graph.reachability import RULE_OPEN_PORT, ReachabilityAnalyzer, finding_id
from cloudg.schema.models import AssetType, CloudAsset, CloudProvider, EdgeType, NetworkEdge

INTERNET = "0.0.0.0/0"
SG = "sg-1"


def _rule(port_range: str | None, protocol: str | None = "TCP", **kw) -> NetworkEdge:
    fields = {
        "source_id": INTERNET,
        "target_id": SG,
        "edge_type": EdgeType.SECURITY_GROUP_RULE,
        "port_range": port_range,
        "protocol": protocol,
        "cidr": INTERNET,
        "direction": "ingress",
    }
    fields.update(kw)
    return NetworkEdge(**fields)


def _build(edges: list[NetworkEdge]):
    return GraphBuilder().build([], edges)


def _open_ports(edges: list[NetworkEdge]) -> dict[str, str]:
    """Sensitive-port finding titles by finding id."""
    findings = ReachabilityAnalyzer(_build(edges))._sensitive_port_findings()
    return {f.id: f.title for f in findings}


def _ssh_id(source: str = INTERNET, target: str = SG) -> str:
    return finding_id(f"{RULE_OPEN_PORT}:22", f"{source}->{target}")


class TestSameProtocolRules:
    """Rules that differ only in their ports."""

    @pytest.mark.parametrize("order", [("22", "443"), ("443", "22")])
    def test_ssh_is_reported_whichever_rule_comes_last(self, order):
        edges = [_rule(port) for port in order]
        graph = _build(edges)
        assert graph.number_of_edges() == 1
        assert graph.edges[INTERNET, SG]["port_range"] == ",".join(order)
        assert list(_open_ports(edges)) == [_ssh_id()]

    def test_merged_edge_keeps_one_finding_per_port(self):
        edges = [_rule("22"), _rule("3389"), _rule("22")]
        assert _build(edges).edges[INTERNET, SG]["port_range"] == "22,3389"
        assert sorted(_open_ports(edges).values()) == [
            "Security group allows RDP (port 3389) from 0.0.0.0/0",
            "Security group allows SSH (port 22) from 0.0.0.0/0",
        ]

    def test_finding_id_matches_a_single_rule_edge(self):
        assert _open_ports([_rule("22")]) == _open_ports([_rule("22"), _rule("443")])

    def test_protocol_case_is_ignored_and_first_spelling_kept(self):
        data = _build([_rule("22", "Tcp"), _rule("443", "TCP")]).edges[INTERNET, SG]
        assert (data["protocol"], data["port_range"]) == ("Tcp", "22,443")

    def test_portless_rules_join_their_raw_values(self):
        data = _build([_rule("-1", "ICMP"), _rule("8--1", "ICMP")]).edges[INTERNET, SG]
        assert (data["protocol"], data["port_range"]) == ("ICMP", "-1,8--1")

    def test_two_empty_port_lists_stay_empty(self):
        assert _build([_rule(None), _rule(None)]).edges[INTERNET, SG]["port_range"] == ""

    def test_empty_port_list_on_a_filter_rule_means_every_port(self):
        # GCP writes a TCP rule without ports as an empty port_range
        data = _build([_rule(None), _rule("443")]).edges[INTERNET, SG]
        assert data["port_range"] == "0-65535,443"

    def test_descriptions_are_joined_once_each(self):
        edges = [
            _rule("22", description="NSG rule ssh"),
            _rule("443", description="NSG rule https"),
            _rule("8443", description="NSG rule https"),
        ]
        data = _build(edges).edges[INTERNET, SG]
        assert data["description"] == "NSG rule ssh; NSG rule https"


class TestMixedProtocolRules:
    """Rules for different protocols on the same pair."""

    @pytest.mark.parametrize(
        "edges",
        [
            [_rule("22"), _rule("-1", "ICMP")],
            [_rule("-1", "ICMP"), _rule("22")],
        ],
        ids=["tcp-then-icmp", "icmp-then-tcp"],
    )
    def test_icmp_rule_does_not_hide_ssh(self, edges):
        data = _build(edges).edges[INTERNET, SG]
        assert data["port_range"] == "22"
        assert {p for p in data["protocol"].split(",")} == {"TCP", "ICMP"}
        assert list(_open_ports(edges)) == [_ssh_id()]

    def test_icmp_wildcard_does_not_open_every_port(self):
        # Azure writes "*" as the port range of an ICMP rule
        edges = [_rule("*", "Icmp"), _rule("443", "Tcp")]
        data = _build(edges).edges[INTERNET, SG]
        assert (data["protocol"], data["port_range"]) == ("Icmp,Tcp", "443")
        assert _open_ports(edges) == {}

    def test_ports_of_both_protocols_are_kept(self):
        edges = [_rule("22"), _rule("53", "UDP"), _rule("6379")]
        data = _build(edges).edges[INTERNET, SG]
        assert (data["protocol"], data["port_range"]) == ("TCP,UDP", "22,53,6379")
        assert len(_open_ports(edges)) == 2

    def test_empty_tcp_rule_becomes_every_port(self):
        data = _build([_rule(None, "TCP"), _rule("53", "UDP")]).edges[INTERNET, SG]
        assert (data["protocol"], data["port_range"]) == ("TCP,UDP", "0-65535,53")

    def test_internet_exposed_edge_without_ports_adds_none(self):
        # A non-filter edge with no port_range only means "no port data"
        edges = [
            _rule(None, "ALL", edge_type=EdgeType.INTERNET_EXPOSED),
            _rule("22", edge_type=EdgeType.INTERNET_EXPOSED),
        ]
        data = _build(edges).edges[INTERNET, SG]
        assert (data["protocol"], data["port_range"]) == ("ALL,TCP", "22")
        assert list(_open_ports(edges)) == [_ssh_id()]


class TestEdgesThatAreNotMerged:
    def test_different_direction_replaces(self):
        edges = [_rule("22"), _rule("443", direction="egress")]
        data = _build(edges).edges[INTERNET, SG]
        assert (data["direction"], data["port_range"]) == ("egress", "443")

    def test_different_edge_type_replaces(self):
        edges = [_rule("22"), _rule(None, None, edge_type=EdgeType.ATTACHED_TO, cidr=None)]
        data = _build(edges).edges[INTERNET, SG]
        assert (data["edge_type"], data["port_range"], data["cidr"]) == ("ATTACHED_TO", "", "")

    def test_non_rule_edges_still_replace(self):
        edges = [
            NetworkEdge(
                source_id="vpc-1", target_id="sub-1", edge_type=EdgeType.CONTAINS, description="a"
            ),
            NetworkEdge(
                source_id="vpc-1", target_id="sub-1", edge_type=EdgeType.CONTAINS, description="b"
            ),
        ]
        assert _build(edges).edges["vpc-1", "sub-1"]["description"] == "b"

    def test_rules_on_other_pairs_are_untouched(self):
        graph = _build([_rule("22"), _rule("443", target_id="sg-2")])
        assert graph.edges[INTERNET, SG]["port_range"] == "22"
        assert graph.edges[INTERNET, "sg-2"]["port_range"] == "443"


class TestCollectorEdges:
    """Rules as the AWS and Azure collectors write them."""

    def test_aws_security_group_rules(self):
        sg = CloudAsset(
            id=SG,
            name="web",
            asset_type=AssetType.SECURITY_GROUP,
            provider=CloudProvider.AWS,
            metadata={
                "group_id": SG,
                "ingress_rules": [
                    {
                        "IpProtocol": "tcp",
                        "FromPort": 22,
                        "ToPort": 22,
                        "IpRanges": [{"CidrIp": INTERNET}],
                    },
                    {
                        "IpProtocol": "icmp",
                        "FromPort": -1,
                        "ToPort": -1,
                        "IpRanges": [{"CidrIp": INTERNET}],
                    },
                    {
                        "IpProtocol": "tcp",
                        "FromPort": 443,
                        "ToPort": 443,
                        "IpRanges": [{"CidrIp": INTERNET}],
                    },
                ],
            },
        )
        collector = AsyncAWSCollector(session=None)
        edges = asyncio.run(collector._collect_sg_edges([sg]))
        assert len(edges) == 3
        graph = GraphBuilder().build([sg], edges)
        assert graph.number_of_edges() == 1
        assert graph.edges[INTERNET, SG]["port_range"] == "22,443"
        assert list(_open_ports(edges)) == [_ssh_id()]

    def test_azure_nsg_rules(self):
        nsg = CloudAsset(
            id="nsg-1",
            name="nsg",
            asset_type=AssetType.NSG,
            provider=CloudProvider.AZURE,
            metadata={
                "ingress_rules": [
                    {
                        "name": "rdp",
                        "access": "Allow",
                        "protocol": "Tcp",
                        "source_address_prefix": "Internet",
                        "destination_port_range": "3389",
                    },
                    {
                        "name": "web",
                        "access": "Allow",
                        "protocol": "Tcp",
                        "source_address_prefix": "Internet",
                        "destination_port_ranges": ["80", "443"],
                    },
                ]
            },
        )
        collector = AzureCollector(object(), "00000000-0000-0000-0000-000000000000")
        collector._cached_assets = [nsg]
        edges = asyncio.run(collector.collect_edges())
        assert [e.port_range for e in edges] == ["3389", "80,443"]
        data = GraphBuilder().build([nsg], edges).edges["Internet", "nsg-1"]
        assert data["port_range"] == "3389,80,443"
        assert data["description"] == "NSG rule rdp; NSG rule web"


def test_exports_carry_the_merged_edge(tmp_path):
    builder = GraphBuilder()
    builder.build([], [_rule("22"), _rule("443")])
    links = builder.to_d3_json()["links"]
    assert [(link["port_range"], link["protocol"]) for link in links] == [("22,443", "TCP")]
    loaded = GraphBuilder().load_graphml(builder.save_graphml(tmp_path / "g.graphml"))
    assert loaded.edges[INTERNET, SG]["port_range"] == "22,443"
