"""Tests for sensitive-port findings on internet-facing rule edges (cloudg.graph.ports)."""

from __future__ import annotations

import asyncio
import uuid

import networkx as nx
import pytest

from cloudg.collectors.aws import AsyncAWSCollector
from cloudg.collectors.azure import AzureCollector
from cloudg.graph.builder import GraphBuilder
from cloudg.graph.ports import (
    ALL_PORTS,
    covers_all_ports,
    edge_port_ranges,
    is_internet_source,
    parse_port_ranges,
    port_in_ranges,
)
from cloudg.graph.reachability import SENSITIVE_PORTS, ReachabilityAnalyzer
from cloudg.schema.models import (
    AssetType,
    CloudAsset,
    CloudProvider,
    EdgeType,
    NetworkEdge,
)

INTERNET = "0.0.0.0/0"


def _port_findings(graph: nx.DiGraph) -> list:
    """The open-port findings among everything generate_findings() reports."""
    findings = ReachabilityAnalyzer(graph).generate_findings()
    return [f for f in findings if f.title.startswith("Security group allows")]


def _open_ports(edges: list[NetworkEdge], assets: list[CloudAsset] | None = None) -> list[int]:
    """Sensitive ports reported open, sorted, through the real graph builder."""
    builder = GraphBuilder()
    builder.build(assets or [], edges)
    findings = _port_findings(builder.graph)
    return sorted(int(f.evidence.split("port ")[1].split(",")[0]) for f in findings)


def _rule(port_range: str | None, protocol: str = "TCP", **kw) -> NetworkEdge:
    params = {
        "source_id": INTERNET,
        "target_id": "sg-web",
        "edge_type": EdgeType.SECURITY_GROUP_RULE,
        "port_range": port_range,
        "protocol": protocol,
        "cidr": INTERNET,
        "direction": "ingress",
    }
    params.update(kw)
    return NetworkEdge(**params)


# ---------------------------------------------------------------------------
# parse_port_ranges
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("port_range", "protocol", "expected"),
    [
        ("22", "TCP", ((22, 22),)),
        ("0-65535", "ALL", ALL_PORTS),
        ("2200-2300", "TCP", ((2200, 2300),)),
        ("22,3389,8000-8100", "Tcp", ((22, 22), (3389, 3389), (8000, 8100))),
        (" 22 , 80 ", "TCP", ((22, 22), (80, 80))),
        ("*", "*", ALL_PORTS),
        ("*", "Tcp", ALL_PORTS),
        ("22,*", "Udp", ((22, 22), (0, 65535))),
        # empty: every port for all-protocols and port-carrying protocols
        ("", "ALL", ALL_PORTS),
        (None, "-1", ALL_PORTS),
        ("", "TCP", ALL_PORTS),
        ("", "udp", ALL_PORTS),
        ("", "", ()),
        (None, None, ()),
        # AWS ICMP writes type and code in the port fields
        ("8--1", "ICMP", ()),
        ("-1", "ICMPV6", ()),
        ("0-65535", "1", ()),
        ("*", "Esp", ()),
        # invalid tokens are skipped
        ("70000", "TCP", ()),
        ("30-20", "TCP", ()),
        ("ssh", "TCP", ()),
        ("22,ssh", "TCP", ((22, 22),)),
        ("-1", "ALL", ALL_PORTS),
    ],
)
def test_parse_port_ranges(port_range, protocol, expected):
    assert parse_port_ranges(port_range, protocol) == expected


def test_port_in_ranges_is_inclusive():
    ranges = ((20, 22), (3389, 3389))
    assert port_in_ranges(20, ranges)
    assert port_in_ranges(22, ranges)
    assert port_in_ranges(3389, ranges)
    assert not port_in_ranges(23, ranges)
    assert not port_in_ranges(3390, ranges)
    assert not port_in_ranges(22, ())


def test_covers_all_ports():
    assert covers_all_ports(ALL_PORTS)
    assert covers_all_ports(((1000, 65535), (0, 999)))
    assert covers_all_ports(((0, 80), (50, 65535)))
    assert not covers_all_ports(((1, 65535),))
    assert not covers_all_ports(((0, 79), (81, 65535)))
    assert not covers_all_ports(())


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("0.0.0.0/0", True),
        ("::/0", True),
        ("Internet", True),
        ("INTERNET", True),
        ("*", True),
        ("Any", True),
        (" internet ", True),
        ("10.0.0.0/8", False),
        ("VirtualNetwork", False),
        ("AzureLoadBalancer", False),
        ("0.0.0.0/1", False),
        ("", False),
        (None, False),
    ],
)
def test_is_internet_source(value, expected):
    assert is_internet_source(value) is expected


def test_empty_port_range_means_all_ports_only_on_filter_rules():
    rule = {"edge_type": "SECURITY_GROUP_RULE", "port_range": "", "protocol": "ALL"}
    nacl = {"edge_type": "NACL_RULE", "port_range": "", "protocol": "TCP"}
    exposure = {"edge_type": "INTERNET_EXPOSED", "port_range": "", "protocol": "ALL"}
    exposure_ports = {"edge_type": "INTERNET_EXPOSED", "port_range": "443", "protocol": "TCP"}
    assert edge_port_ranges(rule) == ALL_PORTS
    assert edge_port_ranges(nacl) == ALL_PORTS
    assert edge_port_ranges(exposure) == ()
    assert edge_port_ranges(exposure_ports) == ((443, 443),)


# ---------------------------------------------------------------------------
# Open-port findings from generate_findings()
# ---------------------------------------------------------------------------


def test_all_ports_open_reports_every_sensitive_port():
    assert _open_ports([_rule("0-65535", "ALL")]) == sorted(SENSITIVE_PORTS)


def test_protocol_all_with_empty_range_reports_every_sensitive_port():
    assert _open_ports([_rule(None, "ALL")]) == sorted(SENSITIVE_PORTS)


def test_wide_tcp_range_covering_ssh_and_rdp():
    assert _open_ports([_rule("20-3400")]) == [22, 1433, 3306, 3389]


@pytest.mark.parametrize("port_range", ["2200-2300", "33890", "122", "5432-5432x", "80,443"])
def test_digit_substrings_do_not_match(port_range):
    assert _open_ports([_rule(port_range)]) == []


def test_exact_single_port():
    assert _open_ports([_rule("3389")]) == [3389]


def test_icmp_rule_opens_no_ports():
    assert _open_ports([_rule("8--1", "ICMP")]) == []


def test_egress_rule_is_not_an_inbound_opening():
    egress = _rule("0-65535", "ALL", source_id="sg-web", target_id=INTERNET, direction="egress")
    assert _open_ports([egress]) == []


def test_non_internet_cidr_is_ignored():
    assert _open_ports([_rule("22", source_id="10.0.0.0/8", cidr="10.0.0.0/8")]) == []


def test_internet_exposed_edge_without_ports_reports_nothing():
    edge = NetworkEdge(
        source_id=INTERNET,
        target_id="bucket",
        edge_type=EdgeType.INTERNET_EXPOSED,
        protocol="ALL",
        cidr=INTERNET,
    )
    assert _open_ports([edge]) == []


def test_overlapping_ranges_yield_one_finding_per_port():
    # 22 is in all three tokens; the edge still gets a single SSH finding
    assert _open_ports([_rule("22,20-30,0-100")]) == [22]


def test_ports_list_on_a_hand_built_graph_is_honoured():
    """GraphBuilder never writes ``ports``; a graph built by hand may carry it."""
    graph = nx.DiGraph()
    graph.add_edge(INTERNET, "sg-web", cidr=INTERNET, ports=[6379], port_range="", protocol="")
    findings = _port_findings(graph)
    assert [f.title for f in findings] == ["Security group allows Redis (port 6379) from 0.0.0.0/0"]


def test_finding_points_at_rule_target():
    sg = CloudAsset(
        id="sg-web",
        name="web",
        asset_type=AssetType.SECURITY_GROUP,
        provider=CloudProvider.AWS,
        arn="arn:aws:ec2:us-east-1:111111111111:security-group/sg-web",
    )
    builder = GraphBuilder()
    builder.build([sg], [_rule("22")])
    (finding,) = ReachabilityAnalyzer(builder.graph).generate_findings()
    assert finding.resource_id == "sg-web"
    assert finding.resource_arn == sg.arn
    assert finding.evidence == f"Edge from {INTERNET} to sg-web, port 22, cidr {INTERNET}"


# ---------------------------------------------------------------------------
# Collector output end to end
# ---------------------------------------------------------------------------


def _aws_sg(
    ingress: list[dict], egress: list[dict] | None = None, asset_id: str = "sg-0abc"
) -> CloudAsset:
    return CloudAsset(
        id=asset_id,
        arn="arn:aws:ec2:us-east-1:111111111111:security-group/sg-0abc",
        name="web",
        asset_type=AssetType.SECURITY_GROUP,
        provider=CloudProvider.AWS,
        metadata={
            "group_id": "sg-0abc",
            "ingress_rules": ingress,
            "egress_rules": egress or [],
        },
    )


def _aws_edges(sg: CloudAsset) -> list[NetworkEdge]:
    collector = AsyncAWSCollector(session=None, region="us-east-1", account_id="111111111111")
    return asyncio.run(collector._collect_sg_edges([sg]))


def test_aws_all_traffic_rule_reports_ssh_and_rdp():
    # describe_security_groups omits FromPort / ToPort for IpProtocol -1
    sg = _aws_sg([{"IpProtocol": "-1", "IpRanges": [{"CidrIp": INTERNET}]}])
    edges = _aws_edges(sg)
    assert edges[0].port_range == "0-65535"
    open_ports = _open_ports(edges, [sg])
    assert 22 in open_ports
    assert 3389 in open_ports


def test_aws_default_egress_rule_reports_nothing():
    sg = _aws_sg([], egress=[{"IpProtocol": "-1", "IpRanges": [{"CidrIp": INTERNET}]}])
    assert _open_ports(_aws_edges(sg), [sg]) == []


def test_aws_neighbouring_ranges_are_not_false_positives():
    sg = _aws_sg(
        [
            {
                "IpProtocol": "tcp",
                "FromPort": 2200,
                "ToPort": 2300,
                "IpRanges": [{"CidrIp": INTERNET}],
            }
        ]
    )
    assert _open_ports(_aws_edges(sg), [sg]) == []


def test_aws_icmp_rule_reports_nothing():
    sg = _aws_sg(
        [{"IpProtocol": "icmp", "FromPort": 8, "ToPort": -1, "IpRanges": [{"CidrIp": INTERNET}]}]
    )
    assert _open_ports(_aws_edges(sg), [sg]) == []


def _azure_nsg() -> CloudAsset:
    return CloudAsset(
        id="nsg-web",
        name="nsg-web",
        asset_type=AssetType.NSG,
        provider=CloudProvider.AZURE,
    )


def test_azure_comma_joined_ranges():
    nsg = _azure_nsg()
    rule = {
        "name": "allow-admin",
        "access": "Allow",
        "protocol": "Tcp",
        "source_address_prefix": INTERNET,
        "destination_port_ranges": ["443", "3380-3390", "8000-8100"],
    }
    edges = AzureCollector._rule_edges(nsg, rule, {})
    assert edges[0].port_range == "443,3380-3390,8000-8100"
    assert _open_ports(edges, [nsg]) == [3389, 8080]


def test_azure_star_port_range_reports_every_sensitive_port():
    nsg = _azure_nsg()
    rule = {
        "name": "allow-all",
        "access": "Allow",
        "protocol": "*",
        "source_address_prefix": INTERNET,
        "destination_port_range": "*",
    }
    edges = AzureCollector._rule_edges(nsg, rule, {})
    assert _open_ports(edges, [nsg]) == sorted(SENSITIVE_PORTS)


def _tcp(port: int, cidr: str = INTERNET) -> dict:
    return {"IpProtocol": "tcp", "FromPort": port, "ToPort": port, "IpRanges": [{"CidrIp": cidr}]}


def _aws_scan(sg_id: str, instance_id: str) -> list:
    """One collection: an SG with internet rules for 22 and 443 and an instance in it."""
    sg = _aws_sg([_tcp(22), _tcp(443)], asset_id=sg_id)
    vm = CloudAsset(
        id=instance_id,
        name="web-1",
        asset_type=AssetType.EC2,
        provider=CloudProvider.AWS,
        arn="arn:aws:ec2:us-east-1:111111111111:instance/i-0web1",
    )
    edges = [
        *_aws_edges(sg),
        NetworkEdge(source_id=vm.id, target_id=sg.id, edge_type=EdgeType.ATTACHED_TO),
    ]
    graph = GraphBuilder().build([sg, vm], edges)
    return ReachabilityAnalyzer(graph).generate_findings()


def test_aws_group_with_several_internet_rules_reports_ssh():
    findings = _aws_scan("sg-asset", "vm-asset")
    by_title = {f.title: f for f in findings}
    assert sorted(by_title) == [
        "Security group allows SSH (port 22) from 0.0.0.0/0",
        "Unexpected internet-exposed resource: web-1",
    ]
    ssh = by_title["Security group allows SSH (port 22) from 0.0.0.0/0"]
    assert ssh.resource_id == "sg-asset"
    assert ssh.resource_arn.endswith("security-group/sg-0abc")


def test_finding_ids_are_stable_across_collections():
    """CloudAsset ids are fresh uuid4s per collection; the finding ids are not."""
    first = sorted((f.title, f.id) for f in _aws_scan(str(uuid.uuid4()), str(uuid.uuid4())))
    second = sorted((f.title, f.id) for f in _aws_scan(str(uuid.uuid4()), str(uuid.uuid4())))
    assert len(first) == 2
    assert first == second


@pytest.mark.parametrize("source", ["Internet", "*", "Any"])
def test_azure_service_tag_sources_report_open_ports(source):
    nsg = _azure_nsg()
    rule = {
        "name": "allow-ssh",
        "access": "Allow",
        "protocol": "Tcp",
        "source_address_prefix": source,
        "destination_port_range": "22",
    }
    edges = AzureCollector._rule_edges(nsg, rule, {})
    assert edges[0].cidr == source
    assert _open_ports(edges, [nsg]) == [22]


def test_azure_rule_without_source_is_treated_as_any():
    nsg = _azure_nsg()
    rule = {"name": "open", "access": "Allow", "protocol": "Tcp", "destination_port_range": "3389"}
    assert _open_ports(AzureCollector._rule_edges(nsg, rule, {}), [nsg]) == [3389]
