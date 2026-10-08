"""Tests for sensitive-port findings on internet-facing rule edges."""

from __future__ import annotations

import asyncio

import networkx as nx
import pytest

from cloudg.collectors.aws import AsyncAWSCollector
from cloudg.collectors.azure import AzureCollector
from cloudg.graph.builder import GraphBuilder
from cloudg.graph.ports import (
    ALL_PORTS,
    edge_port_ranges,
    parse_port_ranges,
    port_in_ranges,
)
from cloudg.graph.reachability import SENSITIVE_PORTS, ReachabilityAnalyzer

from __future__ import annotations

import uuid

import pytest

from cloudg.graph.builder import GraphBuilder
from cloudg.graph.reachability import (
    RULE_OPEN_PORT,
    RULE_SENSITIVE_EXPOSURE,
    RULE_UNEXPECTED_EXPOSURE,
    ReachabilityAnalyzer,
    finding_id,
)
from cloudg.schema.models import (
    AssetType,
    CloudAsset,
    CloudProvider,
    EdgeType,
    NetworkEdge,
)

INTERNET = "0.0.0.0/0"


def _open_ports(edges: list[NetworkEdge], assets: list[CloudAsset] | None = None) -> list[int]:
    """Sensitive ports reported open, sorted, through the real graph builder."""
    builder = GraphBuilder()
    builder.build(assets or [], edges)
    findings = ReachabilityAnalyzer(builder.graph)._sensitive_port_findings()
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
# _sensitive_port_findings
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


def test_ports_attribute_on_graph_edge_is_still_honoured():
    graph = nx.DiGraph()
    graph.add_edge(INTERNET, "sg-web", cidr=INTERNET, ports=[6379], port_range="", protocol="")
    findings = ReachabilityAnalyzer(graph)._sensitive_port_findings()
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
    (finding,) = ReachabilityAnalyzer(builder.graph)._sensitive_port_findings()
    assert finding.resource_id == "sg-web"
    assert finding.resource_arn == sg.arn
    assert finding.evidence == f"Edge from {INTERNET} to sg-web, port 22, cidr {INTERNET}"


# ---------------------------------------------------------------------------
# Collector output end to end
# ---------------------------------------------------------------------------


def _aws_sg(ingress: list[dict], egress: list[dict] | None = None) -> CloudAsset:
    return CloudAsset(
        id="sg-0abc",
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
=======
    Severity,
)

INTERNET = "0.0.0.0/0"
T = AssetType
E = EdgeType


def _asset(aid: str, asset_type: AssetType) -> CloudAsset:
    return CloudAsset(
        id=aid,
        name=aid,
        asset_type=asset_type,
        provider=CloudProvider.AWS,
        arn=f"arn:aws:test:us-east-1:111111111111:{aid}",
    )


def _edge(source: str, target: str, edge_type: EdgeType, **kw) -> NetworkEdge:
    return NetworkEdge(source_id=source, target_id=target, edge_type=edge_type, **kw)


def _analyzer(assets: list[CloudAsset], edges: list[NetworkEdge]) -> ReachabilityAnalyzer:
    builder = GraphBuilder()
    builder.build(assets, edges)
    return ReachabilityAnalyzer(builder.graph)


def _exposed(assets: list[CloudAsset], edges: list[NetworkEdge]) -> set[str]:
    return _analyzer(assets, edges).find_internet_exposed()


# A web tier behind an ALB, a bastion with SSH open, a database reachable only
# from the app security group, and an IAM graph that grants the app role
# access to the database, a bucket and (through a trust) a shared role.
def _estate_assets() -> list[CloudAsset]:
    return [
        _asset("acct-prod", T.CLOUD_ACCOUNT),
        _asset("vpc-prod", T.VPC),
        _asset("subnet-private", T.SUBNET),
        _asset("sg-web", T.SECURITY_GROUP),
        _asset("sg-admin", T.SECURITY_GROUP),
        _asset("sg-app", T.SECURITY_GROUP),
        _asset("sg-db", T.SECURITY_GROUP),
        _asset("alb-web", T.LOAD_BALANCER),
        _asset("tg-web", T.TARGET_GROUP),
        _asset("web-1", T.EC2),
        _asset("bastion", T.EC2),
        _asset("orders-db", T.RDS_INSTANCE),
        _asset("data-bucket", T.S3_BUCKET),
        _asset("app-role", T.IAM_ROLE),
        _asset("admin-policy", T.IAM_POLICY),
        _asset("deploy-role", T.IAM_ROLE),
        _asset("artifacts-bucket", T.S3_BUCKET),
        _asset("api-handler", T.LAMBDA_FUNCTION),
    ]


def _estate_edges() -> list[NetworkEdge]:
    return [
        # placement and hierarchy
        _edge("acct-prod", "vpc-prod", E.CONTAINS),
        _edge("vpc-prod", "subnet-private", E.CONTAINS),
        _edge("subnet-private", "web-1", E.CONTAINS),
        _edge("subnet-private", "orders-db", E.CONTAINS),
        # internet ingress
        _edge(INTERNET, "sg-web", E.SECURITY_GROUP_RULE, cidr=INTERNET, port_range="443"),
        _edge(INTERNET, "sg-admin", E.SECURITY_GROUP_RULE, cidr=INTERNET, port_range="22"),
        _edge(INTERNET, "alb-web", E.INTERNET_EXPOSED, cidr=INTERNET),
        # security group membership and an east-west rule
        _edge("alb-web", "sg-web", E.ATTACHED_TO),
        _edge("bastion", "sg-admin", E.ATTACHED_TO),
        _edge("web-1", "sg-app", E.ATTACHED_TO),
        _edge("orders-db", "sg-db", E.ATTACHED_TO),
        _edge("sg-app", "sg-db", E.SECURITY_GROUP_RULE, port_range="5432", direction="ingress"),
        _edge("sg-db", INTERNET, E.SECURITY_GROUP_RULE, cidr=INTERNET, direction="egress"),
        # load balancing
        _edge("alb-web", "tg-web", E.LOAD_BALANCER_TARGET),
        _edge("tg-web", "web-1", E.LOAD_BALANCER_TARGET),
        # identity
        _edge("web-1", "app-role", E.ASSUMES_ROLE),
        _edge("app-role", "orders-db", E.GRANTS_ACCESS),
        _edge("app-role", "data-bucket", E.GRANTS_ACCESS),
        _edge("app-role", "deploy-role", E.IAM_TRUST),
        _edge("admin-policy", "app-role", E.IAM_POLICY_ATTACHMENT),
        _edge("deploy-role", "artifacts-bucket", E.GRANTS_ACCESS),
        # non-network dependencies
        _edge("data-bucket", "api-handler", E.INVOKES),
    ]


class TestInternetExposureTraversal:
    """find_internet_exposed() follows network-flow edges only."""

    def test_estate_exposes_only_network_reachable_assets(self):
        exposed = _exposed(_estate_assets(), _estate_edges())
        assert exposed == {"sg-web", "sg-admin", "alb-web", "bastion", "tg-web", "web-1"}

    def test_iam_reachable_database_has_no_exposure_finding(self):
        findings = _analyzer(_estate_assets(), _estate_edges()).generate_findings()
        assert all(f.resource_id != "orders-db" for f in findings)
        assert not any(f.title.startswith("Internet-exposed RDS_INSTANCE") for f in findings)
        flagged = {f.resource_id for f in findings}
        assert flagged.isdisjoint(
            {"app-role", "data-bucket", "deploy-role", "artifacts-bucket", "api-handler"}
        )

    @pytest.mark.parametrize(
        "edge_type",
        [
            E.GRANTS_ACCESS,
            E.ASSUMES_ROLE,
            E.IAM_TRUST,
            E.IAM_POLICY_ATTACHMENT,
            E.INVOKES,
            E.REFERENCES,
            E.USES_IMAGE,
            E.LOGS_TO,
            E.MANAGES,
        ],
    )
    def test_non_network_edges_are_not_traversed(self, edge_type):
        assets = [_asset("public-vm", T.EC2), _asset("db", T.RDS_INSTANCE)]
        edges = [
            _edge(INTERNET, "public-vm", E.INTERNET_EXPOSED, cidr=INTERNET),
            _edge("public-vm", "db", edge_type),
        ]
        assert _exposed(assets, edges) == {"public-vm"}

    @pytest.mark.parametrize(
        "edge_type",
        [
            E.INTERNET_EXPOSED,
            E.LOAD_BALANCER_TARGET,
            E.ROUTE,
            E.PEERING,
            E.SECURITY_GROUP_RULE,
            E.NACL_RULE,
        ],
    )
    def test_network_flow_edges_are_traversed(self, edge_type):
        assets = [_asset("entry", T.API_GATEWAY), _asset("backend", T.EC2)]
        edges = [
            _edge(INTERNET, "entry", E.INTERNET_EXPOSED, cidr=INTERNET),
            _edge("entry", "backend", edge_type),
        ]
        assert _exposed(assets, edges) == {"entry", "backend"}

    def test_egress_rules_are_not_traversed(self):
        assets = [_asset("sg", T.SECURITY_GROUP), _asset("other", T.EC2)]
        edges = [
            _edge(INTERNET, "sg", E.SECURITY_GROUP_RULE, cidr=INTERNET),
            _edge("sg", "other", E.SECURITY_GROUP_RULE, direction="egress"),
        ]
        assert _exposed(assets, edges) == {"sg"}

    def test_egress_to_internet_does_not_make_group_an_entry_point(self):
        """Every default security group allows egress to 0.0.0.0/0."""
        assets = [_asset("sg", T.SECURITY_GROUP), _asset("vm", T.EC2)]
        edges = [
            _edge("sg", INTERNET, E.SECURITY_GROUP_RULE, cidr=INTERNET, direction="egress"),
            _edge("vm", "sg", E.ATTACHED_TO),
        ]
        assert _exposed(assets, edges) == set()


class TestAttachmentDirection:
    """ATTACHED_TO is followed only in the direction traffic travels."""

    def test_group_reaches_attached_resource(self):
        assets = [_asset("sg", T.SECURITY_GROUP), _asset("vm", T.EC2)]
        edges = [
            _edge(INTERNET, "sg", E.SECURITY_GROUP_RULE, cidr=INTERNET),
            _edge("vm", "sg", E.ATTACHED_TO),
        ]
        assert _exposed(assets, edges) == {"sg", "vm"}

    def test_exposed_member_does_not_expose_its_group_or_peers(self):
        assets = [_asset("sg", T.SECURITY_GROUP), _asset("vm", T.EC2), _asset("peer", T.EC2)]
        edges = [
            _edge(INTERNET, "vm", E.INTERNET_EXPOSED, cidr=INTERNET),
            _edge("vm", "sg", E.ATTACHED_TO),
            _edge("peer", "sg", E.ATTACHED_TO),
        ]
        assert _exposed(assets, edges) == {"vm"}

    def test_declared_protected_by_sg_reverses_attachment(self):
        """An unresolved group endpoint still counts as a filter by relationship."""
        assets = [_asset("vm", T.EC2)]
        edges = [
            _edge(INTERNET, "sg-0native", E.SECURITY_GROUP_RULE, cidr=INTERNET),
            _edge("vm", "sg-0native", E.ATTACHED_TO, relationship="PROTECTED_BY_SG"),
        ]
        assert _exposed(assets, edges) == {"sg-0native", "vm"}

    def test_interface_and_public_ip_forward_to_their_resource(self):
        assets = [
            _asset("pip", T.ELASTIC_IP),
            _asset("nic", T.NETWORK_INTERFACE),
            _asset("vm", T.VIRTUAL_MACHINE),
        ]
        edges = [
            _edge(INTERNET, "pip", E.INTERNET_EXPOSED, cidr=INTERNET),
            _edge("pip", "nic", E.ATTACHED_TO),
            _edge("nic", "vm", E.ATTACHED_TO),
        ]
        assert _exposed(assets, edges) == {"pip", "nic", "vm"}

    def test_other_attachments_are_not_traffic_paths(self):
        assets = [
            _asset("app", T.APP_SERVICE),
            _asset("subnet", T.SUBNET),
            _asset("db", T.AZURE_SQL),
        ]
        edges = [
            _edge(INTERNET, "app", E.INTERNET_EXPOSED, cidr=INTERNET),
            # VNet integration is outbound; it does not admit traffic into the subnet
            _edge("app", "subnet", E.ATTACHED_TO),
            _edge("subnet", "db", E.CONTAINS),
        ]
        assert _exposed(assets, edges) == {"app"}


class TestContainmentTraversal:
    """CONTAINS is followed only where it models network placement."""

    def test_nsg_on_subnet_exposes_subnet_contents(self):
        assets = [
            _asset("nsg", T.NSG),
            _asset("subnet", T.SUBNET),
            _asset("vm", T.VIRTUAL_MACHINE),
        ]
        edges = [
            _edge(INTERNET, "nsg", E.SECURITY_GROUP_RULE, cidr=INTERNET),
            _edge("subnet", "nsg", E.ATTACHED_TO),
            _edge("subnet", "vm", E.CONTAINS),
        ]
        assert _exposed(assets, edges) == {"nsg", "subnet", "vm"}

    def test_peered_vpc_exposes_its_subnets(self):
        assets = [
            _asset("vpc-a", T.VPC),
            _asset("vpc-b", T.VPC),
            _asset("subnet-b", T.SUBNET),
        ]
        edges = [
            _edge(INTERNET, "vpc-a", E.INTERNET_EXPOSED, cidr=INTERNET),
            _edge("vpc-a", "vpc-b", E.PEERING),
            _edge("vpc-b", "subnet-b", E.CONTAINS),
        ]
        assert _exposed(assets, edges) == {"vpc-a", "vpc-b", "subnet-b"}

    @pytest.mark.parametrize(
        "parent_type",
        [T.ORGANIZATION, T.ORG_UNIT, T.CLOUD_ACCOUNT, T.EKS_CLUSTER, T.K8S_NAMESPACE],
    )
    def test_hierarchy_containment_is_not_traversed(self, parent_type):
        assets = [_asset("parent", parent_type), _asset("child", T.K8S_WORKLOAD)]
        edges = [
            _edge(INTERNET, "parent", E.INTERNET_EXPOSED, cidr=INTERNET),
            _edge("parent", "child", E.CONTAINS),
        ]
        assert _exposed(assets, edges) == {"parent"}


class TestEntryPoints:
    """Only internet sources seed the walk."""

    def test_private_cidr_placeholder_is_not_an_entry_point(self):
        assets = [_asset("sg", T.SECURITY_GROUP), _asset("vm", T.EC2)]
        edges = [
            _edge("10.0.0.0/8", "sg", E.SECURITY_GROUP_RULE, cidr="10.0.0.0/8"),
            _edge("vm", "sg", E.ATTACHED_TO),
        ]
        assert _exposed(assets, edges) == set()

    def test_unresolved_reference_is_not_an_entry_point(self):
        assets = [_asset("api", T.API_GATEWAY), _asset("backend", T.EC2)]
        edges = [
            _edge("arn:aws:route53:::hostedzone/missing", "api", E.ROUTE),
            _edge("api", "backend", E.ROUTE),
        ]
        assert _exposed(assets, edges) == set()

    @pytest.mark.parametrize("source", ["Internet", "*", "Any", "::/0"])
    def test_internet_service_tags_seed_the_walk(self, source):
        assets = [_asset("nsg", T.NSG), _asset("vm", T.VIRTUAL_MACHINE)]
        edges = [
            _edge(source, "nsg", E.SECURITY_GROUP_RULE, cidr=source, direction="ingress"),
            _edge("vm", "nsg", E.ATTACHED_TO),
        ]
        assert _exposed(assets, edges) == {"nsg", "vm"}


class TestFindingIds:
    """Reachability finding ids are a hash of rule + asset."""

    def test_ids_are_stable_across_runs(self):
        first = _analyzer(_estate_assets(), _estate_edges()).generate_findings()
        second = _analyzer(_estate_assets(), _estate_edges()).generate_findings()
        assert [f.id for f in first] == [f.id for f in second]
        assert len({f.id for f in first}) == len(first)

    def test_ids_hash_rule_and_asset(self):
        assets = [
            _asset("sg", T.SECURITY_GROUP),
            _asset("db", T.RDS_INSTANCE),
            _asset("vm", T.EC2),
        ]
        edges = [
            _edge(INTERNET, "sg", E.SECURITY_GROUP_RULE, cidr=INTERNET, port_range="22"),
            _edge("db", "sg", E.ATTACHED_TO),
            _edge("vm", "sg", E.ATTACHED_TO),
        ]
        by_title = {f.title: f for f in _analyzer(assets, edges).generate_findings()}

        db = by_title["Internet-exposed RDS_INSTANCE: db"]
        assert db.severity == Severity.CRITICAL
        assert db.id == finding_id(RULE_SENSITIVE_EXPOSURE, "db")

        vm = by_title["Unexpected internet-exposed resource: vm"]
        assert vm.id == finding_id(RULE_UNEXPECTED_EXPOSURE, "vm")
        # The group itself is a rule container: only its open-port finding is reported
        assert "Unexpected internet-exposed resource: sg" not in by_title

        ssh = by_title["Security group allows SSH (port 22) from 0.0.0.0/0"]
        assert ssh.id == finding_id(f"{RULE_OPEN_PORT}:22", f"{INTERNET}->sg")

    def test_ids_are_uuids_and_differ_by_rule_and_asset(self):
        a = finding_id(RULE_SENSITIVE_EXPOSURE, "db")
        assert str(uuid.UUID(a)) == a
        assert a != finding_id(RULE_UNEXPECTED_EXPOSURE, "db")
        assert a != finding_id(RULE_SENSITIVE_EXPOSURE, "db-2")
