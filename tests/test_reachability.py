"""Tests for internet-exposure traversal and reachability findings."""

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
        assets = [_asset("sg", T.SECURITY_GROUP), _asset("db", T.RDS_INSTANCE)]
        edges = [
            _edge(INTERNET, "sg", E.SECURITY_GROUP_RULE, cidr=INTERNET, port_range="22"),
            _edge("db", "sg", E.ATTACHED_TO),
        ]
        by_title = {f.title: f for f in _analyzer(assets, edges).generate_findings()}

        db = by_title["Internet-exposed RDS_INSTANCE: db"]
        assert db.severity == Severity.CRITICAL
        assert db.id == finding_id(RULE_SENSITIVE_EXPOSURE, "db")

        sg = by_title["Unexpected internet-exposed resource: sg"]
        assert sg.id == finding_id(RULE_UNEXPECTED_EXPOSURE, "sg")

        ssh = by_title["Security group allows SSH (port 22) from 0.0.0.0/0"]
        assert ssh.id == finding_id(f"{RULE_OPEN_PORT}:22", f"{INTERNET}->sg")

    def test_ids_are_uuids_and_differ_by_rule_and_asset(self):
        a = finding_id(RULE_SENSITIVE_EXPOSURE, "db")
        assert str(uuid.UUID(a)) == a
        assert a != finding_id(RULE_UNEXPECTED_EXPOSURE, "db")
        assert a != finding_id(RULE_SENSITIVE_EXPOSURE, "db-2")
