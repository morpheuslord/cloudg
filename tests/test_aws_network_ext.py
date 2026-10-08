"""Tests for the extended network collectors (cloudg.inventory.aws_services.network_ext):
VPN / hybrid, Transit Gateway routing, PrivateLink, API Gateway depth,
deep CloudFront, Route 53 Resolver, Direct Connect, Global Accelerator,
ELBv2 listener rules, VPC Lattice and Network Manager."""

from __future__ import annotations

import asyncio
import io
import json
import zipfile
from typing import Any

import boto3
import pytest
from moto import mock_aws

from cloudg.coverage import ServiceStatus
from cloudg.inventory.aws_deep import AWSDeepInventoryCollector
from cloudg.inventory.aws_services.network_ext import (
    _bucket_from_domain,
    _policy_is_public,
    _unique,
)
from cloudg.inventory.aws_services._base import rel
from cloudg.inventory.linker import RelationshipLinker
from cloudg.schema.models import AssetType, EdgeType

ACCOUNT = "123456789012"
FOREIGN = "999999999999"


@pytest.fixture
def aws_credentials(monkeypatch):
    for key, value in {
        "AWS_ACCESS_KEY_ID": "testing",
        "AWS_SECRET_ACCESS_KEY": "testing",
        "AWS_SECURITY_TOKEN": "testing",
        "AWS_SESSION_TOKEN": "testing",
        "AWS_DEFAULT_REGION": "us-east-1",
    }.items():
        monkeypatch.setenv(key, value)


def _edge(edges, src, dst, edge_type=None):
    return [
        e
        for e in edges
        if e.source_id == src.id
        and e.target_id == dst.id
        and (edge_type is None or e.edge_type == edge_type)
    ]


def _lambda_zip() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("h.py", "def h(e, c):\n    return None\n")
    return buf.getvalue()


def _collector(session, services, **kwargs):
    return AWSDeepInventoryCollector(
        session=session,
        region="us-east-1",
        account_id=ACCOUNT,
        kubernetes=False,
        tagging_sweep=False,
        services=services,
        **kwargs,
    )


def _run(collector):
    assets = asyncio.run(collector.collect())
    linker = RelationshipLinker(assets)
    edges = linker.link()
    return assets, edges, linker


def _status(collector, name):
    return next(s.status for s in collector.coverage.services if s.service == name)


def _one(assets, asset_type, pred=lambda a: True):
    found = [a for a in assets if a.asset_type == asset_type and pred(a)]
    assert found, f"no {asset_type} asset matched"
    return found[0]


# ── Fake async client for services moto does not cover ─────────────────


class _FakePaginator:
    def __init__(self, client: "_FakeClient", op: str) -> None:
        self._client, self._op = client, op

    async def paginate(self, **kwargs: Any):
        yield self._client.respond(self._op, kwargs)


class _FakeClient:
    """Minimal aiobotocore client stand-in: each operation returns one page."""

    def __init__(self, responses: dict[str, Any]) -> None:
        self._responses = responses
        self.calls: list[tuple[str, dict]] = []

    def respond(self, op: str, kwargs: dict) -> dict:
        self.calls.append((op, kwargs))
        r = self._responses.get(op)
        if r is None:
            raise RuntimeError(f"unexpected call {op}")
        if isinstance(r, Exception):
            raise r
        return r(**kwargs) if callable(r) else r

    def get_paginator(self, op: str) -> _FakePaginator:
        return _FakePaginator(self, op)

    def __getattr__(self, op: str):
        async def call(**kwargs: Any) -> dict:
            return self.respond(op, kwargs)

        return call

    async def __aenter__(self) -> "_FakeClient":
        return self

    async def __aexit__(self, *exc: Any) -> None:
        return None


def _patch_clients(monkeypatch, collector, fakes: dict[str, _FakeClient]):
    real = collector._client

    def client(service, region=None):
        return fakes[service] if service in fakes else real(service, region)

    monkeypatch.setattr(collector, "_client", client)


# ── Pure helpers ────────────────────────────────────────────────────────


class TestHelpers:
    def test_bucket_from_origin_domains(self):
        assert _bucket_from_domain("assets.s3.amazonaws.com") == "assets"
        assert _bucket_from_domain("my.site.s3.eu-west-1.amazonaws.com") == "my.site"
        assert _bucket_from_domain("web.s3-website-us-east-1.amazonaws.com") == "web"
        assert _bucket_from_domain("web.s3-website.eu-central-1.amazonaws.com") == "web"
        assert _bucket_from_domain("app-123.us-east-1.elb.amazonaws.com") is None

    def test_policy_is_public(self):
        public = {
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": "*",
                    "Action": "vpc-lattice-svcs:Invoke",
                    "Resource": "*",
                }
            ]
        }
        scoped = {
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": "*",
                    "Action": "*",
                    "Resource": "*",
                    "Condition": {"StringEquals": {"aws:PrincipalOrgID": "o-1"}},
                }
            ]
        }
        assert _policy_is_public(json.dumps(public))
        assert not _policy_is_public(scoped)
        assert not _policy_is_public(None)

    def test_unique_relations(self):
        a = rel("x", EdgeType.ROUTE)
        out = _unique([a, None, rel("x", EdgeType.ROUTE), rel("x", EdgeType.ROUTE, reverse=True)])
        assert len(out) == 2

    def test_tasks_registered_with_families(self):
        collector = AWSDeepInventoryCollector(
            session=boto3.Session(region_name="us-east-1"),
            account_id=ACCOUNT,
            kubernetes=False,
            tagging_sweep=False,
        )
        tasks = collector._network_ext_tasks()
        assert tasks["vpn"][1:] == ("hybrid", False)
        assert tasks["global_accelerator"][1:] == ("network", True)
        assert tasks["network_manager"][1:] == ("hybrid", True)
        assert "cloudfront" not in tasks  # overridden, not re-registered
        # the deep CloudFront collector replaces the shallow base one
        assert collector._collect_cloudfront.__func__.__module__.endswith("network_ext")

    def test_global_tasks_skipped_outside_primary_region(self):
        collector = AWSDeepInventoryCollector(
            session=boto3.Session(region_name="us-east-1"),
            account_id=ACCOUNT,
            kubernetes=False,
            tagging_sweep=False,
            is_primary_region=False,
        )
        names = set(collector._service_tasks())
        assert {"vpn", "tgw_routing", "elb_rules"} <= names
        assert not names & {
            "global_accelerator",
            "network_manager",
            "direct_connect_gateways",
            "cloudfront",
        }

    def test_sections_raise_only_when_all_fail(self):
        collector = _collector(boto3.Session(region_name="us-east-1"), ["vpn"])

        async def ok():
            return []

        async def bad():
            raise RuntimeError("boom")

        assert asyncio.run(collector._nx_sections(ok, bad)) == []
        with pytest.raises(RuntimeError):
            asyncio.run(collector._nx_sections(bad, bad))


# ── moto-backed collectors ──────────────────────────────────────────────


@mock_aws
class TestHybridAndTransit:
    def _estate(self, session):
        ec2 = session.client("ec2")
        vpc = ec2.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]["VpcId"]
        subnet = ec2.create_subnet(
            VpcId=vpc, CidrBlock="10.0.1.0/24", AvailabilityZone="us-east-1a"
        )["Subnet"]["SubnetId"]
        cgw = ec2.create_customer_gateway(Type="ipsec.1", PublicIp="203.0.113.10", BgpAsn=65000)[
            "CustomerGateway"
        ]["CustomerGatewayId"]
        vgw = ec2.create_vpn_gateway(Type="ipsec.1")["VpnGateway"]["VpnGatewayId"]
        ec2.attach_vpn_gateway(VpcId=vpc, VpnGatewayId=vgw)
        vpn = ec2.create_vpn_connection(
            Type="ipsec.1",
            CustomerGatewayId=cgw,
            VpnGatewayId=vgw,
            Options={"StaticRoutesOnly": True},
        )["VpnConnection"]["VpnConnectionId"]
        eigw = ec2.create_egress_only_internet_gateway(VpcId=vpc)["EgressOnlyInternetGateway"][
            "EgressOnlyInternetGatewayId"
        ]
        pl = ec2.create_managed_prefix_list(
            PrefixListName="corp",
            MaxEntries=5,
            AddressFamily="IPv4",
            Entries=[{"Cidr": "10.10.0.0/16"}],
        )["PrefixList"]["PrefixListId"]
        tgw = ec2.create_transit_gateway()["TransitGateway"]["TransitGatewayId"]
        att = ec2.create_transit_gateway_vpc_attachment(
            TransitGatewayId=tgw, VpcId=vpc, SubnetIds=[subnet]
        )["TransitGatewayVpcAttachment"]["TransitGatewayAttachmentId"]
        rtb = ec2.create_transit_gateway_route_table(TransitGatewayId=tgw)[
            "TransitGatewayRouteTable"
        ]["TransitGatewayRouteTableId"]
        ec2.associate_transit_gateway_route_table(
            TransitGatewayAttachmentId=att, TransitGatewayRouteTableId=rtb
        )
        ec2.enable_transit_gateway_route_table_propagation(
            TransitGatewayAttachmentId=att, TransitGatewayRouteTableId=rtb
        )
        ec2.create_transit_gateway_route(
            DestinationCidrBlock="10.0.0.0/16",
            TransitGatewayRouteTableId=rtb,
            TransitGatewayAttachmentId=att,
        )
        peer = ec2.create_transit_gateway_peering_attachment(
            TransitGatewayId=tgw,
            PeerTransitGatewayId="tgw-0123456789abcdef0",
            PeerAccountId=FOREIGN,
            PeerRegion="eu-west-1",
        )["TransitGatewayPeeringAttachment"]["TransitGatewayAttachmentId"]
        nlb = session.client("elbv2").create_load_balancer(
            Name="svc", Subnets=[subnet], Type="network", Scheme="internal"
        )["LoadBalancers"][0]["LoadBalancerArn"]
        svc = ec2.create_vpc_endpoint_service_configuration(
            NetworkLoadBalancerArns=[nlb], AcceptanceRequired=False
        )["ServiceConfiguration"]["ServiceId"]
        ec2.modify_vpc_endpoint_service_permissions(
            ServiceId=svc, AddAllowedPrincipals=[f"arn:aws:iam::{FOREIGN}:root"]
        )
        return locals()

    def test_vpn_tgw_prefix_lists_and_endpoint_services(self, aws_credentials):
        session = boto3.Session(region_name="us-east-1")
        ids = self._estate(session)
        collector = _collector(session, ["network", "hybrid"])
        assets, edges, linker = _run(collector)
        for task in ("vpn", "egress_only_igw", "prefix_lists", "tgw_routing", "endpoint_services"):
            assert _status(collector, task) == ServiceStatus.SUCCESS, task

        by_alias = {}
        for a in assets:
            for alias in a.metadata.get("aliases", []):
                by_alias.setdefault(alias, a)
        vpc = _one(assets, AssetType.VPC, lambda a: a.metadata.get("vpc_id") == ids["vpc"])
        vpn, cgw, vgw = by_alias[ids["vpn"]], by_alias[ids["cgw"]], by_alias[ids["vgw"]]
        assert vpn.asset_type == AssetType.VPN_CONNECTION
        assert (
            cgw.asset_type == AssetType.CUSTOMER_GATEWAY
            and cgw.metadata["ip_address"] == "203.0.113.10"
        )
        assert vpn.metadata["vpn_gateway_id"] == ids["vgw"]
        assert "CustomerGatewayConfiguration" not in json.dumps(vpn.model_dump(mode="json"))
        assert _edge(edges, vpn, cgw, EdgeType.ROUTE)
        assert _edge(edges, vpn, vgw, EdgeType.ATTACHED_TO)
        assert _edge(edges, vgw, vpc, EdgeType.ATTACHED_TO)

        eigw = by_alias[ids["eigw"]]
        assert eigw.asset_type == AssetType.INTERNET_GATEWAY and eigw.metadata["egress_only"]
        assert _edge(edges, eigw, vpc, EdgeType.ATTACHED_TO)

        pl = by_alias[ids["pl"]]
        assert pl.asset_type == AssetType.PREFIX_LIST and pl.metadata["entry_count"] == 1
        assert not [
            a
            for a in assets
            if a.asset_type == AssetType.PREFIX_LIST and a.metadata.get("owner_id") == "AWS"
        ]

        tgw = _one(assets, AssetType.TRANSIT_GATEWAY)
        rtb = by_alias[ids["rtb"]]
        assert rtb.asset_type == AssetType.ROUTE_TABLE
        assert _edge(edges, tgw, rtb, EdgeType.CONTAINS)
        route = _edge(edges, rtb, vpc, EdgeType.ROUTE)
        assert route and route[0].relationship == "TRANSIT_ROUTED"
        assert route[0].properties["associated"] and route[0].properties["propagated"]

        peering = by_alias[ids["peer"]]
        assert peering.asset_type == AssetType.PEERING_CONNECTION
        assert peering.metadata["cross_account"] and peering.metadata["cross_region"]
        assert _edge(edges, tgw, peering, EdgeType.PEERING)
        foreign = next(a for a in linker.external_assets if a.account_id == FOREIGN)
        assert _edge(edges, peering, foreign, EdgeType.PEERING)

        svc = by_alias[ids["svc"]]
        nlb = next(a for a in assets if a.arn == ids["nlb"])
        assert svc.asset_type == AssetType.ENDPOINT_SERVICE
        assert _edge(edges, svc, nlb, EdgeType.LOAD_BALANCER_TARGET)
        assert _edge(edges, foreign, svc, EdgeType.GRANTS_ACCESS)
        assert not svc.is_internet_exposed


@mock_aws
class TestApiGatewayDepth:
    def test_authorizers_vpc_links_and_custom_domains(self, aws_credentials):
        session = boto3.Session(region_name="us-east-1")
        ec2 = session.client("ec2")
        vpc = ec2.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]["VpcId"]
        subnet = ec2.create_subnet(VpcId=vpc, CidrBlock="10.0.1.0/24")["Subnet"]["SubnetId"]
        sg = ec2.create_security_group(GroupName="link", Description="d", VpcId=vpc)["GroupId"]
        nlb = session.client("elbv2").create_load_balancer(
            Name="private", Subnets=[subnet], Type="network", Scheme="internal"
        )["LoadBalancers"][0]["LoadBalancerArn"]
        role = session.client("iam").create_role(
            RoleName="auth",
            AssumeRolePolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": []}),
        )["Role"]["Arn"]
        fn = session.client("lambda").create_function(
            FunctionName="authz",
            Runtime="python3.12",
            Role=role,
            Handler="h.h",
            Code={"ZipFile": _lambda_zip()},
        )["FunctionArn"]
        cert = session.client("acm").request_certificate(DomainName="api.example.com")[
            "CertificateArn"
        ]

        rest = session.client("apigateway")
        api = rest.create_rest_api(name="orders", endpointConfiguration={"types": ["REGIONAL"]})[
            "id"
        ]
        rest.create_authorizer(
            restApiId=api,
            name="token",
            type="TOKEN",
            identitySource="method.request.header.Authorization",
            authorizerUri=f"arn:aws:apigateway:us-east-1:lambda:path/2015-03-31/functions/{fn}/invocations",
        )
        link = rest.create_vpc_link(name="to-nlb", targetArns=[nlb])["id"]
        domain = rest.create_domain_name(
            domainName="api.example.com",
            regionalCertificateArn=cert,
            endpointConfiguration={"types": ["REGIONAL"]},
        )
        root = rest.get_resources(restApiId=api)["items"][0]["id"]
        rest.put_method(restApiId=api, resourceId=root, httpMethod="GET", authorizationType="NONE")
        rest.put_integration(restApiId=api, resourceId=root, httpMethod="GET", type="MOCK")
        rest.create_deployment(restApiId=api, stageName="prod")
        rest.create_base_path_mapping(
            domainName="api.example.com", restApiId=api, basePath="v1", stage="prod"
        )

        v2 = session.client("apigatewayv2")
        http_api = v2.create_api(Name="web", ProtocolType="HTTP")["ApiId"]
        v2_link = v2.create_vpc_link(Name="v2", SubnetIds=[subnet], SecurityGroupIds=[sg])[
            "VpcLinkId"
        ]
        v2.create_domain_name(
            DomainName="web.example.com",
            DomainNameConfigurations=[{"CertificateArn": cert, "EndpointType": "REGIONAL"}],
        )
        v2.create_api_mapping(ApiId=http_api, DomainName="web.example.com", Stage="$default")

        r53 = session.client("route53")
        zone = r53.create_hosted_zone(Name="example.com", CallerReference="1")["HostedZone"]["Id"]
        r53.change_resource_record_sets(
            HostedZoneId=zone,
            ChangeBatch={
                "Changes": [
                    {
                        "Action": "CREATE",
                        "ResourceRecordSet": {
                            "Name": "api.example.com",
                            "Type": "A",
                            "AliasTarget": {
                                "HostedZoneId": "Z1UJRXOUMOOFQ8",
                                "DNSName": domain["regionalDomainName"],
                                "EvaluateTargetHealth": False,
                            },
                        },
                    }
                ]
            },
        )

        collector = _collector(
            session, ["serverless", "route53", "acm", "subnets", "security_groups", "elbv2"]
        )
        assets, edges, _ = _run(collector)
        for task in ("apigateway_authorizers", "apigateway_vpc_links", "apigateway_domains"):
            assert _status(collector, task) == ServiceStatus.SUCCESS, task

        by_arn = {a.arn: a for a in assets}
        rest_api = by_arn[f"arn:aws:apigateway:us-east-1::/restapis/{api}"]
        http = by_arn[f"arn:aws:apigateway:us-east-1::/apis/{http_api}"]
        function = by_arn[fn]
        certificate = by_arn[cert]

        token = next(
            a
            for a in assets
            if a.metadata.get("resource_kind") == "apigateway_authorizer"
            and a.metadata["api_id"] == api
        )
        assert _edge(edges, rest_api, token, EdgeType.REFERENCES)
        assert _edge(edges, token, function, EdgeType.INVOKES)
        # HTTP API authorizers: moto lacks apigatewayv2 GetAuthorizers (see the fake-client test)

        rest_link = by_arn[f"arn:aws:apigateway:us-east-1::/vpclinks/{link}"]
        assert rest_link.asset_type == AssetType.VPC_LINK
        assert _edge(edges, rest_link, by_arn[nlb], EdgeType.LOAD_BALANCER_TARGET)
        http_link = by_arn[f"arn:aws:apigateway:us-east-1::/vpclinks/{v2_link}"]
        subnet_asset = next(
            a
            for a in assets
            if a.asset_type == AssetType.SUBNET and a.metadata.get("subnet_id") == subnet
        )
        sg_asset = next(
            a
            for a in assets
            if a.asset_type == AssetType.SECURITY_GROUP and a.metadata.get("group_id") == sg
        )
        assert _edge(edges, subnet_asset, http_link, EdgeType.CONTAINS)
        assert _edge(edges, http_link, sg_asset, EdgeType.ATTACHED_TO)

        api_domain = _one(assets, AssetType.CUSTOM_DOMAIN, lambda a: a.name == "api.example.com")
        web_domain = _one(assets, AssetType.CUSTOM_DOMAIN, lambda a: a.name == "web.example.com")
        assert api_domain.is_internet_exposed
        assert _edge(edges, api_domain, rest_api, EdgeType.ROUTE)
        assert _edge(edges, api_domain, certificate, EdgeType.REFERENCES)
        assert _edge(edges, web_domain, http, EdgeType.ROUTE)
        record = _one(assets, AssetType.DNS_RECORD, lambda a: a.name == "api.example.com")
        assert _edge(edges, record, api_domain, EdgeType.ROUTE)  # alias -> regional domain name


@mock_aws
class TestEdgeAndResolver:
    def test_cloudfront_listener_rules_and_resolver(self, aws_credentials):
        session = boto3.Session(region_name="us-east-1")
        ec2 = session.client("ec2")
        vpc = ec2.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]["VpcId"]
        s1 = ec2.create_subnet(VpcId=vpc, CidrBlock="10.0.1.0/24", AvailabilityZone="us-east-1a")[
            "Subnet"
        ]["SubnetId"]
        s2 = ec2.create_subnet(VpcId=vpc, CidrBlock="10.0.2.0/24", AvailabilityZone="us-east-1b")[
            "Subnet"
        ]["SubnetId"]
        sg = ec2.create_security_group(GroupName="dns", Description="d", VpcId=vpc)["GroupId"]
        s3 = session.client("s3")
        s3.create_bucket(Bucket="site-assets")
        s3.create_bucket(Bucket="cf-logs")
        cert = session.client("acm").request_certificate(DomainName="www.example.com")[
            "CertificateArn"
        ]

        elb = session.client("elbv2")
        alb = elb.create_load_balancer(
            Name="web", Subnets=[s1, s2], SecurityGroups=[sg], Scheme="internet-facing"
        )["LoadBalancers"][0]
        tg = elb.create_target_group(Name="api", Protocol="HTTP", Port=80, VpcId=vpc)[
            "TargetGroups"
        ][0]["TargetGroupArn"]
        tg2 = elb.create_target_group(Name="static", Protocol="HTTP", Port=80, VpcId=vpc)[
            "TargetGroups"
        ][0]["TargetGroupArn"]
        listener = elb.create_listener(
            LoadBalancerArn=alb["LoadBalancerArn"],
            Protocol="HTTP",
            Port=80,
            DefaultActions=[{"Type": "forward", "TargetGroupArn": tg2}],
        )["Listeners"][0]["ListenerArn"]
        elb.create_rule(
            ListenerArn=listener,
            Priority=10,
            Conditions=[{"Field": "path-pattern", "Values": ["/api/*"]}],
            Actions=[{"Type": "forward", "TargetGroupArn": tg}],
        )

        cf = session.client("cloudfront")
        dist = cf.create_distribution(
            DistributionConfig={
                "CallerReference": "1",
                "Aliases": {"Quantity": 1, "Items": ["www.example.com"]},
                "Origins": {
                    "Quantity": 2,
                    "Items": [
                        {
                            "Id": "s3",
                            "DomainName": "site-assets.s3.us-east-1.amazonaws.com",
                            "S3OriginConfig": {"OriginAccessIdentity": ""},
                        },
                        {
                            "Id": "alb",
                            "DomainName": alb["DNSName"],
                            "CustomOriginConfig": {
                                "HTTPPort": 80,
                                "HTTPSPort": 443,
                                "OriginProtocolPolicy": "https-only",
                            },
                            "CustomHeaders": {
                                "Quantity": 1,
                                "Items": [
                                    {"HeaderName": "X-Origin-Verify", "HeaderValue": "s3cr3t"}
                                ],
                            },
                        },
                    ],
                },
                "DefaultCacheBehavior": {
                    "TargetOriginId": "s3",
                    "ViewerProtocolPolicy": "redirect-to-https",
                    "MinTTL": 0,
                    "ForwardedValues": {"QueryString": False, "Cookies": {"Forward": "none"}},
                },
                "Comment": "site",
                "Enabled": True,
                "Logging": {
                    "Enabled": True,
                    "IncludeCookies": False,
                    "Bucket": "cf-logs.s3.amazonaws.com",
                    "Prefix": "cf/",
                },
                "ViewerCertificate": {
                    "ACMCertificateArn": cert,
                    "SSLSupportMethod": "sni-only",
                    "MinimumProtocolVersion": "TLSv1.2_2021",
                },
                "WebACLId": "arn:aws:wafv2:us-east-1:123456789012:global/webacl/edge/abc",
            }
        )["Distribution"]

        r53 = session.client("route53")
        zone = r53.create_hosted_zone(Name="example.com", CallerReference="z")["HostedZone"]["Id"]
        r53.change_resource_record_sets(
            HostedZoneId=zone,
            ChangeBatch={
                "Changes": [
                    {
                        "Action": "CREATE",
                        "ResourceRecordSet": {
                            "Name": "www.example.com",
                            "Type": "A",
                            "AliasTarget": {
                                "HostedZoneId": "Z2FDTNDATAQYW2",
                                "DNSName": dist["DomainName"],
                                "EvaluateTargetHealth": False,
                            },
                        },
                    }
                ]
            },
        )

        resolver = session.client("route53resolver")
        endpoint = resolver.create_resolver_endpoint(
            CreatorRequestId="e",
            Name="outbound",
            SecurityGroupIds=[sg],
            Direction="OUTBOUND",
            IpAddresses=[{"SubnetId": s1}, {"SubnetId": s2}],
        )["ResolverEndpoint"]
        rule = resolver.create_resolver_rule(
            CreatorRequestId="r",
            Name="corp",
            RuleType="FORWARD",
            DomainName="corp.example.",
            TargetIps=[{"Ip": "192.168.0.2", "Port": 53}],
            ResolverEndpointId=endpoint["Id"],
        )["ResolverRule"]
        resolver.associate_resolver_rule(ResolverRuleId=rule["Id"], VPCId=vpc)
        logs = session.client("logs")
        logs.create_log_group(logGroupName="dns-queries")
        dest = f"arn:aws:logs:us-east-1:{ACCOUNT}:log-group:dns-queries"
        qlc = resolver.create_resolver_query_log_config(
            Name="ql", DestinationArn=dest, CreatorRequestId="q"
        )["ResolverQueryLogConfig"]
        resolver.associate_resolver_query_log_config(
            ResolverQueryLogConfigId=qlc["Id"], ResourceId=vpc
        )

        collector = _collector(
            session,
            [
                "cloudfront",
                "s3",
                "elbv2",
                "elb_rules",
                "route53",
                "route53_resolver",
                "acm",
                "vpc",
                "subnets",
                "security_groups",
                "log_groups",
            ],
        )
        assets, edges, _ = _run(collector)
        for task in ("cloudfront", "elb_rules", "route53_resolver"):
            assert _status(collector, task) == ServiceStatus.SUCCESS, task
        by_arn = {a.arn: a for a in assets}

        # CloudFront
        cf_asset = by_arn[dist["ARN"]]
        assert cf_asset.asset_type == AssetType.CLOUDFRONT and cf_asset.is_internet_exposed
        for key in ("status", "domain_name", "origins", "web_acl_id", "viewer_protocol_policy"):
            assert key in cf_asset.metadata, key
        assert cf_asset.metadata["viewer_protocol_policy"] == "redirect-to-https"
        assert {"www.example.com"} <= set(cf_asset.metadata["aliases"])
        assert "s3cr3t" not in json.dumps(cf_asset.model_dump(mode="json"))
        bucket, logs_bucket, alb_asset = (
            by_arn["arn:aws:s3:::site-assets"],
            by_arn["arn:aws:s3:::cf-logs"],
            by_arn[alb["LoadBalancerArn"]],
        )
        assert _edge(edges, cf_asset, bucket, EdgeType.ROUTE)
        assert _edge(edges, cf_asset, alb_asset, EdgeType.ROUTE)
        assert _edge(edges, cf_asset, logs_bucket, EdgeType.LOGS_TO)
        assert _edge(edges, cf_asset, by_arn[cert], EdgeType.REFERENCES)
        record = _one(assets, AssetType.DNS_RECORD, lambda a: a.name == "www.example.com")
        assert _edge(edges, record, cf_asset, EdgeType.ROUTE)

        # Listener + rules
        lst = by_arn[listener]
        assert lst.metadata["resource_kind"] == "lb_listener" and lst.is_internet_exposed
        assert lst.metadata["rules"][0]["paths"] == ["/api/*"]
        assert _edge(edges, alb_asset, lst, EdgeType.CONTAINS)
        assert _edge(edges, lst, by_arn[tg], EdgeType.ROUTE)
        assert _edge(edges, lst, by_arn[tg2], EdgeType.ROUTE)

        # Route 53 Resolver
        vpc_asset = _one(assets, AssetType.VPC, lambda a: a.metadata.get("vpc_id") == vpc)
        ep = by_arn[endpoint["Arn"]]
        assert ep.asset_type == AssetType.DNS_RESOLVER and ep.metadata["direction"] == "OUTBOUND"
        sg_asset = _one(
            assets, AssetType.SECURITY_GROUP, lambda a: a.metadata.get("group_id") == sg
        )
        subnet_asset = _one(assets, AssetType.SUBNET, lambda a: a.metadata.get("subnet_id") == s1)
        assert _edge(edges, ep, sg_asset, EdgeType.ATTACHED_TO)
        assert _edge(edges, subnet_asset, ep, EdgeType.CONTAINS)
        rule_asset = by_arn[rule["Arn"]]
        assert rule_asset.metadata["target_ips"] == ["192.168.0.2:53"]
        assert _edge(edges, rule_asset, ep, EdgeType.ROUTE)
        assert _edge(edges, rule_asset, vpc_asset, EdgeType.ATTACHED_TO)
        ql = by_arn[qlc["Arn"]]
        log_group = _one(assets, AssetType.LOG_GROUP, lambda a: a.name == "dns-queries")
        assert _edge(edges, ql, log_group, EdgeType.LOGS_TO)
        assert _edge(edges, vpc_asset, ql, EdgeType.LOGS_TO)


@mock_aws
class TestLatticeAndNetworkManager:
    def test_vpc_lattice(self, aws_credentials):
        session = boto3.Session(region_name="us-east-1")
        ec2 = session.client("ec2")
        vpc = ec2.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]["VpcId"]
        inst = ec2.run_instances(ImageId="ami-12c6146b", MinCount=1, MaxCount=1)["Instances"][0][
            "InstanceId"
        ]
        vl = session.client("vpc-lattice")
        sn = vl.create_service_network(name="mesh", authType="AWS_IAM")
        svc = vl.create_service(name="orders", authType="AWS_IAM")
        vl.create_service_network_vpc_association(
            serviceNetworkIdentifier=sn["id"], vpcIdentifier=vpc
        )
        vl.create_service_network_service_association(
            serviceNetworkIdentifier=sn["id"], serviceIdentifier=svc["id"]
        )
        vl.put_auth_policy(
            resourceIdentifier=svc["arn"],
            policy=json.dumps(
                {
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Principal": "*",
                            "Action": "vpc-lattice-svcs:Invoke",
                            "Resource": "*",
                        }
                    ]
                }
            ),
        )

        collector = _collector(session, ["vpc_lattice", "vpc", "ec2"])
        assets, edges, _ = _run(collector)
        assert _status(collector, "vpc_lattice") == ServiceStatus.SUCCESS
        by_arn = {a.arn: a for a in assets}
        network, service = by_arn[sn["arn"]], by_arn[svc["arn"]]
        assert network.asset_type == AssetType.SERVICE_NETWORK
        assert service.asset_type == AssetType.ENDPOINT_SERVICE and service.is_internet_exposed
        vpc_asset = _one(assets, AssetType.VPC, lambda a: a.metadata.get("vpc_id") == vpc)
        assert _edge(edges, network, vpc_asset, EdgeType.ATTACHED_TO)
        assert _edge(edges, network, service, EdgeType.CONTAINS)
        assert inst  # instance created for target resolution in the fake test below

    def test_network_manager(self, aws_credentials):
        session = boto3.Session(region_name="us-east-1")
        nm = session.client("networkmanager", region_name="us-west-2")
        gn = nm.create_global_network(Description="wan")["GlobalNetwork"]
        core = nm.create_core_network(GlobalNetworkId=gn["GlobalNetworkId"], Description="core")[
            "CoreNetwork"
        ]
        collector = _collector(session, ["network_manager"])
        assets, edges, _ = _run(collector)
        assert _status(collector, "network_manager") == ServiceStatus.SUCCESS
        by_arn = {a.arn: a for a in assets}
        g, c = by_arn[gn["GlobalNetworkArn"]], by_arn[core["CoreNetworkArn"]]
        assert g.region == "global" and c.metadata["resource_kind"] == "core_network"
        assert _edge(edges, g, c, EdgeType.CONTAINS)


# ── Fake clients: Direct Connect, Global Accelerator, gaps in moto ─────


@mock_aws
class TestFakeClientCollectors:
    def test_direct_connect_and_global_accelerator(self, aws_credentials, monkeypatch):
        session = boto3.Session(region_name="us-east-1")
        ec2 = session.client("ec2")
        vpc = ec2.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]["VpcId"]
        s1 = ec2.create_subnet(VpcId=vpc, CidrBlock="10.0.1.0/24", AvailabilityZone="us-east-1a")[
            "Subnet"
        ]["SubnetId"]
        s2 = ec2.create_subnet(VpcId=vpc, CidrBlock="10.0.2.0/24", AvailabilityZone="us-east-1b")[
            "Subnet"
        ]["SubnetId"]
        vgw = ec2.create_vpn_gateway(Type="ipsec.1")["VpnGateway"]["VpnGatewayId"]
        tgw = ec2.create_transit_gateway()["TransitGateway"]["TransitGatewayId"]
        alb = session.client("elbv2").create_load_balancer(Name="edge", Subnets=[s1, s2])[
            "LoadBalancers"
        ][0]["LoadBalancerArn"]

        dxcon, dxlag, dxvif, dxgw = (
            "dxcon-ffabc123",
            "dxlag-ffdef456",
            "dxvif-ffggg789",
            "5f3c7b2e-0000-4000-8000-000000000001",
        )
        dx = _FakeClient(
            {
                "describe_connections": {
                    "connections": [
                        {
                            "connectionId": dxcon,
                            "connectionName": "dc1",
                            "connectionState": "available",
                            "region": "us-east-1",
                            "ownerAccount": ACCOUNT,
                            "location": "EqDC2",
                            "bandwidth": "10Gbps",
                            "lagId": dxlag,
                            "macSecKeys": [{"ckn": "secret-ckn"}],
                        }
                    ]
                },
                "describe_lags": {
                    "lags": [
                        {
                            "lagId": dxlag,
                            "lagName": "lag",
                            "lagState": "available",
                            "region": "us-east-1",
                            "ownerAccount": ACCOUNT,
                            "connections": [{"connectionId": dxcon}],
                        }
                    ]
                },
                "describe_virtual_interfaces": {
                    "virtualInterfaces": [
                        {
                            "virtualInterfaceId": dxvif,
                            "virtualInterfaceName": "private",
                            "virtualInterfaceType": "private",
                            "virtualInterfaceState": "available",
                            "connectionId": dxcon,
                            "region": "us-east-1",
                            "ownerAccount": ACCOUNT,
                            "directConnectGatewayId": dxgw,
                            "authKey": "bgp-secret",
                            "customerRouterConfig": "router-secret",
                            "bgpPeers": [
                                {
                                    "asn": 65000,
                                    "authKey": "bgp-secret",
                                    "bgpPeerState": "available",
                                    "bgpStatus": "up",
                                }
                            ],
                        }
                    ]
                },
                "describe_direct_connect_gateways": {
                    "directConnectGateways": [
                        {
                            "directConnectGatewayId": dxgw,
                            "directConnectGatewayName": "dxgw",
                            "ownerAccount": ACCOUNT,
                            "directConnectGatewayState": "available",
                            "amazonSideAsn": 64512,
                        }
                    ]
                },
                "describe_direct_connect_gateway_associations": {
                    "directConnectGatewayAssociations": [
                        {
                            "directConnectGatewayId": dxgw,
                            "associationState": "associated",
                            "associatedGateway": {
                                "id": vgw,
                                "type": "virtualPrivateGateway",
                                "ownerAccount": ACCOUNT,
                                "region": "us-east-1",
                            },
                        },
                        {
                            "directConnectGatewayId": dxgw,
                            "associationState": "associated",
                            "associatedGateway": {
                                "id": tgw,
                                "type": "transitGateway",
                                "ownerAccount": ACCOUNT,
                                "region": "us-east-1",
                            },
                        },
                        {
                            "directConnectGatewayId": dxgw,
                            "associationState": "associated",
                            "associatedGateway": {
                                "id": "vgw-0aaaabbbbccccdddd",
                                "type": "virtualPrivateGateway",
                                "ownerAccount": FOREIGN,
                                "region": "eu-west-1",
                            },
                        },
                    ]
                },
                "describe_direct_connect_gateway_attachments": {
                    "directConnectGatewayAttachments": [
                        {
                            "directConnectGatewayId": dxgw,
                            "virtualInterfaceId": dxvif,
                            "virtualInterfaceRegion": "us-east-1",
                            "virtualInterfaceOwnerAccount": ACCOUNT,
                            "attachmentState": "attached",
                        }
                    ]
                },
            }
        )
        accel_arn = f"arn:aws:globalaccelerator::{ACCOUNT}:accelerator/abcd"
        listener_arn = f"{accel_arn}/listener/0123"
        ga = _FakeClient(
            {
                "list_accelerators": {
                    "Accelerators": [
                        {
                            "AcceleratorArn": accel_arn,
                            "Name": "global",
                            "Enabled": True,
                            "Status": "DEPLOYED",
                            "DnsName": "a1234.awsglobalaccelerator.com",
                            "IpSets": [{"IpAddresses": ["75.2.0.1", "99.83.0.1"]}],
                        }
                    ]
                },
                "list_listeners": {
                    "Listeners": [
                        {
                            "ListenerArn": listener_arn,
                            "Protocol": "TCP",
                            "PortRanges": [{"FromPort": 443, "ToPort": 443}],
                        }
                    ]
                },
                "list_endpoint_groups": {
                    "EndpointGroups": [
                        {
                            "EndpointGroupArn": f"{listener_arn}/endpoint-group/1",
                            "EndpointGroupRegion": "us-east-1",
                            "EndpointDescriptions": [
                                {"EndpointId": alb, "Weight": 128, "HealthState": "HEALTHY"}
                            ],
                        }
                    ]
                },
                "list_custom_routing_accelerators": RuntimeError("AccessDenied"),
            }
        )
        collector = _collector(
            session,
            [
                "direct_connect",
                "direct_connect_gateways",
                "global_accelerator",
                "vpn",
                "transit_gateways",
                "elbv2",
            ],
        )
        _patch_clients(monkeypatch, collector, {"directconnect": dx, "globalaccelerator": ga})
        assets, edges, linker = _run(collector)
        for task in ("direct_connect", "direct_connect_gateways", "global_accelerator"):
            assert _status(collector, task) == ServiceStatus.SUCCESS, task

        dumped = json.dumps([a.model_dump(mode="json") for a in assets])
        for secret in ("bgp-secret", "router-secret", "secret-ckn"):
            assert secret not in dumped

        by_kind = {
            a.metadata.get("resource_kind"): a
            for a in assets
            if a.asset_type == AssetType.DIRECT_CONNECT
        }
        con, lag, vif, gw = (
            by_kind["dx_connection"],
            by_kind["dx_lag"],
            by_kind["dx_virtual_interface"],
            by_kind["dx_gateway"],
        )
        assert gw.region == "global"
        assert _edge(edges, lag, con, EdgeType.CONTAINS)
        assert _edge(edges, vif, con, EdgeType.ATTACHED_TO)
        assert _edge(edges, vif, gw, EdgeType.ROUTE)
        vgw_asset = _one(assets, AssetType.VPN_GATEWAY)
        tgw_asset = _one(assets, AssetType.TRANSIT_GATEWAY)
        assert _edge(edges, gw, vgw_asset, EdgeType.ROUTE)
        assert _edge(edges, gw, tgw_asset, EdgeType.ROUTE)
        foreign = next(a for a in linker.external_assets if a.account_id == FOREIGN)
        assert _edge(edges, gw, foreign, EdgeType.ROUTE)

        accel = _one(assets, AssetType.GLOBAL_ACCELERATOR)
        assert accel.is_internet_exposed and accel.region == "global"
        assert accel.metadata["ip_addresses"] == ["75.2.0.1", "99.83.0.1"]
        assert {"a1234.awsglobalaccelerator.com"} <= set(accel.metadata["aliases"])
        alb_asset = next(a for a in assets if a.arn == alb)
        assert _edge(edges, accel, alb_asset, EdgeType.LOAD_BALANCER_TARGET)
        assert ("list_custom_routing_accelerators", {}) in ga.calls

    def test_dns_firewall_and_endpoint_connections(self, aws_credentials, monkeypatch):
        session = boto3.Session(region_name="us-east-1")
        ec2 = session.client("ec2")
        vpc = ec2.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]["VpcId"]
        fw_group = "rslvr-frg-0123456789abcdef"
        r53r = _FakeClient(
            {
                "list_resolver_endpoints": {"ResolverEndpoints": []},
                "list_resolver_rules": {
                    "ResolverRules": [
                        {
                            "Id": "rslvr-autodefined-rr-internet-resolver",
                            "RuleType": "RECURSIVE",
                            "DomainName": ".",
                        },
                        {
                            "Id": "rslvr-rr-shared",
                            "Arn": f"arn:aws:route53resolver:us-east-1:{FOREIGN}:resolver-rule/rslvr-rr-shared",
                            "RuleType": "FORWARD",
                            "DomainName": "onprem.corp.",
                            "OwnerId": FOREIGN,
                            "ShareStatus": "SHARED_WITH_ME",
                            "TargetIps": [{"Ip": "10.1.1.1", "Port": 53}],
                        },
                    ]
                },
                "list_resolver_rule_associations": {
                    "ResolverRuleAssociations": [
                        {"ResolverRuleId": "rslvr-rr-shared", "VPCId": vpc, "Status": "COMPLETE"}
                    ]
                },
                "list_firewall_rule_groups": {
                    "FirewallRuleGroups": [
                        {
                            "Id": fw_group,
                            "Arn": f"arn:aws:route53resolver:us-east-1:{ACCOUNT}:firewall-rule-group/{fw_group}",
                            "Name": "block-bad",
                            "OwnerId": ACCOUNT,
                        }
                    ]
                },
                "list_firewall_rule_group_associations": {
                    "FirewallRuleGroupAssociations": [
                        {
                            "FirewallRuleGroupId": fw_group,
                            "VpcId": vpc,
                            "Priority": 101,
                            "Status": "COMPLETE",
                        }
                    ]
                },
                "list_resolver_query_log_configs": RuntimeError("AccessDenied"),
            }
        )
        collector = _collector(session, ["route53_resolver", "vpc"])
        _patch_clients(monkeypatch, collector, {"route53resolver": r53r})
        assets, edges, _ = _run(collector)
        assert (
            _status(collector, "route53_resolver") == ServiceStatus.SUCCESS
        )  # partial failure tolerated
        vpc_asset = _one(assets, AssetType.VPC, lambda a: a.metadata.get("vpc_id") == vpc)
        rules = [a for a in assets if a.metadata.get("resource_kind") == "resolver_rule"]
        assert len(rules) == 1 and rules[0].metadata["shared_from_other_account"]
        assert _edge(edges, rules[0], vpc_asset, EdgeType.ATTACHED_TO)
        fw = _one(assets, AssetType.NETWORK_FIREWALL)
        assert fw.name == "block-bad"
        assert _edge(edges, fw, vpc_asset, EdgeType.PROTECTS)

    def test_endpoint_service_consumers(self, aws_credentials, monkeypatch):
        session = boto3.Session(region_name="us-east-1")
        svc = "vpce-svc-0123456789abcdef0"
        own_ep, foreign_ep = "vpce-0aaaaaaaaaaaaaaa1", "vpce-0bbbbbbbbbbbbbbb2"
        ec2 = _FakeClient(
            {
                "describe_vpc_endpoint_service_configurations": {
                    "ServiceConfigurations": [
                        {
                            "ServiceId": svc,
                            "ServiceName": f"com.amazonaws.vpce.us-east-1.{svc}",
                            "AcceptanceRequired": False,
                            "NetworkLoadBalancerArns": [],
                            "PrivateDnsName": "svc.example.com",
                        }
                    ]
                },
                "describe_vpc_endpoint_connections": {
                    "VpcEndpointConnections": [
                        {
                            "ServiceId": svc,
                            "VpcEndpointId": own_ep,
                            "VpcEndpointOwner": ACCOUNT,
                            "VpcEndpointState": "available",
                        },
                        {
                            "ServiceId": svc,
                            "VpcEndpointId": foreign_ep,
                            "VpcEndpointOwner": FOREIGN,
                            "VpcEndpointState": "available",
                        },
                    ]
                },
                "describe_vpc_endpoint_service_permissions": {
                    "AllowedPrincipals": [{"Principal": "*"}]
                },
            }
        )
        collector = _collector(session, ["endpoint_services"])
        _patch_clients(monkeypatch, collector, {"ec2": ec2})
        assets, edges, linker = _run(collector)
        service = _one(assets, AssetType.ENDPOINT_SERVICE)
        assert service.is_internet_exposed and service.metadata["allows_any_principal"]
        assert service.metadata["consumer_count"] == 2
        own_ep_arn = f"arn:aws:ec2:us-east-1:{ACCOUNT}:vpc-endpoint/{own_ep}"
        assert any(r["target"] == own_ep_arn for r in service.metadata["relations"])
        foreign = next(a for a in linker.external_assets if a.account_id == FOREIGN)
        assert _edge(edges, foreign, service, EdgeType.ROUTE)

    def test_http_api_authorizers(self, aws_credentials, monkeypatch):
        session = boto3.Session(region_name="us-east-1")
        fn = f"arn:aws:lambda:us-east-1:{ACCOUNT}:function:authz"
        rest = _FakeClient({"get_rest_apis": {"items": []}})
        v2 = _FakeClient(
            {
                "get_apis": {
                    "Items": [{"ApiId": "abcdefghij", "Name": "web", "ProtocolType": "HTTP"}]
                },
                "get_authorizers": {
                    "Items": [
                        {
                            "AuthorizerId": "jwt1",
                            "Name": "jwt",
                            "AuthorizerType": "JWT",
                            "JwtConfiguration": {
                                "Issuer": "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_Abc123",
                                "Audience": ["c"],
                            },
                        },
                        {
                            "AuthorizerId": "lam1",
                            "Name": "lambda",
                            "AuthorizerType": "REQUEST",
                            "AuthorizerUri": f"arn:aws:apigateway:us-east-1:lambda:path/2015-03-31/functions/{fn}/invocations",
                        },
                    ]
                },
                "get_routes": {
                    "Items": [
                        {"RouteKey": "GET /me", "AuthorizationType": "JWT", "AuthorizerId": "jwt1"},
                        {"RouteKey": "GET /public", "AuthorizationType": "NONE"},
                    ]
                },
            }
        )
        collector = _collector(session, ["apigateway_authorizers"])
        _patch_clients(monkeypatch, collector, {"apigateway": rest, "apigatewayv2": v2})
        assets = asyncio.run(collector.collect())
        auths = {a.metadata["authorizer_type"]: a for a in assets}
        jwt = auths["JWT"]
        assert jwt.arn == "arn:aws:apigateway:us-east-1::/apis/abcdefghij/authorizers/jwt1"
        assert jwt.metadata["routes"] == ["GET /me"] and jwt.metadata["route_count"] == 1
        targets = {r["target"]: r for r in jwt.metadata["relations"]}
        assert "us-east-1_Abc123" in targets  # user pool ID resolves via the pool ARN tail
        assert targets["arn:aws:apigateway:us-east-1::/apis/abcdefghij"]["reverse"]
        lam = auths["REQUEST"]
        assert any(
            r["target"] == fn and r["edge"] == EdgeType.INVOKES.value
            for r in lam.metadata["relations"]
        )
