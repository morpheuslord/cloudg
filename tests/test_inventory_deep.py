"""Tests for deep inventory mapping: service collectors, typed relationships,
Organizations / Control Tower discovery, Kubernetes mapping and
interdependency analysis."""

from __future__ import annotations

import asyncio
import io
import json
import zipfile

import boto3
import pytest
from click.testing import CliRunner
from moto import mock_aws

from cloudg.config import CloudGConfig
from cloudg.inventory.aws_deep import AWSDeepInventoryCollector, select_tasks
from cloudg.inventory.aws_services.containers import image_repository
from cloudg.inventory.dependencies import (
    DependencyGraph,
    cross_account_edges,
    security_coverage,
)
from cloudg.inventory.kubernetes import eks_token, map_cluster_objects
from cloudg.inventory.linker import RelationshipLinker
from cloudg.inventory.mapper import (
    InventoryMapper,
    InventoryResult,
    add_account_hierarchy,
    deduplicate,
)
from cloudg.inventory.organization import (
    OrganizationTopology,
    _parse_manifest,
    discover_control_tower,
    discover_organization,
)
from cloudg.schema.models import (
    AssetType,
    CloudAsset,
    CloudProvider,
    EdgeType,
    NetworkEdge,
)

ACCOUNT = "123456789012"


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


def _asset(name, asset_type, arn=None, metadata=None, account="111111111111", region="us-east-1"):
    return CloudAsset(
        name=name,
        asset_type=asset_type,
        provider=CloudProvider.AWS,
        arn=arn,
        metadata=metadata or {},
        account_id=account,
        region=region,
    )


def _rel(target, edge, relationship=None, reverse=False):
    out = {"target": target, "edge": edge.value}
    if relationship:
        out["relationship"] = relationship
    if reverse:
        out["reverse"] = True
    return out


def _edge(edges, src, dst, edge_type=None):
    return [
        e for e in edges
        if e.source_id == src.id and e.target_id == dst.id
        and (edge_type is None or e.edge_type == edge_type)
    ]


# ── Helpers and task selection ──


class TestHelpers:
    def test_image_repository_strips_tag_and_digest(self):
        base = "123456789012.dkr.ecr.us-east-1.amazonaws.com/team/app"
        assert image_repository(f"{base}:1.2.3") == base
        assert image_repository(f"{base}@sha256:abc") == base
        assert image_repository("localhost:5000/app:dev") == "localhost:5000/app"
        assert image_repository("nginx") == "nginx"

    def test_select_tasks_by_family_and_exclusion(self):
        names = ["ec2", "ecr", "ecs", "eks", "lambda", "guardduty", "iam", "tagging_sweep"]
        assert select_tasks(names, ["containers"]) == ["ecr", "ecs", "eks"]
        assert "guardduty" not in select_tasks(names, ["all"], ["security"])
        assert select_tasks(names, ["lambda", "iam"]) == ["lambda", "iam"]
        assert select_tasks(names, ["kubernetes"]) == ["eks"]


# ── Linker: declared relations and scoped resolution ──


class TestLinkerRelations:
    def test_declared_relation_and_reverse(self):
        queue = _asset("jobs", AssetType.MESSAGE_QUEUE, arn="arn:aws:sqs:us-east-1:111111111111:jobs")
        fn = _asset(
            "worker",
            AssetType.LAMBDA_FUNCTION,
            arn="arn:aws:lambda:us-east-1:111111111111:function:worker",
            metadata={"relations": [_rel(queue.arn, EdgeType.INVOKES, "TRIGGERED_BY", reverse=True)]},
        )
        edges = RelationshipLinker([queue, fn]).link()
        hits = _edge(edges, queue, fn, EdgeType.INVOKES)
        assert hits and hits[0].relationship == "TRIGGERED_BY"

    def test_image_reference_resolves_to_repository(self):
        uri = "111111111111.dkr.ecr.us-east-1.amazonaws.com/app"
        repo = _asset(
            "app",
            AssetType.CONTAINER_REGISTRY,
            arn="arn:aws:ecr:us-east-1:111111111111:repository/app",
            metadata={"repository_uri": uri},
        )
        td = _asset(
            "web:3",
            AssetType.TASK_DEFINITION,
            arn="arn:aws:ecs:us-east-1:111111111111:task-definition/web:3",
            metadata={"relations": [_rel(f"{uri}:v7", EdgeType.USES_IMAGE)]},
        )
        assert _edge(RelationshipLinker([repo, td]).link(), td, repo, EdgeType.USES_IMAGE)

    def test_qualified_lambda_arn_resolves(self):
        fn = _asset("fn", AssetType.LAMBDA_FUNCTION, arn="arn:aws:lambda:us-east-1:111111111111:function:fn")
        rule = _asset(
            "r",
            AssetType.EVENT_RULE,
            arn="arn:aws:events:us-east-1:111111111111:rule/r",
            metadata={"relations": [_rel(f"{fn.arn}:live", EdgeType.INVOKES)]},
        )
        assert _edge(RelationshipLinker([fn, rule]).link(), rule, fn, EdgeType.INVOKES)

    def test_ambiguous_names_resolve_within_account(self):
        sg_a = _asset("default", AssetType.SECURITY_GROUP, arn="arn:aws:ec2:us-east-1:111111111111:security-group/sg-0aaaaaaaaaaaaaaaa", account="111111111111")
        sg_b = _asset("default", AssetType.SECURITY_GROUP, arn="arn:aws:ec2:us-east-1:222222222222:security-group/sg-0bbbbbbbbbbbbbbbb", account="222222222222")
        stack = _asset(
            "stack",
            AssetType.IAC_STACK,
            arn="arn:aws:cloudformation:us-east-1:222222222222:stack/stack/x",
            account="222222222222",
            metadata={"relations": [_rel("default", EdgeType.MANAGES)]},
        )
        edges = RelationshipLinker([sg_a, sg_b, stack]).link()
        assert _edge(edges, stack, sg_b, EdgeType.MANAGES)
        assert not _edge(edges, stack, sg_a)

    def test_ambiguous_names_across_foreign_accounts_are_not_guessed(self):
        sg_a = _asset("default", AssetType.SECURITY_GROUP, arn="arn:aws:ec2:us-east-1:111111111111:security-group/sg-0aaaaaaaaaaaaaaaa", account="111111111111")
        sg_b = _asset("default", AssetType.SECURITY_GROUP, arn="arn:aws:ec2:us-east-1:222222222222:security-group/sg-0bbbbbbbbbbbbbbbb", account="222222222222")
        other = _asset(
            "x",
            AssetType.IAC_STACK,
            arn="arn:aws:cloudformation:us-east-1:333333333333:stack/x/y",
            account="333333333333",
            metadata={"relations": [_rel("default", EdgeType.MANAGES)]},
        )
        linker = RelationshipLinker([sg_a, sg_b, other])
        edges = linker.link()
        assert not [e for e in edges if e.edge_type == EdgeType.MANAGES]
        assert linker.unresolved and linker.unresolved[0]["target"] == "default"

    def test_cross_account_trust_creates_external_account(self):
        role = _asset(
            "deploy",
            AssetType.IAM_ROLE,
            arn="arn:aws:iam::111111111111:role/deploy",
            region="global",
            metadata={"relations": [_rel("arn:aws:iam::999999999999:root", EdgeType.IAM_TRUST, "CROSS_ACCOUNT_TRUST", reverse=True)]},
        )
        linker = RelationshipLinker([role])
        edges = linker.link()
        assert len(linker.external_assets) == 1
        ext = linker.external_assets[0]
        assert ext.asset_type == AssetType.CLOUD_ACCOUNT and ext.metadata["external"]
        trust = _edge(edges, ext, role, EdgeType.IAM_TRUST)
        assert trust and trust[0].relationship == "CROSS_ACCOUNT_TRUST"

    def test_cross_account_trust_resolves_to_known_account(self):
        account = _asset("prod", AssetType.CLOUD_ACCOUNT, arn="arn:aws:iam::999999999999:root",
                         account="999999999999", region="global", metadata={"account_id": "999999999999"})
        role = _asset(
            "deploy",
            AssetType.IAM_ROLE,
            arn="arn:aws:iam::111111111111:role/deploy",
            region="global",
            metadata={"relations": [_rel("999999999999", EdgeType.IAM_TRUST, reverse=True)]},
        )
        linker = RelationshipLinker([account, role])
        edges = linker.link()
        assert not linker.external_assets
        assert _edge(edges, account, role, EdgeType.IAM_TRUST)

    def test_same_account_unknown_target_is_unresolved_not_external(self):
        fn = _asset(
            "fn",
            AssetType.LAMBDA_FUNCTION,
            arn="arn:aws:lambda:us-east-1:111111111111:function:fn",
            metadata={"relations": [_rel("arn:aws:sqs:us-east-1:111111111111:deleted", EdgeType.REFERENCES)]},
        )
        linker = RelationshipLinker([fn])
        assert linker.link() == []
        assert not linker.external_assets
        assert linker.unresolved[0]["target"].endswith(":deleted")

    def test_generic_scan_skips_declared_relations(self):
        q = _asset("q", AssetType.MESSAGE_QUEUE, arn="arn:aws:sqs:us-east-1:111111111111:q")
        fn = _asset(
            "fn",
            AssetType.LAMBDA_FUNCTION,
            arn="arn:aws:lambda:us-east-1:111111111111:function:fn",
            metadata={"relations": [_rel(q.arn, EdgeType.INVOKES, reverse=True)]},
        )
        edges = RelationshipLinker([q, fn]).link()
        assert len(edges) == 1 and edges[0].edge_type == EdgeType.INVOKES

    def test_dns_alias_resolves_load_balancer(self):
        lb = _asset("alb", AssetType.LOAD_BALANCER, arn="arn:aws:elasticloadbalancing:us-east-1:111111111111:loadbalancer/app/alb/1",
                    metadata={"dns_name": "alb-1.us-east-1.elb.amazonaws.com"})
        rec = _asset("www.example.com", AssetType.DNS_RECORD, arn="arn:aws:route53:::hostedzone/Z/A/www.example.com", region="global",
                     metadata={"relations": [_rel("dualstack.ALB-1.us-east-1.elb.amazonaws.com.", EdgeType.ROUTE, "DNS_RESOLVED")]})
        assert _edge(RelationshipLinker([lb, rec]).link(), rec, lb, EdgeType.ROUTE)


# ── Mapper building blocks ──


class TestMapperHelpers:
    def test_deduplicate_merges_relations_and_remaps_edges(self):
        sweep = _asset("t", AssetType.NOTIFICATION_TOPIC, arn="arn:aws:sns:us-east-1:1:t",
                       metadata={"discovered_via": "tagging-api"})
        rich = _asset("t", AssetType.NOTIFICATION_TOPIC, arn="arn:aws:sns:us-east-1:1:t",
                      metadata={"relations": [{"target": "x", "edge": "INVOKES"}]})
        dup = _asset("t", AssetType.NOTIFICATION_TOPIC, arn="arn:aws:sns:us-east-1:1:t",
                     metadata={"relations": [{"target": "y", "edge": "INVOKES"}]})
        other = _asset("o", AssetType.MESSAGE_QUEUE, arn="arn:aws:sqs:us-east-1:1:o")
        edges = [NetworkEdge(source_id=dup.id, target_id=other.id, edge_type=EdgeType.INVOKES)]
        assets, new_edges = deduplicate([sweep, rich, dup, other], edges)
        assert len(assets) == 2
        kept = next(a for a in assets if a.arn.endswith(":t"))
        assert kept.id == rich.id
        assert {r["target"] for r in kept.metadata["relations"]} == {"x", "y"}
        assert new_edges[0].source_id == rich.id

    def test_account_hierarchy_contains_only_top_level(self):
        vpc = _asset("vpc", AssetType.VPC, arn="arn:aws:ec2:us-east-1:111111111111:vpc/vpc-1")
        subnet = _asset("sn", AssetType.SUBNET, arn="arn:aws:ec2:us-east-1:111111111111:subnet/subnet-1")
        edges = [NetworkEdge(source_id=vpc.id, target_id=subnet.id, edge_type=EdgeType.CONTAINS)]
        assets, edges = add_account_hierarchy([vpc, subnet], edges)
        account = next(a for a in assets if a.asset_type == AssetType.CLOUD_ACCOUNT)
        assert account.arn == "arn:aws:iam::111111111111:root"
        assert _edge(edges, account, vpc, EdgeType.CONTAINS)
        assert not _edge(edges, account, subnet)

    def test_summary_ignores_hierarchy_for_unlinked(self):
        bucket = _asset("b", AssetType.S3_BUCKET, arn="arn:aws:s3:::b")
        assets, edges = add_account_hierarchy([bucket], [])
        result = InventoryResult(assets=assets, edges=edges, providers=["aws"])
        assert result.summary["unlinked_assets"] == 1
        assert result.summary["accounts"] == 1


# ── Dependency analysis ──


def _dependency_fixture():
    key = _asset("key", AssetType.KMS_KEY, arn="arn:aws:kms:us-east-1:111111111111:key/k")
    role = _asset("role", AssetType.IAM_ROLE, arn="arn:aws:iam::111111111111:role/r", region="global")
    queue = _asset("queue", AssetType.MESSAGE_QUEUE, arn="arn:aws:sqs:us-east-1:111111111111:q")
    fn = _asset("fn", AssetType.LAMBDA_FUNCTION, arn="arn:aws:lambda:us-east-1:111111111111:function:fn")
    table = _asset("table", AssetType.DYNAMODB_TABLE, arn="arn:aws:dynamodb:us-east-1:111111111111:table/t")
    alb = _asset("alb", AssetType.LOAD_BALANCER, arn="arn:aws:elasticloadbalancing:us-east-1:111111111111:loadbalancer/app/a/1")
    alb.is_internet_exposed = True
    waf = _asset("waf", AssetType.WAF_WEB_ACL, arn="arn:aws:wafv2:us-east-1:111111111111:regional/webacl/w/1")
    edges = [
        NetworkEdge(source_id=fn.id, target_id=role.id, edge_type=EdgeType.ASSUMES_ROLE),
        NetworkEdge(source_id=queue.id, target_id=fn.id, edge_type=EdgeType.INVOKES),
        NetworkEdge(source_id=queue.id, target_id=key.id, edge_type=EdgeType.REFERENCES, relationship="ENCRYPTED_BY_KMS"),
        NetworkEdge(source_id=table.id, target_id=key.id, edge_type=EdgeType.REFERENCES, relationship="ENCRYPTED_BY_KMS"),
        NetworkEdge(source_id=role.id, target_id=table.id, edge_type=EdgeType.GRANTS_ACCESS),
        NetworkEdge(source_id=waf.id, target_id=alb.id, edge_type=EdgeType.PROTECTS),
    ]
    return [key, role, queue, fn, table, alb, waf], edges


class TestDependencies:
    def test_upstream_and_downstream(self):
        assets, edges = _dependency_fixture()
        key, role, queue, fn, table, alb, waf = assets
        graph = DependencyGraph(assets, edges)
        upstream = {link.asset_id for link in graph.depends_on(fn.id)}
        # fn needs its role, the queue triggering it, and transitively the table and key
        assert {role.id, queue.id, table.id, key.id} <= upstream
        blast = {link.asset_id for link in graph.dependents(key.id)}
        assert {queue.id, table.id, fn.id, role.id} <= blast
        assert alb.id in {link.asset_id for link in graph.dependents(waf.id)}

    def test_shared_dependencies_and_blast_radius(self):
        assets, edges = _dependency_fixture()
        graph = DependencyGraph(assets, edges)
        shared = graph.shared_dependencies()
        assert shared[0]["name"] == "key" and shared[0]["direct_dependents"] == 2
        radius = graph.blast_radius()
        assert radius[0]["name"] == "key"

    def test_tree_view(self):
        assets, edges = _dependency_fixture()
        graph = DependencyGraph(assets, edges)
        view = graph.tree(graph.find("fn").id, direction="up", max_depth=2)
        names = {c["name"] for c in view["depends_on"]}
        assert names == {"role", "queue"}
        assert "dependents" not in view

    def test_find_by_arn_name_and_tail(self):
        assets, edges = _dependency_fixture()
        graph = DependencyGraph(assets, edges)
        assert graph.find("arn:aws:iam::111111111111:role/r").name == "role"
        assert graph.find("table").name == "table"
        assert graph.find("does-not-exist") is None

    def test_security_coverage(self):
        assets, edges = _dependency_fixture()
        detector = _asset("gd", AssetType.THREAT_DETECTOR, arn="cloudg:aws:guardduty:us-east-1:111111111111:not-enabled",
                          metadata={"security_service": "guardduty", "enabled": False})
        scanner = _asset("inspector", AssetType.VULNERABILITY_SCANNER, arn="arn:aws:inspector2:us-east-1:111111111111:scanner",
                         metadata={"security_service": "inspector2", "enabled": True})
        fn = next(a for a in assets if a.name == "fn")
        edges = edges + [NetworkEdge(source_id=scanner.id, target_id=fn.id, edge_type=EdgeType.MONITORS)]
        alb2 = _asset("alb2", AssetType.LOAD_BALANCER, arn="arn:aws:elasticloadbalancing:us-east-1:111111111111:loadbalancer/app/b/2")
        alb2.is_internet_exposed = True
        cov = security_coverage(assets + [detector, scanner, alb2], edges)
        assert cov["gaps"] == ["111111111111/us-east-1: guardduty"]
        assert not cov["workloads_without_vulnerability_scanning"]
        assert [u["name"] for u in cov["internet_facing_without_waf"]] == ["alb2"]

    def test_cross_account_edges(self):
        a = _asset("a", AssetType.IAM_ROLE, arn="arn:aws:iam::111111111111:role/a", account="111111111111")
        b = _asset("b", AssetType.S3_BUCKET, arn="arn:aws:s3:::b", account="222222222222")
        edges = [NetworkEdge(source_id=a.id, target_id=b.id, edge_type=EdgeType.GRANTS_ACCESS)]
        out = cross_account_edges([a, b], edges)
        assert out[0]["source_account"] == "111111111111" and out[0]["target_account"] == "222222222222"


# ── Kubernetes ──


class _FakeReader:
    def __init__(self, objects):
        self._objects = objects

    def list(self, path):
        return iter(self._objects.get(path, []))


class TestKubernetes:
    CLUSTER = "arn:aws:eks:us-east-1:111111111111:cluster/prod"

    def _objects(self):
        image = "111111111111.dkr.ecr.us-east-1.amazonaws.com/api:2.1"
        return {
            "/api/v1/namespaces": [{"metadata": {"name": "shop"}, "status": {"phase": "Active"}}],
            "/api/v1/serviceaccounts": [
                {"metadata": {"name": "api", "namespace": "shop",
                              "annotations": {"eks.amazonaws.com/role-arn": "arn:aws:iam::111111111111:role/api"}}}
            ],
            "/apis/apps/v1/deployments": [
                {
                    "metadata": {"name": "api", "namespace": "shop"},
                    "spec": {
                        "replicas": 3,
                        "template": {
                            "metadata": {"labels": {"app": "api"}},
                            "spec": {"serviceAccountName": "api", "containers": [{"name": "api", "image": image}]},
                        },
                    },
                }
            ],
            "/api/v1/services": [
                {
                    "metadata": {"name": "api", "namespace": "shop"},
                    "spec": {"type": "LoadBalancer", "selector": {"app": "api"}, "ports": [{"port": 443}]},
                    "status": {"loadBalancer": {"ingress": [{"hostname": "abc.elb.us-east-1.amazonaws.com"}]}},
                }
            ],
            "/apis/networking.k8s.io/v1/ingresses": [
                {
                    "metadata": {"name": "web", "namespace": "shop"},
                    "spec": {"rules": [{"host": "shop.example.com", "http": {"paths": [{"backend": {"service": {"name": "api"}}}]}}]},
                }
            ],
        }

    def test_map_cluster_objects_links_everything(self):
        k8s = map_cluster_objects(_FakeReader(self._objects()), self.CLUSTER, "us-east-1", "111111111111")
        types = {a.asset_type for a in k8s}
        assert {AssetType.K8S_NAMESPACE, AssetType.K8S_SERVICE_ACCOUNT, AssetType.K8S_WORKLOAD,
                AssetType.K8S_SERVICE, AssetType.K8S_INGRESS} <= types

        cluster = _asset("prod", AssetType.EKS_CLUSTER, arn=self.CLUSTER)
        role = _asset("api", AssetType.IAM_ROLE, arn="arn:aws:iam::111111111111:role/api", region="global")
        repo = _asset("api", AssetType.CONTAINER_REGISTRY, arn="arn:aws:ecr:us-east-1:111111111111:repository/api",
                      metadata={"repository_uri": "111111111111.dkr.ecr.us-east-1.amazonaws.com/api"})
        lb = _asset("k8s-lb", AssetType.LOAD_BALANCER, arn="arn:aws:elasticloadbalancing:us-east-1:111111111111:loadbalancer/net/k/1",
                    metadata={"dns_name": "abc.elb.us-east-1.amazonaws.com"})
        assets = k8s + [cluster, role, repo, lb]
        edges = RelationshipLinker(assets).link()

        by_kind = {(a.metadata.get("kind"), a.name): a for a in k8s}
        deploy = by_kind[("Deployment", "shop/api")]
        sa = by_kind[("ServiceAccount", "shop/api")]
        svc = by_kind[("Service", "shop/api")]
        ing = by_kind[("Ingress", "shop/web")]
        ns = by_kind[("Namespace", "shop")]

        assert _edge(edges, deploy, repo, EdgeType.USES_IMAGE)
        assert _edge(edges, deploy, sa)
        assert _edge(edges, sa, role, EdgeType.ASSUMES_ROLE)
        assert _edge(edges, svc, deploy, EdgeType.LOAD_BALANCER_TARGET)
        assert _edge(edges, lb, svc, EdgeType.ROUTE)
        assert _edge(edges, ing, svc, EdgeType.ROUTE)
        assert _edge(edges, cluster, ns, EdgeType.CONTAINS)
        assert _edge(edges, ns, deploy, EdgeType.CONTAINS)
        assert svc.is_internet_exposed

    def test_eks_token_format(self, aws_credentials):
        token = eks_token(boto3.Session(region_name="us-east-1"), "prod", "us-east-1")
        assert token.startswith("k8s-aws-v1.")
        import base64

        payload = token[len("k8s-aws-v1."):]
        url = base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)).decode()
        assert "Action=GetCallerIdentity" in url and "x-k8s-aws-id" in url.lower()


# ── Deep AWS collector against moto ──


def _lambda_zip() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("h.py", "def h(e, c):\n    return None\n")
    return buf.getvalue()


@mock_aws
class TestDeepServiceCollectors:
    def _estate(self, session):
        iam = session.client("iam")
        trust = {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"},
                {"Effect": "Allow", "Principal": {"AWS": "arn:aws:iam::999999999999:root"}, "Action": "sts:AssumeRole"},
            ],
        }
        role = iam.create_role(RoleName="app", AssumeRolePolicyDocument=json.dumps(trust))["Role"]["Arn"]
        sqs = session.client("sqs")
        queue_url = sqs.create_queue(QueueName="jobs")["QueueUrl"]
        queue = sqs.get_queue_attributes(QueueUrl=queue_url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
        iam.put_role_policy(
            RoleName="app",
            PolicyName="q",
            PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": [
                {"Effect": "Allow", "Action": "sqs:ReceiveMessage", "Resource": queue}]}),
        )
        lam = session.client("lambda")
        fn = lam.create_function(FunctionName="worker", Runtime="python3.12", Role=role, Handler="h.h",
                                 Code={"ZipFile": _lambda_zip()})["FunctionArn"]
        lam.create_event_source_mapping(EventSourceArn=queue, FunctionName="worker")
        sns = session.client("sns")
        topic = sns.create_topic(Name="alerts")["TopicArn"]
        sns.subscribe(TopicArn=topic, Protocol="sqs", Endpoint=queue)
        repo = session.client("ecr").create_repository(repositoryName="api")["repository"]
        ecs = session.client("ecs")
        ecs.create_cluster(clusterName="prod")
        td = ecs.register_task_definition(
            family="api",
            containerDefinitions=[{"name": "api", "image": repo["repositoryUri"] + ":1.0", "memory": 256}],
            taskRoleArn=role,
        )["taskDefinition"]["taskDefinitionArn"]
        ecs.create_service(cluster="prod", serviceName="api", taskDefinition=td, desiredCount=1)
        events = session.client("events")
        events.put_rule(Name="nightly", ScheduleExpression="rate(1 day)")
        events.put_targets(Rule="nightly", Targets=[{"Id": "1", "Arn": fn}])
        s3 = session.client("s3")
        s3.create_bucket(Bucket="uploads")
        s3.put_bucket_notification_configuration(
            Bucket="uploads",
            NotificationConfiguration={"QueueConfigurations": [{"QueueArn": queue, "Events": ["s3:ObjectCreated:*"]}]},
        )
        session.client("guardduty").create_detector(Enable=True)
        return {"role": role, "queue": queue, "fn": fn, "topic": topic, "repo": repo["repositoryArn"], "td": td}

    def _collect(self, session, **kwargs):
        collector = AWSDeepInventoryCollector(
            session=session, region="us-east-1", account_id=ACCOUNT, kubernetes=False, **kwargs
        )
        return asyncio.run(collector.collect()), collector

    def test_services_are_mapped_and_linked(self, aws_credentials):
        session = boto3.Session(region_name="us-east-1")
        ids = self._estate(session)
        assets, _ = self._collect(session)
        by_arn = {a.arn: a for a in assets}
        types = {a.asset_type for a in assets}
        for expected in (
            AssetType.CONTAINER_REGISTRY, AssetType.CONTAINER_SERVICE, AssetType.TASK_DEFINITION,
            AssetType.MESSAGE_QUEUE, AssetType.NOTIFICATION_TOPIC, AssetType.EVENT_RULE,
            AssetType.THREAT_DETECTOR, AssetType.LAMBDA_FUNCTION, AssetType.IAM_ROLE,
        ):
            assert expected in types, expected

        edges = RelationshipLinker(assets).link()
        fn, queue, role = by_arn[ids["fn"]], by_arn[ids["queue"]], by_arn[ids["role"]]
        td, repo, topic = by_arn[ids["td"]], by_arn[ids["repo"]], by_arn[ids["topic"]]
        bucket = by_arn["arn:aws:s3:::uploads"]
        rule = next(a for a in assets if a.asset_type == AssetType.EVENT_RULE)

        assert _edge(edges, queue, fn, EdgeType.INVOKES)  # event source mapping
        assert _edge(edges, fn, role, EdgeType.ASSUMES_ROLE)
        assert _edge(edges, td, repo, EdgeType.USES_IMAGE)
        assert _edge(edges, td, role, EdgeType.ASSUMES_ROLE)
        assert _edge(edges, topic, queue, EdgeType.INVOKES)  # SNS -> SQS subscription
        assert _edge(edges, rule, fn, EdgeType.INVOKES)
        assert _edge(edges, bucket, queue, EdgeType.INVOKES)  # S3 notification
        assert _edge(edges, role, queue, EdgeType.GRANTS_ACCESS)  # inline policy grant
        assert role.metadata["trusted_external_accounts"] == ["999999999999"]
        assert "lambda.amazonaws.com" in role.metadata["trusted_services"]

    def test_disabled_security_services_are_visible(self, aws_credentials):
        session = boto3.Session(region_name="us-east-1")
        assets, _ = self._collect(session, services=["security"])
        detectors = [a for a in assets if a.metadata.get("security_service") == "guardduty"]
        assert detectors and detectors[0].metadata["enabled"] is False

    def test_global_services_only_in_primary_region(self, aws_credentials):
        session = boto3.Session(region_name="us-east-1")
        self._estate(session)
        assets, collector = self._collect(session, is_primary_region=False)
        assert not [a for a in assets if a.asset_type in (AssetType.IAM_ROLE, AssetType.S3_BUCKET)]
        assert "iam" not in {s.service for s in collector.coverage.services}

    def test_service_filter(self, aws_credentials):
        session = boto3.Session(region_name="us-east-1")
        self._estate(session)
        assets, collector = self._collect(session, services=["containers"], tagging_sweep=False)
        assert {s.service for s in collector.coverage.services} == {"ecr", "ecs", "eks"}
        assert {a.asset_type for a in assets} <= {
            AssetType.CONTAINER_REGISTRY, AssetType.CONTAINER_SERVICE, AssetType.TASK_DEFINITION,
            AssetType.ECS_CLUSTER,
        }

    def test_eks_cluster_and_nodegroup(self, aws_credentials):
        session = boto3.Session(region_name="us-east-1")
        ids = self._estate(session)
        ec2 = session.client("ec2")
        vpc = ec2.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]["VpcId"]
        subnet = ec2.create_subnet(VpcId=vpc, CidrBlock="10.0.1.0/24")["Subnet"]["SubnetId"]
        eks = session.client("eks")
        eks.create_cluster(name="k", roleArn=ids["role"], resourcesVpcConfig={"subnetIds": [subnet]})
        eks.create_nodegroup(clusterName="k", nodegroupName="ng", subnets=[subnet], nodeRole=ids["role"])
        assets, _ = self._collect(session, services=["containers", "network", "identity"], tagging_sweep=False)
        cluster = next(a for a in assets if a.asset_type == AssetType.EKS_CLUSTER)
        ng = next(a for a in assets if a.asset_type == AssetType.NODE_GROUP)
        sn = next(a for a in assets if a.metadata.get("subnet_id") == subnet)
        role = next(a for a in assets if a.arn == ids["role"])
        edges = RelationshipLinker(assets).link()
        assert _edge(edges, cluster, ng, EdgeType.CONTAINS)
        assert _edge(edges, ng, role, EdgeType.ASSUMES_ROLE)
        assert _edge(edges, sn, ng, EdgeType.CONTAINS)


# ── Organizations / Control Tower ──


class _FakeControlTower:
    def __init__(self, manifest, controls):
        self._manifest = manifest
        self._controls = controls

    def get_paginator(self, op):
        data = {
            "list_landing_zones": {"landingZones": [{"arn": "arn:aws:controltower:us-east-1:123456789012:landingzone/LZ"}]},
            "list_enabled_controls": {"enabledControls": self._controls},
            "list_enabled_baselines": {"enabledBaselines": []},
        }[op]

        class _P:
            def paginate(self, **kwargs):
                return [data]

        return _P()

    def get_landing_zone(self, landingZoneIdentifier):
        return {"landingZone": {"arn": landingZoneIdentifier, "version": "3.3", "status": "ACTIVE",
                                "manifest": self._manifest}}


class _SessionWithCT:
    def __init__(self, session, ct):
        self._session = session
        self._ct = ct
        self.region_name = "us-east-1"

    def client(self, name, **kwargs):
        if name == "controltower":
            return self._ct
        return self._session.client(name, **kwargs)


class TestOrganization:
    def test_parse_manifest_v3_and_v4(self):
        v3 = {"governedRegions": ["us-east-1", "eu-west-1"],
              "centralizedLogging": {"accountId": "222222222222"},
              "securityRoles": {"accountId": "333333333333"}}
        regions, shared = _parse_manifest(v3)
        assert regions == ["us-east-1", "eu-west-1"]
        assert shared == {"log_archive": "222222222222", "audit": "333333333333"}
        v4 = {"config": {"accountId": "444444444444", "enabled": True},
              "backup": {"configurations": {"backupAdmin": {"accountId": "555555555555"}}}}
        _, shared4 = _parse_manifest(v4)
        assert shared4 == {"config_aggregator": "444444444444", "backup_admin": "555555555555"}

    def _build_org(self, session):
        org = session.client("organizations")
        org.create_organization(FeatureSet="ALL")
        root = org.list_roots()["Roots"][0]["Id"]
        workloads = org.create_organizational_unit(ParentId=root, Name="Workloads")["OrganizationalUnit"]["Id"]
        prod = org.create_organizational_unit(ParentId=workloads, Name="Prod")["OrganizationalUnit"]["Id"]
        security = org.create_organizational_unit(ParentId=root, Name="Security")["OrganizationalUnit"]["Id"]

        def account(name, parent):
            acct_id = org.create_account(AccountName=name, Email=f"{name}@example.com")["CreateAccountStatus"]["AccountId"]
            org.move_account(AccountId=acct_id, SourceParentId=root, DestinationParentId=parent)
            return acct_id

        ids = {"prod": account("prod", prod), "audit": account("audit", security), "dev": account("dev", workloads)}
        scp = org.create_policy(
            Name="deny-leave",
            Description="d",
            Type="SERVICE_CONTROL_POLICY",
            Content=json.dumps({"Version": "2012-10-17", "Statement": [
                {"Effect": "Deny", "Action": "organizations:LeaveOrganization", "Resource": "*"}]}),
        )["Policy"]["PolicySummary"]["Id"]
        org.attach_policy(PolicyId=scp, TargetId=workloads)
        return {"root": root, "workloads": workloads, "prod_ou": prod, "security": security, **ids}

    @mock_aws
    def test_discover_organization(self, aws_credentials):
        session = boto3.Session(region_name="us-east-1")
        ids = self._build_org(session)
        topo = discover_organization(session, control_tower=False)
        assert topo.management_account_id == ACCOUNT
        assert {ids["prod"], ids["audit"], ids["dev"], ACCOUNT} <= set(topo.accounts)
        assert topo.accounts[ids["prod"]].ou_path == ["Root", "Workloads", "Prod"]
        scp = next(p for p in topo.policies if p.name == "deny-leave")
        assert scp.targets == [ids["workloads"]]

        # OU filters include nested OUs; exclusions and management toggles apply
        assert set(topo.target_accounts(include_ous=["Workloads"])) == {ids["prod"], ids["dev"]}
        assert topo.target_accounts(include_ous=[ids["prod_ou"]]) == [ids["prod"]]
        assert ACCOUNT not in topo.target_accounts(include_management_account=False)
        assert ids["dev"] not in topo.target_accounts(exclude_accounts=[ids["dev"]])

    @mock_aws
    def test_topology_assets_link_into_a_tree(self, aws_credentials):
        session = boto3.Session(region_name="us-east-1")
        ids = self._build_org(session)
        controls = [{"arn": "arn:aws:controltower:us-east-1:123456789012:enabledcontrol/C1",
                     "controlIdentifier": "arn:aws:controlcatalog:::control/abc",
                     "targetIdentifier": f"arn:aws:organizations::{ACCOUNT}:ou/o-x/{ids['workloads']}",
                     "statusSummary": {"status": "SUCCEEDED"}}]
        manifest = {"governedRegions": ["us-east-1", "eu-west-1"],
                    "centralizedLogging": {"accountId": ids["audit"]},
                    "securityRoles": {"accountId": ids["audit"]}}
        topo = discover_organization(session, control_tower=False)
        discover_control_tower(_SessionWithCT(session, _FakeControlTower(manifest, controls)), topo)
        assert topo.control_tower_enabled
        assert topo.governed_regions == ["us-east-1", "eu-west-1"]
        assert topo.shared_accounts["audit"] == ids["audit"]

        # OU ARNs from moto differ from the fake control target; align them
        wl = topo.ous[ids["workloads"]]
        topo.enabled_controls[0]["targetIdentifier"] = wl.arn

        assets = topo.to_assets()
        edges = RelationshipLinker(assets).link()
        by_arn = {a.arn: a for a in assets}
        prod_account = by_arn[f"arn:aws:iam::{ids['prod']}:root"]
        prod_ou = next(a for a in assets if a.metadata.get("ou_id") == ids["prod_ou"])
        workloads_ou = next(a for a in assets if a.metadata.get("ou_id") == ids["workloads"])
        scp = next(a for a in assets if a.asset_type == AssetType.ORG_POLICY and a.name == "deny-leave")
        control = next(a for a in assets if a.asset_type == AssetType.GUARDRAIL)
        lz = next(a for a in assets if a.asset_type == AssetType.LANDING_ZONE)

        assert _edge(edges, prod_ou, prod_account, EdgeType.CONTAINS)
        assert _edge(edges, workloads_ou, prod_ou, EdgeType.CONTAINS)
        assert _edge(edges, scp, workloads_ou, EdgeType.GOVERNS)
        assert _edge(edges, control, workloads_ou, EdgeType.GOVERNS)
        assert _edge(edges, lz, by_arn[f"arn:aws:iam::{ids['audit']}:root"], EdgeType.MANAGES)
        assert prod_account.metadata["ou_path"] == ["Root", "Workloads", "Prod"]

    def test_target_accounts_skips_suspended(self):
        from cloudg.inventory.organization import OrgAccount

        topo = OrganizationTopology(management_account_id="1")
        topo.accounts = {
            "1": OrgAccount(id="1", name="mgmt", arn="", status="ACTIVE", parent_id="r-1"),
            "2": OrgAccount(id="2", name="old", arn="", status="SUSPENDED", parent_id="r-1"),
        }
        assert topo.target_accounts() == ["1"]
        assert topo.target_accounts(include_suspended=True) == ["1", "2"]


@mock_aws
class TestOrganizationMapping:
    def test_map_inventory_across_org_accounts(self, aws_credentials):
        session = boto3.Session(region_name="us-east-1")
        org = session.client("organizations")
        org.create_organization(FeatureSet="ALL")
        root = org.list_roots()["Roots"][0]["Id"]
        ou = org.create_organizational_unit(ParentId=root, Name="Workloads")["OrganizationalUnit"]["Id"]
        member = org.create_account(AccountName="prod", Email="p@example.com")["CreateAccountStatus"]["AccountId"]
        org.move_account(AccountId=member, SourceParentId=root, DestinationParentId=ou)

        # One VPC in the management account, one in the member account
        session.client("ec2").create_vpc(CidrBlock="10.1.0.0/16")
        creds = session.client("sts").assume_role(
            RoleArn=f"arn:aws:iam::{member}:role/AWSControlTowerExecution", RoleSessionName="test-setup"
        )["Credentials"]
        member_session = boto3.Session(
            aws_access_key_id=creds["AccessKeyId"],
            aws_secret_access_key=creds["SecretAccessKey"],
            aws_session_token=creds["SessionToken"],
            region_name="us-east-1",
        )
        member_vpc = member_session.client("ec2").create_vpc(CidrBlock="10.2.0.0/16")["Vpc"]["VpcId"]

        cfg = CloudGConfig(providers=["aws"])
        cfg.aws.regions = ["us-east-1"]
        cfg.aws.organization.enabled = True
        cfg.aws.organization.control_tower = False
        cfg.inventory.services = ["network"]
        cfg.inventory.kubernetes = False

        result = InventoryMapper(cfg, tagging_sweep=False).map_inventory_sync()

        accounts = {a.account_id for a in result.assets if a.asset_type == AssetType.VPC}
        assert {ACCOUNT, member} <= accounts
        assert result.organization and member in result.organization["accounts"]
        assert cfg.aws.accounts == []  # caller's config is not mutated

        member_account = next(
            a for a in result.assets if a.asset_type == AssetType.CLOUD_ACCOUNT and a.account_id == member
        )
        ou_node = next(a for a in result.assets if a.metadata.get("ou_id") == ou)
        vpc_node = next(a for a in result.assets if a.metadata.get("vpc_id") == member_vpc)
        assert _edge(result.edges, ou_node, member_account, EdgeType.CONTAINS)
        assert _edge(result.edges, member_account, vpc_node, EdgeType.CONTAINS)
        assert result.summary["organization"]["accounts"] >= 2


# ── Export, load and the deps command ──


class TestExportAndCli:
    def _result(self):
        assets, edges = _dependency_fixture()
        return InventoryResult(assets=assets, edges=edges, providers=["aws"])

    def test_export_load_roundtrip(self, tmp_path):
        paths = self._result().export(tmp_path)
        assert paths["dependencies"].exists()
        analysis = json.loads(paths["dependencies"].read_text())
        assert analysis["shared_dependencies"][0]["name"] == "key"
        loaded = InventoryResult.load(tmp_path)
        assert len(loaded.assets) == 7 and len(loaded.edges) == 6
        assert {e.edge_type for e in loaded.edges} >= {EdgeType.INVOKES, EdgeType.PROTECTS}

    def test_deps_command(self, tmp_path):
        from cloudg.cli import cli

        self._result().export(tmp_path)
        runner = CliRunner()
        out = runner.invoke(cli, ["deps", "fn", "--map", str(tmp_path), "--json", "--direction", "up"])
        assert out.exit_code == 0, out.output
        assert '"depends_on"' in out.output and "queue" in out.output
        overview = runner.invoke(cli, ["deps", "--map", str(tmp_path)])
        assert overview.exit_code == 0, overview.output
        assert "Most shared dependencies" in overview.output
        missing = runner.invoke(cli, ["deps", "nope", "--map", str(tmp_path)])
        assert missing.exit_code == 1

    def test_graph_export_carries_relationships(self, tmp_path):
        paths = self._result().export(tmp_path)
        graph = json.loads(paths["graph"].read_text())
        rels = {link["relationship"] for link in graph["links"]}
        assert "ENCRYPTED_BY_KMS" in rels
        assert all("account_id" in n for n in graph["nodes"])


def test_ontology_uses_declared_relationship():
    from cloudg.graph.ontology import RelationType, infer_relations

    edge = NetworkEdge(source_id="a", target_id="b", edge_type=EdgeType.REFERENCES, relationship="ENCRYPTED_BY_KMS")
    assert infer_relations(edge, {})[0] == RelationType.ENCRYPTED_BY_KMS
    typed = NetworkEdge(source_id="a", target_id="b", edge_type=EdgeType.INVOKES)
    assert infer_relations(typed, {}) == [RelationType.INVOKES]
