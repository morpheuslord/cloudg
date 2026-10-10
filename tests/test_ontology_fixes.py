"""Regression tests: ontology export formats and queries, NACL_RULE
relations, raw metadata, RAG chunk count, blast radius at the internet
placeholder and findings.json timestamps."""

from __future__ import annotations

import asyncio
import json
from datetime import datetime

import networkx as nx
import pytest
from rdflib import Graph

from cloudg.api import CloudGEngine
from cloudg.config import CloudGConfig
from cloudg.graph.builder import GraphBuilder
from cloudg.graph.ontology import (
    CMP,
    CMR,
    CloudOntology,
    RelationType,
    infer_relations,
    ontology_extension,
    ontology_format,
)
from cloudg.graph.reachability import ReachabilityAnalyzer
from cloudg.renderers.json_export import JSONExporter
from cloudg.schema.models import (
    AssetType,
    CloudAsset,
    CloudProvider,
    EdgeType,
    NetworkEdge,
    ScanResult,
)


def _asset(aid: str, asset_type: AssetType, name: str | None = None, **kw) -> CloudAsset:
    return CloudAsset(
        id=aid, name=name or aid, asset_type=asset_type, provider=CloudProvider.AWS, **kw
    )


# ── 25: one format-to-extension table ──


@pytest.mark.parametrize(
    "fmt,rdflib_fmt,ext",
    [
        ("turtle", "turtle", "ttl"),
        ("TTL", "turtle", "ttl"),
        ("json-ld", "json-ld", "jsonld"),
        ("jsonld", "json-ld", "jsonld"),
        ("xml", "xml", "rdf"),
        ("rdfxml", "xml", "rdf"),
        ("nt", "nt", "nt"),
        ("ntriples", "nt", "nt"),
        ("bogus", "turtle", "ttl"),
    ],
)
def test_ontology_format_table(fmt, rdflib_fmt, ext):
    assert ontology_format(fmt) == (rdflib_fmt, ext)
    assert ontology_extension(fmt) == ext


def _small_estate():
    vpc = _asset("vpc-1", AssetType.VPC)
    subnet = _asset("subnet-1", AssetType.SUBNET)
    ec2 = _asset("ec2-1", AssetType.EC2)
    edges = [
        NetworkEdge(source_id="vpc-1", target_id="subnet-1", edge_type=EdgeType.CONTAINS),
        NetworkEdge(source_id="subnet-1", target_id="ec2-1", edge_type=EdgeType.CONTAINS),
    ]
    return [vpc, subnet, ec2], edges


def test_engine_writes_each_format_to_its_own_file(tmp_path):
    cfg = CloudGConfig()
    cfg.ontology.export_formats = ["turtle", "nt", "jsonld", "xml"]
    assets, edges = _small_estate()
    result = asyncio.run(CloudGEngine(cfg).analyze(assets, edges, [], output_dir=tmp_path))

    for ext, rdflib_fmt in (("ttl", "turtle"), ("nt", "nt"), ("jsonld", "json-ld"), ("rdf", "xml")):
        path = tmp_path / f"ontology.{ext}"
        assert path.exists(), ext
        assert len(Graph().parse(path, format=rdflib_fmt)) == result.ontology_triples

    # 25: the RAG chunk count is set and matches the JSONL file
    assert result.rag_chunks_path is not None
    lines = [x for x in result.rag_chunks_path.read_text().splitlines() if x.strip()]
    assert result.rag_chunk_count == len(lines) > 0


def test_cli_ontology_phase_uses_the_same_extensions(tmp_path):
    from cloudg.cli_run_helpers import _ontology_phase

    cfg = CloudGConfig()
    cfg.ontology.export_formats = ["jsonld", "ntriples", "rdfxml"]
    assets, edges = _small_estate()
    _ontology_phase(cfg, assets, edges, [], tmp_path)
    assert sorted(p.name for p in tmp_path.iterdir()) == [
        "ontology.jsonld",
        "ontology.nt",
        "ontology.rdf",
    ]


# ── ontology.include_raw_metadata ──


def test_raw_metadata_off_by_default_and_on_when_asked():
    asset = _asset("db-1", AssetType.RDS_INSTANCE, metadata={"engine": "postgres", "port": 5432})
    plain = CloudOntology()
    plain.build([asset], [])
    assert not list(plain.graph.objects(CMR["db-1"], CMP["hasRawMetadata"]))

    onto = CloudOntology(include_raw_metadata=True)
    onto.build([asset], [])
    (literal,) = list(onto.graph.objects(CMR["db-1"], CMP["hasRawMetadata"]))
    assert json.loads(str(literal)) == {"engine": "postgres", "port": 5432}


def test_engine_passes_include_raw_metadata(tmp_path):
    cfg = CloudGConfig()
    cfg.ontology.include_raw_metadata = True
    cfg.ontology.export_formats = ["turtle"]
    cfg.rag.enabled = False
    asset = _asset("db-1", AssetType.RDS_INSTANCE, metadata={"engine": "postgres"})
    asyncio.run(CloudGEngine(cfg).analyze([asset], [], [], output_dir=tmp_path))
    assert "hasRawMetadata" in (tmp_path / "ontology.ttl").read_text()


# ── 27: neighbourhood queries ──


class TestNeighbourhood:
    def _onto(self, ids=("vpc-1", "subnet-1", "ec2-1")):
        vpc_id, subnet_id, ec2_id = ids
        assets = [
            _asset(vpc_id, AssetType.VPC, name="prod-vpc"),
            _asset(subnet_id, AssetType.SUBNET, name="prod-subnet"),
            _asset(ec2_id, AssetType.EC2, name="web"),
        ]
        edges = [
            NetworkEdge(source_id=vpc_id, target_id=subnet_id, edge_type=EdgeType.CONTAINS),
            NetworkEdge(source_id=subnet_id, target_id=ec2_id, edge_type=EdgeType.CONTAINS),
        ]
        onto = CloudOntology()
        onto.build(assets, edges)
        return onto

    def test_multi_hop(self):
        onto = self._onto()
        rows = onto.query_asset_neighbourhood("vpc-1", hops=2)
        assert [(r["neighbour"], r["neighbourName"], r["hops"]) for r in rows] == [
            (str(CMR["subnet-1"]), "prod-subnet", 1),
            (str(CMR["ec2-1"]), "web", 2),
        ]
        assert len(onto.query_asset_neighbourhood("vpc-1", hops=1)) >= 1
        one_hop_only = onto.query_asset_neighbourhood("subnet-1", hops=2)
        assert [r["neighbour"] for r in one_hop_only] == [str(CMR["ec2-1"])]

    @pytest.mark.parametrize(
        "ids",
        [
            (
                "arn:aws:ec2:us-east-1:1:vpc/vpc-1",
                "arn:aws:ec2:us-east-1:1:subnet/subnet-1",
                "arn:aws:ec2:us-east-1:1:instance/i-1",
            ),
            ("vpc:1", "sub/net", "a b"),
        ],
    )
    def test_ids_with_colons_and_slashes(self, ids):
        onto = self._onto(ids)
        rows = onto.query_asset_neighbourhood(ids[1], hops=1)
        neighbours = {r["neighbour"] for r in rows}
        assert {str(CMR[ids[0]]), str(CMR[ids[2]])} <= neighbours
        deep = onto.query_asset_neighbourhood(ids[0], hops=3)
        assert [r["neighbour"] for r in deep] == [str(CMR[ids[1]]), str(CMR[ids[2]])]

    def test_unknown_asset_gives_no_rows(self):
        onto = self._onto()
        assert onto.query_asset_neighbourhood("nope", hops=1) == []
        assert onto.query_asset_neighbourhood("nope", hops=3) == []

    def test_query_unbound_values_are_none(self):
        onto = self._onto()
        rows = onto.query(
            """
            SELECT ?s ?missing WHERE {
                ?s cmp:hasName "web" .
                OPTIONAL { ?s cmp:noSuchProperty ?missing }
            }
            """
        )
        assert rows == [{"s": str(CMR["ec2-1"]), "missing": None}]

    def test_query_bindings(self):
        onto = self._onto()
        rows = onto.query(
            "SELECT ?name WHERE { ?s cmp:hasName ?name }", bindings={"s": CMR["subnet-1"]}
        )
        assert rows == [{"name": "prod-subnet"}]


# ── 28: NACL_RULE edges get rule relations, never PROTECTED_BY_NACL ──


class TestNaclRuleRelations:
    def test_ingress_from_internet(self):
        nacl = _asset("acl-1", AssetType.NACL)
        edge = NetworkEdge(
            source_id="0.0.0.0/0",
            target_id="acl-1",
            edge_type=EdgeType.NACL_RULE,
            cidr="0.0.0.0/0",
            port_range="22",
            protocol="TCP",
            direction="ingress",
        )
        rels = set(infer_relations(edge, {"acl-1": nacl}))
        assert {RelationType.INGRESS_ALLOWED, RelationType.INTERNET_REACHABLE} <= rels
        assert RelationType.ONLY_SSH in rels
        assert RelationType.PROTECTED_BY_NACL not in rels

    def test_egress_restricted_cidr(self):
        nacl = _asset("acl-1", AssetType.NACL)
        edge = NetworkEdge(
            source_id="acl-1",
            target_id="10.0.0.0/8",
            edge_type=EdgeType.NACL_RULE,
            cidr="10.0.0.0/8",
            port_range="0-65535",
            protocol="ALL",
            direction="egress",
        )
        rels = set(infer_relations(edge, {"acl-1": nacl}))
        assert {RelationType.EGRESS_ALLOWED, RelationType.CIDR_RESTRICTED} <= rels
        assert RelationType.PROTECTED_BY_NACL not in rels

    def test_same_relations_as_security_group_rule(self):
        target = _asset("x", AssetType.SECURITY_GROUP)
        kw = dict(cidr="0.0.0.0/0", port_range="443", protocol="TCP", direction="ingress")
        sg = NetworkEdge(
            source_id="0.0.0.0/0", target_id="x", edge_type=EdgeType.SECURITY_GROUP_RULE, **kw
        )
        nacl = NetworkEdge(source_id="0.0.0.0/0", target_id="x", edge_type=EdgeType.NACL_RULE, **kw)
        assert infer_relations(nacl, {"x": target}) == infer_relations(sg, {"x": target})

    def test_ontology_has_nacl_rule_triples(self):
        nacl = _asset("acl-1", AssetType.NACL)
        onto = CloudOntology()
        onto.build(
            [nacl],
            [
                NetworkEdge(
                    source_id="0.0.0.0/0",
                    target_id="acl-1",
                    edge_type=EdgeType.NACL_RULE,
                    cidr="0.0.0.0/0",
                    protocol="ALL",
                    direction="ingress",
                )
            ],
        )
        assert (CMR["0.0.0.0/0"], CMP["INGRESS_ALLOWED"], CMR["acl-1"]) in onto.graph


# ── 29: blast radius stops at the internet placeholder ──


def test_blast_radius_stops_at_internet_placeholder():
    web = _asset("web", AssetType.EC2)
    web_sg = _asset("web-sg", AssetType.SECURITY_GROUP)
    db = _asset("db", AssetType.RDS_INSTANCE)
    other = _asset("other", AssetType.EC2)
    other_sg = _asset("other-sg", AssetType.SECURITY_GROUP)
    edges = [
        NetworkEdge(source_id="web", target_id="web-sg", edge_type=EdgeType.ATTACHED_TO),
        NetworkEdge(
            source_id="web-sg",
            target_id="0.0.0.0/0",
            edge_type=EdgeType.SECURITY_GROUP_RULE,
            cidr="0.0.0.0/0",
            protocol="ALL",
            direction="egress",
        ),
        NetworkEdge(
            source_id="web-sg",
            target_id="db",
            edge_type=EdgeType.SECURITY_GROUP_RULE,
            cidr="10.0.0.0/8",
            direction="ingress",
        ),
        # Something else open to the internet
        NetworkEdge(
            source_id="0.0.0.0/0",
            target_id="other-sg",
            edge_type=EdgeType.SECURITY_GROUP_RULE,
            cidr="0.0.0.0/0",
            port_range="443",
            protocol="TCP",
            direction="ingress",
        ),
        NetworkEdge(source_id="other", target_id="other-sg", edge_type=EdgeType.ATTACHED_TO),
        NetworkEdge(source_id="0.0.0.0/0", target_id="other", edge_type=EdgeType.INTERNET_EXPOSED),
    ]
    graph = GraphBuilder().build([web, web_sg, db, other, other_sg], edges)
    analyzer = ReachabilityAnalyzer(graph)

    radius = analyzer.compute_blast_radius("web")
    assert set(radius["reachable_nodes"]) == {"web-sg", "db", "0.0.0.0/0"}
    assert radius["depth"] == 2

    # Starting at the placeholder still walks its edges
    from_internet = analyzer.compute_blast_radius("0.0.0.0/0")
    assert {"other-sg", "other"} <= set(from_internet["reachable_nodes"])
    assert analyzer.compute_blast_radius("missing") == {
        "reachable_nodes": [],
        "depth": 0,
        "risk_score": 0.0,
    }


def test_blast_radius_isolated_node():
    graph = nx.DiGraph()
    graph.add_node("lonely", asset_type="EC2")
    assert ReachabilityAnalyzer(graph).compute_blast_radius("lonely") == {
        "reachable_nodes": [],
        "depth": 0,
        "risk_score": 0.0,
    }


# ── 30: findings.json timestamps ──


def test_findings_json_timestamps_are_iso_and_null(tmp_path):
    started = datetime(2026, 10, 9, 8, 30, 15)
    path = JSONExporter(output_dir=str(tmp_path)).export(ScanResult(started_at=started))
    meta = json.loads(path.read_text())["metadata"]
    assert meta["started_at"] == "2026-10-09T08:30:15"
    assert meta["completed_at"] is None
    assert datetime.fromisoformat(meta["started_at"]) == started

    done = datetime(2026, 10, 9, 9, 0, 0, 123456)
    path = JSONExporter(output_dir=str(tmp_path)).export(
        ScanResult(started_at=started, completed_at=done)
    )
    meta = json.loads(path.read_text())["metadata"]
    assert datetime.fromisoformat(meta["completed_at"]) == done
    assert meta["provider"] is None and meta["account_id"] is None
