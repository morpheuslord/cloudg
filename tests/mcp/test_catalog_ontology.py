"""Ontology / SPARQL / RAG tools."""

from __future__ import annotations

import pytest

from cloudg.mcp.catalog.ontology import prepare_readonly
from cloudg.mcp.core import InvalidArgumentsError


async def test_ontology_stats(call, layer):
    out = await call("ontology_stats")
    assert out["built_now"] is True and out["total_triples"] > 100
    assert out["relation_group_counts"]
    out = await call("ontology_stats")
    assert out["built_now"] is False


async def test_ontology_progress_reported(layer):
    seen = []
    ctx = layer.context()
    ctx.progress_callback = lambda p, t, m: seen.append((p, t, m))
    import asyncio

    ctx.loop = asyncio.get_running_loop()
    await layer.call_tool("ontology_stats", {}, context=ctx)
    await asyncio.sleep(0.05)
    assert seen and seen[-1][0] == 1


async def test_sparql_select_ask_construct(call):
    q = ("SELECT ?r ?name WHERE { ?s cmp:INTERNET_REACHABLE ?r . ?r cmp:hasName ?name } "
         "ORDER BY ?name")
    out = await call("sparql_query", query=q)
    assert out["query_type"] == "SelectQuery"
    names = {r["name"] for r in out["rows"]}
    assert {"web-alb", "public-api"} <= names
    assert all(r["r"].startswith("cmr:") for r in out["rows"])
    out = await call("sparql_query", query=q, compact_uris=False)
    assert out["rows"][0]["r"].startswith("https://cloudg.io/resource/")
    out = await call("sparql_query", query="SELECT ?s WHERE { ?s ?p ?o }", limit=3)
    assert out["returned"] == 3 and out["truncated"] and "hint" in out
    out = await call("sparql_query", query="ASK { ?s a cm:RelationalDatabase }")
    assert out["answer"] is True
    out = await call("sparql_query",
                     query="CONSTRUCT { ?s cmp:hasName ?n } WHERE { ?s cmp:hasName ?n } LIMIT 2")
    assert out["returned"] == 2 and set(out["rows"][0]) == {"subject", "predicate", "object"}
    out = await call("sparql_query", query='SELECT ?from WHERE { ?from cmp:hasName "web-1" }')
    assert out["returned"] == 1  # a variable named ?from is fine


@pytest.mark.parametrize("query,needle", [
    ("INSERT DATA { cmr:x cmp:hasName 'x' }", "read-only"),
    ("PREFIX ex: <http://e/> DELETE WHERE { ?s ?p ?o }", "read-only"),
    ("DROP ALL", "read-only"),
    ("SELECT ?s FROM <http://evil.example/data.ttl> WHERE { ?s ?p ?o }", "FROM"),
    ("SELECT ?s WHERE { SERVICE <http://evil.example/sparql> { ?s ?p ?o } }", "SERVICE"),
    ("SELEKT nonsense", "parse error"),
])
async def test_sparql_rejections(call, query, needle):
    msg = await call.error("sparql_query", query=query)
    assert needle in msg


def test_prepare_readonly_allows_strings_with_keywords():
    prepare_readonly('SELECT ?s WHERE { ?s cmp:hasName "delete me # not a comment" }')
    with pytest.raises(InvalidArgumentsError):
        prepare_readonly("LOAD <http://x>")


async def test_ontology_neighbourhood(call):
    out = await call("ontology_neighbourhood", ref="orders-db")
    preds = set(out["predicates"])
    assert "FINDING_AFFECTS" in preds or "ENCRYPTED_BY_KMS" in preds
    assert all(t["depth"] == 1 for t in out["triples"])
    deeper = await call("ontology_neighbourhood", ref="orders-db", hops=2)
    assert deeper["returned"] >= out["returned"]
    small = await call("ontology_neighbourhood", ref="orders-db", hops=3, limit=2)
    assert small["truncated"] and small["returned"] == 2
    assert "Did you mean" in await call.error("ontology_neighbourhood", ref="orders-dbx")


async def test_relation_groups(call):
    out = await call("relation_groups")
    assert set(out["groups"]) == {"NETWORK", "CONTAINMENT", "IAM", "DATA_FLOW", "SECURITY",
                                  "COMPUTE", "GOVERNANCE"}
    assert out["groups"]["IAM"]["total"] >= 1
    out = await call("relation_groups", group="iam", limit=2)
    assert out["group"] == "IAM" and "CROSS_ACCOUNT_TRUST" in out["relation_types"]
    assert out["total"] >= 1
    assert "relation group" in await call.error("relation_groups", group="FINANCE")


@pytest.mark.parametrize("chunk_type", ["entity", "community", "relation_group"])
async def test_rag_chunks(call, chunk_type):
    out = await call("rag_chunks", chunk_type=chunk_type, limit=2)
    assert out["items"] and out["items"][0]["chunk_type"] == chunk_type
    assert out["items"][0]["content"]


async def test_rag_chunk_filters(call):
    out = await call("rag_chunks", ref="web-1")
    assert [i["chunk_id"] for i in out["items"]] == ["entity::web-1"]
    out = await call("rag_chunks", min_severity="CRITICAL")
    assert {i["chunk_id"] for i in out["items"]} == {"entity::sg-admin", "entity::az-nsg"}
    out = await call("rag_chunks", query="api-handler", limit=1)
    assert out["returned"] == 1 and out["next_cursor"]
    assert "severity" in await call.error("rag_chunks", min_severity="NOPE")


@pytest.mark.parametrize("fmt,ext", [("turtle", "ttl"), ("json-ld", "jsonld"), ("xml", "rdf"),
                                     ("nt", "nt")])
async def test_export_ontology(call, workspace, fmt, ext):
    out = await call("export_ontology", format=fmt, filename="onto")
    assert out["path"].endswith(f"onto.{ext}") and out["bytes"] > 100
    assert out["path"].startswith(str(workspace.output_root))


async def test_export_ontology_rejects_paths(call):
    assert "filename" in await call.error("export_ontology", filename="../escape")
