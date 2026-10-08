"""Ontology and RAG tools: the RDF/OWL knowledge graph cloudg builds from a
dataset (~60 typed relations in 7 groups), read-only SPARQL over it, an
asset's semantic neighbourhood, relation-group views, RAG-ready chunks and
ontology export.

The ontology is built lazily on first use and cached per dataset; on large
maps the first call can take a while.
"""

from __future__ import annotations

import re
from collections import deque
from typing import Annotated, Any, Literal

from pydantic import Field

from cloudg.mcp.catalog._common import (
    Catalog,
    Cursor,
    DatasetArg,
    RefArg,
    SparqlOut,
    asset_uri,
    fingerprint,
    paginate,
    parse_enum,
    schema,
    ws_dataset,
)
from cloudg.mcp.core import Capability, InvalidArgumentsError, Registry, Sensitivity

CATEGORY = "ontology"
R, FS = Capability.READ_STATE, Capability.WRITE_FS

OntologyFormat = Literal["turtle", "json-ld", "xml", "nt"]
ChunkType = Literal["entity", "community", "relation_group"]
FORMAT_EXT = {"turtle": "ttl", "json-ld": "jsonld", "xml": "rdf", "nt": "nt"}
FORMAT_MIME = {
    "turtle": "text/turtle",
    "json-ld": "application/ld+json",
    "xml": "application/rdf+xml",
    "nt": "application/n-triples",
}
_FORBIDDEN_NODES = {"ServiceGraphPattern"}
_STRING_LIT = re.compile(r"(\"\"\".*?\"\"\"|'''.*?'''|\"(?:\\.|[^\"\\])*\"|'(?:\\.|[^'\\])*')",
                         re.S)
_COMMENT = re.compile(r"#[^\n]*")
_UPDATE_START = re.compile(
    r"^\s*(?:(?:PREFIX\s+\S*\s*<[^>]*>|BASE\s*<[^>]*>)\s*)*"
    r"(INSERT|DELETE|LOAD|CLEAR|DROP|CREATE|ADD|MOVE|COPY|WITH)\b",
    re.I,
)
_DATA_PROPS = {"hasName", "hasARN", "hasRegion", "hasProvider", "hasAccountId", "hasCIDR",
               "hasPort", "hasProtocol", "hasSeverity", "hasRiskScore", "isInternetExposed"}


def namespaces() -> dict[str, Any]:
    from rdflib.namespace import OWL, RDF, RDFS, XSD

    from cloudg.graph.ontology import CM, CMP, CMR

    return {"cm": CM, "cmr": CMR, "cmp": CMP, "rdf": RDF, "rdfs": RDFS, "owl": OWL, "xsd": XSD}


def compact(term: Any) -> str:
    s = str(term)
    for prefix, ns in namespaces().items():
        if s.startswith(str(ns)):
            return f"{prefix}:{s[len(str(ns)):]}"
    return s


def _walk(node: Any) -> Any:
    from rdflib.plugins.sparql.parserutils import CompValue

    if isinstance(node, CompValue):
        yield node.name
        for v in node.values():
            yield from _walk(v)
    elif isinstance(node, (list, tuple)):
        for v in node:
            yield from _walk(v)


def prepare_readonly(query: str) -> Any:
    """Parse a SPARQL query and refuse anything that is not a local,
    read-only SELECT / ASK / CONSTRUCT / DESCRIBE."""
    from rdflib.plugins.sparql import prepareQuery

    stripped = _COMMENT.sub(" ", _STRING_LIT.sub('""', query))
    if _UPDATE_START.match(stripped):
        raise InvalidArgumentsError("Only read-only queries are allowed (SELECT, ASK, "
                                    "CONSTRUCT, DESCRIBE); SPARQL UPDATE is rejected.")
    try:
        prepared = prepareQuery(query, initNs=namespaces())
    except Exception as exc:
        msg = str(exc).splitlines()[0][:300]
        raise InvalidArgumentsError(
            f"SPARQL parse error: {msg}. Only SELECT / ASK / CONSTRUCT / DESCRIBE are allowed; "
            "prefixes cm:, cmr:, cmp:, rdf:, rdfs:, owl:, xsd: are predefined."
        ) from None
    algebra = prepared.algebra
    if algebra.get("datasetClause"):
        raise InvalidArgumentsError("FROM / FROM NAMED clauses are not allowed (they would load "
                                    "external data). Query the dataset's graph directly.")
    if _FORBIDDEN_NODES & set(_walk(algebra)):
        raise InvalidArgumentsError("SERVICE (federated queries to remote endpoints) is not "
                                    "allowed.")
    return prepared


def _ontology(ctx: Any, ds: Any) -> Any:
    """The dataset's ontology, reporting progress while building it."""
    if not ds.has_ontology():
        sync = getattr(ctx, "report_progress_sync", None)
        if sync:
            sync(0, 1, f"building ontology for {len(ds.assets)} assets")
        onto = ds.ontology()
        if sync:
            sync(1, 1, "ontology built")
        return onto
    return ds.ontology()

CATALOG = Catalog()

_RO = dict(read_only=True, idempotent=True, open_world=False, category=CATEGORY)

@CATALOG.tool(title="Ontology statistics", sensitivity=Sensitivity.INTERNAL, **_RO)
def ontology_stats(ctx: Any, dataset: DatasetArg = "") -> dict:
    """Size and shape of the dataset's RDF ontology: triples, classes,
    individuals, and counts per relation type and relation group (builds
    the ontology on first call)."""
    ds = ws_dataset(ctx, dataset)
    built = not ds.has_ontology()
    stats = _ontology(ctx, ds).stats()
    ctx.link("cloudg://ontology/turtle", "ontology (turtle)", mime_type="text/turtle")
    return {"dataset": ds.name, "built_now": built, **stats}

@CATALOG.tool(title="SPARQL query", sensitivity=Sensitivity.CONFIDENTIAL,
          output_schema=schema(SparqlOut), timeout_seconds=120, **_RO)
def sparql_query(
    ctx: Any,
    query: Annotated[str, Field(min_length=1, max_length=20_000, description=(
        "Read-only SPARQL (SELECT / ASK / CONSTRUCT / DESCRIBE). Predefined prefixes: "
        "cm: (classes, e.g. cm:RelationalDatabase), cmp: (relations / properties, e.g. "
        "cmp:INTERNET_REACHABLE, cmp:hasName), cmr: (individuals, cmr:<asset id>), rdf:, "
        "rdfs:, owl:, xsd:. FROM, SERVICE and UPDATE are rejected."))],
    limit: Annotated[int, Field(ge=1, le=1000)] = 100,
    compact_uris: Annotated[bool, Field(description="Shorten URIs to prefix:name.")] = True,
    dataset: DatasetArg = "",
) -> dict:
    """Run a read-only SPARQL query against the dataset's ontology.
    Example (internet-reachable databases):
    SELECT ?r ?name WHERE { ?s cmp:INTERNET_REACHABLE ?r . ?r a
    cm:RelationalDatabase ; cmp:hasName ?name }"""
    prepared = prepare_readonly(query)
    ds = ws_dataset(ctx, dataset)
    g = _ontology(ctx, ds).graph
    res = g.query(prepared)
    qtype = prepared.algebra.name
    fmt = compact if compact_uris else str
    out: dict[str, Any] = {"dataset": ds.name, "query_type": qtype}
    if qtype == "AskQuery":
        out.update(answer=bool(res.askAnswer), rows=[], returned=0, truncated=False)
        return out
    rows: list[dict[str, Any]] = []
    truncated = False
    if qtype == "SelectQuery":
        for row in res:
            if len(rows) >= limit:
                truncated = True
                break
            rows.append({str(var): (fmt(val) if val is not None else None)
                         for var, val in zip(res.vars, row)})
    else:  # CONSTRUCT / DESCRIBE -> triples
        for s, p, o in res:
            if len(rows) >= limit:
                truncated = True
                break
            rows.append({"subject": fmt(s), "predicate": fmt(p), "object": fmt(o)})
    out.update(rows=rows, returned=len(rows), truncated=truncated)
    if truncated:
        out["hint"] = "More rows exist: add LIMIT / OFFSET to the query or raise limit."
    return out

@CATALOG.tool(title="Ontology neighbourhood", sensitivity=Sensitivity.CONFIDENTIAL, **_RO)
def ontology_neighbourhood(
    ctx: Any,
    ref: RefArg,
    hops: Annotated[int, Field(ge=1, le=3)] = 1,
    limit: Annotated[int, Field(ge=1, le=500)] = 100,
    dataset: DatasetArg = "",
) -> dict:
    """Semantic relations around an asset in the ontology (e.g.
    PROTECTED_BY_SG, ENCRYPTED_BY_KMS, INTERNET_REACHABLE,
    FINDING_AFFECTS, TAGGED_WITH), up to `hops` away, as
    subject-predicate-object triples with names."""
    from rdflib import URIRef

    from cloudg.graph.ontology import CMP, CMR

    ds = ws_dataset(ctx, dataset)
    a = ds.resolve_asset(ref)
    g = _ontology(ctx, ds).graph
    cmp_ns = str(CMP)
    name_p = CMP["hasName"]

    def name(node: Any) -> str:
        n = g.value(node, name_p)
        return str(n) if n is not None else compact(node)

    start = CMR[a.id]
    seen = {start}
    triples: list[dict[str, Any]] = []
    queue: deque[tuple[Any, int]] = deque([(start, 0)])
    truncated = False
    while queue and not truncated:
        node, depth = queue.popleft()
        if depth >= hops:
            continue
        edges = [(node, p, o, o) for p, o in g.predicate_objects(node)]
        edges += [(s, p, node, s) for s, p in g.subject_predicates(node)]
        for s, p, o, other in edges:
            ps = str(p)
            if not ps.startswith(cmp_ns) or ps[len(cmp_ns):] in _DATA_PROPS:
                continue
            if not isinstance(other, URIRef):
                continue
            if len(triples) >= limit:
                truncated = True
                break
            triples.append({"subject": name(s), "predicate": ps[len(cmp_ns):],
                            "object": name(o), "depth": depth + 1,
                            "subject_id": compact(s), "object_id": compact(o)})
            if other not in seen:
                seen.add(other)
                queue.append((other, depth + 1))
    preds: dict[str, int] = {}
    for t in triples:
        preds[t["predicate"]] = preds.get(t["predicate"], 0) + 1
    ctx.link(asset_uri(a.id), a.name)
    return {"dataset": ds.name, "asset": {"id": a.id, "name": a.name,
                                          "type": a.asset_type.value},
            "predicates": preds, "triples": triples, "returned": len(triples),
            "truncated": truncated}

@CATALOG.tool(title="Relation groups", sensitivity=Sensitivity.CONFIDENTIAL, **_RO)
def relation_groups(
    ctx: Any,
    group: Annotated[str, Field(description="NETWORK, CONTAINMENT, IAM, DATA_FLOW, "
                                "SECURITY, COMPUTE or GOVERNANCE; empty = overview.")] = "",
    limit: Annotated[int, Field(ge=1, le=500)] = 100,
    cursor: Cursor = "",
    dataset: DatasetArg = "",
) -> dict:
    """Without group: counts of every semantic relation group and type in
    the dataset's ontology. With group: the triples of that group (e.g.
    every IAM relation: ROLE_ASSUMES_ROLE, CROSS_ACCOUNT_TRUST...),
    paginated."""
    from cloudg.graph.ontology import RelationGroup, get_relations_for_group

    ds = ws_dataset(ctx, dataset)
    onto = _ontology(ctx, ds)
    if not group:
        stats = ds.cached("ontology_stats", onto.stats)
        groups = {}
        for g in RelationGroup:
            types = {rt.value: stats["relation_type_counts"].get(rt.value, 0)
                     for rt in get_relations_for_group(g)}
            groups[g.value] = {"total": stats["relation_group_counts"].get(g.value, 0),
                               "types": {k: v for k, v in types.items() if v}}
        return {"dataset": ds.name, "groups": groups}
    grp = parse_enum(group, RelationGroup, "relation group")
    rows = ds.cached(f"relgroup:{grp.value}", lambda: onto.query_by_relation_group(grp))
    rows = [{k: compact(v) if k in ("src", "tgt") else v for k, v in r.items()} for r in rows]
    page, env = paginate(rows, limit, cursor, fingerprint(ds, g=grp.value))
    return {"dataset": ds.name, "group": grp.value,
            "relation_types": [rt.value for rt in get_relations_for_group(grp)],
            **env, "items": page}

@CATALOG.tool(title="RAG chunks", sensitivity=Sensitivity.CONFIDENTIAL, **_RO)
def rag_chunks(
    ctx: Any,
    chunk_type: ChunkType = "entity",
    ref: Annotated[str, Field(description="Entity chunks: only this asset's chunk.")] = "",
    query: Annotated[str, Field(description="Substring of chunk content.")] = "",
    min_severity: Annotated[str, Field(description="Entity chunks: severity_max at or "
                                       "above.")] = "",
    limit: Annotated[int, Field(ge=1, le=100)] = 10,
    cursor: Cursor = "",
    dataset: DatasetArg = "",
) -> dict:
    """Retrieval-ready text chunks with metadata: entity (one per asset
    with its relations and findings), community (Louvain clusters of
    tightly-connected resources with risk), relation_group (all triples
    of a semantic group). Good context for summarising an area."""
    from cloudg.mcp.state import SEVERITY_RANK

    ds = ws_dataset(ctx, dataset)
    chunks = ds.rag_chunks(chunk_type)
    q = query.lower()
    aid = ds.resolve_asset(ref).id if ref else None
    rank = SEVERITY_RANK[min_severity.upper()] if min_severity.upper() in SEVERITY_RANK \
        else None
    if min_severity and rank is None:
        raise InvalidArgumentsError(f"Unknown severity {min_severity!r}.")
    sel = []
    for c in chunks:
        if aid and c.chunk_id != f"entity::{aid}":
            continue
        if q and q not in c.content.lower():
            continue
        if rank is not None and SEVERITY_RANK.get(c.metadata.get("severity_max", ""), -1) \
                < rank:
            continue
        sel.append(c)
    page, env = paginate(sel, limit, cursor,
                         fingerprint(ds, t=chunk_type, r=aid, q=q, s=min_severity))
    return {"dataset": ds.name, "chunk_type": chunk_type, **env,
            "items": [{"chunk_id": c.chunk_id, "chunk_type": c.chunk_type,
                       "content": c.content, "metadata": c.metadata} for c in page]}

@CATALOG.tool(title="Export ontology", category=CATEGORY, sensitivity=Sensitivity.CONFIDENTIAL,
          capabilities={R, FS}, read_only=False, destructive=False, idempotent=True,
          open_world=False)
def export_ontology(
    ctx: Any,
    format: OntologyFormat = "turtle",
    filename: Annotated[str, Field(pattern=r"^[A-Za-z0-9_.\-]{1,100}$",
                                   description="File name (no directories); extension "
                                   "added if missing.")] = "ontology",
    dataset: DatasetArg = "",
) -> dict:
    """Write the dataset's ontology to the workspace output directory as
    Turtle, JSON-LD, RDF/XML or N-Triples. Returns the path; read the
    cloudg://ontology/{format} resource instead to get the content
    without writing a file."""
    ds = ws_dataset(ctx, dataset)
    ext = FORMAT_EXT[format]
    name = filename if filename.endswith(f".{ext}") else f"{filename}.{ext}"
    path = ctx.workspace.output_path(name)
    onto = _ontology(ctx, ds)
    onto.save(path, fmt=format)
    ctx.link(f"cloudg://ontology/{format}", f"ontology ({format})",
             mime_type=FORMAT_MIME[format])
    return {"dataset": ds.name, "path": str(path), "format": format,
            "triples": onto.triple_count, "bytes": path.stat().st_size}


def register(reg: Registry) -> None:
    """Add this module's tools to ``reg``."""
    CATALOG.register(reg)
