"""Read-only SPARQL for the ontology tools: query vetting and bounded
result collection.

Vetting refuses SPARQL UPDATE, FROM / FROM NAMED and SERVICE before the
query reaches rdflib. The UPDATE check is a linear scan of the query's
prologue (no backtracking regular expression), so a hostile query string
cannot stall it.

Result collection is bounded: rows are read one at a time and the read
stops at ``limit`` rows or when the deadline passes. rdflib evaluates
SELECT patterns lazily, so a query whose pattern multiplies out (a
cartesian product of unrelated triple patterns) stops after the first
``limit`` rows instead of enumerating every combination. Clauses that
need the whole solution set first (ORDER BY, GROUP BY / aggregates,
DISTINCT over a large set) and CONSTRUCT / DESCRIBE, which rdflib builds
eagerly, are only bounded by the tool's ``timeout_seconds``.
"""

from __future__ import annotations

import re
import time
from typing import Any, Callable, Iterable

from cloudg.mcp.core import InvalidArgumentsError

QUERY_DEADLINE_S = 60.0

_FORBIDDEN_NODES = {"ServiceGraphPattern"}
_COMMENT = re.compile(r"#[^\n]*")
_UPDATE_KEYWORDS = frozenset(
    {"INSERT", "DELETE", "LOAD", "CLEAR", "DROP", "CREATE", "ADD", "MOVE", "COPY", "WITH"}
)
_PROLOGUE_KEYWORDS = frozenset({"PREFIX", "BASE"})


def namespaces() -> dict[str, Any]:
    from rdflib.namespace import OWL, RDF, RDFS, XSD

    from cloudg.graph.ontology import CM, CMP, CMR

    return {"cm": CM, "cmr": CMR, "cmp": CMP, "rdf": RDF, "rdfs": RDFS, "owl": OWL, "xsd": XSD}


def compact(term: Any) -> str:
    s = str(term)
    for prefix, ns in namespaces().items():
        if s.startswith(str(ns)):
            return f"{prefix}:{s[len(str(ns)) :]}"
    return s


def _skip_space(text: str, i: int) -> int:
    while i < len(text) and text[i].isspace():
        i += 1
    return i


def _word_end(text: str, i: int) -> int:
    while i < len(text) and text[i].isalpha():
        i += 1
    return i


def first_keyword(text: str) -> str:
    """The first keyword after the PREFIX / BASE prologue, upper-cased.

    Each PREFIX / BASE declaration is skipped up to the ``>`` that closes
    its IRI. The scan only moves forward, so it is linear in the length of
    ``text``."""
    i = 0
    while True:
        i = _skip_space(text, i)
        end = _word_end(text, i)
        word = text[i:end].upper()
        if word not in _PROLOGUE_KEYWORDS:
            return word
        close = text.find(">", end)
        if close < 0:
            return ""
        i = close + 1


def _walk(node: Any) -> Any:
    from rdflib.plugins.sparql.parserutils import CompValue

    if isinstance(node, CompValue):
        yield node.name
        for v in node.values():
            yield from _walk(v)
    elif isinstance(node, (list, tuple)):
        for v in node:
            yield from _walk(v)


def _literal_end(query: str, start: int, unterminated: set[str]) -> int:
    """End of the string literal opening at ``start``, or -1 when none
    does. ``unterminated`` remembers the quote forms already known to have
    no closing quote further on, so no stretch of the query is scanned
    twice for the same form."""
    quote = query[start]
    triple = quote * 3
    if query.startswith(triple, start) and triple not in unterminated:
        close = query.find(triple, start + 3)
        if close >= 0:
            return close + 3
        unterminated.add(triple)
    if quote in unterminated:
        return -1
    pos = start + 1
    while pos < len(query):
        char = query[pos]
        if char == "\\":
            pos += 2
        elif char == quote:
            return pos + 1
        else:
            pos += 1
    unterminated.add(quote)
    return -1


def _blank_strings(query: str) -> str:
    """``query`` with every SPARQL string literal (``"..."``, ``'...'`` and
    their triple-quoted forms) replaced by ``""``, in linear time. A regular
    expression doing the same backtracks quadratically on a query full of
    unterminated quotes."""
    out: list[str] = []
    pos = 0
    unterminated: set[str] = set()
    while pos < len(query):
        end = _literal_end(query, pos, unterminated) if query[pos] in "\"'" else -1
        if end < 0:
            out.append(query[pos])
            pos += 1
        else:
            out.append('""')
            pos = end
    return "".join(out)


def prepare_readonly(query: str) -> Any:
    """Parse a SPARQL query and refuse anything that is not a local,
    read-only SELECT / ASK / CONSTRUCT / DESCRIBE."""
    from rdflib.plugins.sparql import prepareQuery

    stripped = _COMMENT.sub(" ", _blank_strings(query))
    if first_keyword(stripped) in _UPDATE_KEYWORDS:
        raise InvalidArgumentsError(
            "Only read-only queries are allowed (SELECT, ASK, "
            "CONSTRUCT, DESCRIBE); SPARQL UPDATE is rejected."
        )
    try:
        prepared = prepareQuery(query, initNs=namespaces())
    except Exception as exc:  # rdflib raises pyparsing / ValueError / custom errors
        msg = str(exc).splitlines()[0][:300]
        raise InvalidArgumentsError(
            f"SPARQL parse error: {msg}. Only SELECT / ASK / CONSTRUCT / DESCRIBE are allowed; "
            "prefixes cm:, cmr:, cmp:, rdf:, rdfs:, owl:, xsd: are predefined."
        ) from None
    algebra = prepared.algebra
    if algebra.get("datasetClause"):
        raise InvalidArgumentsError(
            "FROM / FROM NAMED clauses are not allowed (they would load "
            "external data). Query the dataset's graph directly."
        )
    if _FORBIDDEN_NODES & set(_walk(algebra)):
        raise InvalidArgumentsError(
            "SERVICE (federated queries to remote endpoints) is not allowed."
        )
    return prepared


def collect(
    rows: Iterable[Any],
    limit: int,
    convert: Callable[[Any], dict[str, Any]],
    deadline: float,
) -> tuple[list[dict[str, Any]], bool, bool]:
    """Read at most ``limit`` converted rows before ``deadline``
    (``time.monotonic()``). Returns (rows, truncated, timed_out)."""
    out: list[dict[str, Any]] = []
    for row in rows:
        if len(out) >= limit:
            return out, True, False
        if time.monotonic() > deadline:
            return out, True, True
        out.append(convert(row))
    return out, False, False


def _kind(val: Any) -> str:
    from rdflib import BNode, Literal

    if isinstance(val, Literal):
        return "literal"
    if isinstance(val, BNode):
        return "bnode"
    return "uri"


def run_query(g: Any, prepared: Any, limit: int, compact_uris: bool) -> dict[str, Any]:
    """Execute a vetted query with the row cap and deadline described in
    the module docstring."""
    res = g.query(prepared)
    qtype = prepared.algebra.name
    if qtype == "AskQuery":
        return {
            "query_type": qtype,
            "answer": bool(res.askAnswer),
            "rows": [],
            "returned": 0,
            "truncated": False,
        }
    fmt = compact if compact_uris else str
    deadline = time.monotonic() + QUERY_DEADLINE_S
    kinds: dict[str, str] = {}
    if qtype == "SelectQuery":
        names = [str(v) for v in res.vars]

        def convert(row: Any) -> dict[str, Any]:
            for name, val in zip(names, row):
                if val is not None:
                    kinds.setdefault(name, _kind(val))
            return {n: (fmt(v) if v is not None else None) for n, v in zip(names, row)}

        rows, truncated, timed_out = collect(res, limit, convert, deadline)
    else:  # CONSTRUCT / DESCRIBE -> triples
        kinds = {"subject": "uri", "predicate": "uri", "object": "term"}
        rows, truncated, timed_out = collect(
            res,
            limit,
            lambda t: {"subject": fmt(t[0]), "predicate": fmt(t[1]), "object": fmt(t[2])},
            deadline,
        )
    out: dict[str, Any] = {
        "query_type": qtype,
        "rows": rows,
        "returned": len(rows),
        "truncated": truncated,
        "variable_kinds": kinds,
    }
    if timed_out:
        out["hint"] = f"Stopped after {QUERY_DEADLINE_S:.0f}s. Narrow the patterns or add LIMIT."
    elif truncated:
        out["hint"] = "More rows exist: add LIMIT / OFFSET to the query or raise limit."
    return out
