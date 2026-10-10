"""Text and sizing of RAG chunks: the line builders and the token budget
:class:`cloudg.graph.rag_export.RAGExporter` uses."""

from __future__ import annotations

import json
from collections import defaultdict
from typing import Any

import networkx as nx

from cloudg.graph.ontology import (
    RelationGroup,
    get_relation_group,
    infer_relations,
    iter_asset_relations,
)
from cloudg.inventory.dependencies import AssetIndex
from cloudg.schema.models import (
    CloudAsset,
    Finding,
    NetworkEdge,
    Severity,
)


_SEVERITY_ORDER = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFO: 4,
}
_SEVERITY_RANK = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4, "NONE": 5}


def _index_findings(
    findings: list[Finding] | None, index: AssetIndex | None = None
) -> dict[str, list[Finding]]:
    """Group findings by the asset ID they resolve to.

    ``index`` matches a finding by ID, ARN, unique name, unique ARN tail
    or unique ARN resource-part tail (:meth:`AssetIndex.resolve_finding`);
    findings it cannot place stay keyed by their raw resource_id.
    """
    findings_by_resource: dict[str, list[Finding]] = defaultdict(list)
    if findings:
        for f in findings:
            asset_id = index.resolve_finding(f) if index else None
            findings_by_resource[asset_id or f.resource_id].append(f)
    return findings_by_resource


def _graph_index(
    graph: nx.DiGraph, assets_by_id: dict[str, CloudAsset] | None = None
) -> AssetIndex:
    """Asset index over a graph's nodes, plus any known assets.

    External placeholder nodes are indexed by ID only: their name is
    the ID itself and says nothing about which asset a finding targets.
    """
    index = AssetIndex()
    for node_id, data in graph.nodes(data=True):
        if data.get("is_external"):
            index.add(node_id)
        else:
            index.add(node_id, data.get("arn"), data.get("name"))
    for asset in (assets_by_id or {}).values():
        index.add(asset.id, asset.arn, asset.name)
    return index


# Rough size of one token for chunk budgets: about 4 characters of
# English or identifier text per token for common embedding tokenizers.
CHARS_PER_TOKEN = 4

# Room kept for one "... and N more" line per cut list
_MORE_LINE_RESERVE = 24

CHUNK_STRATEGIES: tuple[str, ...] = ("entity", "community", "relation_group", "hybrid")


def _line_cost(lines: list[str]) -> int:
    """Characters ``lines`` add to a chunk's content (one newline each)."""
    return sum(len(line) + 1 for line in lines)


def _fit_sections(fixed: list[str], sections: list[list[str]], budget: int) -> list[int]:
    """How many lines of each section fit into ``budget`` characters.

    ``fixed`` lines are always kept. When everything fits, every line of
    every section is kept. Otherwise the sections take turns adding their
    next line, so a long list cannot crowd out a short one, and a section
    stops at the first line that does not fit (lines are never skipped).
    Room for an ``... and N more`` line per section is set aside first.
    """
    full = [len(section) for section in sections]
    if _line_cost(fixed) + sum(_line_cost(s) for s in sections) <= budget:
        return full
    avail = budget - _line_cost(fixed) - _MORE_LINE_RESERVE * len(sections)
    counts = [0] * len(sections)
    open_ = [bool(section) for section in sections]
    while any(open_):
        for i, section in enumerate(sections):
            if not open_[i]:
                continue
            cost = len(section[counts[i]]) + 1
            if cost > avail:
                open_[i] = False
                continue
            avail -= cost
            counts[i] += 1
            if counts[i] == len(section):
                open_[i] = False
    return counts


def _cut(section: list[str], count: int) -> list[str]:
    """The first ``count`` lines of ``section`` plus a line for the rest."""
    if count >= len(section):
        return section
    return [*section[:count], f"  ... and {len(section) - count} more"]


def _entity_header_lines(asset: CloudAsset) -> list[str]:
    """Build the base descriptive lines for an entity chunk."""
    content_lines = [
        f"Resource: {asset.name}",
        f"Type: {asset.asset_type.value}",
        f"Provider: {asset.provider.value}",
        f"Region: {asset.region}",
    ]
    if asset.arn:
        content_lines.append(f"ARN: {asset.arn}")
    if asset.account_id:
        content_lines.append(f"Account: {asset.account_id}")
    if asset.is_internet_exposed:
        content_lines.append("⚠ INTERNET EXPOSED")
    if asset.tags:
        content_lines.append(f"Tags: {json.dumps(asset.tags)}")
    return content_lines


def _edge_evidence(edge: NetworkEdge) -> str:
    """Format an edge's port/protocol/cidr details as evidence text."""
    evidence_parts = []
    if edge.port_range:
        evidence_parts.append(f"port {edge.port_range}")
    if edge.protocol:
        evidence_parts.append(edge.protocol)
    if edge.cidr:
        evidence_parts.append(f"cidr {edge.cidr}")
    return ", ".join(evidence_parts) if evidence_parts else ""


def _entity_relations(
    asset: CloudAsset,
    assets_by_id: dict[str, CloudAsset],
    outgoing: dict[str, list[NetworkEdge]],
    incoming: dict[str, list[NetworkEdge]],
) -> list[dict[str, str]]:
    """Collect inferred relations for an asset's 1-hop neighbourhood."""
    chunk_relations: list[dict[str, str]] = []

    # Outgoing edges
    for edge in outgoing.get(asset.id, []):
        tgt_name = assets_by_id.get(edge.target_id, None)
        tgt_label = tgt_name.name if tgt_name else edge.target_id
        for rel in infer_relations(edge, assets_by_id):
            chunk_relations.append(
                {
                    "predicate": rel.value,
                    "direction": "outgoing",
                    "object": tgt_label,
                    "object_id": edge.target_id,
                    "evidence": _edge_evidence(edge),
                }
            )

    # Incoming edges
    for edge in incoming.get(asset.id, []):
        src_name = assets_by_id.get(edge.source_id, None)
        src_label = src_name.name if src_name else edge.source_id
        for rel in infer_relations(edge, assets_by_id):
            chunk_relations.append(
                {
                    "predicate": rel.value,
                    "direction": "incoming",
                    "object": src_label,
                    "object_id": edge.source_id,
                    "evidence": "",
                }
            )

    return chunk_relations


def _entity_findings_lines(
    resource_findings: list[Finding],
) -> tuple[list[str], str, set[str]]:
    """Render one line per finding, most severe first.

    Returns (lines, max severity, compliance frameworks of all findings).
    """
    if not resource_findings:
        return [], "NONE", set()

    sorted_findings = sorted(resource_findings, key=lambda f: _SEVERITY_ORDER.get(f.severity, 5))
    severity_max = sorted_findings[0].severity.value
    compliance_frameworks: set[str] = set()
    lines: list[str] = []
    for f in sorted_findings:
        lines.append(f"  [{f.severity.value}] {f.title}")
        compliance_frameworks.update(f.compliance_frameworks)
    return lines, severity_max, compliance_frameworks


def _summarize_community_members(
    graph: nx.DiGraph,
    members: list[str],
    findings_by_resource: dict[str, list[Finding]],
) -> dict[str, Any]:
    """Aggregate per-member stats and summary lines for a community."""
    type_counts: dict[str, int] = defaultdict(int)
    member_lines: list[str] = []
    total_findings = 0
    max_severity = "NONE"
    frameworks: set[str] = set()
    exposed_count = 0

    for node_id in members:
        node_data = graph.nodes.get(node_id, {})
        asset_type = node_data.get("asset_type", "UNKNOWN")
        type_counts[asset_type] += 1

        if node_data.get("is_internet_exposed"):
            exposed_count += 1

        name = node_data.get("name", node_id)
        member_lines.append(f"  • {name} ({asset_type})")

        for f in findings_by_resource.get(node_id, []):
            total_findings += 1
            if _SEVERITY_RANK.get(f.severity.value, 5) < _SEVERITY_RANK.get(max_severity, 5):
                max_severity = f.severity.value
            frameworks.update(f.compliance_frameworks)

    return {
        "type_counts": type_counts,
        "member_lines": member_lines,
        "total_findings": total_findings,
        "max_severity": max_severity,
        "frameworks": frameworks,
        "exposed_count": exposed_count,
    }


def _count_community_edges(graph: nx.DiGraph, member_set: set[str]) -> tuple[int, int]:
    """Count a community's internal vs external edges."""
    internal_edges = 0
    external_edges = 0
    for u, v in graph.edges():
        if u in member_set and v in member_set:
            internal_edges += 1
        elif u in member_set or v in member_set:
            external_edges += 1
    return internal_edges, external_edges


def _label(asset_id: str, assets_by_id: dict[str, CloudAsset]) -> str:
    """Display name of an asset id, or the id itself when it is not an asset."""
    asset = assets_by_id.get(asset_id)
    return asset.name if asset else asset_id


def _triple(
    subject_id: str, predicate: str, object_id: str, assets_by_id: dict[str, CloudAsset]
) -> dict[str, str]:
    """A relation triple with display labels and empty edge evidence."""
    return {
        "subject": _label(subject_id, assets_by_id),
        "subject_id": subject_id,
        "predicate": predicate,
        "object": _label(object_id, assets_by_id),
        "object_id": object_id,
        "port_range": "",
        "protocol": "",
        "cidr": "",
    }


def _group_relation_triples(
    edges: list[NetworkEdge],
    assets_by_id: dict[str, CloudAsset],
) -> dict[RelationGroup, list[dict[str, str]]]:
    """Group relation triples by their relation group.

    The triples are the relations inferred from every edge (with the
    edge's port, protocol and CIDR as evidence) followed by the asset-level
    relations of every asset in ``assets_by_id``, the same two sources the
    ontology is built from.
    """
    group_triples: dict[RelationGroup, list[dict[str, str]]] = defaultdict(list)

    for edge in edges:
        for rel in infer_relations(edge, assets_by_id):
            triple = _triple(edge.source_id, rel.value, edge.target_id, assets_by_id)
            triple["port_range"] = edge.port_range or ""
            triple["protocol"] = edge.protocol or ""
            triple["cidr"] = edge.cidr or ""
            group_triples[get_relation_group(rel)].append(triple)

    for asset, rel, object_id in iter_asset_relations(list(assets_by_id.values())):
        group_triples[get_relation_group(rel)].append(
            _triple(asset.id, rel.value, object_id, assets_by_id)
        )

    return group_triples


def _triple_evidence(triple: dict[str, str]) -> str:
    """Format optional port/protocol/cidr evidence for a triple line."""
    if not (triple["port_range"] or triple["protocol"] or triple["cidr"]):
        return ""
    parts = [p for p in [triple["port_range"], triple["protocol"], triple["cidr"]] if p]
    return f" [{', '.join(parts)}]"


def _relation_group_lines(
    group: RelationGroup,
    triples: list[dict[str, str]],
    type_counts: dict[str, int],
    budget: int,
) -> tuple[list[str], int]:
    """Content lines of a relation-group chunk: totals, distribution, triples.

    Returns the lines and how many triples fit into ``budget`` characters.
    """
    content_lines = [
        f"Relation Group: {group.value}",
        f"Total relations: {len(triples)}",
        "",
        "Relation type distribution:",
    ]
    for rt_name, count in sorted(type_counts.items(), key=lambda x: -x[1]):
        content_lines.append(f"  {rt_name}: {count}")

    content_lines.append("\nTriples:")
    triple_lines = [
        f"  {t['subject']} → {t['predicate']} → {t['object']}{_triple_evidence(t)}" for t in triples
    ]
    (shown,) = _fit_sections(content_lines, [triple_lines], budget)
    return [*content_lines, *_cut(triple_lines, shown)], shown
