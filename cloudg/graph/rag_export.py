"""RAG-ready export — generates chunked, metadata-enriched representations
of the cloud infrastructure graph for retrieval-augmented generation.

Three complementary chunking strategies:
1. Entity-centric: one chunk per cloud asset with 1-hop neighbourhood
2. Community-detection: Louvain clusters with aggregate summaries
3. Relation-group: one chunk per semantic relation group (Network, IAM, etc.)
"""

from __future__ import annotations

import json
import logging
from collections import defaultdict
from pathlib import Path
from typing import Any

import networkx as nx

from cloudg.graph.ontology import (
    RelationGroup,
    get_relation_group,
    infer_relations,
)
from cloudg.inventory.dependencies import AssetIndex
from cloudg.schema.models import (
    CloudAsset,
    Finding,
    NetworkEdge,
    Severity,
)

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Chunk models
# ---------------------------------------------------------------------------


class RAGChunk:
    """A single chunk for RAG retrieval."""

    def __init__(
        self,
        chunk_id: str,
        chunk_type: str,
        content: str,
        metadata: dict[str, Any],
        relations: list[dict[str, str]] | None = None,
    ) -> None:
        self.chunk_id = chunk_id
        self.chunk_type = chunk_type
        self.content = content
        self.metadata = metadata
        self.relations = relations or []

    def to_dict(self) -> dict[str, Any]:
        return {
            "chunk_id": self.chunk_id,
            "chunk_type": self.chunk_type,
            "content": self.content,
            "metadata": self.metadata,
            "relations": self.relations,
        }


# ---------------------------------------------------------------------------
# Community detection helper
# ---------------------------------------------------------------------------


def _detect_communities(graph: nx.DiGraph) -> dict[str, int]:
    """Run Louvain community detection on the graph.

    Returns mapping of node_id → community_id.
    """
    try:
        import community as community_louvain
    except ImportError:
        logger.warning(
            "python-louvain not installed. Falling back to connected components. "
            "Install with: pip install python-louvain"
        )
        # Fallback: use connected components as pseudo-communities
        undirected = graph.to_undirected()
        mapping: dict[str, int] = {}
        for idx, component in enumerate(nx.connected_components(undirected)):
            for node in component:
                mapping[node] = idx
        return mapping

    undirected = graph.to_undirected()
    partition = community_louvain.best_partition(undirected)
    return partition


# ---------------------------------------------------------------------------
# Chunk-shaping helpers
# ---------------------------------------------------------------------------

# Severity → sort rank (lower is more severe)
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

    ``index`` matches a finding by ID, ARN, unique name or unique ARN
    tail; findings it cannot place stay keyed by their raw resource_id.
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
    """Render findings lines; returns (lines, max severity, compliance frameworks)."""
    if not resource_findings:
        return [], "NONE", set()

    lines = [f"\nFindings ({len(resource_findings)}):"]
    sorted_findings = sorted(resource_findings, key=lambda f: _SEVERITY_ORDER.get(f.severity, 5))
    severity_max = sorted_findings[0].severity.value if sorted_findings else "NONE"
    compliance_frameworks: set[str] = set()
    for f in sorted_findings[:10]:
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


def _group_relation_triples(
    edges: list[NetworkEdge],
    assets_by_id: dict[str, CloudAsset],
) -> dict[RelationGroup, list[dict[str, str]]]:
    """Group edge triples by their inferred relation group."""
    group_triples: dict[RelationGroup, list[dict[str, str]]] = defaultdict(list)

    for edge in edges:
        src_name = assets_by_id.get(edge.source_id)
        tgt_name = assets_by_id.get(edge.target_id)
        src_label = src_name.name if src_name else edge.source_id
        tgt_label = tgt_name.name if tgt_name else edge.target_id

        for rel in infer_relations(edge, assets_by_id):
            group = get_relation_group(rel)
            group_triples[group].append(
                {
                    "subject": src_label,
                    "subject_id": edge.source_id,
                    "predicate": rel.value,
                    "object": tgt_label,
                    "object_id": edge.target_id,
                    "port_range": edge.port_range or "",
                    "protocol": edge.protocol or "",
                    "cidr": edge.cidr or "",
                }
            )

    return group_triples


def _triple_evidence(triple: dict[str, str]) -> str:
    """Format optional port/protocol/cidr evidence for a triple line."""
    if not (triple["port_range"] or triple["protocol"] or triple["cidr"]):
        return ""
    parts = [p for p in [triple["port_range"], triple["protocol"], triple["cidr"]] if p]
    return f" [{', '.join(parts)}]"


# ---------------------------------------------------------------------------
# RAG Exporter
# ---------------------------------------------------------------------------


class RAGExporter:
    """Generates RAG-ready chunks from cloud infrastructure data.

    Three strategies, each producing different chunk types for retrieval:

    1. **Entity-centric**: one chunk per asset with all direct relations,
       findings, and compliance status. Best for "tell me about resource X".

    2. **Community-detection**: Louvain-clustered groups of tightly-connected
       resources. Best for "what's the blast radius of this subnet?".

    3. **Relation-group**: all triples of a semantic group (Network, IAM, etc.).
       Best for "show me all IAM access rules" or "list all network paths".
    """

    def __init__(self, max_chunk_tokens: int = 2000) -> None:
        self._max_tokens = max_chunk_tokens

    # ------------------------------------------------------------------
    # Strategy 1: Entity-centric chunks
    # ------------------------------------------------------------------

    def export_entity_chunks(
        self,
        assets: list[CloudAsset],
        edges: list[NetworkEdge],
        findings: list[Finding] | None = None,
    ) -> list[RAGChunk]:
        """Generate one chunk per cloud asset with 1-hop neighbourhood."""
        assets_by_id = {a.id: a for a in assets}
        findings_by_resource = _index_findings(findings, AssetIndex(assets_by_id.values()))

        # Build adjacency from edges
        outgoing: dict[str, list[NetworkEdge]] = defaultdict(list)
        incoming: dict[str, list[NetworkEdge]] = defaultdict(list)
        for edge in edges:
            outgoing[edge.source_id].append(edge)
            incoming[edge.target_id].append(edge)

        chunks = [
            self._build_entity_chunk(
                asset,
                _entity_relations(asset, assets_by_id, outgoing, incoming),
                findings_by_resource.get(asset.id, []),
            )
            for asset in assets
        ]

        logger.info("Generated %d entity chunks", len(chunks))
        return chunks

    def _build_entity_chunk(
        self,
        asset: CloudAsset,
        chunk_relations: list[dict[str, str]],
        resource_findings: list[Finding],
    ) -> RAGChunk:
        """Assemble content, metadata, and relations into one entity chunk."""
        content_lines = _entity_header_lines(asset)

        # Add relations to content
        if chunk_relations:
            content_lines.append(f"\nRelations ({len(chunk_relations)}):")
            for rel in chunk_relations[:30]:  # Cap to avoid huge chunks
                arrow = "→" if rel["direction"] == "outgoing" else "←"
                content_lines.append(f"  {arrow} {rel['predicate']}: {rel['object']}")

        # Findings
        finding_lines, severity_max, compliance_frameworks = _entity_findings_lines(
            resource_findings
        )
        content_lines.extend(finding_lines)

        # Metadata
        metadata = {
            "asset_type": asset.asset_type.value,
            "provider": asset.provider.value,
            "region": asset.region,
            "account_id": asset.account_id or "",
            "is_internet_exposed": asset.is_internet_exposed,
            "relation_types": sorted({rel["predicate"] for rel in chunk_relations}),
            "severity_max": severity_max,
            "compliance_frameworks": sorted(compliance_frameworks),
            "neighbour_count": len(chunk_relations),
            "finding_count": len(resource_findings),
            "arn": asset.arn or "",
        }

        return RAGChunk(
            chunk_id=f"entity::{asset.id}",
            chunk_type="entity",
            content="\n".join(content_lines),
            metadata=metadata,
            relations=chunk_relations,
        )

    # ------------------------------------------------------------------
    # Strategy 2: Community-detection chunks
    # ------------------------------------------------------------------

    def export_community_chunks(
        self,
        graph: nx.DiGraph,
        assets_by_id: dict[str, CloudAsset] | None = None,
        findings: list[Finding] | None = None,
    ) -> list[RAGChunk]:
        """Generate one chunk per detected community of resources."""
        if graph.number_of_nodes() == 0:
            return []

        partition = _detect_communities(graph)

        # Group nodes by community
        communities: dict[int, list[str]] = defaultdict(list)
        for node_id, comm_id in partition.items():
            communities[comm_id].append(node_id)

        findings_by_resource = _index_findings(findings, _graph_index(graph, assets_by_id))

        chunks = [
            self._build_community_chunk(graph, comm_id, members, findings_by_resource)
            for comm_id, members in communities.items()
            if len(members) >= 2  # Skip singleton communities
        ]

        logger.info("Generated %d community chunks", len(chunks))
        return chunks

    def _build_community_chunk(
        self,
        graph: nx.DiGraph,
        comm_id: int,
        members: list[str],
        findings_by_resource: dict[str, list[Finding]],
    ) -> RAGChunk:
        """Assemble content and metadata for one community chunk."""
        summary = _summarize_community_members(graph, members, findings_by_resource)
        internal_edges, external_edges = _count_community_edges(graph, set(members))
        total_findings = summary["total_findings"]
        exposed_count = summary["exposed_count"]

        content_lines = [f"Community {comm_id} ({len(members)} resources):"]
        content_lines.extend(summary["member_lines"])
        content_lines.append(f"\nAsset types: {dict(summary['type_counts'])}")
        content_lines.append(f"Internal edges: {internal_edges}, External edges: {external_edges}")
        if exposed_count:
            content_lines.append(f"⚠ {exposed_count} internet-exposed resources")
        if total_findings:
            content_lines.append(
                f"Findings: {total_findings} (max severity: {summary['max_severity']})"
            )

        risk_score = min(10.0, len(members) * 0.3 + total_findings * 0.5 + exposed_count * 2.0)

        metadata = {
            "community_id": comm_id,
            "member_count": len(members),
            "asset_types": dict(summary["type_counts"]),
            "internal_edges": internal_edges,
            "external_edges": external_edges,
            "internet_exposed_count": exposed_count,
            "finding_count": total_findings,
            "severity_max": summary["max_severity"],
            "compliance_frameworks": sorted(summary["frameworks"]),
            "risk_score": round(risk_score, 1),
        }

        return RAGChunk(
            chunk_id=f"community::{comm_id}",
            chunk_type="community",
            content="\n".join(content_lines),
            metadata=metadata,
        )

    # ------------------------------------------------------------------
    # Strategy 3: Relation-group chunks
    # ------------------------------------------------------------------

    def export_relation_chunks(
        self,
        edges: list[NetworkEdge],
        assets_by_id: dict[str, CloudAsset],
    ) -> list[RAGChunk]:
        """Generate one chunk per semantic relation group."""
        # Group edges by inferred relation group
        group_triples = _group_relation_triples(edges, assets_by_id)

        chunks = [
            self._build_relation_group_chunk(group, triples)
            for group, triples in group_triples.items()
        ]

        logger.info("Generated %d relation-group chunks", len(chunks))
        return chunks

    def _build_relation_group_chunk(
        self,
        group: RelationGroup,
        triples: list[dict[str, str]],
    ) -> RAGChunk:
        """Assemble content and metadata for one relation-group chunk."""
        content_lines = [
            f"Relation Group: {group.value}",
            f"Total relations: {len(triples)}",
            "",
        ]

        # Summarise relation type distribution
        type_counts: dict[str, int] = defaultdict(int)
        for t in triples:
            type_counts[t["predicate"]] += 1

        content_lines.append("Relation type distribution:")
        for rt_name, count in sorted(type_counts.items(), key=lambda x: -x[1]):
            content_lines.append(f"  {rt_name}: {count}")

        content_lines.append("\nTriples:")
        for t in triples[:50]:  # Cap for chunk size
            content_lines.append(
                f"  {t['subject']} → {t['predicate']} → {t['object']}{_triple_evidence(t)}"
            )

        if len(triples) > 50:
            content_lines.append(f"  ... and {len(triples) - 50} more")

        metadata = {
            "relation_group": group.value,
            "total_relations": len(triples),
            "relation_type_counts": dict(type_counts),
            "unique_subjects": len({t["subject_id"] for t in triples}),
            "unique_objects": len({t["object_id"] for t in triples}),
        }

        return RAGChunk(
            chunk_id=f"relation_group::{group.value}",
            chunk_type="relation_group",
            content="\n".join(content_lines),
            metadata=metadata,
            relations=[
                {
                    "predicate": t["predicate"],
                    "object": t["object"],
                    "evidence": f"{t['port_range']} {t['protocol']} {t['cidr']}".strip(),
                }
                for t in triples[:50]
            ],
        )

    # ------------------------------------------------------------------
    # Combined export
    # ------------------------------------------------------------------

    def export_all(
        self,
        assets: list[CloudAsset],
        edges: list[NetworkEdge],
        graph: nx.DiGraph,
        findings: list[Finding] | None = None,
        output_dir: str | Path = "./reports",
    ) -> dict[str, Path]:
        """Export all chunk types to files.

        Returns:
            Dict mapping chunk type → output file path.
        """
        out = Path(output_dir)
        out.mkdir(parents=True, exist_ok=True)

        assets_by_id = {a.id: a for a in assets}
        all_chunks: list[RAGChunk] = []

        # Strategy 1
        entity_chunks = self.export_entity_chunks(assets, edges, findings)
        all_chunks.extend(entity_chunks)

        # Strategy 2
        community_chunks = self.export_community_chunks(graph, assets_by_id, findings)
        all_chunks.extend(community_chunks)

        # Strategy 3
        relation_chunks = self.export_relation_chunks(edges, assets_by_id)
        all_chunks.extend(relation_chunks)

        # Write JSONL (one JSON object per line — standard for vector DBs)
        chunks_path = out / "rag_chunks.jsonl"
        with open(chunks_path, "w") as f:
            for chunk in all_chunks:
                f.write(json.dumps(chunk.to_dict(), default=str) + "\n")

        # Write metadata index
        index = {
            "total_chunks": len(all_chunks),
            "entity_chunks": len(entity_chunks),
            "community_chunks": len(community_chunks),
            "relation_group_chunks": len(relation_chunks),
            "chunk_ids": [c.chunk_id for c in all_chunks],
            "chunk_types": list({c.chunk_type for c in all_chunks}),
        }
        index_path = out / "rag_metadata_index.json"
        with open(index_path, "w") as f:
            json.dump(index, f, indent=2)

        logger.info(
            "RAG export complete: %d chunks (%d entity, %d community, %d relation) -> %s",
            len(all_chunks),
            len(entity_chunks),
            len(community_chunks),
            len(relation_chunks),
            out,
        )

        return {
            "chunks": chunks_path,
            "index": index_path,
        }
