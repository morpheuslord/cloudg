"""RAG-ready export: chunked, metadata-enriched representations of the
cloud infrastructure graph for retrieval-augmented generation.

Three complementary chunking strategies:
1. Entity-centric: one chunk per cloud asset with 1-hop neighbourhood
2. Community-detection: Louvain clusters with aggregate summaries
3. Relation-group: one chunk per semantic relation group (Network, IAM, etc.)

``rag.chunk_strategy`` picks which of them :meth:`RAGExporter.export_all`
writes (``hybrid``: all three). ``rag.max_chunk_tokens`` bounds the
length of a chunk's content, counted as about 4 characters per token: the
lists in a chunk (relations, findings, community members, triples) are
cut, in order, when the next line would not fit, and an
``... and N more`` line says how many were left out.

Relation-group chunks carry the same relations the ontology holds: the
relations inferred from each edge plus the asset-level ones inferred from
metadata (``ENCRYPTED_BY_KMS``, VPC containment from ``vpc_id``, tag
governance, rotation, EC2 security group membership).
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
)
from cloudg.inventory.dependencies import AssetIndex
from cloudg.schema.models import (
    CloudAsset,
    Finding,
    NetworkEdge,
)

from cloudg.graph.rag_text import (
    CHUNK_STRATEGIES,
    _index_findings,
    _graph_index,
    CHARS_PER_TOKEN,
    _fit_sections,
    _cut,
    _entity_header_lines,
    _entity_relations,
    _entity_findings_lines,
    _summarize_community_members,
    _count_community_edges,
    _group_relation_triples,
    _relation_group_lines,
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
def _write_export(out: Path, all_chunks: list[RAGChunk], counts: dict[str, int]) -> dict[str, Path]:
    """Write the JSONL chunks and the metadata index; return both paths."""
    # Write JSONL (one JSON object per line, the usual vector DB input)
    chunks_path = out / "rag_chunks.jsonl"
    with open(chunks_path, "w") as f:
        for chunk in all_chunks:
            f.write(json.dumps(chunk.to_dict(), default=str) + "\n")

    index = {
        "total_chunks": len(all_chunks),
        **counts,
        "chunk_ids": [c.chunk_id for c in all_chunks],
        "chunk_types": list({c.chunk_type for c in all_chunks}),
    }
    index_path = out / "rag_metadata_index.json"
    with open(index_path, "w") as f:
        json.dump(index, f, indent=2)
    return {"chunks": chunks_path, "index": index_path}


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

    def __init__(self, max_chunk_tokens: int = 2000, chunk_strategy: str = "hybrid") -> None:
        """
        Args:
            max_chunk_tokens: Approximate content size limit of one chunk
                (``rag.max_chunk_tokens``), counted as
                :data:`CHARS_PER_TOKEN` characters per token. Lists that
                do not fit are cut with an ``... and N more`` line; the
                fixed lines of a chunk (an asset's name, type, ARN, tags)
                are always kept, so one chunk can still go over the limit.
            chunk_strategy: Chunk kinds :meth:`export_all` writes
                (``rag.chunk_strategy``): ``entity``, ``community``,
                ``relation_group``, or ``hybrid`` for all three.

        Raises:
            ValueError: ``max_chunk_tokens`` is below 1 or
                ``chunk_strategy`` is not one of the four names.
        """
        if max_chunk_tokens < 1:
            raise ValueError(f"max_chunk_tokens must be at least 1, got {max_chunk_tokens}")
        if chunk_strategy not in CHUNK_STRATEGIES:
            raise ValueError(
                f"Unknown chunk_strategy {chunk_strategy!r}; expected one of "
                + ", ".join(CHUNK_STRATEGIES)
            )
        self._max_tokens = max_chunk_tokens
        self._strategy = chunk_strategy

    @property
    def _budget(self) -> int:
        """Content size limit of one chunk, in characters."""
        return self._max_tokens * CHARS_PER_TOKEN

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
        header = _entity_header_lines(asset)
        relation_lines = [
            f"  {'→' if rel['direction'] == 'outgoing' else '←'} "
            f"{rel['predicate']}: {rel['object']}"
            for rel in chunk_relations
        ]
        finding_lines, severity_max, compliance_frameworks = _entity_findings_lines(
            resource_findings
        )
        relations_title = [f"\nRelations ({len(chunk_relations)}):"] if chunk_relations else []
        findings_title = [f"\nFindings ({len(resource_findings)}):"] if resource_findings else []

        # Both lists share the chunk budget; see _fit_sections
        n_relations, n_findings = _fit_sections(
            [*header, *relations_title, *findings_title],
            [relation_lines, finding_lines],
            self._budget,
        )
        content_lines = [
            *header,
            *relations_title,
            *_cut(relation_lines, n_relations),
            *findings_title,
            *_cut(finding_lines, n_findings),
        ]

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

        title = [f"Community {comm_id} ({len(members)} resources):"]
        tail = [
            f"\nAsset types: {dict(summary['type_counts'])}",
            f"Internal edges: {internal_edges}, External edges: {external_edges}",
        ]
        if exposed_count:
            tail.append(f"⚠ {exposed_count} internet-exposed resources")
        if total_findings:
            tail.append(f"Findings: {total_findings} (max severity: {summary['max_severity']})")
        member_lines = summary["member_lines"]
        (shown,) = _fit_sections([*title, *tail], [member_lines], self._budget)
        content_lines = [*title, *_cut(member_lines, shown), *tail]

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
        type_counts: dict[str, int] = defaultdict(int)
        for t in triples:
            type_counts[t["predicate"]] += 1
        content_lines, shown = _relation_group_lines(group, triples, type_counts, self._budget)

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
                for t in triples[:shown]
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
        """Export the chunk kinds of the chunk strategy to files.

        With the default ``hybrid`` strategy that is all three kinds; any
        other strategy writes one kind and counts the others as 0 in
        rag_metadata_index.json.

        Returns:
            Dict mapping chunk type → output file path.
        """
        out = Path(output_dir)
        out.mkdir(parents=True, exist_ok=True)

        assets_by_id = {a.id: a for a in assets}
        kinds = (
            {"entity", "community", "relation_group"}
            if self._strategy == "hybrid"
            else {self._strategy}
        )
        entity_chunks = (
            self.export_entity_chunks(assets, edges, findings) if "entity" in kinds else []
        )
        community_chunks = (
            self.export_community_chunks(graph, assets_by_id, findings)
            if "community" in kinds
            else []
        )
        relation_chunks = (
            self.export_relation_chunks(edges, assets_by_id) if "relation_group" in kinds else []
        )
        all_chunks = [*entity_chunks, *community_chunks, *relation_chunks]
        paths = _write_export(
            out,
            all_chunks,
            {
                "entity_chunks": len(entity_chunks),
                "community_chunks": len(community_chunks),
                "relation_group_chunks": len(relation_chunks),
            },
        )

        logger.info(
            "RAG export complete: %d chunks (%d entity, %d community, %d relation) -> %s",
            len(all_chunks),
            len(entity_chunks),
            len(community_chunks),
            len(relation_chunks),
            out,
        )
        return paths
