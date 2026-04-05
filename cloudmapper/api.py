"""CloudMapper programmatic API — integration-ready entry point.

Designed for embedding CloudMapper in larger systems. Provides:
- Single `CloudMapperEngine` class for full pipeline control
- `PipelineResult` dataclass for structured output consumption
- Event hooks for real-time integration callbacks
- Async-first with sync wrapper for non-async callers

Usage:
    from cloudmapper.api import CloudMapperEngine
    from cloudmapper.config import CloudMapperConfig

    config = CloudMapperConfig(providers=["aws", "azure"])
    engine = CloudMapperEngine(config)

    # Full pipeline
    result = await engine.run_pipeline()

    # Or step-by-step
    collection = await engine.collect()
    findings = await engine.scan(collection.assets, collection.edges)
    analysis = await engine.analyze(collection.assets, collection.edges, findings)
"""

from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from cloudmapper.config import CloudMapperConfig
from cloudmapper.coverage import CollectionCoverage
from cloudmapper.schema.models import (
    CloudAsset,
    Finding,
    NetworkEdge,
    ScanResult,
)

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Result dataclasses
# ---------------------------------------------------------------------------


@dataclass
class CollectionResult:
    """Output of the collection phase."""

    assets: list[CloudAsset] = field(default_factory=list)
    edges: list[NetworkEdge] = field(default_factory=list)
    coverage: list[CollectionCoverage] = field(default_factory=list)
    providers_scanned: list[str] = field(default_factory=list)
    regions_scanned: dict[str, list[str]] = field(default_factory=dict)
    duration_ms: int = 0


@dataclass
class AnalysisResult:
    """Output of the analysis phase (graph, ontology, RAG)."""

    graph_nodes: int = 0
    graph_edges: int = 0
    ontology_triples: int = 0
    ontology_path: Path | None = None
    rag_chunks_path: Path | None = None
    rag_chunk_count: int = 0
    terraform_paths: dict[str, Path] = field(default_factory=dict)
    attack_paths: list[Any] = field(default_factory=list)
    reachability_findings: list[Finding] = field(default_factory=list)


@dataclass
class PipelineResult:
    """Complete pipeline output — single object for downstream consumption.

    This is the primary return type for `CloudMapperEngine.run_pipeline()`.
    Designed for easy serialisation and integration with larger systems.
    """

    # Core data
    assets: list[CloudAsset] = field(default_factory=list)
    edges: list[NetworkEdge] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    scan_result: ScanResult | None = None

    # Analysis outputs
    graph_nodes: int = 0
    graph_edges: int = 0
    ontology_triples: int = 0
    rag_chunks_path: Path | None = None
    terraform_paths: dict[str, Path] = field(default_factory=dict)
    attack_paths: list[Any] = field(default_factory=list)

    # Metadata
    providers_scanned: list[str] = field(default_factory=list)
    regions_scanned: dict[str, list[str]] = field(default_factory=dict)
    coverage: list[CollectionCoverage] = field(default_factory=list)
    report_paths: dict[str, Path] = field(default_factory=dict)
    duration_ms: int = 0
    errors: list[str] = field(default_factory=list)

    @property
    def total_assets(self) -> int:
        return len(self.assets)

    @property
    def total_findings(self) -> int:
        return len(self.findings)

    @property
    def severity_breakdown(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for f in self.findings:
            sev = f.severity.value
            counts[sev] = counts.get(sev, 0) + 1
        return counts

    def to_summary(self) -> dict[str, Any]:
        """Return a summary dict for downstream consumption."""
        return {
            "total_assets": self.total_assets,
            "total_findings": self.total_findings,
            "severity_breakdown": self.severity_breakdown,
            "providers_scanned": self.providers_scanned,
            "regions_scanned": self.regions_scanned,
            "graph_nodes": self.graph_nodes,
            "graph_edges": self.graph_edges,
            "ontology_triples": self.ontology_triples,
            "attack_paths_count": len(self.attack_paths),
            "duration_ms": self.duration_ms,
            "errors": self.errors,
        }


# ---------------------------------------------------------------------------
# Event hook types
# ---------------------------------------------------------------------------

# Callback signatures (all optional)
OnCollectionComplete = Callable[[CollectionResult], None]
OnScanComplete = Callable[[list[Finding]], None]
OnFinding = Callable[[Finding], None]
OnAnalysisComplete = Callable[[AnalysisResult], None]
OnPhaseStart = Callable[[str], None]  # phase name
OnError = Callable[[str, Exception], None]  # phase name, exception


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------


class CloudMapperEngine:
    """Integration-ready programmatic API for CloudMapper.

    Provides fine-grained control over the pipeline for embedding in
    larger security orchestration systems.

    Example:
        engine = CloudMapperEngine(config)
        engine.on_finding = lambda f: send_to_siem(f)
        result = await engine.run_pipeline()
    """

    def __init__(self, config: CloudMapperConfig) -> None:
        self.config = config

        # Event hooks — set these before calling run_pipeline()
        self.on_collection_complete: OnCollectionComplete | None = None
        self.on_scan_complete: OnScanComplete | None = None
        self.on_finding: OnFinding | None = None
        self.on_analysis_complete: OnAnalysisComplete | None = None
        self.on_phase_start: OnPhaseStart | None = None
        self.on_error: OnError | None = None

    def _emit_phase_start(self, phase: str) -> None:
        if self.on_phase_start:
            try:
                self.on_phase_start(phase)
            except Exception:
                pass

    def _emit_error(self, phase: str, exc: Exception) -> None:
        if self.on_error:
            try:
                self.on_error(phase, exc)
            except Exception:
                pass

    # ------------------------------------------------------------------
    # Phase 1: Collection
    # ------------------------------------------------------------------

    async def collect(self) -> CollectionResult:
        """Run multi-provider asset collection.

        Returns:
            CollectionResult with assets, edges, and coverage.
        """
        self._emit_phase_start("collection")
        start = time.time()

        from cloudmapper.collectors.multi import MultiAccountCollector

        collector = MultiAccountCollector(self.config)

        try:
            assets, edges, coverage = await collector.collect_all()
        except Exception as exc:
            logger.error("Collection failed: %s", exc)
            self._emit_error("collection", exc)
            return CollectionResult(duration_ms=int((time.time() - start) * 1000))

        result = CollectionResult(
            assets=assets,
            edges=edges,
            coverage=coverage,
            providers_scanned=self.config.providers,
            regions_scanned=getattr(collector, "_resolved_regions", {}),
            duration_ms=int((time.time() - start) * 1000),
        )

        if self.on_collection_complete:
            try:
                self.on_collection_complete(result)
            except Exception:
                pass

        return result

    # ------------------------------------------------------------------
    # Phase 2: Scanning
    # ------------------------------------------------------------------

    async def scan(
        self,
        assets: list[CloudAsset],
        edges: list[NetworkEdge],
    ) -> list[Finding]:
        """Run security scanners and graph analysis.

        Returns:
            List of all findings.
        """
        self._emit_phase_start("scanning")
        all_findings: list[Finding] = []

        # Graph-based reachability analysis
        try:
            from cloudmapper.graph.builder import GraphBuilder
            from cloudmapper.graph.reachability import ReachabilityAnalyzer

            builder = GraphBuilder()
            graph = builder.build(assets, edges)
            analyzer = ReachabilityAnalyzer(graph)
            reachability = analyzer.generate_findings()
            all_findings.extend(reachability)
        except Exception as exc:
            logger.error("Graph analysis failed: %s", exc)
            self._emit_error("graph_analysis", exc)

        # IAM linting
        try:
            from cloudmapper.scanners.iam_linter import IAMLinter

            linter = IAMLinter()
            iam_findings = linter.analyze_policies(assets)
            all_findings.extend(iam_findings)
        except Exception as exc:
            logger.error("IAM linting failed: %s", exc)
            self._emit_error("iam_linting", exc)

        # Emit per-finding callbacks
        if self.on_finding:
            for f in all_findings:
                try:
                    self.on_finding(f)
                except Exception:
                    pass

        if self.on_scan_complete:
            try:
                self.on_scan_complete(all_findings)
            except Exception:
                pass

        return all_findings

    # ------------------------------------------------------------------
    # Phase 3: Analysis (ontology, RAG, terraform)
    # ------------------------------------------------------------------

    async def analyze(
        self,
        assets: list[CloudAsset],
        edges: list[NetworkEdge],
        findings: list[Finding],
        output_dir: str | Path = "./reports",
    ) -> AnalysisResult:
        """Run ontology, RAG, and Terraform analysis.

        Returns:
            AnalysisResult with all analysis outputs.
        """
        self._emit_phase_start("analysis")
        out = Path(output_dir)
        out.mkdir(parents=True, exist_ok=True)
        result = AnalysisResult()

        # Graph
        try:
            from cloudmapper.graph.builder import GraphBuilder

            builder = GraphBuilder()
            graph = builder.build(assets, edges)
            result.graph_nodes = graph.number_of_nodes()
            result.graph_edges = graph.number_of_edges()

            # Reachability
            from cloudmapper.graph.reachability import ReachabilityAnalyzer

            analyzer = ReachabilityAnalyzer(graph)
            result.reachability_findings = analyzer.generate_findings()

            # Attack paths
            try:
                result.attack_paths = builder.find_lateral_movement_paths()
            except Exception:
                pass
        except Exception as exc:
            logger.error("Graph build failed: %s", exc)
            self._emit_error("graph_build", exc)
            graph = None

        # Ontology
        if self.config.ontology.enabled:
            try:
                from cloudmapper.graph.ontology import CloudOntology

                ontology = CloudOntology()
                ontology.build(assets, edges, findings)
                stats = ontology.stats()
                result.ontology_triples = stats["total_triples"]

                for fmt in self.config.ontology.export_formats:
                    ext_map = {"turtle": "ttl", "json-ld": "jsonld", "xml": "rdf"}
                    ext = ext_map.get(fmt, "ttl")
                    path = ontology.save(out / f"ontology.{ext}", fmt=fmt)
                    result.ontology_path = path
            except Exception as exc:
                logger.error("Ontology build failed: %s", exc)
                self._emit_error("ontology", exc)

        # RAG export
        if self.config.rag.enabled and graph is not None:
            try:
                from cloudmapper.graph.rag_export import RAGExporter

                rag = RAGExporter(max_chunk_tokens=self.config.rag.max_chunk_tokens)
                rag_paths = rag.export_all(assets, edges, graph, findings, output_dir=out)
                result.rag_chunks_path = rag_paths["chunks"]
            except Exception as exc:
                logger.error("RAG export failed: %s", exc)
                self._emit_error("rag_export", exc)

        # Terraform
        if self.config.terraform.enabled:
            try:
                from cloudmapper.renderers.terraform_export import TerraformExporter

                tf_dir = self.config.terraform.output_dir or str(out / "terraform")
                tf = TerraformExporter(output_dir=tf_dir)
                result.terraform_paths = tf.export(assets, edges)
            except Exception as exc:
                logger.error("Terraform export failed: %s", exc)
                self._emit_error("terraform", exc)

        if self.on_analysis_complete:
            try:
                self.on_analysis_complete(result)
            except Exception:
                pass

        return result

    # ------------------------------------------------------------------
    # Full pipeline
    # ------------------------------------------------------------------

    async def run_pipeline(self, output_dir: str | Path = "./reports") -> PipelineResult:
        """Run the complete CloudMapper pipeline.

        Phases:
        1. Collection (multi-provider, multi-region)
        2. Scanning (reachability, IAM linting)
        3. Analysis (ontology, RAG, Terraform)
        4. Normalisation
        5. Report generation

        Returns:
            PipelineResult with all outputs.
        """
        start = time.time()
        out = Path(output_dir)
        out.mkdir(parents=True, exist_ok=True)
        errors: list[str] = []

        # Phase 1: Collect
        collection = await self.collect()

        # Phase 2: Scan
        findings = await self.scan(collection.assets, collection.edges)

        # Phase 3: Analyse
        analysis = await self.analyze(
            collection.assets, collection.edges, findings, output_dir=out
        )

        # Phase 4: Normalise
        self._emit_phase_start("normalisation")
        scan_result = None
        all_findings = findings + analysis.reachability_findings
        try:
            from cloudmapper.normaliser import FindingsNormaliser

            normaliser = FindingsNormaliser(rules_dir=self.config.rulesets.rules_dir)
            scan_result = normaliser.normalise(
                analysis.reachability_findings, findings, [],
                assets=collection.assets,
            )
            scan_result.edges = collection.edges
            all_findings = scan_result.findings
        except Exception as exc:
            logger.error("Normalisation failed: %s", exc)
            errors.append(f"normalisation: {exc}")
            self._emit_error("normalisation", exc)

        # Phase 5: Reports
        self._emit_phase_start("reporting")
        report_paths: dict[str, Path] = {}
        if scan_result:
            try:
                from cloudmapper.graph.builder import GraphBuilder

                builder = GraphBuilder()
                builder.build(collection.assets, collection.edges)
                graph_json = builder.to_d3_json()

                from cloudmapper.renderers.json_export import JSONExporter

                exporter = JSONExporter(output_dir=str(out))
                report_paths["json"] = Path(exporter.export(scan_result, graph_json=graph_json))

                from cloudmapper.renderers.html_report import HTMLReportGenerator

                html_gen = HTMLReportGenerator(output_dir=str(out))
                report_paths["html"] = Path(html_gen.generate(scan_result, graph_json=graph_json))
            except Exception as exc:
                logger.error("Report generation failed: %s", exc)
                errors.append(f"reporting: {exc}")
                self._emit_error("reporting", exc)

        return PipelineResult(
            assets=collection.assets,
            edges=collection.edges,
            findings=all_findings,
            scan_result=scan_result,
            graph_nodes=analysis.graph_nodes,
            graph_edges=analysis.graph_edges,
            ontology_triples=analysis.ontology_triples,
            rag_chunks_path=analysis.rag_chunks_path,
            terraform_paths=analysis.terraform_paths,
            attack_paths=analysis.attack_paths,
            providers_scanned=collection.providers_scanned,
            regions_scanned=collection.regions_scanned,
            coverage=collection.coverage,
            report_paths=report_paths,
            duration_ms=int((time.time() - start) * 1000),
            errors=errors,
        )

    # ------------------------------------------------------------------
    # Sync wrapper
    # ------------------------------------------------------------------

    def run_pipeline_sync(self, output_dir: str | Path = "./reports") -> PipelineResult:
        """Synchronous wrapper for `run_pipeline()`.

        Convenience for non-async callers (e.g. scripts, notebooks).
        """
        return asyncio.run(self.run_pipeline(output_dir))
