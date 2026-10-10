"""CloudG programmatic API: the integration-ready entry point.

Designed for embedding CloudG in larger systems. Provides:
- Single `CloudGEngine` class for full pipeline control
- `PipelineResult` dataclass for structured output consumption
- Event hooks for real-time integration callbacks
- Async-first with sync wrapper for non-async callers

Usage:
    from cloudg.api import CloudGEngine
    from cloudg.config import CloudGConfig

    config = CloudGConfig(providers=["aws", "azure"])
    engine = CloudGEngine(config)

    # Full pipeline
    result = await engine.run_pipeline()

    # Or step-by-step
    collection = await engine.collect()
    findings = await engine.scan(collection.assets, collection.edges)
    analysis = await engine.analyze(collection.assets, collection.edges, findings)
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import time
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from cloudg.config import CloudGConfig
from cloudg.coverage import CollectionCoverage
from cloudg.schema.models import (
    CloudAsset,
    Finding,
    NetworkEdge,
    ScanResult,
)

# resolve_iac_dirs lives with the scanner runs; re-exported here (public API)
from cloudg.api_scanners import ScannerRunsMixin, resolve_iac_dirs

__all__ = [
    "AnalysisResult",
    "CloudGEngine",
    "CollectionResult",
    "PipelineResult",
    "collection_failed",
    "failed_collection_targets",
    "resolve_iac_dirs",
]

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
    """Complete pipeline output: a single object for downstream consumption.

    This is the primary return type for `CloudGEngine.run_pipeline()`.
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


def collection_failed(assets: list[Any], coverage: list[CollectionCoverage]) -> bool:
    """True when collection produced nothing because it failed.

    That is: no assets, and no collector reported success (an empty but
    readable account still has successful coverage records).
    """
    if assets:
        return False
    return not any(
        svc.status.value in ("SUCCESS", "PARTIAL") for cov in coverage for svc in cov.services
    )


# Coverage records that mean a whole provider / account / region failed
# (not just one service inside it)
_TARGET_RECORDS = ("aws_full", "azure_full", "gcp_full", "sts_assume_role")


def failed_collection_targets(coverage: list[CollectionCoverage]) -> list[str]:
    """One line per provider, account or region whose collection failed as a
    whole, e.g. ``"aws 123456789012/eu-west-1: AccessDenied ..."``.

    Single services that failed inside an otherwise collected target are
    left out; they are in the coverage records.
    """
    lines: list[str] = []
    for cov in coverage:
        for svc in cov.services:
            if svc.status.value == "FAILED" and svc.service in _TARGET_RECORDS:
                where = "/".join(x for x in (cov.account_id, cov.region) if x) or "all"
                lines.append(f"{cov.provider} {where}: {svc.error or 'failed'}")
    return lines


def _run_sync(coro: Any, name: str) -> Any:
    """``asyncio.run(coro)`` with a clear error inside a running event loop."""
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(coro)
    coro.close()
    raise RuntimeError(
        f"{name}_sync() cannot run inside a running event loop (Jupyter and async "
        f"applications run one); use 'await engine.{name}()' there instead"
    )


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------


class CloudGEngine(ScannerRunsMixin):
    """Integration-ready programmatic API for CloudG.

    Provides fine-grained control over the pipeline for embedding in
    larger security orchestration systems.

    Example:
        engine = CloudGEngine(config)
        engine.on_finding = lambda f: send_to_siem(f)
        result = await engine.run_pipeline()
    """

    def __init__(self, config: CloudGConfig) -> None:
        self.config = config

        # Event hooks: set these before calling run_pipeline()
        self.on_collection_complete: OnCollectionComplete | None = None
        self.on_scan_complete: OnScanComplete | None = None
        self.on_finding: OnFinding | None = None
        self.on_analysis_complete: OnAnalysisComplete | None = None
        self.on_phase_start: OnPhaseStart | None = None
        self.on_error: OnError | None = None

        # While run_pipeline() runs, every emitted error is also kept here
        self._error_sink: list[str] | None = None

    def _output_dir(self, output_dir: str | Path | None) -> Path:
        """``output_dir``, or ``report.output_dir`` from the config when None."""
        return Path(output_dir if output_dir is not None else self.config.report.output_dir)

    def _emit_phase_start(self, phase: str) -> None:
        if self.on_phase_start:
            try:
                self.on_phase_start(phase)
            except Exception:
                logger.debug("Event hook raised; ignoring", exc_info=True)

    @contextlib.contextmanager
    def _collect_errors(self, errors: list[str]) -> Iterator[None]:
        """Record every error emitted inside the block in ``errors`` too."""
        previous = getattr(self, "_error_sink", None)
        self._error_sink = errors
        try:
            yield
        finally:
            self._error_sink = previous

    def _emit_error(self, phase: str, exc: Exception) -> None:
        sink = getattr(self, "_error_sink", None)
        if sink is not None:
            sink.append(f"{phase}: {exc}")
        if self.on_error:
            try:
                self.on_error(phase, exc)
            except Exception:
                logger.debug("Event hook raised; ignoring", exc_info=True)

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

        from cloudg.collectors.multi import MultiAccountCollector

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
                logger.debug("Event hook raised; ignoring", exc_info=True)

        return result

    # ------------------------------------------------------------------
    # Inventory mapping (scanner-independent)
    # ------------------------------------------------------------------

    async def map_inventory(
        self,
        output_dir: str | Path | None = None,
        findings: list[Finding] | None = None,
        tagging_sweep: bool | None = None,
    ) -> "Any":
        """Map the complete infrastructure inventory; no scanners are involved.

        Runs the deep inventory collectors (full network fabric plus
        catch-all sweeps: AWS Resource Groups Tagging API, Azure ARM
        ``resources.list``, GCP Cloud Asset Inventory) and links every
        asset into an interconnected map.

        Args:
            output_dir: When set, exports inventory-map.json / .graphml /
                inventory-graph.json there.
            findings: Optional scanner findings produced elsewhere; when
                given (with output_dir), asset-map.json and
                compliance-map.json are exported as well.
            tagging_sweep: Override config.inventory.tagging_sweep
                (False skips the AWS tagging-API sweep).

        Returns:
            InventoryResult with assets, edges, coverage, and summary.
        """
        self._emit_phase_start("inventory_mapping")
        from cloudg.inventory import InventoryMapper

        mapper = InventoryMapper(self.config, tagging_sweep=tagging_sweep)
        try:
            result = await mapper.map_inventory()
        except Exception as exc:
            logger.error("Inventory mapping failed: %s", exc)
            self._emit_error("inventory_mapping", exc)
            raise

        if output_dir is not None:
            result.export(output_dir)
            if findings:
                mapper.export_merged(result, findings, output_dir)
        return result

    def map_inventory_sync(
        self,
        output_dir: str | Path | None = None,
        findings: list[Finding] | None = None,
        tagging_sweep: bool | None = None,
    ) -> "Any":
        """Synchronous wrapper for :meth:`map_inventory`.

        Raises RuntimeError inside a running event loop; await
        :meth:`map_inventory` there instead.
        """
        return _run_sync(self.map_inventory(output_dir, findings, tagging_sweep), "map_inventory")

    # ------------------------------------------------------------------
    # Phase 2: Scanning
    # ------------------------------------------------------------------

    async def scan(
        self,
        assets: list[CloudAsset],
        edges: list[NetworkEdge],
        iac_dir: str | None = None,
        images: list[str] | None = None,
        profile: str | None = None,
        output_dir: str | Path | None = None,
    ) -> list[Finding]:
        """Run security scanners and graph analysis.

        Runs all scanners enabled in config.scanners.enabled in parallel,
        built-in ones and plugins registered under the ``cloudg.scanners``
        entry point group. Unknown names and scanners whose CLI is not
        installed are logged and skipped. Without images, Trivy scans the
        IaC directories instead; the IAM linter runs only when ``iam`` is
        enabled (and there are assets). Each scanner process is killed
        after config.scanners.timeout_seconds; timeouts and failures are
        reported through ``on_error``.

        Args:
            assets: Collected cloud assets.
            edges: Network edges between assets.
            iac_dir: IaC directory for Checkov and Trivy (falls back to config).
            images: Container images for Trivy (falls back to config).
            profile: AWS profile for scanner auth (falls back to the
                configured AWS auth, aws.profile included).
            output_dir: Directory for scanner output files (default:
                ``report.output_dir``).

        Returns:
            List of all findings. ``on_finding`` receives copies of each
            scanner's findings as that scanner finishes.
        """
        self._emit_phase_start("scanning")
        all_findings: list[Finding] = []
        out = self._output_dir(output_dir)
        out.mkdir(parents=True, exist_ok=True)

        from cloudg.api_scanners import plan_scanner_jobs

        # Graph-based reachability analysis
        reachability = self._run_reachability_analysis(assets, edges)
        self._emit_findings(reachability)
        all_findings.extend(reachability)

        resolved_iac_dirs = self._resolve_scan_iac_dirs(iac_dir, assets, edges, out)

        # Resolve images
        resolved_images: list[str] = images or list(self.config.scanners.trivy_images)

        plan = plan_scanner_jobs(
            self.config,
            list(self.config.scanners.enabled),
            providers=list(self.config.providers),
            profile=profile,
            out=out,
            assets=assets,
            iac_dirs=resolved_iac_dirs,
            images=resolved_images,
        )
        # Run all scanners concurrently
        all_findings.extend(self._run_scan_plan(plan))

        self._emit_scan_complete(all_findings)

        return all_findings

    # ------------------------------------------------------------------
    # Ingest: use existing scanner outputs instead of running scanners
    # ------------------------------------------------------------------

    def ingest_reports(self, reports: dict[str, list[str | Path]]) -> list[Finding]:
        """Parse pre-existing scanner reports instead of running scanners.

        For deployments where Prowler/ScoutSuite/Checkov/Trivy already ran
        elsewhere (CI, another host, a scheduled job): feed their native
        output files here and get back cloudg findings, ready for
        `normalise_findings()` / `analyze()`.

        Args:
            reports: Tool name -> list of report paths (file or directory),
                e.g. {"prowler": ["./prowler-out/"], "trivy": ["scan.json"]}.

        Returns:
            Combined list of findings.
        """
        self._emit_phase_start("ingest")
        from cloudg.ingest import ingest_reports as _ingest

        findings = _ingest(reports)
        self._emit_scan_results(findings)
        return findings

    def normalise_findings(
        self,
        findings: list[Finding],
        assets: list[CloudAsset] | None = None,
    ) -> ScanResult:
        """Deduplicate, merge across scanners, score, and map to compliance.

        Applies the same pipeline `run_pipeline()` uses: within-scanner
        dedupe, cross-scanner merging via rules/check_equivalence.yaml,
        severity scoring, and compliance-framework mapping.
        """
        from cloudg.normaliser import FindingsNormaliser

        normaliser = FindingsNormaliser(
            rules_dir=self.config.rulesets.rules_dir,
            load_external=self.config.rulesets.load_external,
        )
        return normaliser.normalise(findings, assets=assets or [])

    async def run_from_reports(
        self,
        reports: dict[str, list[str | Path]],
        output_dir: str | Path | None = None,
    ) -> PipelineResult:
        """Run the cloudg pipeline on existing scanner outputs.

        Needs no cloud access and no scanner binaries. Phases: ingest,
        normalise, reports (JSON and HTML, as ``report.formats`` allows;
        written to ``report.output_dir`` when ``output_dir`` is None).
        Collection does not run, so
        graph/ontology/Terraform outputs that need live assets are empty;
        combine with `collect()` + `analyze()` when cloud credentials are
        available.

        Returns:
            PipelineResult with findings, scan_result, and report paths.
        """
        start = time.time()
        out = self._output_dir(output_dir)
        out.mkdir(parents=True, exist_ok=True)
        errors: list[str] = []
        with self._collect_errors(errors):
            return self._run_from_reports(reports, out, start, errors)

    def _run_from_reports(
        self,
        reports: dict[str, list[str | Path]],
        out: Path,
        start: float,
        errors: list[str],
    ) -> PipelineResult:
        findings = self.ingest_reports(reports)

        self._emit_phase_start("normalisation")
        scan_result = None
        all_findings = findings
        try:
            scan_result = self.normalise_findings(findings)
            all_findings = scan_result.findings
        except Exception as exc:
            self._record_phase_error("normalisation", "Normalisation failed", exc)

        self._emit_phase_start("reporting")
        report_paths = self._write_reports(scan_result, out) if scan_result else {}

        return PipelineResult(
            findings=all_findings,
            scan_result=scan_result,
            report_paths=report_paths,
            duration_ms=int((time.time() - start) * 1000),
            errors=errors,
        )

    def _record_phase_error(self, phase: str, label: str, exc: Exception) -> None:
        """Log a failed pipeline phase and emit it (which also records it
        in the running pipeline's ``errors``)."""
        logger.error("%s: %s", label, exc)
        self._emit_error(phase, exc)

    def _write_reports(
        self,
        scan_result: ScanResult,
        out: Path,
        graph_json: dict[str, Any] | None = None,
        collection: CollectionResult | None = None,
    ) -> dict[str, Path]:
        """Write the reports in ``report.formats``; a failure is emitted as an error.

        The SVG map needs collected assets, so it is only written when
        ``collection`` is given.
        """
        report_paths: dict[str, Path] = {}
        formats = self.config.report.formats
        try:
            if "json" in formats:
                from cloudg.renderers.json_export import JSONExporter

                exporter = JSONExporter(output_dir=str(out))
                report_paths["json"] = Path(exporter.export(scan_result, graph_json=graph_json))

            if "html" in formats:
                from cloudg.renderers.html_report import HTMLReportGenerator

                html_gen = HTMLReportGenerator(
                    output_dir=str(out), inline_js=self.config.report.inline_js
                )
                report_paths["html"] = Path(html_gen.generate(scan_result, graph_json=graph_json))

            if "svg" in formats and collection is not None:
                from cloudg.renderers.svg import SVGRenderer

                svg = SVGRenderer(output_dir=str(out))
                report_paths["svg"] = Path(svg.render(collection.assets, collection.edges))
        except Exception as exc:
            self._record_phase_error("reporting", "Report generation failed", exc)
        return report_paths

    def run_from_reports_sync(
        self,
        reports: dict[str, list[str | Path]],
        output_dir: str | Path | None = None,
    ) -> PipelineResult:
        """Synchronous wrapper for `run_from_reports()`.

        Raises RuntimeError inside a running event loop; await
        `run_from_reports()` there instead.
        """
        return _run_sync(self.run_from_reports(reports, output_dir), "run_from_reports")

    # ------------------------------------------------------------------
    # Phase 3: Analysis (ontology, RAG, terraform)
    # ------------------------------------------------------------------

    async def analyze(
        self,
        assets: list[CloudAsset],
        edges: list[NetworkEdge],
        findings: list[Finding],
        output_dir: str | Path | None = None,
    ) -> AnalysisResult:
        """Run ontology, RAG, and Terraform analysis.

        Files go to ``output_dir``, or ``report.output_dir`` when it is None.

        Returns:
            AnalysisResult with all analysis outputs.
        """
        self._emit_phase_start("analysis")
        out = self._output_dir(output_dir)
        out.mkdir(parents=True, exist_ok=True)
        result = AnalysisResult()

        # Graph
        graph = self._analyze_graph(result, assets, edges)

        # Ontology
        if self.config.ontology.enabled:
            self._analyze_ontology(result, assets, edges, findings, out)

        # RAG export
        if self.config.rag.enabled and graph is not None:
            self._analyze_rag(result, assets, edges, graph, findings, out)

        # Terraform
        if self.config.terraform.enabled:
            self._analyze_terraform(result, assets, edges, out)

        if self.on_analysis_complete:
            try:
                self.on_analysis_complete(result)
            except Exception:
                logger.debug("Event hook raised; ignoring", exc_info=True)

        return result

    def _analyze_graph(
        self,
        result: AnalysisResult,
        assets: list[CloudAsset],
        edges: list[NetworkEdge],
    ) -> Any:
        """Build the asset graph and derive reachability/attack paths.

        Returns the built graph, or None when the build failed.
        """
        try:
            from cloudg.graph.builder import GraphBuilder

            builder = GraphBuilder(max_nodes_warn=self.config.graph.max_nodes_warn)
            graph = builder.build(assets, edges)
            result.graph_nodes = graph.number_of_nodes()
            result.graph_edges = graph.number_of_edges()

            # Reachability
            from cloudg.graph.reachability import ReachabilityAnalyzer

            analyzer = ReachabilityAnalyzer(graph)
            result.reachability_findings = analyzer.generate_findings()

            # Attack paths
            try:
                result.attack_paths = builder.find_lateral_movement_paths()
            except Exception:
                logger.debug("Event hook raised; ignoring", exc_info=True)
        except Exception as exc:
            logger.error("Graph build failed: %s", exc)
            self._emit_error("graph_build", exc)
            return None
        return graph

    def _analyze_ontology(
        self,
        result: AnalysisResult,
        assets: list[CloudAsset],
        edges: list[NetworkEdge],
        findings: list[Finding],
        out: Path,
    ) -> None:
        """Build the ontology and export it in the configured formats."""
        try:
            from cloudg.graph.ontology import CloudOntology

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

    def _analyze_rag(
        self,
        result: AnalysisResult,
        assets: list[CloudAsset],
        edges: list[NetworkEdge],
        graph: Any,
        findings: list[Finding],
        out: Path,
    ) -> None:
        """Export RAG chunks from the built graph."""
        try:
            from cloudg.graph.rag_export import RAGExporter

            rag = RAGExporter(
                max_chunk_tokens=self.config.rag.max_chunk_tokens,
                chunk_strategy=self.config.rag.chunk_strategy,
            )
            rag_paths = rag.export_all(assets, edges, graph, findings, output_dir=out)
            result.rag_chunks_path = rag_paths["chunks"]
        except Exception as exc:
            logger.error("RAG export failed: %s", exc)
            self._emit_error("rag_export", exc)

    def _analyze_terraform(
        self,
        result: AnalysisResult,
        assets: list[CloudAsset],
        edges: list[NetworkEdge],
        out: Path,
    ) -> None:
        """Export the Terraform recreation of the collected assets."""
        try:
            from cloudg.renderers.terraform_export import TerraformExporter, terraform_output_dir

            tf_dir = terraform_output_dir(self.config.terraform, out)
            tf = TerraformExporter(output_dir=tf_dir)
            result.terraform_paths = tf.export(assets, edges)
        except Exception as exc:
            logger.error("Terraform export failed: %s", exc)
            self._emit_error("terraform", exc)

    # ------------------------------------------------------------------
    # Full pipeline
    # ------------------------------------------------------------------

    async def run_pipeline(self, output_dir: str | Path | None = None) -> PipelineResult:
        """Run the complete CloudG pipeline.

        Phases: 1. collection (multi-provider, multi-region), 2. scanning
        (reachability and every enabled scanner), 3. analysis (ontology,
        RAG, Terraform), 4. normalisation, 5. report generation
        (``report.formats``). Files go to ``output_dir``, or
        ``report.output_dir`` when it is None.

        Returns:
            PipelineResult with all outputs. ``errors`` lists every failure
            of the run, each as ``"<phase>: <message>"``: everything
            reported through ``on_error`` (scanners, analysis,
            normalisation, reporting), plus one ``collection:`` line per
            provider, account or region that could not be collected.
        """
        start = time.time()
        out = self._output_dir(output_dir)
        out.mkdir(parents=True, exist_ok=True)
        errors: list[str] = []
        with self._collect_errors(errors):
            return await self._run_pipeline(out, start, errors)

    async def _run_pipeline(self, out: Path, start: float, errors: list[str]) -> PipelineResult:
        # Phase 1: Collect
        collection = await self.collect()
        errors.extend(
            f"collection: {line}" for line in failed_collection_targets(collection.coverage)
        )
        if collection_failed(collection.assets, collection.coverage) and not any(
            e.startswith("collection:") for e in errors
        ):
            errors.append("collection: no assets collected and no collector succeeded")

        # Phase 2: Scan (all enabled scanners in parallel), with the
        # configured AWS auth (aws.profile included)
        findings = await self.scan(
            collection.assets,
            collection.edges,
            profile=self.config.aws.profile,
            output_dir=out,
        )

        # Phase 3: Analyse
        analysis = await self.analyze(collection.assets, collection.edges, findings, output_dir=out)

        # Phase 4: Normalise
        scan_result, all_findings = self._normalise_pipeline_findings(
            collection, findings, analysis
        )

        # Phase 5: Reports
        report_paths = self._generate_pipeline_reports(scan_result, collection, out)

        return PipelineResult(
            assets=collection.assets,
            edges=collection.edges,
            findings=all_findings,
            scan_result=scan_result,
            report_paths=report_paths,
            duration_ms=int((time.time() - start) * 1000),
            errors=errors,
            **self._pipeline_outputs(collection, analysis),
        )

    @staticmethod
    def _pipeline_outputs(collection: CollectionResult, analysis: AnalysisResult) -> dict[str, Any]:
        """Collection coverage and analysis outputs carried into a PipelineResult."""
        return {
            "graph_nodes": analysis.graph_nodes,
            "graph_edges": analysis.graph_edges,
            "ontology_triples": analysis.ontology_triples,
            "rag_chunks_path": analysis.rag_chunks_path,
            "terraform_paths": analysis.terraform_paths,
            "attack_paths": analysis.attack_paths,
            "providers_scanned": collection.providers_scanned,
            "regions_scanned": collection.regions_scanned,
            "coverage": collection.coverage,
        }

    def _normalise_pipeline_findings(
        self,
        collection: CollectionResult,
        findings: list[Finding],
        analysis: AnalysisResult,
    ) -> tuple[ScanResult | None, list[Finding]]:
        """Normalise pipeline findings; returns (scan_result, all_findings)."""
        self._emit_phase_start("normalisation")
        scan_result = None
        all_findings = findings + analysis.reachability_findings
        try:
            from cloudg.normaliser import FindingsNormaliser

            normaliser = FindingsNormaliser(
                rules_dir=self.config.rulesets.rules_dir,
                load_external=self.config.rulesets.load_external,
            )
            scan_result = normaliser.normalise(
                analysis.reachability_findings,
                findings,
                [],
                assets=collection.assets,
            )
            scan_result.edges = collection.edges
            all_findings = scan_result.findings
        except Exception as exc:
            self._record_phase_error("normalisation", "Normalisation failed", exc)
        return scan_result, all_findings

    def _generate_pipeline_reports(
        self,
        scan_result: ScanResult | None,
        collection: CollectionResult,
        out: Path,
    ) -> dict[str, Path]:
        """Generate the pipeline reports (with graph JSON) in ``report.formats``."""
        self._emit_phase_start("reporting")
        if not scan_result:
            return {}
        try:
            from cloudg.graph.builder import GraphBuilder

            builder = GraphBuilder(max_nodes_warn=self.config.graph.max_nodes_warn)
            builder.build(collection.assets, collection.edges)
            graph_json = builder.to_d3_json()
        except Exception as exc:
            self._record_phase_error("reporting", "Report generation failed", exc)
            return {}
        return self._write_reports(scan_result, out, graph_json=graph_json, collection=collection)

    # ------------------------------------------------------------------
    # Sync wrapper
    # ------------------------------------------------------------------

    def run_pipeline_sync(self, output_dir: str | Path | None = None) -> PipelineResult:
        """Synchronous wrapper for `run_pipeline()`, for scripts and other
        code that is not already running an event loop.

        Raises RuntimeError when an event loop is already running in this
        thread; use ``await engine.run_pipeline()`` there instead.
        """
        return _run_sync(self.run_pipeline(output_dir), "run_pipeline")
