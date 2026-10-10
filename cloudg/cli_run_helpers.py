"""Pipeline-phase helpers for the `cloudg run` command.

Each function implements one phase of the full pipeline (collect → graph →
export → scan → ontology → render). All terminal rendering goes through
:mod:`cloudg.ui`.
"""

from __future__ import annotations

import asyncio
import json
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any

from cloudg import ui
from cloudg.ui import console

if TYPE_CHECKING:
    from cloudg.config import CloudGConfig

logger = logging.getLogger(__name__)


def _collect_assets(cfg: CloudGConfig) -> tuple[list[Any], list[Any], list[Any]]:
    """Phase 1: Asset Collection via the multi-provider orchestrator."""
    ui.phase("Phase 1 · Asset Collection")

    from cloudg.api import failed_collection_targets
    from cloudg.collectors.multi import MultiAccountCollector

    multi_collector = MultiAccountCollector(cfg)
    try:
        with console.status("[accent]Collecting assets across providers…[/]", spinner="dots"):
            assets, edges, coverage_records = asyncio.run(multi_collector.collect_all())
        ui.success(f"[metric]{len(assets)}[/] assets, [metric]{len(edges)}[/] edges")
        if hasattr(multi_collector, "_resolved_regions"):
            for prov, regs in multi_collector._resolved_regions.items():
                ui.detail(f"{prov}: {len(regs)} regions")
    except Exception as exc:
        ui.error_panel("Collection failed", exc)
        return [], [], []
    for line in failed_collection_targets(coverage_records)[:10]:
        ui.fail(f"Not collected: {line}")
    return assets, edges, coverage_records


def _graph_phase(
    cfg: CloudGConfig, assets: list[Any], edges: list[Any], output_dir: Path
) -> tuple[Any, dict[str, Any], list[Any]]:
    """Phase 2: Graph Analysis. Returns (graph, d3 graph json, reachability findings)."""
    ui.phase("Phase 2 · Graph Analysis")

    from cloudg.graph.builder import GraphBuilder
    from cloudg.graph.reachability import ReachabilityAnalyzer

    graph_builder = GraphBuilder(max_nodes_warn=cfg.graph.max_nodes_warn)
    graph = graph_builder.build(assets, edges)
    graph_json = graph_builder.to_d3_json()

    # Persist graph as GraphML
    if cfg.graph.persist_graphml:
        graphml_path = output_dir / "topology.graphml"
        graph_builder.save_graphml(graphml_path)
        ui.artifact("GraphML", graphml_path)

    # Cytoscape export
    if cfg.graph.export_cytoscape:
        cytoscape_path = output_dir / "topology-cytoscape.json"
        with open(cytoscape_path, "w") as f:
            json.dump(graph_builder.to_cytoscape_json(), f, indent=2, default=str)
        ui.artifact("Cytoscape", cytoscape_path)

    analyzer = ReachabilityAnalyzer(graph)
    reachability_findings = analyzer.generate_findings()
    ui.success(
        f"Graph: [metric]{graph.number_of_nodes()}[/] nodes, "
        f"[metric]{graph.number_of_edges()}[/] edges"
    )
    ui.success(f"Reachability findings: [metric]{len(reachability_findings)}[/]")

    # Attack paths
    if cfg.graph.compute_attack_paths:
        lateral_paths = graph_builder.find_lateral_movement_paths()
        if lateral_paths:
            ui.warn(f"{len(lateral_paths)} lateral movement paths detected")

    return graph, graph_json, reachability_findings


def _export_rag_phase(
    cfg: CloudGConfig,
    assets: list[Any],
    edges: list[Any],
    graph: Any,
    findings: list[Any],
    output_dir: Path,
) -> None:
    """Phase 2c: RAG Export."""
    ui.phase("Phase 2c · RAG Export")
    try:
        from cloudg.graph.rag_export import RAGExporter

        rag = RAGExporter(
            max_chunk_tokens=cfg.rag.max_chunk_tokens, chunk_strategy=cfg.rag.chunk_strategy
        )
        rag_paths = rag.export_all(assets, edges, graph, findings=findings, output_dir=output_dir)
        ui.artifact("RAG chunks", rag_paths["chunks"])
        ui.artifact("RAG index", rag_paths["index"])
    except Exception as exc:
        ui.fail(f"RAG export failed: {exc}")


def _update_rag_export(
    cfg: CloudGConfig,
    assets: list[Any],
    edges: list[Any],
    graph: Any,
    findings: list[Any],
    output_dir: Path,
) -> None:
    """Silent RAG update pass so the export includes all security findings."""
    try:
        from cloudg.graph.rag_export import RAGExporter

        rag = RAGExporter(
            max_chunk_tokens=cfg.rag.max_chunk_tokens, chunk_strategy=cfg.rag.chunk_strategy
        )
        rag.export_all(assets, edges, graph, findings=findings, output_dir=output_dir)
    except Exception:
        # RAG already ran in Phase 2c, this is an update pass
        logger.debug("RAG update pass failed; keeping Phase 2c export", exc_info=True)


def _terraform_phase(
    cfg: CloudGConfig,
    terraform_flag: bool,
    assets: list[Any],
    edges: list[Any],
    output_dir: Path,
) -> str | None:
    """Phase 2d: Terraform Recreation. Returns the export directory, or None."""
    if not (terraform_flag or cfg.terraform.enabled):
        return None
    ui.phase("Phase 2d · Terraform Recreation")
    try:
        from cloudg.renderers.terraform_export import TerraformExporter

        from cloudg.renderers.terraform_export import terraform_output_dir

        tf_dir = str(terraform_output_dir(cfg.terraform, output_dir))
        tf_exporter = TerraformExporter(output_dir=tf_dir)
        preview = tf_exporter.preview(assets)
        ui.detail(
            f"Preview: {preview['total_mapped']} resources mappable, "
            f"{preview['total_unmapped']} unmapped"
        )

        tf_paths = tf_exporter.export(assets, edges)
        ui.artifact("Provider", tf_paths["provider"])
        ui.artifact("Variables", tf_paths["variables"])
        ui.artifact("Main", tf_paths["main"])
        ui.artifact("Import", tf_paths["import_commands"])
        return tf_dir
    except Exception as exc:
        ui.fail(f"Terraform export failed: {exc}")
        return None


def _resolve_scan_iac_dirs(cfg: CloudGConfig, iac_dir: str | None, tf_dir: str | None) -> list[str]:
    """Resolve IaC scan targets: CLI flag, then config, then the Terraform recreation.

    There is no fallback to ".": scanning the directory cloudg runs from is
    not a scan of the cloud, and its zero findings look like a clean result.
    """
    from cloudg.api import resolve_iac_dirs

    resolved_iac_dirs, iac_source = resolve_iac_dirs(iac_dir, cfg.scanners.iac_directories, tf_dir)
    if iac_source == "terraform":
        ui.detail(
            "IaC scanners target the Terraform recreation of the live "
            f"infrastructure ({resolved_iac_dirs[0]})"
        )
    return resolved_iac_dirs


def _scanner_phase(
    cfg: CloudGConfig,
    scanner_list: list[str],
    profile: str | None,
    iac_dir: str | None,
    resolved_images: list[str],
    tf_dir: str | None,
    assets: list[Any],
    output_dir: Path,
) -> tuple[list[Any], list[Any]]:
    """Phase 3: run all enabled scanners in parallel.

    Scanner selection, credentials, regions and timeouts follow the same
    rules as :meth:`cloudg.api.CloudGEngine.scan`. The IAM linter runs only
    when ``iam`` is in the scanner list.

    Returns (scanner findings, IAM linter findings).
    """
    from cloudg.api_scanners import plan_scanner_jobs
    from cloudg.cli_helpers import _run_scan_plan, _show_scan_plan

    ui.phase("Phase 3 · Security Scanning", note="running scanners in parallel")
    resolved_iac_dirs = _resolve_scan_iac_dirs(cfg, iac_dir, tf_dir)
    plan = plan_scanner_jobs(
        cfg,
        scanner_list,
        providers=list(cfg.providers),
        profile=profile,
        out=output_dir,
        assets=assets,
        iac_dirs=resolved_iac_dirs,
        images=resolved_images,
    )
    _show_scan_plan(plan)
    outcome = _run_scan_plan(plan)
    return outcome.findings_of("iam", exclude=True), outcome.findings_of("iam")


def _ontology_phase(
    cfg: CloudGConfig,
    assets: list[Any],
    edges: list[Any],
    findings: list[Any],
    output_dir: Path,
) -> None:
    """Phase 3b: Semantic Ontology (runs AFTER scanners so findings are included)."""
    ui.phase("Phase 3b · Semantic Ontology", note="includes security findings")
    try:
        from cloudg.graph.ontology import CloudOntology

        cloud_ontology = CloudOntology()
        cloud_ontology.build(assets, edges, findings=findings)
        stats = cloud_ontology.stats()
        ui.success(
            f"Ontology: [metric]{stats['total_triples']}[/] triples, "
            f"[metric]{stats['classes_used']}[/] classes, "
            f"[metric]{stats['individuals']}[/] individuals"
        )
        ui.success(f"Security findings in ontology: [metric]{len(findings)}[/]")

        for fmt in cfg.ontology.export_formats:
            ext_map = {"turtle": "ttl", "json-ld": "jsonld", "xml": "rdf", "nt": "nt"}
            ext = ext_map.get(fmt, "ttl")
            onto_path = cloud_ontology.save(output_dir / f"ontology.{ext}", fmt=fmt)
            ui.artifact(f"Ontology ({fmt})", onto_path)

        # Group summary
        for group, count in stats["relation_group_counts"].items():
            ui.detail(f"{group}: {count} relations")
    except Exception as exc:
        ui.fail(f"Ontology build failed: {exc}")


def _render_run_reports(
    scan_result: Any,
    graph_json: dict[str, Any],
    assets: list[Any],
    edges: list[Any],
    output_dir: Path,
    cfg: CloudGConfig | None = None,
) -> None:
    """Phase 5: render the reports in ``report.formats`` (JSON, SVG, HTML)."""
    ui.phase("Phase 5 · Report Generation")

    from cloudg.config import ReportConfig
    from cloudg.renderers.html_report import HTMLReportGenerator
    from cloudg.renderers.json_export import JSONExporter
    from cloudg.renderers.svg import SVGRenderer

    report_cfg = cfg.report if cfg is not None else ReportConfig()

    if "json" in report_cfg.formats:
        exporter = JSONExporter(output_dir=str(output_dir))
        json_path = exporter.export(scan_result, graph_json=graph_json)
        ui.artifact("JSON", json_path)

    if "svg" in report_cfg.formats:
        svg_renderer = SVGRenderer(output_dir=str(output_dir))
        svg_path = svg_renderer.render(assets, edges)
        ui.artifact("SVG", svg_path)

    if "html" in report_cfg.formats:
        html_gen = HTMLReportGenerator(output_dir=str(output_dir), inline_js=report_cfg.inline_js)
        html_path = html_gen.generate(scan_result, graph_json=graph_json)
        ui.artifact("HTML", html_path)


@dataclass
class RunProducts:
    """What the collection and graph phases of ``cloudg run`` produced."""

    assets: list[Any]
    edges: list[Any]
    graph: Any
    graph_json: dict[str, Any]
    reachability_findings: list[Any]
    coverage_records: list[Any] = field(default_factory=list)


def _post_scan_phases(
    cfg: CloudGConfig,
    kwargs: dict[str, Any],
    products: RunProducts,
    scanner_findings: list[Any],
    iam_findings: list[Any],
    output_dir: Path,
) -> None:
    """Run everything after the scanner phase: ontology, RAG update,
    normalisation, report rendering and the results summary."""
    from cloudg.normaliser import FindingsNormaliser

    assets, edges = products.assets, products.edges
    reachability_findings = products.reachability_findings
    # Combine all findings for downstream phases
    all_security_findings = scanner_findings + iam_findings + reachability_findings
    console.print()
    ui.success(f"[bold]Phase 3 complete:[/] [metric]{len(all_security_findings)}[/] total findings")

    # Phase 3b: Semantic Ontology (runs AFTER scanners so findings are included)
    if kwargs["ontology"] and cfg.ontology.enabled:
        _ontology_phase(cfg, assets, edges, all_security_findings, output_dir)

    # Also update RAG export with all findings
    if kwargs["rag_export"] and cfg.rag.enabled:
        _update_rag_export(cfg, assets, edges, products.graph, all_security_findings, output_dir)

    # Phase 4: Normalise (with external rulesets)
    ui.phase("Phase 4 · Normalisation")
    normaliser = FindingsNormaliser(
        rules_dir=cfg.rulesets.rules_dir, load_external=cfg.rulesets.load_external
    )
    scan_result = normaliser.normalise(
        reachability_findings, scanner_findings, iam_findings, assets=assets
    )
    scan_result.edges = edges
    ui.success(f"[metric]{len(scan_result.findings)}[/] normalised findings")

    # Phase 5: Render
    _render_run_reports(scan_result, products.graph_json, assets, edges, output_dir, cfg)

    # Summary
    ui.section("Results")
    ui.summary_table(scan_result.summary)

    # Coverage summary
    if products.coverage_records:
        ui.coverage_table(products.coverage_records)

    console.print()
    ui.success(f"All reports saved to [path]{output_dir}[/]")


def _collection_verdict(products: RunProducts) -> int:
    """Say how collection went and return the exit status for `cloudg run`:
    EXIT_COLLECTION_FAILED when nothing at all could be collected, else 0."""
    from cloudg.api import collection_failed, failed_collection_targets
    from cloudg.cli_helpers import EXIT_COLLECTION_FAILED

    failed = failed_collection_targets(products.coverage_records)
    if collection_failed(products.assets, products.coverage_records):
        detail = "\n".join(failed[:10]) or "the collectors raised before recording coverage"
        ui.error_panel(
            "Collection failed for every target",
            f"{detail}\n\nThe reports hold scanner findings only. "
            f"Exit status {EXIT_COLLECTION_FAILED}.",
        )
        return EXIT_COLLECTION_FAILED
    if failed:
        ui.warn(
            f"Collection was partial: {len(failed)} target(s) failed "
            "(see the coverage table); the run still succeeded"
        )
    return 0
