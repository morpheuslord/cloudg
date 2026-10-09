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
    return assets, edges, coverage_records


def _graph_phase(
    cfg: CloudGConfig, assets: list[Any], edges: list[Any], output_dir: Path
) -> tuple[Any, dict[str, Any], list[Any]]:
    """Phase 2: Graph Analysis. Returns (graph, d3 graph json, reachability findings)."""
    ui.phase("Phase 2 · Graph Analysis")

    from cloudg.graph.builder import GraphBuilder
    from cloudg.graph.reachability import ReachabilityAnalyzer

    graph_builder = GraphBuilder()
    graph = graph_builder.build(assets, edges)
    graph_json = graph_builder.to_d3_json()

    # Persist graph as GraphML
    graphml_path = output_dir / "topology.graphml"
    graph_builder.save_graphml(graphml_path)
    ui.artifact("GraphML", graphml_path)

    # Cytoscape export
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

        rag = RAGExporter(max_chunk_tokens=cfg.rag.max_chunk_tokens)
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

        rag = RAGExporter(max_chunk_tokens=cfg.rag.max_chunk_tokens)
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

        tf_dir = cfg.terraform.output_dir or str(output_dir / "terraform")
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


def _scan_prowler(cfg: CloudGConfig, prov: str, profile: str | None, output_dir: Path) -> list[Any]:
    from cloudg.scanners.prowler import ProwlerScanner

    prowler_region = cfg.aws.regions[0] if cfg.aws.regions else None
    s = ProwlerScanner(
        provider=prov,
        profile=profile,
        output_dir=str(output_dir / "prowler" / prov),
        extra_args=cfg.scanners.prowler_extra_args or [],
        aws_access_key_id=cfg.aws.access_key_id if prov == "aws" else None,
        aws_secret_access_key=cfg.aws.secret_access_key if prov == "aws" else None,
        aws_region=prowler_region if prov == "aws" else None,
    )
    return s.run()


def _scan_scoutsuite(
    cfg: CloudGConfig, prov: str, profile: str | None, output_dir: Path
) -> list[Any]:
    from cloudg.scanners.scoutsuite import ScoutSuiteScanner

    s = ScoutSuiteScanner(
        provider=prov,
        profile=profile if prov == "aws" else None,
        report_dir=str(output_dir / "scoutsuite" / prov),
        extra_args=cfg.scanners.scoutsuite_extra_args or [],
    )
    return s.run()


def _scan_checkov(cfg: CloudGConfig, target_dir: str) -> list[Any]:
    from cloudg.scanners.checkov import CheckovScanner

    frameworks = cfg.scanners.checkov_frameworks or []
    s = CheckovScanner(
        target_dir=target_dir,
        frameworks=frameworks if frameworks else None,
        extra_args=cfg.scanners.checkov_extra_args or [],
    )
    return s.run()


def _scan_trivy_images(cfg: CloudGConfig, image_list: list[str]) -> list[Any]:
    from cloudg.scanners.trivy import TrivyScanner

    s = TrivyScanner(extra_args=cfg.scanners.trivy_extra_args or [])
    return s.scan_images(image_list)


def _scan_trivy_fs(cfg: CloudGConfig, target_dirs: list[str]) -> list[Any]:
    from cloudg.scanners.trivy import TrivyScanner

    s = TrivyScanner(extra_args=cfg.scanners.trivy_extra_args or [])
    return s.scan_filesystem(target_dirs)


def _scan_iam(assets: list[Any]) -> list[Any]:
    from cloudg.scanners.iam_linter import IAMLinter

    return IAMLinter().analyze_policies(assets)


def _submit_provider_scanners(
    submit: Any,
    cfg: CloudGConfig,
    scanner_list: list[str],
    profile: str | None,
    output_dir: Path,
) -> None:
    """Submit Prowler and ScoutSuite, one instance per provider."""
    if "prowler" in scanner_list:
        for prov in cfg.providers:
            if prov in ("aws", "azure", "gcp"):
                submit(
                    f"Prowler ({prov})",
                    f"Prowler [muted]({prov})[/]",
                    _scan_prowler,
                    cfg,
                    prov,
                    profile,
                    output_dir,
                )
    else:
        ui.skip("Prowler: not enabled")

    if "scoutsuite" in scanner_list:
        for prov in cfg.providers:
            if prov in ("aws", "azure", "gcp"):
                submit(
                    f"ScoutSuite ({prov})",
                    f"ScoutSuite [muted]({prov})[/]",
                    _scan_scoutsuite,
                    cfg,
                    prov,
                    profile,
                    output_dir,
                )
    else:
        ui.skip("ScoutSuite: not enabled")


def _submit_checkov(
    submit: Any, cfg: CloudGConfig, scanner_list: list[str], iac_dirs: list[str]
) -> None:
    """Submit Checkov against each resolved IaC directory."""
    if "checkov" not in scanner_list:
        ui.skip("Checkov: not enabled")
        return
    if not iac_dirs:
        ui.warn(
            "Checkov: nothing to scan; pass --iac-dir, set "
            "scanners.iac_directories, or enable --terraform to scan the "
            "recreated infrastructure"
        )
        return
    frameworks = cfg.scanners.checkov_frameworks or []
    fw_label = ", ".join(frameworks) if frameworks else "auto-detect"
    for d in iac_dirs:
        submit(
            f"Checkov ({d})",
            f"Checkov [muted](target: {d}, frameworks: {fw_label})[/]",
            _scan_checkov,
            cfg,
            d,
        )


def _submit_trivy_and_iam(
    submit: Any,
    cfg: CloudGConfig,
    scanner_list: list[str],
    iac_dirs: list[str],
    images: list[str],
    assets: list[Any],
) -> None:
    """Submit Trivy (images or filesystem fallback) and the IAM linter."""
    if "trivy" in scanner_list:
        if images:
            submit(
                "Trivy (images)",
                f"Trivy [muted]({len(images)} images)[/]",
                _scan_trivy_images,
                cfg,
                images,
            )
        elif iac_dirs:
            ui.warn("Trivy: no images configured, falling back to filesystem scan")
            submit(
                "Trivy (filesystem)",
                f"Trivy filesystem [muted]({len(iac_dirs)} directories)[/]",
                _scan_trivy_fs,
                cfg,
                iac_dirs,
            )
        else:
            ui.warn("Trivy: nothing to scan; configure --images, --iac-dir, or enable --terraform")
    else:
        ui.skip("Trivy: not enabled")

    # IAM Linter: always runs internally to analyze collected assets
    if "iam" in scanner_list or assets:
        submit("IAM Linter", "IAM Lint", _scan_iam, assets)


def _collect_scanner_results(
    progress: Any,
    future_to_scanner: dict[Any, tuple[str, Any]],
    cfg: CloudGConfig,
    scanner_findings: list[Any],
    iam_findings: list[Any],
) -> None:
    """Drain scanner futures, routing findings and reporting task status."""
    import concurrent.futures

    for future in concurrent.futures.as_completed(future_to_scanner):
        scanner_name, task_id = future_to_scanner[future]
        try:
            findings = future.result(timeout=cfg.scanners.timeout_seconds)
            if scanner_name == "IAM Linter":
                iam_findings.extend(findings)
            else:
                scanner_findings.extend(findings)
            ui.task_done(progress, task_id, f"{scanner_name}: {len(findings)} findings")
        except concurrent.futures.TimeoutError:
            ui.task_failed(
                progress,
                task_id,
                f"{scanner_name} timed out after {cfg.scanners.timeout_seconds}s",
            )
        except Exception as exc:
            ui.task_failed(progress, task_id, f"{scanner_name} failed: {exc}")


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


def _run_scanners_parallel(
    cfg: CloudGConfig,
    scanner_list: list[str],
    profile: str | None,
    resolved_iac_dirs: list[str],
    resolved_images: list[str],
    assets: list[Any],
    output_dir: Path,
) -> tuple[list[Any], list[Any]]:
    """Submit every enabled scanner to a thread pool and gather their findings."""
    import concurrent.futures

    scanner_findings: list[Any] = []
    iam_findings: list[Any] = []
    max_workers = len(scanner_list) + len(cfg.providers) + 1  # +1 for IAM linter
    with ui.scanner_progress() as progress:
        with concurrent.futures.ThreadPoolExecutor(max_workers=max(max_workers, 2)) as executor:
            future_to_scanner: dict[concurrent.futures.Future, tuple[str, Any]] = {}

            def submit(name: str, description: str, fn: Any, *args: Any) -> None:
                task_id = progress.add_task(description, total=None)
                future_to_scanner[executor.submit(fn, *args)] = (name, task_id)

            _submit_provider_scanners(submit, cfg, scanner_list, profile, output_dir)
            _submit_checkov(submit, cfg, scanner_list, resolved_iac_dirs)
            _submit_trivy_and_iam(
                submit, cfg, scanner_list, resolved_iac_dirs, resolved_images, assets
            )

            _collect_scanner_results(
                progress, future_to_scanner, cfg, scanner_findings, iam_findings
            )

    return scanner_findings, iam_findings


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

    Returns (scanner findings, IAM linter findings).
    """
    ui.phase("Phase 3 · Security Scanning", note="running scanners in parallel")
    resolved_iac_dirs = _resolve_scan_iac_dirs(cfg, iac_dir, tf_dir)
    return _run_scanners_parallel(
        cfg, scanner_list, profile, resolved_iac_dirs, resolved_images, assets, output_dir
    )


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
) -> None:
    """Phase 5: render JSON, SVG and HTML reports."""
    ui.phase("Phase 5 · Report Generation")

    from cloudg.renderers.html_report import HTMLReportGenerator
    from cloudg.renderers.json_export import JSONExporter
    from cloudg.renderers.svg import SVGRenderer

    exporter = JSONExporter(output_dir=str(output_dir))
    json_path = exporter.export(scan_result, graph_json=graph_json)
    ui.artifact("JSON", json_path)

    svg_renderer = SVGRenderer(output_dir=str(output_dir))
    svg_path = svg_renderer.render(assets, edges)
    ui.artifact("SVG", svg_path)

    html_gen = HTMLReportGenerator(output_dir=str(output_dir))
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
    normaliser = FindingsNormaliser(rules_dir=cfg.rulesets.rules_dir)
    scan_result = normaliser.normalise(
        reachability_findings, scanner_findings, iam_findings, assets=assets
    )
    scan_result.edges = edges
    ui.success(f"[metric]{len(scan_result.findings)}[/] normalised findings")

    # Phase 5: Render
    _render_run_reports(scan_result, products.graph_json, assets, edges, output_dir)

    # Summary
    ui.section("Results")
    ui.summary_table(scan_result.summary)

    # Coverage summary
    if products.coverage_records:
        ui.coverage_table(products.coverage_records)

    console.print()
    ui.success(f"All reports saved to [path]{output_dir}[/]")
