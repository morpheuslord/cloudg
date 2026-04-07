"""CloudMapper CLI — Click-based command-line interface."""

from __future__ import annotations

import asyncio
import json
import logging
import sys
from pathlib import Path
from typing import Any

import click
from rich.console import Console
from rich.logging import RichHandler
from rich.table import Table

from cloudmapper import __version__

console = Console()

# Global config reference (set by CLI group)
_config = None


def setup_logging(verbose: bool = False, log_file: str | None = None) -> None:
    """Configure structured logging with Rich + optional file output."""
    level = logging.DEBUG if verbose else logging.INFO
    handlers: list[logging.Handler] = [
        RichHandler(rich_tracebacks=True, console=console)
    ]
    if log_file:
        file_handler = logging.FileHandler(log_file)
        file_handler.setFormatter(
            logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s")
        )
        handlers.append(file_handler)
    logging.basicConfig(level=level, format="%(message)s", datefmt="[%X]", handlers=handlers)


@click.group()
@click.version_option(version=__version__, prog_name="cloudmapper")
@click.option("-v", "--verbose", is_flag=True, help="Enable debug logging")
@click.option("-c", "--config", "config_path", default=None, help="Path to config.yaml")
@click.option("--log-file", default=None, help="Path to log file")
def cli(verbose: bool, config_path: str | None, log_file: str | None) -> None:
    """☁️  CloudMapper — Cloud Infrastructure Mapping & Security Intelligence Agent."""
    global _config
    from cloudmapper.config import load_config

    _config = load_config(config_path)
    effective_verbose = verbose or _config.verbose
    effective_log = log_file or _config.log_file
    setup_logging(effective_verbose, effective_log)


# ─────────────────────────────────────────────────────────────────────
# COLLECT command
# ─────────────────────────────────────────────────────────────────────


@cli.command()
@click.option(
    "-p", "--provider",
    type=click.Choice(["aws", "azure", "gcp"], case_sensitive=False),
    required=True,
    help="Cloud provider to collect from",
)
@click.option("--profile", default=None, help="AWS profile name")
@click.option("--region", default="us-east-1", help="AWS region")
@click.option("--subscription-id", default=None, help="Azure subscription ID")
@click.option("--project-id", default=None, help="GCP project ID")
@click.option(
    "-o", "--output",
    default="./reports",
    help="Output directory",
)
def collect(
    provider: str,
    profile: str | None,
    region: str,
    subscription_id: str | None,
    project_id: str | None,
    output: str,
) -> None:
    """Collect cloud assets from the specified provider."""
    console.print(f"[bold cyan]☁️  Collecting assets from {provider.upper()}...[/]")

    from cloudmapper.credentials import CredentialResolver

    resolver = CredentialResolver()
    output_dir = Path(output)
    output_dir.mkdir(parents=True, exist_ok=True)

    async def _collect() -> dict[str, Any]:
        if provider == "aws":
            from cloudmapper.collectors.aws import AsyncAWSCollector

            creds = resolver.resolve_aws(profile=profile, region=region)
            collector = AsyncAWSCollector(
                session=creds.session, region=creds.region, account_id=creds.account_id
            )
        elif provider == "azure":
            from cloudmapper.collectors.azure import AzureCollector

            creds = resolver.resolve_azure(subscription_id=subscription_id)
            collector = AzureCollector(
                credential=creds.credential,
                subscription_id=creds.subscription_id,
            )
        elif provider == "gcp":
            from cloudmapper.collectors.gcp import GCPCollector

            creds = resolver.resolve_gcp(project_id=project_id)
            collector = GCPCollector(
                project_id=creds.project_id, credentials=creds.credentials
            )
        else:
            raise click.BadParameter(f"Unknown provider: {provider}")

        assets, edges = await collector.run()
        return {
            "assets": [a.model_dump(mode="json") for a in assets],
            "edges": [e.model_dump(mode="json") for e in edges],
        }

    try:
        result = asyncio.run(_collect())
    except Exception as exc:
        console.print(f"[bold red]✗ Collection failed:[/] {exc}")
        sys.exit(1)

    # Save results
    inventory_path = output_dir / f"inventory-{provider}.json"
    with open(inventory_path, "w") as f:
        json.dump(result, f, indent=2, default=str)

    # Summary table
    table = Table(title="Collection Summary")
    table.add_column("Metric", style="cyan")
    table.add_column("Count", style="bold green")
    table.add_row("Assets", str(len(result["assets"])))
    table.add_row("Edges", str(len(result["edges"])))
    console.print(table)
    console.print(f"[green]✓ Saved to {inventory_path}[/]")


# ─────────────────────────────────────────────────────────────────────
# SCAN command
# ─────────────────────────────────────────────────────────────────────


@cli.command()
@click.option("-p", "--provider", default="aws", help="Cloud provider")
@click.option("--profile", default=None, help="AWS profile name")
@click.option("--iac-dir", default=None, help="IaC directory for Checkov (defaults to '.')")
@click.option("--images", default=None, help="Comma-separated container images for Trivy")
@click.option(
    "-o", "--output",
    default="./reports",
    help="Output directory",
)
@click.option(
    "--scanners",
    default="prowler,checkov",
    help="Comma-separated list of scanners to run (prowler,scoutsuite,checkov,trivy,iam)",
)
def scan(
    provider: str,
    profile: str | None,
    iac_dir: str | None,
    images: str | None,
    output: str,
    scanners: str,
) -> None:
    """Run security scanners and generate findings."""
    import concurrent.futures

    console.print("[bold cyan]🔍 Running security scans...[/]")

    output_dir = Path(output)
    output_dir.mkdir(parents=True, exist_ok=True)
    scanner_list = [s.strip().lower() for s in scanners.split(",")]
    all_findings: list[Any] = []

    resolved_iac_dir = iac_dir or "."
    resolved_images = [i.strip() for i in images.split(",")] if images else []

    console.print(f"  [bold]Scanners:[/] {', '.join(scanner_list)}")

    def _run_prowler() -> list[Any]:
        from cloudmapper.scanners.prowler import ProwlerScanner
        console.print("  → Running Prowler...")
        s = ProwlerScanner(provider=provider, profile=profile, output_dir=str(output_dir / "prowler"))
        return s.run()

    def _run_scoutsuite() -> list[Any]:
        from cloudmapper.scanners.scoutsuite import ScoutSuiteScanner
        console.print("  → Running ScoutSuite...")
        s = ScoutSuiteScanner(provider=provider, profile=profile, report_dir=str(output_dir / "scoutsuite"))
        return s.run()

    def _run_checkov() -> list[Any]:
        from cloudmapper.scanners.checkov import CheckovScanner
        console.print(f"  → Running Checkov (target: {resolved_iac_dir})...")
        s = CheckovScanner(target_dir=resolved_iac_dir)
        return s.run()

    def _run_trivy() -> list[Any]:
        from cloudmapper.scanners.trivy import TrivyScanner
        console.print(f"  → Running Trivy ({len(resolved_images)} images)...")
        s = TrivyScanner()
        return s.scan_images(resolved_images)

    def _run_trivy_fs() -> list[Any]:
        from cloudmapper.scanners.trivy import TrivyScanner
        console.print(f"  → Running Trivy filesystem scan (target: {resolved_iac_dir})...")
        s = TrivyScanner()
        return s.scan_filesystem([resolved_iac_dir])

    with concurrent.futures.ThreadPoolExecutor(max_workers=len(scanner_list) + 1) as executor:
        future_to_name: dict[concurrent.futures.Future, str] = {}

        if "prowler" in scanner_list:
            future_to_name[executor.submit(_run_prowler)] = "Prowler"

        if "scoutsuite" in scanner_list:
            future_to_name[executor.submit(_run_scoutsuite)] = "ScoutSuite"

        if "checkov" in scanner_list:
            future_to_name[executor.submit(_run_checkov)] = "Checkov"

        if "trivy" in scanner_list:
            if resolved_images:
                future_to_name[executor.submit(_run_trivy)] = "Trivy"
            else:
                console.print("  [yellow]⊘ Trivy: no images specified, falling back to filesystem scan[/yellow]")
                future_to_name[executor.submit(_run_trivy_fs)] = "Trivy (filesystem)"

        for future in concurrent.futures.as_completed(future_to_name):
            name = future_to_name[future]
            try:
                findings = future.result(timeout=3600)
                all_findings.extend(findings)
                console.print(f"    [green]{len(findings)} findings from {name}[/]")
            except Exception as exc:
                console.print(f"    [red]✗ {name} failed: {exc}[/]")

    # Save raw findings
    findings_path = output_dir / "raw-findings.json"
    with open(findings_path, "w") as f:
        json.dump(
            [f.model_dump(mode="json") for f in all_findings],
            f,
            indent=2,
            default=str,
        )

    console.print(f"\n[green]✓ Total: {len(all_findings)} findings saved to {findings_path}[/]")


# ─────────────────────────────────────────────────────────────────────
# REPORT command
# ─────────────────────────────────────────────────────────────────────


@cli.command()
@click.option(
    "-i", "--input",
    "input_file",
    required=True,
    help="Path to findings.json from a previous run",
)
@click.option(
    "-o", "--output",
    default="./reports",
    help="Output directory",
)
@click.option(
    "--format",
    "fmt",
    type=click.Choice(["html", "json", "svg", "all"]),
    default="all",
    help="Output format",
)
def report(input_file: str, output: str, fmt: str) -> None:
    """Generate reports from existing scan data."""
    console.print("[bold cyan]📊 Generating reports...[/]")

    input_path = Path(input_file)
    if not input_path.exists():
        console.print(f"[bold red]✗ Input file not found: {input_path}[/]")
        sys.exit(1)

    output_dir = Path(output)
    output_dir.mkdir(parents=True, exist_ok=True)

    with open(input_path) as f:
        data = json.load(f)

    from cloudmapper.schema.models import CloudAsset, Finding, ScanResult

    # Reconstruct ScanResult
    assets = [CloudAsset.model_validate(a) for a in data.get("assets", [])]
    findings = [Finding.model_validate(f) for f in data.get("findings", [])]
    graph_data = data.get("graph", {"nodes": [], "links": []})

    scan_result = ScanResult(assets=assets, findings=findings)

    if fmt in ("json", "all"):
        from cloudmapper.renderers.json_export import JSONExporter

        exporter = JSONExporter(output_dir=str(output_dir))
        path = exporter.export(scan_result, graph_json=graph_data)
        console.print(f"  [green]✓ JSON: {path}[/]")

    if fmt in ("svg", "all"):
        from cloudmapper.renderers.svg import SVGRenderer

        renderer = SVGRenderer(output_dir=str(output_dir))
        path = renderer.render(assets, scan_result.edges)
        console.print(f"  [green]✓ SVG: {path}[/]")

    if fmt in ("html", "all"):
        from cloudmapper.renderers.html_report import HTMLReportGenerator

        generator = HTMLReportGenerator(output_dir=str(output_dir))
        path = generator.generate(scan_result, graph_json=graph_data)
        console.print(f"  [green]✓ HTML: {path}[/]")


# ─────────────────────────────────────────────────────────────────────
# RUN command (full pipeline)
# ─────────────────────────────────────────────────────────────────────


@cli.command()
@click.option(
    "-p", "--provider",
    type=click.Choice(["aws", "azure", "gcp", "all"], case_sensitive=False),
    multiple=True,
    required=True,
    help="Cloud provider(s) to scan. Use multiple times or 'all' for simultaneous scanning.",
)
@click.option("--profile", default=None, help="AWS profile name (fallback if no direct keys)")
@click.option("--aws-key", default=None, help="AWS access key ID (direct credential)")
@click.option("--aws-secret", default=None, help="AWS secret access key (direct credential)")
@click.option("--region", default=None, help="AWS region (ignored if --regions is set)")
@click.option("--subscription-id", default=None, help="Azure subscription ID")
@click.option("--project-id", default=None, help="GCP project ID")
@click.option("--iac-dir", default=None, help="IaC directory for Checkov")
@click.option("--images", default=None, help="Container images for Trivy (comma-separated)")
@click.option(
    "-o", "--output",
    default="./reports",
    help="Output directory",
)
@click.option(
    "--scanners",
    default=None,
    help="Scanners to run (comma-separated: prowler,scoutsuite,checkov,trivy,iam). Defaults to config.yaml scanners.enabled.",
)
@click.option("--ontology/--no-ontology", default=True, help="Build semantic ontology graph")
@click.option("--rag-export/--no-rag-export", default=True, help="Generate RAG-ready chunks")
@click.option("--terraform/--no-terraform", default=False, help="Generate Terraform .tf.json recreation files")
@click.option(
    "--regions",
    "scan_regions",
    default=None,
    help="Regions to scan: 'all' for auto-discovery, or comma-separated list (e.g. 'us-east-1,eu-west-1')",
)
def run(
    provider: tuple[str, ...],
    profile: str | None,
    aws_key: str | None,
    aws_secret: str | None,
    region: str | None,
    subscription_id: str | None,
    project_id: str | None,
    iac_dir: str | None,
    images: str | None,
    output: str,
    scanners: str | None,
    ontology: bool,
    rag_export: bool,
    terraform: bool,
    scan_regions: str | None,
) -> None:
    """Run the full pipeline: collect → scan → normalise → render.

    Supports multi-provider scanning:
        cloudmapper run -p aws -p azure
        cloudmapper run -p all
        cloudmapper run -p aws --regions all
        cloudmapper run -p aws --aws-key AKIAXX --aws-secret yyy
    """
    console.print("[bold cyan]🚀 CloudMapper Full Pipeline[/]")
    console.print("=" * 50)

    output_dir = Path(output)
    output_dir.mkdir(parents=True, exist_ok=True)

    from cloudmapper.config import CloudMapperConfig
    from cloudmapper.credentials import CredentialResolver
    from cloudmapper.graph.builder import GraphBuilder
    from cloudmapper.graph.reachability import ReachabilityAnalyzer
    from cloudmapper.normaliser import FindingsNormaliser
    from cloudmapper.registry import PluginRegistry
    from cloudmapper.renderers.html_report import HTMLReportGenerator
    from cloudmapper.renderers.json_export import JSONExporter
    from cloudmapper.renderers.svg import SVGRenderer
    from cloudmapper.scanners.iam_linter import IAMLinter
    from cloudmapper.schema.models import ScanResult

    # Use global config if loaded, else defaults
    cfg: CloudMapperConfig = _config or CloudMapperConfig()

    # Resolve providers from CLI flags
    providers_list = list(provider)
    if "all" in providers_list:
        providers_list = ["aws", "azure", "gcp"]
    cfg.providers = providers_list

    # Resolve regions from CLI flag
    if scan_regions:
        if scan_regions.lower() == "all":
            region_list = ["ALL"]
        else:
            region_list = [r.strip() for r in scan_regions.split(",")]
        cfg.aws.regions = region_list
        cfg.azure.regions = region_list
        cfg.gcp.regions = region_list
    elif region:
        cfg.aws.regions = [region]

    # Inject subscription/project IDs from CLI flags
    if subscription_id:
        cfg.azure.subscription_ids = [subscription_id]
    if project_id:
        cfg.gcp.project_ids = [project_id]
    if profile:
        cfg.aws.profile = profile
    if aws_key:
        cfg.aws.access_key_id = aws_key
    if aws_secret:
        cfg.aws.secret_access_key = aws_secret

    registry = PluginRegistry()
    coverage_records = []

    # ── Resolve scanner list from CLI flag or config ──
    if scanners is not None:
        scanner_list = [s.strip().lower() for s in scanners.split(",")]
    else:
        scanner_list = [s.strip().lower() for s in cfg.scanners.enabled]
    console.print(f"\n[bold]Providers:[/] {', '.join(cfg.providers)}")
    console.print(f"[bold]Scanners:[/]  {', '.join(scanner_list)}")
    console.print(f"[bold]AWS regions:[/] {cfg.aws.regions}")
    if "azure" in cfg.providers:
        console.print(f"[bold]Azure regions:[/] {cfg.azure.regions}")
    if "gcp" in cfg.providers:
        console.print(f"[bold]GCP regions:[/] {cfg.gcp.regions}")

    # ── Resolve IaC directories: CLI flag → config → default "." ──
    resolved_iac_dirs: list[str] = []
    if iac_dir:
        resolved_iac_dirs = [iac_dir]
    elif cfg.scanners.iac_directories:
        resolved_iac_dirs = list(cfg.scanners.iac_directories)
    else:
        resolved_iac_dirs = ["."]

    # ── Resolve container images: CLI flag → config ──
    resolved_images: list[str] = []
    if images:
        resolved_images = [i.strip() for i in images.split(",")]
    elif cfg.scanners.trivy_images:
        resolved_images = list(cfg.scanners.trivy_images)

    # Phase 1: Asset Collection (always uses multi-provider orchestrator)
    console.print("\n[bold]Phase 1: Asset Collection[/]")

    from cloudmapper.collectors.multi import MultiAccountCollector

    multi_collector = MultiAccountCollector(cfg)

    try:
        assets, edges, coverage_records = asyncio.run(multi_collector.collect_all())
        console.print(f"  [green]✓ {len(assets)} assets, {len(edges)} edges[/]")
        if hasattr(multi_collector, '_resolved_regions'):
            for prov, regs in multi_collector._resolved_regions.items():
                console.print(f"    {prov}: {len(regs)} regions")
    except Exception as exc:
        console.print(f"  [red]✗ Collection failed: {exc}[/]")
        assets, edges = [], []

    # Phase 2: Graph Analysis
    console.print("\n[bold]Phase 2: Graph Analysis[/]")
    graph_builder = GraphBuilder()
    graph = graph_builder.build(assets, edges)
    graph_json = graph_builder.to_d3_json()

    # Persist graph as GraphML
    graphml_path = output_dir / "topology.graphml"
    graph_builder.save_graphml(graphml_path)
    console.print(f"  [green]✓ GraphML: {graphml_path}[/]")

    # Cytoscape export
    cytoscape_path = output_dir / "topology-cytoscape.json"
    with open(cytoscape_path, "w") as f:
        json.dump(graph_builder.to_cytoscape_json(), f, indent=2, default=str)
    console.print(f"  [green]✓ Cytoscape: {cytoscape_path}[/]")

    analyzer = ReachabilityAnalyzer(graph)
    reachability_findings = analyzer.generate_findings()
    console.print(f"  [green]✓ Graph: {graph.number_of_nodes()} nodes, {graph.number_of_edges()} edges[/]")
    console.print(f"  [green]✓ Reachability findings: {len(reachability_findings)}[/]")

    # Attack paths
    if cfg.graph.compute_attack_paths:
        lateral_paths = graph_builder.find_lateral_movement_paths()
        if lateral_paths:
            console.print(f"  [yellow]⚠ {len(lateral_paths)} lateral movement paths detected[/]")

    # Phase 2b: Semantic Ontology — deferred to after scanner phase
    # (so security/compliance findings can be included in the ontology)

    # Phase 2c: RAG Export
    if rag_export and cfg.rag.enabled:
        console.print("\n[bold]Phase 2c: RAG Export[/]")
        try:
            from cloudmapper.graph.rag_export import RAGExporter

            rag = RAGExporter(max_chunk_tokens=cfg.rag.max_chunk_tokens)
            rag_paths = rag.export_all(
                assets, edges, graph,
                findings=reachability_findings,
                output_dir=output_dir,
            )
            console.print(f"  [green]✓ RAG chunks: {rag_paths['chunks']}[/]")
            console.print(f"  [green]✓ RAG index: {rag_paths['index']}[/]")
        except Exception as exc:
            console.print(f"  [red]✗ RAG export failed: {exc}[/]")

    # Phase 2d: Terraform Recreation
    if terraform or cfg.terraform.enabled:
        console.print("\n[bold]Phase 2d: Terraform Recreation[/]")
        try:
            from cloudmapper.renderers.terraform_export import TerraformExporter

            tf_dir = cfg.terraform.output_dir or str(output_dir / "terraform")
            tf_exporter = TerraformExporter(output_dir=tf_dir)
            preview = tf_exporter.preview(assets)
            console.print(f"  [dim]Preview: {preview['total_mapped']} resources mappable, "
                          f"{preview['total_unmapped']} unmapped[/]")

            tf_paths = tf_exporter.export(assets, edges)
            console.print(f"  [green]✓ Provider: {tf_paths['provider']}[/]")
            console.print(f"  [green]✓ Variables: {tf_paths['variables']}[/]")
            console.print(f"  [green]✓ Main: {tf_paths['main']}[/]")
            console.print(f"  [green]✓ Import: {tf_paths['import_commands']}[/]")
        except Exception as exc:
            console.print(f"  [red]✗ Terraform export failed: {exc}[/]")

    import concurrent.futures

    # Phase 3: Security Scanning (all scanners in parallel)
    console.print("\n[bold]Phase 3: Security Scanning[/bold] (Running in parallel)")
    scanner_findings: list[Any] = []

    def run_prowler(prov: str) -> list[Any]:
        from cloudmapper.scanners.prowler import ProwlerScanner
        console.print(f"  → [cyan]Prowler ({prov})[/cyan] started...")
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
        findings = s.run()
        console.print(f"  [green]✓ Prowler ({prov}):[/green] {len(findings)} findings")
        return findings

    def run_scoutsuite(prov: str) -> list[Any]:
        from cloudmapper.scanners.scoutsuite import ScoutSuiteScanner
        console.print(f"  → [cyan]ScoutSuite ({prov})[/cyan] started...")
        s = ScoutSuiteScanner(
            provider=prov,
            profile=profile if prov == "aws" else None,
            report_dir=str(output_dir / "scoutsuite" / prov),
            extra_args=cfg.scanners.scoutsuite_extra_args or [],
        )
        findings = s.run()
        console.print(f"  [green]✓ ScoutSuite ({prov}):[/green] {len(findings)} findings")
        return findings

    def run_checkov(target_dir: str) -> list[Any]:
        from cloudmapper.scanners.checkov import CheckovScanner
        frameworks = cfg.scanners.checkov_frameworks or []
        fw_label = ", ".join(frameworks) if frameworks else "auto-detect"
        console.print(f"  → [cyan]Checkov[/cyan] started (target: {target_dir}, frameworks: {fw_label})...")
        s = CheckovScanner(
            target_dir=target_dir,
            frameworks=frameworks if frameworks else None,
            extra_args=cfg.scanners.checkov_extra_args or [],
        )
        findings = s.run()
        console.print(f"  [green]✓ Checkov:[/green] {len(findings)} findings")
        return findings

    def run_trivy(image_list: list[str]) -> list[Any]:
        from cloudmapper.scanners.trivy import TrivyScanner
        console.print(f"  → [cyan]Trivy[/cyan] started ({len(image_list)} images)...")
        s = TrivyScanner(extra_args=cfg.scanners.trivy_extra_args or [])
        findings = s.scan_images(image_list)
        console.print(f"  [green]✓ Trivy (images):[/green] {len(findings)} findings")
        return findings

    def run_trivy_fs(target_dirs: list[str]) -> list[Any]:
        from cloudmapper.scanners.trivy import TrivyScanner
        console.print(f"  → [cyan]Trivy (filesystem)[/cyan] started ({len(target_dirs)} directories)...")
        s = TrivyScanner(extra_args=cfg.scanners.trivy_extra_args or [])
        findings = s.scan_filesystem(target_dirs)
        console.print(f"  [green]✓ Trivy (filesystem):[/green] {len(findings)} findings")
        return findings

    def run_iam_linter() -> list[Any]:
        from cloudmapper.scanners.iam_linter import IAMLinter
        console.print("  → [cyan]IAM Lint[/cyan] started...")
        iam_linter = IAMLinter()
        findings = iam_linter.analyze_policies(assets)
        console.print(f"  [green]✓ IAM Lint:[/green] {len(findings)} findings")
        return findings

    # Execute ALL enabled scanners concurrently
    iam_findings: list[Any] = []
    max_workers = len(scanner_list) + len(cfg.providers) + 1  # +1 for IAM linter
    with concurrent.futures.ThreadPoolExecutor(max_workers=max(max_workers, 2)) as executor:
        future_to_scanner: dict[concurrent.futures.Future, str] = {}

        # Prowler — one instance per provider
        if "prowler" in scanner_list:
            for prov in cfg.providers:
                if prov in ("aws", "azure", "gcp"):
                    future_to_scanner[executor.submit(run_prowler, prov)] = f"Prowler ({prov})"
        else:
            console.print("  [dim]⊘ Prowler: not enabled[/dim]")

        # ScoutSuite — one instance per provider
        if "scoutsuite" in scanner_list:
            for prov in cfg.providers:
                if prov in ("aws", "azure", "gcp"):
                    future_to_scanner[executor.submit(run_scoutsuite, prov)] = f"ScoutSuite ({prov})"
        else:
            console.print("  [dim]⊘ ScoutSuite: not enabled[/dim]")

        # Checkov — always runs against resolved IaC directories
        if "checkov" in scanner_list:
            for d in resolved_iac_dirs:
                future_to_scanner[executor.submit(run_checkov, d)] = f"Checkov ({d})"
        else:
            console.print("  [dim]⊘ Checkov: not enabled[/dim]")

        # Trivy — runs against container images if available, otherwise falls back to filesystem scan
        if "trivy" in scanner_list:
            if resolved_images:
                future_to_scanner[executor.submit(run_trivy, resolved_images)] = "Trivy (images)"
            else:
                console.print("  [yellow]⊘ Trivy: no images configured, falling back to filesystem scan[/yellow]")
                future_to_scanner[executor.submit(run_trivy_fs, resolved_iac_dirs)] = "Trivy (filesystem)"
        else:
            console.print("  [dim]⊘ Trivy: not enabled[/dim]")

        # IAM Linter — always runs internally to analyze collected assets
        if "iam" in scanner_list or assets:
            future_to_scanner[executor.submit(run_iam_linter)] = "IAM Linter"

        for future in concurrent.futures.as_completed(future_to_scanner):
            scanner_name = future_to_scanner[future]
            try:
                findings = future.result(timeout=cfg.scanners.timeout_seconds)
                if scanner_name == "IAM Linter":
                    iam_findings.extend(findings)
                else:
                    scanner_findings.extend(findings)
            except concurrent.futures.TimeoutError:
                console.print(f"  [red]✗ {scanner_name} timed out after {cfg.scanners.timeout_seconds}s[/red]")
            except Exception as exc:
                console.print(f"  [red]✗ {scanner_name} failed:[/red] {exc}")

    # Combine all findings for downstream phases
    all_security_findings = scanner_findings + iam_findings + reachability_findings
    console.print(f"\n  [bold green]✓ Phase 3 complete:[/bold green] {len(all_security_findings)} total findings")

    # Phase 3b: Semantic Ontology (runs AFTER scanners so findings are included)
    if ontology and cfg.ontology.enabled:
        console.print("\n[bold]Phase 3b: Semantic Ontology (with security findings)[/]")
        try:
            from cloudmapper.graph.ontology import CloudOntology

            cloud_ontology = CloudOntology()
            cloud_ontology.build(assets, edges, findings=all_security_findings)
            stats = cloud_ontology.stats()
            console.print(f"  [green]✓ Ontology: {stats['total_triples']} triples, "
                          f"{stats['classes_used']} classes, {stats['individuals']} individuals[/]")
            console.print(f"  [green]✓ Security findings in ontology: {len(all_security_findings)}[/]")

            for fmt in cfg.ontology.export_formats:
                ext_map = {"turtle": "ttl", "json-ld": "jsonld", "xml": "rdf", "nt": "nt"}
                ext = ext_map.get(fmt, "ttl")
                onto_path = cloud_ontology.save(output_dir / f"ontology.{ext}", fmt=fmt)
                console.print(f"  [green]✓ Ontology ({fmt}): {onto_path}[/]")

            # Group summary
            for group, count in stats['relation_group_counts'].items():
                console.print(f"    {group}: {count} relations")
        except Exception as exc:
            console.print(f"  [red]✗ Ontology build failed: {exc}[/]")

    # Also update RAG export with all findings
    if rag_export and cfg.rag.enabled:
        try:
            from cloudmapper.graph.rag_export import RAGExporter
            rag = RAGExporter(max_chunk_tokens=cfg.rag.max_chunk_tokens)
            rag_paths = rag.export_all(
                assets, edges, graph,
                findings=all_security_findings,
                output_dir=output_dir,
            )
        except Exception:
            pass  # RAG already ran in Phase 2c, this is an update pass

    # Phase 4: Normalise (with external rulesets)
    console.print("\n[bold]Phase 4: Normalisation[/]")
    normaliser = FindingsNormaliser(rules_dir=cfg.rulesets.rules_dir)
    scan_result = normaliser.normalise(
        reachability_findings, scanner_findings, iam_findings, assets=assets
    )
    scan_result.edges = edges
    console.print(f"  [green]✓ {len(scan_result.findings)} normalised findings[/]")

    # Phase 5: Render
    console.print("\n[bold]Phase 5: Report Generation[/]")

    exporter = JSONExporter(output_dir=str(output_dir))
    json_path = exporter.export(scan_result, graph_json=graph_json)
    console.print(f"  [green]✓ JSON: {json_path}[/]")

    svg_renderer = SVGRenderer(output_dir=str(output_dir))
    svg_path = svg_renderer.render(assets, edges)
    console.print(f"  [green]✓ SVG: {svg_path}[/]")

    html_gen = HTMLReportGenerator(template_dir="./templates", output_dir=str(output_dir))
    html_path = html_gen.generate(scan_result, graph_json=graph_json)
    console.print(f"  [green]✓ HTML: {html_path}[/]")

    # Summary
    console.print("\n" + "=" * 50)
    summary = scan_result.summary
    table = Table(title="🏁 Pipeline Summary")
    table.add_column("Metric", style="cyan")
    table.add_column("Value", style="bold")
    table.add_row("Assets", str(summary["total_assets"]))
    table.add_row("Findings", str(summary["total_findings"]))
    for sev, count in summary["severity_breakdown"].items():
        color = {"CRITICAL": "red", "HIGH": "yellow", "MEDIUM": "blue"}.get(sev, "white")
        table.add_row(sev, f"[{color}]{count}[/]")
    table.add_row("Frameworks", ", ".join(summary["compliance_frameworks"]))
    console.print(table)

    # Coverage summary
    if coverage_records:
        cov_table = Table(title="📊 Collection Coverage")
        cov_table.add_column("Region", style="cyan")
        cov_table.add_column("Account", style="dim")
        cov_table.add_column("Coverage", style="bold")
        cov_table.add_column("Failures", style="red")
        for cov in coverage_records:
            summary_data = cov.to_summary()
            failures = ", ".join(f["service"] for f in summary_data["failures"]) or "—"
            cov_table.add_row(
                summary_data["region"] or "—",
                summary_data["account_id"] or "—",
                f"{summary_data['coverage_pct']}%",
                failures,
            )
        console.print(cov_table)

    console.print(f"\n[bold green]✓ All reports saved to {output_dir}[/]")


if __name__ == "__main__":
    cli()
