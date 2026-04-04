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
@click.option("--iac-dir", default=None, help="IaC directory for Checkov")
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
    console.print("[bold cyan]🔍 Running security scans...[/]")

    output_dir = Path(output)
    output_dir.mkdir(parents=True, exist_ok=True)
    scanner_list = [s.strip().lower() for s in scanners.split(",")]
    all_findings: list[Any] = []

    if "prowler" in scanner_list:
        from cloudmapper.scanners.prowler import ProwlerScanner

        console.print("  → Running Prowler...")
        scanner = ProwlerScanner(provider=provider, profile=profile, output_dir=str(output_dir / "prowler"))
        findings = scanner.run()
        all_findings.extend(findings)
        console.print(f"    [green]{len(findings)} findings[/]")

    if "scoutsuite" in scanner_list:
        from cloudmapper.scanners.scoutsuite import ScoutSuiteScanner

        console.print("  → Running ScoutSuite...")
        scanner = ScoutSuiteScanner(provider=provider, profile=profile, report_dir=str(output_dir / "scoutsuite"))
        findings = scanner.run()
        all_findings.extend(findings)
        console.print(f"    [green]{len(findings)} findings[/]")

    if "checkov" in scanner_list and iac_dir:
        from cloudmapper.scanners.checkov import CheckovScanner

        console.print("  → Running Checkov...")
        scanner = CheckovScanner(target_dir=iac_dir)
        findings = scanner.run()
        all_findings.extend(findings)
        console.print(f"    [green]{len(findings)} findings[/]")

    if "trivy" in scanner_list and images:
        from cloudmapper.scanners.trivy import TrivyScanner

        console.print("  → Running Trivy...")
        scanner = TrivyScanner()
        image_list = [i.strip() for i in images.split(",")]
        findings = scanner.scan_images(image_list)
        all_findings.extend(findings)
        console.print(f"    [green]{len(findings)} findings[/]")

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
    type=click.Choice(["aws", "azure", "gcp"], case_sensitive=False),
    required=True,
    help="Cloud provider",
)
@click.option("--profile", default=None, help="AWS profile name")
@click.option("--region", default="us-east-1", help="AWS region")
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
    default="prowler,checkov",
    help="Scanners to run (comma-separated)",
)
def run(
    provider: str,
    profile: str | None,
    region: str,
    subscription_id: str | None,
    project_id: str | None,
    iac_dir: str | None,
    images: str | None,
    output: str,
    scanners: str,
) -> None:
    """Run the full pipeline: collect → scan → normalise → render."""
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
    cfg: CloudMapperConfig = _config or CloudMapperConfig(provider=provider)
    registry = PluginRegistry()
    resolver = CredentialResolver()
    coverage_records = []

    # Phase 1: Collect (multi-account/multi-region when config available)
    console.print("\n[bold]Phase 1: Asset Collection[/]")

    use_multi = (
        (provider == "aws" and (len(cfg.aws.regions) > 1 or cfg.aws.accounts))
        or (provider == "azure" and len(cfg.azure.subscription_ids) > 1)
        or (provider == "gcp" and len(cfg.gcp.project_ids) > 1)
    )

    if use_multi:
        from cloudmapper.collectors.multi import MultiAccountCollector

        console.print("  [dim]Multi-account/multi-region mode[/]")
        multi_collector = MultiAccountCollector(cfg)

        try:
            assets, edges, coverage_records = asyncio.run(multi_collector.collect_all())
            console.print(f"  [green]✓ {len(assets)} assets, {len(edges)} edges[/]")
        except Exception as exc:
            console.print(f"  [red]✗ Collection failed: {exc}[/]")
            assets, edges = [], []
    else:
        async def _collect():
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

            return await collector.run()

        try:
            assets, edges = asyncio.run(_collect())
            console.print(f"  [green]✓ {len(assets)} assets, {len(edges)} edges[/]")
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

    # Phase 3: Security Scanning
    console.print("\n[bold]Phase 3: Security Scanning[/]")
    scanner_list = [s.strip().lower() for s in scanners.split(",")]
    scanner_findings: list[Any] = []

    if "prowler" in scanner_list:
        from cloudmapper.scanners.prowler import ProwlerScanner

        console.print("  → Prowler...")
        s = ProwlerScanner(provider=provider, profile=profile, output_dir=str(output_dir / "prowler"))
        findings = s.run()
        scanner_findings.extend(findings)
        console.print(f"    [green]{len(findings)} findings[/]")

    if "checkov" in scanner_list and iac_dir:
        from cloudmapper.scanners.checkov import CheckovScanner

        console.print("  → Checkov...")
        s = CheckovScanner(target_dir=iac_dir)
        findings = s.run()
        scanner_findings.extend(findings)
        console.print(f"    [green]{len(findings)} findings[/]")

    if "trivy" in scanner_list and images:
        from cloudmapper.scanners.trivy import TrivyScanner

        console.print("  → Trivy...")
        s = TrivyScanner()
        findings = s.scan_images([i.strip() for i in images.split(",")])
        scanner_findings.extend(findings)
        console.print(f"    [green]{len(findings)} findings[/]")

    # IAM Linting
    console.print("  → IAM Lint...")
    iam_linter = IAMLinter()
    iam_findings = iam_linter.analyze_policies(assets)
    console.print(f"    [green]{len(iam_findings)} findings[/]")

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

    html_gen = HTMLReportGenerator(output_dir=str(output_dir))
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
