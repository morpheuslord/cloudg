"""CloudG CLI: Click-based command-line interface.

All terminal rendering goes through :mod:`cloudg.ui`, the Rich UI layer.
"""

from __future__ import annotations

import asyncio
import json
import logging
import sys
from pathlib import Path
from typing import Any

import click
from rich.logging import RichHandler

from cloudg import __version__, ui
from cloudg.cli_commands import run
from cloudg.cli_helpers import (
    _gather_ingest_reports,
    _load_scan_assets,
    _parse_ingest_reports,
    _render_ingest_reports,
    _resolve_run_images,
    _resolve_run_scanners,
    _run_scan_plan,
    _show_scan_plan,
)
from cloudg.cli_inventory import deps, map_inventory
from cloudg.mcp.cli import mcp_group
from cloudg.ui import console

# Global config reference (set by CLI group)
_config = None


def setup_logging(verbose: bool = False, log_file: str | None = None) -> None:
    """Configure structured logging with Rich + optional file output."""
    level = logging.DEBUG if verbose else logging.INFO
    handlers: list[logging.Handler] = [
        RichHandler(rich_tracebacks=True, console=console, show_path=verbose)
    ]
    if log_file:
        file_handler = logging.FileHandler(log_file)
        file_handler.setFormatter(
            logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s")
        )
        handlers.append(file_handler)
    logging.basicConfig(level=level, format="%(message)s", datefmt="[%X]", handlers=handlers)


class BannerGroup(click.Group):
    """Click group that shows the cloudg banner above its help text.

    The group callback only runs when a subcommand is invoked, so without
    this the banner would be missing from ``cloudg`` and ``cloudg --help``.
    """

    def get_help(self, ctx: click.Context) -> str:
        ui.print_banner(__version__)
        return super().get_help(ctx)

    def resolve_command(
        self, ctx: click.Context, args: list[str]
    ) -> tuple[str | None, click.Command | None, list[str]]:
        # Runs before the group callback: keep the subcommand's arguments so
        # the callback can tell whether the output is machine-readable.
        name, cmd, rest = super().resolve_command(ctx, args)
        ctx.meta["cloudg.subcommand_args"] = list(rest)
        return name, cmd, rest


def _machine_readable(ctx: click.Context) -> bool:
    """True when the subcommand writes data to stdout (``mcp``, ``--json``)."""
    if ctx.invoked_subcommand == "mcp":
        return True
    args = ctx.meta.get("cloudg.subcommand_args", [])
    if "--" in args:
        args = args[: args.index("--")]
    return "--json" in args


@click.group(cls=BannerGroup)
@click.version_option(version=__version__, prog_name="cloudg")
@click.option("-v", "--verbose", is_flag=True, help="Enable debug logging")
@click.option("-c", "--config", "config_path", default=None, help="Path to config.yaml")
@click.option("--log-file", default=None, help="Path to log file")
@click.pass_context
def cli(ctx: click.Context, verbose: bool, config_path: str | None, log_file: str | None) -> None:
    """☁️  cloudg (cloud graphing): infrastructure mapping and security intelligence."""
    global _config
    from cloudg.config import load_config

    if _machine_readable(ctx):
        # stdout carries the MCP stdio protocol or the command's JSON: the
        # banner, progress and log lines go to stderr instead
        console.stderr = True
        ctx.call_on_close(lambda: setattr(console, "stderr", False))
    ui.print_banner(__version__)
    _config = load_config(config_path)
    # Expose the loaded config to subcommands defined outside this module
    ctx.obj = _config
    effective_verbose = verbose or _config.verbose
    effective_log = log_file or _config.log_file
    setup_logging(effective_verbose, effective_log)


# ─────────────────────────────────────────────────────────────────────
# COLLECT command
# ─────────────────────────────────────────────────────────────────────


def _first_region(regions: list[str]) -> str | None:
    """The first configured region, or None for ``ALL`` / nothing."""
    from cloudg.region_discovery import is_all_regions

    if not regions or is_all_regions(regions):
        return None
    return regions[0]


def _build_collector(
    provider: str,
    resolver: Any,
    *,
    cfg: Any = None,
    profile: str | None,
    region: str | None,
    subscription_id: str | None,
    project_id: str | None,
) -> Any:
    """Resolve credentials for ``provider`` and return its collector.

    Flags win over the config's auth section (``aws``, ``azure``, ``gcp``
    in config.yaml), which wins over the environment and default chains.
    """
    from cloudg.config import CloudGConfig

    cfg = cfg or CloudGConfig()
    if provider == "aws":
        from cloudg.collectors.aws import AsyncAWSCollector

        creds = resolver.resolve_aws(
            profile=profile,
            region=region or _first_region(cfg.aws.regions),
            config=cfg.aws,
        )
        return AsyncAWSCollector(
            session=creds.session, region=creds.region, account_id=creds.account_id
        )
    if provider == "azure":
        from cloudg.collectors.azure import AzureCollector

        creds = resolver.resolve_azure(
            subscription_id=subscription_id or next(iter(cfg.azure.subscription_ids), None),
            config=cfg.azure,
        )
        return AzureCollector(
            credential=creds.credential,
            subscription_id=creds.subscription_id,
        )
    if provider == "gcp":
        from cloudg.collectors.gcp import GCPCollector

        creds = resolver.resolve_gcp(
            project_id=project_id or next(iter(cfg.gcp.project_ids), None),
            config=cfg.gcp,
        )
        return GCPCollector(project_id=creds.project_id, credentials=creds.credentials)
    raise click.BadParameter(f"Unknown provider: {provider}")


async def _collect_inventory(
    provider: str, resolver: Any, collector_kwargs: dict[str, Any]
) -> dict[str, Any]:
    """Run the provider's collector and return its assets and edges as JSON data."""
    collector = _build_collector(provider, resolver, **collector_kwargs)
    assets, edges = await collector.run()
    return {
        "assets": [a.model_dump(mode="json") for a in assets],
        "edges": [e.model_dump(mode="json") for e in edges],
    }


@cli.command()
@click.option(
    "-p",
    "--provider",
    type=click.Choice(["aws", "azure", "gcp"], case_sensitive=False),
    required=True,
    help="Cloud provider to collect from",
)
@click.option("--profile", default=None, help="AWS profile name (overrides aws.profile)")
@click.option(
    "--region",
    default=None,
    help="AWS region (default: the first of aws.regions, else AWS_DEFAULT_REGION or us-east-1)",
)
@click.option("--subscription-id", default=None, help="Azure subscription ID")
@click.option("--project-id", default=None, help="GCP project ID")
@click.option(
    "-o",
    "--output",
    default="./reports",
    help="Output directory",
)
@click.pass_context
def collect(
    ctx: click.Context,
    provider: str,
    profile: str | None,
    region: str | None,
    subscription_id: str | None,
    project_id: str | None,
    output: str,
) -> None:
    """Collect cloud assets from the specified provider.

    Credentials come from the flags, then the provider's section of
    config.yaml (-c), then the environment and default credential chain.
    """
    ui.section(f"Asset Collection: {provider.upper()}")

    from cloudg.credentials import CredentialResolver

    resolver = CredentialResolver()
    output_dir = Path(output)
    output_dir.mkdir(parents=True, exist_ok=True)

    collector_kwargs = {
        "cfg": ctx.obj,
        "profile": profile,
        "region": region,
        "subscription_id": subscription_id,
        "project_id": project_id,
    }
    try:
        with console.status(
            f"[accent]Collecting assets from {provider.upper()}…[/]", spinner="dots"
        ):
            result = asyncio.run(_collect_inventory(provider, resolver, collector_kwargs))
    except Exception as exc:
        ui.error_panel("Collection failed", exc)
        sys.exit(1)

    # Save results
    inventory_path = output_dir / f"inventory-{provider}.json"
    with open(inventory_path, "w") as f:
        json.dump(result, f, indent=2, default=str)

    ui.stats_table(
        "Collection Summary",
        {"Assets": len(result["assets"]), "Edges": len(result["edges"])},
    )
    ui.artifact("Inventory", inventory_path)


# ─────────────────────────────────────────────────────────────────────
# SCAN command
# ─────────────────────────────────────────────────────────────────────


@cli.command()
@click.option(
    "-p",
    "--provider",
    type=click.Choice(["aws", "azure", "gcp"], case_sensitive=False),
    default="aws",
    show_default=True,
    help="Cloud provider for Prowler and ScoutSuite",
)
@click.option("--profile", default=None, help="AWS profile name (overrides aws.profile)")
@click.option(
    "--iac-dir",
    default=None,
    help="IaC directory for Checkov and the Trivy filesystem scan "
    "(default: scanners.iac_directories; without either they are skipped)",
)
@click.option("--images", default=None, help="Comma-separated container images for Trivy")
@click.option(
    "--assets",
    "assets_path",
    default=None,
    help="Collected assets for the IAM linter: inventory-<provider>.json from "
    "`cloudg collect`, inventory-map.json from `cloudg map`, or a findings.json",
)
@click.option(
    "-o",
    "--output",
    default="./reports",
    help="Output directory",
)
@click.option(
    "--scanners",
    default=None,
    help="Comma-separated scanners to run (prowler,scoutsuite,checkov,trivy,iam or a "
    "plugin name). Defaults to config.yaml scanners.enabled.",
)
@click.pass_context
def scan(
    ctx: click.Context,
    provider: str,
    profile: str | None,
    iac_dir: str | None,
    images: str | None,
    assets_path: str | None,
    output: str,
    scanners: str | None,
) -> None:
    """Run security scanners and write raw-findings.json.

    Uses the scanner settings, credentials, regions and timeout from
    config.yaml (-c), like `cloudg run`. The IAM linter reads IAM policies
    from collected assets, so it only runs with --assets; without it,
    `iam` is skipped with a warning.

    Exits with status 1 when none of the requested scanners could run
    (not installed, nothing to scan, unresolved credentials) or every one
    of them failed.
    """
    ui.section("Security Scan")

    from cloudg.api_scanners import plan_scanner_jobs, resolve_iac_dirs
    from cloudg.config import CloudGConfig

    cfg: CloudGConfig = (ctx.obj or CloudGConfig()).model_copy(deep=True)
    provider = provider.lower()
    cfg.providers = [provider]
    if profile:
        cfg.aws.profile = profile

    output_dir = Path(output)
    output_dir.mkdir(parents=True, exist_ok=True)
    scanner_list = _resolve_run_scanners(cfg, scanners)
    resolved_iac_dirs, _ = resolve_iac_dirs(iac_dir, cfg.scanners.iac_directories)
    resolved_images = _resolve_run_images(images, cfg)
    try:
        assets = _load_scan_assets(assets_path)
    except (OSError, ValueError) as exc:
        ui.error_panel("Could not load --assets", exc)
        sys.exit(1)

    ui.config_panel(
        "Scan Configuration",
        {
            "Provider": provider,
            "Scanners": ", ".join(scanner_list) or "none",
            "IaC directories": ", ".join(resolved_iac_dirs) or "none",
            "Assets": str(len(assets)) if assets_path else "none (IAM linter needs --assets)",
            "Timeout": f"{cfg.scanners.timeout_seconds}s per scanner",
        },
    )

    plan = plan_scanner_jobs(
        cfg,
        scanner_list,
        providers=[provider],
        profile=profile,
        out=output_dir,
        assets=assets,
        iac_dirs=resolved_iac_dirs,
        images=resolved_images,
    )
    _show_scan_plan(plan)
    if not plan.jobs:
        ui.error_panel(
            "No scanner could run",
            f"None of the requested scanners ({', '.join(scanner_list) or 'none'}) could run; "
            "see the notes above.",
        )
        sys.exit(1)

    outcome = _run_scan_plan(plan)
    all_findings = outcome.findings

    # Save raw findings
    findings_path = output_dir / "raw-findings.json"
    with open(findings_path, "w") as f:
        json.dump(
            [f.model_dump(mode="json") for f in all_findings],
            f,
            indent=2,
            default=str,
        )

    console.print()
    ui.success(f"Total: [metric]{len(all_findings)}[/] findings")
    ui.artifact("Raw findings", findings_path)
    if not outcome.completed:
        ui.error_panel("Every scanner failed", "No requested scanner finished; see above.")
        sys.exit(1)


# ─────────────────────────────────────────────────────────────────────
# REPORT command
# ─────────────────────────────────────────────────────────────────────


@cli.command()
@click.option(
    "-i",
    "--input",
    "input_file",
    required=True,
    help="findings.json from `cloudg run` / `cloudg ingest` / a previous report, "
    "or raw-findings.json from `cloudg scan` (normalised first)",
)
@click.option(
    "-o",
    "--output",
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
@click.option(
    "--overwrite",
    is_flag=True,
    help="Allow writing findings.json over the input file",
)
def report(input_file: str, output: str, fmt: str, overwrite: bool) -> None:
    """Generate reports from existing scan data.

    A findings.json keeps its scan ID, timestamps, compliance results and
    edges. A raw-findings.json (a plain list of findings) is normalised
    (deduplicated, scored, mapped to compliance) first. The command refuses
    to write findings.json over its own input unless --overwrite is given;
    pick another -o instead.
    """
    ui.section("Report Generation")

    from cloudg.cli_helpers import _load_report_input

    input_path = Path(input_file)
    if not input_path.exists():
        ui.error_panel("Input file not found", input_path)
        sys.exit(1)

    output_dir = Path(output)
    json_target = output_dir / "findings.json"
    if (
        fmt in ("json", "all")
        and not overwrite
        and json_target.exists()
        and json_target.resolve() == input_path.resolve()
    ):
        ui.error_panel(
            "Refusing to overwrite the input",
            f"{input_path} would be replaced by the new findings.json. "
            "Pass -o <another directory>, --format html/svg, or --overwrite.",
        )
        sys.exit(1)

    try:
        scan_result, graph_data = _load_report_input(
            input_path, rules_dir=_config.rulesets.rules_dir if _config else None
        )
    except (OSError, ValueError) as exc:
        ui.error_panel("Could not read the input", exc)
        sys.exit(1)

    output_dir.mkdir(parents=True, exist_ok=True)

    if fmt in ("json", "all"):
        from cloudg.renderers.json_export import JSONExporter

        exporter = JSONExporter(output_dir=str(output_dir))
        path = exporter.export(scan_result, graph_json=graph_data)
        ui.artifact("JSON", path)

    if fmt in ("svg", "all"):
        from cloudg.renderers.svg import SVGRenderer

        renderer = SVGRenderer(output_dir=str(output_dir))
        path = renderer.render(scan_result.assets, scan_result.edges)
        ui.artifact("SVG", path)

    if fmt in ("html", "all"):
        from cloudg.renderers.html_report import HTMLReportGenerator

        generator = HTMLReportGenerator(
            output_dir=str(output_dir), inline_js=_config.report.inline_js if _config else True
        )
        path = generator.generate(scan_result, graph_json=graph_data)
        ui.artifact("HTML", path)


# ─────────────────────────────────────────────────────────────────────
# INGEST command (use existing scanner outputs)
# ─────────────────────────────────────────────────────────────────────


def _normalise_and_report_ingest(
    all_findings: list[Any], tool_count: int, output: str, fmt: str
) -> None:
    """Normalise ingested findings, then write the raw findings and the reports."""
    # Normalise: dedupe within and across scanners, score, map compliance
    from cloudg.normaliser import FindingsNormaliser

    cfg = _config
    normaliser = FindingsNormaliser(
        rules_dir=cfg.rulesets.rules_dir if cfg else None,
        load_external=cfg.rulesets.load_external if cfg else True,
    )
    scan_result = normaliser.normalise(all_findings)

    output_dir = Path(output)
    output_dir.mkdir(parents=True, exist_ok=True)

    # Save raw (pre-normalisation) findings alongside the reports
    raw_path = output_dir / "raw-findings.json"
    with open(raw_path, "w") as f:
        dumped = [fi.model_dump(mode="json") for fi in all_findings]
        json.dump(dumped, f, indent=2, default=str)

    _render_ingest_reports(
        scan_result, fmt, output_dir, inline_js=cfg.report.inline_js if cfg else True
    )

    ui.artifact("Raw findings", raw_path)

    console.print()
    ui.success(
        f"Ingested [metric]{len(all_findings)}[/] findings from {tool_count} tool(s), "
        f"[metric]{len(scan_result.findings)}[/] after deduplication"
    )


@cli.command()
@click.option(
    "--prowler",
    "prowler_paths",
    multiple=True,
    help="Prowler ASFF or OCSF JSON output (file or output directory). Repeatable.",
)
@click.option(
    "--scoutsuite",
    "scoutsuite_paths",
    multiple=True,
    help="ScoutSuite results (scoutsuite_results_*.js file or report directory). Repeatable.",
)
@click.option(
    "--checkov",
    "checkov_paths",
    multiple=True,
    help="Checkov JSON output (file or directory containing results_json.json). Repeatable.",
)
@click.option(
    "--trivy",
    "trivy_paths",
    multiple=True,
    help="Trivy JSON output from image or fs scans (file or directory). Repeatable.",
)
@click.option(
    "-o",
    "--output",
    default="./reports",
    help="Output directory for reports",
)
@click.option(
    "--format",
    "fmt",
    type=click.Choice(["html", "json", "all"]),
    default="all",
    help="Report format",
)
def ingest(
    prowler_paths: tuple[str, ...],
    scoutsuite_paths: tuple[str, ...],
    checkov_paths: tuple[str, ...],
    trivy_paths: tuple[str, ...],
    output: str,
    fmt: str,
) -> None:
    """Aggregate existing scanner outputs; no scanners are executed.

    Feed cloudg the native output files of scans you already ran
    (Prowler, ScoutSuite, Checkov, Trivy, in any combination) and it
    normalises, deduplicates across scanners via the check-equivalence
    rulesets, maps compliance frameworks, and generates reports.

    Example:

        cloudg ingest --prowler ./prowler-out/ --trivy ./trivy.json
    """
    ui.section("Ingest Scanner Outputs")

    reports = _gather_ingest_reports(prowler_paths, scoutsuite_paths, checkov_paths, trivy_paths)
    if not reports:
        msg = "Pass at least one report: --prowler, --scoutsuite, --checkov, or --trivy"
        ui.error_panel("No inputs", msg)
        sys.exit(1)

    ui.config_panel(
        "Ingest Configuration",
        {tool: ", ".join(paths) for tool, paths in reports.items()},
    )

    all_findings, per_tool = _parse_ingest_reports(reports)

    if not all_findings:
        ui.warn("No findings parsed from the given reports")

    _normalise_and_report_ingest(all_findings, len(per_tool), output, fmt)


# ─────────────────────────────────────────────────────────────────────
# RUN command (full pipeline): defined in cloudg.cli_commands
# MAP / DEPS commands (inventory mapping): defined in cloudg.cli_inventory
# ─────────────────────────────────────────────────────────────────────

cli.add_command(run)
cli.add_command(map_inventory)
cli.add_command(deps)
cli.add_command(mcp_group)


if __name__ == "__main__":
    # Click injects the arguments at call time
    cli()  # pylint: disable=no-value-for-parameter
