"""CloudG CLI — Click-based command-line interface.

All terminal rendering goes through :mod:`cloudg.ui`, the Rich UI layer.
"""

from __future__ import annotations

import asyncio
import json
import logging
import sys
from pathlib import Path
from typing import TYPE_CHECKING, Any

import click
from rich.logging import RichHandler

from cloudg import __version__, ui
from cloudg.ui import console

if TYPE_CHECKING:
    from cloudg.config import CloudGConfig

logger = logging.getLogger(__name__)

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


@click.group(cls=BannerGroup)
@click.version_option(version=__version__, prog_name="cloudg")
@click.option("-v", "--verbose", is_flag=True, help="Enable debug logging")
@click.option("-c", "--config", "config_path", default=None, help="Path to config.yaml")
@click.option("--log-file", default=None, help="Path to log file")
def cli(verbose: bool, config_path: str | None, log_file: str | None) -> None:
    """☁️  cloudg — cloud graphing: infrastructure mapping and security intelligence."""
    global _config
    from cloudg.config import load_config

    ui.print_banner(__version__)
    _config = load_config(config_path)
    effective_verbose = verbose or _config.verbose
    effective_log = log_file or _config.log_file
    setup_logging(effective_verbose, effective_log)


# ─────────────────────────────────────────────────────────────────────
# COLLECT command
# ─────────────────────────────────────────────────────────────────────


@cli.command()
@click.option(
    "-p",
    "--provider",
    type=click.Choice(["aws", "azure", "gcp"], case_sensitive=False),
    required=True,
    help="Cloud provider to collect from",
)
@click.option("--profile", default=None, help="AWS profile name")
@click.option("--region", default="us-east-1", help="AWS region")
@click.option("--subscription-id", default=None, help="Azure subscription ID")
@click.option("--project-id", default=None, help="GCP project ID")
@click.option(
    "-o",
    "--output",
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
    ui.section(f"Asset Collection — {provider.upper()}")

    from cloudg.credentials import CredentialResolver

    resolver = CredentialResolver()
    output_dir = Path(output)
    output_dir.mkdir(parents=True, exist_ok=True)

    async def _collect() -> dict[str, Any]:
        if provider == "aws":
            from cloudg.collectors.aws import AsyncAWSCollector

            creds = resolver.resolve_aws(profile=profile, region=region)
            collector = AsyncAWSCollector(
                session=creds.session, region=creds.region, account_id=creds.account_id
            )
        elif provider == "azure":
            from cloudg.collectors.azure import AzureCollector

            creds = resolver.resolve_azure(subscription_id=subscription_id)
            collector = AzureCollector(
                credential=creds.credential,
                subscription_id=creds.subscription_id,
            )
        elif provider == "gcp":
            from cloudg.collectors.gcp import GCPCollector

            creds = resolver.resolve_gcp(project_id=project_id)
            collector = GCPCollector(project_id=creds.project_id, credentials=creds.credentials)
        else:
            raise click.BadParameter(f"Unknown provider: {provider}")

        assets, edges = await collector.run()
        return {
            "assets": [a.model_dump(mode="json") for a in assets],
            "edges": [e.model_dump(mode="json") for e in edges],
        }

    try:
        with console.status(
            f"[accent]Collecting assets from {provider.upper()}…[/]", spinner="dots"
        ):
            result = asyncio.run(_collect())
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


def _parse_region_flag(scan_regions: str) -> list[str]:
    """Parse a --regions flag value into a region list ('all' → ['ALL'])."""
    if scan_regions.lower() == "all":
        return ["ALL"]
    return [r.strip() for r in scan_regions.split(",")]


# ─────────────────────────────────────────────────────────────────────
# MAP command (scanner-independent inventory mapping)
# ─────────────────────────────────────────────────────────────────────


@cli.command(name="map")
@click.option(
    "-p",
    "--provider",
    type=click.Choice(["aws", "azure", "gcp", "all"], case_sensitive=False),
    multiple=True,
    default=("aws",),
    show_default=True,
    help="Provider(s) to map. Use multiple times or 'all'.",
)
@click.option("--profile", default=None, help="AWS profile name")
@click.option(
    "--regions",
    "scan_regions",
    default=None,
    help="Regions: 'all' for auto-discovery, or comma-separated list",
)
@click.option("--subscription-id", default=None, help="Azure subscription ID")
@click.option("--project-id", default=None, help="GCP project ID")
@click.option(
    "--findings",
    "findings_paths",
    multiple=True,
    help="Existing cloudg findings JSON (raw-findings.json or a cloudg report) "
    "to merge into asset/compliance maps. Repeatable.",
)
@click.option(
    "--sweep/--no-sweep",
    default=True,
    show_default=True,
    help="Catch-all sweep (AWS Resource Groups Tagging API) for resources "
    "without a dedicated collector",
)
@click.option("-o", "--output", default="./reports", help="Output directory")
def map_inventory(
    provider: tuple[str, ...],
    profile: str | None,
    scan_regions: str | None,
    subscription_id: str | None,
    project_id: str | None,
    findings_paths: tuple[str, ...],
    sweep: bool,
    output: str,
) -> None:
    """Map the complete infrastructure inventory — no scanners involved.

    Deep-collects everything deployed (or default) across the configured
    providers, including the network fabric (route tables, gateways, ENIs,
    volumes, peering) and a catch-all sweep so services without a dedicated
    collector still appear. Every asset is then linked into an
    interconnected map: attachment, containment, routing, and
    cross-service references.

    Optionally merge previously generated scanner findings to produce an
    asset map and a compliance map:

        cloudg map -p aws --regions all --findings ./reports/raw-findings.json
    """
    ui.section("Inventory Mapping")

    from cloudg.config import CloudGConfig
    from cloudg.inventory import InventoryMapper

    cfg: CloudGConfig = _config or CloudGConfig()

    providers_list = list(provider)
    if "all" in providers_list:
        providers_list = ["aws", "azure", "gcp"]
    cfg.providers = providers_list

    if scan_regions:
        region_list = _parse_region_flag(scan_regions)
        cfg.aws.regions = region_list
        cfg.azure.regions = region_list
        cfg.gcp.regions = region_list
    if profile:
        cfg.aws.profile = profile
    if subscription_id:
        cfg.azure.subscription_ids = [subscription_id]
    if project_id:
        cfg.gcp.project_ids = [project_id]

    ui.config_panel(
        "Map Configuration",
        {
            "Providers": ", ".join(cfg.providers),
            "AWS regions": ", ".join(cfg.aws.regions),
            "Catch-all sweep": "enabled" if sweep else "disabled",
            "Scanners": "none (inventory mapping is scanner-independent)",
        },
    )

    mapper = InventoryMapper(cfg, tagging_sweep=sweep)

    try:
        with console.status("[accent]Mapping infrastructure inventory…[/]", spinner="dots"):
            result = mapper.map_inventory_sync()
    except Exception as exc:
        ui.error_panel("Inventory mapping failed", exc)
        sys.exit(1)

    output_dir = Path(output)
    paths = result.export(output_dir)

    summary = result.summary
    ui.stats_table(
        "Inventory Summary",
        {
            "Assets": summary["total_assets"],
            "Interconnections": summary["total_edges"],
            "Services": len(summary["assets_by_service"]),
            "Internet-exposed": summary["internet_exposed"],
            "Unlinked assets": summary["unlinked_assets"],
        },
    )
    for svc, count in list(summary["assets_by_service"].items())[:15]:
        ui.detail(f"{svc}: {count} assets")

    ui.artifact("Inventory map", paths["map"])
    ui.artifact("GraphML", paths["graphml"])
    ui.artifact("Graph JSON", paths["graph"])

    # Optional merge with existing scanner findings
    if findings_paths:
        from cloudg.schema.models import Finding

        findings: list[Any] = []
        for fpath in findings_paths:
            try:
                with open(fpath) as f:
                    data = json.load(f)
                raw = data if isinstance(data, list) else data.get("findings", [])
                findings.extend(Finding.model_validate(item) for item in raw)
            except (OSError, ValueError) as exc:
                ui.warn(f"Skipping findings file {fpath}: {exc}")

        if findings:
            merged_paths = mapper.export_merged(result, findings, output_dir)
            ui.success(f"Merged [metric]{len(findings)}[/] findings into the inventory")
            ui.artifact("Asset map", merged_paths["asset_map"])
            ui.artifact("Compliance map", merged_paths["compliance_map"])

    console.print()
    ui.success(f"Inventory map saved to [path]{output_dir}[/]")


# ─────────────────────────────────────────────────────────────────────
# SCAN command
# ─────────────────────────────────────────────────────────────────────


def _basic_prowler(provider: str, profile: str | None, output_dir: Path) -> list[Any]:
    from cloudg.scanners.prowler import ProwlerScanner

    s = ProwlerScanner(provider=provider, profile=profile, output_dir=str(output_dir / "prowler"))
    return s.run()


def _basic_scoutsuite(provider: str, profile: str | None, output_dir: Path) -> list[Any]:
    from cloudg.scanners.scoutsuite import ScoutSuiteScanner

    s = ScoutSuiteScanner(
        provider=provider, profile=profile, report_dir=str(output_dir / "scoutsuite")
    )
    return s.run()


def _basic_checkov(iac_dir: str) -> list[Any]:
    from cloudg.scanners.checkov import CheckovScanner

    return CheckovScanner(target_dir=iac_dir).run()


def _basic_trivy_images(images: list[str]) -> list[Any]:
    from cloudg.scanners.trivy import TrivyScanner

    return TrivyScanner().scan_images(images)


def _basic_trivy_fs(iac_dir: str) -> list[Any]:
    from cloudg.scanners.trivy import TrivyScanner

    return TrivyScanner().scan_filesystem([iac_dir])


def _build_scan_jobs(
    provider: str,
    profile: str | None,
    scanner_list: list[str],
    iac_dir: str,
    images: list[str],
    output_dir: Path,
) -> list[tuple[str, str, Any]]:
    """Build (name, progress description, callable) tuples for `cloudg scan`."""
    jobs: list[tuple[str, str, Any]] = []
    if "prowler" in scanner_list:
        jobs.append(("Prowler", "Prowler", lambda: _basic_prowler(provider, profile, output_dir)))
    if "scoutsuite" in scanner_list:
        jobs.append(
            ("ScoutSuite", "ScoutSuite", lambda: _basic_scoutsuite(provider, profile, output_dir))
        )
    if "checkov" in scanner_list:
        jobs.append(
            (
                "Checkov",
                f"Checkov [muted](target: {iac_dir})[/]",
                lambda: _basic_checkov(iac_dir),
            )
        )
    if "trivy" in scanner_list:
        if images:
            jobs.append(
                (
                    "Trivy",
                    f"Trivy [muted]({len(images)} images)[/]",
                    lambda: _basic_trivy_images(images),
                )
            )
        else:
            ui.warn("Trivy: no images specified, falling back to filesystem scan")
            jobs.append(
                (
                    "Trivy (filesystem)",
                    f"Trivy filesystem [muted](target: {iac_dir})[/]",
                    lambda: _basic_trivy_fs(iac_dir),
                )
            )
    return jobs


def _run_scan_jobs(jobs: list[tuple[str, str, Any]]) -> list[Any]:
    """Execute scan jobs in parallel with progress display; return all findings."""
    import concurrent.futures

    all_findings: list[Any] = []
    with ui.scanner_progress() as progress:
        with concurrent.futures.ThreadPoolExecutor(max_workers=len(jobs) + 1) as executor:
            future_to_task: dict[concurrent.futures.Future, tuple[str, Any]] = {}
            for name, description, fn in jobs:
                task_id = progress.add_task(description, total=None)
                future_to_task[executor.submit(fn)] = (name, task_id)

            for future in concurrent.futures.as_completed(future_to_task):
                name, task_id = future_to_task[future]
                try:
                    findings = future.result(timeout=3600)
                    all_findings.extend(findings)
                    ui.task_done(progress, task_id, f"{name} — {len(findings)} findings")
                except Exception as exc:
                    ui.task_failed(progress, task_id, f"{name} failed: {exc}")
    return all_findings


@cli.command()
@click.option("-p", "--provider", default="aws", help="Cloud provider")
@click.option("--profile", default=None, help="AWS profile name")
@click.option("--iac-dir", default=None, help="IaC directory for Checkov (defaults to '.')")
@click.option("--images", default=None, help="Comma-separated container images for Trivy")
@click.option(
    "-o",
    "--output",
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
    ui.section("Security Scan")

    output_dir = Path(output)
    output_dir.mkdir(parents=True, exist_ok=True)
    scanner_list = [s.strip().lower() for s in scanners.split(",")]

    resolved_iac_dir = iac_dir or "."
    resolved_images = [i.strip() for i in images.split(",")] if images else []

    ui.config_panel(
        "Scan Configuration",
        {"Provider": provider, "Scanners": ", ".join(scanner_list)},
    )

    jobs = _build_scan_jobs(
        provider, profile, scanner_list, resolved_iac_dir, resolved_images, output_dir
    )
    all_findings = _run_scan_jobs(jobs)

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


# ─────────────────────────────────────────────────────────────────────
# REPORT command
# ─────────────────────────────────────────────────────────────────────


@cli.command()
@click.option(
    "-i",
    "--input",
    "input_file",
    required=True,
    help="Path to findings.json from a previous run",
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
def report(input_file: str, output: str, fmt: str) -> None:
    """Generate reports from existing scan data."""
    ui.section("Report Generation")

    input_path = Path(input_file)
    if not input_path.exists():
        ui.error_panel("Input file not found", input_path)
        sys.exit(1)

    output_dir = Path(output)
    output_dir.mkdir(parents=True, exist_ok=True)

    with open(input_path) as f:
        data = json.load(f)

    from cloudg.schema.models import CloudAsset, Finding, ScanResult

    # Reconstruct ScanResult
    assets = [CloudAsset.model_validate(a) for a in data.get("assets", [])]
    findings = [Finding.model_validate(f) for f in data.get("findings", [])]
    graph_data = data.get("graph", {"nodes": [], "links": []})

    scan_result = ScanResult(assets=assets, findings=findings)

    if fmt in ("json", "all"):
        from cloudg.renderers.json_export import JSONExporter

        exporter = JSONExporter(output_dir=str(output_dir))
        path = exporter.export(scan_result, graph_json=graph_data)
        ui.artifact("JSON", path)

    if fmt in ("svg", "all"):
        from cloudg.renderers.svg import SVGRenderer

        renderer = SVGRenderer(output_dir=str(output_dir))
        path = renderer.render(assets, scan_result.edges)
        ui.artifact("SVG", path)

    if fmt in ("html", "all"):
        from cloudg.renderers.html_report import HTMLReportGenerator

        generator = HTMLReportGenerator(output_dir=str(output_dir))
        path = generator.generate(scan_result, graph_json=graph_data)
        ui.artifact("HTML", path)


# ─────────────────────────────────────────────────────────────────────
# INGEST command (use existing scanner outputs)
# ─────────────────────────────────────────────────────────────────────


def _gather_ingest_reports(
    prowler_paths: tuple[str, ...],
    scoutsuite_paths: tuple[str, ...],
    checkov_paths: tuple[str, ...],
    trivy_paths: tuple[str, ...],
) -> dict[str, list[str]]:
    """Group the per-tool report paths passed on the command line."""
    reports: dict[str, list[str]] = {}
    for tool, paths in (
        ("prowler", prowler_paths),
        ("scoutsuite", scoutsuite_paths),
        ("checkov", checkov_paths),
        ("trivy", trivy_paths),
    ):
        if paths:
            reports[tool] = list(paths)
    return reports


def _parse_ingest_reports(reports: dict[str, list[str]]) -> tuple[list[Any], dict[str, int]]:
    """Parse each report file into findings; returns (findings, per-tool counts)."""
    from cloudg.ingest import parse_report

    all_findings: list[Any] = []
    per_tool: dict[str, int] = {}
    for tool, paths in reports.items():
        count = 0
        for path in paths:
            try:
                findings = parse_report(tool, path)
            except (ValueError, FileNotFoundError) as exc:
                ui.warn(f"{tool}: skipping {path} — {exc}")
                continue
            count += len(findings)
            all_findings.extend(findings)
        per_tool[tool] = count
        ui.detail(f"{tool}: {count} findings")
    return all_findings, per_tool


def _render_ingest_reports(scan_result: Any, fmt: str, output_dir: Path) -> None:
    """Render the requested report formats for `cloudg ingest`."""
    if fmt in ("json", "all"):
        from cloudg.renderers.json_export import JSONExporter

        exporter = JSONExporter(output_dir=str(output_dir))
        path = exporter.export(scan_result)
        ui.artifact("JSON", path)

    if fmt in ("html", "all"):
        from cloudg.renderers.html_report import HTMLReportGenerator

        generator = HTMLReportGenerator(output_dir=str(output_dir))
        path = generator.generate(scan_result)
        ui.artifact("HTML", path)


@cli.command()
@click.option(
    "--prowler",
    "prowler_paths",
    multiple=True,
    help="Prowler ASFF JSON output (file or output directory). Repeatable.",
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
    """Aggregate existing scanner outputs — no scanners are executed.

    Feed cloudg the native output files of scans you already ran
    (Prowler, ScoutSuite, Checkov, Trivy — any combination) and it
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

    # Normalise: dedupe within and across scanners, score, map compliance
    from cloudg.normaliser import FindingsNormaliser

    cfg = _config
    normaliser = FindingsNormaliser(rules_dir=cfg.rulesets.rules_dir if cfg else None)
    scan_result = normaliser.normalise(all_findings)

    output_dir = Path(output)
    output_dir.mkdir(parents=True, exist_ok=True)

    # Save raw (pre-normalisation) findings alongside the reports
    raw_path = output_dir / "raw-findings.json"
    with open(raw_path, "w") as f:
        dumped = [fi.model_dump(mode="json") for fi in all_findings]
        json.dump(dumped, f, indent=2, default=str)

    _render_ingest_reports(scan_result, fmt, output_dir)

    ui.artifact("Raw findings", raw_path)

    console.print()
    ui.success(
        f"Ingested [metric]{len(all_findings)}[/] findings from {len(per_tool)} tool(s) — "
        f"[metric]{len(scan_result.findings)}[/] after deduplication"
    )


# ─────────────────────────────────────────────────────────────────────
# RUN command (full pipeline)
# ─────────────────────────────────────────────────────────────────────

# CLI flag → (config section, attribute) for direct credential injection
_CREDENTIAL_OVERRIDES: tuple[tuple[str, str, str], ...] = (
    ("aws_key", "aws", "access_key_id"),
    ("aws_secret", "aws", "secret_access_key"),
    ("aws_session_token", "aws", "session_token"),
    ("aws_role_arn", "aws", "role_arn"),
    ("aws_external_id", "aws", "external_id"),
    ("aws_web_identity_token_file", "aws", "web_identity_token_file"),
    ("azure_tenant_id", "azure", "tenant_id"),
    ("azure_client_id", "azure", "client_id"),
    ("azure_client_secret", "azure", "client_secret"),
    ("azure_cert_path", "azure", "certificate_path"),
    ("azure_federated_token_file", "azure", "federated_token_file"),
    ("gcp_credentials_file", "gcp", "credentials_file"),
    ("gcp_impersonate_sa", "gcp", "impersonate_service_account"),
)


def _apply_run_overrides(cfg: CloudGConfig, kwargs: dict[str, Any]) -> None:
    """Apply `cloudg run` CLI flags (providers, regions, credentials) onto the config."""
    providers_list = list(kwargs["provider"])
    if "all" in providers_list:
        providers_list = ["aws", "azure", "gcp"]
    cfg.providers = providers_list

    scan_regions = kwargs["scan_regions"]
    if scan_regions:
        region_list = _parse_region_flag(scan_regions)
        cfg.aws.regions = region_list
        cfg.azure.regions = region_list
        cfg.gcp.regions = region_list
    elif kwargs["region"]:
        cfg.aws.regions = [kwargs["region"]]

    if kwargs["subscription_id"]:
        cfg.azure.subscription_ids = [kwargs["subscription_id"]]
    if kwargs["project_id"]:
        cfg.gcp.project_ids = [kwargs["project_id"]]
    if kwargs["profile"]:
        cfg.aws.profile = kwargs["profile"]
    if kwargs["azure_managed_identity"]:
        cfg.azure.use_managed_identity = True
    for flag, section, attr in _CREDENTIAL_OVERRIDES:
        value = kwargs[flag]
        if value:
            setattr(getattr(cfg, section), attr, value)


def _resolve_run_scanners(cfg: CloudGConfig, scanners: str | None) -> list[str]:
    """Resolve the scanner list from the CLI flag or config.yaml scanners.enabled."""
    if scanners is not None:
        return [s.strip().lower() for s in scanners.split(",")]
    return [s.strip().lower() for s in cfg.scanners.enabled]


def _show_run_config(cfg: CloudGConfig, scanner_list: list[str], output_dir: Path) -> None:
    """Print the run configuration panel."""
    run_config: dict[str, str] = {
        "Providers": ", ".join(cfg.providers),
        "Scanners": ", ".join(scanner_list),
        "AWS regions": ", ".join(cfg.aws.regions),
    }
    if "azure" in cfg.providers:
        run_config["Azure regions"] = ", ".join(cfg.azure.regions)
    if "gcp" in cfg.providers:
        run_config["GCP regions"] = ", ".join(cfg.gcp.regions)
    run_config["Output"] = str(output_dir)
    ui.config_panel("Run Configuration", run_config)


def _resolve_run_images(images: str | None, cfg: CloudGConfig) -> list[str]:
    """Resolve container images for Trivy: CLI flag → config."""
    if images:
        return [i.strip() for i in images.split(",")]
    if cfg.scanners.trivy_images:
        return list(cfg.scanners.trivy_images)
    return []


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
    """Submit Prowler and ScoutSuite — one instance per provider."""
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
            "Checkov: nothing to scan — pass --iac-dir, set "
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
            ui.warn("Trivy: nothing to scan — configure --images, --iac-dir, or enable --terraform")
    else:
        ui.skip("Trivy: not enabled")

    # IAM Linter — always runs internally to analyze collected assets
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
            ui.task_done(progress, task_id, f"{scanner_name} — {len(findings)} findings")
        except concurrent.futures.TimeoutError:
            ui.task_failed(
                progress,
                task_id,
                f"{scanner_name} timed out after {cfg.scanners.timeout_seconds}s",
            )
        except Exception as exc:
            ui.task_failed(progress, task_id, f"{scanner_name} failed: {exc}")


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
    import concurrent.futures

    ui.phase("Phase 3 · Security Scanning", note="running scanners in parallel")

    # ── Resolve IaC scan targets: CLI flag → config → Terraform recreation ──
    # No fallback to "." — scanning the directory cloudg runs from is not a
    # scan of the cloud, and its zero findings look like a clean result.
    from cloudg.api import resolve_iac_dirs

    resolved_iac_dirs, iac_source = resolve_iac_dirs(iac_dir, cfg.scanners.iac_directories, tf_dir)
    if iac_source == "terraform":
        ui.detail(
            "IaC scanners target the Terraform recreation of the live "
            f"infrastructure ({resolved_iac_dirs[0]})"
        )

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


@cli.command()
@click.option(
    "-p",
    "--provider",
    type=click.Choice(["aws", "azure", "gcp", "all"], case_sensitive=False),
    multiple=True,
    required=True,
    help="Cloud provider(s) to scan. Use multiple times or 'all' for simultaneous scanning.",
)
@click.option("--profile", default=None, help="AWS profile name (fallback if no direct keys)")
@click.option("--aws-key", default=None, help="AWS access key ID (direct credential)")
@click.option("--aws-secret", default=None, help="AWS secret access key (direct credential)")
@click.option("--aws-session-token", default=None, help="AWS session token (temporary credentials)")
@click.option(
    "--aws-role-arn",
    default=None,
    help="Role ARN to assume via STS (or OIDC target with --aws-web-identity-token-file)",
)
@click.option(
    "--aws-external-id",
    default=None,
    help="ExternalId for AssumeRole (third-party auditor pattern)",
)
@click.option(
    "--aws-web-identity-token-file",
    default=None,
    help="OIDC token file for AssumeRoleWithWebIdentity (GitHub Actions, EKS)",
)
@click.option("--region", default=None, help="AWS region (ignored if --regions is set)")
@click.option("--subscription-id", default=None, help="Azure subscription ID")
@click.option(
    "--azure-tenant-id",
    default=None,
    help="Azure AD tenant ID (service principal / workload identity)",
)
@click.option(
    "--azure-client-id", default=None, help="Azure service principal or workload identity client ID"
)
@click.option("--azure-client-secret", default=None, help="Azure service principal client secret")
@click.option("--azure-cert-path", default=None, help="Azure service principal certificate path")
@click.option(
    "--azure-federated-token-file",
    default=None,
    help="Federated OIDC token file (Azure workload identity)",
)
@click.option(
    "--azure-managed-identity",
    is_flag=True,
    default=False,
    help="Authenticate with the host's Azure managed identity",
)
@click.option("--project-id", default=None, help="GCP project ID")
@click.option(
    "--gcp-credentials-file",
    default=None,
    help="GCP service account key JSON or workload identity federation config",
)
@click.option("--gcp-impersonate-sa", default=None, help="GCP service account email to impersonate")
@click.option("--iac-dir", default=None, help="IaC directory for Checkov")
@click.option("--images", default=None, help="Container images for Trivy (comma-separated)")
@click.option(
    "-o",
    "--output",
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
@click.option(
    "--terraform/--no-terraform", default=False, help="Generate Terraform .tf.json recreation files"
)
@click.option(
    "--regions",
    "scan_regions",
    default=None,
    help="Regions to scan: 'all' for auto-discovery, or comma-separated list (e.g. 'us-east-1,eu-west-1')",
)
def run(**kwargs: Any) -> None:
    """Run the full pipeline: collect → scan → normalise → render.

    Supports multi-provider scanning:
        cloudg run -p aws -p azure
        cloudg run -p all
        cloudg run -p aws --regions all
        cloudg run -p aws --aws-key AKIAXX --aws-secret yyy
    """
    ui.section("Full Pipeline")

    output_dir = Path(kwargs["output"])
    output_dir.mkdir(parents=True, exist_ok=True)

    from cloudg.config import CloudGConfig
    from cloudg.normaliser import FindingsNormaliser

    # Use global config if loaded, else defaults; then apply CLI overrides
    cfg: CloudGConfig = _config or CloudGConfig()
    _apply_run_overrides(cfg, kwargs)

    scanner_list = _resolve_run_scanners(cfg, kwargs["scanners"])
    _show_run_config(cfg, scanner_list, output_dir)
    resolved_images = _resolve_run_images(kwargs["images"], cfg)

    # Phase 1: Asset Collection (always uses multi-provider orchestrator)
    assets, edges, coverage_records = _collect_assets(cfg)

    # Phase 2: Graph Analysis
    graph, graph_json, reachability_findings = _graph_phase(cfg, assets, edges, output_dir)

    # Phase 2b: Semantic Ontology — deferred to after scanner phase
    # (so security/compliance findings can be included in the ontology)

    # Phase 2c: RAG Export
    rag_enabled = kwargs["rag_export"] and cfg.rag.enabled
    if rag_enabled:
        _export_rag_phase(cfg, assets, edges, graph, reachability_findings, output_dir)

    # Phase 2d: Terraform Recreation
    tf_dir = _terraform_phase(cfg, kwargs["terraform"], assets, edges, output_dir)

    # Phase 3: Security Scanning (all scanners in parallel)
    scanner_findings, iam_findings = _scanner_phase(
        cfg,
        scanner_list,
        kwargs["profile"],
        kwargs["iac_dir"],
        resolved_images,
        tf_dir,
        assets,
        output_dir,
    )

    # Combine all findings for downstream phases
    all_security_findings = scanner_findings + iam_findings + reachability_findings
    console.print()
    ui.success(f"[bold]Phase 3 complete:[/] [metric]{len(all_security_findings)}[/] total findings")

    # Phase 3b: Semantic Ontology (runs AFTER scanners so findings are included)
    if kwargs["ontology"] and cfg.ontology.enabled:
        _ontology_phase(cfg, assets, edges, all_security_findings, output_dir)

    # Also update RAG export with all findings
    if rag_enabled:
        _update_rag_export(cfg, assets, edges, graph, all_security_findings, output_dir)

    # Phase 4: Normalise (with external rulesets)
    ui.phase("Phase 4 · Normalisation")
    normaliser = FindingsNormaliser(rules_dir=cfg.rulesets.rules_dir)
    scan_result = normaliser.normalise(
        reachability_findings, scanner_findings, iam_findings, assets=assets
    )
    scan_result.edges = edges
    ui.success(f"[metric]{len(scan_result.findings)}[/] normalised findings")

    # Phase 5: Render
    _render_run_reports(scan_result, graph_json, assets, edges, output_dir)

    # Summary
    ui.section("Results")
    ui.summary_table(scan_result.summary)

    # Coverage summary
    if coverage_records:
        ui.coverage_table(coverage_records)

    console.print()
    ui.success(f"All reports saved to [path]{output_dir}[/]")


if __name__ == "__main__":
    # Click injects the arguments at call time
    cli()  # pylint: disable=no-value-for-parameter
