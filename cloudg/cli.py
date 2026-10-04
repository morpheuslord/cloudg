"""CloudG CLI — Click-based command-line interface.

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
    _build_scan_jobs,
    _gather_ingest_reports,
    _parse_ingest_reports,
    _parse_region_flag,
    _render_ingest_reports,
    _run_scan_jobs,
)
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


@click.group(cls=BannerGroup)
@click.version_option(version=__version__, prog_name="cloudg")
@click.option("-v", "--verbose", is_flag=True, help="Enable debug logging")
@click.option("-c", "--config", "config_path", default=None, help="Path to config.yaml")
@click.option("--log-file", default=None, help="Path to log file")
@click.pass_context
def cli(ctx: click.Context, verbose: bool, config_path: str | None, log_file: str | None) -> None:
    """☁️  cloudg — cloud graphing: infrastructure mapping and security intelligence."""
    global _config
    from cloudg.config import load_config

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
    "--accounts",
    default=None,
    help="AWS: comma-separated account IDs to map (assumes --role-name in each)",
)
@click.option("--role-name", default=None, help="AWS: role to assume in each mapped account")
@click.option(
    "--org/--no-org",
    "org",
    default=None,
    help="AWS: discover every account in the Organization / Control Tower "
    "landing zone and map them all (run from the management account)",
)
@click.option(
    "--org-role",
    default=None,
    help="AWS: role assumed in member accounts (default AWSControlTowerExecution)",
)
@click.option("--ou", "ous", multiple=True, help="AWS: only accounts under this OU (ID or name). Repeatable.")
@click.option(
    "--exclude-account", "exclude_accounts", multiple=True, help="AWS: skip this account. Repeatable."
)
@click.option(
    "--ct-home-region", default=None, help="AWS: Control Tower home region (auto-detected)"
)
@click.option(
    "--services",
    default=None,
    help="Service families/collectors to map, comma-separated (e.g. containers,serverless,security)",
)
@click.option(
    "--exclude-services", default=None, help="Service families/collectors to skip, comma-separated"
)
@click.option(
    "--kubernetes/--no-kubernetes",
    default=None,
    help="Map workloads inside EKS clusters through the Kubernetes API",
)
@click.option(
    "--cloud-control/--no-cloud-control",
    default=None,
    help="AWS: list every resource type with a Cloud Control list handler, "
    "tagged or not (breadth for services without a dedicated collector)",
)
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
    accounts: str | None,
    role_name: str | None,
    org: bool | None,
    org_role: str | None,
    ous: tuple[str, ...],
    exclude_accounts: tuple[str, ...],
    ct_home_region: str | None,
    services: str | None,
    exclude_services: str | None,
    kubernetes: bool | None,
    cloud_control: bool | None,
    findings_paths: tuple[str, ...],
    sweep: bool,
    output: str,
) -> None:
    """Map the complete infrastructure inventory — no scanners involved.

    Deep-collects everything deployed (or default) across the configured
    providers: the network fabric, compute, containers (ECR, ECS, EKS and
    the Kubernetes workloads inside clusters), serverless and event wiring,
    data stores, DNS, CloudFormation stacks, IAM, and the security services
    and scanners watching it all. Every asset is linked into an
    interconnected map with typed relationships (invokes, uses image,
    assumes role, protects, monitors, manages, governs, ...).

    With --org, every account of the AWS Organization is mapped, together
    with the OU tree, SCPs and, when present, the Control Tower landing
    zone, its governed regions and enabled controls:

    \b
        cloudg map -p aws --org --regions all

    Optionally merge previously generated scanner findings to produce an
    asset map and a compliance map:

    \b
        cloudg map -p aws --regions all --findings ./reports/raw-findings.json

    Explore interdependencies afterwards with `cloudg deps`.
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
    if accounts:
        cfg.aws.accounts = [a.strip() for a in accounts.split(",") if a.strip()]
    if role_name:
        cfg.aws.role_name = role_name

    org_cfg = cfg.aws.organization
    if org is not None:
        org_cfg.enabled = org
    if org_role:
        org_cfg.role_name = org_role
    if ous:
        org_cfg.include_ous = list(ous)
    if exclude_accounts:
        org_cfg.exclude_accounts = list(exclude_accounts)
    if ct_home_region:
        org_cfg.home_region = ct_home_region
    if services:
        cfg.inventory.services = [s.strip() for s in services.split(",") if s.strip()]
    if exclude_services:
        cfg.inventory.exclude_services = [s.strip() for s in exclude_services.split(",") if s.strip()]
    if kubernetes is not None:
        cfg.inventory.kubernetes = kubernetes
    if cloud_control is not None:
        cfg.inventory.cloud_control = cloud_control

    panel = {
        "Providers": ", ".join(cfg.providers),
        "AWS regions": ", ".join(cfg.aws.regions),
        "Services": ", ".join(cfg.inventory.services)
        + (f" (excluding {', '.join(cfg.inventory.exclude_services)})" if cfg.inventory.exclude_services else ""),
        "Kubernetes workloads": "enabled" if cfg.inventory.kubernetes else "disabled",
        "Catch-all sweep": "enabled" if sweep else "disabled",
        "Cloud Control sweep": "enabled" if cfg.inventory.cloud_control else "disabled",
        "Scanners": "none (inventory mapping is scanner-independent)",
    }
    if org_cfg.enabled:
        panel["Organization"] = "discover all accounts" + (
            f" under {', '.join(org_cfg.include_ous)}" if org_cfg.include_ous else ""
        )
        panel["Member role"] = org_cfg.role_name or cfg.aws.role_name or "AWSControlTowerExecution"
    elif cfg.aws.accounts:
        panel["AWS accounts"] = ", ".join(cfg.aws.accounts)
    ui.config_panel("Map Configuration", panel)

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
    org_summary = summary.get("organization")
    if org_summary:
        ui.stats_table(
            "Organization",
            {
                "Organization": org_summary["id"],
                "Accounts": org_summary["accounts"],
                "Organizational units": org_summary["ous"],
                "Control Tower": "yes" if org_summary["control_tower"] else "no",
                "Governed regions": ", ".join(org_summary["governed_regions"]) or "—",
            },
        )
    ui.stats_table(
        "Inventory Summary",
        {
            "Assets": summary["total_assets"],
            "Interconnections": summary["total_edges"],
            "Accounts": summary["accounts"],
            "Services": len(summary["assets_by_service"]),
            "Internet-exposed": summary["internet_exposed"],
            "Cross-account edges": summary["cross_account_edges"],
            "External accounts referenced": summary["external_accounts"],
            "Security service gaps": summary["security_service_gaps"],
            "Unlinked assets": summary["unlinked_assets"],
            "Unresolved references": summary["unresolved_references"],
        },
    )
    for svc, count in list(summary["assets_by_service"].items())[:15]:
        ui.detail(f"{svc}: {count} assets")

    analysis = json.loads(paths["dependencies"].read_text())
    ui.ranked_table(
        "Most shared dependencies",
        ["Asset", "Type", "Direct dependents"],
        [[d["name"], d["type"], d["direct_dependents"]] for d in analysis["shared_dependencies"][:10]],
    )
    ui.ranked_table(
        "Largest blast radius",
        ["Asset", "Type", "Dependents", "Accounts", "Exposed"],
        [
            [d["name"], d["type"], d["transitive_dependents"], d["accounts_affected"], d["internet_exposed_dependents"]]
            for d in analysis["largest_blast_radius"][:10]
        ],
    )
    for gap in analysis["security_coverage"]["gaps"][:15]:
        ui.warn(f"Security service not enabled: {gap}")

    failed = [
        f"{c.account_id or '-'} {c.region or ''} {s.service}"
        for c in result.coverage
        for s in c.services
        if s.status.value == "FAILED"
    ]
    if failed:
        ui.warn(f"{len(failed)} collectors failed (see inventory coverage / -v): {', '.join(failed[:8])}")

    ui.artifact("Inventory map", paths["map"])
    ui.artifact("GraphML", paths["graphml"])
    ui.artifact("Graph JSON", paths["graph"])
    ui.artifact("Dependencies", paths["dependencies"])
    if "organization" in paths:
        ui.artifact("Organization", paths["organization"])

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
# DEPS command (interdependency queries over a saved inventory map)
# ─────────────────────────────────────────────────────────────────────


@cli.command(name="deps")
@click.argument("asset", required=False)
@click.option(
    "-m",
    "--map",
    "map_path",
    default="./reports",
    show_default=True,
    help="inventory-map.json, or the directory holding it",
)
@click.option(
    "-d",
    "--direction",
    type=click.Choice(["up", "down", "both"]),
    default="both",
    show_default=True,
    help="up = what the asset depends on, down = what depends on it (blast radius)",
)
@click.option("--depth", default=3, show_default=True, help="Levels to expand")
@click.option("--top", default=15, show_default=True, help="Rows in the overview tables")
@click.option("--json", "as_json", is_flag=True, help="Print JSON instead of tables/trees")
def deps(asset: str | None, map_path: str, direction: str, depth: int, top: int, as_json: bool) -> None:
    """Explore interdependencies in a saved inventory map.

    With an ASSET (ARN, resource ID, internal ID, or unique name), show what
    it depends on and what depends on it. Without one, show the most shared
    dependencies, the largest blast radius and cross-account edges.

    \b
        cloudg deps arn:aws:iam::123456789012:role/app-role
        cloudg deps my-queue --direction down --depth 5
        cloudg deps --map ./reports
    """
    from cloudg.inventory import InventoryResult

    try:
        result = InventoryResult.load(map_path)
    except (OSError, ValueError) as exc:
        ui.error_panel("Could not load the inventory map", exc)
        sys.exit(1)
    graph = result.dependency_graph()

    if asset:
        found = graph.find(asset)
        if found is None:
            ui.fail(f"No unique asset matches {asset!r}; use its ARN or resource ID")
            sys.exit(1)
        view = graph.tree(found.id, direction=direction, max_depth=depth)
        if as_json:
            console.print_json(json.dumps(view, default=str))
        else:
            ui.dependency_tree(view)
        return

    from cloudg.inventory.dependencies import cross_account_edges

    overview = {
        "shared_dependencies": graph.shared_dependencies(top),
        "largest_blast_radius": graph.blast_radius(top=top),
        "cross_account_edges": cross_account_edges(result.assets, result.edges),
    }
    if as_json:
        console.print_json(json.dumps(overview, default=str))
        return
    ui.section("Interdependencies")
    ui.ranked_table(
        "Most shared dependencies",
        ["Asset", "Type", "Account", "Direct dependents"],
        [[d["name"], d["type"], d["account_id"] or "-", d["direct_dependents"]] for d in overview["shared_dependencies"]],
    )
    ui.ranked_table(
        "Largest blast radius",
        ["Asset", "Type", "Dependents", "Accounts", "Exposed"],
        [
            [d["name"], d["type"], d["transitive_dependents"], d["accounts_affected"], d["internet_exposed_dependents"]]
            for d in overview["largest_blast_radius"]
        ],
    )
    ui.ranked_table(
        "Cross-account edges",
        ["Source", "Relationship", "Target", "External"],
        [
            [e["source"], e["relationship"] or e["edge_type"], e["target"], "yes" if e["external"] else ""]
            for e in overview["cross_account_edges"][:top]
        ],
    )


# ─────────────────────────────────────────────────────────────────────
# SCAN command
# ─────────────────────────────────────────────────────────────────────


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
# RUN command (full pipeline) — defined in cloudg.cli_commands
# ─────────────────────────────────────────────────────────────────────

cli.add_command(run)


if __name__ == "__main__":
    # Click injects the arguments at call time
    cli()  # pylint: disable=no-value-for-parameter
