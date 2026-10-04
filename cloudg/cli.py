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
from cloudg.ui import console

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
        if scan_regions.lower() == "all":
            region_list = ["ALL"]
        else:
            region_list = [r.strip() for r in scan_regions.split(",")]
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

    panel = {
        "Providers": ", ".join(cfg.providers),
        "AWS regions": ", ".join(cfg.aws.regions),
        "Services": ", ".join(cfg.inventory.services)
        + (f" (excluding {', '.join(cfg.inventory.exclude_services)})" if cfg.inventory.exclude_services else ""),
        "Kubernetes workloads": "enabled" if cfg.inventory.kubernetes else "disabled",
        "Catch-all sweep": "enabled" if sweep else "disabled",
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
    import concurrent.futures

    ui.section("Security Scan")

    output_dir = Path(output)
    output_dir.mkdir(parents=True, exist_ok=True)
    scanner_list = [s.strip().lower() for s in scanners.split(",")]
    all_findings: list[Any] = []

    resolved_iac_dir = iac_dir or "."
    resolved_images = [i.strip() for i in images.split(",")] if images else []

    ui.config_panel(
        "Scan Configuration",
        {"Provider": provider, "Scanners": ", ".join(scanner_list)},
    )

    def _run_prowler() -> list[Any]:
        from cloudg.scanners.prowler import ProwlerScanner

        s = ProwlerScanner(
            provider=provider, profile=profile, output_dir=str(output_dir / "prowler")
        )
        return s.run()

    def _run_scoutsuite() -> list[Any]:
        from cloudg.scanners.scoutsuite import ScoutSuiteScanner

        s = ScoutSuiteScanner(
            provider=provider, profile=profile, report_dir=str(output_dir / "scoutsuite")
        )
        return s.run()

    def _run_checkov() -> list[Any]:
        from cloudg.scanners.checkov import CheckovScanner

        s = CheckovScanner(target_dir=resolved_iac_dir)
        return s.run()

    def _run_trivy() -> list[Any]:
        from cloudg.scanners.trivy import TrivyScanner

        s = TrivyScanner()
        return s.scan_images(resolved_images)

    def _run_trivy_fs() -> list[Any]:
        from cloudg.scanners.trivy import TrivyScanner

        s = TrivyScanner()
        return s.scan_filesystem([resolved_iac_dir])

    with ui.scanner_progress() as progress:
        with concurrent.futures.ThreadPoolExecutor(max_workers=len(scanner_list) + 1) as executor:
            future_to_task: dict[concurrent.futures.Future, tuple[str, Any]] = {}

            def submit(name: str, description: str, fn: Any) -> None:
                task_id = progress.add_task(description, total=None)
                future_to_task[executor.submit(fn)] = (name, task_id)

            if "prowler" in scanner_list:
                submit("Prowler", "Prowler", _run_prowler)

            if "scoutsuite" in scanner_list:
                submit("ScoutSuite", "ScoutSuite", _run_scoutsuite)

            if "checkov" in scanner_list:
                submit("Checkov", f"Checkov [muted](target: {resolved_iac_dir})[/]", _run_checkov)

            if "trivy" in scanner_list:
                if resolved_images:
                    submit(
                        "Trivy",
                        f"Trivy [muted]({len(resolved_images)} images)[/]",
                        _run_trivy,
                    )
                else:
                    ui.warn("Trivy: no images specified, falling back to filesystem scan")
                    submit(
                        "Trivy (filesystem)",
                        f"Trivy filesystem [muted](target: {resolved_iac_dir})[/]",
                        _run_trivy_fs,
                    )

            for future in concurrent.futures.as_completed(future_to_task):
                name, task_id = future_to_task[future]
                try:
                    findings = future.result(timeout=3600)
                    all_findings.extend(findings)
                    ui.task_done(progress, task_id, f"{name} — {len(findings)} findings")
                except Exception as exc:
                    ui.task_failed(progress, task_id, f"{name} failed: {exc}")

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

    reports: dict[str, list[str]] = {}
    if prowler_paths:
        reports["prowler"] = list(prowler_paths)
    if scoutsuite_paths:
        reports["scoutsuite"] = list(scoutsuite_paths)
    if checkov_paths:
        reports["checkov"] = list(checkov_paths)
    if trivy_paths:
        reports["trivy"] = list(trivy_paths)

    if not reports:
        ui.error_panel(
            "No inputs",
            "Pass at least one report: --prowler, --scoutsuite, --checkov, or --trivy",
        )
        sys.exit(1)

    ui.config_panel(
        "Ingest Configuration",
        {tool: ", ".join(paths) for tool, paths in reports.items()},
    )

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
        json.dump(
            [fi.model_dump(mode="json") for fi in all_findings],
            f,
            indent=2,
            default=str,
        )

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

    ui.artifact("Raw findings", raw_path)

    console.print()
    ui.success(
        f"Ingested [metric]{len(all_findings)}[/] findings "
        f"from {len(per_tool)} tool(s) — "
        f"[metric]{len(scan_result.findings)}[/] after deduplication"
    )


# ─────────────────────────────────────────────────────────────────────
# RUN command (full pipeline)
# ─────────────────────────────────────────────────────────────────────


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
def run(
    provider: tuple[str, ...],
    profile: str | None,
    aws_key: str | None,
    aws_secret: str | None,
    aws_session_token: str | None,
    aws_role_arn: str | None,
    aws_external_id: str | None,
    aws_web_identity_token_file: str | None,
    region: str | None,
    subscription_id: str | None,
    azure_tenant_id: str | None,
    azure_client_id: str | None,
    azure_client_secret: str | None,
    azure_cert_path: str | None,
    azure_federated_token_file: str | None,
    azure_managed_identity: bool,
    project_id: str | None,
    gcp_credentials_file: str | None,
    gcp_impersonate_sa: str | None,
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
        cloudg run -p aws -p azure
        cloudg run -p all
        cloudg run -p aws --regions all
        cloudg run -p aws --aws-key AKIAXX --aws-secret yyy
    """
    ui.section("Full Pipeline")

    output_dir = Path(output)
    output_dir.mkdir(parents=True, exist_ok=True)

    from cloudg.config import CloudGConfig
    from cloudg.graph.builder import GraphBuilder
    from cloudg.graph.reachability import ReachabilityAnalyzer
    from cloudg.normaliser import FindingsNormaliser
    from cloudg.renderers.html_report import HTMLReportGenerator
    from cloudg.renderers.json_export import JSONExporter
    from cloudg.renderers.svg import SVGRenderer
    from cloudg.scanners.iam_linter import IAMLinter

    # Use global config if loaded, else defaults
    cfg: CloudGConfig = _config or CloudGConfig()

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

    # Inject credentials and IDs from CLI flags
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
    if aws_session_token:
        cfg.aws.session_token = aws_session_token
    if aws_role_arn:
        cfg.aws.role_arn = aws_role_arn
    if aws_external_id:
        cfg.aws.external_id = aws_external_id
    if aws_web_identity_token_file:
        cfg.aws.web_identity_token_file = aws_web_identity_token_file
    if azure_tenant_id:
        cfg.azure.tenant_id = azure_tenant_id
    if azure_client_id:
        cfg.azure.client_id = azure_client_id
    if azure_client_secret:
        cfg.azure.client_secret = azure_client_secret
    if azure_cert_path:
        cfg.azure.certificate_path = azure_cert_path
    if azure_federated_token_file:
        cfg.azure.federated_token_file = azure_federated_token_file
    if azure_managed_identity:
        cfg.azure.use_managed_identity = True
    if gcp_credentials_file:
        cfg.gcp.credentials_file = gcp_credentials_file
    if gcp_impersonate_sa:
        cfg.gcp.impersonate_service_account = gcp_impersonate_sa

    coverage_records = []

    # ── Resolve scanner list from CLI flag or config ──
    if scanners is not None:
        scanner_list = [s.strip().lower() for s in scanners.split(",")]
    else:
        scanner_list = [s.strip().lower() for s in cfg.scanners.enabled]

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

    # ── Resolve container images: CLI flag → config ──
    resolved_images: list[str] = []
    if images:
        resolved_images = [i.strip() for i in images.split(",")]
    elif cfg.scanners.trivy_images:
        resolved_images = list(cfg.scanners.trivy_images)

    # Phase 1: Asset Collection (always uses multi-provider orchestrator)
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
        assets, edges = [], []

    # Phase 2: Graph Analysis
    ui.phase("Phase 2 · Graph Analysis")
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

    # Phase 2b: Semantic Ontology — deferred to after scanner phase
    # (so security/compliance findings can be included in the ontology)

    # Phase 2c: RAG Export
    if rag_export and cfg.rag.enabled:
        ui.phase("Phase 2c · RAG Export")
        try:
            from cloudg.graph.rag_export import RAGExporter

            rag = RAGExporter(max_chunk_tokens=cfg.rag.max_chunk_tokens)
            rag_paths = rag.export_all(
                assets,
                edges,
                graph,
                findings=reachability_findings,
                output_dir=output_dir,
            )
            ui.artifact("RAG chunks", rag_paths["chunks"])
            ui.artifact("RAG index", rag_paths["index"])
        except Exception as exc:
            ui.fail(f"RAG export failed: {exc}")

    # Phase 2d: Terraform Recreation
    tf_dir: str | None = None
    if terraform or cfg.terraform.enabled:
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
        except Exception as exc:
            ui.fail(f"Terraform export failed: {exc}")
            tf_dir = None

    import concurrent.futures

    # Phase 3: Security Scanning (all scanners in parallel)
    ui.phase("Phase 3 · Security Scanning", note="running scanners in parallel")
    scanner_findings: list[Any] = []

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

    def run_prowler(prov: str) -> list[Any]:
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

    def run_scoutsuite(prov: str) -> list[Any]:
        from cloudg.scanners.scoutsuite import ScoutSuiteScanner

        s = ScoutSuiteScanner(
            provider=prov,
            profile=profile if prov == "aws" else None,
            report_dir=str(output_dir / "scoutsuite" / prov),
            extra_args=cfg.scanners.scoutsuite_extra_args or [],
        )
        return s.run()

    def run_checkov(target_dir: str) -> list[Any]:
        from cloudg.scanners.checkov import CheckovScanner

        frameworks = cfg.scanners.checkov_frameworks or []
        s = CheckovScanner(
            target_dir=target_dir,
            frameworks=frameworks if frameworks else None,
            extra_args=cfg.scanners.checkov_extra_args or [],
        )
        return s.run()

    def run_trivy(image_list: list[str]) -> list[Any]:
        from cloudg.scanners.trivy import TrivyScanner

        s = TrivyScanner(extra_args=cfg.scanners.trivy_extra_args or [])
        return s.scan_images(image_list)

    def run_trivy_fs(target_dirs: list[str]) -> list[Any]:
        from cloudg.scanners.trivy import TrivyScanner

        s = TrivyScanner(extra_args=cfg.scanners.trivy_extra_args or [])
        return s.scan_filesystem(target_dirs)

    def run_iam_linter() -> list[Any]:
        iam_linter = IAMLinter()
        return iam_linter.analyze_policies(assets)

    checkov_frameworks = cfg.scanners.checkov_frameworks or []
    checkov_fw_label = ", ".join(checkov_frameworks) if checkov_frameworks else "auto-detect"

    # Execute ALL enabled scanners concurrently
    iam_findings: list[Any] = []
    max_workers = len(scanner_list) + len(cfg.providers) + 1  # +1 for IAM linter
    with ui.scanner_progress() as progress:
        with concurrent.futures.ThreadPoolExecutor(max_workers=max(max_workers, 2)) as executor:
            future_to_scanner: dict[concurrent.futures.Future, tuple[str, Any]] = {}

            def submit(name: str, description: str, fn: Any, *args: Any) -> None:
                task_id = progress.add_task(description, total=None)
                future_to_scanner[executor.submit(fn, *args)] = (name, task_id)

            # Prowler — one instance per provider
            if "prowler" in scanner_list:
                for prov in cfg.providers:
                    if prov in ("aws", "azure", "gcp"):
                        submit(
                            f"Prowler ({prov})", f"Prowler [muted]({prov})[/]", run_prowler, prov
                        )
            else:
                ui.skip("Prowler: not enabled")

            # ScoutSuite — one instance per provider
            if "scoutsuite" in scanner_list:
                for prov in cfg.providers:
                    if prov in ("aws", "azure", "gcp"):
                        submit(
                            f"ScoutSuite ({prov})",
                            f"ScoutSuite [muted]({prov})[/]",
                            run_scoutsuite,
                            prov,
                        )
            else:
                ui.skip("ScoutSuite: not enabled")

            # Checkov — runs against resolved IaC directories
            if "checkov" in scanner_list:
                if resolved_iac_dirs:
                    for d in resolved_iac_dirs:
                        submit(
                            f"Checkov ({d})",
                            f"Checkov [muted](target: {d}, frameworks: {checkov_fw_label})[/]",
                            run_checkov,
                            d,
                        )
                else:
                    ui.warn(
                        "Checkov: nothing to scan — pass --iac-dir, set "
                        "scanners.iac_directories, or enable --terraform to scan the "
                        "recreated infrastructure"
                    )
            else:
                ui.skip("Checkov: not enabled")

            # Trivy — scans container images if configured, else the IaC targets
            if "trivy" in scanner_list:
                if resolved_images:
                    submit(
                        "Trivy (images)",
                        f"Trivy [muted]({len(resolved_images)} images)[/]",
                        run_trivy,
                        resolved_images,
                    )
                elif resolved_iac_dirs:
                    ui.warn("Trivy: no images configured, falling back to filesystem scan")
                    submit(
                        "Trivy (filesystem)",
                        f"Trivy filesystem [muted]({len(resolved_iac_dirs)} directories)[/]",
                        run_trivy_fs,
                        resolved_iac_dirs,
                    )
                else:
                    ui.warn(
                        "Trivy: nothing to scan — configure --images, "
                        "--iac-dir, or enable --terraform"
                    )
            else:
                ui.skip("Trivy: not enabled")

            # IAM Linter — always runs internally to analyze collected assets
            if "iam" in scanner_list or assets:
                submit("IAM Linter", "IAM Lint", run_iam_linter)

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

    # Combine all findings for downstream phases
    all_security_findings = scanner_findings + iam_findings + reachability_findings
    console.print()
    ui.success(f"[bold]Phase 3 complete:[/] [metric]{len(all_security_findings)}[/] total findings")

    # Phase 3b: Semantic Ontology (runs AFTER scanners so findings are included)
    if ontology and cfg.ontology.enabled:
        ui.phase("Phase 3b · Semantic Ontology", note="includes security findings")
        try:
            from cloudg.graph.ontology import CloudOntology

            cloud_ontology = CloudOntology()
            cloud_ontology.build(assets, edges, findings=all_security_findings)
            stats = cloud_ontology.stats()
            ui.success(
                f"Ontology: [metric]{stats['total_triples']}[/] triples, "
                f"[metric]{stats['classes_used']}[/] classes, "
                f"[metric]{stats['individuals']}[/] individuals"
            )
            ui.success(f"Security findings in ontology: [metric]{len(all_security_findings)}[/]")

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

    # Also update RAG export with all findings
    if rag_export and cfg.rag.enabled:
        try:
            from cloudg.graph.rag_export import RAGExporter

            rag = RAGExporter(max_chunk_tokens=cfg.rag.max_chunk_tokens)
            rag_paths = rag.export_all(
                assets,
                edges,
                graph,
                findings=all_security_findings,
                output_dir=output_dir,
            )
        except Exception:
            # RAG already ran in Phase 2c, this is an update pass
            logger.debug("RAG update pass failed; keeping Phase 2c export", exc_info=True)

    # Phase 4: Normalise (with external rulesets)
    ui.phase("Phase 4 · Normalisation")
    normaliser = FindingsNormaliser(rules_dir=cfg.rulesets.rules_dir)
    scan_result = normaliser.normalise(
        reachability_findings, scanner_findings, iam_findings, assets=assets
    )
    scan_result.edges = edges
    ui.success(f"[metric]{len(scan_result.findings)}[/] normalised findings")

    # Phase 5: Render
    ui.phase("Phase 5 · Report Generation")

    exporter = JSONExporter(output_dir=str(output_dir))
    json_path = exporter.export(scan_result, graph_json=graph_json)
    ui.artifact("JSON", json_path)

    svg_renderer = SVGRenderer(output_dir=str(output_dir))
    svg_path = svg_renderer.render(assets, edges)
    ui.artifact("SVG", svg_path)

    html_gen = HTMLReportGenerator(output_dir=str(output_dir))
    html_path = html_gen.generate(scan_result, graph_json=graph_json)
    ui.artifact("HTML", html_path)

    # Summary
    ui.section("Results")
    ui.summary_table(scan_result.summary)

    # Coverage summary
    if coverage_records:
        ui.coverage_table(coverage_records)

    console.print()
    ui.success(f"All reports saved to [path]{output_dir}[/]")


if __name__ == "__main__":
    cli()
