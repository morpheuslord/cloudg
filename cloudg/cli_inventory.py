"""CloudG inventory commands: `map` and `deps`.

Both are defined here and registered on the CLI group in :mod:`cloudg.cli`
via ``cli.add_command(...)``. They are scanner-independent: `map` builds the
interconnected inventory, `deps` queries a saved one.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import TYPE_CHECKING, Any

import click

from cloudg import ui
from cloudg.cli_helpers import _parse_region_flag
from cloudg.ui import console

if TYPE_CHECKING:
    from cloudg.config import CloudGConfig


def _csv_list(value: str) -> list[str]:
    """Split a comma-separated flag value, dropping blanks."""
    return [item.strip() for item in value.split(",") if item.strip()]


# ─────────────────────────────────────────────────────────────────────
# MAP command helpers
# ─────────────────────────────────────────────────────────────────────


def _apply_scope_overrides(cfg: CloudGConfig, kwargs: dict[str, Any]) -> None:
    """Apply provider, region and account-scope flags to the config."""
    providers_list = list(kwargs["provider"])
    if "all" in providers_list:
        providers_list = ["aws", "azure", "gcp"]
    cfg.providers = providers_list

    if kwargs["scan_regions"]:
        region_list = _parse_region_flag(kwargs["scan_regions"])
        cfg.aws.regions = region_list
        cfg.azure.regions = region_list
        cfg.gcp.regions = region_list
    if kwargs["profile"]:
        cfg.aws.profile = kwargs["profile"]
    if kwargs["subscription_id"]:
        cfg.azure.subscription_ids = [kwargs["subscription_id"]]
    if kwargs["project_id"]:
        cfg.gcp.project_ids = [kwargs["project_id"]]
    if kwargs["accounts"]:
        cfg.aws.accounts = _csv_list(kwargs["accounts"])
    if kwargs["role_name"]:
        cfg.aws.role_name = kwargs["role_name"]


def _apply_org_overrides(cfg: CloudGConfig, kwargs: dict[str, Any]) -> None:
    """Apply the AWS Organization / Control Tower flags to the config."""
    org_cfg = cfg.aws.organization
    if kwargs["org"] is not None:
        org_cfg.enabled = kwargs["org"]
    if kwargs["org_role"]:
        org_cfg.role_name = kwargs["org_role"]
    if kwargs["ous"]:
        org_cfg.include_ous = list(kwargs["ous"])
    if kwargs["exclude_accounts"]:
        org_cfg.exclude_accounts = list(kwargs["exclude_accounts"])
    if kwargs["ct_home_region"]:
        org_cfg.home_region = kwargs["ct_home_region"]


def _apply_inventory_overrides(cfg: CloudGConfig, kwargs: dict[str, Any]) -> None:
    """Apply service selection and optional-collector flags to the config."""
    if kwargs["services"]:
        cfg.inventory.services = _csv_list(kwargs["services"])
    if kwargs["exclude_services"]:
        cfg.inventory.exclude_services = _csv_list(kwargs["exclude_services"])
    if kwargs["kubernetes"] is not None:
        cfg.inventory.kubernetes = kwargs["kubernetes"]
    if kwargs["cloud_control"] is not None:
        cfg.inventory.cloud_control = kwargs["cloud_control"]


def _enabled(flag: Any) -> str:
    return "enabled" if flag else "disabled"


def _show_map_config(cfg: CloudGConfig, sweep: bool) -> None:
    """Render the "Map Configuration" panel."""
    inv = cfg.inventory
    excluded = f" (excluding {', '.join(inv.exclude_services)})" if inv.exclude_services else ""
    panel = {
        "Providers": ", ".join(cfg.providers),
        "AWS regions": ", ".join(cfg.aws.regions),
        "Services": ", ".join(inv.services) + excluded,
        "Kubernetes workloads": _enabled(inv.kubernetes),
        "Catch-all sweep": _enabled(sweep),
        "Cloud Control sweep": _enabled(inv.cloud_control),
        "Scanners": "none (inventory mapping is scanner-independent)",
    }
    org_cfg = cfg.aws.organization
    if org_cfg.enabled:
        panel["Organization"] = "discover all accounts" + (
            f" under {', '.join(org_cfg.include_ous)}" if org_cfg.include_ous else ""
        )
        panel["Member role"] = org_cfg.role_name or cfg.aws.role_name or "AWSControlTowerExecution"
    elif cfg.aws.accounts:
        panel["AWS accounts"] = ", ".join(cfg.aws.accounts)
    ui.config_panel("Map Configuration", panel)


def _show_map_summary(summary: dict[str, Any]) -> None:
    """Render the organization and inventory summary tables."""
    org_summary = summary.get("organization")
    if org_summary:
        ui.stats_table(
            "Organization",
            {
                "Organization": org_summary["id"],
                "Accounts": org_summary["accounts"],
                "Organizational units": org_summary["ous"],
                "Control Tower": "yes" if org_summary["control_tower"] else "no",
                "Governed regions": ", ".join(org_summary["governed_regions"]) or "-",
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


def _blast_radius_table(rows: list[dict[str, Any]]) -> None:
    """Render the "Largest blast radius" table (shared by `map` and `deps`)."""
    ui.ranked_table(
        "Largest blast radius",
        ["Asset", "Type", "Dependents", "Accounts", "Exposed"],
        [
            [
                d["name"],
                d["type"],
                d["transitive_dependents"],
                d["accounts_affected"],
                d["internet_exposed_dependents"],
            ]
            for d in rows
        ],
    )


def _show_map_dependencies(analysis: dict[str, Any]) -> None:
    """Render the dependency highlights and security-service gaps of a map."""
    ui.ranked_table(
        "Most shared dependencies",
        ["Asset", "Type", "Direct dependents"],
        [
            [d["name"], d["type"], d["direct_dependents"]]
            for d in analysis["shared_dependencies"][:10]
        ],
    )
    _blast_radius_table(analysis["largest_blast_radius"][:10])
    for gap in analysis["security_coverage"]["gaps"][:15]:
        ui.warn(f"Security service not enabled: {gap}")


def _warn_failed_collectors(result: Any) -> None:
    failed = [
        f"{c.account_id or '-'} {c.region or ''} {s.service}"
        for c in result.coverage
        for s in c.services
        if s.status.value == "FAILED"
    ]
    if failed:
        ui.warn(
            f"{len(failed)} collectors failed (see inventory coverage / -v): {', '.join(failed[:8])}"
        )


def _show_map_artifacts(paths: dict[str, Path]) -> None:
    ui.artifact("Inventory map", paths["map"])
    ui.artifact("GraphML", paths["graphml"])
    ui.artifact("Graph JSON", paths["graph"])
    ui.artifact("Dependencies", paths["dependencies"])
    if "organization" in paths:
        ui.artifact("Organization", paths["organization"])


def _load_findings(findings_paths: tuple[str, ...]) -> list[Any]:
    """Load cloudg findings from raw-findings.json files or cloudg reports."""
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
    return findings


def _merge_findings(
    mapper: Any, result: Any, findings_paths: tuple[str, ...], output_dir: Path
) -> None:
    """Merge existing scanner findings into asset and compliance maps."""
    findings = _load_findings(findings_paths)
    if findings:
        merged_paths = mapper.export_merged(result, findings, output_dir)
        ui.success(f"Merged [metric]{len(findings)}[/] findings into the inventory")
        ui.artifact("Asset map", merged_paths["asset_map"])
        ui.artifact("Compliance map", merged_paths["compliance_map"])


# ─────────────────────────────────────────────────────────────────────
# MAP command (scanner-independent inventory mapping)
# ─────────────────────────────────────────────────────────────────────


@click.command(name="map")
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
@click.option(
    "--ou", "ous", multiple=True, help="AWS: only accounts under this OU (ID or name). Repeatable."
)
@click.option(
    "--exclude-account",
    "exclude_accounts",
    multiple=True,
    help="AWS: skip this account. Repeatable.",
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
@click.pass_context
def map_inventory(ctx: click.Context, **kwargs: Any) -> None:
    """Map the complete infrastructure inventory, with no scanners involved.

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

    # Use the config loaded by the CLI group if any, else defaults
    cfg: CloudGConfig = ctx.obj or CloudGConfig()
    _apply_scope_overrides(cfg, kwargs)
    _apply_org_overrides(cfg, kwargs)
    _apply_inventory_overrides(cfg, kwargs)
    _show_map_config(cfg, kwargs["sweep"])

    mapper = InventoryMapper(cfg, tagging_sweep=kwargs["sweep"])
    try:
        with console.status("[accent]Mapping infrastructure inventory…[/]", spinner="dots"):
            result = mapper.map_inventory_sync()
    except Exception as exc:
        ui.error_panel("Inventory mapping failed", exc)
        sys.exit(1)

    output_dir = Path(kwargs["output"])
    paths = result.export(output_dir)
    _show_map_summary(result.summary)
    _show_map_dependencies(json.loads(paths["dependencies"].read_text()))
    _warn_failed_collectors(result)
    _show_map_artifacts(paths)

    # Optional merge with existing scanner findings
    if kwargs["findings_paths"]:
        _merge_findings(mapper, result, kwargs["findings_paths"], output_dir)

    console.print()
    ui.success(f"Inventory map saved to [path]{output_dir}[/]")


# ─────────────────────────────────────────────────────────────────────
# DEPS command (interdependency queries over a saved inventory map)
# ─────────────────────────────────────────────────────────────────────


def _print_json(data: Any) -> None:
    console.print_json(json.dumps(data, default=str))


def _show_asset_deps(graph: Any, kwargs: dict[str, Any]) -> None:
    """Show what one asset depends on and what depends on it."""
    asset = kwargs["asset"]
    found = graph.find(asset)
    if found is None:
        ui.fail(f"No unique asset matches {asset!r}; use its ARN or resource ID")
        sys.exit(1)
    view = graph.tree(found.id, direction=kwargs["direction"], max_depth=kwargs["depth"])
    if kwargs["as_json"]:
        _print_json(view)
    else:
        ui.dependency_tree(view)


def _show_deps_overview(overview: dict[str, Any], top: int) -> None:
    """Render the interdependency overview tables."""
    ui.section("Interdependencies")
    ui.ranked_table(
        "Most shared dependencies",
        ["Asset", "Type", "Account", "Direct dependents"],
        [
            [d["name"], d["type"], d["account_id"] or "-", d["direct_dependents"]]
            for d in overview["shared_dependencies"]
        ],
    )
    _blast_radius_table(overview["largest_blast_radius"])
    ui.ranked_table(
        "Cross-account edges",
        ["Source", "Relationship", "Target", "External"],
        [
            [
                e["source"],
                e["relationship"] or e["edge_type"],
                e["target"],
                "yes" if e["external"] else "",
            ]
            for e in overview["cross_account_edges"][:top]
        ],
    )


@click.command(name="deps")
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
def deps(**kwargs: Any) -> None:
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
        result = InventoryResult.load(kwargs["map_path"])
    except (OSError, ValueError) as exc:
        ui.error_panel("Could not load the inventory map", exc)
        sys.exit(1)
    graph = result.dependency_graph()

    if kwargs["asset"]:
        _show_asset_deps(graph, kwargs)
        return

    from cloudg.inventory.dependencies import cross_account_edges

    top = kwargs["top"]
    overview = {
        "shared_dependencies": graph.shared_dependencies(top),
        "largest_blast_radius": graph.blast_radius(top=top),
        "cross_account_edges": cross_account_edges(result.assets, result.edges),
    }
    if kwargs["as_json"]:
        _print_json(overview)
        return
    _show_deps_overview(overview, top)
