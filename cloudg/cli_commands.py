"""CloudG CLI commands that live outside :mod:`cloudg.cli`.

The `run` command (full pipeline) is defined here and registered on the
CLI group in :mod:`cloudg.cli` via ``cli.add_command(run)``.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import click

from cloudg import ui
from cloudg.cli_helpers import (
    _apply_run_overrides,
    _resolve_run_images,
    _resolve_run_scanners,
    _show_run_config,
)
from cloudg.cli_run_helpers import (
    _collect_assets,
    _export_rag_phase,
    _graph_phase,
    RunProducts,
    _post_scan_phases,
    _scanner_phase,
    _terraform_phase,
)


@click.command()
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
@click.pass_context
def run(ctx: click.Context, **kwargs: Any) -> None:
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

    # Use the config loaded by the CLI group if any, else defaults;
    # then apply CLI overrides
    cfg: CloudGConfig = ctx.obj or CloudGConfig()
    _apply_run_overrides(cfg, kwargs)

    scanner_list = _resolve_run_scanners(cfg, kwargs["scanners"])
    _show_run_config(cfg, scanner_list, output_dir)
    resolved_images = _resolve_run_images(kwargs["images"], cfg)

    products, tf_dir = _pre_scan_phases(cfg, kwargs, output_dir)

    # Phase 3: Security Scanning (all scanners in parallel)
    scanner_findings, iam_findings = _scanner_phase(
        cfg,
        scanner_list,
        kwargs["profile"],
        kwargs["iac_dir"],
        resolved_images,
        tf_dir,
        products.assets,
        output_dir,
    )

    # Phases 3b to 5: ontology, RAG update, normalisation, reports, summary
    _post_scan_phases(cfg, kwargs, products, scanner_findings, iam_findings, output_dir)


def _pre_scan_phases(
    cfg: Any, kwargs: dict[str, Any], output_dir: Path
) -> tuple[RunProducts, str | None]:
    """Phases 1 to 2d of ``cloudg run``: collection, graph, RAG and Terraform.

    Returns what those phases produced and the Terraform output directory.
    """
    # Phase 1: Asset Collection (always uses multi-provider orchestrator)
    assets, edges, coverage_records = _collect_assets(cfg)

    # Phase 2: Graph Analysis
    graph, graph_json, reachability_findings = _graph_phase(cfg, assets, edges, output_dir)

    # Phase 2b: Semantic Ontology, deferred to after the scanner phase
    # (so security/compliance findings can be included in the ontology)

    # Phase 2c: RAG Export
    if kwargs["rag_export"] and cfg.rag.enabled:
        _export_rag_phase(cfg, assets, edges, graph, reachability_findings, output_dir)

    # Phase 2d: Terraform Recreation
    tf_dir = _terraform_phase(cfg, kwargs["terraform"], assets, edges, output_dir)

    products = RunProducts(
        assets, edges, graph, graph_json, reachability_findings, coverage_records
    )
    return products, tf_dir
