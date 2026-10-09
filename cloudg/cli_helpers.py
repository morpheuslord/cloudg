"""Helper functions for the CloudG CLI commands.

Shared by :mod:`cloudg.cli` and :mod:`cloudg.cli_commands`; all terminal
rendering goes through :mod:`cloudg.ui`.
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING, Any

from cloudg import ui

if TYPE_CHECKING:
    from cloudg.config import CloudGConfig


def _parse_region_flag(scan_regions: str) -> list[str]:
    """Parse a --regions flag value into a region list ('all' → ['ALL'])."""
    if scan_regions.lower() == "all":
        return ["ALL"]
    return [r.strip() for r in scan_regions.split(",")]


# ─────────────────────────────────────────────────────────────────────
# SCAN command helpers
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
                    ui.task_done(progress, task_id, f"{name}: {len(findings)} findings")
                except Exception as exc:
                    ui.task_failed(progress, task_id, f"{name} failed: {exc}")
    return all_findings


# ─────────────────────────────────────────────────────────────────────
# INGEST command helpers
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
                ui.warn(f"{tool}: skipping {path} ({exc})")
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


# ─────────────────────────────────────────────────────────────────────
# RUN command configuration helpers
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
