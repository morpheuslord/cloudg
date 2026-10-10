"""Helper functions for the CloudG CLI commands.

Shared by :mod:`cloudg.cli` and :mod:`cloudg.cli_commands`; all terminal
rendering goes through :mod:`cloudg.ui`.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any

from rich.markup import escape

from cloudg import ui

if TYPE_CHECKING:
    from cloudg.config import CloudGConfig


def _parse_region_flag(scan_regions: str) -> list[str]:
    """Parse a --regions flag value into a region list ('all' → ['ALL'])."""
    if scan_regions.lower() == "all":
        return ["ALL"]
    return [r.strip() for r in scan_regions.split(",")]


# Exit status of `cloudg run` when collection failed for every target
# (provider, account and region). Partial collection still exits 0.
EXIT_COLLECTION_FAILED = 3


# ─────────────────────────────────────────────────────────────────────
# SCAN / RUN scanner helpers
# ─────────────────────────────────────────────────────────────────────

_BUILTIN_SCANNER_LABELS = {
    "prowler": "Prowler",
    "scoutsuite": "ScoutSuite",
    "checkov": "Checkov",
    "trivy": "Trivy",
    "iam": "IAM linter",
}


def _show_scan_plan(plan: Any) -> None:
    """Print what the scanner plan skipped and why (not enabled, not
    installed, nothing to scan, unresolved credentials)."""
    requested = set(plan.requested)
    for name, label in _BUILTIN_SCANNER_LABELS.items():
        if name not in requested:
            ui.skip(f"{label}: not enabled")
    render = {"skip": ui.skip, "warning": ui.warn, "info": ui.detail}
    for level, message in plan.notes:
        render.get(level, ui.warn)(escape(message))
    for phase, exc in plan.errors:
        ui.fail(escape(f"{phase}: {exc}"))


@dataclass
class ScanOutcome:
    """Findings of a scanner plan run from the CLI, per job."""

    results: list[tuple[Any, list[Any]]] = field(default_factory=list)  # (job, findings)
    completed: int = 0
    failed: int = 0

    @property
    def findings(self) -> list[Any]:
        return [f for _, findings in self.results for f in findings]

    def findings_of(self, scanner: str, *, exclude: bool = False) -> list[Any]:
        """Findings of jobs for ``scanner`` (or of every other job with exclude).

        Returns a FindingList carrying the jobs' passing checks (Prowler), so
        the normaliser can mark the controls they cover as PASS.
        """
        from cloudg.normaliser import FindingList

        selected = FindingList()
        for job, findings in self.results:
            if (job.scanner == scanner) != exclude:
                selected.extend(findings)
                selected.passed_checks.update(getattr(findings, "passed_checks", None) or ())
        return selected


def _run_scan_plan(plan: Any) -> ScanOutcome:
    """Run the planned scanner jobs in parallel with a progress display.

    A scanner that times out (scanners.timeout_seconds) or fails is shown as
    failed; findings it produced before that are kept.
    """
    import concurrent.futures

    from cloudg.api_scanners import ScannerFailed

    outcome = ScanOutcome()
    if not plan.jobs:
        return outcome
    failures: list[str] = []
    with ui.scanner_progress() as progress:
        with concurrent.futures.ThreadPoolExecutor(max_workers=max(len(plan.jobs), 2)) as executor:
            future_to_job: dict[concurrent.futures.Future, tuple[Any, Any]] = {}
            for job in plan.jobs:
                task_id = progress.add_task(escape(job.label), total=None)
                future_to_job[executor.submit(job.fn)] = (job, task_id)

            for future in concurrent.futures.as_completed(future_to_job):
                job, task_id = future_to_job[future]
                try:
                    findings = future.result()
                except ScannerFailed as exc:
                    outcome.failed += 1
                    outcome.results.append((job, exc.findings))
                    kept = f"; kept {len(exc.findings)} findings" if exc.findings else ""
                    ui.task_failed(progress, task_id, f"{escape(job.label)}: did not finish")
                    failures.append(f"{job.label}: {exc}{kept}")
                    continue
                except Exception as exc:
                    outcome.failed += 1
                    ui.task_failed(progress, task_id, f"{escape(job.label)}: failed")
                    failures.append(f"{job.label} failed: {exc}")
                    continue
                outcome.completed += 1
                outcome.results.append((job, findings))
                ui.task_done(progress, task_id, f"{escape(job.label)}: {len(findings)} findings")
    # In full here: progress lines are cut to the terminal width
    for line in failures:
        ui.fail(escape(line))
    return outcome


def _load_scan_assets(path: str | None) -> list[Any]:
    """Assets for the IAM linter, from a file with a top-level "assets" list:
    inventory-<provider>.json (`cloudg collect`), inventory-map.json
    (`cloudg map`, or the directory holding it) or findings.json."""
    if not path:
        return []
    import json

    from cloudg.schema.models import CloudAsset

    p = Path(path)
    if p.is_dir():
        p = p / "inventory-map.json"
    with open(p) as f:
        data = json.load(f)
    raw = data.get("assets", []) if isinstance(data, dict) else []
    return [CloudAsset.model_validate(a) for a in raw]


# ─────────────────────────────────────────────────────────────────────
# REPORT command helpers
# ─────────────────────────────────────────────────────────────────────

_METADATA_FIELDS = ("scan_id", "provider", "account_id", "region", "started_at", "completed_at")


def _load_report_input(path: Path, rules_dir: str | None = None) -> tuple[Any, dict[str, Any]]:
    """Read `cloudg report -i` input into (ScanResult, D3 graph JSON).

    - findings.json (a JSON object): restored as written, with its scan ID,
      provider, account, region, timestamps, assets, findings, compliance
      results, edges and graph. Files written before findings.json carried
      edges get them back from the graph links.
    - raw-findings.json (a JSON list of findings, from `cloudg scan` or
      `cloudg ingest`): normalised first, like `cloudg ingest` does.

    Raises:
        ValueError: the file is neither of the two.
    """
    import json

    from cloudg.schema.models import CloudAsset, ComplianceResult, Finding, ScanResult

    with open(path) as f:
        data = json.load(f)

    if isinstance(data, list):
        from cloudg.normaliser import FindingsNormaliser

        findings = [Finding.model_validate(item) for item in data]
        return FindingsNormaliser(rules_dir=rules_dir).normalise(findings), {
            "nodes": [],
            "links": [],
        }
    if not isinstance(data, dict):
        raise ValueError(
            f"{path}: expected a findings.json object or a raw-findings.json list, "
            f"got {type(data).__name__}"
        )

    graph = data.get("graph") or {"nodes": [], "links": []}
    metadata = data.get("metadata") or {}
    restored = {
        key: metadata[key]
        for key in _METADATA_FIELDS
        if metadata.get(key) not in (None, "", "None")
    }
    if "edges" in data:
        edges = _validate_edges(data.get("edges") or [])
    else:
        edges = _edges_from_graph(graph)
    scan_result = ScanResult(
        assets=[CloudAsset.model_validate(a) for a in data.get("assets", [])],
        findings=[Finding.model_validate(f) for f in data.get("findings", [])],
        compliance=[ComplianceResult.model_validate(c) for c in data.get("compliance", [])],
        edges=edges,
        **restored,
    )
    return scan_result, graph


def _validate_edges(raw: list[Any]) -> list[Any]:
    from cloudg.schema.models import NetworkEdge

    return [NetworkEdge.model_validate(e) for e in raw]


def _edges_from_graph(graph: dict[str, Any]) -> list[Any]:
    """Rebuild edges from D3 graph links (for findings.json files without "edges")."""
    from pydantic import ValidationError

    from cloudg.schema.models import NetworkEdge

    edges = []
    for link in graph.get("links", []):
        fields = {
            "source_id": link.get("source"),
            "target_id": link.get("target"),
            "edge_type": link.get("type"),
            "port_range": link.get("port_range"),
            "protocol": link.get("protocol"),
            "cidr": link.get("cidr"),
            "direction": link.get("direction") or "ingress",
            "relationship": link.get("relationship") or None,
            "description": link.get("description") or None,
        }
        try:
            edges.append(NetworkEdge.model_validate(fields))
        except ValidationError:
            continue  # e.g. an edge type this version does not know
    return edges


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
    """Parse each report file into findings; returns (findings, per-tool counts).

    The findings are a FindingList carrying the checks Prowler reports
    passed, so normalising them gives those controls PASS results."""
    from cloudg.ingest import parse_report
    from cloudg.normaliser import FindingList

    all_findings = FindingList()
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
            all_findings.passed_checks.update(getattr(findings, "passed_checks", None) or ())
        per_tool[tool] = count
        ui.detail(f"{tool}: {count} findings")
    return all_findings, per_tool


def _render_ingest_reports(
    scan_result: Any, fmt: str, output_dir: Path, inline_js: bool = True
) -> None:
    """Render the requested report formats for `cloudg ingest`."""
    if fmt in ("json", "all"):
        from cloudg.renderers.json_export import JSONExporter

        exporter = JSONExporter(output_dir=str(output_dir))
        path = exporter.export(scan_result)
        ui.artifact("JSON", path)

    if fmt in ("html", "all"):
        from cloudg.renderers.html_report import HTMLReportGenerator

        generator = HTMLReportGenerator(output_dir=str(output_dir), inline_js=inline_js)
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
    names = scanners.split(",") if scanners is not None else cfg.scanners.enabled
    return [s.strip().lower() for s in names if s.strip()]


def _check_account_scope(cfg: CloudGConfig) -> None:
    """--accounts / aws.accounts needs a role name to reach those accounts."""
    import click

    from cloudg.credentials import check_aws_account_scope

    if "aws" not in cfg.providers:
        return
    try:
        check_aws_account_scope(cfg.aws)
    except ValueError as exc:
        raise click.UsageError(str(exc)) from exc


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
