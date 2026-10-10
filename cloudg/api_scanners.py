"""Scanner runs of :class:`cloudg.api.CloudGEngine` (the ``scan`` phase).

Split out of :mod:`cloudg.api` to keep that module readable; the engine
inherits these methods from :class:`ScannerRunsMixin`, and
:func:`resolve_iac_dirs` stays importable from ``cloudg.api``.

The scanner planning here (:func:`plan_scanner_jobs`) is shared with the
``cloudg scan`` and ``cloudg run`` commands, so the CLI and the library pick
scanners, credentials, regions and timeouts the same way.
"""

from __future__ import annotations

import functools
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from cloudg.schema.models import CloudAsset, Finding, NetworkEdge

__all__ = [
    "ScanJob",
    "ScanPlan",
    "ScannerFailed",
    "ScannerRunsMixin",
    "plan_scanner_jobs",
    "resolve_iac_dirs",
]

logger = logging.getLogger(__name__)


def resolve_iac_dirs(
    iac_dir: str | None,
    config_dirs: list[str] | None,
    terraform_dir: str | Path | None = None,
) -> tuple[list[str], str | None]:
    """Resolve which directories the IaC scanners (Checkov, Trivy fs) target.

    Priority: explicit dir -> configured dirs -> the generated Terraform
    recreation of the live infrastructure. There is deliberately no fallback
    to "." any more: scanning whatever directory cloudg happens to run from
    is not a scan of the cloud, and its zero findings read like a clean bill
    of health.

    Returns:
        (dirs, source) where source is "cli", "config", "terraform", or
        None when there is nothing for the IaC scanners to target.
    """
    if iac_dir:
        return [iac_dir], "cli"
    if config_dirs:
        return list(config_dirs), "config"
    if terraform_dir:
        tf_path = Path(terraform_dir)
        if tf_path.is_dir() and any(tf_path.glob("*.tf.json")):
            return [str(tf_path)], "terraform"
    return [], None


# ---------------------------------------------------------------------------
# Scanner runs
# ---------------------------------------------------------------------------


class ScannerFailed(RuntimeError):
    """A scanner started but did not finish (timeout, launch failure).

    ``findings`` holds whatever it produced before that (for example the
    images Trivy did scan), so callers can keep partial results.
    """

    def __init__(self, scanner: str, errors: list[str], findings: list[Finding]) -> None:
        super().__init__(f"{scanner} " + "; ".join(errors))
        self.errors = list(errors)
        self.findings = findings


def _finish(label: str, scanner: Any, findings: list[Finding]) -> list[Finding]:
    """Return ``findings``, or raise ScannerFailed when the wrapper recorded errors."""
    errors = list(getattr(scanner, "errors", None) or [])
    if errors:
        raise ScannerFailed(label, errors, findings)
    return findings


def scanner_regions(config: Any) -> list[str]:
    """AWS regions to hand the cloud scanners; [] for ``ALL`` (their default)."""
    from cloudg.region_discovery import is_all_regions

    regions = [r for r in config.aws.regions if r and r.strip()]
    if not regions or is_all_regions(regions):
        return []
    return regions


def resolve_aws_scanner_auth(config: Any, profile: str | None) -> tuple[str | None, dict[str, str]]:
    """(profile, env) for the AWS scanner processes.

    ``profile`` (``--profile``) replaces aws.profile; everything else comes
    from the config (keys, session token, role_arn, OIDC web identity), in
    the order :func:`cloudg.credentials.build_aws_session` uses.

    Raises:
        RuntimeError: assuming role_arn failed.
    """
    from cloudg.credentials import aws_scanner_auth

    aws_cfg = config.aws
    if profile and profile != aws_cfg.profile:
        aws_cfg = aws_cfg.model_copy(update={"profile": profile})
    regions = scanner_regions(config)
    return aws_scanner_auth(aws_cfg, regions[0] if regions else None)


def scan_prowler(
    config: Any,
    prov: str,
    profile: str | None,
    out: Path,
    auth: tuple[str | None, dict[str, str]] | None = None,
) -> list[Finding]:
    """Run Prowler for one provider with the configured credentials, regions and timeout.

    ``auth`` is the already resolved (profile, env) for AWS; when None it
    is resolved here.
    """
    from cloudg.scanners.prowler import ProwlerScanner

    if prov == "aws":
        scan_profile, env = auth if auth is not None else resolve_aws_scanner_auth(config, profile)
        regions = scanner_regions(config)
    else:
        scan_profile, env, regions = None, {}, []
    scanner = ProwlerScanner(
        provider=prov,
        profile=scan_profile,
        output_dir=str(out / "prowler" / prov),
        extra_args=config.scanners.prowler_extra_args or [],
        aws_access_key_id=env.get("AWS_ACCESS_KEY_ID"),
        aws_secret_access_key=env.get("AWS_SECRET_ACCESS_KEY"),
        aws_session_token=env.get("AWS_SESSION_TOKEN"),
        aws_region=regions[0] if regions else None,
        aws_regions=regions,
        timeout_seconds=config.scanners.timeout_seconds,
    )
    return _finish("Prowler", scanner, scanner.run())


def scan_scoutsuite(
    config: Any,
    prov: str,
    profile: str | None,
    out: Path,
    auth: tuple[str | None, dict[str, str]] | None = None,
) -> list[Finding]:
    """Run ScoutSuite for one provider with the configured credentials, regions and timeout."""
    from cloudg.scanners.scoutsuite import ScoutSuiteScanner

    if prov == "aws":
        scan_profile, env = auth if auth is not None else resolve_aws_scanner_auth(config, profile)
        regions = scanner_regions(config)
    else:
        scan_profile, env, regions = None, {}, []
    scanner = ScoutSuiteScanner(
        provider=prov,
        profile=scan_profile,
        report_dir=str(out / "scoutsuite" / prov),
        extra_args=config.scanners.scoutsuite_extra_args or [],
        timeout_seconds=config.scanners.timeout_seconds,
        env=env,
        regions=regions,
    )
    return _finish("ScoutSuite", scanner, scanner.run())


def scan_checkov(config: Any, target_dir: str) -> list[Finding]:
    """Run Checkov against one IaC directory."""
    from cloudg.scanners.checkov import CheckovScanner

    scanner = CheckovScanner(
        target_dir=target_dir,
        frameworks=config.scanners.checkov_frameworks or None,
        extra_args=config.scanners.checkov_extra_args or [],
        timeout_seconds=config.scanners.timeout_seconds,
    )
    return _finish("Checkov", scanner, scanner.run())


def scan_trivy_images(config: Any, images: list[str]) -> list[Finding]:
    """Run Trivy against container images."""
    from cloudg.scanners.trivy import TrivyScanner

    scanner = TrivyScanner(
        extra_args=config.scanners.trivy_extra_args or [],
        timeout_seconds=config.scanners.timeout_seconds,
    )
    return _finish("Trivy", scanner, scanner.scan_images(images))


def scan_trivy_fs(config: Any, target_dirs: list[str]) -> list[Finding]:
    """Run Trivy against filesystem directories (the fallback without images)."""
    from cloudg.scanners.trivy import TrivyScanner

    scanner = TrivyScanner(
        extra_args=config.scanners.trivy_extra_args or [],
        timeout_seconds=config.scanners.timeout_seconds,
    )
    return _finish("Trivy", scanner, scanner.scan_filesystem(target_dirs))


def scan_iam(assets: list[CloudAsset]) -> list[Finding]:
    """Lint the IAM policies of collected assets."""
    from cloudg.scanners.iam_linter import IAMLinter

    return IAMLinter().analyze_policies(assets)


def scan_plugin(
    scanner_cls: Any,
    config: Any,
    name: str,
    *,
    profile: str | None,
    out: Path,
    assets: list[CloudAsset],
    iac_dirs: list[str],
    images: list[str],
    providers: list[str] | None = None,
) -> list[Finding]:
    """Run a scanner plugin registered under the ``cloudg.scanners`` entry point group."""
    from cloudg.registry import run_plugin_scanner

    providers = list(providers if providers is not None else config.providers)
    return run_plugin_scanner(
        scanner_cls,
        config=config,
        provider=providers[0] if providers else None,
        profile=profile or config.aws.profile,
        output_dir=str(out / name),
        assets=assets,
        iac_dirs=iac_dirs,
        images=images,
        timeout_seconds=config.scanners.timeout_seconds,
    )


# ---------------------------------------------------------------------------
# Planning
# ---------------------------------------------------------------------------

_SCANNER_CLASSES = {
    "prowler": "cloudg.scanners.prowler:ProwlerScanner",
    "scoutsuite": "cloudg.scanners.scoutsuite:ScoutSuiteScanner",
    "checkov": "cloudg.scanners.checkov:CheckovScanner",
    "trivy": "cloudg.scanners.trivy:TrivyScanner",
}

_INSTALL_HINTS = {
    "prowler": "pip install prowler",
    "scoutsuite": "pip install scoutsuite",
    "checkov": "pip install checkov",
    "trivy": "https://trivy.dev/",
}

_LABELS = {
    "prowler": "Prowler",
    "scoutsuite": "ScoutSuite",
    "checkov": "Checkov",
    "trivy": "Trivy",
    "iam": "IAM linter",
}


def scanner_available(name: str) -> bool:
    """True when the built-in scanner ``name`` can run here (its CLI is on PATH).

    The IAM linter is part of cloudg and always available.
    """
    path = _SCANNER_CLASSES.get(name)
    if path is None:
        return True
    import importlib

    module_path, class_name = path.split(":")
    return bool(getattr(importlib.import_module(module_path), class_name).is_available())


@dataclass
class ScanJob:
    """One scanner run: ``fn()`` returns its findings."""

    name: str  # stable id, e.g. "prowler-aws", "checkov-./infra", "trivy-fs"
    label: str  # for people, e.g. "Prowler (aws)"
    scanner: str  # the requested scanner name, e.g. "prowler"
    fn: Callable[[], list[Finding]]


@dataclass
class ScanPlan:
    """What :func:`plan_scanner_jobs` decided.

    ``notes`` are (level, message) pairs, level being "skip", "warning" or
    "info"; ``errors`` are (phase, exception) failures found while planning
    (credential resolution); ``unknown`` lists names nothing provides.
    """

    jobs: list[ScanJob] = field(default_factory=list)
    notes: list[tuple[str, str]] = field(default_factory=list)
    errors: list[tuple[str, Exception]] = field(default_factory=list)
    requested: list[str] = field(default_factory=list)
    unknown: list[str] = field(default_factory=list)
    # AWS scanner credentials, resolved at most once per plan
    _aws_auth: Any = field(default=None, repr=False)

    @property
    def ran(self) -> set[str]:
        """Requested scanner names with at least one job."""
        return {job.scanner for job in self.jobs}


def plan_scanner_jobs(
    config: Any,
    names: list[str],
    *,
    providers: list[str],
    profile: str | None,
    out: Path,
    assets: list[CloudAsset],
    iac_dirs: list[str],
    images: list[str],
) -> ScanPlan:
    """Turn requested scanner names into runnable jobs.

    - Names resolve through :func:`cloudg.registry.select_scanners`:
      built-ins, then ``cloudg.scanners`` plugins; unknown names are
      warned about and skipped.
    - A built-in whose CLI is not installed is skipped with a note.
    - Prowler and ScoutSuite run once per provider; their AWS credentials
      are resolved once, from ``profile`` and the config.
    - Checkov runs per IaC directory; Trivy scans ``images``, or the IaC
      directories when there are no images.
    - The IAM linter runs only when ``iam`` is requested, and needs
      ``assets``: it lints the IAM policies of collected assets.
    """
    from cloudg.registry import select_scanners

    selection = select_scanners(names)
    plan = ScanPlan(requested=selection.names + selection.unknown, unknown=selection.unknown)

    for name in selection.builtin:
        if not scanner_available(name):
            plan.notes.append(("skip", f"{_LABELS[name]}: not installed ({_INSTALL_HINTS[name]})"))
            continue
        if name in ("prowler", "scoutsuite"):
            _plan_cloud_scanner(plan, config, name, providers, profile, out)
        elif name == "checkov":
            _plan_checkov(plan, config, iac_dirs)
        elif name == "trivy":
            _plan_trivy(plan, config, iac_dirs, images)
        elif name == "iam":
            if assets:
                plan.jobs.append(
                    ScanJob("iam", "IAM linter", "iam", functools.partial(scan_iam, assets))
                )
            else:
                plan.notes.append(
                    (
                        "warning",
                        "IAM linter: skipped, no collected assets to lint (it reads the IAM "
                        "policies of collected assets)",
                    )
                )

    for name, scanner_cls in selection.plugins.items():
        fn = functools.partial(
            scan_plugin,
            scanner_cls,
            config,
            name,
            profile=profile,
            out=out,
            assets=assets,
            iac_dirs=iac_dirs,
            images=images,
            providers=providers,
        )
        plan.jobs.append(ScanJob(name, f"{name} (plugin)", name, fn))
    return plan


def _plan_cloud_scanner(
    plan: ScanPlan,
    config: Any,
    name: str,
    providers: list[str],
    profile: str | None,
    out: Path,
) -> None:
    """Prowler / ScoutSuite: one job per provider, AWS auth resolved once per plan."""
    run = scan_prowler if name == "prowler" else scan_scoutsuite
    for prov in providers:
        if prov not in ("aws", "azure", "gcp"):
            continue
        auth = None
        if prov == "aws":
            auth = _plan_aws_auth(plan, config, profile)
            if auth is None:
                plan.notes.append(
                    ("skip", f"{_LABELS[name]} (aws): skipped, AWS credentials did not resolve")
                )
                continue
        fn = functools.partial(run, config, prov, profile, out, auth)
        plan.jobs.append(ScanJob(f"{name}-{prov}", f"{_LABELS[name]} ({prov})", name, fn))


_AUTH_FAILED = object()


def _plan_aws_auth(
    plan: ScanPlan, config: Any, profile: str | None
) -> tuple[str | None, dict[str, str]] | None:
    """Resolve the AWS scanner credentials once per plan; None when that failed."""
    if plan._aws_auth is _AUTH_FAILED:
        return None
    if plan._aws_auth is not None:
        return plan._aws_auth
    try:
        plan._aws_auth = resolve_aws_scanner_auth(config, profile)
    except Exception as exc:
        logger.error("AWS credentials for the scanners did not resolve: %s", exc)
        plan.errors.append(("scanner_auth", exc))
        plan._aws_auth = _AUTH_FAILED
        return None
    return plan._aws_auth


def _plan_checkov(plan: ScanPlan, config: Any, iac_dirs: list[str]) -> None:
    if not iac_dirs:
        plan.notes.append(
            (
                "warning",
                "Checkov: nothing to scan; pass --iac-dir, set scanners.iac_directories, or "
                "enable terraform to scan the recreated infrastructure",
            )
        )
        return
    for d in iac_dirs:
        plan.jobs.append(
            ScanJob(
                f"checkov-{d}",
                f"Checkov ({d})",
                "checkov",
                functools.partial(scan_checkov, config, d),
            )
        )


def _plan_trivy(plan: ScanPlan, config: Any, iac_dirs: list[str], images: list[str]) -> None:
    if images:
        fn = functools.partial(scan_trivy_images, config, list(images))
        plan.jobs.append(ScanJob("trivy", f"Trivy ({len(images)} images)", "trivy", fn))
    elif iac_dirs:
        plan.notes.append(("info", "Trivy: no images configured, scanning the IaC directories"))
        fn = functools.partial(scan_trivy_fs, config, list(iac_dirs))
        plan.jobs.append(
            ScanJob("trivy-fs", f"Trivy filesystem ({len(iac_dirs)} directories)", "trivy", fn)
        )
    else:
        plan.notes.append(
            (
                "warning",
                "Trivy: nothing to scan; pass --images or --iac-dir, set "
                "scanners.trivy_images or scanners.iac_directories, or enable terraform",
            )
        )


# ---------------------------------------------------------------------------
# Engine mixin
# ---------------------------------------------------------------------------


class ScannerRunsMixin:
    """Reachability analysis, IaC target resolution and the parallel scanner
    runs; mixed into CloudGEngine, which provides ``config``, the event
    hooks and ``_emit_error``."""

    config: Any
    on_finding: Callable[[Finding], None] | None
    on_scan_complete: Callable[[list[Finding]], None] | None
    _emit_error: Callable[[str, Exception], None]

    def _run_reachability_analysis(
        self, assets: list[CloudAsset], edges: list[NetworkEdge]
    ) -> list[Finding]:
        """Graph-based reachability analysis for the scanning phase."""
        try:
            from cloudg.graph.builder import GraphBuilder
            from cloudg.graph.reachability import ReachabilityAnalyzer

            builder = GraphBuilder(max_nodes_warn=self.config.graph.max_nodes_warn)
            graph = builder.build(assets, edges)
            analyzer = ReachabilityAnalyzer(graph)
            return analyzer.generate_findings()
        except Exception as exc:
            logger.error("Graph analysis failed: %s", exc)
            self._emit_error("graph_analysis", exc)
            return []

    def _resolve_scan_iac_dirs(
        self,
        iac_dir: str | None,
        assets: list[CloudAsset],
        edges: list[NetworkEdge],
        out: Path,
    ) -> list[str]:
        """Resolve the IaC directories the scanners should target.

        When nothing is configured but Terraform recreation is enabled,
        generate it now and scan that: the IaC scanners then audit the live
        infrastructure via its Terraform representation instead of an
        unrelated local directory.
        """
        tf_dir: str | None = None
        if (
            not iac_dir
            and not self.config.scanners.iac_directories
            and self.config.terraform.enabled
        ):
            from cloudg.renderers.terraform_export import TerraformExporter, terraform_output_dir

            tf_dir = str(terraform_output_dir(self.config.terraform, out))
            try:
                TerraformExporter(output_dir=tf_dir).export(assets, edges)
            except Exception as exc:
                logger.error("Terraform export for IaC scanning failed: %s", exc)
                self._emit_error("terraform", exc)
                tf_dir = None

        resolved_iac_dirs, iac_source = resolve_iac_dirs(
            iac_dir, self.config.scanners.iac_directories, tf_dir
        )
        if iac_source == "terraform":
            logger.info("IaC scanners target the Terraform recreation at %s", resolved_iac_dirs[0])
        return resolved_iac_dirs

    def _run_scan_plan(self, plan: ScanPlan) -> list[Finding]:
        """Run every planned job concurrently and collect their findings.

        ``on_finding`` fires for each scanner's findings as soon as that
        scanner finishes. A scanner that exceeds scanners.timeout_seconds is
        killed by its own subprocess timeout and reported through
        ``on_error`` (as are scanners that fail outright); findings it
        produced before that are kept.
        """
        import concurrent.futures

        for level, message in plan.notes:
            getattr(logger, "info" if level == "info" else "warning")(message)
        for phase, exc in plan.errors:
            self._emit_error(phase, exc)
        if not plan.jobs:
            return []

        from cloudg.normaliser import FindingList

        # A FindingList, so Prowler's passing checks reach the normaliser
        scanner_findings = FindingList()
        with concurrent.futures.ThreadPoolExecutor(max_workers=max(len(plan.jobs), 2)) as executor:
            future_to_job = {executor.submit(job.fn): job for job in plan.jobs}
            for future in concurrent.futures.as_completed(future_to_job):
                job = future_to_job[future]
                try:
                    findings = future.result()
                except ScannerFailed as exc:
                    logger.error("[%s] did not finish: %s", job.name, exc)
                    self._emit_error(job.name, exc)
                    findings = exc.findings
                except Exception as exc:
                    logger.error("[%s] failed: %s", job.name, exc)
                    self._emit_error(job.name, exc)
                    continue
                scanner_findings.extend(findings)
                scanner_findings.passed_checks.update(
                    getattr(findings, "passed_checks", None) or ()
                )
                logger.info("[%s] %d findings", job.name, len(findings))
                self._emit_findings(findings)

        return scanner_findings

    def _emit_findings(self, findings: list[Finding]) -> None:
        """Hand copies of ``findings`` to ``on_finding``, one call per finding.

        Copies, because normalisation later merges and rescores the
        originals in place.
        """
        if not self.on_finding:
            return
        for f in findings:
            try:
                self.on_finding(f.model_copy(deep=True))
            except Exception:
                logger.debug("Event hook raised; ignoring", exc_info=True)

    def _emit_scan_complete(self, all_findings: list[Finding]) -> None:
        """Hand copies of every finding of the scan to ``on_scan_complete``."""
        if self.on_scan_complete:
            try:
                self.on_scan_complete([f.model_copy(deep=True) for f in all_findings])
            except Exception:
                logger.debug("Event hook raised; ignoring", exc_info=True)

    def _emit_scan_results(self, all_findings: list[Finding]) -> None:
        """Emit per-finding and scan-complete callbacks (with copies)."""
        self._emit_findings(all_findings)
        self._emit_scan_complete(all_findings)
