"""Scanner runs of :class:`cloudg.api.CloudGEngine` (the ``scan`` phase).

Split out of :mod:`cloudg.api` to keep that module readable; the engine
inherits these methods from :class:`ScannerRunsMixin`, and
:func:`resolve_iac_dirs` stays importable from ``cloudg.api``.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Callable

from cloudg.schema.models import CloudAsset, Finding, NetworkEdge

__all__ = ["ScannerRunsMixin", "resolve_iac_dirs"]

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

            builder = GraphBuilder()
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
        scanner_list: list[str],
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
            tf_dir = self.config.terraform.output_dir or str(out / "terraform")
            try:
                from cloudg.renderers.terraform_export import TerraformExporter

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
        elif not resolved_iac_dirs and "checkov" in scanner_list:
            logger.warning(
                "Skipping Checkov: no IaC directory configured. "
                "Pass iac_dir, set scanners.iac_directories, or enable terraform "
                "so the recreated infrastructure can be scanned."
            )
        return resolved_iac_dirs

    def _run_prowler(self, prov: str, profile: str | None, out: Path) -> list[Finding]:
        from cloudg.scanners.prowler import ProwlerScanner

        region = self.config.aws.regions[0] if self.config.aws.regions else None
        scanner = ProwlerScanner(
            provider=prov,
            profile=profile,
            output_dir=str(out / "prowler" / prov),
            extra_args=self.config.scanners.prowler_extra_args or [],
            aws_access_key_id=self.config.aws.access_key_id if prov == "aws" else None,
            aws_secret_access_key=self.config.aws.secret_access_key if prov == "aws" else None,
            aws_region=region if prov == "aws" else None,
        )
        return scanner.run()

    def _run_scoutsuite(self, prov: str, profile: str | None, out: Path) -> list[Finding]:
        from cloudg.scanners.scoutsuite import ScoutSuiteScanner

        scanner = ScoutSuiteScanner(
            provider=prov,
            profile=profile if prov == "aws" else None,
            report_dir=str(out / "scoutsuite" / prov),
            extra_args=self.config.scanners.scoutsuite_extra_args or [],
        )
        return scanner.run()

    def _run_checkov(self, target_dir: str) -> list[Finding]:
        from cloudg.scanners.checkov import CheckovScanner

        scanner = CheckovScanner(
            target_dir=target_dir,
            frameworks=self.config.scanners.checkov_frameworks or None,
            extra_args=self.config.scanners.checkov_extra_args or [],
        )
        return scanner.run()

    def _run_trivy(self, image_list: list[str]) -> list[Finding]:
        from cloudg.scanners.trivy import TrivyScanner

        scanner = TrivyScanner(extra_args=self.config.scanners.trivy_extra_args or [])
        return scanner.scan_images(image_list)

    def _run_iam_linter(self, assets: list[CloudAsset]) -> list[Finding]:
        from cloudg.scanners.iam_linter import IAMLinter

        linter = IAMLinter()
        return linter.analyze_policies(assets)

    def _submit_scanner_jobs(
        self,
        executor: Any,
        scanner_list: list[str],
        assets: list[CloudAsset],
        resolved_iac_dirs: list[str],
        resolved_images: list[str],
        profile: str | None,
        out: Path,
    ) -> dict[Any, str]:
        """Submit one job per enabled scanner target; returns future -> name."""
        future_to_name: dict[Any, str] = {}

        if "prowler" in scanner_list:
            for prov in self.config.providers:
                future_to_name[executor.submit(self._run_prowler, prov, profile, out)] = (
                    f"prowler-{prov}"
                )

        if "scoutsuite" in scanner_list:
            for prov in self.config.providers:
                future_to_name[executor.submit(self._run_scoutsuite, prov, profile, out)] = (
                    f"scoutsuite-{prov}"
                )

        if "checkov" in scanner_list:
            for d in resolved_iac_dirs:
                future_to_name[executor.submit(self._run_checkov, d)] = f"checkov-{d}"

        if "trivy" in scanner_list and resolved_images:
            future_to_name[executor.submit(self._run_trivy, resolved_images)] = "trivy"

        # IAM linter always runs if assets exist
        if assets:
            future_to_name[executor.submit(self._run_iam_linter, assets)] = "iam"

        return future_to_name

    def _run_scanners_parallel(
        self,
        scanner_list: list[str],
        assets: list[CloudAsset],
        resolved_iac_dirs: list[str],
        resolved_images: list[str],
        profile: str | None,
        out: Path,
    ) -> list[Finding]:
        """Run all enabled scanners concurrently and collect their findings."""
        import concurrent.futures

        scanner_findings: list[Finding] = []
        max_workers = len(scanner_list) + len(self.config.providers) + 1
        with concurrent.futures.ThreadPoolExecutor(max_workers=max(max_workers, 2)) as executor:
            future_to_name = self._submit_scanner_jobs(
                executor, scanner_list, assets, resolved_iac_dirs, resolved_images, profile, out
            )

            for future in concurrent.futures.as_completed(future_to_name):
                name = future_to_name[future]
                try:
                    findings = future.result(timeout=self.config.scanners.timeout_seconds)
                    scanner_findings.extend(findings)
                    logger.info("[%s] %d findings", name, len(findings))
                except concurrent.futures.TimeoutError:
                    logger.error(
                        "[%s] timed out after %ds", name, self.config.scanners.timeout_seconds
                    )
                    self._emit_error(name, TimeoutError(f"{name} timed out"))
                except Exception as exc:
                    logger.error("[%s] failed: %s", name, exc)
                    self._emit_error(name, exc)

        return scanner_findings

    def _emit_scan_results(self, all_findings: list[Finding]) -> None:
        """Emit per-finding and scan-complete callbacks."""
        if self.on_finding:
            for f in all_findings:
                try:
                    self.on_finding(f)
                except Exception:
                    logger.debug("Event hook raised; ignoring", exc_info=True)

        if self.on_scan_complete:
            try:
                self.on_scan_complete(all_findings)
            except Exception:
                logger.debug("Event hook raised; ignoring", exc_info=True)
