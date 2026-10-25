"""Checkov IaC static analysis scanner wrapper."""

from __future__ import annotations

import json
import logging
import shutil
import subprocess  # nosec B404 - runs the wrapped scanner CLIs with argv lists, never a shell
from typing import Any

from cloudg.exceptions import ReportParseError, ScannerExecutionError
from cloudg.scanners._errors import ScannerErrorLog
from cloudg.schema.models import Finding, Severity

logger = logging.getLogger(__name__)

_SEVERITY_MAP = {
    "CRITICAL": Severity.CRITICAL,
    "HIGH": Severity.HIGH,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
    "INFO": Severity.INFO,
    "UNKNOWN": Severity.MEDIUM,
}


class CheckovScanner(ScannerErrorLog):
    """Wraps Checkov CLI to scan IaC directories for misconfigurations.

    Supports Terraform, CloudFormation, ARM templates, Kubernetes manifests.
    With ``strict=True`` a failure raises a :mod:`cloudg.exceptions`
    ``ScannerError`` instead of being recorded in ``errors``.
    """

    scanner_name = "checkov"
    executable = "checkov"
    install_hint = "pip install checkov"

    def __init__(
        self,
        target_dir: str = ".",
        frameworks: list[str] | None = None,
        extra_args: list[str] | None = None,
        timeout_seconds: int = 1800,
        strict: bool = False,
    ) -> None:
        self._target_dir = target_dir
        self._frameworks = frameworks or []
        self._extra_args = extra_args or []
        self._timeout_seconds = timeout_seconds
        self._init_errors(strict)

    @staticmethod
    def is_available() -> bool:
        """Check if Checkov is installed."""
        return shutil.which("checkov") is not None

    def run(self) -> list[Finding]:
        """Execute Checkov scan and return normalised findings.

        If no frameworks are configured, Checkov auto-detects all applicable
        frameworks (terraform, cloudformation, arm, kubernetes, etc.) in the
        target directory, which is the correct behaviour for cloud
        infrastructure scanning.
        """
        if not self.is_available():
            self._missing()
            return []

        cmd = [
            "checkov",
            "-d",
            self._target_dir,
            "--output",
            "json",
            "--quiet",
        ]

        # Pass all frameworks in one shot; omit flag entirely for auto-detect
        if self._frameworks:
            cmd.extend(["--framework", *self._frameworks])

        cmd.extend(self._extra_args)

        logger.info("Running Checkov: %s", " ".join(cmd))

        try:
            # The argv list starts with the scanner binary name and shell=False;
            # user-controlled parts are arguments, not code.
            result = subprocess.run(  # nosemgrep: python.lang.security.audit.dangerous-subprocess-use-audit.dangerous-subprocess-use-audit # nosec B603
                cmd,
                capture_output=True,
                text=True,
                timeout=self._timeout_seconds,
                check=False,  # Checkov returns non-zero on failures found
            )
        except subprocess.TimeoutExpired:
            logger.error("Checkov scan timed out after %ds", self._timeout_seconds)
            self._timed_out(self._timeout_seconds, self._target_dir)
            return []
        except Exception as exc:
            logger.error("Failed to run Checkov: %s", exc)
            self._fail(
                ScannerExecutionError("checkov", f"could not run: {exc}", target=self._target_dir)
            )
            return []

        return self._parse_output(result.stdout)

    @classmethod
    def parse_report(cls, path: str, *, strict: bool = False) -> list[Finding]:
        """Parse existing Checkov JSON output without running Checkov.

        Accepts the JSON report file (``checkov --output json``, saved to a
        file, or ``--output-file-path``'s ``results_json.json``) or a
        directory containing it. With ``strict=True`` an unreadable or
        malformed file raises :class:`~cloudg.exceptions.ReportParseError`
        instead of being skipped with a warning.
        """
        from pathlib import Path

        p = Path(path)
        if p.is_dir():
            candidates = list(p.rglob("results_json.json")) or list(p.rglob("*.json"))
            if not candidates:
                if strict:
                    raise ReportParseError("checkov", "no JSON results found", path=str(path))
                logger.warning("No Checkov JSON results found in %s", path)
                return []
        else:
            candidates = [p]

        scanner = cls._report_reader(strict)
        findings: list[Finding] = []
        for file_path in candidates:
            try:
                text = file_path.read_text()
            except OSError as exc:
                if strict:
                    raise ReportParseError(
                        "checkov", f"could not read: {exc}", path=str(file_path)
                    ) from exc
                logger.warning("Failed to read Checkov output %s: %s", file_path, exc)
                continue
            findings.extend(scanner._parse_output(text, source=str(file_path)))
        return findings

    def _parse_output(self, stdout: str, source: str | None = None) -> list[Finding]:
        """Parse Checkov JSON output from stdout (or from the file ``source``)."""
        findings: list[Finding] = []

        if not stdout.strip():
            logger.warning("Checkov produced no output")
            return []

        try:
            data = json.loads(stdout)
        except json.JSONDecodeError as exc:
            logger.warning("Failed to parse Checkov JSON output: %s", exc)
            self._bad_output(f"output is not JSON: {exc}", path=source)
            return []

        # Checkov output can be a list (multiple frameworks) or single dict
        if isinstance(data, list):
            for framework_result in data:
                findings.extend(self._parse_framework_result(framework_result))
        elif isinstance(data, dict):
            findings.extend(self._parse_framework_result(data))

        logger.info("Parsed %d findings from Checkov", len(findings))
        return findings

    def _parse_framework_result(self, data: dict[str, Any]) -> list[Finding]:
        """Parse a single framework result block."""
        findings: list[Finding] = []

        check_type = data.get("check_type", "unknown")
        failed_checks = data.get("results", {}).get("failed_checks", [])

        for check in failed_checks:
            severity_str = check.get("severity", "MEDIUM")
            if isinstance(severity_str, str):
                severity = _SEVERITY_MAP.get(severity_str.upper(), Severity.MEDIUM)
            else:
                severity = Severity.MEDIUM

            resource = check.get("resource", "")
            file_path = check.get("file_path", "")
            file_line_range = check.get("file_line_range", [])

            evidence = f"File: {file_path}"
            if file_line_range:
                evidence += f", Lines: {file_line_range}"

            guideline = check.get("guideline", "")
            check_id = check.get("check_id", "")

            findings.append(
                Finding(
                    resource_id=resource,
                    resource_arn=resource,
                    severity=severity,
                    title=f"[Checkov/{check_type}] {check.get('check_name', check_id)}",
                    description=check.get("check_name", ""),
                    evidence=evidence,
                    remediation=guideline if guideline else f"See Checkov check {check_id}",
                    source_tool="checkov",
                    source_finding_id=check_id,
                    compliance_frameworks=self._map_compliance(check_id),
                )
            )

        return findings

    def _map_compliance(self, check_id: str) -> list[str]:
        """Map Checkov check ID to compliance frameworks."""
        # Checkov checks often map to CIS/NIST
        frameworks = []
        check_lower = check_id.lower()
        if "cis" in check_lower:
            frameworks.append("CIS")
        if "nist" in check_lower:
            frameworks.append("NIST-800-53")
        if "pci" in check_lower:
            frameworks.append("PCI-DSS")
        if not frameworks:
            frameworks.append("CIS")  # Default for IaC misconfigs
        return frameworks
