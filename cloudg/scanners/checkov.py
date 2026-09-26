"""Checkov IaC static analysis scanner wrapper."""

from __future__ import annotations

import json
import logging
import shutil
import subprocess
from typing import Any

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


class CheckovScanner:
    """Wraps Checkov CLI to scan IaC directories for misconfigurations.

    Supports Terraform, CloudFormation, ARM templates, Kubernetes manifests.
    """

    def __init__(
        self,
        target_dir: str = ".",
        frameworks: list[str] | None = None,
        extra_args: list[str] | None = None,
    ) -> None:
        self._target_dir = target_dir
        self._frameworks = frameworks or []
        self._extra_args = extra_args or []

    @staticmethod
    def is_available() -> bool:
        """Check if Checkov is installed."""
        return shutil.which("checkov") is not None

    def run(self) -> list[Finding]:
        """Execute Checkov scan and return normalised findings.

        If no frameworks are configured, Checkov auto-detects all applicable
        frameworks (terraform, cloudformation, arm, kubernetes, etc.) in the
        target directory — which is the correct behaviour for cloud
        infrastructure scanning.
        """
        if not self.is_available():
            logger.warning(
                "Checkov is not installed. Install with: pip install checkov. "
                "Skipping Checkov scan."
            )
            return []

        cmd = [
            "checkov",
            "-d", self._target_dir,
            "--output", "json",
            "--quiet",
        ]

        # Pass all frameworks in one shot; omit flag entirely for auto-detect
        if self._frameworks:
            cmd.extend(["--framework", *self._frameworks])

        cmd.extend(self._extra_args)

        logger.info("Running Checkov: %s", " ".join(cmd))

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=1800,
                check=False,  # Checkov returns non-zero on failures found
            )
        except subprocess.TimeoutExpired:
            logger.error("Checkov scan timed out")
            return []
        except Exception as exc:
            logger.error("Failed to run Checkov: %s", exc)
            return []

        return self._parse_output(result.stdout)

    def _parse_output(self, stdout: str) -> list[Finding]:
        """Parse Checkov JSON output from stdout."""
        findings: list[Finding] = []

        if not stdout.strip():
            logger.warning("Checkov produced no output")
            return []

        try:
            data = json.loads(stdout)
        except json.JSONDecodeError as exc:
            logger.warning("Failed to parse Checkov JSON output: %s", exc)
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
