"""Trivy container and CVE scanner wrapper."""

from __future__ import annotations

import json
import logging
import shutil
import subprocess
from typing import Any

from cloudmapper.schema.models import Finding, Severity

logger = logging.getLogger(__name__)

_SEVERITY_MAP = {
    "CRITICAL": Severity.CRITICAL,
    "HIGH": Severity.HIGH,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
    "UNKNOWN": Severity.INFO,
}


class TrivyScanner:
    """Wraps Trivy CLI for container image CVE and secret scanning.

    Scans container images from ECR/ACR/GCR and maps CVEs to findings.
    """

    def __init__(
        self,
        extra_args: list[str] | None = None,
    ) -> None:
        self._extra_args = extra_args or []

    @staticmethod
    def is_available() -> bool:
        """Check if Trivy is installed."""
        return shutil.which("trivy") is not None

    def scan_image(self, image: str) -> list[Finding]:
        """Scan a single container image for CVEs.

        Args:
            image: Full image reference (e.g. 123456.dkr.ecr.us-east-1.amazonaws.com/app:latest).

        Returns:
            List of Finding objects for discovered CVEs.
        """
        if not self.is_available():
            logger.warning(
                "Trivy is not installed. Install from: https://trivy.dev/. "
                "Skipping Trivy scan."
            )
            return []

        cmd = [
            "trivy",
            "image",
            "--format", "json",
            "--quiet",
            *self._extra_args,
            image,
        ]

        logger.info("Running Trivy: %s", " ".join(cmd))

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=1800,
                check=False,
            )
        except subprocess.TimeoutExpired:
            logger.error("Trivy scan timed out for image %s", image)
            return []
        except Exception as exc:
            logger.error("Failed to run Trivy for %s: %s", image, exc)
            return []

        return self._parse_output(result.stdout, image)

    def scan_images(self, images: list[str]) -> list[Finding]:
        """Scan multiple container images.

        Args:
            images: List of image references.

        Returns:
            Combined list of Finding objects.
        """
        all_findings: list[Finding] = []
        for image in images:
            all_findings.extend(self.scan_image(image))
        return all_findings

    def _parse_output(self, stdout: str, image: str) -> list[Finding]:
        """Parse Trivy JSON output."""
        findings: list[Finding] = []

        if not stdout.strip():
            return []

        try:
            data = json.loads(stdout)
        except json.JSONDecodeError as exc:
            logger.warning("Failed to parse Trivy JSON: %s", exc)
            return []

        results = data.get("Results", [])
        for result in results:
            target = result.get("Target", "")
            target_type = result.get("Type", "")

            # CVE vulnerabilities
            for vuln in result.get("Vulnerabilities", []):
                finding = self._parse_vulnerability(vuln, image, target, target_type)
                if finding:
                    findings.append(finding)

            # Secret findings
            for secret in result.get("Secrets", []):
                finding = self._parse_secret(secret, image, target)
                if finding:
                    findings.append(finding)

        logger.info("Parsed %d findings from Trivy for %s", len(findings), image)
        return findings

    def _parse_vulnerability(
        self,
        vuln: dict[str, Any],
        image: str,
        target: str,
        target_type: str,
    ) -> Finding | None:
        """Parse a single Trivy CVE vulnerability."""
        try:
            severity_str = vuln.get("Severity", "UNKNOWN").upper()
            severity = _SEVERITY_MAP.get(severity_str, Severity.MEDIUM)

            cve_id = vuln.get("VulnerabilityID", "")
            pkg_name = vuln.get("PkgName", "")
            installed_version = vuln.get("InstalledVersion", "")
            fixed_version = vuln.get("FixedVersion", "")

            description = vuln.get("Description", "")
            if len(description) > 500:
                description = description[:500] + "..."

            cvss_score = None
            cvss_data = vuln.get("CVSS", {})
            for source in cvss_data.values():
                if isinstance(source, dict) and "V3Score" in source:
                    cvss_score = source["V3Score"]
                    break

            remediation = ""
            if fixed_version:
                remediation = f"Update {pkg_name} from {installed_version} to {fixed_version}"
            else:
                remediation = f"No fix available for {cve_id} in {pkg_name}. Consider alternative packages."

            return Finding(
                resource_id=image,
                resource_arn=image,
                severity=severity,
                title=f"[Trivy] {cve_id}: {pkg_name} ({target_type})",
                description=description,
                evidence=f"Image: {image}, Target: {target}, Package: {pkg_name}@{installed_version}",
                remediation=remediation,
                source_tool="trivy",
                source_finding_id=cve_id,
                cvss_score=cvss_score,
                compliance_frameworks=["CVE"],
            )
        except Exception as exc:
            logger.debug("Failed to parse Trivy vulnerability: %s", exc)
            return None

    def _parse_secret(
        self,
        secret: dict[str, Any],
        image: str,
        target: str,
    ) -> Finding | None:
        """Parse a Trivy secret finding."""
        try:
            return Finding(
                resource_id=image,
                resource_arn=image,
                severity=Severity.HIGH,
                title=f"[Trivy] Secret found in container image: {secret.get('RuleID', 'unknown')}",
                description=f"Category: {secret.get('Category', '')}, Title: {secret.get('Title', '')}",
                evidence=f"Image: {image}, Target: {target}, Match: {secret.get('Match', '')[:200]}",
                remediation="Remove secrets from container images. Use secret management services (AWS Secrets Manager, Azure Key Vault, GCP Secret Manager).",
                source_tool="trivy",
                source_finding_id=secret.get("RuleID", ""),
            )
        except Exception as exc:
            logger.debug("Failed to parse Trivy secret: %s", exc)
            return None
