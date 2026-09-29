"""Trivy container and CVE scanner wrapper."""

from __future__ import annotations

import json
import logging
import shutil
import subprocess  # nosec B404 - runs the wrapped scanner CLIs with argv lists, never a shell
from typing import Any

from cloudg.schema.models import Finding, Severity

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
                "Trivy is not installed. Install from: https://trivy.dev/. Skipping Trivy scan."
            )
            return []

        cmd = [
            "trivy",
            "image",
            "--format",
            "json",
            "--quiet",
            *self._extra_args,
            image,
        ]

        logger.info("Running Trivy: %s", " ".join(cmd))

        try:
            # The argv list starts with the scanner binary name and shell=False;
            # user-controlled parts are arguments, not code.
            result = subprocess.run(  # nosemgrep: python.lang.security.audit.dangerous-subprocess-use-audit.dangerous-subprocess-use-audit # nosec B603
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

    def scan_filesystem(self, directories: list[str]) -> list[Finding]:
        """Scan filesystem directories for misconfigurations and vulnerabilities.

        Uses 'trivy fs' to scan IaC files, lock files, and other artifacts
        without requiring container images.

        Args:
            directories: List of directory paths to scan.

        Returns:
            Combined list of Finding objects.
        """
        if not self.is_available():
            logger.warning(
                "Trivy is not installed. Install from: https://trivy.dev/. "
                "Skipping Trivy filesystem scan."
            )
            return []

        all_findings: list[Finding] = []
        for directory in directories:
            cmd = [
                "trivy",
                "fs",
                "--format",
                "json",
                "--quiet",
                "--scanners",
                "vuln,misconfig,secret",
                *self._extra_args,
                directory,
            ]

            logger.info("Running Trivy filesystem scan: %s", " ".join(cmd))

            try:
                # The argv list starts with the scanner binary name and shell=False;
                # user-controlled parts are arguments, not code.
                result = subprocess.run(  # nosemgrep: python.lang.security.audit.dangerous-subprocess-use-audit.dangerous-subprocess-use-audit # nosec B603
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=1800,
                    check=False,
                )
            except subprocess.TimeoutExpired:
                logger.error("Trivy filesystem scan timed out for %s", directory)
                continue
            except Exception as exc:
                logger.error("Failed to run Trivy fs for %s: %s", directory, exc)
                continue

            findings = self._parse_fs_output(result.stdout, directory)
            all_findings.extend(findings)

        return all_findings

    @classmethod
    def parse_report(cls, path: str) -> list[Finding]:
        """Parse existing Trivy JSON output without running Trivy.

        Accepts a ``trivy image|fs --format json`` report file or a
        directory of them. Image scans and filesystem/repository scans are
        told apart by the report's ``ArtifactType`` field.
        """
        from pathlib import Path

        p = Path(path)
        if p.is_dir():
            candidates = sorted(p.rglob("*.json"))
            if not candidates:
                logger.warning("No Trivy JSON results found in %s", path)
                return []
        else:
            candidates = [p]

        scanner = cls()
        findings: list[Finding] = []
        for file_path in candidates:
            try:
                content = file_path.read_text()
                data = json.loads(content)
            except (OSError, json.JSONDecodeError) as exc:
                logger.warning("Failed to read Trivy output %s: %s", file_path, exc)
                continue
            if not isinstance(data, dict):
                logger.warning("Unrecognised Trivy output structure in %s", file_path)
                continue

            artifact = data.get("ArtifactName", str(file_path))
            if data.get("ArtifactType") == "container_image":
                findings.extend(scanner._parse_output(content, artifact))
            else:
                # filesystem / repository scans: the fs parser also handles
                # misconfigurations and secrets, so it covers everything else
                findings.extend(scanner._parse_fs_output(content, artifact))
        return findings

    def _parse_fs_output(self, stdout: str, directory: str) -> list[Finding]:
        """Parse Trivy filesystem scan JSON output."""
        findings: list[Finding] = []

        if not stdout.strip():
            logger.warning("Trivy fs produced no output for %s", directory)
            return []

        try:
            data = json.loads(stdout)
        except json.JSONDecodeError as exc:
            logger.warning("Failed to parse Trivy fs JSON: %s", exc)
            return []

        results = data.get("Results", [])
        for result in results:
            target = result.get("Target", "")
            target_type = result.get("Type", "")

            # Vulnerabilities (from lock files, package manifests)
            for vuln in result.get("Vulnerabilities", []):
                finding = self._parse_vulnerability(vuln, directory, target, target_type)
                if finding:
                    findings.append(finding)

            # Misconfigurations (from IaC files)
            for misconfig in result.get("Misconfigurations", []):
                finding = self._parse_misconfig(misconfig, directory, target)
                if finding:
                    findings.append(finding)

            # Secret findings
            for secret in result.get("Secrets", []):
                finding = self._parse_secret(secret, directory, target)
                if finding:
                    findings.append(finding)

        logger.info("Parsed %d findings from Trivy fs for %s", len(findings), directory)
        return findings

    def _parse_misconfig(
        self,
        misconfig: dict[str, Any],
        directory: str,
        target: str,
    ) -> Finding | None:
        """Parse a single Trivy misconfiguration finding."""
        try:
            severity_str = misconfig.get("Severity", "UNKNOWN").upper()
            severity = _SEVERITY_MAP.get(severity_str, Severity.MEDIUM)

            misconfig_id = misconfig.get("ID", "")
            title = misconfig.get("Title", "")
            description = misconfig.get("Description", "")
            if len(description) > 500:
                description = description[:500] + "..."

            resolution = misconfig.get("Resolution", "")
            primary_url = misconfig.get("PrimaryURL", "")

            return Finding(
                resource_id=directory,
                resource_arn=directory,
                severity=severity,
                title=f"[Trivy/IaC] {misconfig_id}: {title}",
                description=description,
                evidence=f"Directory: {directory}, Target: {target}",
                remediation=resolution
                if resolution
                else primary_url or f"See Trivy check {misconfig_id}",
                source_tool="trivy",
                source_finding_id=misconfig_id,
                compliance_frameworks=["CIS"],
            )
        except Exception as exc:
            logger.debug("Failed to parse Trivy misconfiguration: %s", exc)
            return None

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
                remediation = (
                    f"No fix available for {cve_id} in {pkg_name}. Consider alternative packages."
                )

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
            logger.debug("Failed to parse a Trivy sensitive-data result: %s", exc)
            return None
