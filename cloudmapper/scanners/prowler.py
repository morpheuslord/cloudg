"""Prowler CSPM scanner wrapper — runs Prowler CLI and parses ASFF JSON output."""

from __future__ import annotations

import glob
import json
import logging
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any

from cloudmapper.schema.models import Finding, Severity

logger = logging.getLogger(__name__)

# Map Prowler severity labels to our enum
_SEVERITY_MAP = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "informational": Severity.INFO,
    "info": Severity.INFO,
}

# Compliance framework mapping from Prowler check prefixes
_COMPLIANCE_MAP = {
    "cis": "CIS",
    "nist": "NIST-800-53",
    "pci": "PCI-DSS",
    "gdpr": "GDPR",
    "hipaa": "HIPAA",
    "soc2": "SOC2",
}


class ProwlerScanner:
    """Wraps Prowler CLI to run cloud security checks and parse ASFF JSON output.

    Usage:
        scanner = ProwlerScanner(provider="aws", profile="default")
        findings = scanner.run()
    """

    def __init__(
        self,
        provider: str = "aws",
        profile: str | None = None,
        output_dir: str | None = None,
        extra_args: list[str] | None = None,
    ) -> None:
        self._provider = provider
        self._profile = profile
        self._output_dir = output_dir or tempfile.mkdtemp(prefix="prowler_")
        self._extra_args = extra_args or []

    @staticmethod
    def is_available() -> bool:
        """Check if Prowler CLI is installed."""
        return shutil.which("prowler") is not None

    def run(self) -> list[Finding]:
        """Execute Prowler scan and return normalised findings.

        Returns:
            List of Finding objects parsed from Prowler ASFF JSON output.
        """
        if not self.is_available():
            logger.warning(
                "Prowler is not installed. Install with: pip install prowler. "
                "Skipping Prowler scan."
            )
            return []

        cmd = [
            "prowler",
            self._provider,
            "-M", "json-asff",
            "-o", self._output_dir,
        ]

        if self._profile and self._provider == "aws":
            cmd.extend(["-p", self._profile])

        cmd.extend(self._extra_args)

        logger.info("Running Prowler: %s", " ".join(cmd))

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=3600,  # 1 hour timeout
                check=False,
            )

            if result.returncode != 0:
                logger.warning("Prowler exited with code %d: %s", result.returncode, result.stderr[:500])

        except subprocess.TimeoutExpired:
            logger.error("Prowler scan timed out")
            return []
        except Exception as exc:
            logger.error("Failed to run Prowler: %s", exc)
            return []

        return self._parse_output()

    def _parse_output(self) -> list[Finding]:
        """Parse Prowler ASFF JSON output files."""
        findings: list[Finding] = []
        output_files = glob.glob(f"{self._output_dir}/**/*.json", recursive=True)

        for file_path in output_files:
            try:
                with open(file_path) as f:
                    content = f.read().strip()
                    if not content:
                        continue

                    # Prowler may output JSON array or JSONL
                    if content.startswith("["):
                        data = json.loads(content)
                    else:
                        data = [json.loads(line) for line in content.splitlines() if line.strip()]

                    for item in data:
                        finding = self._parse_asff_finding(item)
                        if finding:
                            findings.append(finding)

            except (json.JSONDecodeError, OSError) as exc:
                logger.warning("Failed to parse Prowler output %s: %s", file_path, exc)

        logger.info("Parsed %d findings from Prowler", len(findings))
        return findings

    def _parse_asff_finding(self, asff: dict[str, Any]) -> Finding | None:
        """Convert a single ASFF finding to our Finding model."""
        try:
            # Extract severity
            severity_label = (
                asff.get("Severity", {}).get("Label", "")
                or asff.get("ProductFields", {}).get("Severity", "")
            ).lower()
            severity = _SEVERITY_MAP.get(severity_label, Severity.MEDIUM)

            # Extract resource ARN
            resources = asff.get("Resources", [])
            resource_arn = resources[0].get("Id", "") if resources else ""

            # Extract compliance frameworks
            compliance = []
            compliance_data = asff.get("Compliance", {})
            for standard in compliance_data.get("RelatedRequirements", []):
                for prefix, framework in _COMPLIANCE_MAP.items():
                    if prefix in standard.lower():
                        compliance.append(framework)
                        break

            # Extract status — skip PASS findings
            status = asff.get("Compliance", {}).get("Status", "")
            if status.upper() == "PASSED":
                return None

            return Finding(
                resource_id=resource_arn,
                resource_arn=resource_arn,
                severity=severity,
                title=asff.get("Title", "Unknown Prowler Finding"),
                description=asff.get("Description", ""),
                evidence=json.dumps(asff.get("ProductFields", {}), default=str)[:1000],
                remediation=(
                    asff.get("Remediation", {})
                    .get("Recommendation", {})
                    .get("Text", "")
                ),
                source_tool="prowler",
                source_finding_id=asff.get("Id", ""),
                compliance_frameworks=list(set(compliance)),
            )
        except Exception as exc:
            logger.debug("Failed to parse ASFF finding: %s", exc)
            return None
