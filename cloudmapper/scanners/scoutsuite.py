"""ScoutSuite multi-cloud audit scanner wrapper."""

from __future__ import annotations

import json
import logging
import re
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any

from cloudmapper.schema.models import Finding, Severity

logger = logging.getLogger(__name__)

_SEVERITY_MAP = {
    "danger": Severity.CRITICAL,
    "warning": Severity.HIGH,
    "caution": Severity.MEDIUM,
    "good": Severity.INFO,
}


class ScoutSuiteScanner:
    """Wraps ScoutSuite CLI — runs `scout` and parses the results JS file.

    ScoutSuite produces a `scoutsuite_results.js` file containing a JSON
    object assigned to a JS variable. We strip the variable assignment
    and parse the JSON.
    """

    def __init__(
        self,
        provider: str = "aws",
        profile: str | None = None,
        report_dir: str | None = None,
        extra_args: list[str] | None = None,
    ) -> None:
        self._provider = provider
        self._profile = profile
        self._report_dir = report_dir or tempfile.mkdtemp(prefix="scoutsuite_")
        self._extra_args = extra_args or []

    @staticmethod
    def is_available() -> bool:
        """Check if ScoutSuite CLI is installed."""
        return shutil.which("scout") is not None

    def run(self) -> list[Finding]:
        """Execute ScoutSuite scan and return normalised findings."""
        if not self.is_available():
            logger.warning(
                "ScoutSuite is not installed. Install with: pip install scoutsuite. "
                "Skipping ScoutSuite scan."
            )
            return []

        cmd = ["scout", self._provider, "--report-dir", self._report_dir, "--no-browser"]

        if self._profile and self._provider == "aws":
            cmd.extend(["--profile", self._profile])

        cmd.extend(self._extra_args)

        logger.info("Running ScoutSuite: %s", " ".join(cmd))

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=3600,
                check=False,
            )
            if result.returncode != 0:
                logger.warning(
                    "ScoutSuite exited with code %d: %s",
                    result.returncode,
                    result.stderr[:500],
                )
        except subprocess.TimeoutExpired:
            logger.error("ScoutSuite scan timed out")
            return []
        except Exception as exc:
            logger.error("Failed to run ScoutSuite: %s", exc)
            return []

        return self._parse_output()

    def _parse_output(self) -> list[Finding]:
        """Parse ScoutSuite results JS file."""
        findings: list[Finding] = []

        report_dir = Path(self._report_dir)
        # ScoutSuite outputs: scoutsuite-results/scoutsuite_results*.js
        results_files = list(report_dir.rglob("scoutsuite_results*.js"))

        if not results_files:
            logger.warning("No ScoutSuite results found in %s", self._report_dir)
            return []

        for results_file in results_files:
            try:
                content = results_file.read_text()

                # Strip JS variable assignment: scoutsuite_results = {...}
                # The JSON object starts after the first '='
                match = re.search(r"=\s*({.*})\s*;?\s*$", content, re.DOTALL)
                if not match:
                    logger.warning("Could not extract JSON from %s", results_file)
                    continue

                data = json.loads(match.group(1))
                findings.extend(self._extract_findings(data))

            except (json.JSONDecodeError, OSError) as exc:
                logger.warning("Failed to parse ScoutSuite results: %s", exc)

        logger.info("Parsed %d findings from ScoutSuite", len(findings))
        return findings

    def _extract_findings(self, data: dict[str, Any]) -> list[Finding]:
        """Extract findings from parsed ScoutSuite JSON data."""
        findings: list[Finding] = []

        # ScoutSuite organises findings by service
        services = data.get("services", {})

        for service_name, service_data in services.items():
            if not isinstance(service_data, dict):
                continue

            findings_data = service_data.get("findings", {})
            for finding_key, finding_data in findings_data.items():
                if not isinstance(finding_data, dict):
                    continue

                flagged_items = finding_data.get("flagged_items", 0)
                if flagged_items == 0:
                    continue

                severity_str = finding_data.get("level", "warning").lower()
                severity = _SEVERITY_MAP.get(severity_str, Severity.MEDIUM)

                items = finding_data.get("items", [])
                for item in items:
                    findings.append(
                        Finding(
                            resource_id=item if isinstance(item, str) else str(item),
                            resource_arn=item if isinstance(item, str) else "",
                            severity=severity,
                            title=f"[ScoutSuite] {service_name}: {finding_data.get('description', finding_key)}",
                            description=finding_data.get("rationale", ""),
                            remediation=finding_data.get("remediation", ""),
                            source_tool="scoutsuite",
                            source_finding_id=finding_key,
                            compliance_frameworks=finding_data.get("references", []),
                        )
                    )

        return findings
