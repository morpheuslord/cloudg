"""ScoutSuite multi-cloud audit scanner wrapper."""

from __future__ import annotations

import json
import logging
import re
import shutil
import subprocess  # nosec B404 - runs the wrapped scanner CLIs with argv lists, never a shell
import tempfile
from pathlib import Path
from typing import Any

from cloudg.schema.models import Finding, Severity

logger = logging.getLogger(__name__)

_SEVERITY_MAP = {
    "danger": Severity.CRITICAL,
    "warning": Severity.HIGH,
    "caution": Severity.MEDIUM,
    "good": Severity.INFO,
}


# Compliance benchmark names in a ScoutSuite rule's ``compliance`` list
# (lower-case substring) to the framework name cloudg uses
_COMPLIANCE_MAP = {"cis": "CIS"}


def _compliance_frameworks(finding_data: dict[str, Any]) -> list[str]:
    """Frameworks named by a ScoutSuite finding's ``compliance`` entries.

    Entries look like ``{"name": "CIS Amazon Web Services Foundations",
    "version": "1.2.0", "reference": "1.3"}``. The finding's ``references``
    are documentation URLs, not frameworks, and are not used here.
    """
    frameworks: list[str] = []
    for entry in finding_data.get("compliance") or []:
        name = str(entry.get("name", "") if isinstance(entry, dict) else entry).lower()
        for needle, framework in _COMPLIANCE_MAP.items():
            if needle in name and framework not in frameworks:
                frameworks.append(framework)
    return frameworks


class ScoutSuiteScanner:
    """Wraps ScoutSuite CLI: runs `scout` and parses the results JS file.

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
        timeout_seconds: int = 3600,
        env: dict[str, str] | None = None,
        regions: list[str] | None = None,
    ) -> None:
        """``timeout_seconds`` is how long ScoutSuite may run; ``env`` adds
        environment variables (for example resolved AWS credentials) to the
        process. ``regions`` limits an AWS scan (``--regions``); None, empty
        or ["ALL"] scans every region, and a ``--regions`` in ``extra_args``
        wins."""
        self._provider = provider
        self._profile = profile
        self._report_dir = report_dir or tempfile.mkdtemp(prefix="scoutsuite_")
        self._extra_args = extra_args or []
        self._timeout_seconds = timeout_seconds
        self._env = dict(env or {})
        self._regions = [
            r for r in (regions or []) if r and r.strip() and r.strip().upper() != "ALL"
        ]
        #: Why the last run did not finish (timeout, launch failure); empty on success
        self.errors: list[str] = []

    def _build_env(self) -> dict[str, str] | None:
        """Process environment: the parent's plus ``env`` (None when unchanged)."""
        if not self._env:
            return None
        import os

        env = os.environ.copy()
        env.update(self._env)
        if "AWS_ACCESS_KEY_ID" in self._env:
            # botocore ignores the key variables while a profile is selected
            env.pop("AWS_PROFILE", None)
            if "AWS_SESSION_TOKEN" not in self._env:
                env.pop("AWS_SESSION_TOKEN", None)
        return env

    def _build_command(self) -> list[str]:
        """Build the ``scout`` argv list."""
        cmd = ["scout", self._provider, "--report-dir", self._report_dir, "--no-browser"]

        if self._profile and self._provider == "aws":
            cmd.extend(["--profile", self._profile])

        if (
            self._provider == "aws"
            and self._regions
            and not any(arg.split("=", 1)[0] == "--regions" for arg in self._extra_args)
        ):
            cmd.extend(["--regions", *self._regions])

        cmd.extend(self._extra_args)
        return cmd

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

        cmd = self._build_command()

        logger.info("Running ScoutSuite: %s", " ".join(cmd))

        try:
            # The argv list starts with the scanner binary name and shell=False;
            # user-controlled parts are arguments, not code.
            result = subprocess.run(  # nosemgrep: python.lang.security.audit.dangerous-subprocess-use-audit.dangerous-subprocess-use-audit # nosec B603
                cmd,
                capture_output=True,
                text=True,
                timeout=self._timeout_seconds,
                check=False,
                env=self._build_env(),
            )
            if result.returncode != 0:
                logger.warning(
                    "ScoutSuite exited with code %d: %s",
                    result.returncode,
                    result.stderr[:500],
                )
        except subprocess.TimeoutExpired:
            logger.error("ScoutSuite scan timed out after %ds", self._timeout_seconds)
            self.errors.append(f"timed out after {self._timeout_seconds}s")
            return []
        except Exception as exc:
            logger.error("Failed to run ScoutSuite: %s", exc)
            self.errors.append(f"could not run: {exc}")
            return []

        return self._parse_output()

    @classmethod
    def parse_report(cls, path: str) -> list[Finding]:
        """Parse existing ScoutSuite results without running ScoutSuite.

        Accepts the ``scoutsuite_results_*.js`` file itself or a report
        directory that is searched recursively for it (ScoutSuite's
        ``--report-dir`` output directory works as-is).
        """
        p = Path(path)
        if p.is_dir():
            files = list(p.rglob("scoutsuite_results*.js"))
            if not files:
                logger.warning("No ScoutSuite results found in %s", path)
        else:
            files = [p]
        return cls()._parse_files(files)

    def _parse_output(self) -> list[Finding]:
        """Parse ScoutSuite results JS file."""
        report_dir = Path(self._report_dir)
        # ScoutSuite outputs: scoutsuite-results/scoutsuite_results*.js
        results_files = list(report_dir.rglob("scoutsuite_results*.js"))

        if not results_files:
            logger.warning("No ScoutSuite results found in %s", self._report_dir)
            return []

        return self._parse_files(results_files)

    def _parse_files(self, results_files: list[Path]) -> list[Finding]:
        """Parse a list of ScoutSuite results JS files."""
        findings: list[Finding] = []

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

                frameworks = _compliance_frameworks(finding_data)
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
                            compliance_frameworks=list(frameworks),
                        )
                    )

        return findings
