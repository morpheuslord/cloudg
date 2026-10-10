"""Prowler CSPM scanner wrapper: runs Prowler CLI and parses ASFF JSON output."""

from __future__ import annotations

import glob
import json
import logging
import shutil
import subprocess  # nosec B404 - runs the wrapped scanner CLIs with argv lists, never a shell
import tempfile
from typing import Any

from cloudg.normaliser import FindingList, prowler_check_id
from cloudg.scanners.prowler_ocsf import (
    is_ocsf_record,
    ocsf_check_id,
    ocsf_status,
    parse_ocsf_record,
)
from cloudg.schema.models import Finding, Severity

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


def _get(item: dict[str, Any], *keys: str) -> Any:
    """``item[k1][k2]...``, or "" when a level is missing or not a dict."""
    value: Any = item
    for key in keys:
        value = value.get(key) if isinstance(value, dict) else None
    return "" if value is None else value


# Keyword settings ProwlerScanner accepts on top of its positional arguments
_PROWLER_SETTINGS = frozenset(
    {
        "aws_access_key_id",
        "aws_secret_access_key",
        "aws_session_token",
        "aws_regions",
        "timeout_seconds",
        "env",
    }
)


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
        aws_region: str | None = None,
        **settings: Any,
    ) -> None:
        """Args beyond the provider and paths:

        aws_region: AWS_DEFAULT_REGION for the process; None or "ALL"
            leaves it unset.

        Keyword-only settings (all optional):

        aws_access_key_id / aws_secret_access_key / aws_session_token:
            Credentials exported to the Prowler process (and AWS_PROFILE
            removed from its environment so they take effect).
        aws_regions: Regions to scan, passed as ``-f``. None, empty or
            ["ALL"] passes nothing, so Prowler scans every region. An
            ``-f`` / ``--region`` / ``--filter-region`` in ``extra_args``
            wins.
        timeout_seconds: How long Prowler may run before it is killed
            (default 3600).
        env: Extra environment variables for the process.

        Raises:
            TypeError: an unknown setting is passed.
        """
        unknown = set(settings) - _PROWLER_SETTINGS
        if unknown:
            raise TypeError(f"ProwlerScanner got unexpected settings: {', '.join(sorted(unknown))}")
        self._provider = provider
        self._profile = profile
        self._output_dir = output_dir or tempfile.mkdtemp(prefix="prowler_")
        self._extra_args = extra_args or []
        self._aws_access_key_id = settings.get("aws_access_key_id")
        self._aws_secret_access_key = settings.get("aws_secret_access_key")
        self._aws_session_token = settings.get("aws_session_token")
        self._aws_region = aws_region
        self._timeout_seconds = settings.get("timeout_seconds", 3600)
        self._env = dict(settings.get("env") or {})
        self._aws_regions = [
            r
            for r in (settings.get("aws_regions") or [])
            if r and r.strip() and r.strip().upper() != "ALL"
        ]
        #: Why the last run did not finish (timeout, launch failure); empty on success
        self.errors: list[str] = []

    @staticmethod
    def is_available() -> bool:
        """Check if Prowler CLI is installed."""
        return shutil.which("prowler") is not None

    def run(self) -> list[Finding]:
        """Execute Prowler scan and return normalised findings.

        Streams stdout/stderr live for real-time progress output.

        Returns:
            List of Finding objects parsed from Prowler ASFF JSON output.
        """
        import time

        if not self.is_available():
            logger.warning(
                "Prowler is not installed. Install with: pip install prowler. "
                "Skipping Prowler scan."
            )
            return []

        cmd = self._build_command()
        logger.info("[Prowler] Starting: %s", " ".join(cmd))

        env = self._build_env()
        start_time = time.time()

        if not self._execute(cmd, env, start_time):
            return []

        return self._parse_output()

    def _build_command(self) -> list[str]:
        """Build the Prowler CLI argv list."""
        cmd = [
            "prowler",
            self._provider,
            "-M",
            "json-asff",
            "-o",
            self._output_dir,
        ]

        if self._profile and self._provider == "aws":
            cmd.extend(["-p", self._profile])

        region_flags = {"-f", "--region", "--filter-region"}
        if (
            self._provider == "aws"
            and self._aws_regions
            and not any(arg.split("=", 1)[0] in region_flags for arg in self._extra_args)
        ):
            cmd.extend(["-f", *self._aws_regions])

        cmd.extend(self._extra_args)
        return cmd

    def _build_env(self) -> dict[str, str]:
        """Build environment with AWS credentials for the subprocess."""
        import os

        env = os.environ.copy()
        env.update(self._env)
        if self._aws_access_key_id and self._aws_secret_access_key:
            env["AWS_ACCESS_KEY_ID"] = self._aws_access_key_id
            env["AWS_SECRET_ACCESS_KEY"] = self._aws_secret_access_key
            if self._aws_session_token:
                env["AWS_SESSION_TOKEN"] = self._aws_session_token
            else:
                env.pop("AWS_SESSION_TOKEN", None)
            # botocore ignores the key variables while a profile is selected
            env.pop("AWS_PROFILE", None)
        if self._aws_region and self._aws_region.upper() != "ALL":
            env["AWS_DEFAULT_REGION"] = self._aws_region
        elif (env.get("AWS_DEFAULT_REGION") or "").upper() == "ALL":
            env.pop("AWS_DEFAULT_REGION")
        return env

    def _stream_output(self, proc: Any, start_time: float) -> None:
        """Stream process output, logging progress every 25 checks."""
        import time

        check_count = 0
        for line in proc.stdout:
            stripped = line.rstrip()
            if not stripped:
                continue
            # Count checks for progress reporting
            if "PASS" in stripped or "FAIL" in stripped or "WARNING" in stripped:
                check_count += 1
                if check_count % 25 == 0:
                    elapsed = int(time.time() - start_time)
                    logger.info("[Prowler] %d checks completed (%ds elapsed)", check_count, elapsed)
            elif "Executing" in stripped or "Service" in stripped:
                logger.info("[Prowler] %s", stripped[:120])

    def _execute(self, cmd: list[str], env: dict[str, str], start_time: float) -> bool:
        """Run the Prowler process; returns False when the run failed outright."""
        import time
        import threading

        try:
            # Use Popen for live streaming instead of blocking subprocess.run
            # The argv list starts with the prowler binary and shell=False;
            # user-controlled parts are arguments, not code.
            proc = subprocess.Popen(  # nosemgrep: python.lang.security.audit.dangerous-subprocess-use-audit.dangerous-subprocess-use-audit # nosec B603
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                env=env,
                bufsize=1,  # line-buffered
            )

            # Stream output in a reader thread
            reader = threading.Thread(
                target=self._stream_output, args=(proc, start_time), daemon=True
            )
            reader.start()

            proc.wait(timeout=self._timeout_seconds)
            reader.join(timeout=5)

            elapsed = int(time.time() - start_time)
            if proc.returncode != 0:
                logger.warning("[Prowler] Exited with code %d after %ds", proc.returncode, elapsed)
            else:
                logger.info("[Prowler] Completed successfully in %ds", elapsed)

        except subprocess.TimeoutExpired:
            logger.error(
                "[Prowler] Scan timed out after %ds; killing process", self._timeout_seconds
            )
            proc.kill()
            self.errors.append(f"timed out after {self._timeout_seconds}s")
            return False
        except Exception as exc:
            logger.error("[Prowler] Failed to run: %s", exc)
            self.errors.append(f"could not run: {exc}")
            return False

        return True

    #: Prowler check names that passed in the last parsed output (ASFF
    #: ``PASSED`` or OCSF ``PASS`` records); see :class:`cloudg.normaliser.FindingList`
    passed_checks: frozenset[str] = frozenset()

    @classmethod
    def parse_report(cls, path: str) -> list[Finding]:
        """Parse existing Prowler output without running Prowler.

        Accepts a single ASFF (``-M json-asff``) or OCSF (``-M json-ocsf``,
        Prowler 4 and later) JSON / JSONL file, or a directory that is
        searched recursively for ``*.json`` files (Prowler's ``-o`` output
        directory works as-is). Returns a :class:`~cloudg.normaliser.FindingList`
        of the failing checks whose ``passed_checks`` names the checks that
        passed.
        """
        import os

        scanner = cls()
        if os.path.isdir(path):
            files = glob.glob(f"{path}/**/*.json", recursive=True)
        else:
            files = [path]
        return scanner._parse_files(files)

    def _parse_output(self) -> list[Finding]:
        """Parse Prowler ASFF / OCSF JSON output files."""
        output_files = glob.glob(f"{self._output_dir}/**/*.json", recursive=True)
        return self._parse_files(output_files)

    def _parse_files(self, output_files: list[str]) -> list[Finding]:
        """Parse a list of Prowler ASFF or OCSF JSON/JSONL files.

        Each record is read as OCSF when it has OCSF keys, else as ASFF.
        Passing checks give no finding; their names are collected in
        :attr:`passed_checks` and on the returned list.
        """
        findings = FindingList()

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

                    for item in self._records(data):
                        finding = self._parse_record(item, findings.passed_checks)
                        if finding:
                            findings.append(finding)

            except (json.JSONDecodeError, OSError) as exc:
                logger.warning("Failed to parse Prowler output %s: %s", file_path, exc)

        self.passed_checks = frozenset(findings.passed_checks)
        logger.info(
            "Parsed %d findings from Prowler (%d passed checks)",
            len(findings),
            len(findings.passed_checks),
        )
        return findings

    @staticmethod
    def _records(data: Any) -> list[Any]:
        """The finding records of one parsed file: a list of records, or an
        ASFF ``{"Findings": [...]}`` batch."""
        items = data if isinstance(data, list) else [data]
        records: list[Any] = []
        for item in items:
            if isinstance(item, dict) and isinstance(item.get("Findings"), list):
                records.extend(item["Findings"])
            else:
                records.append(item)
        return records

    def _parse_record(self, item: Any, passed: set[str]) -> Finding | None:
        """One ASFF or OCSF record to a Finding; a passing check is added to
        ``passed`` instead."""
        if not isinstance(item, dict):
            return None
        if is_ocsf_record(item):
            if ocsf_status(item) == "PASS":
                check = ocsf_check_id(item)
                if check:
                    passed.add(check)
                return None
            try:
                return parse_ocsf_record(item, _SEVERITY_MAP, _COMPLIANCE_MAP)
            except Exception as exc:
                logger.debug("Failed to parse OCSF finding: %s", exc)
                return None
        if str(_get(item, "Compliance", "Status")).upper() == "PASSED":
            check = prowler_check_id(item.get("GeneratorId")) or prowler_check_id(item.get("Id"))
            if check:
                passed.add(check)
            return None
        return self._parse_asff_finding(item)

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

            # Extract status; skip PASS findings
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
                remediation=(asff.get("Remediation", {}).get("Recommendation", {}).get("Text", "")),
                source_tool="prowler",
                source_finding_id=asff.get("Id", ""),
                compliance_frameworks=list(set(compliance)),
            )
        except Exception as exc:
            logger.debug("Failed to parse ASFF finding: %s", exc)
            return None
