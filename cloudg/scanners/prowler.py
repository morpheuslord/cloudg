"""Prowler CSPM scanner wrapper — runs Prowler CLI and parses ASFF JSON output."""

from __future__ import annotations

import glob
import json
import logging
import shutil
import subprocess  # nosec B404 - runs the wrapped scanner CLIs with argv lists, never a shell
import tempfile
from typing import Any

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
        aws_access_key_id: str | None = None,
        aws_secret_access_key: str | None = None,
        aws_region: str | None = None,
    ) -> None:
        self._provider = provider
        self._profile = profile
        self._output_dir = output_dir or tempfile.mkdtemp(prefix="prowler_")
        self._extra_args = extra_args or []
        self._aws_access_key_id = aws_access_key_id
        self._aws_secret_access_key = aws_secret_access_key
        self._aws_region = aws_region

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
        import os
        import time
        import threading

        if not self.is_available():
            logger.warning(
                "Prowler is not installed. Install with: pip install prowler. "
                "Skipping Prowler scan."
            )
            return []

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

        cmd.extend(self._extra_args)

        logger.info("[Prowler] Starting: %s", " ".join(cmd))

        # Build environment with AWS credentials for the subprocess
        env = os.environ.copy()
        if self._aws_access_key_id:
            env["AWS_ACCESS_KEY_ID"] = self._aws_access_key_id
        if self._aws_secret_access_key:
            env["AWS_SECRET_ACCESS_KEY"] = self._aws_secret_access_key
        if self._aws_region:
            env["AWS_DEFAULT_REGION"] = self._aws_region

        start_time = time.time()

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
            def _stream_output():
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
                            logger.info(
                                "[Prowler] %d checks completed (%ds elapsed)", check_count, elapsed
                            )
                    elif "Executing" in stripped or "Service" in stripped:
                        logger.info("[Prowler] %s", stripped[:120])

            reader = threading.Thread(target=_stream_output, daemon=True)
            reader.start()

            proc.wait(timeout=3600)
            reader.join(timeout=5)

            elapsed = int(time.time() - start_time)
            if proc.returncode != 0:
                logger.warning("[Prowler] Exited with code %d after %ds", proc.returncode, elapsed)
            else:
                logger.info("[Prowler] Completed successfully in %ds", elapsed)

        except subprocess.TimeoutExpired:
            logger.error("[Prowler] Scan timed out after 3600s — killing process")
            proc.kill()
            return []
        except Exception as exc:
            logger.error("[Prowler] Failed to run: %s", exc)
            return []

        return self._parse_output()

    @classmethod
    def parse_report(cls, path: str) -> list[Finding]:
        """Parse existing Prowler ASFF JSON output without running Prowler.

        Accepts a single ASFF JSON/JSONL file or a directory that is
        searched recursively for ``*.json`` files (Prowler's ``-o`` output
        directory works as-is).
        """
        import os

        scanner = cls()
        if os.path.isdir(path):
            files = glob.glob(f"{path}/**/*.json", recursive=True)
        else:
            files = [path]
        return scanner._parse_files(files)

    def _parse_output(self) -> list[Finding]:
        """Parse Prowler ASFF JSON output files."""
        output_files = glob.glob(f"{self._output_dir}/**/*.json", recursive=True)
        return self._parse_files(output_files)

    def _parse_files(self, output_files: list[str]) -> list[Finding]:
        """Parse a list of Prowler ASFF JSON/JSONL files."""
        findings: list[Finding] = []

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
                remediation=(asff.get("Remediation", {}).get("Recommendation", {}).get("Text", "")),
                source_tool="prowler",
                source_finding_id=asff.get("Id", ""),
                compliance_frameworks=list(set(compliance)),
            )
        except Exception as exc:
            logger.debug("Failed to parse ASFF finding: %s", exc)
            return None
