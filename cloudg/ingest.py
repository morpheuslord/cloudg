"""Ingest pre-existing scanner reports without running the scanners.

Lets cloudg act purely as an aggregation and analysis layer: users run
Prowler, ScoutSuite, Checkov, or Trivy however they like (CI jobs, other
machines, scheduled scans) and feed the raw output files to cloudg for
normalisation, cross-scanner deduplication via the check-equivalence
rulesets, compliance mapping, and report generation.

Usage:
    from cloudg.ingest import ingest_reports

    findings = ingest_reports({
        "prowler": ["./prowler-output/"],
        "trivy": ["./trivy-image.json", "./trivy-fs.json"],
    })
"""

from __future__ import annotations

import logging
from pathlib import Path

from cloudg.normaliser import FindingList
from cloudg.schema.models import Finding

logger = logging.getLogger(__name__)

# Tool name -> scanner class with a parse_report(path) classmethod
SUPPORTED_TOOLS = ("prowler", "scoutsuite", "checkov", "trivy")


def parse_report(tool: str, path: str | Path) -> list[Finding]:
    """Parse one existing scanner report (file or directory) into findings.

    Args:
        tool: One of ``prowler``, ``scoutsuite``, ``checkov``, ``trivy``.
        path: The tool's native output: a report file or output directory.

    Returns:
        List of normalised Finding objects (empty when nothing parses).
        Prowler reports, ASFF or OCSF, return a
        :class:`~cloudg.normaliser.FindingList` whose ``passed_checks``
        names the checks that passed; pass the list to
        :meth:`~cloudg.normaliser.FindingsNormaliser.normalise` as is and
        the compliance controls those checks map to get PASS results.

    Raises:
        ValueError: For an unsupported tool name.
        FileNotFoundError: When the path does not exist.
    """
    tool = tool.strip().lower()
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"Report path does not exist: {path}")

    if tool == "prowler":
        from cloudg.scanners.prowler import ProwlerScanner

        return ProwlerScanner.parse_report(str(p))
    if tool == "scoutsuite":
        from cloudg.scanners.scoutsuite import ScoutSuiteScanner

        return ScoutSuiteScanner.parse_report(str(p))
    if tool == "checkov":
        from cloudg.scanners.checkov import CheckovScanner

        return CheckovScanner.parse_report(str(p))
    if tool == "trivy":
        from cloudg.scanners.trivy import TrivyScanner

        return TrivyScanner.parse_report(str(p))

    raise ValueError(f"Unsupported tool '{tool}'. Supported: {', '.join(SUPPORTED_TOOLS)}")


def ingest_reports(reports: dict[str, list[str | Path]]) -> list[Finding]:
    """Parse existing reports from several tools into one findings list.

    Args:
        reports: Mapping of tool name to report paths, e.g.
            ``{"prowler": ["./prowler-out/"], "checkov": ["results_json.json"]}``.
            Any combination and any subset of tools is fine.

    Returns:
        Combined :class:`~cloudg.normaliser.FindingList` of findings from
        every report that parsed, carrying the passed checks of every
        Prowler report. A path that fails to parse is logged and skipped
        rather than aborting the whole ingest.
    """
    all_findings = FindingList()
    for tool, paths in reports.items():
        for path in paths:
            try:
                findings = parse_report(tool, path)
            except (ValueError, FileNotFoundError) as exc:
                logger.error("Skipping %s report %s: %s", tool, path, exc)
                continue
            logger.info("[%s] %d findings ingested from %s", tool, len(findings), path)
            all_findings.extend(findings)
            all_findings.passed_checks.update(getattr(findings, "passed_checks", None) or ())
    return all_findings
