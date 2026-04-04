"""Findings normaliser — merges, deduplicates, and scores findings from all sources."""

from __future__ import annotations

import logging
from collections import defaultdict
from datetime import datetime
from typing import Any

from cloudmapper.schema.models import (
    ComplianceResult,
    ComplianceStatus,
    Finding,
    ScanResult,
    Severity,
)

logger = logging.getLogger(__name__)

# Compliance framework mapping for common finding types
_FRAMEWORK_RULES: dict[str, list[dict[str, str]]] = {
    "CIS": [
        {"pattern": "s3.*public", "control": "CIS-2.1.1"},
        {"pattern": "root.*mfa", "control": "CIS-1.5"},
        {"pattern": "root.*used", "control": "CIS-1.7"},
        {"pattern": "cloudtrail", "control": "CIS-3.1"},
        {"pattern": "flow.*log", "control": "CIS-3.9"},
        {"pattern": "encryption", "control": "CIS-2.1"},
        {"pattern": "access.*key.*rotat", "control": "CIS-1.4"},
    ],
    "NIST-800-53": [
        {"pattern": "access.*control", "control": "AC-2"},
        {"pattern": "encryption", "control": "SC-28"},
        {"pattern": "logging", "control": "AU-2"},
        {"pattern": "mfa", "control": "IA-2"},
        {"pattern": "network", "control": "SC-7"},
    ],
    "PCI-DSS": [
        {"pattern": "encryption", "control": "PCI-3.4"},
        {"pattern": "firewall", "control": "PCI-1.1"},
        {"pattern": "access", "control": "PCI-7.1"},
        {"pattern": "logging", "control": "PCI-10.1"},
    ],
    "GDPR": [
        {"pattern": "encryption", "control": "GDPR-32"},
        {"pattern": "access.*control", "control": "GDPR-25"},
        {"pattern": "logging", "control": "GDPR-30"},
    ],
}


class FindingsNormaliser:
    """Merges findings from all scanners, deduplicates, scores, and maps to compliance.

    Deduplication key: (resource_arn, title)
    Scoring: composite of severity + CVSS + source tool confidence
    """

    def __init__(self) -> None:
        self._findings: list[Finding] = []
        self._compliance: list[ComplianceResult] = []

    def normalise(
        self,
        *finding_lists: list[Finding],
        assets: list | None = None,
    ) -> ScanResult:
        """Merge, deduplicate, score, and map findings to compliance.

        Args:
            finding_lists: Variable number of finding lists from different sources.
            assets: Optional asset list for the ScanResult container.

        Returns:
            ScanResult with normalised findings and compliance mappings.
        """
        # Merge all findings
        all_findings: list[Finding] = []
        for finding_list in finding_lists:
            all_findings.extend(finding_list)

        logger.info("Normalising %d total findings from %d sources", len(all_findings), len(finding_lists))

        # Deduplicate
        deduplicated = self._deduplicate(all_findings)
        logger.info("After deduplication: %d findings", len(deduplicated))

        # Score findings
        scored = self._score_findings(deduplicated)

        # Sort by severity
        severity_order = {
            Severity.CRITICAL: 0,
            Severity.HIGH: 1,
            Severity.MEDIUM: 2,
            Severity.LOW: 3,
            Severity.INFO: 4,
        }
        scored.sort(key=lambda f: severity_order.get(f.severity, 5))

        # Map to compliance frameworks
        compliance = self._map_compliance(scored)

        self._findings = scored
        self._compliance = compliance

        return ScanResult(
            assets=assets or [],
            findings=scored,
            compliance=compliance,
            completed_at=datetime.utcnow(),
        )

    def _deduplicate(self, findings: list[Finding]) -> list[Finding]:
        """Deduplicate findings by (resource_arn, title) key.

        When duplicates are found, keep the highest-severity one and
        merge source tools.
        """
        seen: dict[tuple[str, str], Finding] = {}

        for finding in findings:
            key = (finding.resource_arn or finding.resource_id, finding.title)

            if key in seen:
                existing = seen[key]
                # Keep higher severity
                severity_rank = {
                    Severity.CRITICAL: 0,
                    Severity.HIGH: 1,
                    Severity.MEDIUM: 2,
                    Severity.LOW: 3,
                    Severity.INFO: 4,
                }
                if severity_rank.get(finding.severity, 5) < severity_rank.get(
                    existing.severity, 5
                ):
                    # Merge source info
                    merged_tool = f"{existing.source_tool}, {finding.source_tool}"
                    finding.source_tool = merged_tool
                    seen[key] = finding
                else:
                    existing.source_tool = f"{existing.source_tool}, {finding.source_tool}"
            else:
                seen[key] = finding

        return list(seen.values())

    def _score_findings(self, findings: list[Finding]) -> list[Finding]:
        """Apply composite scoring to findings."""
        for finding in findings:
            # CVSS-based adjustment
            if finding.cvss_score is not None and finding.cvss_score >= 9.0:
                finding.severity = Severity.CRITICAL
            elif finding.cvss_score is not None and finding.cvss_score >= 7.0:
                if finding.severity not in (Severity.CRITICAL,):
                    finding.severity = Severity.HIGH

            # Merge compliance frameworks from any additional mappings
            additional = self._auto_map_frameworks(finding)
            for fw in additional:
                if fw not in finding.compliance_frameworks:
                    finding.compliance_frameworks.append(fw)

        return findings

    def _auto_map_frameworks(self, finding: Finding) -> list[str]:
        """Auto-map finding to compliance frameworks based on title/description keywords."""
        frameworks: list[str] = []
        text = f"{finding.title} {finding.description}".lower()

        for framework, rules in _FRAMEWORK_RULES.items():
            for rule in rules:
                import re
                if re.search(rule["pattern"], text, re.IGNORECASE):
                    if framework not in frameworks:
                        frameworks.append(framework)
                    break

        return frameworks

    def _map_compliance(self, findings: list[Finding]) -> list[ComplianceResult]:
        """Generate ComplianceResult entries from findings."""
        # Group findings by compliance framework
        framework_findings: dict[str, list[str]] = defaultdict(list)

        for finding in findings:
            for fw in finding.compliance_frameworks:
                framework_findings[fw].append(finding.id)

        results: list[ComplianceResult] = []
        for framework, finding_ids in framework_findings.items():
            results.append(
                ComplianceResult(
                    framework=framework,
                    control_id=f"{framework}-aggregate",
                    control_title=f"{framework} Findings Summary",
                    status=ComplianceStatus.FAIL if finding_ids else ComplianceStatus.PASS,
                    finding_ids=finding_ids,
                )
            )

        return results
