"""Findings normaliser — pass-through aggregator using scanner-native compliance mappings.

Primary: Extracts compliance IDs from scanner-native fields (Prowler ASFF, Checkov, etc.)
Secondary: Loads external rulesets from YAML files in rules/ directory
Fallback: Pattern-matching rules for untagged findings only
"""

from __future__ import annotations

import logging
import re
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from typing import Any

from cloudmapper.schema.models import (
    ComplianceResult,
    ComplianceStatus,
    Finding,
    ScanResult,
    Severity,
)

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────────
# FALLBACK ONLY — used when scanners don't emit compliance metadata.
# All real compliance mappings come from scanner-native outputs.
# ─────────────────────────────────────────────────────────────────
_FALLBACK_RULES: dict[str, list[dict[str, str]]] = {
    "CIS": [
        {"pattern": r"s3.*public", "control": "CIS-2.1.2"},
        {"pattern": r"root.*mfa", "control": "CIS-1.5"},
        {"pattern": r"cloudtrail", "control": "CIS-3.1"},
        {"pattern": r"flow.*log", "control": "CIS-3.9"},
        {"pattern": r"encryption", "control": "CIS-2.1"},
        {"pattern": r"access.*key.*rotat", "control": "CIS-1.4"},
    ],
    "NIST-800-53": [
        {"pattern": r"access.*control", "control": "AC-2"},
        {"pattern": r"encryption", "control": "SC-28"},
        {"pattern": r"logging", "control": "AU-2"},
        {"pattern": r"mfa", "control": "IA-2"},
        {"pattern": r"network", "control": "SC-7"},
    ],
    "PCI-DSS": [
        {"pattern": r"encryption", "control": "PCI-3.4"},
        {"pattern": r"firewall", "control": "PCI-1.1"},
        {"pattern": r"access", "control": "PCI-7.1"},
        {"pattern": r"logging", "control": "PCI-10.1"},
    ],
    "GDPR": [
        {"pattern": r"encryption", "control": "GDPR-32"},
        {"pattern": r"access.*control", "control": "GDPR-25"},
        {"pattern": r"logging", "control": "GDPR-30"},
    ],
    "SOC2": [
        {"pattern": r"access.*control", "control": "SOC2-CC6.1"},
        {"pattern": r"encryption", "control": "SOC2-CC6.7"},
        {"pattern": r"monitoring|logging", "control": "SOC2-CC7.2"},
    ],
    "HIPAA": [
        {"pattern": r"encryption", "control": "HIPAA-164.312(a)(2)(iv)"},
        {"pattern": r"access.*control", "control": "HIPAA-164.312(a)(1)"},
        {"pattern": r"audit|log", "control": "HIPAA-164.312(b)"},
    ],
}


def _load_external_rulesets(rules_dir: str | Path) -> dict[str, list[dict[str, Any]]]:
    """Load YAML rulesets from the rules directory.

    Each YAML file should have:
        framework: str
        controls:
          - id: str
            patterns: list[str]
            severity: str (optional)
    """
    rules_path = Path(rules_dir)
    rulesets: dict[str, list[dict[str, Any]]] = {}

    if not rules_path.exists():
        return rulesets

    try:
        import yaml
    except ImportError:
        logger.debug("PyYAML not installed, skipping external rulesets")
        return rulesets

    for yaml_file in rules_path.glob("*.yaml"):
        try:
            with open(yaml_file) as f:
                data = yaml.safe_load(f) or {}

            framework = data.get("framework", yaml_file.stem)
            controls = data.get("controls", [])
            if controls:
                rulesets[framework] = controls
                logger.debug("Loaded %d rules from %s", len(controls), yaml_file.name)

        except Exception as exc:
            logger.warning("Failed to load ruleset %s: %s", yaml_file, exc)

    return rulesets


class FindingsNormaliser:
    """Pass-through aggregator: merges findings from all scanners.

    Compliance mapping priority:
    1. Scanner-native fields (Prowler ASFF RelatedRequirements, Checkov check_id, etc.)
    2. External YAML rulesets from rules/ directory
    3. Fallback regex patterns for untagged findings

    Deduplication key: (resource_arn, title)
    Scoring: composite of severity + CVSS
    """

    def __init__(self, rules_dir: str | Path = "./rules") -> None:
        self._findings: list[Finding] = []
        self._compliance: list[ComplianceResult] = []
        self._external_rules = _load_external_rulesets(rules_dir)

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

        logger.info(
            "Normalising %d total findings from %d sources",
            len(all_findings),
            len(finding_lists),
        )

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
                    # Merge source info and compliance frameworks
                    merged_tool = f"{existing.source_tool}, {finding.source_tool}"
                    merged_frameworks = list(
                        set(existing.compliance_frameworks + finding.compliance_frameworks)
                    )
                    finding.source_tool = merged_tool
                    finding.compliance_frameworks = merged_frameworks
                    seen[key] = finding
                else:
                    existing.source_tool = f"{existing.source_tool}, {finding.source_tool}"
                    existing.compliance_frameworks = list(
                        set(existing.compliance_frameworks + finding.compliance_frameworks)
                    )
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

            # Enrich compliance frameworks using three-tier approach:
            # 1. Scanner-native frameworks are already on the finding (primary)
            # 2. External YAML rulesets (secondary)
            # 3. Fallback regex (last resort)
            if not finding.compliance_frameworks:
                # Only apply external+fallback if scanner didn't provide any
                additional = self._map_from_external_rulesets(finding)
                if not additional:
                    additional = self._map_from_fallback_rules(finding)
                for fw in additional:
                    if fw not in finding.compliance_frameworks:
                        finding.compliance_frameworks.append(fw)

        return findings

    def _map_from_external_rulesets(self, finding: Finding) -> list[str]:
        """Map finding to compliance frameworks using external YAML rulesets."""
        frameworks: list[str] = []
        text = f"{finding.title} {finding.description}".lower()

        for framework, controls in self._external_rules.items():
            for control in controls:
                patterns = control.get("patterns", [])
                for pattern in patterns:
                    if re.search(pattern, text, re.IGNORECASE):
                        if framework not in frameworks:
                            frameworks.append(framework)
                        break

        return frameworks

    def _map_from_fallback_rules(self, finding: Finding) -> list[str]:
        """FALLBACK: Map finding to frameworks when no scanner-native or external match."""
        frameworks: list[str] = []
        text = f"{finding.title} {finding.description}".lower()

        for framework, rules in _FALLBACK_RULES.items():
            for rule in rules:
                if re.search(rule["pattern"], text, re.IGNORECASE):
                    if framework not in frameworks:
                        frameworks.append(framework)
                    break

        return frameworks

    def _map_compliance(self, findings: list[Finding]) -> list[ComplianceResult]:
        """Generate per-control ComplianceResult entries from findings."""
        # Group findings by (framework, control_id) — using source_finding_id
        # when available, otherwise aggregate by framework
        control_findings: dict[tuple[str, str], list[str]] = defaultdict(list)

        for finding in findings:
            for fw in finding.compliance_frameworks:
                # Use scanner-native control ID if available in source_finding_id
                control_id = self._extract_control_id(finding, fw)
                control_findings[(fw, control_id)].append(finding.id)

        results: list[ComplianceResult] = []
        for (framework, control_id), finding_ids in control_findings.items():
            results.append(
                ComplianceResult(
                    framework=framework,
                    control_id=control_id,
                    control_title=f"{framework} — {control_id}",
                    status=ComplianceStatus.FAIL if finding_ids else ComplianceStatus.PASS,
                    finding_ids=finding_ids,
                )
            )

        return results

    @staticmethod
    def _extract_control_id(finding: Finding, framework: str) -> str:
        """Extract a control ID from the scanner-native finding ID.

        Prowler example source_finding_id: "prowler-aws-iam_root_hardware_mfa_enabled-..."
        Checkov example: "CKV_AWS_18"

        Falls back to framework-aggregate if no specific ID found.
        """
        src_id = finding.source_finding_id or ""

        # Prowler: extract check name from ASFF Id
        if "prowler" in finding.source_tool.lower() and "-" in src_id:
            parts = src_id.split("-")
            if len(parts) >= 4:
                return f"{framework}/{'-'.join(parts[2:4])}"

        # Checkov: check_id is typically "CKV_AWS_XX"
        if "checkov" in finding.source_tool.lower() and src_id.startswith("CKV"):
            return f"{framework}/{src_id}"

        # Trivy: CVE IDs
        if "trivy" in finding.source_tool.lower() and src_id.startswith("CVE"):
            return f"{framework}/{src_id}"

        return f"{framework}-aggregate"
