"""Findings normaliser: pass-through aggregator using scanner-native compliance mappings.

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

from cloudg.schema.models import (
    ComplianceResult,
    ComplianceStatus,
    Finding,
    ScanResult,
    Severity,
)

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────────
# FALLBACK ONLY: used when scanners don't emit compliance metadata.
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


# Strips leading scanner tags such as "[Checkov/terraform]" or "[Trivy]"
# so titles from different scanners can be compared.
_TITLE_TAG_RE = re.compile(r"^\s*(\[[^\]]+\]\s*)+")
_TITLE_JUNK_RE = re.compile(r"[^a-z0-9]+")

# Prowler ASFF Ids look like
# "prowler-aws-iam_root_hardware_mfa_enabled-123456789012-eu-west-1-...";
# the check name is the third dash-separated token (check names use
# underscores, never dashes).
_PROWLER_ASFF_ID_RE = re.compile(r"^prowler-[a-z0-9]+-([a-z0-9_]+)-")


def _normalise_title(title: str) -> str:
    """Normalise a finding title for cross-scanner comparison.

    Lowercases, drops leading scanner tags, and collapses punctuation and
    whitespace, so "[Checkov/terraform] Encryption at rest enabled." and
    "Encryption At Rest Enabled" compare equal.
    """
    text = _TITLE_TAG_RE.sub("", title).lower()
    return _TITLE_JUNK_RE.sub(" ", text).strip()


def _load_check_equivalence(rules_dir: str | Path) -> dict[tuple[str, str], str]:
    """Load the cross-scanner check-equivalence map from check_equivalence.yaml.

    Returns a mapping of (scanner, check_id) -> canonical semantic ID.
    Two findings from different scanners may only be merged when both of
    their checks resolve to the same canonical ID.
    """
    path = Path(rules_dir) / "check_equivalence.yaml"
    if not path.exists():
        return {}

    try:
        import yaml
    except ImportError:
        logger.debug("PyYAML not installed, skipping check equivalence map")
        return {}

    try:
        with open(path) as f:
            data = yaml.safe_load(f) or {}
    except Exception as exc:
        logger.warning("Failed to load check equivalence map %s: %s", path, exc)
        return {}

    index: dict[tuple[str, str], str] = {}
    for entry in data.get("equivalences", []) or []:
        canonical = str(entry.get("id", "")).strip()
        if not canonical:
            continue
        for scanner, check_ids in (entry.get("checks") or {}).items():
            for check_id in check_ids or []:
                index[(str(scanner).lower(), str(check_id))] = canonical
    if index:
        logger.debug("Loaded %d check equivalences from %s", len(index), path.name)
    return index


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

    for yaml_file in sorted(rules_path.rglob("*.yaml")):
        try:
            with open(yaml_file) as f:
                data = yaml.safe_load(f) or {}

            framework = data.get("framework", yaml_file.stem)
            controls = data.get("controls", [])
            if controls:
                # Merge: several files may extend the same framework
                # (e.g. hand-written patterns + generated check mappings)
                rulesets.setdefault(framework, []).extend(controls)
                logger.debug("Loaded %d rules from %s", len(controls), yaml_file.name)

        except Exception as exc:
            logger.warning("Failed to load ruleset %s: %s", yaml_file, exc)

    return rulesets


class FindingsNormaliser:
    """Pass-through aggregator: merges findings from all scanners.

    Compliance mapping priority:
    1. Scanner-native fields (Prowler ASFF RelatedRequirements, Checkov check_id, etc.)
    2. Exact check-ID lookup against ruleset `checks` lists (generated from
       Prowler's public compliance data; see scripts/import_prowler_compliance.py)
    3. External YAML ruleset regex patterns from the rules/ directory
    4. Fallback regex patterns for untagged findings

    Deduplication (two passes):
    1. Within a scanner: keyed on (scanner, check_id, resource), so two
       different checks that share a generic title on the same resource
       never collapse into one finding.
    2. Across scanners: collapsed only when the normalised titles match
       AND the checks resolve to the same canonical semantic ID in
       rules/check_equivalence.yaml. Findings with no check ID at all
       (title-only tools) merge on exact normalised title.
    Scoring: composite of severity + CVSS
    """

    def __init__(self, rules_dir: str | Path | None = None, load_external: bool = True) -> None:
        """
        Args:
            rules_dir: Directory of YAML rulesets (default: the packaged ones).
            load_external: False skips the YAML rulesets
                (``rulesets.load_external``), so compliance comes only from
                scanner-native fields and the built-in fallback patterns.
                check_equivalence.yaml is still loaded for deduplication.
        """
        if rules_dir is None:
            from cloudg.config import _default_rules_dir

            rules_dir = _default_rules_dir()
        self._findings: list[Finding] = []
        self._compliance: list[ComplianceResult] = []
        self._external_rules = _load_external_rulesets(rules_dir) if load_external else {}
        self._check_equivalence = _load_check_equivalence(rules_dir)
        # Exact-match index: scanner check ID -> [(framework, control_id, title)]
        self._check_index: dict[str, list[tuple[str, str, str]]] = {}
        for framework, controls in self._external_rules.items():
            for control in controls:
                for check in control.get("checks", []) or []:
                    self._check_index.setdefault(check, []).append(
                        (framework, str(control.get("id", "")), control.get("title", ""))
                    )
        # Per-finding exact matches recorded during scoring, keyed by finding id
        self._exact_matches: dict[str, list[tuple[str, str, str]]] = {}

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
        """Deduplicate findings in two passes.

        Pass 1, within a scanner, keyed on (scanner, check_id, resource):
        the same check re-reported for the same resource (e.g. via two
        report formats, or once per compliance framework) is a true
        duplicate. Findings without a check ID fall back to their
        normalised title as the discriminator, so two *different* checks
        that happen to share a generic title ("encryption at rest
        enabled") on the same bucket are never collapsed.

        Pass 2, across scanners: merge only when the normalised titles
        match AND both checks resolve to the same canonical semantic ID
        in the equivalence map. Findings that carry no check ID at all
        merge with each other on exact normalised title (the only signal
        those tools provide). A known check is never merged with an
        unknown or non-equivalent one: visible duplication is preferred
        over silently dropping a scanner's coverage.

        Merging keeps the highest severity and unions source tools and
        compliance frameworks.
        """
        # ── Pass 1: within-scanner ──
        by_scanner_check: dict[tuple[str, str, str], Finding] = {}
        for finding in findings:
            resource = finding.resource_arn or finding.resource_id
            check_id = self._dedupe_check_id(finding)
            discriminator = check_id if check_id else f"title:{_normalise_title(finding.title)}"
            key = (finding.source_tool, discriminator, resource)

            if key in by_scanner_check:
                by_scanner_check[key] = self._merge_pair(by_scanner_check[key], finding)
            else:
                by_scanner_check[key] = finding

        # ── Pass 2: across scanners, grouped by (resource, normalised title) ──
        groups: dict[tuple[str, str], list[Finding]] = defaultdict(list)
        for finding in by_scanner_check.values():
            resource = finding.resource_arn or finding.resource_id
            groups[(resource, _normalise_title(finding.title))].append(finding)

        result: list[Finding] = []
        for group in groups.values():
            # Each entry: (finding, canonical semantic ID or None, has_check_id)
            merged: list[tuple[Finding, str | None, bool]] = []
            for finding in group:
                check_id = self._dedupe_check_id(finding)
                canonical = self._canonical_check(finding, check_id)
                target = None
                for idx, (other, other_canonical, other_has_check) in enumerate(merged):
                    if bool(check_id) != other_has_check:
                        continue  # never merge a known check with an unknown one
                    if check_id:
                        # Both known: require matching semantics
                        if canonical is None or canonical != other_canonical:
                            continue
                    # Both unknown: exact normalised title (the group key) suffices
                    target = idx
                    break

                if target is None:
                    merged.append((finding, canonical, bool(check_id)))
                else:
                    other, other_canonical, other_has_check = merged[target]
                    merged[target] = (
                        self._merge_pair(other, finding),
                        other_canonical,
                        other_has_check,
                    )

            result.extend(entry[0] for entry in merged)

        return result

    @staticmethod
    def _dedupe_check_id(finding: Finding) -> str:
        """Extract the scanner's own check ID for dedupe keying.

        Prowler embeds the check name in its ASFF Id; Checkov, Trivy and
        ScoutSuite already report a bare check/rule ID. Returns "" when
        the finding carries no usable check ID.
        """
        src = (finding.source_finding_id or "").strip()
        if not src:
            return ""

        match = _PROWLER_ASFF_ID_RE.match(src)
        if match:
            return match.group(1)

        return src

    def _canonical_check(self, finding: Finding, check_id: str) -> str | None:
        """Resolve (scanner, check_id) to a canonical semantic ID, or None."""
        if not check_id:
            return None
        # source_tool may already be a merged list ("prowler, scoutsuite");
        # the check ID always comes from the first (primary) tool.
        scanner = finding.source_tool.split(",")[0].strip().lower()
        return self._check_equivalence.get((scanner, check_id))

    @staticmethod
    def _merge_pair(existing: Finding, incoming: Finding) -> Finding:
        """Merge two duplicate findings, keeping the highest severity.

        Returns the surviving finding with source tools and compliance
        frameworks unioned.
        """
        severity_rank = {
            Severity.CRITICAL: 0,
            Severity.HIGH: 1,
            Severity.MEDIUM: 2,
            Severity.LOW: 3,
            Severity.INFO: 4,
        }
        if severity_rank.get(incoming.severity, 5) < severity_rank.get(existing.severity, 5):
            keep, other = incoming, existing
        else:
            keep, other = existing, incoming

        merged_tools = [t.strip() for t in keep.source_tool.split(",")]
        for tool in (t.strip() for t in other.source_tool.split(",")):
            if tool not in merged_tools:
                merged_tools.append(tool)
        keep.source_tool = ", ".join(merged_tools)

        for fw in other.compliance_frameworks:
            if fw not in keep.compliance_frameworks:
                keep.compliance_frameworks.append(fw)

        return keep

    def _score_findings(self, findings: list[Finding]) -> list[Finding]:
        """Apply composite scoring to findings."""
        for finding in findings:
            # CVSS-based adjustment
            if finding.cvss_score is not None and finding.cvss_score >= 9.0:
                finding.severity = Severity.CRITICAL
            elif finding.cvss_score is not None and finding.cvss_score >= 7.0:
                if finding.severity not in (Severity.CRITICAL,):
                    finding.severity = Severity.HIGH

            # Enrich compliance frameworks:
            # 1. Scanner-native frameworks are already on the finding (primary)
            # 2. Exact check-ID lookup (high precision, always applied)
            # 3. External YAML ruleset regex patterns (secondary)
            # 4. Fallback regex (last resort)
            exact = self._match_check_ids(finding)
            if exact:
                self._exact_matches[finding.id] = exact
                for fw, _control_id, _title in exact:
                    if fw not in finding.compliance_frameworks:
                        finding.compliance_frameworks.append(fw)

            if not finding.compliance_frameworks:
                # Only apply pattern tiers if nothing else provided a mapping
                additional = self._map_from_external_rulesets(finding)
                if not additional:
                    additional = self._map_from_fallback_rules(finding)
                for fw in additional:
                    if fw not in finding.compliance_frameworks:
                        finding.compliance_frameworks.append(fw)

        return findings

    def _match_check_ids(self, finding: Finding) -> list[tuple[str, str, str]]:
        """Match a finding's scanner check ID against ruleset `checks` lists.

        Prowler ASFF finding IDs embed the check name between dashes
        (e.g. "prowler-aws-iam_root_hardware_mfa_enabled-123-eu-west-1-..."),
        and check names themselves never contain dashes, so splitting the
        source ID on separators yields the check name as one token.
        """
        if not self._check_index:
            return []

        src = finding.source_finding_id or ""
        matches: list[tuple[str, str, str]] = []
        seen: set[tuple[str, str]] = set()
        for token in re.split(r"[-/:\s]", src):
            for fw, control_id, title in self._check_index.get(token, []):
                if (fw, control_id) not in seen:
                    seen.add((fw, control_id))
                    matches.append((fw, control_id, title))
        return matches

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
        # Group findings by (framework, control_id). Exact check-ID matches
        # (from ruleset `checks` lists) give the real control ID and title;
        # everything else falls back to parsing source_finding_id.
        control_findings: dict[tuple[str, str], list[str]] = defaultdict(list)
        control_titles: dict[tuple[str, str], str] = {}

        for finding in findings:
            exact = self._exact_matches.get(finding.id, [])
            exact_frameworks = set()
            for fw, control_id, title in exact:
                control_findings[(fw, control_id)].append(finding.id)
                if title:
                    control_titles[(fw, control_id)] = title
                exact_frameworks.add(fw)

            for fw in finding.compliance_frameworks:
                if fw in exact_frameworks:
                    continue
                # Use scanner-native control ID if available in source_finding_id
                control_id = self._extract_control_id(finding, fw)
                control_findings[(fw, control_id)].append(finding.id)

        results: list[ComplianceResult] = []
        for (framework, control_id), finding_ids in control_findings.items():
            results.append(
                ComplianceResult(
                    framework=framework,
                    control_id=control_id,
                    control_title=control_titles.get(
                        (framework, control_id), f"{framework} {control_id}"
                    ),
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
