"""SARIF 2.1.0 export of a scan result, for GitHub code scanning and other
SARIF consumers.

Cloud findings point at resources, not at source files, so each result's
physical location is a stable pseudo path,
``cloud/<provider>/<account>/<region>/<resource>``, and the resource ARN or
ID is also given as a logical location. Code scanning shows such alerts
without a code snippet, and keeps one alert per resource and rule across
runs through the partial fingerprint.
"""

from __future__ import annotations

import hashlib
import json
import logging
import re
from pathlib import Path
from typing import Any
from urllib.parse import quote

from cloudg import __version__
from cloudg.normaliser import prowler_check_id
from cloudg.schema.models import CloudAsset, Finding, ScanResult, Severity

logger = logging.getLogger(__name__)

SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
INFORMATION_URI = "https://morpheuslord.github.io/cloudg/"

# GitHub code scanning reads `security-severity` (0.0 to 10.0) to rank alerts
# as critical (9.0+), high (7.0+), medium (4.0+) or low.
_SECURITY_SEVERITY = {
    Severity.CRITICAL: "9.5",
    Severity.HIGH: "8.0",
    Severity.MEDIUM: "5.5",
    Severity.LOW: "3.0",
    Severity.INFO: "0.0",
}
_LEVEL = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}


def _slug(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-") or "finding"


def rule_id(finding: Finding) -> str:
    """``<tool>/<check id>``, or ``<tool>/<slug of the title>`` without a check id.

    A Prowler finding Id names one resource, so the check name inside it is
    used instead, as the normaliser does when it deduplicates.
    """
    src = (finding.source_finding_id or "").strip()
    check = prowler_check_id(src) or src or _slug(finding.title)
    return f"{_slug(finding.source_tool)}/{check}"


def _segment(value: str | None) -> str:
    """One URI path segment; never empty, ``.`` or ``..``."""
    text = quote(value or "unknown", safe="")
    return text if text not in ("", ".", "..") else "unknown"


def _artifact_uri(finding: Finding, asset: CloudAsset | None) -> str:
    if asset is None:
        return f"cloud/unknown/{_segment(finding.resource_arn or finding.resource_id)}"
    parts = [asset.provider.value.lower(), asset.account_id, asset.region, asset.id]
    return "cloud/" + "/".join(_segment(p) for p in parts)


def _fingerprint(finding: Finding) -> str:
    key = "|".join((rule_id(finding), finding.resource_arn or finding.resource_id))
    return hashlib.sha256(key.encode()).hexdigest()


def _rule(finding: Finding) -> dict[str, Any]:
    tags = ["security", "cloud", finding.source_tool, *finding.compliance_frameworks]
    return {
        "id": rule_id(finding),
        "name": finding.title[:255],
        "shortDescription": {"text": finding.title},
        "fullDescription": {"text": finding.description or finding.title},
        "help": {"text": finding.remediation or finding.description or finding.title},
        "defaultConfiguration": {"level": _LEVEL[finding.severity]},
        "properties": {
            "tags": list(dict.fromkeys(tags)),
            "security-severity": _SECURITY_SEVERITY[finding.severity],
            "precision": "high",
        },
    }


def _result(finding: Finding, asset: CloudAsset | None) -> dict[str, Any]:
    target = finding.resource_arn or finding.resource_id
    result: dict[str, Any] = {
        "ruleId": rule_id(finding),
        "level": _LEVEL[finding.severity],
        "message": {"text": f"{finding.title} ({target})"},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": _artifact_uri(finding, asset)},
                    "region": {"startLine": 1},
                },
                "logicalLocations": [{"fullyQualifiedName": target, "kind": "resource"}],
            }
        ],
        "partialFingerprints": {"cloudgFinding/v1": _fingerprint(finding)},
        "properties": {
            "severity": finding.severity.value,
            "risk_score": finding.risk_score,
            "source_tool": finding.source_tool,
            "resource_id": finding.resource_id,
            "compliance_frameworks": finding.compliance_frameworks,
        },
    }
    if finding.is_suppressed:
        result["suppressions"] = [{"kind": "external"}]
    return result


def _rules(findings: list[Finding]) -> list[dict[str, Any]]:
    """One rule per rule ID, described by its most severe finding."""
    worst: dict[str, Finding] = {}
    order = list(_LEVEL)  # CRITICAL first
    for f in findings:
        current = worst.get(rule_id(f))
        if current is None or order.index(f.severity) < order.index(current.severity):
            worst[rule_id(f)] = f
    return [_rule(f) for f in worst.values()]


def build_sarif(scan_result: ScanResult) -> dict[str, Any]:
    """The SARIF 2.1.0 log for ``scan_result``, as a JSON-ready dict.

    Suppressed findings are kept and marked with an external suppression,
    so code scanning closes their alerts instead of losing track of them.
    """
    assets = {a.id: a for a in scan_result.assets}
    findings = scan_result.findings
    return {
        "$schema": SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "cloudg",
                        "version": __version__,
                        "semanticVersion": __version__,
                        "informationUri": INFORMATION_URI,
                        "rules": _rules(findings),
                    }
                },
                "results": [_result(f, assets.get(f.resource_id)) for f in findings],
            }
        ],
    }


def write_sarif(scan_result: ScanResult, path: str | Path) -> Path:
    """Write ``build_sarif(scan_result)`` to ``path`` (parents are created)."""
    out = Path(path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(build_sarif(scan_result), indent=2))
    logger.debug("Exported SARIF to %s", out)
    return out
