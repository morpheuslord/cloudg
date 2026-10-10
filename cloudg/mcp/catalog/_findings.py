"""Helpers behind the findings tools: filtering, sorting, grouping, risk
ranking, compliance merging and report ingestion."""

from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Any, Callable, Sequence

from cloudg.mcp.catalog._common import (
    ArgsFilter,
    asset_brief,
    finding_brief,
    parse_enums,
    parse_severity,
)
from cloudg.mcp.core import InvalidArgumentsError
from cloudg.mcp.state import SEVERITY_RANK, Dataset, check_prowler_input
from cloudg.schema.models import ComplianceResult, ComplianceStatus, Finding, Severity

FindingPredicate = Callable[[Finding], bool]


@dataclass(frozen=True)
class FindingFilter(ArgsFilter):
    """The filters list_findings accepts (empty = no filter)."""

    severities: Sequence[str] | None = None
    min_severity: str = ""
    source_tool: str = ""
    framework: str = ""
    resource: str = ""
    query: str = ""
    include_suppressed: bool = False


def _predicates(flt: FindingFilter) -> list[FindingPredicate]:
    preds: list[FindingPredicate] = []
    if not flt.include_suppressed:
        preds.append(lambda f: not f.is_suppressed)
    sevs = {s.value for s in parse_enums(flt.severities, Severity, "severity")}
    if sevs:
        preds.append(lambda f: f.severity.value in sevs)
    if flt.min_severity:
        min_rank = SEVERITY_RANK[parse_severity(flt.min_severity).value]
        preds.append(lambda f: SEVERITY_RANK[f.severity.value] >= min_rank)
    tool = flt.source_tool.lower()
    if tool:
        preds.append(lambda f: tool in f.source_tool.lower())
    fw = flt.framework.lower()
    if fw:
        preds.append(lambda f: any(fw in x.lower() for x in f.compliance_frameworks))
    q = flt.query.lower().strip()
    if q:
        preds.append(lambda f: q in f.title.lower() or q in (f.description or "").lower())
    return preds


def filter_findings(ds: Dataset, flt: FindingFilter | None = None) -> list[Finding]:
    """Findings of ``ds`` matching every filter of ``flt``."""
    flt = flt or FindingFilter()
    preds = _predicates(flt)
    asset_id = ds.resolve_asset(flt.resource).id if flt.resource else None
    pool = ds.findings_by_asset.get(asset_id, []) if asset_id else ds.findings
    return [f for f in pool if all(p(f) for p in preds)]


_SORT_KEYS: dict[str, Callable[[Finding], Any]] = {
    "risk": lambda f: (-f.risk_score, -SEVERITY_RANK[f.severity.value], f.id),
    "severity": lambda f: (-SEVERITY_RANK[f.severity.value], -f.risk_score, f.id),
    "source_tool": lambda f: (f.source_tool, -f.risk_score, f.id),
    "title": lambda f: (f.title.lower(), f.id),
}


def sort_findings(items: list[Finding], sort_by: str) -> list[Finding]:
    if sort_by == "detected_at":
        return sorted(items, key=lambda f: (f.detected_at, f.id), reverse=True)
    return sorted(items, key=_SORT_KEYS.get(sort_by, _SORT_KEYS["title"]))


def finding_group_keys(ds: Dataset, f: Finding, group_by: str) -> list[str]:
    """The findings_summary groups a finding counts towards."""
    if group_by == "severity":
        return [f.severity.value]
    if group_by == "source_tool":
        return [f.source_tool]
    if group_by == "framework":
        return list(f.compliance_frameworks or ["(none)"])
    aid = ds.finding_asset_id(f)
    a = ds.by_id.get(aid) if aid else None
    if a is None:
        return ["unmapped"]
    if group_by == "asset_type":
        return [a.asset_type.value]
    if group_by == "account":
        return [a.account_id or "unknown"]
    return [a.name]


def summarise_findings(ds: Dataset, group_by: str, include_suppressed: bool) -> dict[str, Any]:
    """Group counts with a severity breakdown per group."""
    groups: dict[str, dict[str, int]] = {}
    for f in ds.findings:
        if f.is_suppressed and not include_suppressed:
            continue
        for key in finding_group_keys(ds, f, group_by):
            g = groups.setdefault(key, {"total": 0})
            g["total"] += 1
            g[f.severity.value] = g.get(f.severity.value, 0) + 1
    return groups


def _risk_row(ds: Dataset, aid: str, open_f: list[Finding], reachable: set[str]) -> dict:
    a = ds.by_id[aid]
    base = max(f.risk_score for f in open_f)
    exposed = a.is_internet_exposed or aid in reachable
    exposure = 1.5 if exposed else 1.0
    blast = len(ds.dependency_graph().dependents(aid, max_depth=6))
    blast_f = 1.0 + min(1.0, math.log10(1 + blast) / 2)
    volume = 1.0 + min(0.5, 0.05 * (len(open_f) - 1))
    return {
        "asset": asset_brief(ds, a),
        "score": round(base * exposure * blast_f * volume, 2),
        "components": {
            "max_finding_risk": base,
            "exposure_factor": exposure,
            "internet_reachable": exposed,
            "transitive_dependents": blast,
            "blast_factor": round(blast_f, 3),
            "open_findings": len(open_f),
            "volume_factor": round(volume, 3),
        },
        "top_findings": [
            finding_brief(ds, f) for f in sorted(open_f, key=lambda f: -f.risk_score)[:3]
        ],
    }


def risk_ranking(ds: Dataset, min_severity: str = "") -> list[dict[str, Any]]:
    """Assets ranked by worst finding x exposure x blast radius x volume."""
    min_rank = SEVERITY_RANK[parse_severity(min_severity).value] if min_severity else -1
    reachable = ds.internet_reachable()
    rows = []
    for aid, fs in ds.findings_by_asset.items():
        open_f = [
            f for f in fs if not f.is_suppressed and SEVERITY_RANK[f.severity.value] >= min_rank
        ]
        if open_f and aid in ds.by_id:
            rows.append(_risk_row(ds, aid, open_f, reachable))
    rows.sort(key=lambda r: (-r["score"], r["asset"]["name"]))
    return rows


def _merge_one(n: ComplianceResult, c: ComplianceResult, alive: list[str]) -> ComplianceResult:
    ids = list(dict.fromkeys([*n.finding_ids, *alive]))
    title = n.control_title
    if c.control_title and (not title or title.startswith(f"{c.framework} ")):
        title = c.control_title
    n = n.model_copy(update={"finding_ids": ids, "control_title": title})
    if ids:
        n = n.model_copy(update={"status": ComplianceStatus.FAIL})
    return n


def merge_compliance(
    old: list[ComplianceResult], new: list[ComplianceResult], finding_ids: set[str]
) -> list[ComplianceResult]:
    """Combine loaded compliance results with a fresh normalisation.

    Controls the normaliser evaluated take its result, plus any surviving
    finding ids the loaded result already mapped to them; controls it did
    not evaluate (scanner-native mappings, PASS results, other tools) are
    kept with their finding ids filtered to findings that still exist. A
    kept result whose findings all disappeared is dropped."""
    fresh = {(c.framework, c.control_id): c for c in new}
    out: list[ComplianceResult] = []
    for c in old:
        key = (c.framework, c.control_id)
        alive = [i for i in c.finding_ids if i in finding_ids]
        if key in fresh:
            fresh[key] = _merge_one(fresh[key], c, alive)
        elif alive or not c.finding_ids:
            out.append(c.model_copy(update={"finding_ids": alive}))
    return out + list(fresh.values())


def renormalise(ws: Any, ds: Dataset, *extra: list[Finding]) -> None:
    """Run the normaliser over the dataset's findings (plus ``extra``),
    keeping suppression flags, and store the result. Existing compliance
    results are merged with the new ones (see :func:`merge_compliance`)."""
    from cloudg.normaliser import FindingsNormaliser

    rulesets = getattr(ws.config, "rulesets", None)
    rules = getattr(rulesets, "rules_dir", None)
    load_external = getattr(rulesets, "load_external", True)
    suppressed = {f.id for f in ds.findings if f.is_suppressed}
    sr = FindingsNormaliser(rules_dir=rules, load_external=load_external).normalise(
        ds.findings, *extra, assets=ds.assets
    )
    for f in sr.findings:
        if f.id in suppressed:
            f.is_suppressed = True
    merged = merge_compliance(ds.compliance, sr.compliance, {f.id for f in sr.findings})
    ds.replace_findings(sr.findings, merged)


def check_report_tools(reports: dict[str, list[str]]) -> None:
    """Refuse tools cloudg has no report parser for."""
    from cloudg.ingest import SUPPORTED_TOOLS

    bad = [t for t in reports if t.lower() not in SUPPORTED_TOOLS]
    if bad:
        raise InvalidArgumentsError(
            f"Unsupported tool(s) {', '.join(bad)}. Supported: {', '.join(SUPPORTED_TOOLS)}"
        )


def parse_reports(ws: Any, reports: dict[str, list[str]]) -> tuple[list, list, list[Finding]]:
    """Parse every (tool, path) of ``reports``: (per_path, errors, findings)."""
    from cloudg.ingest import parse_report

    check_report_tools(reports)
    per_path: list[dict[str, Any]] = []
    errors: list[dict[str, Any]] = []
    new: list[Finding] = []
    for tool, paths in reports.items():
        for p in paths:
            safe = ws.check_path(p, must_exist=False)
            try:
                if tool.lower() == "prowler" and safe.exists():
                    check_prowler_input(safe)
                fs = parse_report(tool, safe)
            except (ValueError, FileNotFoundError, InvalidArgumentsError) as exc:
                msg = exc.message if isinstance(exc, InvalidArgumentsError) else str(exc)
                errors.append({"tool": tool, "path": p, "error": msg})
                continue
            per_path.append({"tool": tool, "path": p, "findings": len(fs)})
            new.extend(fs)
    return per_path, errors, new
