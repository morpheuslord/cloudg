"""Findings tools: browse, summarise, prioritise, suppress and ingest
security findings.

Findings come from scanners (Prowler, ScoutSuite, Checkov, Trivy, the IAM
linter), from cloudg's own graph reachability analysis, or from a loaded
findings.json. Each finding is matched to an asset by id / ARN / name.
"""

from __future__ import annotations

import math
from typing import Annotated, Any, Literal

from pydantic import Field

from cloudg.mcp.catalog._common import (
    DEFAULT_LIMIT,
    FINDING_FIELDS,
    Cursor,
    DatasetArg,
    FindingPageOut,
    Limit,
    RefArg,
    TopRisksOut,
    asset_brief,
    asset_uri,
    bounded,
    check_fields,
    finding_brief,
    finding_uri,
    fingerprint,
    paginate,
    parse_enums,
    parse_severity,
    project,
    schema,
    ws_dataset,
)
from cloudg.mcp.core import Capability, InvalidArgumentsError, Registry, Sensitivity
from cloudg.mcp.state import SEVERITY_RANK, Dataset, check_prowler_input
from cloudg.schema.models import ComplianceResult, ComplianceStatus, Finding, Severity

CATEGORY = "findings"
R, W, FS = Capability.READ_STATE, Capability.WRITE_STATE, Capability.READ_FS

FindingSort = Literal["risk", "severity", "detected_at", "title", "source_tool"]
FindingGroup = Literal["severity", "source_tool", "framework", "asset_type", "account", "asset"]


def filter_findings(
    ds: Dataset,
    *,
    severities: list[str] | None = None,
    min_severity: str = "",
    source_tool: str = "",
    framework: str = "",
    resource: str = "",
    query: str = "",
    include_suppressed: bool = False,
) -> list[Finding]:
    sevs = {s.value for s in parse_enums(severities, Severity, "severity")}
    min_rank = SEVERITY_RANK[parse_severity(min_severity).value] if min_severity else None
    asset_id = ds.resolve_asset(resource).id if resource else None
    pool = ds.findings_by_asset.get(asset_id, []) if asset_id else ds.findings
    q = query.lower().strip()
    fw = framework.lower()
    tool = source_tool.lower()
    out = []
    for f in pool:
        if f.is_suppressed and not include_suppressed:
            continue
        if sevs and f.severity.value not in sevs:
            continue
        if min_rank is not None and SEVERITY_RANK[f.severity.value] < min_rank:
            continue
        if tool and tool not in f.source_tool.lower():
            continue
        if fw and not any(fw in x.lower() for x in f.compliance_frameworks):
            continue
        if q and q not in f.title.lower() and q not in (f.description or "").lower():
            continue
        out.append(f)
    return out


def _sort_findings(items: list[Finding], sort_by: str) -> list[Finding]:
    if sort_by == "risk":
        return sorted(items, key=lambda f: (-f.risk_score, -SEVERITY_RANK[f.severity.value], f.id))
    if sort_by == "severity":
        return sorted(items, key=lambda f: (-SEVERITY_RANK[f.severity.value], -f.risk_score, f.id))
    if sort_by == "detected_at":
        return sorted(items, key=lambda f: (f.detected_at, f.id), reverse=True)
    if sort_by == "source_tool":
        return sorted(items, key=lambda f: (f.source_tool, -f.risk_score, f.id))
    return sorted(items, key=lambda f: (f.title.lower(), f.id))


def risk_ranking(ds: Dataset, min_severity: str = "") -> list[dict[str, Any]]:
    """Assets ranked by worst finding x exposure x blast radius x volume."""
    min_rank = SEVERITY_RANK[parse_severity(min_severity).value] if min_severity else -1
    dep = ds.dependency_graph()
    reachable = ds.internet_reachable()
    rows = []
    for aid, fs in ds.findings_by_asset.items():
        open_f = [f for f in fs if not f.is_suppressed and SEVERITY_RANK[f.severity.value]
                  >= min_rank]
        a = ds.by_id.get(aid)
        if not open_f or a is None:
            continue
        base = max(f.risk_score for f in open_f)
        exposed = a.is_internet_exposed or aid in reachable
        exposure = 1.5 if exposed else 1.0
        blast = len(dep.dependents(aid, max_depth=6))
        blast_f = 1.0 + min(1.0, math.log10(1 + blast) / 2)
        volume = 1.0 + min(0.5, 0.05 * (len(open_f) - 1))
        score = round(base * exposure * blast_f * volume, 2)
        rows.append({
            "asset": asset_brief(ds, a),
            "score": score,
            "components": {
                "max_finding_risk": base,
                "exposure_factor": exposure,
                "internet_reachable": exposed,
                "transitive_dependents": blast,
                "blast_factor": round(blast_f, 3),
                "open_findings": len(open_f),
                "volume_factor": round(volume, 3),
            },
            "top_findings": [finding_brief(ds, f) for f in
                             sorted(open_f, key=lambda f: -f.risk_score)[:3]],
        })
    rows.sort(key=lambda r: (-r["score"], r["asset"]["name"]))
    return rows


def stable_finding_id(f: Finding) -> str:
    """Deterministic id for a generated finding: hash of tool, rule and asset."""
    import hashlib

    raw = f"{f.source_tool}|{f.title}|{f.resource_id}|{f.evidence or ''}"
    return "reach-" + hashlib.sha256(raw.encode()).hexdigest()[:16]


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
            n = fresh[key]
            ids = list(dict.fromkeys([*n.finding_ids, *alive]))
            title = n.control_title
            if c.control_title and (not title or title.startswith(f"{c.framework} ")):
                title = c.control_title
            n = n.model_copy(update={"finding_ids": ids, "control_title": title})
            if ids:
                n = n.model_copy(update={"status": ComplianceStatus.FAIL})
            fresh[key] = n
            continue
        if c.finding_ids and not alive:
            continue
        out.append(c.model_copy(update={"finding_ids": alive}))
    return out + list(fresh.values())


def renormalise(ws: Any, ds: Dataset, *extra: list[Finding]) -> None:
    """Run the normaliser over the dataset's findings (plus ``extra``),
    keeping suppression flags, and store the result. Existing compliance
    results are merged with the new ones (see :func:`merge_compliance`)."""
    from cloudg.normaliser import FindingsNormaliser

    rules = getattr(getattr(ws.config, "rulesets", None), "rules_dir", None)
    suppressed = {f.id for f in ds.findings if f.is_suppressed}
    sr = FindingsNormaliser(rules_dir=rules).normalise(ds.findings, *extra, assets=ds.assets)
    for f in sr.findings:
        if f.id in suppressed:
            f.is_suppressed = True
    merged = merge_compliance(ds.compliance, sr.compliance, {f.id for f in sr.findings})
    ds.replace_findings(sr.findings, merged)


def register(reg: Registry) -> None:
    ro = dict(read_only=True, idempotent=True, open_world=False, category=CATEGORY)

    @reg.tool(title="List findings", sensitivity=Sensitivity.CONFIDENTIAL,
              output_schema=schema(FindingPageOut), tags={"start-here"}, **ro)
    def list_findings(
        ctx: Any,
        severities: Annotated[list[str] | None, Field(
            description="Any of CRITICAL, HIGH, MEDIUM, LOW, INFO.")] = None,
        min_severity: Annotated[str, Field(description="At or above this severity.")] = "",
        source_tool: Annotated[str, Field(description="Substring of the producing tool, e.g. "
                                          "'prowler', 'cloudg-reachability'.")] = "",
        framework: Annotated[str, Field(description="Substring of a compliance framework, "
                                        "e.g. 'CIS', 'PCI'.")] = "",
        resource: Annotated[str, Field(description="Only findings on this asset (ref).")] = "",
        query: Annotated[str, Field(description="Substring of title or description.")] = "",
        include_suppressed: bool = False,
        sort_by: FindingSort = "risk",
        fields: Annotated[list[str] | None, Field(
            description=f"Project items to these fields. Valid: {', '.join(FINDING_FIELDS)}")]
        = None,
        limit: Limit = DEFAULT_LIMIT,
        cursor: Cursor = "",
        dataset: DatasetArg = "",
    ) -> dict:
        """Search findings by severity, tool, compliance framework, asset or
        text, sorted by risk (default), severity, date, title or tool, with
        cursor pagination. Suppressed findings are hidden unless
        include_suppressed=true. Use get_finding for evidence and
        remediation."""
        ds = ws_dataset(ctx, dataset)
        proj = check_fields(fields, FINDING_FIELDS)
        items = _sort_findings(filter_findings(
            ds, severities=severities, min_severity=min_severity, source_tool=source_tool,
            framework=framework, resource=resource, query=query,
            include_suppressed=include_suppressed), sort_by)
        fp = fingerprint(ds, s=severities, m=min_severity, t=source_tool, f=framework,
                         r=resource, q=query, i=include_suppressed, o=sort_by)
        page, env = paginate(items, limit, cursor, fp)
        sev: dict[str, int] = {}
        for f in items:
            sev[f.severity.value] = sev.get(f.severity.value, 0) + 1
        return {"dataset": ds.name, **env, "severity_breakdown": sev,
                "items": [project(finding_brief(ds, f), proj) for f in page]}

    @reg.tool(title="Get finding", sensitivity=Sensitivity.CONFIDENTIAL, **ro)
    def get_finding(
        ctx: Any,
        finding_id: Annotated[str, Field(min_length=1, description="Finding id (or the "
                                         "scanner's source_finding_id).")],
        dataset: DatasetArg = "",
    ) -> dict:
        """One finding in full: description, evidence, remediation, CVSS,
        compliance frameworks and the controls it fails, the affected asset
        and whether it is suppressed (and why)."""
        ds = ws_dataset(ctx, dataset)
        f = ds.get_finding(finding_id)
        out = {**finding_brief(ds, f), "description": f.description, "evidence": f.evidence,
               "remediation": f.remediation, "source_finding_id": f.source_finding_id}
        out["controls"] = [
            {"framework": c.framework, "control_id": c.control_id,
             "control_title": c.control_title, "status": c.status.value}
            for c in ds.compliance if f.id in c.finding_ids
        ]
        if f.is_suppressed:
            out["suppression_reason"] = ds.suppression_reasons.get(f.id, "")
        aid = ds.finding_asset_id(f)
        if aid:
            out["asset"] = asset_brief(ds, ds.by_id[aid])
            ctx.link(asset_uri(aid), out["asset"]["name"], title="Affected asset")
        ctx.link(finding_uri(f.id), f.title)
        return out

    @reg.tool(title="Findings summary", sensitivity=Sensitivity.INTERNAL, **ro)
    def findings_summary(
        ctx: Any,
        group_by: FindingGroup = "severity",
        include_suppressed: bool = False,
        top: Annotated[int, Field(ge=1, le=200)] = 25,
        dataset: DatasetArg = "",
    ) -> dict:
        """Finding counts grouped by severity, tool, compliance framework,
        asset type, account or asset, each group with its severity
        breakdown. Findings not matched to any mapped asset are counted
        under 'unmapped'."""
        ds = ws_dataset(ctx, dataset)
        groups: dict[str, dict[str, int]] = {}

        def add(key: str, f: Finding) -> None:
            g = groups.setdefault(key, {"total": 0})
            g["total"] += 1
            g[f.severity.value] = g.get(f.severity.value, 0) + 1

        for f in ds.findings:
            if f.is_suppressed and not include_suppressed:
                continue
            aid = ds.finding_asset_id(f)
            a = ds.by_id.get(aid) if aid else None
            if group_by == "severity":
                add(f.severity.value, f)
            elif group_by == "source_tool":
                add(f.source_tool, f)
            elif group_by == "framework":
                for fw in f.compliance_frameworks or ["(none)"]:
                    add(fw, f)
            elif group_by == "asset_type":
                add(a.asset_type.value if a else "unmapped", f)
            elif group_by == "account":
                add((a.account_id or "unknown") if a else "unmapped", f)
            else:
                add(a.name if a else "unmapped", f)
        ordered = sorted(groups.items(), key=lambda kv: (
            -SEVERITY_RANK.get(kv[0], -1) if group_by == "severity" else -kv[1]["total"], kv[0]))
        return {
            "dataset": ds.name,
            "group_by": group_by,
            "total": sum(1 for f in ds.findings if include_suppressed or not f.is_suppressed),
            "suppressed": sum(1 for f in ds.findings if f.is_suppressed),
            "groups": dict(ordered[:top]),
            "truncated": len(groups) > top,
        }

    @reg.tool(title="Findings for asset", sensitivity=Sensitivity.CONFIDENTIAL,
              output_schema=schema(FindingPageOut), **ro)
    def findings_for_asset(
        ctx: Any,
        ref: RefArg,
        include_suppressed: bool = False,
        limit: Limit = DEFAULT_LIMIT,
        dataset: DatasetArg = "",
    ) -> dict:
        """All findings on one asset, highest risk first."""
        ds = ws_dataset(ctx, dataset)
        a = ds.resolve_asset(ref)
        fs = _sort_findings(
            [f for f in ds.findings_by_asset.get(a.id, [])
             if include_suppressed or not f.is_suppressed], "risk")
        page, env = bounded(fs, limit)
        return {"dataset": ds.name, "asset": asset_brief(ds, a), **env,
                "items": [finding_brief(ds, f) for f in page]}

    @reg.tool(title="Top risks", sensitivity=Sensitivity.CONFIDENTIAL,
              output_schema=schema(TopRisksOut), **ro)
    def top_risks(
        ctx: Any,
        top: Annotated[int, Field(ge=1, le=100)] = 10,
        min_severity: str = "",
        dataset: DatasetArg = "",
    ) -> dict:
        """Assets to fix first. Score = worst open finding's risk (0-10) x
        exposure (1.5 if internet-exposed or reachable from 0.0.0.0/0 in the
        graph) x blast radius (1-2, log of
        transitive dependents) x volume (up to 1.5 for many findings). Each
        item shows the score components and its top three findings."""
        ds = ws_dataset(ctx, dataset)
        rows = risk_ranking(ds, min_severity)
        return {"dataset": ds.name, "items": rows[:top], "total_candidates": len(rows),
                "formula": "max_risk * exposure * blast * volume"}

    @reg.tool(title="Suppress findings", category=CATEGORY,
              sensitivity=Sensitivity.CONFIDENTIAL, capabilities={R, W}, read_only=False,
              destructive=False, idempotent=True, open_world=False)
    def suppress_findings(
        ctx: Any,
        finding_ids: Annotated[list[str], Field(min_length=1, max_length=500)],
        reason: Annotated[str, Field(min_length=3, max_length=500,
                                     description="Why (accepted risk, false positive...).")],
        dataset: DatasetArg = "",
    ) -> dict:
        """Mark findings as suppressed (accepted risk / false positive) in
        the in-memory dataset. Suppressed findings drop out of list_findings,
        summaries, top_risks and prompts; reverse with unsuppress_findings.
        Nothing is written to disk or to the cloud."""
        ds = ws_dataset(ctx, dataset)
        res = ds.set_suppressed(finding_ids, True, reason)
        if res["changed"]:
            ctx.workspace.mutated(ds)
        return {"dataset": ds.name, "suppressed": res["changed"],
                "already_suppressed": res["unchanged"], "not_found": res["not_found"]}

    @reg.tool(title="Unsuppress findings", category=CATEGORY,
              sensitivity=Sensitivity.CONFIDENTIAL, capabilities={R, W}, read_only=False,
              destructive=False, idempotent=True, open_world=False)
    def unsuppress_findings(
        ctx: Any,
        finding_ids: Annotated[list[str], Field(min_length=1, max_length=500)],
        dataset: DatasetArg = "",
    ) -> dict:
        """Restore suppressed findings so they count again."""
        ds = ws_dataset(ctx, dataset)
        res = ds.set_suppressed(finding_ids, False)
        if res["changed"]:
            ctx.workspace.mutated(ds)
        return {"dataset": ds.name, "unsuppressed": res["changed"],
                "not_suppressed": res["unchanged"], "not_found": res["not_found"]}

    @reg.tool(title="Ingest scanner reports", category=CATEGORY,
              sensitivity=Sensitivity.CONFIDENTIAL, capabilities={R, W, FS}, read_only=False,
              destructive=False, idempotent=False, open_world=False)
    def ingest_reports(
        ctx: Any,
        reports: Annotated[dict[str, list[str]], Field(
            description="Tool -> report paths (files or directories inside an allowed root), "
            "e.g. {'prowler': ['out/prowler/'], 'trivy': ['scan.json']}. Tools: prowler, "
            "scoutsuite, checkov, trivy.")],
        dataset: Annotated[str, Field(description="Dataset to add the findings to; empty = "
                                      "active. Created if new_dataset is true.")] = "",
        new_dataset: Annotated[bool, Field(description="Create a new findings-only dataset "
                                           "named `dataset` instead.")] = False,
        normalise: Annotated[bool, Field(description="Deduplicate across scanners and map to "
                                         "compliance frameworks afterwards.")] = True,
        activate: Annotated[bool, Field(description="With new_dataset: make the new dataset "
                                        "the active one (like load_dataset).")] = True,
        replace: Annotated[bool, Field(description="With new_dataset: overwrite an existing "
                                       "dataset of that name.")] = False,
    ) -> dict:
        """Parse existing Prowler (ASFF) / ScoutSuite / Checkov / Trivy output
        (no scanner is run, no cloud access) and add the findings to a
        dataset, matching them to its assets by ARN / id. With
        new_dataset=true the findings go into a new dataset, which becomes
        the active one unless activate=false; the result's `active` field
        says which dataset is active afterwards. Tip: snapshot_dataset first
        to diff before / after."""
        from cloudg.ingest import SUPPORTED_TOOLS, parse_report
        from cloudg.mcp.state import Dataset as _Dataset

        ws = ctx.workspace
        bad = [t for t in reports if t.lower() not in SUPPORTED_TOOLS]
        if bad:
            raise InvalidArgumentsError(
                f"Unsupported tool(s) {', '.join(bad)}. Supported: {', '.join(SUPPORTED_TOOLS)}")
        if new_dataset:
            new_name = ws.check_name(dataset or ws.unique_name("ingested"), replace=replace)
        else:
            target = ws_dataset(ctx, dataset)
        per_path, errors, new = [], [], []
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
        if new_dataset:
            ds = ws.add(_Dataset(name=new_name, source="ingest", kind="report"),
                        activate=activate, replace=replace)
        else:
            ds = target
        before = len(ds.findings)
        if normalise:
            renormalise(ws, ds, new)
        else:
            ds.add_findings(new)
        ws.mutated(ds)
        matched = sum(1 for f in new if ds.finding_asset_id(f))
        return {"dataset": ds.name, "parsed": len(new), "per_path": per_path, "errors": errors,
                "findings_before": before, "findings_after": len(ds.findings),
                "matched_to_assets": matched, "normalised": normalise,
                "active": ws.active_name}

    @reg.tool(title="Normalise findings", category=CATEGORY,
              sensitivity=Sensitivity.INTERNAL, capabilities={R, W}, read_only=False,
              destructive=False, idempotent=True, open_world=False)
    def normalise_findings(ctx: Any, dataset: DatasetArg = "") -> dict:
        """Re-run cloudg's normaliser on a dataset's findings: deduplicate
        within and across scanners (check-equivalence rules), score, and
        rebuild the compliance-control mapping."""
        ds = ws_dataset(ctx, dataset)
        before, before_c = len(ds.findings), len(ds.compliance)
        renormalise(ctx.workspace, ds)
        ctx.workspace.mutated(ds)
        return {"dataset": ds.name, "findings_before": before, "findings_after": len(ds.findings),
                "compliance_results_before": before_c,
                "compliance_results_after": len(ds.compliance),
                "frameworks": sorted({c.framework for c in ds.compliance})}

    @reg.tool(title="Reachability findings", category=CATEGORY,
              sensitivity=Sensitivity.CONFIDENTIAL, capabilities={R, W}, read_only=False,
              destructive=False, idempotent=False, open_world=False)
    def reachability_findings(
        ctx: Any,
        add_to_dataset: Annotated[bool, Field(description="Append them to the dataset's "
                                              "findings (otherwise preview only).")] = False,
        limit: Limit = DEFAULT_LIMIT,
        dataset: DatasetArg = "",
    ) -> dict:
        """Run cloudg's graph reachability analysis: internet-exposed data
        stores (CRITICAL), unexpected internet exposure (HIGH) and sensitive
        ports open to 0.0.0.0/0 (CRITICAL). Preview, or add them to the
        dataset (skipping ones already present). Ids are stable (derived from
        the rule and the asset), so a previewed id is the id that gets added."""
        from cloudg.graph.reachability import ReachabilityAnalyzer

        ds = ws_dataset(ctx, dataset)
        found = [
            f.model_copy(update={"id": stable_finding_id(f)})
            for f in ReachabilityAnalyzer(ds.graph.copy()).generate_findings()
        ]
        existing = {(f.source_tool, f.title, f.resource_id) for f in ds.findings}
        fresh = [f for f in found if (f.source_tool, f.title, f.resource_id) not in existing]
        added = 0
        if add_to_dataset and fresh:
            added = ds.add_findings(fresh)
            ctx.workspace.mutated(ds)
        page, env = bounded(fresh, limit)
        return {"dataset": ds.name, "generated": len(found), "new": len(fresh), "added": added,
                **env, "items": [finding_brief(ds, f) for f in page]}
