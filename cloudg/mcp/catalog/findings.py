"""Findings tools: browse, summarise, prioritise, suppress and ingest
security findings.

Findings come from scanners (Prowler, ScoutSuite, Checkov, Trivy, the IAM
linter), from cloudg's own graph reachability analysis, or from a loaded
findings.json. Each finding is matched to an asset by id / ARN / name.
"""

from __future__ import annotations

from typing import Annotated, Any, Literal

from pydantic import BaseModel, Field

from cloudg.mcp.catalog._common import (
    DEFAULT_LIMIT,
    FINDING_FIELDS,
    Catalog,
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
    project,
    schema,
    ws_dataset,
)
from cloudg.mcp.catalog._findings import (
    FindingFilter,
    check_report_tools,
    filter_findings,
    merge_compliance,
    parse_reports,
    renormalise,
    risk_ranking,
    sort_findings,
    summarise_findings,
)
from cloudg.mcp.core import Capability, Registry, Sensitivity
from cloudg.mcp.state import SEVERITY_RANK, Dataset

__all__ = [
    "CATALOG",
    "FindingFilter",
    "filter_findings",
    "merge_compliance",
    "register",
    "renormalise",
    "risk_ranking",
]

CATEGORY = "findings"
R, W, FS = Capability.READ_STATE, Capability.WRITE_STATE, Capability.READ_FS

FindingSort = Literal["risk", "severity", "detected_at", "title", "source_tool"]
FindingGroup = Literal["severity", "source_tool", "framework", "asset_type", "account", "asset"]


SeveritiesArg = Annotated[
    list[str] | None, Field(description="Any of CRITICAL, HIGH, MEDIUM, LOW, INFO.")
]
MinSeverityArg = Annotated[str, Field(description="At or above this severity.")]
SourceToolArg = Annotated[
    str,
    Field(description="Substring of the producing tool, e.g. 'prowler', 'cloudg-reachability'."),
]
FrameworkArg = Annotated[
    str, Field(description="Substring of a compliance framework, e.g. 'CIS', 'PCI'.")
]
ResourceArg = Annotated[str, Field(description="Only findings on this asset (ref).")]
QueryArg = Annotated[str, Field(description="Substring of title or description.")]
FieldsArg = Annotated[
    list[str] | None,
    Field(description=f"Project items to these fields. Valid: {', '.join(FINDING_FIELDS)}"),
]
ReportsArg = Annotated[
    dict[str, list[str]],
    Field(
        description="Tool -> report paths (files or directories inside an allowed root), "
        "e.g. {'prowler': ['out/prowler/'], 'trivy': ['scan.json']}. Tools: prowler, "
        "scoutsuite, checkov, trivy."
    ),
]
IngestDatasetArg = Annotated[
    str,
    Field(
        description="Dataset to add the findings to; empty = active. Created if new_dataset "
        "is true."
    ),
]
NewDatasetArg = Annotated[
    bool, Field(description="Create a new findings-only dataset named `dataset` instead.")
]
NormaliseArg = Annotated[
    bool,
    Field(description="Deduplicate across scanners and map to compliance frameworks afterwards."),
]
ActivateArg = Annotated[
    bool,
    Field(description="With new_dataset: make the new dataset the active one (like load_dataset)."),
]
ReplaceArg = Annotated[
    bool, Field(description="With new_dataset: overwrite an existing dataset of that name.")
]


class ListFindingsArgs(BaseModel):
    """list_findings arguments (the MCP wire schema)."""

    severities: SeveritiesArg = None
    min_severity: MinSeverityArg = ""
    source_tool: SourceToolArg = ""
    framework: FrameworkArg = ""
    resource: ResourceArg = ""
    query: QueryArg = ""
    include_suppressed: bool = False
    sort_by: FindingSort = "risk"
    fields: FieldsArg = None
    limit: Limit = DEFAULT_LIMIT
    cursor: Cursor = ""
    dataset: DatasetArg = ""


CATALOG = Catalog()

_RO = dict(read_only=True, idempotent=True, open_world=False, category=CATEGORY)


@CATALOG.tool(
    title="List findings",
    sensitivity=Sensitivity.CONFIDENTIAL,
    output_schema=schema(FindingPageOut),
    tags={"start-here"},
    **_RO,
)
def list_findings(ctx: Any, args: ListFindingsArgs) -> dict:
    """Search findings by severity, tool, compliance framework, asset or
    text, sorted by risk (default), severity, date, title or tool, with
    cursor pagination. Suppressed findings are hidden unless
    include_suppressed=true. Use get_finding for evidence and
    remediation."""
    ds = ws_dataset(ctx, args.dataset)
    proj = check_fields(args.fields, FINDING_FIELDS)
    flt = FindingFilter.from_args(dict(args))
    items = sort_findings(filter_findings(ds, flt), args.sort_by)
    fp = fingerprint(ds, f=flt.key(), o=args.sort_by)
    page, env = paginate(items, args.limit, args.cursor, fp)
    sev: dict[str, int] = {}
    for f in items:
        sev[f.severity.value] = sev.get(f.severity.value, 0) + 1
    items_out = [project(finding_brief(ds, f), proj) for f in page]
    return {"dataset": ds.name, **env, "severity_breakdown": sev, "items": items_out}


@CATALOG.tool(title="Get finding", sensitivity=Sensitivity.CONFIDENTIAL, **_RO)
def get_finding(
    ctx: Any,
    finding_id: Annotated[
        str, Field(min_length=1, description="Finding id (or the scanner's source_finding_id).")
    ],
    dataset: DatasetArg = "",
) -> dict:
    """One finding in full: description, evidence, remediation, CVSS,
    compliance frameworks and the controls it fails, the affected asset
    and whether it is suppressed (and why)."""
    ds = ws_dataset(ctx, dataset)
    f = ds.get_finding(finding_id)
    out = {
        **finding_brief(ds, f),
        "description": f.description,
        "evidence": f.evidence,
        "remediation": f.remediation,
        "source_finding_id": f.source_finding_id,
    }
    out["controls"] = [
        {
            "framework": c.framework,
            "control_id": c.control_id,
            "control_title": c.control_title,
            "status": c.status.value,
        }
        for c in ds.compliance
        if f.id in c.finding_ids
    ]
    if f.is_suppressed:
        out["suppression_reason"] = ds.suppression_reasons.get(f.id, "")
    aid = ds.finding_asset_id(f)
    if aid:
        out["asset"] = asset_brief(ds, ds.by_id[aid])
        ctx.link(asset_uri(aid), out["asset"]["name"], title="Affected asset")
    ctx.link(finding_uri(f.id), f.title)
    return out


@CATALOG.tool(title="Findings summary", sensitivity=Sensitivity.INTERNAL, **_RO)
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
    groups = summarise_findings(ds, group_by, include_suppressed)
    ordered = sorted(
        groups.items(),
        key=lambda kv: (
            -SEVERITY_RANK.get(kv[0], -1) if group_by == "severity" else -kv[1]["total"],
            kv[0],
        ),
    )
    return {
        "dataset": ds.name,
        "group_by": group_by,
        "total": sum(1 for f in ds.findings if include_suppressed or not f.is_suppressed),
        "suppressed": sum(1 for f in ds.findings if f.is_suppressed),
        "groups": dict(ordered[:top]),
        "truncated": len(groups) > top,
    }


@CATALOG.tool(
    title="Findings for asset",
    sensitivity=Sensitivity.CONFIDENTIAL,
    output_schema=schema(FindingPageOut),
    **_RO,
)
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
    fs = sort_findings(
        [
            f
            for f in ds.findings_by_asset.get(a.id, [])
            if include_suppressed or not f.is_suppressed
        ],
        "risk",
    )
    page, env = bounded(fs, limit)
    return {
        "dataset": ds.name,
        "asset": asset_brief(ds, a),
        **env,
        "items": [finding_brief(ds, f) for f in page],
    }


@CATALOG.tool(
    title="Top risks",
    sensitivity=Sensitivity.CONFIDENTIAL,
    output_schema=schema(TopRisksOut),
    **_RO,
)
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
    return {
        "dataset": ds.name,
        "items": rows[:top],
        "total_candidates": len(rows),
        "formula": "max_risk * exposure * blast * volume",
    }


@CATALOG.tool(
    title="Suppress findings",
    category=CATEGORY,
    sensitivity=Sensitivity.CONFIDENTIAL,
    capabilities={R, W},
    read_only=False,
    destructive=False,
    idempotent=True,
    open_world=False,
)
def suppress_findings(
    ctx: Any,
    finding_ids: Annotated[list[str], Field(min_length=1, max_length=500)],
    reason: Annotated[
        str,
        Field(min_length=3, max_length=500, description="Why (accepted risk, false positive...)."),
    ],
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
    return {
        "dataset": ds.name,
        "suppressed": res["changed"],
        "already_suppressed": res["unchanged"],
        "not_found": res["not_found"],
    }


@CATALOG.tool(
    title="Unsuppress findings",
    category=CATEGORY,
    sensitivity=Sensitivity.CONFIDENTIAL,
    capabilities={R, W},
    read_only=False,
    destructive=False,
    idempotent=True,
    open_world=False,
)
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
    return {
        "dataset": ds.name,
        "unsuppressed": res["changed"],
        "not_suppressed": res["unchanged"],
        "not_found": res["not_found"],
    }


@CATALOG.tool(
    title="Ingest scanner reports",
    category=CATEGORY,
    sensitivity=Sensitivity.CONFIDENTIAL,
    capabilities={R, W, FS},
    read_only=False,
    destructive=False,
    idempotent=False,
    open_world=False,
)
def ingest_reports(
    ctx: Any,
    reports: ReportsArg,
    dataset: IngestDatasetArg = "",
    new_dataset: NewDatasetArg = False,
    normalise: NormaliseArg = True,
    activate: ActivateArg = True,
    replace: ReplaceArg = False,
) -> dict:
    """Parse existing Prowler (ASFF) / ScoutSuite / Checkov / Trivy output
    (no scanner is run, no cloud access) and add the findings to a
    dataset, matching them to its assets by ARN / id. With
    new_dataset=true the findings go into a new dataset, which becomes
    the active one unless activate=false; the result's `active` field
    says which dataset is active afterwards. Tip: snapshot_dataset first
    to diff before / after."""
    ws = ctx.workspace
    check_report_tools(reports)
    # Validate the destination before parsing anything
    if new_dataset:
        target: Any = ws.check_name(dataset or ws.unique_name("ingested"), replace=replace)
    else:
        target = ws_dataset(ctx, dataset)
    per_path, errors, new = parse_reports(ws, reports)
    if new_dataset:
        target = ws.add(
            Dataset(name=target, source="ingest", kind="report"), activate=activate, replace=replace
        )
    before = len(target.findings)
    _store_findings(ws, target, new, normalise)
    return {
        "dataset": target.name,
        "parsed": len(new),
        "per_path": per_path,
        "errors": errors,
        "findings_before": before,
        "findings_after": len(target.findings),
        "matched_to_assets": sum(1 for f in new if target.finding_asset_id(f)),
        "normalised": normalise,
        "active": ws.active_name,
    }


def _store_findings(ws: Any, ds: Dataset, new: list, normalise: bool) -> None:
    if normalise:
        renormalise(ws, ds, new)
    else:
        ds.add_findings(new)
    ws.mutated(ds)


@CATALOG.tool(
    title="Normalise findings",
    category=CATEGORY,
    sensitivity=Sensitivity.INTERNAL,
    capabilities={R, W},
    read_only=False,
    destructive=False,
    idempotent=True,
    open_world=False,
)
def normalise_findings(ctx: Any, dataset: DatasetArg = "") -> dict:
    """Re-run cloudg's normaliser on a dataset's findings: deduplicate
    within and across scanners (check-equivalence rules), score, and
    rebuild the compliance-control mapping."""
    ds = ws_dataset(ctx, dataset)
    before, before_c = len(ds.findings), len(ds.compliance)
    renormalise(ctx.workspace, ds)
    ctx.workspace.mutated(ds)
    return {
        "dataset": ds.name,
        "findings_before": before,
        "findings_after": len(ds.findings),
        "compliance_results_before": before_c,
        "compliance_results_after": len(ds.compliance),
        "frameworks": sorted({c.framework for c in ds.compliance}),
    }


@CATALOG.tool(
    title="Reachability findings",
    category=CATEGORY,
    sensitivity=Sensitivity.CONFIDENTIAL,
    capabilities={R, W},
    read_only=False,
    destructive=False,
    idempotent=False,
    open_world=False,
)
def reachability_findings(
    ctx: Any,
    add_to_dataset: Annotated[
        bool, Field(description="Append them to the dataset's findings (otherwise preview only).")
    ] = False,
    limit: Limit = DEFAULT_LIMIT,
    dataset: DatasetArg = "",
) -> dict:
    """Run cloudg's graph reachability analysis: internet-exposed data
    stores (CRITICAL), unexpected internet exposure (HIGH) and sensitive
    ports open to 0.0.0.0/0 (CRITICAL). Preview, or add them to the
    dataset (skipping ones already present). Ids come from the analyser and
    are stable across scans (derived from the rule and the asset's ARN or
    id), so a previewed id is the id that gets added."""
    from cloudg.graph.reachability import ReachabilityAnalyzer

    ds = ws_dataset(ctx, dataset)
    found = ReachabilityAnalyzer(ds.graph.copy()).generate_findings()
    have_ids = {f.id for f in ds.findings}
    have_keys = {(f.source_tool, f.title, f.resource_id) for f in ds.findings}
    fresh = [
        f
        for f in found
        if f.id not in have_ids and (f.source_tool, f.title, f.resource_id) not in have_keys
    ]
    added = 0
    if add_to_dataset and fresh:
        added = ds.add_findings(fresh)
        ctx.workspace.mutated(ds)
    page, env = bounded(fresh, limit)
    return {
        "dataset": ds.name,
        "generated": len(found),
        "new": len(fresh),
        "added": added,
        **env,
        "items": [finding_brief(ds, f) for f in page],
    }


def register(reg: Registry) -> None:
    """Add this module's tools to ``reg``."""
    CATALOG.register(reg)
