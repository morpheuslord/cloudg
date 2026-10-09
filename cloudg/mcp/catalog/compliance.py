"""Compliance tools: framework catalog, per-framework posture, controls,
one control's status, and the assets behind compliance gaps.

Two sources are combined. The rulesets shipped with cloudg in ``cloudg/rules``
(CIS, NIST 800-53, PCI DSS, ISO 27001, SOC 2, HIPAA, GDPR, MITRE
ATT&CK...) describe the controls; the dataset's ``ComplianceResult`` list
and each finding's ``compliance_frameworks`` say which controls fail and
on what.
"""

from __future__ import annotations

from typing import Annotated, Any, Literal

from pydantic import Field

from cloudg.mcp.catalog._common import (
    DEFAULT_LIMIT,
    Catalog,
    ComplianceSummaryOut,
    Cursor,
    DatasetArg,
    Limit,
    asset_brief,
    bounded,
    fingerprint,
    paginate,
    parse_severity,
    schema,
    ws_dataset,
)
from cloudg.mcp.catalog._compliance import (
    briefs,
    control_definition,
    control_findings,
    control_results,
    control_state,
    dataset_control_rows,
    framework_rollup,
    gap_rows,
    missing_control_error,
    ruleset_catalog,
    ruleset_control_rows,
)
from cloudg.mcp.catalog._compliance import fw_match as _fw_match
from cloudg.mcp.catalog._compliance import rules_dir as _rules_dir
from cloudg.mcp.core import Registry, Sensitivity
from cloudg.mcp.state import SEVERITY_RANK

__all__ = ["CATALOG", "_fw_match", "_rules_dir", "framework_rollup", "register", "ruleset_catalog"]

CATEGORY = "compliance"

ControlStatus = Literal["", "PASS", "FAIL", "NOT_APPLICABLE", "MANUAL"]


CATALOG = Catalog()

_RO = dict(read_only=True, idempotent=True, open_world=False, category=CATEGORY)


@CATALOG.tool(
    title="List compliance frameworks", sensitivity=Sensitivity.PUBLIC, capabilities=(), **_RO
)
def list_frameworks(
    ctx: Any,
    provider: Annotated[str, Field(description="aws, azure or gcp.")] = "",
) -> dict:
    """Compliance frameworks cloudg can map findings to (from its
    shipped rulesets): name, versions, providers and control counts.
    Needs no dataset."""
    cat = ruleset_catalog(_rules_dir(ctx))
    items = []
    for fw, e in sorted(cat.items()):
        if (
            provider
            and provider.lower() not in {p.lower() for p in e["providers"]}
            and e["providers"]
        ):
            continue
        items.append(
            {
                "framework": fw,
                "versions": sorted(e["versions"]),
                "providers": sorted(e["providers"]),
                "controls": len(e["controls"]),
                "files": e["files"],
            }
        )
    return {"total": len(items), "items": items}


@CATALOG.tool(
    title="Compliance summary",
    sensitivity=Sensitivity.INTERNAL,
    output_schema=schema(ComplianceSummaryOut),
    **_RO,
)
def compliance_summary(
    ctx: Any,
    framework: Annotated[
        str, Field(description="Framework name or substring (e.g. 'CIS', 'PCI'); empty = all.")
    ] = "",
    dataset: DatasetArg = "",
) -> dict:
    """Compliance posture per framework: controls evaluated / failing /
    passing, pass rate, open findings by severity and affected assets.
    Drill down with list_controls / control_status / compliance_gaps."""
    ds = ws_dataset(ctx, dataset)
    rows = framework_rollup(ds, framework)
    out: dict[str, Any] = {"dataset": ds.name, "frameworks": rows}
    if not rows:
        out["hint"] = (
            "No compliance data matched. Findings need compliance_frameworks (run "
            "normalise_findings after ingesting scanner reports); list_frameworks shows "
            "the framework names."
        )
    for r in rows[:5]:
        ctx.link(r["uri"], f"{r['framework']} compliance")
    return out


@CATALOG.tool(title="List controls", sensitivity=Sensitivity.INTERNAL, **_RO)
def list_controls(
    ctx: Any,
    framework: Annotated[str, Field(min_length=1, description="Framework name or substring.")],
    status: ControlStatus = "",
    source: Annotated[
        Literal["dataset", "ruleset"],
        Field(
            description="dataset = controls evaluated for this dataset; ruleset = every "
            "control the framework defines."
        ),
    ] = "dataset",
    limit: Limit = DEFAULT_LIMIT,
    cursor: Cursor = "",
    dataset: DatasetArg = "",
) -> dict:
    """Controls of a framework: either the ones evaluated against the
    dataset (with status and finding counts) or the full ruleset
    definition (ids, titles, mapped scanner checks)."""
    if source == "ruleset":
        matches, rows = ruleset_control_rows(ruleset_catalog(_rules_dir(ctx)), framework)
        page, env = paginate(rows, limit, cursor, fingerprint(None, f=framework, s="rs"))
        return {"source": "ruleset", "frameworks": matches, **env, "items": page}
    ds = ws_dataset(ctx, dataset)
    rows = dataset_control_rows(ds, framework, status)
    page, env = paginate(rows, limit, cursor, fingerprint(ds, f=framework, s=status))
    return {"dataset": ds.name, "source": "dataset", **env, "items": page}


@CATALOG.tool(title="Control status", sensitivity=Sensitivity.CONFIDENTIAL, **_RO)
def control_status(
    ctx: Any,
    framework: Annotated[str, Field(min_length=1)],
    control_id: Annotated[str, Field(min_length=1)],
    limit: Annotated[int, Field(ge=1, le=200)] = 25,
    dataset: DatasetArg = "",
) -> dict:
    """One control: its definition (from the ruleset), status in the
    dataset, the findings that fail it and the affected assets."""
    ds = ws_dataset(ctx, dataset)
    results = control_results(ds, framework, control_id)
    definition = control_definition(ruleset_catalog(_rules_dir(ctx)), framework, control_id)
    if not results and definition is None:
        raise missing_control_error(ds, framework, control_id)
    open_f = control_findings(ds, results)
    assets = {ds.finding_asset_id(f) for f in open_f} - {None}
    page, env = bounded(open_f, limit)
    return {
        "dataset": ds.name,
        "framework": framework,
        "control_id": control_id,
        "definition": definition,
        "status": control_state(results, open_f),
        "results": [
            {
                "framework": c.framework,
                "control_id": c.control_id,
                "control_title": c.control_title,
                "status": c.status.value,
            }
            for c in results
        ],
        "open_findings": env["total"],
        "findings": briefs(ds, page),
        "affected_assets": [asset_brief(ds, ds.by_id[a]) for a in sorted(assets)][:limit],
        "truncated": env["truncated"],
    }


@CATALOG.tool(title="Compliance gaps", sensitivity=Sensitivity.CONFIDENTIAL, **_RO)
def compliance_gaps(
    ctx: Any,
    framework: Annotated[str, Field(description="Framework name or substring; empty = all.")] = "",
    min_severity: str = "",
    limit: Limit = DEFAULT_LIMIT,
    cursor: Cursor = "",
    dataset: DatasetArg = "",
) -> dict:
    """Assets that fail compliance, worst first: per asset the frameworks
    and controls it fails, open findings, max severity and exposure."""
    ds = ws_dataset(ctx, dataset)
    min_rank = SEVERITY_RANK[parse_severity(min_severity).value] if min_severity else -1
    rows = gap_rows(ds, framework, min_rank)
    page, env = paginate(rows, limit, cursor, fingerprint(ds, f=framework, m=min_severity))
    return {"dataset": ds.name, "framework": framework or None, **env, "items": page}


def register(reg: Registry) -> None:
    """Add this module's tools to ``reg``."""
    CATALOG.register(reg)
