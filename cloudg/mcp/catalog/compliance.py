"""Compliance tools: framework catalog, per-framework posture, controls,
one control's status, and the assets behind compliance gaps.

Two sources are combined. The rulesets shipped with cloudg in ``cloudg/rules``
(CIS, NIST 800-53, PCI DSS, ISO 27001, SOC 2, HIPAA, GDPR, MITRE
ATT&CK...) describe the controls; the dataset's ``ComplianceResult`` list
and each finding's ``compliance_frameworks`` say which controls fail and
on what.
"""

from __future__ import annotations

import functools
import logging
from pathlib import Path
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
    finding_brief,
    fingerprint,
    max_severity,
    paginate,
    parse_severity,
    schema,
    ws_dataset,
)
from cloudg.mcp.core import Registry, Sensitivity
from cloudg.mcp.state import SEVERITY_RANK, Dataset, ReferenceNotFoundError

CATEGORY = "compliance"
logger = logging.getLogger("cloudg.mcp")

ControlStatus = Literal["", "PASS", "FAIL", "NOT_APPLICABLE", "MANUAL"]


@functools.lru_cache(maxsize=4)
def ruleset_catalog(rules_dir: str) -> dict[str, dict[str, Any]]:
    """framework -> {versions, providers, files, controls: {id: title}}."""
    try:
        import yaml
    except ImportError:  # pragma: no cover (pyyaml is a core dependency)
        return {}
    loader = getattr(yaml, "CSafeLoader", yaml.SafeLoader)
    out: dict[str, dict[str, Any]] = {}
    for path in sorted(Path(rules_dir).rglob("*.yaml")):
        if path.name == "check_equivalence.yaml":
            continue
        try:
            data = yaml.load(path.read_text(), Loader=loader) or {}
        except Exception as exc:
            logger.debug("Skipping ruleset %s: %s", path, exc)
            continue
        fw = str(data.get("framework") or path.stem)
        entry = out.setdefault(fw, {"framework": fw, "versions": set(), "providers": set(),
                                    "sources": set(), "files": [], "controls": {}})
        if data.get("version"):
            entry["versions"].add(str(data["version"]))
        if data.get("provider"):
            entry["providers"].add(str(data["provider"]))
        if data.get("source"):
            entry["sources"].add(str(data["source"]).split(",")[0])
        entry["files"].append(path.name)
        for c in data.get("controls", []) or []:
            cid = str(c.get("id", ""))
            if cid:
                entry["controls"].setdefault(cid, {"title": c.get("title"),
                                                   "severity": c.get("severity"),
                                                   "checks": len(c.get("checks", []) or [])})
    return out


def _rules_dir(ctx: Any) -> str:
    rd = getattr(getattr(ctx.config, "rulesets", None), "rules_dir", None)
    if rd:
        return str(rd)
    from cloudg.config import _default_rules_dir

    return _default_rules_dir()


def _fw_match(name: str, wanted: str) -> bool:
    return not wanted or wanted.lower() == name.lower() or wanted.lower() in name.lower()


def framework_rollup(ds: Dataset, framework: str = "") -> list[dict[str, Any]]:
    """Per-framework posture from compliance results + finding tags."""
    fws: dict[str, dict[str, Any]] = {}

    def entry(fw: str) -> dict[str, Any]:
        return fws.setdefault(fw, {"framework": fw, "controls_total": 0, "controls_failing": 0,
                                   "controls_passing": 0, "controls_other": 0,
                                   "findings": set(), "assets": set(), "severity": {}})

    for c in ds.compliance:
        if not _fw_match(c.framework, framework):
            continue
        e = entry(c.framework)
        e["controls_total"] += 1
        key = {"FAIL": "controls_failing", "PASS": "controls_passing"}.get(
            c.status.value, "controls_other")
        e[key] += 1
        e["findings"].update(c.finding_ids)
    for f in ds.findings:
        if f.is_suppressed:
            continue
        for fw in f.compliance_frameworks:
            if _fw_match(fw, framework):
                entry(fw)["findings"].add(f.id)
    for e in fws.values():
        for fid in list(e["findings"]):
            f = ds.findings_by_id.get(fid)
            if f is None or f.is_suppressed:
                e["findings"].discard(fid)
                continue
            e["severity"][f.severity.value] = e["severity"].get(f.severity.value, 0) + 1
            aid = ds.finding_asset_id(f)
            if aid:
                e["assets"].add(aid)
    out = []
    for e in sorted(fws.values(), key=lambda x: -len(x["findings"])):
        total = e["controls_total"]
        out.append({
            "framework": e["framework"],
            "controls_evaluated": total,
            "controls_failing": e["controls_failing"],
            "controls_passing": e["controls_passing"],
            "controls_other": e["controls_other"],
            "pass_rate": round(e["controls_passing"] / total * 100, 1) if total else None,
            "open_findings": len(e["findings"]),
            "severity_breakdown": dict(sorted(e["severity"].items(),
                                              key=lambda kv: -SEVERITY_RANK[kv[0]])),
            "affected_assets": len(e["assets"]),
            "uri": f"cloudg://compliance/{e['framework']}",
        })
    return out

CATALOG = Catalog()

_RO = dict(read_only=True, idempotent=True, open_world=False, category=CATEGORY)

@CATALOG.tool(title="List compliance frameworks", sensitivity=Sensitivity.PUBLIC,
          capabilities=(), **_RO)
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
        if provider and provider.lower() not in {p.lower() for p in e["providers"]} and \
                e["providers"]:
            continue
        items.append({"framework": fw, "versions": sorted(e["versions"]),
                      "providers": sorted(e["providers"]), "controls": len(e["controls"]),
                      "files": e["files"]})
    return {"total": len(items), "items": items}

@CATALOG.tool(title="Compliance summary", sensitivity=Sensitivity.INTERNAL,
          output_schema=schema(ComplianceSummaryOut), **_RO)
def compliance_summary(
    ctx: Any,
    framework: Annotated[str, Field(description="Framework name or substring "
                                    "(e.g. 'CIS', 'PCI'); empty = all.")] = "",
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
    framework: Annotated[str, Field(min_length=1, description="Framework name or "
                                    "substring.")],
    status: ControlStatus = "",
    source: Annotated[Literal["dataset", "ruleset"], Field(
        description="dataset = controls evaluated for this dataset; ruleset = every "
        "control the framework defines.")] = "dataset",
    limit: Limit = DEFAULT_LIMIT,
    cursor: Cursor = "",
    dataset: DatasetArg = "",
) -> dict:
    """Controls of a framework: either the ones evaluated against the
    dataset (with status and finding counts) or the full ruleset
    definition (ids, titles, mapped scanner checks)."""
    if source == "ruleset":
        cat = ruleset_catalog(_rules_dir(ctx))
        matches = [fw for fw in cat if _fw_match(fw, framework)]
        if not matches:
            raise ReferenceNotFoundError(
                f"No ruleset framework matches {framework!r}. Known: {', '.join(sorted(cat))}")
        rows = [{"framework": fw, "control_id": cid, **meta}
                for fw in matches for cid, meta in cat[fw]["controls"].items()]
        page, env = paginate(rows, limit, cursor, fingerprint(None, f=framework, s="rs"))
        return {"source": "ruleset", "frameworks": matches, **env, "items": page}
    ds = ws_dataset(ctx, dataset)
    rows = []
    for c in ds.compliance:
        if not _fw_match(c.framework, framework) or (status and c.status.value != status):
            continue
        open_ids = [i for i in c.finding_ids
                    if i in ds.findings_by_id and not ds.findings_by_id[i].is_suppressed]
        rows.append({"framework": c.framework, "control_id": c.control_id,
                     "control_title": c.control_title, "status": c.status.value,
                     "findings": len(c.finding_ids), "open_findings": len(open_ids),
                     "max_severity": max_severity(ds.findings_by_id[i] for i in open_ids)})
    rows.sort(key=lambda r: (-SEVERITY_RANK.get(r["max_severity"] or "", -1),
                             -r["open_findings"], r["control_id"]))
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
    results = [c for c in ds.compliance if _fw_match(c.framework, framework)
               and (c.control_id == control_id or c.control_id.endswith(control_id))]
    cat = ruleset_catalog(_rules_dir(ctx))
    definition = None
    for fw, e in cat.items():
        if _fw_match(fw, framework) and control_id in e["controls"]:
            definition = {"framework": fw, "control_id": control_id,
                          **e["controls"][control_id]}
            break
    if not results and definition is None:
        known = sorted({c.control_id for c in ds.compliance if _fw_match(c.framework,
                                                                          framework)})[:10]
        raise ReferenceNotFoundError(
            f"No control {control_id!r} for framework {framework!r}. "
            + (f"Controls in this dataset: {', '.join(known)}" if known else
               "Use list_controls(framework=..., source='ruleset') to browse.")
        )
    fids = list(dict.fromkeys(i for c in results for i in c.finding_ids))
    fs = [ds.findings_by_id[i] for i in fids if i in ds.findings_by_id]
    open_f = [f for f in fs if not f.is_suppressed]
    assets = {ds.finding_asset_id(f) for f in open_f} - {None}
    page, env = bounded(open_f, limit)
    status = "NOT_EVALUATED"
    if results:
        status = "FAIL" if any(c.status.value == "FAIL" for c in results) and open_f else \
            results[0].status.value
        if status == "FAIL" and not open_f:
            status = "PASS (all findings suppressed)"
    return {
        "dataset": ds.name,
        "framework": framework,
        "control_id": control_id,
        "definition": definition,
        "status": status,
        "results": [{"framework": c.framework, "control_id": c.control_id,
                     "control_title": c.control_title, "status": c.status.value}
                    for c in results],
        "open_findings": env["total"],
        "findings": [finding_brief(ds, f) for f in page],
        "affected_assets": [asset_brief(ds, ds.by_id[a]) for a in sorted(assets)][:limit],
        "truncated": env["truncated"],
    }

@CATALOG.tool(title="Compliance gaps", sensitivity=Sensitivity.CONFIDENTIAL, **_RO)
def compliance_gaps(
    ctx: Any,
    framework: Annotated[str, Field(description="Framework name or substring; empty = "
                                    "all.")] = "",
    min_severity: str = "",
    limit: Limit = DEFAULT_LIMIT,
    cursor: Cursor = "",
    dataset: DatasetArg = "",
) -> dict:
    """Assets that fail compliance, worst first: per asset the frameworks
    and controls it fails, open findings, max severity and exposure."""
    ds = ws_dataset(ctx, dataset)
    min_rank = SEVERITY_RANK[parse_severity(min_severity).value] if min_severity else -1
    ctrl_by_finding: dict[str, list[str]] = {}
    for c in ds.compliance:
        if c.status.value == "FAIL" and _fw_match(c.framework, framework):
            for fid in c.finding_ids:
                ctrl_by_finding.setdefault(fid, []).append(f"{c.framework}:{c.control_id}")
    per_asset: dict[str, dict[str, Any]] = {}
    for f in ds.findings:
        if f.is_suppressed or SEVERITY_RANK[f.severity.value] < min_rank:
            continue
        fws = [fw for fw in f.compliance_frameworks if _fw_match(fw, framework)]
        ctrls = ctrl_by_finding.get(f.id, [])
        if not fws and not ctrls:
            continue
        aid = ds.finding_asset_id(f) or f"unmapped:{f.resource_arn or f.resource_id}"
        e = per_asset.setdefault(aid, {"frameworks": set(), "controls": set(),
                                       "findings": []})
        e["frameworks"].update(fws or [c.split(":")[0] for c in ctrls])
        e["controls"].update(ctrls)
        e["findings"].append(f)
    rows = []
    for aid, e in per_asset.items():
        a = ds.by_id.get(aid)
        base = asset_brief(ds, a) if a else {"id": aid, "name": aid.split(":", 1)[1],
                                             "unmapped": True}
        rows.append({**base, "frameworks": sorted(e["frameworks"]),
                     "failing_controls": sorted(e["controls"])[:20],
                     "gap_findings": len(e["findings"]),
                     "gap_max_severity": max_severity(e["findings"])})
    rows.sort(key=lambda r: (-SEVERITY_RANK.get(r["gap_max_severity"] or "", -1),
                             not r.get("internet_exposed"), -r["gap_findings"], r["name"]))
    page, env = paginate(rows, limit, cursor,
                         fingerprint(ds, f=framework, m=min_severity))
    return {"dataset": ds.name, "framework": framework or None, **env, "items": page}


def register(reg: Registry) -> None:
    """Add this module's tools to ``reg``."""
    CATALOG.register(reg)
