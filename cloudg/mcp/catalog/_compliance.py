"""Helpers behind the compliance tools: the shipped ruleset catalog, the
per-framework rollup, control rows, one control's status and the
per-asset gap rows."""

from __future__ import annotations

import functools
import logging
from pathlib import Path
from typing import Any

from cloudg.mcp.catalog._common import asset_brief, finding_brief, max_severity
from cloudg.mcp.state import SEVERITY_RANK, Dataset, ReferenceNotFoundError
from cloudg.schema.models import ComplianceResult, Finding

logger = logging.getLogger("cloudg.mcp")

_STATUS_KEY = {"FAIL": "controls_failing", "PASS": "controls_passing"}  # nosec B105


def _load_yaml(path: Path) -> dict[str, Any]:
    import yaml

    data = yaml.safe_load(path.read_text())
    return data if isinstance(data, dict) else {}


def _add_ruleset(out: dict[str, dict[str, Any]], path: Path, data: dict[str, Any]) -> None:
    fw = str(data.get("framework") or path.stem)
    entry = out.setdefault(
        fw,
        {
            "framework": fw,
            "versions": set(),
            "providers": set(),
            "sources": set(),
            "files": [],
            "controls": {},
        },
    )
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
            entry["controls"].setdefault(
                cid,
                {
                    "title": c.get("title"),
                    "severity": c.get("severity"),
                    "checks": len(c.get("checks", []) or []),
                },
            )


@functools.lru_cache(maxsize=4)
def ruleset_catalog(rules_dir: str) -> dict[str, dict[str, Any]]:
    """framework -> {versions, providers, files, controls: {id: title}}."""
    out: dict[str, dict[str, Any]] = {}
    for path in sorted(Path(rules_dir).rglob("*.yaml")):
        if path.name == "check_equivalence.yaml":
            continue
        try:
            data = _load_yaml(path)
        except Exception as exc:  # a broken ruleset file must not break the catalog
            logger.debug("Skipping ruleset %s: %s", path, exc)
            continue
        _add_ruleset(out, path, data)
    return out


def rules_dir(ctx: Any) -> str:
    rd = getattr(getattr(ctx.config, "rulesets", None), "rules_dir", None)
    if rd:
        return str(rd)
    from cloudg.config import _default_rules_dir

    return _default_rules_dir()


def fw_match(name: str, wanted: str) -> bool:
    return not wanted or wanted.lower() == name.lower() or wanted.lower() in name.lower()


# ---------------------------------------------------------------------------
# Framework rollup
# ---------------------------------------------------------------------------


def _rollup_entry(fws: dict[str, dict[str, Any]], fw: str) -> dict[str, Any]:
    return fws.setdefault(
        fw,
        {
            "framework": fw,
            "controls_total": 0,
            "controls_failing": 0,
            "controls_passing": 0,
            "controls_other": 0,
            "findings": set(),
            "assets": set(),
            "severity": {},
        },
    )


def _collect_rollup(ds: Dataset, framework: str) -> dict[str, dict[str, Any]]:
    fws: dict[str, dict[str, Any]] = {}
    for c in ds.compliance:
        if fw_match(c.framework, framework):
            e = _rollup_entry(fws, c.framework)
            e["controls_total"] += 1
            e[_STATUS_KEY.get(c.status.value, "controls_other")] += 1
            e["findings"].update(c.finding_ids)
    for f in ds.findings:
        if f.is_suppressed:
            continue
        for fw in f.compliance_frameworks:
            if fw_match(fw, framework):
                _rollup_entry(fws, fw)["findings"].add(f.id)
    return fws


def _settle_findings(ds: Dataset, e: dict[str, Any]) -> None:
    """Drop missing / suppressed findings and count severities and assets."""
    for fid in list(e["findings"]):
        f = ds.findings_by_id.get(fid)
        if f is None or f.is_suppressed:
            e["findings"].discard(fid)
            continue
        e["severity"][f.severity.value] = e["severity"].get(f.severity.value, 0) + 1
        aid = ds.finding_asset_id(f)
        if aid:
            e["assets"].add(aid)


def _rollup_row(e: dict[str, Any]) -> dict[str, Any]:
    total = e["controls_total"]
    return {
        "framework": e["framework"],
        "controls_evaluated": total,
        "controls_failing": e["controls_failing"],
        "controls_passing": e["controls_passing"],
        "controls_other": e["controls_other"],
        "pass_rate": round(e["controls_passing"] / total * 100, 1) if total else None,
        "open_findings": len(e["findings"]),
        "severity_breakdown": dict(
            sorted(e["severity"].items(), key=lambda kv: -SEVERITY_RANK[kv[0]])
        ),
        "affected_assets": len(e["assets"]),
        "uri": f"cloudg://compliance/{e['framework']}",
    }


def framework_rollup(ds: Dataset, framework: str = "") -> list[dict[str, Any]]:
    """Per-framework posture from compliance results + finding tags."""
    fws = _collect_rollup(ds, framework)
    for e in fws.values():
        _settle_findings(ds, e)
    return [_rollup_row(e) for e in sorted(fws.values(), key=lambda x: -len(x["findings"]))]


# ---------------------------------------------------------------------------
# Controls
# ---------------------------------------------------------------------------


def open_control_findings(ds: Dataset, c: ComplianceResult) -> list[Finding]:
    return [
        ds.findings_by_id[i]
        for i in c.finding_ids
        if i in ds.findings_by_id and not ds.findings_by_id[i].is_suppressed
    ]


def ruleset_control_rows(cat: dict[str, Any], framework: str) -> tuple[list[str], list[dict]]:
    matches = [fw for fw in cat if fw_match(fw, framework)]
    if not matches:
        raise ReferenceNotFoundError(
            "No ruleset framework matches the name. Known: " + ", ".join(sorted(cat)),
            data={"value": framework, "known": sorted(cat)},
        )
    rows = [
        {"framework": fw, "control_id": cid, **meta}
        for fw in matches
        for cid, meta in cat[fw]["controls"].items()
    ]
    return matches, rows


def dataset_control_rows(ds: Dataset, framework: str, status: str) -> list[dict[str, Any]]:
    rows = []
    for c in ds.compliance:
        if not fw_match(c.framework, framework) or (status and c.status.value != status):
            continue
        open_f = open_control_findings(ds, c)
        rows.append(
            {
                "framework": c.framework,
                "control_id": c.control_id,
                "control_title": c.control_title,
                "status": c.status.value,
                "findings": len(c.finding_ids),
                "open_findings": len(open_f),
                "max_severity": max_severity(open_f),
            }
        )
    rows.sort(
        key=lambda r: (
            -SEVERITY_RANK.get(r["max_severity"] or "", -1),
            -r["open_findings"],
            r["control_id"],
        )
    )
    return rows


def control_definition(cat: dict[str, Any], framework: str, control_id: str) -> dict | None:
    for fw, e in cat.items():
        if fw_match(fw, framework) and control_id in e["controls"]:
            return {"framework": fw, "control_id": control_id, **e["controls"][control_id]}
    return None


def control_results(ds: Dataset, framework: str, control_id: str) -> list[ComplianceResult]:
    return [
        c
        for c in ds.compliance
        if fw_match(c.framework, framework)
        and (c.control_id == control_id or c.control_id.endswith(control_id))
    ]


def missing_control_error(ds: Dataset, framework: str, control_id: str) -> Exception:
    known = sorted({c.control_id for c in ds.compliance if fw_match(c.framework, framework)})
    hint = (
        "Controls in this dataset: " + ", ".join(known[:10])
        if known
        else "Use list_controls(framework=..., source='ruleset') to browse."
    )
    return ReferenceNotFoundError(
        "No such control for that framework. " + hint,
        data={"value": control_id, "framework": framework, "known": known[:10]},
    )


def control_state(results: list[ComplianceResult], open_f: list[Finding]) -> str:
    if not results:
        return "NOT_EVALUATED"
    failing = any(c.status.value == "FAIL" for c in results)
    status = "FAIL" if failing and open_f else results[0].status.value
    if status == "FAIL" and not open_f:
        return "PASS (all findings suppressed)"
    return status


def control_findings(ds: Dataset, results: list[ComplianceResult]) -> list[Finding]:
    fids = list(dict.fromkeys(i for c in results for i in c.finding_ids))
    return [
        ds.findings_by_id[i]
        for i in fids
        if i in ds.findings_by_id and not ds.findings_by_id[i].is_suppressed
    ]


# ---------------------------------------------------------------------------
# Gaps
# ---------------------------------------------------------------------------


def _failing_controls(ds: Dataset, framework: str) -> dict[str, list[str]]:
    ctrl_by_finding: dict[str, list[str]] = {}
    for c in ds.compliance:
        if c.status.value == "FAIL" and fw_match(c.framework, framework):
            for fid in c.finding_ids:
                ctrl_by_finding.setdefault(fid, []).append(f"{c.framework}:{c.control_id}")
    return ctrl_by_finding


def _gap_groups(ds: Dataset, framework: str, min_rank: int) -> dict[str, dict[str, Any]]:
    ctrl_by_finding = _failing_controls(ds, framework)
    per_asset: dict[str, dict[str, Any]] = {}
    for f in ds.findings:
        if f.is_suppressed or SEVERITY_RANK[f.severity.value] < min_rank:
            continue
        fws = [fw for fw in f.compliance_frameworks if fw_match(fw, framework)]
        ctrls = ctrl_by_finding.get(f.id, [])
        if not fws and not ctrls:
            continue
        aid = ds.finding_asset_id(f) or f"unmapped:{f.resource_arn or f.resource_id}"
        e = per_asset.setdefault(aid, {"frameworks": set(), "controls": set(), "findings": []})
        e["frameworks"].update(fws or [c.split(":")[0] for c in ctrls])
        e["controls"].update(ctrls)
        e["findings"].append(f)
    return per_asset


def gap_rows(ds: Dataset, framework: str, min_rank: int) -> list[dict[str, Any]]:
    rows = []
    for aid, e in _gap_groups(ds, framework, min_rank).items():
        a = ds.by_id.get(aid)
        base = (
            asset_brief(ds, a) if a else {"id": aid, "name": aid.split(":", 1)[1], "unmapped": True}
        )
        rows.append(
            {
                **base,
                "frameworks": sorted(e["frameworks"]),
                "failing_controls": sorted(e["controls"])[:20],
                "gap_findings": len(e["findings"]),
                "gap_max_severity": max_severity(e["findings"]),
            }
        )
    rows.sort(
        key=lambda r: (
            -SEVERITY_RANK.get(r["gap_max_severity"] or "", -1),
            not r.get("internet_exposed"),
            -r["gap_findings"],
            r["name"],
        )
    )
    return rows


def briefs(ds: Dataset, findings: list[Finding]) -> list[dict[str, Any]]:
    return [finding_brief(ds, f) for f in findings]
