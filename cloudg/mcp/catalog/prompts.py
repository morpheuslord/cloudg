"""Prompts: packaged security-analysis jobs.

Each prompt returns a user message with the task and the exact tools to
call next, then the relevant workspace context so the model starts
informed without a dozen tool calls: embedded resources whose URI serves
exactly the embedded content (dataset summary, asset, finding, framework)
and, for computed context that has no resource (top risks, diffs), a
second text message with a JSON block. With no dataset loaded the prompt
says how to load one instead of failing.
"""

from __future__ import annotations

import json
from typing import Any, Callable
from urllib.parse import quote

from cloudg.mcp.catalog._common import asset_brief, asset_uri, finding_uri
from cloudg.mcp.catalog.resources import (
    complete_asset,
    complete_dataset,
    complete_finding,
    complete_framework,
    complete_severity,
    finding_detail,
    framework_detail,
)
from cloudg.mcp.core import (
    EmbeddedResource,
    PromptArgument,
    PromptMessage,
    PromptResult,
    PromptSpec,
    Registry,
    Sensitivity,
    TextContent,
    TextResourceContents,
)
from cloudg.mcp.state import Dataset, NoDatasetError, ReferenceNotFoundError

CATEGORY = "prompts"

NO_DATA = (
    "No cloudg dataset is loaded yet. First call `workspace_status`, then load data with "
    "`load_dataset(path=...)` (an inventory-map.json, findings.json or scanner report inside "
    "an allowed directory) or collect it with `map_inventory`. Then run this prompt again."
)


def _dataset(ctx: Any, name: str | None) -> Dataset | None:
    try:
        return ctx.workspace.get(name or None)
    except NoDatasetError:
        if name:
            raise
        return None


def _result(
    description: str,
    task: str,
    context: dict[str, Any] | None = None,
    resources: list[tuple[str, Any]] = (),  # type: ignore[assignment]
) -> PromptResult:
    msgs = [PromptMessage("user", TextContent(task))]
    if context is not None:
        msgs.append(PromptMessage("user", TextContent(
            "Context for this task (JSON):\n```json\n"
            + json.dumps(context, indent=1, default=str) + "\n```")))
    for uri, data in resources:
        msgs.append(PromptMessage("user", EmbeddedResource(TextResourceContents(
            uri, json.dumps(data, indent=2, ensure_ascii=False, default=str)))))
    return PromptResult(msgs, description)


def _summary_res(ds: Dataset) -> tuple[str, Any]:
    """``cloudg://datasets/{name}/summary`` and its exact content."""
    return f"cloudg://datasets/{ds.name}/summary", ds.summary()


def _is_active(ctx: Any, ds: Dataset) -> bool:
    """Asset / finding / compliance resources read the active dataset, so
    they are only embedded when the prompt targets it."""
    return ctx.workspace.active_name == ds.name


def _overview(ds: Dataset) -> dict[str, Any]:
    s = ds.summary()
    keep = ("dataset", "providers", "total_assets", "total_edges", "open_findings",
            "severity_breakdown", "accounts", "regions", "internet_exposed",
            "cross_account_edges", "compliance_frameworks", "assets_by_type")
    return {k: s[k] for k in keep if k in s}


def _top_risks(ds: Dataset, n: int = 5, min_severity: str = "") -> list[dict[str, Any]]:
    from cloudg.mcp.catalog.findings import risk_ranking

    return [{"asset": r["asset"]["name"], "id": r["asset"]["id"], "type": r["asset"]["type"],
             "score": r["score"], "internet_exposed": r["asset"]["internet_exposed"],
             "top_finding": r["top_findings"][0]["title"] if r["top_findings"] else None}
            for r in risk_ranking(ds, min_severity)[:n]]


def _add(reg: Registry, name: str, title: str, description: str,
         arguments: list[PromptArgument], sensitivity: Sensitivity,
         fn: Callable[..., Any]) -> None:
    reg.add(PromptSpec(name=name, handler=fn, title=title, description=description,
                       arguments=arguments, category=CATEGORY, sensitivity=sensitivity,
                       tags={"workflow"}))


def _ds_arg() -> PromptArgument:
    return PromptArgument("dataset", "Dataset name; empty = active dataset.",
                          completion=complete_dataset)


def register(reg: Registry) -> None:
    # -- posture --------------------------------------------------------

    def security_posture_review(ctx: Any, dataset: str = "") -> PromptResult:
        ds = _dataset(ctx, dataset)
        if ds is None:
            return _result("Security posture review", NO_DATA)
        from cloudg.mcp.catalog.compliance import framework_rollup

        ctx_data = {"top_risks": _top_risks(ds),
                    "compliance": framework_rollup(ds)[:5]}
        task = f"""Review the security posture of the cloud estate in dataset `{ds.name}`.
The embedded JSON has the overview, the five riskiest assets and compliance posture.

Work through, calling cloudg tools as needed:
1. `top_risks(top=10)`: the assets to fix first and why (score components).
2. `internet_exposure()` and `attack_paths()` for what an outside attacker can reach.
3. `lateral_movement_paths()` and `cross_account_edges(external_only=true)` (identity pivots).
4. `security_coverage()`: missing GuardDuty / Inspector / WAF etc.
5. `compliance_summary()` to find the weakest frameworks.

Deliver: an overall rating (critical / poor / fair / good) with justification, the top 5
risks with evidence (asset, finding, exposure, blast radius), quick wins, and structural
improvements. Cite asset names / ids exactly as tools return them."""
        return _result("Security posture review", task, ctx_data, [_summary_res(ds)])

    _add(reg, "security_posture_review", "Security posture review",
         "Whole-estate security review: risks, exposure, identity pivots, coverage gaps, "
         "compliance.", [_ds_arg()], Sensitivity.CONFIDENTIAL, security_posture_review)

    def executive_summary(ctx: Any, dataset: str = "") -> PromptResult:
        ds = _dataset(ctx, dataset)
        if ds is None:
            return _result("Executive summary", NO_DATA)
        task = f"""Write a one-page executive summary of the cloud security state of dataset
`{ds.name}` for non-technical leadership, from the embedded figures (call
`findings_summary`, `compliance_summary` and `top_risks(top=3)` for anything missing).

Structure: headline (one sentence), scale of the estate, risk level with the 3 issues that
matter most in business terms, compliance standing, and 3 recommended decisions with rough
effort. No identifiers or jargon; numbers rounded."""
        return _result("Executive summary", task, _overview(ds), [_summary_res(ds)])

    _add(reg, "executive_summary", "Executive summary",
         "Non-technical one-page summary of the estate's security state.", [_ds_arg()],
         Sensitivity.INTERNAL, executive_summary)

    def attack_surface_report(ctx: Any, dataset: str = "") -> PromptResult:
        ds = _dataset(ctx, dataset)
        if ds is None:
            return _result("Attack surface report", NO_DATA)
        exposed = [a for a in ds.assets if a.is_internet_exposed]
        by_type: dict[str, int] = {}
        for a in exposed:
            by_type[a.asset_type.value] = by_type.get(a.asset_type.value, 0) + 1
        ctx_data = {"internet_exposed_total": len(exposed), "exposed_by_type": by_type,
                    "exposed_sample": [asset_brief(ds, a) for a in exposed[:15]]}
        task = f"""Map the external attack surface of dataset `{ds.name}`.

1. `internet_exposure(limit=100)`: every exposed asset with the rules exposing it, sensitive
   ports and WAF protection.
2. `get_edges(internet_only=true, port=22)` and `port=3389` for admin ports open to the world.
3. `attack_paths(max_paths=20)`: routes from the internet to data stores, secrets, keys, roles.
4. For the worst 3 paths, `find_paths(source='internet', target=<asset>)` and
   `findings_for_asset` on each hop.

Report: entry points ranked by risk, exposed sensitive services, the critical paths with
every hop explained, and concrete fixes (close rule X, add WAF to Y, move Z private)."""
        return _result("Attack surface report", task, ctx_data, [_summary_res(ds)])

    _add(reg, "attack_surface_report", "Attack surface report",
         "External attack surface: exposed assets, open admin ports, internet-to-crown-jewel "
         "paths.", [_ds_arg()], Sensitivity.CONFIDENTIAL, attack_surface_report)

    # -- one asset ------------------------------------------------------

    def _asset_ctx(ds: Dataset, ref: str) -> dict[str, Any]:
        from cloudg.mcp.catalog.resources import asset_detail

        return asset_detail(ds, ref)

    def investigate_asset(ctx: Any, ref: str, dataset: str = "") -> PromptResult:
        ds = _dataset(ctx, dataset)
        if ds is None:
            return _result("Investigate asset", NO_DATA)
        data = _asset_ctx(ds, ref)
        task = f"""Investigate the asset `{data.get('name', ref)}` (id `{data['id']}`) in dataset
`{ds.name}`. Its current detail is embedded.

1. `get_asset(ref='{data['id']}')` and `get_asset_metadata` (specific keys) for configuration.
2. `neighbors(ref, depth=2)` for what it connects to, then `depends_on` / `dependents`.
3. `findings_for_asset(ref)` then `get_finding` on the serious ones.
4. `blast_radius(ref)` and, if it is exposed, `find_paths(source='internet', target=ref)`.
5. `ontology_neighbourhood(ref)` for semantic relations (encryption, protection, ownership).

Report what it is, who owns it (tags), how it is exposed, what it can reach, what depends on
it, its findings, and prioritised recommendations."""
        if _is_active(ctx, ds):
            return _result("Investigate asset", task, None, [(asset_uri(data["id"]), data)])
        return _result("Investigate asset", task, data)

    _add(reg, "investigate_asset", "Investigate asset",
         "Deep dive on one asset: config, relations, exposure, findings, blast radius.",
         [PromptArgument("ref", "Asset id, ARN or unique name.", True, complete_asset),
          _ds_arg()], Sensitivity.CONFIDENTIAL, investigate_asset)

    def blast_radius_assessment(ctx: Any, ref: str, dataset: str = "") -> PromptResult:
        ds = _dataset(ctx, dataset)
        if ds is None:
            return _result("Blast radius assessment", NO_DATA)
        a = ds.resolve_asset(ref)
        deps = ds.dependency_graph().dependents(a.id, 10)
        data = {"asset": asset_brief(ds, a), "transitive_dependents": len(deps),
                "accounts_affected": sorted({ds.by_id[d.asset_id].account_id or "" for d in deps}
                                            - {""}),
                "direct_dependents": [asset_brief(ds, ds.by_id[d.asset_id])
                                      for d in deps if d.depth == 1][:20]}
        task = f"""Assess the blast radius of `{a.name}` ({a.asset_type.value}) in `{ds.name}` if
it is (a) compromised and (b) deleted or unavailable.

1. `blast_radius(ref='{a.id}')`: dependency and network reach, sensitive stores reachable.
2. `dependency_tree(ref, direction='down')` shows what breaks, layer by layer.
3. `lateral_movement_paths(start='{a.id}')` for identity pivots from it.
4. `findings_for_asset` on the most critical dependents.

Report both scenarios with affected services / accounts / data, severity, and containment
and resilience recommendations (least privilege, redundancy, segmentation)."""
        res = [(asset_uri(a.id), _asset_ctx(ds, a.id))] if _is_active(ctx, ds) else []
        return _result("Blast radius assessment", task, data, res)

    _add(reg, "blast_radius_assessment", "Blast radius assessment",
         "Impact of compromise or loss of one asset.",
         [PromptArgument("ref", "Asset id, ARN or unique name.", True, complete_asset),
          _ds_arg()], Sensitivity.CONFIDENTIAL, blast_radius_assessment)

    def change_impact_analysis(ctx: Any, ref: str, change: str = "",
                               dataset: str = "") -> PromptResult:
        ds = _dataset(ctx, dataset)
        if ds is None:
            return _result("Change impact analysis", NO_DATA)
        a = ds.resolve_asset(ref)
        dg = ds.dependency_graph()
        data = {"asset": asset_brief(ds, a),
                "depends_on": [asset_brief(ds, ds.by_id[d.asset_id])
                               for d in dg.depends_on(a.id, 1)][:20],
                "dependents": [asset_brief(ds, ds.by_id[d.asset_id])
                               for d in dg.dependents(a.id, 1)][:20]}
        what = change or "a configuration change"
        task = f"""Plan the change "{what}" to `{a.name}` ({a.asset_type.value}) in `{ds.name}`.
Direct upstream / downstream dependencies are embedded.

1. `dependents(ref='{a.id}', max_depth=5)` and `dependency_tree(ref, direction='down')`.
2. `shared_dependencies()`: is it a single point of failure?
3. `cross_account_edges(account_id='{a.account_id or ''}')` for other accounts affected.
4. `get_asset_metadata(ref)` for the settings being changed.

Deliver: affected components ranked by impact, risks, pre-checks, a rollout and rollback
plan, and how to verify (e.g. snapshot_dataset now, re-collect after, diff_datasets)."""
        res = [(asset_uri(a.id), _asset_ctx(ds, a.id))] if _is_active(ctx, ds) else []
        return _result("Change impact analysis", task, data, res)

    _add(reg, "change_impact_analysis", "Change impact analysis",
         "What a planned change to one asset affects, with rollout and rollback plan.",
         [PromptArgument("ref", "Asset id, ARN or unique name.", True, complete_asset),
          PromptArgument("change", "The planned change, in words."), _ds_arg()],
         Sensitivity.CONFIDENTIAL, change_impact_analysis)

    # -- identity / compliance / remediation -----------------------------

    def cross_account_trust_review(ctx: Any, dataset: str = "") -> PromptResult:
        ds = _dataset(ctx, dataset)
        if ds is None:
            return _result("Cross-account trust review", NO_DATA)
        from cloudg.inventory.dependencies import cross_account_edges

        rows = ds.cached("cross_account", lambda: cross_account_edges(ds.assets, ds.edges))
        pairs: dict[str, int] = {}
        for r in rows:
            k = f"{r['source_account']} -> {r['target_account']} ({r['edge_type']})"
            pairs[k] = pairs.get(k, 0) + 1
        data = {"cross_account_edges": len(rows), "external": sum(1 for r in rows
                                                                   if r["external"]),
                "by_account_pair": pairs}
        task = f"""Review trust relationships across account boundaries in `{ds.name}`.

1. `cross_account_edges(external_only=true)` then all of them by account pair.
2. `get_edges(edge_types=['IAM_TRUST'])` and `get_edges(edge_types=['GRANTS_ACCESS'],
   cross_account_only=true)`.
3. `lateral_movement_paths()`: chains a compromised external principal could follow.
4. `organization_topology(include_policies=true)` for SCPs that limit the blast radius.

Flag unknown / external accounts, overly broad trust (account root, wildcards), missing
external-id conditions, and recommend tightening with evidence for each."""
        return _result("Cross-account trust review", task, data, [_summary_res(ds)])

    _add(reg, "cross_account_trust_review", "Cross-account trust review",
         "IAM trust and grants across account boundaries, external accounts, pivot chains.",
         [_ds_arg()], Sensitivity.CONFIDENTIAL, cross_account_trust_review)

    def compliance_gap_analysis(ctx: Any, framework: str, dataset: str = "") -> PromptResult:
        ds = _dataset(ctx, dataset)
        if ds is None:
            return _result("Compliance gap analysis", NO_DATA)
        from cloudg.mcp.catalog.compliance import framework_rollup

        data = {"framework": framework, "posture": framework_rollup(ds, framework)}
        task = f"""Run a {framework} compliance gap analysis on `{ds.name}`.

1. `compliance_summary(framework='{framework}')`.
2. `list_controls(framework='{framework}', status='FAIL')` and
   `list_controls(framework='{framework}', source='ruleset')` for the full control set.
3. `control_status` on the failing controls with the most / worst findings.
4. `compliance_gaps(framework='{framework}')` to list the assets behind the gaps.

Deliver: pass rate and failing controls grouped by domain, the assets responsible, a
remediation backlog ordered by severity x effort, and evidence references (finding ids)."""
        try:
            detail = framework_detail(ds, framework)
        except ReferenceNotFoundError:
            return _result("Compliance gap analysis", task, data)
        if _is_active(ctx, ds):
            uri = "cloudg://compliance/" + quote(framework, safe="")
            return _result("Compliance gap analysis", task, None, [(uri, detail)])
        return _result("Compliance gap analysis", task, detail)

    _add(reg, "compliance_gap_analysis", "Compliance gap analysis",
         "Failing controls, responsible assets and a remediation backlog for one framework.",
         [PromptArgument("framework", "Framework, e.g. CIS-AWS, PCI-DSS, NIST-800-53.", True,
                         complete_framework), _ds_arg()],
         Sensitivity.CONFIDENTIAL, compliance_gap_analysis)

    def remediation_plan(ctx: Any, severity: str = "HIGH", dataset: str = "") -> PromptResult:
        ds = _dataset(ctx, dataset)
        if ds is None:
            return _result("Remediation plan", NO_DATA)
        sev = (severity or "HIGH").upper()
        data = {"min_severity": sev, "top_risks": _top_risks(ds, 10, sev)}
        task = f"""Build a remediation plan for open findings at {sev} or above in `{ds.name}`.

1. `list_findings(min_severity='{sev}', limit=100)` (page with next_cursor if needed).
2. `top_risks(top=20, min_severity='{sev}')` to order work by real risk.
3. `get_finding` for remediation text; `blast_radius` on assets where a fix may disrupt.
4. Group fixes that share a root cause (same security group, role, policy, account setting).

Deliver: phased plan (now / this sprint / next quarter) with owner hints from tags, each
item with finding ids, affected assets, the fix, its risk reduction and change risk. Note
accepted risks that could be suppressed (suppress_findings) with the reason."""
        return _result("Remediation plan", task, data, [_summary_res(ds)])

    _add(reg, "remediation_plan", "Remediation plan",
         "Phased fix plan for findings at or above a severity.",
         [PromptArgument("severity", "Minimum severity (default HIGH).", False,
                         complete_severity), _ds_arg()],
         Sensitivity.CONFIDENTIAL, remediation_plan)

    def incident_triage(ctx: Any, finding_id: str, dataset: str = "") -> PromptResult:
        ds = _dataset(ctx, dataset)
        if ds is None:
            return _result("Incident triage", NO_DATA)
        f = ds.get_finding(finding_id)
        data = finding_detail(ds, f)
        aid = ds.finding_asset_id(f)
        target = aid or f.resource_arn or f.resource_id
        task = f"""Triage the finding "{f.title}" ({f.severity.value}, id `{f.id}`) in
`{ds.name}` as a potential incident.

1. `get_finding(finding_id='{f.id}')` for evidence and mapped controls.
2. `get_asset(ref='{target}')` and `internet_exposure()`: is the affected asset reachable?
3. `find_paths(source='internet', target='{target}')` and `blast_radius(ref='{target}')`.
4. `lateral_movement_paths(start='{target}')` to see where an attacker goes next.

Deliver: is it exploitable (likely / possible / unlikely) and why, impact if exploited,
immediate containment steps, evidence to collect, the permanent fix, and severity
re-rating if justified."""
        if _is_active(ctx, ds):
            return _result("Incident triage", task, None, [(finding_uri(f.id), data)])
        return _result("Incident triage", task, data)

    _add(reg, "incident_triage", "Incident triage",
         "Exploitability, impact and containment for one finding.",
         [PromptArgument("finding_id", "Finding id.", True, complete_finding), _ds_arg()],
         Sensitivity.CONFIDENTIAL, incident_triage)

    def drift_review(ctx: Any, base: str, target: str = "") -> PromptResult:
        ws = ctx.workspace
        diff = ws.diff(base, target or None, limit=25)
        task = f"""Review what changed between dataset `{diff['base']}` (before) and
`{diff['target']}` (after). The diff is embedded (counts plus the first items).

Call `diff_datasets(base='{diff['base']}', target='{diff['target']}', limit=200)` for more,
and `get_asset` / `findings_for_asset` on anything suspicious. Report: new or newly exposed
assets, removed controls (security groups, WAF, logging), new trust edges, findings
introduced vs resolved, and whether each change looks intended or like drift."""
        return _result("Drift review", task, diff)

    _add(reg, "drift_review", "Drift review",
         "Explain the differences between two datasets (before / after).",
         [PromptArgument("base", "Baseline dataset.", True, complete_dataset),
          PromptArgument("target", "Later dataset; empty = active.", False, complete_dataset)],
         Sensitivity.CONFIDENTIAL, drift_review)
