"""Prompts: messages, embedded context, required arguments, completions."""

from __future__ import annotations

import json

import pytest

from cloudg.mcp.core import EmbeddedResource, InvalidArgumentsError, NotFoundError, TextContent

ARGS = {
    "security_posture_review": {},
    "executive_summary": {},
    "attack_surface_report": {},
    "investigate_asset": {"ref": "web-1"},
    "blast_radius_assessment": {"ref": "kms-main"},
    "change_impact_analysis": {"ref": "sg-app", "change": "remove port 5432"},
    "cross_account_trust_review": {},
    "compliance_gap_analysis": {"framework": "CIS-AWS"},
    "remediation_plan": {"severity": "critical"},
    "incident_triage": {"finding_id": "f-ssh-open"},
    "drift_review": {"base": "sample"},
}


def _context(result) -> dict:
    """Merge the prompt's context: the JSON block of its text context
    message (if any) and every embedded resource."""
    out: dict = {}
    for m in result.messages[1:]:
        if isinstance(m.content, EmbeddedResource):
            out.update(json.loads(m.content.resource.text))
        elif isinstance(m.content, TextContent) and "```json" in m.content.text:
            out.update(json.loads(m.content.text.split("```json", 1)[1].rsplit("```", 1)[0]))
    assert out, "prompt should carry workspace context"
    return out


@pytest.mark.parametrize("name", list(ARGS))
async def test_prompt_renders(layer, name):
    result = await layer.get_prompt(name, ARGS[name])
    task = result.messages[0].content
    assert isinstance(task, TextContent) and len(task.text) > 200
    assert "`" in task.text  # names concrete tools to call
    assert result.description
    ctx = _context(result)
    assert ctx
    wire = result.to_wire()
    assert {m["content"]["type"] for m in wire["messages"][1:]} <= {"resource", "text"}


async def test_prompt_contents(layer):
    r = await layer.get_prompt("security_posture_review", {})
    ctx = _context(r)
    assert ctx["dataset"] == "sample" and ctx["total_assets"] > 40
    assert {x["id"] for x in ctx["top_risks"][:2]} == {"sg-admin", "az-nsg"}
    r = await layer.get_prompt("investigate_asset", {"ref": "i-0web1"})
    assert "web-1" not in r.messages[0].content.text  # names live in the context only
    assert _context(r)["id"] == "web-1"
    assert _context(r)["findings"][0]["id"] == "f-web-cve"
    r = await layer.get_prompt("remediation_plan", {})
    assert "HIGH" in r.messages[0].content.text
    r = await layer.get_prompt("remediation_plan", {"severity": "critical"})
    assert {x["id"] for x in _context(r)["top_risks"]} == {"sg-admin", "az-nsg"}
    r = await layer.get_prompt("cross_account_trust_review", {})
    assert _context(r)["external"] >= 1
    r = await layer.get_prompt("incident_triage", {"finding_id": "f-ssh-open"})
    assert "sg-admin" not in r.messages[0].content.text
    assert _context(r)["target_ref"] == "sg-admin"
    r = await layer.get_prompt("change_impact_analysis", {"ref": "sg-app"})
    assert _context(r)["planned_change"] == "a configuration change"
    assert "sg-app" not in r.messages[0].content.text
    r = await layer.get_prompt("blast_radius_assessment", {"ref": "kms-main"})
    assert _context(r)["transitive_dependents"] >= 4


async def test_prompts_without_dataset(tmp_path):
    from cloudg.mcp.layer import CloudGMCPLayer
    from cloudg.mcp.state import Workspace

    layer = CloudGMCPLayer(
        policy="open", workspace=Workspace(allowed_roots=[tmp_path], output_dir=tmp_path)
    )
    for name in ("security_posture_review", "investigate_asset", "executive_summary"):
        r = await layer.get_prompt(name, ARGS[name] or None)
        assert "No cloudg dataset is loaded" in r.messages[0].content.text
        assert len(r.messages) == 1


async def test_prompt_errors(layer):
    with pytest.raises(InvalidArgumentsError, match="ref"):
        await layer.get_prompt("investigate_asset", {})
    with pytest.raises(NotFoundError, match="close match") as exc:
        await layer.get_prompt("investigate_asset", {"ref": "web-9"})
    assert "web-9" not in exc.value.message and exc.value.data["value"] == "web-9"
    with pytest.raises(NotFoundError):
        await layer.get_prompt("incident_triage", {"finding_id": "nope"})
    with pytest.raises(NotFoundError, match="No such dataset"):
        await layer.get_prompt("executive_summary", {"dataset": "nope"})
    with pytest.raises(NotFoundError):
        await layer.get_prompt("no_such_prompt", {})


async def test_prompt_completions(layer):
    async def comp(prompt, arg, value):
        out = await layer.complete(
            {"type": "ref/prompt", "name": prompt}, {"name": arg, "value": value}
        )
        return out["values"]

    assert "web-1" in await comp("investigate_asset", "ref", "web")
    assert await comp("incident_triage", "finding_id", "f-rdp") == ["f-rdp-open"]
    assert await comp("remediation_plan", "severity", "c") == ["CRITICAL"]
    assert "CIS-AWS" in await comp("compliance_gap_analysis", "framework", "aws")
    assert await comp("drift_review", "base", "s") == ["sample"]
    assert await comp("executive_summary", "dataset", "") == ["sample"]
    assert await comp("investigate_asset", "unknown_arg", "x") == []


def test_prompt_sensitivity(layer):
    from cloudg.mcp.core import Sensitivity

    specs = layer.registry.prompts
    assert specs["executive_summary"].sensitivity == Sensitivity.INTERNAL
    assert specs["investigate_asset"].sensitivity == Sensitivity.CONFIDENTIAL


@pytest.mark.parametrize("name", list(ARGS))
async def test_prompt_task_text_carries_no_workspace_values(layer, name):
    """Names, ids and the caller's arguments stay in the structured context,
    where the privacy transforms see them with their keys."""
    result = await layer.get_prompt(name, ARGS[name])
    task = result.messages[0].content.text
    for value in (
        "sample",
        "web-1",
        "kms-main",
        "sg-app",
        "sg-admin",
        "f-ssh-open",
        "CIS-AWS",
        "remove port 5432",
        "111111111111",
    ):
        assert value not in task, (name, value)


@pytest.mark.parametrize("name", list(ARGS))
async def test_prompt_context_messages_carry_render_markers(layer, name):
    """Every data message says how its text was rendered from its data, so
    the layer can transform the data and render it again."""
    from cloudg.mcp.catalog.prompts import render_json, render_json_block

    # The handler's own output: the layer consumes the markers
    result = layer.registry.prompts[name].handler(layer.context(), **ARGS[name])
    renders = {"json-block": render_json_block, "json": render_json}
    for m in result.messages[1:]:
        c = m.content
        holder = c.resource if isinstance(c, EmbeddedResource) else c
        meta = holder.meta or {}
        assert set(meta) >= {"cloudg/data", "cloudg/render"}, name
        assert holder.text == renders[meta["cloudg/render"]](meta["cloudg/data"])
