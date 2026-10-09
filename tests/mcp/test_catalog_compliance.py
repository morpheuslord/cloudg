"""Compliance tools."""

from __future__ import annotations

from cloudg.mcp.catalog.compliance import ruleset_catalog


async def test_list_frameworks(call):
    out = await call("list_frameworks")
    names = {i["framework"] for i in out["items"]}
    assert {"CIS-AWS", "NIST-800-53"} & names
    assert all(i["controls"] > 0 for i in out["items"])
    aws = await call("list_frameworks", provider="aws")
    azure = await call("list_frameworks", provider="azure")
    assert aws["total"] >= 1 and azure["total"] >= 1 and aws["total"] <= out["total"]


def test_ruleset_catalog_cached():
    from cloudg.config import _default_rules_dir

    a = ruleset_catalog(_default_rules_dir())
    assert a is ruleset_catalog(_default_rules_dir())
    assert ruleset_catalog("/nonexistent") == {}


async def test_compliance_summary(call, layer):
    out = await call("compliance_summary")
    fws = {f["framework"]: f for f in out["frameworks"]}
    cis = fws["CIS-AWS"]
    assert cis["controls_evaluated"] == 4 and cis["controls_failing"] == 3
    assert cis["pass_rate"] == 25.0 and cis["open_findings"] == 6
    assert cis["affected_assets"] == 5  # ghost finding is unmapped
    assert fws["CIS-Azure"]["severity_breakdown"] == {"CRITICAL": 1}
    out = await call("compliance_summary", framework="pci")
    assert [f["framework"] for f in out["frameworks"]] == ["PCI-DSS"]
    out = await call("compliance_summary", framework="HIPAA")
    assert out["frameworks"] == [] and "hint" in out
    res = await layer.call_tool("compliance_summary", {})
    assert any(getattr(c, "uri", "") == "cloudg://compliance/CIS-AWS" for c in res.content)


async def test_list_controls_dataset(call):
    out = await call("list_controls", framework="CIS-AWS")
    assert out["total"] == 4 and out["items"][0]["max_severity"] == "CRITICAL"
    out = await call("list_controls", framework="CIS-AWS", status="PASS")
    assert [c["control_id"] for c in out["items"]] == ["3.1"]
    page = await call("list_controls", framework="CIS", limit=2)
    assert page["next_cursor"] and page["total"] == 6
    assert "status" in await call.error("list_controls", framework="CIS", status="BROKEN")


async def test_list_controls_ruleset(call):
    out = await call("list_controls", framework="CIS-AWS", source="ruleset", limit=5)
    assert out["source"] == "ruleset" and out["total"] > 10 and len(out["items"]) == 5
    assert {"framework", "control_id", "title"} <= set(out["items"][0])
    msg = await call.error("list_controls", framework="ZZZ-NOPE", source="ruleset")
    assert "Known:" in msg


async def test_control_status(call, workspace):
    out = await call("control_status", framework="CIS-AWS", control_id="5.2")
    assert out["status"] == "FAIL" and out["open_findings"] == 1
    assert out["affected_assets"][0]["id"] == "sg-admin"
    assert out["findings"][0]["id"] == "f-ssh-open"
    out = await call("control_status", framework="CIS-AWS", control_id="3.1")
    assert out["status"] == "PASS"
    workspace.get().set_suppressed(["f-ssh-open"], True)
    out = await call("control_status", framework="CIS-AWS", control_id="5.2")
    assert out["status"].startswith("PASS")
    # A control defined in the shipped ruleset but not evaluated here
    out = await call("control_status", framework="CIS-AWS", control_id="1.1")
    assert out["status"] == "NOT_EVALUATED" and out["definition"]["title"]
    msg = await call.error("control_status", framework="CIS-AWS", control_id="99.99")
    assert "Controls in this dataset" in msg
    msg = await call.error("control_status", framework="NOPE", control_id="99.99")
    assert "list_controls" in msg


async def test_compliance_gaps(call):
    out = await call("compliance_gaps")
    first = out["items"][0]
    assert first["gap_max_severity"] == "CRITICAL"
    ids = {i["id"] for i in out["items"]}
    assert {"sg-admin", "az-nsg", "logs-bucket"} <= ids
    ghost = next(i for i in out["items"] if i.get("unmapped"))
    assert ghost["name"] == "arn:aws:s3:::ghost-bucket"
    out = await call("compliance_gaps", framework="CIS-Azure")
    assert [i["id"] for i in out["items"]] == ["az-nsg"]
    assert out["items"][0]["failing_controls"] == ["CIS-Azure:6.1"]
    out = await call("compliance_gaps", min_severity="HIGH", limit=2)
    assert out["returned"] == 2 and out["next_cursor"]
