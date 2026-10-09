"""Findings tools."""

from __future__ import annotations

import json

import pytest


async def test_list_findings_default_sort_and_suppression(call):
    out = await call("list_findings")
    assert out["total"] == 11  # one suppressed hidden
    assert out["items"][0]["severity"] == "CRITICAL"
    risks = [i["risk_score"] for i in out["items"]]
    assert risks == sorted(risks, reverse=True)
    assert out["severity_breakdown"]["CRITICAL"] == 2
    out = await call("list_findings", include_suppressed=True)
    assert out["total"] == 12


async def test_list_findings_filters(call):
    out = await call("list_findings", severities=["high"])
    assert {i["severity"] for i in out["items"]} == {"HIGH"} and out["total"] == 5
    out = await call("list_findings", min_severity="HIGH")
    assert out["total"] == 7
    out = await call("list_findings", source_tool="SCOUT")
    assert {i["id"] for i in out["items"]} == {"f-logs-public", "f-rdp-open", "f-ghost"}
    out = await call("list_findings", framework="pci")
    assert {i["id"] for i in out["items"]} == {"f-ssh-open", "f-logs-public", "f-web-cve"}
    out = await call("list_findings", resource="orders-db")
    assert [i["id"] for i in out["items"]] == ["f-db-backup"]
    out = await call("list_findings", query="openssl")
    assert [i["id"] for i in out["items"]] == ["f-web-cve"]
    out = await call("list_findings", resource="data-bucket", include_suppressed=True)
    assert out["items"][0]["is_suppressed"] is True
    ghost = (await call("list_findings", query="lifecycle"))["items"][0]
    assert ghost["asset_id"] is None and ghost["resource_arn"] == "arn:aws:s3:::ghost-bucket"


@pytest.mark.parametrize("sort_by", ["risk", "severity", "detected_at", "title", "source_tool"])
async def test_list_findings_sorts(call, sort_by):
    out = await call("list_findings", sort_by=sort_by)
    assert out["total"] == 11
    if sort_by == "title":
        titles = [i["title"].lower() for i in out["items"]]
        assert titles == sorted(titles)


async def test_list_findings_projection_pagination_errors(call):
    out = await call("list_findings", fields=["severity"], limit=4)
    assert set(out["items"][0]) == {"id", "severity"} and out["next_cursor"]
    nxt = await call("list_findings", fields=["severity"], limit=4, cursor=out["next_cursor"])
    assert nxt["offset"] == 4
    assert "Valid fields" in await call.error("list_findings", fields=["evil"])
    assert "severity" in await call.error("list_findings", severities=["URGENT"])
    assert "close match" in await call.error("list_findings", resource="orderz-db")


async def test_get_finding(call, layer, workspace):
    out = await call("get_finding", finding_id="f-ssh-open")
    assert out["remediation"] == "Restrict 22 to the VPN."
    assert out["asset"]["id"] == "sg-admin"
    assert {(c["framework"], c["control_id"]) for c in out["controls"]} == {
        ("CIS-AWS", "5.2"),
        ("PCI-DSS", "1.3.1"),
    }
    res = await layer.call_tool("get_finding", {"finding_id": "f-ssh-open"})
    uris = {getattr(c, "uri", None) for c in res.content}
    assert {"cloudg://findings/f-ssh-open", "cloudg://assets/sg-admin"} <= uris
    workspace.get().suppression_reasons["f-versioning"] = "accepted"
    out = await call("get_finding", finding_id="f-versioning")
    assert out["suppression_reason"] == "accepted"
    out = await call("get_finding", finding_id="CVE-2024-1234")  # by source id
    assert out["id"] == "f-web-cve"
    assert "list_findings" in await call.error("get_finding", finding_id="nope")


@pytest.mark.parametrize(
    "group_by,key",
    [
        ("severity", "CRITICAL"),
        ("source_tool", "prowler"),
        ("framework", "CIS-AWS"),
        ("asset_type", "SECURITY_GROUP"),
        ("account", "111111111111"),
        ("asset", "web-1"),
    ],
)
async def test_findings_summary(call, group_by, key):
    out = await call("findings_summary", group_by=group_by)
    assert key in out["groups"] and out["groups"][key]["total"] >= 1
    assert out["total"] == 11 and out["suppressed"] == 1


async def test_findings_summary_details(call):
    out = await call("findings_summary", group_by="asset_type")
    assert out["groups"]["unmapped"]["total"] == 1
    out = await call("findings_summary", group_by="severity")
    assert list(out["groups"])[0] == "CRITICAL"
    out = await call("findings_summary", group_by="framework", include_suppressed=True, top=2)
    assert len(out["groups"]) == 2 and out["truncated"] and out["total"] == 12


async def test_findings_for_asset(call):
    out = await call("findings_for_asset", ref="web-1")
    assert [i["id"] for i in out["items"]] == ["f-web-cve"]
    out = await call("findings_for_asset", ref="data-bucket")
    assert out["total"] == 0
    out = await call("findings_for_asset", ref="data-bucket", include_suppressed=True)
    assert out["total"] == 1
    assert "close match" in await call.error("findings_for_asset", ref="web-")


async def test_top_risks(call):
    out = await call("top_risks", top=3)
    names = [i["asset"]["id"] for i in out["items"]]
    assert set(names[:2]) == {"sg-admin", "az-nsg"}
    comp = out["items"][0]["components"]
    assert comp["exposure_factor"] == 1.5 and comp["internet_reachable"]
    assert out["total_candidates"] >= 8
    out = await call("top_risks", min_severity="CRITICAL")
    assert {i["asset"]["id"] for i in out["items"]} == {"sg-admin", "az-nsg"}


async def test_suppress_and_unsuppress(call, layer):
    events = []
    layer.workspace.on_change(lambda k, u: events.append((k, u)))
    out = await call("suppress_findings", finding_ids=["f-web-cve", "nope"], reason="patched")
    assert out["suppressed"] == ["f-web-cve"] and out["not_found"] == ["nope"]
    assert ("resource", "cloudg://datasets/sample/summary") in events
    assert (await call("findings_for_asset", ref="web-1"))["total"] == 0
    out = await call("suppress_findings", finding_ids=["f-web-cve"], reason="again")
    assert out["already_suppressed"] == ["f-web-cve"]
    out = await call("unsuppress_findings", finding_ids=["f-web-cve", "f-ssh-open"])
    assert out["unsuppressed"] == ["f-web-cve"] and out["not_suppressed"] == ["f-ssh-open"]
    assert "reason" in await call.error("suppress_findings", finding_ids=["x"], reason="")
    assert "finding_ids" in await call.error("unsuppress_findings", finding_ids=[])


def _trivy_report(path):
    path.write_text(
        json.dumps(
            {
                "SchemaVersion": 2,
                "ArtifactName": "app:1",
                "ArtifactType": "container_image",
                "Results": [
                    {
                        "Target": "app:1",
                        "Vulnerabilities": [
                            {
                                "VulnerabilityID": "CVE-2025-0001",
                                "PkgName": "libx",
                                "InstalledVersion": "1",
                                "Severity": "HIGH",
                                "Title": "libx overflow",
                                "Description": "d",
                            },
                            {
                                "VulnerabilityID": "CVE-2025-0002",
                                "PkgName": "liby",
                                "InstalledVersion": "1",
                                "Severity": "LOW",
                                "Title": "liby leak",
                                "Description": "d",
                            },
                        ],
                    }
                ],
            }
        )
    )
    return path


async def test_ingest_reports_into_active(call, sample_paths, workspace):
    report = _trivy_report(sample_paths["root"] / "trivy.json")
    before = len(workspace.get().findings)
    out = await call("ingest_reports", reports={"trivy": [str(report)]})
    assert out["parsed"] == 2 and out["per_path"][0]["findings"] == 2
    assert out["findings_after"] >= before + 2 and out["normalised"]
    assert (await call("findings_summary"))["suppressed"] == 1  # suppression survives


async def test_ingest_reports_new_dataset_no_normalise(call, sample_paths, workspace):
    report = _trivy_report(sample_paths["root"] / "trivy.json")
    out = await call(
        "ingest_reports",
        reports={"trivy": [str(report), str(report) + ".x"]},
        dataset="scans",
        new_dataset=True,
        normalise=False,
    )
    assert out["dataset"] == "scans" and out["findings_after"] == 2
    assert out["errors"][0]["path"].endswith(".x")
    assert workspace.active_name == "scans"


async def test_ingest_reports_errors(call):
    assert "Unsupported tool" in await call.error("ingest_reports", reports={"nmap": ["x"]})
    assert "outside the allowed roots" in await call.error(
        "ingest_reports", reports={"trivy": ["/etc/hosts"]}
    )


async def test_normalise_findings(call, workspace):
    out = await call("normalise_findings")
    assert out["findings_after"] <= out["findings_before"]
    assert out["compliance_results_after"] >= 1
    ds = workspace.get()
    assert ds.findings_by_id["f-versioning"].is_suppressed


async def test_reachability_findings(call, workspace):
    out = await call("reachability_findings")
    assert out["generated"] >= 3 and out["added"] == 0
    assert any("SSH" in i["title"] for i in out["items"])
    before = len(workspace.get().findings)
    out = await call("reachability_findings", add_to_dataset=True)
    assert out["added"] == out["new"] and len(workspace.get().findings) == before + out["added"]
    again = await call("reachability_findings", add_to_dataset=True)
    assert again["new"] == 0 and again["added"] == 0
