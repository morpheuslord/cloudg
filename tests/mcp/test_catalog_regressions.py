"""Regression tests for bugs found by calling every tool (tool-reference pass)."""

from __future__ import annotations

import json

import pytest

from cloudg.mcp.core import Capability, InvalidArgumentsError
from cloudg.mcp.state import detect_kind, load_dataset_file

# -- 1. ARN tails split on ":" as well as "/" ---------------------------------


@pytest.mark.parametrize(
    "ref,asset_id",
    [
        ("function:api-handler", "api-handler"),
        ("secret:orders-db-credentials-AbC", "db-secret"),
        ("orders-db-credentials-AbC", "db-secret"),
        ("db:orders-db", "orders-db"),
        ("log-group:/aws/lambda/api-handler", "log-group"),
        ("instance/i-0web1", "web-1"),
        ("i-0web1", "web-1"),
        ("role/deploy-role", "deploy-role"),
        ("key/1111-2222", "kms-main"),
    ],
)
async def test_arn_tail_refs(call, ref, asset_id):
    assert (await call("get_asset", ref=ref))["id"] == asset_id


def test_ref_description_examples_resolve(sample_dataset):
    from cloudg.mcp.catalog._common import RefArg

    desc = RefArg.__metadata__[0].description
    assert "function:api" in desc
    assert sample_dataset.find_asset("function:api-handler").id == "api-handler"


# -- 2. same-name datasets are refused unless replace=true --------------------


async def test_snapshot_refuses_existing_name(call, workspace):
    await call(
        "load_dataset",
        path=str(workspace.allowed_roots[0] / "report"),
        name="report",
        activate=False,
    )
    msg, data = await call.error_data("snapshot_dataset", new_name="report", dataset="sample")
    assert "already exists" in msg and "replace=true" in msg
    assert data["suggested"] == "report-2" and "report-2" not in msg
    assert len(workspace.get("report").findings) == 12  # untouched
    out = await call("snapshot_dataset", new_name="report", dataset="sample", replace=True)
    assert out["assets"] == len(workspace.get("sample").assets)


async def test_load_dataset_refuses_existing_name(call, sample_paths, workspace):
    msg = await call.error("load_dataset", path=str(sample_paths["report"]), name="sample")
    assert "already exists" in msg
    assert workspace.get("sample").kind == "inventory"
    out = await call("load_dataset", path=str(sample_paths["report"]), name="sample", replace=True)
    assert out["kind"] == "report"


async def test_workspace_add_defaults_to_refusing(workspace, sample_dataset):
    with pytest.raises(InvalidArgumentsError, match="already exists"):
        workspace.add(sample_dataset)
    workspace.add(sample_dataset, replace=True)


# -- 3. ingest_reports(new_dataset=true): activation explicit -----------------


def _trivy(path):
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
                            }
                        ],
                    }
                ],
            }
        )
    )
    return path


async def test_ingest_new_dataset_activation(call, sample_paths, workspace):
    report = _trivy(sample_paths["root"] / "t.json")
    out = await call(
        "ingest_reports",
        reports={"trivy": [str(report)]},
        dataset="scans",
        new_dataset=True,
        activate=False,
    )
    assert out["active"] == "sample" and workspace.active_name == "sample"
    out = await call(
        "ingest_reports", reports={"trivy": [str(report)]}, dataset="scans2", new_dataset=True
    )
    assert out["active"] == "scans2"
    msg = await call.error(
        "ingest_reports", reports={"trivy": [str(report)]}, dataset="sample", new_dataset=True
    )
    assert "already exists" in msg
    out = await call(
        "ingest_reports",
        reports={"trivy": [str(report)]},
        dataset="sample",
        new_dataset=True,
        replace=True,
        activate=False,
    )
    assert out["findings_after"] == 1


# -- 5. renormalisation keeps loaded compliance results -----------------------


async def test_normalise_keeps_loaded_compliance(call, workspace):
    before = {(c.framework, c.control_id) for c in workspace.get().compliance}
    await call("normalise_findings")
    after = {(c.framework, c.control_id) for c in workspace.get().compliance}
    assert before <= after
    cis = next(
        f
        for f in (await call("compliance_summary", framework="CIS-AWS"))["frameworks"]
        if f["framework"] == "CIS-AWS"
    )
    assert cis["controls_evaluated"] >= 4 and cis["controls_passing"] >= 1
    out = await call("control_status", framework="CIS-AWS", control_id="5.2")
    assert out["status"] == "FAIL" and out["findings"][0]["id"] == "f-ssh-open"


async def test_ingest_keeps_loaded_compliance(call, sample_paths, workspace):
    before = {(c.framework, c.control_id) for c in workspace.get().compliance}
    await call("ingest_reports", reports={"trivy": [str(_trivy(sample_paths["root"] / "t.json"))]})
    assert before <= {(c.framework, c.control_id) for c in workspace.get().compliance}


def test_merge_compliance_rules():
    from cloudg.mcp.catalog.findings import merge_compliance
    from cloudg.schema.models import ComplianceResult, ComplianceStatus

    old = [
        ComplianceResult(
            framework="F",
            control_id="1",
            control_title="kept",
            status=ComplianceStatus.FAIL,
            finding_ids=["a", "gone"],
        ),
        ComplianceResult(
            framework="F", control_id="2", status=ComplianceStatus.FAIL, finding_ids=["gone"]
        ),
        ComplianceResult(framework="F", control_id="3", status=ComplianceStatus.PASS),
        ComplianceResult(
            framework="F",
            control_id="4",
            control_title="real title",
            status=ComplianceStatus.FAIL,
            finding_ids=["b"],
        ),
    ]
    new = [
        ComplianceResult(
            framework="F",
            control_id="4",
            control_title="F - 4",
            status=ComplianceStatus.FAIL,
            finding_ids=["c"],
        )
    ]
    out = {c.control_id: c for c in merge_compliance(old, new, {"a", "b", "c"})}
    assert set(out) == {"1", "3", "4"}  # 2 lost all its findings
    assert out["1"].finding_ids == ["a"]
    assert out["4"].finding_ids == ["c", "b"] and out["4"].control_title == "real title"


# -- 6. Prowler OCSF output is refused clearly ----------------------------------

OCSF = [
    {
        "message": "x",
        "finding_info": {"title": "t", "uid": "u"},
        "class_uid": 2004,
        "severity_id": 3,
        "status_code": "FAIL",
        "metadata": {"product": {"name": "Prowler"}},
    }
]


def test_ocsf_detected_and_refused(tmp_path):
    f = tmp_path / "prowler-output.ocsf.json"
    f.write_text(json.dumps(OCSF))
    with pytest.raises(InvalidArgumentsError, match="json-asff"):
        detect_kind(f)
    with pytest.raises(InvalidArgumentsError, match="OCSF"):
        load_dataset_file(f, "x", kind="prowler")
    jsonl = tmp_path / "p.jsonl"
    jsonl.write_text(json.dumps(OCSF[0]) + "\n" + json.dumps(OCSF[0]) + "\n")
    with pytest.raises(InvalidArgumentsError, match="OCSF"):
        detect_kind(jsonl)
    d = tmp_path / "prowler-dir"
    d.mkdir()
    (d / "out.json").write_text(json.dumps(OCSF))
    with pytest.raises(InvalidArgumentsError, match="OCSF"):
        load_dataset_file(d, "x", kind="prowler")


def test_asff_still_detected(tmp_path):
    f = tmp_path / "asff.json"
    f.write_text(json.dumps([{"SchemaVersion": "2018-10-08", "ProductArn": "arn:x", "Title": "t"}]))
    assert detect_kind(f) == "prowler"


async def test_ingest_reports_reports_ocsf_per_path(call, sample_paths):
    f = sample_paths["root"] / "ocsf.json"
    f.write_text(json.dumps(OCSF))
    out = await call("ingest_reports", reports={"prowler": [str(f)]})
    assert out["parsed"] == 0 and "json-asff" in out["errors"][0]["error"]


# -- 7. minor correctness ---------------------------------------------------------


async def test_find_paths_truncated_only_when_more_exist(call):
    every = await call(
        "find_paths", source="web-1", target="web-2", mode="undirected", max_paths=50
    )
    n = every["total_found"]
    assert not every["truncated"] and n >= 2
    exact = await call("find_paths", source="web-1", target="web-2", mode="undirected", max_paths=n)
    assert exact["total_found"] == n and not exact["truncated"]
    fewer = await call(
        "find_paths", source="web-1", target="web-2", mode="undirected", max_paths=n - 1
    )
    assert fewer["truncated"] and len(fewer["paths"]) == n - 1


async def test_dependency_tree_truncated_only_when_pruned(call):
    def count(nodes):
        return sum(1 + count(n.get("children", [])) for n in nodes)

    full = await call("dependency_tree", ref="kms-main", direction="down", max_nodes=1000)
    n = count(full["dependents"])
    assert not full["truncated"]
    exact = await call("dependency_tree", ref="kms-main", direction="down", max_nodes=n)
    assert not exact["truncated"] and count(exact["dependents"]) == n
    less = await call("dependency_tree", ref="kms-main", direction="down", max_nodes=n - 1)
    assert less["truncated"]


async def test_ontology_class_consistent(call, layer):
    tool = await call("explain_asset_type", asset_type="RDS_INSTANCE")
    res = json.loads(
        (await layer.read_resource("cloudg://schema/asset-types/RDS_INSTANCE"))[0].text
    )
    assert tool["ontology_class"] == res["ontology_class"] == "cm:RelationalDatabase"


@pytest.mark.parametrize(
    "uri,mime",
    [
        ("cloudg://graph/d3", "application/json"),
        ("cloudg://graph/cytoscape", "application/json"),
        ("cloudg://graph/graphml", "application/graphml+xml"),
        ("cloudg://ontology/turtle", "text/turtle"),
        ("cloudg://ontology/json-ld", "application/ld+json"),
    ],
)
async def test_format_resources_report_their_mime(layer, uri, mime):
    assert (await layer.read_resource(uri))[0].mime_type == mime


@pytest.mark.parametrize(
    "name,args",
    [
        ("security_posture_review", {}),
        ("investigate_asset", {"ref": "web-1"}),
        ("blast_radius_assessment", {"ref": "kms-main"}),
        ("incident_triage", {"finding_id": "f-ssh-open"}),
        ("compliance_gap_analysis", {"framework": "CIS-AWS"}),
        ("remediation_plan", {}),
        ("change_impact_analysis", {"ref": "sg-app"}),
        ("executive_summary", {}),
    ],
)
async def test_prompt_embedded_uris_serve_that_content(layer, name, args):
    from cloudg.mcp.core import EmbeddedResource

    result = await layer.get_prompt(name, args)
    embedded = [m.content for m in result.messages if isinstance(m.content, EmbeddedResource)]
    assert embedded, name
    for e in embedded:
        served = json.loads((await layer.read_resource(e.resource.uri))[0].text)
        assert json.loads(e.resource.text) == served, e.resource.uri


async def test_prompt_on_inactive_dataset_does_not_embed_active_uris(
    layer, workspace, sample_dataset
):
    from cloudg.mcp.core import EmbeddedResource

    workspace.add(sample_dataset.copy("other"), activate=False)
    result = await layer.get_prompt("investigate_asset", {"ref": "web-1", "dataset": "other"})
    assert not [m for m in result.messages if isinstance(m.content, EmbeddedResource)]
    assert "```json" in result.messages[1].content.text


async def test_completion_has_more(layer, workspace):
    from cloudg.schema.models import AssetType, CloudAsset, CloudProvider

    ds = workspace.get()
    ds.assets += [
        CloudAsset(
            id=f"bulk-{i}",
            name=f"bulk-{i:03d}",
            asset_type=AssetType.EC2,
            provider=CloudProvider.AWS,
        )
        for i in range(150)
    ]
    ds.invalidate()
    out = await layer.complete(
        {"type": "ref/resource", "uri": "cloudg://assets/{+ref}"}, {"name": "ref", "value": "bulk"}
    )
    assert out["total"] == 150 and out["hasMore"] is True and len(out["values"]) == 100


def test_run_scanners_declares_read_fs(layer):
    assert Capability.READ_FS in layer.registry.tools["run_scanners"].capabilities


async def test_explain_edge_type_rule_driven(call):
    out = await call("explain_edge_type", edge_type="CONTAINS")
    assert "VPC_CONTAINS_SUBNET" in out["ontology_relations"]
    assert "ports" not in out["ontology_relations"]
    out = await call("explain_edge_type", edge_type="IAM_TRUST")
    assert "CROSS_ACCOUNT_TRUST" in out["ontology_relations"]


# -- 8. stable ids for generated reachability findings -----------------------------


async def test_reachability_preview_ids_are_stable(call, workspace):
    a = await call("reachability_findings")
    b = await call("reachability_findings")
    assert [i["id"] for i in a["items"]] == [i["id"] for i in b["items"]]
    # The analyser's own deterministic ids (uuid5 of rule + asset key) are kept
    from cloudg.graph.reachability import ReachabilityAnalyzer

    native = {f.id for f in ReachabilityAnalyzer(workspace.get().graph.copy()).generate_findings()}
    assert {i["id"] for i in a["items"]} <= native
    added = await call("reachability_findings", add_to_dataset=True)
    ids = {f.id for f in workspace.get().findings}
    assert {i["id"] for i in added["items"]} <= ids
