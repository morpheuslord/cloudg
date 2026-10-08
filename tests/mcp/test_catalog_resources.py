"""Resources, resource templates and completions."""

from __future__ import annotations

import json
from urllib.parse import quote

import pytest

from cloudg.mcp.catalog import resources as res_mod
from cloudg.mcp.core import NotFoundError


async def read_json(layer, uri):
    contents = await layer.read_resource(uri)
    return json.loads(contents[0].text)


async def test_static_resources(layer):
    ws = await read_json(layer, "cloudg://workspace")
    assert ws["active_dataset"] == "sample"
    ds = await read_json(layer, "cloudg://datasets")
    assert ds["datasets"][0]["name"] == "sample"
    fs = await read_json(layer, "cloudg://findings/summary")
    assert fs["open_findings"] == 11 and fs["by_tool"]["prowler"] >= 3
    comp = await read_json(layer, "cloudg://compliance")
    assert comp["frameworks"][0]["framework"] == "CIS-AWS"
    d3 = await read_json(layer, "cloudg://graph/d3")
    assert {"nodes", "links"} <= set(d3)
    types = await read_json(layer, "cloudg://schema/asset-types")
    assert "EC2" in types["Compute"]
    edges = await read_json(layer, "cloudg://schema/edge-types")
    assert edges["CONTAINS"]["dependency_direction"] == "reverse"
    rel = await read_json(layer, "cloudg://schema/relation-types")
    assert "IAM" in rel
    docs = await read_json(layer, "cloudg://docs")
    assert "mcp" in docs["topics"] and "edge-types" in docs["topics"]


async def test_ontology_turtle_resource(layer):
    contents = await layer.read_resource("cloudg://ontology/turtle")
    assert contents[0].mime_type == "text/turtle" and "@prefix" in contents[0].text


@pytest.mark.parametrize("fmt,mime", [("json-ld", "application/ld+json"),
                                      ("nt", "application/n-triples"),
                                      ("xml", "application/rdf+xml")])
async def test_ontology_template(layer, fmt, mime):
    contents = await layer.read_resource(f"cloudg://ontology/{fmt}")
    assert contents[0].mime_type == mime and contents[0].text


@pytest.mark.parametrize("fmt", ["cytoscape", "graphml"])
async def test_graph_template(layer, fmt):
    contents = await layer.read_resource(f"cloudg://graph/{fmt}")
    assert contents[0].text
    if fmt == "graphml":
        assert contents[0].mime_type == "application/graphml+xml"


async def test_bad_formats_are_not_found(layer):
    with pytest.raises(NotFoundError):
        await layer.read_resource("cloudg://graph/png")
    with pytest.raises(NotFoundError):
        await layer.read_resource("cloudg://ontology/n3")


async def test_asset_templates(layer):
    out = await read_json(layer, "cloudg://assets/web-1")
    assert out["id"] == "web-1" and out["relations"]["outgoing"]["ASSUMES_ROLE"] == 1
    arn = "arn:aws:ec2:us-east-1:111111111111:instance/i-0web1"
    assert (await read_json(layer, f"cloudg://assets/{arn}"))["id"] == "web-1"
    assert (await read_json(layer, "cloudg://assets/" + quote(arn, safe="")))["id"] == "web-1"
    nb = await read_json(layer, f"cloudg://assets/{arn}/neighbors")
    assert nb["asset"] == "web-1" and len(nb["edges"]) == 5
    nb = await read_json(layer, "cloudg://assets/" + quote("0.0.0.0/0", safe="") + "/neighbors")
    assert nb["asset"] == "0.0.0.0/0" and nb["neighbors"]
    ext = await read_json(layer, "cloudg://assets/" + quote("0.0.0.0/0", safe=""))
    assert ext["external"] is True
    fs = await read_json(layer, "cloudg://assets/sg-admin/findings")
    assert fs["findings"][0]["id"] == "f-ssh-open"
    with pytest.raises(NotFoundError, match="Did you mean"):
        await layer.read_resource("cloudg://assets/web-9")


async def test_tool_links_resolve(layer):
    """Every resource link a tool returns can actually be read."""
    for name, args in [("get_asset", {"ref": "web-1"}),
                       ("get_finding", {"finding_id": "f-ssh-open"}),
                       ("dataset_summary", {}), ("compliance_summary", {}),
                       ("ontology_stats", {}), ("workspace_status", {})]:
        res = await layer.call_tool(name, args)
        links = [c for c in res.content if getattr(c, "uri", None)]
        assert links, name
        for link in links:
            assert await layer.read_resource(link.uri), link.uri


async def test_finding_templates(layer):
    out = await read_json(layer, "cloudg://findings/f-ssh-open")
    assert out["remediation"] == "Restrict 22 to the VPN."
    out = await read_json(layer, "cloudg://findings/severity/high")
    assert out["severity"] == "HIGH" and out["total"] == 5
    with pytest.raises(NotFoundError):
        await layer.read_resource("cloudg://findings/severity/URGENT")
    with pytest.raises(NotFoundError):
        await layer.read_resource("cloudg://findings/f-none")


async def test_dataset_and_compliance_templates(layer):
    out = await read_json(layer, "cloudg://datasets/sample/summary")
    assert out["dataset"] == "sample"
    with pytest.raises(NotFoundError):
        await layer.read_resource("cloudg://datasets/nope/summary")
    out = await read_json(layer, "cloudg://compliance/CIS-AWS")
    assert out["posture"][0]["framework"] == "CIS-AWS"
    assert out["failing_controls"][0]["max_severity"] == "CRITICAL"
    out = await read_json(layer, "cloudg://compliance/cis-aws")
    assert out["posture"][0]["framework"] == "CIS-AWS"
    with pytest.raises(NotFoundError):
        await layer.read_resource("cloudg://compliance/HIPAA")


async def test_schema_and_docs_templates(layer):
    out = await read_json(layer, "cloudg://schema/asset-types/ec2")
    assert out["ontology_class"] == "cm:ComputeInstance" and out["terraform_type"] == "aws_instance"
    with pytest.raises(NotFoundError):
        await layer.read_resource("cloudg://schema/asset-types/TOASTER")
    contents = await layer.read_resource("cloudg://docs/mcp")
    assert contents[0].mime_type == "text/markdown" and "workspace_status" in contents[0].text
    text = (await layer.read_resource("cloudg://docs/edge-types"))[0].text
    assert text.startswith("## 6. Edge types") and "## 7." not in text
    text = (await layer.read_resource("cloudg://docs/python-api"))[0].text
    assert text.startswith("## Python API") and "### Methods" in text
    with pytest.raises(NotFoundError, match="Topics"):
        await layer.read_resource("cloudg://docs/nope")


def test_doc_topics_all_resolve():
    for topic in res_mod.DOC_TOPICS:
        text = res_mod.doc_section(topic)
        assert "not found" not in text, topic


def test_docs_missing_install(monkeypatch, tmp_path):
    monkeypatch.setattr(res_mod, "docs_dir", lambda: None)
    assert "not installed" in res_mod.doc_section("cli")
    monkeypatch.undo()
    monkeypatch.setenv("CLOUDG_DOCS_DIR", str(tmp_path))
    assert res_mod.docs_dir() == tmp_path
    assert "not installed" in res_mod.doc_section("cli")
    (tmp_path / "DOCUMENTATION.md").write_text("# x\n\n## Other\n")
    assert "not found" in res_mod.doc_section("cli")


async def test_resources_without_dataset(tmp_path):
    from cloudg.mcp.layer import CloudGMCPLayer
    from cloudg.mcp.state import Workspace

    layer = CloudGMCPLayer(policy="open", workspace=Workspace(allowed_roots=[tmp_path],
                                                              output_dir=tmp_path))
    ws = await read_json(layer, "cloudg://workspace")
    assert ws["datasets"] == []
    with pytest.raises(NotFoundError, match="load_dataset"):
        await layer.read_resource("cloudg://graph/d3")
    assert (await layer.complete({"type": "ref/resource", "uri": "cloudg://assets/{+ref}"},
                                 {"name": "ref", "value": "w"}))["values"] == []
    fw = await layer.complete({"type": "ref/resource", "uri": "cloudg://compliance/{framework}"},
                              {"name": "framework", "value": "cis"})
    assert fw["values"]  # falls back to the shipped rulesets


async def test_unknown_resource(layer):
    with pytest.raises(NotFoundError):
        await layer.read_resource("cloudg://nothing")


# ---------------------------------------------------------------------------
# Completions
# ---------------------------------------------------------------------------


async def complete(layer, uri, var, value, **ctx_args):
    out = await layer.complete({"type": "ref/resource", "uri": uri},
                               {"name": var, "value": value}, context_arguments=ctx_args)
    return out["values"]


async def test_completions(layer, workspace, sample_dataset):
    assert await complete(layer, "cloudg://datasets/{dataset}/summary", "dataset", "sa") == \
        ["sample"]
    vals = await complete(layer, "cloudg://assets/{+ref}", "ref", "web")
    assert vals[:3] == ["web-1", "web-2", "web-acl"] or {"web-1", "web-2"} <= set(vals)
    assert "web-alb" in vals or "web-tg" in vals
    vals = await complete(layer, "cloudg://assets/{+ref}", "ref", "arn:aws:rds")
    assert vals == ["orders-db"]
    vals = await complete(layer, "cloudg://assets/{+ref}", "ref", "admin")
    assert "sg-admin" in vals and "bastion-admin" in vals
    vals = await complete(layer, "cloudg://findings/{finding_id}", "finding_id", "f-ss")
    assert vals == ["f-ssh-open"]
    assert await complete(layer, "cloudg://findings/severity/{severity}", "severity", "h") == \
        ["HIGH"]
    vals = await complete(layer, "cloudg://compliance/{framework}", "framework", "cis")
    assert set(vals) == {"CIS-AWS", "CIS-Azure", "CIS-GCP"}
    assert await complete(layer, "cloudg://docs/{topic}", "topic", "edge") == \
        ["edges", "edge-types"]
    assert await complete(layer, "cloudg://graph/{format}", "format", "c") == ["cytoscape"]
    assert await complete(layer, "cloudg://ontology/{format}", "format", "j") == ["json-ld"]
    assert "EC2" in await complete(layer, "cloudg://schema/asset-types/{asset_type}",
                                   "asset_type", "ec")
    # context argument picks the dataset
    other = sample_dataset.copy("other")
    other.assets = [a for a in other.assets if a.id != "web-2"]
    workspace.add(other, activate=False)
    vals = await complete(layer, "cloudg://assets/{+ref}", "ref", "web-", dataset="other")
    assert "web-2" not in vals and "web-1" in vals


async def test_ambiguous_names_complete_to_ids(layer, workspace):
    from cloudg.schema.models import AssetType, CloudAsset, CloudProvider

    ds = workspace.get()
    ds.assets.append(CloudAsset(id="dup-web-1", name="web-1", asset_type=AssetType.EC2,
                                provider=CloudProvider.AWS, arn="arn:aws:ec2:x:2:instance/i-dup"))
    ds.invalidate()
    vals = await complete(layer, "cloudg://assets/{+ref}", "ref", "web-1")
    assert "arn:aws:ec2:x:2:instance/i-dup" in vals and "web-1" not in vals
