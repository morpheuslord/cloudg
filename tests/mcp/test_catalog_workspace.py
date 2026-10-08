"""Workspace tools."""

from __future__ import annotations

import pytest

from cloudg.mcp.layer import CloudGMCPLayer
from cloudg.mcp.state import Workspace


async def test_workspace_status_and_links(call, layer):
    out = await call("workspace_status")
    assert out["active_dataset"] == "sample"
    assert out["datasets"][0]["assets"] > 40
    res = await layer.call_tool("workspace_status", {})
    assert any(getattr(c, "uri", None) == "cloudg://workspace" for c in res.content)


async def test_workspace_status_empty_suggests_next_steps(tmp_path):
    layer = CloudGMCPLayer(policy="open", workspace=Workspace(allowed_roots=[tmp_path],
                                                              output_dir=tmp_path))
    res = await layer.call_tool("workspace_status", {})
    assert res.structured["datasets"] == []
    assert any("load_dataset" in s for s in res.structured["next_steps"])
    res = await layer.call_tool("find_assets", {})
    assert res.is_error and "load_dataset" in res.content[0].text


async def test_list_datasets(call):
    out = await call("list_datasets")
    assert out["total"] == 1 and out["datasets"][0]["active"] is True


async def test_load_select_unload(call, sample_paths):
    out = await call("load_dataset", path=str(sample_paths["report"]), name="rep",
                     activate=False)
    assert out["loaded"] == "rep" and out["active"] is False and out["total_findings"] == 12
    assert (await call("list_datasets"))["total"] == 2
    out = await call("select_dataset", name="rep")
    assert out["active_dataset"] == "rep"
    out = await call("dataset_summary")
    assert out["dataset"] == "rep"
    out = await call("unload_dataset", name="rep")
    assert out["remaining"] == ["sample"] and out["active_dataset"] == "sample"


async def test_load_dataset_auto_name_and_kind(call, sample_paths):
    out = await call("load_dataset", path=str(sample_paths["inventory_map"]))
    assert out["loaded"] == "inventory" and out["kind"] == "inventory"


async def test_load_dataset_errors(call, sample_paths):
    msg = await call.error("load_dataset", path="/etc/hosts")
    assert "outside the allowed roots" in msg
    msg = await call.error("load_dataset", path=str(sample_paths["root"] / "missing"))
    assert "does not exist" in msg
    msg = await call.error("load_dataset", path=str(sample_paths["report"]), kind="excel")
    assert "kind" in msg
    msg = await call.error("load_dataset", path=str(sample_paths["report"]), name="bad name")
    assert "Invalid dataset name" in msg


async def test_select_unknown(call):
    msg = await call.error("select_dataset", name="nope")
    assert "No dataset named 'nope'" in msg and "sample" in msg


async def test_snapshot_and_diff_tools(call, workspace):
    out = await call("snapshot_dataset", new_name="before")
    assert out["snapshot"] == "before" and out["kind"] == "snapshot"
    ds = workspace.get("sample")
    ds.assets = [a for a in ds.assets if a.id != "bastion"]
    ds.invalidate()
    out = await call("diff_datasets", base="before")
    assert out["base"] == "before" and out["target"] == "sample"
    assert [a["id"] for a in out["assets"]["removed"]["items"]] == ["bastion"]
    assert out["edges"]["removed"]["count"] >= 2
    msg = await call.error("diff_datasets", base="nope")
    assert "No dataset named" in msg


async def test_dataset_summary(call, layer):
    out = await call("dataset_summary")
    assert out["open_findings"] == 11 and out["internet_exposed"] == 6
    assert out["accounts"] >= 4
    msg = await call.error("dataset_summary", dataset="nope")
    assert "nope" in msg


@pytest.mark.parametrize("tool", ["select_dataset", "unload_dataset"])
async def test_required_arguments_validated(call, tool):
    msg = await call.error(tool)
    assert "name" in msg


async def test_layer_change_notifications(call, layer, sample_paths):
    events = []
    layer.on_change(lambda kind, uri: events.append((kind, uri)))
    await call("load_dataset", path=str(sample_paths["report"]), name="rep2", activate=False)
    assert ("resources", None) in events
    assert ("resource", "cloudg://datasets/rep2/summary") in events
    events.clear()
    await call("select_dataset", name="rep2")
    assert ("resource", "cloudg://workspace") in events and ("resources", None) not in events
    events.clear()
    await call("unload_dataset", name="rep2")
    assert ("resources", None) in events
