"""Inventory tools: search, detail, aggregates, org topology."""

from __future__ import annotations

from cloudg.mcp.state import Dataset


async def test_find_assets_filters(call):
    out = await call("find_assets", asset_types=["EC2"])
    assert {i["id"] for i in out["items"]} == {"web-1", "web-2", "bastion"}
    out = await call("find_assets", provider="azure")
    assert {i["provider"] for i in out["items"]} == {"AZURE"}
    out = await call("find_assets", internet_exposed=True, asset_types=["ec2", "s3-bucket"])
    assert {i["id"] for i in out["items"]} == {"bastion", "logs-bucket"}
    out = await call("find_assets", tag="owner=web-team")
    assert {i["id"] for i in out["items"]} == {"alb-web", "web-1", "web-2"}
    out = await call("find_assets", tag="data")
    assert {i["id"] for i in out["items"]} == {"orders-db", "data-bucket"}
    out = await call("find_assets", region="EU-WEST-1")
    assert {i["id"] for i in out["items"]} == {"artifacts-bucket", "ecr-repo"}
    out = await call("find_assets", account_id="222222222222")
    assert "deploy-role" in {i["id"] for i in out["items"]}
    out = await call("find_assets", has_findings=True, min_severity="critical")
    assert {i["id"] for i in out["items"]} == {"sg-admin", "az-nsg"}
    out = await call("find_assets", has_findings=False, asset_types=["S3_BUCKET"])
    assert {i["id"] for i in out["items"]} == {"data-bucket", "artifacts-bucket"}
    out = await call("find_assets", query="ORDERS")
    assert {i["id"] for i in out["items"]} == {"orders-db", "db-secret"}
    out = await call("find_assets", query="pii")  # matches tag values
    assert {i["id"] for i in out["items"]} == {"orders-db", "data-bucket"}


async def test_find_assets_sort_and_projection(call):
    out = await call("find_assets", sort_by="risk", limit=3, fields=["name", "max_severity"])
    assert out["items"][0]["max_severity"] == "CRITICAL"
    assert set(out["items"][0]) == {"id", "name", "max_severity"}
    out = await call("find_assets", asset_types=["EC2"], sort_by="name", descending=True)
    assert [i["name"] for i in out["items"]] == ["web-2", "web-1", "bastion"]
    out = await call("find_assets", sort_by="findings", limit=1)
    assert out["items"][0]["open_findings"] >= 1
    out = await call("find_assets", fields=["tags"], asset_types=["VPC"])
    assert out["items"][0]["tags"]["owner"] == "platform"
    for key in ("type", "region", "account"):
        assert (await call("find_assets", sort_by=key))["total"] > 40


async def test_find_assets_pagination(call):
    first = await call("find_assets", limit=10)
    assert first["returned"] == 10 and first["truncated"] and first["next_cursor"]
    seen = {i["id"] for i in first["items"]}
    cursor = first["next_cursor"]
    while cursor:
        page = await call("find_assets", limit=10, cursor=cursor)
        ids = {i["id"] for i in page["items"]}
        assert not ids & seen
        seen |= ids
        cursor = page["next_cursor"]
    assert len(seen) == first["total"]


async def test_find_assets_cursor_errors(call, workspace):
    first = await call("find_assets", limit=5)
    msg = await call.error("find_assets", limit=5, cursor=first["next_cursor"], provider="aws")
    assert "Stale cursor" in msg
    msg = await call.error("find_assets", cursor="garbage!!")
    assert "Invalid cursor" in msg
    workspace.get().invalidate()  # dataset changed -> cursor stale
    msg = await call.error("find_assets", limit=5, cursor=first["next_cursor"])
    assert "Stale cursor" in msg


async def test_find_assets_bad_filters(call):
    msg, data = await call.error_data("find_assets", asset_types=["EC3"])
    assert "Unknown asset type" in msg and "EC2" in msg and "EC3" not in msg
    assert data["value"] == "EC3"
    msg = await call.error("find_assets", provider="oracle")
    assert "provider" in msg
    msg = await call.error("find_assets", fields=["bogus"])
    assert "Valid fields" in msg
    msg = await call.error("find_assets", min_severity="severe")
    assert "severity" in msg
    msg = await call.error("find_assets", limit=0)
    assert "limit" in msg
    out = await call("find_assets", query="zzzz-nothing")
    assert out["total"] == 0 and "hint" in out


async def test_get_asset(call, layer):
    out = await call("get_asset", ref="i-0web1")
    assert out["id"] == "web-1" and out["service"] == "ec2"
    assert out["relations"]["outgoing"]["ASSUMES_ROLE"] == 1
    assert out["relations"]["incoming"]["LOAD_BALANCER_TARGET"] == 1
    assert [f["id"] for f in out["findings"]] == ["f-web-cve"]
    assert "user_data" in out["metadata_keys"]
    assert "user_data" not in out  # raw metadata only via get_asset_metadata
    assert out["dependencies"]["direct_depends_on"] >= 2
    res = await layer.call_tool("get_asset", {"ref": "web-1"})
    uris = [getattr(c, "uri", None) for c in res.content]
    assert "cloudg://assets/web-1" in uris and "cloudg://assets/web-1/neighbors" in uris
    out = await call("get_asset", ref="web-1", include_findings=False, max_relations=1)
    assert "findings" not in out and out["relations"]["truncated"]


async def test_get_asset_not_found_suggests(call):
    msg, data = await call.error_data("get_asset", ref="web-9")
    assert "close match" in msg and "web-9" not in msg and "web-1" not in msg
    assert data["value"] == "web-9"
    assert "web-1" in {s["name"] for s in data["suggestions"]}
    assert {"name", "arn", "type", "dataset"} <= set(data["suggestions"][0])


async def test_get_asset_metadata(call):
    out = await call("get_asset_metadata", ref="web-1")
    assert out["metadata"]["instance_type"] == "t3.large" and not out["truncated"]
    out = await call("get_asset_metadata", ref="web-1", keys=["imds_v2", "nope"])
    assert out["metadata"] == {"imds_v2": False} and out["missing_keys"] == ["nope"]


async def test_get_asset_metadata_truncates(call, workspace):
    ds = workspace.get()
    ds.find_asset("web-2").metadata["blob"] = "x" * 5000
    ds.find_asset("web-2").metadata["small"] = 1
    out = await call("get_asset_metadata", ref="web-2", max_chars=1000)
    assert out["truncated"] and "blob" not in out["metadata"] and out["metadata"]["small"] == 1
    assert "key_sizes" in out


async def test_count_assets(call):
    out = await call("count_assets")
    assert out["groups"]["S3_BUCKET"] == 3 and out["total"] > 40
    out = await call("count_assets", group_by="provider")
    assert set(out["groups"]) == {"AWS", "AZURE", "GCP"}
    out = await call("count_assets", group_by="exposure")
    assert out["groups"]["internet_exposed"] == 6
    out = await call("count_assets", group_by="severity", provider="aws")
    assert out["groups"]["CRITICAL"] == 1 and "NONE" in out["groups"]
    out = await call("count_assets", group_by="service", provider="aws")
    assert "ec2" in out["groups"]
    out = await call("count_assets", group_by="account", top=1)
    assert len(out["groups"]) == 1 and out["truncated"]
    out = await call("count_assets", group_by="region", asset_types=["EC2"])
    assert out["groups"] == {"us-east-1": 3}
    msg = await call.error("count_assets", group_by="color")
    assert "group_by" in msg


async def test_list_asset_types_accounts_regions_tags(call):
    out = await call("list_asset_types")
    types = {i["type"]: i for i in out["items"]}
    assert types["EC2"]["count"] == 3 and types["EC2"]["internet_exposed"] == 1
    out = await call("list_accounts")
    accts = {i["account_id"]: i for i in out["items"]}
    assert accts["999999999999"]["external"] is True
    assert accts["111111111111"]["name"] == "prod"
    assert "us-east-1" in accts["111111111111"]["regions"]
    page = await call("list_accounts", limit=1)
    assert page["next_cursor"]
    out = await call("list_regions")
    regions = {i["region"]: i for i in out["items"]}
    assert regions["westeurope"]["providers"] == ["AZURE"]
    assert out["scanned_regions"]["aws"] == ["us-east-1", "eu-west-1"]
    out = await call("list_tags")
    keys = {i["key"]: i for i in out["items"]}
    assert keys["owner"]["top_values"]["web-team"] == 3
    out = await call("list_tags", key="env")
    assert [i["key"] for i in out["items"]] == ["env"]


async def test_coverage_report(call, workspace, sample_dataset):
    # inventory-map.json keeps the coverage records and loading restores them
    out = await call("coverage_report")
    assert out["failed"] == 1 and out["coverage_pct"] == 66.7
    assert out["records"][0]["failures"][0]["service"] == "rds"
    workspace.add(sample_dataset, activate=True, replace=True)
    out = await call("coverage_report")
    assert out["failed"] == 1 and out["coverage_pct"] == 66.7
    workspace.add(Dataset(name="bare"), activate=True, replace=True)
    out = await call("coverage_report")
    assert out["records"] == [] and "note" in out


async def test_unresolved_references(call):
    out = await call("unresolved_references")
    assert out["total"] == 1 and out["items"][0]["edge"] == "ASSUMES_ROLE"


async def test_organization_topology(call, workspace, sample_dataset):
    out = await call("organization_topology", include_policies=True)
    assert out["source"] == "organization_discovery"
    assert out["organization_id"] == "o-sample" and out["control_tower_enabled"]
    assert {a["name"] for a in out["accounts"]} == {"prod", "shared-services"}
    assert out["policies"][0]["type"] == "SERVICE_CONTROL_POLICY"
    out = await call("organization_topology", max_accounts=1)
    assert out["truncated"] and "policies" not in out
    # Fallback: hierarchy assets only
    ds = sample_dataset.copy("noorg")
    ds.organization = None
    workspace.add(ds)
    out = await call("organization_topology", include_policies=True)
    assert out["source"] == "map_assets"
    nodes = {n["id"]: n for n in out["nodes"]}
    assert nodes["acct-prod"]["parent_id"] == "ou-workloads"
    assert out["policies"][0]["targets"] == ["ou-workloads"]
    empty = Dataset(name="empty")
    workspace.add(empty)
    out = await call("organization_topology")
    assert out["source"] is None and "note" in out
