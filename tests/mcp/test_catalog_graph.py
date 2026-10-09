"""Graph / relationship tools."""

from __future__ import annotations

import pytest


async def test_neighbors(call, layer):
    out = await call("neighbors", ref="web-1")
    ids = {n["id"] for n in out["nodes"]}
    assert ids == {"sg-app", "app-role", "subnet-private", "tg-web", "inspector"}
    assert out["edge_count"] == 5 and not out["truncated"]
    out = await call(
        "neighbors",
        ref="web-1",
        direction="out",
        edge_types=["ASSUMES_ROLE", "GRANTS_ACCESS"],
        depth=2,
    )
    ids = {n["id"] for n in out["nodes"]}
    assert ids == {"app-role", "data-bucket", "orders-db"}
    out = await call("neighbors", ref="web-1", direction="in")
    assert {n["id"] for n in out["nodes"]} == {"subnet-private", "tg-web", "inspector"}
    out = await call("neighbors", ref="kms-main", depth=4, limit=3)
    assert out["truncated"] and out["node_count"] == 3
    out = await call("neighbors", ref="internet")
    assert out["asset"]["id"] == "0.0.0.0/0" and out["node_count"] >= 6
    res = await layer.call_tool("neighbors", {"ref": "web-1"})
    assert any(getattr(c, "uri", "").endswith("/neighbors") for c in res.content)


async def test_neighbors_errors(call):
    assert "close match" in await call.error("neighbors", ref="web-7")
    assert "edge type" in await call.error("neighbors", ref="web-1", edge_types=["FOO"])
    assert "depth" in await call.error("neighbors", ref="web-1", depth=9)


async def test_get_edges(call):
    out = await call("get_edges", internet_only=True, port=22)
    assert [e["target"] for e in out["items"]] == ["sg-admin"]
    out = await call("get_edges", internet_only=True, port=3389)
    assert [e["target"] for e in out["items"]] == ["az-nsg"]
    out = await call("get_edges", source="app-role")
    assert {e["target"] for e in out["items"]} == {"data-bucket", "orders-db", "deploy-role"}
    out = await call("get_edges", target="deploy-role", edge_types=["IAM_TRUST"])
    assert {e["source"] for e in out["items"]} == {"app-role", "acct-vendor"}
    assert all(e["cross_account"] for e in out["items"])
    out = await call("get_edges", cross_account_only=True)
    assert out["total"] >= 2
    out = await call("get_edges", relationship="ENCRYPTED_BY_KMS")
    assert out["total"] == 4
    out = await call("get_edges", source="internet", edge_types=["INTERNET_EXPOSED"])
    assert {e["target"] for e in out["items"]} == {"alb-web", "api-gw", "logs-bucket", "gcp-gcs"}
    out = await call("get_edges", port=5432)
    assert [e["id"] for e in out["items"]] == ["e-sgapp-sgdb"]
    page = await call("get_edges", limit=5)
    nxt = await call("get_edges", limit=5, cursor=page["next_cursor"])
    assert nxt["offset"] == 5
    assert "No asset matches" in await call.error("get_edges", target="nothing-here")


async def test_find_paths(call):
    out = await call("find_paths", source="internet", target="orders-db")
    assert out["paths"] and out["paths"][0]["summary"].startswith("0.0.0.0/0 -> web-alb")
    assert out["paths"][0]["edge_types"][-1] == "GRANTS_ACCESS"
    out = await call("find_paths", source="internet", target="bastion", mode="flow")
    assert out["paths"][0]["edge_types"] == ["SECURITY_GROUP_RULE", "SG_ADMITS"]
    out = await call("find_paths", source="internet", target="bastion", mode="directed")
    assert out["paths"] == [] and "hint" in out
    out = await call("find_paths", source="web-1", target="web-2", mode="undirected", max_paths=2)
    assert len(out["paths"]) == 2 and out["truncated"]
    out = await call("find_paths", source="internet", target="orders-db", max_depth=2)
    assert out["paths"] == []
    assert "close match" in await call.error("find_paths", source="web-1", target="orderz-db")


async def test_attack_paths(call):
    out = await call("attack_paths")
    summaries = [p["summary"] for p in out["paths"]]
    assert "web-alb -> web-tg -> web-1 -> app-role -> orders-db" in summaries
    assert any(s.endswith("orders-db-credentials") for s in summaries)
    top = out["paths"][0]
    assert {"score", "target_weight", "findings_on_path", "entry"} <= set(top)
    assert out["paths"] == sorted(out["paths"], key=lambda p: (-p["score"], p["length"]))
    out = await call("attack_paths", target="db-secret")
    assert out["targets_considered"] == 1 and out["paths"][0]["nodes"][-1]["id"] == "db-secret"
    out = await call("attack_paths", max_paths=1)
    assert len(out["paths"]) == 1 and out["truncated"]


async def test_attack_paths_nothing_exposed(call, workspace, sample_dataset):
    ds = sample_dataset.copy("closed")
    ds.edges = [e for e in ds.edges if e.source_id != "0.0.0.0/0"]
    for a in ds.assets:
        a.is_internet_exposed = False
    workspace.add(ds)
    out = await call("attack_paths")
    assert out["paths"] == [] and "hint" in out
    assert "no internet node" in await call.error("find_paths", source="internet", target="web-1")


async def test_lateral_movement_paths(call):
    out = await call("lateral_movement_paths")
    summaries = {p["summary"] for p in out["paths"]}
    assert "vendor-co -> deploy-role -> shared-artifacts" in summaries
    assert "bastion -> bastion-admin -> orders-db-credentials" in summaries
    out = await call("lateral_movement_paths", start="web-1")
    assert {p["summary"] for p in out["paths"]} >= {"web-1 -> app-role -> orders-db"}
    assert any("deploy-role" in p["summary"] for p in out["paths"])
    out = await call("lateral_movement_paths", max_paths=1)
    assert out["truncated"] and len(out["paths"]) == 1


async def test_internet_exposure(call):
    out = await call("internet_exposure")
    assert out["total"] == 6
    first = out["items"][0]
    assert first["id"] in ("bastion", "az-vm") and first["sensitive_ports_open"]
    alb = next(i for i in out["items"] if i["id"] == "alb-web")
    assert alb["protected_by_waf"] is True
    bastion = next(i for i in out["items"] if i["id"] == "bastion")
    assert bastion["internet_rules"][0]["via"] == "sg-admin"
    out = await call("internet_exposure", asset_types=["S3_BUCKET"], include_reachable=True)
    assert [i["id"] for i in out["items"]] == ["logs-bucket"]
    assert out["graph_reachable"]["total"] > 5
    page = await call("internet_exposure", limit=2)
    assert page["next_cursor"]


async def test_blast_radius(call):
    out = await call("blast_radius", ref="kms-main")
    dep = out["dependency"]
    assert dep["transitive_dependents"] >= 4
    assert {"api-handler", "data-bucket", "orders-db", "db-secret"} <= {
        i["id"] for i in dep["items"]
    }
    assert dep["by_depth"]["1"] == 4
    out = await call("blast_radius", ref="app-role")
    assert {n["id"] for n in out["network"]["sensitive_reachable"]} >= {"orders-db", "data-bucket"}
    assert out["network"]["risk_score"] > 0
    out = await call("blast_radius", ref="kms-main", limit=1)
    assert out["dependency"]["truncated"] and len(out["dependency"]["items"]) == 1


async def test_depends_on_dependents_tree(call):
    out = await call("depends_on", ref="api-handler")
    ids = {i["id"] for i in out["items"]}
    assert {"lambda-role", "kms-main", "log-group", "ecr-repo", "api-gw"} <= ids
    assert all("via" in i and "depth" in i for i in out["items"])
    out = await call("dependents", ref="sg-app")
    assert {i["id"] for i in out["items"]} >= {"web-1", "web-2"}
    out = await call("depends_on", ref="api-handler", limit=1)
    assert out["truncated"] and out["returned"] == 1
    out = await call("dependency_tree", ref="api-handler", direction="up", max_depth=2)
    assert "depends_on" in out and "dependents" not in out
    assert out["asset"]["id"] == "api-handler"
    out = await call("dependency_tree", ref="kms-main", direction="down", max_nodes=2)
    assert out["truncated"]
    out = await call("dependency_tree", ref="acct-prod", include_hierarchy=True)
    assert out["asset"]["id"] == "acct-prod"


async def test_shared_and_largest(call):
    out = await call("shared_dependencies")
    assert out["items"][0]["id"] == "kms-main"
    out = await call("largest_blast_radius", top=3)
    assert len(out["items"]) <= 3 and out["items"][0]["transitive_dependents"] > 0


async def test_cross_account_edges(call):
    out = await call("cross_account_edges")
    assert out["total"] >= 2
    assert any("999999999999" in k for k in out["by_account_pair"])
    out = await call("cross_account_edges", external_only=True)
    assert all(i["external"] for i in out["items"]) and out["total"] >= 1
    out = await call("cross_account_edges", account_id="222222222222", edge_types=["IAM_TRUST"])
    assert {i["source_account"] for i in out["items"]} == {"111111111111", "999999999999"}


@pytest.mark.parametrize("metric", ["degree", "in_degree", "out_degree", "betweenness"])
async def test_centrality(call, metric):
    out = await call("centrality_top", metric=metric, top=5)
    assert len(out["items"]) == 5
    scores = [i["score"] for i in out["items"]]
    assert scores == sorted(scores, reverse=True)
    out = await call("centrality_top", metric=metric, asset_types=["IAM_ROLE"])
    assert {i["type"] for i in out["items"]} == {"IAM_ROLE"}


@pytest.mark.parametrize("fmt", ["d3", "cytoscape", "graphml"])
async def test_subgraph_export(call, fmt):
    out = await call("subgraph_export", seeds=["web-1"], depth=1, format=fmt)
    assert out["nodes"] == 6 and out["edges"] >= 5
    if fmt == "d3":
        assert {n["id"] for n in out["graph"]["nodes"]} >= {"web-1", "app-role"}
    elif fmt == "cytoscape":
        assert out["graph"]["elements"]["nodes"]
    else:
        assert out["graph"].startswith("<?xml") or "<graphml" in out["graph"]


async def test_subgraph_export_limits(call):
    out = await call("subgraph_export", seeds=["kms-main", "web-1"], depth=3, max_nodes=4)
    assert out["truncated"] and out["nodes"] <= 4
    out = await call("subgraph_export", seeds=["web-1"], depth=0)
    assert out["nodes"] == 1
    out = await call("subgraph_export", seeds=["web-1"], edge_types=["ASSUMES_ROLE"])
    assert out["nodes"] == 2
    assert "seeds" in await call.error("subgraph_export", seeds=[])


async def test_security_coverage_and_graph_stats(call):
    out = await call("security_coverage")
    assert out["gaps"]["items"] == ["111111111111/us-east-1: securityhub"]
    unscanned = {i["name"] for i in out["workloads_without_vulnerability_scanning"]["items"]}
    assert {"web-2", "bastion", "api-handler", "app-images"} <= unscanned
    assert "web-1" not in unscanned
    waf = {i["name"] for i in out["internet_facing_without_waf"]["items"]}
    assert "public-api" in waf and "web-alb" not in waf
    out = await call("graph_stats")
    assert out["asset_nodes"] > 40 and out["placeholder_nodes"] == 1
    assert out["components"] >= 1 and out["edges_by_type"]["CONTAINS"] >= 5
