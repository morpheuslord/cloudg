"""The isometric map's scene: layout, painter's footprints and trace routing."""

from __future__ import annotations

import itertools
import json
import re
import shutil
import subprocess

import pytest

from cloudg.graph.builder import GraphBuilder
from cloudg.renderers import html_report
from cloudg.renderers.html_report import HTMLReportGenerator
from cloudg.renderers.iso_scene import MAX_SCENE_ASSETS, build_scene, category_of, edge_family
from cloudg.schema.models import (
    AssetType,
    CloudAsset,
    CloudProvider,
    EdgeType,
    NetworkEdge,
    ScanResult,
)
from tests.mcp.fixtures import sample_estate


@pytest.fixture(scope="module")
def estate():
    inv = sample_estate.build_inventory()
    graph = GraphBuilder()
    graph.build(inv.assets, inv.edges)
    scan = ScanResult(assets=inv.assets, edges=inv.edges, findings=sample_estate.findings())
    return scan, graph.to_d3_json(), build_scene(scan, graph.to_d3_json())


def _runs(trace):
    """The horizontal runs of a trace as (axis, fixed coordinate, z, lo, hi)."""
    out = []
    for (ax, ay, az), (bx, by, bz) in itertools.pairwise(trace["points"]):
        if az != bz or (ax == bx and ay == by):
            continue
        if ay == by:
            out.append(("x", ay, az, min(ax, bx), max(ax, bx)))
        else:
            out.append(("y", ax, az, min(ay, by), max(ay, by)))
    return out


class TestLayout:
    def test_every_asset_is_drawn_once(self, estate):
        scan, _, scene = estate
        drawn = {n["id"] for n in scene["nodes"]}
        drawn |= {p["asset_id"] for p in scene["platforms"] if p["asset_id"]}
        assert drawn == {a.id for a in scan.assets}
        assert len(scene["nodes"]) == len({n["id"] for n in scene["nodes"]})

    def test_networks_and_subnets_become_platforms(self, estate):
        _, _, scene = estate
        kinds = {p["label"]: p["kind"] for p in scene["platforms"]}
        assert kinds["prod-vpc"] == "network"
        assert kinds["prod-private-a"] == "subnet"
        assert kinds["hub-vnet"] == "network"

    def test_contents_stand_inside_and_on_top_of_their_platform(self, estate):
        _, _, scene = estate
        plats = {p["id"]: p for p in scene["platforms"]}
        for item in scene["platforms"] + scene["nodes"]:
            parent = plats.get(item.get("parent") or "")
            if not parent:
                continue
            if "w" in item and "asset_id" in item:
                x0, y0, x1, y1 = item["x"], item["y"], item["x"] + item["w"], item["y"] + item["d"]
            else:
                x0, y0 = item["x"] - item["w"] / 2, item["y"] - item["d"] / 2
                x1, y1 = item["x"] + item["w"] / 2, item["y"] + item["d"] / 2
            assert parent["x"] <= x0 + 1e-6 and x1 <= parent["x"] + parent["w"] + 1e-6
            assert parent["y"] <= y0 + 1e-6 and y1 <= parent["y"] + parent["d"] + 1e-6
            assert item["z"] == pytest.approx(parent["z"] + parent["h"])

    def test_siblings_have_disjoint_footprints(self, estate):
        """The page's painter's sort relies on siblings never overlapping."""
        _, _, scene = estate
        by_parent: dict[str, list[tuple[float, float, float, float]]] = {}
        for p in scene["platforms"]:
            rect = (p["x"], p["y"], p["x"] + p["w"], p["y"] + p["d"])
            by_parent.setdefault(p["parent"] or "", []).append(rect)
        for rects in by_parent.values():
            for a, b in itertools.combinations(rects, 2):
                assert (
                    a[2] <= b[0] + 1e-6
                    or b[2] <= a[0] + 1e-6
                    or a[3] <= b[1] + 1e-6
                    or b[3] <= a[1] + 1e-6
                )

    def test_identity_and_governance_sit_on_the_control_deck(self, estate):
        _, _, scene = estate
        deck = next(p for p in scene["platforms"] if p["kind"] == "deck")
        on_deck = {n["name"] for n in scene["nodes"] if n["parent"] == deck["id"]}
        assert {"app-role", "deploy-role", "sample-org", "prod"} <= on_deck
        ground = [n for n in scene["nodes"] if n["parent"] != deck["id"]]
        ground_top = max(n["z"] + n["h"] for n in ground)
        assert deck["z"] > ground_top
        # The deck stands behind the plate, never over it
        base = next(
            p for p in scene["platforms"] if p["kind"] == "provider" and p["provider"] == "AWS"
        )
        assert deck["y"] + deck["d"] <= base["y"]

    def test_findings_and_exposure_are_carried_on_nodes(self, estate):
        _, _, scene = estate
        nodes = {n["name"]: n for n in scene["nodes"]}
        assert nodes["sg-admin"]["worst"] == "CRITICAL"
        assert nodes["web-alb"]["exposed"] is True
        assert nodes["web-tg"]["worst"] is None

    def test_internet_is_an_external_mast(self, estate):
        _, _, scene = estate
        assert [e["kind"] for e in scene["externals"]] == ["internet"]
        mast = scene["externals"][0]
        assert mast["y"] > max(p["y"] + p["d"] for p in scene["platforms"])

    def test_scene_is_json_and_compact(self, estate):
        _, _, scene = estate
        text = json.dumps(scene)
        assert len(text) < 60_000


class TestTraces:
    def test_containment_is_not_drawn_as_traces(self, estate):
        _, _, scene = estate
        assert all(t["type"] != "CONTAINS" for t in scene["traces"])
        assert len(scene["traces"]) == 44

    def test_routes_are_orthogonal_and_end_on_their_assets(self, estate):
        _, _, scene = estate
        ends = {n["id"]: n for n in scene["nodes"] + scene["externals"]}
        for trace in scene["traces"]:
            pts = trace["points"]
            for a, b in itertools.pairwise(pts):
                assert sum(1 for i in range(3) if a[i] != b[i]) <= 1, trace["id"]
            for end, node in ((pts[0], ends[trace["source"]]), (pts[-1], ends[trace["target"]])):
                assert end[2] == pytest.approx(node["z"] + node["h"])
                assert abs(end[0] - node["x"]) <= max(node["w"], node["d"]) / 2
                assert abs(end[1] - node["y"]) <= max(node["w"], node["d"]) / 2
            # The lane is above both ends
            assert pts[1][2] > max(pts[0][2], pts[-1][2])

    def test_no_two_traces_share_a_horizontal_run(self, estate):
        _, _, scene = estate
        runs = [(t["id"], r) for t in scene["traces"] for r in _runs(t)]
        for (ta, a), (tb, b) in itertools.combinations(runs, 2):
            if ta == tb or a[0] != b[0] or abs(a[2] - b[2]) > 1e-6 or abs(a[1] - b[1]) >= 1.2:
                continue
            overlap = min(a[4], b[4]) - max(a[3], b[3])
            assert overlap <= 0.5, f"{ta} and {tb} share a run"

    def test_no_two_traces_share_a_port(self, estate):
        _, _, scene = estate
        ports = [tuple(t["points"][0]) for t in scene["traces"]]
        ports += [tuple(t["points"][-1]) for t in scene["traces"]]
        assert len(ports) == len(set(ports))

    def test_families(self, estate):
        _, _, scene = estate
        fam = {(t["type"], t["relationship"]): t["family"] for t in scene["traces"]}
        assert fam[("INTERNET_EXPOSED", "INTERNET_REACHABLE")] == "exposure"
        assert fam[("ASSUMES_ROLE", None)] == "identity"
        assert fam[("LOAD_BALANCER_TARGET", None)] == "network"
        assert fam[("PROTECTS", None)] == "governance"

    def test_parallel_edges_collapse_into_one_counted_trace(self):
        a = CloudAsset(
            id="a", name="a", asset_type=AssetType.EC2, provider=CloudProvider.AWS, region="r"
        )
        b = CloudAsset(
            id="b",
            name="b",
            asset_type=AssetType.RDS_INSTANCE,
            provider=CloudProvider.AWS,
            region="r",
        )
        edges = [
            NetworkEdge(
                source_id="a", target_id="b", edge_type=EdgeType.SECURITY_GROUP_RULE, port_range=p
            )
            for p in ("5432", "5433")
        ]
        scene = build_scene(ScanResult(assets=[a, b], edges=edges))
        assert len(scene["traces"]) == 1
        assert scene["traces"][0]["count"] == 2


class TestEdgeCases:
    def test_empty_scan(self):
        scene = build_scene(ScanResult())
        assert scene["nodes"] == [] and scene["traces"] == [] and scene["platforms"] == []

    def test_metadata_places_assets_without_contains_edges(self):
        vpc = CloudAsset(
            id="v",
            name="vpc-1",
            asset_type=AssetType.VPC,
            provider=CloudProvider.AWS,
            region="r",
            metadata={"vpc_id": "vpc-1"},
        )
        vm = CloudAsset(
            id="i",
            name="vm",
            asset_type=AssetType.EC2,
            provider=CloudProvider.AWS,
            region="r",
            metadata={"vpc_id": "vpc-1"},
        )
        scene = build_scene(ScanResult(assets=[vpc, vm]))
        node = scene["nodes"][0]
        assert node["parent"] == "c:v"

    def test_too_large(self, monkeypatch):
        monkeypatch.setattr("cloudg.renderers.iso_scene.MAX_SCENE_ASSETS", 1)
        assets = [
            CloudAsset(id=str(i), name=str(i), asset_type=AssetType.EC2, provider=CloudProvider.AWS)
            for i in range(2)
        ]
        scene = build_scene(ScanResult(assets=assets))
        assert scene == {"too_large": True, "asset_count": 2, "limit": 1}
        assert MAX_SCENE_ASSETS >= 1000

    @pytest.mark.parametrize(
        "value, category",
        [
            ("EC2", "compute"),
            ("LAMBDA_FUNCTION", "function"),
            ("EKS_CLUSTER", "cluster"),
            ("RDS_INSTANCE", "database"),
            ("S3_BUCKET", "storage"),
            ("IAM_ROLE", "identity"),
            ("KMS_KEY", "secret"),
            ("SECURITY_GROUP", "security"),
            ("ORG_POLICY", "governance"),
            ("LOAD_BALANCER", "network"),
            ("MESSAGE_QUEUE", "messaging"),
            ("LOG_GROUP", "observability"),
            ("ML_ENDPOINT", "ml"),
            ("OTHER", "other"),
        ],
    )
    def test_categories(self, value, category):
        assert category_of(value) == category

    def test_every_asset_type_has_a_category(self):
        for value in AssetType:
            assert category_of(value.value)

    def test_unknown_edge_types_are_data(self):
        assert edge_family("SOMETHING_NEW") == "data"


class TestReport:
    def test_report_embeds_the_scene_and_the_engines(self, estate, tmp_path):
        scan, graph, _ = estate
        page = HTMLReportGenerator(output_dir=str(tmp_path)).generate(scan, graph_json=graph)
        text = page.read_text(encoding="utf-8")
        assert "var IsoKit = (function" in text
        assert "hairline kernel sha256" in text
        assert '"traces":' in text and '"platforms":' in text

    def test_missing_engines_leave_the_2d_map(self, estate, tmp_path, monkeypatch):
        scan, graph, _ = estate
        monkeypatch.setattr(html_report, "MAP_ENGINES", {"isokit": "missing.js"})
        page = HTMLReportGenerator(output_dir=str(tmp_path)).generate(scan, graph_json=graph)
        text = page.read_text(encoding="utf-8")
        assert "var IsoKit = (function" not in text
        assert "renderTreeTopology" in text

    def test_layout_failure_never_costs_the_report(self, estate, tmp_path, monkeypatch):
        scan, graph, _ = estate

        def boom(*_a, **_k):
            raise ValueError("bad layout")

        monkeypatch.setattr(html_report, "build_scene", boom)
        page = HTMLReportGenerator(output_dir=str(tmp_path)).generate(scan, graph_json=graph)
        assert '"error": "bad layout"' in page.read_text(encoding="utf-8")


@pytest.mark.skipif(shutil.which("node") is None, reason="node is not installed")
def test_inline_scripts_share_one_global_scope(estate, tmp_path):
    """Every inline script runs in the same global scope, so a top-level name
    declared twice (a figure's const against the report's function) stops the
    report's own script from loading at all."""
    scan, graph, _ = estate
    page = HTMLReportGenerator(output_dir=str(tmp_path)).generate(scan, graph_json=graph)
    text = page.read_text(encoding="utf-8")
    scripts = re.findall(r"<script>\n(.*?)\n\s*</script>", text, re.S)
    assert len(scripts) == len(html_report.VENDORED_LIBRARIES) + len(html_report.MAP_ENGINES) + 1
    main = scripts[-1]
    main = main[: main.index("// ── Init ──")]
    stub = "globalThis.window = globalThis; globalThis.document = {};\n"
    js = tmp_path / "all.js"
    # Chart.js and D3 are skipped: they need a DOM to load and declare nothing that clashes
    js.write_text(
        stub
        + "\n;\n".join(scripts[2:-1] + [main])
        + "\nconsole.log(typeof IsoKit, typeof HL, Object.keys(window.HAIRLINE_FIGURES), typeof buildMap)\n",
        encoding="utf-8",
    )
    proc = subprocess.run(
        ["node", str(js)], capture_output=True, text=True, timeout=60, check=False
    )
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.split() == ["object", "object", "[", "'tray'", "]", "function"]
