"""config.yaml keys that used to be accepted but never read, and the
checks CloudGConfig runs on a loaded file (unknown keys, null values)."""

from __future__ import annotations

import json
import logging
from pathlib import Path

import pytest
import yaml

from cloudg.api import CloudGEngine
from cloudg.config import CloudGConfig, _default_rules_dir, load_config
from cloudg.graph.builder import GraphBuilder
from cloudg.normaliser import FindingsNormaliser
from cloudg.schema.models import Finding, ScanResult, Severity
from tests.test_rag_export import _make_assets, _make_edges

REPO_ROOT = Path(__file__).resolve().parent.parent


# ── Unknown keys ──


def test_unknown_keys_warn_in_every_section(caplog):
    data = {
        "bogus_top": 1,
        "aws": {"regoins": ["us-east-1"], "organization": {"enabeld": True}},
        "azure": {"tenant": "x"},
        "gcp": {"project": "p"},
        "scanners": {"timeout": 5},
        "inventory": {"sweep": True},
        "graph": {"max_nodes": 5},
        "ontology": {"formats": []},
        "rag": {"strategy": "entity"},
        "terraform": {"dir": "x"},
        "report": {"format": ["html"]},
        "rulesets": {"dir": "x"},
        "ratelimit": {"bogus": 1},
    }
    with caplog.at_level(logging.WARNING, logger="cloudg.config"):
        cfg = CloudGConfig.model_validate(data)
    text = caplog.text
    for key in (
        "bogus_top",
        "aws.regoins",
        "aws.organization.enabeld",
        "azure.tenant",
        "gcp.project",
        "scanners.timeout",
        "inventory.sweep",
        "graph.max_nodes",
        "ontology.formats",
        "rag.strategy",
        "terraform.dir",
        "report.format",
        "rulesets.dir",
    ):
        assert f"Unknown config key {key} is ignored" in text, key
    # ratelimit checks its own keys; reported once, not twice
    assert text.count("ratelimit.bogus") == 1
    assert cfg.graph.max_nodes_warn == 10000


def test_shipped_config_yaml_has_no_unknown_keys(caplog):
    with caplog.at_level(logging.WARNING, logger="cloudg.config"):
        cfg = load_config(REPO_ROOT / "config.yaml")
    assert "Unknown config key" not in caplog.text
    assert cfg.report.inline_js is True


# ── rulesets ──


@pytest.mark.parametrize("value", [None, "", "  "])
def test_rules_dir_null_means_packaged_rules(value):
    cfg = CloudGConfig.model_validate({"rulesets": {"rules_dir": value}})
    assert cfg.rulesets.rules_dir == _default_rules_dir()


def test_rules_dir_null_from_yaml(tmp_path):
    path = tmp_path / "c.yaml"
    path.write_text("rulesets:\n  rules_dir: null\n")
    assert load_config(path).rulesets.rules_dir == _default_rules_dir()


def _zebra_rules(tmp_path: Path) -> Path:
    rules = tmp_path / "rules"
    rules.mkdir()
    (rules / "zebra.yaml").write_text(
        yaml.safe_dump({"framework": "ZEBRA", "controls": [{"id": "Z1", "patterns": ["zebra"]}]})
    )
    return rules


def _zebra_finding() -> Finding:
    return Finding(
        resource_id="r1",
        severity=Severity.LOW,
        title="Zebra stripes found",
        description="zebra",
        source_tool="custom",
    )


def test_load_external_false_skips_yaml_rulesets(tmp_path):
    rules = _zebra_rules(tmp_path)
    on = FindingsNormaliser(rules_dir=rules).normalise([_zebra_finding()])
    off = FindingsNormaliser(rules_dir=rules, load_external=False).normalise([_zebra_finding()])
    assert "ZEBRA" in on.findings[0].compliance_frameworks
    assert "ZEBRA" not in off.findings[0].compliance_frameworks


def test_engine_reads_load_external(tmp_path):
    rules = _zebra_rules(tmp_path)
    cfg = CloudGConfig.model_validate(
        {"rulesets": {"rules_dir": str(rules), "load_external": False}}
    )
    result = CloudGEngine(cfg).normalise_findings([_zebra_finding()])
    assert "ZEBRA" not in result.findings[0].compliance_frameworks
    cfg.rulesets.load_external = True
    result = CloudGEngine(cfg).normalise_findings([_zebra_finding()])
    assert "ZEBRA" in result.findings[0].compliance_frameworks


# ── report ──


def test_report_formats_are_normalised_and_unknown_ones_dropped(caplog):
    with caplog.at_level(logging.WARNING, logger="cloudg.config"):
        cfg = CloudGConfig.model_validate({"report": {"formats": ["HTML", "pdf", "html", "svg"]}})
    assert cfg.report.formats == ["html", "svg"]
    assert "'pdf'" in caplog.text
    assert CloudGConfig.model_validate({"report": {"formats": "json"}}).report.formats == ["json"]


def _scan_result() -> ScanResult:
    return ScanResult(assets=_make_assets(), findings=[_zebra_finding()])


def test_engine_reports_follow_formats_and_inline_js(tmp_path):
    cfg = CloudGConfig.model_validate({"report": {"formats": ["html"], "inline_js": False}})
    engine = CloudGEngine(cfg)
    errors: list[str] = []
    paths = engine._write_reports(_scan_result(), tmp_path, errors)
    assert not errors
    assert set(paths) == {"html"}
    assert not (tmp_path / "findings.json").exists()
    assert "cdn.jsdelivr.net" in paths["html"].read_text(encoding="utf-8")


def test_engine_run_from_reports_uses_report_output_dir(tmp_path, monkeypatch):
    out = tmp_path / "configured"
    cfg = CloudGConfig.model_validate({"report": {"output_dir": str(out), "formats": ["json"]}})
    engine = CloudGEngine(cfg)
    monkeypatch.setattr(engine, "ingest_reports", lambda reports: [_zebra_finding()])
    result = engine.run_from_reports_sync({})
    assert not result.errors
    assert result.report_paths["json"].parent == out
    assert (out / "findings.json").exists()


def test_engine_explicit_output_dir_wins(tmp_path, monkeypatch):
    cfg = CloudGConfig.model_validate({"report": {"output_dir": str(tmp_path / "unused")}})
    engine = CloudGEngine(cfg)
    monkeypatch.setattr(engine, "ingest_reports", lambda reports: [_zebra_finding()])
    result = engine.run_from_reports_sync({}, output_dir=tmp_path / "given")
    assert result.report_paths["json"].parent == tmp_path / "given"
    assert not (tmp_path / "unused").exists()


def test_run_render_phase_follows_formats_and_inline_js(tmp_path):
    from cloudg.cli_run_helpers import _render_run_reports

    cfg = CloudGConfig.model_validate({"report": {"formats": ["svg", "html"], "inline_js": False}})
    graph_json = {"nodes": [], "links": []}
    _render_run_reports(_scan_result(), graph_json, _make_assets(), _make_edges(), tmp_path, cfg)
    assert (tmp_path / "topology.svg").exists()
    assert not (tmp_path / "findings.json").exists()
    assert "cdn.jsdelivr.net" in (tmp_path / "report.html").read_text(encoding="utf-8")

    # Without a config every format is written, as before
    other = tmp_path / "all"
    _render_run_reports(_scan_result(), graph_json, _make_assets(), _make_edges(), other)
    assert {p.name for p in other.iterdir()} >= {"findings.json", "topology.svg", "report.html"}


# ── graph ──


def test_graph_builder_warns_at_configured_threshold(caplog):
    assets, edges = _make_assets(), _make_edges()
    with caplog.at_level(logging.WARNING, logger="cloudg.graph.builder"):
        GraphBuilder(max_nodes_warn=len(assets)).build(assets, edges)
    assert "Large graph" not in caplog.text
    with caplog.at_level(logging.WARNING, logger="cloudg.graph.builder"):
        GraphBuilder(max_nodes_warn=len(assets) - 1).build(assets, edges)
    assert "Large graph" in caplog.text
    caplog.clear()
    with caplog.at_level(logging.WARNING, logger="cloudg.graph.builder"):
        GraphBuilder(max_nodes_warn=0).build(assets, edges)
    assert "Large graph" not in caplog.text


def test_engine_graph_uses_max_nodes_warn(caplog):
    cfg = CloudGConfig.model_validate({"graph": {"max_nodes_warn": 1}})
    engine = CloudGEngine(cfg)
    with caplog.at_level(logging.WARNING, logger="cloudg.graph.builder"):
        engine._run_reachability_analysis(_make_assets(), _make_edges())
    assert "graph.max_nodes_warn is 1" in caplog.text


@pytest.mark.parametrize(
    ("graph_cfg", "expected"),
    [
        ({}, {"topology.graphml"}),
        ({"persist_graphml": False}, set()),
        ({"export_cytoscape": True}, {"topology.graphml", "topology-cytoscape.json"}),
        (
            {"persist_graphml": False, "export_cytoscape": True},
            {"topology-cytoscape.json"},
        ),
    ],
)
def test_run_graph_phase_files_follow_config(tmp_path, graph_cfg, expected):
    from cloudg.cli_run_helpers import _graph_phase

    cfg = CloudGConfig.model_validate({"graph": graph_cfg})
    assets = _make_assets()
    for a in assets:  # GraphML cannot hold a None ARN
        a.arn = f"arn:aws:ec2:us-east-1:111:{a.id}"
    graph, graph_json, _ = _graph_phase(cfg, assets, _make_edges(), tmp_path)
    assert graph.number_of_nodes() > 0
    assert graph_json["nodes"]
    assert {p.name for p in tmp_path.iterdir()} == expected
    if "topology-cytoscape.json" in expected:
        assert json.loads((tmp_path / "topology-cytoscape.json").read_text())


# ── rag ──


def test_engine_rag_uses_chunk_strategy(tmp_path):
    cfg = CloudGConfig.model_validate(
        {"rag": {"chunk_strategy": "entity"}, "ontology": {"enabled": False}}
    )
    engine = CloudGEngine(cfg)
    import asyncio

    result = asyncio.run(engine.analyze(_make_assets(), _make_edges(), [], output_dir=tmp_path))
    lines = result.rag_chunks_path.read_text().splitlines()
    assert lines
    assert {json.loads(line)["chunk_type"] for line in lines} == {"entity"}
