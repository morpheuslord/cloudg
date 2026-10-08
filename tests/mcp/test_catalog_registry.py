"""Catalog-wide invariants: every primitive is described, typed, annotated
and categorised; the wire shapes are valid MCP."""

from __future__ import annotations

import inspect

import pytest

from cloudg.mcp.catalog import CATEGORIES, default_registry
from cloudg.mcp.core import Capability, Sensitivity

REG = default_registry()
OWN_CATEGORIES = {"workspace", "inventory", "graph", "findings", "compliance", "ontology",
                  "export", "live", "meta", "prompts"}


def own_tools():
    return [s for s in REG.tools.values() if s.category != "privacy"]


def test_catalog_size():
    assert len(own_tools()) >= 40
    assert len(REG.resources) >= 8
    assert len(REG.templates) >= 8
    assert len(REG.prompts) >= 10


@pytest.mark.parametrize("spec", own_tools(), ids=lambda s: s.name)
def test_tool_metadata(spec):
    assert spec.category in OWN_CATEGORIES and spec.category in CATEGORIES
    assert len(spec.description) > 40, "descriptions must tell the model when to use it"
    assert spec.title
    ann = spec.annotations
    assert ann.read_only is not None and ann.idempotent is not None
    assert ann.open_world is not None
    if not ann.read_only:
        assert ann.destructive is not None
    assert isinstance(spec.sensitivity, Sensitivity)
    # capabilities are consistent with annotations
    if ann.read_only:
        assert not spec.capabilities & {Capability.WRITE_STATE, Capability.WRITE_FS,
                                        Capability.CLOUD_ACCESS, Capability.EXEC}
    # Tools that reach cloud APIs or spawn processes are open-world
    if spec.capabilities & {Capability.CLOUD_ACCESS, Capability.EXEC}:
        assert ann.open_world is True
    else:
        assert ann.open_world is False


@pytest.mark.parametrize("spec", own_tools(), ids=lambda s: s.name)
def test_tool_input_schema_matches_signature(spec):
    schema = spec.input_schema
    assert schema["type"] == "object" and schema["additionalProperties"] is False
    params = [p for p in inspect.signature(spec.handler).parameters if p != "ctx"]
    assert set(schema.get("properties", {})) == set(params)
    for name, prop in schema["properties"].items():
        assert prop, f"{spec.name}.{name} has an empty (untyped) schema"
    required = set(schema.get("required", []))
    for p in inspect.signature(spec.handler).parameters.values():
        if p.name != "ctx":
            assert (p.name in required) == (p.default is inspect.Parameter.empty)


@pytest.mark.parametrize("spec", own_tools(), ids=lambda s: s.name)
def test_tool_wire(spec):
    wire = spec.to_wire()
    assert wire["name"] == spec.name
    assert wire["inputSchema"]["type"] == "object"
    assert "annotations" in wire and "readOnlyHint" in wire["annotations"]
    if spec.output_schema:
        assert wire["outputSchema"]["type"] == "object"


def test_paginated_tools_have_cursor_and_limit():
    paged = [s for s in own_tools() if "cursor" in s.input_schema["properties"]]
    assert len(paged) >= 10
    for s in paged:
        assert "limit" in s.input_schema["properties"], s.name


def test_dataset_argument_everywhere_it_matters():
    reads = [s for s in own_tools() if s.category in ("inventory", "graph", "findings",
                                                       "ontology", "export")
             and s.name not in ("ingest_reports",)]
    for s in reads:
        assert "dataset" in s.input_schema["properties"], s.name


def test_sensitivity_levels_used():
    levels = {s.sensitivity for s in own_tools()}
    assert levels == set(Sensitivity)
    assert REG.tools["get_asset_metadata"].sensitivity == Sensitivity.RESTRICTED
    assert REG.tools["describe_schema"].sensitivity == Sensitivity.PUBLIC
    assert REG.tools["count_assets"].sensitivity == Sensitivity.INTERNAL


def test_live_tools_are_async_and_open_world():
    for name in ("map_inventory", "collect_assets", "run_scanners", "run_pipeline"):
        spec = REG.tools[name]
        assert inspect.iscoroutinefunction(spec.handler)
        assert spec.annotations.open_world and Capability.CLOUD_ACCESS in spec.capabilities
        assert spec.timeout_seconds and spec.timeout_seconds >= 3600


def test_resources_and_templates_metadata():
    for spec in [*REG.resources.values(), *REG.templates.values()]:
        if spec.category == "privacy":
            continue
        assert spec.description and spec.title, spec.name
        assert spec.category in CATEGORIES
        wire = spec.to_wire()
        assert wire["name"] and wire["mimeType"]
    for spec in REG.templates.values():
        if spec.category == "privacy":
            continue
        for var in spec.variables:
            assert var in spec.completions, f"{spec.uri_template} lacks completion for {var}"


def test_template_matching():
    found = REG.find_template("cloudg://assets/arn:aws:ec2:us-east-1:1:instance/i-1/neighbors")
    assert found and found[0].uri_template == "cloudg://assets/{+ref}/neighbors"
    assert found[1]["ref"] == "arn:aws:ec2:us-east-1:1:instance/i-1"
    found = REG.find_template("cloudg://assets/arn%3Aaws%3As3%3A%3A%3Ab%2Fk")
    assert found[0].uri_template == "cloudg://assets/{+ref}"
    assert found[1]["ref"] == "arn:aws:s3:::b/k"
    found = REG.find_template("cloudg://findings/severity/HIGH")
    assert found[0].uri_template == "cloudg://findings/severity/{severity}"
    found = REG.find_template("cloudg://findings/f-1")
    assert found[0].uri_template == "cloudg://findings/{finding_id}"
    assert REG.find_template("cloudg://datasets/x/summary")[1] == {"dataset": "x"}
    assert REG.find_template("cloudg://unknown/x") is None


def test_prompts_metadata():
    for spec in REG.prompts.values():
        if spec.category == "privacy":
            continue
        assert spec.category == "prompts" and spec.description and spec.title
        for arg in spec.arguments:
            assert arg.description
            if arg.required:
                assert arg.completion is not None, f"{spec.name}.{arg.name}"
        wire = spec.to_wire()
        assert wire["name"] == spec.name


def test_privacy_module_is_optional(monkeypatch):
    import builtins

    real_import = builtins.__import__

    def fake(name, globals=None, locals=None, fromlist=(), level=0):
        if fromlist and "privacy" in fromlist and name == "cloudg.mcp.catalog":
            raise ImportError("no privacy")
        return real_import(name, globals, locals, fromlist, level)

    monkeypatch.setattr(builtins, "__import__", fake)
    reg = default_registry()
    assert "find_assets" in reg.tools
    assert not any(s.category == "privacy" for s in reg.tools.values())


OUTPUT_CALLS = {
    "find_assets": {}, "get_asset": {"ref": "web-1"}, "neighbors": {"ref": "web-1"},
    "find_paths": {"source": "internet", "target": "orders-db"}, "attack_paths": {},
    "lateral_movement_paths": {}, "list_findings": {}, "findings_for_asset": {"ref": "web-1"},
    "top_risks": {}, "workspace_status": {}, "dataset_summary": {}, "count_assets": {},
    "diff_datasets": {"base": "sample"}, "get_edges": {}, "depends_on": {"ref": "api-handler"},
    "dependents": {"ref": "kms-main"}, "sparql_query": {"query": "ASK { ?s ?p ?o }"},
    "compliance_summary": {},
}


async def test_structured_results_match_output_schemas(layer):
    jsonschema = pytest.importorskip("jsonschema")
    with_schema = {s.name for s in own_tools() if s.output_schema}
    assert with_schema <= set(OUTPUT_CALLS), with_schema - set(OUTPUT_CALLS)
    for name, args in OUTPUT_CALLS.items():
        res = await layer.call_tool(name, args)
        assert not res.is_error, name
        jsonschema.validate(res.structured, layer.registry.tools[name].output_schema)


def test_wire_shapes_validate_with_mcp_sdk(layer):
    types = pytest.importorskip("mcp.types")
    for w in layer.tools_wire():
        types.Tool.model_validate(w)
    for w in layer.resources_wire():
        types.Resource.model_validate(w)
    for w in layer.resource_templates_wire():
        types.ResourceTemplate.model_validate(w)
    for w in layer.prompts_wire():
        types.Prompt.model_validate(w)
