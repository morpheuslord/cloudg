"""Tools whose handler takes one pydantic arguments model (``ctx, args: Model``)
expose the same flat ``inputSchema`` as the equivalent signature and are
called with the validated model through every adapter path."""

from __future__ import annotations

from typing import Annotated, Literal

import pytest
from pydantic import BaseModel, Field

from cloudg.mcp.adapters import export_definitions
from cloudg.mcp.core import InvalidArgumentsError, Registry
from cloudg.mcp.layer import CloudGMCPLayer
from cloudg.mcp.native import NativeMCPServer
from cloudg.mcp.schema import input_schema_for, validate_arguments


class Inner(BaseModel):
    key: str


class FindArgs(BaseModel):
    query: Annotated[str, Field(description="Substring match on name/ARN")] = ""
    limit: Annotated[int, Field(ge=1, le=500, description="Page size")] = 50
    kind: Literal["a", "b"] | None = None
    tags: list[str] = Field(default_factory=list)
    inner: Inner | None = None
    dataset: Annotated[str, Field(description="Dataset name")]


def find_by_signature(
    ctx,
    query: Annotated[str, Field(description="Substring match on name/ARN")] = "",
    limit: Annotated[int, Field(ge=1, le=500, description="Page size")] = 50,
    kind: Literal["a", "b"] | None = None,
    tags: list[str] = Field(default_factory=list),
    inner: Inner | None = None,
    *,
    dataset: Annotated[str, Field(description="Dataset name")],
) -> dict:
    return {}


def find_by_model(ctx, args: FindArgs) -> dict:
    return {}


def test_model_schema_equals_signature_schema() -> None:
    model_schema = input_schema_for(find_by_model)
    assert model_schema == input_schema_for(find_by_signature)
    assert model_schema["additionalProperties"] is False
    assert "$defs" not in model_schema and "title" not in model_schema
    assert set(model_schema["properties"]) == set(FindArgs.model_fields)


def test_model_validation_passes_the_model_and_keeps_error_format() -> None:
    out = validate_arguments(find_by_model, {"dataset": "x", "limit": 3})
    args = out["args"]
    assert type(args) is FindArgs
    assert (args.dataset, args.limit, args.query) == ("x", 3, "")
    assert args.model_fields_set == {"dataset", "limit"}
    for bad in ({"dataset": "x", "nope": 1}, {"limit": 0}):
        with pytest.raises(InvalidArgumentsError) as by_model:
            validate_arguments(find_by_model, bad)
        with pytest.raises(InvalidArgumentsError) as by_signature:
            validate_arguments(find_by_signature, bad)
        assert by_model.value.message == by_signature.value.message
        assert by_model.value.data == by_signature.value.data


def test_only_a_single_parameter_named_args_is_a_model() -> None:
    def other_name(ctx, params: FindArgs) -> dict:
        return {}

    schema = input_schema_for(other_name)
    assert list(schema["properties"]) == ["params"]


async def test_model_tool_runs_through_layer_and_adapters(tmp_path) -> None:
    reg = Registry()

    @reg.tool(category="test")
    def model_tool(ctx, args: FindArgs) -> dict:
        """Echo the validated arguments."""
        return {"echo": args.model_dump()}

    layer = CloudGMCPLayer(registry=reg, policy="open")
    result = await layer.call_tool("model_tool", {"dataset": "d", "tags": ["t"]})
    assert not result.is_error
    assert result.structured["echo"]["dataset"] == "d"
    assert result.structured["echo"]["tags"] == ["t"]
    bad = await layer.call_tool("model_tool", {"limit": 0})
    assert bad.is_error and "dataset: Field required" in bad.content[0].text

    wire = export_definitions(layer).tools[0]
    assert wire["inputSchema"] == input_schema_for(find_by_signature)

    server = NativeMCPServer(layer)
    session = server.create_session()
    await session.handle(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {"protocolVersion": "2025-11-25", "capabilities": {}},
        }
    )
    resp = await session.handle(
        {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {"name": "model_tool", "arguments": {"dataset": "z"}},
        }
    )
    assert resp["result"]["structuredContent"]["echo"]["dataset"] == "z"
