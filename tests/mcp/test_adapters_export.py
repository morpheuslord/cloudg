"""Tests for the framework-free export, server detection and build helpers."""

from __future__ import annotations

from typing import Any

import pytest

from cloudg.mcp.adapters import (
    build_server,
    detect_server_kind,
    export_definitions,
    register_into,
    to_anthropic_tools,
    to_openai_tools,
)
from cloudg.mcp.adapters._common import normalize_kinds, owns_prompt, owns_resource, owns_tool
from cloudg.mcp.context import Principal
from cloudg.mcp.core import NotFoundError
from cloudg.mcp.native import NativeMCPServer
from tests.mcp._adapter_testkit import build_layer


async def test_export_definitions_and_handlers() -> None:
    layer = build_layer()
    exported = export_definitions(layer)
    assert exported.tools == layer.tools_wire()
    assert exported.resources == layer.resources_wire()
    assert exported.resource_templates == layer.resource_templates_wire()
    assert exported.prompts == layer.prompts_wire()
    assert exported.server["name"] == "cloudg"
    assert set(exported.as_dict()) == {
        "server",
        "tools",
        "resources",
        "resourceTemplates",
        "prompts",
    }

    result = await exported.dispatch("tools/call", {"name": "echo", "arguments": {"text": "q"}})
    assert result["structuredContent"] == {"text": "q"} and result["isError"] is False
    assert (await exported.dispatch("tools/list"))["tools"] == exported.tools
    read = await exported.dispatch("resources/read", {"uri": "test://info"})
    assert '"hello"' in read["contents"][0]["text"]
    prompt = await exported.dispatch("prompts/get", {"name": "greet", "arguments": {"name": "E"}})
    assert prompt["messages"][0]["content"]["text"] == "Hi E!"
    comp = await exported.dispatch(
        "completion/complete",
        {
            "ref": {"type": "ref/resource", "uri": "test://items/{item_id}"},
            "argument": {"name": "item_id", "value": "be"},
        },
    )
    assert comp["completion"]["values"] == ["beta"]
    assert (await exported.dispatch("resources/templates/list"))["resourceTemplates"]
    assert (await exported.dispatch("prompts/list"))["prompts"]
    assert (await exported.dispatch("resources/list"))["resources"]
    assert (await exported.tool_functions["echo"](text="fn"))["structuredContent"] == {"text": "fn"}
    with pytest.raises(KeyError):
        await exported.dispatch("nope")
    with pytest.raises(NotFoundError):
        await exported.dispatch("tools/call", {"name": "missing"})


async def test_export_uses_principal_per_call() -> None:
    layer = build_layer()
    seen: list[Principal] = []

    async def spy(info: Any, call_next: Any) -> Any:
        seen.append(info.principal)
        return await call_next(info)

    layer.use(spy)
    exported = export_definitions(layer, Principal(id="default-p"))
    await exported.dispatch("tools/call", {"name": "echo", "arguments": {"text": "x"}})
    await exported.dispatch(
        "tools/call", {"name": "echo", "arguments": {"text": "x"}}, principal=Principal(id="other")
    )
    assert [p.id for p in seen] == ["default-p", "other"]


def test_function_calling_formats() -> None:
    layer = build_layer()
    openai = to_openai_tools(layer)
    assert openai[0]["type"] == "function"
    assert openai[0]["function"]["parameters"] == layer.tools_wire()[0]["inputSchema"]
    anthropic = to_anthropic_tools(layer)
    assert anthropic[0]["name"] == "echo" and "input_schema" in anthropic[0]


def test_detection_and_build() -> None:
    layer = build_layer()
    with pytest.raises(TypeError):
        detect_server_kind(object())
    native = build_server(layer, "native")
    assert isinstance(native, NativeMCPServer) and detect_server_kind(native) == "native"
    assert register_into(layer, native) is native
    with pytest.raises(ValueError):
        register_into(build_layer(), native)
    with pytest.raises(ValueError):
        build_server(layer, "bogus")
    with pytest.raises(ValueError):
        normalize_kinds({"tools", "nope"})


def test_ownership_with_prefix() -> None:
    layer = build_layer(prefix="cg_")
    assert owns_tool(layer, "cg_echo") and not owns_tool(layer, "echo")
    assert owns_prompt(layer, "cg_greet") and not owns_prompt(layer, "greet")
    assert owns_resource(layer, "test://info") and owns_resource(layer, "test://items/x")
    assert not owns_resource(layer, "other://x")
