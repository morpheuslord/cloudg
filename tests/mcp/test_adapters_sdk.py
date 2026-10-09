"""Adapter tests for the official ``mcp`` SDK.

* mcp 2.x: ``MCPServer`` and the low-level ``Server`` through the SDK's
  in-memory ``Client`` in both protocol eras (``mode="legacy"`` ->
  2025-11-25 handshake, ``mode="auto"`` -> 2026-07-28 stateless).
* mcp 1.x: ``FastMCP`` and the low-level ``Server`` through
  ``mcp.shared.memory.create_connected_server_and_client_session``.

Each section is skipped when the other major version is installed.
"""

from __future__ import annotations

import asyncio
import importlib.metadata
from typing import Any

import pytest

from cloudg.mcp.adapters import build_server, detect_server_kind, register_into
from cloudg.mcp.context import Principal
from tests.mcp._adapter_testkit import build_layer

pytest.importorskip("mcp")
SDK_MAJOR = int(importlib.metadata.version("mcp").split(".")[0])

pytestmark = pytest.mark.filterwarnings("ignore")

v2_only = pytest.mark.skipif(SDK_MAJOR < 2, reason="needs mcp 2.x")
v1_only = pytest.mark.skipif(SDK_MAJOR >= 2, reason="needs mcp 1.x")


def dump(model: Any) -> dict[str, Any]:
    return model.model_dump(by_alias=True, mode="json", exclude_none=True)


def assert_exact_tools(listed: list[Any], layer: Any) -> None:
    got = {t.name: dump(t) for t in listed}
    for wire in layer.tools_wire():
        tool = got[wire["name"]]
        for key in ("inputSchema", "outputSchema", "annotations", "title", "description"):
            assert tool.get(key) == wire.get(key), (wire["name"], key)
        assert tool["_meta"] == wire["_meta"]


def host_mcpserver() -> Any:
    if SDK_MAJOR >= 2:
        from mcp.server.mcpserver import MCPServer

        server = MCPServer("host")
    else:
        from mcp.server.fastmcp import FastMCP

        server = FastMCP("host")

    @server.tool()
    def host_tool(x: int) -> int:
        """A tool the host server already had."""
        return x + 1

    return server


# ---------------------------------------------------------------------------
# mcp 2.x
# ---------------------------------------------------------------------------


@pytest.fixture(params=["mcpserver", "lowlevel"])
def v2_target(request: Any) -> tuple[Any, Any, str]:
    layer = build_layer()
    if request.param == "mcpserver":
        server = host_mcpserver()
        register_into(layer, server)
    else:
        server = build_server(layer, "lowlevel")
    return layer, server, request.param


@v2_only
@pytest.mark.parametrize("mode", ["legacy", "auto"])
async def test_v2_definitions_and_calls(v2_target: tuple[Any, Any, str], mode: str) -> None:
    from mcp import Client
    from mcp.types import PromptReference, ResourceTemplateReference

    layer, server, kind = v2_target
    assert detect_server_kind(server) == ("sdk-highlevel" if kind == "mcpserver" else "lowlevel")
    async with Client(server, mode=mode) as client:
        assert client.protocol_version == ("2025-11-25" if mode == "legacy" else "2026-07-28")
        tools = (await client.list_tools()).tools
        assert_exact_tools(tools, layer)
        if kind == "mcpserver":
            assert "host_tool" in [t.name for t in tools]
            host = await client.call_tool("host_tool", {"x": 41})
            assert "42" in host.content[0].text

        progress: list[float] = []

        async def on_progress(p: float, total: float | None, message: str | None) -> None:
            progress.append(p)

        slow = await client.call_tool("slow", {"steps": 3}, progress_callback=on_progress)
        assert slow.structured_content == {"done": 3} and not slow.is_error
        assert progress == [1, 2, 3]
        assert (await client.call_tool("fail", {})).is_error
        assert (await client.call_tool("echo", {"times": 99})).is_error
        stats = await client.call_tool("stats", {})
        assert stats.structured_content["count"] == 4
        linked = await client.call_tool("linked", {})
        assert any(getattr(c, "type", "") == "resource_link" for c in linked.content)

        resources = (await client.list_resources()).resources
        assert [dump(r) for r in resources if r.uri == "test://info"] == [
            w for w in layer.resources_wire() if w["uri"] == "test://info"
        ]
        templates = (await client.list_resource_templates()).resource_templates
        assert [t.uri_template for t in templates] == ["test://items/{item_id}"]
        read = await client.read_resource("test://items/alpha")
        assert '"index": 0' in read.contents[0].text
        with pytest.raises(Exception) as err:
            await client.read_resource("test://items/omega")
        expected = -32002 if mode == "legacy" else -32602
        assert getattr(getattr(err.value, "error", None), "code", None) == expected

        completion = await client.complete(
            ResourceTemplateReference(type="ref/resource", uri="test://items/{item_id}"),
            {"name": "item_id", "value": "g"},
        )
        assert completion.completion.values == ["gamma"]
        completion = await client.complete(
            PromptReference(type="ref/prompt", name="greet"), {"name": "name", "value": "al"}
        )
        assert completion.completion.values == ["alpha"]
        prompt = await client.get_prompt("greet", {"name": "Ada", "style": "formal"})
        assert prompt.messages[0].content.text == "Good day, Ada."
        if kind == "lowlevel":
            with pytest.raises(Exception):
                await client.call_tool("no_such_tool", {})
        else:  # unknown names fall through to MCPServer, which reports an isError result
            assert (await client.call_tool("no_such_tool", {})).is_error


@v2_only
async def test_v2_capabilities_and_legacy_notifications(v2_target: tuple[Any, Any, str]) -> None:
    from mcp import Client

    layer, server, _ = v2_target
    received: list[Any] = []
    logs: list[Any] = []

    async def on_message(message: Any) -> None:
        received.append(message)

    async def on_log(params: Any) -> None:
        logs.append(params)

    async with Client(
        server, mode="legacy", message_handler=on_message, logging_callback=on_log
    ) as client:
        caps = client.server_capabilities
        assert caps.tools.list_changed and caps.resources.subscribe
        assert caps.completions is not None and caps.logging is not None
        await client.subscribe_resource("test://info")
        await client.call_tool("slow", {"steps": 1})
        await client.call_tool("touch", {"uri": "test://info"})
        for _ in range(100):
            names = {type(m).__name__ for m in received}
            if {"ResourceUpdatedNotification", "ToolListChangedNotification"} <= names:
                break
            await asyncio.sleep(0.02)
        names = {type(m).__name__ for m in received}
        assert "ResourceUpdatedNotification" in names
        assert "ToolListChangedNotification" in names
        assert logs and logs[0].data == {"step": 1}
        await client.set_logging_level("error")
        logs.clear()
        await client.call_tool("slow", {"steps": 1})
        await asyncio.sleep(0.05)
        assert logs == []


@v2_only
async def test_v2_listen_stream(v2_target: tuple[Any, Any, str]) -> None:
    from mcp import Client

    _, server, _ = v2_target
    async with Client(server, mode="auto") as client:
        async with client.listen(
            tools_list_changed=True, resource_subscriptions=["test://info"]
        ) as sub:
            await client.call_tool("touch", {"uri": "test://info"})
            seen = set()
            for _ in range(2):
                seen.add(type(await asyncio.wait_for(sub.__anext__(), 5)).__name__)
            assert seen == {"ToolsListChanged", "ResourceUpdated"}


@v2_only
async def test_v2_principal_resolution_policy_and_prefix() -> None:
    from mcp import Client

    layer = build_layer()
    seen: list[Principal] = []

    async def spy(info: Any, call_next: Any) -> Any:
        seen.append(info.principal)
        return await call_next(info)

    layer.use(spy)

    def is_allowed(spec: Any, principal: Any = None) -> bool:
        return not (spec.name == "fail" and "admin" not in principal.roles)

    layer.policy.is_allowed = is_allowed  # type: ignore[method-assign]
    server = host_mcpserver()
    register_into(
        layer,
        server,
        prefix="cg_",
        principal_resolver=lambda info: Principal(id="svc", roles={"analyst"}),
    )
    async with Client(server, mode="legacy") as client:
        names = [t.name for t in (await client.list_tools()).tools]
        assert "cg_echo" in names and "echo" not in names and "host_tool" in names
        assert "cg_fail" not in names
        assert (await client.call_tool("cg_echo", {"text": "y"})).structured_content == {
            "text": "y"
        }
        with pytest.raises(Exception):
            await client.call_tool("cg_fail", {})
        prompt = await client.get_prompt("cg_greet", {"name": "P"})
        assert prompt.messages[0].content.text == "Hi P!"
    assert seen and all(p.id == "svc" for p in seen)


@v2_only
async def test_v2_mcp_param_schema_hook() -> None:
    layer = build_layer()
    server = host_mcpserver()
    register_into(layer, server)
    lowlevel = server._lowlevel_server
    assert lowlevel.get_tool_input_schema("echo") == layer.registry.tools["echo"].input_schema
    assert lowlevel.get_tool_input_schema("host_tool") is not None


@v2_only
async def test_v2_include_subset() -> None:
    from mcp import Client

    layer = build_layer()
    server = build_server(layer, "lowlevel", include={"tools"})
    async with Client(server, mode="legacy") as client:
        assert client.server_capabilities.prompts is None
        assert (await client.list_tools()).tools


# ---------------------------------------------------------------------------
# mcp 1.x
# ---------------------------------------------------------------------------


@v1_only
@pytest.mark.parametrize("kind", ["fastmcp", "lowlevel"])
async def test_v1_adapters(kind: str) -> None:
    from mcp.shared.memory import create_connected_server_and_client_session
    from mcp.types import PromptReference

    try:
        from mcp.types import ResourceTemplateReference
    except ImportError:  # pragma: no cover (old 1.x)
        from mcp.types import ResourceReference as ResourceTemplateReference

    layer = build_layer()
    if kind == "fastmcp":
        server = host_mcpserver()
        register_into(layer, server)
    else:
        server = build_server(layer, "lowlevel")
    received: list[Any] = []

    async def on_message(message: Any) -> None:
        received.append(message)

    async with create_connected_server_and_client_session(
        server, message_handler=on_message
    ) as session:
        tools = (await session.list_tools()).tools
        assert_exact_tools(tools, layer)
        if kind == "fastmcp":
            assert "host_tool" in [t.name for t in tools]
        progress: list[float] = []

        async def on_progress(p: float, total: float | None, message: str | None) -> None:
            progress.append(p)

        slow = await session.call_tool("slow", {"steps": 2}, progress_callback=on_progress)
        assert dump(slow)["structuredContent"] == {"done": 2}
        assert progress == [1, 2]
        assert dump(await session.call_tool("fail", {}))["isError"] is True
        read = await session.read_resource("test://items/beta")
        assert '"index": 1' in read.contents[0].text
        completion = await session.complete(
            ResourceTemplateReference(type="ref/resource", uri="test://items/{item_id}"),
            {"name": "item_id", "value": "b"},
        )
        assert completion.completion.values == ["beta"]
        completion = await session.complete(
            PromptReference(type="ref/prompt", name="greet"), {"name": "name", "value": "d"}
        )
        assert completion.completion.values == ["delta"]
        prompt = await session.get_prompt("greet", {"name": "Ola"})
        assert prompt.messages[0].content.text == "Hi Ola!"
        await session.subscribe_resource("test://info")
        await session.call_tool("touch", {"uri": "test://info"})
        for _ in range(100):
            if any("ResourceUpdated" in repr(m) for m in received):
                break
            await asyncio.sleep(0.02)
        assert any("ResourceUpdated" in repr(m) for m in received)
        assert any("ToolListChanged" in repr(m) for m in received)


async def test_lowlevel_never_forwards_raw_exception_text() -> None:
    from cloudg.mcp.adapters.lowlevel import install
    from cloudg.mcp.core import AccessDeniedError
    from mcp.server.lowlevel import Server

    binding = install(build_layer(), Server("host"))

    async def crash() -> None:
        raise ValueError("secret detail arn:aws:iam::111111111111:role/x")

    async def denied() -> None:
        raise AccessDeniedError("Access denied", data={"policy": "p"})

    with pytest.raises(Exception) as caught:
        await binding._through_layer(crash())
    assert "111111111111" not in str(caught.value) and "Internal error" in str(caught.value)
    with pytest.raises(Exception) as caught:
        await binding._through_layer(denied())
    assert "Access denied" in str(caught.value)
