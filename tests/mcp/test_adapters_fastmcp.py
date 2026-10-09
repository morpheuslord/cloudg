"""Adapter tests for the standalone ``fastmcp`` package (2.x / 3.x / 4.x).

Skipped unless ``fastmcp`` is installed. Verified in scratch environments
with fastmcp 2.14 (mcp 1.30), 3.4 (mcp 1.30) and 4.0 (mcp 2.3).
"""

from __future__ import annotations

import asyncio
from typing import Any

import pytest

from cloudg.mcp.adapters import build_server, detect_server_kind, register_into
from cloudg.mcp.context import Principal
from tests.mcp._adapter_testkit import build_layer

fastmcp = pytest.importorskip("fastmcp")

pytestmark = pytest.mark.filterwarnings("ignore")


def dump(model: Any) -> dict[str, Any]:
    return model.model_dump(by_alias=True, mode="json", exclude_none=True)


def make_server() -> tuple[Any, Any]:
    layer = build_layer()
    server = fastmcp.FastMCP("host")

    @server.tool
    def host_tool(x: int) -> int:
        """A tool the host server already had."""
        return x + 1

    register_into(layer, server)
    return layer, server


async def test_detected_as_fastmcp() -> None:
    _, server = make_server()
    assert detect_server_kind(server) == "fastmcp"


async def test_tools_keep_exact_definitions() -> None:
    layer, server = make_server()
    async with fastmcp.Client(server) as client:
        tools = {t.name: dump(t) for t in await client.list_tools()}
    assert "host_tool" in tools
    for wire in layer.tools_wire():
        got = tools[wire["name"]]
        assert got["inputSchema"] == wire["inputSchema"]
        assert got.get("outputSchema") == wire.get("outputSchema")
        assert got.get("annotations") == wire.get("annotations")
        assert got["description"] == wire["description"]
        for key, value in wire["_meta"].items():
            assert got["_meta"][key] == value
    assert tools["echo"]["title"] == "Echo"


async def test_tool_calls() -> None:
    _, server = make_server()
    progress: list[float] = []

    async def on_progress(p: float, total: float | None, message: str | None) -> None:
        progress.append(p)

    async with fastmcp.Client(server) as client:
        ok = dump(await client.call_tool_mcp("echo", {"text": "ab", "times": 2}))
        assert ok["structuredContent"] == {"text": "abab"} and not ok.get("isError")
        slow = dump(await client.call_tool_mcp("slow", {"steps": 2}, progress_handler=on_progress))
        assert slow["structuredContent"] == {"done": 2}
        assert progress == [1, 2]
        failed = dump(await client.call_tool_mcp("fail", {}))
        assert failed["isError"] is True
        invalid = dump(await client.call_tool_mcp("echo", {"times": 99}))
        assert invalid["isError"] is True
        stats = dump(await client.call_tool_mcp("stats", {}))
        assert stats["structuredContent"]["count"] == 4
        host = dump(await client.call_tool_mcp("host_tool", {"x": 1}))
        assert "2" in host["content"][0]["text"]


async def test_resources_templates_prompts_completions() -> None:
    layer, server = make_server()
    async with fastmcp.Client(server) as client:
        uris = [str(r.uri) for r in await client.list_resources()]
        assert "test://info" in uris
        templates = [
            t.uriTemplate if hasattr(t, "uriTemplate") else t.uri_template
            for t in await client.list_resource_templates()
        ]
        assert "test://items/{item_id}" in templates
        info = await client.read_resource("test://info")
        assert '"hello"' in info[0].text
        item = await client.read_resource("test://items/delta")
        assert '"index": 3' in item[0].text
        prompt = dump(await client.get_prompt("greet", {"name": "Bo"}))
        assert prompt["messages"][0]["content"]["text"] == "Hi Bo!"
        import mcp.types as T

        ref_cls = getattr(T, "ResourceTemplateReference", None) or T.ResourceReference
        completion = await client.complete(
            ref_cls(type="ref/resource", uri="test://items/{item_id}"),
            {"name": "item_id", "value": "d"},
        )
        assert completion.values == ["delta"]
        prompt_completion = await client.complete(
            T.PromptReference(type="ref/prompt", name="greet"), {"name": "name", "value": "b"}
        )
        assert prompt_completion.values == ["beta"]


async def test_policy_filters_lists_and_calls() -> None:
    layer, server = make_server()
    policy = layer.policy

    def is_allowed(spec: Any, principal: Any = None) -> bool:
        return spec.name not in ("fail", "info")

    policy.is_allowed = is_allowed  # type: ignore[method-assign]
    async with fastmcp.Client(server) as client:
        names = [t.name for t in await client.list_tools()]
        assert "fail" not in names and "echo" in names and "host_tool" in names
        uris = [str(r.uri) for r in await client.list_resources()]
        assert "test://info" not in uris
        hidden = dump(await client.call_tool_mcp("fail", {}))
        assert hidden.get("isError") is True or "Unknown" in str(hidden)


async def test_principal_resolver_is_used() -> None:
    layer = build_layer()
    server = fastmcp.FastMCP("host")
    seen: list[Principal] = []

    async def spy(info: Any, call_next: Any) -> Any:
        seen.append(info.principal)
        return await call_next(info)

    layer.use(spy)
    register_into(
        layer, server, principal_resolver=lambda info: Principal(id="resolved", roles={"r1"})
    )
    async with fastmcp.Client(server) as client:
        await client.call_tool_mcp("echo", {"text": "x"})
    assert seen and seen[0].id == "resolved"


async def test_prefix_and_build_server() -> None:
    layer = build_layer()
    server = fastmcp.FastMCP("host")
    register_into(layer, server, prefix="cg_")
    async with fastmcp.Client(server) as client:
        names = [t.name for t in await client.list_tools()]
        assert "cg_echo" in names and "echo" not in names
        result = dump(await client.call_tool_mcp("cg_echo", {"text": "p"}))
        assert result["structuredContent"] == {"text": "p"}
        prompt = dump(await client.get_prompt("cg_greet", {"name": "Q"}))
        assert prompt["messages"][0]["content"]["text"] == "Hi Q!"

    built = build_server(build_layer(), "fastmcp")
    async with fastmcp.Client(built) as client:
        assert "echo" in [t.name for t in await client.list_tools()]


def _legacy_client(server: Any, **kwargs: Any) -> Any:
    """fastmcp 4 negotiates 2026-07-28 by default, where change
    notifications only travel on subscriptions/listen streams; pin the
    handshake era for the session-notification test."""
    import inspect

    if "mode" in inspect.signature(fastmcp.Client.__init__).parameters:
        kwargs["mode"] = "legacy"
    return fastmcp.Client(server, **kwargs)


async def test_change_notifications() -> None:
    layer, server = make_server()
    received: list[Any] = []

    async def handler(message: Any) -> None:
        received.append(message)

    async with _legacy_client(server, message_handler=handler) as client:
        await client.session.subscribe_resource("test://info")
        await client.call_tool_mcp("touch", {"uri": "test://info"})
        for _ in range(100):
            if any("ResourceUpdated" in repr(m) for m in received) and any(
                "ToolListChanged" in repr(m) for m in received
            ):
                break
            await asyncio.sleep(0.02)
    assert any("ToolListChanged" in repr(m) for m in received)
    assert any("ResourceUpdated" in repr(m) for m in received)


async def test_listen_stream_on_modern_fastmcp() -> None:
    subs = pytest.importorskip("mcp.client.subscriptions")
    _, server = make_server()
    async with fastmcp.Client(server) as client:
        if client.session.protocol_version != "2026-07-28":
            pytest.skip("fastmcp client negotiated a handshake-era version")
        async with subs.listen(client.session, tools_list_changed=True) as sub:
            await client.call_tool_mcp("touch", {})
            event = await asyncio.wait_for(sub.__anext__(), 5)
            assert type(event).__name__ == "ToolsListChanged"
