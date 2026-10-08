"""Protocol-engine tests for the dependency-free native MCP server
(:mod:`cloudg.mcp.native.protocol`), driven in memory through
:meth:`Session.handle`."""

from __future__ import annotations

import asyncio
from typing import Any

import pytest

from cloudg.mcp.native import NativeMCPServer
from cloudg.mcp.native.jsonrpc import (
    CLIENT_CAPABILITIES_META_KEY,
    LOG_LEVEL_META_KEY,
    PROTOCOL_VERSION_META_KEY,
    SERVER_INFO_META_KEY,
    SUBSCRIPTION_ID_META_KEY,
)
from tests.mcp._adapter_testkit import build_layer

MODERN = "2026-07-28"
ENVELOPE = {PROTOCOL_VERSION_META_KEY: MODERN, CLIENT_CAPABILITIES_META_KEY: {}}


class Harness:
    def __init__(self, page_size: int = 100, **layer_kwargs: Any) -> None:
        self.layer = build_layer(**layer_kwargs)
        self.server = NativeMCPServer(self.layer, page_size=page_size)
        self.sent: list[dict[str, Any]] = []
        self.session = self.server.create_session(send=self._send)
        self._id = 0

    async def _send(self, msg: dict[str, Any]) -> None:
        self.sent.append(msg)

    async def request(self, method: str, params: dict[str, Any] | None = None,
                      **kw: Any) -> dict[str, Any]:
        self._id += 1
        msg: dict[str, Any] = {"jsonrpc": "2.0", "id": self._id, "method": method}
        if params is not None:
            msg["params"] = params
        resp = await self.session.handle(msg, **kw)
        assert resp is not None and resp["id"] == self._id
        return resp

    async def notify(self, method: str, params: dict[str, Any] | None = None) -> None:
        msg: dict[str, Any] = {"jsonrpc": "2.0", "method": method}
        if params is not None:
            msg["params"] = params
        assert await self.session.handle(msg) is None

    async def init(self, version: str = "2025-11-25") -> dict[str, Any]:
        resp = await self.request("initialize", {
            "protocolVersion": version, "capabilities": {},
            "clientInfo": {"name": "pytest", "version": "1"},
        })
        await self.notify("notifications/initialized")
        return resp

    async def modern(self, method: str, params: dict[str, Any] | None = None,
                     meta: dict[str, Any] | None = None) -> dict[str, Any]:
        p = dict(params or {})
        p["_meta"] = {**ENVELOPE, **(meta or {})}
        return await self.request(method, p)

    def notifications(self, method: str) -> list[dict[str, Any]]:
        return [m for m in self.sent if m.get("method") == method]


@pytest.fixture
def h() -> Harness:
    return Harness()


# ---------------------------------------------------------------------------
# Lifecycle
# ---------------------------------------------------------------------------


async def test_initialize_negotiates_and_advertises(h: Harness) -> None:
    resp = await h.init("2025-06-18")
    result = resp["result"]
    assert result["protocolVersion"] == "2025-06-18"
    caps = result["capabilities"]
    assert caps["tools"] == {"listChanged": True}
    assert caps["resources"] == {"subscribe": True, "listChanged": True}
    assert caps["prompts"] == {"listChanged": True}
    assert "logging" in caps and "completions" in caps
    assert result["serverInfo"]["name"] == "cloudg"
    assert result["instructions"]
    assert h.session.initialized


async def test_unknown_version_counter_offers_latest(h: Harness) -> None:
    resp = await h.init("1999-01-01")
    assert resp["result"]["protocolVersion"] == "2025-11-25"


async def test_2024_version_has_no_completions_capability(h: Harness) -> None:
    resp = await h.init("2024-11-05")
    assert "completions" not in resp["result"]["capabilities"]


async def test_requests_before_initialize_are_rejected_but_ping_works(h: Harness) -> None:
    resp = await h.request("tools/list")
    assert resp["error"]["code"] == -32600
    assert (await h.request("ping"))["result"] == {}


async def test_double_initialize_rejected(h: Harness) -> None:
    await h.init()
    resp = await h.request("initialize", {"protocolVersion": "2025-11-25", "capabilities": {}})
    assert resp["error"]["code"] == -32600


async def test_unknown_method(h: Harness) -> None:
    await h.init()
    resp = await h.request("tools/frobnicate")
    assert resp["error"]["code"] == -32601


# ---------------------------------------------------------------------------
# JSON-RPC framing
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("msg", [
    {"id": 1, "method": "ping"},                       # missing jsonrpc
    {"jsonrpc": "1.0", "id": 1, "method": "ping"},     # wrong version
    {"jsonrpc": "2.0", "id": None, "method": "ping"},  # null id
    {"jsonrpc": "2.0", "id": True, "method": "ping"},  # bool id
    {"jsonrpc": "2.0", "id": 1, "method": 5},          # non-string method
    "garbage",
])
async def test_invalid_requests(h: Harness, msg: Any) -> None:
    resp = await h.session.handle(msg)
    assert resp["error"]["code"] == -32600


async def test_params_must_be_object(h: Harness) -> None:
    await h.init()
    resp = await h.session.handle({"jsonrpc": "2.0", "id": 9, "method": "tools/list",
                                   "params": [1, 2]})
    assert resp["error"]["code"] == -32602


async def test_client_responses_are_ignored(h: Harness) -> None:
    await h.init()
    assert await h.session.handle({"jsonrpc": "2.0", "id": 7, "result": {}}) is None


async def test_batches_allowed_only_for_2025_03_26() -> None:
    old = Harness()
    await old.init("2025-03-26")
    out = await old.session.handle([
        {"jsonrpc": "2.0", "id": 1, "method": "ping"},
        {"jsonrpc": "2.0", "method": "notifications/progress", "params": {}},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
    ])
    assert isinstance(out, list) and [r["id"] for r in out] == [1, 2]

    new = Harness()
    await new.init("2025-06-18")
    out = await new.session.handle([{"jsonrpc": "2.0", "id": 1, "method": "ping"}])
    assert out["error"]["code"] == -32600 and out["id"] is None
    assert (await new.session.handle([]))["error"]["code"] == -32600


async def test_batch_before_initialize_rejected(h: Harness) -> None:
    out = await h.session.handle([{"jsonrpc": "2.0", "id": 1, "method": "initialize",
                                   "params": {"protocolVersion": "2025-03-26"}}])
    assert out["error"]["code"] == -32600


# ---------------------------------------------------------------------------
# Tools
# ---------------------------------------------------------------------------


async def test_tools_list_exact_wire_and_pagination() -> None:
    hh = Harness(page_size=3)
    await hh.init()
    names: list[str] = []
    tools: list[dict[str, Any]] = []
    cursor = None
    pages = 0
    while True:
        params = {"cursor": cursor} if cursor else {}
        result = (await hh.request("tools/list", params))["result"]
        tools += result["tools"]
        pages += 1
        cursor = result.get("nextCursor")
        if not cursor:
            break
    names = [t["name"] for t in tools]
    assert pages == 3
    assert tools == hh.layer.tools_wire()
    echo = next(t for t in tools if t["name"] == "echo")
    assert echo["annotations"]["readOnlyHint"] is True
    assert echo["inputSchema"]["properties"]["times"]["maximum"] == 5
    assert names == sorted(names, key=names.index)  # deterministic order
    bad = await hh.request("tools/list", {"cursor": "not-a-cursor"})
    assert bad["error"]["code"] == -32602


async def test_tool_call_structured_and_errors(h: Harness) -> None:
    await h.init()
    ok = (await h.request("tools/call", {"name": "echo",
                                         "arguments": {"text": "ab", "times": 2}}))["result"]
    assert ok["structuredContent"] == {"text": "abab"}
    assert ok["isError"] is False
    assert ok["content"][0]["type"] == "text"

    bad_args = (await h.request("tools/call", {"name": "echo",
                                               "arguments": {"times": 9}}))["result"]
    assert bad_args["isError"] is True  # validation errors are tool errors (SEP-1303)

    failing = (await h.request("tools/call", {"name": "fail"}))["result"]
    assert failing["isError"] is True

    unknown = await h.request("tools/call", {"name": "nope"})
    assert unknown["error"]["code"] == -32602

    missing = await h.request("tools/call", {})
    assert missing["error"]["code"] == -32602
    bad_type = await h.request("tools/call", {"name": "echo", "arguments": [1]})
    assert bad_type["error"]["code"] == -32602


async def test_resource_links_in_tool_result(h: Harness) -> None:
    await h.init()
    result = (await h.request("tools/call", {"name": "linked"}))["result"]
    links = [c for c in result["content"] if c["type"] == "resource_link"]
    assert links and links[0]["uri"] == "test://items/alpha"


async def test_progress_and_log_notifications(h: Harness) -> None:
    await h.init()
    result = (await h.request("tools/call", {"name": "slow", "arguments": {"steps": 3},
                                             "_meta": {"progressToken": "tok"}}))["result"]
    assert result["structuredContent"] == {"done": 3}
    progress = h.notifications("notifications/progress")
    assert [p["params"]["progress"] for p in progress] == [1, 2, 3]
    assert all(p["params"]["progressToken"] == "tok" and p["params"]["total"] == 3
               for p in progress)
    logs = h.notifications("notifications/message")
    assert len(logs) == 3 and logs[0]["params"]["level"] == "info"
    assert logs[0]["params"]["data"] == {"step": 1}


async def test_no_progress_without_token_and_set_level(h: Harness) -> None:
    await h.init()
    assert (await h.request("logging/setLevel", {"level": "warning"}))["result"] == {}
    await h.request("tools/call", {"name": "slow", "arguments": {"steps": 2}})
    assert h.notifications("notifications/progress") == []
    assert h.notifications("notifications/message") == []
    bad = await h.request("logging/setLevel", {"level": "loud"})
    assert bad["error"]["code"] == -32602


async def test_request_sink_receives_request_scoped_notifications(h: Harness) -> None:
    await h.init()
    sink: list[dict[str, Any]] = []

    async def collect(msg: dict[str, Any]) -> None:
        sink.append(msg)

    await h.request("tools/call", {"name": "slow", "arguments": {"steps": 1},
                                   "_meta": {"progressToken": 5}}, sink=collect)
    assert {m["method"] for m in sink} == {"notifications/progress", "notifications/message"}
    assert h.sent == []


async def test_cancellation_suppresses_response(h: Harness) -> None:
    await h.init()
    task = asyncio.create_task(h.session.handle(
        {"jsonrpc": "2.0", "id": "slow-1", "method": "tools/call",
         "params": {"name": "sleepy", "arguments": {"seconds": 30}}}
    ))
    await asyncio.sleep(0.05)
    await h.notify("notifications/cancelled", {"requestId": "slow-1", "reason": "user"})
    assert await asyncio.wait_for(task, 2) is None
    # unknown ids are ignored
    await h.notify("notifications/cancelled", {"requestId": "nope"})


# ---------------------------------------------------------------------------
# Resources, prompts, completions
# ---------------------------------------------------------------------------


async def test_resources(h: Harness) -> None:
    await h.init()
    listing = (await h.request("resources/list"))["result"]["resources"]
    assert listing == h.layer.resources_wire()
    templates = (await h.request("resources/templates/list"))["result"]["resourceTemplates"]
    assert templates[0]["uriTemplate"] == "test://items/{item_id}"
    contents = (await h.request("resources/read",
                                {"uri": "test://items/beta"}))["result"]["contents"]
    assert contents[0]["uri"] == "test://items/beta" and '"index": 1' in contents[0]["text"]
    missing = await h.request("resources/read", {"uri": "test://items/zeta"})
    assert missing["error"]["code"] == -32002
    assert missing["error"]["data"] == {"uri": "test://items/zeta"}
    unknown = await h.request("resources/read", {"uri": "other://x"})
    assert unknown["error"]["code"] == -32002


async def test_prompts_and_completions(h: Harness) -> None:
    await h.init()
    prompts = (await h.request("prompts/list"))["result"]["prompts"]
    assert prompts[0]["name"] == "greet" and prompts[0]["arguments"][0]["required"] is True
    got = (await h.request("prompts/get", {"name": "greet",
                                           "arguments": {"name": "Ann"}}))["result"]
    assert got["messages"][0]["content"]["text"] == "Hi Ann!"
    missing = await h.request("prompts/get", {"name": "greet", "arguments": {}})
    assert missing["error"]["code"] == -32602
    unknown = await h.request("prompts/get", {"name": "nope"})
    assert unknown["error"]["code"] == -32602

    comp = (await h.request("completion/complete", {
        "ref": {"type": "ref/resource", "uri": "test://items/{item_id}"},
        "argument": {"name": "item_id", "value": "a"},
    }))["result"]["completion"]
    assert comp["values"] == ["alpha"]
    comp = (await h.request("completion/complete", {
        "ref": {"type": "ref/prompt", "name": "greet"},
        "argument": {"name": "name", "value": "g"},
    }))["result"]["completion"]
    assert comp["values"] == ["gamma"]
    bad = await h.request("completion/complete", {"ref": {"type": "ref/x"},
                                                  "argument": {"name": "a"}})
    assert bad["error"]["code"] == -32602


async def test_change_notifications_respect_subscriptions(h: Harness) -> None:
    await h.init()
    await h.request("resources/subscribe", {"uri": "test://info"})
    h.layer.notify_change("resource", "test://info")
    h.layer.notify_change("resource", "test://other")
    h.layer.notify_change("tools")
    h.layer.notify_change("prompts")
    h.layer.notify_change("resources")
    await asyncio.sleep(0.05)
    methods = [m["method"] for m in h.sent]
    assert methods.count("notifications/resources/updated") == 1
    assert h.notifications("notifications/resources/updated")[0]["params"] == {
        "uri": "test://info"}
    assert "notifications/tools/list_changed" in methods
    assert "notifications/prompts/list_changed" in methods
    assert "notifications/resources/list_changed" in methods
    await h.request("resources/unsubscribe", {"uri": "test://info"})
    h.sent.clear()
    h.layer.notify_change("resource", "test://info")
    await asyncio.sleep(0.05)
    assert h.sent == []


async def test_change_from_worker_thread(h: Harness) -> None:
    """``touch`` is a sync handler (runs in a thread) that calls notify_change."""
    await h.init()
    await h.request("resources/subscribe", {"uri": "test://info"})
    await h.request("tools/call", {"name": "touch", "arguments": {"uri": "test://info"}})
    for _ in range(50):
        if h.notifications("notifications/resources/updated"):
            break
        await asyncio.sleep(0.01)
    assert h.notifications("notifications/resources/updated")
    assert h.notifications("notifications/tools/list_changed")


async def test_no_change_notifications_before_initialized(h: Harness) -> None:
    h.layer.notify_change("tools")
    await asyncio.sleep(0.02)
    assert h.sent == []


# ---------------------------------------------------------------------------
# 2026-07-28 stateless era
# ---------------------------------------------------------------------------


async def test_discover_and_modern_stamps(h: Harness) -> None:
    disc = (await h.modern("server/discover"))["result"]
    assert MODERN in disc["supportedVersions"] and "2025-11-25" in disc["supportedVersions"]
    assert disc["resultType"] == "complete"
    assert disc["_meta"][SERVER_INFO_META_KEY]["name"] == "cloudg"
    tools = (await h.modern("tools/list"))["result"]
    assert tools["ttlMs"] == 0 and tools["cacheScope"] == "private"
    assert tools["resultType"] == "complete"
    call = (await h.modern("tools/call", {"name": "echo", "arguments": {"text": "z"}}))["result"]
    assert call["resultType"] == "complete" and "ttlMs" not in call
    assert call["_meta"][SERVER_INFO_META_KEY]["version"]
    read = (await h.modern("resources/read", {"uri": "test://info"}))["result"]
    assert read["cacheScope"] == "private"
    missing = await h.modern("resources/read", {"uri": "test://items/zeta"})
    assert missing["error"]["code"] == -32602  # not -32002 on 2026-07-28


async def test_modern_envelope_validation(h: Harness) -> None:
    resp = await h.request("tools/list", {"_meta": {PROTOCOL_VERSION_META_KEY: MODERN}})
    assert resp["error"]["code"] == -32602
    resp = await h.request("tools/list", {"_meta": {PROTOCOL_VERSION_META_KEY: "2099-01-01",
                                                    CLIENT_CAPABILITIES_META_KEY: {}}})
    assert resp["error"]["code"] == -32022
    assert resp["error"]["data"] == {"supported": [MODERN], "requested": "2099-01-01"}


async def test_modern_only_and_legacy_only_methods(h: Harness) -> None:
    assert (await h.modern("ping"))["error"]["code"] == -32601
    assert (await h.modern("logging/setLevel", {"level": "info"}))["error"]["code"] == -32601
    assert (await h.modern("resources/subscribe", {"uri": "x"}))["error"]["code"] == -32601
    # the connection is now modern: the handshake is refused, un-enveloped calls too
    resp = await h.request("initialize", {"protocolVersion": "2025-11-25", "capabilities": {}})
    assert resp["error"]["code"] == -32022
    assert (await h.request("tools/list"))["error"]["code"] == -32602

    legacy = Harness()
    await legacy.init()
    assert (await legacy.modern("tools/list"))["error"]["code"] == -32600
    assert (await legacy.request("server/discover"))["error"]["code"] == -32601


async def test_modern_logging_requires_opt_in(h: Harness) -> None:
    await h.modern("tools/call", {"name": "slow", "arguments": {"steps": 1}})
    assert h.notifications("notifications/message") == []
    await h.modern("tools/call", {"name": "slow", "arguments": {"steps": 1}},
                   meta={LOG_LEVEL_META_KEY: "debug", "progressToken": "p"})
    assert len(h.notifications("notifications/message")) == 1
    assert len(h.notifications("notifications/progress")) == 1
    h.sent.clear()
    await h.modern("tools/call", {"name": "slow", "arguments": {"steps": 1}},
                   meta={LOG_LEVEL_META_KEY: "error"})
    assert h.notifications("notifications/message") == []


async def test_subscriptions_listen(h: Harness) -> None:
    frames: list[dict[str, Any]] = []

    async def sink(msg: dict[str, Any]) -> None:
        frames.append(msg)

    listen = asyncio.create_task(h.session.handle({
        "jsonrpc": "2.0", "id": "L1", "method": "subscriptions/listen",
        "params": {"_meta": ENVELOPE, "notifications": {
            "toolsListChanged": True, "promptsListChanged": False,
            "resourceSubscriptions": ["test://info"]}},
    }, sink=sink))
    for _ in range(50):
        if frames:
            break
        await asyncio.sleep(0.01)
    ack = frames[0]
    assert ack["method"] == "notifications/subscriptions/acknowledged"
    assert ack["params"]["notifications"] == {"toolsListChanged": True,
                                              "resourceSubscriptions": ["test://info"]}
    assert ack["params"]["_meta"][SUBSCRIPTION_ID_META_KEY] == "L1"
    h.layer.notify_change("tools")
    h.layer.notify_change("prompts")  # not requested
    h.layer.notify_change("resource", "test://info")
    h.layer.notify_change("resource", "test://other")
    await asyncio.sleep(0.05)
    methods = [f["method"] for f in frames[1:]]
    assert methods == ["notifications/tools/list_changed", "notifications/resources/updated"]
    assert all(f["params"]["_meta"][SUBSCRIPTION_ID_META_KEY] == "L1" for f in frames[1:])
    h.server.close_listens()
    final = await asyncio.wait_for(listen, 2)
    assert final["result"]["_meta"][SUBSCRIPTION_ID_META_KEY] == "L1"
    assert final["result"]["resultType"] == "complete"


# ---------------------------------------------------------------------------
# Wire validation against the official schema (when mcp_types is installed)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("version", ["2024-11-05", "2025-03-26", "2025-06-18", "2025-11-25",
                                     MODERN])
async def test_results_validate_against_sdk_schema(version: str) -> None:
    methods = pytest.importorskip("mcp_types.methods")
    hh = Harness()
    if version != MODERN:
        init = await hh.init(version)
        methods.serialize_server_result("initialize", version, init["result"])

    async def call(method: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        if version == MODERN:
            resp = await hh.modern(method, params)
        else:
            resp = await hh.request(method, params)
        assert "result" in resp, resp
        methods.serialize_server_result(method, version, resp["result"])
        return resp["result"]

    await call("tools/list")
    await call("tools/call", {"name": "echo", "arguments": {"text": "x"}})
    await call("tools/call", {"name": "fail"})
    await call("tools/call", {"name": "linked"})
    await call("resources/list")
    await call("resources/templates/list")
    await call("resources/read", {"uri": "test://info"})
    await call("prompts/list")
    await call("prompts/get", {"name": "greet", "arguments": {"name": "x"}})
    await call("completion/complete", {"ref": {"type": "ref/prompt", "name": "greet"},
                                       "argument": {"name": "name", "value": ""}})
    if version == MODERN:
        await call("server/discover")
