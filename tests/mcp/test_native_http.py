"""Streamable HTTP / legacy SSE transport tests for the native MCP server,
over real localhost sockets with :mod:`urllib` (and the official SDK client
when it is installed)."""

from __future__ import annotations

import asyncio
import json
import time
import urllib.error
import urllib.request
from typing import Any, Callable

import pytest

from cloudg.mcp.native import HTTPConfig, NativeHTTPServer, NativeMCPServer, TokenAuth
from cloudg.mcp.native.jsonrpc import CLIENT_CAPABILITIES_META_KEY, PROTOCOL_VERSION_META_KEY
from tests.mcp._adapter_testkit import build_layer

ACCEPT_BOTH = "application/json, text/event-stream"
MODERN = "2026-07-28"
ENVELOPE = {PROTOCOL_VERSION_META_KEY: MODERN, CLIENT_CAPABILITIES_META_KEY: {}}


def _blocking(
    url: str, method: str, body: Any, headers: dict[str, str], timeout: float
) -> tuple[int, dict[str, str], bytes]:
    data = body if isinstance(body, bytes) or body is None else json.dumps(body).encode()
    req = urllib.request.Request(url, data=data, method=method, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, {k.lower(): v for k, v in resp.headers.items()}, resp.read()
    except urllib.error.HTTPError as exc:
        return exc.code, {k.lower(): v for k, v in exc.headers.items()}, exc.read()


async def http(
    url: str,
    method: str = "POST",
    body: Any = None,
    headers: dict[str, str] | None = None,
    timeout: float = 10,
) -> tuple[int, dict[str, str], bytes]:
    h = {"Accept": ACCEPT_BOTH}
    if body is not None:
        h["Content-Type"] = "application/json"
    h.update(headers or {})
    return await asyncio.to_thread(_blocking, url, method, body, h, timeout)


def sse_events(raw: bytes) -> list[tuple[str | None, str]]:
    events = []
    for block in raw.decode().split("\n\n"):
        name, data = None, []
        for line in block.splitlines():
            if line.startswith("event:"):
                name = line[6:].strip()
            elif line.startswith("data:"):
                data.append(line[5:].lstrip())
        if data:
            events.append((name, "\n".join(data)))
    return events


def sse_messages(raw: bytes) -> list[dict[str, Any]]:
    return [json.loads(d) for name, d in sse_events(raw) if name in (None, "message")]


class Srv:
    def __init__(self, http_server: NativeHTTPServer) -> None:
        self.http = http_server
        self.url = http_server.url
        self.base = self.url.rsplit("/mcp", 1)[0]
        self.layer = http_server.mcp.layer
        self._id = 0

    def rpc(self, method: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        self._id += 1
        msg: dict[str, Any] = {"jsonrpc": "2.0", "id": self._id, "method": method}
        if params is not None:
            msg["params"] = params
        return msg

    async def initialize(
        self, version: str = "2025-11-25", headers: dict[str, str] | None = None
    ) -> str:
        status, hdrs, body = await http(
            self.url,
            body=self.rpc(
                "initialize",
                {
                    "protocolVersion": version,
                    "capabilities": {},
                    "clientInfo": {"name": "urllib", "version": "1"},
                },
            ),
            headers=headers,
        )
        assert status == 200, body
        assert json.loads(body)["result"]["protocolVersion"] == version
        sid = hdrs["mcp-session-id"]
        status, _, body = await http(
            self.url,
            body={"jsonrpc": "2.0", "method": "notifications/initialized"},
            headers={"Mcp-Session-Id": sid, **(headers or {})},
        )
        assert status == 202 and body == b""
        return sid


@pytest.fixture
async def make_server() -> Any:
    servers: list[NativeHTTPServer] = []

    async def factory(**cfg: Any) -> Srv:
        cfg.setdefault("port", 0)
        cfg.setdefault("keepalive_interval", 0.3)
        server = NativeHTTPServer(NativeMCPServer(build_layer()), HTTPConfig(**cfg))
        await server.start()
        servers.append(server)
        return Srv(server)

    yield factory
    for s in servers:
        await s.aclose()


# ---------------------------------------------------------------------------
# Sessions and message flow
# ---------------------------------------------------------------------------


async def test_session_lifecycle_json_and_sse(make_server: Callable[..., Any]) -> None:
    srv = await make_server()
    sid = await srv.initialize()
    headers = {"Mcp-Session-Id": sid, "MCP-Protocol-Version": "2025-11-25"}

    status, hdrs, body = await http(srv.url, body=srv.rpc("tools/list"), headers=headers)
    assert status == 200 and hdrs["content-type"].startswith("application/json")
    assert [t["name"] for t in json.loads(body)["result"]["tools"]][:2] == ["echo", "stats"]

    # tools/call may stream: SSE with progress notifications, then the response
    call = srv.rpc(
        "tools/call", {"name": "slow", "arguments": {"steps": 2}, "_meta": {"progressToken": "t1"}}
    )
    status, hdrs, body = await http(srv.url, body=call, headers=headers)
    assert status == 200 and hdrs["content-type"].startswith("text/event-stream")
    msgs = sse_messages(body)
    assert [m.get("method") for m in msgs[:-1]].count("notifications/progress") == 2
    assert msgs[-1]["id"] == call["id"] and msgs[-1]["result"]["structuredContent"] == {"done": 2}

    # a client that only accepts JSON gets JSON
    status, hdrs, body = await http(
        srv.url,
        body=srv.rpc("tools/call", {"name": "echo", "arguments": {"text": "hi"}}),
        headers={**headers, "Accept": "application/json"},
    )
    assert hdrs["content-type"].startswith("application/json")
    assert json.loads(body)["result"]["structuredContent"] == {"text": "hi"}

    # DELETE ends the session
    status, _, _ = await http(srv.url, method="DELETE", headers=headers)
    assert status == 200
    status, _, _ = await http(srv.url, body=srv.rpc("tools/list"), headers=headers)
    assert status == 404


async def test_session_errors(make_server: Callable[..., Any]) -> None:
    srv = await make_server()
    sid = await srv.initialize("2025-06-18")
    status, _, _ = await http(srv.url, body=srv.rpc("tools/list"))
    assert status == 400  # missing Mcp-Session-Id
    status, _, _ = await http(
        srv.url, body=srv.rpc("tools/list"), headers={"Mcp-Session-Id": "deadbeef"}
    )
    assert status == 404
    status, _, _ = await http(
        srv.url,
        body=srv.rpc("tools/list"),
        headers={"Mcp-Session-Id": sid, "MCP-Protocol-Version": "2025-11-25"},
    )
    assert status == 400  # differs from the negotiated version
    status, _, _ = await http(
        srv.url,
        body=srv.rpc("tools/list"),
        headers={"Mcp-Session-Id": sid, "MCP-Protocol-Version": "1999-01-01"},
    )
    assert status == 400
    status, _, body = await http(
        srv.url, body=srv.rpc("tools/list"), headers={"Mcp-Session-Id": sid}
    )
    assert status == 200 and "result" in json.loads(body)  # header optional


async def test_request_validation(make_server: Callable[..., Any]) -> None:
    srv = await make_server(max_body_bytes=2048)
    status, _, _ = await http(srv.url, body=b"{}", headers={"Content-Type": "text/plain"})
    assert status == 415
    status, _, _ = await http(srv.url, body=srv.rpc("ping"), headers={"Accept": "text/html"})
    assert status == 406
    status, _, body = await http(srv.url, body=b"{not json")
    assert status == 400 and json.loads(body)["error"]["code"] == -32700
    status, _, _ = await http(srv.url, body=b"x" * 5000)
    assert status == 413
    status, _, _ = await http(srv.url, method="PUT", body=b"{}")
    assert status == 405
    status, _, _ = await http(srv.base + "/elsewhere", method="GET")
    assert status == 404
    status, _, body = await http(srv.base + "/healthz", method="GET")
    assert status == 200 and json.loads(body) == {"status": "ok"}


async def test_dns_rebinding_protection(make_server: Callable[..., Any]) -> None:
    srv = await make_server()
    init = srv.rpc("initialize", {"protocolVersion": "2025-11-25", "capabilities": {}})
    status, _, _ = await http(srv.url, body=init, headers={"Origin": "https://evil.example"})
    assert status == 403
    status, _, _ = await http(srv.url, body=init, headers={"Host": "evil.example:80"})
    assert status == 421
    status, _, _ = await http(srv.url, body=init, headers={"Origin": "http://localhost:3000"})
    assert status == 200


def test_origin_host_guard_rules() -> None:
    from cloudg.mcp.native.http import OriginHostGuard

    loopback = OriginHostGuard("127.0.0.1")
    assert loopback.check("127.0.0.1:8765", None) is None
    assert loopback.check("evil.example", None) == (421, "Invalid Host header")
    assert loopback.check("localhost:1", "https://evil.example")[0] == 403
    # a public bind relaxes only the Host check; Origin stays enforced
    public = OriginHostGuard("0.0.0.0")
    assert public.check("mcp.example.com", None) is None
    assert public.check("mcp.example.com", "https://evil.example")[0] == 403
    # DNS rebinding: with no Host allow-list the attacker's rebound name is
    # both Host and Origin, so same-origin is not accepted there
    assert public.check("attacker.example:8765", "http://attacker.example:8765")[0] == 403
    assert public.check("mcp.example.com", "http://localhost:3000") is None
    pinned = OriginHostGuard("0.0.0.0", None, ["mcp.example.com"])
    assert pinned.check("mcp.example.com", "https://mcp.example.com") is None  # same-origin
    custom = OriginHostGuard("0.0.0.0", ["https://app.example"], ["mcp.example.com"])
    assert custom.check("other.example", None)[0] == 421
    assert custom.check("mcp.example.com", "https://app.example") is None
    assert custom.check("mcp.example.com", "http://localhost:3000")[0] == 403


async def test_custom_origin_and_cors(make_server: Callable[..., Any]) -> None:
    srv = await make_server(cors_origins=["https://app.example"])
    status, hdrs, _ = await http(
        srv.url, method="OPTIONS", headers={"Origin": "https://app.example"}
    )
    assert status == 204
    assert hdrs["access-control-allow-origin"] == "https://app.example"
    assert "mcp-session-id" in hdrs["access-control-allow-headers"].lower()
    status, hdrs, _ = await http(
        srv.url,
        body=srv.rpc("initialize", {"protocolVersion": "2025-11-25", "capabilities": {}}),
        headers={"Origin": "https://app.example"},
    )
    assert status == 200 and "mcp-session-id" in hdrs["access-control-expose-headers"].lower()
    plain = await make_server()
    status, _, _ = await http(plain.url, method="OPTIONS")
    assert status == 405


async def test_bearer_tokens_and_session_binding(make_server: Callable[..., Any]) -> None:
    auth = TokenAuth({"tok-a": "analyst", "tok-b": "admin,analyst"})
    srv = await make_server(auth=auth)
    init = srv.rpc("initialize", {"protocolVersion": "2025-11-25", "capabilities": {}})
    status, hdrs, _ = await http(srv.url, body=init)
    assert status == 401 and hdrs["www-authenticate"].startswith("Bearer")
    status, _, _ = await http(srv.url, body=init, headers={"Authorization": "Bearer wrong"})
    assert status == 401
    sid = await srv.initialize(headers={"Authorization": "Bearer tok-a"})
    ok = {"Mcp-Session-Id": sid, "Authorization": "Bearer tok-a"}
    status, _, _ = await http(srv.url, body=srv.rpc("tools/list"), headers=ok)
    assert status == 200
    stolen = {"Mcp-Session-Id": sid, "Authorization": "Bearer tok-b"}
    status, _, _ = await http(srv.url, body=srv.rpc("tools/list"), headers=stolen)
    assert status == 404  # sessions are bound to the principal that created them
    status, _, _ = await http(srv.base + "/healthz", method="GET")
    assert status == 200  # health stays unauthenticated


async def test_token_principal_reaches_the_layer(make_server: Callable[..., Any]) -> None:
    srv = await make_server(auth=TokenAuth({"tok": "auditor"}))
    seen: list[Any] = []

    async def spy(info: Any, call_next: Any) -> Any:
        seen.append(info.principal)
        return await call_next(info)

    srv.layer.use(spy)
    sid = await srv.initialize(headers={"Authorization": "Bearer tok"})
    await http(
        srv.url,
        body=srv.rpc("tools/call", {"name": "echo", "arguments": {"text": "x"}}),
        headers={
            "Mcp-Session-Id": sid,
            "Authorization": "Bearer tok",
            "Accept": "application/json",
        },
    )
    assert seen and "auditor" in seen[0].roles and seen[0].id.startswith("token-")


# ---------------------------------------------------------------------------
# Server -> client streams
# ---------------------------------------------------------------------------


def _read_stream_until(
    url: str, headers: dict[str, str], predicate: Callable[[list], bool], timeout: float
) -> list[tuple[str | None, str]]:
    req = urllib.request.Request(url, method="GET", headers=headers)
    events: list[tuple[str | None, str]] = []
    deadline = time.monotonic() + timeout
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        buf = b""
        while time.monotonic() < deadline:
            line = resp.readline()
            if not line:
                break
            buf += line
            if line in (b"\n", b"\r\n"):
                events.extend(sse_events(buf))
                buf = b""
                if predicate(events):
                    break
    return events


async def test_get_stream_delivers_change_notifications(make_server: Callable[..., Any]) -> None:
    srv = await make_server()
    sid = await srv.initialize()
    headers = {"Mcp-Session-Id": sid, "Accept": "text/event-stream"}
    await http(
        srv.url,
        body=srv.rpc("resources/subscribe", {"uri": "test://info"}),
        headers={"Mcp-Session-Id": sid},
    )

    def got_both(events: list) -> bool:
        methods = {json.loads(d).get("method") for _, d in events}
        return {"notifications/resources/updated", "notifications/tools/list_changed"} <= methods

    reader = asyncio.create_task(
        asyncio.to_thread(_read_stream_until, srv.url, headers, got_both, 8)
    )
    for _ in range(100):
        if any(hs.stream_open for hs in srv.http._sessions.values()):
            break
        await asyncio.sleep(0.02)
    status, _, _ = await http(srv.url, method="GET", headers=headers)
    assert status == 409  # one standalone stream per session
    await http(
        srv.url,
        body=srv.rpc("tools/call", {"name": "touch", "arguments": {}}),
        headers={"Mcp-Session-Id": sid, "Accept": "application/json"},
    )
    events = await reader
    assert got_both(events)
    # GET without a session / wrong Accept
    status, _, _ = await http(srv.url, method="GET", headers={"Accept": "text/event-stream"})
    assert status == 405
    status, _, _ = await http(
        srv.url, method="GET", headers={"Mcp-Session-Id": sid, "Accept": "application/json"}
    )
    assert status == 406


async def test_legacy_sse_transport(make_server: Callable[..., Any]) -> None:
    plain = await make_server()
    status, _, _ = await http(plain.base + "/sse", method="GET")
    assert status == 404  # the deprecated transport is opt-in
    srv = await make_server(enable_sse=True)
    sse_url = srv.base + "/sse"
    state: dict[str, Any] = {}

    def reader() -> list[tuple[str | None, str]]:
        req = urllib.request.Request(sse_url, headers={"Accept": "text/event-stream"})
        events: list[tuple[str | None, str]] = []
        with urllib.request.urlopen(req, timeout=8) as resp:
            buf = b""
            while True:
                line = resp.readline()
                if not line:
                    break
                buf += line
                if line in (b"\n", b"\r\n"):
                    events.extend(sse_events(buf))
                    buf = b""
                    if events and "endpoint" not in state:
                        state["endpoint"] = events[0][1]
                    if any('"id":2' in d for _, d in events):
                        break
        return events

    task = asyncio.create_task(asyncio.to_thread(reader))
    for _ in range(200):
        if "endpoint" in state:
            break
        await asyncio.sleep(0.02)
    endpoint = state["endpoint"]
    assert endpoint.startswith("/messages/?session_id=")
    post_url = srv.base + endpoint
    status, _, body = await http(
        post_url,
        body={
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {"protocolVersion": "2024-11-05", "capabilities": {}},
        },
    )
    assert status == 202 and body == b""
    await http(post_url, body={"jsonrpc": "2.0", "method": "notifications/initialized"})
    await http(post_url, body={"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
    events = await task
    replies = [json.loads(d) for name, d in events if name == "message"]
    assert replies[0]["result"]["protocolVersion"] == "2024-11-05"
    assert replies[1]["id"] == 2 and replies[1]["result"]["tools"]
    status, _, _ = await http(srv.base + "/messages/?session_id=nope", body={"jsonrpc": "2.0"})
    assert status == 404


# ---------------------------------------------------------------------------
# 2026-07-28 stateless requests, stateless mode, JSON mode
# ---------------------------------------------------------------------------


def modern_headers(method: str, name: str | None = None, version: str = MODERN) -> dict[str, str]:
    h = {"MCP-Protocol-Version": version, "Mcp-Method": method}
    if name is not None:
        h["Mcp-Name"] = name
    return h


async def test_modern_requests(make_server: Callable[..., Any]) -> None:
    srv = await make_server()
    msg = srv.rpc("tools/list", {"_meta": ENVELOPE})
    status, _, body = await http(srv.url, body=msg, headers=modern_headers("tools/list"))
    result = json.loads(body)["result"]
    assert status == 200 and result["resultType"] == "complete" and result["tools"]

    async def rejected(body: Any, headers: dict[str, str]) -> dict[str, Any]:
        status, _, raw = await http(srv.url, body=body, headers=headers)
        assert status == 400, raw
        return json.loads(raw)["error"]

    # like mcp 2.3: both headers are required and must match the body (-32020)
    assert (await rejected(msg, {}))["code"] == -32020
    assert (await rejected(msg, {"MCP-Protocol-Version": MODERN}))["code"] == -32020
    assert (await rejected(msg, {"Mcp-Method": "tools/list"}))["code"] == -32020
    assert (await rejected(msg, modern_headers("tools/list", version="2025-11-25")))[
        "code"
    ] == -32020
    assert (await rejected(msg, modern_headers("prompts/list")))["code"] == -32020

    call = srv.rpc("tools/call", {"name": "echo", "arguments": {"text": "x"}, "_meta": ENVELOPE})
    json_only = {"Accept": "application/json"}
    assert (await rejected(call, {**modern_headers("tools/call"), **json_only}))[
        "code"
    ] == -32020  # Mcp-Name missing
    assert (await rejected(call, {**modern_headers("tools/call", "stats"), **json_only}))[
        "code"
    ] == -32020
    status, _, body = await http(
        srv.url, body=call, headers={**modern_headers("tools/call", "echo"), **json_only}
    )
    assert status == 200 and json.loads(body)["result"]["structuredContent"] == {"text": "x"}
    encoded = "=?base64?ZWNobw==?="  # "echo"
    status, _, _ = await http(
        srv.url, body=call, headers={**modern_headers("tools/call", encoded), **json_only}
    )
    assert status == 200

    no_caps = srv.rpc("tools/list", {"_meta": {PROTOCOL_VERSION_META_KEY: MODERN}})
    assert (await rejected(no_caps, modern_headers("tools/list")))["code"] == -32602

    bad = srv.rpc("tools/list", {"_meta": {**ENVELOPE, PROTOCOL_VERSION_META_KEY: "2099-01-01"}})
    err = await rejected(bad, modern_headers("tools/list", version="2099-01-01"))
    assert err["code"] == -32022 and err["data"]["supported"] == [MODERN]

    status, _, body = await http(
        srv.url, body=srv.rpc("nope/nope", {"_meta": ENVELOPE}), headers=modern_headers("nope/nope")
    )
    assert status == 404 and json.loads(body)["error"]["code"] == -32601
    status, _, _ = await http(srv.url, body=[srv.rpc("tools/list", {"_meta": ENVELOPE})])
    assert status == 400


async def test_stateless_and_json_modes(make_server: Callable[..., Any]) -> None:
    srv = await make_server(stateless=True, json_response=True)
    status, _, body = await http(
        srv.url,
        body=srv.rpc(
            "tools/call", {"name": "slow", "arguments": {"steps": 1}, "_meta": {"progressToken": 1}}
        ),
        headers={"MCP-Protocol-Version": "2025-06-18"},
    )
    assert status == 200 and json.loads(body)["result"]["structuredContent"] == {"done": 1}
    status, hdrs, body = await http(
        srv.url, body=srv.rpc("initialize", {"protocolVersion": "2025-11-25", "capabilities": {}})
    )
    assert status == 200 and "mcp-session-id" not in hdrs
    status, _, _ = await http(srv.url, method="GET", headers={"Accept": "text/event-stream"})
    assert status == 405
    status, _, _ = await http(srv.url, method="DELETE")
    assert status == 405


async def test_idle_sessions_expire(make_server: Callable[..., Any]) -> None:
    srv = await make_server(session_idle_timeout=0.1)
    await srv.initialize()
    srv.http._reaper.cancel()
    for hs in srv.http._sessions.values():
        hs.last_seen -= 10
    srv.http._reaper = asyncio.create_task(srv.http._reap_sessions())
    for _ in range(100):
        if not srv.http._sessions:
            break
        await asyncio.sleep(0.05)
    assert not srv.http._sessions


async def test_max_sessions(make_server: Callable[..., Any]) -> None:
    srv = await make_server(max_sessions=1)
    await srv.initialize()
    status, _, _ = await http(
        srv.url, body=srv.rpc("initialize", {"protocolVersion": "2025-11-25", "capabilities": {}})
    )
    assert status == 503


async def test_per_principal_session_cap_evicts_oldest_idle(
    make_server: Callable[..., Any],
) -> None:
    srv = await make_server(max_sessions_per_principal=2)
    first = await srv.initialize()
    second = await srv.initialize()
    third = await srv.initialize()  # evicts ``first``, the least recently used
    assert set(srv.http._sessions) == {second, third}
    status, _, _ = await http(srv.url, body=srv.rpc("ping"), headers={"Mcp-Session-Id": first})
    assert status == 404
    status, _, _ = await http(srv.url, body=srv.rpc("ping"), headers={"Mcp-Session-Id": third})
    assert status == 200


async def test_session_cap_refuses_when_every_session_streams(
    make_server: Callable[..., Any],
) -> None:
    srv = await make_server(max_sessions_per_principal=1)
    await srv.initialize()
    for hs in srv.http._sessions.values():
        hs.stream_open = True
    status, _, body = await http(
        srv.url, body=srv.rpc("initialize", {"protocolVersion": "2025-11-25", "capabilities": {}})
    )
    assert status == 503 and b"Too many sessions" in body


async def test_slow_request_head_is_cut_off(make_server: Callable[..., Any]) -> None:
    srv = await make_server(header_timeout=0.3)
    host, port = srv.http.bound
    reader, writer = await asyncio.open_connection(host, port)
    writer.write(b"POST /mcp HTTP/1.1\r\nHost: 127.0.0.1\r\n")  # never finishes the head
    await writer.drain()
    started = time.monotonic()
    assert await asyncio.wait_for(reader.read(), 5) == b""  # closed by the server
    assert time.monotonic() - started < 4
    writer.close()


async def test_connection_cap(make_server: Callable[..., Any]) -> None:
    srv = await make_server(max_connections=1)
    host, port = srv.http.bound
    _, held = await asyncio.open_connection(host, port)  # occupies the only slot
    await asyncio.sleep(0.1)
    reader, writer = await asyncio.open_connection(host, port)
    reply = await asyncio.wait_for(reader.read(), 5)
    assert reply.startswith(b"HTTP/1.1 503")
    writer.close()
    held.close()


async def test_body_over_limit_is_refused_before_reading(make_server: Callable[..., Any]) -> None:
    srv = await make_server(max_body_bytes=100)
    host, port = srv.http.bound
    reader, writer = await asyncio.open_connection(host, port)
    writer.write(
        b"POST /mcp HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json"
        b"\r\nContent-Length: 1000000\r\n\r\n"
    )  # no body sent at all
    await writer.drain()
    reply = await asyncio.wait_for(reader.read(), 5)
    assert reply.startswith(b"HTTP/1.1 413")
    writer.close()


# ---------------------------------------------------------------------------
# Official SDK client against the native server
# ---------------------------------------------------------------------------


@pytest.mark.filterwarnings("ignore")
@pytest.mark.parametrize("mode", ["legacy", "auto"])
async def test_sdk_client_over_native_http(make_server: Callable[..., Any], mode: str) -> None:
    mcp = pytest.importorskip("mcp")
    if not hasattr(mcp, "Client"):
        pytest.skip("needs the mcp 2.x Client")
    srv = await make_server()
    received: list[Any] = []

    async def on_message(message: Any) -> None:
        received.append(message)

    async with mcp.Client(srv.url, mode=mode, message_handler=on_message) as client:
        assert client.protocol_version == ("2025-11-25" if mode == "legacy" else MODERN)
        tools = (await client.list_tools()).tools
        wire = {t["name"]: t for t in srv.layer.tools_wire()}
        for tool in tools:
            dumped = tool.model_dump(by_alias=True, mode="json", exclude_none=True)
            assert dumped["inputSchema"] == wire[tool.name]["inputSchema"]
            assert dumped.get("annotations") == wire[tool.name].get("annotations")
        progress: list[float] = []

        async def on_progress(p: float, total: float | None, message: str | None) -> None:
            progress.append(p)

        result = await client.call_tool("slow", {"steps": 2}, progress_callback=on_progress)
        assert result.structured_content == {"done": 2} and progress == [1, 2]
        assert (await client.call_tool("fail", {})).is_error
        stats = await client.call_tool("stats", {})  # declares outputSchema
        assert stats.structured_content["count"] == 4
        read = await client.read_resource("test://items/gamma")
        assert '"index": 2' in read.contents[0].text
        if mode == "legacy":
            await client.subscribe_resource("test://info")
            await client.call_tool("touch", {})
            for _ in range(100):
                if any("ResourceUpdated" in type(m).__name__ for m in received):
                    break
                await asyncio.sleep(0.02)
            assert any("ResourceUpdated" in type(m).__name__ for m in received)
        else:
            async with client.listen(tools_list_changed=True) as sub:
                await client.call_tool("touch", {})
                event = await asyncio.wait_for(sub.__anext__(), 5)
                assert type(event).__name__ == "ToolsListChanged"
