"""Tests for :mod:`cloudg.mcp.server`: layer construction from CLI options and
serving over HTTP with each flavor."""

from __future__ import annotations

import asyncio
import contextlib
import importlib.util
import json
import socket
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

import pytest

from cloudg.mcp.core import Capability
from cloudg.mcp.server import (
    TokenAuthASGIMiddleware,
    _ensure_stderr_logging,
    create_layer_from_options,
    read_only_registry,
    resolve_flavor,
    serve_async,
    validate_serve_options,
)
from tests.mcp._adapter_testkit import _permissive_policy, build_registry

pytestmark = pytest.mark.filterwarnings("ignore")


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


async def wait_for_port(port: int, timeout: float = 15) -> None:
    deadline = asyncio.get_running_loop().time() + timeout
    while asyncio.get_running_loop().time() < deadline:
        try:
            _, writer = await asyncio.open_connection("127.0.0.1", port)
            writer.close()
            return
        except OSError:
            await asyncio.sleep(0.05)
    raise TimeoutError(f"port {port} never opened")


def post(url: str, body: Any, headers: dict[str, str] | None = None) -> tuple[int, bytes]:
    req = urllib.request.Request(url, data=json.dumps(body).encode(), method="POST", headers={
        "Content-Type": "application/json", "Accept": "application/json, text/event-stream",
        **(headers or {})})
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status, resp.read()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read()


@contextlib.asynccontextmanager
async def running(layer: Any, **kwargs: Any) -> Any:
    port = free_port()
    task = asyncio.create_task(serve_async(layer, "http", port=port, **kwargs))
    try:
        await wait_for_port(port)
        yield f"http://127.0.0.1:{port}/mcp"
    finally:
        task.cancel()
        with contextlib.suppress(BaseException):
            await asyncio.wait_for(task, 10)


def test_create_layer_from_options(tmp_path: Path) -> None:
    layer = create_layer_from_options(
        registry=build_registry(), policy=_permissive_policy(), prefix="cg_",
        exclude_categories=["admin"], audit_log=tmp_path / "a.jsonl", cache_ttl=30,
        max_concurrency=4,
    )
    names = [t["name"] for t in layer.tools_wire()]
    assert "cg_echo" in names and "cg_touch" not in names
    assert "cloudg://metrics" in layer.registry.resources
    kinds = [type(m).__name__ for m in layer.middleware]
    assert kinds == ["AuditLogMiddleware", "MetricsMiddleware", "ConcurrencyLimitMiddleware",
                     "CachingMiddleware"]
    with pytest.raises(FileNotFoundError):
        create_layer_from_options(registry=build_registry(), policy=_permissive_policy(),
                                  datasets=[str(tmp_path / "missing.json")])


def test_read_only_registry() -> None:
    reg = build_registry()
    ro = read_only_registry(reg)
    assert "touch" not in ro.tools and "echo" in ro.tools
    assert all(not (s.capabilities & {Capability.WRITE_FS, Capability.CLOUD_ACCESS,
                                       Capability.EXEC}) for s in ro.tools.values())
    assert ro.resources.keys() == reg.resources.keys()


def test_resolve_flavor() -> None:
    expected = "sdk" if importlib.util.find_spec("mcp") else "native"
    assert resolve_flavor("auto") == expected
    assert resolve_flavor("native") == "native"
    with pytest.raises(ValueError):
        resolve_flavor("bogus")


def test_validate_serve_options() -> None:
    assert validate_serve_options("native", "http", cors_origins=["https://a"]) == "native"
    with pytest.raises(ValueError, match="cors-origin"):
        validate_serve_options("sdk", "http", cors_origins=["https://a"])
    with pytest.raises(ValueError, match="cors-origin"):
        validate_serve_options("fastmcp", "http", cors_origins=["https://a"])
    with pytest.raises(ValueError, match="fastmcp"):
        validate_serve_options("fastmcp", "sse", stateless=True)
    assert validate_serve_options("fastmcp", "http", json_response=True,
                                  stateless=True) == "fastmcp"
    assert validate_serve_options("sdk", "stdio", cors_origins=["x"]) == "sdk"
    with pytest.raises(ValueError):
        validate_serve_options("native", "pigeon")


async def _asgi_status(mw: Any, headers: dict[str, str]) -> int:
    sent: list[dict[str, Any]] = []

    async def app(scope: Any, receive: Any, send: Any) -> None:
        await send({"type": "http.response.start", "status": 200, "headers": []})

    async def send(message: dict[str, Any]) -> None:
        sent.append(message)

    mw.app = app
    scope = {"type": "http", "headers": [(k.lower().encode(), v.encode())
                                         for k, v in headers.items()]}
    await mw(scope, None, send)
    return sent[0]["status"]


async def test_asgi_guard_keeps_origin_check_on_public_binds() -> None:
    from cloudg.mcp.native.http import OriginHostGuard
    from cloudg.mcp.native.auth import TokenAuth

    public = TokenAuthASGIMiddleware(None, None, OriginHostGuard("0.0.0.0"))
    assert await _asgi_status(public, {"Host": "mcp.example.com"}) == 200
    assert await _asgi_status(public, {"Host": "mcp.example.com",
                                       "Origin": "https://evil.example"}) == 403
    assert await _asgi_status(public, {"Host": "mcp.example.com",
                                       "Origin": "https://mcp.example.com"}) == 200
    pinned = TokenAuthASGIMiddleware(None, TokenAuth({"t": "r"}),
                                     OriginHostGuard("0.0.0.0", None, ["mcp.example.com"]))
    assert await _asgi_status(pinned, {"Host": "other.example"}) == 421
    assert await _asgi_status(pinned, {"Host": "mcp.example.com"}) == 401
    assert await _asgi_status(pinned, {"Host": "mcp.example.com",
                                       "Authorization": "Bearer t"}) == 200


def test_logging_setup_leaves_root_alone(monkeypatch: pytest.MonkeyPatch) -> None:
    import logging

    root = logging.getLogger()
    cloudg_logger = logging.getLogger("cloudg")
    monkeypatch.setattr(root, "handlers", [])
    monkeypatch.setattr(cloudg_logger, "handlers", [])
    monkeypatch.setattr(cloudg_logger, "level", cloudg_logger.level)
    _ensure_stderr_logging("DEBUG")
    _ensure_stderr_logging("INFO")
    assert root.handlers == []  # root untouched
    assert len(cloudg_logger.handlers) == 1 and cloudg_logger.level == logging.INFO
    sentinel = logging.NullHandler()
    monkeypatch.setattr(root, "handlers", [sentinel])
    monkeypatch.setattr(cloudg_logger, "handlers", [])
    _ensure_stderr_logging("WARNING")
    assert root.handlers == [sentinel] and cloudg_logger.handlers == []


async def test_serve_rejects_unknown_transport() -> None:
    with pytest.raises(ValueError):
        await serve_async(object(), "carrier-pigeon")  # type: ignore[arg-type]


async def test_native_flavor_http_with_auth() -> None:
    layer = create_layer_from_options(registry=build_registry(), policy=_permissive_policy())
    port = free_port()
    ready: asyncio.Future[Any] = asyncio.get_running_loop().create_future()
    task = asyncio.create_task(serve_async(layer, "http", flavor="native", port=port,
                                           auth_tokens=["tok:analyst"], ready=ready))
    try:
        host, bound = await asyncio.wait_for(ready, 10)
        assert bound == port
        url = f"http://127.0.0.1:{port}/mcp"
        init = {"jsonrpc": "2.0", "id": 1, "method": "initialize",
                "params": {"protocolVersion": "2025-11-25", "capabilities": {}}}
        status, _ = await asyncio.to_thread(post, url, init)
        assert status == 401
        status, body = await asyncio.to_thread(post, url, init, {"Authorization": "Bearer tok"})
        assert status == 200 and json.loads(body)["result"]["serverInfo"]["name"] == "cloudg"
    finally:
        task.cancel()
        with contextlib.suppress(BaseException):
            await task


@pytest.mark.parametrize("mode", ["legacy", "auto"])
async def test_sdk_flavor_http(mode: str) -> None:
    mcp = pytest.importorskip("mcp")
    if not hasattr(mcp, "Client"):
        pytest.skip("needs the mcp 2.x Client")
    layer = create_layer_from_options(registry=build_registry(), policy=_permissive_policy())
    async with running(layer, flavor="sdk") as url:
        async with mcp.Client(url, mode=mode) as client:
            tools = {t.name: t for t in (await client.list_tools()).tools}
            assert tools["echo"].input_schema == layer.registry.tools["echo"].input_schema
            result = await client.call_tool("echo", {"text": "sdk"})
            assert result.structured_content == {"text": "sdk"}


async def test_sdk_flavor_http_auth_and_principal() -> None:
    pytest.importorskip("mcp")
    layer = create_layer_from_options(registry=build_registry(), policy=_permissive_policy())
    seen: list[Any] = []

    async def spy(info: Any, call_next: Any) -> Any:
        seen.append(info.principal)
        return await call_next(info)

    layer.use(spy)
    async with running(layer, flavor="sdk", auth_tokens=["tok:auditor:auditor-1"],
                       json_response=True, stateless=True) as url:
        call = {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                "params": {"name": "echo", "arguments": {"text": "x"}}}
        status, _ = await asyncio.to_thread(post, url, call)
        assert status == 401
        status, _ = await asyncio.to_thread(
            post, url, call, {"Authorization": "Bearer tok", "Origin": "https://evil.example"})
        assert status == 403  # cloudg Origin guard in front of the SDK app
        init = {"jsonrpc": "2.0", "id": 0, "method": "initialize",
                "params": {"protocolVersion": "2025-11-25", "capabilities": {},
                           "clientInfo": {"name": "t", "version": "1"}}}
        headers = {"Authorization": "Bearer tok", "MCP-Protocol-Version": "2025-11-25"}
        await asyncio.to_thread(post, url, init, headers)
        status, body = await asyncio.to_thread(post, url, call, headers)
        assert status == 200, body
        assert json.loads(body)["result"]["structuredContent"] == {"text": "x"}
    assert seen and seen[-1].id == "auditor-1" and "auditor" in seen[-1].roles


async def test_fastmcp_flavor_http() -> None:
    pytest.importorskip("fastmcp")
    import fastmcp

    layer = create_layer_from_options(registry=build_registry(), policy=_permissive_policy())
    async with running(layer, flavor="fastmcp") as url:
        async with fastmcp.Client(url) as client:
            names = [t.name for t in await client.list_tools()]
            assert "echo" in names
        call = {"jsonrpc": "2.0", "id": 1, "method": "ping"}
        status, _ = await asyncio.to_thread(post, url, call, {"Origin": "https://evil.example"})
        assert status == 403


async def test_fastmcp_flavor_applies_http_options() -> None:
    pytest.importorskip("fastmcp")
    layer = create_layer_from_options(registry=build_registry(), policy=_permissive_policy())
    async with running(layer, flavor="fastmcp", json_response=True, stateless=True,
                       allowed_origins=["https://app.example"],
                       auth_tokens=["tok:analyst"]) as url:
        init = {"jsonrpc": "2.0", "id": 1, "method": "initialize",
                "params": {"protocolVersion": "2025-06-18", "capabilities": {},
                           "clientInfo": {"name": "t", "version": "1"}}}
        status, _ = await asyncio.to_thread(post, url, init)
        assert status == 401
        ok = {"Authorization": "Bearer tok", "Origin": "https://app.example"}
        status, _ = await asyncio.to_thread(post, url, init,
                                            {**ok, "Origin": "http://localhost:3000"})
        assert status == 403  # --allowed-origin replaced the loopback default
        status, body = await asyncio.to_thread(post, url, init, ok)
        assert status == 200 and json.loads(body)["result"]["serverInfo"]  # JSON, not SSE
