"""Streamable HTTP (and legacy HTTP+SSE) transport for the native MCP server.

A small HTTP/1.1 server on :func:`asyncio.start_server`, with no web framework.

Streamable HTTP (``POST`` / ``GET`` / ``DELETE`` on one endpoint, default
``/mcp``), per the 2025-03-26 through 2025-11-25 transport spec:

* ``POST`` carries one JSON-RPC message (or a batch where the negotiated
  revision allows it). Notifications / responses only get ``202 Accepted``.
  Requests get ``application/json``, or a ``text/event-stream`` when the call
  may stream request-scoped notifications (progress, log messages) and the
  client accepts SSE.
* ``Mcp-Session-Id`` is issued on the ``initialize`` response; later requests
  without it get ``400``, unknown / expired / deleted ids ``404``. Sessions
  are bound to the principal that created them.
* ``MCP-Protocol-Version`` is validated (``400`` when unsupported or
  different from the negotiated revision).
* ``GET`` opens the session's standalone SSE stream (list-changed and
  resource-updated notifications); ``DELETE`` ends the session.
* The 2026-07-28 stateless envelope is accepted on ``POST`` without a
  session; ``subscriptions/listen`` answers with a long-lived SSE stream.

Security defaults: bind ``127.0.0.1``; ``Origin`` validated against an
allow-list (``403``) and, on loopback binds, ``Host`` validated against
loopback names (``421``) to stop DNS rebinding; optional static bearer
tokens (``401`` + ``WWW-Authenticate``); request bodies capped (``413``);
CORS disabled unless origins are configured.

The deprecated 2024-11-05 HTTP+SSE transport can be enabled
(``HTTPConfig.enable_sse`` / ``--transport sse``) on ``/sse`` + ``/messages/``
for old clients.
"""

from __future__ import annotations

import asyncio
import base64
import contextlib
import fnmatch
import ipaddress
import json
import logging
import secrets
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Any, Iterable
from urllib.parse import parse_qs, urlsplit

from cloudg.mcp.context import Principal
from cloudg.mcp.native.auth import RequestInfo, TokenAuth
from cloudg.mcp.native.jsonrpc import (
    CLIENT_CAPABILITIES_META_KEY,
    DEFAULT_HTTP_VERSION,
    HANDSHAKE_VERSIONS,
    HEADER_MISMATCH,
    INVALID_PARAMS,
    INVALID_REQUEST,
    METHOD_NOT_FOUND,
    MODERN_VERSIONS,
    PARSE_ERROR,
    PROTOCOL_VERSION_META_KEY,
    SUPPORTED_VERSIONS,
    UNSUPPORTED_PROTOCOL_VERSION,
    dumps,
    is_request,
)
from cloudg.mcp.native.protocol import NativeMCPServer, Session, has_modern_envelope

logger = logging.getLogger("cloudg.mcp.native.http")

__all__ = ["HTTPConfig", "NativeHTTPServer", "OriginHostGuard", "run_http_async"]

_REASONS = {
    200: "OK", 202: "Accepted", 204: "No Content", 400: "Bad Request", 401: "Unauthorized",
    403: "Forbidden", 404: "Not Found", 405: "Method Not Allowed", 406: "Not Acceptable",
    409: "Conflict", 413: "Payload Too Large", 415: "Unsupported Media Type",
    421: "Misdirected Request", 431: "Request Header Fields Too Large",
    500: "Internal Server Error", 503: "Service Unavailable",
}
_LOOPBACK_ORIGINS = [
    f"{scheme}://{host}{port}"
    for scheme in ("http", "https")
    for host in ("localhost", "127.0.0.1", "[::1]")
    for port in ("", ":*")
]
_LOOPBACK_HOSTS = ["localhost", "localhost:*", "127.0.0.1", "127.0.0.1:*", "[::1]", "[::1]:*"]
#: Methods whose handling may emit request-scoped notifications.
_STREAMING_METHODS = {"tools/call", "resources/read", "prompts/get", "subscriptions/listen"}
_MAX_HEADER_BYTES = 64 * 1024


@dataclass
class HTTPConfig:
    """Settings for :class:`NativeHTTPServer`.

    Attributes:
        host / port: Bind address (``port=0`` picks a free port).
        path: The Streamable HTTP endpoint.
        enable_sse: Also serve the deprecated 2024-11-05 HTTP+SSE transport.
        sse_path / message_path: Legacy SSE endpoints.
        allowed_origins: ``Origin`` patterns (``fnmatch``; ``*`` allows any).
            ``None`` allows loopback origins; same-origin requests are always
            accepted (see :class:`OriginHostGuard`).
        allowed_hosts: ``Host`` patterns. ``None`` restricts loopback binds to
            loopback names and skips the Host check on other binds (the Origin
            check stays on).
        auth: Bearer-token authentication (``None`` = no auth).
        json_response: Always answer POSTs with JSON (never SSE).
        stateless: No sessions; every POST is self-contained.
        max_body_bytes: Request body limit.
        session_idle_timeout: Seconds of inactivity before a session expires.
        max_sessions: Concurrent session cap (``503`` beyond it).
        keepalive_interval: Seconds between SSE keep-alive comments.
        cors_origins: Origins granted CORS (off when empty).
        health_path: Unauthenticated liveness endpoint (``None`` disables).
    """

    host: str = "127.0.0.1"
    port: int = 8765
    path: str = "/mcp"
    enable_sse: bool = False
    sse_path: str = "/sse"
    message_path: str = "/messages/"
    allowed_origins: list[str] | None = None
    allowed_hosts: list[str] | None = None
    auth: TokenAuth | None = None
    json_response: bool = False
    stateless: bool = False
    max_body_bytes: int = 4 * 1024 * 1024
    session_idle_timeout: float = 3600.0
    max_sessions: int = 1000
    keepalive_interval: float = 15.0
    cors_origins: list[str] = field(default_factory=list)
    health_path: str | None = "/healthz"


@dataclass
class _Request:
    method: str
    target: str
    path: str
    query: dict[str, list[str]]
    version: str
    headers: dict[str, str]
    body: bytes

    @property
    def keep_alive(self) -> bool:
        conn = self.headers.get("connection", "").lower()
        if self.version == "HTTP/1.0":
            return "keep-alive" in conn
        return "close" not in conn


class _HTTPError(Exception):
    def __init__(self, status: int, message: str, *, close: bool = True) -> None:
        super().__init__(message)
        self.status = status
        self.message = message
        self.close = close


@dataclass(eq=False)
class _HTTPSession:
    session: Session
    principal: Principal
    outbox: deque[dict[str, Any] | None] = field(default_factory=lambda: deque(maxlen=512))
    wakeup: asyncio.Event = field(default_factory=asyncio.Event)
    stream_open: bool = False
    last_seen: float = field(default_factory=time.monotonic)
    kind: str = "streamable"  # streamable | sse

    async def push(self, message: dict[str, Any] | None) -> None:
        self.outbox.append(message)
        self.wakeup.set()


def _is_loopback(host: str) -> bool:
    if host in ("localhost", ""):
        return True
    try:
        return ipaddress.ip_address(host.strip("[]")).is_loopback
    except ValueError:
        return False


def _accepts(headers: dict[str, str]) -> tuple[bool, bool]:
    """(accepts JSON, accepts SSE) from the Accept header."""
    accept = headers.get("accept", "")
    if not accept.strip():
        return True, True
    types = {part.split(";")[0].strip().lower() for part in accept.split(",")}
    any_type = "*/*" in types
    return (
        any_type or "application/json" in types or "application/*" in types,
        any_type or "text/event-stream" in types or "text/*" in types,
    )


_NAME_BEARING = {"tools/call": "name", "prompts/get": "name", "resources/read": "uri"}


def _decode_header_value(value: str | None) -> str | None:
    """Decode the ``=?base64?...?=`` form used for non-ASCII MCP header values."""
    if value is None:
        return None
    if value.startswith("=?base64?") and value.endswith("?="):
        try:
            return base64.b64decode(value[9:-2]).decode("utf-8")
        except (ValueError, UnicodeDecodeError):
            return value
    return value


def _modern_rejection(msg: dict[str, Any], headers: dict[str, str]) -> tuple[int, str, Any] | None:
    """Validate a 2026-07-28 request's envelope and MCP headers (HTTP 400 cases).

    Same ladder and codes as the official SDK, first failure wins:

    1. ``params._meta`` carries the protocol version and client capabilities,
       else ``-32602``.
    2. ``MCP-Protocol-Version`` equals the envelope version and ``Mcp-Method``
       equals the body's method (both headers are required), and for
       ``tools/call`` / ``prompts/get`` / ``resources/read`` ``Mcp-Name``
       equals the named parameter, else ``-32020`` (HeaderMismatch).
    3. The version is a supported string, else ``-32602`` (not a string) or
       ``-32022`` (UnsupportedProtocolVersion, with the supported list).
    """
    params = msg.get("params") or {}
    meta = params.get("_meta") or {}
    missing = [k for k in (PROTOCOL_VERSION_META_KEY, CLIENT_CAPABILITIES_META_KEY)
               if k not in meta]
    if missing:
        return INVALID_PARAMS, "params._meta is missing the required envelope key(s): " \
                               f"{', '.join(missing)}", None
    version = meta.get(PROTOCOL_VERSION_META_KEY)
    pv_header = headers.get("mcp-protocol-version")
    if pv_header is None or pv_header != version:
        return HEADER_MISMATCH, "MCP-Protocol-Version header does not match the request " \
                                "envelope's protocol version", None
    if headers.get("mcp-method") != msg.get("method"):
        return HEADER_MISMATCH, "Mcp-Method header does not match the request body's method", None
    name_key = _NAME_BEARING.get(str(msg.get("method")))
    if name_key and params.get(name_key) is not None and _decode_header_value(
            headers.get("mcp-name")) != params.get(name_key):
        return HEADER_MISMATCH, "Mcp-Name header does not match the request body's " \
                                f"{name_key!r} parameter", None
    if not isinstance(version, str):
        return INVALID_PARAMS, "the protocol-version envelope value must be a string", None
    if version not in MODERN_VERSIONS:
        return UNSUPPORTED_PROTOCOL_VERSION, f"Unsupported protocol version: {version}", {
            "supported": list(MODERN_VERSIONS), "requested": version}
    return None


def _match_any(value: str, patterns: Iterable[str]) -> bool:
    value = value.lower()
    return any(p == "*" or fnmatch.fnmatchcase(value, p.lower()) for p in patterns)


class OriginHostGuard:
    """DNS-rebinding protection shared by every HTTP flavor.

    * ``Origin``: absent (non-browser client) is accepted. Otherwise it must
      match ``allowed_origins`` (default: loopback origins on any port) or be
      same-origin, meaning its ``host:port`` equals the request's ``Host``.
      Rejected with ``403``. This check is always on, whatever the bind.
    * ``Host``: checked against ``allowed_hosts`` when given; on a loopback
      bind without ``allowed_hosts`` it must be a loopback name; on any other
      bind without ``allowed_hosts`` it is not checked (the server cannot know
      the names it is reached by). Rejected with ``421``.
    """

    def __init__(self, bind_host: str, allowed_origins: Iterable[str] | None = None,
                 allowed_hosts: Iterable[str] | None = None,
                 extra_origins: Iterable[str] = ()) -> None:
        self.origins = list(allowed_origins) if allowed_origins is not None else list(
            _LOOPBACK_ORIGINS)
        self.origins.extend(extra_origins)
        if allowed_hosts is not None:
            self.hosts: list[str] | None = list(allowed_hosts)
        elif _is_loopback(bind_host):
            self.hosts = list(_LOOPBACK_HOSTS)
        else:
            self.hosts = None

    def check(self, host: str | None, origin: str | None) -> tuple[int, str] | None:
        """``None`` when acceptable, else ``(status, message)``."""
        if self.hosts is not None and (host is None or not _match_any(host, self.hosts)):
            return 421, "Invalid Host header"
        if origin and not _match_any(origin, self.origins):
            same_origin = bool(host) and urlsplit(origin).netloc.lower() == (host or "").lower()
            if not same_origin:
                return 403, "Forbidden: invalid Origin"
        return None


class _SSE:
    """Chunked ``text/event-stream`` response writer."""

    def __init__(self, writer: asyncio.StreamWriter) -> None:
        self.writer = writer
        self.started = False

    async def start(self, headers: dict[str, str]) -> None:
        base = {
            "Content-Type": "text/event-stream",
            "Cache-Control": "no-cache, no-transform",
            "Transfer-Encoding": "chunked",
            "X-Accel-Buffering": "no",
            **headers,
        }
        self.writer.write(_head(200, base))
        await self.writer.drain()
        self.started = True

    async def _chunk(self, data: bytes) -> None:
        self.writer.write(b"%x\r\n%s\r\n" % (len(data), data))
        await self.writer.drain()

    async def event(self, data: str, event: str | None = None) -> None:
        lines = []
        if event:
            lines.append(f"event: {event}")
        lines.extend(f"data: {line}" for line in data.split("\n"))
        await self._chunk(("\n".join(lines) + "\n\n").encode("utf-8"))

    async def message(self, msg: Any) -> None:
        await self.event(dumps(msg), "message")

    async def comment(self, text: str = "keepalive") -> None:
        await self._chunk(f": {text}\n\n".encode())

    async def end(self) -> None:
        self.writer.write(b"0\r\n\r\n")
        await self.writer.drain()


def _head(status: int, headers: dict[str, str]) -> bytes:
    lines = [f"HTTP/1.1 {status} {_REASONS.get(status, 'Status')}", "Server: cloudg-mcp"]
    lines.extend(f"{k}: {v}" for k, v in headers.items())
    return ("\r\n".join(lines) + "\r\n\r\n").encode("latin-1")


def _jsonrpc_error_body(code: int, message: str, data: Any = None) -> bytes:
    err: dict[str, Any] = {"code": code, "message": message}
    if data is not None:
        err["data"] = data
    return json.dumps({"jsonrpc": "2.0", "id": None, "error": err}).encode()


class NativeHTTPServer:
    """Asyncio HTTP server exposing a :class:`NativeMCPServer`."""

    def __init__(self, server: NativeMCPServer, config: HTTPConfig | None = None) -> None:
        self.mcp = server
        self.config = config or HTTPConfig()
        self._sessions: dict[str, _HTTPSession] = {}
        self._server: asyncio.base_events.Server | None = None
        self._reaper: asyncio.Task[Any] | None = None
        self._conn_tasks: set[asyncio.Task[Any]] = set()
        self.bound: tuple[str, int] | None = None
        cfg = self.config
        self.guard = OriginHostGuard(cfg.host, cfg.allowed_origins, cfg.allowed_hosts,
                                     extra_origins=cfg.cors_origins)

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    @property
    def url(self) -> str:
        host, port = self.bound or (self.config.host, self.config.port)
        shown = f"[{host}]" if ":" in host else host
        return f"http://{shown}:{port}{self.config.path}"

    async def start(self) -> tuple[str, int]:
        cfg = self.config
        if not _is_loopback(cfg.host) and not cfg.auth:
            logger.warning(
                "MCP HTTP server bound to %s without authentication; anyone who can reach "
                "this address can call cloudg tools. Use --auth-token or bind 127.0.0.1.",
                cfg.host,
            )
        self._server = await asyncio.start_server(
            self._on_connection, cfg.host, cfg.port, limit=_MAX_HEADER_BYTES
        )
        sock = self._server.sockets[0].getsockname()
        self.bound = (sock[0], sock[1])
        self.mcp._bind_loop()
        self._reaper = asyncio.create_task(self._reap_sessions())
        logger.info("cloudg MCP server listening on %s", self.url)
        return self.bound

    async def serve_forever(self) -> None:
        if self._server is None:
            await self.start()
        assert self._server is not None
        try:
            await self._server.serve_forever()
        finally:
            await self.aclose()

    async def aclose(self) -> None:
        self.mcp.close_listens()
        for hs in list(self._sessions.values()):
            await self._end_session(hs)
        self._sessions.clear()
        if self._reaper:
            self._reaper.cancel()
        if self._server is not None:
            self._server.close()
            with contextlib.suppress(Exception):
                await asyncio.wait_for(self._server.wait_closed(), 2)
        for task in list(self._conn_tasks):
            task.cancel()
        await asyncio.sleep(0)

    async def _reap_sessions(self) -> None:
        timeout = self.config.session_idle_timeout
        interval = max(1.0, min(60.0, timeout / 2))
        while True:
            await asyncio.sleep(interval)
            now = time.monotonic()
            for sid, hs in list(self._sessions.items()):
                if not hs.stream_open and now - hs.last_seen > timeout:
                    logger.debug("expiring idle MCP session %s", sid)
                    self._sessions.pop(sid, None)
                    await self._end_session(hs)

    async def _end_session(self, hs: _HTTPSession) -> None:
        hs.session.close()
        await hs.push(None)

    # ------------------------------------------------------------------
    # HTTP plumbing
    # ------------------------------------------------------------------

    async def _on_connection(self, reader: asyncio.StreamReader,
                             writer: asyncio.StreamWriter) -> None:
        task = asyncio.current_task()
        if task:
            self._conn_tasks.add(task)
        try:
            while True:
                try:
                    req = await asyncio.wait_for(self._read_request(reader), timeout=120)
                except _HTTPError as exc:
                    await self._send(writer, exc.status, _jsonrpc_error_body(INVALID_REQUEST,
                                                                             exc.message),
                                     keep_alive=False)
                    break
                except (asyncio.TimeoutError, asyncio.IncompleteReadError, ConnectionError,
                        asyncio.LimitOverrunError, ValueError):
                    break
                if req is None:
                    break
                try:
                    keep = await self._dispatch(req, writer)
                except _HTTPError as exc:
                    await self._send(writer, exc.status, _jsonrpc_error_body(INVALID_REQUEST,
                                                                             exc.message),
                                     keep_alive=not exc.close and req.keep_alive)
                    keep = not exc.close and req.keep_alive
                except (ConnectionError, asyncio.CancelledError):
                    break
                except Exception:
                    logger.exception("unhandled error serving %s %s", req.method, req.path)
                    with contextlib.suppress(Exception):
                        await self._send(writer, 500, _jsonrpc_error_body(-32603, "Internal error"),
                                         keep_alive=False)
                    break
                if not keep:
                    break
        finally:
            if task:
                self._conn_tasks.discard(task)
            with contextlib.suppress(Exception):
                writer.close()
                await writer.wait_closed()

    async def _read_request(self, reader: asyncio.StreamReader) -> _Request | None:
        try:
            raw = await reader.readuntil(b"\r\n\r\n")
        except asyncio.IncompleteReadError as exc:
            if not exc.partial.strip():
                return None
            raise
        except asyncio.LimitOverrunError:
            raise _HTTPError(431, "Request headers too large") from None
        text = raw.decode("latin-1")
        lines = text.split("\r\n")
        try:
            method, target, version = lines[0].split(" ", 2)
        except ValueError:
            raise _HTTPError(400, "Malformed request line") from None
        headers: dict[str, str] = {}
        for line in lines[1:]:
            if not line:
                continue
            name, sep, value = line.partition(":")
            if not sep:
                raise _HTTPError(400, "Malformed header")
            key = name.strip().lower()
            headers[key] = f"{headers[key]}, {value.strip()}" if key in headers else value.strip()
        body = b""
        limit = self.config.max_body_bytes
        if "chunked" in headers.get("transfer-encoding", "").lower():
            parts: list[bytes] = []
            size = 0
            while True:
                line = await reader.readline()
                n = int(line.split(b";")[0].strip() or b"0", 16)
                if n == 0:
                    while (await reader.readline()) not in (b"\r\n", b"\n", b""):
                        pass
                    break
                size += n
                if size > limit:
                    raise _HTTPError(413, "Request body too large")
                parts.append(await reader.readexactly(n))
                await reader.readexactly(2)
            body = b"".join(parts)
        elif headers.get("content-length"):
            try:
                n = int(headers["content-length"])
            except ValueError:
                raise _HTTPError(400, "Invalid Content-Length") from None
            if n < 0:
                raise _HTTPError(400, "Invalid Content-Length")
            if n > limit:
                raise _HTTPError(413, "Request body too large")
            body = await reader.readexactly(n)
        split = urlsplit(target)
        return _Request(
            method=method.upper(),
            target=target,
            path=split.path or "/",
            query=parse_qs(split.query),
            version=version.strip().upper(),
            headers=headers,
            body=body,
        )

    async def _send(
        self,
        writer: asyncio.StreamWriter,
        status: int,
        body: bytes = b"",
        *,
        content_type: str | None = "application/json",
        headers: dict[str, str] | None = None,
        keep_alive: bool = True,
    ) -> None:
        h: dict[str, str] = {}
        if body and content_type:
            h["Content-Type"] = content_type
        h["Content-Length"] = str(len(body))
        if not keep_alive:
            h["Connection"] = "close"
        h.update(headers or {})
        writer.write(_head(status, h) + body)
        await writer.drain()

    def _cors_headers(self, req: _Request) -> dict[str, str]:
        origin = req.headers.get("origin")
        if not origin or not self.config.cors_origins or not _match_any(
            origin, self.config.cors_origins
        ):
            return {}
        return {
            "Access-Control-Allow-Origin": origin,
            "Vary": "Origin",
            "Access-Control-Expose-Headers": "Mcp-Session-Id, MCP-Protocol-Version",
        }

    # ------------------------------------------------------------------
    # Routing
    # ------------------------------------------------------------------

    async def _dispatch(self, req: _Request, writer: asyncio.StreamWriter) -> bool:
        cfg = self.config
        cors = self._cors_headers(req)
        rejected = self.guard.check(req.headers.get("host"), req.headers.get("origin"))
        if rejected is not None:
            status, message = rejected
            await self._send(writer, status, _jsonrpc_error_body(INVALID_REQUEST, message),
                             keep_alive=False)
            return False
        if req.method == "OPTIONS":
            if not cors:
                await self._send(writer, 405, headers={"Allow": "GET, POST, DELETE"},
                                 keep_alive=req.keep_alive)
                return req.keep_alive
            await self._send(writer, 204, headers={
                **cors,
                "Access-Control-Allow-Methods": "GET, POST, DELETE, OPTIONS",
                "Access-Control-Allow-Headers": "Content-Type, Authorization, Accept, "
                "Mcp-Session-Id, MCP-Protocol-Version, Mcp-Method, Mcp-Name, Last-Event-ID",
                "Access-Control-Max-Age": "600",
            }, keep_alive=req.keep_alive)
            return req.keep_alive
        if cfg.health_path and req.path == cfg.health_path and req.method == "GET":
            await self._send(writer, 200, b'{"status":"ok"}', headers=cors,
                             keep_alive=req.keep_alive)
            return req.keep_alive

        token_principal: Principal | None = None
        if cfg.auth:
            token_principal = cfg.auth.authenticate(req.headers.get("authorization"))
            if token_principal is None and cfg.auth.required:
                await self._send(
                    writer, 401, _jsonrpc_error_body(INVALID_REQUEST, "Unauthorized"),
                    headers={**cors, "WWW-Authenticate": 'Bearer realm="cloudg-mcp"'},
                    keep_alive=req.keep_alive,
                )
                return req.keep_alive
        principal = self.mcp.resolve_principal(
            RequestInfo(
                transport="http",
                headers=req.headers,
                session_id=req.headers.get("mcp-session-id"),
                principal=token_principal,
                raw=req,
            )
        )

        if req.path == cfg.path:
            if req.method == "POST":
                return await self._post(req, writer, principal, cors)
            if req.method == "GET":
                return await self._get(req, writer, principal, cors)
            if req.method == "DELETE":
                return await self._delete(req, writer, principal, cors)
            await self._send(writer, 405, headers={**cors, "Allow": "GET, POST, DELETE"},
                             keep_alive=req.keep_alive)
            return req.keep_alive
        if cfg.enable_sse and req.path == cfg.sse_path and req.method == "GET":
            return await self._legacy_sse(req, writer, principal, cors)
        if cfg.enable_sse and req.path.rstrip("/") == cfg.message_path.rstrip("/"):
            if req.method == "POST":
                return await self._legacy_message(req, writer, principal, cors)
        await self._send(writer, 404, _jsonrpc_error_body(INVALID_REQUEST, "Not Found"),
                         headers=cors, keep_alive=req.keep_alive)
        return req.keep_alive

    def _lookup(self, req: _Request, principal: Principal, sid: str | None) -> _HTTPSession:
        if not sid:
            raise _HTTPError(400, "Bad Request: Mcp-Session-Id header is required", close=False)
        hs = self._sessions.get(sid)
        if hs is None or hs.session.closed or hs.principal.id != principal.id:
            raise _HTTPError(404, "Session not found", close=False)
        hs.last_seen = time.monotonic()
        return hs

    def _new_session(self, principal: Principal, kind: str) -> _HTTPSession:
        if len(self._sessions) >= self.config.max_sessions:
            raise _HTTPError(503, "Too many sessions", close=False)
        sid = secrets.token_hex(16)
        holder: dict[str, _HTTPSession] = {}

        async def send(message: dict[str, Any]) -> None:
            await holder["hs"].push(message)

        session = self.mcp.create_session(
            transport="http" if kind == "streamable" else "sse",
            send=send, principal=principal, session_id=sid,
        )
        hs = _HTTPSession(session=session, principal=principal, kind=kind)
        holder["hs"] = hs
        self._sessions[sid] = hs
        return hs

    # -- POST -------------------------------------------------------------

    async def _post(
        self, req: _Request, writer: asyncio.StreamWriter, principal: Principal,
        cors: dict[str, str],
    ) -> bool:
        cfg = self.config
        ctype = req.headers.get("content-type", "").split(";")[0].strip().lower()
        if ctype != "application/json":
            raise _HTTPError(415, "Content-Type must be application/json", close=False)
        wants_json, wants_sse = _accepts(req.headers)
        if not (wants_json or wants_sse):
            raise _HTTPError(406, "Not Acceptable: accept application/json or "
                                  "text/event-stream", close=False)
        try:
            msg = json.loads(req.body.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            await self._send(writer, 400, _jsonrpc_error_body(PARSE_ERROR, "Parse error"),
                             headers=cors, keep_alive=req.keep_alive)
            return req.keep_alive
        if not isinstance(msg, (dict, list)):
            await self._send(writer, 400, _jsonrpc_error_body(INVALID_REQUEST, "Invalid Request"),
                             headers=cors, keep_alive=req.keep_alive)
            return req.keep_alive
        items = msg if isinstance(msg, list) else [msg]
        has_requests = any(is_request(m) for m in items)
        pv_header = req.headers.get("mcp-protocol-version")
        extra: dict[str, str] = dict(cors)

        # 2026-07-28: self-describing stateless request
        if isinstance(msg, list) and any(
            isinstance(m, dict) and has_modern_envelope(m.get("params")) for m in msg
        ):
            await self._send(writer, 400, _jsonrpc_error_body(
                INVALID_REQUEST, "JSON-RPC batches are not supported by protocol version "
                "2026-07-28"), headers=cors, keep_alive=req.keep_alive)
            return req.keep_alive
        if isinstance(msg, dict) and is_request(msg) and has_modern_envelope(msg.get("params")):
            rejection = _modern_rejection(msg, req.headers)
            if rejection is not None:
                code, message, data = rejection
                err: dict[str, Any] = {"code": code, "message": message}
                if data is not None:
                    err["data"] = data
                body = json.dumps({"jsonrpc": "2.0", "id": msg.get("id"), "error": err})
                await self._send(writer, 400, body.encode(), headers=cors,
                                 keep_alive=req.keep_alive)
                return req.keep_alive
            session = self.mcp.create_session(transport="http", principal=principal,
                                              register=False)
            return await self._respond(req, writer, session, msg, principal, extra,
                                       wants_json, wants_sse, modern=True)

        if pv_header is not None and pv_header not in SUPPORTED_VERSIONS:
            raise _HTTPError(400, f"Unsupported MCP-Protocol-Version: {pv_header}", close=False)

        is_init = isinstance(msg, dict) and msg.get("method") == "initialize" and is_request(msg)
        if cfg.stateless:
            if is_init:
                session = self.mcp.create_session(transport="http", principal=principal,
                                                  register=False)
            else:
                version = pv_header if pv_header in HANDSHAKE_VERSIONS else DEFAULT_HTTP_VERSION
                session = self.mcp.create_session(transport="http", principal=principal,
                                                  stateless_version=version, register=False)
        elif is_init:
            hs = self._new_session(principal, "streamable")
            session = hs.session
            extra["Mcp-Session-Id"] = hs.session.session_id or ""
        else:
            hs = self._lookup(req, principal, req.headers.get("mcp-session-id"))
            session = hs.session
            if (pv_header is not None and pv_header in HANDSHAKE_VERSIONS
                    and session.protocol_version and pv_header != session.protocol_version):
                raise _HTTPError(
                    400,
                    f"MCP-Protocol-Version {pv_header} does not match the negotiated "
                    f"version {session.protocol_version}",
                    close=False,
                )
        if not has_requests:
            await session.handle(msg, principal=principal)
            await self._send(writer, 202, headers=extra, keep_alive=req.keep_alive)
            return req.keep_alive
        return await self._respond(req, writer, session, msg, principal, extra, wants_json,
                                   wants_sse, modern=False)

    async def _respond(
        self,
        req: _Request,
        writer: asyncio.StreamWriter,
        session: Session,
        msg: Any,
        principal: Principal,
        headers: dict[str, str],
        wants_json: bool,
        wants_sse: bool,
        *,
        modern: bool,
    ) -> bool:
        items = msg if isinstance(msg, list) else [msg]
        streaming = any(
            is_request(m) and m.get("method") in _STREAMING_METHODS for m in items
        )
        listen = any(is_request(m) and m.get("method") == "subscriptions/listen" for m in items)
        use_sse = wants_sse and (listen or (not self.config.json_response
                                            and (streaming or not wants_json)))
        if listen and not wants_sse:
            raise _HTTPError(406, "subscriptions/listen requires Accept: text/event-stream",
                             close=False)
        if not use_sse:
            response = await session.handle(msg, principal=principal)
            if response is None:
                await self._send(writer, 202, headers=headers, keep_alive=req.keep_alive)
            else:
                status = 200
                if (modern and isinstance(response, dict)
                        and (response.get("error") or {}).get("code") == METHOD_NOT_FOUND):
                    status = 404
                await self._send(writer, status, dumps(response).encode("utf-8"),
                                 headers=headers, keep_alive=req.keep_alive)
            return req.keep_alive

        sse = _SSE(writer)
        queue: asyncio.Queue[dict[str, Any]] = asyncio.Queue()

        async def sink(message: dict[str, Any]) -> None:
            await queue.put(message)

        task = asyncio.create_task(session.handle(msg, sink=sink, principal=principal))
        try:
            await sse.start(headers)
            while True:
                getter = asyncio.ensure_future(queue.get())
                done, _ = await asyncio.wait(
                    {getter, task}, timeout=self.config.keepalive_interval,
                    return_when=asyncio.FIRST_COMPLETED,
                )
                if getter in done:
                    await sse.message(getter.result())
                    continue
                getter.cancel()
                with contextlib.suppress(asyncio.CancelledError):
                    await getter
                if task in done:
                    break
                await sse.comment()
            while not queue.empty():
                await sse.message(queue.get_nowait())
            response = task.result()
            for item in (response if isinstance(response, list) else [response]):
                if item is not None:
                    await sse.message(item)
            await sse.end()
        except (ConnectionError, asyncio.CancelledError):
            # 2026-07-28: a broken stream loses the request; 2025: keep running
            if modern or listen:
                task.cancel()
            raise
        return req.keep_alive

    # -- GET / DELETE -------------------------------------------------------

    async def _get(
        self, req: _Request, writer: asyncio.StreamWriter, principal: Principal,
        cors: dict[str, str],
    ) -> bool:
        if self.config.stateless:
            await self._send(writer, 405, headers={**cors, "Allow": "POST"},
                             keep_alive=req.keep_alive)
            return req.keep_alive
        _, wants_sse = _accepts(req.headers)
        if not wants_sse:
            raise _HTTPError(406, "Not Acceptable: GET requires Accept: text/event-stream",
                             close=False)
        sid = req.headers.get("mcp-session-id")
        if not sid:
            await self._send(writer, 405, headers={**cors, "Allow": "POST, DELETE"},
                             keep_alive=req.keep_alive)
            return req.keep_alive
        hs = self._lookup(req, principal, sid)
        if hs.stream_open:
            raise _HTTPError(409, "Conflict: a GET stream is already open for this session",
                             close=False)
        await self._pump(hs, writer, cors)
        return False

    async def _pump(self, hs: _HTTPSession, writer: asyncio.StreamWriter,
                    headers: dict[str, str], first_event: tuple[str, str] | None = None) -> None:
        sse = _SSE(writer)
        hs.stream_open = True
        try:
            await sse.start(headers)
            if first_event:
                await sse.event(first_event[1], first_event[0])
            while True:
                while hs.outbox:
                    item = hs.outbox.popleft()
                    if item is None:
                        await sse.end()
                        return
                    await sse.message(item)
                hs.wakeup.clear()
                try:
                    await asyncio.wait_for(hs.wakeup.wait(), self.config.keepalive_interval)
                except asyncio.TimeoutError:
                    await sse.comment()
                hs.last_seen = time.monotonic()
        except (ConnectionError, asyncio.CancelledError):
            pass
        finally:
            hs.stream_open = False
            hs.last_seen = time.monotonic()

    async def _delete(
        self, req: _Request, writer: asyncio.StreamWriter, principal: Principal,
        cors: dict[str, str],
    ) -> bool:
        if self.config.stateless:
            await self._send(writer, 405, headers={**cors, "Allow": "POST"},
                             keep_alive=req.keep_alive)
            return req.keep_alive
        sid = req.headers.get("mcp-session-id")
        hs = self._lookup(req, principal, sid)
        self._sessions.pop(sid or "", None)
        await self._end_session(hs)
        await self._send(writer, 200, headers=cors, keep_alive=req.keep_alive)
        return req.keep_alive

    # -- legacy HTTP+SSE (2024-11-05) ------------------------------------------

    async def _legacy_sse(
        self, req: _Request, writer: asyncio.StreamWriter, principal: Principal,
        cors: dict[str, str],
    ) -> bool:
        hs = self._new_session(principal, "sse")
        sid = hs.session.session_id or ""
        endpoint = f"{self.config.message_path}?session_id={sid}"
        try:
            await self._pump(hs, writer, cors, first_event=("endpoint", endpoint))
        finally:
            self._sessions.pop(sid, None)
            hs.session.close()
        return False

    async def _legacy_message(
        self, req: _Request, writer: asyncio.StreamWriter, principal: Principal,
        cors: dict[str, str],
    ) -> bool:
        sid = (req.query.get("session_id") or [""])[0]
        if not sid:
            raise _HTTPError(400, "session_id query parameter is required", close=False)
        hs = self._sessions.get(sid)
        if hs is None or hs.kind != "sse" or hs.principal.id != principal.id:
            raise _HTTPError(404, "Session not found", close=False)
        try:
            msg = json.loads(req.body.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            await self._send(writer, 400, _jsonrpc_error_body(PARSE_ERROR, "Parse error"),
                             headers=cors, keep_alive=req.keep_alive)
            return req.keep_alive
        hs.last_seen = time.monotonic()

        async def run() -> None:
            response = await hs.session.handle(msg, principal=principal)
            if response is not None:
                await hs.push(response)  # type: ignore[arg-type]

        concurrent = isinstance(msg, list) or (
            is_request(msg) and msg.get("method") != "initialize"
        )
        if concurrent:
            task = asyncio.create_task(run())
            self._conn_tasks.add(task)
            task.add_done_callback(self._conn_tasks.discard)
        else:
            await run()
        await self._send(writer, 202, headers=cors, keep_alive=req.keep_alive)
        return req.keep_alive


async def run_http_async(server: NativeMCPServer, config: HTTPConfig | None = None) -> None:
    """Serve ``server`` over HTTP until cancelled."""
    http = NativeHTTPServer(server, config)
    await http.start()
    await http.serve_forever()
