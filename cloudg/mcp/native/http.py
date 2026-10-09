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
tokens (``401`` + ``WWW-Authenticate``, compared in constant time and never
logged); request bodies capped before they are read (``413``); request heads
must arrive within ``header_timeout``; concurrent connections and sessions
(overall and per principal) are capped; session ids are 128-bit random and
bound to the principal that created them; CORS disabled unless origins are
configured.

The deprecated 2024-11-05 HTTP+SSE transport can be enabled
(``HTTPConfig.enable_sse`` / ``--transport sse``) on ``/sse`` + ``/messages/``
for old clients.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import time
from typing import Any

from cloudg.mcp.context import Principal
from cloudg.mcp.native._http_io import (
    MAX_HEADER_BYTES,
    HTTPError,
    OriginHostGuard,
    Request,
    SSEWriter,
    accepts,
    post_accepts,
    head,
    is_loopback,
    jsonrpc_error_body,
    match_any,
    modern_rejection,
    read_request,
)
from cloudg.mcp.native._http_sessions import (
    Exchange,
    HTTPConfig,
    HTTPSession,
    SessionTable,
    pump,
    stream_until_done,
)
from cloudg.mcp.native.auth import RequestInfo
from cloudg.mcp.native.jsonrpc import (
    DEFAULT_HTTP_VERSION,
    HANDSHAKE_VERSIONS,
    INVALID_REQUEST,
    METHOD_NOT_FOUND,
    PARSE_ERROR,
    SUPPORTED_VERSIONS,
    dumps,
    is_request,
)
from cloudg.mcp.native.protocol import NativeMCPServer, Session, has_modern_envelope

logger = logging.getLogger("cloudg.mcp.native.http")

__all__ = ["HTTPConfig", "NativeHTTPServer", "OriginHostGuard", "run_http_async"]

#: Methods whose handling may emit request-scoped notifications.
_STREAMING_METHODS = {"tools/call", "resources/read", "prompts/get", "subscriptions/listen"}
_NO_BODY = object()
_ALLOW_HEADERS = (
    "Content-Type, Authorization, Accept, Mcp-Session-Id, MCP-Protocol-Version, "
    "Mcp-Method, Mcp-Name, Last-Event-ID"
)


class NativeHTTPServer:
    """Asyncio HTTP server exposing a :class:`NativeMCPServer`."""

    def __init__(self, server: NativeMCPServer, config: HTTPConfig | None = None) -> None:
        self.mcp = server
        self.config = config or HTTPConfig()
        self.table = SessionTable(server, self.config)
        self._sessions = self.table.sessions
        self._server: asyncio.base_events.Server | None = None
        self._reaper: asyncio.Task[Any] | None = None
        self._conn_tasks: set[asyncio.Task[Any]] = set()
        self._connections = 0
        self.bound: tuple[str, int] | None = None
        cfg = self.config
        self.guard = OriginHostGuard(
            cfg.host, cfg.allowed_origins, cfg.allowed_hosts, extra_origins=cfg.cors_origins
        )

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
        if not is_loopback(cfg.host) and not cfg.auth:
            logger.warning(
                "MCP HTTP server bound to %s without authentication; anyone who can reach "
                "this address can call cloudg tools. Use --auth-token or bind 127.0.0.1.",
                cfg.host,
            )
        self._server = await asyncio.start_server(
            self._on_connection, cfg.host, cfg.port, limit=MAX_HEADER_BYTES
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
        if self._server is None:  # pragma: no cover (start() sets it or raises)
            raise RuntimeError("HTTP server failed to start")
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
        await self.table.reap_forever()

    async def _end_session(self, hs: HTTPSession) -> None:
        await self.table.end(hs)

    # ------------------------------------------------------------------
    # HTTP plumbing
    # ------------------------------------------------------------------

    async def _on_connection(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        task = asyncio.current_task()
        if task:
            self._conn_tasks.add(task)
        self._connections += 1
        try:
            if self._connections > self.config.max_connections:
                await self._send_error(writer, 503, "Too many connections", keep_alive=False)
                return
            while await self._serve_one(reader, writer):
                pass
        finally:
            self._connections -= 1
            if task:
                self._conn_tasks.discard(task)
            with contextlib.suppress(Exception):
                writer.close()
                await writer.wait_closed()

    async def _serve_one(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> bool:
        """Read and answer one request; ``True`` to keep the connection."""
        cfg = self.config
        try:
            req = await read_request(
                reader,
                max_body=cfg.max_body_bytes,
                header_timeout=cfg.header_timeout,
                body_timeout=cfg.body_timeout,
            )
        except HTTPError as exc:
            await self._send_error(writer, exc.status, exc.message, keep_alive=False)
            return False
        except (
            asyncio.TimeoutError,
            asyncio.IncompleteReadError,
            ConnectionError,
            asyncio.LimitOverrunError,
            ValueError,
        ):
            return False
        if req is None:
            return False
        try:
            return await self._dispatch(req, writer)
        except HTTPError as exc:
            keep = not exc.close and req.keep_alive
            await self._send_error(writer, exc.status, exc.message, keep_alive=keep)
            return keep
        except (ConnectionError, asyncio.CancelledError):
            return False
        except Exception:
            logger.exception("unhandled error serving %s %s", req.method, req.path)
            with contextlib.suppress(Exception):
                await self._send(
                    writer, 500, jsonrpc_error_body(-32603, "Internal error"), keep_alive=False
                )
            return False

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
        writer.write(head(status, h) + body)
        await writer.drain()

    async def _send_error(
        self,
        writer: asyncio.StreamWriter,
        status: int,
        message: str,
        *,
        code: int = INVALID_REQUEST,
        headers: dict[str, str] | None = None,
        keep_alive: bool = True,
    ) -> None:
        body = jsonrpc_error_body(code, message)
        await self._send(writer, status, body, headers=headers, keep_alive=keep_alive)

    async def _reply(
        self, req: Request, writer: asyncio.StreamWriter, status: int, **kwargs: Any
    ) -> bool:
        """Send a bodiless or JSON reply that honours keep-alive."""
        await self._send(writer, status, keep_alive=req.keep_alive, **kwargs)
        return req.keep_alive

    def _cors_headers(self, req: Request) -> dict[str, str]:
        origin = req.headers.get("origin")
        if (
            not origin
            or not self.config.cors_origins
            or not match_any(origin, self.config.cors_origins)
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

    async def _dispatch(self, req: Request, writer: asyncio.StreamWriter) -> bool:
        cfg = self.config
        cors = self._cors_headers(req)
        rejected = self.guard.check(req.headers.get("host"), req.headers.get("origin"))
        if rejected is not None:
            await self._send_error(writer, *rejected, keep_alive=False)
            return False
        if req.method == "OPTIONS":
            return await self._preflight(req, writer, cors)
        if cfg.health_path and req.path == cfg.health_path and req.method == "GET":
            return await self._reply(req, writer, 200, body=b'{"status":"ok"}', headers=cors)
        principal = await self._authenticate(req, writer, cors)
        if principal is None:
            return req.keep_alive
        return await self._route(req, writer, principal, cors)

    async def _preflight(
        self, req: Request, writer: asyncio.StreamWriter, cors: dict[str, str]
    ) -> bool:
        if not cors:
            return await self._reply(req, writer, 405, headers={"Allow": "GET, POST, DELETE"})
        preflight = {
            **cors,
            "Access-Control-Allow-Methods": "GET, POST, DELETE, OPTIONS",
            "Access-Control-Allow-Headers": _ALLOW_HEADERS,
            "Access-Control-Max-Age": "600",
        }
        return await self._reply(req, writer, 204, headers=preflight)

    async def _authenticate(
        self, req: Request, writer: asyncio.StreamWriter, cors: dict[str, str]
    ) -> Principal | None:
        """The caller's principal, or ``None`` after answering ``401``."""
        auth = self.config.auth
        token_principal: Principal | None = None
        if auth:
            token_principal = auth.authenticate(req.headers.get("authorization"))
            if token_principal is None and auth.required:
                challenge = {**cors, "WWW-Authenticate": 'Bearer realm="cloudg-mcp"'}
                await self._send_error(
                    writer, 401, "Unauthorized", headers=challenge, keep_alive=req.keep_alive
                )
                return None
        info = RequestInfo(
            transport="http",
            headers=req.headers,
            session_id=req.headers.get("mcp-session-id"),
            principal=token_principal,
            raw=req,
        )
        return self.mcp.resolve_principal(info)

    async def _route(
        self, req: Request, writer: asyncio.StreamWriter, principal: Principal, cors: dict
    ) -> bool:
        cfg = self.config
        if req.path == cfg.path:
            handler = {"POST": self._post, "GET": self._get, "DELETE": self._delete}.get(req.method)
            if handler is None:
                return await self._reply(
                    req, writer, 405, headers={**cors, "Allow": "GET, POST, DELETE"}
                )
            return await handler(req, writer, principal, cors)
        if cfg.enable_sse and req.path == cfg.sse_path and req.method == "GET":
            return await self._legacy_sse(req, writer, principal, cors)
        legacy_post = req.path.rstrip("/") == cfg.message_path.rstrip("/") and req.method == "POST"
        if cfg.enable_sse and legacy_post:
            return await self._legacy_message(req, writer, principal, cors)
        await self._send_error(writer, 404, "Not Found", headers=cors, keep_alive=req.keep_alive)
        return req.keep_alive

    # -- POST -------------------------------------------------------------

    async def _json_body(self, req: Request, writer: asyncio.StreamWriter, cors: dict) -> Any:
        """The decoded JSON body, or ``_NO_BODY`` after answering ``400``."""
        try:
            return json.loads(req.body.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            await self._send_error(
                writer,
                400,
                "Parse error",
                code=PARSE_ERROR,
                headers=cors,
                keep_alive=req.keep_alive,
            )
            return _NO_BODY

    async def _post(
        self, req: Request, writer: asyncio.StreamWriter, principal: Principal, cors: dict
    ) -> bool:
        wants_json, wants_sse = post_accepts(req)
        msg = await self._json_body(req, writer, cors)
        if msg is _NO_BODY:
            return req.keep_alive
        if not isinstance(msg, (dict, list)):
            await self._send_error(
                writer, 400, "Invalid Request", headers=cors, keep_alive=req.keep_alive
            )
            return req.keep_alive
        ex = Exchange(req, writer, principal, dict(cors), msg, None, wants_json, wants_sse)
        if isinstance(msg, list) and any(
            isinstance(m, dict) and has_modern_envelope(m.get("params")) for m in msg
        ):
            text = "JSON-RPC batches are not supported by protocol version 2026-07-28"
            await self._send_error(writer, 400, text, headers=cors, keep_alive=req.keep_alive)
            return req.keep_alive
        if isinstance(msg, dict) and is_request(msg) and has_modern_envelope(msg.get("params")):
            return await self._post_modern(ex)
        ex.session = await self._post_session(ex)
        if not any(is_request(m) for m in ex.items):
            await ex.session.handle(msg, principal=principal)
            return await self._reply(req, writer, 202, headers=ex.headers)
        return await self._respond(ex)

    async def _post_modern(self, ex: Exchange) -> bool:
        """A 2026-07-28 self-describing request: no session."""
        rejection = modern_rejection(ex.msg, ex.req.headers)
        if rejection is not None:
            body = jsonrpc_error_body(*rejection, req_id=ex.msg.get("id"))
            return await self._reply(ex.req, ex.writer, 400, body=body, headers=ex.headers)
        ex.session = self.mcp.create_session(
            transport="http", principal=ex.principal, register=False
        )
        ex.modern = True
        return await self._respond(ex)

    async def _post_session(self, ex: Exchange) -> Session:
        """The session a handshake-era POST runs in (created on initialize)."""
        req, principal = ex.req, ex.principal
        pv_header = req.headers.get("mcp-protocol-version")
        if pv_header is not None and pv_header not in SUPPORTED_VERSIONS:
            raise HTTPError(400, f"Unsupported MCP-Protocol-Version: {pv_header}", close=False)
        msg = ex.msg
        is_init = isinstance(msg, dict) and msg.get("method") == "initialize" and is_request(msg)
        if self.config.stateless:
            version = None
            if not is_init:
                version = pv_header if pv_header in HANDSHAKE_VERSIONS else DEFAULT_HTTP_VERSION
            return self.mcp.create_session(
                transport="http", principal=principal, stateless_version=version, register=False
            )
        if is_init:
            hs = await self.table.new(principal, "streamable")
            ex.headers["Mcp-Session-Id"] = hs.session.session_id or ""
            return hs.session
        session = self.table.lookup(principal, req.headers.get("mcp-session-id")).session
        negotiated = session.protocol_version
        if pv_header in HANDSHAKE_VERSIONS and negotiated and pv_header != negotiated:
            raise HTTPError(
                400,
                f"MCP-Protocol-Version {pv_header} does not match the negotiated "
                f"version {negotiated}",
                close=False,
            )
        return session

    async def _respond(self, ex: Exchange) -> bool:
        items = ex.items
        streaming = any(is_request(m) and m.get("method") in _STREAMING_METHODS for m in items)
        listen = any(is_request(m) and m.get("method") == "subscriptions/listen" for m in items)
        if listen and not ex.wants_sse:
            raise HTTPError(
                406, "subscriptions/listen requires Accept: text/event-stream", close=False
            )
        sse_ok = not self.config.json_response and (streaming or not ex.wants_json)
        if ex.wants_sse and (listen or sse_ok):
            await self._respond_sse(ex, cancel_on_disconnect=ex.modern or listen)
        else:
            await self._respond_json(ex)
        return ex.req.keep_alive

    async def _respond_json(self, ex: Exchange) -> None:
        response = await ex.session.handle(ex.msg, principal=ex.principal)  # type: ignore[union-attr]
        if response is None:
            await self._send(ex.writer, 202, headers=ex.headers, keep_alive=ex.req.keep_alive)
            return
        status = 200
        error = response.get("error") if isinstance(response, dict) else None
        if ex.modern and (error or {}).get("code") == METHOD_NOT_FOUND:
            status = 404
        body = dumps(response).encode("utf-8")
        await self._send(ex.writer, status, body, headers=ex.headers, keep_alive=ex.req.keep_alive)

    async def _respond_sse(self, ex: Exchange, *, cancel_on_disconnect: bool) -> None:
        sse = SSEWriter(ex.writer)
        queue: asyncio.Queue[dict[str, Any]] = asyncio.Queue()

        async def sink(message: dict[str, Any]) -> None:
            await queue.put(message)

        task = asyncio.create_task(
            ex.session.handle(ex.msg, sink=sink, principal=ex.principal)  # type: ignore[union-attr]
        )
        try:
            await sse.start(ex.headers)
            await stream_until_done(sse, queue, task, self.config.keepalive_interval)
            response = task.result()
            for item in response if isinstance(response, list) else [response]:
                if item is not None:
                    await sse.message(item)
            await sse.end()
        except (ConnectionError, asyncio.CancelledError):
            # 2026-07-28: a broken stream loses the request; 2025: keep running
            if cancel_on_disconnect:
                task.cancel()
            raise

    # -- GET / DELETE -------------------------------------------------------

    async def _stateless_refusal(
        self, req: Request, writer: asyncio.StreamWriter, cors: dict
    ) -> bool | None:
        """``405`` for GET / DELETE in stateless mode (no sessions)."""
        if not self.config.stateless:
            return None
        return await self._reply(req, writer, 405, headers={**cors, "Allow": "POST"})

    async def _get(
        self, req: Request, writer: asyncio.StreamWriter, principal: Principal, cors: dict
    ) -> bool:
        refused = await self._stateless_refusal(req, writer, cors)
        if refused is not None:
            return refused
        _, wants_sse = accepts(req.headers)
        if not wants_sse:
            raise HTTPError(
                406, "Not Acceptable: GET requires Accept: text/event-stream", close=False
            )
        sid = req.headers.get("mcp-session-id")
        if not sid:
            return await self._reply(req, writer, 405, headers={**cors, "Allow": "POST, DELETE"})
        hs = self.table.lookup(principal, sid)
        if hs.stream_open:
            raise HTTPError(
                409, "Conflict: a GET stream is already open for this session", close=False
            )
        await pump(hs, writer, cors, self.config.keepalive_interval)
        return False

    async def _delete(
        self, req: Request, writer: asyncio.StreamWriter, principal: Principal, cors: dict
    ) -> bool:
        refused = await self._stateless_refusal(req, writer, cors)
        if refused is not None:
            return refused
        sid = req.headers.get("mcp-session-id")
        hs = self.table.lookup(principal, sid)
        self._sessions.pop(sid or "", None)
        await self._end_session(hs)
        return await self._reply(req, writer, 200, headers=cors)

    # -- legacy HTTP+SSE (2024-11-05) ------------------------------------------

    async def _legacy_sse(
        self, req: Request, writer: asyncio.StreamWriter, principal: Principal, cors: dict
    ) -> bool:
        hs = await self.table.new(principal, "sse")
        sid = hs.session.session_id or ""
        endpoint = f"{self.config.message_path}?session_id={sid}"
        try:
            await pump(
                hs, writer, cors, self.config.keepalive_interval, first_event=("endpoint", endpoint)
            )
        finally:
            self._sessions.pop(sid, None)
            hs.session.close()
        return False

    async def _legacy_message(
        self, req: Request, writer: asyncio.StreamWriter, principal: Principal, cors: dict
    ) -> bool:
        sid = (req.query.get("session_id") or [""])[0]
        if not sid:
            raise HTTPError(400, "session_id query parameter is required", close=False)
        hs = self._sessions.get(sid)
        if hs is None or hs.kind != "sse" or hs.principal.id != principal.id:
            raise HTTPError(404, "Session not found", close=False)
        msg = await self._json_body(req, writer, cors)
        if msg is _NO_BODY:
            return req.keep_alive
        hs.last_seen = time.monotonic()

        async def run() -> None:
            response = await hs.session.handle(msg, principal=principal)
            if response is not None:
                await hs.push(response)  # type: ignore[arg-type]

        if isinstance(msg, list) or (is_request(msg) and msg.get("method") != "initialize"):
            task = asyncio.create_task(run())
            self._conn_tasks.add(task)
            task.add_done_callback(self._conn_tasks.discard)
        else:
            await run()
        return await self._reply(req, writer, 202, headers=cors)


async def run_http_async(server: NativeMCPServer, config: HTTPConfig | None = None) -> None:
    """Serve ``server`` over HTTP until cancelled."""
    http = NativeHTTPServer(server, config)
    await http.start()
    await http.serve_forever()
