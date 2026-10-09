"""Transport-independent MCP protocol engine for the native server.

:class:`NativeMCPServer` wraps a :class:`~cloudg.mcp.layer.CloudGMCPLayer`
and speaks the Model Context Protocol over JSON-RPC 2.0 without any
third-party dependency. A transport (stdio, streamable HTTP, legacy SSE, or
a test harness) creates one :class:`Session` per client connection and feeds
it decoded JSON messages; the session returns the response(s) and pushes
server-initiated notifications through the callables it was given.

Supported protocol revisions:

* Handshake era (``2024-11-05``, ``2025-03-26``, ``2025-06-18`` and
  ``2025-11-25``): ``initialize`` / ``notifications/initialized`` lifecycle
  with version negotiation, ``ping``, ``logging/setLevel``,
  ``resources/subscribe`` / ``unsubscribe``, list-changed and
  resource-updated notifications, ``notifications/cancelled``, progress
  notifications, and JSON-RPC batches where the negotiated revision allows
  them (``2024-11-05`` / ``2025-03-26``).
* Stateless era (``2026-07-28``): every request carries its protocol
  version and client capabilities in ``params._meta``; ``server/discover``;
  ``subscriptions/listen`` streams for change notifications; per-request log
  opt-in; ``resultType`` / ``ttlMs`` / ``cacheScope`` and the ``serverInfo``
  stamp on results.

Like the official SDK, the first request on a connection decides its era.

Every request is executed through the layer (``call_tool``,
``read_resource``, ``get_prompt``, ``complete``), so policies, transforms and
middleware apply exactly as for in-process calls. List results are paginated
with opaque cursors.
"""

from __future__ import annotations

import asyncio
import base64
import json
import logging
import weakref
from typing import TYPE_CHECKING, Any

from cloudg.mcp.context import Principal
from cloudg.mcp.native._methods import METHODS
from cloudg.mcp.native._shared import (
    ListenStream,
    RequestCtx,
    Sender,
    change_message,
    expand_change,
    level_ok,
    normalize_level,
    run_on_loop,
)
from cloudg.mcp.native.auth import PrincipalResolver, RequestInfo, default_principal_resolver
from cloudg.mcp.native.jsonrpc import (
    BATCH_VERSIONS,
    CACHEABLE_METHODS,
    CLIENT_CAPABILITIES_META_KEY,
    CLIENT_INFO_META_KEY,
    INTERNAL_ERROR,
    INVALID_PARAMS,
    INVALID_REQUEST,
    LATEST_HANDSHAKE_VERSION,
    LOG_LEVEL_META_KEY,
    LOG_LEVELS,
    METHOD_NOT_FOUND,
    MODERN_VERSIONS,
    PROTOCOL_VERSION_META_KEY,
    SERVER_INFO_META_KEY,
    UNSUPPORTED_PROTOCOL_VERSION,
    JSONRPCError,
    error_response,
    is_response,
    result_response,
    valid_id,
)

if TYPE_CHECKING:  # pragma: no cover
    from cloudg.mcp.layer import CloudGMCPLayer

logger = logging.getLogger("cloudg.mcp.native")

__all__ = ["NativeMCPServer", "Session", "Sender", "has_modern_envelope", "normalize_level"]


def has_modern_envelope(params: Any) -> bool:
    """True when ``params._meta`` carries the 2026-07-28 protocol-version key."""
    if not isinstance(params, dict):
        return False
    meta = params.get("_meta")
    return isinstance(meta, dict) and PROTOCOL_VERSION_META_KEY in meta


class NativeMCPServer:
    """Dependency-free MCP server over a :class:`CloudGMCPLayer`.

    Args:
        layer: The layer whose primitives are served.
        page_size: Items per page for list methods (``0`` disables paging).
        principal_resolver: ``fn(RequestInfo) -> Principal | None`` used by
            transports to identify callers (default:
            :func:`~cloudg.mcp.native.auth.default_principal_resolver`).
        default_log_level: Minimum level forwarded as
            ``notifications/message`` until the client calls
            ``logging/setLevel`` (handshake era).
        cache_ttl_ms / cache_scope: ``ttlMs`` / ``cacheScope`` reported on
            cacheable 2026-07-28 results. Lists vary per principal, hence the
            ``private`` default.
        title: Human-readable server title in ``serverInfo``.
    """

    def __init__(
        self,
        layer: "CloudGMCPLayer",
        *,
        page_size: int = 100,
        principal_resolver: PrincipalResolver | None = None,
        default_log_level: str = "info",
        cache_ttl_ms: int = 0,
        cache_scope: str = "private",
        title: str | None = "cloudg",
    ) -> None:
        self.layer = layer
        self.page_size = max(0, int(page_size))
        self.principal_resolver = principal_resolver or default_principal_resolver
        self.default_log_level = normalize_level(default_log_level)
        self.cache_ttl_ms = int(cache_ttl_ms)
        self.cache_scope = cache_scope
        self.title = title
        self.sessions: "weakref.WeakSet[Session]" = weakref.WeakSet()
        self._listens: set[ListenStream] = set()
        self._loop: asyncio.AbstractEventLoop | None = None
        self_ref = weakref.ref(self)

        def _listener(kind: str, uri: str | None) -> None:
            server = self_ref()
            if server is not None:
                server._on_layer_change(kind, uri)

        layer.on_change(_listener)

    # ------------------------------------------------------------------
    # Identity / capabilities
    # ------------------------------------------------------------------

    def server_info(self) -> dict[str, Any]:
        info: dict[str, Any] = {"name": self.layer.name, "version": str(self.layer.version)}
        if self.title:
            info["title"] = self.title
        return info

    def capabilities(self, version: str) -> dict[str, Any]:
        caps: dict[str, Any] = {
            "tools": {"listChanged": True},
            "resources": {"subscribe": True, "listChanged": True},
            "prompts": {"listChanged": True},
            "logging": {},
        }
        if version != "2024-11-05":
            caps["completions"] = {}
        return caps

    def resolve_principal(self, info: RequestInfo) -> Principal:
        try:
            principal = self.principal_resolver(info)
        except Exception:
            logger.exception("principal resolver failed; using anonymous")
            principal = None
        return principal or default_principal_resolver(
            RequestInfo(transport="http" if info.transport not in ("stdio", "memory") else "stdio")
        )

    # ------------------------------------------------------------------
    # Sessions
    # ------------------------------------------------------------------

    def create_session(
        self,
        *,
        transport: str = "stdio",
        send: Sender | None = None,
        principal: Principal | None = None,
        session_id: str | None = None,
        stateless_version: str | None = None,
        register: bool = True,
    ) -> "Session":
        """Create a session. ``stateless_version`` makes a pre-initialised
        handshake-era session (stateless HTTP mode); ``register=False``
        keeps a one-shot session out of change-notification fan-out."""
        self._bind_loop()
        session = Session(
            self,
            transport=transport,
            send=send,
            principal=principal,
            session_id=session_id,
            stateless_version=stateless_version,
        )
        if register and stateless_version is None:
            self.sessions.add(session)
        return session

    def _bind_loop(self) -> None:
        if self._loop is None:
            try:
                self._loop = asyncio.get_running_loop()
            except RuntimeError:
                pass

    def add_listen(self, stream: ListenStream) -> None:
        self._listens.add(stream)

    def discard_listen(self, stream: ListenStream) -> None:
        self._listens.discard(stream)

    def close_listens(self) -> None:
        """Ask every open ``subscriptions/listen`` stream to finish with its
        final result (graceful closure)."""
        for stream in list(self._listens):
            try:
                stream.queue.put_nowait(None)
            except asyncio.QueueFull:
                pass

    async def aclose(self) -> None:
        """End every open listen stream gracefully and close sessions."""
        self.close_listens()
        for session in list(self.sessions):
            session.close()
        await asyncio.sleep(0)

    # ------------------------------------------------------------------
    # Change notifications (layer.on_change -> clients)
    # ------------------------------------------------------------------

    def _on_layer_change(self, kind: str, uri: str | None) -> None:
        run_on_loop(self._loop, self._dispatch_change, kind, uri)

    def _dispatch_change(self, kind: str, uri: str | None) -> None:
        for ev_kind, ev_uri in expand_change(kind, uri):
            for stream in list(self._listens):
                if stream.wants(ev_kind, ev_uri):
                    try:
                        stream.queue.put_nowait((ev_kind, ev_uri))
                    except asyncio.QueueFull:
                        logger.warning("listen stream backlog full; dropping event")
            for session in list(self.sessions):
                session._emit_change(ev_kind, ev_uri)

    # ------------------------------------------------------------------
    # Pagination
    # ------------------------------------------------------------------

    def paginate(
        self, kind: str, items: list[dict[str, Any]], cursor: Any
    ) -> tuple[list[dict[str, Any]], str | None]:
        offset = 0
        if cursor is not None:
            if not isinstance(cursor, str):
                raise JSONRPCError(INVALID_PARAMS, "Invalid cursor")
            try:
                padded = cursor + "=" * (-len(cursor) % 4)
                data = json.loads(base64.urlsafe_b64decode(padded.encode()).decode())
                if data.get("k") != kind:
                    raise ValueError("cursor kind mismatch")
                offset = int(data["o"])
                if offset < 0:
                    raise ValueError("negative offset")
            except Exception:
                raise JSONRPCError(INVALID_PARAMS, "Invalid cursor") from None
        if not self.page_size:
            return items[offset:], None
        page = items[offset : offset + self.page_size]
        nxt = offset + self.page_size
        if nxt >= len(items):
            return page, None
        token = base64.urlsafe_b64encode(json.dumps({"k": kind, "o": nxt}).encode()).decode()
        return page, token.rstrip("=")


class Session:
    """One client connection (or one stateless HTTP exchange).

    Transports call :meth:`handle` with each decoded JSON message. ``send``
    delivers server-initiated messages that are not tied to a request
    (list-changed, resource-updated); request-scoped notifications (progress,
    log messages, listen-stream frames) go to the ``sink`` passed with the
    request, falling back to ``send``.
    """

    def __init__(
        self,
        server: NativeMCPServer,
        *,
        transport: str = "stdio",
        send: Sender | None = None,
        principal: Principal | None = None,
        session_id: str | None = None,
        stateless_version: str | None = None,
    ) -> None:
        self.server = server
        self.layer = server.layer
        self.transport = transport
        self.send = send
        self.principal = principal or server.resolve_principal(RequestInfo(transport=transport))
        self.session_id = session_id
        self.era: str | None = None
        self.protocol_version: str | None = None
        self.client_info: dict[str, Any] | None = None
        self.client_capabilities: dict[str, Any] | None = None
        self.init_responded = False
        self.initialized = False
        self.log_level: str = server.default_log_level
        self.subscriptions: set[str] = set()
        self.closed = False
        self._inflight: dict[Any, asyncio.Task[Any]] = {}
        self._cancelled: set[Any] = set()
        self._pending_sends: set[asyncio.Task[Any]] = set()
        if stateless_version is not None:
            self.era = "legacy"
            self.protocol_version = stateless_version
            self.init_responded = self.initialized = True

    # ------------------------------------------------------------------
    # Outbound
    # ------------------------------------------------------------------

    async def send_standalone(self, message: dict[str, Any]) -> None:
        if self.send is None or self.closed:
            return
        try:
            await self.send(message)
        except Exception:
            logger.debug("dropping server notification: transport send failed", exc_info=True)

    def _emit_change(self, kind: str, uri: str | None) -> None:
        if self.closed or self.era != "legacy" or not self.initialized or self.send is None:
            return
        if kind == "resource" and uri not in self.subscriptions:
            return
        msg = change_message(kind, uri)
        task = asyncio.ensure_future(self.send_standalone(msg))
        self._pending_sends.add(task)
        task.add_done_callback(self._pending_sends.discard)

    def close(self) -> None:
        self.closed = True
        for rid, task in list(self._inflight.items()):
            self._cancelled.add(rid)
            task.cancel()

    # ------------------------------------------------------------------
    # Inbound
    # ------------------------------------------------------------------

    def batch_allowed(self) -> bool:
        return self.era == "legacy" and self.protocol_version in BATCH_VERSIONS

    async def handle(
        self,
        message: Any,
        *,
        sink: Sender | None = None,
        principal: Principal | None = None,
    ) -> dict[str, Any] | list[dict[str, Any]] | None:
        """Process one decoded JSON-RPC message (or batch). Returns the
        response object, a list for batches, or ``None`` when nothing is to
        be sent back (notifications, responses, cancelled requests)."""
        if self.server._loop is None:
            self.server._bind_loop()
        if isinstance(message, list):
            if not message:
                return error_response(None, INVALID_REQUEST, "Invalid Request: empty batch")
            if not self.batch_allowed():
                return error_response(
                    None,
                    INVALID_REQUEST,
                    "JSON-RPC batches are not supported"
                    + (
                        f" by protocol version {self.protocol_version}"
                        if self.protocol_version
                        else " before initialization"
                    ),
                )
            results = await asyncio.gather(*(self._handle_one(m, sink, principal) for m in message))
            out = [r for r in results if r is not None]
            return out or None
        return await self._handle_one(message, sink, principal)

    async def _handle_one(
        self, msg: Any, sink: Sender | None, principal: Principal | None
    ) -> dict[str, Any] | None:
        rejected = _rejection(msg)
        if rejected is not _ACCEPT:
            return rejected  # type: ignore[return-value]
        method, params = msg["method"], msg.get("params") or {}
        if "id" in msg:
            return await self._handle_request(
                msg["id"], method, params, sink, principal or self.principal
            )
        await self._handle_notification(method, params)
        return None

    async def _handle_notification(self, method: str, params: dict[str, Any]) -> None:
        if method == "notifications/initialized":
            if self.era in (None, "legacy") and self.init_responded:
                self.initialized = True
            return
        if method == "notifications/cancelled":
            rid = params.get("requestId")
            task = self._inflight.get(rid)
            if task is not None and not task.done():
                self._cancelled.add(rid)
                task.cancel()
            return
        # notifications/progress, notifications/roots/list_changed, unknown: ignored

    async def _handle_request(
        self,
        req_id: Any,
        method: str,
        params: dict[str, Any],
        sink: Sender | None,
        principal: Principal,
    ) -> dict[str, Any] | None:
        task = asyncio.current_task()
        if task is not None:
            self._inflight[req_id] = task
        try:
            rc = self._route(req_id, method, params, sink, principal)
            impl = METHODS.get((rc.modern, method))
            if impl is None:
                raise JSONRPCError(METHOD_NOT_FOUND, "Method not found", method)
            result = await impl(self, rc, params)
            if rc.modern:
                result = self._stamp_modern(method, result)
            return result_response(req_id, result)
        except JSONRPCError as exc:
            return {"jsonrpc": "2.0", "id": req_id, "error": exc.to_error()}
        except asyncio.CancelledError:
            if req_id in self._cancelled:
                if task is not None and hasattr(task, "uncancel"):
                    task.uncancel()
                logger.debug("request %r cancelled by client", req_id)
                return None
            raise
        except Exception:
            logger.exception("internal error handling %s", method)
            return error_response(req_id, INTERNAL_ERROR, "Internal error")
        finally:
            self._inflight.pop(req_id, None)
            self._cancelled.discard(req_id)

    def _route(
        self,
        req_id: Any,
        method: str,
        params: dict[str, Any],
        sink: Sender | None,
        principal: Principal,
    ) -> RequestCtx:
        meta = params.get("_meta") if isinstance(params.get("_meta"), dict) else {}
        if method == "initialize":
            self._check_initialize(params)
            return RequestCtx(self, req_id, method, "", False, principal, sink, meta, None)
        if has_modern_envelope(params):
            version, log_level = self._enter_modern(meta)
            return RequestCtx(self, req_id, method, version, True, principal, sink, meta, log_level)
        if self.era == "modern":
            raise JSONRPCError(
                INVALID_PARAMS,
                f"params._meta must be an object carrying the required "
                f"{PROTOCOL_VERSION_META_KEY!r} and {CLIENT_CAPABILITIES_META_KEY!r} envelope keys",
            )
        if not self.init_responded and method != "ping":
            raise JSONRPCError(INVALID_REQUEST, "Server not initialized: send initialize first")
        version = self.protocol_version or LATEST_HANDSHAKE_VERSION
        return RequestCtx(
            self, req_id, method, version, False, principal, sink, meta, self.log_level
        )

    def _check_initialize(self, params: dict[str, Any]) -> None:
        if self.era != "modern":
            return
        requested = params.get("protocolVersion")
        raise JSONRPCError(
            UNSUPPORTED_PROTOCOL_VERSION,
            "connection is serving the 2026-07-28 protocol; initialize is not accepted",
            {
                "supported": list(MODERN_VERSIONS),
                **({"requested": requested} if isinstance(requested, str) else {}),
            },
        )

    def _enter_modern(self, meta: dict[str, Any]) -> tuple[str, str | None]:
        """Validate a 2026-07-28 envelope and switch the connection to that
        era; returns ``(version, requested log level)``."""
        if self.era == "legacy":
            raise JSONRPCError(
                INVALID_REQUEST,
                "this connection serves the handshake protocol era; requests carrying "
                "the 2026-07-28 envelope are not accepted on it",
            )
        if CLIENT_CAPABILITIES_META_KEY not in meta:
            raise JSONRPCError(
                INVALID_PARAMS,
                f"params._meta is missing the required envelope key(s): "
                f"{CLIENT_CAPABILITIES_META_KEY}",
            )
        version = meta.get(PROTOCOL_VERSION_META_KEY)
        if not isinstance(version, str):
            raise JSONRPCError(
                INVALID_PARAMS, "the protocol-version envelope value must be a string"
            )
        if version not in MODERN_VERSIONS:
            raise JSONRPCError(
                UNSUPPORTED_PROTOCOL_VERSION,
                f"Unsupported protocol version: {version}",
                {"supported": list(MODERN_VERSIONS), "requested": version},
            )
        self.era = "modern"
        self.protocol_version = version
        caps = meta.get(CLIENT_CAPABILITIES_META_KEY)
        self.client_capabilities = caps if isinstance(caps, dict) else None
        info = meta.get(CLIENT_INFO_META_KEY)
        if isinstance(info, dict):
            self.client_info = info
        lvl = meta.get(LOG_LEVEL_META_KEY)
        return version, (lvl if lvl in LOG_LEVELS else None)

    def _stamp_modern(self, method: str, result: dict[str, Any]) -> dict[str, Any]:
        result = dict(result)
        result.setdefault("resultType", "complete")
        if method in CACHEABLE_METHODS:
            result.setdefault("ttlMs", self.server.cache_ttl_ms)
            result.setdefault("cacheScope", self.server.cache_scope)
        meta = dict(result.get("_meta") or {})
        meta.setdefault(SERVER_INFO_META_KEY, self.server.server_info())
        result["_meta"] = meta
        return result

    # ------------------------------------------------------------------
    # Helpers for method implementations
    # ------------------------------------------------------------------

    def tool_context(self, rc: RequestCtx) -> Any:
        """The layer :class:`~cloudg.mcp.context.ToolContext` for one request,
        wired to send progress and log notifications to its client."""
        token = rc.meta.get("progressToken")
        if token is not None and not valid_id(token):
            token = None
        last: list[float] = []

        async def progress(progress: float, total: float | None, message: str | None) -> None:
            if token is None:
                return
            if last and progress <= last[0]:
                return  # spec: progress MUST increase
            last[:] = [progress]
            params: dict[str, Any] = {"progressToken": token, "progress": progress}
            if total is not None:
                params["total"] = total
            if message:
                params["message"] = message
            await rc.notify("notifications/progress", params)

        async def log(level: Any, data: Any, logger_name: str | None) -> None:
            lvl = normalize_level(level)
            threshold = rc.log_level if rc.modern else self.log_level
            if not level_ok(lvl, threshold):
                return
            params: dict[str, Any] = {"level": lvl, "data": data}
            if logger_name:
                params["logger"] = logger_name
            await rc.notify("notifications/message", params)

        return self.layer.context(
            rc.principal,
            request_id=rc.req_id,
            progress_callback=progress,
            log_callback=log,
            session=self,
        )

    _tool_context = tool_context  # pre-0.6.1 name


_ACCEPT = object()


def _rejection(msg: Any) -> Any:
    """The error response for a malformed message, ``None`` to drop it
    silently (stray responses, bad notifications), or ``_ACCEPT``."""
    rid = msg.get("id") if isinstance(msg, dict) and valid_id(msg.get("id")) else None
    if not isinstance(msg, dict) or msg.get("jsonrpc") != "2.0":
        return error_response(rid, INVALID_REQUEST, "Invalid Request")
    if "method" not in msg:
        # we never send requests, so responses are stray and ignored
        return None if is_response(msg) else error_response(rid, INVALID_REQUEST, "Invalid Request")
    if not isinstance(msg["method"], str):
        return error_response(rid, INVALID_REQUEST, "Invalid Request: method must be a string")
    has_id = "id" in msg
    if has_id and not valid_id(msg["id"]):
        return error_response(None, INVALID_REQUEST, "Invalid Request: bad id")
    params = msg.get("params")
    if params is not None and not isinstance(params, dict):
        return error_response(rid, INVALID_PARAMS, "params must be an object") if has_id else None
    return _ACCEPT
