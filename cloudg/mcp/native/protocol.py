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
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Awaitable, Callable

from cloudg.mcp.context import Principal
from cloudg.mcp.core import InvalidArgumentsError, MCPLayerError, NotFoundError
from cloudg.mcp.native.auth import PrincipalResolver, RequestInfo, default_principal_resolver
from cloudg.mcp.native.jsonrpc import (
    BATCH_VERSIONS,
    CACHEABLE_METHODS,
    CLIENT_CAPABILITIES_META_KEY,
    CLIENT_INFO_META_KEY,
    HANDSHAKE_VERSIONS,
    INTERNAL_ERROR,
    INVALID_PARAMS,
    INVALID_REQUEST,
    LATEST_HANDSHAKE_VERSION,
    LOG_LEVEL_META_KEY,
    LOG_LEVELS,
    METHOD_NOT_FOUND,
    MODERN_VERSIONS,
    PROTOCOL_VERSION_META_KEY,
    RESOURCE_NOT_FOUND,
    SERVER_INFO_META_KEY,
    SUBSCRIPTION_ID_META_KEY,
    SUPPORTED_VERSIONS,
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

Sender = Callable[[dict[str, Any]], Awaitable[None]]

__all__ = ["NativeMCPServer", "Session", "Sender", "has_modern_envelope", "normalize_level"]


def has_modern_envelope(params: Any) -> bool:
    """True when ``params._meta`` carries the 2026-07-28 protocol-version key."""
    if not isinstance(params, dict):
        return False
    meta = params.get("_meta")
    return isinstance(meta, dict) and PROTOCOL_VERSION_META_KEY in meta


def normalize_level(level: Any) -> str:
    """Map Python / loose level names onto the MCP (RFC 5424) levels."""
    if isinstance(level, int):
        if level >= logging.CRITICAL:
            return "critical"
        if level >= logging.ERROR:
            return "error"
        if level >= logging.WARNING:
            return "warning"
        if level >= logging.INFO:
            return "info"
        return "debug"
    name = str(level).lower()
    aliases = {"warn": "warning", "fatal": "critical", "exception": "error", "trace": "debug"}
    name = aliases.get(name, name)
    return name if name in LOG_LEVELS else "info"


def _level_ok(level: str, threshold: str | None) -> bool:
    if threshold is None:
        return False
    return LOG_LEVELS.index(level) >= LOG_LEVELS.index(threshold)


_CHANGE_METHODS = {
    "tools": "notifications/tools/list_changed",
    "prompts": "notifications/prompts/list_changed",
    "resources": "notifications/resources/list_changed",
}
_LISTEN_FLAGS = {
    "tools": "toolsListChanged",
    "prompts": "promptsListChanged",
    "resources": "resourcesListChanged",
}


@dataclass(eq=False)
class _ListenStream:
    """One open ``subscriptions/listen`` stream (2026-07-28)."""

    honored: dict[str, Any]
    queue: asyncio.Queue[tuple[str, str | None] | None] = field(
        default_factory=lambda: asyncio.Queue(maxsize=1024)
    )

    def wants(self, kind: str, uri: str | None) -> bool:
        if kind == "resource":
            return uri is not None and uri in (self.honored.get("resourceSubscriptions") or ())
        flag = _LISTEN_FLAGS.get(kind)
        return bool(flag and self.honored.get(flag))


@dataclass
class _RequestCtx:
    """Per-request state handed to method implementations."""

    session: "Session"
    req_id: Any
    method: str
    version: str
    modern: bool
    principal: Principal
    sink: Sender | None
    meta: dict[str, Any]
    log_level: str | None

    async def notify(self, method: str, params: dict[str, Any]) -> None:
        msg = {"jsonrpc": "2.0", "method": method, "params": params}
        if self.sink is not None:
            await self.sink(msg)
        else:
            await self.session.send_standalone(msg)


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
        self._listens: set[_ListenStream] = set()
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
        loop = self._loop
        if loop is None or loop.is_closed():
            return
        try:
            running = asyncio.get_running_loop()
        except RuntimeError:
            running = None
        if running is loop:
            self._dispatch_change(kind, uri)
        else:  # called from a worker thread (sync handler) -> hop to the loop
            loop.call_soon_threadsafe(self._dispatch_change, kind, uri)

    def _dispatch_change(self, kind: str, uri: str | None) -> None:
        events: list[tuple[str, str | None]] = []
        if kind in ("resource", "resource_updated", "updated"):
            if uri:
                events.append(("resource", uri))
        elif kind in _CHANGE_METHODS:
            events.append((kind, None))
            if kind == "resources" and uri:
                events.append(("resource", uri))
        for ev_kind, ev_uri in events:
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
        if kind == "resource":
            if uri not in self.subscriptions:
                return
            msg = {"jsonrpc": "2.0", "method": "notifications/resources/updated",
                   "params": {"uri": uri}}
        else:
            msg = {"jsonrpc": "2.0", "method": _CHANGE_METHODS[kind]}
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
                    + (f" by protocol version {self.protocol_version}" if self.protocol_version
                       else " before initialization"),
                )
            results = await asyncio.gather(
                *(self._handle_one(m, sink, principal) for m in message)
            )
            out = [r for r in results if r is not None]
            return out or None
        return await self._handle_one(message, sink, principal)

    async def _handle_one(
        self, msg: Any, sink: Sender | None, principal: Principal | None
    ) -> dict[str, Any] | None:
        if not isinstance(msg, dict) or msg.get("jsonrpc") != "2.0":
            rid = msg.get("id") if isinstance(msg, dict) and valid_id(msg.get("id")) else None
            return error_response(rid, INVALID_REQUEST, "Invalid Request")
        if "method" in msg:
            method = msg["method"]
            params = msg.get("params")
            has_id = "id" in msg
            if not isinstance(method, str):
                return error_response(
                    msg.get("id") if valid_id(msg.get("id")) else None,
                    INVALID_REQUEST,
                    "Invalid Request: method must be a string",
                )
            if has_id and not valid_id(msg["id"]):
                return error_response(None, INVALID_REQUEST, "Invalid Request: bad id")
            if params is not None and not isinstance(params, dict):
                if has_id:
                    return error_response(msg["id"], INVALID_PARAMS, "params must be an object")
                return None
            if has_id:
                return await self._handle_request(
                    msg["id"], method, params or {}, sink, principal or self.principal
                )
            await self._handle_notification(method, params or {})
            return None
        if is_response(msg):
            return None  # we never send requests; ignore stray responses
        return error_response(
            msg.get("id") if valid_id(msg.get("id")) else None, INVALID_REQUEST, "Invalid Request"
        )

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
            impl = _METHODS.get((rc.modern, method))
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
    ) -> _RequestCtx:
        meta = params.get("_meta") if isinstance(params.get("_meta"), dict) else {}
        if method == "initialize":
            if self.era == "modern":
                requested = params.get("protocolVersion")
                raise JSONRPCError(
                    UNSUPPORTED_PROTOCOL_VERSION,
                    "connection is serving the 2026-07-28 protocol; initialize is not accepted",
                    {"supported": list(MODERN_VERSIONS),
                     **({"requested": requested} if isinstance(requested, str) else {})},
                )
            return _RequestCtx(self, req_id, method, "", False, principal, sink, meta, None)

        if has_modern_envelope(params):
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
                raise JSONRPCError(INVALID_PARAMS, "the protocol-version envelope value must be a "
                                                   "string")
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
            log_level = lvl if lvl in LOG_LEVELS else None
            return _RequestCtx(self, req_id, method, version, True, principal, sink, meta,
                               log_level)

        if self.era == "modern":
            raise JSONRPCError(
                INVALID_PARAMS,
                f"params._meta must be an object carrying the required "
                f"{PROTOCOL_VERSION_META_KEY!r} and {CLIENT_CAPABILITIES_META_KEY!r} envelope keys",
            )
        if not self.init_responded and method != "ping":
            raise JSONRPCError(INVALID_REQUEST, "Server not initialized: send initialize first")
        return _RequestCtx(
            self, req_id, method, self.protocol_version or LATEST_HANDSHAKE_VERSION, False,
            principal, sink, meta, self.log_level,
        )

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

    def _tool_context(self, rc: _RequestCtx) -> Any:
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
            if not _level_ok(lvl, threshold):
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


# ---------------------------------------------------------------------------
# Method implementations
# ---------------------------------------------------------------------------

MethodImpl = Callable[[Session, _RequestCtx, dict[str, Any]], Awaitable[dict[str, Any]]]


def _str_param(params: dict[str, Any], key: str) -> str:
    value = params.get(key)
    if not isinstance(value, str) or not value:
        raise JSONRPCError(INVALID_PARAMS, f"Missing or invalid parameter: {key}")
    return value


def _layer_error(exc: MCPLayerError, *, not_found_code: int = INVALID_PARAMS,
                 data: Any = None) -> JSONRPCError:
    if isinstance(exc, NotFoundError):
        return JSONRPCError(not_found_code, exc.message, data if data is not None else exc.data)
    if isinstance(exc, InvalidArgumentsError):
        return JSONRPCError(INVALID_PARAMS, exc.message, exc.data)
    return JSONRPCError(exc.code, exc.message, exc.data)


async def _m_initialize(s: Session, rc: _RequestCtx, params: dict[str, Any]) -> dict[str, Any]:
    if s.init_responded:
        raise JSONRPCError(INVALID_REQUEST, "Session already initialized")
    requested = params.get("protocolVersion")
    if not isinstance(requested, str):
        raise JSONRPCError(INVALID_PARAMS, "initialize requires a protocolVersion string")
    version = requested if requested in HANDSHAKE_VERSIONS else LATEST_HANDSHAKE_VERSION
    s.era = "legacy"
    s.protocol_version = version
    s.client_capabilities = params.get("capabilities") if isinstance(
        params.get("capabilities"), dict) else {}
    s.client_info = params.get("clientInfo") if isinstance(params.get("clientInfo"), dict) else None
    s.init_responded = True
    result: dict[str, Any] = {
        "protocolVersion": version,
        "capabilities": s.server.capabilities(version),
        "serverInfo": s.server.server_info(),
    }
    if s.layer.instructions:
        result["instructions"] = s.layer.instructions
    return result


async def _m_ping(s: Session, rc: _RequestCtx, params: dict[str, Any]) -> dict[str, Any]:
    return {}


async def _m_discover(s: Session, rc: _RequestCtx, params: dict[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {
        "supportedVersions": list(SUPPORTED_VERSIONS),
        "capabilities": s.server.capabilities(rc.version),
    }
    if s.layer.instructions:
        out["instructions"] = s.layer.instructions
    return out


async def _m_tools_list(s: Session, rc: _RequestCtx, params: dict[str, Any]) -> dict[str, Any]:
    items = s.layer.tools_wire(rc.principal)
    page, nxt = s.server.paginate("tools", items, params.get("cursor"))
    out: dict[str, Any] = {"tools": page}
    if nxt:
        out["nextCursor"] = nxt
    return out


async def _m_tools_call(s: Session, rc: _RequestCtx, params: dict[str, Any]) -> dict[str, Any]:
    name = _str_param(params, "name")
    arguments = params.get("arguments")
    if arguments is not None and not isinstance(arguments, dict):
        raise JSONRPCError(INVALID_PARAMS, "arguments must be an object")
    ctx = s._tool_context(rc)
    try:
        result = await s.layer.call_tool(name, arguments or {}, principal=rc.principal, context=ctx)
    except NotFoundError as exc:
        raise JSONRPCError(INVALID_PARAMS, exc.message, {"name": name}) from None
    except MCPLayerError as exc:
        raise _layer_error(exc) from None
    return result.to_wire()


async def _m_resources_list(s: Session, rc: _RequestCtx, params: dict[str, Any]) -> dict[str, Any]:
    items = s.layer.resources_wire(rc.principal)
    page, nxt = s.server.paginate("resources", items, params.get("cursor"))
    out: dict[str, Any] = {"resources": page}
    if nxt:
        out["nextCursor"] = nxt
    return out


async def _m_templates_list(s: Session, rc: _RequestCtx, params: dict[str, Any]) -> dict[str, Any]:
    items = s.layer.resource_templates_wire(rc.principal)
    page, nxt = s.server.paginate("templates", items, params.get("cursor"))
    out: dict[str, Any] = {"resourceTemplates": page}
    if nxt:
        out["nextCursor"] = nxt
    return out


async def _m_resources_read(s: Session, rc: _RequestCtx, params: dict[str, Any]) -> dict[str, Any]:
    uri = _str_param(params, "uri")
    ctx = s._tool_context(rc)
    try:
        contents = await s.layer.read_resource(uri, principal=rc.principal, context=ctx)
    except MCPLayerError as exc:
        code = INVALID_PARAMS if rc.modern else RESOURCE_NOT_FOUND
        raise _layer_error(exc, not_found_code=code, data={"uri": uri}) from None
    return {"contents": [c.to_wire() for c in contents]}


async def _m_subscribe(s: Session, rc: _RequestCtx, params: dict[str, Any]) -> dict[str, Any]:
    s.subscriptions.add(_str_param(params, "uri"))
    return {}


async def _m_unsubscribe(s: Session, rc: _RequestCtx, params: dict[str, Any]) -> dict[str, Any]:
    s.subscriptions.discard(_str_param(params, "uri"))
    return {}


async def _m_prompts_list(s: Session, rc: _RequestCtx, params: dict[str, Any]) -> dict[str, Any]:
    items = s.layer.prompts_wire(rc.principal)
    page, nxt = s.server.paginate("prompts", items, params.get("cursor"))
    out: dict[str, Any] = {"prompts": page}
    if nxt:
        out["nextCursor"] = nxt
    return out


async def _m_prompts_get(s: Session, rc: _RequestCtx, params: dict[str, Any]) -> dict[str, Any]:
    name = _str_param(params, "name")
    arguments = params.get("arguments")
    if arguments is not None and not isinstance(arguments, dict):
        raise JSONRPCError(INVALID_PARAMS, "arguments must be an object")
    ctx = s._tool_context(rc)
    try:
        result = await s.layer.get_prompt(name, arguments or {}, principal=rc.principal,
                                          context=ctx)
    except MCPLayerError as exc:
        raise _layer_error(exc) from None
    return result.to_wire()


async def _m_complete(s: Session, rc: _RequestCtx, params: dict[str, Any]) -> dict[str, Any]:
    ref = params.get("ref")
    argument = params.get("argument")
    if not isinstance(ref, dict) or ref.get("type") not in ("ref/prompt", "ref/resource"):
        raise JSONRPCError(INVALID_PARAMS, "Invalid completion ref")
    if not isinstance(argument, dict) or not isinstance(argument.get("name"), str):
        raise JSONRPCError(INVALID_PARAMS, "Invalid completion argument")
    context = params.get("context") if isinstance(params.get("context"), dict) else {}
    ctx_args = context.get("arguments") if isinstance(context.get("arguments"), dict) else None
    try:
        completion = await s.layer.complete(
            ref, argument, principal=rc.principal, context_arguments=ctx_args
        )
    except MCPLayerError as exc:
        raise _layer_error(exc) from None
    return {"completion": completion}


async def _m_set_level(s: Session, rc: _RequestCtx, params: dict[str, Any]) -> dict[str, Any]:
    level = params.get("level")
    if level not in LOG_LEVELS:
        raise JSONRPCError(INVALID_PARAMS, f"Invalid log level: {level!r}")
    s.log_level = level
    return {}


async def _m_listen(s: Session, rc: _RequestCtx, params: dict[str, Any]) -> dict[str, Any]:
    requested = params.get("notifications")
    if not isinstance(requested, dict):
        raise JSONRPCError(INVALID_PARAMS, "subscriptions/listen requires a notifications filter")
    honored: dict[str, Any] = {}
    for flag in _LISTEN_FLAGS.values():
        if requested.get(flag) is True:
            honored[flag] = True
    uris = requested.get("resourceSubscriptions")
    if isinstance(uris, list):
        clean = [u for u in uris if isinstance(u, str)]
        if clean:
            honored["resourceSubscriptions"] = clean
    meta = {SUBSCRIPTION_ID_META_KEY: rc.req_id}
    stream = _ListenStream(honored)
    s.server._listens.add(stream)
    try:
        await rc.notify(
            "notifications/subscriptions/acknowledged",
            {"notifications": honored, "_meta": dict(meta)},
        )
        while True:
            event = await stream.queue.get()
            if event is None:
                break
            kind, uri = event
            if kind == "resource":
                await rc.notify("notifications/resources/updated",
                                {"uri": uri, "_meta": dict(meta)})
            else:
                await rc.notify(_CHANGE_METHODS[kind], {"_meta": dict(meta)})
    finally:
        s.server._listens.discard(stream)
    return {"_meta": dict(meta)}


_COMMON: dict[str, MethodImpl] = {
    "tools/list": _m_tools_list,
    "tools/call": _m_tools_call,
    "resources/list": _m_resources_list,
    "resources/templates/list": _m_templates_list,
    "resources/read": _m_resources_read,
    "prompts/list": _m_prompts_list,
    "prompts/get": _m_prompts_get,
    "completion/complete": _m_complete,
}
_LEGACY_ONLY: dict[str, MethodImpl] = {
    "initialize": _m_initialize,
    "ping": _m_ping,
    "resources/subscribe": _m_subscribe,
    "resources/unsubscribe": _m_unsubscribe,
    "logging/setLevel": _m_set_level,
}
_MODERN_ONLY: dict[str, MethodImpl] = {
    "server/discover": _m_discover,
    "subscriptions/listen": _m_listen,
}
_METHODS: dict[tuple[bool, str], MethodImpl] = {
    **{(False, m): f for m, f in {**_COMMON, **_LEGACY_ONLY}.items()},
    **{(True, m): f for m, f in {**_COMMON, **_MODERN_ONLY}.items()},
}
