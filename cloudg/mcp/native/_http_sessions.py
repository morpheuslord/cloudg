"""Configuration and session bookkeeping of the native Streamable HTTP
server (:mod:`cloudg.mcp.native.http`, which re-exports :class:`HTTPConfig`).

Session ids are 128 random bits (:func:`secrets.token_hex`), bound to the
principal that created them; :class:`SessionTable` enforces the overall and
per-principal caps and expires idle sessions.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import secrets
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Any

from cloudg.mcp.context import Principal
from cloudg.mcp.native._http_io import HTTPError, Request, SSEWriter
from cloudg.mcp.native.auth import TokenAuth
from cloudg.mcp.native.protocol import NativeMCPServer, Session

logger = logging.getLogger("cloudg.mcp.native.http")

__all__ = ["Exchange", "HTTPConfig", "HTTPSession", "SessionTable", "pump", "stream_until_done"]


@dataclass
class HTTPConfig:
    """Settings for :class:`NativeHTTPServer`.

    Attributes:
        host / port: Bind address (``port=0`` picks a free port).
        path: The Streamable HTTP endpoint.
        enable_sse: Also serve the deprecated 2024-11-05 HTTP+SSE transport.
        sse_path / message_path: Legacy SSE endpoints.
        allowed_origins: ``Origin`` patterns (``fnmatch``; ``*`` allows any).
            ``None`` allows loopback origins; same-origin requests are
            accepted when the ``Host`` header is validated (see
            :class:`OriginHostGuard`).
        allowed_hosts: ``Host`` patterns. ``None`` restricts loopback binds to
            loopback names and skips the Host check on other binds (the Origin
            check stays on).
        auth: Bearer-token authentication (``None`` = no auth).
        json_response: Always answer POSTs with JSON (never SSE).
        stateless: No sessions; every POST is self-contained.
        max_body_bytes: Request body limit (checked before the body is read).
        session_idle_timeout: Seconds of inactivity before a session expires.
        max_sessions: Concurrent session cap (``503`` beyond it).
        max_sessions_per_principal: Sessions one principal may hold; at the
            cap its least recently used idle session is ended to make room
            (``503`` when none is idle).
        max_connections: Concurrent connection cap (``503`` beyond it).
        header_timeout: Seconds a client has to send a request line and
            headers (also the keep-alive idle limit).
        body_timeout: Seconds a client has to send a request body.
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
    max_sessions_per_principal: int = 100
    max_connections: int = 512
    header_timeout: float = 30.0
    body_timeout: float = 120.0
    keepalive_interval: float = 15.0
    cors_origins: list[str] = field(default_factory=list)
    health_path: str | None = "/healthz"


@dataclass(eq=False)
class HTTPSession:
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


@dataclass
class Exchange:
    """One POST being answered: the request, its session and the decoded
    message, plus what the client accepts."""

    req: Request
    writer: asyncio.StreamWriter
    principal: Principal
    headers: dict[str, str]
    msg: Any = None
    session: Session | None = None
    wants_json: bool = True
    wants_sse: bool = True
    modern: bool = False

    @property
    def items(self) -> list[Any]:
        return self.msg if isinstance(self.msg, list) else [self.msg]


class SessionTable:
    """Live Streamable HTTP / legacy SSE sessions of one server."""

    def __init__(self, mcp: NativeMCPServer, config: HTTPConfig) -> None:
        self.mcp = mcp
        self.config = config
        self.sessions: dict[str, HTTPSession] = {}

    def lookup(self, principal: Principal, sid: str | None) -> HTTPSession:
        """The caller's session ``sid``: ``400`` without an id, ``404`` when
        unknown, closed, or owned by another principal."""
        if not sid:
            raise HTTPError(400, "Bad Request: Mcp-Session-Id header is required", close=False)
        hs = self.sessions.get(sid)
        if hs is None or hs.session.closed or hs.principal.id != principal.id:
            raise HTTPError(404, "Session not found", close=False)
        hs.last_seen = time.monotonic()
        return hs

    async def end(self, hs: HTTPSession) -> None:
        hs.session.close()
        await hs.push(None)

    async def _make_room(self, principal: Principal) -> None:
        """Enforce the per-principal cap by ending that principal's least
        recently used idle session; ``503`` when all of them are streaming."""
        mine = [(sid, hs) for sid, hs in self.sessions.items() if hs.principal.id == principal.id]
        if len(mine) < self.config.max_sessions_per_principal:
            return
        idle = [(hs.last_seen, sid, hs) for sid, hs in mine if not hs.stream_open]
        if not idle:
            raise HTTPError(503, "Too many sessions for this caller", close=False)
        _, sid, hs = min(idle, key=lambda item: item[0])
        logger.info("session cap reached for a principal; ending its oldest idle session")
        self.sessions.pop(sid, None)
        await self.end(hs)

    async def new(self, principal: Principal, kind: str) -> HTTPSession:
        """A new session for ``principal`` (``kind``: streamable | sse)."""
        await self._make_room(principal)
        if len(self.sessions) >= self.config.max_sessions:
            raise HTTPError(503, "Too many sessions", close=False)
        sid = secrets.token_hex(16)
        holder: dict[str, HTTPSession] = {}

        async def send(message: dict[str, Any]) -> None:
            await holder["hs"].push(message)

        session = self.mcp.create_session(
            transport="http" if kind == "streamable" else "sse",
            send=send,
            principal=principal,
            session_id=sid,
        )
        hs = HTTPSession(session=session, principal=principal, kind=kind)
        holder["hs"] = hs
        self.sessions[sid] = hs
        return hs

    async def reap_forever(self) -> None:
        """Expire sessions idle (no open stream) for ``session_idle_timeout``."""
        timeout = self.config.session_idle_timeout
        interval = max(1.0, min(60.0, timeout / 2))
        while True:
            await asyncio.sleep(interval)
            now = time.monotonic()
            for sid, hs in list(self.sessions.items()):
                if not hs.stream_open and now - hs.last_seen > timeout:
                    logger.debug("expiring idle MCP session")
                    self.sessions.pop(sid, None)
                    await self.end(hs)


# -- SSE streaming ----------------------------------------------------------


async def stream_until_done(
    sse: SSEWriter,
    queue: asyncio.Queue[dict[str, Any]],
    task: asyncio.Task[Any],
    keepalive: float,
) -> None:
    """Forward request-scoped notifications until ``task`` finishes,
    with keep-alive comments while it is quiet."""
    while True:
        getter = asyncio.ensure_future(queue.get())
        done, _ = await asyncio.wait(
            {getter, task},
            timeout=keepalive,
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


async def pump(
    hs: HTTPSession,
    writer: asyncio.StreamWriter,
    headers: dict[str, str],
    keepalive: float,
    first_event: tuple[str, str] | None = None,
) -> None:
    """Serve a session's standalone SSE stream until the session ends or
    the client goes away (a failed keep-alive write ends it)."""
    sse = SSEWriter(writer)
    hs.stream_open = True
    try:
        await sse.start(headers)
        if first_event:
            await sse.event(first_event[1], first_event[0])
        while await _pump_once(hs, sse, keepalive):
            hs.last_seen = time.monotonic()
    except (ConnectionError, asyncio.CancelledError):
        logger.debug("SSE stream closed by the client or the server")
    finally:
        hs.stream_open = False
        hs.last_seen = time.monotonic()


async def _pump_once(hs: HTTPSession, sse: SSEWriter, keepalive: float) -> bool:
    while hs.outbox:
        item = hs.outbox.popleft()
        if item is None:
            await sse.end()
            return False
        await sse.message(item)
    hs.wakeup.clear()
    try:
        await asyncio.wait_for(hs.wakeup.wait(), keepalive)
    except asyncio.TimeoutError:
        await sse.comment()
    return True
