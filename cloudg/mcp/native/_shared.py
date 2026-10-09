"""Helpers shared by the native protocol engine and the SDK adapters.

Standard library only: log level handling, the change-notification model
(which events a layer change produces and which JSON-RPC notification each
becomes), per-request state of the native engine, and the mapping of layer
errors onto JSON-RPC error codes.
"""

from __future__ import annotations

import asyncio
import importlib
import logging
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Awaitable, Callable

from cloudg.mcp.core import InvalidArgumentsError, MCPLayerError, NotFoundError
from cloudg.mcp.native.jsonrpc import INVALID_PARAMS, LOG_LEVELS

if TYPE_CHECKING:  # pragma: no cover
    from cloudg.mcp.context import Principal
    from cloudg.mcp.native.protocol import Session

__all__ = [
    "CHANGE_METHODS",
    "LISTEN_FLAGS",
    "ListenStream",
    "RequestCtx",
    "Sender",
    "change_message",
    "expand_change",
    "layer_error_parts",
    "level_ok",
    "normalize_level",
    "run_on_loop",
    "sdk_installed",
]

Sender = Callable[[dict[str, Any]], Awaitable[None]]

CHANGE_METHODS = {
    "tools": "notifications/tools/list_changed",
    "prompts": "notifications/prompts/list_changed",
    "resources": "notifications/resources/list_changed",
}
LISTEN_FLAGS = {
    "tools": "toolsListChanged",
    "prompts": "promptsListChanged",
    "resources": "resourcesListChanged",
}
_LEVEL_ALIASES = {"warn": "warning", "fatal": "critical", "exception": "error", "trace": "debug"}
_NUMERIC_LEVELS = (
    (logging.CRITICAL, "critical"),
    (logging.ERROR, "error"),
    (logging.WARNING, "warning"),
    (logging.INFO, "info"),
)


def normalize_level(level: Any) -> str:
    """Map Python / loose level names onto the MCP (RFC 5424) levels."""
    if isinstance(level, int):
        return next((name for floor, name in _NUMERIC_LEVELS if level >= floor), "debug")
    name = str(level).lower()
    name = _LEVEL_ALIASES.get(name, name)
    return name if name in LOG_LEVELS else "info"


def level_ok(level: str, threshold: str | None) -> bool:
    """True when ``level`` is at or above ``threshold`` (``None``: nothing)."""
    if threshold is None:
        return False
    return LOG_LEVELS.index(level) >= LOG_LEVELS.index(threshold)


def expand_change(kind: str, uri: str | None) -> list[tuple[str, str | None]]:
    """The notification events one ``layer.notify_change(kind, uri)`` causes:
    ``("tools" | "prompts" | "resources", None)`` list changes and
    ``("resource", uri)`` updates."""
    if kind in ("resource", "resource_updated", "updated"):
        return [("resource", uri)] if uri else []
    if kind not in CHANGE_METHODS:
        return []
    events: list[tuple[str, str | None]] = [(kind, None)]
    if kind == "resources" and uri:
        events.append(("resource", uri))
    return events


def change_message(kind: str, uri: str | None, meta: dict[str, Any] | None = None) -> dict:
    """The JSON-RPC notification for one change event."""
    params: dict[str, Any] = {}
    if kind == "resource":
        method = "notifications/resources/updated"
        params["uri"] = uri
    else:
        method = CHANGE_METHODS[kind]
    if meta:
        params["_meta"] = dict(meta)
    msg: dict[str, Any] = {"jsonrpc": "2.0", "method": method}
    if params:
        msg["params"] = params
    return msg


def sdk_installed() -> bool:
    """True when the official ``mcp`` SDK's low-level server is importable."""
    try:
        importlib.import_module("mcp.server.lowlevel")
    except ImportError:
        return False
    return True


def run_on_loop(loop: asyncio.AbstractEventLoop | None, fn: Callable[..., Any], *args: Any) -> None:
    """Call ``fn(*args)`` on ``loop``: directly when already running on it,
    else (from a worker thread running a sync handler) through
    ``call_soon_threadsafe``. Does nothing once the loop is gone."""
    if loop is None or loop.is_closed():
        return
    try:
        running = asyncio.get_running_loop()
    except RuntimeError:
        running = None
    if running is loop:
        fn(*args)
    else:
        loop.call_soon_threadsafe(fn, *args)


def layer_error_parts(
    exc: MCPLayerError, *, not_found_code: int = INVALID_PARAMS, data: Any = None
) -> tuple[int, str, Any]:
    """``(code, message, data)`` of the JSON-RPC error for a layer error.
    ``data`` replaces the error's own data for not-found errors."""
    if isinstance(exc, NotFoundError):
        return not_found_code, exc.message, data if data is not None else exc.data
    if isinstance(exc, InvalidArgumentsError):
        return INVALID_PARAMS, exc.message, exc.data
    return exc.code, exc.message, exc.data


@dataclass(eq=False)
class ListenStream:
    """One open ``subscriptions/listen`` stream (2026-07-28)."""

    honored: dict[str, Any]
    queue: asyncio.Queue[tuple[str, str | None] | None] = field(
        default_factory=lambda: asyncio.Queue(maxsize=1024)
    )

    def wants(self, kind: str, uri: str | None) -> bool:
        if kind == "resource":
            return uri is not None and uri in (self.honored.get("resourceSubscriptions") or ())
        flag = LISTEN_FLAGS.get(kind)
        return bool(flag and self.honored.get(flag))


@dataclass
class RequestCtx:
    """Per-request state handed to method implementations."""

    session: "Session"
    req_id: Any
    method: str
    version: str
    modern: bool
    principal: "Principal"
    sink: Sender | None
    meta: dict[str, Any]
    log_level: str | None

    async def notify(self, method: str, params: dict[str, Any]) -> None:
        msg = {"jsonrpc": "2.0", "method": method, "params": params}
        if self.sink is not None:
            await self.sink(msg)
        else:
            await self.session.send_standalone(msg)
