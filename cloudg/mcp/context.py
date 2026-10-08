"""Per-call context handed to every tool, resource and prompt handler."""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Awaitable, Callable

from cloudg.mcp.core import ContentAnnotations, ResourceLink

if TYPE_CHECKING:  # pragma: no cover
    from cloudg.mcp.layer import CloudGMCPLayer
    from cloudg.mcp.state import Workspace

logger = logging.getLogger("cloudg.mcp")

ProgressCallback = Callable[[float, float | None, str | None], Awaitable[None] | None]
LogCallback = Callable[[str, Any, str | None], Awaitable[None] | None]

# MCP (RFC 5424) log levels -> stdlib levels
LOG_LEVELS = {
    "debug": logging.DEBUG,
    "info": logging.INFO,
    "notice": logging.INFO + 5,
    "warning": logging.WARNING,
    "error": logging.ERROR,
    "critical": logging.CRITICAL,
    "alert": logging.CRITICAL + 5,
    "emergency": logging.CRITICAL + 10,
}


@dataclass
class Principal:
    """Who is calling. Adapters derive it from the transport (HTTP auth
    header, stdio = local user); policies key access and transform rules
    off ``roles``."""

    id: str = "anonymous"
    roles: set[str] = field(default_factory=lambda: {"default"})
    attributes: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def local(cls) -> "Principal":
        return cls(id="local", roles={"default", "local"})


@dataclass
class ToolContext:
    """Context for one MCP request.

    Handlers use it to reach the shared :class:`~cloudg.mcp.state.Workspace`
    (loaded datasets and cached analyses), report progress, emit log
    notifications, and attach resource links to their result.
    """

    layer: "CloudGMCPLayer"
    principal: Principal = field(default_factory=Principal)
    kind: str = "tool"  # tool | resource | prompt | completion
    name: str = ""
    request_id: Any = None
    # Adapter-supplied callbacks; no-ops when the transport lacks them
    progress_callback: ProgressCallback | None = None
    log_callback: LogCallback | None = None
    # Opaque adapter session (mcp ServerSession / fastmcp Context / None)
    session: Any = None
    links: list[ResourceLink] = field(default_factory=list)
    meta: dict[str, Any] = field(default_factory=dict)
    # Event loop serving the request; lets sync handlers (which run in a
    # worker thread) report progress via report_progress_sync
    loop: asyncio.AbstractEventLoop | None = None
    _last_progress: float | None = field(default=None, repr=False)

    @property
    def workspace(self) -> "Workspace":
        return self.layer.workspace

    @property
    def config(self) -> Any:
        return self.layer.workspace.config

    async def report_progress(
        self, progress: float, total: float | None = None, message: str | None = None
    ) -> None:
        if self.progress_callback is None:
            return
        # MCP requires progress to increase with every notification
        if self._last_progress is not None and progress <= self._last_progress:
            return
        self._last_progress = progress
        try:
            res = self.progress_callback(progress, total, message)
            if hasattr(res, "__await__"):
                await res  # type: ignore[misc]
        except Exception:  # progress must never break a tool
            logger.debug("progress callback failed", exc_info=True)

    def report_progress_sync(
        self, progress: float, total: float | None = None, message: str | None = None
    ) -> None:
        """Progress from a sync handler running in a worker thread."""
        loop = self.loop
        if self.progress_callback is None or loop is None or loop.is_closed():
            return
        try:
            asyncio.run_coroutine_threadsafe(self.report_progress(progress, total, message), loop)
        except RuntimeError:
            logger.debug("progress dropped: loop not running", exc_info=True)

    async def log(self, level: str, data: Any, logger_name: str | None = "cloudg") -> None:
        """Send an MCP ``notifications/message`` (and log locally).
        ``level`` is an MCP level: debug, info, notice, warning, error,
        critical, alert or emergency."""
        level = str(level).lower()
        if level not in LOG_LEVELS:
            level = "info"
        logger.log(LOG_LEVELS[level], "%s", data)
        if self.log_callback is None:
            return
        try:
            res = self.log_callback(level, data, logger_name)
            if hasattr(res, "__await__"):
                await res  # type: ignore[misc]
        except Exception:
            logger.debug("log callback failed", exc_info=True)

    def link(
        self,
        uri: str,
        name: str,
        *,
        title: str | None = None,
        description: str | None = None,
        mime_type: str | None = "application/json",
        priority: float | None = None,
    ) -> None:
        """Attach a ``resource_link`` content block to this call's result."""
        ann = ContentAnnotations(priority=priority) if priority is not None else None
        self.links.append(
            ResourceLink(
                uri=uri,
                name=name,
                title=title,
                description=description,
                mime_type=mime_type,
                annotations=ann,
            )
        )
