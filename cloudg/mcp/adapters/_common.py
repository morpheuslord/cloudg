"""Helpers shared by the framework adapters.

* ownership checks: does a tool name / prompt name / resource URI belong to
  the cloudg layer, or to the host server's own primitives?
* :class:`ChangeFanout` forwards ``layer.on_change`` events to every live
  client session the adapter has seen, from any thread.
* small utilities: SDK version detection, level normalisation, safe calls.
"""

from __future__ import annotations

import asyncio
import importlib.metadata
import logging
import weakref
from typing import TYPE_CHECKING, Any, Awaitable, Callable, Iterable

from cloudg.mcp.context import Principal
from cloudg.mcp.core import MCPLayerError
from cloudg.mcp.native._shared import (
    expand_change,
    layer_error_parts,
    normalize_level,
    run_on_loop,
)
from cloudg.mcp.native.auth import (
    PRINCIPAL_SCOPE_KEY,
    PrincipalResolver,
    RequestInfo,
    default_principal_resolver,
)

if TYPE_CHECKING:  # pragma: no cover
    from cloudg.mcp.layer import CloudGMCPLayer

logger = logging.getLogger("cloudg.mcp.adapters")

ALL_KINDS = frozenset(
    {"tools", "resources", "templates", "prompts", "completions", "logging", "subscriptions"}
)

__all__ = [
    "ALL_KINDS",
    "ChangeFanout",
    "call_layer",
    "layer_error_parts",
    "normalize_kinds",
    "normalize_level",
    "owns_prompt",
    "owns_resource",
    "owns_template",
    "owns_tool",
    "package_version",
    "resolve_principal",
    "scope_principal",
    "send_change",
]


def package_version(name: str) -> str | None:
    try:
        return importlib.metadata.version(name)
    except importlib.metadata.PackageNotFoundError:
        return None


def major_version(name: str) -> int | None:
    v = package_version(name)
    if not v:
        return None
    try:
        return int(v.split(".")[0])
    except ValueError:
        return None


def normalize_kinds(include: Iterable[str] | None) -> frozenset[str]:
    if include is None:
        return ALL_KINDS
    kinds = frozenset(include)
    unknown = kinds - ALL_KINDS
    if unknown:
        raise ValueError(f"Unknown primitive kinds: {sorted(unknown)}; use {sorted(ALL_KINDS)}")
    return kinds


def owns_tool(layer: "CloudGMCPLayer", name: str) -> bool:
    if layer.prefix and not name.startswith(layer.prefix):
        return False
    return layer.internal_name(name) in layer.registry.tools


def owns_prompt(layer: "CloudGMCPLayer", name: str) -> bool:
    if layer.prefix and not name.startswith(layer.prefix):
        return False
    return layer.internal_name(name) in layer.registry.prompts


def owns_resource(layer: "CloudGMCPLayer", uri: str) -> bool:
    return uri in layer.registry.resources or layer.registry.find_template(uri) is not None


def owns_template(layer: "CloudGMCPLayer", uri_template: str) -> bool:
    return uri_template in layer.registry.templates


def resolve_principal(resolver: PrincipalResolver | None, info: RequestInfo) -> Principal:
    if resolver is not None:
        try:
            principal = resolver(info)
        except Exception:
            logger.exception("principal resolver failed; falling back to the default")
            principal = None
        if principal is not None:
            return principal
    return default_principal_resolver(info)


def lower_headers(headers: Any) -> dict[str, str]:
    if not headers:
        return {}
    try:
        items = headers.items()
    except AttributeError:
        return {}
    return {str(k).lower(): str(v) for k, v in items}


def scope_principal(request: Any) -> Principal | None:
    """The principal an auth middleware stored on an ASGI request
    (``scope["cloudg.principal"]`` or ``scope["state"]["cloudg.principal"]``)."""
    scope = getattr(request, "scope", None)
    if not isinstance(scope, dict):
        return None
    principal = scope.get(PRINCIPAL_SCOPE_KEY)
    state = scope.get("state")
    if principal is None and isinstance(state, dict):
        principal = state.get(PRINCIPAL_SCOPE_KEY)
    return principal


async def call_layer(
    call: Awaitable[Any],
    on_layer_error: Callable[[MCPLayerError], Exception],
    on_internal_error: Callable[[], Exception],
) -> Any:
    """Await a layer call. Layer errors (already run through the caller's
    output pipeline by the layer) map through ``on_layer_error``; anything
    else is logged here and replaced by ``on_internal_error()``, so raw
    exception text never reaches the client."""
    try:
        return await call
    except MCPLayerError as exc:
        raise on_layer_error(exc) from None
    except Exception:
        logger.exception("cloudg MCP layer call failed")
        raise on_internal_error() from None


async def send_change(session: Any, kind: str, uri: str | None) -> None:
    """Send one change notification through an SDK ``ServerSession``."""
    if kind == "tools":
        await session.send_tool_list_changed()
    elif kind == "prompts":
        await session.send_prompt_list_changed()
    elif kind == "resources":
        await session.send_resource_list_changed()
    elif kind == "resource" and uri:
        await session.send_resource_updated(uri)


Notifier = Callable[[Any, str, "str | None"], Awaitable[None]]


class ChangeFanout:
    """Forward layer change events to tracked client sessions.

    Adapters call :meth:`track` with each session object seen while handling
    a request and give a ``notifier(session, kind, uri)`` coroutine that
    sends the right notification for that framework. Events raised from
    worker threads are marshalled onto the event loop the adapter runs on.
    Resource-updated events only go to sessions subscribed to the URI.
    """

    def __init__(
        self,
        layer: "CloudGMCPLayer",
        notifier: Notifier,
        publish: Callable[[str, "str | None"], Awaitable[None]] | None = None,
    ) -> None:
        self.notifier = notifier
        self.publish = publish
        self.sessions: "weakref.WeakSet[Any]" = weakref.WeakSet()
        self.subscriptions: "weakref.WeakKeyDictionary[Any, set[str]]" = weakref.WeakKeyDictionary()
        self.log_levels: "weakref.WeakKeyDictionary[Any, str]" = weakref.WeakKeyDictionary()
        self.loop: asyncio.AbstractEventLoop | None = None
        self._pending: set[asyncio.Future[Any]] = set()
        ref = weakref.ref(self)

        def listener(kind: str, uri: str | None) -> None:
            me = ref()
            if me is not None:
                me.on_change(kind, uri)

        layer.on_change(listener)

    def bind_loop(self) -> None:
        if self.loop is None:
            try:
                self.loop = asyncio.get_running_loop()
            except RuntimeError:
                pass

    def track(self, session: Any) -> None:
        self.bind_loop()
        if session is None:
            return
        try:
            self.sessions.add(session)
        except TypeError:  # not weak-referenceable
            pass

    def subscribe(self, session: Any, uri: str) -> None:
        try:
            self.subscriptions.setdefault(session, set()).add(uri)
        except TypeError:
            pass

    def unsubscribe(self, session: Any, uri: str) -> None:
        try:
            self.subscriptions.get(session, set()).discard(uri)
        except TypeError:
            pass

    def set_level(self, session: Any, level: str) -> None:
        try:
            self.log_levels[session] = level
        except TypeError:
            pass

    def level_for(self, session: Any) -> str | None:
        try:
            return self.log_levels.get(session)
        except TypeError:
            return None

    def on_change(self, kind: str, uri: str | None) -> None:
        run_on_loop(self.loop, self._schedule, kind, uri)

    def _schedule(self, kind: str, uri: str | None) -> None:
        fut = asyncio.ensure_future(self._dispatch(kind, uri))
        self._pending.add(fut)
        fut.add_done_callback(self._pending.discard)

    def _wants(self, session: Any, kind: str, uri: str | None) -> bool:
        if kind != "resource":
            return True
        try:
            subs = self.subscriptions.get(session) or set()
        except TypeError:
            subs = set()
        return uri in subs

    async def _dispatch(self, kind: str, uri: str | None) -> None:
        for ev_kind, ev_uri in expand_change(kind, uri):
            if self.publish is not None:
                try:
                    await self.publish(ev_kind, ev_uri)
                except Exception:
                    logger.debug("subscription bus publish failed", exc_info=True)
            for session in [s for s in list(self.sessions) if self._wants(s, ev_kind, ev_uri)]:
                try:
                    await self.notifier(session, ev_kind, ev_uri)
                except Exception:
                    logger.debug("dropping session after failed notification", exc_info=True)
                    self.sessions.discard(session)
