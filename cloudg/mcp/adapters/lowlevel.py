"""Adapter for the official SDK's low-level ``Server`` (mcp 1.x and 2.x).

The low-level server dispatches JSON-RPC methods to handler callables. This
adapter *wraps* the handlers already registered (if any) instead of
replacing them: list methods return the host's own primitives followed by
the cloudg ones, and ``tools/call`` / ``resources/read`` / ``prompts/get`` /
``completion/complete`` route by ownership: cloudg names / URIs go to the
:class:`~cloudg.mcp.layer.CloudGMCPLayer`, everything else to the original
handler. A server with no handlers simply becomes a cloudg server.

Because tools are listed from the layer's wire dicts, the exact
``inputSchema`` / ``outputSchema`` / ``annotations`` / ``title`` / ``_meta``
reach the client; the SDK never re-derives anything from Python signatures.

Version differences handled here:

* mcp 2.x: ``Server.add_request_handler(method, params_type, handler)``
  with ``handler(ctx: ServerRequestContext, params)``; progress via
  ``ctx.session.report_progress``; log messages via
  ``ctx.session.send_log_message``; legacy-era change notifications through
  the per-connection ``Connection``; 2026-07-28 change notifications through
  the ``subscriptions/listen`` bus (installed when the server has none).
* mcp 1.x: ``Server.request_handlers[RequestType] = handler(req)``
  returning ``ServerResult``; request context from ``server.request_context``.

The higher-level ``MCPServer`` (2.x) and ``FastMCP`` (1.x) are adapted by
applying this module to their inner low-level server
(:mod:`cloudg.mcp.adapters.mcp_sdk`).
"""

from __future__ import annotations

import logging
import warnings
from typing import TYPE_CHECKING, Any, Awaitable, Callable

from cloudg.mcp.adapters._common import (
    ChangeFanout,
    lower_headers,
    normalize_kinds,
    normalize_level,
    owns_prompt,
    owns_resource,
    owns_template,
    owns_tool,
    resolve_principal,
)
from cloudg.mcp.context import Principal
from cloudg.mcp.core import InvalidArgumentsError, MCPLayerError, NotFoundError
from cloudg.mcp.native.auth import PRINCIPAL_SCOPE_KEY, PrincipalResolver, RequestInfo
from cloudg.mcp.native.jsonrpc import INVALID_PARAMS, LOG_LEVELS, RESOURCE_NOT_FOUND

if TYPE_CHECKING:  # pragma: no cover
    from cloudg.mcp.layer import CloudGMCPLayer

logger = logging.getLogger("cloudg.mcp.adapters.lowlevel")

__all__ = ["LowLevelBinding", "install", "is_lowlevel_server"]

OrigCall = Callable[[], Awaitable[Any]] | None

# method -> (v1 request class, v2 params class, result class, kind gate, impl name)
_METHODS: list[tuple[str, str, str, str, str]] = [
    ("tools/list", "ListToolsRequest", "PaginatedRequestParams", "tools", "_list_tools"),
    ("tools/call", "CallToolRequest", "CallToolRequestParams", "tools", "_call_tool"),
    ("resources/list", "ListResourcesRequest", "PaginatedRequestParams", "resources",
     "_list_resources"),
    ("resources/templates/list", "ListResourceTemplatesRequest", "PaginatedRequestParams",
     "templates", "_list_templates"),
    ("resources/read", "ReadResourceRequest", "ReadResourceRequestParams", "resources",
     "_read_resource"),
    ("prompts/list", "ListPromptsRequest", "PaginatedRequestParams", "prompts", "_list_prompts"),
    ("prompts/get", "GetPromptRequest", "GetPromptRequestParams", "prompts", "_get_prompt"),
    ("completion/complete", "CompleteRequest", "CompleteRequestParams", "completions",
     "_complete"),
    ("resources/subscribe", "SubscribeRequest", "SubscribeRequestParams", "subscriptions",
     "_subscribe"),
    ("resources/unsubscribe", "UnsubscribeRequest", "UnsubscribeRequestParams", "subscriptions",
     "_unsubscribe"),
    ("logging/setLevel", "SetLevelRequest", "SetLevelRequestParams", "logging", "_set_level"),
]


def is_lowlevel_server(obj: Any) -> bool:
    try:
        from mcp.server.lowlevel import Server
    except Exception:
        return False
    return isinstance(obj, Server)


def _dump(params: Any) -> dict[str, Any]:
    if params is None:
        return {}
    if isinstance(params, dict):
        return params
    try:
        return params.model_dump(by_alias=True, mode="json", exclude_none=True)
    except Exception:
        return {}


class LowLevelBinding:
    """The installed adapter; keeps the change fan-out alive.

    Attributes:
        layer / server: What was bound.
        sdk_major: 1 or 2.
        fanout: Forwards ``layer.notify_change`` to connected clients.
    """

    def __init__(
        self,
        layer: "CloudGMCPLayer",
        server: Any,
        *,
        include: Any = None,
        principal_resolver: PrincipalResolver | None = None,
        owner: Any = None,
        list_changed: bool = True,
    ) -> None:
        import mcp.types as T

        self.layer = layer
        self.server = server
        self.owner = owner
        self.T = T
        self.kinds = normalize_kinds(include)
        self.resolver = principal_resolver
        self.sdk_major = 2 if hasattr(server, "add_request_handler") else 1
        self.modern_versions: tuple[str, ...] = ()
        if self.sdk_major == 2:
            try:
                from mcp_types.version import MODERN_PROTOCOL_VERSIONS

                self.modern_versions = tuple(MODERN_PROTOCOL_VERSIONS)
            except Exception:  # pragma: no cover (layout change)
                self.modern_versions = ("2026-07-28",)
        self.bus = self._find_bus() if self.sdk_major == 2 else None
        self.fanout = ChangeFanout(layer, self._notify, self._publish if self.bus else None)
        self._install()
        if list_changed:
            self._patch_initialization_options()
        if self.sdk_major == 2:
            self._patch_input_schema()
        try:
            server.__dict__.setdefault("_cloudg_bindings", []).append(self)
        except Exception:
            pass

    # ------------------------------------------------------------------
    # Installation
    # ------------------------------------------------------------------

    def _install(self) -> None:
        T = self.T
        for method, v1_req, v2_params, kind, impl_name in _METHODS:
            if kind not in self.kinds:
                continue
            impl = getattr(self, impl_name)
            if self.sdk_major == 2:
                entry = self.server.get_request_handler(method)
                orig = entry.handler if entry is not None else None
                ptype = entry.params_type if entry is not None else getattr(T, v2_params)
                self.server.add_request_handler(method, ptype, self._v2_handler(impl, orig))
            else:
                req_cls = getattr(T, v1_req, None)
                if req_cls is None:  # very old 1.x without this method
                    continue
                orig = self.server.request_handlers.get(req_cls)
                self.server.request_handlers[req_cls] = self._v1_handler(impl, orig)

    def _v2_handler(self, impl: Any, orig: Any) -> Any:
        async def handler(ctx: Any, params: Any) -> Any:
            orig_call = (lambda: orig(ctx, params)) if orig is not None else None
            return await impl(ctx, _dump(params), orig_call)

        return handler

    def _v1_handler(self, impl: Any, orig: Any) -> Any:
        T = self.T
        server = self.server

        async def handler(req: Any) -> Any:
            try:
                ctx = server.request_context
            except LookupError:
                ctx = None

            async def orig_call() -> Any:
                res = await orig(req)
                return getattr(res, "root", res)

            params = _dump(getattr(req, "params", None)) if req is not None else {}
            result = await impl(ctx, params, orig_call if orig is not None else None)
            return T.ServerResult(result)

        return handler

    def _find_bus(self) -> Any:
        bus = getattr(self.owner, "_subscriptions", None)
        if bus is not None:
            return bus
        entry = self.server.get_request_handler("subscriptions/listen")
        if entry is not None:
            return getattr(entry.handler, "_bus", None)
        if "subscriptions" not in self.kinds:
            return None
        try:
            from mcp.server.subscriptions import InMemorySubscriptionBus, ListenHandler

            bus = InMemorySubscriptionBus()
            self.server.add_request_handler(
                "subscriptions/listen", self.T.SubscriptionsListenRequestParams,
                ListenHandler(bus),
            )
            return bus
        except Exception:
            logger.debug("could not install a subscriptions/listen handler", exc_info=True)
            return None

    def _patch_initialization_options(self) -> None:
        server = self.server
        if getattr(server, "_cloudg_init_patched", False):
            return
        try:
            from mcp.server.lowlevel import NotificationOptions
        except Exception:  # pragma: no cover
            return
        original = server.create_initialization_options

        def create_initialization_options(notification_options: Any = None, *args: Any,
                                          **kwargs: Any) -> Any:
            if notification_options is None:
                notification_options = NotificationOptions(
                    prompts_changed=True, resources_changed=True, tools_changed=True
                )
            return original(notification_options, *args, **kwargs)

        server.create_initialization_options = create_initialization_options
        server._cloudg_init_patched = True

    def _patch_input_schema(self) -> None:
        server = self.server
        previous = getattr(server, "get_tool_input_schema", None)
        layer = self.layer

        def get_tool_input_schema(name: str) -> Any:
            if owns_tool(layer, name):
                spec = layer.registry.tools.get(layer.internal_name(name))
                return spec.input_schema if spec is not None else None
            return previous(name) if previous is not None else None

        if "tools" in self.kinds and previous is not None:
            server.get_tool_input_schema = get_tool_input_schema

    # ------------------------------------------------------------------
    # Request context helpers
    # ------------------------------------------------------------------

    def _is_modern(self, ctx: Any) -> bool:
        return bool(self.modern_versions) and getattr(ctx, "protocol_version", None) in (
            self.modern_versions
        )

    def _session_key(self, ctx: Any) -> Any:
        if ctx is None:
            return None
        session = getattr(ctx, "session", None)
        if self.sdk_major == 2:
            if self._is_modern(ctx):
                return None
            return getattr(session, "_connection", None)
        return session

    def request_info(self, ctx: Any) -> RequestInfo:
        request = getattr(ctx, "request", None) if ctx is not None else None
        headers = lower_headers(getattr(request, "headers", None)) if request is not None else {}
        principal: Principal | None = None
        scope = getattr(request, "scope", None)
        if isinstance(scope, dict):
            principal = scope.get(PRINCIPAL_SCOPE_KEY)
            state = scope.get("state")
            if principal is None and isinstance(state, dict):
                principal = state.get(PRINCIPAL_SCOPE_KEY)
        token = None
        try:
            from mcp.server.auth.middleware.auth_context import get_access_token

            token = get_access_token()
        except Exception:
            token = None
        client_info = None
        try:
            params = ctx.session.client_params  # type: ignore[union-attr]
            info = getattr(params, "client_info", None) or getattr(params, "clientInfo", None)
            if info is not None:
                client_info = info.model_dump(mode="json")
        except Exception:
            client_info = None
        return RequestInfo(
            transport="http" if request is not None else "stdio",
            headers=headers,
            session_id=headers.get("mcp-session-id"),
            client_info=client_info,
            access_token=token,
            principal=principal,
            raw=ctx,
        )

    def _principal(self, ctx: Any) -> Principal:
        return resolve_principal(self.resolver, self.request_info(ctx))

    def _track(self, ctx: Any) -> None:
        self.fanout.track(self._session_key(ctx))

    def _error(self, code: int, message: str, data: Any = None) -> Exception:
        if self.sdk_major == 2:
            from mcp.shared.exceptions import MCPError

            return MCPError(code, message, data)
        from mcp.shared.exceptions import McpError
        from mcp.types import ErrorData

        return McpError(ErrorData(code=code, message=message, data=data))

    def _layer_error(self, exc: MCPLayerError, not_found_code: int = INVALID_PARAMS,
                     data: Any = None) -> Exception:
        if isinstance(exc, NotFoundError):
            return self._error(not_found_code, exc.message, data if data is not None else exc.data)
        if isinstance(exc, InvalidArgumentsError):
            return self._error(INVALID_PARAMS, exc.message, exc.data)
        return self._error(exc.code, exc.message, exc.data)

    def _tool_context(self, ctx: Any, principal: Principal) -> Any:
        session = getattr(ctx, "session", None) if ctx is not None else None
        request_id = getattr(ctx, "request_id", None) if ctx is not None else None
        modern = self._is_modern(ctx)
        key = self._session_key(ctx)
        fanout = self.fanout
        last: list[float] = []

        async def progress(value: float, total: float | None, message: str | None) -> None:
            if session is None:
                return
            if last and value <= last[0]:
                return
            last[:] = [value]
            if self.sdk_major == 2:
                await session.report_progress(value, total, message)
                return
            meta = getattr(ctx, "meta", None)
            token = getattr(meta, "progressToken", None) if meta is not None else None
            if token is None:
                return
            try:
                await session.send_progress_notification(
                    token, value, total, message=message, related_request_id=request_id
                )
            except TypeError:  # older 1.x without ``message``
                await session.send_progress_notification(token, value, total)

        async def log(level: Any, data: Any, logger_name: str | None) -> None:
            if session is None:
                return
            lvl = normalize_level(level)
            if not modern:
                threshold = fanout.level_for(key) or "info"
                if LOG_LEVELS.index(lvl) < LOG_LEVELS.index(threshold):
                    return
            with warnings.catch_warnings():
                warnings.simplefilter("ignore")
                await session.send_log_message(
                    level=lvl, data=data, logger=logger_name, related_request_id=request_id
                )

        return self.layer.context(
            principal,
            request_id=request_id,
            progress_callback=progress,
            log_callback=log,
            session=session,
        )

    async def _merge(self, orig_call: OrigCall, ours: list[dict[str, Any]], field: str,
                     key: str, model: Any) -> Any:
        if orig_call is None:
            return model.model_validate({field: ours})
        base = await orig_call()
        data = base if isinstance(base, dict) else base.model_dump(
            by_alias=True, mode="json", exclude_none=True
        )
        if data.get("nextCursor"):
            return base  # cloudg entries are appended to the host's last page
        existing = list(data.get(field) or [])
        seen = {item.get(key) for item in existing}
        clashes = [o[key] for o in ours if o.get(key) in seen]
        if clashes:
            logger.warning("host server already defines %s %s; keeping the host's", field, clashes)
        data = dict(data)
        data[field] = existing + [o for o in ours if o.get(key) not in seen]
        return model.model_validate(data)

    # ------------------------------------------------------------------
    # Method implementations (params are wire dicts)
    # ------------------------------------------------------------------

    async def _list_tools(self, ctx: Any, p: dict[str, Any], orig_call: OrigCall) -> Any:
        self._track(ctx)
        ours = self.layer.tools_wire(self._principal(ctx))
        return await self._merge(orig_call, ours, "tools", "name", self.T.ListToolsResult)

    async def _call_tool(self, ctx: Any, p: dict[str, Any], orig_call: OrigCall) -> Any:
        name = str(p.get("name", ""))
        if not owns_tool(self.layer, name):
            if orig_call is not None:
                return await orig_call()
            raise self._error(INVALID_PARAMS, f"Unknown tool: {name}")
        self._track(ctx)
        principal = self._principal(ctx)
        tctx = self._tool_context(ctx, principal)
        try:
            result = await self.layer.call_tool(
                name, p.get("arguments") or {}, principal=principal, context=tctx
            )
        except MCPLayerError as exc:
            raise self._layer_error(exc, data={"name": name}) from None
        return self.T.CallToolResult.model_validate(result.to_wire())

    async def _list_resources(self, ctx: Any, p: dict[str, Any], orig_call: OrigCall) -> Any:
        self._track(ctx)
        ours = self.layer.resources_wire(self._principal(ctx))
        return await self._merge(orig_call, ours, "resources", "uri", self.T.ListResourcesResult)

    async def _list_templates(self, ctx: Any, p: dict[str, Any], orig_call: OrigCall) -> Any:
        self._track(ctx)
        ours = self.layer.resource_templates_wire(self._principal(ctx))
        return await self._merge(orig_call, ours, "resourceTemplates", "uriTemplate",
                                 self.T.ListResourceTemplatesResult)

    async def _read_resource(self, ctx: Any, p: dict[str, Any], orig_call: OrigCall) -> Any:
        uri = str(p.get("uri", ""))
        if not owns_resource(self.layer, uri):
            if orig_call is not None:
                return await orig_call()
            code = INVALID_PARAMS if self._is_modern(ctx) else RESOURCE_NOT_FOUND
            raise self._error(code, f"Unknown resource: {uri}", {"uri": uri})
        self._track(ctx)
        principal = self._principal(ctx)
        tctx = self._tool_context(ctx, principal)
        try:
            contents = await self.layer.read_resource(uri, principal=principal, context=tctx)
        except MCPLayerError as exc:
            code = INVALID_PARAMS if self._is_modern(ctx) else RESOURCE_NOT_FOUND
            raise self._layer_error(exc, not_found_code=code, data={"uri": uri}) from None
        return self.T.ReadResourceResult.model_validate(
            {"contents": [c.to_wire() for c in contents]}
        )

    async def _list_prompts(self, ctx: Any, p: dict[str, Any], orig_call: OrigCall) -> Any:
        self._track(ctx)
        ours = self.layer.prompts_wire(self._principal(ctx))
        return await self._merge(orig_call, ours, "prompts", "name", self.T.ListPromptsResult)

    async def _get_prompt(self, ctx: Any, p: dict[str, Any], orig_call: OrigCall) -> Any:
        name = str(p.get("name", ""))
        if not owns_prompt(self.layer, name):
            if orig_call is not None:
                return await orig_call()
            raise self._error(INVALID_PARAMS, f"Unknown prompt: {name}")
        self._track(ctx)
        principal = self._principal(ctx)
        tctx = self._tool_context(ctx, principal)
        try:
            result = await self.layer.get_prompt(
                name, p.get("arguments") or {}, principal=principal, context=tctx
            )
        except MCPLayerError as exc:
            raise self._layer_error(exc) from None
        return self.T.GetPromptResult.model_validate(result.to_wire())

    async def _complete(self, ctx: Any, p: dict[str, Any], orig_call: OrigCall) -> Any:
        ref = p.get("ref") or {}
        argument = p.get("argument") or {}
        ours = (ref.get("type") == "ref/prompt" and owns_prompt(self.layer, str(ref.get("name"))))
        ours = ours or (
            ref.get("type") == "ref/resource" and owns_template(self.layer, str(ref.get("uri")))
        )
        if not ours:
            if orig_call is not None:
                return await orig_call()
            return self.T.CompleteResult.model_validate({"completion": {"values": []}})
        context = p.get("context") or {}
        try:
            completion = await self.layer.complete(
                ref, argument, principal=self._principal(ctx),
                context_arguments=context.get("arguments"),
            )
        except MCPLayerError as exc:
            raise self._layer_error(exc) from None
        return self.T.CompleteResult.model_validate({"completion": completion})

    async def _subscribe(self, ctx: Any, p: dict[str, Any], orig_call: OrigCall) -> Any:
        key = self._session_key(ctx)
        self.fanout.track(key)
        self.fanout.subscribe(key, str(p.get("uri", "")))
        if orig_call is not None:
            return await orig_call()
        return self.T.EmptyResult()

    async def _unsubscribe(self, ctx: Any, p: dict[str, Any], orig_call: OrigCall) -> Any:
        self.fanout.unsubscribe(self._session_key(ctx), str(p.get("uri", "")))
        if orig_call is not None:
            return await orig_call()
        return self.T.EmptyResult()

    async def _set_level(self, ctx: Any, p: dict[str, Any], orig_call: OrigCall) -> Any:
        level = p.get("level")
        if level in LOG_LEVELS:
            self.fanout.set_level(self._session_key(ctx), str(level))
        if orig_call is not None:
            return await orig_call()
        return self.T.EmptyResult()

    # ------------------------------------------------------------------
    # Change notifications
    # ------------------------------------------------------------------

    async def _notify(self, session: Any, kind: str, uri: str | None) -> None:
        if kind == "tools":
            await session.send_tool_list_changed()
        elif kind == "prompts":
            await session.send_prompt_list_changed()
        elif kind == "resources":
            await session.send_resource_list_changed()
        elif kind == "resource" and uri:
            await session.send_resource_updated(uri)

    async def _publish(self, kind: str, uri: str | None) -> None:
        from mcp.shared.subscriptions import (
            PromptsListChanged,
            ResourcesListChanged,
            ResourceUpdated,
            ToolsListChanged,
        )

        event: Any
        if kind == "tools":
            event = ToolsListChanged()
        elif kind == "prompts":
            event = PromptsListChanged()
        elif kind == "resources":
            event = ResourcesListChanged()
        elif kind == "resource" and uri:
            event = ResourceUpdated(uri=uri)
        else:
            return
        await self.bus.publish(event)


def install(
    layer: "CloudGMCPLayer",
    server: Any,
    *,
    include: Any = None,
    principal_resolver: PrincipalResolver | None = None,
    owner: Any = None,
    list_changed: bool = True,
) -> LowLevelBinding:
    """Bind ``layer`` into an mcp low-level ``Server`` (1.x or 2.x)."""
    return LowLevelBinding(
        layer,
        server,
        include=include,
        principal_resolver=principal_resolver,
        owner=owner,
        list_changed=list_changed,
    )
