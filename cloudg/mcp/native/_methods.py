"""MCP method implementations of the native protocol engine.

Each ``_m_*`` coroutine takes the :class:`~cloudg.mcp.native.protocol.Session`,
the per-request :class:`~cloudg.mcp.native._shared.RequestCtx` and the
request ``params`` and returns the result object. :data:`METHODS` maps
``(modern, method)`` to the implementation.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Awaitable, Callable

from cloudg.mcp.core import MCPLayerError
from cloudg.mcp.native._shared import (
    LISTEN_FLAGS,
    ListenStream,
    RequestCtx,
    change_message,
    layer_error_parts,
)
from cloudg.mcp.native.jsonrpc import (
    HANDSHAKE_VERSIONS,
    INVALID_PARAMS,
    INVALID_REQUEST,
    LATEST_HANDSHAKE_VERSION,
    LOG_LEVELS,
    RESOURCE_NOT_FOUND,
    SUBSCRIPTION_ID_META_KEY,
    SUPPORTED_VERSIONS,
    JSONRPCError,
)

if TYPE_CHECKING:  # pragma: no cover
    from cloudg.mcp.native.protocol import Session

__all__ = ["METHODS", "MethodImpl"]

MethodImpl = Callable[["Session", RequestCtx, dict[str, Any]], Awaitable[dict[str, Any]]]


def _str_param(params: dict[str, Any], key: str) -> str:
    value = params.get(key)
    if not isinstance(value, str) or not value:
        raise JSONRPCError(INVALID_PARAMS, f"Missing or invalid parameter: {key}")
    return value


def _name_and_arguments(params: dict[str, Any]) -> tuple[str, dict[str, Any]]:
    """``(name, arguments)`` of a ``tools/call`` / ``prompts/get`` request."""
    name = _str_param(params, "name")
    arguments = params.get("arguments")
    if arguments is not None and not isinstance(arguments, dict):
        raise JSONRPCError(INVALID_PARAMS, "arguments must be an object")
    return name, arguments or {}


async def _through_layer(call: Awaitable[Any], **error_kw: Any) -> Any:
    """Await a layer call, turning layer errors into JSON-RPC errors."""
    try:
        return await call
    except MCPLayerError as exc:
        raise JSONRPCError(*layer_error_parts(exc, **error_kw)) from None


def _listing(s: "Session", kind: str, key: str, items: list[dict], params: dict) -> dict:
    page, nxt = s.server.paginate(kind, items, params.get("cursor"))
    out: dict[str, Any] = {key: page}
    if nxt:
        out["nextCursor"] = nxt
    return out


async def _m_initialize(s: "Session", rc: RequestCtx, params: dict[str, Any]) -> dict[str, Any]:
    if s.init_responded:
        raise JSONRPCError(INVALID_REQUEST, "Session already initialized")
    requested = params.get("protocolVersion")
    if not isinstance(requested, str):
        raise JSONRPCError(INVALID_PARAMS, "initialize requires a protocolVersion string")
    version = requested if requested in HANDSHAKE_VERSIONS else LATEST_HANDSHAKE_VERSION
    s.era = "legacy"
    s.protocol_version = version
    caps, info = params.get("capabilities"), params.get("clientInfo")
    s.client_capabilities = caps if isinstance(caps, dict) else {}
    s.client_info = info if isinstance(info, dict) else None
    s.init_responded = True
    result: dict[str, Any] = {
        "protocolVersion": version,
        "capabilities": s.server.capabilities(version),
        "serverInfo": s.server.server_info(),
    }
    if s.layer.instructions:
        result["instructions"] = s.layer.instructions
    return result


async def _m_ping(s: "Session", rc: RequestCtx, params: dict[str, Any]) -> dict[str, Any]:
    return {}


async def _m_discover(s: "Session", rc: RequestCtx, params: dict[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {
        "supportedVersions": list(SUPPORTED_VERSIONS),
        "capabilities": s.server.capabilities(rc.version),
    }
    if s.layer.instructions:
        out["instructions"] = s.layer.instructions
    return out


async def _m_tools_list(s: "Session", rc: RequestCtx, params: dict[str, Any]) -> dict[str, Any]:
    return _listing(s, "tools", "tools", s.layer.tools_wire(rc.principal), params)


async def _m_tools_call(s: "Session", rc: RequestCtx, params: dict[str, Any]) -> dict[str, Any]:
    name, arguments = _name_and_arguments(params)
    call = s.layer.call_tool(name, arguments, principal=rc.principal, context=s.tool_context(rc))
    result = await _through_layer(call, data={"name": name})
    return result.to_wire()


async def _m_resources_list(s: "Session", rc: RequestCtx, params: dict[str, Any]) -> dict:
    return _listing(s, "resources", "resources", s.layer.resources_wire(rc.principal), params)


async def _m_templates_list(s: "Session", rc: RequestCtx, params: dict[str, Any]) -> dict:
    items = s.layer.resource_templates_wire(rc.principal)
    return _listing(s, "templates", "resourceTemplates", items, params)


async def _m_resources_read(s: "Session", rc: RequestCtx, params: dict[str, Any]) -> dict:
    uri = _str_param(params, "uri")
    call = s.layer.read_resource(uri, principal=rc.principal, context=s.tool_context(rc))
    code = INVALID_PARAMS if rc.modern else RESOURCE_NOT_FOUND
    contents = await _through_layer(call, not_found_code=code, data={"uri": uri})
    return {"contents": [c.to_wire() for c in contents]}


async def _m_subscribe(s: "Session", rc: RequestCtx, params: dict[str, Any]) -> dict[str, Any]:
    s.subscriptions.add(_str_param(params, "uri"))
    return {}


async def _m_unsubscribe(s: "Session", rc: RequestCtx, params: dict[str, Any]) -> dict[str, Any]:
    s.subscriptions.discard(_str_param(params, "uri"))
    return {}


async def _m_prompts_list(s: "Session", rc: RequestCtx, params: dict[str, Any]) -> dict:
    return _listing(s, "prompts", "prompts", s.layer.prompts_wire(rc.principal), params)


async def _m_prompts_get(s: "Session", rc: RequestCtx, params: dict[str, Any]) -> dict[str, Any]:
    name, arguments = _name_and_arguments(params)
    call = s.layer.get_prompt(name, arguments, principal=rc.principal, context=s.tool_context(rc))
    result = await _through_layer(call)
    return result.to_wire()


async def _m_complete(s: "Session", rc: RequestCtx, params: dict[str, Any]) -> dict[str, Any]:
    ref = params.get("ref")
    argument = params.get("argument")
    if not isinstance(ref, dict) or ref.get("type") not in ("ref/prompt", "ref/resource"):
        raise JSONRPCError(INVALID_PARAMS, "Invalid completion ref")
    if not isinstance(argument, dict) or not isinstance(argument.get("name"), str):
        raise JSONRPCError(INVALID_PARAMS, "Invalid completion argument")
    context = params.get("context") if isinstance(params.get("context"), dict) else {}
    ctx_args = context.get("arguments") if isinstance(context.get("arguments"), dict) else None
    call = s.layer.complete(ref, argument, principal=rc.principal, context_arguments=ctx_args)
    return {"completion": await _through_layer(call)}


async def _m_set_level(s: "Session", rc: RequestCtx, params: dict[str, Any]) -> dict[str, Any]:
    level = params.get("level")
    if level not in LOG_LEVELS:
        raise JSONRPCError(INVALID_PARAMS, f"Invalid log level: {level!r}")
    s.log_level = level
    return {}


def _listen_filter(requested: dict[str, Any]) -> dict[str, Any]:
    honored: dict[str, Any] = {f: True for f in LISTEN_FLAGS.values() if requested.get(f) is True}
    uris = requested.get("resourceSubscriptions")
    if isinstance(uris, list):
        clean = [u for u in uris if isinstance(u, str)]
        if clean:
            honored["resourceSubscriptions"] = clean
    return honored


async def _m_listen(s: "Session", rc: RequestCtx, params: dict[str, Any]) -> dict[str, Any]:
    requested = params.get("notifications")
    if not isinstance(requested, dict):
        raise JSONRPCError(INVALID_PARAMS, "subscriptions/listen requires a notifications filter")
    honored = _listen_filter(requested)
    meta = {SUBSCRIPTION_ID_META_KEY: rc.req_id}
    stream = ListenStream(honored)
    s.server.add_listen(stream)
    try:
        await rc.notify(
            "notifications/subscriptions/acknowledged",
            {"notifications": honored, "_meta": dict(meta)},
        )
        while True:
            event = await stream.queue.get()
            if event is None:
                break
            msg = change_message(*event, meta=meta)
            await rc.notify(msg["method"], msg["params"])
    finally:
        s.server.discard_listen(stream)
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
METHODS: dict[tuple[bool, str], MethodImpl] = {
    **{(False, m): f for m, f in {**_COMMON, **_LEGACY_ONLY}.items()},
    **{(True, m): f for m, f in {**_COMMON, **_MODERN_ONLY}.items()},
}
