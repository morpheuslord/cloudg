"""Framework-free export of the layer's MCP definitions.

For custom servers, gateways and agent frameworks that do not use an MCP SDK:
:func:`export_definitions` returns the exact MCP wire definitions (as the
active policy shows them to a principal) plus async handlers for every
method. Every handler goes through the layer, so policies, transforms and
middleware still apply.

Also small converters to function-calling formats:

* :func:`to_openai_tools`: OpenAI ``tools=[{"type": "function", ...}]``.
* :func:`to_anthropic_tools`: Anthropic Messages API ``tools=[...]``.
* :func:`to_langchain_tools`: LangChain ``StructuredTool`` objects
  (requires ``langchain-core``).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Awaitable, Callable

from cloudg.mcp.context import Principal
from cloudg.mcp.core import NotFoundError

if TYPE_CHECKING:  # pragma: no cover
    from cloudg.mcp.layer import CloudGMCPLayer

__all__ = [
    "ExportedDefinitions",
    "export_definitions",
    "to_anthropic_tools",
    "to_langchain_tools",
    "to_openai_tools",
]

Handler = Callable[..., Awaitable[dict[str, Any]]]


@dataclass
class ExportedDefinitions:
    """Wire definitions + handlers.

    Attributes:
        server: ``{"name", "version", "instructions"}``.
        tools / resources / resource_templates / prompts: MCP wire dicts
            (camelCase, ready for ``tools/list`` etc.).
        handlers: ``{method: async fn(params: dict, *, principal=None) -> result
            wire dict}`` for ``tools/list``, ``tools/call``, ``resources/list``,
            ``resources/templates/list``, ``resources/read``, ``prompts/list``,
            ``prompts/get`` and ``completion/complete``.
        tool_functions: ``{tool name: async fn(**arguments) -> result wire}``.
    """

    server: dict[str, Any]
    tools: list[dict[str, Any]]
    resources: list[dict[str, Any]]
    resource_templates: list[dict[str, Any]]
    prompts: list[dict[str, Any]]
    handlers: dict[str, Handler] = field(default_factory=dict)
    tool_functions: dict[str, Callable[..., Awaitable[dict[str, Any]]]] = field(
        default_factory=dict
    )

    async def dispatch(
        self,
        method: str,
        params: dict[str, Any] | None = None,
        *,
        principal: Principal | None = None,
    ) -> dict[str, Any]:
        """Run one MCP method; raises ``KeyError`` for unknown methods and
        :class:`~cloudg.mcp.core.MCPLayerError` for protocol-level errors."""
        return await self.handlers[method](params or {}, principal=principal)

    def as_dict(self) -> dict[str, Any]:
        return {
            "server": self.server,
            "tools": self.tools,
            "resources": self.resources,
            "resourceTemplates": self.resource_templates,
            "prompts": self.prompts,
        }


class _Handlers:
    """Per-method MCP handlers bound to one layer; a handler called without
    a principal acts as ``default``."""

    def __init__(self, layer: "CloudGMCPLayer", default: Principal) -> None:
        self.layer = layer
        self.default = default

    def who(self, principal: Principal | None) -> Principal:
        return principal or self.default

    async def tools_list(
        self, params: dict[str, Any], *, principal: Principal | None = None
    ) -> dict:
        return {"tools": self.layer.tools_wire(self.who(principal))}

    async def tools_call(
        self, params: dict[str, Any], *, principal: Principal | None = None
    ) -> dict:
        result = await self.layer.call_tool(
            params["name"], params.get("arguments") or {}, principal=self.who(principal)
        )
        return result.to_wire()

    async def resources_list(
        self, params: dict[str, Any], *, principal: Principal | None = None
    ) -> dict:
        return {"resources": self.layer.resources_wire(self.who(principal))}

    async def templates_list(
        self, params: dict[str, Any], *, principal: Principal | None = None
    ) -> dict:
        return {"resourceTemplates": self.layer.resource_templates_wire(self.who(principal))}

    async def resources_read(
        self, params: dict[str, Any], *, principal: Principal | None = None
    ) -> dict:
        contents = await self.layer.read_resource(params["uri"], principal=self.who(principal))
        return {"contents": [c.to_wire() for c in contents]}

    async def prompts_list(
        self, params: dict[str, Any], *, principal: Principal | None = None
    ) -> dict:
        return {"prompts": self.layer.prompts_wire(self.who(principal))}

    async def prompts_get(
        self, params: dict[str, Any], *, principal: Principal | None = None
    ) -> dict:
        result = await self.layer.get_prompt(
            params["name"], params.get("arguments") or {}, principal=self.who(principal)
        )
        return result.to_wire()

    async def complete(self, params: dict[str, Any], *, principal: Principal | None = None) -> dict:
        ctx = params.get("context") or {}
        completion = await self.layer.complete(
            params["ref"],
            params["argument"],
            principal=self.who(principal),
            context_arguments=ctx.get("arguments"),
        )
        return {"completion": completion}

    def by_method(self) -> dict[str, Handler]:
        return {
            "tools/list": self.tools_list,
            "tools/call": self.tools_call,
            "resources/list": self.resources_list,
            "resources/templates/list": self.templates_list,
            "resources/read": self.resources_read,
            "prompts/list": self.prompts_list,
            "prompts/get": self.prompts_get,
            "completion/complete": self.complete,
        }

    def tool_function(self, name: str) -> Callable[..., Awaitable[dict[str, Any]]]:
        """``async fn(**arguments)`` calling tool ``name`` as ``default``."""
        layer, default = self.layer, self.default

        async def call(**arguments: Any) -> dict[str, Any]:
            return (await layer.call_tool(name, arguments, principal=default)).to_wire()

        call.__name__ = name
        return call


def export_definitions(
    layer: "CloudGMCPLayer", principal: Principal | None = None
) -> ExportedDefinitions:
    """Snapshot the layer's definitions for ``principal`` (default: local
    user) and build per-method handlers."""
    default = principal or Principal.local()
    handlers = _Handlers(layer, default)
    tools = layer.tools_wire(default)
    return ExportedDefinitions(
        server={
            "name": layer.name,
            "version": str(layer.version),
            "instructions": layer.instructions,
        },
        tools=tools,
        resources=layer.resources_wire(default),
        resource_templates=layer.resource_templates_wire(default),
        prompts=layer.prompts_wire(default),
        handlers=handlers.by_method(),
        tool_functions={t["name"]: handlers.tool_function(t["name"]) for t in tools},
    )


def to_openai_tools(
    layer: "CloudGMCPLayer", principal: Principal | None = None
) -> list[dict[str, Any]]:
    """OpenAI Chat Completions / Responses function-tool definitions."""
    out = []
    for t in layer.tools_wire(principal):
        out.append(
            {
                "type": "function",
                "function": {
                    "name": t["name"],
                    "description": t.get("description") or t.get("title") or t["name"],
                    "parameters": t["inputSchema"],
                },
            }
        )
    return out


def to_anthropic_tools(
    layer: "CloudGMCPLayer", principal: Principal | None = None
) -> list[dict[str, Any]]:
    """Anthropic Messages API tool definitions."""
    return [
        {
            "name": t["name"],
            "description": t.get("description") or t.get("title") or t["name"],
            "input_schema": t["inputSchema"],
        }
        for t in layer.tools_wire(principal)
    ]


def to_langchain_tools(layer: "CloudGMCPLayer", principal: Principal | None = None) -> list[Any]:
    """LangChain ``StructuredTool`` objects that call the layer (async).

    The tool returns the result text; ``response_format="content_and_artifact"``
    exposes the structured content as the artifact.
    """
    try:
        from langchain_core.tools import StructuredTool
    except ImportError as exc:  # pragma: no cover (optional dependency)
        raise ImportError("to_langchain_tools() needs `pip install langchain-core`") from exc
    who = principal or Principal.local()
    tools = []
    for t in layer.tools_wire(who):
        name = t["name"]

        async def run(_name: str = name, **arguments: Any) -> tuple[str, Any]:
            try:
                result = await layer.call_tool(_name, arguments, principal=who)
            except NotFoundError as exc:
                return str(exc), None
            text = "\n".join(c.text for c in result.content if hasattr(c, "text"))
            return text, result.structured

        tools.append(
            StructuredTool.from_function(
                coroutine=run,
                name=name,
                description=t.get("description") or name,
                args_schema=t["inputSchema"],
                response_format="content_and_artifact",
            )
        )
    return tools
