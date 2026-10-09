"""Adapter for the standalone ``fastmcp`` package (2.x, 3.x and 4.x).

fastmcp manages tools, resources, templates and prompts as component
objects, so cloudg registers *component subclasses* whose definitions are
taken verbatim from the layer's wire dicts (``parameters`` = the layer's
``inputSchema``, plus ``output_schema``, ``annotations``, ``title`` and
``meta``) and whose ``run`` / ``read`` / ``render`` delegate to the layer.
fastmcp therefore never re-derives a schema from a Python signature, and
fastmcp features (its middleware, auth, ``mount``, tags, the in-memory
``fastmcp.Client``) keep working.

On top of the components the adapter installs:

* a fastmcp middleware that filters list results through the cloudg policy
  for the calling principal (and refreshes per-principal ``outputSchema``),
* on fastmcp's inner SDK low-level server: cloudg's ``completion/complete``
  handling, ``resources/subscribe``, and (fastmcp 4 / mcp 2.x) a
  ``subscriptions/listen`` handler (fastmcp itself serves none of these),
* change notifications (``layer.notify_change``) to the sessions seen, and
  to listen streams on the 2026-07-28 protocol.

Error mapping: unknown / hidden primitives raise fastmcp ``NotFoundError``;
other layer errors raise ``ToolError`` / ``ResourceError`` / ``PromptError``;
``isError`` tool results are passed through with their structured content.
"""

from __future__ import annotations

import base64
import inspect
import logging
from types import SimpleNamespace
from typing import TYPE_CHECKING, Any

from cloudg.mcp.adapters._common import (
    ChangeFanout,
    call_layer,
    lower_headers,
    normalize_kinds,
    normalize_level,
    resolve_principal,
    scope_principal,
    send_change,
)
from cloudg.mcp.context import Principal
from cloudg.mcp.core import (
    BlobResourceContents,
    MCPLayerError,
    NotFoundError,
    ResourceTemplateSpec,
)
from cloudg.mcp.native.auth import PrincipalResolver, RequestInfo

if TYPE_CHECKING:  # pragma: no cover
    from cloudg.mcp.layer import CloudGMCPLayer

logger = logging.getLogger("cloudg.mcp.adapters.fastmcp")

__all__ = ["FastMCPBinding", "install", "is_fastmcp_server"]


def is_fastmcp_server(obj: Any) -> bool:
    return any(
        cls.__module__.split(".")[0] == "fastmcp" and cls.__name__ == "FastMCP"
        for cls in type(obj).__mro__
    )


def _fields(model: Any) -> set[str]:
    return set(getattr(model, "model_fields", {}) or {})


def _fastmcp_api() -> SimpleNamespace:
    """The fastmcp classes the adapter needs, across fastmcp 2.x to 4.x."""
    import mcp.types as MT
    from fastmcp import exceptions as fx
    from fastmcp.prompts import Prompt
    from fastmcp.resources import Resource, ResourceTemplate
    from fastmcp.tools import Tool

    api = SimpleNamespace(MT=MT, fx=fx, Prompt=Prompt, Resource=Resource, Tool=Tool)
    api.ResourceTemplate = ResourceTemplate
    try:
        from fastmcp.tools import ToolResult
    except ImportError:  # fastmcp 2.x
        from fastmcp.tools.tool import ToolResult
    try:
        from fastmcp.prompts import PromptArgument
    except ImportError:  # fastmcp 2.x
        from fastmcp.prompts.prompt import PromptArgument
    api.ToolResult, api.PromptArgument = ToolResult, PromptArgument
    try:
        from fastmcp.resources import ResourceContent, ResourceResult
    except ImportError:  # fastmcp 2.x: read() returns str | bytes
        ResourceContent = ResourceResult = None  # type: ignore[assignment,misc]
    try:
        from fastmcp.prompts import Message, PromptResult
    except ImportError:  # fastmcp 2.x: render() returns list[PromptMessage]
        Message = PromptResult = None  # type: ignore[assignment,misc]
    api.ResourceContent, api.ResourceResult = ResourceContent, ResourceResult
    api.Message, api.PromptResult = Message, PromptResult
    return api


def _component_classes(binding: "FastMCPBinding", api: SimpleNamespace) -> SimpleNamespace:
    """fastmcp component subclasses whose run / read / render delegate to
    ``binding``."""

    class CloudGTool(api.Tool):  # type: ignore[misc,name-defined]
        async def run(self, arguments: dict[str, Any]) -> Any:
            return await binding._run_tool(self.name, arguments)

    class CloudGResource(api.Resource):  # type: ignore[misc,name-defined]
        async def read(self) -> Any:
            return await binding._read(str(self.uri))

    class CloudGTemplate(api.ResourceTemplate):  # type: ignore[misc,name-defined]
        def matches(self, uri: str) -> dict[str, Any] | None:
            spec = binding.layer.registry.templates.get(self.uri_template)
            return spec.match(uri) if spec is not None else None

        async def create_resource(self, uri: str, params: dict[str, Any]) -> Any:
            return binding._make_resource(CloudGResource, uri, self)

        async def read(self, arguments: dict[str, Any]) -> Any:
            spec = binding.layer.registry.templates[self.uri_template]
            return await binding._read(spec.expand(**arguments))

    class CloudGPrompt(api.Prompt):  # type: ignore[misc,name-defined]
        async def render(self, arguments: dict[str, Any] | None = None) -> Any:
            return await binding._render(self.name, arguments or {})

    return SimpleNamespace(
        Tool=CloudGTool, Resource=CloudGResource, Template=CloudGTemplate, Prompt=CloudGPrompt
    )


class FastMCPBinding:
    """Registers the layer's primitives on a ``fastmcp.FastMCP`` server."""

    def __init__(
        self,
        layer: "CloudGMCPLayer",
        server: Any,
        *,
        include: Any = None,
        principal_resolver: PrincipalResolver | None = None,
    ) -> None:
        api = _fastmcp_api()
        self.layer = layer
        self.server = server
        self.kinds = normalize_kinds(include)
        self.resolver = principal_resolver
        self.MT = api.MT
        self.fx = api.fx
        self._ResourceContent = api.ResourceContent
        self._ResourceResult = api.ResourceResult
        self._FMessage = api.Message
        self._FPromptResult = api.PromptResult
        self._FToolResult = api.ToolResult
        self._FPromptArgument = api.PromptArgument
        self.fanout = ChangeFanout(layer, self._notify)
        components = _component_classes(self, api)
        self.CloudGTool = components.Tool
        self.CloudGResource = components.Resource
        self.CloudGTemplate = components.Template
        self.CloudGPrompt = components.Prompt
        self._result_cls = self._make_result_class(api.ToolResult)

        self.lowlevel: Any = None
        self._register()
        self._install_middleware()
        self._install_lowlevel()
        if self.lowlevel is not None:
            # one fan-out for everything: the low-level binding also serves
            # resources/subscribe and the 2026-07-28 subscriptions/listen bus
            self.fanout = self.lowlevel.fanout

    # ------------------------------------------------------------------
    # Registration
    # ------------------------------------------------------------------

    def _register(self) -> None:
        if "tools" in self.kinds:
            self._register_tools()
        if "resources" in self.kinds:
            for spec in self.layer.registry.resources.values():
                self.server.add_resource(self._make_resource(self.CloudGResource, spec.uri, spec))
        if "templates" in self.kinds:
            self._register_templates()
        if "prompts" in self.kinds:
            self._register_prompts()

    def _register_tools(self) -> None:
        layer, tool_fields = self.layer, _fields(self.CloudGTool)
        for spec in layer.registry.tools.values():
            wire = spec.to_wire(layer.exposed_name(spec.name))
            kwargs: dict[str, Any] = {
                "name": wire["name"],
                "description": wire.get("description") or None,
                "parameters": wire["inputSchema"],
                "output_schema": wire.get("outputSchema"),
                "tags": {"cloudg", spec.category, *spec.tags},
            }
            if wire.get("annotations"):
                kwargs["annotations"] = self.MT.ToolAnnotations.model_validate(wire["annotations"])
            _add_optional(kwargs, tool_fields, wire, title=wire.get("title"))
            self.server.add_tool(self.CloudGTool(**kwargs))

    def _register_templates(self) -> None:
        tmpl_fields = _fields(self.CloudGTemplate)
        for tspec in self.layer.registry.templates.values():
            wire = tspec.to_wire()
            kwargs: dict[str, Any] = {
                "uri_template": tspec.uri_template,
                "name": tspec.name,
                "description": tspec.description or None,
                "mime_type": tspec.mime_type,
                "parameters": _template_parameters(tspec),
                "tags": {"cloudg", tspec.category, *tspec.tags},
            }
            _add_optional(kwargs, tmpl_fields, wire, title=tspec.title)
            if wire.get("annotations") and "annotations" in tmpl_fields:
                kwargs["annotations"] = self.MT.Annotations.model_validate(wire["annotations"])
            self.server.add_template(self.CloudGTemplate(**kwargs))

    def _register_prompts(self) -> None:
        layer, prompt_fields = self.layer, _fields(self.CloudGPrompt)
        for pspec in layer.registry.prompts.values():
            arguments = [
                self._FPromptArgument(
                    name=a.name, description=a.description or None, required=a.required
                )
                for a in pspec.arguments
            ]
            kwargs: dict[str, Any] = {
                "name": layer.exposed_name(pspec.name),
                "description": pspec.description or None,
                "arguments": arguments,
                "tags": {"cloudg", pspec.category, *pspec.tags},
            }
            _add_optional(kwargs, prompt_fields, pspec.to_wire(), title=pspec.title)
            self.server.add_prompt(self.CloudGPrompt(**kwargs))

    def _make_resource(self, cls: Any, uri: str, source: Any) -> Any:
        fields = _fields(cls)
        kwargs: dict[str, Any] = {
            "uri": uri,
            "name": getattr(source, "name", "") or uri,
            "description": getattr(source, "description", None) or None,
            "mime_type": getattr(source, "mime_type", None) or "application/json",
        }
        tags = getattr(source, "tags", None)
        if tags is not None:
            kwargs["tags"] = {"cloudg", *tags}
        title = getattr(source, "title", None)
        if title and "title" in fields:
            kwargs["title"] = title
        to_wire = getattr(source, "to_wire", None)
        if callable(to_wire) and "meta" in fields:
            try:
                kwargs["meta"] = to_wire().get("_meta")
            except (TypeError, ValueError, AttributeError):  # a fastmcp component, not a spec
                logger.debug("no cloudg wire metadata for resource %s", uri)
        return cls(**kwargs)

    def _install_middleware(self) -> None:
        try:
            from fastmcp.server.middleware import Middleware
        except ImportError:  # pragma: no cover (fastmcp < 2.9)
            logger.warning(
                "fastmcp has no middleware support; cloudg policy filtering of "
                "list results is disabled (calls are still enforced)"
            )
            return
        binding = self

        class CloudGPolicyFilter(Middleware):  # type: ignore[misc,valid-type]
            async def on_list_tools(self, context: Any, call_next: Any) -> Any:
                return binding._filter_tools(await call_next(context))

            async def on_list_resources(self, context: Any, call_next: Any) -> Any:
                return binding._filter_resources(await call_next(context))

            async def on_list_resource_templates(self, context: Any, call_next: Any) -> Any:
                return binding._filter_templates(await call_next(context))

            async def on_list_prompts(self, context: Any, call_next: Any) -> Any:
                return binding._filter_prompts(await call_next(context))

        self.server.add_middleware(CloudGPolicyFilter())

    def _install_lowlevel(self) -> None:
        """Completions, resource subscriptions and (2026-07-28) the listen
        bus are protocol-level features fastmcp components cannot express:
        bind them on fastmcp's inner SDK low-level server."""
        kinds = self.kinds & {"completions", "subscriptions"}
        inner = getattr(self.server, "_mcp_server", None)
        if inner is None or not kinds:
            return
        from cloudg.mcp.adapters.lowlevel import install as install_lowlevel

        try:
            self.lowlevel = install_lowlevel(
                self.layer,
                inner,
                include=kinds,
                principal_resolver=self.resolver,
                list_changed=False,
            )
        except Exception:
            logger.debug("could not bind cloudg protocol features on fastmcp", exc_info=True)

    # ------------------------------------------------------------------
    # Per-request helpers
    # ------------------------------------------------------------------

    def _context(self) -> Any:
        try:
            from fastmcp.server.dependencies import get_context

            return get_context()
        except Exception:
            return None

    def request_info(self, ctx: Any = None) -> RequestInfo:
        request = None
        headers: dict[str, str] = {}
        token = None
        try:
            from fastmcp.server.dependencies import get_http_request

            request = get_http_request()
        except Exception:
            request = None
        if request is not None:
            headers = lower_headers(getattr(request, "headers", None))
        try:
            from fastmcp.server.dependencies import get_access_token

            token = get_access_token()
        except Exception:
            token = None
        principal = scope_principal(request)
        return RequestInfo(
            transport="http" if request is not None else "stdio",
            headers=headers,
            session_id=headers.get("mcp-session-id"),
            access_token=token,
            principal=principal,
            raw=ctx,
        )

    def _principal(self, ctx: Any = None) -> Principal:
        return resolve_principal(self.resolver, self.request_info(ctx))

    def _track(self, ctx: Any) -> None:
        if ctx is None:
            return
        try:
            session = ctx.session
        except Exception:
            return
        target = getattr(session, "_connection", None) or session
        self.fanout.track(target)

    def _tool_context(self, ctx: Any, principal: Principal) -> Any:
        last: list[float] = []

        async def progress(value: float, total: float | None, message: str | None) -> None:
            if ctx is None or (last and value <= last[0]):
                return
            last[:] = [value]
            await ctx.report_progress(value, total, message)

        async def log(level: Any, data: Any, logger_name: str | None) -> None:
            if ctx is None:
                return
            text = data if isinstance(data, str) else _json(data)
            await ctx.log(text, level=normalize_level(level), logger_name=logger_name)

        request_id = None
        if ctx is not None:
            try:
                request_id = ctx.request_id
            except Exception:
                request_id = None
        return self.layer.context(
            principal,
            request_id=request_id,
            progress_callback=progress,
            log_callback=log,
            session=ctx,
        )

    # ------------------------------------------------------------------
    # Execution
    # ------------------------------------------------------------------

    def _make_result_class(self, base: Any) -> Any:
        if hasattr(base, "from_mcp_result"):
            return None  # fastmcp 4 preserves the exact wire result itself
        try:
            import pydantic

            is_model = issubclass(base, pydantic.BaseModel)
        except Exception:
            is_model = False
        if is_model:
            from pydantic import PrivateAttr

            class RawToolResult(base):  # type: ignore[misc,valid-type]
                _cloudg_raw: Any = PrivateAttr(default=None)

                def to_mcp_result(self) -> Any:
                    if self._cloudg_raw is not None:
                        return self._cloudg_raw
                    return super().to_mcp_result()

            return RawToolResult

        class PlainRawToolResult(base):  # type: ignore[misc,valid-type]
            _cloudg_raw: Any = None

            def to_mcp_result(self) -> Any:
                if self._cloudg_raw is not None:
                    return self._cloudg_raw
                return super().to_mcp_result()

        return PlainRawToolResult

    def _tool_result(self, wire: dict[str, Any]) -> Any:
        call_result = self.MT.CallToolResult.model_validate(wire)
        if self._result_cls is None:
            return self._FToolResult.from_mcp_result(call_result)
        kwargs: dict[str, Any] = {
            "content": list(call_result.content),
            "structured_content": wire.get("structuredContent"),
            "meta": wire.get("_meta"),
        }
        if "is_error" in inspect.signature(self._result_cls.__init__).parameters:
            kwargs["is_error"] = bool(wire.get("isError"))
        result = self._result_cls(**kwargs)
        result._cloudg_raw = call_result
        return result

    async def _call(self, method: str, target: str, *args: Any, error_cls: Any) -> Any:
        """Run ``layer.<method>(target, *args)`` for the current fastmcp
        request; layer errors map to fastmcp errors, anything else to a
        generic ``error_cls("Internal error")``."""
        ctx = self._context()
        self._track(ctx)
        principal = self._principal(ctx)
        call = getattr(self.layer, method)(
            target, *args, principal=principal, context=self._tool_context(ctx, principal)
        )

        def mapped(exc: MCPLayerError) -> Exception:
            if isinstance(exc, NotFoundError):
                return self.fx.NotFoundError(exc.message)
            return error_cls(exc.message)

        return await call_layer(call, mapped, lambda: error_cls("Internal error"))

    async def _run_tool(self, name: str, arguments: dict[str, Any]) -> Any:
        result = await self._call("call_tool", name, arguments or {}, error_cls=self.fx.ToolError)
        return self._tool_result(result.to_wire())

    async def _read(self, uri: str) -> Any:
        contents = await self._call("read_resource", uri, error_cls=self.fx.ResourceError)
        if self._ResourceResult is not None:
            items = []
            for c in contents:
                raw: Any = (
                    base64.b64decode(c.blob) if isinstance(c, BlobResourceContents) else c.text
                )
                items.append(self._ResourceContent(raw, mime_type=c.mime_type, meta=c.meta))
            return self._ResourceResult(items)
        if not contents:
            return ""
        first = contents[0]
        if isinstance(first, BlobResourceContents):
            return base64.b64decode(first.blob)
        return first.text

    async def _render(self, name: str, arguments: dict[str, Any]) -> Any:
        error_cls = getattr(self.fx, "PromptError", self.fx.ToolError)
        result = await self._call("get_prompt", name, arguments, error_cls=error_cls)
        wire = result.to_wire()
        MT = self.MT
        if self._FPromptResult is None:
            return [MT.PromptMessage.model_validate(m) for m in wire["messages"]]
        messages = []
        for m in wire["messages"]:
            content = m["content"]
            ctype = content.get("type")
            model = {
                "text": MT.TextContent,
                "image": MT.ImageContent,
                "audio": getattr(MT, "AudioContent", None),
                "resource": MT.EmbeddedResource,
            }.get(ctype)
            value = model.model_validate(content) if model is not None else _json(content)
            messages.append(self._FMessage(value, role=m["role"]))
        return self._FPromptResult(messages, description=wire.get("description"))

    # ------------------------------------------------------------------
    # Policy filtering of list results
    # ------------------------------------------------------------------

    def _filter_tools(self, tools: Any) -> Any:
        principal = self._principal(self._context())
        wires = {w["name"]: w for w in self.layer.tools_wire(principal)}
        out = []
        for tool in tools:
            if isinstance(tool, self.CloudGTool):
                wire = wires.get(tool.name)
                if wire is None:
                    continue
                if wire.get("outputSchema") != tool.output_schema:
                    tool = tool.model_copy(update={"output_schema": wire.get("outputSchema")})
            out.append(tool)
        return out

    def _filter_resources(self, resources: Any) -> Any:
        principal = self._principal(self._context())
        allowed = {w["uri"] for w in self.layer.resources_wire(principal)}
        return [
            r for r in resources if not isinstance(r, self.CloudGResource) or str(r.uri) in allowed
        ]

    def _filter_templates(self, templates: Any) -> Any:
        principal = self._principal(self._context())
        allowed = {w["uriTemplate"] for w in self.layer.resource_templates_wire(principal)}
        return [
            t
            for t in templates
            if not isinstance(t, self.CloudGTemplate) or t.uri_template in allowed
        ]

    def _filter_prompts(self, prompts: Any) -> Any:
        principal = self._principal(self._context())
        allowed = {w["name"] for w in self.layer.prompts_wire(principal)}
        return [p for p in prompts if not isinstance(p, self.CloudGPrompt) or p.name in allowed]

    # ------------------------------------------------------------------
    # Change notifications
    # ------------------------------------------------------------------

    async def _notify(self, session: Any, kind: str, uri: str | None) -> None:
        await send_change(session, kind, uri)


def _add_optional(
    kwargs: dict[str, Any], fields: set[str], wire: dict[str, Any], *, title: str | None
) -> None:
    """Set ``title`` / ``meta`` when this fastmcp version has those fields."""
    if "title" in fields and title:
        kwargs["title"] = title
    if "meta" in fields:
        kwargs["meta"] = wire.get("_meta")


def _template_parameters(spec: ResourceTemplateSpec) -> dict[str, Any]:
    props = {v: {"type": "string"} for v in spec.variables}
    return {"type": "object", "properties": props, "required": list(props)}


def _json(value: Any) -> str:
    import json

    return json.dumps(value, ensure_ascii=False, default=str)


def install(
    layer: "CloudGMCPLayer",
    server: Any,
    *,
    include: Any = None,
    principal_resolver: PrincipalResolver | None = None,
) -> FastMCPBinding:
    """Register the layer's primitives on a standalone ``fastmcp.FastMCP``."""
    return FastMCPBinding(layer, server, include=include, principal_resolver=principal_resolver)
