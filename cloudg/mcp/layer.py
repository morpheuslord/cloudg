"""The cloudg MCP layer: one object that owns the registry, the workspace,
the policy and the middleware chain, and dispatches MCP requests.

Adapters never call handlers directly; they go through
:meth:`CloudGMCPLayer.call_tool`, :meth:`read_resource`,
:meth:`get_prompt` and :meth:`complete`. Whichever server a request arrives
through, it gets the same validation, access control, transforms
(redaction / pseudonymisation / projection / annotation / substitution),
timeouts and audit trail.
"""

from __future__ import annotations

import asyncio
import base64
import logging
import re
import time
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Awaitable, Callable, Iterable

from pydantic import BaseModel

from cloudg.mcp.context import Principal, ToolContext
from cloudg.mcp.core import (
    META_PREFIX,
    BlobResourceContents,
    EmbeddedResource,
    InvalidArgumentsError,
    MCPLayerError,
    NotFoundError,
    PromptMessage,
    PromptResult,
    PromptSpec,
    Registry,
    ResourceLink,
    ResourceSpec,
    ResourceTemplateSpec,
    TextContent,
    TextResourceContents,
    ToolResult,
    ToolSpec,
    maybe_await,
    render_json,
)
from cloudg.mcp.schema import validate_arguments
from cloudg.mcp.transforms.base import TransformContext

if TYPE_CHECKING:  # pragma: no cover
    from cloudg.config import CloudGConfig
    from cloudg.mcp.policy import Policy
    from cloudg.mcp.state import Workspace

logger = logging.getLogger("cloudg.mcp")

DEFAULT_INSTRUCTIONS = """\
cloudg exposes a multi-cloud (AWS / Azure / GCP) infrastructure inventory,
its relationship graph, security findings, compliance mappings and an RDF
ontology. Start with `workspace_status` (or read cloudg://workspace) to see
which datasets are loaded; load one with `load_dataset` or collect live data
with `map_inventory`. Identifiers in results may be pseudonymised by policy:
pass them back to tools unchanged and they resolve to the real resource.
Prefer the narrow query tools (find_assets, get_asset, neighbors, paths)
over dumping whole datasets; results are paginated."""


@dataclass
class CallInfo:
    """What a middleware sees about the request it wraps."""

    kind: str  # tool | resource | prompt | completion
    name: str  # tool/prompt name, resource URI, or template of a completion
    spec: Any
    arguments: dict[str, Any]
    principal: Principal
    context: ToolContext
    started: float = field(default_factory=time.monotonic)


_EMPTY_COMPLETION: dict[str, Any] = {"values": [], "total": 0, "hasMore": False}
_PREFIX_RE = re.compile(r"^[A-Za-z0-9_.\-]{0,64}$")

Next = Callable[[CallInfo], Awaitable[Any]]
# ``async def middleware(info: CallInfo, call_next: Next) -> Any``; for tools
# the value is a ToolResult, for resources a list of contents, for prompts a
# PromptResult. Raise an MCPLayerError to reject the call.
Middleware = Callable[[CallInfo, Next], Awaitable[Any]]


def _jsonable(value: Any) -> Any:
    """Convert handler output into JSON-compatible Python data."""
    if isinstance(value, BaseModel):
        return value.model_dump(mode="json", exclude={"raw_data"})
    if hasattr(value, "to_dict") and callable(value.to_dict):
        return _jsonable(value.to_dict())
    if isinstance(value, dict):
        return {str(k): _jsonable(v) for k, v in value.items()}
    if isinstance(value, (list, tuple, set, frozenset)):
        return [_jsonable(v) for v in value]
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    if hasattr(value, "value") and isinstance(getattr(value, "value"), (str, int)):
        return value.value  # Enum
    if hasattr(value, "__dataclass_fields__"):
        import dataclasses

        return _jsonable(dataclasses.asdict(value))
    return str(value)


dumps = render_json


class CloudGMCPLayer:
    """Plug-and-play MCP layer over cloudg.

    Args:
        config: cloudg configuration (providers, credentials...). Defaults
            to ``CloudGConfig()``.
        workspace: Shared state; created from ``config`` when omitted.
        policy: Access + transform policy: a :class:`~cloudg.mcp.policy.Policy`,
            a built-in profile name (``"open"``, ``"standard"``,
            ``"strict"``...), a path to a YAML/JSON policy file, or a dict.
        registry: Primitives to expose. Defaults to the full cloudg catalog.
        include_categories / exclude_categories: Filter the catalog by
            category (``inventory``, ``graph``, ``findings``...).
        include_tools / exclude_tools: Filter by tool name.
        prefix: Prepended to every tool and prompt name (``"cloudg_"``) so
            the primitives can be mounted into another server without name
            collisions.
        middleware: Extra middleware, outermost first.
        default_timeout: Seconds before a tool call is cancelled.
        max_output_chars: Hard cap on the rendered text of one result.
    """

    def __init__(
        self,
        config: "CloudGConfig | None" = None,
        *,
        workspace: "Workspace | None" = None,
        policy: "Policy | str | dict[str, Any] | None" = None,
        registry: Registry | None = None,
        include_categories: Iterable[str] | None = None,
        exclude_categories: Iterable[str] | None = None,
        include_tools: Iterable[str] | None = None,
        exclude_tools: Iterable[str] | None = None,
        prefix: str = "",
        middleware: Iterable[Middleware] = (),
        default_timeout: float | None = 300.0,
        max_output_chars: int = 200_000,
        name: str = "cloudg",
        version: str | None = None,
        instructions: str | None = None,
    ) -> None:
        from cloudg import __version__
        from cloudg.mcp.policy import Policy

        if workspace is None:
            from cloudg.config import CloudGConfig
            from cloudg.mcp.state import Workspace

            workspace = Workspace(config or CloudGConfig())
        self.workspace = workspace
        self.policy: Policy = policy if isinstance(policy, Policy) else Policy.load(policy)

        if registry is None:
            from cloudg.mcp.catalog import default_registry

            registry = default_registry()
        self.registry = self._filter_registry(
            registry, include_categories, exclude_categories, include_tools, exclude_tools
        )
        self.prefix = ""
        self.set_prefix(prefix)
        self.middleware: list[Middleware] = list(middleware)
        self.default_timeout = default_timeout
        self.max_output_chars = max_output_chars
        self.name = name
        self.version = version or __version__
        self.instructions = instructions if instructions is not None else DEFAULT_INSTRUCTIONS
        # Notified with (kind, uri) when a resource changes (dataset loaded,
        # workspace mutated); adapters forward these as
        # notifications/resources/updated and list_changed.
        self._change_listeners: list[Callable[[str, str | None], Any]] = []
        self._loop: asyncio.AbstractEventLoop | None = None
        if callable(getattr(workspace, "on_change", None)):
            workspace.on_change(self.notify_change)

    # ------------------------------------------------------------------
    # Construction helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _filter_registry(
        registry: Registry,
        include_categories: Iterable[str] | None,
        exclude_categories: Iterable[str] | None,
        include_tools: Iterable[str] | None,
        exclude_tools: Iterable[str] | None,
    ) -> Registry:
        inc_c = set(include_categories) if include_categories else None
        exc_c = set(exclude_categories or ())
        inc_t = set(include_tools) if include_tools else None
        exc_t = set(exclude_tools or ())
        if not (inc_c or exc_c or inc_t or exc_t):
            return registry

        def keep(spec: Any) -> bool:
            if inc_c is not None and spec.category not in inc_c:
                return False
            if spec.category in exc_c:
                return False
            if isinstance(spec, ToolSpec):
                if inc_t is not None and spec.name not in inc_t:
                    return False
                if spec.name in exc_t:
                    return False
            return True

        out = Registry()
        for spec in [
            *registry.tools.values(),
            *registry.resources.values(),
            *registry.templates.values(),
            *registry.prompts.values(),
        ]:
            if keep(spec):
                out.add(spec)
        return out

    def set_prefix(self, prefix: str) -> None:
        """Change the name prefix of every exposed tool and prompt. The
        prefix belongs to the layer, so one layer has one prefix: mount two
        layers to expose the catalog under two prefixes."""
        if not isinstance(prefix, str) or not _PREFIX_RE.match(prefix):
            raise ValueError(f"Invalid prefix {prefix!r}: use up to 64 of A-Z a-z 0-9 _ . -")
        self.prefix = prefix

    def use(self, middleware: Middleware) -> "CloudGMCPLayer":
        """Append a middleware (innermost so far)."""
        self.middleware.append(middleware)
        return self

    def on_change(self, listener: Callable[[str, str | None], Any]) -> None:
        """Register ``listener(kind, uri)``; kind is ``"resources"``
        (list changed), ``"resource"`` (one URI updated), ``"tools"`` or
        ``"prompts"``."""
        self._change_listeners.append(listener)

    def notify_change(self, kind: str, uri: str | None = None) -> None:
        """Fan a change out to the listeners, on the server's event loop:
        sync handlers run in worker threads and adapters' notification
        code is not thread-safe."""
        loop = self._loop
        if loop is not None and loop.is_running():
            try:
                running = asyncio.get_running_loop()
            except RuntimeError:
                running = None
            if running is not loop:
                loop.call_soon_threadsafe(self._dispatch_change, kind, uri)
                return
        self._dispatch_change(kind, uri)

    def _dispatch_change(self, kind: str, uri: str | None) -> None:
        for listener in list(self._change_listeners):
            try:
                listener(kind, uri)
            except Exception:
                logger.debug("change listener failed", exc_info=True)

    # ------------------------------------------------------------------
    # Names
    # ------------------------------------------------------------------

    def exposed_name(self, name: str) -> str:
        return f"{self.prefix}{name}"

    def internal_name(self, exposed: str) -> str:
        """Registry name for an exposed tool or prompt name. With a prefix
        set, only prefixed names resolve: a host server mounting the layer
        may own a tool with the bare name."""
        if not self.prefix:
            return exposed
        if exposed.startswith(self.prefix):
            return exposed[len(self.prefix) :]
        return "\0unprefixed:" + exposed  # never a registry key

    def context(self, principal: Principal | None = None, **kwargs: Any) -> ToolContext:
        return ToolContext(layer=self, principal=principal or Principal.local(), **kwargs)

    def _remember_loop(self) -> None:
        try:
            self._loop = asyncio.get_running_loop()
        except RuntimeError:
            pass

    # ------------------------------------------------------------------
    # Listing
    # ------------------------------------------------------------------

    def list_tools(self, principal: Principal | None = None) -> list[ToolSpec]:
        p = principal or Principal.local()
        return [s for s in self.registry.tools.values() if self.policy.is_allowed(s, p)]

    def list_resources(self, principal: Principal | None = None) -> list[ResourceSpec]:
        p = principal or Principal.local()
        return [s for s in self.registry.resources.values() if self.policy.is_allowed(s, p)]

    def list_resource_templates(
        self, principal: Principal | None = None
    ) -> list[ResourceTemplateSpec]:
        p = principal or Principal.local()
        return [s for s in self.registry.templates.values() if self.policy.is_allowed(s, p)]

    def list_prompts(self, principal: Principal | None = None) -> list[PromptSpec]:
        p = principal or Principal.local()
        return [s for s in self.registry.prompts.values() if self.policy.is_allowed(s, p)]

    def tools_wire(self, principal: Principal | None = None) -> list[dict[str, Any]]:
        """``tools/list`` entries for ``principal``.

        ``outputSchema`` is withheld when the caller's output pipeline is
        non-empty: masking or projection changes the shape of
        ``structuredContent``, and clients reject results that do not
        validate against an advertised schema.
        """
        p = principal or Principal.local()
        return [
            s.to_wire(
                self.exposed_name(s.name),
                include_output_schema=not self.policy.output_pipeline(s, p),
            )
            for s in self.list_tools(p)
        ]

    def resources_wire(self, principal: Principal | None = None) -> list[dict[str, Any]]:
        return [s.to_wire() for s in self.list_resources(principal)]

    def resource_templates_wire(self, principal: Principal | None = None) -> list[dict[str, Any]]:
        return [s.to_wire() for s in self.list_resource_templates(principal)]

    def prompts_wire(self, principal: Principal | None = None) -> list[dict[str, Any]]:
        return [s.to_wire(self.exposed_name(s.name)) for s in self.list_prompts(principal)]

    # ------------------------------------------------------------------
    # Middleware plumbing
    # ------------------------------------------------------------------

    async def _run_chain(self, info: CallInfo, terminal: Next) -> Any:
        chain: Next = terminal
        for mw in reversed(self.middleware):
            chain = _bind(mw, chain)
        return await chain(info)

    def _transform(self, value: Any, spec: Any, principal: Principal, kind: str) -> tuple[Any, dict]:
        pipeline = self.policy.output_pipeline(spec, principal)
        if not pipeline:
            return value, {}
        tctx = TransformContext(
            principal=principal, spec=spec, kind=kind, direction="output", vault=self.policy.vault
        )
        return pipeline.apply(value, tctx), tctx.report

    def _untransform_arguments(
        self, arguments: dict[str, Any], spec: Any, principal: Principal, kind: str
    ) -> dict[str, Any]:
        pipeline = self.policy.input_pipeline(spec, principal)
        if not pipeline:
            return arguments
        tctx = TransformContext(
            principal=principal, spec=spec, kind=kind, direction="input", vault=self.policy.vault
        )
        return pipeline.apply(arguments, tctx)

    async def _invoke(self, fn: Callable[..., Any], ctx: ToolContext, kwargs: dict[str, Any]) -> Any:
        """Run a handler: coroutine functions on the loop, plain functions
        in a worker thread so blocking graph/ontology work does not stall
        the server."""
        self._remember_loop()
        ctx.loop = self._loop
        if asyncio.iscoroutinefunction(fn):
            return await fn(ctx, **kwargs)
        result = await asyncio.to_thread(fn, ctx, **kwargs)
        return await maybe_await(result)

    # ------------------------------------------------------------------
    # Tools
    # ------------------------------------------------------------------

    def get_tool(self, name: str, principal: Principal | None = None) -> ToolSpec:
        principal = principal or Principal.local()
        spec = self.registry.tools.get(self.internal_name(name))
        if spec is None or not self.policy.is_allowed(spec, principal):
            self._record_hidden("tool", name, principal)
            raise NotFoundError(f"Unknown tool: {name}")
        return spec

    def _record_hidden(self, kind: str, name: str, principal: Principal) -> None:
        """Audit a call to an unknown or policy-hidden primitive: probing
        for hidden tools is worth seeing in the audit trail."""
        record = getattr(self.policy, "record_hidden", None)
        if record is not None:
            try:
                record(kind, name, principal)
            except Exception:
                logger.debug("record_hidden failed", exc_info=True)

    async def call_tool(
        self,
        name: str,
        arguments: dict[str, Any] | None = None,
        *,
        principal: Principal | None = None,
        context: ToolContext | None = None,
    ) -> ToolResult:
        """Call a tool. Unknown tools raise :class:`NotFoundError`; every
        other failure (bad arguments, access denied, handler error,
        timeout) comes back as an ``isError`` result the model can read."""
        principal = principal or (context.principal if context else Principal.local())
        spec = self.get_tool(name, principal)
        ctx = context or self.context(principal)
        ctx.principal, ctx.kind, ctx.name = principal, "tool", spec.name
        info = CallInfo("tool", spec.name, spec, dict(arguments or {}), principal, ctx)
        try:
            return await self._run_chain(info, self._tool_terminal)
        except MCPLayerError as exc:
            # Includes NotFoundError raised by a handler ("asset not found"):
            # the model can recover from an isError result, not from a
            # protocol error.
            return self._error_result(exc.message, spec, principal, exc.code, exc.data)

    async def _tool_terminal(self, info: CallInfo) -> ToolResult:
        spec: ToolSpec = info.spec
        try:
            self.policy.check_call(spec, info.principal, info.arguments)
            try:
                arguments = self._untransform_arguments(
                    info.arguments, spec, info.principal, "tool"
                )
            except MCPLayerError as exc:
                # check_call already audited this call as allowed; the input
                # pipeline (e.g. a secret in the arguments) refused it
                record = getattr(self.policy, "record_rejection", None)
                if record is not None:
                    record(spec, info.principal, info.arguments, exc)
                raise
            kwargs = validate_arguments(spec.handler, arguments)
            timeout = spec.timeout_seconds or self.default_timeout
            coro = self._invoke(spec.handler, info.context, kwargs)
            raw = await (asyncio.wait_for(coro, timeout) if timeout else coro)
        except (MCPLayerError, InvalidArgumentsError):
            raise
        except asyncio.TimeoutError:
            return self._error_result(f"Tool {spec.name} timed out", spec, info.principal, "timeout")
        except Exception as exc:
            logger.exception("Tool %s failed", spec.name)
            # Exception text often quotes ARNs / account ids: it goes
            # through the same output pipeline as a normal result.
            return self._error_result(
                f"{type(exc).__name__}: {exc}", spec, info.principal, "handler_error"
            )
        return self._finalise_tool_result(raw, info)

    def _error_result(
        self, message: str, spec: Any, principal: Principal, code: Any, data: Any = None
    ) -> ToolResult:
        text, _ = self._transform(message, spec, principal, "tool")
        meta: dict[str, Any] = {f"{META_PREFIX}error_code": code}
        if data is not None:
            meta[f"{META_PREFIX}error_data"], _ = self._transform(
                _jsonable(data), spec, principal, "tool"
            )
        return ToolResult(content=[TextContent(str(text))], is_error=True, meta=meta)

    def _transform_links(
        self, links: list[ResourceLink], spec: Any, principal: Principal, kind: str
    ) -> list[ResourceLink]:
        out = []
        for link in links:
            wire, _ = self._transform(
                {"uri": link.uri, "name": link.name, "title": link.title,
                 "description": link.description},
                spec, principal, kind,
            )
            out.append(
                ResourceLink(
                    uri=str(wire.get("uri", link.uri)),
                    name=str(wire.get("name", link.name)),
                    title=wire.get("title"),
                    description=wire.get("description"),
                    mime_type=link.mime_type,
                    size=link.size,
                    annotations=link.annotations,
                    meta=link.meta,
                )
            )
        return out

    def _finalise_tool_result(self, raw: Any, info: CallInfo) -> ToolResult:
        spec: ToolSpec = info.spec
        if isinstance(raw, ToolResult):
            result = raw
            if result.structured is not None:
                result.structured, report = self._transform(
                    result.structured, spec, info.principal, "tool"
                )
            else:
                report = {}
            for i, c in enumerate(result.content):
                if isinstance(c, TextContent):
                    text, r = self._transform(c.text, spec, info.principal, "tool")
                    result.content[i] = TextContent(str(text), c.annotations, c.meta)
                    _merge_report(report, r)
                elif isinstance(c, ResourceLink):
                    result.content[i] = self._transform_links([c], spec, info.principal, "tool")[0]
                elif isinstance(c, EmbeddedResource) and isinstance(
                    c.resource, TextResourceContents
                ):
                    text, r = self._transform(c.resource.text, spec, info.principal, "tool")
                    res = c.resource
                    c.resource = TextResourceContents(res.uri, str(text), res.mime_type, res.meta)
                    _merge_report(report, r)
            if result.meta:
                result.meta, r = self._transform(result.meta, spec, info.principal, "tool")
                _merge_report(report, r)
        else:
            data = _jsonable(raw)
            structured = data if isinstance(data, dict) else {"result": data}
            structured, report = self._transform(structured, spec, info.principal, "tool")
            text = dumps(structured)
            if len(text) > self.max_output_chars:
                report["truncated_chars"] = len(text) - self.max_output_chars
                text = text[: self.max_output_chars] + "\n... [truncated by cloudg mcp layer]"
            result = ToolResult(content=[TextContent(text)], structured=structured)
        result.content.extend(
            self._transform_links(info.context.links, spec, info.principal, "tool")
        )
        if report:
            result.meta[f"{META_PREFIX}transforms"] = report
        result.meta.setdefault(
            f"{META_PREFIX}duration_ms", int((time.monotonic() - info.started) * 1000)
        )
        return result

    # ------------------------------------------------------------------
    # Resources
    # ------------------------------------------------------------------

    def _resolve_resource(
        self, uri: str, principal: Principal
    ) -> tuple[ResourceSpec | ResourceTemplateSpec, dict[str, str]]:
        spec: Any = self.registry.resources.get(uri)
        values: dict[str, str] = {}
        if spec is None:
            found = self.registry.find_template(uri)
            if found:
                spec, values = found
        if spec is None or not self.policy.is_allowed(spec, principal):
            self._record_hidden("resource", uri, principal)
            raise NotFoundError(f"Unknown resource: {uri}")
        return spec, values

    async def read_resource(
        self,
        uri: str,
        *,
        principal: Principal | None = None,
        context: ToolContext | None = None,
    ) -> list[TextResourceContents | BlobResourceContents]:
        principal = principal or (context.principal if context else Principal.local())
        spec, values = self._resolve_resource(uri, principal)
        ctx = context or self.context(principal)
        ctx.principal, ctx.kind, ctx.name = principal, "resource", uri
        info = CallInfo("resource", uri, spec, values, principal, ctx)
        return await self._run_chain(info, self._resource_terminal)

    async def _resource_terminal(self, info: CallInfo) -> list[Any]:
        spec = info.spec
        self.policy.check_call(spec, info.principal, info.arguments)
        values = self._untransform_arguments(info.arguments, spec, info.principal, "resource")
        raw = await self._invoke(spec.handler, info.context, values)
        uri, mime = info.name, spec.mime_type
        if isinstance(raw, list) and raw and all(
            isinstance(x, (TextResourceContents, BlobResourceContents)) for x in raw
        ):
            out = []
            for item in raw:
                if isinstance(item, TextResourceContents):
                    text, _ = self._transform(item.text, spec, info.principal, "resource")
                    item = TextResourceContents(item.uri, str(text), item.mime_type, item.meta)
                out.append(item)
            return out
        if isinstance(raw, bytes):
            return [BlobResourceContents(uri, base64.b64encode(raw).decode(), mime)]
        if isinstance(raw, str):
            text, report = self._transform(raw, spec, info.principal, "resource")
            meta = {f"{META_PREFIX}transforms": report} if report else None
            return [TextResourceContents(uri, str(text), mime, meta)]
        data, report = self._transform(_jsonable(raw), spec, info.principal, "resource")
        meta = {f"{META_PREFIX}transforms": report} if report else None
        return [TextResourceContents(uri, dumps(data), mime or "application/json", meta)]

    # ------------------------------------------------------------------
    # Prompts
    # ------------------------------------------------------------------

    async def get_prompt(
        self,
        name: str,
        arguments: dict[str, Any] | None = None,
        *,
        principal: Principal | None = None,
        context: ToolContext | None = None,
    ) -> PromptResult:
        principal = principal or (context.principal if context else Principal.local())
        spec = self.registry.prompts.get(self.internal_name(name))
        if spec is None or not self.policy.is_allowed(spec, principal):
            self._record_hidden("prompt", name, principal)
            raise NotFoundError(f"Unknown prompt: {name}")
        args = dict(arguments or {})
        missing = [a.name for a in spec.arguments if a.required and not args.get(a.name)]
        if missing:
            raise InvalidArgumentsError(f"Missing required prompt arguments: {', '.join(missing)}")
        ctx = context or self.context(principal)
        ctx.principal, ctx.kind, ctx.name = principal, "prompt", spec.name
        info = CallInfo("prompt", spec.name, spec, args, principal, ctx)
        return await self._run_chain(info, self._prompt_terminal)

    async def _prompt_terminal(self, info: CallInfo) -> PromptResult:
        spec: PromptSpec = info.spec
        self.policy.check_call(spec, info.principal, info.arguments)
        args = self._untransform_arguments(info.arguments, spec, info.principal, "prompt")
        known = {a.name for a in spec.arguments}
        raw = await self._invoke(
            spec.handler, info.context, {k: v for k, v in args.items() if k in known}
        )
        if isinstance(raw, PromptResult):
            result = raw
        elif isinstance(raw, str):
            result = PromptResult([PromptMessage("user", TextContent(raw))], spec.description)
        else:
            result = PromptResult(list(raw), spec.description)
        for m in result.messages:
            if isinstance(m.content, TextContent):
                text, _ = self._transform(m.content.text, spec, info.principal, "prompt")
                m.content = TextContent(str(text), m.content.annotations, m.content.meta)
            elif isinstance(m.content, EmbeddedResource) and isinstance(
                m.content.resource, TextResourceContents
            ):
                text, _ = self._transform(m.content.resource.text, spec, info.principal, "prompt")
                m.content.resource.text = str(text)
            elif isinstance(m.content, ResourceLink):
                m.content = self._transform_links([m.content], spec, info.principal, "prompt")[0]
        return result

    # ------------------------------------------------------------------
    # Completions
    # ------------------------------------------------------------------

    async def complete(
        self,
        ref: dict[str, Any],
        argument: dict[str, Any],
        *,
        principal: Principal | None = None,
        context_arguments: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """``completion/complete``. ``ref`` is ``{"type": "ref/prompt",
        "name": ...}`` or ``{"type": "ref/resource", "uri": <template>}``;
        ``argument`` is ``{"name": ..., "value": ...}``. Returns the wire
        ``completion`` object."""
        principal = principal or Principal.local()
        arg_name, partial = argument.get("name", ""), str(argument.get("value", ""))
        spec: Any = None
        fn: Callable[..., Any] | None = None
        if ref.get("type") == "ref/prompt":
            spec = self.registry.prompts.get(self.internal_name(ref.get("name", "")))
            if spec is not None:
                fn = next((a.completion for a in spec.arguments if a.name == arg_name), None)
        elif ref.get("type") == "ref/resource":
            spec = self.registry.templates.get(ref.get("uri", ""))
            if spec is not None:
                fn = spec.completions.get(arg_name)
        if spec is None or fn is None or not self.policy.is_allowed(spec, principal):
            return dict(_EMPTY_COMPLETION)
        ctx = self.context(principal, kind="completion", name=arg_name)
        ctx.meta["completion_fn"] = fn
        name = spec.name if isinstance(spec, PromptSpec) else spec.uri_template
        args = {"argument": arg_name, "value": partial, "context": dict(context_arguments or {})}
        info = CallInfo("completion", name, spec, args, principal, ctx)
        # Completions disclose data too: they run through the middleware
        # chain (audit, metrics) and the policy's rate limits and transforms
        return await self._run_chain(info, self._completion_terminal)

    async def _completion_terminal(self, info: CallInfo) -> dict[str, Any]:
        spec, principal = info.spec, info.principal
        arg_name = info.arguments["argument"]
        self.policy.check_call(spec, principal, {"__completion__": arg_name})
        restored = self._untransform_arguments(
            {"partial": info.arguments["value"], "arguments": info.arguments["context"]},
            spec, principal, "completion",
        )
        ctx = info.context
        ctx.meta["arguments"] = restored.get("arguments", {})
        fn = ctx.meta.pop("completion_fn")
        try:
            raw = await self._invoke(
                fn, ctx, {"partial": str(restored.get("partial", info.arguments["value"]))}
            )
            values = [str(v) for v in raw]
        except Exception:
            logger.debug("completion failed", exc_info=True)
            return dict(_EMPTY_COMPLETION)
        if values:
            # Wrap each value under its argument name: key-based detectors
            # (asset names, account ids...) need a key to recognise a bare
            # value, exactly as they would in a tool result.
            key = arg_name or "value"
            wrapped, _ = self._transform([{key: v} for v in values], spec, principal, "completion")
            values = [str(w.get(key, "")) if isinstance(w, dict) else str(w) for w in wrapped]
        return {"values": values[:100], "total": len(values), "hasMore": len(values) > 100}

    # ------------------------------------------------------------------
    # Embedding / serving conveniences (implemented by the adapters)
    # ------------------------------------------------------------------

    def register_into(self, server: Any, **kwargs: Any) -> Any:
        """Mount every tool, resource, template and prompt into an existing
        MCP server object (mcp SDK ``MCPServer`` / ``FastMCP`` / low-level
        ``Server``, or a standalone ``fastmcp.FastMCP``). See
        :func:`cloudg.mcp.adapters.register_into`."""
        from cloudg.mcp.adapters import register_into

        return register_into(self, server, **kwargs)

    def serve(self, transport: str = "stdio", **kwargs: Any) -> None:
        """Run this layer as a standalone MCP server. See
        :func:`cloudg.mcp.server.serve`."""
        from cloudg.mcp.server import serve

        serve(self, transport=transport, **kwargs)


def _bind(mw: Middleware, nxt: Next) -> Next:
    async def call(info: CallInfo) -> Any:
        return await mw(info, nxt)

    return call


def _merge_report(into: dict[str, Any], other: dict[str, Any]) -> None:
    for k, v in other.items():
        if isinstance(v, (int, float)) and isinstance(into.get(k), (int, float)):
            into[k] += v
        else:
            into.setdefault(k, v)


