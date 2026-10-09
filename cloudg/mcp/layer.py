"""The cloudg MCP layer: one object that owns the registry, the workspace,
the policy and the middleware chain, and dispatches MCP requests.

Adapters never call handlers directly; they go through
:meth:`CloudGMCPLayer.call_tool`, :meth:`read_resource`,
:meth:`get_prompt` and :meth:`complete`. Whichever server a request arrives
through, it gets the same validation, access control, transforms
(redaction / pseudonymisation / projection / annotation / substitution),
timeouts and audit trail. Output shaping lives in
:mod:`cloudg.mcp.layer_output`, construction options in
:mod:`cloudg.mcp.layer_options`.
"""

from __future__ import annotations

import asyncio
import inspect
import logging
import re
import time
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Awaitable, Callable

from cloudg.mcp.context import Principal, ToolContext
from cloudg.mcp.core import (
    META_PREFIX,
    BlobResourceContents,
    InvalidArgumentsError,
    MCPLayerError,
    NotFoundError,
    PromptResult,
    PromptSpec,
    ResourceSpec,
    ResourceTemplateSpec,
    TextResourceContents,
    ToolResult,
    ToolSpec,
    maybe_await,
    render_json,
)
from cloudg.mcp.layer_options import LayerOptions, filter_registry
from cloudg.mcp.layer_output import (
    OutputScope,
    error_result,
    jsonable,
    restored_pairs,
    shape_prompt,
    shape_resource,
    shape_tool_result,
    transform_error,
)
from cloudg.mcp.schema import validate_arguments
from cloudg.mcp.transforms.base import TransformContext

if TYPE_CHECKING:  # pragma: no cover
    from cloudg.config import CloudGConfig
    from cloudg.mcp.policy import Policy

__all__ = ["CallInfo", "CloudGMCPLayer", "LayerOptions", "Middleware", "Next"]

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
    #: The call's :class:`~cloudg.mcp.layer_output.OutputScope` (set by the layer).
    output: Any = field(default=None, repr=False)


_EMPTY_COMPLETION: dict[str, Any] = {"values": [], "total": 0, "hasMore": False}
_PREFIX_RE = re.compile(r"^[A-Za-z0-9_.\-]{0,64}$")
#: ``ToolContext.meta`` key holding the canonical URI of a resource read.
URI_META_KEY = f"{META_PREFIX}uri"

Next = Callable[[CallInfo], Awaitable[Any]]
# ``async def middleware(info: CallInfo, call_next: Next) -> Any``; for tools
# the value is a ToolResult, for resources a list of contents, for prompts a
# PromptResult. Raise an MCPLayerError to reject the call.
Middleware = Callable[[CallInfo, Next], Awaitable[Any]]

dumps = render_json
_URI_KEYWORD: dict[Any, bool] = {}


def _policy_call(fn: Callable[..., Any], *args: Any, uri: str | None = None) -> Any:
    """Call a policy method, passing the concrete resource ``uri`` when the
    policy accepts it (older policies only match the spec's own URI)."""
    if uri is not None:
        key = getattr(fn, "__func__", fn)
        accepts = _URI_KEYWORD.get(key)
        if accepts is None:
            try:
                params = inspect.signature(fn).parameters.values()
            except (TypeError, ValueError):
                params = ()  # type: ignore[assignment]
            accepts = any(p.name == "uri" or p.kind is p.VAR_KEYWORD for p in params)
            _URI_KEYWORD[key] = accepts
        if accepts:
            return fn(*args, uri=uri)
    return fn(*args)


class CloudGMCPLayer:
    """Plug-and-play MCP layer over cloudg.

    Args:
        config: cloudg configuration (providers, credentials...). Defaults
            to ``CloudGConfig()``.
        options: All other settings as one :class:`LayerOptions`.
        **kwargs: The same settings as keywords (each field of
            :class:`LayerOptions`): ``workspace``, ``policy`` (a
            :class:`~cloudg.mcp.policy.Policy`, profile name, policy file
            path or dict), ``registry``, ``include_categories`` /
            ``exclude_categories``, ``include_tools`` / ``exclude_tools``,
            ``prefix`` (prepended to every tool and prompt name),
            ``middleware`` (outermost first), ``default_timeout`` (seconds
            before a tool call is cancelled), ``max_output_chars``, ``name``,
            ``version`` and ``instructions``. Unknown keywords raise
            :class:`TypeError`.
    """

    def __init__(
        self,
        config: "CloudGConfig | None" = None,
        *,
        options: LayerOptions | None = None,
        **kwargs: Any,
    ) -> None:
        from cloudg import __version__
        from cloudg.mcp.policy import Policy as PolicyClass

        opts = LayerOptions.build(options, kwargs)
        workspace = opts.workspace
        if workspace is None:
            from cloudg.config import CloudGConfig
            from cloudg.mcp.state import Workspace

            workspace = Workspace(config or CloudGConfig())
        self.workspace = workspace
        policy = opts.policy
        self.policy: Policy = (
            policy if isinstance(policy, PolicyClass) else PolicyClass.load(policy)
        )
        registry = opts.registry
        if registry is None:
            from cloudg.mcp.catalog import default_registry

            registry = default_registry()
        self.registry = filter_registry(registry, opts)
        self.prefix = ""
        self.set_prefix(opts.prefix)
        self.middleware: list[Middleware] = list(opts.middleware)
        self.default_timeout = opts.default_timeout
        self.max_output_chars = opts.max_output_chars
        self.name = opts.name
        self.version = opts.version or __version__
        self.instructions = (
            opts.instructions if opts.instructions is not None else DEFAULT_INSTRUCTIONS
        )
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
            logger.debug("no running event loop to remember")

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
    # Middleware plumbing, transforms
    # ------------------------------------------------------------------

    async def _run_chain(self, info: CallInfo, terminal: Next) -> Any:
        chain: Next = terminal
        for mw in reversed(self.middleware):
            chain = _bind(mw, chain)
        return await chain(info)

    def _transform(
        self, value: Any, spec: Any, principal: Principal, kind: str
    ) -> tuple[Any, dict]:
        """``(transformed, report)`` for ``value`` under the caller's output
        pipeline."""
        return OutputScope(self.policy, spec, principal, kind).apply(value)

    def _begin(
        self, kind: str, name: str, spec: Any, args: dict[str, Any], ctx: ToolContext
    ) -> CallInfo:
        """Set up one call: its context and its output scope (also used for
        the progress and log notifications the handler sends)."""
        scope = OutputScope(self.policy, spec, ctx.principal, kind)
        ctx.kind, ctx.name = kind, name
        ctx.transform_output = lambda value: scope(jsonable(value))
        return CallInfo(kind, name, spec, args, ctx.principal, ctx, output=scope)

    def _scope(self, info: CallInfo) -> OutputScope:
        if info.output is None:  # a middleware built its own CallInfo
            info.output = OutputScope(self.policy, info.spec, info.principal, info.kind)
        return info.output

    def _untransform(self, info: CallInfo, values: dict[str, Any]) -> dict[str, Any]:
        """Run the input pipeline (secret guards, pseudonym reversal) and
        remember the real values it restored for the output side."""
        pipeline = self.policy.input_pipeline(info.spec, info.principal)
        if not pipeline:
            return values
        tctx = TransformContext(
            principal=info.principal,
            spec=info.spec,
            kind=info.kind,
            direction="input",
            vault=self.policy.vault,
        )
        out = pipeline.apply(values, tctx)
        self._scope(info).add_restored(restored_pairs(values, out, tctx))
        return out

    async def _invoke(
        self, fn: Callable[..., Any], ctx: ToolContext, kwargs: dict[str, Any]
    ) -> Any:
        """Run a handler: coroutine functions on the loop, plain functions
        in a worker thread so blocking graph/ontology work does not stall
        the server."""
        self._remember_loop()
        ctx.loop = self._loop
        if asyncio.iscoroutinefunction(fn):
            return await fn(ctx, **kwargs)
        result = await asyncio.to_thread(fn, ctx, **kwargs)
        return await maybe_await(result)

    async def _invoke_guarded(self, info: CallInfo, kwargs: dict[str, Any]) -> Any:
        """:meth:`_invoke` for resources and prompts: an unexpected handler
        exception becomes an internal :class:`MCPLayerError` (transformed by
        the caller) instead of leaking raw exception text through an
        adapter."""
        try:
            return await self._invoke(info.spec.handler, info.context, kwargs)
        except MCPLayerError:
            raise
        except Exception as exc:
            logger.exception("%s %s failed", info.kind.capitalize(), info.name)
            raise MCPLayerError(f"{type(exc).__name__}: {exc}") from None

    def _record(self, hook: str, *args: Any) -> None:
        """Call an optional policy audit hook (``record_hidden`` /
        ``record_rejection``); failures are logged, never raised."""
        record = getattr(self.policy, hook, None)
        if record is not None:
            try:
                record(*args)
            except Exception:
                logger.debug("%s failed", hook, exc_info=True)

    # ------------------------------------------------------------------
    # Tools
    # ------------------------------------------------------------------

    def get_tool(self, name: str, principal: Principal | None = None) -> ToolSpec:
        principal = principal or Principal.local()
        spec = self.registry.tools.get(self.internal_name(name))
        if spec is None or not self.policy.is_allowed(spec, principal):
            self._record("record_hidden", "tool", name, principal)
            raise NotFoundError(f"Unknown tool: {name}")
        return spec

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
        ctx.principal = principal
        info = self._begin("tool", spec.name, spec, dict(arguments or {}), ctx)
        try:
            return await self._run_chain(info, self._tool_terminal)
        except MCPLayerError as exc:
            # Includes NotFoundError raised by a handler ("asset not found"):
            # the model can recover from an isError result, not from a
            # protocol error.
            return error_result(self._scope(info), exc.message, exc.code, exc.data)

    async def _tool_terminal(self, info: CallInfo) -> ToolResult:
        spec: ToolSpec = info.spec
        scope = self._scope(info)
        try:
            self.policy.check_call(spec, info.principal, info.arguments)
            try:
                arguments = self._untransform(info, info.arguments)
            except MCPLayerError as exc:
                # check_call already audited this call as allowed; the input
                # pipeline (e.g. a secret in the arguments) refused it
                self._record("record_rejection", spec, info.principal, info.arguments, exc)
                raise
            kwargs = validate_arguments(spec.handler, arguments)
            timeout = spec.timeout_seconds or self.default_timeout
            coro = self._invoke(spec.handler, info.context, kwargs)
            raw = await (asyncio.wait_for(coro, timeout) if timeout else coro)
        except (MCPLayerError, InvalidArgumentsError):
            raise
        except asyncio.TimeoutError:
            return error_result(scope, f"Tool {spec.name} timed out", "timeout")
        except Exception as exc:
            logger.exception("Tool %s failed", spec.name)
            # Exception text often quotes ARNs / account ids: it goes
            # through the same output pipeline as a normal result.
            return error_result(scope, f"{type(exc).__name__}: {exc}", "handler_error")
        result, report = shape_tool_result(scope, raw, info.context.links, self.max_output_chars)
        if report:
            result.meta[f"{META_PREFIX}transforms"] = report
        result.meta.setdefault(
            f"{META_PREFIX}duration_ms", int((time.monotonic() - info.started) * 1000)
        )
        return result

    # ------------------------------------------------------------------
    # Resources
    # ------------------------------------------------------------------

    def _resolve_resource(self, uri: str, principal: Principal) -> tuple[Any, dict[str, str], str]:
        """``(spec, template values, canonical URI)`` for ``uri``.

        Template values arrive percent-decoded, so ``cloudg://graph/%64%33``
        names the same resource as ``cloudg://graph/d3``: the canonical URI
        (values filled in verbatim) resolves to the static resource when one
        exists, and is what the policy matches allow / deny patterns against.
        """
        spec: Any = self.registry.resources.get(uri)
        values: dict[str, str] = {}
        canonical = uri
        if spec is None:
            found = self.registry.find_template(uri)
            if found:
                spec, values = found
                canonical = spec.canonical(values)
                static = self.registry.resources.get(canonical)
                if static is not None:
                    spec, values = static, {}
        if spec is None or not _policy_call(self.policy.is_allowed, spec, principal, uri=canonical):
            self._record("record_hidden", "resource", uri, principal)
            raise NotFoundError(f"Unknown resource: {uri}")
        return spec, values, canonical

    async def read_resource(
        self,
        uri: str,
        *,
        principal: Principal | None = None,
        context: ToolContext | None = None,
    ) -> list[TextResourceContents | BlobResourceContents]:
        principal = principal or (context.principal if context else Principal.local())
        spec, values, canonical = self._resolve_resource(uri, principal)
        served = canonical if isinstance(spec, ResourceSpec) else uri
        ctx = context or self.context(principal)
        ctx.principal = principal
        ctx.meta[URI_META_KEY] = canonical
        info = self._begin("resource", served, spec, values, ctx)
        try:
            return await self._run_chain(info, self._resource_terminal)
        except MCPLayerError as exc:
            raise transform_error(self._scope(info), exc) from None

    async def _resource_terminal(self, info: CallInfo) -> list[Any]:
        spec = info.spec
        canonical = info.context.meta.get(URI_META_KEY, info.name)
        _policy_call(self.policy.check_call, spec, info.principal, info.arguments, uri=canonical)
        values = self._untransform(info, info.arguments)
        raw = await self._invoke_guarded(info, values)
        return shape_resource(self._scope(info), raw, info.name, spec.mime_type)

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
            self._record("record_hidden", "prompt", name, principal)
            raise NotFoundError(f"Unknown prompt: {name}")
        args = dict(arguments or {})
        missing = [a.name for a in spec.arguments if a.required and not args.get(a.name)]
        if missing:
            raise InvalidArgumentsError(f"Missing required prompt arguments: {', '.join(missing)}")
        ctx = context or self.context(principal)
        ctx.principal = principal
        info = self._begin("prompt", spec.name, spec, args, ctx)
        try:
            return await self._run_chain(info, self._prompt_terminal)
        except MCPLayerError as exc:
            raise transform_error(self._scope(info), exc) from None

    async def _prompt_terminal(self, info: CallInfo) -> PromptResult:
        spec: PromptSpec = info.spec
        self.policy.check_call(spec, info.principal, info.arguments)
        args = self._untransform(info, info.arguments)
        known = {a.name for a in spec.arguments}
        raw = await self._invoke_guarded(info, {k: v for k, v in args.items() if k in known})
        return shape_prompt(self._scope(info), raw, spec.description)

    # ------------------------------------------------------------------
    # Completions
    # ------------------------------------------------------------------

    def _completion_target(self, ref: dict[str, Any], arg_name: str) -> tuple[Any, Any]:
        """``(spec, completion fn)`` named by a completion ``ref``."""
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
        return spec, fn

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
        spec, fn = self._completion_target(ref, arg_name)
        if spec is None or fn is None or not self.policy.is_allowed(spec, principal):
            return dict(_EMPTY_COMPLETION)
        ctx = self.context(principal)
        ctx.meta["completion_fn"] = fn
        name = spec.name if isinstance(spec, PromptSpec) else spec.uri_template
        args = {"argument": arg_name, "value": partial, "context": dict(context_arguments or {})}
        info = self._begin("completion", name, spec, args, ctx)
        ctx.name = arg_name
        # Completions disclose data too: they run through the middleware
        # chain (audit, metrics) and the policy's rate limits and transforms
        try:
            return await self._run_chain(info, self._completion_terminal)
        except MCPLayerError as exc:
            raise transform_error(self._scope(info), exc) from None

    async def _completion_terminal(self, info: CallInfo) -> dict[str, Any]:
        spec, principal = info.spec, info.principal
        arg_name = info.arguments["argument"]
        self.policy.check_call(spec, principal, {"__completion__": arg_name})
        restored = self._untransform(
            info, {"partial": info.arguments["value"], "arguments": info.arguments["context"]}
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
            wrapped = self._scope(info)([{key: v} for v in values])
            values = [str(w.get(key, "")) if isinstance(w, dict) else str(w) for w in wrapped]
        return {"values": values[:100], "total": len(values), "hasMore": len(values) > 100}

    # ------------------------------------------------------------------
    # Embedding / serving conveniences (implemented by the adapters)
    # ------------------------------------------------------------------

    def register_into(self, server: Any, **kwargs: Any) -> Any:
        """Mount every tool, resource, template and prompt into an existing
        MCP server object (mcp SDK ``MCPServer`` / ``FastMCP`` / low-level
        ``Server``, or a standalone ``fastmcp.FastMCP``). See
        :func:`cloudg.mcp.adapters.register_into` (``prefix=`` changes this
        layer's prefix for every server it is mounted on)."""
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
