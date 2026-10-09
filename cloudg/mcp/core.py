"""Framework-agnostic MCP primitives for the cloudg MCP layer.

Everything the layer exposes (tools, resources, resource templates and
prompts) is described here as plain dataclasses that know nothing about
any particular MCP server implementation. Adapters
(:mod:`cloudg.mcp.adapters`) translate these specs into the official
``mcp`` SDK (1.x ``FastMCP`` or 2.x ``MCPServer`` / low-level ``Server``),
the standalone ``fastmcp`` package, or the dependency-free native server.

The wire shapes produced by the ``to_wire()`` methods follow the MCP
specification (camelCase keys), so adapters can feed them straight into
``mcp.types.<Model>.model_validate``.
"""

from __future__ import annotations

import inspect
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Awaitable, Callable, Iterable

# Re-exported: cloudg.mcp.core is the documented import path for these.
from cloudg.mcp.content import (
    BlobResourceContents,
    Content,
    ContentAnnotations,
    EmbeddedResource,
    Icon,
    ImageContent,
    PromptMessage,
    PromptResult,
    ResourceContents,
    ResourceLink,
    Role,
    TextContent,
    TextResourceContents,
    ToolAnnotations,
    ToolResult,
    _icons_wire,
)

__all__ = [
    "AccessDeniedError",
    "BlobResourceContents",
    "Capability",
    "Content",
    "ContentAnnotations",
    "EmbeddedResource",
    "Handler",
    "Icon",
    "ImageContent",
    "InvalidArgumentsError",
    "MCPLayerError",
    "META_PREFIX",
    "NotFoundError",
    "PromptArgument",
    "PromptMessage",
    "PromptResult",
    "PromptSpec",
    "RateLimitedError",
    "Registry",
    "ResourceContents",
    "ResourceLink",
    "ResourceSpec",
    "ResourceTemplateSpec",
    "Role",
    "SENSITIVITY_ORDER",
    "Sensitivity",
    "TextContent",
    "TextResourceContents",
    "ToolAnnotations",
    "ToolResult",
    "ToolSpec",
    "maybe_await",
    "render_json",
]

# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


# JSON-RPC codes. -32768..-32000 belong to JSON-RPC and -32020..-32099 are
# reserved by MCP, so application errors use -31xxx.
META_PREFIX = "cloudg/"


class MCPLayerError(Exception):
    """Base error for the MCP layer. ``code`` is a JSON-RPC error code."""

    code: int = -32603

    def __init__(self, message: str, *, data: Any = None) -> None:
        super().__init__(message)
        self.message = message
        self.data = data


class InvalidArgumentsError(MCPLayerError):
    """Tool / prompt arguments failed validation."""

    code = -32602


class NotFoundError(MCPLayerError):
    """Unknown tool, prompt, resource URI or dataset. MCP 2026-07-28 maps
    unknown resources to Invalid Params; raised inside a tool handler it
    becomes an ``isError`` result instead."""

    code = -32602


class AccessDeniedError(MCPLayerError):
    """The active policy forbids this operation for the caller."""

    code = -31001


class RateLimitedError(MCPLayerError):
    """The caller exceeded a configured rate limit."""

    code = -31029


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class Sensitivity(str, Enum):
    """How sensitive a primitive's output is. Policies use this to decide
    which transforms (redaction, pseudonymisation...) apply and whether the
    primitive is exposed at all."""

    PUBLIC = "public"  # schema/catalog data, no tenant information
    INTERNAL = "internal"  # aggregate counts, summaries
    CONFIDENTIAL = "confidential"  # asset identifiers, topology, findings
    RESTRICTED = "restricted"  # raw metadata, policies, anything that may hold secrets


SENSITIVITY_ORDER = {s: i for i, s in enumerate(Sensitivity)}


class Capability(str, Enum):
    """Side effects a tool needs. Policies can deny whole capabilities
    (e.g. a read-only deployment denies CLOUD_ACCESS and WRITE_FS)."""

    READ_STATE = "read_state"  # reads loaded datasets only
    WRITE_STATE = "write_state"  # mutates the in-memory workspace
    READ_FS = "read_fs"  # reads files from disk
    WRITE_FS = "write_fs"  # writes files to disk
    CLOUD_ACCESS = "cloud_access"  # calls cloud provider APIs with credentials
    EXEC = "exec"  # spawns external processes (scanners)
    REVEAL = "reveal"  # reverses pseudonymisation / reveals hidden values


# ---------------------------------------------------------------------------
# Specs
# ---------------------------------------------------------------------------

Handler = Callable[..., Any | Awaitable[Any]]

_NAME_RE = re.compile(r"^[A-Za-z0-9_.\-]{1,128}$")


@dataclass
class _BaseSpec:
    name: str
    handler: Handler
    title: str | None = None
    description: str = ""
    category: str = "general"
    tags: set[str] = field(default_factory=set)
    sensitivity: Sensitivity = Sensitivity.CONFIDENTIAL
    capabilities: set[Capability] = field(default_factory=lambda: {Capability.READ_STATE})
    meta: dict[str, Any] = field(default_factory=dict)
    icons: list[Icon] | None = None

    def __post_init__(self) -> None:
        if not self.description:
            self.description = inspect.cleandoc(self.handler.__doc__ or "").strip()

    def _common_wire(self, out: dict[str, Any]) -> dict[str, Any]:
        if self.title:
            out["title"] = self.title
        icons = _icons_wire(self.icons)
        if icons:
            out["icons"] = icons
        out["_meta"] = {
            f"{META_PREFIX}category": self.category,
            f"{META_PREFIX}sensitivity": self.sensitivity.value,
            **({f"{META_PREFIX}tags": sorted(self.tags)} if self.tags else {}),
            **self.meta,
        }
        return out


@dataclass
class ToolSpec(_BaseSpec):
    """A callable tool.

    ``handler(ctx, **arguments)`` may be sync or async. ``input_schema`` is
    derived from the handler signature (see :mod:`cloudg.mcp.schema`) when
    not given. The handler returns any JSON-serialisable value, a pydantic
    model, or a :class:`ToolResult`; the layer normalises it.
    """

    input_schema: dict[str, Any] | None = None
    output_schema: dict[str, Any] | None = None
    annotations: ToolAnnotations = field(default_factory=ToolAnnotations)
    # Transform profile overrides for this tool (see cloudg.mcp.transforms.policy)
    transform_hints: dict[str, Any] = field(default_factory=dict)
    timeout_seconds: float | None = None

    def __post_init__(self) -> None:
        super().__post_init__()
        if not _NAME_RE.match(self.name):
            raise ValueError(f"Invalid tool name {self.name!r}")
        if self.annotations.title is None and self.title:
            self.annotations.title = self.title
        self._derive_hints()
        if self.input_schema is None:
            from cloudg.mcp.schema import input_schema_for

            self.input_schema = input_schema_for(self.handler)

    def _derive_hints(self) -> None:
        """Fill unset behaviour hints from the declared capabilities.

        Clients treat a missing hint pessimistically (destructive,
        open-world), which makes them prompt for every read-only lookup.
        """
        caps = self.capabilities
        writes = caps & {Capability.WRITE_STATE, Capability.WRITE_FS, Capability.EXEC}
        ann = self.annotations
        if ann.read_only is None:
            ann.read_only = not writes
        if ann.destructive is None:
            ann.destructive = False
        # Tools that call cloud APIs or spawn processes reach outside the
        # loaded data: open-world, and never idempotent by default (two
        # collections a minute apart can differ), so caching and retry
        # middleware leave them alone.
        external = bool(caps & {Capability.CLOUD_ACCESS, Capability.EXEC})
        if ann.open_world is None:
            ann.open_world = external
        if ann.idempotent is None and ann.read_only and not external:
            ann.idempotent = True

    def to_wire(
        self, name: str | None = None, *, include_output_schema: bool = True
    ) -> dict[str, Any]:
        exposed = name or self.name
        if not _NAME_RE.match(exposed):
            raise ValueError(f"Invalid exposed tool name {exposed!r}")
        out: dict[str, Any] = {
            "name": exposed,
            "description": self.description,
            "inputSchema": self.input_schema,
        }
        if self.output_schema and include_output_schema:
            out["outputSchema"] = self.output_schema
        ann = self.annotations.to_wire()
        if ann:
            out["annotations"] = ann
        return self._common_wire(out)


@dataclass
class ResourceSpec(_BaseSpec):
    """A static resource at a fixed URI. ``handler(ctx)`` returns ``str``,
    ``bytes``, a JSON-serialisable value, or a list of ResourceContents."""

    uri: str = ""
    mime_type: str = "application/json"
    annotations: ContentAnnotations | None = None
    size: int | None = None

    def to_wire(self) -> dict[str, Any]:
        out: dict[str, Any] = {"uri": self.uri, "name": self.name, "mimeType": self.mime_type}
        if self.description:
            out["description"] = self.description
        if self.size is not None:
            out["size"] = self.size
        if self.annotations:
            ann = self.annotations.to_wire()
            if ann:
                out["annotations"] = ann
        return self._common_wire(out)


@dataclass
class ResourceTemplateSpec(_BaseSpec):
    """A parameterised resource (RFC 6570 level-1 ``{var}`` templates).

    ``handler(ctx, **variables)`` receives the URI variables. ``completions``
    maps a variable name to ``fn(ctx, partial) -> list[str]`` for
    ``completion/complete``.
    """

    uri_template: str = ""
    mime_type: str = "application/json"
    annotations: ContentAnnotations | None = None
    completions: dict[str, Callable[..., Any]] = field(default_factory=dict)

    def __post_init__(self) -> None:
        super().__post_init__()
        self._regex = _template_regex(self.uri_template)

    @property
    def variables(self) -> list[str]:
        return re.findall(r"{\+?([A-Za-z0-9_]+)\*?}", self.uri_template)

    def match(self, uri: str) -> dict[str, str] | None:
        m = self._regex.match(uri)
        if not m:
            return None
        from urllib.parse import unquote

        return {k: unquote(v) for k, v in m.groupdict().items()}

    def expand(self, **values: str) -> str:
        from urllib.parse import quote

        out = self.uri_template
        for k, v in values.items():
            multi = quote(str(v), safe="/:@!$&'()*+,;=")
            out = (
                out.replace("{+" + k + "}", multi)
                .replace("{" + k + "*}", multi)
                .replace("{" + k + "}", quote(str(v), safe=""))
            )
        return out

    def canonical(self, values: dict[str, str]) -> str:
        """The URI with decoded ``values`` filled in verbatim (no
        percent-encoding): ``cloudg://graph/%64%33`` and ``cloudg://graph/d3``
        share one canonical form, which is what access policies match."""
        out = self.uri_template
        for k, v in values.items():
            for form in ("{+" + k + "}", "{" + k + "*}", "{" + k + "}"):
                out = out.replace(form, str(v))
        return out

    def to_wire(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "uriTemplate": self.uri_template,
            "name": self.name,
            "mimeType": self.mime_type,
        }
        if self.description:
            out["description"] = self.description
        if self.annotations:
            ann = self.annotations.to_wire()
            if ann:
                out["annotations"] = ann
        return self._common_wire(out)


def _template_regex(template: str) -> re.Pattern[str]:
    parts = re.split(r"({\+?[A-Za-z0-9_]+\*?})", template)
    rx = ""
    for part in parts:
        m = re.fullmatch(r"{(\+?)([A-Za-z0-9_]+)(\*?)}", part)
        if m:
            # {+var} (RFC 6570 reserved expansion) and the legacy {var*} may
            # span path segments; {var} stops at "/" and "?"
            multi = bool(m.group(1) or m.group(3))
            rx += f"(?P<{m.group(2)}>.+)" if multi else f"(?P<{m.group(2)}>[^/?]+)"
        else:
            rx += re.escape(part)
    return re.compile("^" + rx + "$")


@dataclass
class PromptArgument:
    name: str
    description: str = ""
    required: bool = False
    completion: Callable[..., Any] | None = None
    title: str | None = None

    def to_wire(self) -> dict[str, Any]:
        out: dict[str, Any] = {"name": self.name, "required": self.required}
        if self.title:
            out["title"] = self.title
        if self.description:
            out["description"] = self.description
        return out


@dataclass
class PromptSpec(_BaseSpec):
    """A prompt template. ``handler(ctx, **arguments)`` returns a
    :class:`PromptResult`, a list of PromptMessage, or a plain string (sent
    as one user message)."""

    arguments: list[PromptArgument] = field(default_factory=list)
    # Prompts usually embed workspace summaries
    sensitivity: Sensitivity = Sensitivity.INTERNAL

    def to_wire(self, name: str | None = None) -> dict[str, Any]:
        exposed = name or self.name
        if not _NAME_RE.match(exposed):
            raise ValueError(f"Invalid exposed prompt name {exposed!r}")
        out: dict[str, Any] = {
            "name": exposed,
            "description": self.description,
            "arguments": [a.to_wire() for a in self.arguments],
        }
        return self._common_wire(out)


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------


#: Keyword options of :meth:`Registry.resource` / :meth:`Registry.resource_template`
#: and their defaults.
_RESOURCE_OPTIONS: dict[str, Any] = {
    "name": None,
    "title": None,
    "description": None,
    "mime_type": "application/json",
    "category": "general",
    "tags": (),
    "sensitivity": Sensitivity.CONFIDENTIAL,
    "annotations": None,
    "capabilities": (Capability.READ_STATE,),
    "icons": None,
}


class Registry:
    """Collection of tool / resource / prompt specs.

    Catalog modules expose ``register(registry)`` functions; users can build
    their own registry, merge registries, or register extra primitives with
    the decorators::

        reg = Registry()

        @reg.tool(category="custom", read_only=True)
        def my_tool(ctx, asset_id: str) -> dict: ...
    """

    def __init__(self) -> None:
        self.tools: dict[str, ToolSpec] = {}
        self.resources: dict[str, ResourceSpec] = {}
        self.templates: dict[str, ResourceTemplateSpec] = {}
        self.prompts: dict[str, PromptSpec] = {}

    # -- adding ---------------------------------------------------------

    def add(self, spec: _BaseSpec, *, replace: bool = False) -> _BaseSpec:
        if isinstance(spec, ToolSpec):
            table: dict[str, Any] = self.tools
            key = spec.name
        elif isinstance(spec, ResourceSpec):
            table, key = self.resources, spec.uri
        elif isinstance(spec, ResourceTemplateSpec):
            table, key = self.templates, spec.uri_template
        elif isinstance(spec, PromptSpec):
            table, key = self.prompts, spec.name
        else:  # pragma: no cover (defensive)
            raise TypeError(f"Unsupported spec {type(spec).__name__}")
        if key in table and not replace:
            raise ValueError(f"Duplicate {type(spec).__name__} {key!r}")
        table[key] = spec
        return spec

    def merge(self, other: "Registry", *, replace: bool = False) -> "Registry":
        for spec in [
            *other.tools.values(),
            *other.resources.values(),
            *other.templates.values(),
            *other.prompts.values(),
        ]:
            self.add(spec, replace=replace)
        return self

    def tool(
        self,
        name: str | None = None,
        *,
        title: str | None = None,
        description: str | None = None,
        category: str = "general",
        tags: Iterable[str] = (),
        sensitivity: Sensitivity = Sensitivity.CONFIDENTIAL,
        capabilities: Iterable[Capability] = (Capability.READ_STATE,),
        read_only: bool | None = None,
        destructive: bool | None = None,
        idempotent: bool | None = None,
        open_world: bool | None = None,
        output_schema: dict[str, Any] | None = None,
        transform_hints: dict[str, Any] | None = None,
        timeout_seconds: float | None = None,
        icons: list[Icon] | None = None,
    ) -> Callable[[Handler], Handler]:
        def deco(fn: Handler) -> Handler:
            self.add(
                ToolSpec(
                    name=name or fn.__name__,
                    handler=fn,
                    title=title,
                    description=description or "",
                    category=category,
                    tags=set(tags),
                    sensitivity=sensitivity,
                    capabilities=set(capabilities),
                    annotations=ToolAnnotations(
                        title=title,
                        read_only=read_only,
                        destructive=destructive,
                        idempotent=idempotent,
                        open_world=open_world,
                    ),
                    output_schema=output_schema,
                    transform_hints=dict(transform_hints or {}),
                    timeout_seconds=timeout_seconds,
                    icons=icons,
                )
            )
            return fn

        return deco

    def resource(self, uri: str, **options: Any) -> Callable[[Handler], Handler]:
        """Decorator registering a static :class:`ResourceSpec` at ``uri``.

        Keyword options (all optional): ``name``, ``title``, ``description``,
        ``mime_type`` (default ``application/json``), ``category``, ``tags``,
        ``sensitivity`` (default confidential), ``annotations``,
        ``capabilities`` and ``icons``.
        """
        return self._resource_decorator(ResourceSpec, {"uri": uri}, options)

    def resource_template(
        self,
        uri_template: str,
        *,
        completions: dict[str, Callable[..., Any]] | None = None,
        **options: Any,
    ) -> Callable[[Handler], Handler]:
        """Decorator registering a :class:`ResourceTemplateSpec`.

        Takes the same keyword options as :meth:`resource`, plus
        ``completions`` (variable name to ``fn(ctx, partial)``).
        """
        fixed = {"uri_template": uri_template, "completions": dict(completions or {})}
        return self._resource_decorator(ResourceTemplateSpec, fixed, options)

    def _resource_decorator(
        self, cls: type, fixed: dict[str, Any], options: dict[str, Any]
    ) -> Callable[[Handler], Handler]:
        unknown = sorted(set(options) - set(_RESOURCE_OPTIONS))
        if unknown:
            raise TypeError(f"Unexpected resource option(s): {', '.join(unknown)}")
        opts = {**_RESOURCE_OPTIONS, **options}

        def deco(fn: Handler) -> Handler:
            self.add(
                cls(
                    name=opts["name"] or fn.__name__,
                    handler=fn,
                    title=opts["title"],
                    description=opts["description"] or "",
                    mime_type=opts["mime_type"],
                    category=opts["category"],
                    tags=set(opts["tags"]),
                    sensitivity=opts["sensitivity"],
                    annotations=opts["annotations"],
                    capabilities=set(opts["capabilities"]),
                    icons=opts["icons"],
                    **fixed,
                )
            )
            return fn

        return deco

    def prompt(
        self,
        name: str | None = None,
        *,
        title: str | None = None,
        description: str | None = None,
        arguments: list[PromptArgument] | None = None,
        category: str = "general",
        tags: Iterable[str] = (),
        sensitivity: Sensitivity = Sensitivity.INTERNAL,
        icons: list[Icon] | None = None,
    ) -> Callable[[Handler], Handler]:
        def deco(fn: Handler) -> Handler:
            self.add(
                PromptSpec(
                    name=name or fn.__name__,
                    handler=fn,
                    title=title,
                    description=description or "",
                    arguments=list(arguments or []),
                    category=category,
                    tags=set(tags),
                    sensitivity=sensitivity,
                    icons=icons,
                )
            )
            return fn

        return deco

    # -- lookup ---------------------------------------------------------

    def find_template(self, uri: str) -> tuple[ResourceTemplateSpec, dict[str, str]] | None:
        # Longest template first, so the most specific pattern wins
        # (cloudg://assets/{+ref}/neighbors before cloudg://assets/{+ref})
        for spec in sorted(self.templates.values(), key=lambda s: -len(s.uri_template)):
            values = spec.match(uri)
            if values is not None:
                return spec, values
        return None

    def __len__(self) -> int:
        return len(self.tools) + len(self.resources) + len(self.templates) + len(self.prompts)


def render_json(value: Any) -> str:
    """How the layer renders structured data as text content and JSON
    resources. Size budgets (the projection transform) measure with the
    same function, so their numbers match what the client receives."""
    import json

    return json.dumps(value, indent=2, ensure_ascii=False, default=str)


async def maybe_await(value: Any) -> Any:
    """Await ``value`` if it is awaitable."""
    if inspect.isawaitable(value):
        return await value
    return value
