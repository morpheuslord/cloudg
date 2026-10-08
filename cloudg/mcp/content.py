"""MCP content blocks, annotations and results for the cloudg MCP layer.

Plain dataclasses that know nothing about any MCP server implementation.
Their ``to_wire()`` methods produce the MCP specification's camelCase
shapes. Everything here is re-exported by :mod:`cloudg.mcp.core`, which is
the documented import path.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal

__all__ = [
    "BlobResourceContents",
    "Content",
    "ContentAnnotations",
    "EmbeddedResource",
    "Icon",
    "ImageContent",
    "PromptMessage",
    "PromptResult",
    "ResourceContents",
    "ResourceLink",
    "Role",
    "TextContent",
    "TextResourceContents",
    "ToolAnnotations",
    "ToolResult",
]

Role = Literal["user", "assistant"]


# ---------------------------------------------------------------------------
# Annotations
# ---------------------------------------------------------------------------


@dataclass
class ToolAnnotations:
    """MCP tool behaviour hints (spec ``ToolAnnotations``)."""

    title: str | None = None
    read_only: bool | None = None
    destructive: bool | None = None
    idempotent: bool | None = None
    open_world: bool | None = None

    def to_wire(self) -> dict[str, Any]:
        out: dict[str, Any] = {}
        if self.title is not None:
            out["title"] = self.title
        if self.read_only is not None:
            out["readOnlyHint"] = self.read_only
        if self.destructive is not None:
            out["destructiveHint"] = self.destructive
        if self.idempotent is not None:
            out["idempotentHint"] = self.idempotent
        if self.open_world is not None:
            out["openWorldHint"] = self.open_world
        return out


@dataclass
class ContentAnnotations:
    """MCP content / resource annotations (spec ``Annotations``)."""

    audience: list[Role] | None = None
    priority: float | None = None  # 0.0 (optional) .. 1.0 (required)
    last_modified: str | None = None  # ISO 8601

    def to_wire(self) -> dict[str, Any]:
        out: dict[str, Any] = {}
        if self.audience is not None:
            out["audience"] = list(self.audience)
        if self.priority is not None:
            out["priority"] = max(0.0, min(1.0, float(self.priority)))
        if self.last_modified is not None:
            out["lastModified"] = self.last_modified
        return out


@dataclass
class Icon:
    """An icon for a tool, resource, prompt or the server (MCP 2025-11-25).
    Prefer ``data:`` URIs so clients need not fetch anything."""

    src: str
    mime_type: str | None = None
    sizes: list[str] | None = None  # e.g. ["48x48"]
    theme: Literal["light", "dark"] | None = None

    def to_wire(self) -> dict[str, Any]:
        out: dict[str, Any] = {"src": self.src}
        if self.mime_type:
            out["mimeType"] = self.mime_type
        if self.sizes:
            out["sizes"] = list(self.sizes)
        if self.theme:
            out["theme"] = self.theme
        return out


def _icons_wire(icons: list[Icon] | None) -> list[dict[str, Any]] | None:
    return [i.to_wire() for i in icons] if icons else None


# ---------------------------------------------------------------------------
# Content and results
# ---------------------------------------------------------------------------


@dataclass
class TextContent:
    text: str
    annotations: ContentAnnotations | None = None
    meta: dict[str, Any] | None = None

    def to_wire(self) -> dict[str, Any]:
        out: dict[str, Any] = {"type": "text", "text": self.text}
        _add_common(out, self.annotations, self.meta)
        return out


@dataclass
class ImageContent:
    data: str  # base64
    mime_type: str
    annotations: ContentAnnotations | None = None
    meta: dict[str, Any] | None = None

    def to_wire(self) -> dict[str, Any]:
        out: dict[str, Any] = {"type": "image", "data": self.data, "mimeType": self.mime_type}
        _add_common(out, self.annotations, self.meta)
        return out


@dataclass
class ResourceLink:
    """A pointer to a resource the client may read (spec ``ResourceLink``)."""

    uri: str
    name: str
    title: str | None = None
    description: str | None = None
    mime_type: str | None = None
    size: int | None = None
    annotations: ContentAnnotations | None = None
    meta: dict[str, Any] | None = None

    def to_wire(self) -> dict[str, Any]:
        out: dict[str, Any] = {"type": "resource_link", "uri": self.uri, "name": self.name}
        if self.title:
            out["title"] = self.title
        if self.description:
            out["description"] = self.description
        if self.mime_type:
            out["mimeType"] = self.mime_type
        if self.size is not None:
            out["size"] = self.size
        _add_common(out, self.annotations, self.meta)
        return out


@dataclass
class TextResourceContents:
    uri: str
    text: str
    mime_type: str | None = "application/json"
    meta: dict[str, Any] | None = None

    def to_wire(self) -> dict[str, Any]:
        out: dict[str, Any] = {"uri": self.uri, "text": self.text}
        if self.mime_type:
            out["mimeType"] = self.mime_type
        if self.meta:
            out["_meta"] = self.meta
        return out


@dataclass
class BlobResourceContents:
    uri: str
    blob: str  # base64
    mime_type: str | None = None
    meta: dict[str, Any] | None = None

    def to_wire(self) -> dict[str, Any]:
        out: dict[str, Any] = {"uri": self.uri, "blob": self.blob}
        if self.mime_type:
            out["mimeType"] = self.mime_type
        if self.meta:
            out["_meta"] = self.meta
        return out


ResourceContents = TextResourceContents | BlobResourceContents


@dataclass
class EmbeddedResource:
    resource: ResourceContents
    annotations: ContentAnnotations | None = None
    meta: dict[str, Any] | None = None

    def to_wire(self) -> dict[str, Any]:
        out: dict[str, Any] = {"type": "resource", "resource": self.resource.to_wire()}
        _add_common(out, self.annotations, self.meta)
        return out


Content = TextContent | ImageContent | ResourceLink | EmbeddedResource


def _add_common(
    out: dict[str, Any], annotations: ContentAnnotations | None, meta: dict[str, Any] | None
) -> None:
    if annotations is not None:
        wire = annotations.to_wire()
        if wire:
            out["annotations"] = wire
    if meta:
        out["_meta"] = meta


@dataclass
class ToolResult:
    """Framework-agnostic ``CallToolResult``.

    ``structured`` is the JSON object returned as ``structuredContent``; the
    layer also renders it into ``content`` as text so clients without
    structured-output support still see it.
    """

    content: list[Content] = field(default_factory=list)
    structured: dict[str, Any] | None = None
    is_error: bool = False
    meta: dict[str, Any] = field(default_factory=dict)

    def to_wire(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "content": [c.to_wire() for c in self.content],
            "isError": self.is_error,
        }
        if self.structured is not None:
            out["structuredContent"] = self.structured
        if self.meta:
            out["_meta"] = self.meta
        return out

    @classmethod
    def error(cls, message: str, **meta: Any) -> "ToolResult":
        return cls(content=[TextContent(message)], is_error=True, meta=dict(meta))


@dataclass
class PromptMessage:
    role: Role
    content: Content

    def to_wire(self) -> dict[str, Any]:
        return {"role": self.role, "content": self.content.to_wire()}


@dataclass
class PromptResult:
    messages: list[PromptMessage]
    description: str | None = None

    def to_wire(self) -> dict[str, Any]:
        out: dict[str, Any] = {"messages": [m.to_wire() for m in self.messages]}
        if self.description:
            out["description"] = self.description
        return out
