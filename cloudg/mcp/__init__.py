"""cloudg's MCP layer: expose cloudg's inventory, graph, findings,
compliance and ontology to AI agents over the Model Context Protocol.

Three ways to use it:

1. Run it as a server::

       cloudg mcp serve                      # stdio, for desktop clients
       cloudg mcp serve --transport http     # streamable HTTP on 127.0.0.1:8765

2. Mount every tool, resource and prompt into an MCP server you already
   have (official ``mcp`` SDK 1.x / 2.x, low-level ``Server``, or the
   standalone ``fastmcp`` package)::

       from cloudg.mcp import CloudGMCPLayer
       layer = CloudGMCPLayer(policy="strict", prefix="cloudg_")
       layer.register_into(my_server)

3. Call it in-process::

       result = await layer.call_tool("find_assets", {"internet_exposed": True})

Every request, whichever way it arrives, passes through the same policy:
access control, rate limits, redaction, pseudonymisation, projection and
annotation. See docs/MCP.md.

Importing this package pulls in nothing beyond cloudg's own dependencies;
the SDK adapters import ``mcp`` / ``fastmcp`` only when used.
"""

from __future__ import annotations

from cloudg.mcp.context import Principal, ToolContext
from cloudg.mcp.core import (
    AccessDeniedError,
    Capability,
    ContentAnnotations,
    EmbeddedResource,
    Icon,
    ImageContent,
    InvalidArgumentsError,
    MCPLayerError,
    NotFoundError,
    PromptArgument,
    PromptMessage,
    PromptResult,
    PromptSpec,
    RateLimitedError,
    Registry,
    ResourceLink,
    ResourceSpec,
    ResourceTemplateSpec,
    Sensitivity,
    TextContent,
    TextResourceContents,
    ToolAnnotations,
    ToolResult,
    ToolSpec,
)
from cloudg.mcp.layer import CallInfo, CloudGMCPLayer
from cloudg.mcp.policy import Policy, available_profiles
from cloudg.mcp.state import Dataset, Workspace
from cloudg.mcp.transforms import Pipeline, TokenVault, TransformContext, build_transform


def default_registry() -> Registry:
    """The full cloudg catalog (tools, resources, templates, prompts)."""
    from cloudg.mcp.catalog import default_registry as _default

    return _default()


def register_into(layer: CloudGMCPLayer, server: object, **kwargs: object) -> object:
    """Mount ``layer`` into an existing MCP server object; see
    :func:`cloudg.mcp.adapters.register_into`."""
    from cloudg.mcp.adapters import register_into as _register

    return _register(layer, server, **kwargs)


def build_server(layer: CloudGMCPLayer, flavor: str = "auto") -> object:
    """A ready-to-run server object for ``layer``; see
    :func:`cloudg.mcp.adapters.build_server`."""
    from cloudg.mcp.adapters import build_server as _build

    return _build(layer, flavor=flavor)


def export_definitions(layer: CloudGMCPLayer, principal: Principal | None = None) -> object:
    """Framework-free wire definitions plus async handlers; see
    :func:`cloudg.mcp.adapters.export_definitions`."""
    from cloudg.mcp.adapters import export_definitions as _export

    return _export(layer, principal=principal)


__all__ = [
    "AccessDeniedError",
    "CallInfo",
    "Capability",
    "CloudGMCPLayer",
    "ContentAnnotations",
    "Dataset",
    "EmbeddedResource",
    "Icon",
    "ImageContent",
    "InvalidArgumentsError",
    "MCPLayerError",
    "NotFoundError",
    "Pipeline",
    "Policy",
    "Principal",
    "PromptArgument",
    "PromptMessage",
    "PromptResult",
    "PromptSpec",
    "RateLimitedError",
    "Registry",
    "ResourceLink",
    "ResourceSpec",
    "ResourceTemplateSpec",
    "Sensitivity",
    "TextContent",
    "TextResourceContents",
    "TokenVault",
    "ToolAnnotations",
    "ToolContext",
    "ToolResult",
    "ToolSpec",
    "TransformContext",
    "Workspace",
    "available_profiles",
    "build_server",
    "build_transform",
    "default_registry",
    "export_definitions",
    "register_into",
]
