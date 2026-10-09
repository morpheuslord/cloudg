"""Mount the cloudg MCP layer into existing MCP servers.

One call adds every cloudg tool, resource, resource template, prompt and
completion to a server you already run::

    from mcp.server.mcpserver import MCPServer        # or FastMCP, Server, fastmcp.FastMCP
    from cloudg.mcp.layer import CloudGMCPLayer
    from cloudg.mcp.adapters import register_into

    server = MCPServer("my-platform")
    layer = CloudGMCPLayer(policy="standard")
    register_into(layer, server, prefix="cloudg_")

Supported servers (detected automatically):

=====================================  ==========================================
``mcp.server.mcpserver.MCPServer``     mcp 2.x (:mod:`.mcp_sdk` -> :mod:`.lowlevel`)
``mcp.server.fastmcp.FastMCP``         mcp 1.x (:mod:`.mcp_sdk` -> :mod:`.lowlevel`)
``mcp.server.lowlevel.Server``         mcp 1.x and 2.x (:mod:`.lowlevel`)
``fastmcp.FastMCP``                    standalone fastmcp 2.x / 3.x / 4.x (:mod:`.fastmcp`)
=====================================  ==========================================

Guarantees, whichever server: tools keep the layer's exact ``inputSchema``,
``outputSchema``, ``annotations``, ``title`` and ``_meta``;
``structuredContent`` and ``isError`` pass through; resource templates and
prompts get cloudg's completions; progress and log notifications reach the
client; the caller's :class:`~cloudg.mcp.context.Principal` is resolved per
request (pluggable ``principal_resolver``); ``layer.notify_change`` becomes
list-changed / resource-updated notifications; and every request goes
through ``layer.call_tool`` / ``read_resource`` / ``get_prompt`` /
``complete`` so policies, transforms and middleware apply.

Arguments of :func:`register_into`:

* ``layer``: the cloudg layer.
* ``server``: an MCP server object from the table above.
* ``prefix``: name prefix for tools and prompts, e.g. ``"cloudg_"`` to
  avoid collisions with the host's tools. It sets ``layer.prefix``: the
  prefix belongs to the layer, so it also applies to every other server
  this layer is (or was) mounted on. To expose the catalog under two
  prefixes, mount two layers.
* ``include``: subset of ``{"tools", "resources", "templates", "prompts",
  "completions", "logging", "subscriptions"}`` to register (default: all).
* ``principal_resolver``: ``fn(RequestInfo) -> Principal | None`` mapping
  request facts (HTTP headers, OAuth access token, transport) to the
  caller; defaults to
  :func:`~cloudg.mcp.native.auth.default_principal_resolver`.
* ``list_changed``: advertise ``listChanged`` on SDK servers so clients act
  on change notifications.

Without any MCP framework, :func:`export_definitions` gives the wire
definitions plus async handlers, and :func:`build_server` creates a ready
server object (SDK, fastmcp or the dependency-free native server).
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any, Iterable

from cloudg.mcp.adapters.export import (
    ExportedDefinitions,
    export_definitions,
    to_anthropic_tools,
    to_langchain_tools,
    to_openai_tools,
)
from cloudg.mcp.native.auth import PrincipalResolver, RequestInfo

if TYPE_CHECKING:  # pragma: no cover
    from cloudg.mcp.layer import CloudGMCPLayer

__all__ = [
    "ExportedDefinitions",
    "RequestInfo",
    "build_server",
    "detect_server_kind",
    "export_definitions",
    "register_into",
    "to_anthropic_tools",
    "to_langchain_tools",
    "to_openai_tools",
]

logger = logging.getLogger("cloudg.mcp.adapters")

BUILD_FLAVORS = ("auto", "sdk", "lowlevel", "mcpserver", "fastmcp", "native")


def detect_server_kind(server: Any) -> str:
    """Classify a server object: ``fastmcp`` (standalone package),
    ``sdk-highlevel`` (``MCPServer`` / SDK ``FastMCP``), ``lowlevel``
    (SDK ``Server``), ``native`` (:class:`~cloudg.mcp.native.NativeMCPServer`)."""
    from cloudg.mcp.adapters.fastmcp import is_fastmcp_server
    from cloudg.mcp.adapters.lowlevel import is_lowlevel_server
    from cloudg.mcp.adapters.mcp_sdk import is_sdk_highlevel_server
    from cloudg.mcp.native.protocol import NativeMCPServer

    if isinstance(server, NativeMCPServer):
        return "native"
    if is_fastmcp_server(server):
        return "fastmcp"
    if is_sdk_highlevel_server(server):
        return "sdk-highlevel"
    if is_lowlevel_server(server):
        return "lowlevel"
    # duck typing for subclasses / wrappers
    if hasattr(server, "add_request_handler") or hasattr(server, "request_handlers"):
        return "lowlevel"
    if hasattr(server, "_lowlevel_server") or hasattr(server, "_mcp_server"):
        return "sdk-highlevel"
    raise TypeError(
        f"Don't know how to register cloudg into {type(server).__module__}."
        f"{type(server).__name__}; supported: mcp MCPServer / FastMCP / lowlevel Server, "
        "fastmcp.FastMCP. Use export_definitions(layer) for custom servers."
    )


def _apply_prefix(layer: "CloudGMCPLayer", prefix: str | None) -> None:
    """Set ``layer.prefix`` for :func:`register_into`, warning when that
    replaces a different prefix already in use."""
    if prefix is None:
        return
    if layer.prefix and prefix != layer.prefix:
        logger.warning(
            "register_into(prefix=%r) replaces this layer's prefix %r on every server "
            "it is mounted on; use one layer per prefix",
            prefix,
            layer.prefix,
        )
    layer.set_prefix(prefix)


def _install(kind: str, layer: "CloudGMCPLayer", server: Any, **kwargs: Any) -> Any:
    """Run the adapter for a non-native server ``kind``; ``kwargs`` are
    ``include``, ``principal_resolver`` and ``list_changed``."""
    if kind == "fastmcp":
        from cloudg.mcp.adapters.fastmcp import install

        kwargs.pop("list_changed", None)
        return install(layer, server, **kwargs)
    if kind == "sdk-highlevel":
        from cloudg.mcp.adapters.mcp_sdk import install as install_sdk

        return install_sdk(layer, server, **kwargs)
    from cloudg.mcp.adapters.lowlevel import install as install_lowlevel

    return install_lowlevel(layer, server, **kwargs)


def register_into(
    layer: "CloudGMCPLayer",
    server: Any,
    *,
    prefix: str | None = None,
    include: Iterable[str] | None = None,
    principal_resolver: PrincipalResolver | None = None,
    list_changed: bool = True,
) -> Any:
    """Register the layer's primitives into ``server`` and return the binding.

    The arguments are described under "Arguments of register_into" in the
    module docstring.
    """
    _apply_prefix(layer, prefix)
    kind = detect_server_kind(server)
    if kind == "native":
        if server.layer is not layer:
            raise ValueError("A NativeMCPServer serves exactly one layer (its own)")
        return server
    return _install(
        kind,
        layer,
        server,
        include=include,
        principal_resolver=principal_resolver,
        list_changed=list_changed,
    )


def build_server(
    layer: "CloudGMCPLayer",
    flavor: str = "auto",
    *,
    name: str | None = None,
    principal_resolver: PrincipalResolver | None = None,
    include: Iterable[str] | None = None,
    **native_kwargs: Any,
) -> Any:
    """Create a ready-to-run server object exposing ``layer``.

    Flavors:
        ``auto``: SDK low-level ``Server`` if ``mcp`` is importable, else native.
        ``sdk`` / ``lowlevel``: ``mcp.server.lowlevel.Server``.
        ``mcpserver``: ``MCPServer`` (mcp 2.x) or ``FastMCP`` (mcp 1.x).
        ``fastmcp``: standalone ``fastmcp.FastMCP``.
        ``native``: :class:`~cloudg.mcp.native.NativeMCPServer` (stdlib only).

    The SDK / fastmcp objects carry the binding at ``server._cloudg_binding``.
    """
    if flavor not in BUILD_FLAVORS:
        raise ValueError(f"Unknown flavor {flavor!r}; choose from {BUILD_FLAVORS}")
    if flavor == "auto":
        from cloudg.mcp.native._shared import sdk_installed

        flavor = "lowlevel" if sdk_installed() else "native"
    if flavor == "native":
        from cloudg.mcp.native.protocol import NativeMCPServer

        return NativeMCPServer(layer, principal_resolver=principal_resolver, **native_kwargs)
    server = _new_server(layer, flavor, name)
    binding = register_into(layer, server, include=include, principal_resolver=principal_resolver)
    try:
        server._cloudg_binding = binding
    except (AttributeError, TypeError):  # pragma: no cover (slotted / frozen server classes)
        logger.debug("cannot attach the cloudg binding to %s", type(server).__name__)
    return server


def _new_server(layer: "CloudGMCPLayer", flavor: str, name: str | None) -> Any:
    """A fresh, empty SDK or fastmcp server object for ``build_server``."""
    if flavor in ("sdk", "lowlevel"):
        from cloudg.mcp.adapters.mcp_sdk import create_lowlevel_server

        return create_lowlevel_server(layer, name=name)
    if flavor == "mcpserver":
        from cloudg.mcp.adapters.mcp_sdk import create_highlevel_server

        return create_highlevel_server(layer, name=name)
    import fastmcp

    return fastmcp.FastMCP(name or layer.name, instructions=layer.instructions or None)
