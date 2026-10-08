"""Adapter for the official ``mcp`` SDK's high-level servers.

* mcp **2.x** ``MCPServer`` (``from mcp.server.mcpserver import MCPServer``,
  formerly FastMCP).
* mcp **1.x** ``FastMCP`` (``from mcp.server.fastmcp import FastMCP``).

Neither class has a public API for registering a tool with an explicit JSON
input schema; their decorators always derive schemas from function
signatures. Both are thin layers over a low-level ``Server``
(``MCPServer._lowlevel_server`` / ``FastMCP._mcp_server``), so cloudg binds
there with :mod:`cloudg.mcp.adapters.lowlevel`: the host's own decorated
tools keep working and cloudg's primitives are served with their exact wire
definitions. The inner attribute is private, so this path is checked against
mcp 1.x (1.30) and 2.x (2.3); :func:`install` raises a clear error if a
future SDK renames it.

Also provides constructors for fresh SDK servers used by
:func:`cloudg.mcp.adapters.build_server` and :mod:`cloudg.mcp.server`.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from cloudg.mcp.adapters._common import major_version
from cloudg.mcp.adapters.lowlevel import LowLevelBinding
from cloudg.mcp.adapters.lowlevel import install as install_lowlevel
from cloudg.mcp.native.auth import PrincipalResolver

if TYPE_CHECKING:  # pragma: no cover
    from cloudg.mcp.layer import CloudGMCPLayer

__all__ = [
    "create_highlevel_server",
    "create_lowlevel_server",
    "inner_lowlevel_server",
    "install",
    "is_sdk_highlevel_server",
    "sdk_major",
]


def sdk_major() -> int | None:
    """Major version of the installed ``mcp`` package (``None`` if absent)."""
    return major_version("mcp")


def is_sdk_highlevel_server(obj: Any) -> bool:
    module = type(obj).__module__
    return module.startswith("mcp.server.mcpserver") or module.startswith("mcp.server.fastmcp")


def inner_lowlevel_server(server: Any) -> Any:
    for attr in ("_lowlevel_server", "_mcp_server"):
        inner = getattr(server, attr, None)
        if inner is not None:
            return inner
    raise TypeError(
        f"Cannot find the low-level server inside {type(server).__name__}; this mcp SDK "
        "version is not supported by cloudg's adapter (tested with mcp 1.30 and 2.3). "
        "Build a low-level Server with cloudg.mcp.adapters.build_server(layer) instead."
    )


def install(
    layer: "CloudGMCPLayer",
    server: Any,
    *,
    include: Any = None,
    principal_resolver: PrincipalResolver | None = None,
    list_changed: bool = True,
) -> LowLevelBinding:
    """Bind ``layer`` into an SDK ``MCPServer`` (2.x) or ``FastMCP`` (1.x)."""
    return install_lowlevel(
        layer,
        inner_lowlevel_server(server),
        include=include,
        principal_resolver=principal_resolver,
        owner=server,
        list_changed=list_changed,
    )


def create_lowlevel_server(layer: "CloudGMCPLayer", *, name: str | None = None) -> Any:
    """A bare SDK low-level ``Server`` carrying the layer's identity."""
    from mcp.server.lowlevel import Server

    kwargs: dict[str, Any] = {"version": str(layer.version)}
    if layer.instructions:
        kwargs["instructions"] = layer.instructions
    try:
        return Server(name or layer.name, **kwargs)
    except TypeError:  # very old 1.x without instructions=
        kwargs.pop("instructions", None)
        return Server(name or layer.name, **kwargs)


def create_highlevel_server(layer: "CloudGMCPLayer", *, name: str | None = None) -> Any:
    """A fresh ``MCPServer`` (mcp 2.x) or ``FastMCP`` (mcp 1.x)."""
    if (sdk_major() or 0) >= 2:
        from mcp.server.mcpserver import MCPServer

        return MCPServer(name or layer.name, instructions=layer.instructions or None,
                         version=str(layer.version))
    from mcp.server.fastmcp import FastMCP

    return FastMCP(name or layer.name, instructions=layer.instructions or None)
