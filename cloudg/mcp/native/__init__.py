"""Dependency-free MCP server for the cloudg layer.

Implements the Model Context Protocol (handshake revisions 2024-11-05 through
2025-11-25 and the stateless 2026-07-28 revision) with only the Python
standard library, so ``cloudg mcp serve`` works without the optional ``mcp``
SDK installed.

* :class:`NativeMCPServer` / :class:`Session`: the JSON-RPC protocol engine
  (:mod:`cloudg.mcp.native.protocol`).
* :func:`run_stdio_async`: stdio transport (:mod:`cloudg.mcp.native.stdio`).
* :class:`NativeHTTPServer` / :class:`HTTPConfig`: Streamable HTTP and the
  legacy HTTP+SSE transport (:mod:`cloudg.mcp.native.http`).
* :class:`TokenAuth` / :class:`RequestInfo`: caller identification
  (:mod:`cloudg.mcp.native.auth`).

Example::

    import asyncio
    from cloudg.mcp.layer import CloudGMCPLayer
    from cloudg.mcp.native import NativeMCPServer, run_stdio_async

    server = NativeMCPServer(CloudGMCPLayer(policy="standard"))
    asyncio.run(run_stdio_async(server))
"""

from cloudg.mcp.native.auth import (
    PrincipalResolver,
    RequestInfo,
    TokenAuth,
    default_principal_resolver,
    parse_token_spec,
)
from cloudg.mcp.native.http import HTTPConfig, NativeHTTPServer, run_http_async
from cloudg.mcp.native.jsonrpc import (
    HANDSHAKE_VERSIONS,
    LATEST_HANDSHAKE_VERSION,
    MODERN_VERSIONS,
    SUPPORTED_VERSIONS,
    JSONRPCError,
)
from cloudg.mcp.native.protocol import NativeMCPServer, Session
from cloudg.mcp.native.stdio import run_stdio_async

__all__ = [
    "HANDSHAKE_VERSIONS",
    "HTTPConfig",
    "JSONRPCError",
    "LATEST_HANDSHAKE_VERSION",
    "MODERN_VERSIONS",
    "NativeHTTPServer",
    "NativeMCPServer",
    "PrincipalResolver",
    "RequestInfo",
    "SUPPORTED_VERSIONS",
    "Session",
    "TokenAuth",
    "default_principal_resolver",
    "parse_token_spec",
    "run_http_async",
    "run_stdio_async",
]
