"""JSON-RPC 2.0 framing for the native MCP server.

Message classification, error objects and the protocol constants (versions,
error codes, reserved ``_meta`` keys) shared by the session engine and the
transports. Standard library only.
"""

from __future__ import annotations

import json
from typing import Any

__all__ = [
    "CACHEABLE_METHODS",
    "CLIENT_CAPABILITIES_META_KEY",
    "CLIENT_INFO_META_KEY",
    "HANDSHAKE_VERSIONS",
    "HEADER_MISMATCH",
    "INTERNAL_ERROR",
    "INVALID_PARAMS",
    "INVALID_REQUEST",
    "JSONRPCError",
    "LATEST_HANDSHAKE_VERSION",
    "LATEST_MODERN_VERSION",
    "LOG_LEVELS",
    "LOG_LEVEL_META_KEY",
    "METHOD_NOT_FOUND",
    "MODERN_VERSIONS",
    "PARSE_ERROR",
    "PROTOCOL_VERSION_META_KEY",
    "RESOURCE_NOT_FOUND",
    "SERVER_INFO_META_KEY",
    "SUBSCRIPTION_ID_META_KEY",
    "SUPPORTED_VERSIONS",
    "UNSUPPORTED_PROTOCOL_VERSION",
    "BATCH_VERSIONS",
    "dumps",
    "error_response",
    "is_notification",
    "is_request",
    "is_response",
    "result_response",
    "valid_id",
]

# -- protocol versions -------------------------------------------------------

#: Revisions negotiated through the ``initialize`` handshake, oldest first.
HANDSHAKE_VERSIONS: tuple[str, ...] = ("2024-11-05", "2025-03-26", "2025-06-18", "2025-11-25")
#: Stateless per-request-envelope revisions (no handshake, ``server/discover``).
MODERN_VERSIONS: tuple[str, ...] = ("2026-07-28",)
SUPPORTED_VERSIONS: tuple[str, ...] = (*HANDSHAKE_VERSIONS, *MODERN_VERSIONS)
LATEST_HANDSHAKE_VERSION = HANDSHAKE_VERSIONS[-1]
LATEST_MODERN_VERSION = MODERN_VERSIONS[-1]
#: Revisions whose transports allow JSON-RPC batches (removed in 2025-06-18).
BATCH_VERSIONS: frozenset[str] = frozenset({"2024-11-05", "2025-03-26"})
#: Version assumed for HTTP requests without ``MCP-Protocol-Version``.
DEFAULT_HTTP_VERSION = "2025-03-26"

# -- reserved _meta keys (2026-07-28 envelope) ---------------------------------

PROTOCOL_VERSION_META_KEY = "io.modelcontextprotocol/protocolVersion"
CLIENT_INFO_META_KEY = "io.modelcontextprotocol/clientInfo"
CLIENT_CAPABILITIES_META_KEY = "io.modelcontextprotocol/clientCapabilities"
LOG_LEVEL_META_KEY = "io.modelcontextprotocol/logLevel"
SERVER_INFO_META_KEY = "io.modelcontextprotocol/serverInfo"
SUBSCRIPTION_ID_META_KEY = "io.modelcontextprotocol/subscriptionId"

#: Results that carry ``ttlMs`` / ``cacheScope`` on the 2026-07-28 wire.
CACHEABLE_METHODS: frozenset[str] = frozenset(
    {
        "tools/list",
        "prompts/list",
        "resources/list",
        "resources/templates/list",
        "resources/read",
        "server/discover",
    }
)

# -- error codes ------------------------------------------------------------------

PARSE_ERROR = -32700
INVALID_REQUEST = -32600
METHOD_NOT_FOUND = -32601
INVALID_PARAMS = -32602
INTERNAL_ERROR = -32603
#: Resource not found on handshake-era versions (2026-07-28 uses INVALID_PARAMS).
RESOURCE_NOT_FOUND = -32002
HEADER_MISMATCH = -32020
UNSUPPORTED_PROTOCOL_VERSION = -32022

#: RFC 5424 severities in ascending order (``logging/setLevel``).
LOG_LEVELS: tuple[str, ...] = (
    "debug",
    "info",
    "notice",
    "warning",
    "error",
    "critical",
    "alert",
    "emergency",
)


class JSONRPCError(Exception):
    """Raise inside a method handler to answer with a JSON-RPC error."""

    def __init__(self, code: int, message: str, data: Any = None) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.data = data

    def to_error(self) -> dict[str, Any]:
        err: dict[str, Any] = {"code": self.code, "message": self.message}
        if self.data is not None:
            err["data"] = self.data
        return err


def valid_id(value: Any) -> bool:
    """MCP request ids are strings or integers (never null, never bool)."""
    return (isinstance(value, str) or isinstance(value, int)) and not isinstance(value, bool)


def is_request(msg: Any) -> bool:
    return isinstance(msg, dict) and "method" in msg and "id" in msg


def is_notification(msg: Any) -> bool:
    return isinstance(msg, dict) and "method" in msg and "id" not in msg


def is_response(msg: Any) -> bool:
    return isinstance(msg, dict) and "method" not in msg and ("result" in msg or "error" in msg)


def result_response(req_id: Any, result: dict[str, Any]) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": req_id, "result": result}


def error_response(req_id: Any, code: int, message: str, data: Any = None) -> dict[str, Any]:
    err: dict[str, Any] = {"code": code, "message": message}
    if data is not None:
        err["data"] = data
    return {"jsonrpc": "2.0", "id": req_id, "error": err}


def dumps(message: Any) -> str:
    """Compact single-line JSON (stdio framing forbids embedded newlines)."""
    return json.dumps(message, ensure_ascii=False, separators=(",", ":"), default=str)
