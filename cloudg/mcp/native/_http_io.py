"""HTTP/1.1 plumbing for the native MCP server: request parsing with size
and time limits, response heads, the SSE writer, the 2026-07-28 header
checks and the DNS-rebinding guard (:class:`OriginHostGuard`, re-exported by
:mod:`cloudg.mcp.native.http`). Standard library only.
"""

from __future__ import annotations

import asyncio
import base64
import fnmatch
import ipaddress
import json
from dataclasses import dataclass
from typing import Any, Iterable
from urllib.parse import parse_qs, urlsplit

from cloudg.mcp.native.jsonrpc import (
    CLIENT_CAPABILITIES_META_KEY,
    HEADER_MISMATCH,
    INVALID_PARAMS,
    MODERN_VERSIONS,
    PROTOCOL_VERSION_META_KEY,
    UNSUPPORTED_PROTOCOL_VERSION,
    dumps,
)

__all__ = [
    "MAX_HEADER_BYTES",
    "OriginHostGuard",
    "SSEWriter",
    "HTTPError",
    "Request",
    "accepts",
    "head",
    "is_loopback",
    "jsonrpc_error_body",
    "match_any",
    "modern_rejection",
    "post_accepts",
    "read_request",
]

REASONS = {
    200: "OK",
    202: "Accepted",
    204: "No Content",
    400: "Bad Request",
    401: "Unauthorized",
    403: "Forbidden",
    404: "Not Found",
    405: "Method Not Allowed",
    406: "Not Acceptable",
    408: "Request Timeout",
    409: "Conflict",
    413: "Payload Too Large",
    415: "Unsupported Media Type",
    421: "Misdirected Request",
    431: "Request Header Fields Too Large",
    500: "Internal Server Error",
    503: "Service Unavailable",
}
_LOOPBACK_ORIGINS = [
    f"{scheme}://{host}{port}"
    for scheme in ("http", "https")
    for host in ("localhost", "127.0.0.1", "[::1]")
    for port in ("", ":*")
]
_LOOPBACK_HOSTS = ["localhost", "localhost:*", "127.0.0.1", "127.0.0.1:*", "[::1]", "[::1]:*"]
MAX_HEADER_BYTES = 64 * 1024
_NAME_BEARING = {"tools/call": "name", "prompts/get": "name", "resources/read": "uri"}


@dataclass
class Request:
    method: str
    target: str
    path: str
    query: dict[str, list[str]]
    version: str
    headers: dict[str, str]
    body: bytes

    @property
    def keep_alive(self) -> bool:
        conn = self.headers.get("connection", "").lower()
        if self.version == "HTTP/1.0":
            return "keep-alive" in conn
        return "close" not in conn


class HTTPError(Exception):
    def __init__(self, status: int, message: str, *, close: bool = True) -> None:
        super().__init__(message)
        self.status = status
        self.message = message
        self.close = close


def is_loopback(host: str) -> bool:
    if host in ("localhost", ""):
        return True
    try:
        return ipaddress.ip_address(host.strip("[]")).is_loopback
    except ValueError:
        return False


def accepts(headers: dict[str, str]) -> tuple[bool, bool]:
    """(accepts JSON, accepts SSE) from the Accept header."""
    accept = headers.get("accept", "")
    if not accept.strip():
        return True, True
    types = {part.split(";")[0].strip().lower() for part in accept.split(",")}
    any_type = "*/*" in types
    return (
        any_type or "application/json" in types or "application/*" in types,
        any_type or "text/event-stream" in types or "text/*" in types,
    )


def post_accepts(req: Request) -> tuple[bool, bool]:
    ctype = req.headers.get("content-type", "").split(";")[0].strip().lower()
    if ctype != "application/json":
        raise HTTPError(415, "Content-Type must be application/json", close=False)
    wants_json, wants_sse = accepts(req.headers)
    if not (wants_json or wants_sse):
        raise HTTPError(
            406, "Not Acceptable: accept application/json or text/event-stream", close=False
        )
    return wants_json, wants_sse


def match_any(value: str, patterns: Iterable[str]) -> bool:
    value = value.lower()
    return any(p == "*" or fnmatch.fnmatchcase(value, p.lower()) for p in patterns)


# ---------------------------------------------------------------------------
# Request parsing
# ---------------------------------------------------------------------------


def _parse_head(raw: bytes) -> tuple[str, str, str, dict[str, str]]:
    lines = raw.decode("latin-1").split("\r\n")
    try:
        method, target, version = lines[0].split(" ", 2)
    except ValueError:
        raise HTTPError(400, "Malformed request line") from None
    headers: dict[str, str] = {}
    for line in lines[1:]:
        if not line:
            continue
        name, sep, value = line.partition(":")
        if not sep:
            raise HTTPError(400, "Malformed header")
        key = name.strip().lower()
        headers[key] = f"{headers[key]}, {value.strip()}" if key in headers else value.strip()
    return method, target, version, headers


async def _read_chunked(reader: asyncio.StreamReader, limit: int) -> bytes:
    parts: list[bytes] = []
    size = 0
    while True:
        line = await reader.readline()
        n = int(line.split(b";")[0].strip() or b"0", 16)
        if n == 0:
            while (await reader.readline()) not in (b"\r\n", b"\n", b""):
                pass  # trailer fields are ignored
            return b"".join(parts)
        size += n
        if size > limit:  # checked before the chunk is read
            raise HTTPError(413, "Request body too large")
        parts.append(await reader.readexactly(n))
        await reader.readexactly(2)


async def _read_body(reader: asyncio.StreamReader, headers: dict[str, str], limit: int) -> bytes:
    if "chunked" in headers.get("transfer-encoding", "").lower():
        return await _read_chunked(reader, limit)
    if not headers.get("content-length"):
        return b""
    try:
        n = int(headers["content-length"])
    except ValueError:
        raise HTTPError(400, "Invalid Content-Length") from None
    if n < 0:
        raise HTTPError(400, "Invalid Content-Length")
    if n > limit:  # refused before any of the body is read
        raise HTTPError(413, "Request body too large")
    return await reader.readexactly(n)


async def read_request(
    reader: asyncio.StreamReader,
    *,
    max_body: int,
    header_timeout: float,
    body_timeout: float,
) -> Request | None:
    """Read one request; ``None`` on a clean end of stream. The head must
    arrive within ``header_timeout`` seconds (slow clients cannot hold a
    connection open indefinitely) and the body within ``body_timeout``."""
    try:
        raw = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), header_timeout)
    except asyncio.IncompleteReadError as exc:
        if not exc.partial.strip():
            return None
        raise
    except asyncio.LimitOverrunError:
        raise HTTPError(431, "Request headers too large") from None
    method, target, version, headers = _parse_head(raw)
    body = await asyncio.wait_for(_read_body(reader, headers, max_body), body_timeout)
    split = urlsplit(target)
    return Request(
        method=method.upper(),
        target=target,
        path=split.path or "/",
        query=parse_qs(split.query),
        version=version.strip().upper(),
        headers=headers,
        body=body,
    )


# ---------------------------------------------------------------------------
# 2026-07-28 header checks
# ---------------------------------------------------------------------------


def _decode_header_value(value: str | None) -> str | None:
    """Decode the ``=?base64?...?=`` form used for non-ASCII MCP header values."""
    if value is None:
        return None
    if value.startswith("=?base64?") and value.endswith("?="):
        try:
            return base64.b64decode(value[9:-2]).decode("utf-8")
        except (ValueError, UnicodeDecodeError):
            return value
    return value


def _header_mismatch(msg: dict[str, Any], headers: dict[str, str], version: Any) -> str | None:
    pv_header = headers.get("mcp-protocol-version")
    if pv_header is None or pv_header != version:
        return "MCP-Protocol-Version header does not match the request envelope's protocol version"
    if headers.get("mcp-method") != msg.get("method"):
        return "Mcp-Method header does not match the request body's method"
    params = msg.get("params") or {}
    name_key = _NAME_BEARING.get(str(msg.get("method")))
    if (
        name_key
        and params.get(name_key) is not None
        and _decode_header_value(headers.get("mcp-name")) != params.get(name_key)
    ):
        return f"Mcp-Name header does not match the request body's {name_key!r} parameter"
    return None


def modern_rejection(msg: dict[str, Any], headers: dict[str, str]) -> tuple[int, str, Any] | None:
    """Validate a 2026-07-28 request's envelope and MCP headers (HTTP 400 cases).

    Same ladder and codes as the official SDK, first failure wins:

    1. ``params._meta`` carries the protocol version and client capabilities,
       else ``-32602``.
    2. ``MCP-Protocol-Version`` equals the envelope version and ``Mcp-Method``
       equals the body's method (both headers are required), and for
       ``tools/call`` / ``prompts/get`` / ``resources/read`` ``Mcp-Name``
       equals the named parameter, else ``-32020`` (HeaderMismatch).
    3. The version is a supported string, else ``-32602`` (not a string) or
       ``-32022`` (UnsupportedProtocolVersion, with the supported list).
    """
    meta = (msg.get("params") or {}).get("_meta") or {}
    missing = [
        k for k in (PROTOCOL_VERSION_META_KEY, CLIENT_CAPABILITIES_META_KEY) if k not in meta
    ]
    if missing:
        text = f"params._meta is missing the required envelope key(s): {', '.join(missing)}"
        return INVALID_PARAMS, text, None
    version = meta.get(PROTOCOL_VERSION_META_KEY)
    mismatch = _header_mismatch(msg, headers, version)
    if mismatch:
        return HEADER_MISMATCH, mismatch, None
    if not isinstance(version, str):
        return INVALID_PARAMS, "the protocol-version envelope value must be a string", None
    if version not in MODERN_VERSIONS:
        data = {"supported": list(MODERN_VERSIONS), "requested": version}
        return UNSUPPORTED_PROTOCOL_VERSION, f"Unsupported protocol version: {version}", data
    return None


# ---------------------------------------------------------------------------
# DNS-rebinding guard
# ---------------------------------------------------------------------------


class OriginHostGuard:
    """DNS-rebinding protection shared by every HTTP flavor.

    * ``Host``: checked against ``allowed_hosts`` when given; on a loopback
      bind without ``allowed_hosts`` it must be a loopback name; on any other
      bind without ``allowed_hosts`` it is not checked (the server cannot know
      the names it is reached by). Rejected with ``421``.
    * ``Origin``: absent (non-browser client) is accepted. Otherwise it must
      match ``allowed_origins`` (default: loopback origins on any port), or
      be same-origin (its ``host:port`` equals the request's ``Host``) when
      the ``Host`` header itself was validated. On a non-loopback bind
      without ``allowed_hosts`` an attacker's rebound name controls both
      headers, so same-origin proves nothing there and is not accepted.
      Rejected with ``403``. This check is always on, whatever the bind.
    """

    def __init__(
        self,
        bind_host: str,
        allowed_origins: Iterable[str] | None = None,
        allowed_hosts: Iterable[str] | None = None,
        extra_origins: Iterable[str] = (),
    ) -> None:
        self.origins = (
            list(allowed_origins) if allowed_origins is not None else list(_LOOPBACK_ORIGINS)
        )
        self.origins.extend(extra_origins)
        if allowed_hosts is not None:
            self.hosts: list[str] | None = list(allowed_hosts)
        elif is_loopback(bind_host):
            self.hosts = list(_LOOPBACK_HOSTS)
        else:
            self.hosts = None

    def check(self, host: str | None, origin: str | None) -> tuple[int, str] | None:
        """``None`` when acceptable, else ``(status, message)``."""
        if self.hosts is not None and (host is None or not match_any(host, self.hosts)):
            return 421, "Invalid Host header"
        if origin and not match_any(origin, self.origins):
            same_origin = (
                self.hosts is not None
                and bool(host)
                and urlsplit(origin).netloc.lower() == (host or "").lower()
            )
            if not same_origin:
                return 403, "Forbidden: invalid Origin"
        return None


# ---------------------------------------------------------------------------
# Responses
# ---------------------------------------------------------------------------


def head(status: int, headers: dict[str, str]) -> bytes:
    lines = [f"HTTP/1.1 {status} {REASONS.get(status, 'Status')}", "Server: cloudg-mcp"]
    lines.extend(f"{k}: {v}" for k, v in headers.items())
    return ("\r\n".join(lines) + "\r\n\r\n").encode("latin-1")


def jsonrpc_error_body(code: int, message: str, data: Any = None, req_id: Any = None) -> bytes:
    err: dict[str, Any] = {"code": code, "message": message}
    if data is not None:
        err["data"] = data
    return json.dumps({"jsonrpc": "2.0", "id": req_id, "error": err}).encode()


class SSEWriter:
    """Chunked ``text/event-stream`` response writer."""

    def __init__(self, writer: asyncio.StreamWriter) -> None:
        self.writer = writer
        self.started = False

    async def start(self, headers: dict[str, str]) -> None:
        base = {
            "Content-Type": "text/event-stream",
            "Cache-Control": "no-cache, no-transform",
            "Transfer-Encoding": "chunked",
            "X-Accel-Buffering": "no",
            **headers,
        }
        self.writer.write(head(200, base))
        await self.writer.drain()
        self.started = True

    async def _chunk(self, data: bytes) -> None:
        self.writer.write(b"%x\r\n%s\r\n" % (len(data), data))
        await self.writer.drain()

    async def event(self, data: str, event: str | None = None) -> None:
        lines = []
        if event:
            lines.append(f"event: {event}")
        lines.extend(f"data: {line}" for line in data.split("\n"))
        await self._chunk(("\n".join(lines) + "\n\n").encode("utf-8"))

    async def message(self, msg: Any) -> None:
        await self.event(dumps(msg), "message")

    async def comment(self, text: str = "keepalive") -> None:
        await self._chunk(f": {text}\n\n".encode())

    async def end(self) -> None:
        self.writer.write(b"0\r\n\r\n")
        await self.writer.drain()
