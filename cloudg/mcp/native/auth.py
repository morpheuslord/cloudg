"""Caller identification for the MCP transports.

Every MCP request is executed on behalf of a :class:`~cloudg.mcp.context.Principal`;
policies key visibility, access and data transforms off its ``roles``. This
module turns transport facts into a principal:

* :class:`TokenAuth`: static bearer tokens (``Authorization: Bearer <token>``)
  mapped to principals with roles. Tokens are compared by SHA-256 digest with
  :func:`hmac.compare_digest`, and only digests are kept in memory.
* :class:`RequestInfo`: what an adapter knows about one request (headers,
  transport, session id, an SDK access token...), handed to a pluggable
  *principal resolver* ``fn(info) -> Principal | None``.
* :func:`default_principal_resolver`: the resolver every adapter uses when
  none is supplied: an explicit principal stashed by an auth middleware wins,
  then an SDK ``AccessToken`` (client id + scopes as roles), then the local
  user for stdio, else an anonymous principal.

Only the standard library is used, so the native server stays dependency-free.
"""

from __future__ import annotations

import hashlib
import hmac
import os
from dataclasses import dataclass, field
from typing import Any, Callable, Iterable, Mapping

from cloudg.mcp.context import Principal

__all__ = [
    "PRINCIPAL_SCOPE_KEY",
    "PrincipalResolver",
    "RequestInfo",
    "TokenAuth",
    "anonymous_principal",
    "default_principal_resolver",
    "parse_token_spec",
]

#: Key under which an ASGI / HTTP auth layer stores the authenticated
#: principal (ASGI ``scope`` / Starlette ``request.state``).
PRINCIPAL_SCOPE_KEY = "cloudg.principal"


def anonymous_principal() -> Principal:
    """The principal used for unauthenticated network callers."""
    return Principal(id="anonymous", roles={"default"})


@dataclass
class RequestInfo:
    """Transport-level facts about one MCP request, for principal resolvers.

    Attributes:
        transport: ``stdio`` | ``http`` | ``sse`` | ``memory``.
        headers: HTTP headers, lower-cased names (empty for stdio).
        session_id: Transport session id, when the transport has sessions.
        client_info: The client's ``Implementation`` dict (name/version).
        access_token: An SDK ``AccessToken`` object when the hosting server
            validated an OAuth bearer token.
        principal: A principal already established by an auth middleware.
        raw: The framework's own request context object, for custom resolvers.
    """

    transport: str = "stdio"
    headers: Mapping[str, str] = field(default_factory=dict)
    session_id: str | None = None
    client_info: Mapping[str, Any] | None = None
    access_token: Any = None
    principal: Principal | None = None
    raw: Any = None

    def header(self, name: str, default: str | None = None) -> str | None:
        return self.headers.get(name.lower(), default)

    @property
    def bearer_token(self) -> str | None:
        value = self.header("authorization") or ""
        scheme, _, token = value.partition(" ")
        if scheme.lower() != "bearer" or not token.strip():
            return None
        return token.strip()


PrincipalResolver = Callable[[RequestInfo], "Principal | None"]


def default_principal_resolver(info: RequestInfo) -> Principal:
    """Resolve the caller with no configuration.

    Order: a principal set by an auth layer, an OAuth access token from the
    hosting SDK (``client_id`` becomes the id, scopes become roles), the local
    user for stdio / in-memory transports, otherwise anonymous.
    """
    if info.principal is not None:
        return info.principal
    token = info.access_token
    if token is not None:
        client_id = getattr(token, "client_id", None) or "oauth-client"
        scopes = set(getattr(token, "scopes", None) or ())
        return Principal(
            id=str(client_id),
            roles={"default", *scopes},
            attributes={"auth": "oauth", "scopes": sorted(scopes)},
        )
    if info.transport in ("stdio", "memory"):
        return Principal.local()
    return anonymous_principal()


def _digest(token: str) -> bytes:
    return hashlib.sha256(token.encode("utf-8")).digest()


def _token_id(token: str) -> str:
    return "token-" + hashlib.sha256(token.encode()).hexdigest()[:8]


def _roles(text: str) -> set[str]:
    """Comma-separated roles; every token principal also carries ``default``
    so policy rules written for the default role apply to it."""
    return {"default", *(r.strip() for r in text.split(",") if r.strip())}


def parse_token_spec(spec: str) -> tuple[str, Principal]:
    """Parse ``TOKEN[:ROLES[:ID]]`` into ``(token, principal)``.

    ``ROLES`` is a comma-separated list; the principal always gets the
    ``default`` role in addition. ``ID`` defaults to ``token-<hash prefix>``.

    The roles and id fields are taken from the right, so a token may contain
    colons. A token with a colon must use the full three-field form (the
    fields may be empty): ``abc:def::`` is token ``abc:def`` with only the
    default role, ``abc:def:analyst:`` adds ``analyst``.

    ``env:VARNAME[:ROLES[:ID]]`` reads the secret from the environment
    variable ``VARNAME`` (variable names cannot contain colons).

    Examples: ``s3cret:analyst``, ``env:CLOUDG_MCP_TOKEN:admin,analyst:ci-bot``.
    """
    if spec.startswith("env:"):
        var, _, tail = spec[4:].partition(":")
        token = os.environ.get(var, "") if var else ""
        if not token:
            raise ValueError(f"Environment variable {var!r} for an auth token is empty")
        fields = tail.split(":", 1) if tail else []
    else:
        parts = spec.rsplit(":", 2)
        token, fields = parts[0], parts[1:]
    if not token:
        raise ValueError("Empty auth token")
    roles = _roles(fields[0]) if fields else {"default"}
    pid = fields[1] if len(fields) > 1 and fields[1] else _token_id(token)
    return token, Principal(id=pid, roles=roles, attributes={"auth": "bearer"})


class TokenAuth:
    """Static bearer-token authentication.

    Args:
        tokens: ``{token: Principal | roles}``; roles may be a string
            (``"analyst,admin"``) or an iterable of role names. Principals
            built from roles always include the ``default`` role; a
            ``Principal`` given explicitly is used as is.
        required: When true (default) a request without a valid token is
            rejected; when false it falls back to the anonymous principal.
    """

    def __init__(
        self,
        tokens: Mapping[str, Principal | str | Iterable[str]] | None = None,
        *,
        required: bool = True,
    ) -> None:
        self._entries: list[tuple[bytes, Principal]] = []
        self.required = required
        for token, value in (tokens or {}).items():
            self.add(token, value)

    @classmethod
    def from_specs(cls, specs: Iterable[str], *, required: bool = True) -> "TokenAuth":
        auth = cls(required=required)
        for spec in specs:
            token, principal = parse_token_spec(spec)
            auth.add(token, principal)
        return auth

    def add(self, token: str, value: Principal | str | Iterable[str]) -> None:
        if not token:
            raise ValueError("Empty auth token")
        if isinstance(value, Principal):
            principal = value
        else:
            roles = _roles(value) if isinstance(value, str) else {"default", *value}
            principal = Principal(id=_token_id(token), roles=roles,
                                  attributes={"auth": "bearer"})
        self._entries.append((_digest(token), principal))

    def __bool__(self) -> bool:
        return bool(self._entries)

    def __len__(self) -> int:
        return len(self._entries)

    def lookup(self, token: str | None) -> Principal | None:
        """Return the principal for ``token`` or ``None``. Every entry is
        compared so timing does not reveal which token matched."""
        if not token:
            return None
        probe = _digest(token)
        found: Principal | None = None
        for digest, principal in self._entries:
            if hmac.compare_digest(digest, probe):
                found = principal
        if found is None:
            return None
        return Principal(id=found.id, roles=set(found.roles), attributes=dict(found.attributes))

    def authenticate(self, authorization_header: str | None) -> Principal | None:
        """Validate an ``Authorization`` header value."""
        return self.lookup(RequestInfo(headers={"authorization": authorization_header or ""})
                           .bearer_token)
