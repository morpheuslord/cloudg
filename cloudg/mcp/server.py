"""Run the cloudg MCP layer as a standalone MCP server.

:func:`serve` (blocking) / :func:`serve_async` host a
:class:`~cloudg.mcp.layer.CloudGMCPLayer` over one of:

* ``stdio``: newline-delimited JSON-RPC on stdin/stdout (what desktop
  clients such as Claude Desktop / Claude Code / Cursor launch);
* ``http`` / ``streamable-http``: Streamable HTTP on ``/mcp``;
* ``sse``: Streamable HTTP plus the deprecated HTTP+SSE endpoints
  (``/sse`` + ``/messages/``) for old clients.

with one of these implementations (``flavor``):

* ``native``: the dependency-free server in :mod:`cloudg.mcp.native`;
* ``sdk``: the official ``mcp`` SDK's low-level server (1.x or 2.x) with
  uvicorn for HTTP;
* ``fastmcp``: the standalone ``fastmcp`` package;
* ``auto``: ``sdk`` when ``mcp`` is importable, otherwise ``native``.

Whatever the flavor: HTTP binds ``127.0.0.1`` by default, validates
``Origin`` / ``Host`` against loopback (DNS-rebinding protection), and
optional static bearer tokens (``auth_tokens=["TOKEN:role1,role2", ...]``)
map callers to principals with roles for the policy.

:func:`create_layer_from_options` builds a layer from CLI-style options
(policy, preloaded datasets, category filters, read-only mode, audit log,
metrics) and is what ``cloudg mcp serve`` uses.
"""

from __future__ import annotations

import asyncio
import dataclasses
import json
import logging
import sys
from collections import OrderedDict
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any, Iterable, Sequence

from cloudg.mcp.core import Capability, Registry
from cloudg.mcp.native.auth import PRINCIPAL_SCOPE_KEY, PrincipalResolver, TokenAuth

if TYPE_CHECKING:  # pragma: no cover
    from cloudg.mcp.layer import CloudGMCPLayer

logger = logging.getLogger("cloudg.mcp.server")

__all__ = [
    "FLAVORS",
    "ServeOptions",
    "TRANSPORTS",
    "TokenAuthASGIMiddleware",
    "create_layer_from_options",
    "read_only_registry",
    "resolve_flavor",
    "serve",
    "validate_serve_options",
    "serve_async",
]

TRANSPORTS = ("stdio", "http", "streamable-http", "sse")
FLAVORS = ("auto", "native", "sdk", "fastmcp")
#: Capabilities a read-only deployment drops (in-memory workspace changes,
#: such as loading a dataset, stay allowed).
READ_ONLY_DENIED = frozenset({Capability.WRITE_FS, Capability.CLOUD_ACCESS, Capability.EXEC})


# ---------------------------------------------------------------------------
# Layer construction (CLI options)
# ---------------------------------------------------------------------------


def read_only_registry(registry: Registry) -> Registry:
    """Copy ``registry`` without tools that write files, call cloud APIs,
    run processes, or are marked destructive."""
    out = Registry()
    for spec in registry.tools.values():
        if spec.capabilities & READ_ONLY_DENIED or spec.annotations.destructive:
            continue
        out.add(spec)
    for other in (
        *registry.resources.values(),
        *registry.templates.values(),
        *registry.prompts.values(),
    ):
        out.add(other)
    return out


def _load_dataset(layer: "CloudGMCPLayer", spec: str) -> None:
    name, sep, path = spec.partition("=")
    if not sep:
        name, path = "", spec
    target = Path(path).expanduser()
    if not target.exists():
        raise FileNotFoundError(f"Dataset not found: {target}")
    ws = layer.workspace
    try:
        from cloudg.mcp.state import load_dataset_file  # type: ignore[attr-defined]
    except ImportError:
        load_dataset_file = None
    if load_dataset_file is not None and hasattr(ws, "add"):
        # Operator-supplied path: load it even if it lies outside the
        # workspace's allowed roots (those restrict what *tools* may open).
        base = (
            name
            or (target.parent.name if target.name == "inventory-map.json" else target.stem)
            or "dataset"
        )
        unique = ws.unique_name(base) if hasattr(ws, "unique_name") and not name else base
        ws.add(load_dataset_file(target.resolve(), unique))
    elif hasattr(ws, "load"):
        ws.load(str(target), name or None)
    else:  # pragma: no cover (stub workspace)
        raise RuntimeError("This workspace cannot load datasets")


def _resolve_config(config: Any, config_path: str | None) -> Any:
    if config is None and config_path:
        from cloudg.config import load_config

        return load_config(config_path)
    return config


def _middleware_stack(
    audit_log: str | Path | None,
    metrics: bool,
    max_concurrency: int | None,
    cache_ttl: float | None,
    extra: Sequence[Any],
) -> tuple[list[Any], Any, Any]:
    """``(stack, metrics middleware, cache middleware)`` for the CLI options."""
    from cloudg.mcp.middleware import (
        AuditLogMiddleware,
        CachingMiddleware,
        ConcurrencyLimitMiddleware,
        MetricsMiddleware,
    )

    stack: list[Any] = []
    if audit_log:
        stack.append(AuditLogMiddleware(audit_log))
    metrics_mw = MetricsMiddleware() if metrics else None
    if metrics_mw is not None:
        stack.append(metrics_mw)
    if max_concurrency:
        stack.append(ConcurrencyLimitMiddleware(max_concurrency))
    cache_mw = CachingMiddleware(ttl=cache_ttl) if cache_ttl else None
    if cache_mw is not None:
        stack.append(cache_mw)
    stack.extend(extra)
    return stack, metrics_mw, cache_mw


def _attach_middleware(layer: "CloudGMCPLayer", metrics_mw: Any, cache_mw: Any) -> None:
    from cloudg.mcp.middleware import register_metrics_resource

    if cache_mw is not None:
        cache_mw.attach(layer)
    if metrics_mw is not None and "cloudg://metrics" not in layer.registry.resources:
        try:
            register_metrics_resource(layer, metrics_mw)
        except Exception:  # pragma: no cover (registry is shared / frozen)
            logger.debug("could not register cloudg://metrics", exc_info=True)


def create_layer_from_options(
    *,
    config: Any = None,
    config_path: str | None = None,
    policy: Any = None,
    datasets: Iterable[str] = (),
    prefix: str = "",
    include_categories: Iterable[str] | None = None,
    exclude_categories: Iterable[str] | None = None,
    include_tools: Iterable[str] | None = None,
    exclude_tools: Iterable[str] | None = None,
    read_only: bool = False,
    audit_log: str | Path | None = None,
    metrics: bool = True,
    cache_ttl: float | None = None,
    max_concurrency: int | None = None,
    registry: Registry | None = None,
    middleware: Sequence[Any] = (),
    default_timeout: float | None = 300.0,
    workspace: Any = None,
    **layer_kwargs: Any,
) -> "CloudGMCPLayer":
    """Build a :class:`CloudGMCPLayer` from CLI-style options.

    Args:
        config / config_path: cloudg configuration (or a ``config.yaml`` path).
        policy: Policy object, profile name, file path or dict.
        datasets: Files to preload, ``PATH`` or ``NAME=PATH``.
        read_only: Drop tools that write files, call cloud APIs, run
            scanners or are destructive.
        audit_log: JSONL audit file (see :class:`~cloudg.mcp.middleware.AuditLogMiddleware`).
        metrics: Count calls and expose ``cloudg://metrics``.
        cache_ttl: Cache read-only idempotent tool results for N seconds.
        max_concurrency: Cap concurrent tool calls.
        middleware: Extra middleware (innermost).
    """
    from cloudg.mcp.layer import CloudGMCPLayer, LayerOptions

    if registry is None:
        from cloudg.mcp.catalog import default_registry

        registry = default_registry()
    if read_only:
        registry = read_only_registry(registry)
    stack, metrics_mw, cache_mw = _middleware_stack(
        audit_log, metrics, max_concurrency, cache_ttl, middleware
    )
    options = LayerOptions(
        workspace=workspace,
        policy=policy,
        registry=registry,
        include_categories=include_categories,
        exclude_categories=exclude_categories,
        include_tools=include_tools,
        exclude_tools=exclude_tools,
        prefix=prefix,
        middleware=stack,
        default_timeout=default_timeout,
    )
    layer = CloudGMCPLayer(_resolve_config(config, config_path), options=options, **layer_kwargs)
    _attach_middleware(layer, metrics_mw, cache_mw)
    for spec in datasets:
        _load_dataset(layer, spec)
    return layer


# ---------------------------------------------------------------------------
# Serving
# ---------------------------------------------------------------------------


@dataclass
class ServeOptions:
    """Every keyword argument of :func:`serve_async` / :func:`serve`.

    Attributes:
        flavor: ``auto`` | ``native`` | ``sdk`` | ``fastmcp``.
        host / port / path: HTTP bind address and endpoint.
        auth / auth_tokens: Bearer-token auth (``TokenAuth`` or
            ``["TOKEN:role,role[:id]", "env:VAR:role"]``).
        allowed_origins / allowed_hosts: DNS-rebinding allow-lists, enforced
            the same way by every flavor (see
            :class:`~cloudg.mcp.native.http.OriginHostGuard`).
        cors_origins: Origins granted CORS (native flavor only).
        json_response: Answer POSTs with plain JSON instead of SSE.
        stateless: Session-less Streamable HTTP.
        page_size: List page size (native flavor).
        principal_resolver: Custom ``fn(RequestInfo) -> Principal``.
        log_level: Level of the ``cloudg`` logger (stderr).
        ready: Future resolved with the bound ``(host, port)`` once an HTTP
            server listens (native flavor), for tests and embedding.
    """

    flavor: str = "auto"
    host: str = "127.0.0.1"
    port: int = 8765
    path: str = "/mcp"
    # secrets: kept out of repr() so logging the options cannot leak them
    auth: TokenAuth | None = field(default=None, repr=False)
    auth_tokens: Iterable[str] | None = field(default=None, repr=False)
    allowed_origins: Sequence[str] | None = None
    allowed_hosts: Sequence[str] | None = None
    cors_origins: Sequence[str] = ()
    json_response: bool = False
    stateless: bool = False
    page_size: int = 100
    principal_resolver: PrincipalResolver | None = None
    log_level: str = "INFO"
    ready: "asyncio.Future[Any] | None" = None

    @classmethod
    def build(cls, options: "ServeOptions | None", kwargs: dict[str, Any]) -> "ServeOptions":
        """``options`` updated with ``kwargs``; unknown keywords raise
        :class:`TypeError` like a regular signature would."""
        unknown = sorted(set(kwargs) - {f.name for f in dataclasses.fields(cls)})
        if unknown:
            raise TypeError(
                f"serve_async() got unexpected keyword argument(s): {', '.join(unknown)}"
            )
        return dataclasses.replace(options or cls(), **kwargs)


def resolve_flavor(flavor: str = "auto") -> str:
    if flavor not in FLAVORS:
        raise ValueError(f"Unknown flavor {flavor!r}; choose from {FLAVORS}")
    if flavor != "auto":
        return flavor
    from cloudg.mcp.native._shared import sdk_installed

    return "sdk" if sdk_installed() else "native"


_STDERR_HANDLER_FLAG = "_cloudg_mcp_stderr"


def _ensure_stderr_logging(level: str | int = "INFO") -> None:
    """Set the level of the ``cloudg`` logger and, only when no handler is
    configured anywhere (root or ``cloudg``), give ``cloudg`` a stderr handler.

    Root logging and handlers owned by the host application are left alone.
    On stdio the protocol stays safe regardless: the native and SDK stdio
    transports redirect file descriptor 1 to stderr while serving, so even a
    handler bound to ``sys.stdout`` cannot reach the protocol stream.
    """
    cloudg_logger = logging.getLogger("cloudg")
    if isinstance(level, str):
        level = logging.getLevelName(level.upper())
    cloudg_logger.setLevel(level)
    has_ours = any(getattr(h, _STDERR_HANDLER_FLAG, False) for h in cloudg_logger.handlers)
    if not has_ours and not logging.getLogger().handlers and not cloudg_logger.handlers:
        handler = logging.StreamHandler(sys.stderr)
        handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s"))
        setattr(handler, _STDERR_HANDLER_FLAG, True)
        cloudg_logger.addHandler(handler)


def _token_auth(auth: TokenAuth | None, auth_tokens: Iterable[str] | None) -> TokenAuth | None:
    if auth is not None:
        return auth
    tokens = list(auth_tokens or ())
    return TokenAuth.from_specs(tokens) if tokens else None


def validate_serve_options(
    flavor: str,
    transport: str,
    *,
    cors_origins: Sequence[str] = (),
    json_response: bool = False,
    stateless: bool = False,
) -> str:
    """Resolve ``flavor`` and refuse option combinations a flavor cannot
    honour, instead of silently ignoring them. Returns the resolved flavor.

    Raises:
        ValueError: with a message naming the option and the alternatives.
    """
    if transport not in TRANSPORTS:
        raise ValueError(f"Unknown transport {transport!r}; choose from {TRANSPORTS}")
    resolved = resolve_flavor(flavor)
    if transport == "stdio":
        return resolved
    if cors_origins and resolved != "native":
        raise ValueError(
            "--cors-origin is only supported by the native flavor (use --flavor native)"
        )
    if resolved == "fastmcp" and transport == "sse" and (json_response or stateless):
        raise ValueError(
            "--json-response / --stateless apply to Streamable HTTP; the fastmcp "
            "flavor cannot combine them with --transport sse"
        )
    return resolved


def serve(layer: "CloudGMCPLayer", transport: str = "stdio", **kwargs: Any) -> None:
    """Blocking wrapper around :func:`serve_async` (Ctrl+C stops it)."""
    try:
        asyncio.run(serve_async(layer, transport, **kwargs))
    except KeyboardInterrupt:  # pragma: no cover (interactive)
        logger.info("MCP server stopped (interrupted)")


async def serve_async(
    layer: "CloudGMCPLayer",
    transport: str = "stdio",
    *,
    options: ServeOptions | None = None,
    **kwargs: Any,
) -> None:
    """Serve ``layer`` until the transport closes (stdio EOF) or cancelled.

    ``transport`` is ``stdio`` | ``http`` | ``streamable-http`` | ``sse``.
    The other settings are the fields of :class:`ServeOptions`, passed as
    ``options=`` or as keywords (``flavor``, ``host``, ``port``, ``path``,
    ``auth``, ``auth_tokens``, ``allowed_origins``, ``allowed_hosts``,
    ``cors_origins``, ``json_response``, ``stateless``, ``page_size``,
    ``principal_resolver``, ``log_level``, ``ready``).

    ``Origin`` is always validated: loopback origins are accepted by default,
    and same-origin requests when the ``Host`` header is validated. ``Host``
    is restricted to loopback names on a loopback bind; on any other bind it
    is only checked when ``allowed_hosts`` is given.
    """
    opts = ServeOptions.build(options, kwargs)
    flavor = validate_serve_options(
        opts.flavor,
        transport,
        cors_origins=opts.cors_origins,
        json_response=opts.json_response,
        stateless=opts.stateless,
    )
    _ensure_stderr_logging(opts.log_level)
    opts = dataclasses.replace(opts, flavor=flavor, auth=_token_auth(opts.auth, opts.auth_tokens))
    if transport == "stdio" and opts.auth:
        logger.info("auth tokens are ignored on stdio (the local user launched the server)")
    serve_fn = {"native": _serve_native, "sdk": _serve_sdk}.get(flavor, _serve_fastmcp)
    try:
        await serve_fn(layer, transport, opts)
    finally:
        _save_vault(layer)


def _save_vault(layer: "CloudGMCPLayer") -> None:
    """Persist pseudonyms issued during the session (policies with a vault
    path); atexit covers interpreter exits that skip this."""
    save = getattr(layer.policy, "save_vault", None)
    if save is None:
        return
    try:
        saved = save()
        if saved:
            logger.info("pseudonym vault saved to %s", saved)
    except Exception:
        logger.warning("could not save the pseudonym vault", exc_info=True)


async def _serve_native(layer: "CloudGMCPLayer", transport: str, opts: ServeOptions) -> None:
    from cloudg.mcp.native import HTTPConfig, NativeHTTPServer, NativeMCPServer, run_stdio_async

    server = NativeMCPServer(
        layer, page_size=opts.page_size, principal_resolver=opts.principal_resolver
    )
    if transport == "stdio":
        await run_stdio_async(server)
        return
    config = HTTPConfig(
        host=opts.host,
        port=opts.port,
        path=opts.path,
        auth=opts.auth,
        allowed_origins=_listed(opts.allowed_origins),
        allowed_hosts=_listed(opts.allowed_hosts),
        cors_origins=list(opts.cors_origins),
        json_response=opts.json_response,
        stateless=opts.stateless,
        enable_sse=transport == "sse",
    )
    http = NativeHTTPServer(server, config)
    bound = await http.start()
    print(f"cloudg MCP server (native, {transport}) listening on {http.url}", file=sys.stderr)
    if opts.ready is not None and not opts.ready.done():
        opts.ready.set_result(bound)
    await http.serve_forever()


def _listed(values: Sequence[str] | None) -> list[str] | None:
    return list(values) if values is not None else None


# -- SDK flavor ---------------------------------------------------------------


def _security_settings() -> Any:
    """SDK transport-security settings with its DNS-rebinding check turned off.

    The SDK can only check Host and Origin together, so on a non-loopback
    bind it would have to drop the Origin check as well. cloudg instead runs
    its own :class:`~cloudg.mcp.native.http.OriginHostGuard` in front of the
    SDK app (same rules as the native server), so the SDK check is redundant.
    """
    try:
        from mcp.server.transport_security import TransportSecuritySettings
    except ImportError:  # mcp < 1.10
        return None
    return TransportSecuritySettings(enable_dns_rebinding_protection=False)


class TokenAuthASGIMiddleware:
    """ASGI middleware for SDK / fastmcp HTTP apps: DNS-rebinding guard,
    bearer-token auth and session binding.

    ``guard`` (an :class:`~cloudg.mcp.native.http.OriginHostGuard`) rejects
    bad ``Host`` (421) and ``Origin`` (403) headers exactly like the native
    server. With ``auth``, a missing or unknown bearer token gets 401; on
    success the principal is stored in ``scope["cloudg.principal"]`` and
    ``scope["state"]["cloudg.principal"]``, where the adapters' default
    principal resolution finds it. Lifespan and non-HTTP scopes pass through.

    Session binding: the ``Mcp-Session-Id`` the app issues is remembered
    with the authenticated principal's id (the last ``max_bound_sessions``
    ids), and a request presenting that id as another principal gets 404,
    as on the native server. Ids issued over the legacy HTTP+SSE transport
    travel in the event stream, not a header, so they are not bound here.
    """

    def __init__(
        self,
        app: Any,
        auth: TokenAuth | None,
        guard: Any = None,
        *,
        max_bound_sessions: int = 10000,
    ) -> None:
        self.app = app
        self.auth = auth
        self.guard = guard
        self.max_bound_sessions = max_bound_sessions
        self._owners: OrderedDict[str, str] = OrderedDict()

    @staticmethod
    async def _reject(
        send: Any, status: int, message: str, extra: list[tuple[bytes, bytes]] | None = None
    ) -> None:
        body = json.dumps(
            {"jsonrpc": "2.0", "id": None, "error": {"code": -32600, "message": message}}
        ).encode()
        headers = [
            (b"content-type", b"application/json"),
            (b"content-length", str(len(body)).encode()),
            *(extra or []),
        ]
        await send({"type": "http.response.start", "status": status, "headers": headers})
        await send({"type": "http.response.body", "body": body})

    def _bind_send(self, send: Any, owner: str) -> Any:
        """``send`` that records the session id a response issues."""

        async def recording_send(message: dict[str, Any]) -> None:
            if message.get("type") == "http.response.start":
                for key, value in message.get("headers") or ():
                    if bytes(key).lower() == b"mcp-session-id":
                        self._owners[bytes(value).decode("latin-1")] = owner
                        while len(self._owners) > self.max_bound_sessions:
                            self._owners.popitem(last=False)
            await send(message)

        return recording_send

    async def __call__(self, scope: dict[str, Any], receive: Any, send: Any) -> None:
        if scope.get("type") != "http" or not (self.auth or self.guard):
            await self.app(scope, receive, send)
            return
        headers = {
            k.decode("latin-1").lower(): v.decode("latin-1") for k, v in scope.get("headers", [])
        }
        if self.guard is not None:
            rejected = self.guard.check(headers.get("host"), headers.get("origin"))
            if rejected is not None:
                await self._reject(send, *rejected)
                return
        principal = self.auth.authenticate(headers.get("authorization")) if self.auth else None
        if principal is None and self.auth and self.auth.required:
            challenge = [(b"www-authenticate", b'Bearer realm="cloudg-mcp"')]
            await self._reject(send, 401, "Unauthorized", challenge)
            return
        if principal is not None:
            scope[PRINCIPAL_SCOPE_KEY] = principal
            scope.setdefault("state", {})[PRINCIPAL_SCOPE_KEY] = principal
        owner = principal.id if principal is not None else ""
        sid = headers.get("mcp-session-id")
        if sid and self._owners.get(sid, owner) != owner:
            await self._reject(send, 404, "Session not found")
            return
        await self.app(scope, receive, self._bind_send(send, owner))


def _sdk_major() -> int:
    from cloudg.mcp.adapters._common import major_version

    return major_version("mcp") or 1


async def _sdk_stdio(server: Any, major: int) -> None:
    from mcp.server.stdio import stdio_server

    if major >= 2:  # 2.x stdio_server() diverts fd 1 to stderr itself
        async with stdio_server() as (read, write):
            await server.run(read, write, server.create_initialization_options())
        return
    import io

    import anyio

    from cloudg.mcp.native.stdio import protected_stdout

    with protected_stdout() as proto_out:
        text = io.TextIOWrapper(proto_out, encoding="utf-8", line_buffering=True)
        async with stdio_server(stdout=anyio.wrap_file(text)) as (read, write):
            await server.run(read, write, server.create_initialization_options())


def _sdk_v1_app(server: Any, opts: ServeOptions, security: Any, routes: list[Any]) -> Any:
    """Starlette app hosting an mcp 1.x Streamable HTTP session manager."""
    from contextlib import asynccontextmanager

    from mcp.server.streamable_http_manager import StreamableHTTPSessionManager
    from starlette.applications import Starlette
    from starlette.routing import Route

    manager = StreamableHTTPSessionManager(
        app=server,
        json_response=opts.json_response,
        stateless=opts.stateless,
        security_settings=security,
    )

    async def handle(scope: Any, receive: Any, send: Any) -> None:
        await manager.handle_request(scope, receive, send)

    @asynccontextmanager
    async def lifespan(_: Any) -> Any:
        async with manager.run():
            yield

    endpoint = Route(opts.path, endpoint=_asgi_endpoint(handle), methods=["GET", "POST", "DELETE"])
    return Starlette(routes=[*routes, endpoint], lifespan=lifespan)


def _sse_routes(server: Any, security: Any) -> list[Any]:
    """The deprecated HTTP+SSE endpoints (``/sse`` + ``/messages/``)."""
    from mcp.server.sse import SseServerTransport
    from starlette.routing import Mount, Route

    sse = SseServerTransport("/messages/", security_settings=security)

    async def sse_endpoint(scope: Any, receive: Any, send: Any) -> None:
        async with sse.connect_sse(scope, receive, send) as (read, write):
            await server.run(read, write, server.create_initialization_options())

    return [
        Route("/sse", endpoint=_asgi_endpoint(sse_endpoint), methods=["GET"]),
        Mount("/messages/", app=sse.handle_post_message),
    ]


async def _serve_sdk(layer: "CloudGMCPLayer", transport: str, opts: ServeOptions) -> None:
    from cloudg.mcp.adapters import build_server

    server = build_server(layer, "lowlevel", principal_resolver=opts.principal_resolver)
    major = _sdk_major()
    if transport == "stdio":
        await _sdk_stdio(server, major)
        return
    security = _security_settings()
    routes = _sse_routes(server, security) if transport == "sse" else []
    if major >= 2:
        app = server.streamable_http_app(
            streamable_http_path=opts.path,
            json_response=opts.json_response,
            stateless_http=opts.stateless,
            transport_security=security,
            host=opts.host,
        )
        app.router.routes[:0] = routes
    else:
        app = _sdk_v1_app(server, opts, security, routes)
    print(
        f"cloudg MCP server (mcp SDK {major}.x, {transport}) listening on "
        f"http://{opts.host}:{opts.port}{opts.path}",
        file=sys.stderr,
    )
    await _run_uvicorn(app, opts)


async def _run_uvicorn(app: Any, opts: ServeOptions) -> None:
    """Serve an SDK / fastmcp ASGI app behind the cloudg guard and auth."""
    import uvicorn

    guard = _guard(opts.host, opts.allowed_origins, opts.allowed_hosts)
    asgi = TokenAuthASGIMiddleware(app, opts.auth, guard)
    config = uvicorn.Config(
        asgi, host=opts.host, port=opts.port, log_level=opts.log_level.lower(), lifespan="on"
    )
    await uvicorn.Server(config).serve()


def _asgi_endpoint(fn: Any) -> Any:
    """Wrap a raw ASGI callable so Starlette's ``Route`` treats it as an app
    (not a request/response function)."""

    class _App:
        async def __call__(self, scope: Any, receive: Any, send: Any) -> None:
            await fn(scope, receive, send)

    return _App()


# -- fastmcp flavor -------------------------------------------------------------


def _fastmcp_http_kwargs(server: Any, transport: str, opts: ServeOptions) -> dict[str, Any]:
    import inspect

    kind = "sse" if transport == "sse" else "http"
    accepted = set(inspect.signature(server.http_app).parameters)
    kwargs: dict[str, Any] = {"transport": kind}
    if kind == "http":
        kwargs["path"] = opts.path
        for name, value in (
            ("json_response", opts.json_response),
            ("stateless_http", opts.stateless),
        ):
            if value:
                if name not in accepted:  # pragma: no cover (all known fastmcp accept them)
                    raise ValueError(f"this fastmcp version cannot serve {name}")
                kwargs[name] = value
    if "host_origin_protection" in accepted:
        # the cloudg guard enforces Host / Origin, identically to the other
        # flavors; fastmcp's own check would double-filter
        kwargs["host_origin_protection"] = False
    return kwargs


async def _serve_fastmcp(layer: "CloudGMCPLayer", transport: str, opts: ServeOptions) -> None:
    from cloudg.mcp.adapters import build_server

    server = build_server(layer, "fastmcp", principal_resolver=opts.principal_resolver)
    if transport == "stdio":
        try:
            await server.run_async(transport="stdio", show_banner=False)
        except TypeError:  # older fastmcp without show_banner
            await server.run_async(transport="stdio")
        return
    app = server.http_app(**_fastmcp_http_kwargs(server, transport, opts))
    print(
        f"cloudg MCP server (fastmcp, {transport}) listening on "
        f"http://{opts.host}:{opts.port}{opts.path}",
        file=sys.stderr,
    )
    await _run_uvicorn(app, opts)


def _guard(host: str, allowed_origins: Any, allowed_hosts: Any) -> Any:
    from cloudg.mcp.native.http import OriginHostGuard

    return OriginHostGuard(host, allowed_origins, allowed_hosts)
