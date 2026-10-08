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
import json
import logging
import sys
from pathlib import Path
from typing import TYPE_CHECKING, Any, Iterable, Sequence

from cloudg.mcp.core import Capability, Registry
from cloudg.mcp.native.auth import PRINCIPAL_SCOPE_KEY, PrincipalResolver, TokenAuth

if TYPE_CHECKING:  # pragma: no cover
    from cloudg.mcp.layer import CloudGMCPLayer

logger = logging.getLogger("cloudg.mcp.server")

__all__ = [
    "FLAVORS",
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
    for other in (*registry.resources.values(), *registry.templates.values(),
                  *registry.prompts.values()):
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
        base = name or (target.parent.name if target.name == "inventory-map.json"
                        else target.stem) or "dataset"
        unique = ws.unique_name(base) if hasattr(ws, "unique_name") and not name else base
        ws.add(load_dataset_file(target.resolve(), unique))
    elif hasattr(ws, "load"):
        ws.load(str(target), name or None)
    else:  # pragma: no cover (stub workspace)
        raise RuntimeError("This workspace cannot load datasets")


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
    from cloudg.mcp.layer import CloudGMCPLayer
    from cloudg.mcp.middleware import (
        AuditLogMiddleware,
        CachingMiddleware,
        ConcurrencyLimitMiddleware,
        MetricsMiddleware,
        register_metrics_resource,
    )

    if config is None and config_path:
        from cloudg.config import load_config

        config = load_config(config_path)
    if registry is None:
        from cloudg.mcp.catalog import default_registry

        registry = default_registry()
    if read_only:
        registry = read_only_registry(registry)

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
    stack.extend(middleware)

    layer = CloudGMCPLayer(
        config,
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
        **layer_kwargs,
    )
    if cache_mw is not None:
        cache_mw.attach(layer)
    if metrics_mw is not None and "cloudg://metrics" not in layer.registry.resources:
        try:
            register_metrics_resource(layer, metrics_mw)
        except Exception:  # pragma: no cover (registry is shared / frozen)
            logger.debug("could not register cloudg://metrics", exc_info=True)
    for spec in datasets:
        _load_dataset(layer, spec)
    return layer


# ---------------------------------------------------------------------------
# Serving
# ---------------------------------------------------------------------------


def resolve_flavor(flavor: str = "auto") -> str:
    if flavor not in FLAVORS:
        raise ValueError(f"Unknown flavor {flavor!r}; choose from {FLAVORS}")
    if flavor != "auto":
        return flavor
    try:
        import mcp.server.lowlevel  # noqa: F401

        return "sdk"
    except ImportError:
        return "native"


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
        raise ValueError("--cors-origin is only supported by the native flavor "
                         "(use --flavor native)")
    if resolved == "fastmcp" and transport == "sse" and (json_response or stateless):
        raise ValueError("--json-response / --stateless apply to Streamable HTTP; the fastmcp "
                         "flavor cannot combine them with --transport sse")
    return resolved


def serve(layer: "CloudGMCPLayer", transport: str = "stdio", **kwargs: Any) -> None:
    """Blocking wrapper around :func:`serve_async` (Ctrl+C stops it)."""
    try:
        asyncio.run(serve_async(layer, transport, **kwargs))
    except KeyboardInterrupt:  # pragma: no cover (interactive)
        pass


async def serve_async(
    layer: "CloudGMCPLayer",
    transport: str = "stdio",
    *,
    flavor: str = "auto",
    host: str = "127.0.0.1",
    port: int = 8765,
    path: str = "/mcp",
    auth: TokenAuth | None = None,
    auth_tokens: Iterable[str] | None = None,
    allowed_origins: Sequence[str] | None = None,
    allowed_hosts: Sequence[str] | None = None,
    cors_origins: Sequence[str] = (),
    json_response: bool = False,
    stateless: bool = False,
    page_size: int = 100,
    principal_resolver: PrincipalResolver | None = None,
    log_level: str = "INFO",
    ready: "asyncio.Future[Any] | None" = None,
) -> None:
    """Serve ``layer`` until the transport closes (stdio EOF) or cancelled.

    Args:
        transport: ``stdio`` | ``http`` | ``streamable-http`` | ``sse``.
        flavor: ``auto`` | ``native`` | ``sdk`` | ``fastmcp``.
        host / port / path: HTTP bind address and endpoint.
        auth / auth_tokens: Bearer-token auth (``TokenAuth`` or
            ``["TOKEN:role,role[:id]", "env:VAR:role"]``).
        allowed_origins / allowed_hosts: DNS-rebinding allow-lists, enforced
            the same way by every flavor (see
            :class:`~cloudg.mcp.native.http.OriginHostGuard`). ``Origin`` is
            always validated: loopback origins and same-origin requests are
            accepted by default. ``Host`` is restricted to loopback names on a
            loopback bind; on any other bind it is only checked when
            ``allowed_hosts`` is given.
        cors_origins: Origins granted CORS (native flavor only; refused
            elsewhere).
        json_response: Answer POSTs with plain JSON instead of SSE.
        stateless: Session-less Streamable HTTP.
        page_size: List page size (native flavor).
        principal_resolver: Custom ``fn(RequestInfo) -> Principal``.
        ready: Future resolved with the bound ``(host, port)`` once an HTTP
            server listens (native flavor), for tests and embedding.
    """
    flavor = validate_serve_options(flavor, transport, cors_origins=cors_origins,
                                    json_response=json_response, stateless=stateless)
    _ensure_stderr_logging(log_level)
    token_auth = _token_auth(auth, auth_tokens)
    if transport == "stdio" and token_auth:
        logger.info("auth tokens are ignored on stdio (the local user launched the server)")

    try:
        await _dispatch_serve(layer, flavor, transport, host=host, port=port, path=path,
                              token_auth=token_auth, allowed_origins=allowed_origins,
                              allowed_hosts=allowed_hosts, cors_origins=cors_origins,
                              json_response=json_response, stateless=stateless,
                              page_size=page_size, principal_resolver=principal_resolver,
                              ready=ready, log_level=log_level)
    finally:
        # Persist pseudonyms issued during the session (policies with a vault
        # path); atexit covers interpreter exits that skip this
        save = getattr(layer.policy, "save_vault", None)
        if save is not None:
            try:
                saved = save()
                if saved:
                    logger.info("pseudonym vault saved to %s", saved)
            except Exception:
                logger.warning("could not save the pseudonym vault", exc_info=True)


async def _dispatch_serve(layer: "CloudGMCPLayer", flavor: str, transport: str, *, host: str,
                          port: int, path: str, token_auth: Any, allowed_origins: Any,
                          allowed_hosts: Any, cors_origins: Any, json_response: bool,
                          stateless: bool, page_size: Any, principal_resolver: Any,
                          ready: Any, log_level: Any) -> None:
    if flavor == "native":
        await _serve_native(layer, transport, host=host, port=port, path=path,
                            auth=token_auth, allowed_origins=allowed_origins,
                            allowed_hosts=allowed_hosts, cors_origins=cors_origins,
                            json_response=json_response, stateless=stateless,
                            page_size=page_size, principal_resolver=principal_resolver,
                            ready=ready)
    elif flavor == "sdk":
        await _serve_sdk(layer, transport, host=host, port=port, path=path, auth=token_auth,
                         allowed_origins=allowed_origins, allowed_hosts=allowed_hosts,
                         json_response=json_response, stateless=stateless,
                         principal_resolver=principal_resolver, log_level=log_level)
    else:
        await _serve_fastmcp(layer, transport, host=host, port=port, path=path, auth=token_auth,
                             allowed_origins=allowed_origins, allowed_hosts=allowed_hosts,
                             json_response=json_response, stateless=stateless,
                             principal_resolver=principal_resolver, log_level=log_level)


async def _serve_native(layer: "CloudGMCPLayer", transport: str, *, host: str, port: int,
                        path: str, auth: TokenAuth | None, allowed_origins: Any,
                        allowed_hosts: Any, cors_origins: Any, json_response: bool,
                        stateless: bool, page_size: int,
                        principal_resolver: PrincipalResolver | None,
                        ready: "asyncio.Future[Any] | None") -> None:
    from cloudg.mcp.native import HTTPConfig, NativeHTTPServer, NativeMCPServer, run_stdio_async

    server = NativeMCPServer(layer, page_size=page_size, principal_resolver=principal_resolver)
    if transport == "stdio":
        await run_stdio_async(server)
        return
    config = HTTPConfig(
        host=host, port=port, path=path, auth=auth,
        allowed_origins=list(allowed_origins) if allowed_origins is not None else None,
        allowed_hosts=list(allowed_hosts) if allowed_hosts is not None else None,
        cors_origins=list(cors_origins), json_response=json_response, stateless=stateless,
        enable_sse=transport == "sse",
    )
    http = NativeHTTPServer(server, config)
    bound = await http.start()
    print(f"cloudg MCP server (native, {transport}) listening on {http.url}", file=sys.stderr)
    if ready is not None and not ready.done():
        ready.set_result(bound)
    await http.serve_forever()


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
    """ASGI middleware for SDK / fastmcp HTTP apps: DNS-rebinding guard plus
    bearer-token auth.

    ``guard`` (an :class:`~cloudg.mcp.native.http.OriginHostGuard`) rejects
    bad ``Host`` (421) and ``Origin`` (403) headers exactly like the native
    server. With ``auth``, a missing or unknown bearer token gets 401; on
    success the principal is stored in ``scope["cloudg.principal"]`` and
    ``scope["state"]["cloudg.principal"]``, where the adapters' default
    principal resolution finds it. Lifespan and non-HTTP scopes pass through.
    """

    def __init__(self, app: Any, auth: TokenAuth | None, guard: Any = None) -> None:
        self.app = app
        self.auth = auth
        self.guard = guard

    @staticmethod
    async def _reject(send: Any, status: int, message: str,
                      extra: list[tuple[bytes, bytes]] | None = None) -> None:
        body = json.dumps({"jsonrpc": "2.0", "id": None,
                           "error": {"code": -32600, "message": message}}).encode()
        await send({"type": "http.response.start", "status": status, "headers": [
            (b"content-type", b"application/json"),
            (b"content-length", str(len(body)).encode()),
            *(extra or []),
        ]})
        await send({"type": "http.response.body", "body": body})

    async def __call__(self, scope: dict[str, Any], receive: Any, send: Any) -> None:
        if scope.get("type") != "http" or not (self.auth or self.guard):
            await self.app(scope, receive, send)
            return
        headers = {k.decode("latin-1").lower(): v.decode("latin-1")
                   for k, v in scope.get("headers", [])}
        if self.guard is not None:
            rejected = self.guard.check(headers.get("host"), headers.get("origin"))
            if rejected is not None:
                await self._reject(send, *rejected)
                return
        if not self.auth:
            await self.app(scope, receive, send)
            return
        principal = self.auth.authenticate(headers.get("authorization"))
        if principal is None and self.auth.required:
            await self._reject(send, 401, "Unauthorized",
                               [(b"www-authenticate", b'Bearer realm="cloudg-mcp"')])
            return
        if principal is not None:
            scope[PRINCIPAL_SCOPE_KEY] = principal
            scope.setdefault("state", {})[PRINCIPAL_SCOPE_KEY] = principal
        await self.app(scope, receive, send)


def _sdk_major() -> int:
    from cloudg.mcp.adapters._common import major_version

    return major_version("mcp") or 1


async def _serve_sdk(layer: "CloudGMCPLayer", transport: str, *, host: str, port: int,
                     path: str, auth: TokenAuth | None, allowed_origins: Any, allowed_hosts: Any,
                     json_response: bool, stateless: bool,
                     principal_resolver: PrincipalResolver | None, log_level: str) -> None:
    from cloudg.mcp.adapters import build_server

    server = build_server(layer, "lowlevel", principal_resolver=principal_resolver)
    major = _sdk_major()
    if transport == "stdio":
        from mcp.server.stdio import stdio_server

        if major >= 2:  # 2.x stdio_server() diverts fd 1 to stderr itself
            async with stdio_server() as (read, write):
                await server.run(read, write, server.create_initialization_options())
            return
        import io

        import anyio

        from cloudg.mcp.native.stdio import protected_stdout

        with protected_stdout() as proto_out:
            out = anyio.wrap_file(io.TextIOWrapper(proto_out, encoding="utf-8",
                                                   line_buffering=True))
            async with stdio_server(stdout=out) as (read, write):
                await server.run(read, write, server.create_initialization_options())
        return

    import uvicorn
    from starlette.applications import Starlette
    from starlette.routing import Mount, Route

    security = _security_settings()
    if major >= 2:
        app = server.streamable_http_app(
            streamable_http_path=path, json_response=json_response, stateless_http=stateless,
            transport_security=security, host=host,
        )
        lifespan_owner = None
    else:
        from mcp.server.streamable_http_manager import StreamableHTTPSessionManager

        manager = StreamableHTTPSessionManager(
            app=server, json_response=json_response, stateless=stateless,
            security_settings=security,
        )

        async def handle(scope: Any, receive: Any, send: Any) -> None:
            await manager.handle_request(scope, receive, send)

        lifespan_owner = manager
        app = None
    routes: list[Any] = []
    if transport == "sse":
        from mcp.server.sse import SseServerTransport

        sse = SseServerTransport("/messages/", security_settings=security)

        async def sse_endpoint(scope: Any, receive: Any, send: Any) -> None:
            async with sse.connect_sse(scope, receive, send) as (read, write):
                await server.run(read, write, server.create_initialization_options())

        routes += [Route("/sse", endpoint=_asgi_endpoint(sse_endpoint), methods=["GET"]),
                   Mount("/messages/", app=sse.handle_post_message)]
    if app is None:
        from contextlib import asynccontextmanager

        @asynccontextmanager
        async def lifespan(_: Any) -> Any:
            async with lifespan_owner.run():  # type: ignore[union-attr]
                yield

        app = Starlette(routes=[*routes, Route(path, endpoint=_asgi_endpoint(handle),
                                                methods=["GET", "POST", "DELETE"])],
                        lifespan=lifespan)
    elif routes:
        app.router.routes[:0] = routes
    asgi = TokenAuthASGIMiddleware(app, auth, _guard(host, allowed_origins, allowed_hosts))
    print(f"cloudg MCP server (mcp SDK {major}.x, {transport}) listening on "
          f"http://{host}:{port}{path}", file=sys.stderr)
    config = uvicorn.Config(asgi, host=host, port=port, log_level=log_level.lower(),
                            lifespan="on")
    await uvicorn.Server(config).serve()


def _asgi_endpoint(fn: Any) -> Any:
    """Wrap a raw ASGI callable so Starlette's ``Route`` treats it as an app
    (not a request/response function)."""

    class _App:
        async def __call__(self, scope: Any, receive: Any, send: Any) -> None:
            await fn(scope, receive, send)

    return _App()


# -- fastmcp flavor -------------------------------------------------------------


async def _serve_fastmcp(layer: "CloudGMCPLayer", transport: str, *, host: str, port: int,
                         path: str, auth: TokenAuth | None, allowed_origins: Any,
                         allowed_hosts: Any, json_response: bool, stateless: bool,
                         principal_resolver: PrincipalResolver | None, log_level: str) -> None:
    import inspect

    from cloudg.mcp.adapters import build_server

    server = build_server(layer, "fastmcp", principal_resolver=principal_resolver)
    if transport == "stdio":
        try:
            await server.run_async(transport="stdio", show_banner=False)
        except TypeError:  # older fastmcp without show_banner
            await server.run_async(transport="stdio")
        return
    import uvicorn

    kind = "sse" if transport == "sse" else "http"
    accepted = set(inspect.signature(server.http_app).parameters)
    kwargs: dict[str, Any] = {"transport": kind}
    if kind == "http":
        kwargs["path"] = path
        for name, value in (("json_response", json_response), ("stateless_http", stateless)):
            if value:
                if name not in accepted:  # pragma: no cover (all known fastmcp accept them)
                    raise ValueError(f"this fastmcp version cannot serve {name}")
                kwargs[name] = value
    if "host_origin_protection" in accepted:
        # the cloudg guard below enforces Host / Origin, identically to the
        # other flavors; fastmcp's own check would double-filter
        kwargs["host_origin_protection"] = False
    app = server.http_app(**kwargs)
    asgi = TokenAuthASGIMiddleware(app, auth, _guard(host, allowed_origins, allowed_hosts))
    print(f"cloudg MCP server (fastmcp, {transport}) listening on http://{host}:{port}{path}",
          file=sys.stderr)
    config = uvicorn.Config(asgi, host=host, port=port, log_level=log_level.lower(),
                            lifespan="on")
    await uvicorn.Server(config).serve()


def _guard(host: str, allowed_origins: Any, allowed_hosts: Any) -> Any:
    from cloudg.mcp.native.http import OriginHostGuard

    return OriginHostGuard(host, allowed_origins, allowed_hosts)
