"""Command-line front end (``cloudg mcp``) for the cloudg MCP layer.

Commands::

    cloudg mcp serve      run an MCP server (stdio / streamable HTTP / SSE)
    cloudg mcp tools      list tools (category, sensitivity, annotations)
    cloudg mcp resources  list resources and resource templates
    cloudg mcp prompts    list prompts
    cloudg mcp call       call a tool in-process and print its result
    cloudg mcp read       read a resource in-process
    cloudg mcp config     print a client configuration snippet

The group is registered on the main ``cloudg`` CLI and also exposed as a
stand-alone entry point (``cloudg-mcp = "cloudg.mcp.cli:main"``) and as
``python -m cloudg.mcp``.

stdout discipline: ``serve --transport stdio`` writes nothing but protocol
messages to stdout, and every other command writes only its result there
(tables or ``--json``), so output can be piped. Logs and notices go to
stderr.
"""

from __future__ import annotations

import asyncio
import json
import logging
import shlex
import shutil
import sys
from pathlib import Path
from typing import Any, Callable

import click

from cloudg.mcp.context import Principal

__all__ = ["main", "mcp_group"]

CLIENTS = ("claude-desktop", "claude-code", "cursor", "vscode")


# ---------------------------------------------------------------------------
# Shared options
# ---------------------------------------------------------------------------


def _layer_options(fn: Callable[..., Any]) -> Callable[..., Any]:
    """Options that shape the layer (shared by every command)."""
    options = [
        click.option("-c", "--config", "config_path", default=None,
                     help="cloudg config.yaml (defaults to the parent command's config)."),
        click.option("--policy", default=None, envvar="CLOUDG_MCP_POLICY", show_envvar=True,
                     help="Policy profile name, or a YAML/JSON policy file."),
        click.option("--dataset", "datasets", multiple=True, metavar="[NAME=]PATH",
                     help="Preload a dataset (findings.json, inventory-map.json...). Repeatable."),
        click.option("--prefix", default="", help="Prefix for tool and prompt names."),
        click.option("--include-category", "include_categories", multiple=True,
                     help="Only expose these categories. Repeatable."),
        click.option("--exclude-category", "exclude_categories", multiple=True,
                     help="Hide these categories. Repeatable."),
        click.option("--include-tool", "include_tools", multiple=True,
                     help="Only expose these tools. Repeatable."),
        click.option("--exclude-tool", "exclude_tools", multiple=True,
                     help="Hide these tools. Repeatable."),
        click.option("--read-only", is_flag=True,
                     help="Drop tools that write files, call cloud APIs, run scanners or are "
                          "destructive."),
        click.option("--audit-log", type=click.Path(dir_okay=False), default=None,
                     envvar="CLOUDG_MCP_AUDIT_LOG", show_envvar=True,
                     help="Append a JSONL audit trail (argument values are hashed)."),
        click.option("--timeout", type=float, default=300.0, show_default=True,
                     help="Per-call timeout in seconds."),
        click.option("--registry", "registry_ref", default=None, metavar="MODULE:ATTR",
                     help="Serve a custom Registry (or a zero-argument factory returning one) "
                          "instead of the built-in catalog."),
    ]
    for option in reversed(options):
        fn = option(fn)
    return fn


def _parent_config(ctx: click.Context) -> Any:
    root = ctx.find_root()
    obj = getattr(root, "obj", None)
    try:
        from cloudg.config import CloudGConfig

        return obj if isinstance(obj, CloudGConfig) else None
    except Exception:  # pragma: no cover
        return None


def _load_registry(ref: str | None) -> Any:
    if not ref:
        return None
    import importlib

    from cloudg.mcp.core import Registry

    module_name, _, attr = ref.partition(":")
    try:
        obj: Any = importlib.import_module(module_name)
        for part in (attr or "default_registry").split("."):
            obj = getattr(obj, part)
    except (ImportError, AttributeError) as exc:
        raise click.BadParameter(f"cannot import {ref!r}: {exc}", param_hint="--registry") from exc
    if not isinstance(obj, Registry) and callable(obj):
        obj = obj()
    if not isinstance(obj, Registry):
        raise click.BadParameter(f"{ref!r} is not a cloudg.mcp.core.Registry",
                                 param_hint="--registry")
    return obj


def _build_layer(ctx: click.Context, opts: dict[str, Any], **extra: Any) -> Any:
    from cloudg.mcp.server import create_layer_from_options

    registry = _load_registry(opts.get("registry_ref"))
    try:
        return create_layer_from_options(
            config=None if opts.get("config_path") else _parent_config(ctx),
            config_path=opts.get("config_path"),
            policy=opts.get("policy"),
            datasets=opts.get("datasets") or (),
            prefix=opts.get("prefix") or "",
            include_categories=opts.get("include_categories") or None,
            exclude_categories=opts.get("exclude_categories") or None,
            include_tools=opts.get("include_tools") or None,
            exclude_tools=opts.get("exclude_tools") or None,
            read_only=bool(opts.get("read_only")),
            audit_log=opts.get("audit_log"),
            default_timeout=opts.get("timeout"),
            registry=registry,
            **extra,
        )
    except (FileNotFoundError, ValueError) as exc:
        raise click.ClickException(str(exc)) from exc


def _principal(roles: tuple[str, ...], principal_id: str | None) -> Principal:
    if not roles and not principal_id:
        return Principal.local()
    return Principal(id=principal_id or "cli", roles=set(roles) or {"default"})


def _principal_options(fn: Callable[..., Any]) -> Callable[..., Any]:
    fn = click.option("--role", "roles", multiple=True,
                      help="Call as a principal with this role (repeatable; default: the "
                           "local user).")(fn)
    fn = click.option("--principal-id", default=None, help="Principal id to call as.")(fn)
    return fn


def _stdout_console() -> Any:
    from rich.console import Console

    try:
        tty = sys.stdout.isatty()
    except (AttributeError, ValueError):
        tty = False
    # piped / captured output: wide enough that URIs and names are not folded
    return Console(file=sys.stdout, soft_wrap=False, width=None if tty else 160)


def _setup_cli_logging(verbose: bool = False) -> None:
    from cloudg.mcp.server import _ensure_stderr_logging

    _ensure_stderr_logging("DEBUG" if verbose else "WARNING")


def _echo_json(data: Any) -> None:
    click.echo(json.dumps(data, indent=2, ensure_ascii=False, default=str))


def _first_line(text: str | None, width: int = 90) -> str:
    line = (text or "").strip().splitlines()[0] if (text or "").strip() else ""
    return line if len(line) <= width else line[: width - 1] + "…"


# ---------------------------------------------------------------------------
# Group
# ---------------------------------------------------------------------------


@click.group("mcp")
def mcp_group() -> None:
    """Model Context Protocol server: expose cloudg to AI assistants.

    \b
    Quick start:
      cloudg mcp serve                          # stdio (Claude Desktop / Code, Cursor...)
      cloudg mcp serve --transport http         # http://127.0.0.1:8765/mcp
      cloudg mcp config --client claude-code    # client configuration snippet
    """


# ---------------------------------------------------------------------------
# serve
# ---------------------------------------------------------------------------


@mcp_group.command("serve")
@click.option("--transport", type=click.Choice(["stdio", "http", "streamable-http", "sse"]),
              default="stdio", show_default=True, help="MCP transport.")
@click.option("--host", default="127.0.0.1", show_default=True,
              help="HTTP bind address (keep 127.0.0.1 unless you also set --auth-token).")
@click.option("--port", type=int, default=8765, show_default=True, help="HTTP port.")
@click.option("--path", "http_path", default="/mcp", show_default=True, help="HTTP endpoint.")
@click.option("--flavor", type=click.Choice(["auto", "native", "sdk", "fastmcp"]),
              default="auto", show_default=True,
              help="Server implementation: mcp SDK, standalone fastmcp, or the built-in "
                   "dependency-free server.")
@click.option("--auth-token", "auth_tokens", multiple=True, metavar="TOKEN[:ROLES[:ID]]",
              envvar="CLOUDG_MCP_AUTH_TOKENS", show_envvar=True,
              help="Require 'Authorization: Bearer TOKEN' (HTTP). ROLES is a comma list; "
                   "the principal also gets the 'default' role. TOKEN may be env:VAR. A token "
                   "containing ':' needs the full form TOKEN:ROLES:ID (fields may be empty). "
                   "Repeatable.")
@click.option("--allowed-origin", "allowed_origins", multiple=True,
              help="Allowed browser Origin pattern, replacing the default (loopback origins). "
                   "Same-origin requests are always accepted and the Origin check is on for "
                   "every bind and flavor. Repeatable.")
@click.option("--allowed-host", "allowed_hosts", multiple=True,
              help="Allowed Host header pattern. Default: loopback names on a loopback bind; "
                   "on other binds the Host header is not checked unless this is set "
                   "(Origin still is). Repeatable.")
@click.option("--cors-origin", "cors_origins", multiple=True,
              help="Enable CORS for this browser origin (native flavor only). Repeatable.")
@click.option("--json-response", is_flag=True, help="Answer HTTP POSTs with JSON, never SSE.")
@click.option("--stateless", is_flag=True, help="Session-less Streamable HTTP.")
@click.option("--cache-ttl", type=float, default=None,
              help="Cache read-only idempotent tool results for N seconds.")
@click.option("--max-concurrency", type=int, default=None, help="Max concurrent tool calls.")
@click.option("--page-size", type=int, default=100, show_default=True,
              help="Items per page for list results (native flavor).")
@click.option("--log-level", default="WARNING", show_default=True,
              type=click.Choice(["DEBUG", "INFO", "WARNING", "ERROR"], case_sensitive=False),
              help="Server log level (logs go to stderr).")
@_layer_options
@click.pass_context
def serve_cmd(ctx: click.Context, transport: str, host: str, port: int, http_path: str,
              flavor: str, auth_tokens: tuple[str, ...], allowed_origins: tuple[str, ...],
              allowed_hosts: tuple[str, ...], cors_origins: tuple[str, ...],
              json_response: bool, stateless: bool, cache_ttl: float | None,
              max_concurrency: int | None, page_size: int, log_level: str,
              **layer_opts: Any) -> None:
    """Run an MCP server exposing cloudg's tools, resources and prompts."""
    from cloudg.mcp.server import _ensure_stderr_logging, serve, validate_serve_options

    try:
        validate_serve_options(flavor, transport, cors_origins=cors_origins,
                               json_response=json_response, stateless=stateless)
    except ValueError as exc:
        raise click.UsageError(str(exc)) from exc
    _ensure_stderr_logging(log_level)
    tokens = [t for spec in auth_tokens for t in spec.split()] if auth_tokens else []
    if tokens:
        from cloudg.mcp.native.auth import TokenAuth

        try:
            TokenAuth.from_specs(tokens)
        except ValueError as exc:
            raise click.BadParameter(str(exc), param_hint="--auth-token") from exc
    layer = _build_layer(ctx, layer_opts, cache_ttl=cache_ttl, max_concurrency=max_concurrency)
    serve(
        layer,
        transport,
        flavor=flavor,
        host=host,
        port=port,
        path=http_path,
        auth_tokens=tokens,
        allowed_origins=list(allowed_origins) or None,
        allowed_hosts=list(allowed_hosts) or None,
        cors_origins=list(cors_origins),
        json_response=json_response,
        stateless=stateless,
        page_size=page_size,
        log_level=log_level,
    )


# ---------------------------------------------------------------------------
# Listing
# ---------------------------------------------------------------------------


def _annotation_flags(ann: dict[str, Any]) -> str:
    flags = []
    for key, label in (("readOnlyHint", "read-only"), ("destructiveHint", "destructive"),
                       ("idempotentHint", "idempotent"), ("openWorldHint", "open-world")):
        if ann.get(key) is True:
            flags.append(label)
    return ", ".join(flags)


@mcp_group.command("tools")
@click.option("--json", "as_json", is_flag=True, help="Print the MCP wire definitions as JSON.")
@click.option("--category", "categories", multiple=True, help="Filter by category.")
@_principal_options
@_layer_options
@click.pass_context
def tools_cmd(ctx: click.Context, as_json: bool, categories: tuple[str, ...],
              roles: tuple[str, ...], principal_id: str | None, **layer_opts: Any) -> None:
    """List the tools the active policy exposes."""
    _setup_cli_logging()
    layer = _build_layer(ctx, layer_opts)
    principal = _principal(roles, principal_id)
    tools = [t for t in layer.tools_wire(principal)
             if not categories or t.get("_meta", {}).get("cloudg/category") in categories]
    if as_json:
        _echo_json(tools)
        return
    from rich.table import Table

    table = Table(title=f"cloudg MCP tools ({len(tools)})", show_lines=False)
    for col in ("Tool", "Category", "Sensitivity", "Hints", "Description"):
        table.add_column(col, overflow="fold")
    for t in tools:
        meta = t.get("_meta", {})
        table.add_row(t["name"], str(meta.get("cloudg/category", "")),
                      str(meta.get("cloudg/sensitivity", "")),
                      _annotation_flags(t.get("annotations", {})),
                      _first_line(t.get("description")))
    _stdout_console().print(table)


@mcp_group.command("resources")
@click.option("--json", "as_json", is_flag=True, help="Print the MCP wire definitions as JSON.")
@_principal_options
@_layer_options
@click.pass_context
def resources_cmd(ctx: click.Context, as_json: bool, roles: tuple[str, ...],
                  principal_id: str | None, **layer_opts: Any) -> None:
    """List resources and resource templates."""
    _setup_cli_logging()
    layer = _build_layer(ctx, layer_opts)
    principal = _principal(roles, principal_id)
    resources = layer.resources_wire(principal)
    templates = layer.resource_templates_wire(principal)
    if as_json:
        _echo_json({"resources": resources, "resourceTemplates": templates})
        return
    from rich.table import Table

    table = Table(title=f"cloudg MCP resources ({len(resources)} + {len(templates)} templates)")
    for col in ("URI / template", "Name", "Category", "Sensitivity", "MIME", "Description"):
        table.add_column(col, overflow="fold")
    for r in resources:
        meta = r.get("_meta", {})
        table.add_row(r["uri"], r["name"], str(meta.get("cloudg/category", "")),
                      str(meta.get("cloudg/sensitivity", "")), r.get("mimeType", ""),
                      _first_line(r.get("description")))
    for r in templates:
        meta = r.get("_meta", {})
        table.add_row(r["uriTemplate"], r["name"], str(meta.get("cloudg/category", "")),
                      str(meta.get("cloudg/sensitivity", "")), r.get("mimeType", ""),
                      _first_line(r.get("description")))
    _stdout_console().print(table)


@mcp_group.command("prompts")
@click.option("--json", "as_json", is_flag=True, help="Print the MCP wire definitions as JSON.")
@_principal_options
@_layer_options
@click.pass_context
def prompts_cmd(ctx: click.Context, as_json: bool, roles: tuple[str, ...],
                principal_id: str | None, **layer_opts: Any) -> None:
    """List prompts."""
    _setup_cli_logging()
    layer = _build_layer(ctx, layer_opts)
    prompts = layer.prompts_wire(_principal(roles, principal_id))
    if as_json:
        _echo_json(prompts)
        return
    from rich.table import Table

    table = Table(title=f"cloudg MCP prompts ({len(prompts)})")
    for col in ("Prompt", "Category", "Arguments", "Description"):
        table.add_column(col, overflow="fold")
    for p in prompts:
        args = ", ".join(a["name"] + ("*" if a.get("required") else "")
                         for a in p.get("arguments", []))
        table.add_row(p["name"], str(p.get("_meta", {}).get("cloudg/category", "")), args,
                      _first_line(p.get("description")))
    _stdout_console().print(table)


# ---------------------------------------------------------------------------
# In-process calls
# ---------------------------------------------------------------------------


def _parse_args(raw: str | None) -> dict[str, Any]:
    if not raw:
        return {}
    if raw.startswith("@"):
        raw = Path(raw[1:]).expanduser().read_text(encoding="utf-8")
    elif raw == "-":
        raw = sys.stdin.read()
    try:
        value = json.loads(raw)
    except ValueError as exc:
        raise click.BadParameter(f"not valid JSON: {exc}", param_hint="--args") from exc
    if not isinstance(value, dict):
        raise click.BadParameter("must be a JSON object", param_hint="--args")
    return value


@mcp_group.command("call")
@click.argument("tool")
@click.option("--args", "raw_args", default=None, metavar="JSON|@FILE|-",
              help="Tool arguments as a JSON object, @file.json, or - for stdin.")
@click.option("--raw", is_flag=True, help="Print the full MCP CallToolResult.")
@_principal_options
@_layer_options
@click.pass_context
def call_cmd(ctx: click.Context, tool: str, raw_args: str | None, raw: bool,
             roles: tuple[str, ...], principal_id: str | None, **layer_opts: Any) -> None:
    """Call TOOL in-process (policies and transforms apply) and print the result.

    Exits with status 1 when the tool reports an error.
    """
    from cloudg.mcp.core import MCPLayerError

    _setup_cli_logging()
    arguments = _parse_args(raw_args)
    layer = _build_layer(ctx, layer_opts)
    try:
        result = asyncio.run(layer.call_tool(tool, arguments,
                                             principal=_principal(roles, principal_id)))
    except MCPLayerError as exc:
        raise click.ClickException(exc.message) from exc
    wire = result.to_wire()
    if raw:
        _echo_json(wire)
    elif result.structured is not None:
        _echo_json(result.structured)
    else:
        for block in wire["content"]:
            click.echo(block.get("text") if block.get("type") == "text" else json.dumps(block))
    if result.is_error:
        ctx.exit(1)


@mcp_group.command("read")
@click.argument("uri")
@_principal_options
@_layer_options
@click.pass_context
def read_cmd(ctx: click.Context, uri: str, roles: tuple[str, ...], principal_id: str | None,
             **layer_opts: Any) -> None:
    """Read resource URI in-process and print its contents."""
    from cloudg.mcp.core import MCPLayerError, TextResourceContents

    _setup_cli_logging()
    layer = _build_layer(ctx, layer_opts)
    try:
        contents = asyncio.run(layer.read_resource(uri, principal=_principal(roles, principal_id)))
    except MCPLayerError as exc:
        raise click.ClickException(exc.message) from exc
    for item in contents:
        if isinstance(item, TextResourceContents):
            click.echo(item.text)
        else:
            _echo_json(item.to_wire())


# ---------------------------------------------------------------------------
# Client configuration snippets
# ---------------------------------------------------------------------------


def _server_command(command: str) -> list[str]:
    if command != "auto":
        return shlex.split(command)
    exe = shutil.which("cloudg-mcp")
    if exe:
        return [exe, "serve"]
    exe = shutil.which("cloudg")
    if exe:
        return [exe, "mcp", "serve"]
    return [sys.executable, "-m", "cloudg.mcp", "serve"]


def client_config(
    client: str,
    *,
    name: str = "cloudg",
    transport: str = "stdio",
    url: str = "http://127.0.0.1:8765/mcp",
    command: list[str] | None = None,
    serve_args: list[str] | None = None,
    token_env: str | None = None,
) -> dict[str, Any]:
    """Build the JSON snippet for ``client`` (see ``cloudg mcp config``)."""
    if client not in CLIENTS:
        raise ValueError(f"Unknown client {client!r}; choose from {CLIENTS}")
    argv = list(command or _server_command("auto")) + list(serve_args or [])
    exe, args = argv[0], argv[1:]
    if transport == "stdio":
        if client == "vscode":
            return {"servers": {name: {"type": "stdio", "command": exe, "args": args}}}
        entry: dict[str, Any] = {"command": exe, "args": args}
        if client == "claude-code":
            entry = {"type": "stdio", **entry, "env": {}}
        return {"mcpServers": {name: entry}}
    headers: dict[str, str] = {}
    if token_env:
        ref = "${" + token_env + "}" if client == "claude-code" else "${env:" + token_env + "}"
        headers = {"Authorization": f"Bearer {ref}"}
    if client == "claude-desktop":
        # Claude Desktop's config file launches local commands; bridge remote
        # servers with mcp-remote.
        bridge = ["-y", "mcp-remote", url]
        if token_env:
            bridge += ["--header", f"Authorization:Bearer ${{{token_env}}}"]
        return {"mcpServers": {name: {"command": "npx", "args": bridge}}}
    remote: dict[str, Any] = {"url": url}
    if client in ("claude-code", "vscode"):
        remote = {"type": "http", **remote}
    if headers:
        remote["headers"] = headers
    key = "servers" if client == "vscode" else "mcpServers"
    return {key: {name: remote}}


_CONFIG_HINTS = {
    "claude-desktop": "Merge into claude_desktop_config.json "
                      "(Settings > Developer > Edit Config), then restart Claude Desktop.",
    "claude-code": "Save as .mcp.json in your project root, or run: claude mcp add-json "
                   "<name> '<entry JSON>'.",
    "cursor": "Merge into ~/.cursor/mcp.json (global) or .cursor/mcp.json (project).",
    "vscode": "Save as .vscode/mcp.json (or add under \"mcp\" in settings.json).",
}


@mcp_group.command("config")
@click.option("--client", type=click.Choice(CLIENTS), default="claude-desktop",
              show_default=True, help="Target MCP client.")
@click.option("--name", default="cloudg", show_default=True, help="Server name in the config.")
@click.option("--transport", type=click.Choice(["stdio", "http"]), default="stdio",
              show_default=True, help="Launch locally (stdio) or connect to a running server.")
@click.option("--url", default="http://127.0.0.1:8765/mcp", show_default=True,
              help="Server URL for --transport http.")
@click.option("--command", "command", default="auto", show_default=True,
              help="Server launch command (auto: cloudg-mcp / cloudg / python -m cloudg.mcp).")
@click.option("--policy", default=None, help="Add --policy to the launch arguments.")
@click.option("--dataset", "datasets", multiple=True, help="Add --dataset (repeatable).")
@click.option("--read-only", is_flag=True, help="Add --read-only.")
@click.option("--token-env", default=None, metavar="VAR",
              help="For http: send 'Authorization: Bearer $VAR'.")
def config_cmd(client: str, name: str, transport: str, url: str, command: str,
               policy: str | None, datasets: tuple[str, ...], read_only: bool,
               token_env: str | None) -> None:
    """Print a ready-to-paste MCP client configuration snippet."""
    serve_args: list[str] = []
    if policy:
        serve_args += ["--policy", policy]
    for ds in datasets:
        p = ds.partition("=")
        path = str(Path(p[2] if p[1] else ds).expanduser().resolve())
        serve_args += ["--dataset", f"{p[0]}={path}" if p[1] else path]
    if read_only:
        serve_args.append("--read-only")
    snippet = client_config(client, name=name, transport=transport, url=url,
                            command=_server_command(command), serve_args=serve_args,
                            token_env=token_env)
    _echo_json(snippet)
    click.echo(_CONFIG_HINTS[client], err=True)


def main(argv: list[str] | None = None) -> None:
    """Entry point for ``cloudg-mcp`` / ``python -m cloudg.mcp``."""
    logging.captureWarnings(True)
    mcp_group.main(args=argv, prog_name="cloudg-mcp")


if __name__ == "__main__":  # pragma: no cover
    main()
