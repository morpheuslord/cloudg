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
import os
import sys
from pathlib import Path
from typing import Any

import click

from cloudg.mcp.cli_common import (
    AUTH_TOKENS_ENV,
    _build_layer,
    _echo_json,
    _first_line,
    _layer_options,
    _principal,
    _principal_options,
    _setup_cli_logging,
    _stdout_console,
)
from cloudg.mcp.cli_config import CLIENTS, client_config, config_cmd

__all__ = ["CLIENTS", "client_config", "main", "mcp_group"]


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
@click.option(
    "--transport",
    type=click.Choice(["stdio", "http", "streamable-http", "sse"]),
    default="stdio",
    show_default=True,
    help="MCP transport.",
)
@click.option(
    "--host",
    default="127.0.0.1",
    show_default=True,
    help="HTTP bind address (keep 127.0.0.1 unless you also set --auth-token).",
)
@click.option("--port", type=int, default=8765, show_default=True, help="HTTP port.")
@click.option("--path", "http_path", default="/mcp", show_default=True, help="HTTP endpoint.")
@click.option(
    "--flavor",
    type=click.Choice(["auto", "native", "sdk", "fastmcp"]),
    default="auto",
    show_default=True,
    help="Server implementation: mcp SDK, standalone fastmcp, or the built-in "
    "dependency-free server.",
)
@click.option(
    "--auth-token",
    "auth_tokens",
    multiple=True,
    metavar="TOKEN[:ROLES[:ID]]",
    envvar=AUTH_TOKENS_ENV,
    show_envvar=True,
    help="Require 'Authorization: Bearer TOKEN' (HTTP). ROLES is a comma list; "
    "the principal also gets the 'default' role. TOKEN may be env:VAR. A token "
    "containing ':' needs the full form TOKEN:ROLES:ID (fields may be empty). "
    "Repeatable.",
)
@click.option(
    "--allowed-origin",
    "allowed_origins",
    multiple=True,
    help="Allowed browser Origin pattern, replacing the default (loopback origins). "
    "Same-origin requests are accepted when the Host header is checked (loopback "
    "bind or --allowed-host); the Origin check is on for every bind and flavor. "
    "Repeatable.",
)
@click.option(
    "--allowed-host",
    "allowed_hosts",
    multiple=True,
    help="Allowed Host header pattern. Default: loopback names on a loopback bind; "
    "on other binds the Host header is not checked unless this is set "
    "(Origin still is). Repeatable.",
)
@click.option(
    "--cors-origin",
    "cors_origins",
    multiple=True,
    help="Enable CORS for this browser origin (native flavor only). Repeatable.",
)
@click.option("--json-response", is_flag=True, help="Answer HTTP POSTs with JSON, never SSE.")
@click.option("--stateless", is_flag=True, help="Session-less Streamable HTTP.")
@click.option(
    "--cache-ttl",
    type=float,
    default=None,
    help="Cache read-only idempotent tool results for N seconds.",
)
@click.option("--max-concurrency", type=int, default=None, help="Max concurrent tool calls.")
@click.option(
    "--page-size",
    type=int,
    default=100,
    show_default=True,
    help="Items per page for list results (native flavor).",
)
@click.option(
    "--log-level",
    default="WARNING",
    show_default=True,
    type=click.Choice(["DEBUG", "INFO", "WARNING", "ERROR"], case_sensitive=False),
    help="Server log level (logs go to stderr).",
)
@_layer_options
@click.pass_context
def serve_cmd(ctx: click.Context, **opts: Any) -> None:
    """Run an MCP server exposing cloudg's tools, resources and prompts."""
    from cloudg.mcp.server import (
        ServeOptions,
        _ensure_stderr_logging,
        serve,
        validate_serve_options,
    )

    serve_opts = ServeOptions(
        flavor=opts.pop("flavor"),
        host=opts.pop("host"),
        port=opts.pop("port"),
        path=opts.pop("http_path"),
        auth_tokens=_auth_tokens(opts.pop("auth_tokens")),
        allowed_origins=list(opts.pop("allowed_origins")) or None,
        allowed_hosts=list(opts.pop("allowed_hosts")) or None,
        cors_origins=list(opts.pop("cors_origins")),
        json_response=opts.pop("json_response"),
        stateless=opts.pop("stateless"),
        page_size=opts.pop("page_size"),
        log_level=opts.pop("log_level"),
    )
    transport = opts.pop("transport")
    try:
        validate_serve_options(
            serve_opts.flavor,
            transport,
            cors_origins=serve_opts.cors_origins,
            json_response=serve_opts.json_response,
            stateless=serve_opts.stateless,
        )
    except ValueError as exc:
        raise click.UsageError(str(exc)) from exc
    _ensure_stderr_logging(serve_opts.log_level)
    extra = {"cache_ttl": opts.pop("cache_ttl"), "max_concurrency": opts.pop("max_concurrency")}
    layer = _build_layer(ctx, opts, **extra)
    serve(layer, transport, options=serve_opts)


def _auth_tokens(specs: tuple[str, ...]) -> list[str]:
    """Token specs from ``--auth-token`` / ``$CLOUDG_MCP_AUTH_TOKENS``,
    validated. Given but empty (an unset ``$VAR`` expands to nothing) is an
    error: serving without the authentication the operator asked for would
    fail open."""
    tokens = [t for spec in specs for t in spec.split()]
    env_blank = os.environ.get(AUTH_TOKENS_ENV) is not None and not tokens
    if (specs or env_blank) and not tokens:
        raise click.BadParameter(
            "an empty token was given (is the variable it comes from unset?)",
            param_hint="--auth-token",
        )
    if tokens:
        from cloudg.mcp.native.auth import TokenAuth

        try:
            TokenAuth.from_specs(tokens)
        except ValueError as exc:
            raise click.BadParameter(str(exc), param_hint="--auth-token") from exc
    return tokens


# ---------------------------------------------------------------------------
# Listing
# ---------------------------------------------------------------------------


def _annotation_flags(ann: dict[str, Any]) -> str:
    flags = []
    for key, label in (
        ("readOnlyHint", "read-only"),
        ("destructiveHint", "destructive"),
        ("idempotentHint", "idempotent"),
        ("openWorldHint", "open-world"),
    ):
        if ann.get(key) is True:
            flags.append(label)
    return ", ".join(flags)


@mcp_group.command("tools")
@click.option("--json", "as_json", is_flag=True, help="Print the MCP wire definitions as JSON.")
@click.option("--category", "categories", multiple=True, help="Filter by category.")
@_principal_options
@_layer_options
@click.pass_context
def tools_cmd(
    ctx: click.Context,
    as_json: bool,
    categories: tuple[str, ...],
    roles: tuple[str, ...],
    principal_id: str | None,
    **layer_opts: Any,
) -> None:
    """List the tools the active policy exposes."""
    _setup_cli_logging()
    layer = _build_layer(ctx, layer_opts)
    principal = _principal(roles, principal_id)
    tools = [
        t
        for t in layer.tools_wire(principal)
        if not categories or t.get("_meta", {}).get("cloudg/category") in categories
    ]
    if as_json:
        _echo_json(tools)
        return
    from rich.table import Table

    table = Table(title=f"cloudg MCP tools ({len(tools)})", show_lines=False)
    for col in ("Tool", "Category", "Sensitivity", "Hints", "Description"):
        table.add_column(col, overflow="fold")
    for t in tools:
        meta = t.get("_meta", {})
        table.add_row(
            t["name"],
            str(meta.get("cloudg/category", "")),
            str(meta.get("cloudg/sensitivity", "")),
            _annotation_flags(t.get("annotations", {})),
            _first_line(t.get("description")),
        )
    _stdout_console().print(table)


@mcp_group.command("resources")
@click.option("--json", "as_json", is_flag=True, help="Print the MCP wire definitions as JSON.")
@_principal_options
@_layer_options
@click.pass_context
def resources_cmd(
    ctx: click.Context,
    as_json: bool,
    roles: tuple[str, ...],
    principal_id: str | None,
    **layer_opts: Any,
) -> None:
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
        table.add_row(
            r["uri"],
            r["name"],
            str(meta.get("cloudg/category", "")),
            str(meta.get("cloudg/sensitivity", "")),
            r.get("mimeType", ""),
            _first_line(r.get("description")),
        )
    for r in templates:
        meta = r.get("_meta", {})
        table.add_row(
            r["uriTemplate"],
            r["name"],
            str(meta.get("cloudg/category", "")),
            str(meta.get("cloudg/sensitivity", "")),
            r.get("mimeType", ""),
            _first_line(r.get("description")),
        )
    _stdout_console().print(table)


@mcp_group.command("prompts")
@click.option("--json", "as_json", is_flag=True, help="Print the MCP wire definitions as JSON.")
@_principal_options
@_layer_options
@click.pass_context
def prompts_cmd(
    ctx: click.Context,
    as_json: bool,
    roles: tuple[str, ...],
    principal_id: str | None,
    **layer_opts: Any,
) -> None:
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
        args = ", ".join(
            a["name"] + ("*" if a.get("required") else "") for a in p.get("arguments", [])
        )
        table.add_row(
            p["name"],
            str(p.get("_meta", {}).get("cloudg/category", "")),
            args,
            _first_line(p.get("description")),
        )
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
@click.option(
    "--args",
    "raw_args",
    default=None,
    metavar="JSON|@FILE|-",
    help="Tool arguments as a JSON object, @file.json, or - for stdin.",
)
@click.option("--raw", is_flag=True, help="Print the full MCP CallToolResult.")
@_principal_options
@_layer_options
@click.pass_context
def call_cmd(
    ctx: click.Context,
    tool: str,
    raw_args: str | None,
    raw: bool,
    roles: tuple[str, ...],
    principal_id: str | None,
    **layer_opts: Any,
) -> None:
    """Call TOOL in-process (policies and transforms apply) and print the result.

    Exits with status 1 when the tool reports an error.
    """
    from cloudg.mcp.core import MCPLayerError

    _setup_cli_logging()
    arguments = _parse_args(raw_args)
    layer = _build_layer(ctx, layer_opts)
    try:
        result = asyncio.run(
            layer.call_tool(tool, arguments, principal=_principal(roles, principal_id))
        )
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
def read_cmd(
    ctx: click.Context,
    uri: str,
    roles: tuple[str, ...],
    principal_id: str | None,
    **layer_opts: Any,
) -> None:
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


mcp_group.add_command(config_cmd)


def main(argv: list[str] | None = None) -> None:
    """Entry point for ``cloudg-mcp`` / ``python -m cloudg.mcp``."""
    logging.captureWarnings(True)
    mcp_group.main(args=argv, prog_name="cloudg-mcp")


if __name__ == "__main__":  # pragma: no cover
    main()
