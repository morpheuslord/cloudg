"""``cloudg mcp config``: ready-to-paste MCP client configuration snippets
(re-exported by :mod:`cloudg.mcp.cli`, the documented import path of
:func:`client_config`)."""

from __future__ import annotations

import shlex
import shutil
import sys
from pathlib import Path
from typing import Any

import click

from cloudg.mcp.cli_common import _echo_json

__all__ = ["CLIENTS", "client_config", "config_cmd"]

CLIENTS = ("claude-desktop", "claude-code", "cursor", "vscode")


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
    "vscode": 'Save as .vscode/mcp.json (or add under "mcp" in settings.json).',
}


@click.command("config")
@click.option(
    "--client",
    type=click.Choice(CLIENTS),
    default="claude-desktop",
    show_default=True,
    help="Target MCP client.",
)
@click.option("--name", default="cloudg", show_default=True, help="Server name in the config.")
@click.option(
    "--transport",
    type=click.Choice(["stdio", "http"]),
    default="stdio",
    show_default=True,
    help="Launch locally (stdio) or connect to a running server.",
)
@click.option(
    "--url",
    default="http://127.0.0.1:8765/mcp",
    show_default=True,
    help="Server URL for --transport http.",
)
@click.option(
    "--command",
    "command",
    default="auto",
    show_default=True,
    help="Server launch command (auto: cloudg-mcp / cloudg / python -m cloudg.mcp).",
)
@click.option("--policy", default=None, help="Add --policy to the launch arguments.")
@click.option("--dataset", "datasets", multiple=True, help="Add --dataset (repeatable).")
@click.option("--read-only", is_flag=True, help="Add --read-only.")
@click.option(
    "--token-env", default=None, metavar="VAR", help="For http: send 'Authorization: Bearer $VAR'."
)
def config_cmd(**opts: Any) -> None:
    """Print a ready-to-paste MCP client configuration snippet."""
    serve_args: list[str] = []
    if opts["policy"]:
        serve_args += ["--policy", opts["policy"]]
    for ds in opts["datasets"]:
        p = ds.partition("=")
        path = str(Path(p[2] if p[1] else ds).expanduser().resolve())
        serve_args += ["--dataset", f"{p[0]}={path}" if p[1] else path]
    if opts["read_only"]:
        serve_args.append("--read-only")
    client = opts["client"]
    snippet = client_config(
        client,
        name=opts["name"],
        transport=opts["transport"],
        url=opts["url"],
        command=_server_command(opts["command"]),
        serve_args=serve_args,
        token_env=opts["token_env"],
    )
    _echo_json(snippet)
    click.echo(_CONFIG_HINTS[client], err=True)
