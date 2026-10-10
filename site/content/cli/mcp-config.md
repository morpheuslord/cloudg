---
command: mcp config
lede: Prints a ready-to-paste MCP client configuration for Claude Desktop, Claude Code, Cursor or VS Code.
intro: |
  Each client stores MCP servers in a slightly different JSON shape. `cloudg mcp config` writes the right one, with the launch command and arguments filled in, so you don't have to work out paths by hand.
---

## How it works

The command builds a JSON snippet, prints it on stdout, and prints a one-line hint on stderr saying where the snippet goes. Because the hint is on stderr, you can redirect stdout straight into a file.

`--client` picks the shape. `--transport` picks between two kinds of entry:

| `--transport` | What the client does | Options that apply |
|---|---|---|
| `stdio` (default) | Launches `cloudg mcp serve` itself as a child process | `--command`, `--policy`, `--dataset`, `--read-only` |
| `http` | Connects to a server you already started with `cloudg mcp serve --transport http` | `--url`, `--token-env` |

The two groups don't mix. With `--transport http`, `--policy`, `--dataset` and `--read-only` are ignored, because the running server already has its own options. With `stdio`, `--url` and `--token-env` are ignored.

For stdio, `--command auto` (the default) looks for a launcher in this order: `cloudg-mcp` on `PATH` (giving `cloudg-mcp serve`), then `cloudg` on `PATH` (giving `cloudg mcp serve`), then the current Python interpreter with `-m cloudg.mcp serve`. Found executables are written as absolute paths, which matters for desktop apps that start with a smaller `PATH` than your shell. Any other value is split with `shlex` and used as is. `--policy`, each `--dataset` and `--read-only` are then appended as server arguments, and dataset paths are made absolute.

The client shapes differ like this:

| Client | stdio entry | http entry | Where it goes |
|---|---|---|---|
| `claude-desktop` | `mcpServers.<name>` with `command` and `args` | `npx -y mcp-remote <url>` bridge, since the desktop config only launches local commands | `claude_desktop_config.json` (Settings > Developer > Edit Config), then restart |
| `claude-code` | `mcpServers.<name>` with `type: stdio`, `command`, `args`, `env` | `type: http`, `url`, optional `headers` | `.mcp.json` in the project root, or `claude mcp add-json` |
| `cursor` | `mcpServers.<name>` with `command` and `args` | `url`, optional `headers` | `~/.cursor/mcp.json` or `.cursor/mcp.json` |
| `vscode` | `servers.<name>` with `type: stdio`, `command`, `args` | `type: http`, `url`, optional `headers` | `.vscode/mcp.json`, or under `mcp` in `settings.json` |

`--token-env VAR` adds `Authorization: Bearer ...` using each client's variable syntax: `${VAR}` for Claude Code and the `mcp-remote` bridge, `${env:VAR}` for Cursor and VS Code. The token itself never appears in the file.

## Examples

Print the default Claude Desktop entry. On a machine where neither launcher is on `PATH`, it falls back to the interpreter:

```console
$ cloudg mcp config
{
  "mcpServers": {
    "cloudg": {
      "command": "/opt/cloudg/.venv/bin/python3",
      "args": [
        "-m",
        "cloudg.mcp",
        "serve"
      ]
    }
  }
}
Merge into claude_desktop_config.json (Settings > Developer > Edit Config), then restart Claude Desktop.
```

Write a project `.mcp.json` for Claude Code with a strict, read-only server and one preloaded map:

```console
$ cloudg mcp config --client claude-code --command "cloudg mcp serve" --policy strict --dataset prod=./reports/inventory-map.json --read-only > .mcp.json
Save as .mcp.json in your project root, or run: claude mcp add-json <name> '<entry JSON>'.
$ cat .mcp.json
{
  "mcpServers": {
    "cloudg": {
      "type": "stdio",
      "command": "cloudg",
      "args": [
        "mcp",
        "serve",
        "--policy",
        "strict",
        "--dataset",
        "prod=/home/me/project/reports/inventory-map.json",
        "--read-only"
      ],
      "env": {}
    }
  }
}
```

Point Claude Code at a shared HTTP server that needs a token:

```console
$ cloudg mcp config --client claude-code --transport http --token-env CLOUDG_MCP_TOKEN 2>/dev/null
{
  "mcpServers": {
    "cloudg": {
      "type": "http",
      "url": "http://127.0.0.1:8765/mcp",
      "headers": {
        "Authorization": "Bearer ${CLOUDG_MCP_TOKEN}"
      }
    }
  }
}
```

Connect VS Code to a server on another host:

```bash
cloudg mcp config --client vscode --transport http --url https://mcp.internal.example/mcp --token-env CLOUDG_MCP_TOKEN > .vscode/mcp.json
```

Reach an HTTP server from Claude Desktop through the `mcp-remote` bridge (needs Node.js):

```bash
cloudg mcp config --client claude-desktop --transport http --token-env CLOUDG_MCP_TOKEN
```

Give the server a different name, so it can sit next to another cloudg entry:

```bash
cloudg mcp config --client cursor --name cloudg-prod --dataset prod=./reports/inventory-map.json
```

Generate the same snippet from Python, for example in a provisioning script:

```python title="write_mcp_config.py"
import json

from cloudg.mcp.cli import client_config

snippet = client_config(
    "claude-code",
    command=["cloudg", "mcp", "serve"],
    serve_args=["--policy", "strict", "--read-only"],
)
print(json.dumps(snippet, indent=2))
```

## Exit codes

The command exits 0 after printing. Click returns 2 for an unknown `--client` or `--transport` value.

## Related

:::links
- [Connect a client](/mcp/connect/) Where each client keeps its configuration, step by step.
- [cloudg mcp serve](/cli/mcp-serve/) Every option the generated command can take.
- [Quick start with a desktop client](/mcp/server/quick-start-with-a-desktop-client/) From install to the first question.
- [Built-in profiles](/mcp/privacy/built-in-profiles/) Which `--policy` to put in the launch arguments.
:::
