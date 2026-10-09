---
command: mcp tools
lede: Lists the MCP tools a server would expose, as a table or as the exact `tools/list` JSON a client receives.
intro: |
  Run `cloudg mcp tools` with the same options you plan to give `cloudg mcp serve`. What it prints is what the client will see, after the policy, the filters and `--read-only` have done their work.
---

## How it works

The command builds the same layer `serve` would build from the shared options (`--policy`, `--read-only`, `--include-category` and the rest, listed on [cloudg mcp serve](/cli/mcp-serve/#building-the-layer)), asks it for the tool list of one principal, and prints it. No server starts and no client is involved.

The principal is the local user unless you pass `--role` or `--principal-id`. The local user has the id `local` and the roles `default` and `local`. With either option, the caller becomes a principal with the id you gave (default `cli`) and the roles you gave (default `default`). This is how you check what a token holder will see before you hand out the token: give the same roles you put in its `--auth-token` spec.

Without `--json`, the output is a table with five columns:

| Column | Source |
|---|---|
| Tool | The tool name, with `--prefix` applied |
| Category | `_meta["cloudg/category"]`: `workspace`, `inventory`, `graph`, `findings`, `compliance`, `ontology`, `export`, `live`, `meta` or `privacy` |
| Sensitivity | `_meta["cloudg/sensitivity"]`: `public`, `internal`, `confidential` or `restricted` |
| Hints | The MCP annotations that are true: `read-only`, `destructive`, `idempotent`, `open-world` |
| Description | The first line of the description as written in the source, so it can stop mid-sentence; cut at 90 characters |

```console
$ cloudg mcp tools --category live
                    cloudg MCP tools (5)
┏━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━┳━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Tool              ┃ Category ┃ Sensitivity  ┃ Hints                 ┃ Description                                                        ┃
┡━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━╇━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│ map_inventory     │ live     │ confidential │ open-world            │ Map the complete live inventory (no scanners) with read-only cloud │
│ collect_assets    │ live     │ confidential │ open-world            │ Run the standard multi-provider asset collection (the `cloudg      │
│ run_scanners      │ live     │ confidential │ open-world            │ Run security scanners (external binaries, cloud credentials)       │
│ run_pipeline      │ live     │ confidential │ open-world            │ The complete cloudg pipeline: collect -> scan -> analyse (graph,   │
│ rate_limit_status │ live     │ internal     │ read-only, idempotent │ Live-operation guard and cloud API throttling state, without       │
└───────────────────┴──────────┴──────────────┴───────────────────────┴────────────────────────────────────────────────────────────────────┘
```

With `--json`, the command prints the list of tool definitions exactly as they go over the wire: `name`, `title`, `description`, `inputSchema`, `annotations`, `_meta`, and `outputSchema` where the policy keeps it. Pipe it to `jq` to inspect argument schemas.

`--category` filters on the category and is repeatable. It only filters the printout. To change what a server exposes, use `--include-category` or `--exclude-category`, which `serve` also understands. `--include-tool` and `--exclude-tool` take the names without the prefix.

How many tools you see depends on the policy and the principal. For the local user in 0.6.0:

| Options | Tools listed |
|---|---|
| `--policy open` | 74 |
| none (`standard`) | 73, without `reveal_token` |
| `--role admin` | 74, `reveal_token` included |
| `--read-only` | 65 |
| `--policy read_only` | 66 |
| `--policy strict` | 61 |

stdout carries only the table or the JSON. The banner and any log lines go to stderr, so piping is safe.

## Examples

List every tool the default policy exposes:

```bash
cloudg mcp tools
```

Show only the graph and inventory tools:

```bash
cloudg mcp tools --category graph --category inventory
```

Check what an analyst token will be able to call under your own policy file:

```bash
cloudg mcp tools --policy ./mcp-policy.yaml --role analyst
```

Confirm that a read-only deployment has no tools that touch the cloud:

```bash
cloudg mcp tools --read-only --category live
```

Print the argument schema of one tool:

```bash
cloudg mcp tools --json --include-tool find_assets | jq '.[0].inputSchema'
```

Save the full definitions to diff them between two releases:

```bash
cloudg mcp tools --json --policy open > tools-0.6.0.json
```

## Exit codes

| Code | When |
|---|---|
| 0 | The list was printed |
| 1 | The layer could not be built, for example `Error: Policy file not found: ...` or an invalid `--prefix` |
| 2 | Click rejected an option, or `--registry` did not resolve to a `Registry` |

## Related

:::links
- [Tool index](/mcp/tools/tool-index/) Every tool with its arguments and an example result.
- [cloudg mcp call](/cli/mcp-call/) Call one of the listed tools from the shell.
- [Built-in profiles](/mcp/privacy/built-in-profiles/) What each policy hides and transforms.
- [cloudg mcp serve](/cli/mcp-serve/) The shared layer options in full.
:::
