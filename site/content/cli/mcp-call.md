---
command: mcp call
lede: Calls one MCP tool in-process and prints its result. The policy, privacy transforms and middleware apply exactly as they would for a client.
intro: |
  `cloudg mcp call` is the quickest way to try a tool, debug a policy, or use a tool from a shell script. No server runs and no client is needed.
---

## How it works

Each invocation builds a fresh layer from the shared options (see [cloudg mcp serve](/cli/mcp-serve/#building-the-layer)), calls `TOOL` once as the chosen principal, prints the result and exits. Nothing carries over between invocations. A `load_dataset` call in one command is gone by the next, so pass the data you need with `--dataset` every time.

Arguments go in `--args` as a JSON object. You have three ways to supply it:

| Form | Example |
|---|---|
| Inline JSON | `--args '{"ref": "bastion"}'` |
| A file, prefixed with `@` | `--args @args.json` (a leading `~` is expanded) |
| stdin | `--args -` |

Anything that is not a JSON object is refused before the tool runs, with `Invalid value for --args: not valid JSON: ...` or `must be a JSON object` and exit code 2. Without `--args`, the tool is called with no arguments.

The principal is the local user unless you pass `--role` or `--principal-id`, as on [cloudg mcp tools](/cli/mcp-tools/). A tool the policy hides from that principal behaves as if it did not exist.

What gets printed depends on the result and on `--raw`:

| Result | Printed on stdout |
|---|---|
| Has structured content | The structured content, as indented JSON |
| Text only | Each text block as is; any other block as JSON |
| `--raw` | The whole `CallToolResult`: `content`, `isError`, `structuredContent` and `_meta` |

`--raw` is the way to see what the policy added. Under the default `standard` policy, `_meta` carries a `cloudg/transforms` entry with the result's sensitivity and provenance, and `cloudg/duration_ms`.

A tool that fails returns `isError: true` rather than raising. `call` prints that result like any other and then exits with 1, which makes it usable in `if` statements. Here a typo in an asset reference returns suggestions in the error data:

```console
$ cloudg mcp call get_asset --dataset prod=inventory/inventory-map.json --args '{"ref": "bastoin"}' --raw
{
  "content": [
    {
      "type": "text",
      "text": "No asset matches the reference in this dataset. 2 close matches, see suggestions in the error data. Use find_assets(query=...) to search by name, ARN or tag."
    }
  ],
  "isError": true,
  "_meta": {
    "cloudg/error_code": -32602,
    "cloudg/error_data": {
      "value": "bastoin",
      "dataset": "prod",
      "suggestions": [
        {"id": "bastion", "name": "bastion", "type": "EC2", ...},
        {"id": "admin-role", "name": "bastion-admin", "type": "IAM_ROLE", ...}
      ]
    }
  }
}
$ echo $?
1
```

(Suggestion objects shortened; they also carry `arn`, `account_id` and `dataset`.) This and the next capture use the synthetic estate from `tests/mcp/fixtures/sample_estate.py`.

stdout carries only the result. The banner and logs go to stderr, so `| jq` works.

### Live tools

`map_inventory`, `collect_assets`, `run_scanners` and `run_pipeline` call the cloud. From `call` they use the cloud settings and credentials of the config given with `-c` (on `mcp call` or on the root `cloudg`), and they run their credential preflight before anything else. Their own timeouts (one or two hours) replace the 300-second default of `--timeout`. A policy or `--read-only` that drops them makes them unknown.

## Examples

See what is loaded and where tools may read and write:

```bash
cloudg mcp call workspace_status
```

Search a saved map and keep only two fields per asset:

```console
$ cloudg mcp call find_assets --dataset prod=inventory/inventory-map.json --args '{"query": "bastion", "fields": ["name", "type"]}'
{
  "dataset": "prod",
  "total": 2,
  "offset": 0,
  "returned": 2,
  "next_cursor": null,
  "truncated": false,
  "items": [
    {
      "id": "bastion",
      "name": "bastion",
      "type": "EC2"
    },
    {
      "id": "admin-role",
      "name": "bastion-admin",
      "type": "IAM_ROLE"
    }
  ]
}
```

Count assets by type, with the arguments in a file:

```bash
echo '{"group_by": "type", "top": 10}' > count.json
cloudg mcp call count_assets --dataset prod=./reports/inventory-map.json --args @count.json
```

Build the arguments in a script and pipe them in:

```bash
jq -n --arg ref "arn:aws:iam::123456789012:role/app-role" '{ref: $ref, max_depth: 5}' \
  | cloudg mcp call blast_radius --dataset prod=./reports/inventory-map.json --args -
```

Check whether an analyst could call a tool under your policy:

```bash
cloudg mcp call get_asset_metadata --policy ./mcp-policy.yaml --role analyst --dataset prod=./reports/inventory-map.json --args '{"ref": "bastion"}'
```

Stop a script when a tool reports an error:

```bash
if ! cloudg mcp call get_asset --dataset prod=./reports/inventory-map.json --args '{"ref": "orders-db"}' > orders-db.json; then
  echo "lookup failed, see orders-db.json" >&2
  exit 1
fi
```

## Exit codes

| Code | When |
|---|---|
| 0 | The tool ran and returned `isError: false` |
| 1 | The tool returned `isError: true`; the tool is unknown or hidden (`Error: Unknown tool: NAME`); or the layer could not be built |
| 2 | `--args` is not a JSON object, or another option was rejected |

## Related

:::links
- [Tool index](/mcp/tools/tool-index/) Every tool's arguments and results.
- [Conventions shared by every tool](/mcp/tools/conventions-shared-by-every-tool/) References, pagination, fields and errors.
- [Errors](/mcp/server/errors/) Error codes and what the error data holds.
- [cloudg mcp read](/cli/mcp-read/) The same thing for resources.
- [Live tools and the credential preflight](/mcp/server/live-tools-and-the-credential-preflight/) What happens before a live tool calls the cloud.
:::
