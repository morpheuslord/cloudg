---
command: mcp resources
lede: Lists the MCP resources and resource templates a server would expose, with their URIs, sensitivity and MIME types.
intro: |
  Resources are the read-only side of the MCP server: summaries, graphs, schemas and single assets that a client can fetch by URI without calling a tool. `cloudg mcp resources` shows which ones the active policy lets a principal see.
---

## How it works

The command builds the layer from the shared options (see [cloudg mcp serve](/cli/mcp-serve/#building-the-layer)), asks it for the resources and resource templates visible to one principal, and prints them. The principal options work as on [cloudg mcp tools](/cli/mcp-tools/): the local user by default, or `--role` and `--principal-id` to see what a token holder gets.

There are two kinds of entry. A resource has a fixed URI, such as `cloudg://findings/summary`. A resource template has placeholders in braces that the client fills in, such as `cloudg://assets/{+ref}`. The `{+ref}` form means the value may contain `/` and `:`, so a full ARN fits. The table lists resources first, then templates, under one "URI / template" column:

| Column | Source |
|---|---|
| URI / template | `uri` for a resource, `uriTemplate` for a template |
| Name | The internal name, such as `findings_summary_resource` |
| Category | `_meta["cloudg/category"]` |
| Sensitivity | `_meta["cloudg/sensitivity"]` |
| MIME | `mimeType`, mostly `application/json`; `text/turtle` for the ontology |
| Description | First line of the description |

In 0.6.0, the default policy shows the local user 14 resources and 11 templates:

| Fixed URIs | Templates |
|---|---|
| `cloudg://workspace`, `cloudg://datasets` | `cloudg://datasets/{dataset}/summary` |
| `cloudg://findings/summary` | `cloudg://assets/{+ref}`, `cloudg://assets/{+ref}/neighbors`, `cloudg://assets/{+ref}/findings` |
| `cloudg://compliance` | `cloudg://findings/{finding_id}`, `cloudg://findings/severity/{severity}` |
| `cloudg://graph/d3` | `cloudg://compliance/{framework}` |
| `cloudg://ontology/turtle` | `cloudg://graph/{format}`, `cloudg://ontology/{format}` |
| `cloudg://schema/asset-types`, `cloudg://schema/edge-types`, `cloudg://schema/relation-types` | `cloudg://schema/asset-types/{asset_type}` |
| `cloudg://docs` | `cloudg://docs/{topic}` |
| `cloudg://policy`, `cloudg://privacy/detectors`, `cloudg://ratelimit`, `cloudg://metrics` | |

The list does not depend on loaded datasets. Resources that read data, like `cloudg://findings/summary`, use the active dataset when they are read, so preload one with `--dataset` before you [read](/cli/mcp-read/) them.

`--include-category` and `--exclude-category` apply to resources and templates as well as tools. `--include-tool` and `--exclude-tool` do not touch them.

With `--json`, the output is one object with two keys, `resources` and `resourceTemplates`, each holding the wire definitions a client would receive:

```console
$ cloudg mcp resources --json | jq '.resourceTemplates[0]'
{
  "uriTemplate": "cloudg://datasets/{dataset}/summary",
  "name": "dataset_summary_resource",
  "mimeType": "application/json",
  "description": "Headline numbers of one dataset.",
  "title": "Dataset summary",
  "_meta": {
    "cloudg/category": "workspace",
    "cloudg/sensitivity": "internal"
  }
}
```

stdout carries only the table or the JSON; the banner and logs go to stderr.

## Examples

List all resources and templates for the default policy:

```bash
cloudg mcp resources
```

Print only the URIs, one per line:

```bash
cloudg mcp resources --json | jq -r '.resources[].uri, .resourceTemplates[].uriTemplate'
```

Check which resources an analyst sees under your policy:

```bash
cloudg mcp resources --policy ./mcp-policy.yaml --role analyst
```

See what is left when you hide the ontology and privacy categories:

```bash
cloudg mcp resources --exclude-category ontology --exclude-category privacy
```

## Exit codes

| Code | When |
|---|---|
| 0 | The list was printed |
| 1 | The layer could not be built, for example a missing policy file or dataset |
| 2 | Click rejected an option |

## Related

:::links
- [Resources and resource templates](/mcp/tools/resources-and-resource-templates/) Every resource with an example of its content.
- [cloudg mcp read](/cli/mcp-read/) Fetch one of these URIs from the shell.
- [cloudg mcp tools](/cli/mcp-tools/) The same listing for tools.
- [The workspace](/mcp/server/the-workspace/) Datasets and which one is active.
:::
