---
command: mcp read
lede: Reads one MCP resource in-process and prints its contents, with the policy applied as it would be for a client.
intro: |
  Resources are fetched by URI, such as `cloudg://findings/summary` or `cloudg://assets/<ref>`. `cloudg mcp read` lets you look at one from the shell, which helps when you are writing a policy or checking what an assistant will be shown.
---

## How it works

Like [cloudg mcp call](/cli/mcp-call/), each invocation builds a fresh layer from the shared options (see [cloudg mcp serve](/cli/mcp-serve/#building-the-layer)), reads `URI` once as the chosen principal, prints the contents and exits. Most resources read the active dataset, so load one with `--dataset` on the same command line. Without a dataset, those resources fail:

```console
$ cloudg mcp read cloudg://findings/summary
Error: No dataset is loaded. Call load_dataset(path=...) with an inventory-map.json / findings.json / scanner report, or map_inventory to collect live data.
```

The URI can be a fixed resource or a filled-in template. [cloudg mcp resources](/cli/mcp-resources/) lists both. For the asset templates, the reference can be the internal ID, a unique name, or a full ARN, and the ARN can be written as is or URL-encoded. Quote the URI in the shell, since ARNs contain `:` and `/` and some templates contain characters the shell treats specially.

Text contents are printed as they are, which for most resources is indented JSON and for some is another format: `cloudg://ontology/turtle` prints Turtle, `cloudg://graph/graphml` prints GraphML XML, and `cloudg://docs/{topic}` prints Markdown. Binary contents, if a resource returns any, are printed as their wire JSON with the base64 blob.

The policy decides what the principal may read. A resource it hides gives the same error as one that does not exist. For example, the `strict` profile hides the restricted Turtle export:

```console
$ cloudg mcp read cloudg://ontology/turtle --policy strict --dataset prod=inventory/inventory-map.json
Error: Unknown resource: cloudg://ontology/turtle
```

The principal options (`--role`, `--principal-id`) work as on [cloudg mcp tools](/cli/mcp-tools/). stdout carries only the contents, so the output can be piped or redirected.

## Examples

Headline numbers of a dataset, by name. This capture uses the synthetic estate from the test suite and is cut after the first lines:

```console
$ cloudg mcp read cloudg://datasets/prod/summary --dataset prod=inventory/inventory-map.json
{
  "dataset": "prod",
  "kind": "inventory",
  "source": "/home/me/estate/inventory/inventory-map.json",
  "loaded_at": "2026-10-09T16:24:08+00:00",
  "version": 0,
  "providers": [
    "aws",
    "azure",
    "gcp"
  ],
  "total_assets": 44,
  "total_edges": 56,
  "total_findings": 12,
  "open_findings": 11,
  "suppressed_findings": 1,
  ...
}
```

`total_findings` is not zero although only an inventory map was given: a `findings.json` in the same folder is loaded into the dataset.

Read one asset by ARN:

```bash
cloudg mcp read 'cloudg://assets/arn:aws:ec2:us-east-1:111111111111:instance/i-0bast' --dataset prod=./reports/inventory-map.json
```

List the open critical findings, highest risk first:

```bash
cloudg mcp read cloudg://findings/severity/CRITICAL --dataset prod=./reports/inventory-map.json
```

Export the ontology as Turtle for a triple store:

```bash
cloudg mcp read cloudg://ontology/turtle --dataset prod=./reports/inventory-map.json > estate.ttl
```

Export the graph for Gephi or yEd:

```bash
cloudg mcp read cloudg://graph/graphml --dataset prod=./reports/inventory-map.json > estate.graphml
```

See which documentation topics the server offers to assistants:

```bash
cloudg mcp read cloudg://docs
```

Check what the active policy does, as seen by a given role:

```bash
cloudg mcp read cloudg://policy --policy ./mcp-policy.yaml --role analyst
```

## Exit codes

| Code | When |
|---|---|
| 0 | The contents were printed |
| 1 | The URI is unknown or hidden (`Error: Unknown resource: URI`), the resource failed (for example no dataset loaded), or the layer could not be built |
| 2 | Click rejected an option |

## Related

:::links
- [Resources and resource templates](/mcp/tools/resources-and-resource-templates/) Every resource with example contents.
- [cloudg mcp resources](/cli/mcp-resources/) List the URIs and templates.
- [cloudg mcp call](/cli/mcp-call/) Call a tool instead of reading a resource.
- [The workspace](/mcp/server/the-workspace/) How datasets are loaded and named.
:::
