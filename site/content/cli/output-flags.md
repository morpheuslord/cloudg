---
title: Output flags
lede: "Where cloudg writes its files, which formats each command produces, and the flags that switch outputs on and off: `-o`, `--format`, `--ontology`, `--rag-export`, `--terraform` and `--json`."
---

## -o, --output

Every command that writes files takes `-o/--output`, and it defaults to `./reports` everywhere. The directory is created if it doesn't exist, parents included.

| Command | Writes into `-o` |
|---|---|
| `run` | Reports, graph files, ontology, RAG chunks, native scanner output |
| `map` | Inventory map files, plus asset and compliance maps with `--findings` |
| `collect` | `inventory-<provider>.json` |
| `scan` | `raw-findings.json` and native scanner output |
| `ingest` | `raw-findings.json` and the reports picked by `--format` |
| `report` | The reports picked by `--format` |

`cloudg deps` reads instead of writing. Its `-m/--map` option points at a saved `inventory-map.json` or its folder, with the same `./reports` default, so `map` followed by `deps` works with no options at all.

File names are fixed, so a second run into the same directory overwrites the first. Keep a history with dated folders:

```bash
cloudg run -p aws --regions all -o "./reports/$(date +%F)"
```

`report.output_dir` in `config.yaml` does not change the default of `-o`. It is the default output directory of the MCP workspace, where MCP tools write exports.

## The output directory

After a `cloudg run` with every phase enabled and a `cloudg map` into the same folder, the directory looks like this:

```text
reports/
├── findings.json                normalised result (run, ingest, report)
├── report.html                  interactive report (run, ingest, report)
├── topology.svg                 static topology (run, report)
├── topology.graphml             graph for Gephi, yEd, NetworkX (run)
├── topology-cytoscape.json      graph for Cytoscape.js (run)
├── ontology.ttl                 RDF, Turtle (run, --ontology)
├── ontology.jsonld              RDF, JSON-LD (run, --ontology)
├── rag_chunks.jsonl             retrieval chunks, one per line (run, --rag-export)
├── rag_metadata_index.json      chunk index (run, --rag-export)
├── raw-findings.json            pre-normalisation findings (scan, ingest)
├── inventory-map.json           assets, edges, summary (map)
├── inventory-map.graphml        interconnection graph (map)
├── inventory-graph.json         D3 graph (map)
├── inventory-dependencies.json  shared deps, blast radius, coverage (map)
├── inventory-organization.json  org and Control Tower topology (map --org)
├── asset-map.json               findings per asset (map --findings)
├── compliance-map.json          framework to assets (map --findings)
├── inventory-aws.json           assets and edges of one provider (collect)
├── prowler/aws/                 Prowler's ASFF output (run; scan writes prowler/)
├── scoutsuite/aws/              ScoutSuite's report (run; scan writes scoutsuite/)
└── terraform/                   provider.tf.json, variables.tf.json, main.tf.json, import_commands.sh (run, --terraform)
```

The [output files reference](/reference/output-files/) describes each file's structure.

:::note The Terraform folder doesn't follow -o
The Terraform recreation goes to `terraform.output_dir`, which defaults to `./reports/terraform` whatever `-o` says. cloudg uses `<output>/terraform` only when that key is set to an empty string. If you change `-o`, set `terraform.output_dir` in your config as well.
:::

## --format

Two commands let you pick formats:

| Command | Choices | Default |
|---|---|---|
| `report` | `html`, `json`, `svg`, `all` | `all` |
| `ingest` | `html`, `json`, `all` | `all` |

`json` writes `findings.json`, `html` writes `report.html`, and `svg` writes `topology.svg`. `ingest` has no SVG choice, since it has no inventory to draw.

`run` has no `--format` and always writes all three. The `report.formats` key in `config.yaml` is not read by the CLI. `map` writes its fixed set of inventory files.

## --ontology, --rag-export, --terraform

These three switches exist on `cloudg run` only. Each pairs with a config key, but they combine differently:

| Flag | Default | Config key | Phase runs when |
|---|---|---|---|
| `--ontology/--no-ontology` | on | `ontology.enabled` (default true) | the flag and the key are both on |
| `--rag-export/--no-rag-export` | on | `rag.enabled` (default true) | the flag and the key are both on |
| `--terraform/--no-terraform` | off | `terraform.enabled` (default false) | the flag or the key is on |

So `--ontology` cannot switch the ontology back on when the config turns it off, while `--no-terraform` cannot switch Terraform off when the config turns it on.

What each one writes is shaped by config:

| Output | Settings |
|---|---|
| Ontology | One file per entry in `ontology.export_formats`. `turtle` gives `ontology.ttl`, `json-ld` gives `ontology.jsonld`, `xml` gives `ontology.rdf`, `nt` gives `ontology.nt`. The default is Turtle and JSON-LD. |
| RAG export | `rag.max_chunk_tokens` (default 2000) caps the size of each chunk. |
| Terraform | `terraform.output_dir`, see the note above. |

Turn off the ontology and the RAG export when you only need findings:

```bash
cloudg run -p aws --no-ontology --no-rag-export
```

`--terraform` has a second effect: when no IaC directory is given by `--iac-dir` or `scanners.iac_directories`, Checkov and the Trivy filesystem scan target the generated Terraform. See [cloudg run](/cli/run/#how-it-works).

## --json

`--json` switches a command from tables to machine-readable output on stdout.

| Command | What `--json` prints |
|---|---|
| `deps` | The dependency tree of one asset, or the overview object |
| `mcp tools` | The `tools/list` definitions |
| `mcp resources` | An object with `resources` and `resourceTemplates` |
| `mcp prompts` | The `prompts/list` definitions |

`cloudg mcp call` prints JSON without a flag, and `--raw` there gives the whole `CallToolResult`.

The `mcp` commands send the banner and logs to stderr, so their stdout can be piped straight into `jq`. `deps` does not: the root banner is printed to stdout first. Strip it before parsing:

```bash
cloudg deps --json | sed -n '/^{/,$p' | jq '.shared_dependencies[:3]'
```

## Logs

Two root options control logging for every command. They go before the subcommand:

```bash
cloudg -v --log-file ./cloudg.log run -p aws
```

`-v/--verbose` switches to debug logging, and `--log-file` also writes every log record to a file with timestamps. The config keys `verbose` and `log_file` do the same; the flag wins for the log file, and either one turns on verbose mode. `cloudg mcp serve` has its own `--log-level`, and `--audit-log` for a JSONL audit trail of tool calls.

## Related

:::links
- [Output files](/reference/output-files/) The structure of every file in the output directory.
- [Reports](/guides/reports/) Reading the HTML report and `findings.json`.
- [Graph, ontology and RAG](/guides/graph-ontology-rag/) What the ontology and RAG exports are for.
- [Provider and region flags](/cli/provider-flags/) What gets collected in the first place.
:::
