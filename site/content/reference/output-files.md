---
title: Output files
lede: Every file cloudg writes, which command writes it, and what is inside.
source: docs/DOCUMENTATION.md
since: "0.6.0"
---

Every command writes into one output directory, `-o` / `--output`, which defaults to `./reports` and is created when missing. Files with the same name are overwritten without a prompt, so give each run its own directory when you want to keep history. The exceptions to "everything goes into `-o`" are the Terraform export, the Cloud Control type cache and the MCP server's audit log and vault, listed in their sections below.

## cloudg run

```mermaid caption="Where the files of cloudg run come from, phase by phase"
flowchart LR
  A["Collect"] --> B["Graph"]
  B --> C["RAG export"]
  C --> D["Terraform"]
  D --> E["Scanners"]
  E --> F["Ontology"]
  F --> G["Normalise"]
  G --> H["Render"]
  B -.-> B1["topology.graphml, topology-cytoscape.json"]
  C -.-> C1["rag_chunks.jsonl, rag_metadata_index.json"]
  E -.-> E1["prowler/, scoutsuite/"]
  F -.-> F1["ontology.ttl, ontology.jsonld"]
  H -.-> H1["findings.json, topology.svg, report.html"]
```

| File | Written by | Contents |
|---|---|---|
| `topology.graphml` | graph phase, always | The asset graph from [GraphBuilder](/api/graphbuilder/), for Gephi, yEd or `networkx.read_graphml`. Saved before the reachability walk, so `is_internet_exposed` is the collector's flag |
| `topology-cytoscape.json` | graph phase, always | The same graph as Cytoscape.js `elements` |
| `rag_chunks.jsonl` | RAG export, unless `--no-rag-export` or `rag.enabled: false` | One retrieval chunk per line: entity, community and relation-group chunks ([RAGExporter](/api/ragexporter/)). Written once after the graph phase and rewritten after the scanners with every finding |
| `rag_metadata_index.json` | RAG export | Chunk counts per kind, every `chunk_id` in file order, the chunk types |
| `provider.tf.json`, `variables.tf.json`, `main.tf.json`, `import_commands.sh` | Terraform phase, with `--terraform` or `terraform.enabled: true` | Terraform JSON that recreates the collected resources, and a script of `terraform import` commands. Written to `terraform.output_dir` (default `./reports/terraform`, relative to the working directory, whatever `-o` says) |
| `prowler/<provider>/` | Prowler, when it runs | Prowler's own JSON-ASFF output files, which cloudg parses |
| `scoutsuite/<provider>/` | ScoutSuite, when it runs | ScoutSuite's report directory |
| `ontology.ttl`, `ontology.jsonld` | ontology phase, unless `--no-ontology` or `ontology.enabled: false` | The RDF graph with 64 relation types and the findings ([CloudOntology](/api/cloudontology/)). One file per `ontology.export_formats` entry; `xml` adds `ontology.rdf`, `nt` adds `ontology.nt` |
| `findings.json` | render phase | The normalised result: metadata, summary, assets, findings, compliance mappings, D3 graph. Shape below |
| `topology.svg` | render phase | Static topology diagram |
| `report.html` | render phase | Interactive report: topology, findings table, compliance matrix. The data is embedded, but the page loads Chart.js and D3 from `cdn.jsdelivr.net`, so the charts and the topology need network access when it is opened. `report.inline_js` is not read in 0.6.0 |

Checkov and Trivy write nothing to disk; cloudg reads their stdout. `cloudg run` writes no `raw-findings.json` and no inventory map. All three render files are written whatever `report.formats` says, and `topology.graphml` and `topology-cytoscape.json` are written whatever `graph.persist_graphml` and `graph.export_cytoscape` say: those keys are not read in 0.6.0.

## cloudg collect

| File | Written by | Contents |
|---|---|---|
| `inventory-<provider>.json` | `cloudg collect -p <provider>` | `{"assets": [...], "edges": [...]}` straight from the provider's collector, each serialised with `model_dump(mode="json")`. No linking, no summary; use `cloudg map` for the interconnected inventory |

## cloudg scan

| File | Written by | Contents |
|---|---|---|
| `raw-findings.json` | every scan | A JSON list of `Finding` objects from all scanners, before normalisation: no deduplication, no compliance mapping |
| `prowler/` | Prowler | Prowler's JSON-ASFF output (not split per provider, unlike `cloudg run`) |
| `scoutsuite/` | ScoutSuite | ScoutSuite's report directory |

`cloudg map --findings` accepts this file, or a `findings.json`.

## cloudg map

| File | Written by | Contents |
|---|---|---|
| `inventory-map.json` | every map | The self-contained map: `summary`, `providers`, `regions`, `assets`, `edges`, `unresolved_references`, and `throttling` when a cloud API pushed back. Read by `cloudg deps`, `InventoryResult.load()` and the MCP workspace. Field reference: [inventory-map.json](/reference/inventory/inventory-map-json/) |
| `inventory-map.graphml` | every map | The map's graph, with parallel rule edges merged ([field list](/reference/inventory/inventory-map-graphml/)) |
| `inventory-graph.json` | every map | D3 `nodes` and `links` for `docs/viewer.html` and other front ends ([field list](/reference/inventory/inventory-graph-json/)) |
| `inventory-dependencies.json` | every map | Shared dependencies and largest blast radius (top 25 each), every cross-account edge, security service coverage, unresolved references |
| `inventory-organization.json` | `--org`, or `aws.organization.enabled` | The AWS Organization and Control Tower topology: accounts, OU tree, SCPs, landing zone |
| `asset-map.json` | `--findings`, when at least one finding loads | Every asset with its matched findings, sorted by finding count |
| `compliance-map.json` | `--findings`, when at least one finding loads | Per framework: finding count, severity breakdown, affected assets |

The map's coverage records (which service was collected, partly collected or failed) are shown in the terminal but not saved in `inventory-map.json`.

Outside the output directory, the AWS Cloud Control sweep caches the list of resource types it can enumerate in `~/.cache/cloudg/cloudcontrol-types.json` (or `$CLOUDG_CACHE_DIR/cloudcontrol-types.json`) for seven days.

## cloudg deps --json

`cloudg deps` reads a saved map and writes no file. With `--json` it prints JSON to stdout; redirect it to keep it.

| Invocation | Prints |
|---|---|
| `cloudg deps <asset> --json` | The asset's dependency tree: what it depends on (`up`), what depends on it (`down`), or both, to `--depth` levels |
| `cloudg deps --json` | `{"shared_dependencies", "largest_blast_radius", "cross_account_edges"}`; `--top` limits the first two, the third lists every cross-account edge |

```bash
cloudg deps arn:aws:iam::123456789012:role/orders-worker --json > role-deps.json
cloudg deps --map ./reports --top 50 --json > overview.json
```

The key-by-key shapes are in [cloudg deps --json](/reference/inventory/cloudg-deps-json/).

## cloudg ingest

| File | Written by | Contents |
|---|---|---|
| `raw-findings.json` | every ingest | The parsed findings before normalisation, as a JSON list |
| `findings.json` | `--format json` or `all` (default) | Normalised findings and compliance mappings. `assets` is empty and `graph` has no nodes, because nothing was collected |
| `report.html` | `--format html` or `all` | The HTML report for those findings |

## cloudg report

| File | Written by | Contents |
|---|---|---|
| `findings.json` | `--format json` or `all` (default) | Rewritten from the input's `assets`, `findings` and `graph` |
| `topology.svg` | `--format svg` or `all` | Diagram of the input's assets |
| `report.html` | `--format html` or `all` | The HTML report |

:::warning cloudg report does not round-trip everything
`cloudg report -i` rebuilds the result from `assets`, `findings` and `graph` only. The `findings.json` it writes has an empty `compliance` list, a new `scan_id`, `total_edges: 0` and `completed_at: "None"`, and `topology.svg` is drawn without edges. With the default `-o ./reports`, running it on `./reports/findings.json` overwrites the original. Point `-o` somewhere else.
:::

## cloudg mcp

`cloudg mcp serve` writes nothing unless asked to. These are the files it can produce:

| File | Written by | Contents |
|---|---|---|
| audit log (`--audit-log PATH` or `$CLOUDG_MCP_AUDIT_LOG`) | `AuditLogMiddleware` | One JSON line per call: time, principal, tool or resource name, argument keys, HMAC hashes of the argument values, duration, outcome, sensitivity, transforms applied. Created with mode `0600` and appended to |
| pseudonym vault (`vault.path` in the policy) | the policy's `TokenVault` | The pseudonym mappings, encrypted by default, written atomically with mode `0600` when serving ends or the process exits |
| `findings.json`, `report.html`, inventory files, `<dataset>.graphml`, `asset-map.json` and `compliance-map.json` | the `export_report` tool | Depends on its `format` argument; written under the workspace output directory (`report.output_dir`, default `./reports`) or its `subdir` |
| `terraform/*.tf.json`, `terraform/import_commands.sh` | the `export_terraform` tool | As for `cloudg run`, in the workspace output directory |
| `ontology.ttl` (or `.jsonld`, `.rdf`, `.nt`) | the `export_ontology` tool | The dataset's ontology; the file name comes from its `filename` argument |
| `scans/` | the `run_scanners` live tool | Scanner output, as for `cloudg scan` |
| `pipeline/` | the `run_pipeline` live tool | What `CloudGEngine.run_pipeline()` writes: `findings.json`, `report.html`, ontology and RAG files |

The tools refuse paths that escape the output directory. `cloudg mcp config` prints client configuration to stdout and writes no file.

The global option `cloudg --log-file PATH <command>` (or `log_file` in `config.yaml`) also writes the log to that file, for any command.

## findings.json

`findings.json` is the main machine-readable result of `cloudg run` and `cloudg ingest`, and the input of `cloudg report`. An excerpt from a run with two assets, an SSH rule open to the internet and nothing else, trimmed to one entry per list (the summary still counts both findings):

```json title="reports/findings.json"
{
  "metadata": {
    "scan_id": "cfc19759-897f-407f-b866-a0b977325467",
    "provider": null,
    "account_id": null,
    "region": null,
    "started_at": "2026-10-09 16:47:09.228244",
    "completed_at": "2026-10-09 16:47:09.228230"
  },
  "summary": {"total_assets": 2, "total_findings": 2, "total_edges": 2, "severity_breakdown": {"CRITICAL": 1, "HIGH": 1}, "compliance_frameworks": ["PCI-DSS", "SOC2", "NIST-800-53", "CIS", "ISO-27001"]},
  "assets": [
    {
      "id": "sg-web",
      "arn": "arn:aws:ec2:eu-west-1:123456789012:security-group/sg-web",
      "name": "sg-web",
      "asset_type": "SECURITY_GROUP",
      "provider": "AWS",
      "region": "eu-west-1",
      "account_id": "123456789012",
      "tags": {},
      "metadata": {},
      "collected_at": "2026-10-09T16:47:08.038905",
      "is_internet_exposed": false,
      "display_id": "arn:aws:ec2:eu-west-1:123456789012:security-group/sg-web"
    }
  ],
  "findings": [
    {
      "id": "17cd5168-70ea-5cd1-aa9a-10c4dea0a98e",
      "resource_id": "sg-web",
      "resource_arn": "arn:aws:ec2:eu-west-1:123456789012:security-group/sg-web",
      "severity": "CRITICAL",
      "title": "Security group allows SSH (port 22) from 0.0.0.0/0",
      "description": "A security group rule allows inbound traffic on port 22 (SSH) from 0.0.0.0/0. This is a common attack vector.",
      "evidence": "Edge from 0.0.0.0/0 to sg-web, port 22, cidr 0.0.0.0/0",
      "remediation": "Restrict port 22 (SSH) access to specific IP ranges. Use a bastion host or VPN for administrative access.",
      "source_tool": "cloudg-reachability",
      "source_finding_id": null,
      "compliance_frameworks": [
        "CIS",
        "NIST-800-53",
        "PCI-DSS"
      ],
      "cvss_score": null,
      "detected_at": "2026-10-09T16:47:08.039404",
      "is_suppressed": false,
      "risk_score": 9.5
    }
  ],
  "compliance": [
    {
      "id": "ec4accbd-dd7c-4f79-9561-f903ea125340",
      "framework": "CIS",
      "control_id": "CIS-aggregate",
      "control_title": "CIS CIS-aggregate",
      "status": "FAIL",
      "finding_ids": [
        "17cd5168-70ea-5cd1-aa9a-10c4dea0a98e"
      ],
      "resource_arn": null
    }
  ],
  "graph": {
    "nodes": [
      {"id": "web-1", "name": "web-1", "type": "EC2", "provider": "AWS", "region": "eu-west-1", "arn": "arn:aws:ec2:eu-west-1:123456789012:instance/i-0web1", "account_id": "123456789012", "is_internet_exposed": false, "is_external": false}
    ],
    "links": [
      {"source": "web-1", "target": "sg-web", "type": "ATTACHED_TO", "port_range": "", "protocol": "", "cidr": "", "direction": "ingress", "relationship": "PROTECTED_BY_SG", "description": ""}
    ]
  }
}
```

| Key | Notes |
|---|---|
| `metadata` | Run identity. The timestamps are Python `str(datetime)` (a space, not `T`), and a missing value is the string `"None"`, not `null`. The CLI and the engine leave `provider`, `account_id` and `region` at `null` |
| `summary` | Counts. `total_edges` counts the collected `NetworkEdge` objects, which `findings.json` does not otherwise contain |
| `assets` | `CloudAsset` in JSON mode, without `raw_data`, with the computed `display_id` (ARN, else id). Fields: [CloudAsset](/reference/inventory/cloudasset/) |
| `findings` | `Finding` in JSON mode, sorted by severity, with the computed `risk_score` (severity base, averaged with `cvss_score` when present). Reachability findings have deterministic UUID5 ids; most scanner findings get a fresh UUID on every run. The normaliser can add frameworks the scanner did not set |
| `compliance` | One `ComplianceResult` per framework control, with the ids of the findings that failed it. `<framework>-aggregate` collects findings mapped to a framework but to no specific control |
| `graph` | D3 force-layout data, the same shape as `inventory-graph.json`. Rule edges on the same pair are merged here, so `links` can be shorter than the edge count |

Read it back with the models: `CloudAsset.model_validate(...)` and `Finding.model_validate(...)` accept these entries as they are, which is what `cloudg report` does.

## inventory-map.json

The map `cloudg map` writes, and `cloudg deps` and the MCP workspace read. The same two assets, as a map:

```json title="reports/inventory-map.json"
{
  "summary": {
    "total_assets": 2,
    "total_edges": 2,
    "providers": ["aws"],
    "assets_by_type": {"EC2": 1, "SECURITY_GROUP": 1},
    "assets_by_service": {"ec2": 2},
    "assets_by_region": {"eu-west-1": 2},
    "assets_by_account": {"123456789012": 2},
    "edges_by_type": {"SECURITY_GROUP_RULE": 1, "ATTACHED_TO": 1},
    "edges_by_relationship": {"PROTECTED_BY_SG": 1},
    "unlinked_assets": 0,
    "internet_exposed": 0,
    "accounts": 1,
    "cross_account_edges": 0,
    "external_accounts": 0,
    "security_service_gaps": 0,
    "unresolved_references": 0
  },
  "providers": ["aws"],
  "regions": {"aws": ["eu-west-1"]},
  "assets": [
    {"id": "sg-web", "arn": "arn:aws:ec2:eu-west-1:123456789012:security-group/sg-web",
     "name": "sg-web", "asset_type": "SECURITY_GROUP", "provider": "AWS", "region": "eu-west-1",
     "account_id": "123456789012", "tags": {}, "metadata": {},
     "collected_at": "2026-10-09T16:29:31.447446", "is_internet_exposed": false,
     "display_id": "arn:aws:ec2:eu-west-1:123456789012:security-group/sg-web"}
  ],
  "edges": [
    {"id": "53172b71-cf60-48f5-8bec-def2fbe139cc", "source_id": "0.0.0.0/0", "target_id": "sg-web",
     "edge_type": "SECURITY_GROUP_RULE", "ports": [], "port_range": "22", "protocol": "TCP",
     "cidr": "0.0.0.0/0", "direction": "ingress", "description": null, "relationship": null,
     "properties": {}}
  ],
  "unresolved_references": []
}
```

| Key | Notes |
|---|---|
| `summary` | Counts by type, service, region and account, edge counts by type and relationship, and health counters. `organization` and `throttling` blocks appear only when an organization was mapped or an API throttled. See [summary](/reference/inventory/summary/) |
| `assets` | Every asset, linked and deduplicated. Real collector assets carry rich `metadata`, including the `relations` the linker resolved |
| `edges` | Every edge, parallel rules kept. An endpoint can be a CIDR or another non-asset string, so look endpoints up with `.get()` |
| `unresolved_references` | Declared relations the linker could not resolve, with `source`, `source_name`, `target` and `edge_type` |
| `throttling` | Only when a cloud API throttled the run: the full throttling report of the run |

`edges` here and `links` in `inventory-graph.json` differ in length whenever parallel rules were merged for the graph. Count edges in this file. For every field of every structure, see the [inventory reference](/reference/inventory/inventory-map-json/).

## Related

:::links
- [cloudg run](/cli/run/) The flags that switch outputs on and off.
- [cloudg map](/cli/map/) The inventory map and its companions.
- [Reports](/guides/reports/) Reading `report.html` and `findings.json`.
- [Data models](/api/models/) The Pydantic models behind every JSON file.
- [CloudAsset reference](/reference/inventory/cloudasset/) Every asset field and identifier format.
:::
