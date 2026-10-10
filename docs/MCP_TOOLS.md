# cloudg MCP catalog reference

This is the programmer's reference for everything the cloudg MCP layer exposes: 74 tools, 13 resources, 11 resource templates and 11 prompts in cloudg 0.6.0. Each tool entry lists its arguments, return fields, annotations and policy metadata, followed by a real call and its real result.

Other MCP documents cover the rest of the layer. [MCP.md](MCP.md) explains installation, the `cloudg mcp` CLI, transports and client setup. [MCP_INTERNALS.md](MCP_INTERNALS.md) covers the layer, adapters and middleware. [MCP_PRIVACY.md](MCP_PRIVACY.md) covers policies, transforms and the pseudonym vault. Policies come up here only where they change what a tool returns.

## How the examples were produced

Every JSON example below was captured by a script, not typed by hand. The script wrote the synthetic estate from `tests/mcp/fixtures/sample_estate.py` (an AWS organization with a `prod` and a `shared-services` account, an external vendor account, a few Azure and GCP assets, 44 assets, 56 edges, 12 findings, one of them suppressed) and loaded it with:

```python
from cloudg.config import CloudGConfig
from cloudg.mcp.layer import CloudGMCPLayer
from cloudg.mcp.state import Workspace

ws = Workspace(CloudGConfig(), allowed_roots=[estate], output_dir=estate / "out")
layer = CloudGMCPLayer(policy="open", workspace=ws)
result = await layer.call_tool("load_dataset", {"path": str(estate / "inventory"), "name": "sample"})
```

The `open` policy applies no transforms, so the examples show raw tool output. Under the default `standard` policy, secrets are redacted and every result carries an extra `cloudg/transforms` entry in `_meta`. A few things were changed for print:

- Arrays are cut to the first two or three items, followed by a marker such as `"... 5 more"`; count maps keep five keys plus `"...": "N more"`. The markers are added for this document; the tool returned everything.
- Long strings end in `...` where they were cut.
- `<estate>` stands for the absolute path of the sample-estate directory on the capture machine.
- Error examples are shown as one object holding the tool name, the arguments, and the error result's `text` (`content[0].text`) and `_meta`.
- Calls run in document order against one workspace, so some results depend on earlier calls (for example the dataset `version` grows after a mutation). Where that matters the text says so. The `sample` dataset was loaded again, unmodified, at the start of the Compliance, Ontology, Export, Live, Meta and Privacy sections, so the suppressions and the ingested finding of the Findings section do not show up there. The resource, completion and prompt examples used a fresh workspace holding `sample`, its snapshot `baseline` and `after`, and the recipes a fresh `sample`.
- The script also wrote the inputs some examples need: `scans/prowler-asff.json` (one Prowler ASFF record for `sg-web`), `scans/prowler-ocsf.json` (one Prowler OCSF record) and `after/`, a copy of the inventory edited as described under [`diff_datasets`](#diff_datasets).
- Timestamps (`loaded_at`, `detected_at`, audit `ts`), cursors and pseudonyms differ from run to run.

The live tools (`map_inventory`, `collect_assets`, `run_scanners`, `run_pipeline`) were run against a stub: `cloudg.api.CloudGEngine` was replaced by the `FakeEngine` class from `tests/mcp/test_catalog_export_live_meta.py` and `cloudg.mcp.catalog.live.credential_problems` was patched to return `{}`. The workspace kept its `LiveOperationGuard` with the default settings; its cooldowns were reset between examples that are not about the guard, and the `rate_limit_status` example got a fresh guard. Their results show the real envelope and progress notifications the layer produces, but the inventory inside them is the sample estate, not a cloud account. The credential failure example under `map_inventory` is real: it ran the actual AWS credential check against an empty AWS config with the metadata service disabled.

To repeat any example yourself, use the in-process CLI (see [MCP.md](MCP.md) for every option):

```bash
cloudg mcp call find_assets --policy open --dataset sample=./inventory \
    --args '{"tag": "data=pii", "fields": ["name", "type"]}'
cloudg mcp read cloudg://findings/summary --policy open --dataset sample=./inventory
```

## Tool index

| Tool | Category | Sensitivity | Writes? | Summary |
|---|---|---|---|---|
| [`workspace_status`](#workspace_status) | workspace | internal | no | What is loaded, the active dataset, allowed and output directories. |
| [`list_datasets`](#list_datasets) | workspace | internal | no | Loaded datasets with sizes, kind and the active flag. |
| [`load_dataset`](#load_dataset) | workspace | internal | yes | Load an inventory map, findings report, generic JSON or scanner output as a dataset. |
| [`select_dataset`](#select_dataset) | workspace | internal | yes | Make a loaded dataset the active one. |
| [`unload_dataset`](#unload_dataset) | workspace | internal | yes | Drop a dataset from memory. |
| [`snapshot_dataset`](#snapshot_dataset) | workspace | internal | yes | Deep copy a dataset under a new name. |
| [`diff_datasets`](#diff_datasets) | workspace | confidential | no | Assets, edges and findings that changed between two datasets. |
| [`dataset_summary`](#dataset_summary) | workspace | internal | no | Headline numbers of one dataset. |
| [`find_assets`](#find_assets) | inventory | confidential | no | Filtered, sorted, paginated asset search returning briefs. |
| [`get_asset`](#get_asset) | inventory | confidential | no | One asset with relations, dependency counts and open findings. |
| [`get_asset_metadata`](#get_asset_metadata) | inventory | restricted | no | Raw collector metadata of one asset (restricted). |
| [`count_assets`](#count_assets) | inventory | internal | no | Asset counts grouped by one dimension. |
| [`list_asset_types`](#list_asset_types) | inventory | internal | no | Asset types present, with exposed and finding counts. |
| [`list_accounts`](#list_accounts) | inventory | confidential | no | Accounts, subscriptions and projects with per-account counts. |
| [`list_regions`](#list_regions) | inventory | internal | no | Regions with providers, asset and account counts. |
| [`list_tags`](#list_tags) | inventory | confidential | no | Tag keys and their most common values. |
| [`coverage_report`](#coverage_report) | inventory | internal | no | Collector success and failure per provider, account and region. |
| [`unresolved_references`](#unresolved_references) | inventory | confidential | no | Relations the linker could not resolve. |
| [`organization_topology`](#organization_topology) | inventory | confidential | no | Organization, OUs, accounts, Control Tower and policies. |
| [`neighbors`](#neighbors) | graph | confidential | no | Assets within N hops and the edges between them. |
| [`get_edges`](#get_edges) | graph | confidential | no | Edge search by endpoint, type, relationship, port, origin. |
| [`find_paths`](#find_paths) | graph | confidential | no | Shortest paths between two assets. |
| [`attack_paths`](#attack_paths) | graph | confidential | no | Ranked routes from the internet to sensitive assets. |
| [`lateral_movement_paths`](#lateral_movement_paths) | graph | confidential | no | Identity pivot chains from footholds. |
| [`internet_exposure`](#internet_exposure) | graph | confidential | no | Exposed assets with rules, sensitive ports and WAF evidence. |
| [`blast_radius`](#blast_radius) | graph | confidential | no | Dependency and network impact of one asset. |
| [`depends_on`](#depends_on) | graph | confidential | no | Upstream dependencies of one asset. |
| [`dependents`](#dependents) | graph | confidential | no | Downstream dependents of one asset. |
| [`dependency_tree`](#dependency_tree) | graph | confidential | no | Nested upstream / downstream tree of one asset. |
| [`shared_dependencies`](#shared_dependencies) | graph | confidential | no | Assets that many others depend on directly. |
| [`largest_blast_radius`](#largest_blast_radius) | graph | confidential | no | Assets with the most transitive dependents. |
| [`cross_account_edges`](#cross_account_edges) | graph | confidential | no | Relationships that cross account boundaries. |
| [`centrality_top`](#centrality_top) | graph | confidential | no | Most central assets by degree or betweenness. |
| [`subgraph_export`](#subgraph_export) | graph | restricted | no | Neighbourhood of a few assets as D3, Cytoscape or GraphML. |
| [`security_coverage`](#security_coverage) | graph | confidential | no | Security services per account and region, and the gaps. |
| [`graph_stats`](#graph_stats) | graph | internal | no | Size and shape of the relationship graph. |
| [`list_findings`](#list_findings) | findings | confidential | no | Filtered, sorted, paginated finding search. |
| [`get_finding`](#get_finding) | findings | confidential | no | One finding with evidence, remediation and controls. |
| [`findings_summary`](#findings_summary) | findings | internal | no | Finding counts grouped by one dimension. |
| [`findings_for_asset`](#findings_for_asset) | findings | confidential | no | All findings on one asset. |
| [`top_risks`](#top_risks) | findings | confidential | no | Assets to fix first, with the score components. |
| [`suppress_findings`](#suppress_findings) | findings | confidential | yes | Mark findings as suppressed in memory. |
| [`unsuppress_findings`](#unsuppress_findings) | findings | confidential | yes | Restore suppressed findings. |
| [`ingest_reports`](#ingest_reports) | findings | confidential | yes | Parse existing scanner output into a dataset. |
| [`normalise_findings`](#normalise_findings) | findings | internal | yes | Re-run deduplication and compliance mapping. |
| [`reachability_findings`](#reachability_findings) | findings | confidential | yes | Generate cloudg's own reachability findings. |
| [`list_frameworks`](#list_frameworks) | compliance | public | no | Compliance frameworks in the shipped rulesets. |
| [`compliance_summary`](#compliance_summary) | compliance | internal | no | Posture per framework. |
| [`list_controls`](#list_controls) | compliance | internal | no | Controls evaluated for a dataset, or defined by a ruleset. |
| [`control_status`](#control_status) | compliance | confidential | no | One control with its findings and affected assets. |
| [`compliance_gaps`](#compliance_gaps) | compliance | confidential | no | Assets that fail compliance, worst first. |
| [`ontology_stats`](#ontology_stats) | ontology | internal | no | Triples, classes and relation counts of the ontology. |
| [`sparql_query`](#sparql_query) | ontology | restricted | no | Read-only SPARQL over the dataset's ontology. |
| [`ontology_neighbourhood`](#ontology_neighbourhood) | ontology | confidential | no | Semantic relations around one asset. |
| [`relation_groups`](#relation_groups) | ontology | confidential | no | Relation group counts, or the triples of one group. |
| [`rag_chunks`](#rag_chunks) | ontology | confidential | no | Retrieval-ready text chunks with metadata. |
| [`export_ontology`](#export_ontology) | ontology | confidential | yes | Write the ontology to a file. |
| [`terraform_preview`](#terraform_preview) | export | internal | no | What a Terraform recreation would contain. |
| [`export_terraform`](#export_terraform) | export | confidential | yes | Write a Terraform recreation. |
| [`export_report`](#export_report) | export | confidential | yes | Write report files (JSON, HTML, inventory, GraphML, asset map). |
| [`map_inventory`](#map_inventory) | live | confidential | yes | Live inventory mapping with cloud credentials. |
| [`collect_assets`](#collect_assets) | live | confidential | yes | Live standard asset collection. |
| [`run_scanners`](#run_scanners) | live | confidential | yes | Run scanners against a dataset and add their findings. |
| [`run_pipeline`](#run_pipeline) | live | confidential | yes | Collect, scan, analyse, normalise and report in one run. |
| [`rate_limit_status`](#rate_limit_status) | live | internal | no | Live-operation guard and cloud API throttling state. |
| [`list_capabilities`](#list_capabilities) | meta | public | no | The tools this caller may use, by category, plus workflows. |
| [`describe_schema`](#describe_schema) | meta | public | no | cloudg's vocabulary (asset, edge, severity, relation enums). |
| [`explain_asset_type`](#explain_asset_type) | meta | public | no | How cloudg models one asset type. |
| [`explain_edge_type`](#explain_edge_type) | meta | public | no | How to read one edge type. |
| [`privacy_status`](#privacy_status) | privacy | internal | no | The active privacy policy as it applies to the caller. |
| [`preview_transform`](#preview_transform) | privacy | internal | no | Run the policy's transforms over sample data. |
| [`list_detectors`](#list_detectors) | privacy | public | no | Sensitive-data detectors and the strategy applied to each. |
| [`privacy_audit_log`](#privacy_audit_log) | privacy | restricted | no | Recent access decisions (restricted). |
| [`reveal_token`](#reveal_token) | privacy | restricted | no | Reverse a pseudonym (needs the reveal capability). |

Resources and resource templates are listed in [Resources and resource templates](#resources-and-resource-templates), prompts in [Prompts](#prompts).

## How the catalog is organised

Each module in `cloudg/mcp/catalog/` registers its primitives through a `register(registry)` function. `cloudg.mcp.catalog.default_registry()` calls all of them (`workspace`, `inventory`, `graph`, `findings`, `compliance`, `ontology`, `export`, `live`, `meta`, `resources`, `prompts`), then adds the `privacy` module if it imports. `cloudg.mcp.catalog.CATEGORIES` holds the category descriptions:

| Category | Tools | What it covers |
|---|---|---|
| `workspace` | 8 | Load, select, snapshot, diff and unload datasets |
| `inventory` | 11 | Search, inspect and aggregate assets, accounts, regions, tags, coverage, org |
| `graph` | 17 | Relationships: neighbours, paths, exposure, attack / lateral paths, dependencies, blast radius, centrality, sub-graphs |
| `findings` | 10 | Browse, summarise, prioritise, suppress and ingest security findings |
| `compliance` | 5 | Framework posture, controls and compliance gaps |
| `ontology` | 6 | RDF ontology, read-only SPARQL, semantic neighbourhoods, RAG chunks |
| `export` | 3 | Terraform recreation and report files |
| `live` | 5 | Collect from cloud APIs and run scanners (credentials / binaries; open world) |
| `meta` | 4 | Server capabilities and cloudg's vocabulary |
| `privacy` | 5 | Privacy policy, pseudonym vault and data-handling controls |
| `prompts` | 11 prompts | Packaged analysis workflows |

Resources and templates carry the category of what they show (`workspace`, `inventory`, `graph` and so on), so a category filter removes them along with the tools. To expose part of the catalog, filter the layer or build a registry from a subset of modules:

```python
layer = CloudGMCPLayer(include_categories=["inventory", "graph", "meta"])
layer = CloudGMCPLayer(exclude_categories=["live"], exclude_tools=["get_asset_metadata"])

from cloudg.mcp.core import Registry
from cloudg.mcp.catalog import inventory, graph
reg = Registry()
inventory.register(reg)
graph.register(reg)
layer = CloudGMCPLayer(registry=reg)
```

`prefix="cloudg_"` renames every tool and prompt on the wire (`cloudg_find_assets`), which helps when the layer is mounted into another server. `list_capabilities` reports the prefixed names.

## Conventions shared by every tool

### The call result

A tool returns a JSON object. The layer sends it twice: as `structuredContent`, and as pretty-printed JSON text in `content[0]` for clients without structured output. Resource links the tool attached follow as `resource_link` blocks, and `_meta` carries `cloudg/duration_ms` plus, when the policy transformed anything, a `cloudg/transforms` report. The full wire result of `dataset_summary` with `{"dataset": "report"}`, with the text block cut:

```json
{
  "content": [
    {
      "type": "text",
      "text": "{\n  \"dataset\": \"report\",\n  \"kind\": \"report\",\n  \"source\": \"<estate>/report/findings.json\",\n  \"loaded_at\": \"2026-10-09T14:25:10+00:00\",\n  \"version\": 0,\n  \"provide..."
    },
    {
      "type": "resource_link",
      "uri": "cloudg://datasets/report/summary",
      "name": "report summary",
      "mimeType": "application/json"
    }
  ],
  "isError": false,
  "structuredContent": {
    "dataset": "report",
    "kind": "report",
    "source": "<estate>/report/findings.json",
    "loaded_at": "2026-10-09T14:25:10+00:00",
    "version": 0,
    "providers": [
      "aws",
      "azure",
      "... 1 more"
    ],
    "total_assets": 44,
    "total_edges": 56,
    "total_findings": 12,
    "open_findings": 11,
    "suppressed_findings": 1,
    "severity_breakdown": {
      "CRITICAL": 2,
      "HIGH": 5,
      "MEDIUM": 2,
      "LOW": 1,
      "INFO": 1
    },
    "accounts": 5,
    "regions": 5,
    "internet_exposed": 6,
    "cross_account_edges": 3,
    "unlinked_assets": 2,
    "unresolved_references": 0,
    "compliance_frameworks": [
      "CIS-AWS",
      "CIS-Azure",
      "... 2 more"
    ],
    "assets_by_type": {
      "SECURITY_GROUP": 4,
      "IAM_ROLE": 4,
      "CLOUD_ACCOUNT": 3,
      "EC2": 3,
      "S3_BUCKET": 3,
      "...": "10 more"
    },
    "assets_by_provider": {
      "AWS": 36,
      "AZURE": 5,
      "GCP": 3
    },
    "edges_by_type": {
      "CONTAINS": 12,
      "IAM_TRUST": 2,
      "GOVERNS": 1,
      "SECURITY_GROUP_RULE": 4,
      "ATTACHED_TO": 6,
      "...": "10 more"
    },
    "has_organization": false,
    "coverage_records": 0
  },
  "_meta": {
    "cloudg/duration_ms": 2
  }
}
```

The text rendering is capped at `max_output_chars` (200,000 by default, set on `CloudGMCPLayer`). Past that the text ends with `... [truncated by cloudg mcp layer]`; `structuredContent` is not cut.

### The `dataset` argument

Every tool that reads data takes `dataset`. Empty means the active dataset, which is the one most recently loaded, selected or collected. A name that is not loaded fails; `error_data` holds the name and the list of loaded datasets:

```json
{
  "tool": "select_dataset",
  "arguments": {
    "name": "prod"
  },
  "isError": true,
  "text": "No such dataset. 2 dataset(s) are loaded: see datasets in the error data, or call list_datasets.",
  "_meta": {
    "cloudg/error_code": -32602,
    "cloudg/error_data": {
      "value": "prod",
      "datasets": [
        {
          "dataset": "sample"
        },
        {
          "dataset": "report"
        }
      ]
    }
  }
}
```

With nothing loaded at all, any tool that needs data fails the same way and says how to load something:

```json
{
  "tool": "dataset_summary",
  "arguments": {},
  "isError": true,
  "text": "No dataset is loaded. Call load_dataset(path=...) with an inventory-map.json / findings.json / scanner report, or map_inventory to collect live data.",
  "_meta": {
    "cloudg/error_code": -32602
  }
}
```

A few tools need no dataset: `workspace_status`, `list_datasets`, `list_frameworks`, `list_capabilities`, `describe_schema`, `explain_asset_type`, `explain_edge_type` and the privacy tools. Resources and resource templates always read the active dataset; they have no dataset variable except `cloudg://datasets/{dataset}/summary`.

### Asset references

Arguments named `ref`, `source`, `target`, `start`, `seeds`, `refs` and `resource` take an asset reference. `Dataset.find_asset` (`cloudg/mcp/state/dataset.py`) resolves it with `cloudg.inventory.dependencies.AssetIndex`, the matcher the ontology and the RAG export use too. It tries these in order and stops at the first unique hit:

1. the internal asset id (`web-1`);
2. the exact ARN or cloud resource id (`arn:aws:ec2:us-east-1:111111111111:instance/i-0web1`, an Azure resource id, a GCP full name);
3. an exact name shared by no other asset (`prod-data`);
4. the text after the last `/` of the ARN or resource id, when only one asset has it (`i-0web1`, `sg-0admin`; Azure and GCP ids contribute their last `/` segment);
5. the resource part of an ARN, i.e. everything after the fifth `:` (`function:api-handler`, `db:orders-db`, `instance/i-0web1`), or its last `:` or `/` segment (`api-handler`, `orders-db`), when only one asset has it;
6. a case-insensitive name shared by no other asset.

A name or tail that several assets share does not resolve, and the last two steps are skipped for a reference that is the exact name of more than one asset; use a longer form or the id.

Error messages never repeat the reference you passed or the names of other assets: those go into `_meta.cloudg/error_data`, where the privacy policy can transform them like any other result. When a name matches several assets, `error_data` holds the ids in `ambiguous` and up to five `candidates` (id, name, ARN, type, account). When nothing matches, `error_data.value` is the reference and `suggestions` lists up to five close assets (substring hits on name or ARN first, then fuzzy name matches):

```json
{
  "tool": "get_asset",
  "arguments": {
    "ref": "web-3"
  },
  "isError": true,
  "text": "No asset matches the reference in this dataset. 5 close matches, see suggestions in the error data. Use find_assets(query=...) to search by name, ARN or tag.",
  "_meta": {
    "cloudg/error_code": -32602,
    "cloudg/error_data": {
      "value": "web-3",
      "dataset": "sample",
      "suggestions": [
        {
          "id": "web-2",
          "name": "web-2",
          "arn": "arn:aws:ec2:us-east-1:111111111111:instance/i-0web2",
          "type": "EC2",
          "account_id": "111111111111",
          "dataset": "sample"
        },
        {
          "id": "web-1",
          "name": "web-1",
          "arn": "arn:aws:ec2:us-east-1:111111111111:instance/i-0web1",
          "type": "EC2",
          "account_id": "111111111111",
          "dataset": "sample"
        },
        "... 3 more"
      ]
    }
  }
}
```

A Lambda function by the resource part of its ARN:

Called with the arguments below, `get_asset` returned this `structuredContent`.

```json
{"ref": "function:api-handler", "include_findings": false, "max_relations": 1}
```

```json
{
  "id": "api-handler",
  "name": "api-handler",
  "type": "LAMBDA_FUNCTION",
  "provider": "AWS",
  "region": "us-east-1",
  "account_id": "111111111111",
  "arn": "arn:aws:lambda:us-east-1:111111111111:function:api-handler",
  "internet_exposed": false,
  "open_findings": 1,
  "max_severity": "LOW",
  "uri": "cloudg://assets/api-handler",
  "tags": {
    "owner": "api-team"
  },
  "dataset": "sample",
  "service": "lambda",
  "relations": {
    "outgoing": {
      "ASSUMES_ROLE": 1,
      "LOGS_TO": 1,
      "REFERENCES": 1,
      "USES_IMAGE": 1
    },
    "incoming": {
      "INVOKES": 2
    },
    "sample": [
      {
        "id": "e-lambda-role",
        "source": "api-handler",
        "source_name": "api-handler",
        "target": "lambda-role",
        "target_name": "api-lambda-role",
        "edge_type": "ASSUMES_ROLE",
        "relationship": null
      }
    ],
    "total": 6,
    "truncated": true
  },
  "dependencies": {
    "direct_depends_on": 6,
    "direct_dependents": 0
  },
  "degree": {
    "in": 2,
    "out": 4
  },
  "metadata_keys": [
    "runtime"
  ],
  "collected_at": "2026-01-15T12:00:00+00:00"
}
```

The result also carried these resource links in `content`:

```json
[
  {
    "type": "resource_link",
    "uri": "cloudg://assets/api-handler",
    "name": "api-handler",
    "title": "LAMBDA_FUNCTION api-handler",
    "mimeType": "application/json"
  },
  {
    "type": "resource_link",
    "uri": "cloudg://assets/api-handler/neighbors",
    "name": "api-handler neighbors",
    "mimeType": "application/json"
  }
]
```

The graph tools (`neighbors`, `get_edges`, `find_paths`, `attack_paths`, `lateral_movement_paths`, `subgraph_export`) accept two more forms. `internet`, `public`, `0.0.0.0/0` and `::/0` all mean the internet. The entry points are found the way the reachability analysis finds them: the `0.0.0.0/0` and `::/0` nodes and the source of every ingress edge whose CIDR is `0.0.0.0/0`, `::/0` or an Azure `Internet`, `Any` or `*` tag. `neighbors` and `subgraph_export` start from the first entry point (`0.0.0.0/0` when it exists); `find_paths` and `attack_paths` start from a virtual node, `__internet__` (shown as `internet`), linked to every entry point, so an Azure-only dataset works too. Without any entry point they fail with `This dataset has no internet node (no internet-sourced ingress rules or INTERNET_EXPOSED edges). Use internet_exposure to see assets flagged as exposed.` Any other placeholder node in the graph (a CIDR, an external principal) can be passed by its node id.

Most results name assets by their internal `id` (`cross_account_edges` and the keys in `diff_datasets` use ARNs). Pass ids back when you chain calls; they are the only form that never becomes ambiguous.

### Pagination

List tools take `limit` and `cursor` and return an envelope:

| Field | Meaning |
|---|---|
| `total` | Matches before paging. |
| `offset` | Index of the first item on this page. |
| `returned` | Items on this page. |
| `next_cursor` | Pass it back as `cursor` for the next page; `null` on the last page. |
| `truncated` | `true` when more pages exist. |
| `items` | The page. |

`limit` defaults to 50 and allows 1 to 500 unless the tool's table says otherwise. A cursor looks like `c3.054790bd1d07`: `c`, the offset of the next item, a dot, then the first 12 hex digits of a SHA-256 over the dataset name, the dataset `version`, an id of that particular load of the dataset and the query arguments (`limit` excluded, so the page size may change between pages). The format is short and dotted on purpose: the privacy policies redact long base64-looking strings as secrets, and a redacted cursor could not be passed back.

A cursor only works with the query and dataset version that produced it. Change a filter, mutate the dataset (suppress, ingest, normalise, add reachability findings, run scanners), or load a new dataset under the same name, and the old cursor fails with an invalid-arguments error instead of returning a wrong page. The first two pages of a risk-sorted search:

Called with the arguments below, `find_assets` returned this `structuredContent`.

```json
{"sort_by": "risk", "limit": 3, "fields": ["name", "type", "max_severity", "open_findings"]}
```

```json
{
  "dataset": "sample",
  "total": 44,
  "offset": 0,
  "returned": 3,
  "next_cursor": "c3.054790bd1d07",
  "truncated": true,
  "items": [
    {
      "id": "sg-admin",
      "name": "sg-admin",
      "type": "SECURITY_GROUP",
      "max_severity": "CRITICAL",
      "open_findings": 1
    },
    {
      "id": "bastion",
      "name": "bastion",
      "type": "EC2",
      "max_severity": "HIGH",
      "open_findings": 1
    },
    {
      "id": "logs-bucket",
      "name": "prod-logs",
      "type": "S3_BUCKET",
      "max_severity": "HIGH",
      "open_findings": 1
    }
  ]
}
```

Called with the arguments below, `find_assets` returned this `structuredContent`.

```json
{
  "sort_by": "risk",
  "limit": 3,
  "cursor": "c3.054790bd1d07",
  "fields": [
    "name",
    "type",
    "max_severity",
    "open_findings"
  ]
}
```

```json
{
  "dataset": "sample",
  "total": 44,
  "offset": 3,
  "returned": 3,
  "next_cursor": "c6.054790bd1d07",
  "truncated": true,
  "items": [
    {
      "id": "az-nsg",
      "name": "jump-nsg",
      "type": "NSG",
      "max_severity": "CRITICAL",
      "open_findings": 1
    },
    {
      "id": "gcp-gcs",
      "name": "raw-uploads",
      "type": "GCS_BUCKET",
      "max_severity": "HIGH",
      "open_findings": 1
    },
    {
      "id": "web-1",
      "name": "web-1",
      "type": "EC2",
      "max_severity": "HIGH",
      "open_findings": 1
    }
  ]
}
```

Reusing that cursor with `sort_by: "name"` fails, and so does anything that is not a cursor:

```json
{
  "tool": "find_assets",
  "arguments": {
    "sort_by": "name",
    "limit": 3,
    "cursor": "c3.054790bd1d07"
  },
  "isError": true,
  "text": "Stale cursor: the query arguments or the dataset changed since it was issued. Repeat the call without cursor to start again.",
  "_meta": {
    "cloudg/error_code": -32602
  }
}
```

```json
{
  "tool": "find_assets",
  "arguments": {
    "cursor": "eyJvZmZzZXQiOjN9"
  },
  "isError": true,
  "text": "Invalid cursor. Pass the next_cursor value from the previous result unchanged, or omit cursor to start from the first page.",
  "_meta": {
    "cloudg/error_code": -32602
  }
}
```

Paginated with a cursor: `find_assets`, `list_accounts`, `unresolved_references`, `get_edges`, `internet_exposure`, `cross_account_edges`, `list_findings`, `list_controls`, `compliance_gaps`, `relation_groups` (with `group`) and `rag_chunks`.

Other list tools return the first `limit` or `top` items with `total`, `returned` and `truncated` and no cursor: `list_tags`, `depends_on`, `dependents`, `findings_for_asset`, `reachability_findings`, the three lists of `security_coverage`, `control_status`, and the `graph_reachable` block of `internet_exposure`. `attack_paths` and `lateral_movement_paths` report `total_found` and `truncated`. `count_assets` and `findings_summary` report `group_count` or `truncated` for their groups.

### Field projection

`find_assets` and `list_findings` take `fields`, a list of keys to keep in each item. `id` is always kept and comes first. Unknown names fail before any work is done:

```json
{
  "tool": "find_assets",
  "arguments": {
    "fields": [
      "owner"
    ]
  },
  "isError": true,
  "text": "Unknown field(s) owner. Valid fields: id, name, type, provider, region, account_id, arn, internet_exposed, open_findings, max_severity, tags, uri",
  "_meta": {
    "cloudg/error_code": -32602
  }
}
```

| Tool | Valid `fields` |
|---|---|
| `find_assets` | `id`, `name`, `type`, `provider`, `region`, `account_id`, `arn`, `internet_exposed`, `open_findings`, `max_severity`, `tags`, `uri` |
| `list_findings` | `id`, `title`, `severity`, `risk_score`, `source_tool`, `resource_id`, `resource_arn`, `asset_id`, `asset_name`, `compliance_frameworks`, `is_suppressed`, `cvss_score`, `detected_at`, `uri` |

`tags` is the only asset field that is off by default. `find_assets` adds it to each item only when `fields` asks for it.

### Sorting

| Tool | Order |
|---|---|
| `find_assets` | `sort_by`: `name` (case-insensitive, then id), `type`, `region`, `account`, `risk`, `findings`. `risk` and `findings` start with the highest; `descending: true` reverses whichever order applies. |
| `list_findings` | `sort_by`: `risk` (risk_score, then severity, then id, highest first), `severity` (severity, then risk_score), `detected_at` (newest first), `title`, `source_tool` (then risk_score). |
| `internet_exposure` | Most sensitive ports open first, then no WAF before WAF, then most open findings, then name. |
| `findings_for_asset` | risk_score, highest first. |
| `top_risks` | Score, highest first, then asset name. |
| `attack_paths` | Path score, highest first, then shortest. |
| `lateral_movement_paths` | Highest crown-jewel weight on the chain first, then shortest. |
| `find_paths` | Shortest first. |
| `list_controls` (`source: "dataset"`) | Worst open severity, then most open findings, then control id. |
| `compliance_gaps` | Worst gap severity, then internet-exposed first, then most gap findings, then name. |
| `count_assets`, `findings_summary` | Largest group first (ties by key). `findings_summary` with `group_by: "severity"` uses severity order instead. |
| `list_accounts`, `list_regions`, `list_asset_types`, `list_tags` | Most assets first. |
| `centrality_top` | Score, highest first. |

### Severity

Severities rank `CRITICAL` (4) > `HIGH` (3) > `MEDIUM` (2) > `LOW` (1) > `INFO` (0). `min_severity` keeps items at or above the given level. Severity arguments are case-insensitive and also accept `-` or spaces for `_`. An unknown value fails with the valid list:

```json
{
  "tool": "list_findings",
  "arguments": {
    "min_severity": "SEVERE"
  },
  "isError": true,
  "text": "Unknown severity. Valid values: CRITICAL, HIGH, MEDIUM, LOW, INFO",
  "_meta": {
    "cloudg/error_code": -32602,
    "cloudg/error_data": {
      "value": "SEVERE",
      "valid": [
        "CRITICAL",
        "HIGH",
        "MEDIUM",
        "LOW",
        "INFO"
      ],
      "close_matches": []
    }
  }
}
```

`max_severity` in an asset brief is the worst severity among the asset's open (not suppressed) findings, or `null`. `count_assets` with `group_by: "severity"` reports assets without open findings under `NONE`.

### Enumerated arguments

Asset types, edge types, providers and relation groups are parsed the same way as severities: case-insensitive, with `-` and spaces read as `_`. A miss names up to three close values in the message and lists the valid ones (the first 30 when there are more). `error_data` holds the value that was passed (`value`), every valid value (`valid`) and the close matches (`close_matches`):

```json
{
  "tool": "neighbors",
  "arguments": {
    "ref": "web-1",
    "edge_types": [
      "ASSUMES"
    ]
  },
  "isError": true,
  "text": "Unknown edge type. Did you mean ASSUMES_ROLE? Valid values: SECURITY_GROUP_RULE, NACL_RULE, ROUTE, IAM_TRUST, IAM_POLICY_ATTACHMENT, CONTAINS, PEERING, LOAD_BALANCER_TARGET, INTERNET_EXPOSED, ATTACHED...",
  "_meta": {
    "cloudg/error_code": -32602,
    "cloudg/error_data": {
      "value": "ASSUMES",
      "valid": [
        "SECURITY_GROUP_RULE",
        "NACL_RULE",
        "ROUTE",
        "... 17 more"
      ],
      "close_matches": [
        "ASSUMES_ROLE"
      ]
    }
  }
}
```

The valid values come from `describe_schema`, `list_asset_types` (only the types present in a dataset) or the `cloudg://schema/*` resources.

### Briefs

Most tools describe assets, edges and findings with the same compact objects.

An asset brief (`asset_brief` in `cloudg/mcp/catalog/_common.py`):

| Field | Meaning |
|---|---|
| `id` | Internal asset id. |
| `name` | Display name. |
| `type` | `AssetType` value. |
| `provider` | `AWS`, `AZURE` or `GCP`. |
| `region` | Region, or `global`. |
| `account_id` | Account, subscription or project. |
| `arn` | ARN or cloud resource id; may be null. |
| `internet_exposed` | The collector's `is_internet_exposed` flag. |
| `open_findings` | Findings matched to the asset that are not suppressed. |
| `max_severity` | Worst severity among them, or null. |
| `uri` | `cloudg://assets/{id}`, readable as a resource. |
| `tags` | Only where noted (`get_asset`, `find_assets` with `fields`). |

Path tools use a shorter hop brief with `id`, `name`, `type`, `account_id`, `internet_exposed`, `open_findings` and `max_severity`; null values are left out. Graph placeholders (the internet node, a CIDR, an external id) appear as `{"id", "name", "type": "EXTERNAL", "external": true}`.

An edge brief:

| Field | Meaning |
|---|---|
| `id` | Edge id. |
| `source`, `target` | Endpoint ids. |
| `source_name`, `target_name` | Asset names (the id when the endpoint is not an asset). |
| `edge_type` | `EdgeType` value. |
| `relationship` | Semantic relationship (`CROSS_ACCOUNT_TRUST`, `ENCRYPTED_BY_KMS`...) or null. |
| `port_range`, `protocol`, `cidr`, `description` | Present only when set. |
| `ports` | Explicit ports, first 20, present only when set. |
| `direction` | `ingress` or `egress`, only on `SECURITY_GROUP_RULE` and `NACL_RULE` edges. |
| `cross_account` | `true` when both ends are assets in different accounts; absent otherwise. |

A finding brief:

| Field | Meaning |
|---|---|
| `id` | Finding id. |
| `title`, `severity`, `source_tool` | As reported. |
| `risk_score` | 0 to 10, see [Risk scores](#risk-scores). |
| `resource_id`, `resource_arn` | The resource as the scanner named it. |
| `asset_id`, `asset_name` | The mapped asset, or null when the resource matched nothing. |
| `compliance_frameworks` | Framework tags on the finding. |
| `is_suppressed` | Suppression flag. |
| `cvss_score` | CVSS, or null. |
| `detected_at` | ISO 8601 timestamp. |
| `uri` | `cloudg://findings/{id}`. |

A finding is matched to an asset by its `resource_id` and `resource_arn`, with the same `AssetIndex` tiers as an asset reference: id, then ARN, unique name, unique ARN tail, ARN resource part, and a name in any letter case. A name or tail several assets share matches nothing. Findings that match nothing count as `unmapped` in `findings_summary` and show `asset_id: null`.

### Risk scores

Four different scores appear in results:

- `risk_score` on a finding is computed by the `Finding` model: CRITICAL 9.5, HIGH 7.5, MEDIUM 5.0, LOW 2.5, INFO 0.5; with a CVSS score it is the mean of that value and the CVSS, rounded to one decimal. `f-web-cve` (HIGH, CVSS 8.1) scores 7.8.
- `find_assets` with `sort_by: "risk"` ranks on the worst open finding's `risk_score`, plus 2.0 when the asset is internet-exposed, then the number of open findings.
- `top_risks` scores an asset as `max_finding_risk * exposure * blast * volume`. `exposure` is 1.5 when the asset is flagged internet-exposed or the reachability analysis reaches it from the internet over network-flow edges (`internet_reachable`), else 1.0. `blast` is `1 + min(1, log10(1 + d) / 2)` where `d` counts transitive dependents up to depth 6. `volume` is `1 + min(0.5, 0.05 * (open findings - 1))`. The result is rounded to two decimals, and each item carries the components.
- `attack_paths` scores a path as `target weight + 0.5 * min(10, open findings on the path) - 0.3 * (hops - 1)`. Target weights come from the crown-jewel table: relational databases 10; DynamoDB, data warehouses, secrets and key vaults 9; KMS keys and buckets 8; file systems and search domains 7; caches and access keys 6; IAM roles and users 5. An explicit `target` always weighs 10.
- `blast_radius.network.risk_score` comes from `ReachabilityAnalyzer.compute_blast_radius`: 0.5 per reachable node plus 2.0 per reachable sensitive data store, capped at 10.

### Sensitivity, capabilities and policies

Each primitive declares a sensitivity and the side effects it needs. Policies use both to decide whether a caller sees the primitive and what transforms its output goes through ([MCP_PRIVACY.md](MCP_PRIVACY.md) has the details).

| Sensitivity | Used for |
|---|---|
| `public` | Vocabulary and catalog data with no tenant information (meta tools, `list_frameworks`, `list_detectors`, schema and docs resources). |
| `internal` | Counts and summaries. |
| `confidential` | Identifiers, topology and findings. Most tools. |
| `restricted` | Raw metadata and anything that may hold secrets: `get_asset_metadata`, `privacy_audit_log`, `reveal_token`. Also the outputs the privacy layer cannot look inside, because they are one opaque string: `sparql_query` (its rows are keyed by the query's own variable names), `subgraph_export` and the text graph and ontology resources (`cloudg://graph/{format}`, `cloudg://ontology/turtle`, `cloudg://ontology/{format}`). A profile with a `confidential` ceiling hides all of them. |

| Capability | Meaning | Tools |
|---|---|---|
| `read_state` | Reads loaded datasets or workspace state. | Default for every tool that touches data, and `rate_limit_status`. |
| `write_state` | Changes the in-memory workspace. | `load_dataset`, `select_dataset`, `unload_dataset`, `snapshot_dataset`, `suppress_findings`, `unsuppress_findings`, `ingest_reports`, `normalise_findings`, `reachability_findings`, `map_inventory`, `collect_assets`, `run_scanners`, `run_pipeline`. |
| `read_fs` | Reads files. | `load_dataset`, `ingest_reports`, `run_scanners` (for `iac_dir`). |
| `write_fs` | Writes files under the output directory. | `export_ontology`, `export_terraform`, `export_report`, `run_scanners`, `run_pipeline`. |
| `cloud_access` | Calls provider APIs with the server's credentials. | `map_inventory`, `collect_assets`, `run_scanners`, `run_pipeline`. |
| `exec` | Starts external processes. | `run_scanners`, `run_pipeline`. |
| `reveal` | Reverses pseudonymisation. | `reveal_token`. |

`list_frameworks` and the four meta tools declare no capability at all. A policy can cap sensitivity (`max_sensitivity`) and deny capabilities; with `hide_denied: true` (the default in the shipped profiles) a denied tool disappears from `tools/list`, and calling it anyway gives `Unknown tool`. Measured with `layer.tools_wire()` for the default local principal, each built-in profile hides these tools:

| Profile | Visible tools | Hidden |
|---|---|---|
| `open` | 74 | none |
| `standard` | 73 | `reveal_token` |
| `read_only` | 66 | `collect_assets`, `export_ontology`, `export_report`, `export_terraform`, `map_inventory`, `reveal_token`, `run_pipeline`, `run_scanners` |
| `airgapped` | 69 | `collect_assets`, `map_inventory`, `reveal_token`, `run_pipeline`, `run_scanners` |
| `audit` | 66 | `collect_assets`, `export_ontology`, `export_report`, `export_terraform`, `map_inventory`, `reveal_token`, `run_pipeline`, `run_scanners` |
| `strict` | 61 | `collect_assets`, `export_ontology`, `export_report`, `export_terraform`, `get_asset_metadata`, `map_inventory`, `preview_transform`, `privacy_audit_log`, `reveal_token`, `run_pipeline`, `run_scanners`, `sparql_query`, `subgraph_export` |
| `soc-analyst` | 62 | `collect_assets`, `export_ontology`, `export_report`, `export_terraform`, `get_asset_metadata`, `map_inventory`, `privacy_audit_log`, `reveal_token`, `run_pipeline`, `run_scanners`, `sparql_query`, `subgraph_export` |

Under `soc-analyst` the `analyst` role sees 60 tools (it also loses `rate_limit_status` and `terraform_preview`) and the `lead` role 70 (only the four live tools are hidden).

The CLI flag `--read-only` is different from the `read_only` profile: it removes tools with `write_fs`, `cloud_access` or `exec` and every tool annotated destructive, so it also drops `unload_dataset`.

### Annotations

Every tool sets the four MCP behaviour hints. When a tool leaves one unset, `ToolSpec._derive_hints` fills it from the capabilities: `readOnlyHint` is false when the tool needs `write_state`, `write_fs` or `exec`; `destructiveHint` defaults to false; `openWorldHint` is true only with `cloud_access`; read-only tools default to idempotent. The per-tool lines below show the final values. Only `unload_dataset` is destructive, and only `map_inventory`, `collect_assets`, `run_scanners` and `run_pipeline` are open-world. The tools that change state but are not read-only and not idempotent are `load_dataset`, `snapshot_dataset`, `ingest_reports`, `reachability_findings` and the four collecting live tools.

On the wire the annotations and cloudg's own metadata look like this (from `find_assets`):

```json
{
  "title": "Find assets",
  "readOnlyHint": true,
  "destructiveHint": false,
  "idempotentHint": true,
  "openWorldHint": false
}
```

```json
{
  "cloudg/category": "inventory",
  "cloudg/sensitivity": "confidential",
  "cloudg/tags": [
    "start-here"
  ]
}
```

`cloudg/tags` marks the four tools tagged `start-here` (`workspace_status`, `find_assets`, `list_findings`, `list_capabilities`).

### Output schemas

18 tools publish an `outputSchema`: `workspace_status`, `diff_datasets`, `dataset_summary`, `find_assets`, `get_asset`, `count_assets`, `neighbors`, `get_edges`, `find_paths`, `attack_paths`, `lateral_movement_paths`, `depends_on`, `dependents`, `list_findings`, `findings_for_asset`, `top_risks`, `compliance_summary` and `sparql_query`. Every property in these schemas is optional and every object allows extra keys, so projection and redaction never make a result invalid. The layer still withholds `outputSchema` from `tools/list` whenever the caller's output pipeline is not empty, because masking can change value types; under `standard` no tool advertises one, under `open` all 18 do.

### Resource links

Tools attach `resource_link` content blocks pointing at the resources that hold more detail. A link has `uri`, `name`, an optional `title`, `mimeType` and sometimes `annotations.priority` (1.0 on the dataset summary link of the live tools). Which tool links what is listed in each entry. Links go through the same output transforms as the result, so a pseudonymised name stays pseudonymised in the link.

### Errors

There are two kinds of failure.

A tool error comes back as a normal result with `isError: true`, the message in `content[0].text` and the details in `_meta`: `cloudg/error_code` and, when there is structured detail, `cloudg/error_data`. The model can read it and retry. The message never repeats the value the caller passed and never lists names from the dataset: the value, close matches and valid choices are in `cloudg/error_data` (`value`, `suggestions`, `valid`, `close_matches`), which goes through the caller's output pipeline like a result, so a pseudonymising policy pseudonymises them. Bad arguments, unknown datasets, unresolved references, path violations, denied calls, timeouts and handler exceptions all take this route. Argument validation happens before the handler runs and reports pydantic's error list:

```json
{
  "content": [
    {
      "type": "text",
      "text": "Invalid arguments: limit: Input should be a valid integer, unable to parse string as an integer"
    }
  ],
  "isError": true,
  "_meta": {
    "cloudg/error_code": -32602,
    "cloudg/error_data": [
      {
        "loc": "limit",
        "msg": "Input should be a valid integer, unable to parse string as an integer",
        "type": "int_parsing"
      }
    ]
  }
}
```

A protocol error is raised instead of returned. `call_tool` raises `NotFoundError` (JSON-RPC -32602) for a tool that does not exist or that the policy hides:

```json
{
  "error": "NotFoundError",
  "code": -32602,
  "message": "Unknown tool: no_such_tool"
}
```

Resource reads and prompt requests raise for every failure (unknown URI, unknown asset, missing prompt argument), and adapters turn that into a JSON-RPC error.

| `cloudg/error_code` | Raised for |
|---|---|
| `-32602` | Invalid arguments, unknown dataset, asset, finding, control, enum value or cursor, a dataset name that is already taken. `NotFoundError` and `InvalidArgumentsError` share this code. |
| `-31001` | Access denied: a path outside the allowed roots, an output path escaping the output directory, a policy denial, or `force=true` on a live tool without the admin or operator role. |
| `-31029` | Rate limited: a policy rate limit, or the live operation guard refusing a collection (cooldown, busy, caller quota; see [Live operation guard](#live-operation-guard)). |
| `-32603` | Generic layer error, used by the live tools' credential preflight. |
| `"timeout"` | The tool ran past its timeout (300 s by default, longer where the entry says so). |
| `"handler_error"` | An unexpected exception in a tool handler; the text is `ExceptionType: message`, passed through the output pipeline. Resource and prompt handlers never send raw exception text. |

Tools never accept arguments outside their schema (`additionalProperties: false`):

```json
{
  "tool": "find_assets",
  "arguments": {
    "name": "web-1"
  },
  "isError": true,
  "text": "Invalid arguments: name: Extra inputs are not permitted",
  "_meta": {
    "cloudg/error_code": -32602,
    "cloudg/error_data": [
      {
        "loc": "name",
        "msg": "Extra inputs are not permitted",
        "type": "extra_forbidden"
      }
    ]
  }
}
```

### Progress and change notifications

Two kinds of tool report progress when the client sends a progress token. `ontology_stats`, `sparql_query`, `ontology_neighbourhood`, `relation_groups` and `export_ontology` send `0/1 building ontology for N assets` and `1/1 ontology built` the first time a dataset's ontology is built; later calls use the cache and send nothing. The live tools report one notification per pipeline phase and a final `done` (see [Live](#live)). Progress values only increase; the context drops any notification that does not.

The workspace also tells the layer when data changes. Loading or unloading a dataset sends `notifications/resources/list_changed`; any change also sends `notifications/resources/updated` for `cloudg://workspace`, `cloudg://datasets` and `cloudg://datasets/{name}/summary`. Selecting, snapshotting, suppressing, ingesting, normalising and the live tools all trigger these.

## Tool reference

Each entry starts with a metadata line taken from the registry: category, sensitivity, capabilities, the four annotation values, whether an `outputSchema` is published, and the timeout. The argument tables come from the published `inputSchema`; where the schema has no description, the table adds one.

## Workspace

The workspace holds named datasets in memory. A dataset is one loaded inventory map, findings report or scanner output, or the result of a live collection. Derived structures (lookup indexes, the NetworkX graph, the dependency graph, centrality, the RDF ontology, RAG chunks) are built on first use and cached per dataset, and every mutation drops the cache and bumps the dataset's `version`. At most 16 datasets are kept; adding a 17th evicts the oldest one that is not active. Names must match `^[A-Za-z0-9_.\-]{1,64}$`. A tool that creates a dataset under a name that is already loaded (`load_dataset`, `snapshot_dataset`, `ingest_reports` with `new_dataset`, the live tools) fails before doing any work unless it is called with `replace: true`; the error suggests a free name. Files are read only inside the allowed roots and written only under the output directory, both shown by `workspace_status`.

### `workspace_status`

Category `workspace` · sensitivity `internal` · capabilities `read_state` · readOnly true, destructive false, idempotent true, openWorld false · outputSchema yes · timeout: layer default (300 s)

Shows every loaded dataset, which one is active, and the directories file tools may use. Call it first. With nothing loaded it adds `next_steps`:

Arguments: none.

Called with the arguments below, `workspace_status` returned this `structuredContent`.

```json
{}
```

```json
{
  "active_dataset": null,
  "datasets": [],
  "allowed_roots": [
    "<estate>"
  ],
  "output_dir": "<estate>/out",
  "providers_configured": [
    "aws"
  ],
  "next_steps": [
    "load_dataset(path='<dir with inventory-map.json or findings.json>')",
    "map_inventory(providers=['aws']) to collect live data (needs credentials)"
  ]
}
```

After loading, each dataset appears in the compact form also used by `list_datasets`, and a link to `cloudg://workspace` is attached:

Called with the arguments below, `workspace_status` returned this `structuredContent`.

```json
{}
```

```json
{
  "active_dataset": "sample",
  "datasets": [
    {
      "name": "sample",
      "kind": "inventory",
      "source": "<estate>/inventory",
      "loaded_at": "2026-10-09T14:25:11+00:00",
      "version": 0,
      "providers": [
        "aws",
        "... 2 more"
      ],
      "assets": 44,
      "edges": 56,
      "findings": 12,
      "compliance_results": 8,
      "cached": {
        "graph": false,
        "dependency_graph": false,
        "ontology": false,
        "centrality": false,
        "rag_entity": false
      }
    },
    "... 1 more"
  ],
  "allowed_roots": [
    "<estate>"
  ],
  "output_dir": "<estate>/out",
  "providers_configured": [
    "aws"
  ]
}
```

The result also carried these resource links in `content`:

```json
[
  {
    "type": "resource_link",
    "uri": "cloudg://workspace",
    "name": "workspace",
    "title": "Workspace status",
    "mimeType": "application/json"
  }
]
```

Fields: `active_dataset` (name or null); `datasets[]` with `name`, `kind` (`inventory`, `report`, `generic`, `live`, `snapshot`, or a scanner name), `source` (file path, `live`, `inline`, `ingest` or `snapshot of X`), `loaded_at`, `version`, `providers`, counts of `assets`, `edges`, `findings` and `compliance_results`, and `cached`, which says whether the graph, dependency graph, ontology, centrality and entity RAG chunks are already built; `allowed_roots`; `output_dir`; `providers_configured` (from the cloudg config); `next_steps` only when nothing is loaded.

Allowed roots come from `Workspace(allowed_roots=...)`, else `$CLOUDG_MCP_ALLOWED_ROOTS` (`os.pathsep`-separated), else the current directory plus the configured report directory, leaving out either one when it is `/` or the home directory (with neither left, the workspace refuses to start). The output directory is added to the roots if it is outside them.

Related: `load_dataset`, `list_datasets`, `dataset_summary`.

### `list_datasets`

Category `workspace` · sensitivity `internal` · capabilities `read_state` · readOnly true, destructive false, idempotent true, openWorld false · outputSchema no · timeout: layer default (300 s)

The dataset listing without the directory information, with an `active` flag on each entry.

Arguments: none.

Called with the arguments below, `list_datasets` returned this `structuredContent`.

```json
{}
```

```json
{
  "active_dataset": "sample",
  "datasets": [
    {
      "name": "sample",
      "kind": "inventory",
      "source": "<estate>/inventory",
      "loaded_at": "2026-10-09T14:25:12+00:00",
      "version": 0,
      "providers": [
        "aws",
        "... 2 more"
      ],
      "assets": 44,
      "edges": 56,
      "findings": 12,
      "compliance_results": 8,
      "cached": {
        "graph": false,
        "dependency_graph": false,
        "ontology": false,
        "centrality": false,
        "rag_entity": false
      },
      "active": true
    },
    "... 1 more"
  ],
  "total": 2
}
```

Related: `select_dataset`, `unload_dataset`.

### `load_dataset`

Category `workspace` · sensitivity `internal` · capabilities `read_fs`, `read_state`, `write_state` · readOnly false, destructive false, idempotent false, openWorld false · outputSchema no · timeout: layer default (300 s)

Loads a file or directory as a dataset and makes it active unless `activate` is false. Returns `loaded` (the name), `active`, and every field of `dataset_summary`, and links the `cloudg://datasets/{name}/summary` resource.

| Argument | Type | Default | Constraints | Description |
|---|---|---|---|---|
| `path` | string | required | min length 1 | File or directory inside an allowed root: inventory-map.json (or its directory), a cloudg findings.json report, a generic {assets, edges, findings} JSON, or native Prowler / ScoutSuite / Checkov / Trivy output. |
| `name` | string | `""` |  | Dataset name; default derives from the path. |
| `kind` | string | `"auto"` | one of `auto`, `inventory`, `report`, `generic`, `prowler`, `scoutsuite`, `checkov`, `trivy` | Content type; 'auto' detects it. |
| `activate` | boolean | `true` |  | Make it the active dataset. |
| `replace` | boolean | `false` |  | Overwrite an existing dataset with the same name (otherwise a name clash is an error). |

`path` is resolved against the first allowed root when relative, symlinks included, and must exist inside an allowed root. Without `name` the dataset is named after the parent directory for an `inventory-map.json` file and after the file or directory stem otherwise, with `-2`, `-3`... added when the name is taken. An explicit `name` that is already loaded is refused before the file is read, unless `replace` is true. With `kind: "auto"` the content is detected as follows:

| Path | Detected kind |
|---|---|
| Directory with `inventory-map.json` | `inventory` |
| Directory with `findings.json` | `report` |
| Directory containing `scoutsuite_results*.js` | `scoutsuite` |
| Directory containing `results_json.json` | `checkov` |
| `.js` file or file named `scoutsuite_results*` | `scoutsuite` |
| JSON object with `findings` and `metadata` or `summary` | `report` |
| JSON object with `assets` and `edges` and `unresolved_references` or `regions` | `inventory` |
| Other JSON object with `assets`, `edges` or `findings` | `generic` |
| JSON object with `Results` and `ArtifactName`, `SchemaVersion` or `ArtifactType` | `trivy` |
| JSON object with `check_type`, or a `results` object | `checkov` |
| JSON object with `Findings` | `prowler` |
| JSON array whose first item has `check_type` | `checkov` |
| JSON array whose first item has `ProductArn` or `SchemaVersion` | `prowler` |
| JSON array whose first record looks like OCSF (Prowler 4's default output) | `prowler` |
| JSON array whose first item has `severity`, `title` or `resource_id` | `generic` |
| Other JSON Lines | `prowler` (ASFF or OCSF records) |

An inventory load also reads `findings.json` from the same directory when present (its path lands in the dataset metadata as `findings_source`). Scanner output is parsed with the cloudg ingest parsers and normalised. The Prowler parser reads ASFF and OCSF (the default since Prowler 4), record by record, and Prowler's passing checks give `PASS` results for the ruleset controls only they cover. A Prowler output directory is not detected; pass `kind: "prowler"` for it.

Loading the sample inventory directory:

Called with the arguments below, `load_dataset` returned this `structuredContent`.

```json
{"path": "<estate>/inventory", "name": "sample"}
```

```json
{
  "loaded": "sample",
  "active": true,
  "dataset": "sample",
  "kind": "inventory",
  "source": "<estate>/inventory",
  "loaded_at": "2026-10-09T14:25:12+00:00",
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
  "severity_breakdown": {
    "CRITICAL": 2,
    "HIGH": 5,
    "MEDIUM": 2,
    "LOW": 1,
    "INFO": 1
  },
  "accounts": 5,
  "regions": 5,
  "internet_exposed": 6,
  "cross_account_edges": 3,
  "unlinked_assets": 2,
  "unresolved_references": 1,
  "compliance_frameworks": [
    "CIS-AWS",
    "CIS-Azure",
    "CIS-GCP",
    "... 2 more"
  ],
  "assets_by_type": {
    "SECURITY_GROUP": 4,
    "IAM_ROLE": 4,
    "CLOUD_ACCOUNT": 3,
    "EC2": 3,
    "S3_BUCKET": 3,
    "...": "10 more"
  },
  "assets_by_provider": {
    "AWS": 36,
    "AZURE": 5,
    "GCP": 3
  },
  "edges_by_type": {
    "CONTAINS": 12,
    "GOVERNS": 1,
    "SECURITY_GROUP_RULE": 4,
    "INTERNET_EXPOSED": 4,
    "ATTACHED_TO": 6,
    "...": "10 more"
  },
  "has_organization": true,
  "coverage_records": 1,
  "organization": {
    "id": "o-sample",
    "accounts": 2,
    "ous": 1,
    "control_tower": true,
    "governed_regions": [
      "us-east-1",
      "eu-west-1"
    ]
  }
}
```

The result also carried these resource links in `content`:

```json
[
  {
    "type": "resource_link",
    "uri": "cloudg://datasets/sample/summary",
    "name": "sample summary",
    "title": "Dataset summary",
    "mimeType": "application/json"
  }
]
```

Loading the report file as a second, inactive dataset by a relative path:

Called with the arguments below, `load_dataset` returned this `structuredContent`.

```json
{"path": "report/findings.json", "name": "report", "activate": false}
```

```json
{
  "loaded": "report",
  "active": false,
  "dataset": "report",
  "kind": "report",
  "source": "<estate>/report/findings.json",
  "loaded_at": "2026-10-09T14:25:12+00:00",
  "version": 0,
  "providers": [
    "aws",
    "azure",
    "... 1 more"
  ],
  "total_assets": 44,
  "total_edges": 56,
  "total_findings": 12,
  "open_findings": 11,
  "suppressed_findings": 1,
  "severity_breakdown": {
    "CRITICAL": 2,
    "HIGH": 5,
    "MEDIUM": 2,
    "LOW": 1,
    "INFO": 1
  },
  "accounts": 5,
  "regions": 5,
  "internet_exposed": 6,
  "cross_account_edges": 3,
  "unlinked_assets": 2,
  "unresolved_references": 0,
  "compliance_frameworks": [
    "CIS-AWS",
    "CIS-Azure",
    "... 2 more"
  ],
  "assets_by_type": {
    "SECURITY_GROUP": 4,
    "IAM_ROLE": 4,
    "CLOUD_ACCOUNT": 3,
    "EC2": 3,
    "S3_BUCKET": 3,
    "...": "10 more"
  },
  "assets_by_provider": {
    "AWS": 36,
    "AZURE": 5,
    "GCP": 3
  },
  "edges_by_type": {
    "CONTAINS": 12,
    "IAM_TRUST": 2,
    "GOVERNS": 1,
    "SECURITY_GROUP_RULE": 4,
    "ATTACHED_TO": 6,
    "...": "10 more"
  },
  "has_organization": false,
  "coverage_records": 0
}
```

Errors:

```json
{
  "tool": "load_dataset",
  "arguments": {
    "path": "/etc/passwd"
  },
  "isError": true,
  "text": "Path /etc/passwd is outside the allowed roots (<estate>). Ask the operator to add its directory to the workspace's allowed roots.",
  "_meta": {
    "cloudg/error_code": -31001
  }
}
```

```json
{
  "tool": "load_dataset",
  "arguments": {
    "path": "nope.json"
  },
  "isError": true,
  "text": "Path does not exist: nope.json",
  "_meta": {
    "cloudg/error_code": -32602
  }
}
```

```json
{
  "tool": "load_dataset",
  "arguments": {
    "path": "report/findings.json",
    "name": "sample"
  },
  "isError": true,
  "text": "A dataset with that name already exists. Choose another name (the error data suggests a free one), or pass replace=true to overwrite it.",
  "_meta": {
    "cloudg/error_code": -32602,
    "cloudg/error_data": {
      "existing": "sample",
      "suggested": "sample-2"
    }
  }
}
```

Prowler OCSF output, one failing record for the root account's hardware MFA, as a third, inactive dataset:

Called with the arguments below, `load_dataset` returned this `structuredContent`.

```json
{"path": "scans/prowler-ocsf.json", "name": "ocsf", "activate": false}
```

```json
{
  "loaded": "ocsf",
  "active": false,
  "dataset": "ocsf",
  "kind": "prowler",
  "source": "<estate>/scans/prowler-ocsf.json",
  "loaded_at": "2026-10-10T06:24:43+00:00",
  "version": 0,
  "providers": [],
  "total_assets": 0,
  "total_edges": 0,
  "total_findings": 1,
  "open_findings": 1,
  "suppressed_findings": 0,
  "severity_breakdown": {
    "HIGH": 1
  },
  "accounts": 0,
  "regions": 0,
  "internet_exposed": 0,
  "cross_account_edges": 0,
  "unlinked_assets": 0,
  "unresolved_references": 0,
  "compliance_frameworks": [
    "AWS-Foundational-Security-Best-Practices-AWS",
    "CIS-AWS",
    "GDPR-AWS",
    "... 4 more"
  ],
  "assets_by_type": {},
  "assets_by_provider": {},
  "edges_by_type": {},
  "has_organization": false,
  "coverage_records": 0
}
```

Related: `workspace_status`, `ingest_reports` (add findings to an existing dataset), `map_inventory` (collect instead of load).

### `select_dataset`

Category `workspace` · sensitivity `internal` · capabilities `read_state`, `write_state` · readOnly false, destructive false, idempotent true, openWorld false · outputSchema no · timeout: layer default (300 s)

Makes a loaded dataset the default for every tool, resource and prompt. Returns `active_dataset` plus the dataset's listing entry.

| Argument | Type | Default | Constraints | Description |
|---|---|---|---|---|
| `name` | string | required | min length 1 | Dataset to activate. |

Called with the arguments below, `select_dataset` returned this `structuredContent`.

```json
{"name": "report"}
```

```json
{
  "active_dataset": "report",
  "name": "report",
  "kind": "report",
  "source": "<estate>/report/findings.json",
  "loaded_at": "2026-10-09T14:25:12+00:00",
  "version": 0,
  "providers": [
    "aws",
    "azure",
    "gcp"
  ],
  "assets": 44,
  "edges": 56,
  "findings": 12,
  "compliance_results": 8,
  "cached": {
    "graph": false,
    "dependency_graph": false,
    "ontology": false,
    "centrality": false,
    "rag_entity": false
  }
}
```

An unknown name fails, with the loaded datasets in `error_data` (see [The `dataset` argument](#the-dataset-argument)).

### `unload_dataset`

Category `workspace` · sensitivity `internal` · capabilities `read_state`, `write_state` · readOnly false, destructive true, idempotent true, openWorld false · outputSchema no · timeout: layer default (300 s)

Removes a dataset from memory. Files on disk are untouched; suppressions and ingested findings held only in memory are lost. When the active dataset is removed, the most recently added remaining dataset becomes active (or none). Returns `unloaded`, the new `active_dataset` and `remaining` names.

| Argument | Type | Default | Constraints | Description |
|---|---|---|---|---|
| `name` | string | required | min length 1 | Dataset to drop. |

Called with the arguments below, `unload_dataset` returned this `structuredContent`.

```json
{"name": "pre-ingest"}
```

```json
{
  "unloaded": "pre-ingest",
  "active_dataset": "after",
  "remaining": [
    "sample",
    "report",
    "after"
  ]
}
```

Related: `snapshot_dataset` (keep a copy first), `export_report` (persist to disk).

### `snapshot_dataset`

Category `workspace` · sensitivity `internal` · capabilities `read_state`, `write_state` · readOnly false, destructive false, idempotent false, openWorld false · outputSchema no · timeout: layer default (300 s)

Deep copies a dataset (assets, edges, findings, compliance results, coverage, organization, suppression reasons) under `new_name`, with `kind: "snapshot"` and `source: "snapshot of <name>"`. The copy is not activated. Take one before ingesting findings or re-collecting, then compare with `diff_datasets`. Returns `snapshot` plus the new dataset's listing entry.

| Argument | Type | Default | Constraints | Description |
|---|---|---|---|---|
| `new_name` | string | required | min length 1 | Name for the copy. |
| `dataset` | string | `""` |  | Dataset name (see list_datasets). Empty = the active dataset. |
| `replace` | boolean | `false` |  | Overwrite an existing dataset named new_name (otherwise a name clash is an error). |

Called with the arguments below, `snapshot_dataset` returned this `structuredContent`.

```json
{"new_name": "baseline"}
```

```json
{
  "snapshot": "baseline",
  "name": "baseline",
  "kind": "snapshot",
  "source": "snapshot of sample",
  "loaded_at": "2026-10-09T14:25:12+00:00",
  "version": 0,
  "providers": [
    "aws",
    "azure",
    "gcp"
  ],
  "assets": 44,
  "edges": 56,
  "findings": 12,
  "compliance_results": 8,
  "cached": {
    "graph": false,
    "dependency_graph": false,
    "ontology": false,
    "centrality": false,
    "rag_entity": false
  }
}
```

A `new_name` that is already loaded is refused unless `replace` is true:

```json
{
  "tool": "snapshot_dataset",
  "arguments": {
    "new_name": "report",
    "dataset": "ocsf-test"
  },
  "isError": true,
  "text": "A dataset with that name already exists. Choose another name (the error data suggests a free one), or pass replace=true to overwrite it.",
  "_meta": {
    "cloudg/error_code": -32602,
    "cloudg/error_data": {
      "existing": "report",
      "suggested": "report-2"
    }
  }
}
```

### `diff_datasets`

Category `workspace` · sensitivity `confidential` · capabilities `read_state` · readOnly true, destructive false, idempotent true, openWorld false · outputSchema yes · timeout: layer default (300 s)

Compares two datasets. Assets are matched on ARN (else id), so the same resource matches across collections even if internal ids differ. An asset counts as changed when its name, type, region, account, tags, exposure flag or metadata (hashed) differ. Edges are matched on (source key, target key, edge type, relationship) where keys are ARNs or ids. Findings are matched on (source tool, scanner check id or title, resource key).

| Argument | Type | Default | Constraints | Description |
|---|---|---|---|---|
| `base` | string | required | min length 1 | Baseline dataset (before). |
| `target` | string | `""` |  | Dataset to compare (after); empty = active. |
| `limit` | integer | `50` | 1..500 | Max items per section. |

Every section is `{count, items, truncated}` with at most `limit` items:

| Field | Content |
|---|---|
| `base`, `target` | Dataset names compared. |
| `assets.added`, `assets.removed` | Briefs with `id`, `key` (ARN or id), `name`, `type`, `account_id`, `region`. |
| `assets.changed` | Same brief plus `changed_fields`, and `internet_exposed: {before, after}` when exposure changed. |
| `assets.unchanged` | Count only. |
| `edges.added`, `edges.removed` | `source`, `target` (as keys), `edge_type`, `relationship`. |
| `findings.new`, `findings.resolved` | `id`, `title`, `severity`, `resource`, `source_tool`. |
| `findings.severity_changed` | The same plus `severity_before`. |
| `newly_internet_exposed` | Changed assets that became exposed plus added assets that are exposed. |

The example compares `baseline` (a snapshot of the sample) with `after`, a copy of the sample inventory directory edited by the capture script: the WAF and its `PROTECTS` edge removed, `web-2` made internet-exposed with a new `INTERNET_EXPOSED` edge and a changed owner tag, the SSH finding removed and the RDS backup finding raised from MEDIUM to HIGH.

Called with the arguments below, `diff_datasets` returned this `structuredContent`.

```json
{"base": "baseline", "target": "after"}
```

```json
{
  "base": "baseline",
  "target": "after",
  "assets": {
    "added": {
      "count": 0,
      "items": [],
      "truncated": false
    },
    "removed": {
      "count": 1,
      "items": [
        {
          "id": "waf-web",
          "key": "arn:aws:wafv2:us-east-1:111111111111:regional/webacl/web-acl/1",
          "name": "web-acl",
          "type": "WAF_WEB_ACL",
          "account_id": "111111111111",
          "region": "us-east-1"
        }
      ],
      "truncated": false
    },
    "changed": {
      "count": 1,
      "items": [
        {
          "id": "web-2",
          "key": "arn:aws:ec2:us-east-1:111111111111:instance/i-0web2",
          "name": "web-2",
          "type": "EC2",
          "account_id": "111111111111",
          "region": "us-east-1",
          "changed_fields": [
            "internet_exposed",
            "tags"
          ],
          "internet_exposed": {
            "before": false,
            "after": true
          }
        }
      ],
      "truncated": false
    },
    "unchanged": 42
  },
  "edges": {
    "added": {
      "count": 1,
      "items": [
        {
          "source": "0.0.0.0/0",
          "target": "arn:aws:ec2:us-east-1:111111111111:instance/i-0web2",
          "edge_type": "INTERNET_EXPOSED",
          "relationship": "INTERNET_REACHABLE"
        }
      ],
      "truncated": false
    },
    "removed": {
      "count": 1,
      "items": [
        {
          "source": "arn:aws:wafv2:us-east-1:111111111111:regional/webacl/web-acl/1",
          "target": "arn:aws:elasticloadbalancing:us-east-1:111111111111:loadbalancer/app/web-alb/abc",
          "edge_type": "PROTECTS",
          "relationship": null
        }
      ],
      "truncated": false
    }
  },
  "findings": {
    "new": {
      "count": 0,
      "items": [],
      "truncated": false
    },
    "resolved": {
      "count": 1,
      "items": [
        {
          "id": "f-ssh-open",
          "title": "Security group allows SSH (22) from 0.0.0.0/0",
          "severity": "CRITICAL",
          "resource": "arn:aws:ec2:us-east-1:111111111111:security-group/sg-0admin",
          "source_tool": "prowler"
        }
      ],
      "truncated": false
    },
    "severity_changed": {
      "count": 1,
      "items": [
        {
          "id": "f-db-backup",
          "title": "RDS backup retention below 7 days",
          "severity": "HIGH",
          "resource": "arn:aws:rds:us-east-1:111111111111:db:orders-db",
          "source_tool": "prowler",
          "severity_before": "MEDIUM"
        }
      ],
      "truncated": false
    }
  },
  "newly_internet_exposed": {
    "count": 1,
    "items": [
      {
        "id": "web-2",
        "key": "arn:aws:ec2:us-east-1:111111111111:instance/i-0web2",
        "name": "web-2",
        "type": "EC2",
        "account_id": "111111111111",
        "region": "us-east-1",
        "changed_fields": [
          "internet_exposed",
          "tags"
        ],
        "internet_exposed": {
          "before": false,
          "after": true
        }
      }
    ],
    "truncated": false
  }
}
```

```json
{
  "tool": "diff_datasets",
  "arguments": {
    "base": "yesterday"
  },
  "isError": true,
  "text": "No such dataset. 5 dataset(s) are loaded: see datasets in the error data, or call list_datasets.",
  "_meta": {
    "cloudg/error_code": -32602,
    "cloudg/error_data": {
      "value": "yesterday",
      "datasets": [
        {
          "dataset": "sample"
        },
        {
          "dataset": "report"
        },
        {
          "dataset": "after"
        },
        "... 2 more"
      ]
    }
  }
}
```

Related: `snapshot_dataset`, the `drift_review` prompt, [Recipe: drift between two snapshots](#drift-between-two-snapshots).

### `dataset_summary`

Category `workspace` · sensitivity `internal` · capabilities `read_state` · readOnly true, destructive false, idempotent true, openWorld false · outputSchema yes · timeout: layer default (300 s)

Headline numbers for one dataset. Links `cloudg://datasets/{name}/summary`, which returns the same object.

| Argument | Type | Default | Constraints | Description |
|---|---|---|---|---|
| `dataset` | string | `""` |  | Dataset name (see list_datasets). Empty = the active dataset. |

Called with the arguments below, `dataset_summary` returned this `structuredContent`.

```json
{}
```

```json
{
  "dataset": "sample",
  "kind": "inventory",
  "source": "<estate>/inventory",
  "loaded_at": "2026-10-09T14:25:12+00:00",
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
  "severity_breakdown": {
    "CRITICAL": 2,
    "HIGH": 5,
    "MEDIUM": 2,
    "LOW": 1,
    "INFO": 1
  },
  "accounts": 5,
  "regions": 5,
  "internet_exposed": 6,
  "cross_account_edges": 3,
  "unlinked_assets": 2,
  "unresolved_references": 1,
  "compliance_frameworks": [
    "CIS-AWS",
    "CIS-Azure",
    "CIS-GCP",
    "... 2 more"
  ],
  "assets_by_type": {
    "SECURITY_GROUP": 4,
    "IAM_ROLE": 4,
    "CLOUD_ACCOUNT": 3,
    "EC2": 3,
    "S3_BUCKET": 3,
    "...": "10 more"
  },
  "assets_by_provider": {
    "AWS": 36,
    "AZURE": 5,
    "GCP": 3
  },
  "edges_by_type": {
    "CONTAINS": 12,
    "GOVERNS": 1,
    "SECURITY_GROUP_RULE": 4,
    "INTERNET_EXPOSED": 4,
    "ATTACHED_TO": 6,
    "...": "10 more"
  },
  "has_organization": true,
  "coverage_records": 1,
  "organization": {
    "id": "o-sample",
    "accounts": 2,
    "ous": 1,
    "control_tower": true,
    "governed_regions": [
      "us-east-1",
      "eu-west-1"
    ]
  }
}
```

The result also carried these resource links in `content`:

```json
[
  {
    "type": "resource_link",
    "uri": "cloudg://datasets/sample/summary",
    "name": "sample summary",
    "mimeType": "application/json"
  }
]
```

| Field | Meaning |
|---|---|
| `dataset`, `kind`, `source`, `loaded_at`, `version`, `providers` | Identity of the dataset. |
| `total_assets`, `total_edges`, `total_findings` | Raw counts. |
| `open_findings`, `suppressed_findings`, `severity_breakdown` | Open findings by severity, worst first. |
| `accounts` | Distinct account ids (excluding `unknown`). |
| `regions` | Distinct regions, as a count. |
| `internet_exposed` | Assets flagged exposed. |
| `cross_account_edges` | Edges whose ends are in different accounts. |
| `unlinked_assets` | Assets with no edge at all, excluding organization, OU and account assets. |
| `unresolved_references` | Count of linker misses (`unresolved_references` tool). |
| `compliance_frameworks` | Frameworks present in the compliance results. |
| `assets_by_type` | Top 15 types. |
| `assets_by_provider`, `edges_by_type` | Full breakdowns. |
| `has_organization`, `organization` | Organization summary when discovery data exists. |
| `coverage_records` | Number of collection coverage records (from live collections, and from inventory maps saved with them). |

## Inventory

These tools answer "what do we have". `find_assets` and `count_assets` share one filter implementation (`filter_assets` in `cloudg/mcp/catalog/_inventory.py`).

### `find_assets`

Category `inventory` · sensitivity `confidential` · capabilities `read_state` · readOnly true, destructive false, idempotent true, openWorld false · outputSchema yes · timeout: layer default (300 s)

Searches assets with any combination of filters, sorts, and pages through the result. Items are asset briefs; read an item's `uri` or call `get_asset` for detail.

| Argument | Type | Default | Constraints | Description |
|---|---|---|---|---|
| `query` | string | `""` |  | Case-insensitive substring of name, ARN, id or a tag value. |
| `provider` | string | `""` |  | aws, azure or gcp. |
| `asset_types` | string[] or null | `null` |  | AssetType values, e.g. ['EC2','S3_BUCKET'] (describe_schema). |
| `region` | string | `""` |  | Exact region, e.g. us-east-1. |
| `account_id` | string | `""` |  | Exact account / subscription / project. |
| `tag` | string | `""` |  | Tag filter: 'key' or 'key=value'. |
| `internet_exposed` | boolean or null | `null` |  | Only exposed (true) / not exposed (false). |
| `has_findings` | boolean or null | `null` |  | Only assets with (true) / without (false) open findings. |
| `min_severity` | string | `""` |  | Only assets with an open finding at or above this severity. |
| `sort_by` | string | `"name"` | one of `name`, `type`, `region`, `account`, `risk`, `findings` | 'risk' ranks by worst finding + exposure. |
| `descending` | boolean | `false` |  | Reverse the order. For `risk` and `findings` the default is already highest first, so `true` puts the lowest first. |
| `fields` | string[] or null | `null` |  | Project each item to these fields. Valid: id, name, type, provider, region, account_id, arn, internet_exposed, open_findings, max_severity, tags, uri |
| `limit` | integer | `50` | 1..500 | Maximum items to return. |
| `cursor` | string | `""` |  | Opaque cursor from a previous call's next_cursor; empty = first page. |
| `dataset` | string | `""` |  | Dataset name (see list_datasets). Empty = the active dataset. |

Filter semantics: `query` is a case-insensitive substring match against the name, ARN, id and every tag value. `region` matches exactly but ignores case; `account_id` matches exactly. `tag` is either a key that must be present or `key=value` with an exact value. `has_findings` and `min_severity` look at open findings only. All filters combine with AND. When the dataset has assets but none match, the result adds a `hint` pointing at `list_asset_types`, `list_accounts` and `list_regions`.

Internet-exposed EC2 instances with a HIGH or worse finding:

Called with the arguments below, `find_assets` returned this `structuredContent`.

```json
{"asset_types": ["EC2"], "internet_exposed": true, "min_severity": "HIGH"}
```

```json
{
  "dataset": "sample",
  "total": 1,
  "offset": 0,
  "returned": 1,
  "next_cursor": null,
  "truncated": false,
  "items": [
    {
      "id": "bastion",
      "name": "bastion",
      "type": "EC2",
      "provider": "AWS",
      "region": "us-east-1",
      "account_id": "111111111111",
      "arn": "arn:aws:ec2:us-east-1:111111111111:instance/i-0bast",
      "internet_exposed": true,
      "open_findings": 1,
      "max_severity": "HIGH",
      "uri": "cloudg://assets/bastion"
    }
  ]
}
```

Projection to `name` and `tags` for a tag filter:

Called with the arguments below, `find_assets` returned this `structuredContent`.

```json
{"tag": "owner=web-team", "fields": ["name", "tags"]}
```

```json
{
  "dataset": "sample",
  "total": 3,
  "offset": 0,
  "returned": 3,
  "next_cursor": null,
  "truncated": false,
  "items": [
    {
      "id": "web-1",
      "name": "web-1",
      "tags": {
        "env": "prod",
        "owner": "web-team"
      }
    },
    {
      "id": "web-2",
      "name": "web-2",
      "tags": {
        "env": "prod",
        "owner": "web-team"
      }
    },
    {
      "id": "alb-web",
      "name": "web-alb",
      "tags": {
        "env": "prod",
        "owner": "web-team"
      }
    }
  ]
}
```

No match:

Called with the arguments below, `find_assets` returned this `structuredContent`.

```json
{"query": "kubernetes"}
```

```json
{
  "dataset": "sample",
  "total": 0,
  "offset": 0,
  "returned": 0,
  "next_cursor": null,
  "truncated": false,
  "items": [],
  "hint": "No assets matched. Loosen the filters, or use list_asset_types / list_accounts / list_regions to see valid values."
}
```

Errors include unknown enum values, unknown `fields`, stale or invalid cursors (all shown under [Conventions](#conventions-shared-by-every-tool)) and schema violations:

```json
{
  "tool": "find_assets",
  "arguments": {
    "asset_types": [
      "LAMBDA"
    ]
  },
  "isError": true,
  "text": "Unknown asset type. Did you mean LAMBDA_FUNCTION, ALARM? Valid values: EC2, VIRTUAL_MACHINE, GCE_INSTANCE, LAMBDA_FUNCTION, CLOUD_FUNCTION, ECS_CLUSTER, EKS_CLU...",
  "_meta": {
    "cloudg/error_code": -32602,
    "cloudg/error_data": {
      "value": "LAMBDA",
      "valid": [
        "EC2",
        "VIRTUAL_MACHINE",
        "GCE_INSTANCE",
        "... 153 more"
      ],
      "close_matches": [
        "LAMBDA_FUNCTION",
        "ALARM"
      ]
    }
  }
}
```

```json
{
  "tool": "find_assets",
  "arguments": {
    "limit": 1000
  },
  "isError": true,
  "text": "Invalid arguments: limit: Input should be less than or equal to 500",
  "_meta": {
    "cloudg/error_code": -32602,
    "cloudg/error_data": [
      {
        "loc": "limit",
        "msg": "Input should be less than or equal to 500",
        "type": "less_than_equal"
      }
    ]
  }
}
```

Related: `count_assets` for totals, `get_asset` for one asset, `list_tags` for valid tag values.

### `get_asset`

Category `inventory` · sensitivity `confidential` · capabilities `read_state` · readOnly true, destructive false, idempotent true, openWorld false · outputSchema yes · timeout: layer default (300 s)

One asset in detail. Links `cloudg://assets/{id}` and `cloudg://assets/{id}/neighbors`.

| Argument | Type | Default | Constraints | Description |
|---|---|---|---|---|
| `ref` | string | required | min length 1 | Asset reference: internal id, ARN / cloud resource id, unique name, or unique ARN tail (e.g. 'function:api' or 'i-0abc'). |
| `include_findings` | boolean | `true` |  | Include up to 25 open findings, highest risk first. |
| `max_relations` | integer | `20` | 0..200 | How many edges to list in `relations.sample` (0 lists none; the counts are always complete). |
| `dataset` | string | `""` |  | Dataset name (see list_datasets). Empty = the active dataset. |

| Field | Meaning |
|---|---|
| asset brief fields, `tags` | See [Briefs](#briefs). |
| `dataset` | Dataset the asset came from. |
| `service` | Cloud service derived from the ARN or type (`ec2`, `lambda`, `iam`...). |
| `relations.outgoing`, `relations.incoming` | Edge counts by edge type, complete. |
| `relations.sample` | The first `max_relations` edges (outgoing first) as edge briefs. |
| `relations.total`, `relations.truncated` | Total edges and whether `sample` is cut. |
| `dependencies.direct_depends_on`, `dependencies.direct_dependents` | One-hop counts from the dependency graph. |
| `degree.in`, `degree.out` | Degree in the relationship graph (parallel edges count once). |
| `findings` | Up to 25 open findings, highest risk first (omitted with `include_findings: false`). |
| `metadata_keys` | Up to 100 metadata keys, sorted; fetch values with `get_asset_metadata`. |
| `collected_at` | Collection timestamp or null. |

Looked up by ARN tail `i-0web1`:

Called with the arguments below, `get_asset` returned this `structuredContent`.

```json
{"ref": "i-0web1", "max_relations": 3}
```

```json
{
  "id": "web-1",
  "name": "web-1",
  "type": "EC2",
  "provider": "AWS",
  "region": "us-east-1",
  "account_id": "111111111111",
  "arn": "arn:aws:ec2:us-east-1:111111111111:instance/i-0web1",
  "internet_exposed": false,
  "open_findings": 1,
  "max_severity": "HIGH",
  "uri": "cloudg://assets/web-1",
  "tags": {
    "env": "prod",
    "owner": "web-team"
  },
  "dataset": "sample",
  "service": "ec2",
  "relations": {
    "outgoing": {
      "ATTACHED_TO": 1,
      "ASSUMES_ROLE": 1
    },
    "incoming": {
      "CONTAINS": 1,
      "LOAD_BALANCER_TARGET": 1,
      "MONITORS": 1
    },
    "sample": [
      {
        "id": "e-web1-sg",
        "source": "web-1",
        "source_name": "web-1",
        "target": "sg-app",
        "target_name": "sg-app",
        "edge_type": "ATTACHED_TO",
        "relationship": null
      },
      {
        "id": "e-web1-role",
        "source": "web-1",
        "source_name": "web-1",
        "target": "app-role",
        "target_name": "app-role",
        "edge_type": "ASSUMES_ROLE",
        "relationship": null
      },
      {
        "id": "e-priv-web1",
        "source": "subnet-private",
        "source_name": "prod-private-a",
        "target": "web-1",
        "target_name": "web-1",
        "edge_type": "CONTAINS",
        "relationship": null
      }
    ],
    "total": 5,
    "truncated": true
  },
  "dependencies": {
    "direct_depends_on": 4,
    "direct_dependents": 1
  },
  "degree": {
    "in": 3,
    "out": 2
  },
  "findings": [
    {
      "id": "f-web-cve",
      "title": "CVE-2024-1234 in openssl 3.0.1",
      "severity": "HIGH",
      "risk_score": 7.8,
      "source_tool": "trivy",
      "resource_id": "web-1",
      "resource_arn": null,
      "asset_id": "web-1",
      "asset_name": "web-1",
      "compliance_frameworks": [
        "PCI-DSS"
      ],
      "is_suppressed": false,
      "cvss_score": 8.1,
      "detected_at": "2026-01-15T12:00:00+00:00",
      "uri": "cloudg://findings/f-web-cve"
    }
  ],
  "metadata_keys": [
    "imds_v2",
    "instance_type",
    "user_data"
  ],
  "collected_at": "2026-01-15T12:00:00+00:00"
}
```

The result also carried these resource links in `content`:

```json
[
  {
    "type": "resource_link",
    "uri": "cloudg://assets/web-1",
    "name": "web-1",
    "title": "EC2 web-1",
    "mimeType": "application/json"
  },
  {
    "type": "resource_link",
    "uri": "cloudg://assets/web-1/neighbors",
    "name": "web-1 neighbors",
    "mimeType": "application/json"
  }
]
```

Related: `get_asset_metadata`, `neighbors`, `findings_for_asset`, `blast_radius`, the `investigate_asset` prompt.

### `get_asset_metadata`

Category `inventory` · sensitivity `restricted` · capabilities `read_state` · readOnly true, destructive false, idempotent true, openWorld false · outputSchema no · timeout: layer default (300 s)

The raw metadata the collector stored for an asset: configuration, policy documents, rules, declared relations. It can contain secrets, which is why the tool is `restricted`: `strict` and `soc-analyst` hide it, and `standard` redacts secret-looking values.

| Argument | Type | Default | Constraints | Description |
|---|---|---|---|---|
| `ref` | string | required | min length 1 | Asset reference: internal id, ARN / cloud resource id, unique name, or unique ARN tail (e.g. 'function:api' or 'i-0abc'). |
| `keys` | string[] or null | `null` |  | Only these metadata keys (see get_asset.metadata_keys). |
| `max_chars` | integer | `40000` | 1000..200000 | Size budget for the serialised metadata. Over budget, keys that would cross it are left out and `truncated` is true. |
| `dataset` | string | `""` |  | Dataset name (see list_datasets). Empty = the active dataset. |

Returns `id`, `name`, `type`, `metadata`, `truncated`, and `missing_keys` when some requested keys do not exist. When the serialised metadata is longer than `max_chars`, keys are kept in their stored order while they fit and any key that would cross the budget is left out; `truncated` is then true, `key_sizes` lists the 50 largest keys with their serialised sizes, and `hint` asks for specific keys.

Called with the arguments below, `get_asset_metadata` returned this `structuredContent`.

```json
{"ref": "web-1", "keys": ["instance_type", "imds_v2", "ami"]}
```

```json
{
  "id": "web-1",
  "name": "web-1",
  "type": "EC2",
  "truncated": false,
  "metadata": {
    "instance_type": "t3.large",
    "imds_v2": false
  },
  "missing_keys": [
    "ami"
  ]
}
```

The same asset without `keys`, called through a layer with `policy="standard"`. The `user_data` value is redacted and `_meta` reports the transform:

```json
{
  "structured": {
    "id": "web-1",
    "name": "web-1",
    "type": "EC2",
    "truncated": false,
    "metadata": {
      "instance_type": "t3.large",
      "imds_v2": false,
      "user_data": "[REDACTED:sensitive_field]"
    }
  },
  "meta": {
    "cloudg/transforms": {
      "redacted": {
        "sensitive_field": 1
      },
      "content_annotations": {
        "audience": [
          "user"
        ],
        "priority": 0.75
      },
      "annotations": {
        "classification": {
          "sensitivity": "restricted",
          "withheld_entities": [
            "sensitive_field"
          ]
        },
        "provenance": {
          "kind": "tool",
          "name": "get_asset_metadata",
          "generated_at": "2026-10-09T14:25:17+00:00",
          "policy": "standard",
          "category": "inventory",
          "principal_roles": [
            "default",
            "local"
          ]
        },
        "transformed": {
          "redacted": 1
        }
      }
    },
    "cloudg/duration_ms": 0
  }
}
```

Related: `get_asset` (lists `metadata_keys`).

### `count_assets`

Category `inventory` · sensitivity `internal` · capabilities `read_state` · readOnly true, destructive false, idempotent true, openWorld false · outputSchema yes · timeout: layer default (300 s)

Counts assets grouped by one dimension, with the same filters as `find_assets` (minus text, tag and finding filters). Returns only group keys and counts, so it is `internal`.

| Argument | Type | Default | Constraints | Description |
|---|---|---|---|---|
| `group_by` | string | `"type"` | one of `type`, `provider`, `region`, `account`, `service`, `exposure`, `severity` | Grouping dimension. `service` is the cloud service parsed from the ARN or type, `exposure` is internet_exposed / internal, `severity` is the worst open finding (NONE when there is none). |
| `provider` | string | `""` |  | aws, azure or gcp (case-insensitive). |
| `asset_types` | string[] or null | `null` |  | AssetType values to count. |
| `region` | string | `""` |  | Exact region (case-insensitive). |
| `account_id` | string | `""` |  | Exact account / subscription / project id. |
| `internet_exposed` | boolean or null | `null` |  | Only exposed (true) or only not exposed (false). |
| `top` | integer | `50` | 1..500 | Maximum number of groups returned (largest first). |
| `dataset` | string | `""` |  | Dataset name (see list_datasets). Empty = the active dataset. |

Returns `dataset`, `group_by`, `total` (assets that passed the filters), `group_count`, `groups` (largest first, at most `top`) and `truncated`.

Called with the arguments below, `count_assets` returned this `structuredContent`.

```json
{"group_by": "provider"}
```

```json
{
  "dataset": "sample",
  "group_by": "provider",
  "total": 44,
  "group_count": 3,
  "groups": {
    "AWS": 36,
    "AZURE": 5,
    "GCP": 3
  },
  "truncated": false
}
```

Called with the arguments below, `count_assets` returned this `structuredContent`.

```json
{"group_by": "severity"}
```

```json
{
  "dataset": "sample",
  "group_by": "severity",
  "total": 44,
  "group_count": 6,
  "groups": {
    "NONE": 34,
    "HIGH": 5,
    "CRITICAL": 2,
    "INFO": 1,
    "LOW": 1,
    "MEDIUM": 1
  },
  "truncated": false
}
```

Called with the arguments below, `count_assets` returned this `structuredContent`.

```json
{"group_by": "service", "provider": "aws", "top": 5}
```

```json
{
  "dataset": "sample",
  "group_by": "service",
  "total": 36,
  "group_count": 16,
  "groups": {
    "ec2": 10,
    "iam": 7,
    "organizations": 3,
    "s3": 3,
    "elasticloadbalancing": 2
  },
  "truncated": true
}
```

### `list_asset_types`

Category `inventory` · sensitivity `internal` · capabilities `read_state` · readOnly true, destructive false, idempotent true, openWorld false · outputSchema no · timeout: layer default (300 s)

The asset types present in the dataset with `count`, `internet_exposed` and `open_findings` per type, most common first. Pass these values to `asset_types` filters.

| Argument | Type | Default | Constraints | Description |
|---|---|---|---|---|
| `dataset` | string | `""` |  | Dataset name (see list_datasets). Empty = the active dataset. |

Called with the arguments below, `list_asset_types` returned this `structuredContent`.

```json
{}
```

```json
{
  "dataset": "sample",
  "total_types": 31,
  "items": [
    {
      "type": "SECURITY_GROUP",
      "count": 4,
      "internet_exposed": 0,
      "open_findings": 1
    },
    {
      "type": "IAM_ROLE",
      "count": 4,
      "internet_exposed": 0,
      "open_findings": 1
    },
    {
      "type": "CLOUD_ACCOUNT",
      "count": 3,
      "internet_exposed": 0,
      "open_findings": 0
    },
    "... 28 more"
  ]
}
```

Related: `describe_schema` (every type cloudg knows), `explain_asset_type`.

### `list_accounts`

Category `inventory` · sensitivity `confidential` · capabilities `read_state` · readOnly true, destructive false, idempotent true, openWorld false · outputSchema no · timeout: layer default (300 s)

Accounts, subscriptions and projects seen on assets, most assets first. `name` comes from a `CLOUD_ACCOUNT` asset with the same account id; `external` is true when that asset's metadata marks it as outside the mapped estate (referenced, not collected). Assets without an account id are grouped under `unknown`. Default `limit` is 100.

| Argument | Type | Default | Constraints | Description |
|---|---|---|---|---|
| `limit` | integer | `100` | 1..500 | Maximum items to return. |
| `cursor` | string | `""` |  | Opaque cursor from a previous call's next_cursor; empty = first page. |
| `dataset` | string | `""` |  | Dataset name (see list_datasets). Empty = the active dataset. |

Called with the arguments below, `list_accounts` returned this `structuredContent`.

```json
{}
```

```json
{
  "dataset": "sample",
  "total": 5,
  "offset": 0,
  "returned": 5,
  "next_cursor": null,
  "truncated": false,
  "items": [
    {
      "account_id": "111111111111",
      "provider": "AWS",
      "assets": 31,
      "regions": [
        "global",
        "us-east-1"
      ],
      "internet_exposed": 4,
      "open_findings": 7,
      "name": "prod",
      "external": false
    },
    {
      "account_id": "00000000-aaaa-bbbb-cccc-000000000001",
      "provider": "AZURE",
      "assets": 5,
      "regions": [
        "westeurope"
      ],
      "internet_exposed": 1,
      "open_findings": 1,
      "name": null,
      "external": false
    },
    "... 3 more"
  ]
}
```

Related: `organization_topology`, `cross_account_edges`.

### `list_regions`

Category `inventory` · sensitivity `internal` · capabilities `read_state` · readOnly true, destructive false, idempotent true, openWorld false · outputSchema no · timeout: layer default (300 s)

Regions found on assets with their providers, asset count and number of distinct accounts, plus `scanned_regions`, the regions each provider was configured or scanned for (empty for datasets loaded from a plain report).

| Argument | Type | Default | Constraints | Description |
|---|---|---|---|---|
| `dataset` | string | `""` |  | Dataset name (see list_datasets). Empty = the active dataset. |

Called with the arguments below, `list_regions` returned this `structuredContent`.

```json
{}
```

```json
{
  "dataset": "sample",
  "total": 5,
  "items": [
    {
      "region": "us-east-1",
      "providers": [
        "AWS"
      ],
      "assets": 24,
      "accounts": 1
    },
    {
      "region": "global",
      "providers": [
        "AWS"
      ],
      "assets": 10,
      "accounts": 3
    },
    "... 3 more"
  ],
  "scanned_regions": {
    "aws": [
      "us-east-1",
      "eu-west-1"
    ],
    "azure": [
      "westeurope"
    ],
    "gcp": [
      "europe-west1"
    ]
  }
}
```

### `list_tags`

Category `inventory` · sensitivity `confidential` · capabilities `read_state` · readOnly true, destructive false, idempotent true, openWorld false · outputSchema no · timeout: layer default (300 s)

Tag keys with the number of assets carrying each, the number of distinct values and the most common values (5 per key, or up to `top` when `key` is given). Feed the result into `find_assets(tag="key=value")`.

| Argument | Type | Default | Constraints | Description |
|---|---|---|---|---|
| `key` | string | `""` |  | Only this tag key (shows its values). |
| `top` | integer | `30` | 1..200 | Maximum number of tag keys returned. With `key`, also the number of values shown. |
| `dataset` | string | `""` |  | Dataset name (see list_datasets). Empty = the active dataset. |

Called with the arguments below, `list_tags` returned this `structuredContent`.

```json
{}
```

```json
{
  "dataset": "sample",
  "total": 3,
  "returned": 3,
  "truncated": false,
  "items": [
    {
      "key": "env",
      "assets": 8,
      "distinct_values": 1,
      "top_values": {
        "prod": 8
      }
    },
    {
      "key": "owner",
      "assets": 7,
      "distinct_values": 4,
      "top_values": {
        "web-team": 3,
        "platform": 2,
        "api-team": 1,
        "it-ops": 1
      }
    },
    {
      "key": "data",
      "assets": 2,
      "distinct_values": 1,
      "top_values": {
        "pii": 2
      }
    }
  ]
}
```

Called with the arguments below, `list_tags` returned this `structuredContent`.

```json
{"key": "owner"}
```

```json
{
  "dataset": "sample",
  "total": 1,
  "returned": 1,
  "truncated": false,
  "items": [
    {
      "key": "owner",
      "assets": 7,
      "distinct_values": 4,
      "top_values": {
        "web-team": 3,
        "platform": 2,
        "api-team": 1,
        "it-ops": 1
      }
    }
  ]
}
```

### `coverage_report`

Category `inventory` · sensitivity `internal` · capabilities `read_state` · readOnly true, destructive false, idempotent true, openWorld false · outputSchema no · timeout: layer default (300 s)

Which collectors succeeded or failed per provider, account and region during collection, so gaps such as `AccessDenied` are visible before the map is trusted. Live collections carry coverage records, and so do inventory maps: `cloudg map` saves them in `inventory-map.json`. Each record has `provider`, `region`, `account_id`, `total_services`, `successful`, `failed`, `coverage_pct` and `failures[]` with `service` and `error`, and the tool adds totals. The sample inventory holds one record:

| Argument | Type | Default | Constraints | Description |
|---|---|---|---|---|
| `dataset` | string | `""` |  | Dataset name (see list_datasets). Empty = the active dataset. |

Called with the arguments below, `coverage_report` returned this `structuredContent`.

```json
{}
```

```json
{
  "dataset": "sample",
  "records": [
    {
      "provider": "aws",
      "region": "us-east-1",
      "account_id": "111111111111",
      "total_services": 3,
      "successful": 2,
      "failed": 1,
      "coverage_pct": 66.7,
      "failures": [
        {
          "service": "rds",
          "error": "AccessDenied: rds:DescribeDBInstances"
        }
      ]
    }
  ],
  "total_services": 3,
  "successful": 2,
  "failed": 1,
  "coverage_pct": 66.7
}
```

A dataset without records, such as `report` loaded from a `findings.json`, gets a note instead:

Called with the arguments below, `coverage_report` returned this `structuredContent`.

```json
{"dataset": "report"}
```

```json
{
  "dataset": "report",
  "records": [],
  "note": "This dataset has no coverage records (they come from live collections via map_inventory / collect_assets, and from inventory maps saved with them)."
}
```

A dataset produced by `map_inventory` (stubbed engine, see [How the examples were produced](#how-the-examples-were-produced)) has the same shape:

Called with the arguments below, `coverage_report` returned this `structuredContent`.

```json
{"dataset": "live-aws"}
```

```json
{
  "dataset": "live-aws",
  "records": [
    {
      "provider": "aws",
      "region": "us-east-1",
      "account_id": "111111111111",
      "total_services": 3,
      "successful": 2,
      "failed": 1,
      "coverage_pct": 66.7,
      "failures": [
        {
          "service": "rds",
          "error": "AccessDenied: rds:DescribeDBInstances"
        }
      ]
    }
  ],
  "total_services": 3,
  "successful": 2,
  "failed": 1,
  "coverage_pct": 66.7
}
```

### `unresolved_references`

Category `inventory` · sensitivity `confidential` · capabilities `read_state` · readOnly true, destructive false, idempotent true, openWorld false · outputSchema no · timeout: layer default (300 s)

Relations the linker could not resolve to a mapped asset, for example a role ARN in a service that was not collected. These are blind spots in the graph. Items are passed through as the mapper stored them.

| Argument | Type | Default | Constraints | Description |
|---|---|---|---|---|
| `limit` | integer | `50` | 1..500 | Maximum items to return. |
| `cursor` | string | `""` |  | Opaque cursor from a previous call's next_cursor; empty = first page. |
| `dataset` | string | `""` |  | Dataset name (see list_datasets). Empty = the active dataset. |

Called with the arguments below, `unresolved_references` returned this `structuredContent`.

```json
{}
```

```json
{
  "dataset": "sample",
  "total": 1,
  "offset": 0,
  "returned": 1,
  "next_cursor": null,
  "truncated": false,
  "items": [
    {
      "source": "web-1",
      "source_type": "EC2",
      "target": "arn:aws:iam::111111111111:role/missing-role",
      "edge": "ASSUMES_ROLE"
    }
  ]
}
```

### `organization_topology`

Category `inventory` · sensitivity `confidential` · capabilities `read_state` · readOnly true, destructive false, idempotent true, openWorld false · outputSchema no · timeout: layer default (300 s)

The organization hierarchy. When the dataset carries organization discovery data (AWS Organizations, Control Tower, Azure management groups, GCP folders), the result has `source: "organization_discovery"` with `organization_id`, `management_account_id`, `feature_set`, `control_tower_enabled`, `governed_regions`, `shared_accounts`, `ous[]` (`id`, `name`, `path`, `parent_id`), `accounts[]` (`id`, `name`, `status`, `ou_path`, `parent_id`, at most `max_accounts`), `total_accounts`, `truncated` and, with `include_policies`, `policies[]` (`id`, `name`, `type`, `aws_managed`, `targets`).

| Argument | Type | Default | Constraints | Description |
|---|---|---|---|---|
| `include_policies` | boolean | `false` |  | Add SCPs / org policies and their targets. |
| `max_accounts` | integer | `200` | 1..1000 | Cap on the accounts (or hierarchy nodes) listed. |
| `dataset` | string | `""` |  | Dataset name (see list_datasets). Empty = the active dataset. |

Called with the arguments below, `organization_topology` returned this `structuredContent`.

```json
{"include_policies": true}
```

```json
{
  "dataset": "sample",
  "source": "organization_discovery",
  "organization_id": "o-sample",
  "management_account_id": "111111111111",
  "feature_set": "ALL",
  "control_tower_enabled": true,
  "governed_regions": [
    "us-east-1",
    "eu-west-1"
  ],
  "shared_accounts": {},
  "ous": [
    {
      "id": "ou-work",
      "name": "Workloads",
      "path": [
        "Root",
        "Workloads"
      ],
      "parent_id": "r-root"
    }
  ],
  "accounts": [
    {
      "id": "111111111111",
      "name": "prod",
      "status": "ACTIVE",
      "ou_path": [
        "Root",
        "Workloads"
      ],
      "parent_id": "ou-work"
    },
    {
      "id": "222222222222",
      "name": "shared-services",
      "status": "ACTIVE",
      "ou_path": [
        "Root",
        "Workloads"
      ],
      "parent_id": "ou-work"
    }
  ],
  "total_accounts": 2,
  "truncated": false,
  "policies": [
    {
      "id": "p-1",
      "name": "deny-unapproved-regions",
      "type": "SERVICE_CONTROL_POLICY",
      "aws_managed": false,
      "targets": [
        "ou-work"
      ]
    }
  ]
}
```

Without discovery data it falls back to the organization, OU and account assets on the map (`source: "map_assets"`), with parents taken from `CONTAINS` edges and policies from `ORG_POLICY` assets and their `GOVERNS` edges. The `report` dataset was loaded from `findings.json`, which keeps assets but not the discovery block:

Called with the arguments below, `organization_topology` returned this `structuredContent`.

```json
{"dataset": "report", "include_policies": true}
```

```json
{
  "dataset": "report",
  "source": "map_assets",
  "nodes": [
    {
      "id": "org",
      "name": "sample-org",
      "type": "ORGANIZATION",
      "account_id": "111111111111",
      "parent_id": null,
      "external": false
    },
    {
      "id": "ou-workloads",
      "name": "Workloads",
      "type": "ORG_UNIT",
      "account_id": "111111111111",
      "parent_id": "org",
      "external": false
    },
    "... 3 more"
  ],
  "total": 5,
  "truncated": false,
  "policies": [
    {
      "id": "scp-deny-regions",
      "name": "deny-unapproved-regions",
      "targets": [
        "ou-workloads"
      ]
    }
  ]
}
```

With neither, it returns `source: null` and a `note`.

Related: `list_accounts`, `cross_account_edges`, the `cross_account_trust_review` prompt.

## Graph

The graph tools read three views of the same edges, each built lazily and cached per dataset:

- The relationship graph (`GraphBuilder`, a NetworkX `DiGraph`): edges as collected, read "source verb target". Placeholder nodes such as `0.0.0.0/0` appear when an edge points at something that is not an asset. The graph holds one edge per pair of nodes: parallel `SECURITY_GROUP_RULE`, `NACL_RULE` and `INTERNET_EXPOSED` edges with the same CIDR and direction are merged into one edge whose `port_range` and `protocol` are comma lists, and any other parallel edge replaces the earlier one.
- The flow graph (`Dataset.flow_graph`): the network-flow hops of `cloudg.graph.reachability.network_flow_graph()`, the same walk the internet-exposure analysis uses, plus the identity edges (`ASSUMES_ROLE`, `IAM_TRUST`, `GRANTS_ACCESS`) as explicit pivots, because an attacker who reaches a workload can use its role. Flow hops follow `INTERNET_EXPOSED`, ingress rules, `ROUTE`, `PEERING` and `LOAD_BALANCER_TARGET` edges, `CONTAINS` only out of a VPC, VNet or subnet, `ATTACHED_TO` forward from a network interface or public IP, and `ATTACHED_TO` backwards from a security group, NSG or NACL to what is attached to it, since traffic a group admits reaches those resources. Path results label those reversed hops `SG_ADMITS`. Egress rules, `INVOKES` and the other typed edges are not traffic paths. `find_paths` in `flow` mode and `attack_paths` use it.
- The dependency graph (`cloudg.inventory.dependencies.DependencyGraph`): each edge turned into a "dependent needs dependency" arrow. `forward` edge types (`REFERENCES`, `ATTACHED_TO`, `ROUTE`, `PEERING`, `USES_IMAGE`, `ASSUMES_ROLE`, `LOGS_TO`, `LOAD_BALANCER_TARGET`, `GRANTS_ACCESS`, `IAM_POLICY_ATTACHMENT`, `IAM_TRUST`) make the source depend on the target; `reverse` types (`CONTAINS`, `INVOKES`, `PROTECTS`, `MONITORS`, `MANAGES`, `GOVERNS`) make the target depend on the source; `SECURITY_GROUP_RULE`, `NACL_RULE` and `INTERNET_EXPOSED` create no dependency. `depends_on`, `dependents`, `dependency_tree`, `shared_dependencies`, `largest_blast_radius` and the first half of `blast_radius` use it. [INVENTORY_REFERENCE.md](INVENTORY_REFERENCE.md) sections 6 and 12 have the full table.

`neighbors` and `get_edges` read the raw edge list, so parallel edges are all reported.

### `neighbors`

Category `graph` · sensitivity `confidential` · capabilities `read_state` · readOnly true, destructive false, idempotent true, openWorld false · outputSchema yes · timeout: layer default (300 s)

Breadth-first walk from one asset over the raw edges, up to `depth` hops. `direction: "out"` follows edges that start at the current node, `"in"` edges that end there, `"both"` either. Walking stops adding nodes after `limit` nodes and edges after `2 * limit` edges, and `truncated` turns true. Links `cloudg://assets/{ref}/neighbors` (one hop, all edges).

| Argument | Type | Default | Constraints | Description |
|---|---|---|---|---|
| `ref` | string | required | min length 1 | Asset reference: internal id, ARN / cloud resource id, unique name, or unique ARN tail (e.g. 'function:api' or 'i-0abc'). |
| `direction` | string | `"both"` | one of `out`, `in`, `both` | out = edges from the asset, in = edges to it. |
| `edge_types` | string[] or null | `null` |  | Only these EdgeType values, e.g. ['ASSUMES_ROLE','GRANTS_ACCESS']. |
| `depth` | integer | `1` | 1..4 | Hops to walk from the asset. |
| `limit` | integer | `100` | 1..500 | Node cap. The edge cap is twice this value. |
| `dataset` | string | `""` |  | Dataset name (see list_datasets). Empty = the active dataset. |

Returns `dataset`, `asset` (brief of the start node), `nodes` (briefs of the nodes reached, start excluded), `edges` (edge briefs of every edge walked), `node_count`, `edge_count`, `truncated`.

Called with the arguments below, `neighbors` returned this `structuredContent`.

```json
{"ref": "web-1"}
```

```json
{
  "dataset": "sample",
  "asset": {
    "id": "web-1",
    "name": "web-1",
    "type": "EC2",
    "provider": "AWS",
    "region": "us-east-1",
    "account_id": "111111111111",
    "arn": "arn:aws:ec2:us-east-1:111111111111:instance/i-0web1",
    "internet_exposed": false,
    "open_findings": 1,
    "max_severity": "HIGH",
    "uri": "cloudg://assets/web-1"
  },
  "nodes": [
    {
      "id": "subnet-private",
      "name": "prod-private-a",
      "type": "SUBNET",
      "provider": "AWS",
      "region": "us-east-1",
      "account_id": "111111111111",
      "arn": "arn:aws:ec2:us-east-1:111111111111:subnet/subnet-0priv",
      "internet_exposed": false,
      "open_findings": 0,
      "max_severity": null,
      "uri": "cloudg://assets/subnet-private"
    },
    {
      "id": "sg-app",
      "name": "sg-app",
      "type": "SECURITY_GROUP",
      "provider": "AWS",
      "region": "us-east-1",
      "account_id": "111111111111",
      "arn": "arn:aws:ec2:us-east-1:111111111111:security-group/sg-0app",
      "internet_exposed": false,
      "open_findings": 0,
      "max_severity": null,
      "uri": "cloudg://assets/sg-app"
    },
    "... 3 more"
  ],
  "edges": [
    {
      "id": "e-priv-web1",
      "source": "subnet-private",
      "source_name": "prod-private-a",
      "target": "web-1",
      "target_name": "web-1",
      "edge_type": "CONTAINS",
      "relationship": null
    },
    {
      "id": "e-web1-sg",
      "source": "web-1",
      "source_name": "web-1",
      "target": "sg-app",
      "target_name": "sg-app",
      "edge_type": "ATTACHED_TO",
      "relationship": null
    },
    "... 3 more"
  ],
  "node_count": 5,
  "edge_count": 5,
  "truncated": false
}
```

The result also carried these resource links in `content`:

```json
[
  {
    "type": "resource_link",
    "uri": "cloudg://assets/web-1/neighbors",
    "name": "neighbors",
    "mimeType": "application/json"
  }
]
```

What a Lambda can reach through its role, two hops out over identity edges:

Called with the arguments below, `neighbors` returned this `structuredContent`.

```json
{
  "ref": "api-handler",
  "direction": "out",
  "edge_types": [
    "ASSUMES_ROLE",
    "GRANTS_ACCESS"
  ],
  "depth": 2
}
```

```json
{
  "dataset": "sample",
  "asset": {
    "id": "api-handler",
    "name": "api-handler",
    "type": "LAMBDA_FUNCTION",
    "provider": "AWS",
    "region": "us-east-1",
    "account_id": "111111111111",
    "arn": "arn:aws:lambda:us-east-1:111111111111:function:api-handler",
    "internet_exposed": false,
    "open_findings": 1,
    "max_severity": "LOW",
    "uri": "cloudg://assets/api-handler"
  },
  "nodes": [
    {
      "id": "lambda-role",
      "name": "api-lambda-role",
      "type": "IAM_ROLE",
      "provider": "AWS",
      "region": "global",
      "account_id": "111111111111",
      "arn": "arn:aws:iam::111111111111:role/api-lambda-role",
      "internet_exposed": false,
      "open_findings": 0,
      "max_severity": null,
      "uri": "cloudg://assets/lambda-role"
    },
    {
      "id": "db-secret",
      "name": "orders-db-credentials",
      "type": "SECRET",
      "provider": "AWS",
      "region": "us-east-1",
      "account_id": "111111111111",
      "arn": "arn:aws:secretsmanager:us-east-1:111111111111:secret:orders-db-credentials-AbC",
      "internet_exposed": false,
      "open_findings": 0,
      "max_severity": null,
      "uri": "cloudg://assets/db-secret"
    }
  ],
  "edges": [
    {
      "id": "e-lambda-role",
      "source": "api-handler",
      "source_name": "api-handler",
      "target": "lambda-role",
      "target_name": "api-lambda-role",
      "edge_type": "ASSUMES_ROLE",
      "relationship": null
    },
    {
      "id": "e-lrole-secret",
      "source": "lambda-role",
      "source_name": "api-lambda-role",
      "target": "db-secret",
      "target_name": "orders-db-credentials",
      "edge_type": "GRANTS_ACCESS",
      "relationship": null
    }
  ],
  "node_count": 2,
  "edge_count": 2,
  "truncated": false
}
```

The internet node works as a start:

Called with the arguments below, `neighbors` returned this `structuredContent`.

```json
{"ref": "internet", "direction": "out"}
```

```json
{
  "dataset": "sample",
  "asset": {
    "id": "0.0.0.0/0",
    "name": "0.0.0.0/0",
    "type": "EXTERNAL",
    "external": true
  },
  "nodes": [
    {
      "id": "sg-web",
      "name": "sg-web",
      "type": "SECURITY_GROUP",
      "provider": "AWS",
      "region": "us-east-1",
      "account_id": "111111111111",
      "arn": "arn:aws:ec2:us-east-1:111111111111:security-group/sg-0web",
      "internet_exposed": false,
      "open_findings": 0,
      "max_severity": null,
      "uri": "cloudg://assets/sg-web"
    },
    {
      "id": "sg-admin",
      "name": "sg-admin",
      "type": "SECURITY_GROUP",
      "provider": "AWS",
      "region": "us-east-1",
      "account_id": "111111111111",
      "arn": "arn:aws:ec2:us-east-1:111111111111:security-group/sg-0admin",
      "internet_exposed": false,
      "open_findings": 1,
      "max_severity": "CRITICAL",
      "uri": "cloudg://assets/sg-admin"
    },
    "... 4 more"
  ],
  "edges": [
    {
      "id": "e-inet-sgweb",
      "source": "0.0.0.0/0",
      "source_name": "0.0.0.0/0",
      "target": "sg-web",
      "target_name": "sg-web",
      "edge_type": "SECURITY_GROUP_RULE",
      "relationship": null,
      "port_range": "80,443",
      "protocol": "TCP",
      "cidr": "0.0.0.0/0",
      "ports": [
        443,
        80
      ],
      "direction": "ingress"
    },
    {
      "id": "e-inet-sgadmin",
      "source": "0.0.0.0/0",
      "source_name": "0.0.0.0/0",
      "target": "sg-admin",
      "target_name": "sg-admin",
      "edge_type": "SECURITY_GROUP_RULE",
      "relationship": null,
      "port_range": "22",
      "protocol": "TCP",
      "cidr": "0.0.0.0/0",
      "ports": [
        22
      ],
      "direction": "ingress"
    },
    "... 4 more"
  ],
  "node_count": 7,
  "edge_count": 7,
  "truncated": false
}
```

The result also carried these resource links in `content`:

```json
[
  {
    "type": "resource_link",
    "uri": "cloudg://assets/0.0.0.0%2F0/neighbors",
    "name": "neighbors",
    "mimeType": "application/json"
  }
]
```

Errors:

```json
{
  "tool": "neighbors",
  "arguments": {
    "ref": "web-1",
    "depth": 9
  },
  "isError": true,
  "text": "Invalid arguments: depth: Input should be less than or equal to 4",
  "_meta": {
    "cloudg/error_code": -32602,
    "cloudg/error_data": [
      {
        "loc": "depth",
        "msg": "Input should be less than or equal to 4",
        "type": "less_than_equal"
      }
    ]
  }
}
```

Related: `get_edges` (search edges directly), `subgraph_export` (the same neighbourhood as a graph document), `ontology_neighbourhood` (semantic relations).

### `get_edges`

Category `graph` · sensitivity `confidential` · capabilities `read_state` · readOnly true, destructive false, idempotent true, openWorld false · outputSchema yes · timeout: layer default (300 s)

Searches the raw edge list. All filters combine with AND, and the result pages like any list tool.

| Argument | Type | Default | Constraints | Description |
|---|---|---|---|---|
| `source` | string | `""` |  | Source asset ref (or 'internet'). |
| `target` | string | `""` |  | Target asset ref. |
| `edge_types` | string[] or null | `null` |  | Only these EdgeType values. |
| `relationship` | string | `""` |  | Exact relationship / RelationType. |
| `cross_account_only` | boolean | `false` |  | Only edges whose two endpoints are mapped assets in different accounts. |
| `internet_only` | boolean | `false` |  | Only ingress edges from the internet (0.0.0.0/0, ::/0, or the Azure Internet / Any / * sources). |
| `port` | integer or null | `null` | 0..65535 | Edges allowing this port. |
| `limit` | integer | `50` | 1..500 | Maximum items to return. |
| `cursor` | string | `""` |  | Opaque cursor from a previous call's next_cursor; empty = first page. |
| `dataset` | string | `""` |  | Dataset name (see list_datasets). Empty = the active dataset. |

`internet_only` keeps ingress edges whose source or `cidr` stands for the internet: `0.0.0.0/0`, `::/0`, or the Azure `Internet`, `Any` and `*` sources. `port` keeps edges whose `ports` list contains the port or whose `port_range` opens it, parsed by `cloudg.graph.ports` like the reachability findings: comma lists, `lo-hi` ranges and Azure `*` are understood, an empty port list on a TCP, UDP or all-protocol filter rule means every port, and ICMP rules open no ports. `cross_account_only` keeps edges whose two ends are assets in different accounts. `source` and `target` take references, including `internet`.

Every rule that opens SSH to the internet:

Called with the arguments below, `get_edges` returned this `structuredContent`.

```json
{"internet_only": true, "port": 22}
```

```json
{
  "dataset": "sample",
  "total": 1,
  "offset": 0,
  "returned": 1,
  "next_cursor": null,
  "truncated": false,
  "items": [
    {
      "id": "e-inet-sgadmin",
      "source": "0.0.0.0/0",
      "source_name": "0.0.0.0/0",
      "target": "sg-admin",
      "target_name": "sg-admin",
      "edge_type": "SECURITY_GROUP_RULE",
      "relationship": null,
      "port_range": "22",
      "protocol": "TCP",
      "cidr": "0.0.0.0/0",
      "ports": [
        22
      ],
      "direction": "ingress"
    }
  ]
}
```

Cross-account trust:

Called with the arguments below, `get_edges` returned this `structuredContent`.

```json
{"edge_types": ["IAM_TRUST"], "cross_account_only": true}
```

```json
{
  "dataset": "sample",
  "total": 2,
  "offset": 0,
  "returned": 2,
  "next_cursor": null,
  "truncated": false,
  "items": [
    {
      "id": "e-app-deploy",
      "source": "app-role",
      "source_name": "app-role",
      "target": "deploy-role",
      "target_name": "deploy-role",
      "edge_type": "IAM_TRUST",
      "relationship": "CROSS_ACCOUNT_TRUST",
      "cross_account": true
    },
    {
      "id": "e-vendor-deploy",
      "source": "acct-vendor",
      "source_name": "vendor-co",
      "target": "deploy-role",
      "target_name": "deploy-role",
      "edge_type": "IAM_TRUST",
      "relationship": "CROSS_ACCOUNT_TRUST",
      "cross_account": true
    }
  ]
}
```

Paging over all edges:

Called with the arguments below, `get_edges` returned this `structuredContent`.

```json
{"limit": 2}
```

```json
{
  "dataset": "sample",
  "total": 56,
  "offset": 0,
  "returned": 2,
  "next_cursor": "c2.45682a5c230e",
  "truncated": true,
  "items": [
    {
      "id": "e-org-ou",
      "source": "org",
      "source_name": "sample-org",
      "target": "ou-workloads",
      "target_name": "Workloads",
      "edge_type": "CONTAINS",
      "relationship": null
    },
    {
      "id": "e-ou-prod",
      "source": "ou-workloads",
      "source_name": "Workloads",
      "target": "acct-prod",
      "target_name": "prod",
      "edge_type": "CONTAINS",
      "relationship": null
    }
  ]
}
```

A `source` or `target` that resolves to nothing fails with the usual "No asset matches" error.

### `find_paths`

Category `graph` · sensitivity `confidential` · capabilities `read_state` · readOnly true, destructive false, idempotent true, openWorld false · outputSchema yes · timeout: layer default (300 s)

Shortest simple paths from `source` to `target`, shortest first, using NetworkX `shortest_simple_paths`. Enumeration stops at the first path longer than `max_depth` hops or once `max_paths` paths are collected. `truncated` is true only when another path within `max_depth` exists beyond the ones returned.

| Argument | Type | Default | Constraints | Description |
|---|---|---|---|---|
| `source` | string | required | min length 1 | Start asset ref, or 'internet'. |
| `target` | string | required | min length 1 | End asset ref. |
| `max_depth` | integer | `6` | 1..12 | Longest path (in hops) to return. |
| `max_paths` | integer | `5` | 1..50 | Maximum number of paths, shortest first. |
| `mode` | string | `"flow"` | one of `flow`, `directed`, `undirected` | flow: network-flow hops (as the reachability analysis walks them: security groups admit traffic to attached resources) plus identity pivots (ASSUMES_ROLE, IAM_TRUST, GRANTS_ACCESS); directed: edges as collected; undirected: any connection. |
| `dataset` | string | `""` |  | Dataset name (see list_datasets). Empty = the active dataset. |

Modes: `flow` (default) is the flow graph, best for "can traffic get from A to B, and which identity can it pivot to"; `directed` is the relationship graph as collected; `undirected` ignores direction and answers "are these connected at all". With `source: "internet"` the walk starts at the virtual `__internet__` node linked to every internet entry point.

Each path has `length` (hops), `nodes` (hop briefs), `edge_types` (one per hop, `SG_ADMITS` for derived flow hops) and `summary` (names joined by `->`). The result also echoes `source`, `target` and `mode`, plus `total_found` and `truncated`, and a `hint` when nothing was found.

From the internet to the orders database:

Called with the arguments below, `find_paths` returned this `structuredContent`.

```json
{"source": "internet", "target": "orders-db"}
```

```json
{
  "dataset": "sample",
  "source": {
    "id": "__internet__",
    "name": "internet",
    "type": "EXTERNAL",
    "external": true
  },
  "target": {
    "id": "orders-db",
    "name": "orders-db",
    "type": "RDS_INSTANCE",
    "provider": "AWS",
    "region": "us-east-1",
    "account_id": "111111111111",
    "arn": "arn:aws:rds:us-east-1:111111111111:db:orders-db",
    "internet_exposed": false,
    "open_findings": 1,
    "max_severity": "MEDIUM",
    "uri": "cloudg://assets/orders-db"
  },
  "mode": "flow",
  "paths": [
    {
      "length": 5,
      "nodes": [
        {
          "id": "0.0.0.0/0",
          "name": "0.0.0.0/0",
          "type": "EXTERNAL",
          "external": true
        },
        {
          "id": "alb-web",
          "name": "web-alb",
          "type": "LOAD_BALANCER",
          "account_id": "111111111111",
          "internet_exposed": true,
          "open_findings": 0
        },
        "... 4 more"
      ],
      "edge_types": [
        "INTERNET_EXPOSED",
        "LOAD_BALANCER_TARGET",
        "LOAD_BALANCER_TARGET",
        "... 2 more"
      ],
      "summary": "0.0.0.0/0 -> web-alb -> web-tg -> web-1 -> app-role -> orders-db"
    },
    {
      "length": 5,
      "nodes": [
        {
          "id": "0.0.0.0/0",
          "name": "0.0.0.0/0",
          "type": "EXTERNAL",
          "external": true
        },
        {
          "id": "alb-web",
          "name": "web-alb",
          "type": "LOAD_BALANCER",
          "account_id": "111111111111",
          "internet_exposed": true,
          "open_findings": 0
        },
        "... 4 more"
      ],
      "edge_types": [
        "INTERNET_EXPOSED",
        "LOAD_BALANCER_TARGET",
        "LOAD_BALANCER_TARGET",
        "... 2 more"
      ],
      "summary": "0.0.0.0/0 -> web-alb -> web-tg -> web-2 -> app-role -> orders-db"
    },
    "... 2 more"
  ],
  "total_found": 4,
  "truncated": false
}
```

In `flow` mode the bastion is reachable through its security group; in `directed` mode it is not, because the collected edge runs from the instance to the group:

Called with the arguments below, `find_paths` returned this `structuredContent`.

```json
{"source": "internet", "target": "bastion", "mode": "flow"}
```

```json
{
  "dataset": "sample",
  "source": {
    "id": "__internet__",
    "name": "internet",
    "type": "EXTERNAL",
    "external": true
  },
  "target": {
    "id": "bastion",
    "name": "bastion",
    "type": "EC2",
    "provider": "AWS",
    "region": "us-east-1",
    "account_id": "111111111111",
    "arn": "arn:aws:ec2:us-east-1:111111111111:instance/i-0bast",
    "internet_exposed": true,
    "open_findings": 1,
    "max_severity": "HIGH",
    "uri": "cloudg://assets/bastion"
  },
  "mode": "flow",
  "paths": [
    {
      "length": 2,
      "nodes": [
        {
          "id": "0.0.0.0/0",
          "name": "0.0.0.0/0",
          "type": "EXTERNAL",
          "external": true
        },
        {
          "id": "sg-admin",
          "name": "sg-admin",
          "type": "SECURITY_GROUP",
          "account_id": "111111111111",
          "internet_exposed": false,
          "open_findings": 1,
          "max_severity": "CRITICAL"
        },
        {
          "id": "bastion",
          "name": "bastion",
          "type": "EC2",
          "account_id": "111111111111",
          "internet_exposed": true,
          "open_findings": 1,
          "max_severity": "HIGH"
        }
      ],
      "edge_types": [
        "SECURITY_GROUP_RULE",
        "SG_ADMITS"
      ],
      "summary": "0.0.0.0/0 -> sg-admin -> bastion"
    }
  ],
  "total_found": 1,
  "truncated": false
}
```

Called with the arguments below, `find_paths` returned this `structuredContent`.

```json
{"source": "internet", "target": "bastion", "mode": "directed"}
```

```json
{
  "dataset": "sample",
  "source": {
    "id": "__internet__",
    "name": "internet",
    "type": "EXTERNAL",
    "external": true
  },
  "target": {
    "id": "bastion",
    "name": "bastion",
    "type": "EC2",
    "provider": "AWS",
    "region": "us-east-1",
    "account_id": "111111111111",
    "arn": "arn:aws:ec2:us-east-1:111111111111:instance/i-0bast",
    "internet_exposed": true,
    "open_findings": 1,
    "max_severity": "HIGH",
    "uri": "cloudg://assets/bastion"
  },
  "mode": "directed",
  "paths": [],
  "total_found": 0,
  "truncated": false,
  "hint": "No path within 6 hops in 'directed' mode. Try mode='undirected' or a larger max_depth, or check neighbors() of each end."
}
```

Related: `attack_paths` (ranked, many targets at once), `neighbors`.

### `attack_paths`

Category `graph` · sensitivity `confidential` · capabilities `read_state` · readOnly true, destructive false, idempotent true, openWorld false · outputSchema yes · timeout: layer default (300 s)

Shortest routes from the internet to sensitive assets over the flow graph, ranked. A virtual entry node is linked to every internet entry point (the `0.0.0.0/0` and `::/0` nodes and the sources of internet-sourced ingress rules, Azure `Internet`, `Any` and `*` included) and to every asset flagged internet-exposed, and Dijkstra from it (unweighted, so hop counts) finds one shortest path to each target within `max_depth` hops. Without `target`, the targets are all crown-jewel assets (see [Risk scores](#risk-scores) for the weights); with `target`, only that asset, at weight 10.

| Argument | Type | Default | Constraints | Description |
|---|---|---|---|---|
| `target` | string | `""` |  | Asset to reach; empty = every crown-jewel asset (databases, buckets, secrets, keys, roles). |
| `max_depth` | integer | `8` | 1..12 | Longest path from the entry point, in hops. |
| `max_paths` | integer | `20` | 1..100 | Maximum paths returned after ranking. |
| `dataset` | string | `""` |  | Dataset name (see list_datasets). Empty = the active dataset. |

Each path is a `find_paths`-style path (the virtual entry node is dropped, so it starts at the exposed asset or at an entry point such as `0.0.0.0/0`) plus `entry` (`internet-exposed asset` or `internet-sourced rule`), `target_weight`, `findings_on_path` (open findings on every hop) and `score`. The result has `paths` (at most `max_paths`), `total_found`, `truncated` and `targets_considered`. When nothing is exposed it returns no paths and a `hint`.

Called with the arguments below, `attack_paths` returned this `structuredContent`.

```json
{"max_paths": 3}
```

```json
{
  "dataset": "sample",
  "paths": [
    {
      "length": 4,
      "nodes": [
        {
          "id": "alb-web",
          "name": "web-alb",
          "type": "LOAD_BALANCER",
          "account_id": "111111111111",
          "internet_exposed": true,
          "open_findings": 0
        },
        {
          "id": "tg-web",
          "name": "web-tg",
          "type": "TARGET_GROUP",
          "account_id": "111111111111",
          "internet_exposed": false,
          "open_findings": 0
        },
        "... 3 more"
      ],
      "edge_types": [
        "LOAD_BALANCER_TARGET",
        "LOAD_BALANCER_TARGET",
        "ASSUMES_ROLE",
        "... 1 more"
      ],
      "summary": "web-alb -> web-tg -> web-1 -> app-role -> orders-db",
      "entry": "internet-exposed asset",
      "target_weight": 10,
      "findings_on_path": 2,
      "score": 9.8
    },
    {
      "length": 2,
      "nodes": [
        {
          "id": "bastion",
          "name": "bastion",
          "type": "EC2",
          "account_id": "111111111111",
          "internet_exposed": true,
          "open_findings": 1,
          "max_severity": "HIGH"
        },
        {
          "id": "admin-role",
          "name": "bastion-admin",
          "type": "IAM_ROLE",
          "account_id": "111111111111",
          "internet_exposed": false,
          "open_findings": 0
        },
        {
          "id": "db-secret",
          "name": "orders-db-credentials",
          "type": "SECRET",
          "account_id": "111111111111",
          "internet_exposed": false,
          "open_findings": 0
        }
      ],
      "edge_types": [
        "ASSUMES_ROLE",
        "GRANTS_ACCESS"
      ],
      "summary": "bastion -> bastion-admin -> orders-db-credentials",
      "entry": "internet-exposed asset",
      "target_weight": 9,
      "findings_on_path": 1,
      "score": 8.9
    },
    {
      "length": 1,
      "nodes": [
        {
          "id": "az-vm",
          "name": "jump-vm",
          "type": "VIRTUAL_MACHINE",
          "account_id": "00000000-aaaa-bbbb-cccc-000000000001",
          "internet_exposed": true,
          "open_findings": 0
        },
        {
          "id": "az-kv",
          "name": "hub-kv",
          "type": "KEY_VAULT",
          "account_id": "00000000-aaaa-bbbb-cccc-000000000001",
          "internet_exposed": false,
          "open_findings": 0
        }
      ],
      "edge_types": [
        "GRANTS_ACCESS"
      ],
      "summary": "jump-vm -> hub-kv",
      "entry": "internet-exposed asset",
      "target_weight": 9,
      "findings_on_path": 0,
      "score": 8.7
    }
  ],
  "total_found": 11,
  "truncated": true,
  "targets_considered": 14
}
```

One target:

Called with the arguments below, `attack_paths` returned this `structuredContent`.

```json
{"target": "db-secret"}
```

```json
{
  "dataset": "sample",
  "paths": [
    {
      "length": 2,
      "nodes": [
        {
          "id": "bastion",
          "name": "bastion",
          "type": "EC2",
          "account_id": "111111111111",
          "internet_exposed": true,
          "open_findings": 1,
          "max_severity": "HIGH"
        },
        {
          "id": "admin-role",
          "name": "bastion-admin",
          "type": "IAM_ROLE",
          "account_id": "111111111111",
          "internet_exposed": false,
          "open_findings": 0
        },
        {
          "id": "db-secret",
          "name": "orders-db-credentials",
          "type": "SECRET",
          "account_id": "111111111111",
          "internet_exposed": false,
          "open_findings": 0
        }
      ],
      "edge_types": [
        "ASSUMES_ROLE",
        "GRANTS_ACCESS"
      ],
      "summary": "bastion -> bastion-admin -> orders-db-credentials",
      "entry": "internet-exposed asset",
      "target_weight": 10,
      "findings_on_path": 1,
      "score": 9.9
    }
  ],
  "total_found": 1,
  "truncated": false,
  "targets_considered": 1
}
```

Related: `find_paths(source="internet", target=...)` for alternative routes to one target, `findings_for_asset` on each hop, the `attack_surface_report` prompt.

### `lateral_movement_paths`

Category `graph` · sensitivity `confidential` · capabilities `read_state` · readOnly true, destructive false, idempotent true, openWorld false · outputSchema yes · timeout: layer default (300 s)

Identity pivot chains. The tool builds a graph from `ASSUMES_ROLE`, `IAM_TRUST` and `GRANTS_ACCESS` edges only. Starting points are `start` when given, else every internet-exposed asset plus every `CLOUD_ACCOUNT` asset whose metadata marks it external. From each start it takes the shortest path to every node within `max_depth` hops that has no further identity edge (a leaf). Chains are ranked by the highest crown-jewel weight on the chain, then by length. Starts that have no identity edge are skipped.

| Argument | Type | Default | Constraints | Description |
|---|---|---|---|---|
| `start` | string | `""` |  | Start from this asset; empty = every internet-exposed asset and external account. |
| `max_depth` | integer | `4` | 1..8 | Longest identity chain, in hops. |
| `max_paths` | integer | `25` | 1..100 | Maximum chains returned after ranking. |
| `dataset` | string | `""` |  | Dataset name (see list_datasets). Empty = the active dataset. |

Returns `paths` (each with `length`, `nodes`, `edge_types`, `summary`), `total_found`, `truncated` and `starting_points` (distinct starts considered, including skipped ones).

Called with the arguments below, `lateral_movement_paths` returned this `structuredContent`.

```json
{"max_paths": 4}
```

```json
{
  "dataset": "sample",
  "paths": [
    {
      "length": 1,
      "nodes": [
        {
          "id": "az-vm",
          "name": "jump-vm",
          "type": "VIRTUAL_MACHINE",
          "account_id": "00000000-aaaa-bbbb-cccc-000000000001",
          "internet_exposed": true,
          "open_findings": 0
        },
        {
          "id": "az-kv",
          "name": "hub-kv",
          "type": "KEY_VAULT",
          "account_id": "00000000-aaaa-bbbb-cccc-000000000001",
          "internet_exposed": false,
          "open_findings": 0
        }
      ],
      "edge_types": [
        "GRANTS_ACCESS"
      ],
      "summary": "jump-vm -> hub-kv"
    },
    {
      "length": 2,
      "nodes": [
        {
          "id": "bastion",
          "name": "bastion",
          "type": "EC2",
          "account_id": "111111111111",
          "internet_exposed": true,
          "open_findings": 1,
          "max_severity": "HIGH"
        },
        {
          "id": "admin-role",
          "name": "bastion-admin",
          "type": "IAM_ROLE",
          "account_id": "111111111111",
          "internet_exposed": false,
          "open_findings": 0
        },
        "... 1 more"
      ],
      "edge_types": [
        "ASSUMES_ROLE",
        "GRANTS_ACCESS"
      ],
      "summary": "bastion -> bastion-admin -> orders-db-credentials"
    },
    "... 2 more"
  ],
  "total_found": 5,
  "truncated": true,
  "starting_points": 7
}
```

From one foothold:

Called with the arguments below, `lateral_movement_paths` returned this `structuredContent`.

```json
{"start": "web-1"}
```

```json
{
  "dataset": "sample",
  "paths": [
    {
      "length": 2,
      "nodes": [
        {
          "id": "web-1",
          "name": "web-1",
          "type": "EC2",
          "account_id": "111111111111",
          "internet_exposed": false,
          "open_findings": 1,
          "max_severity": "HIGH"
        },
        {
          "id": "app-role",
          "name": "app-role",
          "type": "IAM_ROLE",
          "account_id": "111111111111",
          "internet_exposed": false,
          "open_findings": 0
        },
        "... 1 more"
      ],
      "edge_types": [
        "ASSUMES_ROLE",
        "GRANTS_ACCESS"
      ],
      "summary": "web-1 -> app-role -> orders-db"
    },
    {
      "length": 2,
      "nodes": [
        {
          "id": "web-1",
          "name": "web-1",
          "type": "EC2",
          "account_id": "111111111111",
          "internet_exposed": false,
          "open_findings": 1,
          "max_severity": "HIGH"
        },
        {
          "id": "app-role",
          "name": "app-role",
          "type": "IAM_ROLE",
          "account_id": "111111111111",
          "internet_exposed": false,
          "open_findings": 0
        },
        "... 1 more"
      ],
      "edge_types": [
        "ASSUMES_ROLE",
        "GRANTS_ACCESS"
      ],
      "summary": "web-1 -> app-role -> prod-data"
    },
    "... 2 more"
  ],
  "total_found": 4,
  "truncated": false,
  "starting_points": 1
}
```

Related: `cross_account_edges`, the `cross_account_trust_review` and `blast_radius_assessment` prompts.

### `internet_exposure`

Category `graph` · sensitivity `confidential` · capabilities `read_state` · readOnly true, destructive false, idempotent true, openWorld false · outputSchema no · timeout: layer default (300 s)

Assets whose collector flag says they are internet-exposed, each with the evidence. `internet_rules` lists (up to 10) ingress edges whose source or CIDR stands for the internet (`0.0.0.0/0`, `::/0`, Azure `Internet`, `Any`, `*`) that reach the asset directly or through a security group or NSG attached to it; egress rules are skipped: `edge_type`, `ports` (the port range, else up to 10 explicit ports, else `all`), `protocol`, and `via` (the group's name, or the edge description). `sensitive_ports_open` is the intersection of those ports with 22, 3389, 3306, 5432, 1433, 27017, 6379, 9200, 5601, 8080 and 8443. `protected_by_waf` is true when a `PROTECTS` edge points at the asset.

| Argument | Type | Default | Constraints | Description |
|---|---|---|---|---|
| `asset_types` | string[] or null | `null` |  | Only these AssetType values. |
| `include_reachable` | boolean | `false` |  | Also list assets transitively reachable from the internet in the graph. |
| `limit` | integer | `50` | 1..500 | Maximum items to return. |
| `cursor` | string | `""` |  | Opaque cursor from a previous call's next_cursor; empty = first page. |
| `dataset` | string | `""` |  | Dataset name (see list_datasets). Empty = the active dataset. |

With `include_reachable: true` the result adds `graph_reachable`: the assets the reachability analysis reaches from the internet over network-flow edges (`total`, `truncated` and the first `limit` node briefs, sorted by id). IAM grants and `INVOKES` edges are not followed, but the walk passes security groups, subnets and load balancers, so the set is wider than the flagged one.

Called with the arguments below, `internet_exposure` returned this `structuredContent`.

```json
{"limit": 3}
```

```json
{
  "dataset": "sample",
  "total": 6,
  "offset": 0,
  "returned": 3,
  "next_cursor": "c3.a2a0bceed308",
  "truncated": true,
  "items": [
    {
      "id": "bastion",
      "name": "bastion",
      "type": "EC2",
      "provider": "AWS",
      "region": "us-east-1",
      "account_id": "111111111111",
      "arn": "arn:aws:ec2:us-east-1:111111111111:instance/i-0bast",
      "internet_exposed": true,
      "open_findings": 1,
      "max_severity": "HIGH",
      "uri": "cloudg://assets/bastion",
      "internet_rules": [
        {
          "edge_type": "SECURITY_GROUP_RULE",
          "ports": "22",
          "protocol": "TCP",
          "via": "sg-admin"
        }
      ],
      "sensitive_ports_open": [
        22
      ],
      "protected_by_waf": false
    },
    {
      "id": "az-vm",
      "name": "jump-vm",
      "type": "VIRTUAL_MACHINE",
      "provider": "AZURE",
      "region": "westeurope",
      "account_id": "00000000-aaaa-bbbb-cccc-000000000001",
      "arn": "/subscriptions/00000000-aaaa-bbbb-cccc-000000000001/resourceGroups/rg-hub/providers/Microsoft.Compute/virtualMachines/jump-vm",
      "internet_exposed": true,
      "open_findings": 0,
      "max_severity": null,
      "uri": "cloudg://assets/az-vm",
      "internet_rules": [
        {
          "edge_type": "SECURITY_GROUP_RULE",
          "ports": "3389",
          "protocol": "TCP",
          "via": "jump-nsg"
        }
      ],
      "sensitive_ports_open": [
        3389
      ],
      "protected_by_waf": false
    },
    "... 1 more"
  ]
}
```

Called with the arguments below, `internet_exposure` returned this `structuredContent`.

```json
{"asset_types": ["S3_BUCKET"], "include_reachable": true, "limit": 3}
```

```json
{
  "dataset": "sample",
  "total": 1,
  "offset": 0,
  "returned": 1,
  "next_cursor": null,
  "truncated": false,
  "items": [
    {
      "id": "logs-bucket",
      "name": "prod-logs",
      "type": "S3_BUCKET",
      "provider": "AWS",
      "region": "us-east-1",
      "account_id": "111111111111",
      "arn": "arn:aws:s3:::prod-logs",
      "internet_exposed": true,
      "open_findings": 1,
      "max_severity": "HIGH",
      "uri": "cloudg://assets/logs-bucket",
      "internet_rules": [
        {
          "edge_type": "INTERNET_EXPOSED",
          "ports": "all",
          "protocol": null,
          "via": "bucket policy Principal *"
        }
      ],
      "sensitive_ports_open": [],
      "protected_by_waf": false
    }
  ],
  "graph_reachable": {
    "total": 12,
    "truncated": true,
    "items": [
      {
        "id": "alb-web",
        "name": "web-alb",
        "type": "LOAD_BALANCER",
        "provider": "AWS",
        "region": "us-east-1",
        "account_id": "111111111111",
        "arn": "arn:aws:elasticloadbalancing:us-east-1:111111111111:loadbalancer/app/web-alb/abc",
        "internet_exposed": true,
        "open_findings": 0,
        "max_severity": null,
        "uri": "cloudg://assets/alb-web"
      },
      {
        "id": "api-gw",
        "name": "public-api",
        "type": "API_GATEWAY",
        "provider": "AWS",
        "region": "us-east-1",
        "account_id": "111111111111",
        "arn": "arn:aws:apigateway:us-east-1::/restapis/a1b2c3",
        "internet_exposed": true,
        "open_findings": 0,
        "max_severity": null,
        "uri": "cloudg://assets/api-gw"
      },
      "... 1 more"
    ]
  }
}
```

Related: `get_edges(internet_only=true, port=...)`, `attack_paths`, `security_coverage` (`internet_facing_without_waf`).

### `blast_radius`

Category `graph` · sensitivity `confidential` · capabilities `read_state` · readOnly true, destructive false, idempotent true, openWorld false · outputSchema no · timeout: layer default (300 s)

What is affected if one asset breaks, changes, is deleted or is compromised, from two angles.

| Argument | Type | Default | Constraints | Description |
|---|---|---|---|---|
| `ref` | string | required | min length 1 | Asset reference: internal id, ARN / cloud resource id, unique name, or unique ARN tail (e.g. 'function:api' or 'i-0abc'). |
| `max_depth` | integer | `10` | 1..15 | Depth limit for the dependency walk. |
| `limit` | integer | `50` | 1..500 | Cap on `dependency.items` and `network.sensitive_reachable`. |
| `dataset` | string | `""` |  | Dataset name (see list_datasets). Empty = the active dataset. |

`dependency` is the availability view: every transitive dependent up to `max_depth`, with `transitive_dependents`, `by_depth` (count per depth, keys are strings), `accounts_affected`, `internet_exposed_dependents`, `items` (asset brief plus `via` edge type, `relationship`, `depth` and `parent_id`, at most `limit`) and `truncated`. `network` is the reach view: `reachable_assets` (assets that are descendants in the relationship graph), `max_depth` (depth of the breadth-first tree), `risk_score` (see [Risk scores](#risk-scores)) and `sensitive_reachable` (crown-jewel assets among them, at most `limit`). Links the asset.

A KMS key has many dependents and reaches nothing:

Called with the arguments below, `blast_radius` returned this `structuredContent`.

```json
{"ref": "kms-main", "limit": 3}
```

```json
{
  "dataset": "sample",
  "asset": {
    "id": "kms-main",
    "name": "prod-main-key",
    "type": "KMS_KEY",
    "provider": "AWS",
    "region": "us-east-1",
    "account_id": "111111111111",
    "arn": "arn:aws:kms:us-east-1:111111111111:key/1111-2222",
    "internet_exposed": false,
    "open_findings": 0,
    "max_severity": null,
    "uri": "cloudg://assets/kms-main"
  },
  "dependency": {
    "transitive_dependents": 12,
    "by_depth": {
      "1": 4,
      "2": 3,
      "3": 3,
      "4": 1,
      "5": 1
    },
    "accounts_affected": [
      "111111111111"
    ],
    "internet_exposed_dependents": 2,
    "items": [
      {
        "id": "api-handler",
        "name": "api-handler",
        "type": "LAMBDA_FUNCTION",
        "provider": "AWS",
        "region": "us-east-1",
        "account_id": "111111111111",
        "arn": "arn:aws:lambda:us-east-1:111111111111:function:api-handler",
        "internet_exposed": false,
        "open_findings": 1,
        "max_severity": "LOW",
        "uri": "cloudg://assets/api-handler",
        "via": "REFERENCES",
        "relationship": "ENCRYPTED_BY_KMS",
        "depth": 1,
        "parent_id": "kms-main"
      },
      {
        "id": "data-bucket",
        "name": "prod-data",
        "type": "S3_BUCKET",
        "provider": "AWS",
        "region": "us-east-1",
        "account_id": "111111111111",
        "arn": "arn:aws:s3:::prod-data",
        "internet_exposed": false,
        "open_findings": 0,
        "max_severity": null,
        "uri": "cloudg://assets/data-bucket",
        "via": "REFERENCES",
        "relationship": "ENCRYPTED_BY_KMS",
        "depth": 1,
        "parent_id": "kms-main"
      },
      {
        "id": "orders-db",
        "name": "orders-db",
        "type": "RDS_INSTANCE",
        "provider": "AWS",
        "region": "us-east-1",
        "account_id": "111111111111",
        "arn": "arn:aws:rds:us-east-1:111111111111:db:orders-db",
        "internet_exposed": false,
        "open_findings": 1,
        "max_severity": "MEDIUM",
        "uri": "cloudg://assets/orders-db",
        "via": "REFERENCES",
        "relationship": "ENCRYPTED_BY_KMS",
        "depth": 1,
        "parent_id": "kms-main"
      }
    ],
    "truncated": true
  },
  "network": {
    "reachable_assets": 0,
    "max_depth": 0,
    "risk_score": 0.0,
    "sensitive_reachable": []
  }
}
```

The result also carried these resource links in `content`:

```json
[
  {
    "type": "resource_link",
    "uri": "cloudg://assets/kms-main",
    "name": "prod-main-key",
    "mimeType": "application/json"
  }
]
```

A role is the opposite:

Called with the arguments below, `blast_radius` returned this `structuredContent`.

```json
{"ref": "app-role", "limit": 5}
```

```json
{
  "dataset": "sample",
  "asset": {
    "id": "app-role",
    "name": "app-role",
    "type": "IAM_ROLE",
    "provider": "AWS",
    "region": "global",
    "account_id": "111111111111",
    "arn": "arn:aws:iam::111111111111:role/app-role",
    "internet_exposed": false,
    "open_findings": 0,
    "max_severity": null,
    "uri": "cloudg://assets/app-role"
  },
  "dependency": {
    "transitive_dependents": 4,
    "by_depth": {
      "1": 2,
      "2": 1,
      "3": 1
    },
    "accounts_affected": [
      "111111111111"
    ],
    "internet_exposed_dependents": 1,
    "items": [
      {
        "id": "web-1",
        "name": "web-1",
        "type": "EC2",
        "provider": "AWS",
        "region": "us-east-1",
        "account_id": "111111111111",
        "arn": "arn:aws:ec2:us-east-1:111111111111:instance/i-0web1",
        "internet_exposed": false,
        "open_findings": 1,
        "max_severity": "HIGH",
        "uri": "cloudg://assets/web-1",
        "via": "ASSUMES_ROLE",
        "relationship": null,
        "depth": 1,
        "parent_id": "app-role"
      },
      {
        "id": "web-2",
        "name": "web-2",
        "type": "EC2",
        "provider": "AWS",
        "region": "us-east-1",
        "account_id": "111111111111",
        "arn": "arn:aws:ec2:us-east-1:111111111111:instance/i-0web2",
        "internet_exposed": false,
        "open_findings": 0,
        "max_severity": null,
        "uri": "cloudg://assets/web-2",
        "via": "ASSUMES_ROLE",
        "relationship": null,
        "depth": 1,
        "parent_id": "app-role"
      },
      "... 2 more"
    ],
    "truncated": false
  },
  "network": {
    "reachable_assets": 11,
    "max_depth": 4,
    "risk_score": 7.5,
    "sensitive_reachable": [
      {
        "id": "artifacts-bucket",
        "name": "shared-artifacts",
        "type": "S3_BUCKET",
        "provider": "AWS",
        "region": "eu-west-1",
        "account_id": "222222222222",
        "arn": "arn:aws:s3:::shared-artifacts",
        "internet_exposed": false,
        "open_findings": 0,
        "max_severity": null,
        "uri": "cloudg://assets/artifacts-bucket"
      },
      {
        "id": "data-bucket",
        "name": "prod-data",
        "type": "S3_BUCKET",
        "provider": "AWS",
        "region": "us-east-1",
        "account_id": "111111111111",
        "arn": "arn:aws:s3:::prod-data",
        "internet_exposed": false,
        "open_findings": 0,
        "max_severity": null,
        "uri": "cloudg://assets/data-bucket"
      },
      "... 3 more"
    ]
  }
}
```

Related: `dependents`, `dependency_tree`, `lateral_movement_paths(start=...)`, the `blast_radius_assessment` prompt.

### `depends_on`

Category `graph` · sensitivity `confidential` · capabilities `read_state` · readOnly true, destructive false, idempotent true, openWorld false · outputSchema yes · timeout: layer default (300 s)

Everything one asset needs, breadth-first over the dependency graph: its role, keys, image, subnet, log group, the queue or API that invokes it. Each item is an asset brief plus `via` (edge type), `relationship`, `depth` and `parent_id` (the node it was reached from). Returns `asset`, `total`, `returned`, `truncated` and `items`.

| Argument | Type | Default | Constraints | Description |
|---|---|---|---|---|
| `ref` | string | required | min length 1 | Asset reference: internal id, ARN / cloud resource id, unique name, or unique ARN tail (e.g. 'function:api' or 'i-0abc'). |
| `max_depth` | integer | `3` | 1..15 | Depth limit for the upstream walk. |
| `limit` | integer | `100` | 1..500 | Maximum items returned. |
| `dataset` | string | `""` |  | Dataset name (see list_datasets). Empty = the active dataset. |

Called with the arguments below, `depends_on` returned this `structuredContent`.

```json
{"ref": "api-handler"}
```

```json
{
  "dataset": "sample",
  "asset": {
    "id": "api-handler",
    "name": "api-handler",
    "type": "LAMBDA_FUNCTION",
    "provider": "AWS",
    "region": "us-east-1",
    "account_id": "111111111111",
    "arn": "arn:aws:lambda:us-east-1:111111111111:function:api-handler",
    "internet_exposed": false,
    "open_findings": 1,
    "max_severity": "LOW",
    "uri": "cloudg://assets/api-handler"
  },
  "total": 7,
  "returned": 7,
  "truncated": false,
  "items": [
    {
      "id": "api-gw",
      "name": "public-api",
      "type": "API_GATEWAY",
      "provider": "AWS",
      "region": "us-east-1",
      "account_id": "111111111111",
      "arn": "arn:aws:apigateway:us-east-1::/restapis/a1b2c3",
      "internet_exposed": true,
      "open_findings": 0,
      "max_severity": null,
      "uri": "cloudg://assets/api-gw",
      "via": "INVOKES",
      "relationship": null,
      "depth": 1,
      "parent_id": "api-handler"
    },
    {
      "id": "data-bucket",
      "name": "prod-data",
      "type": "S3_BUCKET",
      "provider": "AWS",
      "region": "us-east-1",
      "account_id": "111111111111",
      "arn": "arn:aws:s3:::prod-data",
      "internet_exposed": false,
      "open_findings": 0,
      "max_severity": null,
      "uri": "cloudg://assets/data-bucket",
      "via": "INVOKES",
      "relationship": "TRIGGERED_BY",
      "depth": 1,
      "parent_id": "api-handler"
    },
    "... 5 more"
  ]
}
```

### `dependents`

Category `graph` · sensitivity `confidential` · capabilities `read_state` · readOnly true, destructive false, idempotent true, openWorld false · outputSchema yes · timeout: layer default (300 s)

Everything that needs one asset, which is what breaks if it goes away. Same item shape as `depends_on`.

| Argument | Type | Default | Constraints | Description |
|---|---|---|---|---|
| `ref` | string | required | min length 1 | Asset reference: internal id, ARN / cloud resource id, unique name, or unique ARN tail (e.g. 'function:api' or 'i-0abc'). |
| `max_depth` | integer | `3` | 1..15 | Depth limit for the downstream walk. |
| `limit` | integer | `100` | 1..500 | Maximum items returned. |
| `dataset` | string | `""` |  | Dataset name (see list_datasets). Empty = the active dataset. |

Called with the arguments below, `dependents` returned this `structuredContent`.

```json
{"ref": "sg-app"}
```

```json
{
  "dataset": "sample",
  "asset": {
    "id": "sg-app",
    "name": "sg-app",
    "type": "SECURITY_GROUP",
    "provider": "AWS",
    "region": "us-east-1",
    "account_id": "111111111111",
    "arn": "arn:aws:ec2:us-east-1:111111111111:security-group/sg-0app",
    "internet_exposed": false,
    "open_findings": 0,
    "max_severity": null,
    "uri": "cloudg://assets/sg-app"
  },
  "total": 4,
  "returned": 4,
  "truncated": false,
  "items": [
    {
      "id": "web-1",
      "name": "web-1",
      "type": "EC2",
      "provider": "AWS",
      "region": "us-east-1",
      "account_id": "111111111111",
      "arn": "arn:aws:ec2:us-east-1:111111111111:instance/i-0web1",
      "internet_exposed": false,
      "open_findings": 1,
      "max_severity": "HIGH",
      "uri": "cloudg://assets/web-1",
      "via": "ATTACHED_TO",
      "relationship": null,
      "depth": 1,
      "parent_id": "sg-app"
    },
    {
      "id": "web-2",
      "name": "web-2",
      "type": "EC2",
      "provider": "AWS",
      "region": "us-east-1",
      "account_id": "111111111111",
      "arn": "arn:aws:ec2:us-east-1:111111111111:instance/i-0web2",
      "internet_exposed": false,
      "open_findings": 0,
      "max_severity": null,
      "uri": "cloudg://assets/web-2",
      "via": "ATTACHED_TO",
      "relationship": null,
      "depth": 1,
      "parent_id": "sg-app"
    },
    "... 2 more"
  ]
}
```

### `dependency_tree`

Category `graph` · sensitivity `confidential` · capabilities `read_state` · readOnly true, destructive false, idempotent true, openWorld false · outputSchema no · timeout: layer default (300 s)

The nested upstream and downstream tree of one asset, the view `cloudg deps` prints. `direction` picks `depends_on`, `dependents` or both. Each node has `id`, `name`, `type`, `account_id`, `via`, `relationship` and `children`. `include_hierarchy` adds organization and account containment edges. The tree is cut to `max_nodes` nodes depth-first in list order; `truncated` is true only when nodes were actually left out.

| Argument | Type | Default | Constraints | Description |
|---|---|---|---|---|
| `ref` | string | required | min length 1 | Asset reference: internal id, ARN / cloud resource id, unique name, or unique ARN tail (e.g. 'function:api' or 'i-0abc'). |
| `direction` | string | `"both"` | one of `up`, `down`, `both` | up = what it depends on, down = what depends on it. |
| `max_depth` | integer | `3` | 1..6 | Depth of the tree in each direction. |
| `include_hierarchy` | boolean | `false` |  | Include org / account containment edges. |
| `max_nodes` | integer | `200` | 1..1000 | Node budget across both trees; pruning is depth-first in list order. |
| `dataset` | string | `""` |  | Dataset name (see list_datasets). Empty = the active dataset. |

Called with the arguments below, `dependency_tree` returned this `structuredContent`.

```json
{"ref": "api-handler", "direction": "both", "max_depth": 2}
```

```json
{
  "dataset": "sample",
  "asset": {
    "id": "api-handler",
    "name": "api-handler",
    "arn": "arn:aws:lambda:us-east-1:111111111111:function:api-handler",
    "type": "LAMBDA_FUNCTION",
    "account_id": "111111111111",
    "region": "us-east-1"
  },
  "depends_on": [
    {
      "id": "api-gw",
      "name": "public-api",
      "arn": "arn:aws:apigateway:us-east-1::/restapis/a1b2c3",
      "type": "API_GATEWAY",
      "account_id": "111111111111",
      "region": "us-east-1",
      "via": "INVOKES",
      "relationship": null,
      "children": []
    },
    {
      "id": "data-bucket",
      "name": "prod-data",
      "arn": "arn:aws:s3:::prod-data",
      "type": "S3_BUCKET",
      "account_id": "111111111111",
      "region": "us-east-1",
      "via": "INVOKES",
      "relationship": "TRIGGERED_BY",
      "children": []
    },
    "... 4 more"
  ],
  "dependents": [],
  "truncated": false
}
```

Called with the arguments below, `dependency_tree` returned this `structuredContent`.

```json
{"ref": "kms-main", "direction": "down", "max_nodes": 2}
```

```json
{
  "dataset": "sample",
  "asset": {
    "id": "kms-main",
    "name": "prod-main-key",
    "arn": "arn:aws:kms:us-east-1:111111111111:key/1111-2222",
    "type": "KMS_KEY",
    "account_id": "111111111111",
    "region": "us-east-1"
  },
  "dependents": [
    {
      "id": "api-handler",
      "name": "api-handler",
      "arn": "arn:aws:lambda:us-east-1:111111111111:function:api-handler",
      "type": "LAMBDA_FUNCTION",
      "account_id": "111111111111",
      "region": "us-east-1",
      "via": "REFERENCES",
      "relationship": "ENCRYPTED_BY_KMS",
      "children": []
    },
    {
      "id": "data-bucket",
      "name": "prod-data",
      "arn": "arn:aws:s3:::prod-data",
      "type": "S3_BUCKET",
      "account_id": "111111111111",
      "region": "us-east-1",
      "via": "REFERENCES",
      "relationship": "ENCRYPTED_BY_KMS",
      "children": []
    }
  ],
  "truncated": true
}
```

### `shared_dependencies`

Category `graph` · sensitivity `confidential` · capabilities `read_state` · readOnly true, destructive false, idempotent true, openWorld false · outputSchema no · timeout: layer default (300 s)

Single points of failure: the assets with the most direct dependents (one KMS key behind many resources, one role behind every function), not counting pure containment. Items have `id`, `name`, `type`, `account_id` and `direct_dependents`.

| Argument | Type | Default | Constraints | Description |
|---|---|---|---|---|
| `top` | integer | `25` | 1..200 | Number of assets returned. |
| `dataset` | string | `""` |  | Dataset name (see list_datasets). Empty = the active dataset. |

Called with the arguments below, `shared_dependencies` returned this `structuredContent`.

```json
{"top": 5}
```

```json
{
  "dataset": "sample",
  "items": [
    {
      "id": "kms-main",
      "name": "prod-main-key",
      "arn": "arn:aws:kms:us-east-1:111111111111:key/1111-2222",
      "type": "KMS_KEY",
      "account_id": "111111111111",
      "region": "us-east-1",
      "direct_dependents": 4
    },
    {
      "id": "sg-app",
      "name": "sg-app",
      "arn": "arn:aws:ec2:us-east-1:111111111111:security-group/sg-0app",
      "type": "SECURITY_GROUP",
      "account_id": "111111111111",
      "region": "us-east-1",
      "direct_dependents": 2
    },
    {
      "id": "ecr-repo",
      "name": "app-images",
      "arn": "arn:aws:ecr:eu-west-1:222222222222:repository/app-images",
      "type": "CONTAINER_REGISTRY",
      "account_id": "222222222222",
      "region": "eu-west-1",
      "direct_dependents": 2
    },
    "... 2 more"
  ],
  "returned": 5
}
```

### `largest_blast_radius`

Category `graph` · sensitivity `confidential` · capabilities `read_state` · readOnly true, destructive false, idempotent true, openWorld false · outputSchema no · timeout: layer default (300 s)

The assets whose failure or change affects the most others. Items have `id`, `name`, `type`, `account_id`, `transitive_dependents`, `accounts_affected` (a count here) and `internet_exposed_dependents`. Use `blast_radius(ref)` for the detail of one.

| Argument | Type | Default | Constraints | Description |
|---|---|---|---|---|
| `top` | integer | `15` | 1..100 | Number of assets returned. |
| `dataset` | string | `""` |  | Dataset name (see list_datasets). Empty = the active dataset. |

Called with the arguments below, `largest_blast_radius` returned this `structuredContent`.

```json
{"top": 3}
```

```json
{
  "dataset": "sample",
  "items": [
    {
      "id": "kms-main",
      "name": "prod-main-key",
      "arn": "arn:aws:kms:us-east-1:111111111111:key/1111-2222",
      "type": "KMS_KEY",
      "account_id": "111111111111",
      "region": "us-east-1",
      "transitive_dependents": 12,
      "accounts_affected": 1,
      "internet_exposed_dependents": 2
    },
    {
      "id": "vpc-prod",
      "name": "prod-vpc",
      "arn": "arn:aws:ec2:us-east-1:111111111111:vpc/vpc-0prod",
      "type": "VPC",
      "account_id": "111111111111",
      "region": "us-east-1",
      "transitive_dependents": 9,
      "accounts_affected": 1,
      "internet_exposed_dependents": 2
    },
    {
      "id": "ecr-repo",
      "name": "app-images",
      "arn": "arn:aws:ecr:eu-west-1:222222222222:repository/app-images",
      "type": "CONTAINER_REGISTRY",
      "account_id": "222222222222",
      "region": "eu-west-1",
      "transitive_dependents": 8,
      "accounts_affected": 3,
      "internet_exposed_dependents": 1
    }
  ],
  "returned": 3
}
```

### `cross_account_edges`

Category `graph` · sensitivity `confidential` · capabilities `read_state` · readOnly true, destructive false, idempotent true, openWorld false · outputSchema no · timeout: layer default (300 s)

Relationships whose two ends are in different accounts, subscriptions or projects: trust, grants, image pulls, peering, shared resources. Rows come from `cloudg.inventory.dependencies.cross_account_edges` and identify endpoints by ARN (or id when there is none), not by internal id: `source`, `source_account`, `target`, `target_account`, `edge_type`, `relationship`, `external` (true when one side is an account outside the mapped estate). `by_account_pair` counts every matching row, not just the page.

| Argument | Type | Default | Constraints | Description |
|---|---|---|---|---|
| `account_id` | string | `""` |  | Only edges touching this account. |
| `external_only` | boolean | `false` |  | Only edges to accounts outside the mapped estate. |
| `edge_types` | string[] or null | `null` |  | Only these EdgeType values. |
| `limit` | integer | `50` | 1..500 | Maximum items to return. |
| `cursor` | string | `""` |  | Opaque cursor from a previous call's next_cursor; empty = first page. |
| `dataset` | string | `""` |  | Dataset name (see list_datasets). Empty = the active dataset. |

Called with the arguments below, `cross_account_edges` returned this `structuredContent`.

```json
{}
```

```json
{
  "dataset": "sample",
  "total": 3,
  "offset": 0,
  "returned": 3,
  "next_cursor": null,
  "truncated": false,
  "by_account_pair": {
    "111111111111 -> 222222222222": 2,
    "999999999999 -> 222222222222": 1
  },
  "items": [
    {
      "source": "arn:aws:iam::111111111111:role/app-role",
      "source_account": "111111111111",
      "target": "arn:aws:iam::222222222222:role/deploy-role",
      "target_account": "222222222222",
      "edge_type": "IAM_TRUST",
      "relationship": "CROSS_ACCOUNT_TRUST",
      "external": false
    },
    {
      "source": "arn:aws:iam::999999999999:root",
      "source_account": "999999999999",
      "target": "arn:aws:iam::222222222222:role/deploy-role",
      "target_account": "222222222222",
      "edge_type": "IAM_TRUST",
      "relationship": "CROSS_ACCOUNT_TRUST",
      "external": true
    },
    {
      "source": "arn:aws:lambda:us-east-1:111111111111:function:api-handler",
      "source_account": "111111111111",
      "target": "arn:aws:ecr:eu-west-1:222222222222:repository/app-images",
      "target_account": "222222222222",
      "edge_type": "USES_IMAGE",
      "relationship": null,
      "external": false
    }
  ]
}
```

Called with the arguments below, `cross_account_edges` returned this `structuredContent`.

```json
{"external_only": true}
```

```json
{
  "dataset": "sample",
  "total": 1,
  "offset": 0,
  "returned": 1,
  "next_cursor": null,
  "truncated": false,
  "by_account_pair": {
    "999999999999 -> 222222222222": 1
  },
  "items": [
    {
      "source": "arn:aws:iam::999999999999:root",
      "source_account": "999999999999",
      "target": "arn:aws:iam::222222222222:role/deploy-role",
      "target_account": "222222222222",
      "edge_type": "IAM_TRUST",
      "relationship": "CROSS_ACCOUNT_TRUST",
      "external": true
    }
  ]
}
```

Related: `get_edges(cross_account_only=true)`, `lateral_movement_paths`, `organization_topology`.

### `centrality_top`

Category `graph` · sensitivity `confidential` · capabilities `read_state` · readOnly true, destructive false, idempotent true, openWorld false · outputSchema no · timeout: layer default (300 s)

Most connected or most "in the middle" assets in the relationship graph. `degree`, `in_degree` and `out_degree` are NetworkX degree centralities; `betweenness` marks chokepoints that many shortest paths cross. Placeholder nodes take part in the computation but are not ranked. Scores are cached per metric and dataset version. Items are asset briefs plus `score` (5 decimals) and `degree`; `sampled` says whether betweenness was sampled.

| Argument | Type | Default | Constraints | Description |
|---|---|---|---|---|
| `metric` | string | `"degree"` | one of `degree`, `in_degree`, `out_degree`, `betweenness` | Centrality measure. Betweenness is sampled (k=300, seed 7) above 1,500 nodes. |
| `top` | integer | `20` | 1..200 | Number of assets returned. |
| `asset_types` | string[] or null | `null` |  | Only rank these AssetType values. |
| `dataset` | string | `""` |  | Dataset name (see list_datasets). Empty = the active dataset. |

Called with the arguments below, `centrality_top` returned this `structuredContent`.

```json
{"metric": "betweenness", "top": 3}
```

```json
{
  "dataset": "sample",
  "metric": "betweenness",
  "sampled": false,
  "items": [
    {
      "id": "app-role",
      "name": "app-role",
      "type": "IAM_ROLE",
      "provider": "AWS",
      "region": "global",
      "account_id": "111111111111",
      "arn": "arn:aws:iam::111111111111:role/app-role",
      "internet_exposed": false,
      "open_findings": 0,
      "max_severity": null,
      "uri": "cloudg://assets/app-role",
      "score": 0.06078,
      "degree": 5
    },
    {
      "id": "vpc-prod",
      "name": "prod-vpc",
      "type": "VPC",
      "provider": "AWS",
      "region": "us-east-1",
      "account_id": "111111111111",
      "arn": "arn:aws:ec2:us-east-1:111111111111:vpc/vpc-0prod",
      "internet_exposed": false,
      "open_findings": 1,
      "max_severity": "INFO",
      "uri": "cloudg://assets/vpc-prod",
      "score": 0.04863,
      "degree": 3
    },
    {
      "id": "acct-prod",
      "name": "prod",
      "type": "CLOUD_ACCOUNT",
      "provider": "AWS",
      "region": "global",
      "account_id": "111111111111",
      "arn": "arn:aws:iam::111111111111:root",
      "internet_exposed": false,
      "open_findings": 0,
      "max_severity": null,
      "uri": "cloudg://assets/acct-prod",
      "score": 0.03805,
      "degree": 2
    }
  ]
}
```

Called with the arguments below, `centrality_top` returned this `structuredContent`.

```json
{"metric": "in_degree", "top": 3, "asset_types": ["IAM_ROLE"]}
```

```json
{
  "dataset": "sample",
  "metric": "in_degree",
  "sampled": false,
  "items": [
    {
      "id": "app-role",
      "name": "app-role",
      "type": "IAM_ROLE",
      "provider": "AWS",
      "region": "global",
      "account_id": "111111111111",
      "arn": "arn:aws:iam::111111111111:role/app-role",
      "internet_exposed": false,
      "open_findings": 0,
      "max_severity": null,
      "uri": "cloudg://assets/app-role",
      "score": 0.04545,
      "degree": 5
    },
    {
      "id": "deploy-role",
      "name": "deploy-role",
      "type": "IAM_ROLE",
      "provider": "AWS",
      "region": "global",
      "account_id": "222222222222",
      "arn": "arn:aws:iam::222222222222:role/deploy-role",
      "internet_exposed": false,
      "open_findings": 1,
      "max_severity": "HIGH",
      "uri": "cloudg://assets/deploy-role",
      "score": 0.04545,
      "degree": 4
    },
    "... 1 more"
  ]
}
```

### `subgraph_export`

Category `graph` · sensitivity `restricted` · capabilities `read_state` · readOnly true, destructive false, idempotent true, openWorld false · outputSchema no · timeout: layer default (300 s)

The neighbourhood of a few assets as a self-contained graph document, for visualisation or another tool. Each seed is resolved (the internet alias works), the walk goes `depth` hops in both directions over `edge_types` (all when unset), the node set is capped at `max_nodes`, and a fresh `GraphBuilder` renders the assets and the edges between kept nodes. `format` is `d3` (`{nodes, links}`), `cytoscape` (`{elements: {nodes, edges}}`) or `graphml` (an XML string). Returns `format`, `nodes`, `edges`, `truncated` and `graph`. For the whole graph read `cloudg://graph/{format}` instead. The tool is `restricted`: the GraphML form is one opaque string the privacy transforms cannot look inside, so `strict` and the `soc-analyst` analyst do not see it.

| Argument | Type | Default | Constraints | Description |
|---|---|---|---|---|
| `seeds` | string[] | required | min items 1; max items 50 | Asset refs to start from. |
| `depth` | integer | `1` | 0..4 | Hops around each seed (0 = only the seeds). |
| `format` | string | `"d3"` | one of `d3`, `cytoscape`, `graphml` | Output format of `graph`. |
| `max_nodes` | integer | `300` | 1..2000 | Node cap for the whole sub-graph. |
| `edge_types` | string[] or null | `null` |  | Only walk and keep these EdgeType values. |
| `dataset` | string | `""` |  | Dataset name (see list_datasets). Empty = the active dataset. |

Called with the arguments below, `subgraph_export` returned this `structuredContent`.

```json
{"seeds": ["web-1"], "depth": 1, "format": "d3"}
```

```json
{
  "dataset": "sample",
  "format": "d3",
  "nodes": 6,
  "edges": 5,
  "truncated": false,
  "graph": {
    "nodes": [
      {
        "id": "web-1",
        "name": "web-1",
        "type": "EC2",
        "provider": "AWS",
        "region": "us-east-1",
        "arn": "arn:aws:ec2:us-east-1:111111111111:instance/i-0web1",
        "account_id": "111111111111",
        "is_internet_exposed": false,
        "is_external": false
      },
      {
        "id": "subnet-private",
        "name": "prod-private-a",
        "type": "SUBNET",
        "provider": "AWS",
        "region": "us-east-1",
        "arn": "arn:aws:ec2:us-east-1:111111111111:subnet/subnet-0priv",
        "account_id": "111111111111",
        "is_internet_exposed": false,
        "is_external": false
      },
      "... 3 more"
    ],
    "links": [
      {
        "source": "web-1",
        "target": "sg-app",
        "type": "ATTACHED_TO",
        "port_range": "",
        "protocol": "",
        "cidr": "",
        "direction": "ingress",
        "relationship": "",
        "description": ""
      },
      {
        "source": "web-1",
        "target": "app-role",
        "type": "ASSUMES_ROLE",
        "port_range": "",
        "protocol": "",
        "cidr": "",
        "direction": "ingress",
        "relationship": "",
        "description": ""
      },
      "... 2 more"
    ]
  }
}
```

Called with the arguments below, `subgraph_export` returned this `structuredContent`.

```json
{"seeds": ["bastion"], "depth": 1, "format": "cytoscape", "edge_types": ["ASSUMES_ROLE"]}
```

```json
{
  "dataset": "sample",
  "format": "cytoscape",
  "nodes": 2,
  "edges": 1,
  "truncated": false,
  "graph": {
    "elements": {
      "nodes": [
        {
          "data": {
            "id": "bastion",
            "label": "bastion",
            "type": "EC2",
            "provider": "AWS",
            "region": "us-east-1",
            "internet_exposed": true
          }
        },
        {
          "data": {
            "id": "admin-role",
            "label": "bastion-admin",
            "type": "IAM_ROLE",
            "provider": "AWS",
            "region": "global",
            "internet_exposed": false
          }
        }
      ],
      "edges": [
        {
          "data": {
            "source": "bastion",
            "target": "admin-role",
            "type": "ASSUMES_ROLE",
            "port_range": "",
            "protocol": ""
          }
        }
      ]
    }
  }
}
```

Called with the arguments below, `subgraph_export` returned this `structuredContent`.

```json
{"seeds": ["web-1"], "depth": 0, "format": "graphml"}
```

```json
{
  "dataset": "sample",
  "format": "graphml",
  "nodes": 1,
  "edges": 0,
  "truncated": false,
  "graph": "<graphml xmlns=\"http://graphml.graphdrawing.org/xmlns\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:schemaLocation=\"http://graphml.graphdrawing.org/xmlns http://graphml.graphdrawing.org/x..."
}
```

An empty `seeds` list fails schema validation (`min items 1`).

### `security_coverage`

Category `graph` · sensitivity `confidential` · capabilities `read_state` · readOnly true, destructive false, idempotent true, openWorld false · outputSchema no · timeout: layer default (300 s)

Which security services are enabled per account and region, and which workloads nothing watches. `services_by_account_region` maps account to region to service to an enabled flag, built from every asset whose metadata has a `security_service` key (GuardDuty detectors, Security Hub, Inspector and so on, whatever the collectors recorded). `gaps` lists `account/region: service` strings for services recorded as disabled. `workloads_without_vulnerability_scanning` lists EC2 instances, container registries and Lambda functions that no enabled `VULNERABILITY_SCANNER` asset `MONITORS` (items have `name`, `arn`, `type`, `account_id`, `region`); Azure and GCP compute types are not checked. `internet_facing_without_waf` lists internet-exposed load balancers, API gateways and CloudFront distributions without an incoming `PROTECTS` edge (`name`, `arn`, `type`, `account_id`). Each list is `{total, returned, truncated, items}` capped at `limit`.

| Argument | Type | Default | Constraints | Description |
|---|---|---|---|---|
| `limit` | integer | `50` | 1..500 | Cap on each of the three lists. |
| `dataset` | string | `""` |  | Dataset name (see list_datasets). Empty = the active dataset. |

Called with the arguments below, `security_coverage` returned this `structuredContent`.

```json
{}
```

```json
{
  "dataset": "sample",
  "services_by_account_region": {
    "111111111111": {
      "us-east-1": {
        "guardduty": true,
        "securityhub": false,
        "inspector": true
      }
    }
  },
  "gaps": {
    "total": 1,
    "returned": 1,
    "truncated": false,
    "items": [
      "111111111111/us-east-1: securityhub"
    ]
  },
  "workloads_without_vulnerability_scanning": {
    "total": 4,
    "returned": 4,
    "truncated": false,
    "items": [
      {
        "name": "web-2",
        "arn": "arn:aws:ec2:us-east-1:111111111111:instance/i-0web2",
        "type": "EC2",
        "account_id": "111111111111",
        "region": "us-east-1"
      },
      {
        "name": "bastion",
        "arn": "arn:aws:ec2:us-east-1:111111111111:instance/i-0bast",
        "type": "EC2",
        "account_id": "111111111111",
        "region": "us-east-1"
      },
      "... 2 more"
    ]
  },
  "internet_facing_without_waf": {
    "total": 1,
    "returned": 1,
    "truncated": false,
    "items": [
      {
        "name": "public-api",
        "arn": "arn:aws:apigateway:us-east-1::/restapis/a1b2c3",
        "type": "API_GATEWAY",
        "account_id": "111111111111"
      }
    ]
  }
}
```

### `graph_stats`

Category `graph` · sensitivity `internal` · capabilities `read_state` · readOnly true, destructive false, idempotent true, openWorld false · outputSchema no · timeout: layer default (300 s)

Shape of the relationship graph: `nodes` (assets plus placeholders), `asset_nodes`, `placeholder_nodes`, `edges` (raw edge count), `graph_edges` (after parallel rule edges are merged and other parallel edges collapse), `edges_by_type`, `edges_by_relationship` (top 30), `components` (weakly connected), `largest_component`, `isolated_assets`, `density` and `mean_degree`.

| Argument | Type | Default | Constraints | Description |
|---|---|---|---|---|
| `dataset` | string | `""` |  | Dataset name (see list_datasets). Empty = the active dataset. |

Called with the arguments below, `graph_stats` returned this `structuredContent`.

```json
{}
```

```json
{
  "dataset": "sample",
  "nodes": 45,
  "asset_nodes": 44,
  "placeholder_nodes": 1,
  "edges": 56,
  "graph_edges": 56,
  "edges_by_type": {
    "CONTAINS": 12,
    "GOVERNS": 1,
    "SECURITY_GROUP_RULE": 4,
    "INTERNET_EXPOSED": 4,
    "ATTACHED_TO": 6,
    "...": "10 more"
  },
  "edges_by_relationship": {
    "INTERNET_REACHABLE": 4,
    "ENCRYPTED_BY_KMS": 4,
    "CROSS_ACCOUNT_TRUST": 2,
    "READS_FROM": 1,
    "TRIGGERED_BY": 1
  },
  "components": 3,
  "largest_component": 43,
  "isolated_assets": 2,
  "density": 0.028283,
  "mean_degree": 2.489
}
```

## Findings

Findings come from scanners (Prowler, ScoutSuite, Checkov, Trivy, the IAM linter), from cloudg's reachability analysis, or from a loaded `findings.json`. Each finding is matched to an asset as described under [Briefs](#briefs). Suppressed findings stay in the dataset but drop out of `list_findings` (unless asked), every count of open findings, `top_risks`, compliance roll-ups and the prompts.

### `list_findings`

Category `findings` · sensitivity `confidential` · capabilities `read_state` · readOnly true, destructive false, idempotent true, openWorld false · outputSchema yes · timeout: layer default (300 s)

Searches findings with filters, sorting and cursor pagination. `severity_breakdown` counts every match, not only the current page.

| Argument | Type | Default | Constraints | Description |
|---|---|---|---|---|
| `severities` | string[] or null | `null` |  | Any of CRITICAL, HIGH, MEDIUM, LOW, INFO. |
| `min_severity` | string | `""` |  | At or above this severity. |
| `source_tool` | string | `""` |  | Substring of the producing tool, e.g. 'prowler', 'cloudg-reachability'. |
| `framework` | string | `""` |  | Substring of a compliance framework, e.g. 'CIS', 'PCI'. |
| `resource` | string | `""` |  | Only findings on this asset (ref). |
| `query` | string | `""` |  | Substring of title or description. |
| `include_suppressed` | boolean | `false` |  | Also return suppressed findings. |
| `sort_by` | string | `"risk"` | one of `risk`, `severity`, `detected_at`, `title`, `source_tool` | Sort order (see the sorting table). |
| `fields` | string[] or null | `null` |  | Project items to these fields. Valid: id, title, severity, risk_score, source_tool, resource_id, resource_arn, asset_id, asset_name, compliance_frameworks, is_suppressed, cvss_score, detected_at, uri |
| `limit` | integer | `50` | 1..500 | Maximum items to return. |
| `cursor` | string | `""` |  | Opaque cursor from a previous call's next_cursor; empty = first page. |
| `dataset` | string | `""` |  | Dataset name (see list_datasets). Empty = the active dataset. |

Filter semantics: `severities` is an exact set; `min_severity` a threshold; `source_tool` and `framework` are case-insensitive substrings (`pci` matches `PCI-DSS`); `resource` resolves an asset reference and keeps the findings matched to it; `query` is a case-insensitive substring of the title or description.

Called with the arguments below, `list_findings` returned this `structuredContent`.

```json
{"limit": 3}
```

```json
{
  "dataset": "sample",
  "total": 11,
  "offset": 0,
  "returned": 3,
  "next_cursor": "c3.ab0acc7643a8",
  "truncated": true,
  "severity_breakdown": {
    "CRITICAL": 2,
    "HIGH": 5,
    "MEDIUM": 2,
    "LOW": 1,
    "INFO": 1
  },
  "items": [
    {
      "id": "f-rdp-open",
      "title": "NSG allows RDP (3389) from Internet",
      "severity": "CRITICAL",
      "risk_score": 9.5,
      "source_tool": "scoutsuite",
      "resource_id": "az-nsg",
      "resource_arn": null,
      "asset_id": "az-nsg",
      "asset_name": "jump-nsg",
      "compliance_frameworks": [
        "CIS-Azure"
      ],
      "is_suppressed": false,
      "cvss_score": null,
      "detected_at": "2026-01-15T12:00:00+00:00",
      "uri": "cloudg://findings/f-rdp-open"
    },
    {
      "id": "f-ssh-open",
      "title": "Security group allows SSH (22) from 0.0.0.0/0",
      "severity": "CRITICAL",
      "risk_score": 9.5,
      "source_tool": "prowler",
      "resource_id": "sg-admin",
      "resource_arn": "arn:aws:ec2:us-east-1:111111111111:security-group/sg-0admin",
      "asset_id": "sg-admin",
      "asset_name": "sg-admin",
      "compliance_frameworks": [
        "CIS-AWS",
        "PCI-DSS"
      ],
      "is_suppressed": false,
      "cvss_score": null,
      "detected_at": "2026-01-15T12:00:00+00:00",
      "uri": "cloudg://findings/f-ssh-open"
    },
    "... 1 more"
  ]
}
```

With a framework filter and projection:

Called with the arguments below, `list_findings` returned this `structuredContent`.

```json
{"framework": "pci", "fields": ["title", "severity", "asset_name"]}
```

```json
{
  "dataset": "sample",
  "total": 3,
  "offset": 0,
  "returned": 3,
  "next_cursor": null,
  "truncated": false,
  "severity_breakdown": {
    "CRITICAL": 1,
    "HIGH": 2
  },
  "items": [
    {
      "id": "f-ssh-open",
      "title": "Security group allows SSH (22) from 0.0.0.0/0",
      "severity": "CRITICAL",
      "asset_name": "sg-admin"
    },
    {
      "id": "f-web-cve",
      "title": "CVE-2024-1234 in openssl 3.0.1",
      "severity": "HIGH",
      "asset_name": "web-1"
    },
    "... 1 more"
  ]
}
```

Suppressed findings appear only with `include_suppressed`:

Called with the arguments below, `list_findings` returned this `structuredContent`.

```json
{"resource": "data-bucket", "include_suppressed": true}
```

```json
{
  "dataset": "sample",
  "total": 1,
  "offset": 0,
  "returned": 1,
  "next_cursor": null,
  "truncated": false,
  "severity_breakdown": {
    "LOW": 1
  },
  "items": [
    {
      "id": "f-versioning",
      "title": "S3 versioning disabled",
      "severity": "LOW",
      "risk_score": 2.5,
      "source_tool": "prowler",
      "resource_id": "data-bucket",
      "resource_arn": null,
      "asset_id": "data-bucket",
      "asset_name": "prod-data",
      "compliance_frameworks": [
        "CIS-AWS"
      ],
      "is_suppressed": true,
      "cvss_score": null,
      "detected_at": "2026-01-15T12:00:00+00:00",
      "uri": "cloudg://findings/f-versioning"
    }
  ]
}
```

Related: `get_finding`, `findings_summary`, `cloudg://findings/severity/{severity}`.

### `get_finding`

Category `findings` · sensitivity `confidential` · capabilities `read_state` · readOnly true, destructive false, idempotent true, openWorld false · outputSchema no · timeout: layer default (300 s)

One finding in full. `finding_id` is the finding's `id`; a scanner's own `source_finding_id` also works when exactly one finding has it. Returns the finding brief plus `description`, `evidence`, `remediation`, `source_finding_id`, `controls` (every compliance result that lists this finding: `framework`, `control_id`, `control_title`, `status`), `suppression_reason` when suppressed, and `asset` (brief) when the finding is matched. Links the affected asset and `cloudg://findings/{id}`.

| Argument | Type | Default | Constraints | Description |
|---|---|---|---|---|
| `finding_id` | string | required | min length 1 | Finding id (or the scanner's source_finding_id). |
| `dataset` | string | `""` |  | Dataset name (see list_datasets). Empty = the active dataset. |

Called with the arguments below, `get_finding` returned this `structuredContent`.

```json
{"finding_id": "f-ssh-open"}
```

```json
{
  "id": "f-ssh-open",
  "title": "Security group allows SSH (22) from 0.0.0.0/0",
  "severity": "CRITICAL",
  "risk_score": 9.5,
  "source_tool": "prowler",
  "resource_id": "sg-admin",
  "resource_arn": "arn:aws:ec2:us-east-1:111111111111:security-group/sg-0admin",
  "asset_id": "sg-admin",
  "asset_name": "sg-admin",
  "compliance_frameworks": [
    "CIS-AWS",
    "PCI-DSS"
  ],
  "is_suppressed": false,
  "cvss_score": null,
  "detected_at": "2026-01-15T12:00:00+00:00",
  "uri": "cloudg://findings/f-ssh-open",
  "description": "Security group allows SSH (22) from 0.0.0.0/0.",
  "evidence": "IpPermissions 0.0.0.0/0 tcp 22",
  "remediation": "Restrict 22 to the VPN.",
  "source_finding_id": "prowler-aws-ec2_sg_open_22-1",
  "controls": [
    {
      "framework": "CIS-AWS",
      "control_id": "5.2",
      "control_title": "No SG allows 0.0.0.0/0 to admin ports",
      "status": "FAIL"
    },
    {
      "framework": "PCI-DSS",
      "control_id": "1.3.1",
      "control_title": "Inbound traffic restricted",
      "status": "FAIL"
    }
  ],
  "asset": {
    "id": "sg-admin",
    "name": "sg-admin",
    "type": "SECURITY_GROUP",
    "provider": "AWS",
    "region": "us-east-1",
    "account_id": "111111111111",
    "arn": "arn:aws:ec2:us-east-1:111111111111:security-group/sg-0admin",
    "internet_exposed": false,
    "open_findings": 1,
    "max_severity": "CRITICAL",
    "uri": "cloudg://assets/sg-admin"
  }
}
```

The result also carried these resource links in `content`:

```json
[
  {
    "type": "resource_link",
    "uri": "cloudg://assets/sg-admin",
    "name": "sg-admin",
    "title": "Affected asset",
    "mimeType": "application/json"
  },
  {
    "type": "resource_link",
    "uri": "cloudg://findings/f-ssh-open",
    "name": "Security group allows SSH (22) from 0.0.0.0/0",
    "mimeType": "application/json"
  }
]
```

By scanner id (`source_finding_id` of the Trivy finding):

Called with the arguments below, `get_finding` returned this `structuredContent`.

```json
{"finding_id": "CVE-2024-1234"}
```

```json
{
  "id": "f-web-cve",
  "title": "CVE-2024-1234 in openssl 3.0.1",
  "severity": "HIGH",
  "risk_score": 7.8,
  "source_tool": "trivy",
  "resource_id": "web-1",
  "resource_arn": null,
  "asset_id": "web-1",
  "asset_name": "web-1",
  "compliance_frameworks": [
    "PCI-DSS"
  ],
  "is_suppressed": false,
  "cvss_score": 8.1,
  "detected_at": "2026-01-15T12:00:00+00:00",
  "uri": "cloudg://findings/f-web-cve",
  "description": "CVE-2024-1234 in openssl 3.0.1.",
  "evidence": null,
  "remediation": null,
  "source_finding_id": "CVE-2024-1234",
  "controls": [],
  "asset": {
    "id": "web-1",
    "name": "web-1",
    "type": "EC2",
    "provider": "AWS",
    "region": "us-east-1",
    "account_id": "111111111111",
    "arn": "arn:aws:ec2:us-east-1:111111111111:instance/i-0web1",
    "internet_exposed": false,
    "open_findings": 1,
    "max_severity": "HIGH",
    "uri": "cloudg://assets/web-1"
  }
}
```

A miss suggests ids that contain the given text:

```json
{
  "tool": "get_finding",
  "arguments": {
    "finding_id": "f-ssh"
  },
  "isError": true,
  "text": "No finding with that id in this dataset. 1 close match, see suggestions in the error data. Use list_findings to browse finding ids.",
  "_meta": {
    "cloudg/error_code": -32602,
    "cloudg/error_data": {
      "value": "f-ssh",
      "dataset": "sample",
      "suggestions": [
        {
          "finding_id": "f-ssh-open",
          "dataset": "sample"
        }
      ]
    }
  }
}
```

### `findings_summary`

Category `findings` · sensitivity `internal` · capabilities `read_state` · readOnly true, destructive false, idempotent true, openWorld false · outputSchema no · timeout: layer default (300 s)

Finding counts grouped by severity, source tool, compliance framework, asset type, account or asset. Each group is `{"total": n, "<SEVERITY>": n, ...}`. With `group_by: "framework"` a finding counts once in each of its frameworks, and findings without one go under `(none)`. With the asset-based groupings, findings not matched to an asset go under `unmapped`. `total` is the number of findings counted (open, or all with `include_suppressed`), not the sum of the groups; `suppressed` is always the dataset's suppressed count.

| Argument | Type | Default | Constraints | Description |
|---|---|---|---|---|
| `group_by` | string | `"severity"` | one of `severity`, `source_tool`, `framework`, `asset_type`, `account`, `asset` | Grouping dimension. `asset_type`, `account` and `asset` use the matched asset; unmatched findings go to `unmapped`. |
| `include_suppressed` | boolean | `false` |  | Count suppressed findings too. |
| `top` | integer | `25` | 1..200 | Maximum number of groups returned. |
| `dataset` | string | `""` |  | Dataset name (see list_datasets). Empty = the active dataset. |

Called with the arguments below, `findings_summary` returned this `structuredContent`.

```json
{}
```

```json
{
  "dataset": "sample",
  "group_by": "severity",
  "total": 11,
  "suppressed": 1,
  "groups": {
    "CRITICAL": {
      "total": 2,
      "CRITICAL": 2
    },
    "HIGH": {
      "total": 5,
      "HIGH": 5
    },
    "MEDIUM": {
      "total": 2,
      "MEDIUM": 2
    },
    "LOW": {
      "total": 1,
      "LOW": 1
    },
    "INFO": {
      "total": 1,
      "INFO": 1
    }
  },
  "truncated": false
}
```

Called with the arguments below, `findings_summary` returned this `structuredContent`.

```json
{"group_by": "account"}
```

```json
{
  "dataset": "sample",
  "group_by": "account",
  "total": 11,
  "suppressed": 1,
  "groups": {
    "111111111111": {
      "total": 7,
      "CRITICAL": 1,
      "HIGH": 3,
      "MEDIUM": 1,
      "LOW": 1,
      "INFO": 1
    },
    "00000000-aaaa-bbbb-cccc-000000000001": {
      "total": 1,
      "CRITICAL": 1
    },
    "222222222222": {
      "total": 1,
      "HIGH": 1
    },
    "proj-analytics": {
      "total": 1,
      "HIGH": 1
    },
    "unmapped": {
      "total": 1,
      "MEDIUM": 1
    }
  },
  "truncated": false
}
```

Called with the arguments below, `findings_summary` returned this `structuredContent`.

```json
{"group_by": "framework", "include_suppressed": true, "top": 3}
```

```json
{
  "dataset": "sample",
  "group_by": "framework",
  "total": 12,
  "suppressed": 1,
  "groups": {
    "CIS-AWS": {
      "total": 7,
      "CRITICAL": 1,
      "HIGH": 3,
      "MEDIUM": 2,
      "LOW": 1
    },
    "PCI-DSS": {
      "total": 3,
      "CRITICAL": 1,
      "HIGH": 2
    },
    "(none)": {
      "total": 2,
      "LOW": 1,
      "INFO": 1
    }
  },
  "truncated": true
}
```

### `findings_for_asset`

Category `findings` · sensitivity `confidential` · capabilities `read_state` · readOnly true, destructive false, idempotent true, openWorld false · outputSchema yes · timeout: layer default (300 s)

Every finding on one asset, highest risk first, as briefs. Returns `asset`, `total`, `returned`, `truncated` and `items`; no cursor.

| Argument | Type | Default | Constraints | Description |
|---|---|---|---|---|
| `ref` | string | required | min length 1 | Asset reference: internal id, ARN / cloud resource id, unique name, or unique ARN tail (e.g. 'function:api' or 'i-0abc'). |
| `include_suppressed` | boolean | `false` |  | Also return suppressed findings. |
| `limit` | integer | `50` | 1..500 | Maximum items to return. |
| `dataset` | string | `""` |  | Dataset name (see list_datasets). Empty = the active dataset. |

Called with the arguments below, `findings_for_asset` returned this `structuredContent`.

```json
{"ref": "sg-admin"}
```

```json
{
  "dataset": "sample",
  "asset": {
    "id": "sg-admin",
    "name": "sg-admin",
    "type": "SECURITY_GROUP",
    "provider": "AWS",
    "region": "us-east-1",
    "account_id": "111111111111",
    "arn": "arn:aws:ec2:us-east-1:111111111111:security-group/sg-0admin",
    "internet_exposed": false,
    "open_findings": 1,
    "max_severity": "CRITICAL",
    "uri": "cloudg://assets/sg-admin"
  },
  "total": 1,
  "returned": 1,
  "truncated": false,
  "items": [
    {
      "id": "f-ssh-open",
      "title": "Security group allows SSH (22) from 0.0.0.0/0",
      "severity": "CRITICAL",
      "risk_score": 9.5,
      "source_tool": "prowler",
      "resource_id": "sg-admin",
      "resource_arn": "arn:aws:ec2:us-east-1:111111111111:security-group/sg-0admin",
      "asset_id": "sg-admin",
      "asset_name": "sg-admin",
      "compliance_frameworks": [
        "CIS-AWS",
        "PCI-DSS"
      ],
      "is_suppressed": false,
      "cvss_score": null,
      "detected_at": "2026-01-15T12:00:00+00:00",
      "uri": "cloudg://findings/f-ssh-open"
    }
  ]
}
```

### `top_risks`

Category `findings` · sensitivity `confidential` · capabilities `read_state` · readOnly true, destructive false, idempotent true, openWorld false · outputSchema yes · timeout: layer default (300 s)

The assets to fix first. Only assets with at least one open finding (at or above `min_severity`) are candidates; findings on unmapped resources are ignored. The score and its components are described under [Risk scores](#risk-scores). Each item is `{asset, score, components, top_findings}` with the three riskiest findings; the result adds `total_candidates` and the `formula` string.

| Argument | Type | Default | Constraints | Description |
|---|---|---|---|---|
| `top` | integer | `10` | 1..100 | Number of assets returned. |
| `min_severity` | string | `""` |  | Only consider open findings at or above this severity. |
| `dataset` | string | `""` |  | Dataset name (see list_datasets). Empty = the active dataset. |

`internet_reachable` in the components is true for any asset that is flagged exposed or that the reachability analysis reaches from the internet over network-flow edges. On the sample estate that includes the two security groups below: their internet-sourced rules make them reachable, although they are not flagged exposed themselves.

Called with the arguments below, `top_risks` returned this `structuredContent`.

```json
{"top": 3}
```

```json
{
  "dataset": "sample",
  "items": [
    {
      "asset": {
        "id": "az-nsg",
        "name": "jump-nsg",
        "type": "NSG",
        "provider": "AZURE",
        "region": "westeurope",
        "account_id": "00000000-aaaa-bbbb-cccc-000000000001",
        "arn": "/subscriptions/00000000-aaaa-bbbb-cccc-000000000001/resourceGroups/rg-hub/providers/Microsoft.Network/networkSecurityGroups/jump-nsg",
        "internet_exposed": false,
        "open_findings": 1,
        "max_severity": "CRITICAL",
        "uri": "cloudg://assets/az-nsg"
      },
      "score": 16.39,
      "components": {
        "max_finding_risk": 9.5,
        "exposure_factor": 1.5,
        "internet_reachable": true,
        "transitive_dependents": 1,
        "blast_factor": 1.151,
        "open_findings": 1,
        "volume_factor": 1.0
      },
      "top_findings": [
        {
          "id": "f-rdp-open",
          "title": "NSG allows RDP (3389) from Internet",
          "severity": "CRITICAL",
          "risk_score": 9.5,
          "source_tool": "scoutsuite",
          "resource_id": "az-nsg",
          "resource_arn": null,
          "asset_id": "az-nsg",
          "asset_name": "jump-nsg",
          "compliance_frameworks": [
            "CIS-Azure"
          ],
          "is_suppressed": false,
          "cvss_score": null,
          "detected_at": "2026-01-15T12:00:00+00:00",
          "uri": "cloudg://findings/f-rdp-open"
        }
      ]
    },
    {
      "asset": {
        "id": "sg-admin",
        "name": "sg-admin",
        "type": "SECURITY_GROUP",
        "provider": "AWS",
        "region": "us-east-1",
        "account_id": "111111111111",
        "arn": "arn:aws:ec2:us-east-1:111111111111:security-group/sg-0admin",
        "internet_exposed": false,
        "open_findings": 1,
        "max_severity": "CRITICAL",
        "uri": "cloudg://assets/sg-admin"
      },
      "score": 16.39,
      "components": {
        "max_finding_risk": 9.5,
        "exposure_factor": 1.5,
        "internet_reachable": true,
        "transitive_dependents": 1,
        "blast_factor": 1.151,
        "open_findings": 1,
        "volume_factor": 1.0
      },
      "top_findings": [
        {
          "id": "f-ssh-open",
          "title": "Security group allows SSH (22) from 0.0.0.0/0",
          "severity": "CRITICAL",
          "risk_score": 9.5,
          "source_tool": "prowler",
          "resource_id": "sg-admin",
          "resource_arn": "arn:aws:ec2:us-east-1:111111111111:security-group/sg-0admin",
          "asset_id": "sg-admin",
          "asset_name": "sg-admin",
          "compliance_frameworks": [
            "CIS-AWS",
            "PCI-DSS"
          ],
          "is_suppressed": false,
          "cvss_score": null,
          "detected_at": "2026-01-15T12:00:00+00:00",
          "uri": "cloudg://findings/f-ssh-open"
        }
      ]
    },
    "... 1 more"
  ],
  "total_candidates": 10,
  "formula": "max_risk * exposure * blast * volume"
}
```

Related: `get_asset`, `blast_radius`, the `remediation_plan` prompt.

### `suppress_findings`

Category `findings` · sensitivity `confidential` · capabilities `read_state`, `write_state` · readOnly false, destructive false, idempotent true, openWorld false · outputSchema no · timeout: layer default (300 s)

Marks findings as accepted risk or false positive in the in-memory dataset. Nothing is written to disk or to the cloud, and unloading the dataset loses the suppression. The reason is stored per finding (and shown by `get_finding`); suppressing an already suppressed finding replaces its reason. Returns `suppressed` (changed now), `already_suppressed` and `not_found`. The dataset version only changes, and cursors only go stale, when at least one finding changed.

| Argument | Type | Default | Constraints | Description |
|---|---|---|---|---|
| `finding_ids` | string[] | required | min items 1; max items 500 | Finding ids (exact `id`, not source_finding_id). |
| `reason` | string | required | min length 3; max length 500 | Why (accepted risk, false positive...). |
| `dataset` | string | `""` |  | Dataset name (see list_datasets). Empty = the active dataset. |

Called with the arguments below, `suppress_findings` returned this `structuredContent`.

```json
{
  "finding_ids": [
    "f-default-vpc",
    "f-versioning",
    "f-nope"
  ],
  "reason": "Accepted risk: sandbox VPC, tracked in RISK-42"
}
```

```json
{
  "dataset": "sample",
  "suppressed": [
    "f-default-vpc"
  ],
  "already_suppressed": [
    "f-versioning"
  ],
  "not_found": [
    "f-nope"
  ]
}
```

`get_finding` then shows the reason:

Called with the arguments below, `get_finding` returned the `suppression_reason` part of its `structuredContent`.

```json
{"finding_id": "f-default-vpc"}
```

```json
"Accepted risk: sandbox VPC, tracked in RISK-42"
```

```json
{
  "tool": "suppress_findings",
  "arguments": {
    "finding_ids": [
      "f-default-vpc"
    ],
    "reason": "ok"
  },
  "isError": true,
  "text": "Invalid arguments: reason: String should have at least 3 characters",
  "_meta": {
    "cloudg/error_code": -32602,
    "cloudg/error_data": [
      {
        "loc": "reason",
        "msg": "String should have at least 3 characters",
        "type": "string_too_short"
      }
    ]
  }
}
```

### `unsuppress_findings`

Category `findings` · sensitivity `confidential` · capabilities `read_state`, `write_state` · readOnly false, destructive false, idempotent true, openWorld false · outputSchema no · timeout: layer default (300 s)

Restores suppressed findings. Returns `unsuppressed`, `not_suppressed` (were not suppressed) and `not_found`, and drops the stored reasons.

| Argument | Type | Default | Constraints | Description |
|---|---|---|---|---|
| `finding_ids` | string[] | required | min items 1; max items 500 | Finding ids (exact `id`). |
| `dataset` | string | `""` |  | Dataset name (see list_datasets). Empty = the active dataset. |

Called with the arguments below, `unsuppress_findings` returned this `structuredContent`.

```json
{"finding_ids": ["f-default-vpc", "f-web-cve"]}
```

```json
{
  "dataset": "sample",
  "unsuppressed": [
    "f-default-vpc"
  ],
  "not_suppressed": [
    "f-web-cve"
  ],
  "not_found": []
}
```

### `ingest_reports`

Category `findings` · sensitivity `confidential` · capabilities `read_fs`, `read_state`, `write_state` · readOnly false, destructive false, idempotent false, openWorld false · outputSchema no · timeout: layer default (300 s)

Parses existing scanner output (no scanner runs and nothing is sent to the cloud) and adds the findings to a dataset, matching them to assets by ARN, id or name.

| Argument | Type | Default | Constraints | Description |
|---|---|---|---|---|
| `reports` | object (string to string[]) | required |  | Tool -> report paths (files or directories inside an allowed root), e.g. {'prowler': ['out/prowler/'], 'trivy': ['scan.json']}. Tools: prowler, scoutsuite, checkov, trivy. |
| `dataset` | string | `""` |  | Dataset to add the findings to; empty = active. Created if new_dataset is true. |
| `new_dataset` | boolean | `false` |  | Create a new findings-only dataset named `dataset` instead. |
| `normalise` | boolean | `true` |  | Deduplicate across scanners and map to compliance frameworks afterwards. |
| `activate` | boolean | `true` |  | With new_dataset: make the new dataset the active one (like load_dataset). |
| `replace` | boolean | `false` |  | With new_dataset: overwrite an existing dataset of that name. |

Behaviour in detail:

- `reports` maps a tool name (`prowler`, `scoutsuite`, `checkov`, `trivy`, case-insensitive) to a list of files or directories. An unknown tool fails the whole call before anything is read.
- Every path must resolve inside an allowed root; one path outside fails the whole call with an access error. A path that cannot be parsed or does not exist is reported in `errors` and the call continues. Prowler output is read as ASFF or OCSF, record by record, and its passing checks feed the compliance results.
- With `new_dataset: true`, an empty dataset named `dataset` (or `ingested`, made unique) is created with `kind: "report"`, `source: "ingest"`. It becomes the active dataset unless `activate` is false. A name that is already loaded is refused before anything is parsed, unless `replace` is true.
- With `normalise: true` (the default) the normaliser runs over the dataset's existing findings plus the new ones: duplicates across scanners merge, findings get scores and framework tags, and the normaliser's compliance results are merged into the dataset's (`merge_compliance` in `cloudg/mcp/catalog/_findings.py`): a control the normaliser evaluated takes its new result plus any surviving finding ids the old result listed; a control it did not evaluate (scanner-native mappings, PASS results) is kept with its finding ids filtered to findings that still exist, and dropped only when all of them are gone. Suppression flags survive by finding id. With `normalise: false` the findings are appended as parsed.

Returns `dataset`, `parsed`, `per_path` (`tool`, `path`, `findings`), `errors` (`tool`, `path`, `error`), `findings_before`, `findings_after`, `matched_to_assets` (how many parsed findings map to an asset), `normalised` and `active` (the active dataset after the call).

A one-record Prowler ASFF file naming `sg-web` by ARN, taken after `snapshot_dataset` so the change can be diffed:

Called with the arguments below, `ingest_reports` returned this `structuredContent`.

```json
{"reports": {"prowler": ["scans/prowler-asff.json"]}}
```

```json
{
  "dataset": "sample",
  "parsed": 1,
  "per_path": [
    {
      "tool": "prowler",
      "path": "scans/prowler-asff.json",
      "findings": 1
    }
  ],
  "errors": [],
  "findings_before": 12,
  "findings_after": 13,
  "matched_to_assets": 1,
  "normalised": true,
  "active": "sample"
}
```

```json
{
  "tool": "ingest_reports",
  "arguments": {
    "reports": {
      "nmap": [
        "x.xml"
      ]
    }
  },
  "isError": true,
  "text": "Unsupported tool(s) nmap. Supported: prowler, scoutsuite, checkov, trivy",
  "_meta": {
    "cloudg/error_code": -32602
  }
}
```

Called with the arguments below, `ingest_reports` returned this `structuredContent`.

```json
{"reports": {"trivy": ["scans/missing.json"]}}
```

```json
{
  "dataset": "sample",
  "parsed": 0,
  "per_path": [],
  "errors": [
    {
      "tool": "trivy",
      "path": "scans/missing.json",
      "error": "Report path does not exist: <estate>/scans/missing.json"
    }
  ],
  "findings_before": 13,
  "findings_after": 13,
  "matched_to_assets": 0,
  "normalised": true,
  "active": "sample"
}
```

OCSF input into a new, inactive dataset:

Called with the arguments below, `ingest_reports` returned this `structuredContent`.

```json
{
  "reports": {
    "prowler": [
      "scans/prowler-ocsf.json"
    ]
  },
  "dataset": "ocsf-test",
  "new_dataset": true,
  "activate": false
}
```

```json
{
  "dataset": "ocsf-test",
  "parsed": 1,
  "per_path": [
    {
      "tool": "prowler",
      "path": "scans/prowler-ocsf.json",
      "findings": 1
    }
  ],
  "errors": [],
  "findings_before": 0,
  "findings_after": 1,
  "matched_to_assets": 0,
  "normalised": true,
  "active": "sample"
}
```

After this ingest, `compliance_summary(framework="CIS-AWS")` on the same dataset reported 6 evaluated controls: the fixture's `5.2`, `2.1.4`, `1.16` and `3.1` (the PASS included) were kept, and the normaliser added `CIS-AWS/ec2_sg_open_22` (the check name read from the fixture finding's `prowler-aws-ec2_sg_open_22-1` id) and `CIS-AWS-aggregate`.

Called with the arguments below, `compliance_summary` returned this `structuredContent`.

```json
{"framework": "CIS-AWS"}
```

```json
{
  "dataset": "sample",
  "frameworks": [
    {
      "framework": "CIS-AWS",
      "controls_evaluated": 6,
      "controls_failing": 5,
      "controls_passing": 1,
      "controls_other": 0,
      "pass_rate": 16.7,
      "open_findings": 7,
      "severity_breakdown": {
        "CRITICAL": 1,
        "HIGH": 3,
        "MEDIUM": 2,
        "INFO": 1
      },
      "affected_assets": 6,
      "uri": "cloudg://compliance/CIS-AWS"
    }
  ]
}
```

Related: `snapshot_dataset` (before), `diff_datasets` (after), `normalise_findings`, `run_scanners` (run the scanners instead).

### `normalise_findings`

Category `findings` · sensitivity `internal` · capabilities `read_state`, `write_state` · readOnly false, destructive false, idempotent true, openWorld false · outputSchema no · timeout: layer default (300 s)

Re-runs cloudg's normaliser (`cloudg.normaliser.FindingsNormaliser`, with the configured rules directory) over a dataset's findings: deduplication within and across scanners by check-equivalence rules, scoring, and a fresh compliance mapping merged into the existing results the same way `ingest_reports` merges them. Suppression flags survive by id. Returns before and after counts of findings and compliance results and the resulting `frameworks`.

| Argument | Type | Default | Constraints | Description |
|---|---|---|---|---|
| `dataset` | string | `""` |  | Dataset name (see list_datasets). Empty = the active dataset. |

On the sample dataset, after the ingest above had already normalised it once, a second run changes nothing:

Called with the arguments below, `normalise_findings` returned this `structuredContent`.

```json
{}
```

```json
{
  "dataset": "sample",
  "findings_before": 13,
  "findings_after": 13,
  "compliance_results_before": 22,
  "compliance_results_after": 22,
  "frameworks": [
    "CIS-AWS",
    "CIS-Azure",
    "CIS-GCP",
    "... 5 more"
  ]
}
```

### `reachability_findings`

Category `findings` · sensitivity `confidential` · capabilities `read_state`, `write_state` · readOnly false, destructive false, idempotent false, openWorld false · outputSchema no · timeout: layer default (300 s)

Runs `cloudg.graph.reachability.ReachabilityAnalyzer` over a copy of the relationship graph and returns its findings, with `source_tool: "cloudg-reachability"`: a CRITICAL finding for each sensitive data store (RDS, Aurora, Azure SQL, Cloud SQL, DynamoDB) reachable from the internet, a HIGH finding for other reachable assets whose type is not expected to face the internet (load balancers, CloudFront, CDNs and internet gateways are expected; security groups, NSGs, NACLs and target groups are passed through but never reported), and a CRITICAL finding for each sensitive port that an ingress rule opens to the internet (`0.0.0.0/0`, `::/0` or an Azure `Internet`, `Any` or `*` source). "Reachable" follows network-flow edges only, as described under [Graph](#graph): an IAM grant does not make a database reachable, and a function behind a public API gateway is not reported.

Without `add_to_dataset` it only previews. Findings already in the dataset, by id or by (source tool, title, resource id), are skipped, so repeated runs do not duplicate. The ids are the analyser's own: a UUID5 hash of the rule and the asset's ARN (or id), so the same exposure keeps its id from scan to scan and a previewed id is the id that gets added. Added findings are not normalised. Returns `generated`, `new` (not yet in the dataset), `added`, the bounded `total`, `returned`, `truncated` and `items` (briefs of the new ones).

| Argument | Type | Default | Constraints | Description |
|---|---|---|---|---|
| `add_to_dataset` | boolean | `false` |  | Append them to the dataset's findings (otherwise preview only). |
| `limit` | integer | `50` | 1..500 | Maximum items to return. |
| `dataset` | string | `""` |  | Dataset name (see list_datasets). Empty = the active dataset. |

Called with the arguments below, `reachability_findings` returned this `structuredContent`.

```json
{"limit": 3}
```

```json
{
  "dataset": "sample",
  "generated": 9,
  "new": 9,
  "added": 0,
  "total": 9,
  "returned": 3,
  "truncated": true,
  "items": [
    {
      "id": "4404191e-4430-5cd8-9a4d-036bbb058662",
      "title": "Unexpected internet-exposed resource: public-api",
      "severity": "HIGH",
      "risk_score": 7.5,
      "source_tool": "cloudg-reachability",
      "resource_id": "api-gw",
      "resource_arn": "arn:aws:apigateway:us-east-1::/restapis/a1b2c3",
      "asset_id": "api-gw",
      "asset_name": "public-api",
      "compliance_frameworks": [],
      "is_suppressed": false,
      "cvss_score": null,
      "detected_at": "2026-10-09T14:25:22.341914",
      "uri": "cloudg://findings/4404191e-4430-5cd8-9a4d-036bbb058662"
    },
    {
      "id": "1ee8a511-d242-5bf0-8313-163d439997e2",
      "title": "Unexpected internet-exposed resource: jump-vm",
      "severity": "HIGH",
      "risk_score": 7.5,
      "source_tool": "cloudg-reachability",
      "resource_id": "az-vm",
      "resource_arn": "/subscriptions/00000000-aaaa-bbbb-cccc-000000000001/resourceGroups/rg-hub/providers/Microsoft.Compute/virtualMachines/jump-vm",
      "asset_id": "az-vm",
      "asset_name": "jump-vm",
      "compliance_frameworks": [],
      "is_suppressed": false,
      "cvss_score": null,
      "detected_at": "2026-10-09T14:25:22.341937",
      "uri": "cloudg://findings/1ee8a511-d242-5bf0-8313-163d439997e2"
    },
    "... 1 more"
  ]
}
```

Related: `normalise_findings` after adding, `internet_exposure`.

## Compliance

Two sources feed these tools. The rulesets shipped in `cloudg/rules` (CIS for each cloud, NIST 800-53, PCI DSS, ISO 27001, SOC 2, HIPAA, GDPR, AWS Foundational Security Best Practices and others) define frameworks and controls. The dataset's `ComplianceResult` list and each finding's `compliance_frameworks` say which controls fail and on what. A `framework` argument matches case-insensitively, either exactly or as a substring, so `CIS` selects `CIS-AWS`, `CIS-Azure` and `CIS-GCP` together.

The ruleset catalog is read from `config.rulesets.rules_dir` (or cloudg's default rules directory), every `*.yaml` except `check_equivalence.yaml`, and cached per directory for the life of the process.

### `list_frameworks`

Category `compliance` · sensitivity `public` · capabilities none · readOnly true, destructive false, idempotent true, openWorld false · outputSchema no · timeout: layer default (300 s)

The frameworks cloudg can map findings to. Needs no dataset. Each item has `framework`, `versions`, `providers`, `controls` (distinct control ids across its files) and `files`. With `provider`, frameworks tied to other providers are dropped; provider-neutral frameworks (empty `providers`) always stay.

| Argument | Type | Default | Constraints | Description |
|---|---|---|---|---|
| `provider` | string | `""` |  | aws, azure or gcp. |

Called with the arguments below, `list_frameworks` returned this `structuredContent`.

```json
{"provider": "azure"}
```

```json
{
  "total": 12,
  "items": [
    {
      "framework": "CIS-AZURE",
      "versions": [
        "2.0",
        "5.0"
      ],
      "providers": [
        "azure"
      ],
      "controls": 123,
      "files": [
        "cis_azure_v2.yaml",
        "cis_5.0_azure.yaml"
      ]
    },
    {
      "framework": "GDPR",
      "versions": [
        "2016/679"
      ],
      "providers": [],
      "controls": 5,
      "files": [
        "gdpr.yaml"
      ]
    },
    "... 10 more"
  ]
}
```

Without a provider the sample run listed 28 frameworks.

### `compliance_summary`

Category `compliance` · sensitivity `internal` · capabilities `read_state` · readOnly true, destructive false, idempotent true, openWorld false · outputSchema yes · timeout: layer default (300 s)

Posture per framework, from compliance results and finding tags together. Links up to five `cloudg://compliance/{framework}` resources.

| Argument | Type | Default | Constraints | Description |
|---|---|---|---|---|
| `framework` | string | `""` |  | Framework name or substring (e.g. 'CIS', 'PCI'); empty = all. |
| `dataset` | string | `""` |  | Dataset name (see list_datasets). Empty = the active dataset. |

Per framework: `controls_evaluated` (compliance results), `controls_failing`, `controls_passing`, `controls_other` (`NOT_APPLICABLE`, `MANUAL`), `pass_rate` (passing / evaluated * 100, one decimal, null when nothing was evaluated), `open_findings` (open findings linked from a result or tagged with the framework), `severity_breakdown`, `affected_assets` and `uri`. Frameworks are sorted by open findings, most first. When nothing matches, `frameworks` is empty and a `hint` explains that findings need framework tags.

Called with the arguments below, `compliance_summary` returned this `structuredContent`.

```json
{}
```

```json
{
  "dataset": "sample",
  "frameworks": [
    {
      "framework": "CIS-AWS",
      "controls_evaluated": 4,
      "controls_failing": 3,
      "controls_passing": 1,
      "controls_other": 0,
      "pass_rate": 25.0,
      "open_findings": 6,
      "severity_breakdown": {
        "CRITICAL": 1,
        "HIGH": 3,
        "MEDIUM": 2
      },
      "affected_assets": 5,
      "uri": "cloudg://compliance/CIS-AWS"
    },
    {
      "framework": "PCI-DSS",
      "controls_evaluated": 1,
      "controls_failing": 1,
      "controls_passing": 0,
      "controls_other": 0,
      "pass_rate": 0.0,
      "open_findings": 3,
      "severity_breakdown": {
        "CRITICAL": 1,
        "HIGH": 2
      },
      "affected_assets": 3,
      "uri": "cloudg://compliance/PCI-DSS"
    },
    "... 3 more"
  ]
}
```

The result also carried these resource links in `content`:

```json
[
  {
    "type": "resource_link",
    "uri": "cloudg://compliance/CIS-AWS",
    "name": "CIS-AWS compliance",
    "mimeType": "application/json"
  },
  {
    "type": "resource_link",
    "uri": "cloudg://compliance/PCI-DSS",
    "name": "PCI-DSS compliance",
    "mimeType": "application/json"
  },
  {
    "type": "resource_link",
    "uri": "cloudg://compliance/NIST-800-53",
    "name": "NIST-800-53 compliance",
    "mimeType": "application/json"
  },
  "... 2 more"
]
```

Called with the arguments below, `compliance_summary` returned this `structuredContent`.

```json
{"framework": "HIPAA"}
```

```json
{
  "dataset": "sample",
  "frameworks": [],
  "hint": "No compliance data matched. Findings need compliance_frameworks (run normalise_findings after ingesting scanner reports); list_frameworks shows the framework names."
}
```

### `list_controls`

Category `compliance` · sensitivity `internal` · capabilities `read_state` · readOnly true, destructive false, idempotent true, openWorld false · outputSchema no · timeout: layer default (300 s)

Controls of one framework, from either source. With `source: "dataset"` (default) the rows are the dataset's compliance results: `framework`, `control_id`, `control_title`, `status`, `findings` (ids on the result), `open_findings` and `max_severity`, filtered by `status` and sorted worst first. With `source: "ruleset"` the rows are every control the matching ruleset frameworks define: `framework`, `control_id`, `title`, `severity` and `checks` (number of mapped scanner checks); `status` is ignored and the cursor does not depend on any dataset.

| Argument | Type | Default | Constraints | Description |
|---|---|---|---|---|
| `framework` | string | required | min length 1 | Framework name or substring. |
| `status` | string | `""` | one of `""`, `PASS`, `FAIL`, `NOT_APPLICABLE`, `MANUAL` | Only controls with this status (dataset source only). |
| `source` | string | `"dataset"` | one of `dataset`, `ruleset` | dataset = controls evaluated for this dataset; ruleset = every control the framework defines. |
| `limit` | integer | `50` | 1..500 | Maximum items to return. |
| `cursor` | string | `""` |  | Opaque cursor from a previous call's next_cursor; empty = first page. |
| `dataset` | string | `""` |  | Dataset name (see list_datasets). Empty = the active dataset. |

Called with the arguments below, `list_controls` returned this `structuredContent`.

```json
{"framework": "CIS-AWS"}
```

```json
{
  "dataset": "sample",
  "source": "dataset",
  "total": 4,
  "offset": 0,
  "returned": 4,
  "next_cursor": null,
  "truncated": false,
  "items": [
    {
      "framework": "CIS-AWS",
      "control_id": "5.2",
      "control_title": "No SG allows 0.0.0.0/0 to admin ports",
      "status": "FAIL",
      "findings": 1,
      "open_findings": 1,
      "max_severity": "CRITICAL"
    },
    {
      "framework": "CIS-AWS",
      "control_id": "1.16",
      "control_title": "IAM trust least privilege",
      "status": "FAIL",
      "findings": 1,
      "open_findings": 1,
      "max_severity": "HIGH"
    },
    "... 2 more"
  ]
}
```

Called with the arguments below, `list_controls` returned this `structuredContent`.

```json
{"framework": "cis-aws", "source": "ruleset", "limit": 3}
```

```json
{
  "source": "ruleset",
  "frameworks": [
    "CIS-AWS"
  ],
  "total": 81,
  "offset": 0,
  "returned": 3,
  "next_cursor": "c3.a358f04c1624",
  "truncated": true,
  "items": [
    {
      "framework": "CIS-AWS",
      "control_id": "CIS-1.4",
      "title": "Ensure access keys are rotated every 90 days or less",
      "severity": "MEDIUM",
      "checks": 0
    },
    {
      "framework": "CIS-AWS",
      "control_id": "CIS-1.5",
      "title": "Ensure MFA is enabled for the root user",
      "severity": "CRITICAL",
      "checks": 0
    },
    {
      "framework": "CIS-AWS",
      "control_id": "CIS-1.7",
      "title": "Eliminate use of the root user for administrative tasks",
      "severity": "HIGH",
      "checks": 0
    }
  ]
}
```

```json
{
  "tool": "list_controls",
  "arguments": {
    "framework": "FEDRAMP",
    "source": "ruleset"
  },
  "isError": true,
  "text": "No ruleset framework matches the name. Known: AWS-Foundational-Security-Best-Practices-AWS, CIS-AWS, CIS-AZURE, CIS-GCP, GDPR, GDPR-AWS, HIPAA, HIPAA-AWS, HIPAA-AZURE, HIPAA-GCP, ISO-27001, ISO27001-A...",
  "_meta": {
    "cloudg/error_code": -32602,
    "cloudg/error_data": {
      "value": "FEDRAMP",
      "known": [
        "AWS-Foundational-Security-Best-Practices-AWS",
        "CIS-AWS",
        "CIS-AZURE",
        "... 25 more"
      ]
    }
  }
}
```

### `control_status`

Category `compliance` · sensitivity `confidential` · capabilities `read_state` · readOnly true, destructive false, idempotent true, openWorld false · outputSchema no · timeout: layer default (300 s)

One control: its ruleset definition, its status in the dataset, the open findings that fail it and the affected assets. Dataset results match when the control id is equal to `control_id` or ends with it; the definition is the first matching ruleset framework that defines exactly that id. `status` is `NOT_EVALUATED` without dataset results, `FAIL` when a result fails and open findings remain, `PASS (all findings suppressed)` when it failed but every finding is suppressed, otherwise the first result's status. The response echoes `framework` and `control_id` as given, and returns `definition`, `status`, `results`, `open_findings` (count), `findings` and `affected_assets` (both capped at `limit`) and `truncated`.

| Argument | Type | Default | Constraints | Description |
|---|---|---|---|---|
| `framework` | string | required | min length 1 | Framework name or substring. |
| `control_id` | string | required | min length 1 | Control id. A dataset result also matches when its id ends with this value. |
| `limit` | integer | `25` | 1..200 | Cap on `findings` and `affected_assets`. |
| `dataset` | string | `""` |  | Dataset name (see list_datasets). Empty = the active dataset. |

Called with the arguments below, `control_status` returned this `structuredContent`.

```json
{"framework": "CIS-AWS", "control_id": "5.2"}
```

```json
{
  "dataset": "sample",
  "framework": "CIS-AWS",
  "control_id": "5.2",
  "definition": {
    "framework": "CIS-AWS",
    "control_id": "5.2",
    "title": "Ensure no Network ACLs allow ingress from 0.0.0.0/0 to remote server administration ports",
    "severity": null,
    "checks": 3
  },
  "status": "FAIL",
  "results": [
    {
      "framework": "CIS-AWS",
      "control_id": "5.2",
      "control_title": "No SG allows 0.0.0.0/0 to admin ports",
      "status": "FAIL"
    }
  ],
  "open_findings": 1,
  "findings": [
    {
      "id": "f-ssh-open",
      "title": "Security group allows SSH (22) from 0.0.0.0/0",
      "severity": "CRITICAL",
      "risk_score": 9.5,
      "source_tool": "prowler",
      "resource_id": "sg-admin",
      "resource_arn": "arn:aws:ec2:us-east-1:111111111111:security-group/sg-0admin",
      "asset_id": "sg-admin",
      "asset_name": "sg-admin",
      "compliance_frameworks": [
        "CIS-AWS",
        "PCI-DSS"
      ],
      "is_suppressed": false,
      "cvss_score": null,
      "detected_at": "2026-01-15T12:00:00+00:00",
      "uri": "cloudg://findings/f-ssh-open"
    }
  ],
  "affected_assets": [
    {
      "id": "sg-admin",
      "name": "sg-admin",
      "type": "SECURITY_GROUP",
      "provider": "AWS",
      "region": "us-east-1",
      "account_id": "111111111111",
      "arn": "arn:aws:ec2:us-east-1:111111111111:security-group/sg-0admin",
      "internet_exposed": false,
      "open_findings": 1,
      "max_severity": "CRITICAL",
      "uri": "cloudg://assets/sg-admin"
    }
  ],
  "truncated": false
}
```

The ruleset and the dataset can disagree on titles: here the dataset result says "No SG allows 0.0.0.0/0 to admin ports" while the CIS-AWS ruleset entry with id `5.2` is the network ACL control. Both are shown so the caller can tell.

```json
{
  "tool": "control_status",
  "arguments": {
    "framework": "CIS-AWS",
    "control_id": "9.9"
  },
  "isError": true,
  "text": "No such control for that framework. Controls in this dataset: 1.16, 2.1.4, 3.1, 5.2",
  "_meta": {
    "cloudg/error_code": -32602,
    "cloudg/error_data": {
      "value": "9.9",
      "framework": "CIS-AWS",
      "known": [
        "1.16",
        "2.1.4",
        "3.1",
        "5.2"
      ]
    }
  }
}
```

### `compliance_gaps`

Category `compliance` · sensitivity `confidential` · capabilities `read_state` · readOnly true, destructive false, idempotent true, openWorld false · outputSchema no · timeout: layer default (300 s)

Assets that fail compliance, worst first. A finding counts as a gap when it is open, at or above `min_severity`, and either carries a matching framework tag or is linked from a failing compliance result of a matching framework. Rows are asset briefs plus `frameworks`, `failing_controls` (`framework:control_id`, first 20), `gap_findings` and `gap_max_severity`. Findings on resources that are not mapped get a row with `id: "unmapped:<resource>"`, `name: <resource>` and `unmapped: true`.

| Argument | Type | Default | Constraints | Description |
|---|---|---|---|---|
| `framework` | string | `""` |  | Framework name or substring; empty = all. |
| `min_severity` | string | `""` |  | Only findings at or above this severity count as gaps. |
| `limit` | integer | `50` | 1..500 | Maximum items to return. |
| `cursor` | string | `""` |  | Opaque cursor from a previous call's next_cursor; empty = first page. |
| `dataset` | string | `""` |  | Dataset name (see list_datasets). Empty = the active dataset. |

Called with the arguments below, `compliance_gaps` returned this `structuredContent`.

```json
{"framework": "CIS", "limit": 3}
```

```json
{
  "dataset": "sample",
  "framework": "CIS",
  "total": 8,
  "offset": 0,
  "returned": 3,
  "next_cursor": "c3.50cc1e27f5ec",
  "truncated": true,
  "items": [
    {
      "id": "az-nsg",
      "name": "jump-nsg",
      "type": "NSG",
      "provider": "AZURE",
      "region": "westeurope",
      "account_id": "00000000-aaaa-bbbb-cccc-000000000001",
      "arn": "/subscriptions/00000000-aaaa-bbbb-cccc-000000000001/resourceGroups/rg-hub/providers/Microsoft.Network/networkSecurityGroups/jump-nsg",
      "internet_exposed": false,
      "open_findings": 1,
      "max_severity": "CRITICAL",
      "uri": "cloudg://assets/az-nsg",
      "frameworks": [
        "CIS-Azure"
      ],
      "failing_controls": [
        "CIS-Azure:6.1"
      ],
      "gap_findings": 1,
      "gap_max_severity": "CRITICAL"
    },
    {
      "id": "sg-admin",
      "name": "sg-admin",
      "type": "SECURITY_GROUP",
      "provider": "AWS",
      "region": "us-east-1",
      "account_id": "111111111111",
      "arn": "arn:aws:ec2:us-east-1:111111111111:security-group/sg-0admin",
      "internet_exposed": false,
      "open_findings": 1,
      "max_severity": "CRITICAL",
      "uri": "cloudg://assets/sg-admin",
      "frameworks": [
        "CIS-AWS"
      ],
      "failing_controls": [
        "CIS-AWS:5.2"
      ],
      "gap_findings": 1,
      "gap_max_severity": "CRITICAL"
    },
    {
      "id": "bastion",
      "name": "bastion",
      "type": "EC2",
      "provider": "AWS",
      "region": "us-east-1",
      "account_id": "111111111111",
      "arn": "arn:aws:ec2:us-east-1:111111111111:instance/i-0bast",
      "internet_exposed": true,
      "open_findings": 1,
      "max_severity": "HIGH",
      "uri": "cloudg://assets/bastion",
      "frameworks": [
        "CIS-AWS"
      ],
      "failing_controls": [],
      "gap_findings": 1,
      "gap_max_severity": "HIGH"
    }
  ]
}
```

`bastion` lists `CIS-AWS` with no failing control because its IMDSv1 finding is tagged CIS-AWS but no compliance result links it.

Related: the `compliance_gap_analysis` prompt, [Recipe: compliance gap triage](#compliance-gap-triage).

## Ontology

cloudg builds an RDF/OWL ontology from a dataset (`cloudg.graph.ontology.CloudOntology`): one individual per asset (`cmr:<asset id>`), per finding (`cmr:finding_<finding id>`) and per tag (`cmr:tag_<key>_<value>`), typed with classes such as `cm:RelationalDatabase`, and connected by 64 relation types in seven groups (NETWORK, CONTAINMENT, IAM, DATA_FLOW, SECURITY, COMPUTE, GOVERNANCE). Data properties are `cmp:hasName`, `hasARN`, `hasRegion`, `hasProvider`, `hasAccountId`, `hasCIDR`, `hasPort`, `hasProtocol`, `hasSeverity`, `hasRiskScore` and `isInternetExposed`. The ontology is built on first use and cached; on a large map the first call can take a while and reports progress.

Prefixes predefined for SPARQL:

| Prefix | Namespace | Holds |
|---|---|---|
| `cm:` | `https://cloudg.io/ontology#` | Classes. |
| `cmp:` | `https://cloudg.io/property/` | Relations and data properties. |
| `cmr:` | `https://cloudg.io/resource/` | Individuals. |
| `rdf:`, `rdfs:`, `owl:`, `xsd:` | The W3C namespaces | |

How the relations are read. `cmp:FINDING_AFFECTS` points at the asset a finding affects, resolved like an asset reference (id, ARN, unique name, unique ARN tail); only a finding whose resource matches nothing points at `cmr:` plus its raw `resource_id`. A `CONTAINS` edge gets a specific relation only when both endpoint types fit it (`VPC_CONTAINS_SUBNET`, `SUBNET_CONTAINS_INSTANCE`, `CLUSTER_CONTAINS_SERVICE`, `ORG_CONTAINS_ACCOUNT`), otherwise the generic `CONTAINS`. A security group or NACL rule yields `INGRESS_ALLOWED` or `EGRESS_ALLOWED`, `INTERNET_REACHABLE` for an internet source, and port relations read from the parsed port ranges (`ALL_TRAFFIC`, `ONLY_SSH`, `ONLY_HTTP`, `ONLY_HTTPS`, `ONLY_RDP`, `PORT_RESTRICTED`); `PROTECTED_BY_SG` and `PROTECTED_BY_NACL` come from `ATTACHED_TO` edges into a group (`web-alb PROTECTED_BY_SG sg-web`). `ENCRYPTED_BY_KMS` links an encrypted asset to its key.

### `ontology_stats`

Category `ontology` · sensitivity `internal` · capabilities `read_state` · readOnly true, destructive false, idempotent true, openWorld false · outputSchema no · timeout: layer default (300 s)

Size and shape of the ontology: `total_triples`, `classes_used`, `individuals`, `relation_type_counts` (data properties included) and `relation_group_counts`, plus `built_now`, true when this call built it. Links `cloudg://ontology/turtle`.

| Argument | Type | Default | Constraints | Description |
|---|---|---|---|---|
| `dataset` | string | `""` |  | Dataset name (see list_datasets). Empty = the active dataset. |

Called with the arguments below, `ontology_stats` returned this `structuredContent`.

```json
{}
```

```json
{
  "dataset": "sample",
  "built_now": true,
  "total_triples": 1184,
  "classes_used": 30,
  "individuals": 78,
  "relation_type_counts": {
    "hasRiskScore": 12,
    "hasName": 57,
    "hasAccountId": 44,
    "isInternetExposed": 44,
    "INTERNET_REACHABLE": 7,
    "...": "36 more"
  },
  "relation_group_counts": {
    "NETWORK": 16,
    "CONTAINMENT": 15,
    "SECURITY": 38,
    "IAM": 12,
    "GOVERNANCE": 25,
    "COMPUTE": 11,
    "DATA_FLOW": 2
  }
}
```

The result also carried these resource links in `content`:

```json
[
  {
    "type": "resource_link",
    "uri": "cloudg://ontology/turtle",
    "name": "ontology (turtle)",
    "mimeType": "text/turtle"
  }
]
```

A second call reads the cache and reports `"built_now": false`.

### `sparql_query`

Category `ontology` · sensitivity `restricted` · capabilities `read_state` · readOnly true, destructive false, idempotent true, openWorld false · outputSchema yes · timeout 120 s

Runs one read-only SPARQL query against the dataset's ontology. Before parsing, string literals and comments are blanked and the query is rejected if it starts (after `PREFIX` / `BASE` declarations) with `INSERT`, `DELETE`, `LOAD`, `CLEAR`, `DROP`, `CREATE`, `ADD`, `MOVE`, `COPY` or `WITH`; both steps are linear scans, so a hostile query string cannot stall them. After parsing, `FROM` / `FROM NAMED` and any `SERVICE` clause are rejected, so a query can neither change the graph nor load remote data.

The tool is `restricted`. Its rows are keyed by the query's own variable names, so the privacy transforms cannot tell an identifier column from any other, and `strict` and the `soc-analyst` analyst do not see the tool.

| Argument | Type | Default | Constraints | Description |
|---|---|---|---|---|
| `query` | string | required | min length 1; max length 20000 | Read-only SPARQL (SELECT / ASK / CONSTRUCT / DESCRIBE). Predefined prefixes: cm: (classes, e.g. cm:RelationalDatabase), cmp: (relations / properties, e.g. cmp:INTERNET_REACHABLE, cmp:hasName), cmr: (individuals, cmr:<asset id>), rdf:, rdfs:, owl:, xsd:. FROM, SERVICE and UPDATE are rejected. |
| `limit` | integer | `100` | 1..1000 | Row cap applied after the query runs. |
| `compact_uris` | boolean | `true` |  | Shorten URIs to prefix:name. |
| `dataset` | string | `""` |  | Dataset name (see list_datasets). Empty = the active dataset. |

Result by query type (`query_type` is rdflib's algebra name):

| `query_type` | Result |
|---|---|
| `SelectQuery` | `rows`: one object per solution, keyed by variable name. Values are strings (numbers too: `"12"`), URIs are compacted to `prefix:name` unless `compact_uris` is false, unbound variables are null. |
| `AskQuery` | `answer` (boolean), empty `rows`. |
| `ConstructQuery`, `DescribeQuery` | `rows` of `{subject, predicate, object}`. |

`limit` is applied while reading the results, so a query whose patterns multiply out stops after `limit` rows instead of enumerating every combination; when more rows exist, `truncated` is true and a `hint` suggests `LIMIT` / `OFFSET`. Reading also stops after 60 seconds, with a `hint` to narrow the query. Clauses that need the whole solution set first (`ORDER BY`, aggregates, `DISTINCT` over a large set) and `CONSTRUCT` / `DESCRIBE` are bounded only by the tool's 120-second timeout. A `SELECT` result carries `variable_kinds`, which says whether each column holds URIs, literals or both (`term`).

The internet-reachable relation (the example in the tool's own description narrows it to relational databases, which returns no rows on the sample estate because nothing reaches the database directly):

Called with the arguments below, `sparql_query` returned this `structuredContent`.

```json
{
  "query": "SELECT ?r ?name WHERE { ?s cmp:INTERNET_REACHABLE ?r . ?r cmp:hasName ?name } ORDER BY ?name",
  "limit": 20
}
```

```json
{
  "dataset": "sample",
  "query_type": "SelectQuery",
  "rows": [
    {
      "r": "cmr:az-nsg",
      "name": "jump-nsg"
    },
    {
      "r": "cmr:logs-bucket",
      "name": "prod-logs"
    },
    {
      "r": "cmr:api-gw",
      "name": "public-api"
    },
    "... 4 more"
  ],
  "returned": 7,
  "truncated": false,
  "variable_kinds": {
    "r": "uri",
    "name": "literal"
  }
}
```

Called with the arguments below, `sparql_query` returned this `structuredContent`.

```json
{"query": "ASK { ?s a cm:RelationalDatabase }", "limit": 20}
```

```json
{
  "dataset": "sample",
  "query_type": "AskQuery",
  "answer": true,
  "rows": [],
  "returned": 0,
  "truncated": false
}
```

Called with the arguments below, `sparql_query` returned this `structuredContent`.

```json
{"query": "CONSTRUCT { ?s cmp:hasName ?n } WHERE { ?s cmp:hasName ?n } LIMIT 2", "limit": 20}
```

```json
{
  "dataset": "sample",
  "query_type": "ConstructQuery",
  "rows": [
    {
      "subject": "cmr:org",
      "predicate": "cmp:hasName",
      "object": "sample-org"
    },
    {
      "subject": "cmr:ou-workloads",
      "predicate": "cmp:hasName",
      "object": "Workloads"
    }
  ],
  "returned": 2,
  "truncated": false,
  "variable_kinds": {
    "subject": "uri",
    "predicate": "uri",
    "object": "term"
  }
}
```

Called with the arguments below, `sparql_query` returned this `structuredContent`.

```json
{"query": "DESCRIBE cmr:orders-db", "limit": 20}
```

```json
{
  "dataset": "sample",
  "query_type": "DescribeQuery",
  "rows": [
    {
      "subject": "cmr:orders-db",
      "predicate": "rdf:type",
      "object": "cm:RelationalDatabase"
    },
    {
      "subject": "cmr:orders-db",
      "predicate": "cmp:hasProvider",
      "object": "AWS"
    },
    {
      "subject": "cmr:orders-db",
      "predicate": "cmp:hasARN",
      "object": "arn:aws:rds:us-east-1:111111111111:db:orders-db"
    },
    "... 8 more"
  ],
  "returned": 11,
  "truncated": false,
  "variable_kinds": {
    "subject": "uri",
    "predicate": "uri",
    "object": "term"
  }
}
```

Called with the arguments below, `sparql_query` returned this `structuredContent`.

```json
{"query": "SELECT ?s WHERE { ?s ?p ?o }", "limit": 2}
```

```json
{
  "dataset": "sample",
  "query_type": "SelectQuery",
  "rows": [
    {
      "s": "cmp:MONITORED_BY"
    },
    {
      "s": "cmr:tag_owner_api-team"
    }
  ],
  "returned": 2,
  "truncated": true,
  "variable_kinds": {
    "s": "uri"
  },
  "hint": "More rows exist: add LIMIT / OFFSET to the query or raise limit."
}
```

Called with the arguments below, `sparql_query` returned this `structuredContent`.

```json
{"query": "SELECT ?r WHERE { ?r cmp:hasName \"web-1\" }", "compact_uris": false}
```

```json
{
  "dataset": "sample",
  "query_type": "SelectQuery",
  "rows": [
    {
      "r": "https://cloudg.io/resource/web-1"
    }
  ],
  "returned": 1,
  "truncated": false,
  "variable_kinds": {
    "r": "uri"
  }
}
```

Rejections:

```json
{
  "tool": "sparql_query",
  "arguments": {
    "query": "INSERT DATA { cmr:x cmp:hasName 'x' }"
  },
  "isError": true,
  "text": "Only read-only queries are allowed (SELECT, ASK, CONSTRUCT, DESCRIBE); SPARQL UPDATE is rejected.",
  "_meta": {
    "cloudg/error_code": -32602
  }
}
```

```json
{
  "tool": "sparql_query",
  "arguments": {
    "query": "SELECT ?s FROM <http://evil.example/data.ttl> WHERE { ?s ?p ?o }"
  },
  "isError": true,
  "text": "FROM / FROM NAMED clauses are not allowed (they would load external data). Query the dataset's graph directly.",
  "_meta": {
    "cloudg/error_code": -32602
  }
}
```

```json
{
  "tool": "sparql_query",
  "arguments": {
    "query": "SELECT ?s WHERE { SERVICE <http://evil.example/sparql> { ?s ?p ?o } }"
  },
  "isError": true,
  "text": "SERVICE (federated queries to remote endpoints) is not allowed.",
  "_meta": {
    "cloudg/error_code": -32602
  }
}
```

```json
{
  "tool": "sparql_query",
  "arguments": {
    "query": "SELEKT nonsense"
  },
  "isError": true,
  "text": "SPARQL parse error: Expected {SelectQuery | ConstructQuery | DescribeQuery | AskQuery}, found 'SELEKT'  (at char 0), (line:1, col:1). Only SELECT / ASK / CONSTRUCT / DESCRIBE are allowed; prefixes cm:, cmr:, cmp:, rdf:, rdfs:, owl:, xsd: are predefined.",
  "_meta": {
    "cloudg/error_code": -32602
  }
}
```

More queries that work on this ontology are in [SPARQL cookbook](#sparql-cookbook).

### `ontology_neighbourhood`

Category `ontology` · sensitivity `confidential` · capabilities `read_state` · readOnly true, destructive false, idempotent true, openWorld false · outputSchema no · timeout: layer default (300 s)

The semantic relations around one asset, walked breadth-first in both directions over `cmp:` object properties (data properties and literals are skipped) up to `hops`. Each triple has `subject` and `object` (the `hasName` value, else the compact URI), `predicate`, `depth`, `subject_id` and `object_id`. `predicates` counts the predicates among the returned triples. Links the asset.

| Argument | Type | Default | Constraints | Description |
|---|---|---|---|---|
| `ref` | string | required | min length 1 | Asset reference: internal id, ARN / cloud resource id, unique name, or unique ARN tail (e.g. 'function:api' or 'i-0abc'). |
| `hops` | integer | `1` | 1..3 | How far to walk from the asset. |
| `limit` | integer | `100` | 1..500 | Triple cap. |
| `dataset` | string | `""` |  | Dataset name (see list_datasets). Empty = the active dataset. |

Called with the arguments below, `ontology_neighbourhood` returned this `structuredContent`.

```json
{"ref": "orders-db", "limit": 6}
```

```json
{
  "dataset": "sample",
  "asset": {
    "id": "orders-db",
    "name": "orders-db",
    "type": "RDS_INSTANCE"
  },
  "predicates": {
    "TAGGED_WITH": 2,
    "PROTECTED_BY_SG": 1,
    "ENCRYPTED_BY_KMS": 1,
    "SUBNET_CONTAINS_INSTANCE": 1,
    "POLICY_ALLOWS_ACTION": 1
  },
  "triples": [
    {
      "subject": "orders-db",
      "predicate": "TAGGED_WITH",
      "object": "cmr:tag_env_prod",
      "depth": 1,
      "subject_id": "cmr:orders-db",
      "object_id": "cmr:tag_env_prod"
    },
    {
      "subject": "orders-db",
      "predicate": "TAGGED_WITH",
      "object": "cmr:tag_data_pii",
      "depth": 1,
      "subject_id": "cmr:orders-db",
      "object_id": "cmr:tag_data_pii"
    },
    "... 4 more"
  ],
  "returned": 6,
  "truncated": true
}
```

The result also carried these resource links in `content`:

```json
[
  {
    "type": "resource_link",
    "uri": "cloudg://assets/orders-db",
    "name": "orders-db",
    "mimeType": "application/json"
  }
]
```

With `limit: 6` the walk stopped early (`truncated`). Without a limit the same call also returns `FINDING_AFFECTS` from the RDS backup finding, which names the database by ARN and is resolved to the asset, and the two `COMPLIANCE_GOVERNS` triples.

### `relation_groups`

Category `ontology` · sensitivity `confidential` · capabilities `read_state` · readOnly true, destructive false, idempotent true, openWorld false · outputSchema no · timeout: layer default (300 s)

Without `group`: every relation group with its total and the non-zero relation types. With `group` (case-insensitive): `relation_types` (every type in the group, present or not) and a page of triples with `src`, `tgt` (compact URIs), `srcName` and `tgtName`.

| Argument | Type | Default | Constraints | Description |
|---|---|---|---|---|
| `group` | string | `""` |  | NETWORK, CONTAINMENT, IAM, DATA_FLOW, SECURITY, COMPUTE or GOVERNANCE; empty = overview. |
| `limit` | integer | `100` | 1..500 | Page size when `group` is set. |
| `cursor` | string | `""` |  | Opaque cursor from a previous call's next_cursor; empty = first page. |
| `dataset` | string | `""` |  | Dataset name (see list_datasets). Empty = the active dataset. |

Called with the arguments below, `relation_groups` returned this `structuredContent`.

```json
{}
```

```json
{
  "dataset": "sample",
  "groups": {
    "NETWORK": {
      "total": 16,
      "types": {
        "INGRESS_ALLOWED": 4,
        "ONLY_HTTP": 1,
        "ONLY_HTTPS": 1,
        "ONLY_SSH": 1,
        "ONLY_RDP": 1,
        "PORT_RESTRICTED": 1,
        "INTERNET_REACHABLE": 7
      }
    },
    "CONTAINMENT": {
      "total": 15,
      "types": {
        "CONTAINS": 3,
        "VPC_CONTAINS_SUBNET": 2,
        "SUBNET_CONTAINS_INSTANCE": 5,
        "ORG_CONTAINS_ACCOUNT": 2,
        "LB_TARGETS_INSTANCE": 3
      }
    },
    "IAM": {
      "total": 12,
      "types": {
        "ROLE_ASSUMES_ROLE": 2,
        "POLICY_ALLOWS_ACTION": 8,
        "CROSS_ACCOUNT_TRUST": 2
      }
    },
    "DATA_FLOW": {
      "total": 2,
      "types": {
        "READS_FROM": 1,
        "LOGS_TO": 1
      }
    },
    "SECURITY": {
      "total": 38,
      "types": {
        "PROTECTED_BY_SG": 6,
        "PROTECTED_BY_WAF": 1,
        "ENCRYPTED_BY_KMS": 4,
        "FINDING_AFFECTS": 12,
        "COMPLIANCE_GOVERNS": 15
      }
    },
    "COMPUTE": {
      "total": 11,
      "types": {
        "RUNS_ON": 5,
        "TRIGGERED_BY": 1,
        "INVOKES": 1,
        "LOAD_BALANCED_BY": 3,
        "DEPENDS_ON": 1
      }
    },
    "GOVERNANCE": {
      "total": 25,
      "types": {
        "TAGGED_WITH": 17,
        "OWNED_BY": 7,
        "MONITORED_BY": 1
      }
    }
  }
}
```

Called with the arguments below, `relation_groups` returned this `structuredContent`.

```json
{"group": "iam", "limit": 3}
```

```json
{
  "dataset": "sample",
  "group": "IAM",
  "relation_types": [
    "ROLE_ASSUMES_ROLE",
    "USER_HAS_POLICY",
    "ROLE_HAS_POLICY",
    "... 7 more"
  ],
  "total": 12,
  "offset": 0,
  "returned": 3,
  "next_cursor": "c3.548cbba67c13",
  "truncated": true,
  "items": [
    {
      "src": "cmr:app-role",
      "tgt": "cmr:deploy-role",
      "srcName": "app-role",
      "tgtName": "deploy-role"
    },
    {
      "src": "cmr:acct-vendor",
      "tgt": "cmr:deploy-role",
      "srcName": "vendor-co",
      "tgtName": "deploy-role"
    },
    {
      "src": "cmr:app-role",
      "tgt": "cmr:orders-db",
      "srcName": "app-role",
      "tgtName": "orders-db"
    }
  ]
}
```

```json
{
  "tool": "relation_groups",
  "arguments": {
    "group": "FINANCE"
  },
  "isError": true,
  "text": "Unknown relation group. Did you mean GOVERNANCE? Valid values: NETWORK, CONTAINMENT, IAM, DATA_FLOW, SECURITY, COMPUTE, GOVERNANCE",
  "_meta": {
    "cloudg/error_code": -32602,
    "cloudg/error_data": {
      "value": "FINANCE",
      "valid": [
        "NETWORK",
        "CONTAINMENT",
        "IAM",
        "... 4 more"
      ],
      "close_matches": [
        "GOVERNANCE"
      ]
    }
  }
}
```

### `rag_chunks`

Category `ontology` · sensitivity `confidential` · capabilities `read_state` · readOnly true, destructive false, idempotent true, openWorld false · outputSchema no · timeout: layer default (300 s)

Retrieval-ready text chunks from `cloudg.graph.rag_export.RAGExporter`, useful as context for summarising an area. `entity` chunks describe one asset with its relations and findings (`chunk_id` is `entity::<asset id>`); `community` chunks describe Louvain clusters of tightly connected resources with a risk score; `relation_group` chunks list the triples of one semantic group. Each item has `chunk_id`, `chunk_type`, `content` and `metadata`.

| Argument | Type | Default | Constraints | Description |
|---|---|---|---|---|
| `chunk_type` | string | `"entity"` | one of `entity`, `community`, `relation_group` | Which chunk family to return. |
| `ref` | string | `""` |  | Entity chunks: only this asset's chunk. |
| `query` | string | `""` |  | Substring of chunk content. |
| `min_severity` | string | `""` |  | Entity chunks: severity_max at or above. |
| `limit` | integer | `10` | 1..100 | Page size. |
| `cursor` | string | `""` |  | Opaque cursor from a previous call's next_cursor; empty = first page. |
| `dataset` | string | `""` |  | Dataset name (see list_datasets). Empty = the active dataset. |

`ref` keeps only that asset's entity chunk. `query` is a case-insensitive substring of `content`. `min_severity` compares against `metadata.severity_max`, which entity and community chunks carry; it is checked against the five severity names in upper case and fails with `Unknown severity.` otherwise. Entity chunks match findings to assets like the ontology does, so `orders-db` below counts its backup finding, which names the database by ARN.

Called with the arguments below, `rag_chunks` returned this `structuredContent`.

```json
{"ref": "orders-db"}
```

```json
{
  "dataset": "sample",
  "chunk_type": "entity",
  "total": 1,
  "offset": 0,
  "returned": 1,
  "next_cursor": null,
  "truncated": false,
  "items": [
    {
      "chunk_id": "entity::orders-db",
      "chunk_type": "entity",
      "content": "Resource: orders-db\nType: RDS_INSTANCE\nProvider: AWS\nRegion: us-east-1\nARN: arn:aws:rds:us-east-1:111111111111:db:orders-db\nAccount: 111111111111\nTags: {\"env\": \"prod\", \"data\": \"pii\"}\n\nRelations (4):\n  → PROTECTED_BY_SG: sg-db\n  → ENCRYPTED_...",
      "metadata": {
        "asset_type": "RDS_INSTANCE",
        "provider": "AWS",
        "region": "us-east-1",
        "account_id": "111111111111",
        "is_internet_exposed": false,
        "relation_types": [
          "ENCRYPTED_BY_KMS",
          "POLICY_ALLOWS_ACTION",
          "PROTECTED_BY_SG",
          "... 1 more"
        ],
        "severity_max": "MEDIUM",
        "compliance_frameworks": [
          "CIS-AWS",
          "NIST-800-53"
        ],
        "neighbour_count": 4,
        "finding_count": 1,
        "arn": "arn:aws:rds:us-east-1:111111111111:db:orders-db"
      }
    }
  ]
}
```

Called with the arguments below, `rag_chunks` returned this `structuredContent`.

```json
{"chunk_type": "community", "limit": 1}
```

```json
{
  "dataset": "sample",
  "chunk_type": "community",
  "total": 5,
  "offset": 0,
  "returned": 1,
  "next_cursor": "c1.485ea695a67d",
  "truncated": true,
  "items": [
    {
      "chunk_id": "community::1",
      "chunk_type": "community",
      "content": "Community 1 (10 resources):\n  • sample-org (ORGANIZATION)\n  • Workloads (ORG_UNIT)\n  • prod (CLOUD_ACCOUNT)\n  • shared-services (CLOUD_ACCOUNT)\n  • deny-unapproved-regions (ORG_POLICY)\n  • prod-vpc (VPC)\n  • prod-public-a (SUBNET)\n  • sg-admin (SECURITY_GROUP)\n  • bastion (EC2)\n  • bastion-admin (IA...",
      "metadata": {
        "community_id": 1,
        "member_count": 10,
        "asset_types": {
          "ORGANIZATION": 1,
          "ORG_UNIT": 1,
          "CLOUD_ACCOUNT": 2,
          "ORG_POLICY": 1,
          "VPC": 1,
          "...": "4 more"
        },
        "internal_edges": 9,
        "external_edges": 4,
        "internet_exposed_count": 1,
        "finding_count": 3,
        "severity_max": "CRITICAL",
        "compliance_frameworks": [
          "CIS-AWS",
          "PCI-DSS"
        ],
        "risk_score": 6.5
      }
    }
  ]
}
```

Called with the arguments below, `rag_chunks` returned this `structuredContent`.

```json
{"chunk_type": "relation_group", "limit": 1}
```

```json
{
  "dataset": "sample",
  "chunk_type": "relation_group",
  "total": 7,
  "offset": 0,
  "returned": 1,
  "next_cursor": "c1.2e7539349d13",
  "truncated": true,
  "items": [
    {
      "chunk_id": "relation_group::CONTAINMENT",
      "chunk_type": "relation_group",
      "content": "Relation Group: CONTAINMENT\nTotal relations: 15\n\nRelation type distribution:\n  SUBNET_CONTAINS_INSTANCE: 5\n  CONTAINS: 3\n  LB_TARGETS_INSTANCE: 3\n  ORG_CONTAINS_ACCOUNT: 2\n  VPC_CONTAINS_SUBNET: 2\n\nTriples:\n  sample-org → CONTAINS → Workloads\n  Workloads → ORG_CONTAINS_ACCOUNT → prod\n  Workloads → O...",
      "metadata": {
        "relation_group": "CONTAINMENT",
        "total_relations": 15,
        "relation_type_counts": {
          "CONTAINS": 3,
          "ORG_CONTAINS_ACCOUNT": 2,
          "VPC_CONTAINS_SUBNET": 2,
          "SUBNET_CONTAINS_INSTANCE": 5,
          "LB_TARGETS_INSTANCE": 3
        },
        "unique_subjects": 9,
        "unique_objects": 13
      }
    }
  ]
}
```

Called with the arguments below, `rag_chunks` returned this `structuredContent`.

```json
{"min_severity": "CRITICAL", "limit": 5}
```

```json
{
  "dataset": "sample",
  "chunk_type": "entity",
  "total": 2,
  "offset": 0,
  "returned": 2,
  "next_cursor": null,
  "truncated": false,
  "items": [
    {
      "chunk_id": "entity::sg-admin",
      "chunk_type": "entity",
      "content": "Resource: sg-admin\nType: SECURITY_GROUP\nProvider: AWS\nRegion: us-east-1\nARN: arn:aws:ec2:us-east-1:111111111111:security-group/sg-0admin\nAccount: 111111111111\n\nRelations (4):\n  ← INGRESS_ALLOWED: 0.0....",
      "metadata": {
        "asset_type": "SECURITY_GROUP",
        "provider": "AWS",
        "region": "us-east-1",
        "account_id": "111111111111",
        "is_internet_exposed": false,
        "relation_types": [
          "INGRESS_ALLOWED",
          "INTERNET_REACHABLE",
          "... 2 more"
        ],
        "severity_max": "CRITICAL",
        "compliance_frameworks": [
          "CIS-AWS",
          "PCI-DSS"
        ],
        "neighbour_count": 4,
        "finding_count": 1,
        "arn": "arn:aws:ec2:us-east-1:111111111111:security-group/sg-0admin"
      }
    },
    {
      "chunk_id": "entity::az-nsg",
      "chunk_type": "entity",
      "content": "Resource: jump-nsg\nType: NSG\nProvider: AZURE\nRegion: westeurope\nARN: /subscriptions/00000000-aaaa-bbbb-cccc-000000000001/resourceGroups/rg-hub/providers/Microsoft.Network/networkSecurityGroups/jump-ns...",
      "metadata": {
        "asset_type": "NSG",
        "provider": "AZURE",
        "region": "westeurope",
        "account_id": "00000000-aaaa-bbbb-cccc-000000000001",
        "is_internet_exposed": false,
        "relation_types": [
          "INGRESS_ALLOWED",
          "INTERNET_REACHABLE",
          "... 2 more"
        ],
        "severity_max": "CRITICAL",
        "compliance_frameworks": [
          "CIS-Azure"
        ],
        "neighbour_count": 4,
        "finding_count": 1,
        "arn": "/subscriptions/00000000-aaaa-bbbb-cccc-000000000001/resourceGroups/rg-hub/providers/Microsoft.Network/networkSecurityGroups/jump-nsg"
      }
    }
  ]
}
```

### `export_ontology`

Category `ontology` · sensitivity `confidential` · capabilities `read_state`, `write_fs` · readOnly false, destructive false, idempotent true, openWorld false · outputSchema no · timeout: layer default (300 s)

Writes the ontology to `<output_dir>/<filename>.<ext>` as Turtle (`ttl`), JSON-LD (`jsonld`), RDF/XML (`rdf`) or N-Triples (`nt`); the extension is added when missing, and an existing file is overwritten. Returns `path`, `format`, `triples` and `bytes`, and links `cloudg://ontology/{format}`, which returns the same content without writing a file.

| Argument | Type | Default | Constraints | Description |
|---|---|---|---|---|
| `format` | string | `"turtle"` | one of `turtle`, `json-ld`, `xml`, `nt` | RDF serialisation. |
| `filename` | string | `"ontology"` | pattern `^[A-Za-z0-9_.\-]{1,100}$` | File name (no directories); extension added if missing. |
| `dataset` | string | `""` |  | Dataset name (see list_datasets). Empty = the active dataset. |

Called with the arguments below, `export_ontology` returned this `structuredContent`.

```json
{"format": "turtle", "filename": "estate"}
```

```json
{
  "dataset": "sample",
  "path": "<estate>/out/estate.ttl",
  "format": "turtle",
  "triples": 1184,
  "bytes": 43748
}
```

The result also carried these resource links in `content`:

```json
[
  {
    "type": "resource_link",
    "uri": "cloudg://ontology/turtle",
    "name": "ontology (turtle)",
    "mimeType": "text/turtle"
  }
]
```

```json
{
  "tool": "export_ontology",
  "arguments": {
    "filename": "../escape"
  },
  "isError": true,
  "text": "Invalid arguments: filename: String should match pattern '^[A-Za-z0-9_.\\-]{1,100}$'",
  "_meta": {
    "cloudg/error_code": -32602,
    "cloudg/error_data": [
      {
        "loc": "filename",
        "msg": "String should match pattern '^[A-Za-z0-9_.\\-]{1,100}$'",
        "type": "string_pattern_mismatch"
      }
    ]
  }
}
```

## Export

Every export writes under the workspace output directory (`workspace_status.output_dir`). `subdir` must match `^[A-Za-z0-9_.\-/]{0,200}$` and must stay inside the output directory after resolution; `..` escapes and absolute paths elsewhere fail with an access error. Files with the same name are overwritten.

### `terraform_preview`

Category `export` · sensitivity `internal` · capabilities `read_state` · readOnly true, destructive false, idempotent true, openWorld false · outputSchema no · timeout: layer default (300 s)

What a Terraform recreation of the assets would contain, without writing anything: `assets_considered`, `total_mapped`, `total_unmapped`, `resource_types` (Terraform type to count) and `unmapped_asset_types` (asset types with no Terraform mapping). `refs` picks assets explicitly; `asset_types` filters (both may be combined).

| Argument | Type | Default | Constraints | Description |
|---|---|---|---|---|
| `refs` | string[] or null | `null` |  | Only these assets (refs). |
| `asset_types` | string[] or null | `null` |  | Only these AssetType values. |
| `dataset` | string | `""` |  | Dataset name (see list_datasets). Empty = the active dataset. |

Called with the arguments below, `terraform_preview` returned this `structuredContent`.

```json
{}
```

```json
{
  "dataset": "sample",
  "assets_considered": 44,
  "total_mapped": 29,
  "total_unmapped": 15,
  "resource_types": {
    "aws_vpc": 1,
    "aws_subnet": 2,
    "aws_security_group": 4,
    "aws_lb": 1,
    "aws_instance": 3,
    "...": "13 more"
  },
  "unmapped_asset_types": {
    "ORGANIZATION": 1,
    "ORG_UNIT": 1,
    "CLOUD_ACCOUNT": 3,
    "ORG_POLICY": 1,
    "TARGET_GROUP": 1,
    "...": "8 more"
  }
}
```

Called with the arguments below, `terraform_preview` returned this `structuredContent`.

```json
{"refs": ["web-1", "orders-db"]}
```

```json
{
  "dataset": "sample",
  "assets_considered": 2,
  "total_mapped": 2,
  "total_unmapped": 0,
  "resource_types": {
    "aws_instance": 1,
    "aws_db_instance": 1
  },
  "unmapped_asset_types": {}
}
```

```json
{
  "tool": "terraform_preview",
  "arguments": {
    "refs": [
      "web-11"
    ]
  },
  "isError": true,
  "text": "No asset matches the reference in this dataset. 5 close matches, see suggestions in the error data. Use find_assets(query=...) to search by name, ARN or tag.",
  "_meta": {
    "cloudg/error_code": -32602,
    "cloudg/error_data": {
      "value": "web-11",
      "dataset": "sample",
      "suggestions": [
        {
          "id": "web-1",
          "name": "web-1",
          "arn": "arn:aws:ec2:us-east-1:111111111111:instance/i-0web1",
          "type": "EC2",
          "account_id": "111111111111",
          "dataset": "sample"
        },
        {
          "id": "web-2",
          "name": "web-2",
          "arn": "arn:aws:ec2:us-east-1:111111111111:instance/i-0web2",
          "type": "EC2",
          "account_id": "111111111111",
          "dataset": "sample"
        },
        "... 3 more"
      ]
    }
  }
}
```

### `export_terraform`

Category `export` · sensitivity `confidential` · capabilities `read_state`, `write_fs` · readOnly false, destructive false, idempotent true, openWorld false · outputSchema no · timeout: layer default (300 s)

Writes a `.tf.json` recreation of the selected assets (`provider.tf.json`, `variables.tf.json`, `main.tf.json`) and an `import_commands.sh` into `<output_dir>/<subdir>`. Edges with at least one end among the selected assets are passed to the exporter. Returns `output_dir`, `resources` (assets selected) and `files`.

| Argument | Type | Default | Constraints | Description |
|---|---|---|---|---|
| `subdir` | string | `"terraform"` | pattern `^[A-Za-z0-9_.\-/]{0,200}$` | Sub-directory of the workspace output directory ('' = the directory itself). |
| `refs` | string[] or null | `null` |  | Only these assets (refs). |
| `asset_types` | string[] or null | `null` |  | Only these AssetType values. |
| `dataset` | string | `""` |  | Dataset name (see list_datasets). Empty = the active dataset. |

Called with the arguments below, `export_terraform` returned this `structuredContent`.

```json
{"subdir": "tf", "asset_types": ["EC2", "VPC"]}
```

```json
{
  "dataset": "sample",
  "output_dir": "<estate>/out/tf",
  "resources": 4,
  "files": {
    "provider": "<estate>/out/tf/provider.tf.json",
    "variables": "<estate>/out/tf/variables.tf.json",
    "main": "<estate>/out/tf/main.tf.json",
    "import_commands": "<estate>/out/tf/import_commands.sh"
  }
}
```

```json
{
  "tool": "export_terraform",
  "arguments": {
    "subdir": "../../etc"
  },
  "isError": true,
  "text": "Output path ../../etc escapes the output directory <estate>/out.",
  "_meta": {
    "cloudg/error_code": -31001
  }
}
```

### `export_report`

Category `export` · sensitivity `confidential` · capabilities `read_state`, `write_fs` · readOnly false, destructive false, idempotent true, openWorld false · outputSchema no · timeout: layer default (300 s)

Writes the dataset as a cloudg report file set and returns the paths.

| Argument | Type | Default | Constraints | Description |
|---|---|---|---|---|
| `format` | string | `"json"` | one of `json`, `html`, `inventory`, `graphml`, `asset_map` | json: findings.json (assets, findings, compliance, D3 graph); html: interactive report.html; inventory: inventory-map.json + .graphml + graph + dependencies; graphml: the graph only; asset_map: asset-map.json + compliance-map.json (inventory x findings). |
| `subdir` | string | `""` | pattern `^[A-Za-z0-9_.\-/]{0,200}$` | Sub-directory of the workspace output directory ('' = the directory itself). |
| `dataset` | string | `""` |  | Dataset name (see list_datasets). Empty = the active dataset. |

| `format` | Files (`files` keys) |
|---|---|
| `json` | `findings.json` with assets, edges, findings, compliance and the D3 graph (`json`). Loadable again with `load_dataset`. |
| `html` | The interactive `report.html` (`html`). |
| `inventory` | `inventory-map.json`, `.graphml`, the graph JSON, dependencies and organization files (`map`, `graphml`, `graph`, `dependencies`, `organization`). |
| `graphml` | `<dataset>.graphml` (`graphml`). |
| `asset_map` | `asset-map.json` and `compliance-map.json`, the inventory joined with findings (`asset_map`, `compliance_map`). |

Called with the arguments below, `export_report` returned this `structuredContent`.

```json
{"format": "json", "subdir": "reports/json"}
```

```json
{
  "dataset": "sample",
  "format": "json",
  "output_dir": "<estate>/out/reports/json",
  "files": {
    "json": "<estate>/out/reports/json/findings.json"
  }
}
```

Called with the arguments below, `export_report` returned this `structuredContent`.

```json
{"format": "inventory", "subdir": "reports/inventory"}
```

```json
{
  "dataset": "sample",
  "format": "inventory",
  "output_dir": "<estate>/out/reports/inventory",
  "files": {
    "map": "<estate>/out/reports/inventory/inventory-map.json",
    "graphml": "<estate>/out/reports/inventory/inventory-map.graphml",
    "graph": "<estate>/out/reports/inventory/inventory-graph.json",
    "dependencies": "<estate>/out/reports/inventory/inventory-dependencies.json",
    "organization": "<estate>/out/reports/inventory/inventory-organization.json"
  }
}
```

The `html`, `graphml` and `asset_map` runs returned:

`export_report` returned this `structuredContent`.

```json
{
  "dataset": "sample",
  "format": "html",
  "output_dir": "<estate>/out/reports/html",
  "files": {
    "html": "<estate>/out/reports/html/report.html"
  }
}
```

`export_report` returned this `structuredContent`.

```json
{
  "dataset": "sample",
  "format": "graphml",
  "output_dir": "<estate>/out/reports/graphml",
  "files": {
    "graphml": "<estate>/out/reports/graphml/sample.graphml"
  }
}
```

`export_report` returned this `structuredContent`.

```json
{
  "dataset": "sample",
  "format": "asset_map",
  "output_dir": "<estate>/out/reports/asset_map",
  "files": {
    "asset_map": "<estate>/out/reports/asset_map/asset-map.json",
    "compliance_map": "<estate>/out/reports/asset_map/compliance-map.json"
  }
}
```

## Live

`map_inventory`, `collect_assets`, `run_scanners` and `run_pipeline` are the only tools that reach outside the server (`openWorldHint: true`). The fifth tool in this category, `rate_limit_status`, only reports the guard and throttling state. The other four call provider APIs with the credentials configured on the server (`cloud_access`) and, for scanners, start external binaries (`exec`). They run for minutes, report progress per phase, and put their result in the workspace as a new active dataset; the tool result is a summary plus resource links, never the whole inventory. The engine is looked up as `cloudg.api.CloudGEngine` at call time, so tests and embedders can replace it.

The order of checks in every live call is: arguments, then the result dataset's name (format, and no clash unless `replace`), then `force` permission, then the credential preflight, then the live operation guard, and only then the engine. Everything that can be refused is refused before a single cloud API call.

Each call works on a deep copy of the workspace configuration, so `providers`, `regions` and `services` overrides never change the server's config. `providers` must be a subset of `aws`, `azure`, `gcp`; `regions` replaces the region list of every selected provider.

### Credential preflight

Before any API call, `map_inventory`, `collect_assets` and `run_pipeline` (and `run_scanners` when Prowler or ScoutSuite is among the enabled scanners) check the configured credentials locally, unless `preflight` is false. For AWS: explicit access keys pass; a role ARN with a web identity token file passes when the file exists; otherwise the boto3 default chain (profile, environment, instance role) must yield credentials. For Azure, one token is requested for `https://management.azure.com/.default`. For GCP, the credentials must load. The whole check is bounded at 25 seconds. A failure ends the call before any collector starts, with the reason per provider in `error_data.providers`. The real result of the AWS check with an empty AWS config:

```json
{
  "tool": "map_inventory",
  "arguments": {
    "providers": [
      "aws"
    ]
  },
  "isError": true,
  "text": "Cannot collect live data. aws: no credentials found (set aws.profile / access keys in the cloudg config, AWS_PROFILE / AWS_ACCESS_KEY_ID in the server's environment, or run on a host with an instance role). Fix the server's credentials, choose other providers, or work offline with load_dataset. Pass preflight=false to skip this check.",
  "_meta": {
    "cloudg/error_code": -32603,
    "cloudg/error_data": {
      "providers": {
        "aws": "no credentials found (set aws.profile / access keys in the cloudg config, AWS_PROFILE / AWS_ACCESS_KEY_ID in the server's environment, or run on a host with an instance role)"
      }
    }
  }
}
```

When the check does not finish in time the message is `Credential check did not finish within 25s; the cloud identity endpoints look unreachable. Pass preflight=false to try anyway.`

### Live operation guard

An agent can ask for a collection far more often than a person running `cloudg map`. Every live call therefore goes through the workspace's `LiveOperationGuard` (`cloudg/resilience/guard.py`, reachable as `Workspace.live_guard` and replaceable there). The guard works on scopes: one per configured account, profile, subscription or project (`aws/123456789012`, `aws/profile:prod`, `gcp/org:42`), or the bare provider name when the config names none. In the sample run the config named no AWS account, so the scope was `aws`.

- Single-flight: a call identical to one already running (same operation, providers, scopes and collection arguments such as `regions` or `services`; the dataset `name` is not part of the comparison) waits for it and returns the same result with `"joined": true` and a `note`. Only one engine runs.
- Timeout: an operation still running after `operation_timeout_seconds` (`ratelimit.live_operation_timeout_seconds`, default 3600) is cancelled and its scopes are freed; the caller gets reason `timeout`. An operation whose callers have all gone (each cancelled by the client or a tool timeout) is cancelled too.
- Concurrency caps: at most `max_concurrent_per_scope` (default 1) live operations per scope and `max_concurrent_total` (default 2) overall. A different operation on a busy scope is refused with reason `busy`.
- Cooldown: after an operation on a scope finishes (successfully or not), a new one on that scope is refused for `cooldown_seconds` (default 120, overridable per provider) with reason `cooldown`.
- Caller quota: with `caller_max_operations` set, a caller gets at most that many new live operations per `caller_window_seconds` (reason `quota`). It is off by default.

The defaults come from the `ratelimit` section of the cloudg config (`live_cooldown_seconds`, `live_max_concurrent`, `live_max_concurrent_total`, `live_caller_max_operations`, `live_caller_window_seconds`, `live_operation_timeout_seconds`, and `ratelimit.<provider>.live_cooldown_seconds`). `run_scanners` always runs under the guard, so identical scans share one run, but it claims the cloud scopes (and their cooldowns) only when Prowler or ScoutSuite runs; the offline scanners have no scope.

A refusal is a tool error with code `-31029`. `error_data` carries `reason`, `message`, `retry_after_seconds`, `scopes` and `caller` (each only when set), and `use_dataset`: the most recent live dataset already loaded whose providers include every provider of the refused call, which the message tells the caller to query instead. A second `map_inventory` on the same scope right after the first:

```json
{
  "tool": "map_inventory",
  "arguments": {
    "providers": [
      "aws"
    ],
    "name": "live-aws-2"
  },
  "isError": true,
  "text": "live collection of aws ran recently; cooling down, retry in 120s or use the cached dataset. The last live result is already loaded as dataset 'live-aws'; query it instead of collecting again. An admin or operator can pass force=true to skip the cooldown.",
  "_meta": {
    "cloudg/error_code": -31029,
    "cloudg/error_data": {
      "reason": "cooldown",
      "message": "live collection of aws ran recently; cooling down, retry in 120s or use the cached dataset",
      "retry_after_seconds": 120.0,
      "scopes": [
        "aws"
      ],
      "caller": "local",
      "use_dataset": "live-aws"
    }
  }
}
```

`force: true` skips the cooldown, but only for a principal with the `admin` or `operator` role. Anyone else gets an access error, raised before the preflight:

```json
{
  "tool": "map_inventory",
  "arguments": {
    "providers": [
      "aws"
    ],
    "name": "live-aws-2",
    "force": true
  },
  "isError": true,
  "text": "force=true (skip the live cooldown) needs the admin or operator role. Use the dataset from the last collection, or wait for the cooldown to end.",
  "_meta": {
    "cloudg/error_code": -31001
  }
}
```

With the `admin` or `operator` role the same call skips the cooldown and runs. Two `map_inventory(providers=["gcp"])` calls started 50 ms apart, the first with `name: "shared"` and the second without a name, produced one engine run. The second call got the first call's result, dataset `shared` included, plus the join marker:

Called with the arguments below, `map_inventory` returned this `structuredContent`.

```json
{"providers": ["gcp"]}
```

```json
{
  "dataset": "shared",
  "active": true,
  "tool": "map_inventory",
  "duration_s": 0.3,
  "summary": {
    "total_assets": 44,
    "total_edges": 56,
    "total_findings": 0,
    "open_findings": 0,
    "severity_breakdown": {},
    "accounts": 5,
    "regions": 5,
    "internet_exposed": 6,
    "cross_account_edges": 3,
    "assets_by_type": {
      "SECURITY_GROUP": 4,
      "IAM_ROLE": 4,
      "CLOUD_ACCOUNT": 3,
      "EC2": 3,
      "S3_BUCKET": 3,
      "...": "10 more"
    },
    "providers": [
      "aws",
      "... 2 more"
    ]
  },
  "collection_failures": [
    {
      "service": "rds",
      "error": "AccessDenied: rds:DescribeDBInstances"
    }
  ],
  "errors": [
    "aws:rds: AccessDenied"
  ],
  "next_steps": [
    "dataset_summary",
    "... 2 more"
  ],
  "joined": true,
  "note": "An identical live operation was already running; this call shares its result instead of collecting again."
}
```

While that operation held the `gcp` scope, `collect_assets(providers=["gcp"])` was refused as busy:

```json
{
  "tool": "collect_assets",
  "arguments": {
    "providers": [
      "gcp"
    ],
    "name": "busy-try"
  },
  "isError": true,
  "text": "a live operation is already running for gcp; retry when it finishes or use the cached dataset. The last live result is already loaded as dataset 'live-aws'; query it instead of collecting again.",
  "_meta": {
    "cloudg/error_code": -31029,
    "cloudg/error_data": {
      "reason": "busy",
      "message": "a live operation is already running for gcp; retry when it finishes or use the cached dataset",
      "scopes": [
        "gcp"
      ],
      "caller": "local",
      "use_dataset": "live-aws"
    }
  }
}
```

`rate_limit_status` (and the `cloudg://ratelimit` resource) shows the scopes cooling down, so a caller can check before asking.

### Progress

The phase hook of the engine is wired to MCP progress notifications. `progress` is the phase number from this table, capped just below `total`, and the call ends with `progress == total` and the message `done`:

| Phase | Step |
|---|---|
| `inventory_mapping`, `collection` | 1 |
| `scanning`, `ingest` | 2 |
| `analysis` | 3 |
| `normalisation` | 4 |
| `reporting` | 5 |

`total` is 2 for `map_inventory` and `collect_assets`, 3 for `run_scanners` and 6 for `run_pipeline`. `map_inventory` also sends `0.5` with `mapping inventory` before the engine starts. Engine errors reported through the engine's error hook are collected and returned in `errors` as `phase: message` strings.

### What the result looks like

`map_inventory`, `collect_assets` and `run_pipeline` return: `dataset` (the new name), `active: true`, `tool`, `duration_s`, `summary` (`total_assets`, `total_edges`, `total_findings`, `open_findings`, `severity_breakdown`, `accounts`, `regions`, `internet_exposed`, `cross_account_edges`, `assets_by_type`, `providers`), the tool-specific fields below, and `next_steps`. They link `cloudg://datasets/{name}/summary` (priority 1.0) and `cloudg://workspace`.

Without `name`, the dataset is called `<prefix>-<YYYYmmdd-HHMMSS>` (`inventory-`, `collect-`, `pipeline-`). An explicit `name` is checked before anything else runs: a malformed name, or one already loaded without `replace: true`, fails without creating an engine. In the capture run neither of these calls created one:

```json
{
  "tool": "map_inventory",
  "arguments": {
    "name": "my dataset"
  },
  "isError": true,
  "text": "Invalid dataset name: use 1-64 letters, digits, '.', '_' or '-'.",
  "_meta": {
    "cloudg/error_code": -32602,
    "cloudg/error_data": {
      "value": "my dataset"
    }
  }
}
```

```json
{
  "tool": "map_inventory",
  "arguments": {
    "providers": [
      "aws"
    ],
    "name": "sample",
    "force": true
  },
  "isError": true,
  "text": "A dataset with that name already exists. Choose another name (the error data suggests a free one), or pass replace=true to overwrite it.",
  "_meta": {
    "cloudg/error_code": -32602,
    "cloudg/error_data": {
      "existing": "sample",
      "suggested": "sample-2"
    }
  }
}
```

### `map_inventory`

Category `live` · sensitivity `confidential` · capabilities `cloud_access`, `read_state`, `write_state` · readOnly false, destructive false, idempotent false, openWorld true · outputSchema no · timeout 3600 s

The complete live inventory with read-only API calls: deep collectors, catch-all sweeps, relationship linking, and organization discovery across accounts when configured. No scanners. Adds `collection_failures` (first 20 failed services from the coverage records) and `errors`.

| Argument | Type | Default | Constraints | Description |
|---|---|---|---|---|
| `providers` | string[] or null | `null` |  | Subset of aws, azure, gcp; empty = the configured providers. |
| `regions` | string[] or null | `null` |  | Regions to collect for every selected provider; empty = configured regions. |
| `services` | string[] or null | `null` |  | Service families: all, network, compute, containers, kubernetes, serverless, integration, data, storage, identity, security, dns, iac, logging. |
| `tagging_sweep` | boolean or null | `null` |  | AWS Resource Groups Tagging API sweep; default from config. |
| `name` | string | `""` |  | Dataset name for the result; default '<tool>-<timestamp>'. |
| `replace` | boolean | `false` |  | Overwrite an existing dataset with the same name (otherwise a name clash is an error, reported before any cloud call). |
| `preflight` | boolean | `true` |  | Check the configured credentials before calling any cloud API, so a missing profile fails in seconds instead of after every collector has retried. |
| `force` | boolean | `false` |  | Skip the live cooldown for this call. Only honoured for callers with the admin or operator role; others get an access error. |

The examples in this section all ran against the stubbed engine described in [How the examples were produced](#how-the-examples-were-produced).

Called with the arguments below, `map_inventory` returned this `structuredContent`.

```json
{"providers": ["aws"], "regions": ["us-east-1"], "name": "live-aws"}
```

```json
{
  "dataset": "live-aws",
  "active": true,
  "tool": "map_inventory",
  "duration_s": 0.0,
  "summary": {
    "total_assets": 44,
    "total_edges": 56,
    "total_findings": 0,
    "open_findings": 0,
    "severity_breakdown": {},
    "accounts": 5,
    "regions": 5,
    "internet_exposed": 6,
    "cross_account_edges": 3,
    "assets_by_type": {
      "SECURITY_GROUP": 4,
      "IAM_ROLE": 4,
      "CLOUD_ACCOUNT": 3,
      "EC2": 3,
      "S3_BUCKET": 3,
      "...": "10 more"
    },
    "providers": [
      "aws",
      "azure",
      "... 1 more"
    ]
  },
  "collection_failures": [
    {
      "service": "rds",
      "error": "AccessDenied: rds:DescribeDBInstances"
    }
  ],
  "errors": [
    "aws:rds: AccessDenied"
  ],
  "next_steps": [
    "dataset_summary",
    "find_assets",
    "... 2 more"
  ]
}
```

The result also carried these resource links in `content`:

```json
[
  {
    "type": "resource_link",
    "uri": "cloudg://datasets/live-aws/summary",
    "name": "live-aws summary",
    "title": "Dataset summary",
    "mimeType": "application/json",
    "annotations": {
      "priority": 1.0
    }
  },
  {
    "type": "resource_link",
    "uri": "cloudg://workspace",
    "name": "workspace",
    "mimeType": "application/json"
  }
]
```

The progress notifications received during the call (`progress`, `total`, `message`) were:

```json
[
  [
    0.5,
    2.0,
    "mapping inventory"
  ],
  [
    1.0,
    2.0,
    "phase: inventory_mapping"
  ],
  [
    2.0,
    2.0,
    "done"
  ]
]
```

```json
{
  "tool": "map_inventory",
  "arguments": {
    "providers": [
      "oracle"
    ]
  },
  "isError": true,
  "text": "Unknown provider(s) oracle. Use aws, azure, gcp.",
  "_meta": {
    "cloudg/error_code": -32602
  }
}
```

### `collect_assets`

Category `live` · sensitivity `confidential` · capabilities `cloud_access`, `read_state`, `write_state` · readOnly false, destructive false, idempotent false, openWorld true · outputSchema no · timeout 3600 s

The standard multi-provider collection that `cloudg collect` runs (core services, network edges, IAM). Lighter than `map_inventory`. Adds `errors`.

| Argument | Type | Default | Constraints | Description |
|---|---|---|---|---|
| `providers` | string[] or null | `null` |  | Subset of aws, azure, gcp; empty = the configured providers. |
| `regions` | string[] or null | `null` |  | Regions to collect for every selected provider; empty = configured regions. |
| `name` | string | `""` |  | Dataset name for the result; default '<tool>-<timestamp>'. |
| `replace` | boolean | `false` |  | Overwrite an existing dataset with the same name (otherwise a name clash is an error, reported before any cloud call). |
| `preflight` | boolean | `true` |  | Check the configured credentials before calling any cloud API, so a missing profile fails in seconds instead of after every collector has retried. |
| `force` | boolean | `false` |  | Skip the live cooldown for this call. Only honoured for callers with the admin or operator role; others get an access error. |

Called with the arguments below, `collect_assets` returned this `structuredContent`.

```json
{"providers": ["aws", "gcp"], "name": "collected"}
```

```json
{
  "dataset": "collected",
  "active": true,
  "tool": "collect_assets",
  "duration_s": 0.0,
  "summary": {
    "total_assets": 44,
    "total_edges": 56,
    "total_findings": 0,
    "open_findings": 0,
    "severity_breakdown": {},
    "accounts": 5,
    "regions": 5,
    "internet_exposed": 6,
    "cross_account_edges": 3,
    "assets_by_type": {
      "SECURITY_GROUP": 4,
      "IAM_ROLE": 4,
      "CLOUD_ACCOUNT": 3,
      "EC2": 3,
      "S3_BUCKET": 3,
      "...": "10 more"
    },
    "providers": [
      "aws",
      "gcp"
    ]
  },
  "errors": [],
  "next_steps": [
    "dataset_summary",
    "find_assets",
    "... 2 more"
  ]
}
```

The result also carried these resource links in `content`:

```json
[
  {
    "type": "resource_link",
    "uri": "cloudg://datasets/collected/summary",
    "name": "collected summary",
    "title": "Dataset summary",
    "mimeType": "application/json",
    "annotations": {
      "priority": 1.0
    }
  },
  {
    "type": "resource_link",
    "uri": "cloudg://workspace",
    "name": "workspace",
    "mimeType": "application/json"
  }
]
```

The progress notifications received during the call (`progress`, `total`, `message`) were:

```json
[
  [
    1.0,
    2.0,
    "phase: collection"
  ],
  [
    2.0,
    2.0,
    "done"
  ]
]
```

### `run_scanners`

Category `live` · sensitivity `confidential` · capabilities `cloud_access`, `exec`, `read_fs`, `read_state`, `write_fs`, `write_state` · readOnly false, destructive false, idempotent false, openWorld true · outputSchema no · timeout 7200 s

Runs security scanners plus cloudg's reachability analysis against an existing dataset's assets and adds the findings to it. Scanner output files go to `<output_dir>/scans`. `iac_dir` (for Checkov) must be inside an allowed root. Only Prowler and ScoutSuite need cloud credentials, so the preflight runs only when one of them is selected; Checkov, Trivy and the IAM linter run offline. With `normalise` the dataset's findings are deduplicated and compliance-mapped afterwards (merging the compliance results as `normalise_findings` does). Container image names that start with `-` are refused, so an image argument can never be read as a scanner option. Unlike the other three it does not create a dataset.

| Argument | Type | Default | Constraints | Description |
|---|---|---|---|---|
| `scanners` | string[] or null | `null` |  | Subset of prowler, scoutsuite, checkov, trivy, iam; empty = configured. |
| `iac_dir` | string | `""` |  | IaC directory for Checkov (inside an allowed root). |
| `images` | string[] or null | `null` |  | Container images for Trivy. |
| `normalise` | boolean | `true` |  | Deduplicate and compliance-map the dataset's findings after the scan. |
| `dataset` | string | `""` |  | Dataset name (see list_datasets). Empty = the active dataset. |
| `preflight` | boolean | `true` |  | Check the configured credentials before calling any cloud API, so a missing profile fails in seconds instead of after every collector has retried. |
| `force` | boolean | `false` |  | Skip the live cooldown for this call. Only honoured for callers with the admin or operator role; others get an access error. |

Returns `dataset`, `scanners` (the enabled list), `new_findings`, `severity_breakdown` of the new findings, `findings_before`, `findings_after`, `output_dir`, `duration_s`, `errors` and `next_steps`, and links the dataset summary and the workspace. The stubbed engine's scan returns one HIGH finding:

Called with the arguments below, `run_scanners` returned this `structuredContent`.

```json
{"scanners": ["prowler", "iam"], "dataset": "sample"}
```

```json
{
  "dataset": "sample",
  "scanners": [
    "prowler",
    "iam"
  ],
  "new_findings": 1,
  "severity_breakdown": {
    "HIGH": 1
  },
  "findings_before": 12,
  "findings_after": 13,
  "output_dir": "<estate>/out/scans",
  "duration_s": 1.2,
  "errors": [],
  "next_steps": [
    "top_risks",
    "list_findings(min_severity='HIGH')",
    "compliance_summary"
  ]
}
```

The result also carried these resource links in `content`:

```json
[
  {
    "type": "resource_link",
    "uri": "cloudg://datasets/sample/summary",
    "name": "sample summary",
    "title": "Dataset summary",
    "mimeType": "application/json",
    "annotations": {
      "priority": 1.0
    }
  },
  {
    "type": "resource_link",
    "uri": "cloudg://workspace",
    "name": "workspace",
    "mimeType": "application/json"
  }
]
```

The progress notifications received during the call (`progress`, `total`, `message`) were:

```json
[
  [
    2.0,
    3.0,
    "phase: scanning"
  ],
  [
    3,
    3,
    "done"
  ]
]
```

```json
{
  "tool": "run_scanners",
  "arguments": {
    "scanners": [
      "nmap"
    ]
  },
  "isError": true,
  "text": "Unknown scanner(s) nmap. Use: prowler, scoutsuite, checkov, trivy, iam",
  "_meta": {
    "cloudg/error_code": -32602
  }
}
```

```json
{
  "tool": "run_scanners",
  "arguments": {
    "iac_dir": "/etc"
  },
  "isError": true,
  "text": "Path /etc is outside the allowed roots (<estate>). Ask the operator to add its directory to the workspace's allowed roots.",
  "_meta": {
    "cloudg/error_code": -31001
  }
}
```

### `run_pipeline`

Category `live` · sensitivity `confidential` · capabilities `cloud_access`, `exec`, `read_state`, `write_fs`, `write_state` · readOnly false, destructive false, idempotent false, openWorld true · outputSchema no · timeout 7200 s

The whole cloudg pipeline in one call: collect, scan, analyse (graph, ontology, RAG, Terraform), normalise, then JSON and HTML reports under `<output_dir>/<subdir>`. Adds `report_paths`, `attack_paths_found` and `errors` (pipeline errors plus hook errors).

| Argument | Type | Default | Constraints | Description |
|---|---|---|---|---|
| `providers` | string[] or null | `null` |  | Subset of aws, azure, gcp; empty = the configured providers. |
| `regions` | string[] or null | `null` |  | Regions to collect for every selected provider; empty = configured regions. |
| `subdir` | string | `"pipeline"` | pattern `^[A-Za-z0-9_.\-/]{0,200}$` | Output sub-directory for reports. |
| `name` | string | `""` |  | Dataset name for the result; default '<tool>-<timestamp>'. |
| `replace` | boolean | `false` |  | Overwrite an existing dataset with the same name (otherwise a name clash is an error, reported before any cloud call). |
| `preflight` | boolean | `true` |  | Check the configured credentials before calling any cloud API, so a missing profile fails in seconds instead of after every collector has retried. |
| `force` | boolean | `false` |  | Skip the live cooldown for this call. Only honoured for callers with the admin or operator role; others get an access error. |

Called with the arguments below, `run_pipeline` returned this `structuredContent`.

```json
{"subdir": "pipeline", "name": "full"}
```

```json
{
  "dataset": "full",
  "active": true,
  "tool": "run_pipeline",
  "duration_s": 0.0,
  "summary": {
    "total_assets": 44,
    "total_edges": 56,
    "total_findings": 12,
    "open_findings": 11,
    "severity_breakdown": {
      "CRITICAL": 2,
      "HIGH": 5,
      "MEDIUM": 2,
      "LOW": 1,
      "INFO": 1
    },
    "accounts": 5,
    "regions": 5,
    "internet_exposed": 6,
    "cross_account_edges": 3,
    "assets_by_type": {
      "SECURITY_GROUP": 4,
      "IAM_ROLE": 4,
      "CLOUD_ACCOUNT": 3,
      "EC2": 3,
      "S3_BUCKET": 3,
      "...": "10 more"
    },
    "providers": [
      "aws"
    ]
  },
  "report_paths": {
    "json": "<estate>/out/pipeline/findings.json"
  },
  "attack_paths_found": 1,
  "errors": [],
  "next_steps": [
    "dataset_summary",
    "find_assets",
    "... 2 more"
  ]
}
```

The result also carried these resource links in `content`:

```json
[
  {
    "type": "resource_link",
    "uri": "cloudg://datasets/full/summary",
    "name": "full summary",
    "title": "Dataset summary",
    "mimeType": "application/json",
    "annotations": {
      "priority": 1.0
    }
  },
  {
    "type": "resource_link",
    "uri": "cloudg://workspace",
    "name": "workspace",
    "mimeType": "application/json"
  }
]
```

The progress notifications received during the call (`progress`, `total`, `message`) were:

```json
[
  [
    1.0,
    6.0,
    "phase: collection"
  ],
  [
    2.0,
    6.0,
    "phase: scanning"
  ],
  [
    3.0,
    6.0,
    "phase: analysis"
  ],
  "... 3 more"
]
```

```json
{
  "tool": "run_pipeline",
  "arguments": {
    "subdir": "../../x"
  },
  "isError": true,
  "text": "Output path ../../x escapes the output directory <estate>/out.",
  "_meta": {
    "cloudg/error_code": -31001
  }
}
```

### `rate_limit_status`

Category `live` · sensitivity `internal` · capabilities `read_state` · readOnly true, destructive false, idempotent true, openWorld false · outputSchema no · timeout: layer default (300 s)

The live guard and cloud API throttling state, without calling any cloud API. `live_guard` has `in_flight`, `active_total`, `active_by_scope`, `cooling_down` (scope to seconds left), `started` and `joined` counters, and the settings (`cooldown_seconds`, `provider_cooldowns`, `max_concurrent_per_scope`, `max_concurrent_total`, `caller_max_operations`). `throttling` is the summary of cloudg's throttling governor (`cloudg.resilience`): call, throttle, retry and give-up totals, recent messages, skipped services, per-scope figures, tripped circuit breakers and slowed rate buckets. The same object is served as `cloudg://ratelimit`. The tool is in the `live` category, so `exclude_categories=["live"]` removes it too, but it needs only `read_state`, so profiles that deny cloud access keep it.

Arguments: none.

Right after the first `map_inventory` of the capture run:

Called with the arguments below, `rate_limit_status` returned this `structuredContent`.

```json
{}
```

```json
{
  "live_guard": {
    "in_flight": 0,
    "active_total": 0,
    "active_by_scope": {},
    "cooling_down": {
      "aws": 120.0
    },
    "started": 1,
    "joined": 0,
    "cooldown_seconds": 120.0,
    "provider_cooldowns": {},
    "max_concurrent_per_scope": 1,
    "max_concurrent_total": 2,
    "caller_max_operations": 0
  },
  "throttling": {
    "totals": {
      "calls": 0,
      "throttled": 0,
      "transient_errors": 0,
      "retries": 0,
      "gave_up": 0,
      "rejected": 0,
      "breaker_trips": 0,
      "wait_seconds": 0
    },
    "messages": [],
    "skipped": {},
    "scopes": {},
    "breakers": {},
    "slowed_buckets": {}
  }
}
```

## Meta

Static answers with no tenant data. They are `public`, need no capability and no dataset, so even the most restrictive policy keeps them.

### `list_capabilities`

Category `meta` · sensitivity `public` · capabilities none · readOnly true, destructive false, idempotent true, openWorld false · outputSchema no · timeout: layer default (300 s)

What this caller may use: the visible tools grouped by category (each with `name` as exposed, prefix included, `title`, `read_only`, `open_world`, `sensitivity`, `capabilities` and `summary`, the first sentence of its description up to 160 characters), `tool_count`, the number of `resources` and `resource_templates`, the `prompts` names, recommended `workflows` and the `conventions`. Everything is filtered through the policy for the calling principal.

Arguments: none.

Called with the arguments below, `list_capabilities` returned this `structuredContent`.

```json
{}
```

```json
{
  "server": "cloudg",
  "version": "0.6.0",
  "categories": {
    "compliance": [
      {
        "name": "compliance_gaps",
        "title": "Compliance gaps",
        "read_only": true,
        "open_world": false,
        "sensitivity": "confidential",
        "capabilities": [
          "read_state"
        ],
        "summary": "Assets that fail compliance, worst first: per asset the frameworks\nand controls it fails, open findings, max severity an..."
      },
      {
        "name": "compliance_summary",
        "title": "Compliance summary",
        "read_only": true,
        "open_world": false,
        "sensitivity": "internal",
        "capabilities": [
          "read_state"
        ],
        "summary": "Compliance posture per framework: controls evaluated / failing /\npassing, pass rate, open findings by severity and affec..."
      },
      "... 2 more"
    ],
    "export": [
      {
        "name": "export_report",
        "title": "Export report",
        "read_only": false,
        "open_world": false,
        "sensitivity": "confidential",
        "capabilities": [
          "read_state",
          "write_fs"
        ],
        "summary": "Write the dataset as a cloudg report file set into the output\ndirectory and return the file paths."
      },
      {
        "name": "export_terraform",
        "title": "Export Terraform",
        "read_only": false,
        "open_world": false,
        "sensitivity": "confidential",
        "capabilities": [
          "read_state",
          "write_fs"
        ],
        "summary": "Write a Terraform (.tf.json) recreation of the assets (provider,\nvariables, main and an import_commands.sh) into the out..."
      },
      "... 1 more"
    ],
    "...": "8 more categories"
  },
  "tool_count": 74,
  "resources": 13,
  "resource_templates": 11,
  "prompts": [
    "security_posture_review",
    "executive_summary",
    "... 7 more"
  ],
  "workflows": {
    "orient": [
      "workspace_status",
      "dataset_summary",
      "... 2 more"
    ],
    "triage risk": [
      "top_risks",
      "get_asset",
      "... 2 more"
    ],
    "attack surface": [
      "internet_exposure",
      "attack_paths",
      "... 2 more"
    ],
    "change impact": [
      "dependents",
      "dependency_tree",
      "... 2 more"
    ],
    "compliance": [
      "compliance_summary",
      "list_controls",
      "... 2 more"
    ],
    "drift": [
      "snapshot_dataset",
      "map_inventory / load_dataset",
      "... 1 more"
    ],
    "semantic": [
      "ontology_stats",
      "relation_groups",
      "... 2 more"
    ]
  },
  "conventions": {
    "dataset": "empty = active dataset",
    "ref": "asset id, ARN, unique name or unique ARN tail",
    "pagination": "pass next_cursor back as cursor; cursors expire when the dataset changes"
  }
}
```

### `describe_schema`

Category `meta` · sensitivity `public` · capabilities none · readOnly true, destructive false, idempotent true, openWorld false · outputSchema no · timeout: layer default (300 s)

cloudg's vocabulary. `asset_types` maps a family heading (taken from the comments in the `AssetType` enum source) to its type values; `edge_types` maps each edge type to how it reads; `severities`; `relation_groups` maps each relation group to its relation types (with `section: "relation_groups"` only the group names); `compliance_statuses`; `providers`. Use these exact values in filters.

| Argument | Type | Default | Constraints | Description |
|---|---|---|---|---|
| `section` | string | `"all"` | one of `all`, `asset_types`, `edge_types`, `severities`, `relation_types`, `relation_groups`, `compliance_statuses`, `providers` | Which part of the vocabulary to return. |

Called with the arguments below, `describe_schema` returned this `structuredContent`.

```json
{"section": "edge_types"}
```

```json
{
  "edge_types": {
    "SECURITY_GROUP_RULE": "allows traffic",
    "NACL_RULE": "allows traffic",
    "ROUTE": "routes through / forwards to",
    "IAM_TRUST": "may assume",
    "IAM_POLICY_ATTACHMENT": "has policy",
    "CONTAINS": "contains",
    "PEERING": "peers with",
    "LOAD_BALANCER_TARGET": "sends traffic to",
    "INTERNET_EXPOSED": "exposes",
    "ATTACHED_TO": "is attached to",
    "REFERENCES": "uses / points at",
    "INVOKES": "triggers / calls",
    "USES_IMAGE": "runs the image of",
    "ASSUMES_ROLE": "runs as",
    "GRANTS_ACCESS": "is granted access to",
    "LOGS_TO": "sends logs to",
    "PROTECTS": "protects",
    "MONITORS": "monitors",
    "MANAGES": "manages",
    "GOVERNS": "governs"
  }
}
```

Called with the arguments below, `describe_schema` returned this `structuredContent`.

```json
{"section": "relation_groups"}
```

```json
{
  "relation_groups": [
    "NETWORK",
    "CONTAINMENT",
    "IAM",
    "DATA_FLOW",
    "SECURITY",
    "COMPUTE",
    "GOVERNANCE"
  ]
}
```

With `section: "all"` the sample run returned 22 asset families, 20 edge types, 5 severities, 7 relation groups, 4 compliance statuses (`PASS`, `FAIL`, `NOT_APPLICABLE`, `MANUAL`) and 3 providers (`AWS`, `AZURE`, `GCP`).

### `explain_asset_type`

Category `meta` · sensitivity `public` · capabilities none · readOnly true, destructive false, idempotent true, openWorld false · outputSchema no · timeout: layer default (300 s)

How cloudg models one asset type: `family`, `note` (the enum comment, when there is one), `ontology_class`, `terraform_type`, `sensitive_data_store` (the reachability analyser's list), `crown_jewel_weight` (0 when not a crown jewel), `internet_exposure_expected`, and `in_active_dataset` (count) when a dataset is loaded.

| Argument | Type | Default | Constraints | Description |
|---|---|---|---|---|
| `asset_type` | string | required | min length 1 | An AssetType value, e.g. LAMBDA_FUNCTION. |

Called with the arguments below, `explain_asset_type` returned this `structuredContent`.

```json
{"asset_type": "rds_instance"}
```

```json
{
  "asset_type": "RDS_INSTANCE",
  "family": "Database",
  "note": null,
  "ontology_class": "cm:RelationalDatabase",
  "terraform_type": "aws_db_instance",
  "sensitive_data_store": true,
  "crown_jewel_weight": 10,
  "internet_exposure_expected": false,
  "in_active_dataset": 1
}
```

```json
{
  "tool": "explain_asset_type",
  "arguments": {
    "asset_type": "LAMBDA"
  },
  "isError": true,
  "text": "Unknown asset type. Did you mean LAMBDA_FUNCTION, ALARM? Valid values: EC2, VIRTUAL_MACHINE, GCE_INSTANCE, LAMBDA_FUNCTION, CLOUD_FUNCTION, ECS_CLUSTE...",
  "_meta": {
    "cloudg/error_code": -32602,
    "cloudg/error_data": {
      "value": "LAMBDA",
      "valid": [
        "EC2",
        "VIRTUAL_MACHINE",
        "GCE_INSTANCE",
        "... 153 more"
      ],
      "close_matches": [
        "LAMBDA_FUNCTION",
        "ALARM"
      ]
    }
  }
}
```

### `explain_edge_type`

Category `meta` · sensitivity `public` · capabilities none · readOnly true, destructive false, idempotent true, openWorld false · outputSchema no · timeout: layer default (300 s)

How to read one edge type: `reads_as` ("source verb target"), `typical` endpoints, `note` from the enum source, `dependency_direction` (`forward`, `reverse` or `none`, see [Graph](#graph)) and `ontology_relations`, the relation types inferred directly from the edge type, or a string saying the relation depends on ports, CIDRs and endpoint types.

| Argument | Type | Default | Constraints | Description |
|---|---|---|---|---|
| `edge_type` | string | required | min length 1 | An EdgeType value, e.g. ASSUMES_ROLE. |

Called with the arguments below, `explain_edge_type` returned this `structuredContent`.

```json
{"edge_type": "contains"}
```

```json
{
  "edge_type": "CONTAINS",
  "reads_as": "source contains target",
  "typical": "VPC -> subnet, subnet -> instance, account -> resource",
  "note": "VPC contains Subnet",
  "dependency_direction": "reverse",
  "ontology_relations": "inferred from both endpoint types (VPC_CONTAINS_SUBNET, SUBNET_CONTAINS_INSTANCE, CLUSTER_CONTAINS_SERVICE, ORG_CONTAINS_ACCOUNT), else the generic CONTAINS"
}
```

Called with the arguments below, `explain_edge_type` returned this `structuredContent`.

```json
{"edge_type": "ASSUMES_ROLE"}
```

```json
{
  "edge_type": "ASSUMES_ROLE",
  "reads_as": "source runs as target",
  "typical": "function, task, node group, instance profile -> role / service account",
  "note": "compute or service account -> IAM role it runs as",
  "dependency_direction": "forward",
  "ontology_relations": [
    "RUNS_ON"
  ]
}
```

```json
{
  "tool": "explain_edge_type",
  "arguments": {
    "edge_type": "LIKES"
  },
  "isError": true,
  "text": "Unknown edge type. Did you mean INVOKES? Valid values: SECURITY_GROUP_RULE, NACL_RULE, ROUTE, IAM_TRUST, IAM_POLICY_ATTACHMENT, CONTAINS, PEERING, LOA...",
  "_meta": {
    "cloudg/error_code": -32602,
    "cloudg/error_data": {
      "value": "LIKES",
      "valid": [
        "SECURITY_GROUP_RULE",
        "NACL_RULE",
        "ROUTE",
        "... 17 more"
      ],
      "close_matches": [
        "INVOKES"
      ]
    }
  }
}
```

## Privacy

The privacy tools let a caller see what the active policy does to its data. [MCP_PRIVACY.md](MCP_PRIVACY.md) explains the profiles, transforms and the vault; this section covers the tool contracts. The examples ran under `open`, which has no transforms, except where noted.

### `privacy_status`

Category `privacy` · sensitivity `internal` · capabilities `read_state` · readOnly true, destructive false, idempotent true, openWorld false · outputSchema no · timeout: layer default (300 s)

The active policy as it applies to the caller: `policy`, `description`, `loaded_from` (profile name or file), `extends` (inheritance chain), `principal` (`id`, `roles`), `max_sensitivity`, `denied_capabilities`, `visible_tools`, `output_pipeline` (one description per transform; the redact step lists its `strategies` as `{applies_to, strategy, options}` items), `pseudonymisation` (`active`, `vault_scope`, `vault_entries`, `by_entity`, `key_source`), `audit_enabled` and `counters` (allowed, denied, rate-limited, hidden and reveal decisions so far).

Arguments: none.

Called with the arguments below, `privacy_status` returned this `structuredContent`.

```json
{}
```

```json
{
  "policy": "open",
  "description": "No transforms, no restrictions. Trusted local experiments only.",
  "loaded_from": "profile:open",
  "extends": [],
  "principal": {
    "id": "local",
    "roles": [
      "default",
      "local"
    ]
  },
  "max_sensitivity": null,
  "denied_capabilities": [],
  "visible_tools": 74,
  "output_pipeline": [],
  "pseudonymisation": {
    "active": false,
    "vault_scope": "global",
    "vault_entries": 0,
    "by_entity": {},
    "key_source": "random"
  },
  "audit_enabled": false,
  "counters": {
    "allowed": 190
  }
}
```

### `preview_transform`

Category `privacy` · sensitivity `internal` · capabilities `read_state` · readOnly true, destructive false, idempotent true, openWorld false · outputSchema no · timeout: layer default (300 s)

Runs the caller's output pipeline (or the pipeline of `tool`, when given) over sample data and returns `policy`, `tool`, `transformed` and `report`. A JSON string is parsed first unless `parse_json` is false. The tool's own result is exempt from transforms, so the preview is shown as produced. Pseudonyms in a preview come from a separate vault with a random key (`Policy.preview_vault()`), so they never match the pseudonyms in real results and a preview cannot be used to confirm which real value is behind one; nothing is stored. `strict` hides the tool.

| Argument | Type | Default | Constraints | Description |
|---|---|---|---|---|
| `data` | any | required |  | JSON value (object / array / string) or text to transform |
| `tool` | string or null | `null` |  | Preview with the pipeline of this tool (default: the policy's generic pipeline) |
| `parse_json` | boolean | `true` |  | Parse `data` as JSON when it is a JSON string |

Under `open` nothing changes:

Called with the arguments below, `preview_transform` returned this `structuredContent`.

```json
{
  "data": {
    "arn": "arn:aws:iam::111111111111:role/app-role",
    "password": "hunter2",
    "AccessKeyId": "AKIAIOSFODNN7EXAMPLE"
  }
}
```

```json
{
  "policy": "open",
  "tool": null,
  "transformed": {
    "arn": "arn:aws:iam::111111111111:role/app-role",
    "password": "hunter2",
    "AccessKeyId": "AKIAIOSFODNN7EXAMPLE"
  },
  "report": {}
}
```

### `list_detectors`

Category `privacy` · sensitivity `public` · capabilities `read_state` · readOnly true, destructive false, idempotent true, openWorld false · outputSchema no · timeout: layer default (300 s)

The sensitive-entity detectors (content patterns) and key rules (field-name patterns), each with the strategy the caller's policy applies (`redact`, `mask`, `hash`, `pseudonymize`, `generalize`, `drop`, `keep`), filtered by `category` when given. Under `open` there is no redaction transform, so no strategy is attached.

| Argument | Type | Default | Constraints | Description |
|---|---|---|---|---|
| `category` | string or null | `null` |  | Only this category: secret, credential, identifier, network, pii, temporal, free_text |

Called with the arguments below, `list_detectors` returned this `structuredContent`.

```json
{"category": "credential"}
```

```json
{
  "policy": "open",
  "detectors": [
    {
      "name": "aws_access_key_id",
      "entity": "aws_access_key_id",
      "category": "credential",
      "confidence": 0.99,
      "description": "AWS access key IDs (long-term AKIA, temporary ASIA)",
      "enabled": true
    }
  ],
  "key_rules": []
}
```

### `privacy_audit_log`

Category `privacy` · sensitivity `restricted` · capabilities `read_state` · readOnly true, destructive false, idempotent true, openWorld false · outputSchema no · timeout: layer default (300 s)

Recent access decisions kept in memory by the policy: denials and rate-limit hits always, every call when the policy enables `audit`. Arguments appear as field names with keyed hashes, never values. Returns `policy`, `audit_enabled`, `scope`, `total` (after the `decision` filter) and the last `limit` `entries`. A caller with the `admin` or `privacy-admin` role sees every principal's entries (`scope: "all"`); anyone else sees only their own (`scope: "own"`). It is `restricted`: `strict` hides it, and `soc-analyst` shows it only to the `lead` role, whose sensitivity ceiling is `restricted`.

| Argument | Type | Default | Constraints | Description |
|---|---|---|---|---|
| `limit` | integer | `50` | 1..1000 | Most recent entries |
| `decision` | string or null | `null` |  | Filter: allowed, denied or rate_limited |

Called with the arguments below, `privacy_audit_log` returned this `structuredContent`.

```json
{"limit": 3}
```

```json
{
  "policy": "open",
  "audit_enabled": false,
  "scope": "own",
  "total": 0,
  "entries": []
}
```

Under the `soc-analyst` profile for a principal with the `lead` role, after one `reveal_token` call. `lead` is neither `admin` nor `privacy-admin`, so it sees its own entries only:

```json
{
  "policy": "soc-analyst",
  "audit_enabled": true,
  "scope": "own",
  "total": 2,
  "entries": [
    {
      "ts": 1791555925.6701138,
      "decision": "allowed",
      "kind": "tool",
      "name": "reveal_token",
      "principal": "lee",
      "roles": [
        "lead"
      ],
      "arguments": {
        "token": "[REDACTED:sensitive_field]"
      },
      "reason": "reveal"
    },
    {
      "ts": 1791555925.674695,
      "decision": "allowed",
      "kind": "tool",
      "name": "privacy_audit_log",
      "principal": "lee",
      "roles": [
        "lead"
      ],
      "arguments": {
        "limit": "c4fdb6b794fd"
      }
    }
  ]
}
```

### `reveal_token`

Category `privacy` · sensitivity `restricted` · capabilities `reveal` · readOnly true, destructive false, idempotent true, openWorld false · outputSchema no · timeout: layer default (300 s)

Reverses pseudonymisation: returns the real value behind a pseudonym, or replaces every pseudonym inside a longer text. It needs the `reveal` capability, which `standard` grants only to the `admin` and `privacy-admin` roles, `soc-analyst` to `lead`, and `strict` to nobody. Every call is logged on the `cloudg.mcp.audit` logger with a hash of the token, never the value. Returns `pseudonym` (the input), `found`, `value`, and `entity_type` for a direct hit or `replaced` (count) for text.

| Argument | Type | Default | Constraints | Description |
|---|---|---|---|---|
| `token` | string | required | min length 1; max length 20000 | A pseudonym (e.g. an account ID, ARN or IP from a result) or text containing pseudonyms |

Under `open` there is no pseudonym to reverse:

Called with the arguments below, `reveal_token` returned this `structuredContent`.

```json
{"token": "arn:aws:iam::1:role/x"}
```

```json
{
  "pseudonym": "arn:aws:iam::1:role/x",
  "found": false,
  "value": null,
  "replaced": 0
}
```

Under `soc-analyst`, an `analyst` called `get_asset(ref="web-1")` and received a pseudonymised name (the `id`, `uri` and edge names in the same result carry the same pseudonym); a `lead` then revealed it:

```json
{
  "args": {
    "token": "res-661a5c1774"
  },
  "structured": {
    "pseudonym": "res-661a5c1774",
    "found": true,
    "value": "web-1",
    "entity_type": "resource_name"
  },
  "is_error": false,
  "text": null
}
```

Revealing the ARN from the same result restores both parts: the instance id, from the vault, and the account. The `soc-analyst` profile replaces account `111111111111` with the alias `prod-payments` before pseudonymising; `reveal_token` maps the aliases of the caller's own output pipelines back as well, so `replaced` counts two substitutions:

```json
{
  "arn": "arn:aws:ec2:us-east-1:prod-payments:instance/res-755b09a5d1",
  "result": {
    "pseudonym": "arn:aws:ec2:us-east-1:prod-payments:instance/res-755b09a5d1",
    "found": true,
    "value": "arn:aws:ec2:us-east-1:111111111111:instance/i-0web1",
    "replaced": 2
  }
}
```

## Resources and resource templates

Resources are addressable, read-only views of the workspace. Tool results link to them instead of inlining large payloads, and clients can subscribe to them (see [Progress and change notifications](#progress-and-change-notifications)). They always read the active dataset. A static URI wins over a template; among templates the longest one that matches wins, so `cloudg://findings/severity/HIGH` is never read as a finding id. `{var}` stops at `/`, `{+ref}` may contain `/`, and values are percent-decoded before use, so `cloudg://assets/arn%3Aaws%3As3%3A%3A%3Aprod-data` and `cloudg://assets/arn:aws:ec2:us-east-1:111111111111:instance/i-0bast` both work.

Unlike tools, a failed read raises a JSON-RPC error (`-32602` for an unknown URI, asset, finding, dataset, format or topic) instead of returning an error result.

| URI | MIME | Sensitivity | Returns | Completions |
|---|---|---|---|---|
| `cloudg://workspace` | `application/json` | internal | `Workspace.status()`, the `workspace_status` result without `next_steps`. | |
| `cloudg://datasets` | `application/json` | internal | `active_dataset` and the `datasets` listing. | |
| `cloudg://datasets/{dataset}/summary` | `application/json` | internal | The `dataset_summary` object of one dataset. | `dataset` |
| `cloudg://assets/{+ref}` | `application/json` | confidential | Asset brief with tags, relation counts by edge type, up to 10 open findings, `metadata_keys`, dependency counts. For a graph placeholder: `id`, `external`, `name`, `degree`. | `ref` |
| `cloudg://assets/{+ref}/neighbors` | `application/json` | confidential | `asset` (id), `edges` (up to 500 edge briefs), `neighbors` (briefs, or `{id, external}`). | `ref` |
| `cloudg://assets/{+ref}/findings` | `application/json` | confidential | `asset` brief and every open finding, highest risk first. | `ref` |
| `cloudg://findings/summary` | `application/json` | internal | Open and suppressed counts, `severity_breakdown`, `by_tool`. | |
| `cloudg://findings/{finding_id}` | `application/json` | confidential | Finding brief plus `description`, `evidence`, `remediation`. | `finding_id` |
| `cloudg://findings/severity/{severity}` | `application/json` | confidential | The first 200 open findings of one severity by risk, with `total` and `truncated`. | `severity` |
| `cloudg://compliance` | `application/json` | internal | `compliance_summary` for every framework. | |
| `cloudg://compliance/{framework}` | `application/json` | internal | `posture` rows (exact name match preferred, else substring) and up to 300 `failing_controls`. | `framework` |
| `cloudg://graph/d3` | `application/json` | confidential | The whole relationship graph as D3 `{nodes, links}`. | |
| `cloudg://graph/{format}` | `application/json` for `d3` and `cytoscape`, `application/graphml+xml` for `graphml` (the template lists `application/json`) | restricted | `d3`, `cytoscape` or `graphml`. Restricted because the GraphML form is one opaque string; use `cloudg://graph/d3` under a confidential ceiling. | `format` |
| `cloudg://ontology/turtle` | `text/turtle` | restricted | The ontology in Turtle. | |
| `cloudg://ontology/{format}` | the format's own type (the template lists `text/turtle`) | restricted | `turtle`, `json-ld` (`application/ld+json`), `xml` (`application/rdf+xml`), `nt` (`application/n-triples`). | `format` |
| `cloudg://schema/asset-types` | `application/json` | public | Asset types by family. | |
| `cloudg://schema/asset-types/{asset_type}` | `application/json` | public | `asset_type`, `family`, `note`, `ontology_class`, `terraform_type`. | `asset_type` |
| `cloudg://schema/edge-types` | `application/json` | public | Each edge type with `reads_as`, `typical` and `dependency_direction`. | |
| `cloudg://schema/relation-types` | `application/json` | public | Relation types by relation group. | |
| `cloudg://docs` | `application/json` | public | `available` (whether the docs directory was found) and the topic list. | |
| `cloudg://docs/{topic}` | `text/markdown` | public | One documentation section (up to 40,000 characters). | `topic` |
| `cloudg://policy` | `application/json` | internal | `Policy.describe()`: profiles, rules, transforms, rate limits, vault statistics, never the vault key. | |
| `cloudg://privacy/detectors` | `application/json` | public | The `list_detectors` table for the caller. | |
| `cloudg://ratelimit` | `application/json` | internal | The `rate_limit_status` object. | |

A resource template can list only one MIME type, so for the two `{format}` templates the `mimeType` on the read result is the one to trust. Reading an ontology resource builds the ontology if needed but sends no progress notification.

`cloudg://docs/{topic}` cuts sections out of `docs/DOCUMENTATION.md` and `docs/INVENTORY_REFERENCE.md` by heading. Topics: `mcp` (a built-in usage guide), `pipeline`, `cli`, `inputs`, `outputs`, `data-models`, `configuration`, `python-api`, `recipes`, `authentication`, `identifiers`, `edges`, `edge-types`, `relations`, `inventory-summary`, `dependencies`, `inventory-map`, `organization`. The docs directory is `$CLOUDG_DOCS_DIR` or the `docs/` folder next to the installed package; when neither exists, every topic except `mcp` returns a short note pointing at the online documentation.

The examples below were read from a fresh workspace holding `sample`, its snapshot `baseline` and `after`, with `sample` active.

`cloudg://datasets/sample/summary` returns the `dataset_summary` object shown earlier. One asset, addressed by its ARN:

`cloudg://assets/arn:aws:ec2:us-east-1:111111111111:instance/i-0bast` returned one `application/json` content item (1159 characters).

```json
{
  "id": "bastion",
  "name": "bastion",
  "type": "EC2",
  "provider": "AWS",
  "region": "us-east-1",
  "account_id": "111111111111",
  "arn": "arn:aws:ec2:us-east-1:111111111111:instance/i-0bast",
  "internet_exposed": true,
  "open_findings": 1,
  "max_severity": "HIGH",
  "uri": "cloudg://assets/bastion",
  "tags": {
    "env": "prod",
    "owner": "platform"
  },
  "relations": {
    "outgoing": {
      "ATTACHED_TO": 1,
      "ASSUMES_ROLE": 1
    },
    "incoming": {
      "CONTAINS": 1
    }
  },
  "findings": [
    {
      "id": "f-bastion-imds",
      "title": "EC2 instance allows IMDSv1",
      "severity": "HIGH",
      "risk_score": 7.5,
      "source_tool": "prowler",
      "resource_id": "bastion",
      "resource_arn": null,
      "asset_id": "bastion",
      "asset_name": "bastion",
      "compliance_frameworks": [
        "CIS-AWS"
      ],
      "is_suppressed": false,
      "cvss_score": null,
      "detected_at": "2026-01-15T12:00:00+00:00",
      "uri": "cloudg://findings/f-bastion-imds"
    }
  ],
  "metadata_keys": [
    "public_ip"
  ],
  "dependencies": {
    "direct_depends_on": 3,
    "direct_dependents": 0
  }
}
```

Its neighbours, for the internet placeholder node:

`cloudg://assets/0.0.0.0%2F0/neighbors` returned one `application/json` content item (5180 characters).

```json
{
  "asset": "0.0.0.0/0",
  "edges": [
    {
      "id": "e-inet-sgweb",
      "source": "0.0.0.0/0",
      "source_name": "0.0.0.0/0",
      "target": "sg-web",
      "target_name": "sg-web",
      "edge_type": "SECURITY_GROUP_RULE",
      "relationship": null,
      "port_range": "80,443",
      "protocol": "TCP",
      "cidr": "0.0.0.0/0",
      "ports": [
        443,
        80
      ],
      "direction": "ingress"
    },
    {
      "id": "e-inet-sgadmin",
      "source": "0.0.0.0/0",
      "source_name": "0.0.0.0/0",
      "target": "sg-admin",
      "target_name": "sg-admin",
      "edge_type": "SECURITY_GROUP_RULE",
      "relationship": null,
      "port_range": "22",
      "protocol": "TCP",
      "cidr": "0.0.0.0/0",
      "ports": [
        22
      ],
      "direction": "ingress"
    },
    "... 4 more"
  ],
  "neighbors": [
    {
      "id": "sg-web",
      "name": "sg-web",
      "type": "SECURITY_GROUP",
      "provider": "AWS",
      "region": "us-east-1",
      "account_id": "111111111111",
      "arn": "arn:aws:ec2:us-east-1:111111111111:security-group/sg-0web",
      "internet_exposed": false,
      "open_findings": 0,
      "max_severity": null,
      "uri": "cloudg://assets/sg-web"
    },
    {
      "id": "sg-admin",
      "name": "sg-admin",
      "type": "SECURITY_GROUP",
      "provider": "AWS",
      "region": "us-east-1",
      "account_id": "111111111111",
      "arn": "arn:aws:ec2:us-east-1:111111111111:security-group/sg-0admin",
      "internet_exposed": false,
      "open_findings": 1,
      "max_severity": "CRITICAL",
      "uri": "cloudg://assets/sg-admin"
    },
    "... 4 more"
  ]
}
```

`cloudg://assets/sg-admin/findings` returned one `application/json` content item (998 characters).

```json
{
  "asset": {
    "id": "sg-admin",
    "name": "sg-admin",
    "type": "SECURITY_GROUP",
    "provider": "AWS",
    "region": "us-east-1",
    "account_id": "111111111111",
    "arn": "arn:aws:ec2:us-east-1:111111111111:security-group/sg-0admin",
    "internet_exposed": false,
    "open_findings": 1,
    "max_severity": "CRITICAL",
    "uri": "cloudg://assets/sg-admin"
  },
  "findings": [
    {
      "id": "f-ssh-open",
      "title": "Security group allows SSH (22) from 0.0.0.0/0",
      "severity": "CRITICAL",
      "risk_score": 9.5,
      "source_tool": "prowler",
      "resource_id": "sg-admin",
      "resource_arn": "arn:aws:ec2:us-east-1:111111111111:security-group/sg-0admin",
      "asset_id": "sg-admin",
      "asset_name": "sg-admin",
      "compliance_frameworks": [
        "CIS-AWS",
        "PCI-DSS"
      ],
      "is_suppressed": false,
      "cvss_score": null,
      "detected_at": "2026-01-15T12:00:00+00:00",
      "uri": "cloudg://findings/f-ssh-open"
    }
  ]
}
```

`cloudg://findings/summary` returned one `application/json` content item (283 characters).

```json
{
  "dataset": "sample",
  "open_findings": 11,
  "suppressed": 1,
  "severity_breakdown": {
    "CRITICAL": 2,
    "HIGH": 5,
    "MEDIUM": 2,
    "LOW": 1,
    "INFO": 1
  },
  "by_tool": {
    "prowler": 5,
    "scoutsuite": 3,
    "trivy": 1,
    "checkov": 1,
    "iam": 1
  }
}
```

`cloudg://findings/f-ssh-open` returned one `application/json` content item (680 characters).

```json
{
  "id": "f-ssh-open",
  "title": "Security group allows SSH (22) from 0.0.0.0/0",
  "severity": "CRITICAL",
  "risk_score": 9.5,
  "source_tool": "prowler",
  "resource_id": "sg-admin",
  "resource_arn": "arn:aws:ec2:us-east-1:111111111111:security-group/sg-0admin",
  "asset_id": "sg-admin",
  "asset_name": "sg-admin",
  "compliance_frameworks": [
    "CIS-AWS",
    "PCI-DSS"
  ],
  "is_suppressed": false,
  "cvss_score": null,
  "detected_at": "2026-01-15T12:00:00+00:00",
  "uri": "cloudg://findings/f-ssh-open",
  "description": "Security group allows SSH (22) from 0.0.0.0/0.",
  "evidence": "IpPermissions 0.0.0.0/0 tcp 22",
  "remediation": "Restrict 22 to the VPN."
}
```

`cloudg://findings/severity/CRITICAL` returned one `application/json` content item (1220 characters).

```json
{
  "dataset": "sample",
  "severity": "CRITICAL",
  "total": 2,
  "truncated": false,
  "findings": [
    {
      "id": "f-ssh-open",
      "title": "Security group allows SSH (22) from 0.0.0.0/0",
      "severity": "CRITICAL",
      "risk_score": 9.5,
      "source_tool": "prowler",
      "resource_id": "sg-admin",
      "resource_arn": "arn:aws:ec2:us-east-1:111111111111:security-group/sg-0admin",
      "asset_id": "sg-admin",
      "asset_name": "sg-admin",
      "compliance_frameworks": [
        "CIS-AWS",
        "... 1 more"
      ],
      "is_suppressed": false,
      "cvss_score": null,
      "detected_at": "2026-01-15T12:00:00+00:00",
      "uri": "cloudg://findings/f-ssh-open"
    },
    "... 1 more"
  ]
}
```

`cloudg://compliance/CIS-AWS` returned one `application/json` content item (1001 characters).

```json
{
  "dataset": "sample",
  "posture": [
    {
      "framework": "CIS-AWS",
      "controls_evaluated": 4,
      "controls_failing": 3,
      "controls_passing": 1,
      "controls_other": 0,
      "pass_rate": 25.0,
      "open_findings": 6,
      "severity_breakdown": {
        "CRITICAL": 1,
        "HIGH": 3,
        "MEDIUM": 2
      },
      "affected_assets": 5,
      "uri": "cloudg://compliance/CIS-AWS"
    }
  ],
  "failing_controls": [
    {
      "framework": "CIS-AWS",
      "control_id": "5.2",
      "control_title": "No SG allows 0.0.0.0/0 to admin ports",
      "open_findings": 1,
      "max_severity": "CRITICAL"
    },
    {
      "framework": "CIS-AWS",
      "control_id": "1.16",
      "control_title": "IAM trust least privilege",
      "open_findings": 1,
      "max_severity": "HIGH"
    },
    "... 1 more"
  ]
}
```

`cloudg://graph/d3` returned one `application/json` content item (28639 characters).

```json
{
  "nodes": [
    {
      "id": "org",
      "name": "sample-org",
      "type": "ORGANIZATION",
      "provider": "AWS",
      "region": "global",
      "arn": "arn:aws:organizations::111111111111:organization/o-sample",
      "account_id": "111111111111",
      "is_internet_exposed": false,
      "is_external": false
    },
    {
      "id": "ou-workloads",
      "name": "Workloads",
      "type": "ORG_UNIT",
      "provider": "AWS",
      "region": "global",
      "arn": "arn:aws:organizations::111111111111:ou/o-sample/ou-work",
      "account_id": "111111111111",
      "is_internet_exposed": false,
      "is_external": false
    },
    "... 42 more"
  ],
  "links": [
    {
      "source": "org",
      "target": "ou-workloads",
      "type": "CONTAINS",
      "port_range": "",
      "protocol": "",
      "cidr": "",
      "direction": "ingress",
      "relationship": "",
      "description": ""
    },
    {
      "source": "ou-workloads",
      "target": "acct-prod",
      "type": "CONTAINS",
      "port_range": "",
      "protocol": "",
      "cidr": "",
      "direction": "ingress",
      "relationship": "",
      "description": ""
    },
    "... 53 more"
  ]
}
```

`cloudg://graph/graphml` returned one `application/graphml+xml` content item (33946 characters).

```xml
<graphml xmlns="http://graphml.graphdrawing.org/xmlns" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:schemaLocation="http://graphml.graphdrawing.org/xmlns http://graphml.graphdrawing.org/xmlns/1.0/graphml.xsd">
  <key id="d15" for="edge" attr.name="relationship" attr.type="string" />
  <key id="d14" for="edge" attr.name="description" attr.type="string" />
  <key id="d13" for="edge" attr.name="direction" attr.type="string" />
...
```

`cloudg://ontology/turtle` returned one `text/turtle` content item (43748 characters).

```turtle
@prefix cm: <https://cloudg.io/ontology#> .
@prefix cmp: <https://cloudg.io/property/> .
@prefix cmr: <https://cloudg.io/resource/> .
@prefix owl: <http://www.w3.org/2002/07/owl#> .
@prefix rdfs: <http://www.w3.org/2000/01/rdf-schema#> .
@prefix xsd: <http://www.w3.org/2001/XMLSchema#> .

cm:AccessAnalyzer a owl:Class ;
    rdfs:label "AccessAnalyzer" ;
    rdfs:subClassOf cm:CloudResource .

cm:AccessKey a owl:Class ;
    rdfs:label "AccessKey" ;
    rdfs:subClassOf cm:CloudResource .

cm:AccessPoint a owl:Class ;
...
```

`cloudg://schema/asset-types/KMS_KEY` returned one `application/json` content item (150 characters).

```json
{
  "asset_type": "KMS_KEY",
  "family": "Secrets / Keys",
  "note": null,
  "ontology_class": "cm:EncryptionKey",
  "terraform_type": "aws_kms_key"
}
```

`cloudg://schema/edge-types` returned one `application/json` content item (3212 characters).

```json
{
  "SECURITY_GROUP_RULE": {
    "reads_as": "allows traffic",
    "typical": "CIDR -> SG (ingress), SG -> CIDR (egress)",
    "dependency_direction": "none"
  },
  "NACL_RULE": {
    "reads_as": "allows traffic",
    "typical": "network ACL rules",
    "dependency_direction": "none"
  },
  "ROUTE": {
    "reads_as": "routes through / forwards to",
    "typical": "route table -> gateway, DNS record -> load balancer, ingress -> service",
    "dependency_direction": "forward"
  },
  "IAM_TRUST": {
    "reads_as": "may assume",
    "typical": "principal / account / provider -> role",
    "dependency_direction": "forward"
  },
  "IAM_POLICY_ATTACHMENT": {
    "reads_as": "has policy",
    "typical": "user / group / role -> managed policy",
    "dependency_direction": "forward"
  },
  "CONTAINS": {
    "reads_as": "contains",
    "typical": "VPC -> subnet, subnet -> instance, account -> resource",
    "dependency_direction": "reverse"
  },
  "PEERING": {
    "reads_as": "peers with",
    "typical": "VPC -> peering connection -> VPC",
    "dependency_direction": "forward"
  },
  "LOAD_BALANCER_TARGET": {
    "reads_as": "sends traffic to",
    "typical": "load balancer -> target group -> instance",
    "dependency_direction": "forward"
  },
  "INTERNET_EXPOSED": {
    "reads_as": "exposes",
    "typical": "0.0.0.0/0 -> exposed asset",
    "dependency_direction": "none"
  },
  "ATTACHED_TO": {
    "reads_as": "is attached to",
    "typical": "instance -> security group, volume -> instance, ENI -> instance",
    "dependency_direction": "forward"
  },
  "REFERENCES": {
    "reads_as": "uses / points at",
    "typical": "function -> secret, table -> KMS key, queue -> DLQ",
    "dependency_direction": "forward"
  },
  "INVOKES": {
    "reads_as": "triggers / calls",
    "typical": "bucket -> function, queue -> function, rule -> target",
    "dependency_direction": "reverse"
  },
  "USES_IMAGE": {
    "reads_as": "runs the image of",
    "typical": "task definition / workload / function -> registry",
    "dependency_direction": "forward"
  },
  "ASSUMES_ROLE": {
    "reads_as": "runs as",
    "typical": "function, task, node group, instance profile -> role / service account",
    "dependency_direction": "forward"
  },
  "GRANTS_ACCESS": {
    "reads_as": "is granted access to",
    "typical": "principal -> resource its policy names",
    "dependency_direction": "forward"
  },
  "LOGS_TO": {
    "reads_as": "sends logs to",
    "typical": "trail, flow log, LB, function -> log destination",
    "dependency_direction": "forward"
  },
  "PROTECTS": {
    "reads_as": "protects",
    "typical": "WAF -> ALB / API / distribution, firewall -> VPC",
    "dependency_direction": "reverse"
  },
  "MONITORS": {
    "reads_as": "monitors",
    "typical": "Inspector -> instance, GuardDuty -> account, alarm -> resource",
    "dependency_direction": "reverse"
  },
  "MANAGES": {
    "reads_as": "manages",
    "typical": "stack -> resource, ASG -> instance, landing zone -> account",
    "dependency_direction": "reverse"
  },
  "GOVERNS": {
    "reads_as": "governs",
    "typical": "SCP / control / org policy -> OU, account, folder, project",
    "dependency_direction": "reverse"
  }
}
```

`cloudg://docs` returned one `application/json` content item (942 characters).

```json
{
  "available": true,
  "topics": {
    "mcp": "How to use cloudg through MCP",
    "pipeline": "Phases of a cloudg run",
    "cli": "cloudg command-line reference",
    "inputs": "Scanner report formats",
    "outputs": "Files cloudg writes",
    "data-models": "Finding / CloudAsset / NetworkEdge",
    "configuration": "config.yaml reference",
    "python-api": "CloudGEngine and inventory API",
    "recipes": "Integration recipes",
    "authentication": "Cloud credentials",
    "identifiers": "ARN / Azure / GCP / placeholder identifier formats",
    "edges": "NetworkEdge fields",
    "edge-types": "Edge types, direction and dependency semantics",
    "relations": "Declared relations on assets",
    "inventory-summary": "InventoryResult.summary",
    "dependencies": "depends_on / dependents / tree / blast radius",
    "inventory-map": "inventory-map.json format",
    "organization": "Organization / Control Tower topology"
  }
}
```

`cloudg://docs/mcp` returned one `text/markdown` content item (1097 characters).

```markdown
# Using cloudg through MCP

1. `workspace_status` shows what is loaded. Load data with `load_dataset(path=...)`
   (inventory-map.json, findings.json, scanner output) or collect live with
   `map_inventory` (needs cloud credentials on the server).
2. Orient: `dataset_summary`, `count_assets(group_by=...)`, `findings_summary`.
3. Prioritise: `top_risks`, `internet_exposure`, `attack_paths`.
4. Drill down: `get_asset(ref)`, `findings_for_asset`, `neighbors`, `blast_radius`,
   `dependency_tree`, `find_paths`.
5. Compliance: `compliance_summary`, `list_controls`, `control_status`, `compliance_gaps`.
...
```

`cloudg://policy` returned one `application/json` content item (1138 characters).

```json
{
  "deny_tools": [],
  "deny_resources": [],
  "deny_prompts": [],
  "deny_categories": [],
  "allow_capabilities": [],
  "deny_capabilities": [],
  "name": "open",
  "description": "No transforms, no restrictions. Trusted local experiments only.",
  "hide_denied": true,
  "honor_hints": true,
  "audit": false,
  "audit_size": 1000,
  "transforms": [],
  "input_transforms": [],
  "transform_options": {},
  "detectors": [],
  "disabled_detectors": [],
  "roles": {},
  "rules": [],
  "rate_limits": [],
  "vault": {
    "key_env": "CLOUDG_MCP_VAULT_KEY",
    "scope": "global",
    "ttl_seconds": null,
    "path": null,
    "autosave": false,
    "encrypt": true,
    "entries": 0,
    "namespaces": 0,
    "by_entity": {},
    "key_source": "random",
    "key_id": "d03a61100e65",
    "persist_path": null,
    "counters": {},
    "key_configured": false
  },
  "loaded_from": "profile:open",
  "extends_chain": [],
  "effective_denied_capabilities": [],
  "counters": {
    "allowed": 18
  },
  "available_profiles": [
    "airgapped",
    "audit",
    "... 3 more"
  ]
}
```

Read errors:

```json
{
  "uri": "cloudg://assets/web-9",
  "error": "ReferenceNotFoundError",
  "code": -32602,
  "message": "No asset matches the reference in this dataset. 5 close matches, see suggestions in the error data. Use find_assets(query=...) to search by name, ARN or tag."
}
```

```json
{
  "uri": "cloudg://findings/severity/URGENT",
  "error": "ReferenceNotFoundError",
  "code": -32602,
  "message": "Unknown severity; use one of CRITICAL, HIGH, MEDIUM, LOW, INFO"
}
```

```json
{
  "uri": "cloudg://graph/png",
  "error": "ReferenceNotFoundError",
  "code": -32602,
  "message": "Unknown graph format; use d3, cytoscape, graphml"
}
```

```json
{
  "uri": "cloudg://docs/nope",
  "error": "ReferenceNotFoundError",
  "code": -32602,
  "message": "Unknown docs topic. Topics: mcp, pipeline, cli, inputs, outputs, data-models, configuration, python-api, recipes, authentication, identifiers, edges, edge-types, relations, inventory-summary, dependencies, inventory-map, organization"
}
```

```json
{
  "uri": "cloudg://nothing",
  "error": "NotFoundError",
  "code": -32602,
  "message": "Unknown resource: cloudg://nothing"
}
```

From the command line, `cloudg mcp read <uri>` prints the text of each content item:

```bash
cloudg mcp read 'cloudg://compliance/CIS-AWS' --policy open --dataset sample=./inventory
cloudg mcp read 'cloudg://assets/i-0bast' --dataset sample=./inventory
```

## Completions

`completion/complete` is served for every template variable in the table above and for prompt arguments (`dataset`, `ref`, `finding_id`, `framework`, `severity`, `base`, `target`). The layer returns at most 100 values; `total` counts every match and `hasMore` is true when more than 100 matched. Completions pass through the policy like any read: they are rate limited and their values transformed, so a pseudonymising policy completes to pseudonyms.

| Completer | Matching |
|---|---|
| `dataset`, `base`, `target` | Loaded dataset names starting with the input (case-insensitive). |
| `ref` | Assets of the dataset named in the request's context arguments, else the active one. Unique names complete to the name, shared names to the ARN or id. Prefix matches on name, ARN or id come first (sorted), then substring matches. |
| `finding_id` | Finding ids starting with the input, highest risk first. |
| `severity` | Severity names starting with the input (upper-cased). |
| `framework` | Frameworks in the dataset (compliance results and finding tags) containing the input; the ruleset frameworks when the dataset has none. |
| `format` | `d3`, `cytoscape`, `graphml`, or `turtle`, `json-ld`, `xml`, `nt`. |
| `asset_type` | AssetType values starting with the input (upper-cased). |
| `topic` | Documentation topics starting with the input. |

Arguments without a completer (the prompt argument `change`, for example) return an empty list.

```json
{
  "request": {
    "ref": {
      "type": "ref/resource",
      "uri": "cloudg://assets/{+ref}"
    },
    "argument": {
      "name": "ref",
      "value": "web"
    }
  },
  "completion": {
    "values": [
      "web-1",
      "web-2",
      "web-acl",
      "... 3 more"
    ],
    "total": 6,
    "hasMore": false
  }
}
```

```json
{
  "request": {
    "ref": {
      "type": "ref/resource",
      "uri": "cloudg://assets/{+ref}/neighbors"
    },
    "argument": {
      "name": "ref",
      "value": "arn:aws:iam"
    }
  },
  "completion": {
    "values": [
      "api-lambda-role",
      "app-role",
      "bastion-admin",
      "... 4 more"
    ],
    "total": 7,
    "hasMore": false
  }
}
```

```json
{
  "request": {
    "ref": {
      "type": "ref/resource",
      "uri": "cloudg://compliance/{framework}"
    },
    "argument": {
      "name": "framework",
      "value": "cis"
    }
  },
  "completion": {
    "values": [
      "CIS-AWS",
      "CIS-Azure",
      "CIS-GCP"
    ],
    "total": 3,
    "hasMore": false
  }
}
```

```json
{
  "request": {
    "ref": {
      "type": "ref/prompt",
      "name": "investigate_asset"
    },
    "argument": {
      "name": "ref",
      "value": "orders"
    }
  },
  "completion": {
    "values": [
      "orders-db",
      "orders-db-credentials"
    ],
    "total": 2,
    "hasMore": false
  }
}
```

With `dataset` in the context arguments, `ref` completes against that dataset. In `after` the WAF `web-acl` no longer exists, so it is missing here:

```json
{
  "request": {
    "ref": {
      "type": "ref/prompt",
      "name": "investigate_asset"
    },
    "argument": {
      "name": "ref",
      "value": "web"
    },
    "context": {
      "arguments": {
        "dataset": "after"
      }
    }
  },
  "completion": {
    "values": [
      "web-1",
      "web-2",
      "web-alb",
      "... 2 more"
    ],
    "total": 5,
    "hasMore": false
  }
}
```

```json
{
  "request": {
    "ref": {
      "type": "ref/prompt",
      "name": "incident_triage"
    },
    "argument": {
      "name": "finding_id",
      "value": "f-r"
    }
  },
  "completion": {
    "values": [
      "f-rdp-open"
    ],
    "total": 1,
    "hasMore": false
  }
}
```

```json
{
  "request": {
    "ref": {
      "type": "ref/resource",
      "uri": "cloudg://docs/{topic}"
    },
    "argument": {
      "name": "topic",
      "value": "d"
    }
  },
  "completion": {
    "values": [
      "data-models",
      "dependencies"
    ],
    "total": 2,
    "hasMore": false
  }
}
```

## Prompts

Each prompt returns user messages only. The first holds the task and the exact tool calls to make. The task text never contains values from the workspace (dataset, asset, finding or framework names, account ids, the caller's own arguments): it points at the context instead, as in "the asset in the context (`asset.id`)". When data is loaded, the context follows so the model starts informed, in two forms: a text message `Context for this task (JSON):` with a fenced JSON block, and embedded resources whose URI serves exactly the embedded content (the dataset summary, an asset, a finding, a framework). Every context message also carries its data in `_meta["cloudg/data"]` with the rendering rule in `_meta["cloudg/render"]`, so the privacy transforms work on the data with its keys and the text is rendered again from the transformed data. With no dataset loaded and no `dataset` argument, a prompt returns a single message explaining how to load data instead of failing (`drift_review` is the exception: it needs two datasets and raises):

`description`: "Security posture review"

Message 1 (`user`, text):

```text
No cloudg dataset is loaded yet. First call `workspace_status`, then load data with `load_dataset(path=...)` (an inventory-map.json, findings.json or scanner report inside an allowed directory) or collect it with `map_inventory`. Then run this prompt again.
```

A `dataset` argument naming a dataset that is not loaded, a missing required argument, or an unknown asset or finding raises an error:

```json
{
  "arguments": {},
  "error": "InvalidArgumentsError",
  "code": -32602,
  "message": "Missing required prompt arguments: ref"
}
```

```json
{
  "arguments": {
    "ref": "web-9"
  },
  "error": "ReferenceNotFoundError",
  "code": -32602,
  "message": "No asset matches the reference in this dataset. 5 close matches, see suggestions in the error data. Use find_assets(query=...) to search by name, ARN or tag."
}
```

```json
{
  "arguments": {
    "dataset": "nope"
  },
  "error": "NoDatasetError",
  "code": -32602,
  "message": "No such dataset. 3 dataset(s) are loaded: see datasets in the error data, or call list_datasets."
}
```

Asset, finding and framework resources always read the active dataset, so a prompt embeds them only when it targets the active dataset; for another dataset the same data goes into the JSON context message instead. `drift_review` embeds no resource, because no resource serves a diff.

| Prompt | Arguments | Required | Sensitivity | JSON context | Embedded resource | Steers to |
|---|---|---|---|---|---|---|
| `security_posture_review` | `dataset` | none | confidential | The five riskiest assets, posture of the first five frameworks | Dataset summary | `top_risks`, `internet_exposure`, `attack_paths`, `lateral_movement_paths`, `cross_account_edges`, `security_coverage`, `compliance_summary` |
| `executive_summary` | `dataset` | none | internal | Overview figures | Dataset summary | `findings_summary`, `compliance_summary`, `top_risks` |
| `attack_surface_report` | `dataset` | none | confidential | Exposed count, exposed by type, first 15 exposed briefs | Dataset summary | `internet_exposure`, `get_edges`, `attack_paths`, `find_paths`, `findings_for_asset` |
| `investigate_asset` | `ref`, `dataset` | `ref` | confidential | `dataset` (plus the asset detail, when not the active dataset) | `cloudg://assets/{id}` | `get_asset`, `get_asset_metadata`, `neighbors`, `depends_on`, `dependents`, `findings_for_asset`, `get_finding`, `blast_radius`, `find_paths`, `ontology_neighbourhood` |
| `blast_radius_assessment` | `ref`, `dataset` | `ref` | confidential | Asset brief, transitive dependents (depth 10), accounts affected, first 20 direct dependents | `cloudg://assets/{id}` | `blast_radius`, `dependency_tree`, `lateral_movement_paths`, `findings_for_asset` |
| `change_impact_analysis` | `ref`, `change`, `dataset` | `ref` | confidential | Asset brief, up to 20 direct dependencies each way | `cloudg://assets/{id}` | `dependents`, `dependency_tree`, `shared_dependencies`, `cross_account_edges`, `get_asset_metadata`, `snapshot_dataset`, `diff_datasets` |
| `cross_account_trust_review` | `dataset` | none | confidential | Cross-account edge count, external count, counts per account pair and edge type | Dataset summary | `cross_account_edges`, `get_edges`, `lateral_movement_paths`, `organization_topology` |
| `compliance_gap_analysis` | `framework`, `dataset` | `framework` | confidential | `dataset` and `framework` (plus the framework detail, when not the active dataset; the posture alone when the framework does not resolve) | `cloudg://compliance/{framework}` | `compliance_summary`, `list_controls`, `control_status`, `compliance_gaps` |
| `remediation_plan` | `severity` (default `HIGH`), `dataset` | none | confidential | The ten riskiest assets at or above the severity | Dataset summary | `list_findings`, `top_risks`, `get_finding`, `blast_radius`, `suppress_findings` |
| `incident_triage` | `finding_id`, `dataset` | `finding_id` | confidential | `dataset` and `target_ref`, the affected asset (plus the finding detail, when not the active dataset) | `cloudg://findings/{id}` | `get_finding`, `get_asset`, `internet_exposure`, `find_paths`, `blast_radius`, `lateral_movement_paths` |
| `drift_review` | `base`, `target` | `base` | confidential | `diff_datasets(base, target, limit=25)` | none | `diff_datasets`, `get_asset`, `findings_for_asset` |

Every JSON context also names the dataset (`dataset`), and `change_impact_analysis` adds the planned change as `planned_change`. All prompts carry the tag `workflow` in `_meta`. The messages below are real; the embedded JSON is trimmed like the other examples.

### `security_posture_review`

`description`: "Security posture review"

Message 1 (`user`, text):

```text
Review the security posture of the cloud estate in the dataset named in the
context. The embedded JSON has the overview, the five riskiest assets and compliance posture.

Work through, calling cloudg tools as needed:
1. `top_risks(top=10)`: the assets to fix first and why (score components).
2. `internet_exposure()` and `attack_paths()` for what an outside attacker can reach.
3. `lateral_movement_paths()` and `cross_account_edges(external_only=true)` (identity pivots).
4. `security_coverage()`: missing GuardDuty / Inspector / WAF etc.
5. `compliance_summary()` to find the weakest frameworks.

Deliver: an overall rating (critical / poor / fair / good) with justification, the top 5
risks with evidence (asset, finding, exposure, blast radius), quick wins, and structural
improvements. Cite asset names / ids exactly as tools return them.
```

Message 2 (`user`, text): `Context for this task (JSON):` followed by a fenced JSON block:

```json
{
  "dataset": "sample",
  "top_risks": [
    {
      "asset": "jump-nsg",
      "id": "az-nsg",
      "type": "NSG",
      "score": 16.39,
      "internet_exposed": false,
      "top_finding": "NSG allows RDP (3389) from Internet"
    },
    {
      "asset": "sg-admin",
      "id": "sg-admin",
      "type": "SECURITY_GROUP",
      "score": 16.39,
      "internet_exposed": false,
      "top_finding": "Security group allows SSH (22) from 0.0.0.0/0"
    },
    "... 3 more"
  ],
  "compliance": [
    {
      "framework": "CIS-AWS",
      "controls_evaluated": 4,
      "controls_failing": 3,
      "controls_passing": 1,
      "controls_other": 0,
      "pass_rate": 25.0,
      "open_findings": 6,
      "severity_breakdown": {
        "CRITICAL": 1,
        "HIGH": 3,
        "MEDIUM": 2
      },
      "affected_assets": 5,
      "uri": "cloudg://compliance/CIS-AWS"
    },
    {
      "framework": "PCI-DSS",
      "controls_evaluated": 1,
      "controls_failing": 1,
      "controls_passing": 0,
      "controls_other": 0,
      "pass_rate": 0.0,
      "open_findings": 3,
      "severity_breakdown": {
        "CRITICAL": 1,
        "HIGH": 2
      },
      "affected_assets": 3,
      "uri": "cloudg://compliance/PCI-DSS"
    },
    "... 3 more"
  ]
}
```

Message 3 (`user`, embedded resource `cloudg://datasets/sample/summary`, `application/json`): the [`dataset_summary`](#dataset_summary) object of `sample`.

### `executive_summary`

`description`: "Executive summary"

Message 1 (`user`, text):

```text
Write a one-page executive summary of the cloud security state of the dataset
in the context for non-technical leadership, from the embedded figures (call
`findings_summary`, `compliance_summary` and `top_risks(top=3)` for anything missing).

Structure: headline (one sentence), scale of the estate, risk level with the 3 issues that
matter most in business terms, compliance standing, and 3 recommended decisions with rough
effort. No identifiers or jargon; numbers rounded.
```

Message 2 (`user`, text): `Context for this task (JSON):` followed by a fenced JSON block:

```json
{
  "dataset": "sample",
  "providers": [
    "aws",
    "azure",
    "gcp"
  ],
  "total_assets": 44,
  "total_edges": 56,
  "open_findings": 11,
  "severity_breakdown": {
    "CRITICAL": 2,
    "HIGH": 5,
    "MEDIUM": 2,
    "LOW": 1,
    "INFO": 1
  },
  "accounts": 5,
  "regions": 5,
  "internet_exposed": 6,
  "cross_account_edges": 3,
  "compliance_frameworks": [
    "CIS-AWS",
    "CIS-Azure",
    "CIS-GCP",
    "... 2 more"
  ],
  "assets_by_type": {
    "SECURITY_GROUP": 4,
    "IAM_ROLE": 4,
    "CLOUD_ACCOUNT": 3,
    "EC2": 3,
    "S3_BUCKET": 3,
    "...": "10 more"
  }
}
```

Message 3 (`user`, embedded resource `cloudg://datasets/sample/summary`, `application/json`): the [`dataset_summary`](#dataset_summary) object of `sample`.

### `attack_surface_report`

`description`: "Attack surface report"

Message 1 (`user`, text):

```text
Map the external attack surface of the dataset named in the context.

1. `internet_exposure(limit=100)`: every exposed asset with the rules exposing it, sensitive
   ports and WAF protection.
2. `get_edges(internet_only=true, port=22)` and `port=3389` for admin ports open to the world.
3. `attack_paths(max_paths=20)`: routes from the internet to data stores, secrets, keys, roles.
4. For the worst 3 paths, `find_paths(source='internet', target=<asset>)` and
   `findings_for_asset` on each hop.

Report: entry points ranked by risk, exposed sensitive services, the critical paths with
every hop explained, and concrete fixes (close rule X, add WAF to Y, move Z private).
```

Message 2 (`user`, text): `Context for this task (JSON):` followed by a fenced JSON block:

```json
{
  "dataset": "sample",
  "internet_exposed_total": 6,
  "exposed_by_type": {
    "LOAD_BALANCER": 1,
    "EC2": 1,
    "S3_BUCKET": 1,
    "API_GATEWAY": 1,
    "VIRTUAL_MACHINE": 1,
    "GCS_BUCKET": 1
  },
  "exposed_sample": [
    {
      "id": "alb-web",
      "name": "web-alb",
      "type": "LOAD_BALANCER",
      "provider": "AWS",
      "region": "us-east-1",
      "account_id": "111111111111",
      "arn": "arn:aws:elasticloadbalancing:us-east-1:111111111111:loadbalancer/app/web-alb/abc",
      "internet_exposed": true,
      "open_findings": 0,
      "max_severity": null,
      "uri": "cloudg://assets/alb-web"
    },
    {
      "id": "bastion",
      "name": "bastion",
      "type": "EC2",
      "provider": "AWS",
      "region": "us-east-1",
      "account_id": "111111111111",
      "arn": "arn:aws:ec2:us-east-1:111111111111:instance/i-0bast",
      "internet_exposed": true,
      "open_findings": 1,
      "max_severity": "HIGH",
      "uri": "cloudg://assets/bastion"
    },
    "... 4 more"
  ]
}
```

Message 3 (`user`, embedded resource `cloudg://datasets/sample/summary`, `application/json`): the [`dataset_summary`](#dataset_summary) object of `sample`.

### `investigate_asset`

`description`: "Investigate asset"

Message 1 (`user`, text):

```text
Investigate the asset described in the context (use its `id` as `ref` in the
calls below). Its current detail is embedded.

1. `get_asset(ref=<id>)` and `get_asset_metadata` (specific keys) for configuration.
2. `neighbors(ref, depth=2)` for what it connects to, then `depends_on` / `dependents`.
3. `findings_for_asset(ref)` then `get_finding` on the serious ones.
4. `blast_radius(ref)` and, if it is exposed, `find_paths(source='internet', target=ref)`.
5. `ontology_neighbourhood(ref)` for semantic relations (encryption, protection, ownership).

Report what it is, who owns it (tags), how it is exposed, what it can reach, what depends on
it, its findings, and prioritised recommendations.
```

Message 2 (`user`, text): `Context for this task (JSON):` followed by a fenced JSON block:

```json
{
  "dataset": "sample"
}
```

Message 3 (`user`, embedded resource `cloudg://assets/orders-db`, `application/json`):

```json
{
  "id": "orders-db",
  "name": "orders-db",
  "type": "RDS_INSTANCE",
  "provider": "AWS",
  "region": "us-east-1",
  "account_id": "111111111111",
  "arn": "arn:aws:rds:us-east-1:111111111111:db:orders-db",
  "internet_exposed": false,
  "open_findings": 1,
  "max_severity": "MEDIUM",
  "uri": "cloudg://assets/orders-db",
  "tags": {
    "env": "prod",
    "data": "pii"
  },
  "relations": {
    "outgoing": {
      "ATTACHED_TO": 1,
      "REFERENCES": 1
    },
    "incoming": {
      "CONTAINS": 1,
      "GRANTS_ACCESS": 1
    }
  },
  "findings": [
    {
      "id": "f-db-backup",
      "title": "RDS backup retention below 7 days",
      "severity": "MEDIUM",
      "risk_score": 5.0,
      "source_tool": "prowler",
      "resource_id": "arn:aws:rds:us-east-1:111111111111:db:orders-db",
      "resource_arn": null,
      "asset_id": "orders-db",
      "asset_name": "orders-db",
      "compliance_frameworks": [
        "CIS-AWS",
        "NIST-800-53"
      ],
      "is_suppressed": false,
      "cvss_score": null,
      "detected_at": "2026-01-15T12:00:00+00:00",
      "uri": "cloudg://findings/f-db-backup"
    }
  ],
  "metadata_keys": [
    "backup_retention",
    "engine"
  ],
  "dependencies": {
    "direct_depends_on": 3,
    "direct_dependents": 1
  }
}
```

### `blast_radius_assessment`

`description`: "Blast radius assessment"

Message 1 (`user`, text):

```text
Assess the blast radius of the asset in the context (`asset.id`) if it is
(a) compromised and (b) deleted or unavailable.

1. `blast_radius(ref=<asset.id>)`: dependency and network reach, sensitive stores reachable.
2. `dependency_tree(ref, direction='down')` shows what breaks, layer by layer.
3. `lateral_movement_paths(start=<asset.id>)` for identity pivots from it.
4. `findings_for_asset` on the most critical dependents.

Report both scenarios with affected services / accounts / data, severity, and containment
and resilience recommendations (least privilege, redundancy, segmentation).
```

Message 2 (`user`, text): `Context for this task (JSON):` followed by a fenced JSON block:

```json
{
  "dataset": "sample",
  "asset": {
    "id": "kms-main",
    "name": "prod-main-key",
    "type": "KMS_KEY",
    "provider": "AWS",
    "region": "us-east-1",
    "account_id": "111111111111",
    "arn": "arn:aws:kms:us-east-1:111111111111:key/1111-2222",
    "internet_exposed": false,
    "open_findings": 0,
    "max_severity": null,
    "uri": "cloudg://assets/kms-main"
  },
  "transitive_dependents": 12,
  "accounts_affected": [
    "111111111111"
  ],
  "direct_dependents": [
    {
      "id": "api-handler",
      "name": "api-handler",
      "type": "LAMBDA_FUNCTION",
      "provider": "AWS",
      "region": "us-east-1",
      "account_id": "111111111111",
      "arn": "arn:aws:lambda:us-east-1:111111111111:function:api-handler",
      "internet_exposed": false,
      "open_findings": 1,
      "max_severity": "LOW",
      "uri": "cloudg://assets/api-handler"
    },
    {
      "id": "data-bucket",
      "name": "prod-data",
      "type": "S3_BUCKET",
      "provider": "AWS",
      "region": "us-east-1",
      "account_id": "111111111111",
      "arn": "arn:aws:s3:::prod-data",
      "internet_exposed": false,
      "open_findings": 0,
      "max_severity": null,
      "uri": "cloudg://assets/data-bucket"
    },
    "... 2 more"
  ]
}
```

Message 3 (`user`, embedded resource `cloudg://assets/kms-main`, `application/json`):

```json
{
  "id": "kms-main",
  "name": "prod-main-key",
  "type": "KMS_KEY",
  "provider": "AWS",
  "region": "us-east-1",
  "account_id": "111111111111",
  "arn": "arn:aws:kms:us-east-1:111111111111:key/1111-2222",
  "internet_exposed": false,
  "open_findings": 0,
  "max_severity": null,
  "uri": "cloudg://assets/kms-main",
  "tags": {},
  "relations": {
    "outgoing": {},
    "incoming": {
      "REFERENCES": 4
    }
  },
  "findings": [],
  "metadata_keys": [],
  "dependencies": {
    "direct_depends_on": 0,
    "direct_dependents": 4
  }
}
```

### `change_impact_analysis`

`description`: "Change impact analysis"

Message 1 (`user`, text):

```text
Plan the change described in the context (`planned_change`) to the asset in the
context (`asset.id`). Direct upstream / downstream dependencies are embedded.

1. `dependents(ref=<asset.id>, max_depth=5)` and `dependency_tree(ref, direction='down')`.
2. `shared_dependencies()`: is it a single point of failure?
3. `cross_account_edges(account_id=<asset.account_id>)` for other accounts affected.
4. `get_asset_metadata(ref)` for the settings being changed.

Deliver: affected components ranked by impact, risks, pre-checks, a rollout and rollback
plan, and how to verify (e.g. snapshot_dataset now, re-collect after, diff_datasets).
```

Message 2 (`user`, text): `Context for this task (JSON):` followed by a fenced JSON block:

```json
{
  "dataset": "sample",
  "planned_change": "remove port 5432 ingress",
  "asset": {
    "id": "sg-app",
    "name": "sg-app",
    "type": "SECURITY_GROUP",
    "provider": "AWS",
    "region": "us-east-1",
    "account_id": "111111111111",
    "arn": "arn:aws:ec2:us-east-1:111111111111:security-group/sg-0app",
    "internet_exposed": false,
    "open_findings": 0,
    "max_severity": null,
    "uri": "cloudg://assets/sg-app"
  },
  "depends_on": [],
  "dependents": [
    {
      "id": "web-1",
      "name": "web-1",
      "type": "EC2",
      "provider": "AWS",
      "region": "us-east-1",
      "account_id": "111111111111",
      "arn": "arn:aws:ec2:us-east-1:111111111111:instance/i-0web1",
      "internet_exposed": false,
      "open_findings": 1,
      "max_severity": "HIGH",
      "uri": "cloudg://assets/web-1"
    },
    {
      "id": "web-2",
      "name": "web-2",
      "type": "EC2",
      "provider": "AWS",
      "region": "us-east-1",
      "account_id": "111111111111",
      "arn": "arn:aws:ec2:us-east-1:111111111111:instance/i-0web2",
      "internet_exposed": false,
      "open_findings": 0,
      "max_severity": null,
      "uri": "cloudg://assets/web-2"
    }
  ]
}
```

Message 3 (`user`, embedded resource `cloudg://assets/sg-app`, `application/json`):

```json
{
  "id": "sg-app",
  "name": "sg-app",
  "type": "SECURITY_GROUP",
  "provider": "AWS",
  "region": "us-east-1",
  "account_id": "111111111111",
  "arn": "arn:aws:ec2:us-east-1:111111111111:security-group/sg-0app",
  "internet_exposed": false,
  "open_findings": 0,
  "max_severity": null,
  "uri": "cloudg://assets/sg-app",
  "tags": {},
  "relations": {
    "outgoing": {
      "SECURITY_GROUP_RULE": 1
    },
    "incoming": {
      "ATTACHED_TO": 2
    }
  },
  "findings": [],
  "metadata_keys": [],
  "dependencies": {
    "direct_depends_on": 0,
    "direct_dependents": 2
  }
}
```

### `cross_account_trust_review`

`description`: "Cross-account trust review"

Message 1 (`user`, text):

```text
Review trust relationships across account boundaries in the dataset named in the
context.

1. `cross_account_edges(external_only=true)` then all of them by account pair.
2. `get_edges(edge_types=['IAM_TRUST'])` and `get_edges(edge_types=['GRANTS_ACCESS'],
   cross_account_only=true)`.
3. `lateral_movement_paths()`: chains a compromised external principal could follow.
4. `organization_topology(include_policies=true)` for SCPs that limit the blast radius.

Flag unknown / external accounts, overly broad trust (account root, wildcards), missing
external-id conditions, and recommend tightening with evidence for each.
```

Message 2 (`user`, text): `Context for this task (JSON):` followed by a fenced JSON block:

```json
{
  "dataset": "sample",
  "cross_account_edges": 3,
  "external": 1,
  "by_account_pair": {
    "111111111111 -> 222222222222 (IAM_TRUST)": 1,
    "999999999999 -> 222222222222 (IAM_TRUST)": 1,
    "111111111111 -> 222222222222 (USES_IMAGE)": 1
  }
}
```

Message 3 (`user`, embedded resource `cloudg://datasets/sample/summary`, `application/json`): the [`dataset_summary`](#dataset_summary) object of `sample`.

### `compliance_gap_analysis`

`description`: "Compliance gap analysis"

Message 1 (`user`, text):

```text
Run a compliance gap analysis for the framework named in the context
(`framework`, called <framework> below).

1. `compliance_summary(framework=<framework>)`.
2. `list_controls(framework=<framework>, status='FAIL')` and
   `list_controls(framework=<framework>, source='ruleset')` for the full control set.
3. `control_status` on the failing controls with the most / worst findings.
4. `compliance_gaps(framework=<framework>)` to list the assets behind the gaps.

Deliver: pass rate and failing controls grouped by domain, the assets responsible, a
remediation backlog ordered by severity x effort, and evidence references (finding ids).
```

Message 2 (`user`, text): `Context for this task (JSON):` followed by a fenced JSON block:

```json
{
  "dataset": "sample",
  "framework": "PCI-DSS"
}
```

Message 3 (`user`, embedded resource `cloudg://compliance/PCI-DSS`, `application/json`):

```json
{
  "dataset": "sample",
  "posture": [
    {
      "framework": "PCI-DSS",
      "controls_evaluated": 1,
      "controls_failing": 1,
      "controls_passing": 0,
      "controls_other": 0,
      "pass_rate": 0.0,
      "open_findings": 3,
      "severity_breakdown": {
        "CRITICAL": 1,
        "HIGH": 2
      },
      "affected_assets": 3,
      "uri": "cloudg://compliance/PCI-DSS"
    }
  ],
  "failing_controls": [
    {
      "framework": "PCI-DSS",
      "control_id": "1.3.1",
      "control_title": "Inbound traffic restricted",
      "open_findings": 2,
      "max_severity": "CRITICAL"
    }
  ]
}
```

### `remediation_plan`

`severity` is upper-cased and defaults to `HIGH`; it is not checked until `top_risks` runs inside the prompt, so a bad value raises the usual severity error.

`description`: "Remediation plan"

Message 1 (`user`, text):

```text
Build a remediation plan for open findings at CRITICAL or above in the dataset named
in the context.

1. `list_findings(min_severity='CRITICAL', limit=100)` (page with next_cursor if needed).
2. `top_risks(top=20, min_severity='CRITICAL')` to order work by real risk.
3. `get_finding` for remediation text; `blast_radius` on assets where a fix may disrupt.
4. Group fixes that share a root cause (same security group, role, policy, account setting).

Deliver: phased plan (now / this sprint / next quarter) with owner hints from tags, each
item with finding ids, affected assets, the fix, its risk reduction and change risk. Note
accepted risks that could be suppressed (suppress_findings) with the reason.
```

Message 2 (`user`, text): `Context for this task (JSON):` followed by a fenced JSON block:

```json
{
  "dataset": "sample",
  "min_severity": "CRITICAL",
  "top_risks": [
    {
      "asset": "jump-nsg",
      "id": "az-nsg",
      "type": "NSG",
      "score": 16.39,
      "internet_exposed": false,
      "top_finding": "NSG allows RDP (3389) from Internet"
    },
    {
      "asset": "sg-admin",
      "id": "sg-admin",
      "type": "SECURITY_GROUP",
      "score": 16.39,
      "internet_exposed": false,
      "top_finding": "Security group allows SSH (22) from 0.0.0.0/0"
    }
  ]
}
```

Message 3 (`user`, embedded resource `cloudg://datasets/sample/summary`, `application/json`): the [`dataset_summary`](#dataset_summary) object of `sample`.

### `incident_triage`

`description`: "Incident triage"

Message 1 (`user`, text):

```text
Triage the finding in the context (CRITICAL) as a potential
incident. `id` is the finding id and `target_ref` the affected asset (<target> below).

1. `get_finding(finding_id=<id>)` for evidence and mapped controls.
2. `get_asset(ref=<target>)` and `internet_exposure()`: is the affected asset reachable?
3. `find_paths(source='internet', target=<target>)` and `blast_radius(ref=<target>)`.
4. `lateral_movement_paths(start=<target>)` to see where an attacker goes next.

Deliver: is it exploitable (likely / possible / unlikely) and why, impact if exploited,
immediate containment steps, evidence to collect, the permanent fix, and severity
re-rating if justified.
```

Message 2 (`user`, text): `Context for this task (JSON):` followed by a fenced JSON block:

```json
{
  "dataset": "sample",
  "target_ref": "sg-admin"
}
```

Message 3 (`user`, embedded resource `cloudg://findings/f-ssh-open`, `application/json`):

```json
{
  "id": "f-ssh-open",
  "title": "Security group allows SSH (22) from 0.0.0.0/0",
  "severity": "CRITICAL",
  "risk_score": 9.5,
  "source_tool": "prowler",
  "resource_id": "sg-admin",
  "resource_arn": "arn:aws:ec2:us-east-1:111111111111:security-group/sg-0admin",
  "asset_id": "sg-admin",
  "asset_name": "sg-admin",
  "compliance_frameworks": [
    "CIS-AWS",
    "PCI-DSS"
  ],
  "is_suppressed": false,
  "cvss_score": null,
  "detected_at": "2026-01-15T12:00:00+00:00",
  "uri": "cloudg://findings/f-ssh-open",
  "description": "Security group allows SSH (22) from 0.0.0.0/0.",
  "evidence": "IpPermissions 0.0.0.0/0 tcp 22",
  "remediation": "Restrict 22 to the VPN."
}
```

### `drift_review`

There is no `dataset` argument; `target` empty means the active dataset.

`description`: "Drift review"

Message 1 (`user`, text):

```text
Review what changed between the datasets `base` (before) and `target` (after)
named in the context. The diff is embedded (counts plus the first items).

Call `diff_datasets(base=<base>, target=<target>, limit=200)` for more, and `get_asset` /
`findings_for_asset` on anything suspicious. Report: new or newly exposed assets, removed
controls (security groups, WAF, logging), new trust edges, findings introduced vs resolved,
and whether each change looks intended or like drift.
```

Message 2 (`user`, text): `Context for this task (JSON):` followed by a fenced JSON block:

```json
{
  "base": "baseline",
  "target": "after",
  "assets": {
    "added": {
      "count": 0,
      "items": [],
      "truncated": false
    },
    "removed": {
      "count": 1,
      "items": [
        {
          "id": "waf-web",
          "key": "arn:aws:wafv2:us-east-1:111111111111:regional/webacl/web-acl/1",
          "name": "web-acl",
          "type": "WAF_WEB_ACL",
          "account_id": "111111111111",
          "region": "us-east-1"
        }
      ],
      "truncated": false
    },
    "changed": {
      "count": 1,
      "items": [
        {
          "id": "web-2",
          "key": "arn:aws:ec2:us-east-1:111111111111:instance/i-0web2",
          "name": "web-2",
          "type": "EC2",
          "account_id": "111111111111",
          "region": "us-east-1",
          "changed_fields": [
            "internet_exposed",
            "tags"
          ],
          "internet_exposed": {
            "before": false,
            "after": true
          }
        }
      ],
      "truncated": false
    },
    "unchanged": 42
  },
  "edges": {
    "added": {
      "count": 1,
      "items": [
        {
          "source": "0.0.0.0/0",
          "target": "arn:aws:ec2:us-east-1:111111111111:instance/i-0web2",
          "edge_type": "INTERNET_EXPOSED",
          "relationship": "INTERNET_REACHABLE"
        }
      ],
      "truncated": false
    },
    "removed": {
      "count": 1,
      "items": [
        {
          "source": "arn:aws:wafv2:us-east-1:111111111111:regional/webacl/web-acl/1",
          "target": "arn:aws:elasticloadbalancing:us-east-1:111111111111:loadbalancer/app/web-alb/abc",
          "edge_type": "PROTECTS",
          "relationship": null
        }
      ],
      "truncated": false
    }
  },
  "findings": {
    "new": {
      "count": 0,
      "items": [],
      "truncated": false
    },
    "resolved": {
      "count": 1,
      "items": [
        {
          "id": "f-ssh-open",
          "title": "Security group allows SSH (22) from 0.0.0.0/0",
          "severity": "CRITICAL",
          "resource": "arn:aws:ec2:us-east-1:111111111111:security-group/sg-0admin",
          "source_tool": "prowler"
        }
      ],
      "truncated": false
    },
    "severity_changed": {
      "count": 1,
      "items": [
        {
          "id": "f-db-backup",
          "title": "RDS backup retention below 7 days",
          "severity": "HIGH",
          "resource": "arn:aws:rds:us-east-1:111111111111:db:orders-db",
          "source_tool": "prowler",
          "severity_before": "MEDIUM"
        }
      ],
      "truncated": false
    }
  },
  "newly_internet_exposed": {
    "count": 1,
    "items": [
      {
        "id": "web-2",
        "key": "arn:aws:ec2:us-east-1:111111111111:instance/i-0web2",
        "name": "web-2",
        "type": "EC2",
        "account_id": "111111111111",
        "region": "us-east-1",
        "changed_fields": [
          "internet_exposed",
          "tags"
        ],
        "internet_exposed": {
          "before": false,
          "after": true
        }
      }
    ],
    "truncated": false
  }
}
```

## Recipes

Multi-step workflows an agent (or a script) can follow. Each step names the tool and the arguments; the numbers quoted come from the captured runs on the sample estate shown earlier in this document.

### Posture review

The `security_posture_review` prompt packages this sequence.

1. `workspace_status`, then `dataset_summary`: 44 assets, 11 open findings (2 CRITICAL, 5 HIGH), 6 internet-exposed assets, 3 cross-account edges.
2. `findings_summary(group_by="source_tool")` to see where findings come from:

`findings_summary` returned this `structuredContent`.

```json
{
  "dataset": "sample",
  "group_by": "source_tool",
  "total": 11,
  "suppressed": 1,
  "groups": {
    "prowler": {
      "total": 5,
      "CRITICAL": 1,
      "HIGH": 2,
      "MEDIUM": 1,
      "INFO": 1
    },
    "scoutsuite": {
      "total": 3,
      "HIGH": 1,
      "CRITICAL": 1,
      "MEDIUM": 1
    },
    "checkov": {
      "total": 1,
      "LOW": 1
    },
    "iam": {
      "total": 1,
      "HIGH": 1
    },
    "trivy": {
      "total": 1,
      "HIGH": 1
    }
  },
  "truncated": false
}
```

3. `top_risks(top=10)`: `jump-nsg` and `sg-admin` tie at 16.39 (a CRITICAL finding, internet-reachable, small blast radius). The components explain each score.
4. `internet_exposure()`: `bastion` (SSH via `sg-admin`) and `jump-vm` (RDP via `jump-nsg`) sort first, each with a sensitive port open and no WAF.
5. `attack_paths()`: the top path is `web-alb -> web-tg -> web-1 -> app-role -> orders-db` with score 9.8.
6. `lateral_movement_paths()` and `cross_account_edges(external_only=true)`: the vendor account `999999999999` can assume `deploy-role` in `shared-services`.
7. `security_coverage()`: Security Hub disabled in `111111111111/us-east-1`, `public-api` exposed without a WAF, four workloads without vulnerability scanning.
8. `compliance_summary()`: CIS-AWS at a 25.0% pass rate with 6 open findings.

### Investigate an internet-exposed asset

Start from the exposure list and walk outwards from one entry.

1. `internet_exposure()` lists `bastion` first: SSH open through `sg-admin`, no WAF.
2. `get_edges(target="sg-admin")` shows the rule and what the group is attached to:

`get_edges` returned this `structuredContent`.

```json
{
  "dataset": "sample",
  "total": 2,
  "offset": 0,
  "returned": 2,
  "next_cursor": null,
  "truncated": false,
  "items": [
    {
      "id": "e-inet-sgadmin",
      "source": "0.0.0.0/0",
      "source_name": "0.0.0.0/0",
      "target": "sg-admin",
      "target_name": "sg-admin",
      "edge_type": "SECURITY_GROUP_RULE",
      "relationship": null,
      "port_range": "22",
      "protocol": "TCP",
      "cidr": "0.0.0.0/0",
      "ports": [
        22
      ],
      "direction": "ingress"
    },
    {
      "id": "e-bastion-sg",
      "source": "bastion",
      "source_name": "bastion",
      "target": "sg-admin",
      "target_name": "sg-admin",
      "edge_type": "ATTACHED_TO",
      "relationship": null
    }
  ]
}
```

3. `find_paths(source="internet", target="bastion")` confirms the route `0.0.0.0/0 -> sg-admin -> bastion` (flow mode, hop types `SECURITY_GROUP_RULE`, `SG_ADMITS`).
4. `findings_for_asset(ref="bastion")` returns `f-bastion-imds` (IMDSv1, HIGH); `findings_for_asset(ref="sg-admin")` returns the CRITICAL SSH finding.
5. `lateral_movement_paths(start="bastion")` shows where a compromise goes:

`lateral_movement_paths` returned this `structuredContent`.

```json
{
  "dataset": "sample",
  "paths": [
    {
      "length": 2,
      "nodes": [
        {
          "id": "bastion",
          "name": "bastion",
          "type": "EC2",
          "account_id": "111111111111",
          "internet_exposed": true,
          "open_findings": 1,
          "max_severity": "HIGH"
        },
        {
          "id": "admin-role",
          "name": "bastion-admin",
          "type": "IAM_ROLE",
          "account_id": "111111111111",
          "internet_exposed": false,
          "open_findings": 0
        },
        {
          "id": "db-secret",
          "name": "orders-db-credentials",
          "type": "SECRET",
          "account_id": "111111111111",
          "internet_exposed": false,
          "open_findings": 0
        }
      ],
      "edge_types": [
        "ASSUMES_ROLE",
        "GRANTS_ACCESS"
      ],
      "summary": "bastion -> bastion-admin -> orders-db-credentials"
    }
  ],
  "total_found": 1,
  "truncated": false,
  "starting_points": 1
}
```

6. `blast_radius(ref="bastion")`: nothing depends on the bastion, but the network view reaches 4 assets including the database secret and the KMS key:

`blast_radius` returned the `network` part of its `structuredContent`.

```json
{
  "reachable_assets": 4,
  "max_depth": 3,
  "risk_score": 2.0,
  "sensitive_reachable": [
    {
      "id": "admin-role",
      "name": "bastion-admin",
      "type": "IAM_ROLE",
      "provider": "AWS",
      "region": "global",
      "account_id": "111111111111",
      "arn": "arn:aws:iam::111111111111:role/bastion-admin",
      "internet_exposed": false,
      "open_findings": 0,
      "max_severity": null,
      "uri": "cloudg://assets/admin-role"
    },
    {
      "id": "db-secret",
      "name": "orders-db-credentials",
      "type": "SECRET",
      "provider": "AWS",
      "region": "us-east-1",
      "account_id": "111111111111",
      "arn": "arn:aws:secretsmanager:us-east-1:111111111111:secret:orders-db-credentials-AbC",
      "internet_exposed": false,
      "open_findings": 0,
      "max_severity": null,
      "uri": "cloudg://assets/db-secret"
    },
    {
      "id": "kms-main",
      "name": "prod-main-key",
      "type": "KMS_KEY",
      "provider": "AWS",
      "region": "us-east-1",
      "account_id": "111111111111",
      "arn": "arn:aws:kms:us-east-1:111111111111:key/1111-2222",
      "internet_exposed": false,
      "open_findings": 0,
      "max_severity": null,
      "uri": "cloudg://assets/kms-main"
    }
  ]
}
```

The result also carried these resource links in `content`:

```json
[
  {
    "type": "resource_link",
    "uri": "cloudg://assets/bastion",
    "name": "bastion",
    "mimeType": "application/json"
  }
]
```

7. `get_finding(finding_id="f-ssh-open")` for evidence and remediation, then `incident_triage(finding_id="f-ssh-open")` if it should be handled as an incident.

### Blast radius before a change

Planned change: remove the PostgreSQL rule from `sg-app` (the `change_impact_analysis` prompt with `ref="sg-app"` drives the same steps).

1. `get_edges(source="sg-app")` shows the rule being changed:

`get_edges` returned this `structuredContent`.

```json
{
  "dataset": "sample",
  "total": 1,
  "offset": 0,
  "returned": 1,
  "next_cursor": null,
  "truncated": false,
  "items": [
    {
      "id": "e-sgapp-sgdb",
      "source": "sg-app",
      "source_name": "sg-app",
      "target": "sg-db",
      "target_name": "sg-db",
      "edge_type": "SECURITY_GROUP_RULE",
      "relationship": null,
      "port_range": "5432",
      "protocol": "TCP",
      "ports": [
        5432
      ],
      "direction": "ingress"
    }
  ]
}
```

2. `dependents(ref="sg-app")`: `web-1` and `web-2` depend on the group directly (`ATTACHED_TO`), `tg-web` at depth 2 and `alb-web` at depth 3.
3. `dependency_tree(ref="sg-app", direction="down")` gives the same set as a tree for the change ticket.
4. `shared_dependencies()`: `sg-app` has 2 direct dependents, behind `kms-main` (4).
5. `cross_account_edges(account_id="111111111111")` lists the prod account's cross-account edges; of the three in the sample, none involves `sg-app`.
6. `snapshot_dataset(new_name="before-change")`, make the change, collect again with `map_inventory` (or load the new map), then `diff_datasets(base="before-change")`.

### Cross-account trust review

1. `cross_account_edges(external_only=true)`: one external edge, `999999999999 -> 222222222222` (`IAM_TRUST`).
2. `get_edges(edge_types=["IAM_TRUST"], cross_account_only=true)` lists both trusts into `deploy-role`, from `app-role` in prod and from the vendor account.
3. `lateral_movement_paths(start="acct-vendor")` shows what the vendor reaches:

`lateral_movement_paths` returned this `structuredContent`.

```json
{
  "dataset": "sample",
  "paths": [
    {
      "length": 2,
      "nodes": [
        {
          "id": "acct-vendor",
          "name": "vendor-co",
          "type": "CLOUD_ACCOUNT",
          "account_id": "999999999999",
          "internet_exposed": false,
          "open_findings": 0
        },
        {
          "id": "deploy-role",
          "name": "deploy-role",
          "type": "IAM_ROLE",
          "account_id": "222222222222",
          "internet_exposed": false,
          "open_findings": 1,
          "max_severity": "HIGH"
        },
        "... 1 more"
      ],
      "edge_types": [
        "IAM_TRUST",
        "GRANTS_ACCESS"
      ],
      "summary": "vendor-co -> deploy-role -> shared-artifacts"
    },
    {
      "length": 2,
      "nodes": [
        {
          "id": "acct-vendor",
          "name": "vendor-co",
          "type": "CLOUD_ACCOUNT",
          "account_id": "999999999999",
          "internet_exposed": false,
          "open_findings": 0
        },
        {
          "id": "deploy-role",
          "name": "deploy-role",
          "type": "IAM_ROLE",
          "account_id": "222222222222",
          "internet_exposed": false,
          "open_findings": 1,
          "max_severity": "HIGH"
        },
        "... 1 more"
      ],
      "edge_types": [
        "IAM_TRUST",
        "GRANTS_ACCESS"
      ],
      "summary": "vendor-co -> deploy-role -> app-images"
    }
  ],
  "total_found": 2,
  "truncated": false,
  "starting_points": 1
}
```

4. `findings_for_asset(ref="deploy-role")` returns `f-deploy-trust`: "Role trusts an external account without ExternalId" (HIGH).
5. `organization_topology(include_policies=true)`: the SCP `deny-unapproved-regions` targets the Workloads OU, which holds both accounts.
6. The SPARQL equivalent of step 2 is in the [cookbook](#sparql-cookbook).

### Compliance gap triage

1. `compliance_summary(framework="PCI")` gives the posture (1 control evaluated, failing, 3 open findings, 3 affected assets).
2. `list_controls(framework="PCI", status="FAIL")`:

`list_controls` returned this `structuredContent`.

```json
{
  "dataset": "sample",
  "source": "dataset",
  "total": 1,
  "offset": 0,
  "returned": 1,
  "next_cursor": null,
  "truncated": false,
  "items": [
    {
      "framework": "PCI-DSS",
      "control_id": "1.3.1",
      "control_title": "Inbound traffic restricted",
      "status": "FAIL",
      "findings": 2,
      "open_findings": 2,
      "max_severity": "CRITICAL"
    }
  ]
}
```

3. `control_status(framework="PCI-DSS", control_id="1.3.1")` returns the two findings behind the control (SSH open, public S3 read) and the assets. The PCI ruleset has no control `1.3.1`, so `definition` is null.
4. `compliance_gaps(framework="PCI-DSS")` ranks the assets:

`compliance_gaps` returned this `structuredContent`.

```json
{
  "dataset": "sample",
  "framework": "PCI-DSS",
  "total": 3,
  "offset": 0,
  "returned": 3,
  "next_cursor": null,
  "truncated": false,
  "items": [
    {
      "id": "sg-admin",
      "name": "sg-admin",
      "type": "SECURITY_GROUP",
      "provider": "AWS",
      "region": "us-east-1",
      "account_id": "111111111111",
      "arn": "arn:aws:ec2:us-east-1:111111111111:security-group/sg-0admin",
      "internet_exposed": false,
      "open_findings": 1,
      "max_severity": "CRITICAL",
      "uri": "cloudg://assets/sg-admin",
      "frameworks": [
        "PCI-DSS"
      ],
      "failing_controls": [
        "PCI-DSS:1.3.1"
      ],
      "gap_findings": 1,
      "gap_max_severity": "CRITICAL"
    },
    {
      "id": "logs-bucket",
      "name": "prod-logs",
      "type": "S3_BUCKET",
      "provider": "AWS",
      "region": "us-east-1",
      "account_id": "111111111111",
      "arn": "arn:aws:s3:::prod-logs",
      "internet_exposed": true,
      "open_findings": 1,
      "max_severity": "HIGH",
      "uri": "cloudg://assets/logs-bucket",
      "frameworks": [
        "PCI-DSS"
      ],
      "failing_controls": [
        "PCI-DSS:1.3.1"
      ],
      "gap_findings": 1,
      "gap_max_severity": "HIGH"
    },
    {
      "id": "web-1",
      "name": "web-1",
      "type": "EC2",
      "provider": "AWS",
      "region": "us-east-1",
      "account_id": "111111111111",
      "arn": "arn:aws:ec2:us-east-1:111111111111:instance/i-0web1",
      "internet_exposed": false,
      "open_findings": 1,
      "max_severity": "HIGH",
      "uri": "cloudg://assets/web-1",
      "frameworks": [
        "PCI-DSS"
      ],
      "failing_controls": [],
      "gap_findings": 1,
      "gap_max_severity": "HIGH"
    }
  ]
}
```

`web-1` is a gap through its finding's PCI-DSS tag (the CVE) although no compliance result links that finding, hence the empty `failing_controls`.

5. `list_controls(framework="PCI-DSS", source="ruleset")` lists the full control set for coverage questions.

### Drift between two snapshots

1. Before the change: `snapshot_dataset(new_name="baseline")`.
2. After: `load_dataset(path="inventory-after", name="after")` (or `map_inventory(name="after")`).
3. `diff_datasets(base="baseline", target="after")`: the result is shown in full under [`diff_datasets`](#diff_datasets). On the edited estate it reports the WAF removed, its `PROTECTS` edge removed, `web-2` changed (`internet_exposed`, `tags`) and newly exposed, a new `INTERNET_EXPOSED` edge to it, `f-ssh-open` resolved and `f-db-backup` raised from MEDIUM to HIGH.
4. `drift_review(base="baseline", target="after")` turns that diff into a review task with the diff embedded.
5. Follow up with `get_asset(ref="web-2")`, `internet_exposure()` and `find_paths(source="internet", target="web-2")` on what changed.

### SPARQL cookbook

Every query below was run with `sparql_query` against the sample estate; each is followed by its result.

Internet-reachable resources (directly exposed, per the ontology):

```sparql
SELECT ?r ?name WHERE { ?s cmp:INTERNET_REACHABLE ?r . ?r cmp:hasName ?name } ORDER BY ?name
```

```json
{
  "dataset": "sample",
  "query_type": "SelectQuery",
  "rows": [
    {
      "r": "cmr:az-nsg",
      "name": "jump-nsg"
    },
    {
      "r": "cmr:logs-bucket",
      "name": "prod-logs"
    },
    {
      "r": "cmr:api-gw",
      "name": "public-api"
    },
    "... 4 more"
  ],
  "returned": 7,
  "truncated": false,
  "variable_kinds": {
    "r": "uri",
    "name": "literal"
  }
}
```

Assets flagged internet-exposed, with their ontology class:

```sparql
SELECT ?name ?type WHERE { ?r cmp:isInternetExposed true ; cmp:hasName ?name ; a ?type } ORDER BY ?name
```

```json
{
  "dataset": "sample",
  "query_type": "SelectQuery",
  "rows": [
    {
      "name": "bastion",
      "type": "cm:ComputeInstance"
    },
    {
      "name": "jump-vm",
      "type": "cm:ComputeInstance"
    },
    {
      "name": "prod-logs",
      "type": "cm:ObjectStorage"
    },
    "... 3 more"
  ],
  "returned": 6,
  "truncated": false,
  "variable_kinds": {
    "name": "literal",
    "type": "uri"
  }
}
```

Assets tagged `data=pii` (tag individuals are named `cmr:tag_<key>_<value>`):

```sparql
SELECT ?name ?type WHERE { ?r cmp:TAGGED_WITH cmr:tag_data_pii ; cmp:hasName ?name ; a ?type } ORDER BY ?name
```

```json
{
  "dataset": "sample",
  "query_type": "SelectQuery",
  "rows": [
    {
      "name": "orders-db",
      "type": "cm:RelationalDatabase"
    },
    {
      "name": "prod-data",
      "type": "cm:ObjectStorage"
    }
  ],
  "returned": 2,
  "truncated": false,
  "variable_kinds": {
    "name": "literal",
    "type": "uri"
  }
}
```

Security groups or NSGs that open SSH or RDP:

```sparql
SELECT ?rel ?sg WHERE { VALUES ?rel { cmp:ONLY_SSH cmp:ONLY_RDP } ?s ?rel ?t . ?t cmp:hasName ?sg }
```

```json
{
  "dataset": "sample",
  "query_type": "SelectQuery",
  "rows": [
    {
      "rel": "cmp:ONLY_SSH",
      "sg": "sg-admin"
    },
    {
      "rel": "cmp:ONLY_RDP",
      "sg": "jump-nsg"
    }
  ],
  "returned": 2,
  "truncated": false,
  "variable_kinds": {
    "rel": "uri",
    "sg": "literal"
  }
}
```

Everything allowed into each security group:

```sparql
SELECT ?src ?sg WHERE { ?s cmp:INGRESS_ALLOWED ?t . ?t cmp:hasName ?sg . OPTIONAL { ?s cmp:hasName ?src } } ORDER BY ?sg
```

```json
{
  "dataset": "sample",
  "query_type": "SelectQuery",
  "rows": [
    {
      "src": "0.0.0.0/0",
      "sg": "jump-nsg"
    },
    {
      "src": "0.0.0.0/0",
      "sg": "sg-admin"
    },
    {
      "src": "sg-app",
      "sg": "sg-db"
    },
    {
      "src": "0.0.0.0/0",
      "sg": "sg-web"
    }
  ],
  "returned": 4,
  "truncated": false,
  "variable_kinds": {
    "src": "literal",
    "sg": "literal"
  }
}
```

CRITICAL findings and the assets they affect:

```sparql
SELECT ?fname ?sev ?aname WHERE { ?f cmp:FINDING_AFFECTS ?a ; cmp:hasName ?fname ; cmp:hasSeverity ?sev . ?a cmp:hasName ?aname . FILTER(?sev = "CRITICAL") }
```

```json
{
  "dataset": "sample",
  "query_type": "SelectQuery",
  "rows": [
    {
      "fname": "Security group allows SSH (22) from 0.0.0.0/0",
      "sev": "CRITICAL",
      "aname": "sg-admin"
    },
    {
      "fname": "NSG allows RDP (3389) from Internet",
      "sev": "CRITICAL",
      "aname": "jump-nsg"
    }
  ],
  "returned": 2,
  "truncated": false,
  "variable_kinds": {
    "fname": "literal",
    "sev": "literal",
    "aname": "literal"
  }
}
```

Where every finding points; the null names are the findings that name their resource by ARN or display name instead of asset id (see [Ontology](#ontology)):

```sparql
SELECT ?f ?target ?name WHERE { ?f cmp:FINDING_AFFECTS ?target . OPTIONAL { ?target cmp:hasName ?name } } ORDER BY ?f
```

```json
{
  "dataset": "sample",
  "query_type": "SelectQuery",
  "rows": [
    {
      "f": "cmr:finding_f-bastion-imds",
      "target": "cmr:bastion",
      "name": "bastion"
    },
    {
      "f": "cmr:finding_f-db-backup",
      "target": "cmr:orders-db",
      "name": "orders-db"
    },
    {
      "f": "cmr:finding_f-default-vpc",
      "target": "cmr:vpc-prod",
      "name": "prod-vpc"
    },
    "... 9 more"
  ],
  "returned": 12,
  "truncated": false,
  "variable_kinds": {
    "f": "uri",
    "target": "uri",
    "name": "literal"
  }
}
```

Cross-account trust:

```sparql
SELECT ?src ?tgt WHERE { ?s cmp:CROSS_ACCOUNT_TRUST ?t . ?s cmp:hasName ?src . ?t cmp:hasName ?tgt }
```

```json
{
  "dataset": "sample",
  "query_type": "SelectQuery",
  "rows": [
    {
      "src": "app-role",
      "tgt": "deploy-role"
    },
    {
      "src": "vendor-co",
      "tgt": "deploy-role"
    }
  ],
  "returned": 2,
  "truncated": false,
  "variable_kinds": {
    "src": "literal",
    "tgt": "literal"
  }
}
```

Resources encrypted with one KMS key:

```sparql
SELECT ?name WHERE { ?r cmp:ENCRYPTED_BY_KMS ?k . ?k cmp:hasName "prod-main-key" . ?r cmp:hasName ?name } ORDER BY ?name
```

```json
{
  "dataset": "sample",
  "query_type": "SelectQuery",
  "rows": [
    {
      "name": "api-handler"
    },
    {
      "name": "orders-db"
    },
    {
      "name": "orders-db-credentials"
    },
    "... 1 more"
  ],
  "returned": 4,
  "truncated": false,
  "variable_kinds": {
    "name": "literal"
  }
}
```

The most common classes and properties:

```sparql
SELECT ?class (COUNT(?s) AS ?n) WHERE { ?s a ?class . FILTER(STRSTARTS(STR(?class), STR(cm:))) } GROUP BY ?class ORDER BY DESC(?n) LIMIT 5
```

```json
{
  "dataset": "sample",
  "query_type": "SelectQuery",
  "rows": [
    {
      "class": "cm:SecurityFinding",
      "n": "12"
    },
    {
      "class": "cm:EdgeMetadata",
      "n": "10"
    },
    {
      "class": "cm:TagValue",
      "n": "6"
    },
    "... 2 more"
  ],
  "returned": 5,
  "truncated": false,
  "variable_kinds": {
    "class": "uri",
    "n": "literal"
  }
}
```

```sparql
SELECT ?p (COUNT(*) AS ?n) WHERE { ?s ?p ?o . FILTER(STRSTARTS(STR(?p), STR(cmp:))) } GROUP BY ?p ORDER BY DESC(?n) LIMIT 8
```

```json
{
  "dataset": "sample",
  "query_type": "SelectQuery",
  "rows": [
    {
      "p": "cmp:hasName",
      "n": "57"
    },
    {
      "p": "cmp:hasAccountId",
      "n": "44"
    },
    {
      "p": "cmp:isInternetExposed",
      "n": "44"
    },
    "... 5 more"
  ],
  "returned": 8,
  "truncated": false,
  "variable_kinds": {
    "p": "uri",
    "n": "literal"
  }
}
```

Everything about one individual:

```sparql
DESCRIBE cmr:orders-db
```

```json
{
  "dataset": "sample",
  "query_type": "DescribeQuery",
  "rows": [
    {
      "subject": "cmr:orders-db",
      "predicate": "rdf:type",
      "object": "cm:RelationalDatabase"
    },
    {
      "subject": "cmr:orders-db",
      "predicate": "cmp:hasProvider",
      "object": "AWS"
    },
    {
      "subject": "cmr:orders-db",
      "predicate": "cmp:hasARN",
      "object": "arn:aws:rds:us-east-1:111111111111:db:orders-db"
    },
    "... 8 more"
  ],
  "returned": 11,
  "truncated": false,
  "variable_kinds": {
    "subject": "uri",
    "predicate": "uri",
    "object": "term"
  }
}
```

## Behaviour to be aware of

These are properties of the current code (0.6.0) that callers should know about; each was checked against the capture run and is described in more detail in the entry named.

- The relationship graph keeps one edge per pair of nodes. Parallel security group, NACL and internet-exposure rules are merged into one edge with comma lists in `port_range` and `protocol`, so `graph_stats.graph_edges`, `subgraph_export` and the graph resources show fewer edges than `get_edges`, which reads the raw list ([Graph](#graph)).
- "Internet reachable" in `top_risks`, `reachability_findings`, `internet_exposure(include_reachable=true)` and the attack paths follows network-flow edges only, and the path tools add the identity pivots explicitly. `internet_exposure` items and `find_assets(internet_exposed=true)` use the collector's flag only.
- Error messages never contain the value the caller passed or names from the dataset; read `cloudg/error_data` (`value`, `suggestions`, `valid`) for them ([Errors](#errors)).
- `sparql_query`, `subgraph_export` and the text graph and ontology resources are `restricted`, so any profile with a `confidential` ceiling (`strict`, the `soc-analyst` analyst) hides them; `cloudg://graph/d3` stays available.
- `security_coverage` checks vulnerability scanning for EC2, container registries and Lambda only.
- `cross_account_edges` identifies endpoints by ARN where other graph tools use ids; both forms are valid references.
- The live guard's cooldown applies per scope to every caller, so a second agent asking for the same collection within the cooldown gets `-31029` and the name of the dataset to use instead.
