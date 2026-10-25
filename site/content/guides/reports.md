---
title: Reports
description: 'Every path through cloudg ends in the same two files: findings.json for machines and report.html for people. cloudg report rebuilds them from an earlier run without touching the cloud.'
---

Every path through cloudg ends in the same two files: `findings.json` for machines and `report.html` for people. `cloudg report` rebuilds them from an earlier run without touching the cloud.
{ .lede }

**Command** `cloudg report` &middot; **Formats** HTML, JSON, SVG &middot; **Python** `JSONExporter`, `HTMLReportGenerator`, `SVGRenderer` &middot; **Last changed** [v0.6.0](../changelog.md#0.6.0)
{ .page-meta }

The renderers in `cloudg/renderers/` take a normalised `ScanResult` (assets, findings, compliance results) plus, when there is one, the D3 graph of the collected assets. They don't call any cloud API or scanner, which is why `cloudg report` can re-render an old run anywhere.

## Which command writes what

```mermaid
flowchart LR
  RUN["cloudg run"] --> SR["ScanResult and graph"]
  ING["cloudg ingest"] --> SR
  FJ["findings.json from an earlier run"] -->|"cloudg report -i"| SR
  SR --> JSON["findings.json"]
  SR --> HTML["report.html"]
  SR --> SVG["topology.svg"]
  SCAN["cloudg scan, cloudg ingest"] --> RAW["raw-findings.json"]
```
Report inputs and outputs
{ .diagram-caption }

| Command | `findings.json` | `report.html` | `topology.svg` | `raw-findings.json` |
|---|---|---|---|---|
| `cloudg run` | Yes | Yes | Yes | No |
| `cloudg ingest` | With `--format json` or `all` | With `--format html` or `all` | No | Always |
| `cloudg report` | With `--format json` or `all` | With `--format html` or `all` | With `--format svg` or `all` | No |
| `cloudg scan` | No | No | No | Always |
| `run_pipeline()` | Yes | Yes | Yes | No |
| `run_from_reports()` | Yes | Yes | No | No |

`cloudg run`, `run_pipeline()` and `run_from_reports()` write the formats listed in `report.formats`, all three by default. `run_from_reports()` never writes `topology.svg`, because it has no collected assets to draw. `cloudg ingest` and `cloudg report` go by `--format` instead.

`cloudg run` writes more than these (GraphML, Cytoscape JSON when `graph.export_cytoscape` is on, the ontology, RAG chunks, Terraform); those come from the graph and analysis phases and are listed on [Output files](../reference/output-files.md).

Those three are the only report formats. There is no CSV, SARIF or PDF writer in 0.6.0. `findings.json` is easy to convert, though; there's a [CSV recipe](#exporting-to-csv) further down.

## findings.json

`JSONExporter` writes one JSON object with seven keys:

```json title="findings.json"
{
  "metadata": {
    "scan_id": "79964dcf-69c0-4bcb-9d69-2261811e2f67",
    "provider": null,
    "account_id": null,
    "region": null,
    "started_at": "2026-10-10T05:47:10.313561",
    "completed_at": "2026-10-10T05:47:10.313549"
  },
  "summary": {
    "total_assets": 0,
    "total_findings": 5,
    "total_edges": 0,
    "severity_breakdown": {"CRITICAL": 2, "HIGH": 3},
    "compliance_frameworks": ["CIS", "CIS-AWS", "CVE", "NIST-CSF-AWS"]
  },
  "assets": [],
  "findings": [],
  "compliance": [],
  "edges": [],
  "graph": {"nodes": [], "links": []}
}
```

`assets`, `findings`, `compliance` and `edges` are the Pydantic models from `cloudg.schema.models`, serialised in JSON mode. Assets leave out `raw_data`. Findings include the computed `risk_score`. `edges` holds the collected `NetworkEdge` objects, so `cloudg report` can draw the topology again. `graph` holds D3 nodes and links for `cloudg run`, and is empty for ingest. In the `metadata` block, the normaliser doesn't fill in `provider`, `account_id` or `region` in 0.6.0, so expect `null` there. Both timestamps are ISO 8601 strings set at normalisation time, and a `completed_at` that was never set is `null`. The field-by-field reference is on [Output files](../reference/output-files.md), and the models are on [Data models](../api/models.md).

`raw-findings.json` is different: a bare JSON list of `Finding` objects as the parsers produced them, before deduplication, rescoring or compliance mapping. It has no `summary`, `compliance` or `graph`.

## report.html

The HTML report is one file rendered from the Jinja template `cloudg/templates/report.html.j2`. The data is embedded in the page as JSON, and so are Chart.js 4.4.0, D3 7.9.0 and the two engines that draw the map, so the page works offline. You can mail it, attach it to a ticket or archive it next to `findings.json`. The [sample report](../sample-report.md) shows one built from a synthetic three-cloud estate.

The overview at the top gives the scan ID, provider, account and start time, four counters (assets, findings, critical findings and internet-exposed assets) and a bar of findings by severity. Beside it, a ring shows the share of assets with no open findings, and the top risks list holds the six worst findings; clicking one opens it. The top bar switches between the dark and light themes (the choice is remembered in the browser), prints the page, and downloads the findings as CSV or the embedded data as JSON. Below are five tabs.

### The estate map

The Estate map tab draws the estate in three dimensions. Each provider is a base plate. Accounts and regions stand on it as platforms, VPCs and VNets as slabs and subnets as tiles, and every asset stands where it was found, as a small solid whose shape says what kind of asset it is. Identity and governance assets (roles, users, policies, organizations, accounts) sit on a control deck held on posts behind and above the plate. An asset with open findings carries a beacon in the colour of its worst one, an internet-exposed asset has a dashed red ring at its foot, and the internet itself is a mast in front of the plates.

Placement comes from the collected `CONTAINS` edges first and from each asset's `vpc_id` / `subnet_id` metadata after that. Every other relation is a trace line: it leaves its source from a port of its own on the asset's top face, rises to a lane that no other trace uses, runs along the floor plan and drops onto its own port on the target. Trace lines are coloured by family: internet exposure, network paths, identity and access, data and invocation, and governance and protection. The chips above the map hide or show each family. Parallel edges between the same two assets collapse into one trace that counts them.

- Click an asset to light its relations and dim everything else. A dot runs along each lit trace from source to target, and the inspector beside the map lists the asset's details and its relations. Click a relation there to follow that one alone.
- **Trace from internet** lights every path that starts at the internet mast, hop after hop, and says how many assets it reaches.
- Drag to pan, scroll to zoom, and use the turn buttons (or `[` and `]`) to turn the map a quarter at a time. Arrow keys step through the assets, `0` fits the map and Escape clears the selection.
- **Labels** names every asset; without it, names show for the asset under the pointer and the selected asset's neighbours. **Replay** plays the opening animation again, and **Find an asset** jumps to one by name or identifier.

The layout is computed in Python, in `cloudg.renderers.iso_scene.build_scene()`, so it is the same in every browser and is covered by tests. The page projects it with the [Anatomy](https://github.com/wheresryan22/anatomy) iso-kit and animates it. Under reduced motion, nothing moves.

The **2D** switch shows the earlier views: a D3 tree of account, region, VPC, subnet and resources, and a force-directed graph of the collected graph plus one node per finding (linked to its resource by `FINDING_AFFECTS`) and one per compliance framework (linked to its findings by `COMPLIANCE_GOVERNS`). The report opens on the 2D view by itself when the scan has no assets (as after `cloudg ingest`), when it has more than 2500 assets, or when the map engines are missing from the package.

### The other tabs

The Findings tab lists every finding with dropdown filters for severity and source tool and a text search over title, resource and description. Clicking a row, filtered or not, opens a side panel for that finding with the description, evidence, remediation, CVSS score, frameworks and risk score. A filter that matches nothing shows an empty tray, drawn with [Hairline](https://hairline.lucasmarkes.com).

Assets lists every asset with its type, provider, region, exposure and finding count, with a provider filter and a search. Clicking a row opens it on the map.

Analytics has four Chart.js charts: severity distribution, the twelve most common asset types, findings by source tool, and compliance per framework.

Compliance shows one card per framework with its pass rate and Pass and Fail counts. As explained in [Compliance frameworks](compliance.md#report-html), Fail counts the controls that have findings, and Pass counts the controls that only Prowler's passing checks map to. Without passing-check data in the input (no Prowler, or scanners that only report failures), Pass is 0 and the rate reads 0%.

The JSON download saves a file named `findings.json` that holds `findings`, `assets`, `graph`, the tree data and the map's scene. It isn't the same file cloudg writes, but `cloudg report -i` and the viewer both accept it. The CSV download has one row per finding; a cell that starts with `=`, `+`, `-` or `@` gets a leading apostrophe so a spreadsheet does not run it as a formula.

Chart.js and D3 come from `cloudg/templates/vendor/` in the package and add about 485 KB to the file. With `report.inline_js: false` the page loads the same pinned builds from `cdn.jsdelivr.net` instead, with Subresource Integrity hashes, which gives a smaller file that needs network access to show the charts and the 2D views. The map engines (about 64 KB) have no CDN build and are embedded either way.

Everything that comes from scanner output or cloud metadata (titles, descriptions, evidence, resource ids, asset names, framework names) is HTML-escaped before it reaches the page, and the embedded JSON cannot close its `<script>` element early. A report built from someone else's scan files is safe to open.

If the template can't be found or fails to render, cloudg logs a warning and writes a plain fallback page instead: the counters and a findings table, with no script at all.

## topology.svg

`SVGRenderer` draws a static map of the collected assets: VPCs and VNets as containers, subnets inside them, compute, databases and functions inside the subnets, and IAM principals and security groups in side panels. It needs assets, so it only means something after `cloudg run`, or after `cloudg report` on a `findings.json` that has assets.

## cloudg report

`cloudg report` reads a `findings.json` and renders it again. Use it to regenerate the HTML after upgrading cloudg, to produce just the SVG, or to rebuild a report on a machine that never had cloud access.

=== "CLI"

    ```bash
    cloudg report -i ./reports/findings.json -o ./reports-rerendered
    cloudg report -i ./reports/findings.json -o ./reports-rerendered --format html
    cloudg report -i ./archive/2026-09-30/findings.json -o ./archive/2026-09-30/svg --format svg
    ```

=== "Docker"

    ```bash
    docker run --rm \
      -v "$PWD/reports:/data" \
      ghcr.io/morpheuslord/cloudg:latest report -i /data/findings.json -o /data/rerendered
    ```

| Flag | Meaning |
|---|---|
| `-i, --input` | Path to a `findings.json`, or a `raw-findings.json`. Required. |
| `-o, --output` | Output directory, `./reports` by default |
| `--format` | `html`, `json`, `svg` or `all` (default) |
| `--overwrite` | Allow writing `findings.json` over the input file |

A missing input file prints `Input file not found` and exits with code 1.

`cloudg report` restores the whole run from a `findings.json`:

| In the input | After `cloudg report` |
|---|---|
| `assets`, `findings`, `graph` | Kept |
| `compliance` | Kept, so the Compliance tab and chart show the same results |
| `edges` | Kept, so `topology.svg` has its connections. A `findings.json` written before the `edges` key existed gets its edges rebuilt from the `graph` links. |
| `metadata` | Kept: scan ID, provider, account, region, `started_at` and `completed_at` |

Given a `raw-findings.json` (the bare list from `cloudg scan` or `cloudg ingest`), `cloudg report` normalises it first: deduplication, scoring and compliance mapping, as `cloudg ingest` does.

`-o` defaults to `./reports`, which is also where `cloudg run` and `cloudg ingest` write. So that `cloudg report -i ./reports/findings.json` doesn't replace its own input, the command refuses to write `findings.json` over the input file and exits with code 1:

```console
$ cloudg report -i ./reports/findings.json
────────────────────────────── Report Generation ───────────────────────────────
╭───────────────────── ✗ Refusing to overwrite the input ──────────────────────╮
│ reports/findings.json would be replaced by the new findings.json. Pass -o    │
│ <another directory>, --format html/svg, or --overwrite.                      │
╰──────────────────────────────────────────────────────────────────────────────╯
```

Give `-o` another directory, render only `--format html` or `svg`, or pass `--overwrite` when replacing the file is what you want.

## Rendering from Python

The three renderers are plain classes. Each takes an output directory and writes one file, returning its path.

| Class | Call | Default file |
|---|---|---|
| `cloudg.renderers.json_export.JSONExporter(output_dir=".")` | `.export(scan_result, graph_json=None, filename="findings.json")` | `findings.json` |
| `cloudg.renderers.html_report.HTMLReportGenerator(template_dir=None, output_dir=".", inline_js=True)` | `.generate(scan_result, graph_json=None, filename="report.html")` | `report.html` |
| `cloudg.renderers.svg.SVGRenderer(output_dir=".")` | `.render(assets, edges, findings_by_resource=None, filename="topology.svg", width=1800, height=1400)` | `topology.svg` |

### From raw findings {#from-raw-findings}

`raw-findings.json` from `cloudg scan` (or `cloudg ingest`) hasn't been normalised yet. `cloudg report -i raw-findings.json` normalises and renders it in one step; in Python, load it, normalise it, then render:

```python title="raw_to_reports.py"
import json
from pathlib import Path

from cloudg import CloudGConfig, CloudGEngine
from cloudg.renderers.html_report import HTMLReportGenerator
from cloudg.renderers.json_export import JSONExporter
from cloudg.schema.models import Finding

raw = json.loads(Path("./reports/raw-findings.json").read_text())
findings = [Finding.model_validate(item) for item in raw]

engine = CloudGEngine(CloudGConfig())
scan_result = engine.normalise_findings(findings)

out = "./reports-from-raw"
print(JSONExporter(output_dir=out).export(scan_result))
print(HTMLReportGenerator(output_dir=out).generate(scan_result))
print(len(scan_result.compliance), "compliance results")
```

`normalise_findings()` uses `config.rulesets.rules_dir`, so a custom ruleset applies here too.

### Your own template

`HTMLReportGenerator(template_dir=...)` renders a `report.html.j2` from that directory instead of the packaged one. Copy `cloudg/templates/report.html.j2`, change it, and pass the directory. The variables available to a template are `scan_id`, `provider`, `account_id`, `started_at`, `completed_at`, `total_assets`, `total_findings`, `severity_counts`, `resource_types`, `source_tools`, `compliance_summary`, `findings` and `assets`, plus JSON-string versions (`severity_counts_json`, `resource_types_json`, `source_tools_json`, `compliance_summary_json`, `findings_json`, `assets_json`, `graph_json`, `hierarchy_json`, `findings_per_resource_json`) for embedding in scripts. The JSON strings are already safe inside a `<script>` element; mark them `|safe` there. For the libraries, `inline_js` says whether to embed them, `vendored_js.chartjs` and `vendored_js.d3` hold their source, and `cdn_js` holds the pinned CDN URLs and integrity hashes. The map adds `scene_json` (the output of `build_scene()`), `summary` and `summary_json` (providers, accounts, regions, exposed and clean asset counts, edge count and cloudg version) and `top_risks_json` (the indexes of the six worst findings), and `map_js` holds the source of the map engines and the empty-state figure, or nothing when they are missing. Autoescaping is on, so any other value you print is escaped.

### Exporting to CSV {#exporting-to-csv}

For a spreadsheet or a ticketing import, flatten the findings:

```python title="findings_to_csv.py"
import csv
import json
from pathlib import Path

data = json.loads(Path("./reports/findings.json").read_text())
columns = ["severity", "risk_score", "source_tool", "title", "resource_arn",
           "source_finding_id", "compliance_frameworks", "remediation"]

with open("findings.csv", "w", newline="") as fh:
    writer = csv.DictWriter(fh, fieldnames=columns, extrasaction="ignore")
    writer.writeheader()
    for finding in data["findings"]:
        row = dict(finding)
        row["compliance_frameworks"] = ";".join(finding.get("compliance_frameworks", []))
        writer.writerow(row)

print("wrote", len(data["findings"]), "rows to findings.csv")
```

## The report viewer

`docs/viewer.html` in the repository is a standalone page for browsing results without generating anything. Open it in a browser and drop a file on it, or use Open a report. It reads `findings.json` from `cloudg run`, `cloudg ingest` or `cloudg report`, and the bare list in `raw-findings.json` from `cloudg scan`. The file is parsed in the browser and not uploaded anywhere. The page starts with built-in sample data, marked with a "sample data" badge, until you load your own.

It shows severity and tool counts, failed compliance controls per framework (top ten), the most affected resources, a sortable and filterable findings table, and the topology when the file has graph data. Raw findings have no compliance or graph, and the page says so. Unlike the report, it loads D3 from a CDN (`cdnjs.cloudflare.com`).

## Configuration

`config.yaml` has a `report:` section:

```yaml title="config.yaml"
report:
  formats: [html, json, svg]
  inline_js: true
  output_dir: ./reports
```

`formats` lists the reports that `cloudg run`, `run_pipeline()` and `run_from_reports()` write; unknown names are dropped with a warning. `cloudg ingest` and `cloudg report` use `--format` instead. `inline_js` embeds Chart.js and D3 in `report.html` (`true`, the default) or loads them from the CDN (`false`); every command that writes the HTML report reads it. `output_dir` is where the `CloudGEngine` methods write when they get no `output_dir`, and the MCP server's default workspace directory. The CLI commands use `-o` (default `./reports`) and ignore it. The keys are listed on the [report config page](../reference/config/report.md).

## Next

<div class="grid cards link-cards" markdown>

-   [**cloudg report**](../cli/report.md)

    The command reference.

-   [**Output files**](../reference/output-files.md)

    Every file cloudg writes, field by field.

-   [**Compliance frameworks**](compliance.md)

    What the compliance output means.

-   [**Ingesting existing output**](ingesting.md)

    Reports from scans that ran elsewhere.

</div>
