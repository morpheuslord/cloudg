---
command: report
lede: Re-renders the HTML, JSON and SVG reports from a `findings.json` you already have. No cloud access and no scanners.
intro: |
  Use `cloudg report` after upgrading cloudg to get the newer HTML template, or to rebuild one format you skipped. Read the notes on what does not survive the round trip before you point it at your only copy of a report.
---

## How it works

`-i/--input` names a `findings.json` written by `cloudg run`, `cloudg ingest` or `CloudGEngine`. cloudg reads three keys from it:

| Key | Used for |
|---|---|
| `assets` | Validated back into `CloudAsset` objects |
| `findings` | Validated back into `Finding` objects |
| `graph` | The D3 `{nodes, links}` block, passed to the JSON and HTML renderers as is |

From the assets and findings it builds a fresh `ScanResult` and renders the formats `--format` names: `json`, `svg`, `html`, or `all` (the default). The output goes to `-o/--output`, `./reports` unless you say otherwise.

Nothing is normalised again and the config file plays no part.

### What is lost on the way

The `compliance` list and the edges in `findings.json` are not read back. The re-rendered files therefore differ from the originals in a few ways. This comparison is from a report built on the synthetic estate in the test suite:

| Field | Original `findings.json` | After `cloudg report` |
|---|---|---|
| `compliance` | 8 entries | empty |
| `summary.compliance_frameworks` | 5 frameworks | empty |
| `summary.total_edges` | 56 | 0 |
| `metadata.scan_id` | original ID | a new ID |
| `assets`, `findings`, `graph` | as written | unchanged |

In practice the HTML report keeps its topology (it uses the `graph` block) and its findings table, but its compliance matrix is empty. `topology.svg` is drawn from the edges, which are not loaded, so it shows the assets without connections.

:::warning Don't overwrite the source
`-i ./reports/findings.json` with the default `-o ./reports` replaces the input with the reduced version above. Write to another directory:

```bash
cloudg report -i ./reports/findings.json -o ./reports/rerendered
```
:::

`report` only accepts the report shape, an object with those keys. A `raw-findings.json` is a bare JSON list and makes the command fail with `AttributeError: 'list' object has no attribute 'get'`. To build reports from raw findings, pass the scanner files to [cloudg ingest](/cli/ingest/) instead.

A successful run prints one line per file:

```console
$ cloudg report -i ./reports/findings.json -o rep
─────────────────────────── Report Generation ───────────────────────────
  ✓ JSON: rep/findings.json
  ✓ SVG: rep/topology.svg
  ✓ HTML: rep/report.html
```

(Log lines are left out.)

## Examples

Rebuild only the HTML report, for example after upgrading cloudg:

```bash
cloudg report -i ./reports/findings.json --format html -o ./reports/html
```

Rebuild every format into a new folder:

```bash
cloudg report -i ./reports/2026-10-01/findings.json -o ./reports/2026-10-01-rerendered
```

Draw a topology picture of an inventory map. `inventory-map.json` has an `assets` key, so `report` accepts it; the picture has no edges for the reason above:

```bash
cloudg report -i ./reports/inventory-map.json --format svg -o ./reports/svg
```

Render from Python instead when you want to keep the compliance results:

```bash tab="CLI"
cloudg report -i ./reports/findings.json --format html -o ./reports/html
```

```python tab="Python" title="rerender.py"
import json
from pathlib import Path

from cloudg.renderers.html_report import HTMLReportGenerator
from cloudg.schema.models import CloudAsset, ComplianceResult, Finding, ScanResult

data = json.loads(Path("./reports/findings.json").read_text())
scan_result = ScanResult(
    assets=[CloudAsset.model_validate(a) for a in data.get("assets", [])],
    findings=[Finding.model_validate(f) for f in data.get("findings", [])],
    compliance=[ComplianceResult.model_validate(c) for c in data.get("compliance", [])],
)
out = HTMLReportGenerator(output_dir="./reports/html").generate(
    scan_result, graph_json=data.get("graph")
)
print(out)
```

## Output files

| File | Written when | Contents |
|---|---|---|
| `findings.json` | `--format json` or `all` | The rebuilt result, with the losses listed above |
| `topology.svg` | `--format svg` or `all` | Asset picture without edges |
| `report.html` | `--format html` or `all` | Interactive report; findings and topology intact, compliance matrix empty |

## Exit codes

| Code | When |
|---|---|
| 0 | All requested formats were written |
| 1 | The input file does not exist ("Input file not found"), or it is not a report object and the command fails with a traceback |
| 2 | `-i` is missing or `--format` has an unknown value |

## Related

:::links
- [Reports](/guides/reports/) What is in the HTML report and how to read it.
- [Output files](/reference/output-files/) The `findings.json` format.
- [cloudg ingest](/cli/ingest/) Build reports from scanner output.
- [Output flags](/cli/output-flags/) `-o` and `--format` across commands.
:::
