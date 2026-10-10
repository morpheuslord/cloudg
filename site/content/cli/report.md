---
command: report
lede: Re-renders the HTML, JSON and SVG reports from a `findings.json` you already have. No cloud access and no scanners.
intro: |
  Use `cloudg report` after upgrading cloudg to get the newer HTML template, or to rebuild one format you skipped. It also turns a `raw-findings.json` into reports.
---

## How it works

`-i/--input` names a `findings.json` written by `cloudg run`, `cloudg ingest` or `CloudGEngine`, or a `raw-findings.json` from `cloudg scan` or `cloudg ingest`.

A `findings.json` is restored as it was written:

| Key | Used for |
|---|---|
| `metadata` | Scan ID, provider, account, region, `started_at` and `completed_at`, kept as they were |
| `assets` | Validated back into `CloudAsset` objects |
| `findings` | Validated back into `Finding` objects |
| `compliance` | Validated back into `ComplianceResult` objects |
| `edges` | Validated back into `NetworkEdge` objects, for `topology.svg`. A `findings.json` written before this key existed gets its edges rebuilt from the `graph` links |
| `graph` | The D3 `{nodes, links}` block, passed to the JSON and HTML renderers as is |

Nothing is normalised again, so the output matches the input. On a report built from the synthetic estate in the test suite, the rewritten `findings.json` has the same metadata, the same 44 assets, 12 findings, 10 compliance results and 56 edges, and the same graph.

A `raw-findings.json` is a bare JSON list of findings from before normalisation. `cloudg report` normalises it first (deduplication, scoring, compliance mapping, with the rulesets from `rulesets.rules_dir`), as `cloudg ingest` does. Any other JSON stops the command with "Could not read the input" and exit status 1.

The formats `--format` names are rendered: `json`, `svg`, `html`, or `all` (the default). The output goes to `-o/--output`, `./reports` unless you say otherwise. `report.html` embeds Chart.js and D3 unless `report.inline_js` is `false` in the config.

### Writing over the input

`-i ./reports/findings.json` with the default `-o ./reports` would replace the input. `cloudg report` refuses that and exits with status 1:

```console
$ cloudg report -i ./reports/findings.json
────────────────────────────── Report Generation ───────────────────────────────
╭───────────────────── ✗ Refusing to overwrite the input ──────────────────────╮
│ reports/findings.json would be replaced by the new findings.json. Pass -o    │
│ <another directory>, --format html/svg, or --overwrite.                      │
╰──────────────────────────────────────────────────────────────────────────────╯
```

Write to another directory, render only `--format html` or `--format svg`, or pass `--overwrite` when replacing the file is what you want:

```bash
cloudg report -i ./reports/findings.json -o ./reports/rerendered
```

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

Draw a topology picture of an inventory map. `inventory-map.json` has `assets` and `edges` keys, so `report` accepts it:

```bash
cloudg report -i ./reports/inventory-map.json --format svg -o ./reports/svg
```

Turn the raw findings of `cloudg scan` into reports:

```bash
cloudg report -i ./reports/raw-findings.json -o ./reports/scan-report
```

## Output files

| File | Written when | Contents |
|---|---|---|
| `findings.json` | `--format json` or `all` | The restored result (or the normalised one, from raw findings) |
| `topology.svg` | `--format svg` or `all` | Picture of the assets and their edges |
| `report.html` | `--format html` or `all` | Interactive report with findings, topology and compliance |

## Exit codes

| Code | When |
|---|---|
| 0 | All requested formats were written |
| 1 | The input file does not exist ("Input file not found"), it is neither a `findings.json` nor a `raw-findings.json` ("Could not read the input"), or `findings.json` would be written over the input without `--overwrite` |
| 2 | `-i` is missing or `--format` has an unknown value |

## Related

:::links
- [Reports](/guides/reports/) What is in the HTML report and how to read it.
- [Output files](/reference/output-files/) The `findings.json` format.
- [cloudg ingest](/cli/ingest/) Build reports from scanner output.
- [Output flags](/cli/output-flags/) `-o` and `--format` across commands.
:::
