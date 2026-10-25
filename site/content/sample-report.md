---
title: Sample report
description: The interactive report.html that cloudg writes, built from a synthetic three-cloud estate, so you can see it without an account.
hide:
  - toc
---

This is the `report.html` cloudg writes at the end of `cloudg run`, `cloudg ingest` and `cloudg report`, built from a synthetic estate that spans AWS, Azure and GCP. Every account ID, ARN and finding in it is made up, so nothing here describes a real environment.
{ .lede }

[Open full screen](sample-report.html){ .md-button .md-button--primary target="_blank" rel="noopener" }
[How to read a report](guides/reports.md){ .md-button }

<iframe class="sample-report-frame" src="../sample-report.html" title="cloudg sample report" loading="lazy"></iframe>

## Where it comes from

The direct address of the file is [morpheuslord.github.io/cloudg/sample-report.html](https://morpheuslord.github.io/cloudg/sample-report.html). It is rebuilt from the fixtures the MCP test suite uses, with no cloud access, by a script in the repository:

=== "Rebuild it"

    ```bash
    python scripts/build_sample_report.py              # writes site/static/sample-report.html
    python scripts/build_sample_report.py --out ./tmp  # or anywhere else
    ```

=== "Python"

    The script is a few lines around the same classes you would use yourself. Run it from a clone of the repository, because the fixtures live in `tests/`:

    ```python title="build_sample_report.py"
    from cloudg.graph.builder import GraphBuilder
    from cloudg.renderers.html_report import HTMLReportGenerator
    from cloudg.schema.models import ScanResult
    from tests.mcp.fixtures import sample_estate

    inv = sample_estate.build_inventory()
    result = ScanResult(
        assets=inv.assets,
        edges=inv.edges,
        findings=sample_estate.findings(),
        compliance=sample_estate.compliance(),
    )
    graph = GraphBuilder()
    graph.build(inv.assets, inv.edges)

    path = HTMLReportGenerator(output_dir="./tmp").generate(
        result, graph_json=graph.to_d3_json(), filename="sample-report.html"
    )
    print(path)
    ```

The page is a single self-contained file: Chart.js and D3 are inlined (`report.inline_js`, on by default), so it works offline and can be mailed or attached to a ticket as it is. [Reports](guides/reports.md) explains each tab, and [Output files](reference/output-files.md) lists what else a run writes next to it.
