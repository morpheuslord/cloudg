---
title: Examples
description: Complete cloudg scripts for mapping, ingesting, graph exports and error handling, each shown next to the CLI command that does the same and the output it prints.
---

Complete scripts you can save and run, each next to the CLI command that does the same job and the output it printed when these pages were written. They are the files in [`site/examples/`](https://github.com/morpheuslord/cloudg/tree/main/site/examples), included into the pages as they are.
{ .lede }

Most of them need no cloud account. Those marked **offline** build a small estate by hand or read sample scanner reports, so they run on any machine with `pip install cloudg`. The others say which credentials they need.

## Sample reports to work with

The ingest examples read native scanner output. If you have none at hand, this script writes one small report per scanner (Prowler ASFF, ScoutSuite, Checkov and two Trivy reports), shaped like the real tools' output:

??? example "make_sample_reports.py"

    ```python title="make_sample_reports.py"
    --8<-- "make_sample_reports.py"
    ```

Run it in an empty directory, then run the examples from the same directory.

## By task

<div class="grid cards" markdown>

-   :material-map-search-outline:{ .lg .middle } **[Map and query](map-and-query.md)**

    ---

    Map an account, save the map, load it again and ask what depends on what.

-   :material-file-import-outline:{ .lg .middle } **[Ingest and report](ingest-and-report.md)**

    ---

    Merge Prowler, Checkov and Trivy output, gate a CI job on severity and export the findings.

-   :material-graph-outline:{ .lg .middle } **[Graph, ontology and RAG](graph-and-exports.md)**

    ---

    Build the graph from your own assets, find what the internet reaches, query it with SPARQL, cut RAG chunks.

-   :material-alert-octagon-outline:{ .lg .middle } **[Errors and strict mode](errors.md)**

    ---

    Strict scanner wrappers, `raise_for_errors()`, credential checks and strict report parsing.

</div>

## More examples

Every page of the [Python API](../api/index.md) reference has its own examples above the generated reference, and [Python recipes](../guides/python-recipes.md) collects the longer integrations: streaming findings to a SIEM, combining a live inventory with ingested findings, and linking assets from a CMDB.
