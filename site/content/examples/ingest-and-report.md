---
title: Ingest and report
description: Merge Prowler, Checkov and Trivy output into one deduplicated result, render the reports, gate a CI job on severity and export the findings.
---

Already ran the scanners somewhere else? Feed cloudg their native output. No cloud credentials and no scanner binaries are needed, and the core package is enough.
{ .lede }

Every script on this page is **offline**. Run [`make_sample_reports.py`](index.md#sample-reports-to-work-with) in an empty directory first, then copy its Trivy image report to the name the scripts read:

```bash
python make_sample_reports.py
cp trivy-image.json trivy.json
```

## Merge reports and render them

=== "CLI"

    ```bash
    cloudg ingest --prowler ./prowler-output/ --checkov ./results_json.json --trivy ./trivy.json -o ./reports
    ```

=== "Python"

    ```python title="ingest_only.py"
    --8<-- "ingest/ingest_only.py"
    ```

=== "Docker"

    ```bash
    docker run --rm \
      -v "$PWD:/app/input:ro" \
      -v "$PWD/reports:/app/reports" \
      ghcr.io/morpheuslord/cloudg:latest \
      ingest --prowler /app/input/prowler-output/ --checkov /app/input/results_json.json --trivy /app/input/trivy.json
    ```

=== "Output"

    ```console
    $ python ingest_only.py
    phase: ingest
    phase: normalisation
    phase: reporting
    3 {'CRITICAL': 1, 'HIGH': 2}
    {'json': PosixPath('reports/findings.json'), 'html': PosixPath('reports/report.html')}
    CRITICAL 9.7 trivy [Trivy] CVE-2024-0001: openssl (alpine)
    HIGH 7.5 prowler S3 bucket default encryption
    HIGH 7.5 checkov [Checkov/terraform] Ensure S3 bucket has server-side encryption enabled
    ```

`reports/report.html` is the page shown in the [sample report](../sample-report.md), filled with these three findings.

## Parse first, decide later

`parse_report()` reads one report into `Finding` objects without normalising anything, so you can filter or enrich them before the merge. `ingest_reports()` does several at once and skips files it cannot read.

=== "Python"

    ```python title="parse_first.py"
    --8<-- "ingest/parse_first.py"
    ```

=== "Output"

    ```console
    $ python parse_first.py
    INFO cloudg.scanners.prowler: Parsed 1 findings from Prowler (1 passed checks)
    INFO cloudg.scanners.checkov: Parsed 1 findings from Checkov
    INFO cloudg.scanners.trivy: Parsed 1 findings from Trivy for myrepo/app:latest
    INFO cloudg.ingest: [trivy] 1 findings ingested from ./trivy.json
    ERROR cloudg.ingest: Skipping trivy report ./missing.json: Report path does not exist: ./missing.json
    ERROR cloudg.ingest: Skipping trivvy report ./trivy.json: Unsupported tool 'trivvy'. Supported: prowler, scoutsuite, checkov, trivy
    INFO cloudg.normaliser: Normalising 3 total findings from 2 sources
    INFO cloudg.normaliser: After deduplication: 3 findings
    ('prowler', 'scoutsuite', 'checkov', 'trivy')
    2 findings from two reports
    1 findings from the batch
    ValueError: Unsupported tool 'grype'. Supported: prowler, scoutsuite, checkov, trivy
    {'CRITICAL': 1, 'HIGH': 2} 31 control results
    ```

The unknown tool raises `ConfigurationError`, which is a `ValueError`, so the `except ValueError` in the script catches it. [Exceptions](../api/exceptions.md) has the strict variant that raises on an unreadable file as well.

## Merge findings from your own tools

`FindingsNormaliser` takes lists of `Finding` objects from any source. Findings from two scanners about the same check on the same resource are merged into one, with both tools listed.

=== "Python"

    ```python title="normalise_demo.py"
    --8<-- "ingest/normalise_demo.py"
    ```

=== "Output"

    ```console
    $ python normalise_demo.py
    CRITICAL  9.7 trivy            openssl: buffer overflow ['HIPAA', 'NIST-800-53', 'PCI-DSS', 'SOC2']
    HIGH      7.5 trivy, prowler   [Trivy] S3 bucket default encryption ['GDPR-AWS', 'HIPAA-AWS', 'ISO27001-AWS', 'MITRE-ATTACK-AWS']
    LOW       2.5 custom           CloudTrail logging disabled in eu-west-1 ['GDPR', 'HIPAA', 'ISO-27001', 'NIST-800-53']
    38 compliance results
    ```

## Gate a CI job on severity

Write a summary the pipeline can archive, and exit non-zero when anything critical or high turns up.

=== "Python"

    ```python title="save_result.py"
    --8<-- "ingest/save_result.py"
    ```

=== "Output"

    ```console
    $ python save_result.py
    {
      "total_assets": 0,
      "total_findings": 2,
      "severity_breakdown": {
        "CRITICAL": 1,
        "HIGH": 1
      },
      "providers_scanned": [],
      "regions_scanned": {},
      "graph_nodes": 0,
      "graph_edges": 0,
      "ontology_triples": 0,
      "attack_paths_count": 0,
      "duration_ms": 1219,
      "errors": []
    }
    2 critical/high findings, failing the build
    $ echo $?
    1
    ```

=== "GitHub Actions"

    ```yaml title=".github/workflows/scan-gate.yml"
    jobs:
      gate:
        runs-on: ubuntu-latest
        steps:
          - uses: actions/checkout@v4
          - uses: actions/setup-python@v5
            with:
              python-version: "3.12"
          - run: pip install cloudg
          # results_json.json and trivy.json come from earlier steps or artifacts
          - run: python save_result.py
          - uses: actions/upload-artifact@v4
            if: always()
            with:
              name: cloudg-reports
              path: reports/
    ```

[CI and automation](../guides/ci-automation.md) has complete workflows for GitHub Actions, GitLab and scheduled scans.

## Re-render a report, or export the raw findings

=== "CLI"

    ```bash
    cloudg report -i ./reports/findings.json -o ./rendered --format all
    cloudg report -i ./reports/raw-findings.json -o ./rendered
    ```

=== "Python"

    ```python title="export_findings.py"
    --8<-- "ingest/export_findings.py"
    ```

=== "Output"

    ```console
    $ python export_findings.py
    wrote 3 findings to reports/raw-findings.json
    ```

`cloudg report` reads either file: a `findings.json` keeps its scan ID, compliance results and edges, and a `raw-findings.json` is normalised first.

## Related

<div class="grid cards link-cards" markdown>

-   [**Ingesting existing output**](../guides/ingesting.md)

    What each scanner's output must look like, and how deduplication works.

-   [**parse_report**](../api/parse-report.md)

    `parse_report()` and `ingest_reports()` in detail.

-   [**FindingsNormaliser**](../api/findingsnormaliser.md)

    Merging, CVSS rescoring and compliance mapping.

-   [**cloudg ingest**](../cli/ingest.md)

    Every flag of the command.

</div>
