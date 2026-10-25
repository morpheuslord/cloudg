---
title: Errors and strict mode
description: Get exceptions from the cloudg scanner wrappers instead of recorded failures, check credentials before a run, stop a pipeline at the first failed phase and reject unreadable reports.
---

cloudg is built to keep going: a scanner that times out, a service that refuses a call or a report that will not parse is recorded, and the rest of the run carries on. These scripts show how to turn those records into exceptions when your job should stop instead.
{ .lede }

Every exception cloudg raises on purpose derives from `CloudGError`. [Exceptions](../api/exceptions.md) has the class tree and when each one is raised.

## A scanner that raises

**Offline.** With `strict=True` the first failure is raised at once. Without Checkov on `PATH`, that is a `ScannerNotInstalledError`.

=== "Python"

    ```python title="strict_scanner.py"
    --8<-- "errors/strict_scanner.py"
    ```

=== "Output"

    ```console
    $ python strict_scanner.py
    checkov is missing. pip install checkov
    ```

## Decide after the run

`raise_for_errors()` raises what the last run recorded: one failure as it is, several as a `ScannerFailed` that lists each of them. Nothing recorded, nothing raised.

=== "Python"

    ```python title="raise_for_errors.py"
    --8<-- "errors/raise_for_errors.py"
    ```

=== "Output"

    With a `trivy` on `PATH` that prints something other than JSON:

    ```console
    $ python raise_for_errors.py
    0 findings, 2 failures recorded
     - ScannerOutputError output for nginx:1.27 is not JSON: Expecting value: line 1 column 1 (char 0)
     - ScannerOutputError output for python:3.12-slim is not JSON: Expecting value: line 1 column 1 (char 0)
    failed: trivy: output for nginx:1.27 is not JSON: Expecting value: line 1 column 1 (char 0)
    failed: trivy: output for python:3.12-slim is not JSON: Expecting value: line 1 column 1 (char 0)
    ```

## Check credentials before a run

`CloudGEngine.collect()` records failures per service instead of raising. Build the session yourself first and a missing SDK or a refused role stops the job before anything runs.

=== "Python"

    ```python title="engine_errors.py"
    --8<-- "errors/engine_errors.py"
    ```

=== "Output"

    ```console
    $ pip uninstall -y boto3
    $ python engine_errors.py
    boto3 is not installed: pip install 'cloudg[aws]'
    ```

=== "CLI"

    On the CLI, check the exit status instead. `cloudg run` exits 3 when collection failed for every target, and 0 with a warning when only some failed:

    ```bash
    cloudg run -p aws --profile audit --regions eu-west-1
    echo $?
    ```

## Stop at the first failed phase

Drive the phases yourself and check the `on_error` records between them. Exit status 2 means a phase failed, 0 a complete run.

```python title="fail_fast.py"
--8<-- "errors/fail_fast.py"
```

Without credentials, every AWS service fails and the script stops after the collection with exit status 2, before any scanner starts.

## Reject an unreadable report

**Offline.** Each wrapper's `parse_report(path, strict=True)` raises `ReportParseError` for a file that is not a report, instead of skipping it with a warning.

=== "Python"

    ```python title="strict_parse_report.py"
    --8<-- "errors/strict_parse_report.py"
    ```

=== "Output"

    ```console
    $ echo "not json" > results_json.json
    $ python strict_parse_report.py results_json.json
    checkov report results_json.json is unreadable: output is not JSON: Expecting value: line 1 column 1 (char 0)
    ```

## Related

<div class="grid cards link-cards" markdown>

-   [**Exceptions**](../api/exceptions.md)

    The `CloudGError` hierarchy, attribute by attribute.

-   [**Event hooks**](../api/event-hooks.md)

    `on_error` and the other callbacks.

-   [**cloudg.resilience**](../api/resilience.md)

    Circuit breakers, retry budgets and the errors they raise.

-   [**CI and automation**](../guides/ci-automation.md)

    Exit codes and gates in a pipeline.

</div>
