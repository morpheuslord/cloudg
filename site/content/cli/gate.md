---
description: Fails a CI job when a findings.json holds findings at or above a severity, and writes SARIF for code scanning and a Markdown job summary.
command: gate
---

Fails a CI job when a `findings.json` holds findings at or above a severity, and writes SARIF for code scanning and a Markdown job summary.
{ .lede }

`cloudg run`, `cloudg ingest` and `cloudg report` exit 0 whatever they find. `cloudg gate` is the command that decides on findings. Run it after any of them, in the same job. It needs no cloud access and no scanner, only the `findings.json`, so the core `cloudg` package is enough to install. The [GitHub Action](../guides/ci-automation.md#the-github-action) runs it for you.

<!-- cloudg:cli-reference -->

## How it works

`-i/--input` takes a `findings.json`, the directory that holds one (`./reports` by default), or a `raw-findings.json`, which is normalised first as [`cloudg report`](report.md) does.

The gate counts every finding at `--fail-on` or above. Suppressed findings (`is_suppressed: true`) never count, and the summary reports how many were left out. It fails when more than `--max` findings are left, or when the run collected fewer assets than `--min-assets`. A live run that collected zero assets usually means the credentials did not work, so set `--min-assets 1` there. Leave it at 0 for findings from `cloudg ingest`, which never collects assets.

| Exit status | Meaning |
|---|---|
| 0 | The gate passed |
| 4 | The gate failed: too many blocking findings, or too few assets |
| 1 | The input does not exist or cannot be read |
| 2 | A usage error, such as an unknown `--fail-on` value |

Status 4 is distinct on purpose. A pipeline can then tell "the gate found something" from "the gate could not run".

On the `findings.json` in the repository's test fixtures (two AWS assets, four findings, one of them suppressed):

```console
$ cloudg gate -i reports --fail-on high --sarif reports/cloudg.sarif
──────────────────────────────── Security Gate ─────────────────────────────────
Findings by severity
╭──────────┬───────╮
│ Metric   │ Value │
├──────────┼───────┤
│ CRITICAL │     1 │
│ HIGH     │     1 │
│ MEDIUM   │     0 │
│ LOW      │     1 │
│ INFO     │     0 │
╰──────────┴───────╯
                               Blocking findings
╭───────────────────────────┬──────────┬────────────┬──────────────────────────╮
│ Finding                   │ Severity │       Tool │                 Resource │
├───────────────────────────┼──────────┼────────────┼──────────────────────────┤
│ Security group allows SSH │ CRITICAL │    prowler │ arn:aws:ec2:us-east-1:1… │
│ (22) from 0.0.0.0/0       │          │            │                          │
│ S3 bucket allows public   │     HIGH │ scoutsuite │   arn:aws:s3:::prod-logs │
│ read                      │          │            │                          │
╰───────────────────────────┴──────────┴────────────┴──────────────────────────╯
  ✗ Gate failed: 2 finding(s) at HIGH or above, 0 allowed
  ✓ SARIF: reports/cloudg.sarif
```

The exit status is 4. The table lists the 25 worst blocking findings, by severity and then risk score.

### Only report

`--fail-on never` counts and writes everything but never fails. Use it while you tune suppressions, or on a job that should publish SARIF without blocking anything.

### JSON on stdout

`--json` prints the verdict as one JSON document on stdout, and moves the banner and the tables to stderr, so the output can go straight to `jq` or a file:

```console
$ cloudg gate -i reports --fail-on critical --max 1 --json 2>/dev/null
{
  "passed": true,
  "reason": "",
  "fail_on": "CRITICAL",
  "max": 1,
  "blocking": 1,
  "total_findings": 3,
  "suppressed": 1,
  "total_assets": 2,
  "min_assets": 0,
  "counts": {
    "CRITICAL": 1,
    "HIGH": 1,
    "MEDIUM": 0,
    "LOW": 1,
    "INFO": 0
  }
}
```

`total_findings` and `counts` leave out suppressed findings. `reason` is empty when the gate passed.

### SARIF

`--sarif FILE` writes the findings as SARIF 2.1.0, the format GitHub code scanning and most security dashboards import. cloudg findings point at cloud resources, not at lines of code, so each result's location is a stable path made from the resource, such as `cloud/aws/111111111111/us-east-1/sg-admin`. The ARN goes in a logical location as well. Code scanning shows these alerts without a code snippet.

Each scanner check becomes one rule (`prowler/ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_22`, `checkov/CKV_AWS_18`), so every resource that fails the same check sits under one rule. A Prowler finding Id names a single resource, so the check name inside it is used, the same one the normaliser deduplicates on. Findings without a check ID get a rule named after their title. The rule's `security-severity` follows the cloudg severity (9.5 critical, 8.0 high, 5.5 medium, 3.0 low), and code scanning uses it to rank the alerts.

Suppressed findings stay in the file, marked with an external suppression, so code scanning closes their alerts instead of forgetting them. A partial fingerprint built from the rule and the resource keeps one alert per resource across runs.

### Job summary

`--summary FILE` appends a Markdown summary to `FILE`: the verdict, the counts by severity and the ten worst blocking findings. On GitHub Actions, pass `--summary "$GITHUB_STEP_SUMMARY"` and it shows on the run's page. The file is appended to, never replaced, so other steps' summaries survive.

## From Python

The gate is `cloudg.gate.evaluate_gate`, and the SARIF writer is `cloudg.renderers.sarif.write_sarif`. Both take a `ScanResult`, which every pipeline method of `CloudGEngine` returns as `scan_result`:

```python
from cloudg import CloudGConfig, CloudGEngine
from cloudg.gate import evaluate_gate, summary_markdown
from cloudg.renderers.sarif import write_sarif

engine = CloudGEngine(CloudGConfig())
pipeline = engine.run_from_reports_sync({"checkov": ["./results_json.json"]}, output_dir="./reports")
result = pipeline.scan_result

verdict = evaluate_gate(result, fail_on="high", max_blocking=0)
write_sarif(result, "reports/cloudg.sarif")
print(summary_markdown(verdict))
if not verdict.passed:
    raise SystemExit(verdict.reason)
```

`fail_on` takes the same names as `--fail-on`, in any case. `verdict.blocking` is the list of blocking findings, worst first, and `verdict.to_dict()` is the document `--json` prints.
