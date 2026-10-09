---
title: Running scanners
lede: "cloudg doesn't ship its own cloud checks. It drives Prowler, ScoutSuite, Checkov and Trivy as subprocesses, adds a built-in IAM linter, and turns everything they report into one list of findings."
meta:
  - [Commands, "`cloudg scan`, `cloudg run`"]
  - [Python, "`CloudGEngine.scan()`"]
  - [Needs, "Scanner binaries on `PATH`"]
source: cloudg/api_scanners.py
since: "0.6.0"
---

There are two ways to run the scanners. `cloudg scan` runs them on their own, with no collection, and writes the raw findings to disk. `cloudg run` runs them as phase 3 of the full pipeline, after collection and graph analysis, and passes the findings through the normaliser into the reports. The two commands share the scanner wrappers in `cloudg/scanners/` but differ in defaults and in which config keys they read; [the table near the end](#scan-and-run-compared) lists every difference.

If the scans already ran somewhere else (a CI job, another host, a nightly cron) you don't need either command. Hand the output files to [`cloudg ingest`](/guides/ingesting/) instead.

## The scanners

Each scanner has a name you use in `--scanners` and in `scanners.enabled`. Four of them are external programs that cloudg finds with `shutil.which`; the fifth is built in.

| Name | Binary | Install | Scans | Needs cloud credentials |
|---|---|---|---|---|
| `prowler` | `prowler` | `pip install prowler` | Live cloud accounts (CSPM checks) | Yes |
| `scoutsuite` | `scout` | `pip install scoutsuite` | Live cloud accounts (configuration audit) | Yes |
| `checkov` | `checkov` | `pip install checkov` | IaC files: Terraform, CloudFormation, ARM, Kubernetes and more | No |
| `trivy` | `trivy` | Binary from [trivy.dev](https://trivy.dev/) | Container images (CVEs, secrets), or a directory (vulnerabilities, misconfigurations, secrets) | Only for private registries |
| `iam` | none | Parliament ships with cloudg | IAM role trust policies and policy documents from the collected inventory | No (reads collected assets) |

Installing each external tool into its own virtual environment keeps its dependencies away from cloudg's and from the other scanners. The [Docker image](/guides/docker/) does the same: Prowler and Checkov live in separate venvs under `/opt`, with the binaries symlinked onto `PATH`. That image bundles Prowler, Checkov and Trivy. It does not include ScoutSuite.

```bash
python -m venv ~/.venvs/prowler && ~/.venvs/prowler/bin/pip install prowler
python -m venv ~/.venvs/checkov && ~/.venvs/checkov/bin/pip install checkov
ln -s ~/.venvs/prowler/bin/prowler ~/.local/bin/prowler
ln -s ~/.venvs/checkov/bin/checkov ~/.local/bin/checkov
which prowler checkov trivy scout
```

### Prowler

cloudg runs one Prowler process per provider and asks for ASFF output:

```text
prowler <provider> -M json-asff -o <output>/prowler/<provider> [-p <profile>] <prowler_extra_args>
```

`-p` is only added for AWS. Under `cloudg run`, the subprocess environment also gets `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY` when `aws.access_key_id` and `aws.secret_access_key` are set (from config or `--aws-key` / `--aws-secret`), and `AWS_DEFAULT_REGION` set to the first entry of `aws.regions`. Nothing else is forwarded: a session token, `--aws-role-arn` or an OIDC token file that you gave cloudg for collection does not reach Prowler. Give Prowler its own credentials through a profile, the environment, or its own flags in `scanners.prowler_extra_args`.

Prowler's stdout is streamed into the cloudg log, with a progress line every 25 checks. A non-zero exit code is logged as a warning and the output is parsed anyway, since Prowler exits non-zero whenever a check fails. Findings with `Compliance.Status` of `PASSED` are dropped during parsing.

:::warning Regions set to all
With `--regions all`, `aws.regions` holds the literal value `ALL`, and that is what cloudg puts in `AWS_DEFAULT_REGION` for Prowler. If Prowler fails with endpoint errors under `--regions all`, run it with an explicit region list instead. Prowler scans every enabled region by default anyway.
:::

### ScoutSuite

Also one process per provider:

```text
scout <provider> --report-dir <output>/scoutsuite/<provider> --no-browser [--profile <profile>] <scoutsuite_extra_args>
```

`--profile` is only passed for AWS. For Azure and GCP, ScoutSuite needs an authentication mode flag (for example `--cli` for Azure CLI credentials), which you supply through `scanners.scoutsuite_extra_args`. cloudg then searches the report directory for `scoutsuite_results*.js` and parses the JSON inside it.

### Checkov

One process per IaC directory:

```text
checkov -d <dir> --output json --quiet [--framework <f1> <f2> ...] <checkov_extra_args>
```

With `scanners.checkov_frameworks` empty (the default), cloudg leaves out `--framework` so Checkov auto-detects every framework it finds in the directory. A non-zero exit is normal for Checkov when checks fail and is not treated as an error. cloudg reads the JSON from stdout and does not save it.

### Trivy

With images configured, Trivy runs once per image, one after another, inside a single job:

```text
trivy image --format json --quiet <trivy_extra_args> <image>
```

With no images, the CLI commands fall back to a filesystem scan of the IaC directories:

```text
trivy fs --format json --quiet --scanners vuln,misconfig,secret <trivy_extra_args> <dir>
```

Like Checkov, the JSON is read from stdout and not written to disk. Trivy pulls images with its own registry authentication, so log in to private registries (ECR, ACR, Artifact Registry) the way Trivy expects before you start.

### The IAM linter

The linter looks at every collected asset of type `IAM_ROLE` or `IAM_POLICY`. It reads `metadata["assume_role_policy"]` (preferred when present, so for roles it is the trust policy) or `metadata["policy_document"]`, and runs two passes over it. The first is Parliament, which reports wildcard abuse and logical errors as `source_tool="parliament"`. The second is cloudg's own check for `Allow` statements with `Action: *`, or with `Resource: *` combined with a wildcard action or an action under `iam:`, `sts:`, `kms:`, `s3:`, `ec2:` or `lambda:`. Those are reported as HIGH with `source_tool="cloudg-iam"`.

Because it reads collected assets, the linter has nothing to do in `cloudg scan`, which collects nothing.

### Reachability findings

The scan phase also includes findings that come from the graph, not from a scanner. `ReachabilityAnalyzer` walks the asset graph from the internet node and reports exposed resources with `source_tool="cloudg-reachability"`. In `cloudg run` this happens in phase 2, and the results join the scanner findings at normalisation. Like the IAM linter, it needs collected assets.

### Cloud Custodian policies

`cloudg/policies/` (in the repository and inside the installed package) holds four Cloud Custodian policy packs: `custodian.yml` (AWS cost and governance), `custodian-aws-security.yml`, `custodian-azure.yml` and `custodian-gcp.yml`. cloudg never runs them, and `cloudg ingest` cannot read Custodian output. They are there for you to run with `custodian` directly:

```bash
pip install c7n c7n-azure c7n-gcp
custodian run --output-dir ./custodian-output cloudg/policies/custodian-aws-security.yml
```

## Choosing scanners

`--scanners` takes a comma-separated list of the names above. Spaces are trimmed and names are lowercased. An unknown name is ignored without a warning.

```bash tab="CLI"
cloudg run -p aws --regions us-east-1,eu-west-1 --scanners prowler,trivy --images 123456789012.dkr.ecr.us-east-1.amazonaws.com/api:1.4.2
cloudg scan -p aws --profile audit --scanners prowler,scoutsuite -o ./scan-2026-10-09
```

```python tab="Python" title="scan_only.py"
import asyncio

from cloudg import CloudGConfig, CloudGEngine
from cloudg.scanners.checkov import CheckovScanner
from cloudg.scanners.prowler import ProwlerScanner
from cloudg.scanners.trivy import TrivyScanner

for tool in (ProwlerScanner, CheckovScanner, TrivyScanner):
    print(tool.__name__, "installed" if tool.is_available() else "missing")

config = CloudGConfig(providers=["aws"])
config.scanners.enabled = ["checkov", "trivy"]
config.scanners.checkov_frameworks = ["terraform"]

engine = CloudGEngine(config)
engine.on_error = lambda name, exc: print("scanner error:", name, exc)

findings = asyncio.run(
    engine.scan(
        assets=[],
        edges=[],
        iac_dir="./terraform",
        images=["python:3.12-slim"],
        output_dir="./reports",
    )
)
print(len(findings), "findings")
```

```bash tab="Docker"
docker run --rm \
  -v ~/.aws:/home/cloudg/.aws:ro \
  -v "$PWD/reports:/app/reports" \
  ghcr.io/morpheuslord/cloudg:latest scan -p aws --scanners prowler -o /app/reports
```

`cloudg run` without `--scanners` uses `scanners.enabled`, which defaults to all five names. `cloudg scan` without `--scanners` runs `prowler,checkov` and ignores the config list.

The IAM linter is the odd one out. In `cloudg run` it runs whenever collection returned any assets, even if `iam` isn't in the list, so leaving it out of `--scanners` does not switch it off. `CloudGEngine.scan()` behaves the same way.

## IaC targets: --iac-dir and the Terraform fallback

Checkov, and Trivy when it has no images, need a directory. `cloudg run` and `CloudGEngine.scan()` resolve it in a fixed order and stop at the first hit.

```mermaid caption="How cloudg run picks the directories for Checkov and Trivy fs"
flowchart TD
  A{"--iac-dir given?"} -->|yes| X["Scan that directory"]
  A -->|no| B{"scanners.iac_directories set?"}
  B -->|yes| Y["Scan each listed directory"]
  B -->|no| C{"Terraform recreation on and *.tf.json written?"}
  C -->|yes| Z["Scan the recreation of the live cloud"]
  C -->|no| S["Skip Checkov, warn"]
```

The last step is the interesting one. With `--terraform` (or `terraform.enabled: true`) and nothing else configured, cloudg writes a Terraform recreation of the collected infrastructure and points Checkov at it, so Checkov audits your real cloud through its Terraform representation. There is no fallback to the current directory: scanning whatever folder cloudg was started from would produce a clean-looking result that says nothing about the cloud.

```bash
cloudg run -p aws --regions us-east-1 --terraform --scanners checkov,trivy
```

`cloudg scan` is older and simpler. Its `--iac-dir` defaults to `.`, so Checkov (and the Trivy filesystem fallback) scan the working directory unless you say otherwise.

## Container images: --images

`--images` takes a comma-separated list of full image references. Without it, `cloudg run` falls back to `scanners.trivy_images`. If neither is set, the CLI commands run `trivy fs` on the IaC directories instead, and `cloudg run` skips Trivy with a warning when there are no directories either.

`CloudGEngine.scan()` has no filesystem fallback. From Python, Trivy only runs when there are images, either from the `images` argument or from `config.scanners.trivy_images`.

## Configuration

Every key below lives under `scanners:` in `config.yaml`. They apply to `cloudg run` and `CloudGEngine.scan()`; `cloudg scan` ignores all of them. The full reference is on the [scanners config page](/reference/config/scanners/).

```yaml title="config.yaml"
scanners:
  enabled: [prowler, checkov, trivy, iam]
  prowler_extra_args: ["--severity", "critical", "high"]
  scoutsuite_extra_args: []
  checkov_extra_args: ["--skip-check", "CKV_AWS_18"]
  checkov_frameworks: [terraform, cloudformation]   # empty = auto-detect
  trivy_extra_args: ["--severity", "HIGH,CRITICAL", "--ignore-unfixed"]
  trivy_images:
    - 123456789012.dkr.ecr.us-east-1.amazonaws.com/api:1.4.2
    - 123456789012.dkr.ecr.us-east-1.amazonaws.com/worker:1.4.2
  iac_directories: [./infra/terraform, ./infra/k8s]
  timeout_seconds: 3600
```

The `*_extra_args` lists are appended to the scanner's command line as separate arguments, after cloudg's own flags. They are passed to every run of that scanner. When Prowler or ScoutSuite runs once per provider, the same extra arguments go to all of them, so an Azure-only flag will break the AWS run. If you need different flags per cloud, run the providers as separate `cloudg run` invocations with separate config files.

```bash
cloudg -c config.yaml run -p aws --regions us-east-1
```

## Parallelism and timeouts

Every scanner target becomes one job in a thread pool: one Prowler job per provider, one ScoutSuite job per provider, one Checkov job per IaC directory, one Trivy job for all images (or all directories), and one IAM linter job. The pool has `len(scanners) + len(providers) + 1` workers, with a floor of two, so for `cloudg run -p all` with all five scanners that is nine workers. Jobs beyond that wait their turn. Since each job is mostly a subprocess, the threads spend their time waiting and the real CPU load comes from the scanners themselves.

The time limits that actually stop a scanner are the subprocess timeouts inside each wrapper:

| Scanner | Subprocess timeout | What happens when it fires |
|---|---|---|
| Prowler | 3600 s | Process killed, no findings from that provider |
| ScoutSuite | 3600 s | No findings from that provider |
| Checkov | 1800 s per directory | No findings from that directory |
| Trivy | 1800 s per image or directory | That image or directory is skipped, the rest continue |

`scanners.timeout_seconds` (default 3600, minimum 60) is passed to the wait on each job's result. In 0.6.0 that wait only happens after the job has already finished, so the setting does not cut a slow scanner short. Plan around the per-tool limits above.

## When something goes wrong

A missing binary does not fail the run. The wrapper logs a warning such as `Prowler is not installed. Install with: pip install prowler. Skipping Prowler scan.` and returns no findings. The progress display then shows a tick and `Prowler: 0 findings`, which looks exactly like a clean scan. Read the warnings, or check the binaries before you trust a zero:

```console
$ cloudg scan -p aws --scanners prowler,checkov --iac-dir ./infra
[21:50:50] WARNING  Checkov is not installed. Install with: pip install checkov.
                    Skipping Checkov scan.
           WARNING  Prowler is not installed. Install with: pip install prowler.
                    Skipping Prowler scan.
  ✓ Prowler: 0 findings            0:00:00
  ✓ Checkov: 0 findings            0:00:00

  ✓ Total: 0 findings
  ✓ Raw findings: reports/raw-findings.json
```

Other failures follow the same rule: one scanner's problem never stops the others.

| Symptom | Cause | Fix |
|---|---|---|
| `0 findings` from a scanner straight away | Binary not on `PATH` | Install it, or run inside the Docker image |
| `[Prowler] Exited with code 3 after ...` | Prowler found failing checks | Normal; findings are still parsed |
| `Checkov: nothing to scan; pass --iac-dir, ...` | No `--iac-dir`, no `iac_directories`, no Terraform recreation | Pass `--iac-dir` or add `--terraform` |
| `Trivy: nothing to scan` | No images and no IaC directories | Pass `--images` or set `scanners.trivy_images` |
| `No ScoutSuite results found in ...` | ScoutSuite failed before writing results, often authentication | Run the printed `scout` command by hand to see its error |
| `<name> failed: ...` in the progress list | The wrapper raised an exception | Run with `cloudg -v` for the traceback |

From Python, set `engine.on_error` to see failures as they happen. It receives the job name (`prowler-aws`, `checkov-./infra`, `trivy`, `iam`) and the exception. A missing binary is not an error there either; it just yields an empty list.

## Where raw output lands

| Scanner | `cloudg run` and `CloudGEngine.scan()` | `cloudg scan` |
|---|---|---|
| Prowler | `<output>/prowler/<provider>/*.json` (ASFF) | `<output>/prowler/*.json` |
| ScoutSuite | `<output>/scoutsuite/<provider>/` (HTML report and `scoutsuite-results/scoutsuite_results_*.js`) | `<output>/scoutsuite/` |
| Checkov | Not saved (read from stdout) | Not saved |
| Trivy | Not saved (read from stdout) | Not saved |
| All findings | Normalised into `findings.json` and `report.html` | `raw-findings.json`, before normalisation |

:::warning Reusing an output directory
Prowler names each output file after the account and a timestamp, and cloudg parses every `*.json` under the Prowler output directory. Point a second run at the same `-o` and the older ASFF files are parsed again. Repeated checks on the same resource are merged during normalisation, but a problem you fixed after the first run still shows up from the old file. Use a fresh output directory per run.
:::

The Prowler and ScoutSuite directories are in the native formats that `cloudg ingest` reads, so you can re-aggregate them later without scanning again:

```bash
cloudg ingest --prowler ./reports/prowler/aws/ --scoutsuite ./reports/scoutsuite/aws/ -o ./reports-again
```

`raw-findings.json` from `cloudg scan` is a JSON list of cloudg `Finding` objects, not a scanner format. `cloudg report` can't read it. To turn it into reports, normalise it in Python as shown in [Reports](/guides/reports/#from-raw-findings), or merge it into an inventory map with [`cloudg map --findings`](/guides/inventory-mapping/).

## Scan and run compared {#scan-and-run-compared}

| | `cloudg scan` | `cloudg run` (phase 3) |
|---|---|---|
| Collects assets first | No | Yes |
| Default scanners | `prowler,checkov` | `scanners.enabled` (all five) |
| Reads `scanners.*` config keys | No | Yes |
| Providers | One, from `-p` (default `aws`) | Every provider from `-p` |
| IaC directory when none is given | `.` | Config, then the Terraform recreation, else skipped |
| Trivy without images | `trivy fs` on the IaC directory | `trivy fs` on the resolved directories, else skipped |
| IAM linter and reachability | Never | Whenever assets were collected |
| Writes | `raw-findings.json` | `findings.json`, `report.html`, `topology.svg` and the graph files |

## Next

:::links
- [Ingesting existing output](/guides/ingesting/) Aggregate scans that ran elsewhere, with no binaries and no credentials.
- [Compliance frameworks](/guides/compliance/) How findings are tagged with framework controls after the scan.
- [Reports](/guides/reports/) What `findings.json` and `report.html` contain.
- [cloudg scan](/cli/scan/) Every flag of the standalone scan command.
:::
