---
title: CI and automation
description: Run cloudg on a schedule or on every infrastructure change, with short-lived cloud credentials, a severity gate that fails the job, SARIF for code scanning, and the reports kept as build artifacts.
---

Run cloudg on a schedule or on every infrastructure change, with short-lived cloud credentials, a severity gate that fails the job, SARIF for code scanning, and the reports kept as build artifacts.
{ .lede }

**Commands** `cloudg run`, `cloudg gate`, `cloudg map`, `cloudg ingest` &middot; **CI systems** GitHub Actions, GitLab CI, any shell runner &middot; **Last changed** [v0.7.1](../changelog.md#0.7.1)
{ .page-meta }

There are three useful shapes for cloudg in a pipeline, and most teams end up with two of them:

<div class="grid cells" markdown>

<div class="card" markdown>

### Scheduled posture run

`cloudg run` against the live account on a cron, with OIDC credentials, Prowler and the IAM linter. Slow, thorough, read-only.

</div>

<div class="card" markdown>

### Pull request gate

Checkov and Trivy over the IaC in the branch, aggregated with `cloudg ingest`. No cloud access at all, so it is safe for forks.

</div>

<div class="card" markdown>

### Inventory snapshot

`cloudg map` on a cron. No scanners, just the map, kept as an artifact for diffing and for the MCP server.

</div>

</div>

On GitHub, the cloudg action covers the first two. Everywhere else, `cloudg run` (or `cloudg ingest`) followed by `cloudg gate` does the same job in two commands.

## The GitHub Action

The repository is also a GitHub Action. It installs cloudg and the scanners it needs, runs `cloudg run`, gates the result on severity, uploads SARIF to code scanning, writes a job summary and keeps the reports as an artifact. Credentials come from the official login action of each cloud, so no long-lived keys go into secrets.

```yaml title=".github/workflows/cloud-posture.yml"
name: Cloud posture

on:
  schedule:
    - cron: "0 5 * * 1-5"     # weekdays 05:00 UTC
  workflow_dispatch:

permissions:
  contents: read
  id-token: write              # the OIDC token for the cloud login
  security-events: write       # SARIF upload to code scanning

jobs:
  posture:
    runs-on: ubuntu-latest
    timeout-minutes: 120
    steps:
      - uses: actions/checkout@v7

      - uses: aws-actions/configure-aws-credentials@v6
        with:
          role-to-assume: arn:aws:iam::123456789012:role/cloudg-github
          role-session-name: cloudg-${{ github.run_id }}
          aws-region: us-east-1

      - uses: morpheuslord/cloudg@v0.7.1
        with:
          provider: aws
          regions: us-east-1,eu-west-1
          scanners: prowler,iam
          fail-on: critical
          min-assets: "1"
```

Pin the action to a release tag, or to the commit SHA behind it. The tag also decides which cloudg gets installed: `@v0.7.1` installs cloudg 0.7.1 from the action's own checkout, so the action and the CLI cannot drift apart. The `version` input installs a release from PyPI instead.

The job fails when the gate fails (status 4), and also when `cloudg run` exits non-zero, for example 3 when no target could be collected. Either way, the SARIF, the summary and the artifact are uploaded first. The [role to create](#create-the-role) is described below.

### Inputs

| Input | Default | What it does |
|---|---|---|
| `provider` | (required) | `aws`, `azure`, `gcp` or `all`; several are comma-separated |
| `regions` | config | `all`, or a comma-separated list |
| `scanners` | `prowler,iam` | comma-separated subset of `prowler,scoutsuite,checkov,trivy,iam`; empty uses `scanners.enabled` from the config |
| `install-scanners` | `true` | installs Prowler, Checkov and ScoutSuite with uv when they are requested and not on `PATH`. Trivy is not installed: add `aquasecurity/setup-trivy` before the action |
| `config` | | a `config.yaml` in the repository, passed as `-c` |
| `subscription-id`, `project-id` | | the Azure subscription and the GCP project |
| `iac-dir`, `images` | | Checkov's directory and Trivy's images |
| `extra-args` | | more `cloudg run` flags, split on spaces, such as `--no-rag-export --no-ontology` |
| `findings` | | gate this `findings.json` and skip `cloudg run` |
| `output` | `cloudg-reports` | the report directory |
| `fail-on` | `high` | `critical`, `high`, `medium`, `low`, `info` or `never` |
| `max-findings` | `0` | blocking findings tolerated |
| `min-assets` | `0` | fail when fewer assets were collected |
| `sarif`, `upload-sarif` | `true`, `true` | write `cloudg.sarif`, and upload it to code scanning |
| `sarif-category` | `cloudg` | keeps several cloudg jobs apart in code scanning |
| `upload-artifact`, `artifact-name`, `retention-days` | `true`, `cloudg-reports`, `14` | the report artifact |
| `version` | | a cloudg release from PyPI, instead of the action's own checkout |
| `python-version` | `3.12` | Python for cloudg and the scanners |

The outputs are `passed`, `blocking`, `total-findings`, `report-dir` and `sarif-file`.

The SARIF upload needs `security-events: write`, and on a private repository GitHub Advanced Security as well. Without either, the upload step logs an error and the job goes on. Set `upload-sarif: "false"` to skip it.

### Azure and GCP

The same action works behind `azure/login` and `google-github-actions/auth`. cloudg picks the credentials up through `DefaultAzureCredential` (the Azure CLI login that `azure/login` leaves behind) and through Application Default Credentials. [Authentication](authentication.md) has the details.

```yaml title=".github/workflows/cloud-posture-multi.yml"
jobs:
  azure:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v7
      - uses: azure/login@v3
        with:
          client-id: ${{ vars.AZURE_CLIENT_ID }}
          tenant-id: ${{ vars.AZURE_TENANT_ID }}
          subscription-id: ${{ vars.AZURE_SUBSCRIPTION_ID }}
      - uses: morpheuslord/cloudg@v0.7.1
        with:
          provider: azure
          subscription-id: ${{ vars.AZURE_SUBSCRIPTION_ID }}
          config: ci/cloudg-azure.yaml
          scanners: ""
          sarif-category: cloudg-azure
          artifact-name: cloudg-azure

  gcp:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v7
      - uses: google-github-actions/auth@v3
        with:
          workload_identity_provider: projects/123456789/locations/global/workloadIdentityPools/github/providers/github
          service_account: cloudg-audit@my-project.iam.gserviceaccount.com
      - uses: morpheuslord/cloudg@v0.7.1
        with:
          provider: gcp
          project-id: my-project
          scanners: prowler
          sarif-category: cloudg-gcp
          artifact-name: cloudg-gcp
```

Prowler finds the GCP credentials on its own through Application Default Credentials. For Azure it has to be told which login to use, and the IAM linter only reads AWS policies, so the Azure job takes its scanner settings from a config:

```yaml title="ci/cloudg-azure.yaml"
providers: [azure]
scanners:
  enabled: [prowler]
  prowler_extra_args: ["--az-cli-auth"]
```

Both jobs need the same `permissions` block as the AWS workflow. Give each job its own `sarif-category` and `artifact-name`, or the second upload replaces the first.

## Exit codes

cloudg exits non-zero when it cannot do its job. Only `cloudg gate` exits non-zero because of what was found.

| Command | Exits non-zero when | Exits 0 even when |
|---|---|---|
| `cloudg gate` | 4: more findings at `--fail-on` or above than `--max`, or fewer assets than `--min-assets`; 1: the input is missing or unreadable | findings below the threshold, or suppressed findings at any severity |
| `cloudg run` | 3: collection failed for every target (the reports are still written); 2: `aws.accounts` without `aws.role_name`; 1: an unhandled exception escapes | some accounts or regions failed, a scanner is missing or failed, the ontology or RAG export failed |
| `cloudg map` | 1: the mapping raised (bad config, no SDK installed, an `--ou` that matches no OU); 2: `--accounts` without a role name | individual collectors failed or were throttled (recorded in coverage) |
| `cloudg scan` | 1: none of the requested scanners could run, or every one of them failed | some of the requested scanners were missing or failed |
| `cloudg ingest` | 1: no `--prowler`, `--scoutsuite`, `--checkov` or `--trivy` was given | the given paths parsed to zero findings |
| `cloudg report` | 1: the `-i` file does not exist or cannot be read, or `findings.json` would overwrite the input without `--overwrite` | |
| `cloudg collect` | 1: collection raised | |
| any | 2: click usage errors (unknown flag, bad choice) | |

`cloudg run` is still the one to watch. Each phase catches its own errors so the rest of the pipeline still produces something. Exit 3 catches a run where no target could be collected at all, such as a profile that does not exist, a role that cannot be assumed or a runner with no credentials. A partly collected run still exits 0, which is what `--min-assets` on the gate is for.

## A severity gate

Every run writes `findings.json` (see [reports](reports.md)). [`cloudg gate`](../cli/gate.md) reads it and fails the job when it holds too much at or above a severity:

```bash
cloudg run -p aws -o reports
cloudg gate -i reports --fail-on critical --min-assets 1 \
  --sarif reports/cloudg.sarif --summary "$GITHUB_STEP_SUMMARY"
```

Suppressed findings never count. `--max N` tolerates N blocking findings, and `--min-assets 1` fails a live run that collected nothing, which usually means the credentials did not work. Leave `--min-assets` at 0 for ingest-only jobs, since they never collect assets. A failing gate prints the worst findings first and exits 4:

```console
$ cloudg gate -i reports --fail-on high
...
╭───────────────────────────┬──────────┬────────────┬──────────────────────────╮
│ Finding                   │ Severity │       Tool │                 Resource │
├───────────────────────────┼──────────┼────────────┼──────────────────────────┤
│ Security group allows SSH │ CRITICAL │    prowler │ arn:aws:ec2:us-east-1:1… │
│ (22) from 0.0.0.0/0       │          │            │                          │
│ S3 bucket allows public   │     HIGH │ scoutsuite │   arn:aws:s3:::prod-logs │
│ read                      │          │            │                          │
╰───────────────────────────┴──────────┴────────────┴──────────────────────────╯
  ✗ Gate failed: 2 finding(s) at HIGH or above, 0 allowed
```

`--sarif` writes SARIF 2.1.0 for code scanning, `--summary` appends a Markdown summary to a file, and `--json` prints the verdict for scripts. The [cloudg gate](../cli/gate.md) page covers all three.

When cloudg is not installed in the job that decides, `jq` gives the yes or no in one line:

```bash
jq -e '[.findings[] | select(.severity == "CRITICAL" and (.is_suppressed | not))] | length == 0' reports/findings.json
```

When the gate should run inside Python, for example in a job that already uses the engine, see the gate recipe in [Python recipes](python-recipes.md).

## GitHub Actions with OIDC to AWS

No access keys in repository secrets. GitHub mints an OIDC token per job, AWS exchanges it for a role session, and the role only trusts this repository.

<div class="steps" markdown>

### Create the role

In the target account, add GitHub as an identity provider (`token.actions.githubusercontent.com`, audience `sts.amazonaws.com`) once, then create a role with `SecurityAudit` and `ViewOnlyAccess` attached and this trust policy. Replace the account ID and repository:

```json title="cloudg-github-trust.json"
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Federated": "arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com"
      },
      "Action": "sts:AssumeRoleWithWebIdentity",
      "Condition": {
        "StringEquals": {
          "token.actions.githubusercontent.com:aud": "sts.amazonaws.com",
          "token.actions.githubusercontent.com:sub": "repo:acme/cloud-posture:ref:refs/heads/main"
        }
      }
    }
  ]
}
```

!!! warning "Scope the subject"

    A `sub` of `repo:acme/cloud-posture:*` lets every branch and every pull request from a branch assume the role. Pin it to `main` or to a deployment environment (`repo:acme/cloud-posture:environment:cloud-audit`).

### Add a config

The action's inputs cover the common flags. Anything else goes in a config next to the workflow:

```yaml title="ci/cloudg.yaml"
providers: [aws]
aws:
  regions: [us-east-1, eu-west-1]
scanners:
  enabled: [prowler, iam]
  timeout_seconds: 3600      # per scanner
```

### Add the workflow

The workflow from [the GitHub Action](#the-github-action), pointed at the config. An empty `scanners` input leaves the choice to `scanners.enabled`:

```yaml title=".github/workflows/cloud-posture.yml"
      - uses: morpheuslord/cloudg@v0.7.1
        with:
          provider: aws
          config: ci/cloudg.yaml
          scanners: ""
          fail-on: critical
          min-assets: "1"
          retention-days: "30"
```

</div>

Credentials go through `configure-aws-credentials` here, which exports `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY` and `AWS_SESSION_TOKEN` for the whole job; cloudg's collectors and Prowler pick them up through the default chain. cloudg's own `--aws-role-arn` with `--aws-web-identity-token-file` works as well (pass them in `extra-args`): cloudg then assumes the role itself and hands Prowler and ScoutSuite the temporary keys. The login action has the advantage that every other step of the job gets the same credentials. [Authentication](authentication.md#what-the-scanners-receive) has the details.

The login action's session lasts one hour by default. A long organization-wide run can outlive it; raise `role-duration-seconds` (and the role's maximum session duration) or split the run per account.

### Pull requests without cloud access

Infrastructure changes can be gated before they reach an account. Checkov and Trivy scan the branch, cloudg aggregates and deduplicates, and the action gates the result through its `findings` input. No OIDC permission is needed, so this job is safe on forks.

```yaml title=".github/workflows/iac-gate.yml"
name: IaC gate

on:
  pull_request:
    paths: ["infra/**"]

permissions:
  contents: read

jobs:
  iac:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v7

      - uses: actions/setup-python@v7
        with:
          python-version: "3.12"

      - uses: aquasecurity/setup-trivy@v0.3.1

      - name: Scan and aggregate
        run: |
          pip install "cloudg==0.7.1" checkov
          checkov -d infra --output json > checkov.json || true
          trivy fs --format json --scanners vuln,misconfig,secret --output trivy-fs.json infra
          cloudg ingest --checkov checkov.json --trivy trivy-fs.json -o reports

      - uses: morpheuslord/cloudg@v0.7.1
        with:
          provider: aws
          findings: reports/findings.json
          output: reports
          fail-on: high
          upload-sarif: "false"
          artifact-name: iac-gate-${{ github.event.pull_request.number }}
```

`|| true` after Checkov is deliberate: Checkov exits 1 when any check fails, and the decision belongs to the gate, which sees the deduplicated result. The core `cloudg` package is enough here, since ingest needs no cloud SDK. The SARIF upload is off because pull requests from forks get a read-only token; turn it on for branches in the same repository and add `security-events: write`.

## GitLab CI

GitLab issues OIDC tokens through `id_tokens`. Write the token to a file and set `AWS_ROLE_ARN` and `AWS_WEB_IDENTITY_TOKEN_FILE`: boto3's default chain then performs the web identity exchange for cloudg and for Prowler alike. The role's trust policy uses your GitLab host as the provider (`gitlab.com` for SaaS), audience `sts.amazonaws.com`, and a `sub` such as `project_path:acme/cloud-posture:ref_type:branch:ref:main`.

```yaml title=".gitlab-ci.yml"
stages: [posture]

variables:
  PIP_CACHE_DIR: "$CI_PROJECT_DIR/.cache/pip"
  AWS_ROLE_ARN: arn:aws:iam::123456789012:role/cloudg-gitlab
  AWS_DEFAULT_REGION: us-east-1

cloudg-posture:
  stage: posture
  image: python:3.12-slim
  rules:
    - if: $CI_PIPELINE_SOURCE == "schedule"
    - if: $CI_PIPELINE_SOURCE == "web"
  id_tokens:
    AWS_ID_TOKEN:
      aud: sts.amazonaws.com
  cache:
    key: cloudg-0.7.1
    paths: [.cache/pip]
  before_script:
    - pip install "cloudg[aws]==0.7.1" pipx
    - pipx install prowler
    - export PATH="$HOME/.local/bin:$PATH"
    - echo "$AWS_ID_TOKEN" > "$CI_PROJECT_DIR/.web-identity-token"
    - export AWS_WEB_IDENTITY_TOKEN_FILE="$CI_PROJECT_DIR/.web-identity-token"
  script:
    - cloudg -c ci/cloudg.yaml run -p aws -o reports
    - cloudg gate -i reports --fail-on critical --min-assets 1 --sarif reports/cloudg.sarif
  artifacts:
    when: always
    paths: [reports/]
    expire_in: 30 days
```

Do not also pass `--aws-role-arn` here. With `AWS_WEB_IDENTITY_TOKEN_FILE` set in the environment, cloudg would treat that ARN as its own OIDC target and do the exchange itself, which works for the collectors but leaves Prowler on the default chain anyway. Create the schedule under CI/CD, Schedules; the `web` rule lets you start a run by hand.

If `cloudg run` exits 3 the job stops before the gate, and `when: always` still keeps the reports. GitLab's security dashboard reads its own report formats and not SARIF, so the SARIF file stays a plain artifact here.

## Any other runner

Jenkins, Azure Pipelines, Buildkite or a cron box all need the same three things: cloudg installed, credentials in the environment, and the two commands.

```bash title="ci/cloudg.sh"
set -euo pipefail
pip install "cloudg[aws]==0.7.1"
pipx install prowler

status=0
cloudg -c ci/cloudg.yaml run -p aws -o reports || status=$?
cloudg gate -i reports --fail-on critical --min-assets 1 --sarif reports/cloudg.sarif || status=$?
exit "$status"
```

Collecting the status this way runs the gate even after a failed run, so the gate's view of the partial reports is in the log. Keep `reports/` as the job's artifact whatever the result.

## Scheduled inventory snapshots

A map is cheaper than a full run and changes less often than findings. A nightly `cloudg map` gives you `inventory-map.json`, `inventory-dependencies.json` and, with `--org`, `inventory-organization.json`, ready for `cloudg deps`, for diffing, or for an [MCP server](../cli/mcp-serve.md) to load.

```yaml title=".github/workflows/inventory.yml"
name: Inventory snapshot

on:
  schedule:
    - cron: "30 2 * * *"

permissions:
  contents: read
  id-token: write

jobs:
  map:
    runs-on: ubuntu-latest
    timeout-minutes: 90
    steps:
      - uses: actions/setup-python@v7
        with:
          python-version: "3.12"
      - run: pip install "cloudg[aws]==0.7.1"
      - uses: aws-actions/configure-aws-credentials@v6
        with:
          role-to-assume: arn:aws:iam::123456789012:role/cloudg-github
          aws-region: us-east-1
      - run: cloudg map -p aws --regions all -o inventory
      - uses: actions/upload-artifact@v7
        with:
          name: inventory-${{ github.run_id }}
          path: inventory/
          retention-days: 90
```

Throttling during a map is recorded in coverage and in the `throttling` block of `inventory-map.json` rather than failing the job, so check that block when a snapshot looks thin. Several pipelines mapping the same account at once share its API quota; stagger their schedules, or lower `ratelimit.aws.max_rps` for the CI config as described in [rate limits](rate-limits.md).

## Caching and artifacts

Outside the action, two things are worth caching. pip's wheel cache saves the install of the cloud SDKs on every run. Trivy's vulnerability database (`~/.cache/trivy`) is a sizeable download; with the cache restored, Trivy only fetches it again when its copy is out of date. Pin the cloudg version in both the install command and the cache key, so an upgrade invalidates the cache instead of mixing versions.

Do not cache `reports/`. Publish it as an artifact instead. A run's useful files:

| File | Use in CI |
|---|---|
| `findings.json` | the gate's input; also re-renders later with `cloudg report -i` |
| `cloudg.sarif` | written by `cloudg gate --sarif`, for code scanning or another SARIF viewer |
| `report.html` | self-contained, opens from the artifact download |
| `raw-findings.json` | written by `ingest` (and `scan`): findings before deduplication, for debugging the normaliser |
| `inventory-map.json` | the map from `cloudg map`, loadable with `InventoryResult.load` |
| `ontology.ttl`, `rag_chunks.jsonl` | feed downstream analysis or a retrieval index |

The reports describe your estate in detail: account IDs, ARNs, open ports, IAM grants. Keep artifact retention short and the repository private, and use the Docker image or a private runner when the reports must not leave your network. See [Docker](docker.md) for the image, which bundles Prowler, Checkov and Trivy.

<div class="grid cards link-cards" markdown>

-   [**cloudg gate**](../cli/gate.md)

    The gate, SARIF and the job summary.

-   [**Authentication**](authentication.md)

    Every credential method and its precedence.

-   [**Python recipes**](python-recipes.md)

    The gate and the pipeline from Python.

-   [**Ingesting existing output**](ingesting.md)

    What `cloudg ingest` accepts.

</div>
