---
title: CI and automation
lede: "Run cloudg on a schedule or on every infrastructure change, with short-lived cloud credentials, a severity gate that fails the job, and the reports kept as build artifacts."
meta:
  - [Commands, "`cloudg run`, `cloudg map`, `cloudg ingest`"]
  - [CI systems, "GitHub Actions, GitLab CI"]
source: .github/workflows/cloudg.yml
since: "0.6.0"
---

There are three useful shapes for cloudg in a pipeline, and most teams end up with two of them:

:::cells
### Scheduled posture run
`cloudg run` against the live account on a cron, with OIDC credentials, Prowler and the IAM linter. Slow, thorough, read-only.
### Pull request gate
Checkov and Trivy over the IaC in the branch, aggregated with `cloudg ingest`. No cloud access at all, so it is safe for forks.
### Inventory snapshot
`cloudg map` on a cron. No scanners, just the map, kept as an artifact for diffing and for the MCP server.
:::

Before wiring any of them up, know what cloudg's exit code does and does not tell you.

## Exit codes

cloudg exits non-zero when it cannot do its job, never because of what it found. Nothing in the CLI fails on severity.

| Command | Exits non-zero when | Exits 0 even when |
|---|---|---|
| `cloudg run` | 3: collection failed for every target (the reports are still written); 2: `aws.accounts` without `aws.role_name`; 1: an unhandled exception escapes | some accounts or regions failed, a scanner is missing or failed, the ontology or RAG export failed |
| `cloudg map` | 1: the mapping raised (bad config, no SDK installed, an `--ou` that matches no OU); 2: `--accounts` without a role name | individual collectors failed or were throttled (recorded in coverage) |
| `cloudg scan` | 1: none of the requested scanners could run, or every one of them failed | some of the requested scanners were missing or failed |
| `cloudg ingest` | 1: no `--prowler`, `--scoutsuite`, `--checkov` or `--trivy` was given | the given paths parsed to zero findings |
| `cloudg report` | 1: the `-i` file does not exist or cannot be read, or `findings.json` would overwrite the input without `--overwrite` | |
| `cloudg collect` | 1: collection raised | |
| any | 2: click usage errors (unknown flag, bad choice) | |

`cloudg run` is still the one to watch. Each phase catches its own errors so the rest of the pipeline still produces something. Exit 3 catches a run where no target could be collected at all, such as a profile that does not exist, a role that cannot be assumed or a runner with no credentials. A partly collected run still exits 0, so the gate script below also checks the asset count, as well as severity.

## A severity gate

Every run writes `findings.json` (see [reports](/guides/reports/)). Its `findings` list holds the normalised, deduplicated findings, each with `severity`, `risk_score`, `source_tool`, `is_suppressed` and the affected resource, and `summary` holds the totals. Save this as `ci/severity_gate.py` in the repository that runs the job:

```python title="ci/severity_gate.py"
"""Fail a CI job when a cloudg findings.json crosses a severity threshold.

Usage:
    python severity_gate.py reports/findings.json --fail-on HIGH --max 0 --min-assets 1

Exit codes: 0 passed, 1 gate failed, 2 the report is missing or unusable.
"""

import argparse
import json
import sys
from collections import Counter

ORDER = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("findings", help="findings.json written by cloudg run or cloudg ingest")
    parser.add_argument("--fail-on", default="CRITICAL", choices=ORDER,
                        help="lowest severity that blocks (default CRITICAL)")
    parser.add_argument("--max", type=int, default=0,
                        help="blocking findings tolerated (default 0)")
    parser.add_argument("--min-assets", type=int, default=0,
                        help="fail when fewer assets were collected (catches silent auth failures)")
    args = parser.parse_args()

    try:
        with open(args.findings) as fh:
            data = json.load(fh)
    except (OSError, json.JSONDecodeError) as exc:
        print(f"gate: cannot read {args.findings}: {exc}", file=sys.stderr)
        return 2

    assets = data.get("summary", {}).get("total_assets", 0)
    if assets < args.min_assets:
        print(f"gate: only {assets} asset(s) collected, expected at least {args.min_assets}")
        return 2

    threshold = ORDER.index(args.fail_on)
    active = [f for f in data.get("findings", []) if not f.get("is_suppressed")]
    blocking = [f for f in active if ORDER.index(f["severity"]) >= threshold]

    print(f"assets: {assets}, findings by severity: {dict(Counter(f['severity'] for f in active))}")
    for f in sorted(blocking, key=lambda f: -f.get("risk_score", 0))[:25]:
        target = f.get("resource_arn") or f["resource_id"]
        print(f"  [{f['severity']}] {f['title']} ({f['source_tool']}) {target}")

    if len(blocking) > args.max:
        print(f"gate: {len(blocking)} finding(s) at {args.fail_on} or above, {args.max} allowed")
        return 1
    print("gate: passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
```

It needs nothing but the standard library, so it runs before or after cloudg is installed. A failing gate prints the worst offenders first:

```console
$ python ci/severity_gate.py reports/findings.json --fail-on HIGH
assets: 0, findings by severity: {'CRITICAL': 1, 'HIGH': 3}
  [CRITICAL] [Trivy] CVE-2024-0001: openssl (alpine) (trivy) myrepo/app:latest
  [HIGH] S3 bucket default encryption (prowler) arn:aws:s3:::my-bucket
  [HIGH] [Checkov/terraform] Ensure S3 bucket has server-side encryption enabled (checkov) aws_s3_bucket.data
  [HIGH] [Trivy/IaC] AVD-AWS-0088: S3 bucket encryption not enabled (trivy) ./iac
gate: 4 finding(s) at HIGH or above, 0 allowed
```

Use `--min-assets 1` (or a realistic floor for your account) on live runs, and leave it at 0 for ingest-only jobs, which never collect assets. If you only need the yes or no, `jq` does it in one line:

```bash
jq -e '[.findings[] | select(.severity == "CRITICAL" and (.is_suppressed | not))] | length == 0' reports/findings.json
```

When the gate should run inside Python, for example in a job that already uses the engine, see the gate recipe in [Python recipes](/guides/python-recipes/).

## GitHub Actions with OIDC to AWS

No access keys in repository secrets. GitHub mints an OIDC token per job, AWS exchanges it for a role session, and the role only trusts this repository.

::::steps
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

:::warning Scope the subject
A `sub` of `repo:acme/cloud-posture:*` lets every branch and every pull request from a branch assume the role. Pin it to `main` or to a deployment environment (`repo:acme/cloud-posture:environment:cloud-audit`).
:::
### Add the config and the gate

Commit `ci/severity_gate.py` from above and a config next to it:

```yaml title="ci/cloudg.yaml"
providers: [aws]
aws:
  regions: [us-east-1, eu-west-1]
scanners:
  enabled: [prowler, iam]
  timeout_seconds: 3600      # per scanner
```
### Add the workflow

```yaml title=".github/workflows/cloud-posture.yml"
name: Cloud posture

on:
  schedule:
    - cron: "0 5 * * 1-5"     # weekdays 05:00 UTC
  workflow_dispatch:

permissions:
  contents: read
  id-token: write              # lets the job request an OIDC token

concurrency:
  group: cloud-posture
  cancel-in-progress: false

jobs:
  posture:
    runs-on: ubuntu-latest
    timeout-minutes: 120
    steps:
      - uses: actions/checkout@v7

      - uses: actions/setup-python@v7
        with:
          python-version: "3.12"

      - name: Cache pip and the Trivy database
        uses: actions/cache@v6
        with:
          path: |
            ~/.cache/pip
            ~/.cache/trivy
          key: cloudg-0.6.0-${{ runner.os }}

      - name: Install cloudg and scanners
        run: |
          pip install "cloudg[aws]==0.6.0" parliament
          pipx install prowler

      - name: Assume the audit role
        uses: aws-actions/configure-aws-credentials@v6
        with:
          role-to-assume: arn:aws:iam::123456789012:role/cloudg-github
          role-session-name: cloudg-${{ github.run_id }}
          aws-region: us-east-1

      - name: Run cloudg
        run: cloudg -c ci/cloudg.yaml run -p aws -o reports

      - name: Gate on severity
        run: python ci/severity_gate.py reports/findings.json --fail-on CRITICAL --min-assets 1

      - name: Job summary
        if: always()
        run: |
          python - <<'EOF' >> "$GITHUB_STEP_SUMMARY"
          import json
          s = json.load(open("reports/findings.json"))["summary"]
          print(f"### cloudg: {s['total_findings']} findings on {s['total_assets']} assets")
          for sev, n in sorted(s["severity_breakdown"].items()):
              print(f"- {sev}: {n}")
          EOF

      - name: Upload reports
        if: always()
        uses: actions/upload-artifact@v7
        with:
          name: cloudg-${{ github.run_id }}
          path: reports/
          retention-days: 30
```
::::

Credentials go through `configure-aws-credentials` here, which exports `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY` and `AWS_SESSION_TOKEN` for the whole job; cloudg's collectors and Prowler pick them up through the default chain. cloudg's own `--aws-role-arn` with `--aws-web-identity-token-file` works as well: cloudg then assumes the role itself and hands Prowler and ScoutSuite the temporary keys. The action has the advantage that every other step of the job gets the same credentials. [Authentication](/guides/authentication/#what-the-scanners-receive) has the details.

The action's session lasts one hour by default. A long organization-wide run can outlive it; raise `role-duration-seconds` (and the role's maximum session duration) or split the run per account.

`if: always()` on the upload matters: the gate fails the job, and so does `cloudg run` when it exits 3, and the reports are exactly what you want to look at when that happens.

### Pull requests without cloud access

Infrastructure changes can be gated before they reach an account. Checkov and Trivy scan the branch, cloudg aggregates and deduplicates, the gate decides. No OIDC permission is needed, so this job is safe on forks.

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

      - name: Install tools
        run: |
          pip install "cloudg==0.6.0"
          pipx install checkov
          curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin

      - name: Scan
        run: |
          checkov -d infra --output json > checkov.json || true
          trivy fs --format json --scanners vuln,misconfig,secret --output trivy-fs.json infra

      - name: Aggregate
        run: cloudg ingest --checkov checkov.json --trivy trivy-fs.json -o reports

      - name: Gate
        run: python ci/severity_gate.py reports/findings.json --fail-on HIGH

      - uses: actions/upload-artifact@v7
        if: always()
        with:
          name: iac-gate-${{ github.event.pull_request.number }}
          path: reports/
```

`|| true` after Checkov is deliberate: Checkov exits 1 when any check fails, and the decision belongs to the gate, which sees the deduplicated result. The core `cloudg` package is enough here, since ingest needs no cloud SDK.

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
    key: cloudg-0.6.0
    paths: [.cache/pip]
  before_script:
    - pip install "cloudg[aws]==0.6.0" parliament pipx
    - pipx install prowler
    - export PATH="$HOME/.local/bin:$PATH"
    - echo "$AWS_ID_TOKEN" > "$CI_PROJECT_DIR/.web-identity-token"
    - export AWS_WEB_IDENTITY_TOKEN_FILE="$CI_PROJECT_DIR/.web-identity-token"
  script:
    - cloudg -c ci/cloudg.yaml run -p aws -o reports
    - python ci/severity_gate.py reports/findings.json --fail-on CRITICAL --min-assets 1
  artifacts:
    when: always
    paths: [reports/]
    expire_in: 30 days
```

Do not also pass `--aws-role-arn` here. With `AWS_WEB_IDENTITY_TOKEN_FILE` set in the environment, cloudg would treat that ARN as its own OIDC target and do the exchange itself, which works for the collectors but leaves Prowler on the default chain anyway. Create the schedule under CI/CD, Schedules; the `web` rule lets you start a run by hand.

## Scheduled inventory snapshots

A map is cheaper than a full run and changes less often than findings. A nightly `cloudg map` gives you `inventory-map.json`, `inventory-dependencies.json` and, with `--org`, `inventory-organization.json`, ready for `cloudg deps`, for diffing, or for an [MCP server](/cli/mcp-serve/) to load.

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
      - run: pip install "cloudg[aws]==0.6.0"
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

Throttling during a map is recorded in coverage and in the `throttling` block of `inventory-map.json` rather than failing the job, so check that block when a snapshot looks thin. Several pipelines mapping the same account at once share its API quota; stagger their schedules, or lower `ratelimit.aws.max_rps` for the CI config as described in [rate limits](/guides/rate-limits/).

## Caching and artifacts

Three things are worth caching. pip's wheel cache saves the install of the cloud SDKs on every run. Trivy's vulnerability database (`~/.cache/trivy`) is a sizeable download; with the cache restored, Trivy only fetches it again when its copy is out of date. Pin the cloudg version in both the install command and the cache key, so an upgrade invalidates the cache instead of mixing versions.

Do not cache `reports/`. Publish it as an artifact instead. A run's useful files:

| File | Use in CI |
|---|---|
| `findings.json` | the gate's input; also re-renders later with `cloudg report -i` |
| `report.html` | self-contained, opens from the artifact download |
| `raw-findings.json` | written by `ingest` (and `scan`): findings before deduplication, for debugging the normaliser |
| `inventory-map.json` | the map from `cloudg map`, loadable with `InventoryResult.load` |
| `ontology.ttl`, `rag_chunks.jsonl` | feed downstream analysis or a retrieval index |

The reports describe your estate in detail: account IDs, ARNs, open ports, IAM grants. Keep artifact retention short and the repository private, and use the Docker image or a private runner when the reports must not leave your network. See [Docker](/guides/docker/) for the image, which bundles Prowler, Checkov and Trivy.

:::links
- [Authentication](/guides/authentication/) Every credential method and its precedence.
- [Python recipes](/guides/python-recipes/) The gate and the pipeline from Python.
- [Ingesting existing output](/guides/ingesting/) What `cloudg ingest` accepts.
- [cloudg run](/cli/run/) Every flag of the full pipeline.
:::
