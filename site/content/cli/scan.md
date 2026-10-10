---
command: scan
lede: Runs the external security scanners on their own and saves what they found, without collecting assets or normalising.
intro: |
  `cloudg scan` is the scanner phase of `cloudg run` cut loose from the rest. It is handy for checking that your scanner binaries work, or for producing a `raw-findings.json` to merge into a map later. For a complete assessment with deduplication and reports, use [cloudg run](/cli/run/).
---

## How it works

`scan` reads the config loaded with `cloudg -c`, like `run` and `map`, and plans its scanner jobs with the same code as `cloudg run`. From the config it takes `scanners.enabled` (the default for `--scanners`), the `*_extra_args` lists, `checkov_frameworks`, `iac_directories`, `trivy_images` and `timeout_seconds`, plus the AWS credentials and regions (`aws.profile`, keys, `role_arn`, web identity, `aws.regions`). Flags replace the matching config values. Without `-c`, the built-in defaults apply: all five scanners, a 3600-second timeout.

`--scanners` is a comma-separated list of built-in names or [scanner plugin](/api/entry-points/) names; an unknown name is skipped with a warning. Each scanner becomes one or more jobs, and all jobs run in parallel threads with a progress display:

| Scanner | What it runs |
|---|---|
| `prowler` | `prowler <provider> -M json-asff -o <output>/prowler/<provider>`, with the AWS credentials (`-p <profile>`, or keys in the environment) and `-f <regions>` for an explicit `aws.regions` list |
| `scoutsuite` | `scout <provider> --report-dir <output>/scoutsuite/<provider> --no-browser`, with the same AWS credentials and `--regions` |
| `checkov` | Checkov against each IaC directory |
| `trivy` | `trivy image` for the images from `--images` or `scanners.trivy_images`; with no images, a filesystem scan of the IaC directories |
| `iam` | The IAM linter on the assets in `--assets`. Without `--assets` it is skipped with a warning. |

`-p/--provider` is the provider Prowler and ScoutSuite audit: `aws`, `azure` or `gcp` (default `aws`), one value, unlike the repeatable `-p` on `run` and `map`.

The IaC directories come from `--iac-dir`, else `scanners.iac_directories`. There is no fallback to the current directory: with neither set, Checkov and the Trivy filesystem scan are skipped with a warning, because a scan of an unrelated folder would look like a clean result.

`--assets` takes a file with a top-level `assets` list: `inventory-<provider>.json` from `cloudg collect`, `inventory-map.json` from `cloudg map` (or the directory holding it), or a `findings.json`. The IAM linter reads the IAM policies of those assets.

A scanner that is not installed is skipped before the others start and listed as `<scanner>: not installed`. A scanner that raises, or runs longer than `scanners.timeout_seconds`, is shown as failed and its error is printed at the end; a timed-out scanner keeps the findings it produced before that. The other scanners carry on, and the command writes `raw-findings.json` with what the rest found.

Here is a run on a machine where neither Checkov nor Trivy is installed, with a map for the IAM linter:

```console
$ cloudg scan --scanners checkov,trivy,iam --iac-dir ./iac --assets ./inventory-map.json -o out
──────────────────────────────── Security Scan ─────────────────────────────────
╭────────── Scan Configuration ──────────╮
│         Provider  aws                  │
│         Scanners  checkov, trivy, iam  │
│  IaC directories  ./iac                │
│           Assets  2                    │
│          Timeout  3600s per scanner    │
╰────────────────────────────────────────╯
  ⊘ Prowler: not enabled
  ⊘ ScoutSuite: not enabled
  ⊘ Checkov: not installed (pip install checkov)
  ⊘ Trivy: not installed (https://trivy.dev/)
  ✓ IAM linter: 0 findings 0:00:00

  ✓ Total: 0 findings
  ✓ Raw findings: out/raw-findings.json
```

Log lines are left out above.

## Examples

Run the scanners from your config, with Checkov on the Terraform code in `scanners.iac_directories`:

```bash
cloudg -c config.yaml scan -p aws --profile audit
```

Check Terraform code in another folder with Checkov only:

```bash
cloudg scan --scanners checkov --iac-dir ./infra/terraform -o ./reports
```

Scan two container images with Trivy:

```bash
cloudg scan --scanners trivy --images registry.example.com/api:1.4.2,registry.example.com/worker:1.4.2
```

Run Prowler against a GCP project with your application default credentials:

```bash
cloudg scan -p gcp --scanners prowler -o ./reports/gcp
```

Prowler and ScoutSuite want an explicit auth argument for Azure (`--az-cli-auth`, `--cli` and similar). Put it in `scanners.prowler_extra_args` and `scanners.scoutsuite_extra_args` and pass the config:

```bash
cloudg -c azure.yaml scan -p azure --scanners prowler,scoutsuite -o ./reports/azure
```

Lint the IAM policies of a saved inventory map:

```bash
cloudg scan --scanners iam --assets ./reports/inventory-map.json -o ./reports/iam
```

Scan, then overlay the raw findings on an inventory map:

```bash
cloudg scan -p aws --profile audit --scanners prowler -o ./reports
cloudg map -p aws --profile audit --regions all --findings ./reports/raw-findings.json -o ./reports
```

## Output files

| File | Contents |
|---|---|
| `raw-findings.json` | All findings from all scanners as a JSON list, before deduplication or compliance mapping |
| `prowler/<provider>/` | Prowler's native ASFF output, when Prowler ran |
| `scoutsuite/<provider>/` | ScoutSuite's native report, when ScoutSuite ran |

`scan` writes no `findings.json` and no HTML report. To get them, run `cloudg report -i ./reports/raw-findings.json -o ./reports/html`, which normalises the raw findings first, or feed the native files to [cloudg ingest](/cli/ingest/), for example `cloudg ingest --prowler ./reports/prowler/aws/`.

## Exit codes

| Code | When |
|---|---|
| 0 | At least one requested scanner ran to the end; `raw-findings.json` is written |
| 1 | None of the requested scanners could run (not installed, nothing to scan, AWS credentials that did not resolve), every one of them failed, or `--assets` could not be read |
| 2 | Click rejected an option, such as `-p aws2` |

A missing scanner next to one that worked still exits 0, so check the `not installed` lines, or the binaries, when a particular scanner matters.

## Related

:::links
- [Running scanners](/guides/running-scanners/) Install and configure Prowler, ScoutSuite, Checkov and Trivy.
- [cloudg run](/cli/run/) Scanners plus collection, graph, normalisation and reports.
- [cloudg ingest](/cli/ingest/) Normalise and report on scanner output.
- [Provider and region flags](/cli/provider-flags/) How `-p` differs between commands.
:::
