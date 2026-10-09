---
command: scan
lede: Runs the external security scanners on their own and saves what they found, without collecting assets or normalising.
intro: |
  `cloudg scan` is the scanner phase of `cloudg run` cut loose from the rest. It is handy for checking that your scanner binaries work, or for producing a `raw-findings.json` to merge into a map later. For a complete assessment with deduplication and reports, use [cloudg run](/cli/run/).
---

## How it works

The command reads its flags and nothing else. Unlike `run` and `map`, it does not use the config loaded with `cloudg -c`, so `scanners.enabled`, the `*_extra_args` lists, `checkov_frameworks`, `iac_directories` and `trivy_images` have no effect here. Pass everything on the command line.

`--scanners` is a comma-separated list. It defaults to `prowler,checkov`. Each scanner you name becomes one job, and all jobs run in parallel threads with a progress display:

| Scanner | What it runs |
|---|---|
| `prowler` | `prowler <provider> -M json-asff -o <output>/prowler`, with `-p <profile>` when the provider is `aws` |
| `scoutsuite` | `scout <provider> --report-dir <output>/scoutsuite --no-browser`, with `--profile` for `aws` |
| `checkov` | Checkov against `--iac-dir` |
| `trivy` | `trivy image` for each entry in `--images`; with no images, a filesystem scan of `--iac-dir` |
| `iam` | Nothing. The IAM linter needs collected assets, which `scan` does not have, so the name is accepted and ignored. |

`-p/--provider` is passed straight to Prowler and ScoutSuite as their provider argument. It is free text (default `aws`) and takes one value, unlike the repeatable, validated `-p` on `run` and `map`.

`--iac-dir` defaults to the current directory. That is a difference from `cloudg run`, which refuses to fall back to `.` because a scan of an unrelated folder looks like a clean result. With `scan`, make sure you run it from your IaC repository or pass `--iac-dir`.

A scanner that is not installed logs a warning such as "Checkov is not installed. Install with: pip install checkov. Skipping Checkov scan." and reports 0 findings. A scanner that raises is shown as failed. In both cases the other scanners carry on, and the command still writes its output file.

Here is a run on a machine where neither Checkov nor Trivy is installed:

```console
$ cloudg scan --scanners checkov,trivy,iam --iac-dir ./iac -o out
╭────── Scan Configuration ───────╮
│  Provider  aws                  │
│  Scanners  checkov, trivy, iam  │
╰─────────────────────────────────╯
  ⚠ Trivy: no images specified, falling back to filesystem scan
  ✓ Checkov: 0 findings            0:00:00
  ✓ Trivy (filesystem): 0 findings 0:00:00

  ✓ Total: 0 findings
  ✓ Raw findings: out/raw-findings.json
```

The "not installed" warnings are log lines and are left out above. Zero findings next to a green tick does not mean the code is clean; check the log output, or run `checkov --version` and `trivy --version` first.

## Examples

Run the defaults, Prowler and Checkov, from the root of your Terraform repository:

```bash
cloudg scan -p aws --profile audit
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

Prowler and ScoutSuite want an explicit auth argument for Azure (`--az-cli-auth`, `--cli` and similar). `scan` cannot pass extra arguments, so for Azure use `cloudg run` with `scanners.prowler_extra_args` and `scanners.scoutsuite_extra_args` in your config.

Scan, then overlay the raw findings on an inventory map:

```bash
cloudg scan -p aws --profile audit --scanners prowler -o ./reports
cloudg map -p aws --profile audit --regions all --findings ./reports/raw-findings.json -o ./reports
```

## Output files

| File | Contents |
|---|---|
| `raw-findings.json` | All findings from all scanners as a JSON list, before deduplication or compliance mapping |
| `prowler/` | Prowler's native ASFF output, when Prowler ran |
| `scoutsuite/` | ScoutSuite's native report, when ScoutSuite ran |

`scan` writes no `findings.json` and no HTML report. To get them from these results, feed the native files to [cloudg ingest](/cli/ingest/), for example `cloudg ingest --prowler ./reports/prowler/`.

## Exit codes

`scan` exits 0 once `raw-findings.json` is written, whether or not any scanner worked. Click returns 2 for a malformed option. If you need a failing exit status when a scanner is missing, check for the binaries in your script before calling cloudg.

## Related

:::links
- [Running scanners](/guides/running-scanners/) Install and configure Prowler, ScoutSuite, Checkov and Trivy.
- [cloudg run](/cli/run/) Scanners plus collection, graph, normalisation and reports.
- [cloudg ingest](/cli/ingest/) Normalise and report on scanner output.
- [Provider and region flags](/cli/provider-flags/) How `-p` differs between commands.
:::
