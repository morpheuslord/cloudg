# cloudg documentation

**cloudg** (cloud graphing) maps AWS, Azure and GCP infrastructure into a graph, runs security scanners over the same inventory, and turns the results into reports, an ontology, RAG chunks and Terraform recreation files.

This page is the full feature reference: every CLI command, the Python API, configuration, the scanner integrations (including running cloudg on scan outputs you already have), the compliance ruleset system, and the plugin interface.

- [Installation](#installation)
- [The pipeline at a glance](#the-pipeline-at-a-glance)
- [CLI reference](#cli-reference)
  - [`cloudg run`](#cloudg-run--full-pipeline)
  - [`cloudg collect`](#cloudg-collect--asset-collection-only)
  - [`cloudg scan`](#cloudg-scan--scanners-only)
  - [`cloudg ingest`](#cloudg-ingest--use-existing-scanner-outputs)
  - [`cloudg report`](#cloudg-report--re-render-reports)
- [Scanners](#scanners)
- [Working with existing scan results](#working-with-existing-scan-results)
- [Deduplication and the combination rulesets](#deduplication-and-the-combination-rulesets)
- [Compliance frameworks](#compliance-frameworks)
- [Graph, ontology, RAG and Terraform outputs](#graph-ontology-rag-and-terraform-outputs)
- [Configuration file](#configuration-file)
- [Python API](#python-api)
- [Plugin system](#plugin-system)
- [Authentication](#authentication)
- [Docker](#docker)

---

## Installation

From PyPI:

```bash
pip install cloudg            # core: graph engine, normaliser, renderers, ingest
pip install cloudg[aws]       # + boto3 / aioboto3 for AWS collection
pip install cloudg[azure]     # + Azure SDKs
pip install cloudg[gcp]       # + GCP SDKs
pip install cloudg[all]       # everything
```

The cloud SDKs are optional extras. The core package with no extras still gives you the graph engine, the ontology, the findings normaliser, the report renderers, and `cloudg ingest` — enough to aggregate existing scanner outputs on a machine with no cloud credentials at all.

The external scanners — [Prowler](https://github.com/prowler-cloud/prowler), [ScoutSuite](https://github.com/nccgroup/ScoutSuite), [Checkov](https://github.com/bridgecrewio/checkov), [Trivy](https://trivy.dev/) — are separate executables, **not** Python dependencies. Install whichever subset you want; cloudg detects what is on `PATH` and skips the rest with a warning. `install.sh` (Linux/macOS) and `install.bat` (Windows) set up everything including the scanners and cloud CLIs. The Docker image bundles all four scanners.

Python 3.11 or newer.

## The pipeline at a glance

```
collect ──> graph (reachability, attack paths) ──> ontology / RAG / terraform
   │                                                        │
   └──> scanners (prowler, scoutsuite, checkov, trivy, iam) │
                     │                                      │
                     └──> normalise (dedupe, score, map) ──> reports (HTML, JSON, SVG)
```

1. **Collect** — asyncio collection from every configured provider, account and region in parallel. Regions are auto-discovered with `--regions all`.
2. **Graph** — assets and network edges go into a directed NetworkX graph; BFS from the internet node finds exposed resources, and blast-radius scoring estimates what an attacker could reach from each node.
3. **Scan** — the enabled scanners run concurrently over the same inventory. Each is optional (see [Scanners](#scanners)).
4. **Normalise** — findings from all sources are deduplicated within and across scanners, rescored against CVSS, and mapped to 28 compliance frameworks.
5. **Report** — interactive HTML, findings JSON, SVG/GraphML/Cytoscape topology, RDF ontology, RAG chunks, Terraform recreation.

Every phase degrades gracefully: a missing scanner binary, an unreachable provider, or a failed exporter logs a warning and the rest of the pipeline continues.

## CLI reference

Global options come before the subcommand: `cloudg -v -c my-config.yaml <command>`.

| Option | Meaning |
|---|---|
| `-v, --verbose` | debug logging |
| `-c, --config` | path to `config.yaml` |
| `--log-file` | also log to a file |

### `cloudg run` — full pipeline

```bash
cloudg run -p aws --regions us-east-1
cloudg run -p all --regions all                  # every provider, every region
cloudg run -p aws --regions us-east-1 --terraform
cloudg run -p aws --scanners prowler,trivy       # subset of scanners
```

| Flag | Meaning |
|---|---|
| `-p, --provider` | `aws`, `azure`, `gcp` or `all`; repeatable |
| `--regions` | `all` for auto-discovery, or a comma-separated list |
| `--scanners` | comma-separated subset of `prowler,scoutsuite,checkov,trivy,iam`; defaults to `scanners.enabled` in config |
| `--iac-dir` | directory for the IaC scanners (Checkov, Trivy fs) |
| `--images` | container images for Trivy |
| `--ontology/--no-ontology` | RDF ontology export (on by default) |
| `--rag-export/--no-rag-export` | RAG chunk export (on by default) |
| `--terraform/--no-terraform` | Terraform recreation (off by default) |
| `-o, --output` | output directory, `./reports` by default |

Credential flags (`--profile`, `--aws-role-arn`, `--azure-client-id`, `--gcp-credentials-file`, …) are listed under [Authentication](#authentication).

When no IaC directory is configured but `--terraform` is on, the IaC scanners target the generated Terraform recreation of the live infrastructure — so Checkov audits your actual cloud, not whatever directory cloudg happens to run from.

### `cloudg collect` — asset collection only

```bash
cloudg collect -p aws --profile prod --region eu-west-1 -o ./reports
```

Collects assets and network edges from one provider and writes them to the output directory. Useful for building the graph without running any scanners.

### `cloudg scan` — scanners only

```bash
cloudg scan -p aws --scanners prowler,checkov --iac-dir ./terraform
```

Runs the selected scanners concurrently and writes `raw-findings.json`. No collection, no graph.

### `cloudg ingest` — use existing scanner outputs

Already ran the scanners somewhere else — CI, a scheduled job, another machine, a colleague's laptop? Feed cloudg their native output files and it does the aggregation half of the pipeline: normalisation, cross-scanner deduplication via the check-equivalence rulesets, compliance mapping, and report generation. **No scanners are executed and no cloud credentials are needed.**

```bash
cloudg ingest \
  --prowler ./prowler-output/ \
  --scoutsuite ./scoutsuite-report/ \
  --checkov ./results_json.json \
  --trivy ./trivy-image.json --trivy ./trivy-fs.json \
  -o ./reports
```

| Flag | Accepts |
|---|---|
| `--prowler` | ASFF JSON/JSONL file, or Prowler's `-o` output directory (searched recursively for `*.json`) |
| `--scoutsuite` | the `scoutsuite_results_*.js` file, or the `--report-dir` directory |
| `--checkov` | a `checkov --output json` file (or `results_json.json`), or a directory containing it |
| `--trivy` | a `trivy image\|fs --format json` file, or a directory of them; image and filesystem scans are told apart automatically by `ArtifactType` |
| `--format` | `html`, `json` or `all` (default) |
| `-o, --output` | output directory |

Every flag is repeatable and any combination or subset of tools works — one tool alone, or all four together. Generate the scanner outputs with:

```bash
prowler aws -M json-asff -o ./prowler-output
scout aws --report-dir ./scoutsuite-report --no-browser
checkov -d ./iac --output json > results_json.json
trivy image --format json myrepo/app:latest > trivy-image.json
trivy fs --format json --scanners vuln,misconfig,secret ./iac > trivy-fs.json
```

### `cloudg report` — re-render reports

```bash
cloudg report -i ./reports/findings.json --format html
```

Re-generates HTML/JSON/SVG reports from the `findings.json` of a previous run without touching the cloud or the scanners.

## Scanners

| Scanner | What it covers | Binary | Native output cloudg understands |
|---|---|---|---|
| **Prowler** | CSPM checks for AWS/Azure/GCP | `prowler` | ASFF JSON / JSONL |
| **ScoutSuite** | multi-cloud configuration audit | `scout` | `scoutsuite_results_*.js` |
| **Checkov** | IaC static analysis (Terraform, CloudFormation, ARM, Kubernetes) | `checkov` | JSON results |
| **Trivy** | container image CVEs, secrets, IaC misconfigurations, filesystem scans | `trivy` | JSON (image and fs) |
| **IAM linter** | IAM policy analysis over collected assets (parliament / policy_sentry when installed) | built in | — |

Points worth knowing:

- Scanner selection is explicit: `scanners.enabled` in `config.yaml` or `--scanners` on the CLI. Default is all five.
- A scanner whose binary is missing is skipped with a warning — the rest of the pipeline is unaffected. You can install any subset.
- All scanners run concurrently in a thread pool, each with its own timeout (`scanners.timeout_seconds`).
- The IAM linter needs no external binary and always runs when assets exist.

## Working with existing scan results

Three layers, depending on how much control you want:

**CLI** — [`cloudg ingest`](#cloudg-ingest--use-existing-scanner-outputs), described above.

**One call, full pipeline** — `CloudGEngine.run_from_reports()`:

```python
from cloudg import CloudGConfig, CloudGEngine

engine = CloudGEngine(CloudGConfig())
result = engine.run_from_reports_sync(
    {
        "prowler": ["./prowler-output/"],
        "trivy": ["./trivy-image.json", "./trivy-fs.json"],
    },
    output_dir="./reports",
)
print(result.total_findings, result.severity_breakdown)
print(result.report_paths["html"])
```

**Building blocks** — parse and normalise yourself:

```python
from cloudg.ingest import parse_report, ingest_reports

findings = parse_report("prowler", "./prowler-output/")
# or several tools at once:
findings = ingest_reports({"prowler": ["./out/"], "checkov": ["results_json.json"]})

engine = CloudGEngine(CloudGConfig())
scan_result = engine.normalise_findings(findings)   # dedupe + equivalence + compliance
```

Each scanner class also exposes the parser directly: `ProwlerScanner.parse_report(path)`, `ScoutSuiteScanner.parse_report(path)`, `CheckovScanner.parse_report(path)`, `TrivyScanner.parse_report(path)`.

Ingest mode runs no collection, so the outputs that need live assets (topology graph, ontology, RAG, Terraform) are empty. When you have credentials, combine both: `collect()` + `ingest_reports()` + `analyze()`.

## Deduplication and the combination rulesets

Findings are merged in two conservative passes:

1. **Within a scanner** — keyed on `(scanner, check ID, resource)`. The same check re-reported for the same resource (e.g. once per compliance framework, or via two report formats) collapses to one finding. Findings without a check ID fall back to their normalised title.
2. **Across scanners** — merged only when the normalised titles match **and** both check IDs resolve to the same canonical semantic ID in [`cloudg/rules/check_equivalence.yaml`](../cloudg/rules/check_equivalence.yaml). Example entry:

```yaml
- id: aws-s3-default-encryption
  title: S3 bucket default encryption at rest
  checks:
    prowler: [s3_bucket_default_encryption]
    checkov: [CKV_AWS_19]
    trivy: [AVD-AWS-0088]
```

Checks not listed in the equivalence map are never merged across scanners: the safe failure mode is visible duplication, not silently dropping a scanner's coverage. Merging keeps the highest severity and unions the source tools and compliance frameworks, so a merged finding shows `source_tool: "prowler, checkov"`.

This works with whatever subset of tools contributed findings — running two tools instead of four simply means less to merge.

## Compliance frameworks

Findings are tagged with framework controls in four tiers, most precise first:

1. Whatever the scanner itself reports (Prowler ASFF `RelatedRequirements`, Checkov check IDs).
2. Exact check-ID lookup against the shipped rulesets — generated from Prowler's public compliance data (Apache-2.0), covering **28 frameworks, 4,166 controls, 10,236 check mappings** across AWS, Azure and GCP: CIS 5.0 per cloud, NIST 800-53 rev 5, NIST CSF 2.0, PCI DSS 4.0, SOC 2, HIPAA, GDPR, ISO 27001:2022, MITRE ATT&CK, AWS Foundational Security Best Practices, and more.
3. Regex pattern rules for scanners that emit no compliance metadata.
4. A small built-in fallback table.

Add your own framework by dropping a YAML file into the rules directory:

```yaml
framework: MY-FRAMEWORK
controls:
  - id: "MF-1.1"
    title: "Storage is encrypted"
    patterns: ["encrypt.*rest"]        # regex tier
    checks: ["s3_default_encryption"]  # exact tier, optional
```

`cloudg/policies/` additionally ships Cloud Custodian policy packs (AWS governance, AWS security, Azure, GCP) you can run with `custodian run` independently of cloudg.

## Graph, ontology, RAG and Terraform outputs

| Output | What it is |
|---|---|
| `report.html` | interactive report — D3 topology, findings table, compliance matrix; works offline |
| `findings.json` | all findings, assets, edges and compliance results |
| `topology.svg`, `topology.graphml`, `topology-cytoscape.json` | the graph in three formats |
| `ontology.ttl`, `ontology.jsonld` | RDF ontology — ~62 inferred typed relations (`exposed_to_internet`, `assumes_role`, `encrypted_by`, `hosted_in_vpc`, …), SPARQL-queryable |
| `rag_chunks.jsonl`, `rag_metadata_index.json` | the graph chunked three ways (per asset, per Louvain community, per relation domain) for LLM retrieval pipelines |
| `terraform/*.tf.json`, `terraform/import.sh` | Terraform recreation of the live infrastructure (25+ asset types) with an import script to adopt it into state |

## Configuration file

`config.yaml` (or `-c path`) mirrors every CLI flag and adds the persistent settings. The shipped [config.yaml](../config.yaml) documents every field; the highlights:

```yaml
providers: [aws]              # aws, azure, gcp

aws:
  regions: [us-east-1]        # or "all"
  accounts: []                # multi-account fan-out
  role_name: OrganizationAccountAccessRole

scanners:
  enabled: [prowler, scoutsuite, checkov, trivy, iam]
  timeout_seconds: 3600
  iac_directories: []         # targets for Checkov / Trivy fs
  trivy_images: []
  prowler_extra_args: []      # per-scanner passthrough args

ontology:
  enabled: true
  export_formats: [turtle, json-ld]

rag:
  enabled: true
  max_chunk_tokens: 512

terraform:
  enabled: false

rulesets:
  rules_dir: null             # defaults to the packaged cloudg/rules/
```

## Python API

`CloudGEngine` is the integration entry point — async-first with sync wrappers, designed for embedding in larger systems (SIEMs, orchestration platforms, [hol-guard](https://github.com/hashgraph-online/hol-guard)-style command extensions).

```python
from cloudg import CloudGConfig, CloudGEngine

config = CloudGConfig(providers=["aws"])
config.aws.role_arn = "arn:aws:iam::123456789012:role/scanner"

engine = CloudGEngine(config)
engine.on_finding = lambda f: forward_to_siem(f)

result = engine.run_pipeline_sync()      # or: await engine.run_pipeline()
print(result.to_summary())
```

Phase methods, usable independently:

| Method | Does |
|---|---|
| `collect()` | multi-provider asset collection → `CollectionResult` |
| `scan(assets, edges, ...)` | run enabled scanners + graph reachability → findings |
| `ingest_reports(reports)` | parse existing scanner outputs → findings (no execution) |
| `normalise_findings(findings)` | dedupe, merge, score, compliance-map → `ScanResult` |
| `analyze(assets, edges, findings)` | graph, ontology, RAG, Terraform → `AnalysisResult` |
| `run_pipeline()` / `run_pipeline_sync()` | everything → `PipelineResult` |
| `run_from_reports()` / `run_from_reports_sync()` | ingest → normalise → reports → `PipelineResult` |

Event hooks for streaming integration: `on_phase_start`, `on_collection_complete`, `on_finding`, `on_scan_complete`, `on_analysis_complete`, `on_error`. All are plain callables; exceptions raised inside a hook are swallowed so they cannot break the pipeline.

`PipelineResult` carries the assets, edges, findings, `ScanResult`, report paths, coverage records and a `to_summary()` dict for downstream consumption.

## Plugin system

Custom collectors and scanners register through setuptools entry points — no core changes needed:

```toml
[project.entry-points."cloudg.collectors"]
mycloud = "my_package.collector:MyCollector"

[project.entry-points."cloudg.scanners"]
myscanner = "my_package.scanner:MyScanner"
```

A scanner plugin needs a `run() -> list[Finding]` method; a collector plugin follows the base collector interface in `cloudg/collectors/base.py`. `PluginRegistry` discovers entry points at startup and falls back to the built-ins for anything not overridden.

## Authentication

Every provider supports several auth methods, resolved in a fixed priority order, so the same config works on a laptop, in CI, and on cloud compute.

**AWS** — direct keys (`--aws-key` / `--aws-secret` / `--aws-session-token`), OIDC web identity federation (`--aws-role-arn` + `--aws-web-identity-token-file`; the GitHub Actions / EKS pattern), a named profile (`--profile`, including SSO), or the default chain (env vars, cached SSO, instance role). STS role assumption layers on top with `--aws-role-arn` and `--aws-external-id`; multi-account fan-out uses `accounts` + `role_name` in the config.

**Azure** — workload identity federation (`--azure-tenant-id`, `--azure-client-id`, `--azure-federated-token-file`), service principal with secret (`--azure-client-secret`) or certificate (`--azure-cert-path`), managed identity (`--azure-managed-identity`), or the `DefaultAzureCredential` chain (covers `az login`).

**GCP** — a credentials file (`--gcp-credentials-file`: service account key or workload identity federation config), or application default credentials. `--gcp-impersonate-sa` layers service account impersonation on either.

## Docker

The image bundles all four scanners:

```bash
docker build -t cloudg:latest .
docker compose run --rm cloudg run -p aws --regions us-east-1

# or from GitHub Container Registry
docker pull ghcr.io/morpheuslord/cloudg:latest
```

---

*Found a gap in these docs? [Open an issue](https://github.com/morpheuslord/cloudg/issues).*
