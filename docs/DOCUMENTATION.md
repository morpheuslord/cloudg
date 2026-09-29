# cloudg reference

cloudg (cloud graphing) maps AWS, Azure and GCP infrastructure into a graph, runs security scanners over that inventory, and merges every finding into one deduplicated, compliance-mapped result set. It can also skip the scanning entirely and aggregate outputs you already have.

This is the complete reference: every CLI command, the exact input and output formats, the data models, the full Python API with integration examples, configuration, plugins and authentication. Release history lives in the [changelog](https://github.com/morpheuslord/cloudg/blob/main/CHANGELOG.md).

Contents:

- [Installation](#installation)
- [The pipeline](#the-pipeline)
- [CLI reference](#cli-reference)
- [Input requirements](#input-requirements)
- [Output contract](#output-contract)
- [Data models](#data-models)
- [Configuration](#configuration)
- [Python API](#python-api)
- [Integration recipes](#integration-recipes)
- [Plugin system](#plugin-system)
- [Authentication](#authentication)
- [Docker](#docker)

## Installation

From PyPI:

```bash
pip install cloudg            # core
pip install cloudg[aws]       # + boto3, aioboto3
pip install cloudg[azure]     # + Azure management SDKs
pip install cloudg[gcp]       # + google-cloud-asset, google-auth
pip install cloudg[all]       # every provider SDK
```

The cloud SDKs are optional extras, pulled in only when you collect from that provider. The core package alone ships the graph engine, the ontology builder, the findings normaliser, the report renderers and `cloudg ingest`. That is enough to aggregate existing scan results on a machine with no cloud access at all.

The external scanners are separate executables, not Python dependencies: [Prowler](https://github.com/prowler-cloud/prowler) (`pip install prowler`), [ScoutSuite](https://github.com/nccgroup/ScoutSuite) (`pip install scoutsuite`), [Checkov](https://github.com/bridgecrewio/checkov) (`pip install checkov`) and [Trivy](https://trivy.dev/) (binary install). Install whichever subset you want. cloudg checks `PATH` at run time and skips anything missing with a warning; the rest of the pipeline is unaffected. `install.sh` (Linux/macOS) and `install.bat` (Windows) set up all of them plus the cloud CLIs, and the Docker image bundles the four scanner binaries.

Requires Python 3.11 or newer.

## The pipeline

```
collect -> graph -> scan -> normalise -> report
                \-> ontology / RAG / terraform
```

Collection runs all configured providers concurrently with asyncio, iterating accounts and regions per provider. Regions auto-discover when you pass `--regions all`. Assets and network edges go into a directed NetworkX graph: BFS from the internet node finds exposed resources, and blast-radius scoring estimates what an attacker could reach from each node.

The enabled scanners then run in parallel over the same inventory, each in its own thread with its own timeout. Their findings, plus the graph's own reachability findings and the built-in IAM linter's results, all flow into the normaliser, which deduplicates within and across scanners, rescores against CVSS, and maps everything to compliance controls. The renderers turn the final `ScanResult` into the report files listed under [Output contract](#output-contract).

Every phase degrades gracefully. A missing scanner binary, an unreachable provider or a failed exporter logs a warning; nothing else stops.

## CLI reference

Global options go before the subcommand: `cloudg -v -c my-config.yaml run ...`

| Option | Meaning |
|---|---|
| `-v, --verbose` | debug logging |
| `-c, --config PATH` | path to `config.yaml` |
| `--log-file PATH` | also write logs to a file |

### cloudg run

The full pipeline: collect, graph, scan, normalise, report.

```bash
cloudg run -p aws --regions us-east-1
cloudg run -p all --regions all
cloudg run -p aws --scanners prowler,trivy
cloudg run -p aws --regions us-east-1 --terraform
```

| Flag | Meaning |
|---|---|
| `-p, --provider` | `aws`, `azure`, `gcp` or `all`; repeatable |
| `--regions` | `all` for auto-discovery, or a comma-separated list |
| `--scanners` | subset of `prowler,scoutsuite,checkov,trivy,iam`; defaults to `scanners.enabled` in config |
| `--iac-dir` | directory for the IaC scanners (Checkov, Trivy fs) |
| `--images` | comma-separated container images for Trivy |
| `--ontology / --no-ontology` | RDF export, on by default |
| `--rag-export / --no-rag-export` | RAG chunks, on by default |
| `--terraform / --no-terraform` | Terraform recreation, off by default |
| `-o, --output` | output directory, `./reports` by default |

Credential flags are listed under [Authentication](#authentication).

A detail worth knowing: when no IaC directory is configured but `--terraform` is on, the IaC scanners target the generated Terraform recreation of the live infrastructure. Checkov then audits your actual cloud rather than whatever directory cloudg happens to run from. There is deliberately no fallback to `.`: a zero-finding scan of an unrelated directory reads like a clean bill of health, and cloudg refuses to produce one.

### cloudg collect

Asset collection alone, one provider at a time. Writes assets and edges without running any scanner.

```bash
cloudg collect -p aws --profile prod --region eu-west-1 -o ./reports
cloudg collect -p azure --subscription-id <id>
cloudg collect -p gcp --project-id <id>
```

### cloudg scan

Scanners alone, no collection. Writes `raw-findings.json`.

```bash
cloudg scan -p aws --scanners prowler,checkov --iac-dir ./terraform
```

### cloudg ingest

Aggregation without execution. Feed cloudg the native output files of scans that already ran (in CI, on another host, on a schedule) and it runs the normalisation half of the pipeline: cross-scanner dedupe via the check-equivalence rulesets, compliance mapping and report generation. No scanner executes and no cloud credentials are needed.

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
| `--prowler` | ASFF JSON or JSONL file, or Prowler's `-o` output directory (searched recursively for `*.json`) |
| `--scoutsuite` | the `scoutsuite_results_*.js` file, or the `--report-dir` directory |
| `--checkov` | a `checkov --output json` file (or `results_json.json`), or a directory containing it |
| `--trivy` | a `trivy image` or `trivy fs` JSON file, or a directory of them |
| `--format` | `html`, `json` or `all` (default) |
| `-o, --output` | output directory |

Every input flag is repeatable and any combination or subset of tools works: one tool alone, or all four together. See [Input requirements](#input-requirements) for the exact formats.

### cloudg report

Re-render reports from a previous run's `findings.json`. No cloud, no scanners.

```bash
cloudg report -i ./reports/findings.json --format html
```

`--format` takes `html`, `json`, `svg` or `all`.

## Input requirements

This section pins down exactly what each ingest path expects, and the command that produces it.

### Prowler

Produce:

```bash
prowler aws -M json-asff -o ./prowler-output
```

cloudg accepts the output directory itself or any single file from it. Files may be a JSON array or JSONL (one ASFF object per line); both parse. The fields cloudg reads from each ASFF finding:

```json
{
  "Id": "prowler-aws-s3_bucket_default_encryption-123456789012-eu-west-1-...",
  "Title": "S3 bucket default encryption",
  "Description": "...",
  "Severity": {"Label": "HIGH"},
  "Resources": [{"Id": "arn:aws:s3:::my-bucket"}],
  "Compliance": {"Status": "FAILED", "RelatedRequirements": ["CIS 2.1.1"]},
  "Remediation": {"Recommendation": {"Text": "..."}}
}
```

Findings with `Compliance.Status` of `PASSED` are skipped. The check name embedded in `Id` (the third dash-separated token) becomes the dedupe key.

### ScoutSuite

Produce:

```bash
scout aws --report-dir ./scoutsuite-report --no-browser
```

cloudg accepts the report directory (searched recursively for `scoutsuite_results*.js`) or the file itself. The file is JavaScript, a single JSON object assigned to a variable; cloudg strips the assignment and parses the JSON. Findings come from `services.<service>.findings.<key>`, where each entry with `flagged_items > 0` yields one finding per item in `items`. The `level` field maps to severity: `danger` becomes CRITICAL, `warning` HIGH, `caution` MEDIUM.

### Checkov

Produce:

```bash
checkov -d ./iac --output json > results_json.json
```

cloudg accepts the JSON file or a directory containing `results_json.json` (falling back to any `*.json` in the directory). Both shapes Checkov emits parse: a single `{check_type, results}` object, or a list of them when several frameworks ran. Findings come from `results.failed_checks[]`, reading `check_id`, `check_name`, `severity`, `resource`, `file_path`, `file_line_range` and `guideline`.

### Trivy

Produce either or both:

```bash
trivy image --format json myrepo/app:latest > trivy-image.json
trivy fs --format json --scanners vuln,misconfig,secret ./iac > trivy-fs.json
```

cloudg accepts a single JSON file or a directory of them. Each report's top-level `ArtifactType` decides the parser: `container_image` goes through the image parser (vulnerabilities and secrets), everything else (`filesystem`, `repository`) goes through the filesystem parser, which also handles misconfigurations. `ArtifactName` becomes the resource identifier. From each vulnerability cloudg reads `VulnerabilityID`, `PkgName`, `InstalledVersion`, `FixedVersion`, `Severity`, `Description` and the CVSS v3 score when present.

## Output contract

All commands write into the output directory (`./reports` by default).

| File | Contents |
|---|---|
| `report.html` | interactive report: D3 topology, findings table, compliance matrix. Self-contained, works offline. |
| `findings.json` | the machine-readable result, structure below |
| `raw-findings.json` | pre-normalisation findings (from `scan` and `ingest`) |
| `topology.svg`, `topology.graphml`, `topology-cytoscape.json` | the graph in three formats |
| `ontology.ttl`, `ontology.jsonld` | RDF ontology, around 62 inferred relation types, SPARQL-queryable |
| `rag_chunks.jsonl`, `rag_metadata_index.json` | retrieval-ready chunks, one JSON object per line |
| `terraform/*.tf.json`, `terraform/import.sh` | Terraform recreation of live infrastructure, 25+ asset types |

`findings.json` has this shape:

```json
{
  "metadata": {
    "scan_id": "uuid",
    "provider": "AWS",
    "account_id": "...",
    "region": "...",
    "started_at": "...",
    "completed_at": "..."
  },
  "summary": {
    "total_assets": 0,
    "total_findings": 0,
    "total_edges": 0,
    "severity_breakdown": {"CRITICAL": 0, "HIGH": 0},
    "compliance_frameworks": ["CIS", "NIST-800-53"]
  },
  "assets": [],
  "findings": [],
  "compliance": [],
  "graph": {"nodes": [], "links": []}
}
```

`assets`, `findings` and `compliance` are lists of the models below, serialised with Pydantic's JSON mode. `graph` is D3 force-layout data. `cloudg report -i` accepts this same file back, so the format round-trips.

## Data models

Everything flowing through cloudg is a Pydantic v2 model from `cloudg.schema.models`. All models allow extra fields, so scanner-specific attributes survive serialisation.

### Finding

The unit every scanner and parser produces.

| Field | Type | Notes |
|---|---|---|
| `id` | `str` | auto-generated UUID |
| `resource_id` | `str` | internal asset ID or native identifier |
| `resource_arn` | `str \| None` | cloud-native identifier when known |
| `severity` | `Severity` | `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO` |
| `title` | `str` | display title; scanner tags such as `[Checkov/terraform]` are stripped during cross-scanner comparison |
| `description` | `str` | |
| `evidence` | `str \| None` | file path, package version, raw product fields |
| `remediation` | `str \| None` | |
| `source_tool` | `str` | `"prowler"`, `"checkov"`, ...; becomes `"prowler, checkov"` after a merge |
| `source_finding_id` | `str \| None` | the scanner's own check or CVE ID; drives dedupe |
| `compliance_frameworks` | `list[str]` | unioned on merge |
| `cvss_score` | `float \| None` | 0.0 to 10.0 |
| `detected_at` | `datetime` | |
| `is_suppressed` | `bool` | |
| `risk_score` | computed `float` | severity base averaged with CVSS when present |

### CloudAsset

| Field | Type | Notes |
|---|---|---|
| `id` | `str` | auto UUID |
| `arn` | `str \| None` | native identifier |
| `name` | `str` | |
| `asset_type` | `AssetType` | 45-value taxonomy: `EC2`, `S3_BUCKET`, `IAM_ROLE`, `VPC`, `KMS_KEY`, ... |
| `provider` | `CloudProvider` | `AWS`, `AZURE`, `GCP` |
| `region` | `str` | `"global"` for regionless resources |
| `account_id` | `str \| None` | |
| `tags` | `dict[str, str]` | |
| `metadata` | `dict[str, Any]` | normalised extra attributes |
| `is_internet_exposed` | `bool` | set by the graph analysis |

### NetworkEdge

Directed edge between two asset IDs. `edge_type` is one of `SECURITY_GROUP_RULE`, `NACL_RULE`, `ROUTE`, `IAM_TRUST`, `IAM_POLICY_ATTACHMENT`, `CONTAINS`, `PEERING`, `LOAD_BALANCER_TARGET`, `INTERNET_EXPOSED`; the model also carries `ports`, `port_range`, `protocol`, `cidr` and `direction`.

### ComplianceResult

One control-level verdict: `framework` (for example `CIS`, `NIST-800-53`), `control_id`, `control_title`, `status` (`PASS`, `FAIL`, `NOT_APPLICABLE`, `MANUAL`) and the `finding_ids` behind it.

### ScanResult

The aggregate container the normaliser returns and the renderers consume: `assets`, `findings`, `edges`, `compliance`, timing fields, and a computed `summary` dict with totals and the severity breakdown.

## Configuration

`config.yaml` mirrors every CLI flag and adds persistent settings; pass it with `-c` or keep it next to where you run. Everything is optional, defaults are sensible. The shipped [config.yaml](https://github.com/morpheuslord/cloudg/blob/main/config.yaml) documents each field inline. The structure, with defaults:

```yaml
providers: [aws]                # aws, azure, gcp; several at once is fine

aws:
  regions: [us-east-1]          # or [all]
  accounts: []                  # multi-account fan-out
  role_name: null               # role to assume in each account
  role_arn: null                # single-account AssumeRole or OIDC target
  external_id: null
  web_identity_token_file: null
  profile: null
  max_retries: 10
  retry_mode: adaptive

azure:
  subscription_ids: []
  tenant_id: null
  client_id: null
  client_secret: null
  certificate_path: null
  federated_token_file: null
  use_managed_identity: false
  regions: [ALL]

gcp:
  project_ids: []
  credentials_file: null
  impersonate_service_account: null
  regions: [ALL]

scanners:
  enabled: [prowler, scoutsuite, checkov, trivy, iam]
  timeout_seconds: 3600
  iac_directories: []           # targets for Checkov and Trivy fs
  trivy_images: []
  checkov_frameworks: []        # empty = auto-detect
  prowler_extra_args: []        # passthrough args, per scanner

graph:
  persist_graphml: true
  compute_attack_paths: true

ontology:
  enabled: true
  export_formats: [turtle, json-ld]

rag:
  enabled: true
  chunk_strategy: hybrid        # entity | community | relation_group | hybrid
  max_chunk_tokens: 2000

terraform:
  enabled: false
  output_dir: ./reports/terraform

report:
  formats: [html, json, svg]
  inline_js: true               # air-gapped friendly

rulesets:
  rules_dir: null               # defaults to the packaged cloudg/rules/

concurrency_limit: 5
```

In code, the same structure is `CloudGConfig`, a Pydantic model:

```python
from cloudg import CloudGConfig, load_config

config = load_config("config.yaml")          # file, validated
config = CloudGConfig(providers=["aws"])     # or programmatic
config.scanners.enabled = ["prowler", "iam"]
config.aws.regions = ["eu-west-1", "eu-central-1"]
```

## Python API

`CloudGEngine` in `cloudg.api` is the integration entry point: async-first, sync wrappers included, built for embedding in larger systems (SIEM pipelines, orchestration platforms, command extensions such as [hol-guard](https://github.com/hashgraph-online/hol-guard)). The package root re-exports the essentials: `CloudGEngine`, `CloudGConfig`, `load_config`, `PipelineResult`, `CollectionResult`, `AnalysisResult`.

### Construction and hooks

```python
from cloudg import CloudGConfig, CloudGEngine

engine = CloudGEngine(CloudGConfig(providers=["aws"]))

engine.on_phase_start = lambda phase: print(f"phase: {phase}")
engine.on_finding = lambda finding: siem.send(finding.model_dump(mode="json"))
engine.on_error = lambda phase, exc: alerting.notify(phase, exc)
```

Hook signatures:

| Hook | Signature | Fires |
|---|---|---|
| `on_phase_start` | `(phase: str) -> None` | at each phase: `collection`, `scanning`, `ingest`, `analysis`, `normalisation`, `reporting` |
| `on_collection_complete` | `(result: CollectionResult) -> None` | after collection |
| `on_finding` | `(finding: Finding) -> None` | once per finding, after scan or ingest |
| `on_scan_complete` | `(findings: list[Finding]) -> None` | after scan or ingest |
| `on_analysis_complete` | `(result: AnalysisResult) -> None` | after analysis |
| `on_error` | `(phase: str, exc: Exception) -> None` | on any phase failure |

Exceptions raised inside a hook are swallowed, so a broken callback cannot take the pipeline down.

### Methods

`run_pipeline(output_dir="./reports") -> PipelineResult` and its sync twin `run_pipeline_sync()` run everything: collect, scan, analyse, normalise, report.

`collect() -> CollectionResult` runs multi-provider collection alone. The result carries `assets` (`list[CloudAsset]`), `edges` (`list[NetworkEdge]`), per-service `coverage` records, `providers_scanned`, `regions_scanned` and `duration_ms`.

`scan(assets, edges, iac_dir=None, images=None, profile=None, output_dir="./reports") -> list[Finding]` runs the scanners from `config.scanners.enabled` in parallel, plus graph reachability analysis and the IAM linter. Missing binaries are skipped.

`ingest_reports(reports: dict[str, list[str | Path]]) -> list[Finding]` parses existing scanner outputs instead of running anything. Keys are tool names (`prowler`, `scoutsuite`, `checkov`, `trivy`), values are lists of report paths, file or directory. Unparseable paths are logged and skipped rather than raising.

`normalise_findings(findings, assets=None) -> ScanResult` applies the full dedupe, cross-scanner merge, CVSS rescoring and compliance mapping. This is the same code path `run_pipeline` uses.

`analyze(assets, edges, findings, output_dir="./reports") -> AnalysisResult` builds the graph and produces the ontology, RAG chunks, Terraform files, attack paths and reachability findings, gated by the corresponding config sections.

`run_from_reports(reports, output_dir="./reports") -> PipelineResult` and `run_from_reports_sync(...)` chain ingest, normalise and report generation in one call.

### PipelineResult

| Field | Type |
|---|---|
| `assets`, `edges`, `findings` | the collected and normalised data |
| `scan_result` | `ScanResult \| None` |
| `graph_nodes`, `graph_edges`, `ontology_triples` | `int` |
| `rag_chunks_path`, `terraform_paths`, `report_paths` | output locations |
| `attack_paths` | lateral movement paths from the graph |
| `providers_scanned`, `regions_scanned`, `coverage` | collection metadata |
| `duration_ms`, `errors` | run metadata |
| `total_assets`, `total_findings`, `severity_breakdown` | computed properties |
| `to_summary()` | one dict with the headline numbers, ready to serialise |

## Integration recipes

Working examples against the real API. Each is self-contained.

### Aggregate existing scan results, get reports

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
print(result.report_paths["html"])   # ./reports/report.html
for f in result.findings:
    if f.severity.value in ("CRITICAL", "HIGH"):
        print(f.risk_score, f.title, f.resource_arn)
```

### Parse first, decide later

```python
from cloudg import CloudGConfig, CloudGEngine
from cloudg.ingest import parse_report, ingest_reports

findings = parse_report("prowler", "./prowler-output/")
findings += parse_report("checkov", "./results_json.json")
# or in one call:
findings = ingest_reports({"prowler": ["./out/"], "checkov": ["results_json.json"]})

engine = CloudGEngine(CloudGConfig())
scan_result = engine.normalise_findings(findings)

print(scan_result.summary)
for c in scan_result.compliance:
    if c.status.value == "FAIL":
        print(c.framework, c.control_id, len(c.finding_ids))
```

The per-scanner parsers are also public, if you want a single tool with no engine:

```python
from cloudg.scanners.trivy import TrivyScanner

findings = TrivyScanner.parse_report("./trivy-image.json")
```

### Stream findings into a SIEM as they arrive

```python
import asyncio
from cloudg import CloudGConfig, CloudGEngine

engine = CloudGEngine(CloudGConfig(providers=["aws"]))
engine.on_finding = lambda f: queue.put(f.model_dump(mode="json"))
engine.on_error = lambda phase, exc: log.warning("cloudg %s failed: %s", phase, exc)

result = asyncio.run(engine.run_pipeline(output_dir="/var/lib/cloudg/reports"))
```

### Run the phases yourself

```python
import asyncio
from cloudg import CloudGConfig, CloudGEngine

async def main():
    engine = CloudGEngine(CloudGConfig(providers=["aws"]))

    collection = await engine.collect()
    findings = await engine.scan(collection.assets, collection.edges)
    analysis = await engine.analyze(collection.assets, collection.edges, findings)
    scan_result = engine.normalise_findings(findings, assets=collection.assets)

    print(analysis.graph_nodes, "nodes,", len(analysis.attack_paths), "attack paths")
    return scan_result

asyncio.run(main())
```

### Combine live collection with ingested reports

Collection needs credentials; ingest does not. Together they give you the graph outputs and the aggregated findings in one result:

```python
import asyncio
from cloudg import CloudGConfig, CloudGEngine

async def main():
    engine = CloudGEngine(CloudGConfig(providers=["aws"]))

    collection = await engine.collect()
    ingested = engine.ingest_reports({"prowler": ["./ci-prowler-output/"]})
    scan_result = engine.normalise_findings(ingested, assets=collection.assets)
    await engine.analyze(collection.assets, collection.edges, scan_result.findings)

asyncio.run(main())
```

### Gate a CI job on severity

```python
import sys
from cloudg import CloudGConfig, CloudGEngine

result = CloudGEngine(CloudGConfig()).run_from_reports_sync(
    {"checkov": ["results_json.json"], "trivy": ["trivy.json"]}
)
critical = result.severity_breakdown.get("CRITICAL", 0)
if critical:
    print(f"{critical} critical findings, failing the build")
    sys.exit(1)
```

## Plugin system

Custom collectors and scanners register through setuptools entry points; no core changes needed. `PluginRegistry` (in `cloudg.registry`) discovers them at startup and falls back to the built-ins for any name not overridden.

A minimal scanner plugin:

```python
# my_package/scanner.py
from cloudg.schema.models import Finding, Severity

class MyScanner:
    def __init__(self, **kwargs):
        ...

    def run(self) -> list[Finding]:
        return [
            Finding(
                resource_id="arn:aws:s3:::example",
                severity=Severity.HIGH,
                title="Example finding",
                description="What was found and why it matters",
                source_tool="myscanner",
                source_finding_id="MY_CHECK_001",
            )
        ]
```

Registered in the plugin's own `pyproject.toml`:

```toml
[project.entry-points."cloudg.scanners"]
myscanner = "my_package.scanner:MyScanner"

[project.entry-points."cloudg.collectors"]
mycloud = "my_package.collector:MyCollector"
```

After `pip install`, the name is available in `scanners.enabled` and `--scanners`. Collectors follow the base interface in `cloudg/collectors/base.py`. If your scanner emits a stable check ID in `source_finding_id`, you can add it to `rules/check_equivalence.yaml` so its findings merge with equivalent checks from other tools.

## Authentication

Every provider supports several methods, resolved in a fixed priority order, so the same config works on a laptop, in CI and on cloud compute.

AWS, in priority order: direct keys (`--aws-key`, `--aws-secret`, `--aws-session-token` or the standard env vars); OIDC web identity federation (`--aws-role-arn` with `--aws-web-identity-token-file`, the GitHub Actions, GitLab CI and EKS pattern with no long-lived keys); a named CLI profile via `--profile`, SSO included; or nothing, letting the default chain pick up env vars, cached SSO or the instance role. On top of any of these, STS role assumption with `--aws-role-arn` and, for the third-party auditor pattern, `--aws-external-id`. Multi-account fan-out uses `accounts` plus `role_name` in the config, assuming that role in each account before collecting.

Azure, in priority order: workload identity federation (`--azure-tenant-id`, `--azure-client-id`, `--azure-federated-token-file`); a service principal with a client secret (`--azure-client-secret`) or a certificate (`--azure-cert-path`); managed identity (`--azure-managed-identity`, with `managed_identity_client_id` in config for user-assigned identities); or the `DefaultAzureCredential` chain, which covers `az login`.

GCP: a credentials file via `--gcp-credentials-file` (service account key JSON or a workload identity federation `external_account` config), or application default credentials. `--gcp-impersonate-sa` layers service account impersonation on either.

## Docker

The image bundles all four scanner binaries, so it is the shortest path to the full pipeline:

```bash
docker pull ghcr.io/morpheuslord/cloudg:latest
docker compose run --rm cloudg run -p aws --regions us-east-1
```

Or build locally with `docker build -t cloudg:latest .`

---

Found a gap in this reference? [Open an issue](https://github.com/morpheuslord/cloudg/issues).
