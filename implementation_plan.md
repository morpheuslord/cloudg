# Cloud Infrastructure Mapping & Security Intelligence Agent

A Python-based pipeline orchestrator that glues proven security tools (Prowler, ScoutSuite, Checkov, Trivy, Parliament) via subprocess/API calls, normalises output into a shared Pydantic v2 schema, builds a NetworkX reachability graph, and renders topology SVG + findings JSON + interactive HTML reports.

> [!CAUTION]
> **Rule Sourcing Strategy**: All compliance mappings and detection rules MUST come from **scanner-native outputs** and **publicly maintained rulesets** — not hand-written custom regex. Prowler ships 580+ checks with CIS/NIST/PCI-DSS/HIPAA/SOC2 control IDs embedded in its ASFF output. Checkov embeds policy IDs per check. The normaliser acts as a **pass-through aggregator** that preserves these authoritative mappings. Custom `_FRAMEWORK_RULES` regex patterns are retained ONLY as a last-resort fallback for untagged findings from tools that don't emit compliance metadata.

## User Review Required

> [!IMPORTANT]
> This is a large greenfield project (~30 files). The implementation will create a fully functional pipeline framework with real library integrations. Scanner tools (Prowler, Trivy, etc.) are called via subprocess and require separate installation — the code provides graceful degradation when tools aren't installed.

> [!WARNING]
> Some dependencies require system-level tools: `graphviz` for the `diagrams` library SVG output, `trivy` binary, and `prowler` CLI. The Python code will handle missing tools gracefully.

## Proposed Changes

### Project Configuration

#### [NEW] [pyproject.toml](file:///run/media/morpheuslord/Personal_Files/Projects/cloudmapper/pyproject.toml)
- Python 3.11+ project metadata
- All dependencies: `aioboto3`, `azure-identity`, `azure-mgmt-compute`, `azure-mgmt-network`, `azure-mgmt-storage`, `azure-mgmt-resource`, `google-cloud-asset`, `networkx`, `pydantic>=2.0`, `click`, `jinja2`, `svgwrite`, `diagrams`, `parliament`, `policy-sentry`, `rich`, `moto[all]`, `pytest`, `pytest-asyncio`
- CLI entrypoint: `cloudmapper = cloudmapper.cli:cli`

---

### Schema Layer

#### [NEW] [__init__.py](file:///run/media/morpheuslord/Personal_Files/Projects/cloudmapper/cloudmapper/__init__.py)
- Package init with version string

#### [NEW] [models.py](file:///run/media/morpheuslord/Personal_Files/Projects/cloudmapper/cloudmapper/schema/models.py)
- `Severity` enum (CRITICAL, HIGH, MEDIUM, LOW, INFO)
- `CloudProvider` enum (AWS, AZURE, GCP)
- `AssetType` enum (EC2, VPC, SUBNET, S3, RDS, LAMBDA, SECURITY_GROUP, IAM_USER, IAM_ROLE, IAM_POLICY, etc.)
- `CloudAsset` — Pydantic model: `id`, `arn`, `name`, `asset_type`, `provider`, `region`, `tags`, `metadata`, `raw_data`
- `NetworkEdge` — `source_id`, `target_id`, `edge_type`, `ports`, `protocol`, `cidr`
- `Finding` — `id`, `resource_id`, `resource_arn`, `severity`, `title`, `description`, `evidence`, `remediation`, `source_tool`, `compliance_frameworks`, `cvss_score`
- `ComplianceResult` — `framework`, `control_id`, `status`, `finding_ids`
- `ScanResult` — aggregate container: `assets: list[CloudAsset]`, `findings: list[Finding]`, `edges: list[NetworkEdge]`, `compliance: list[ComplianceResult]`

---

### Credential Resolution

#### [NEW] [credentials.py](file:///run/media/morpheuslord/Personal_Files/Projects/cloudmapper/cloudmapper/credentials.py)
- `CredentialResolver` class with `resolve_aws()`, `resolve_azure()`, `resolve_gcp()`
- AWS: uses `boto3.Session` with profile/env var support
- Azure: uses `DefaultAzureCredential` from `azure-identity`
- GCP: uses Application Default Credentials via `google.auth.default()`

---

### Collectors

#### [NEW] [base.py](file:///run/media/morpheuslord/Personal_Files/Projects/cloudmapper/cloudmapper/collectors/base.py)
- `BaseCollector` ABC with `async collect() -> list[CloudAsset]` and `async collect_edges() -> list[NetworkEdge]`

#### [NEW] [aws.py](file:///run/media/morpheuslord/Personal_Files/Projects/cloudmapper/cloudmapper/collectors/aws.py)
- `AsyncAWSCollector(BaseCollector)` using `aioboto3`
- Collects: EC2, S3, RDS, VPCs, Subnets, Security Groups, IAM Users/Roles/Policies, Lambda, ELBv2
- Uses `asyncio.gather()` for concurrent multi-service calls
- Maps each AWS resource to `CloudAsset` schema

#### [NEW] [azure.py](file:///run/media/morpheuslord/Personal_Files/Projects/cloudmapper/cloudmapper/collectors/azure.py)
- `AzureCollector(BaseCollector)` using `azure-mgmt-*` SDKs
- Collects: VMs, VNets, Subnets, NSGs, Storage Accounts, SQL Databases, Key Vault
- Uses `DefaultAzureCredential`

#### [NEW] [gcp.py](file:///run/media/morpheuslord/Personal_Files/Projects/cloudmapper/cloudmapper/collectors/gcp.py)
- `GCPCollector(BaseCollector)` using `google-cloud-asset`
- Uses `AssetServiceClient.search_all_resources()` for batch inventory
- Maps GCP asset types to `CloudAsset`

---

### Graph Engine

#### [NEW] [builder.py](file:///run/media/morpheuslord/Personal_Files/Projects/cloudmapper/cloudmapper/graph/builder.py)
- `GraphBuilder` — builds `nx.DiGraph` from `list[CloudAsset]` + `list[NetworkEdge]`
- Nodes store full `CloudAsset` data as attributes
- Edges store `NetworkEdge` metadata (ports, protocol, cidr)
- Computes degree/betweenness centrality for blast-radius scoring
- `to_d3_json()` — exports `{nodes: [...], links: [...]}` for D3.js

#### [NEW] [reachability.py](file:///run/media/morpheuslord/Personal_Files/Projects/cloudmapper/cloudmapper/graph/reachability.py)
- `ReachabilityAnalyzer` — BFS from `0.0.0.0/0` entry points
- `find_internet_exposed()` — returns set of internet-exposed node IDs
- `compute_blast_radius(node_id)` — BFS from node, returns all reachable nodes
- Generates `Finding` objects for exposed resources (RDS exposed = CRITICAL, ALB = expected)

---

### Security Scanners

#### [NEW] [prowler.py](file:///run/media/morpheuslord/Personal_Files/Projects/cloudmapper/cloudmapper/scanners/prowler.py)
- `ProwlerScanner` — runs `prowler aws -M json-asff -o <dir>` via subprocess
- Parses ASFF JSON output files → maps to `Finding` schema
- Handles missing prowler binary gracefully

#### [NEW] [scoutsuite.py](file:///run/media/morpheuslord/Personal_Files/Projects/cloudmapper/cloudmapper/scanners/scoutsuite.py)
- `ScoutSuiteScanner` — runs `scout aws --report-dir <dir>` via subprocess
- Parses `scoutsuite_results.js` JSON → maps to `Finding` schema

#### [NEW] [checkov.py](file:///run/media/morpheuslord/Personal_Files/Projects/cloudmapper/cloudmapper/scanners/checkov.py)
- `CheckovScanner` — runs `checkov -d <dir> --output json` via subprocess
- Parses JSON output → maps to `Finding` schema

#### [NEW] [trivy.py](file:///run/media/morpheuslord/Personal_Files/Projects/cloudmapper/cloudmapper/scanners/trivy.py)
- `TrivyScanner` — runs `trivy image --format json <image>` via subprocess
- Scans container images from ECR/ACR/GCR
- Maps CVEs to `Finding` with CVSS scores

#### [NEW] [iam_linter.py](file:///run/media/morpheuslord/Personal_Files/Projects/cloudmapper/cloudmapper/scanners/iam_linter.py)
- `IAMLinter` — uses `parliament.analyze_policy_string()` for policy linting
- Analyses each IAM policy document from collected assets
- Generates findings for wildcard abuse, logical errors

---

### Normaliser

#### [NEW] [normaliser.py](file:///run/media/morpheuslord/Personal_Files/Projects/cloudmapper/cloudmapper/normaliser.py)
- `FindingsNormaliser` — pass-through aggregator from all scanners
- Deduplicates by `(resource_arn, title)` key
- Assigns composite severity score (CVSS + severity enum)
- **Primary compliance mapping**: Extracts control IDs directly from scanner-native fields:
  - Prowler ASFF `Compliance.RelatedRequirements` → CIS, NIST, PCI-DSS, HIPAA, SOC2
  - Checkov `check_id` / `guideline` → CIS benchmark controls
  - Trivy `VulnerabilityID` → CVE database references
  - Parliament issues → IAM best practice controls
- **Secondary**: Loads external public rulesets at runtime from `rules/` directory (YAML format)
- **Fallback only**: `_FRAMEWORK_RULES` regex for findings from tools that emit no compliance metadata
- Generates per-control-ID `ComplianceResult` entries (not just aggregate)

---

### External Rulesets

#### [NEW] [rules/](file:///run/media/morpheuslord/Personal_Files/Projects/cloudmapper/rules/)
- Directory for user-supplied and public YAML rulesets loaded at runtime
- Supports: Cloud Custodian policy YAML, CIS Benchmark control mappings, custom organisation policies
- Each ruleset file maps `finding_pattern → framework + control_id`
- Loaded by `normaliser.py` at startup; users can add/remove files without code changes

#### [NEW] [rules/cis_aws_v3.yaml](file:///run/media/morpheuslord/Personal_Files/Projects/cloudmapper/rules/cis_aws_v3.yaml)
- CIS AWS Foundations Benchmark v3.0 control ID mappings sourced from public CIS documentation

#### [NEW] [rules/nist_800_53.yaml](file:///run/media/morpheuslord/Personal_Files/Projects/cloudmapper/rules/nist_800_53.yaml)
- NIST 800-53 control family mappings sourced from NIST SP 800-53 Rev 5

---

### Renderers

#### [NEW] [json_export.py](file:///run/media/morpheuslord/Personal_Files/Projects/cloudmapper/cloudmapper/renderers/json_export.py)
- `JSONExporter` — writes `findings.json` with full asset inventory, findings, graph, compliance

#### [NEW] [svg.py](file:///run/media/morpheuslord/Personal_Files/Projects/cloudmapper/cloudmapper/renderers/svg.py)
- `SVGRenderer` — uses `svgwrite` to generate `topology.svg`
- VPC/subnet containers, resource type nodes, SG edges
- Internet-exposed nodes highlighted red, severity badges

#### [NEW] [html_report.py](file:///run/media/morpheuslord/Personal_Files/Projects/cloudmapper/cloudmapper/renderers/html_report.py)
- `HTMLReportGenerator` — renders Jinja2 template with D3.js + Chart.js
- Self-contained report (all JS/CSS inlined)

#### [NEW] [report.html.j2](file:///run/media/morpheuslord/Personal_Files/Projects/cloudmapper/templates/report.html.j2)
- Interactive D3.js force-directed topology map
- Filterable findings table with severity/service/framework filters
- Chart.js severity donut + resource type bar chart
- Per-finding detail panel with remediation
- Export JSON button

---

### CLI

#### [NEW] [cli.py](file:///run/media/morpheuslord/Personal_Files/Projects/cloudmapper/cloudmapper/cli.py)
- Click CLI with commands: `collect`, `scan`, `report`, `run` (full pipeline)
- `collect` — runs collectors for specified provider
- `scan` — runs security scanners
- `report` — generates outputs from existing JSON
- `run` — full pipeline: collect → scan → normalise → render

---

### Cloud Custodian Policies

#### [NEW] [custodian.yml](file:///run/media/morpheuslord/Personal_Files/Projects/cloudmapper/policies/custodian.yml)
- Unattached EBS volumes, idle ELBs, unused EIPs, stopped instances (30+ days), untagged resources

---

### CI/CD & Docker

#### [NEW] [Dockerfile](file:///run/media/morpheuslord/Personal_Files/Projects/cloudmapper/Dockerfile)
- Based on `python:3.11-slim`, installs all deps + Node.js for CloudSploit

#### [NEW] [cloudmapper.yml](file:///run/media/morpheuslord/Personal_Files/Projects/cloudmapper/.github/workflows/cloudmapper.yml)
- GitHub Actions workflow: runs on schedule & PR, uploads report artefacts

---

### Tests

#### [NEW] [test_collectors.py](file:///run/media/morpheuslord/Personal_Files/Projects/cloudmapper/tests/test_collectors.py)
- `moto`-mocked AWS tests for EC2, S3, VPC, IAM collection
- Verifies CloudAsset schema mapping

#### [NEW] [test_normaliser.py](file:///run/media/morpheuslord/Personal_Files/Projects/cloudmapper/tests/test_normaliser.py)
- Tests deduplication logic, severity scoring, compliance mapping

---

## Verification Plan

### Automated Tests
```bash
# Install the project in development mode
cd /run/media/morpheuslord/Personal_Files/Projects/cloudmapper
pip install -e ".[dev]"

# Run all unit tests
python -m pytest tests/ -v

# Run specific test modules
python -m pytest tests/test_collectors.py -v
python -m pytest tests/test_normaliser.py -v
```

### CLI Verification
```bash
# Verify CLI is installed and shows help
cloudmapper --help
cloudmapper collect --help
cloudmapper scan --help
cloudmapper report --help
cloudmapper run --help
```

### Manual Verification
- **Import check**: `python -c "from cloudmapper.schema.models import CloudAsset, Finding; print('Schema OK')"` — verifies all imports work
- **Graph check**: `python -c "from cloudmapper.graph.builder import GraphBuilder; print('Graph OK')"` — verifies NetworkX integration
- **Template check**: Verify `templates/report.html.j2` is valid Jinja2 by running a test render with sample data
