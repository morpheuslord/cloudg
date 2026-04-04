# ☁️ CloudMapper — Cloud Infrastructure Mapping & Security Intelligence Agent

A Python-based pipeline orchestrator that maps multi-cloud infrastructure, runs proven security scanners, normalises findings into a unified schema, builds a reachability graph, and renders interactive reports — all from a single CLI.

[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://python.org)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

---

## Architecture

```
collect (async)  →  scan (subprocess)  →  normalise  →  render
   │                    │                    │              │
   ├─ AWS (aioboto3)    ├─ Prowler (ASFF)   │ scanner-     ├─ topology.svg
   ├─ Azure (SDK)       ├─ Checkov          │ native IDs   ├─ topology.graphml
   └─ GCP (Asset API)   ├─ ScoutSuite       │ + external   ├─ findings.json
                        ├─ Trivy (CVE)      │   YAML       └─ report.html
                        └─ Parliament       │   rulesets
                                            └─ fallback regex
```

**Key design**: CloudMapper is a *glue layer* — it does not define its own detection rules. Compliance mappings come from **scanner-native outputs** (Prowler's 580+ CIS/NIST/PCI checks, Checkov policy IDs, Trivy CVEs). Custom regex is fallback-only for untagged findings.

---

## Features

| Category | Details |
|---|---|
| **Multi-Cloud** | AWS (15 services), Azure (VMs, VNets, NSGs, Storage, SQL, Key Vault), GCP (Asset API) |
| **Multi-Account** | STS AssumeRole across AWS accounts, Azure subscription iteration, GCP project iteration |
| **Multi-Region** | Concurrent collection across all configured regions via `config.yaml` |
| **Security Scanning** | Prowler, ScoutSuite, Checkov, Trivy, Parliament (IAM linting) |
| **Graph Analysis** | NetworkX reachability, attack path discovery, lateral movement detection, blast radius scoring |
| **Compliance** | CIS, NIST 800-53, PCI-DSS, GDPR, SOC2, HIPAA — sourced from scanner-native outputs + loadable YAML rulesets |
| **Persistence** | GraphML export, Cytoscape.js JSON, D3.js JSON |
| **Reports** | Interactive HTML (inline JS for air-gapped), SVG topology, JSON findings |
| **Reliability** | Adaptive retries with exponential backoff, per-service coverage tracking |
| **Extensibility** | Plugin registry via `importlib.metadata` entry points |

---

## Quick Start

### Install

```bash
# Clone and install
git clone https://github.com/morpheuslord/cloudmapper.git
cd cloudmapper

# Auto-install all dependencies (Python, Graphviz, scanners, cloud CLIs)
chmod +x install.sh && ./install.sh

# Or install Python package only
pip install -e ".[dev]"
```

### Run

```bash
# Full pipeline — single account/region
cloudmapper run --provider aws --region us-east-1

# With config file — multi-account, multi-region
cloudmapper -c config.yaml run --provider aws

# Individual commands
cloudmapper collect --provider aws --region us-east-1
cloudmapper scan --provider aws --scanners prowler,checkov --iac-dir ./infra
cloudmapper report --input ./reports/findings.json --format all
```

### Docker

```bash
docker build -t cloudmapper .
docker run -v ~/.aws:/root/.aws -v $(pwd)/reports:/app/reports \
    cloudmapper run --provider aws
```

---

## Configuration

Copy and customise `config.yaml`:

```yaml
provider: aws

aws:
  regions: [us-east-1, eu-west-1]
  accounts: ["111111111111", "222222222222"]  # Multi-account via STS
  role_name: CloudMapperReadOnly
  max_retries: 10
  retry_mode: adaptive

scanners:
  enabled: [prowler, checkov]
  timeout_seconds: 3600

graph:
  persist_graphml: true
  compute_attack_paths: true

rulesets:
  rules_dir: ./rules        # Drop YAML rulesets here — no code changes needed
  load_external: true
```

---

## Compliance Rule Sourcing

CloudMapper uses a **three-tier compliance mapping** strategy:

| Priority | Source | Example |
|---|---|---|
| **1. Scanner-native** | Prowler ASFF `RelatedRequirements`, Checkov `check_id` | `CIS-1.5`, `CKV_AWS_18` |
| **2. External rulesets** | YAML files in `rules/` directory | `rules/cis_aws_v3.yaml` |
| **3. Fallback regex** | `_FALLBACK_RULES` in `normaliser.py` | Pattern matching (last resort) |

To add a new compliance framework, drop a YAML file into `rules/`:

```yaml
framework: SOC2
controls:
  - id: "SOC2-CC6.1"
    title: "Access Control"
    patterns: ["access.*control", "authorization"]
    severity: HIGH
```

---

## Project Structure

```
cloudmapper/
├── cli.py                  # Click CLI — collect, scan, report, run
├── config.py               # Pydantic v2 YAML config loader
├── credentials.py          # AWS/Azure/GCP credential resolution
├── registry.py             # Plugin discovery via entry_points
├── retry.py                # Async retry with exponential backoff
├── coverage.py             # Per-service collection tracking
├── normaliser.py           # Three-tier compliance aggregator
├── schema/
│   └── models.py           # Pydantic models (CloudAsset, Finding, ScanResult)
├── collectors/
│   ├── base.py             # BaseCollector ABC
│   ├── aws.py              # Async AWS (15 services, AioConfig adaptive)
│   ├── azure.py            # Azure SDK collector
│   ├── gcp.py              # GCP Asset API collector
│   └── multi.py            # Multi-account/region orchestrator
├── scanners/
│   ├── prowler.py          # Prowler ASFF parser
│   ├── scoutsuite.py       # ScoutSuite JS parser
│   ├── checkov.py          # Checkov JSON parser
│   ├── trivy.py            # Trivy CVE parser
│   └── iam_linter.py       # Parliament IAM policy linter
├── graph/
│   ├── builder.py          # NetworkX graph (GraphML, Cytoscape, attack paths)
│   └── reachability.py     # BFS reachability + blast radius analysis
└── renderers/
    ├── svg.py              # SVG topology renderer
    ├── html_report.py      # Jinja2 HTML report (D3.js + Chart.js)
    └── json_export.py      # JSON findings exporter

rules/                      # External YAML rulesets (drop-in, no code changes)
├── cis_aws_v3.yaml         # CIS AWS Foundations Benchmark v3.0
└── nist_800_53.yaml        # NIST SP 800-53 Rev 5

policies/
└── custodian.yml           # Cloud Custodian governance policies

templates/
└── report.html.j2          # Interactive HTML report template

tests/
├── test_collectors.py      # moto-mocked AWS tests
└── test_normaliser.py      # Normaliser + graph tests
```

---

## Extending with Plugins

Register custom collectors or scanners via `pyproject.toml` entry points:

```toml
[project.entry-points."cloudmapper.collectors"]
custom = "my_package.collector:MyCollector"

[project.entry-points."cloudmapper.scanners"]
custom = "my_package.scanner:MyScanner"
```

CloudMapper discovers plugins at runtime via `importlib.metadata` — no core code changes needed.

---

## AWS Services Collected

EC2, S3, RDS, VPC, Subnets, Security Groups, IAM Users, IAM Roles, Lambda, ELBv2, ECS, DynamoDB, CloudFront, Secrets Manager, KMS

---

## Output Files

| File | Description |
|---|---|
| `reports/findings.json` | All findings, assets, edges, compliance results |
| `reports/topology.svg` | Network topology diagram |
| `reports/topology.graphml` | GraphML for Gephi/Neo4j import |
| `reports/topology-cytoscape.json` | Cytoscape.js compatible graph |
| `reports/report.html` | Interactive HTML report (air-gapped capable) |

---

## Requirements

- Python 3.11+
- Graphviz (for SVG generation)
- Cloud CLI credentials configured (`aws configure`, `az login`, `gcloud auth`)
- Optional: Prowler, Checkov, Trivy, ScoutSuite (auto-installed via `install.sh`)

---

## License

MIT
