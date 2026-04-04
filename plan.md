# Cloud Infrastructure Mapping & Security Intelligence Agent
### Antigravity Goggles — Coding Agent Build Plan
**Stack:** Python 3.11+ · AWS / Azure / GCP · Output: SVG · JSON · HTML+JS · April 2026

---

## Design Philosophy: Zero from scratch. Maximum leverage.

The agent is a **pipeline orchestrator — not a scanner**. It glues together proven open-source tools via their Python APIs, normalises their output into a shared schema, and drives the rendering engine. Every component listed below already exists and is maintained in production by large security teams.

| Principle | Implementation |
|---|---|
| Plug-in, don't rewrite | Use `prowler`, `scoutsuite`, `checkov`, `trivy` as Python libs or subprocesses. Call their APIs; consume their JSON. |
| Schema-first | All assets and findings normalised into a single Pydantic v2 schema before any rendering. |
| Async-parallel collection | `asyncio` + `aioboto3` / async Azure SDK fans out all reads concurrently. Large AWS account: ~3 min vs 20 min. |
| Graph-native storage | Assets and relationships stored in Neo4j (via Cartography) or NetworkX (lightweight mode). |

---

## System Architecture: Five-Stage Pipeline

```
┌──────────────────────────────────────────────────────────┐
│                  cloud-mapper CLI / API                  │
└──────────────────────────┬───────────────────────────────┘
                           │
         ┌─────────────────▼──────────────────┐
         │          Credential Resolver        │
         │  aws-vault · boto3 · azure-identity │
         │  google-auth · env / IAM roles      │
         └─────────┬──────────────┬────────────┘
                   │              │
     ┌─────────────▼──┐    ┌──────▼──────────────────────┐
     │  Asset Crawler │    │    Security Scanner Layer    │
     │  cartography   │    │  prowler · scoutsuite        │
     │  steampipe     │    │  checkov · trivy · cloudspl. │
     │  cloudquery    │    │  cloud-custodian             │
     └──────┬─────────┘    └──────────────┬───────────────┘
            │                             │
            └──────────────┬──────────────┘
                           ▼
         ┌─────────────────────────────────────┐
         │     Normaliser  (Pydantic v2)        │
         │  CloudAsset · Finding · Relationship │
         └──────────────────┬──────────────────┘
                            │
          ┌─────────────────▼──────────────────┐
          │       Graph Engine (NetworkX)       │
          │  nodes = assets, edges = relations  │
          │  + optional Neo4j persistence       │
          └──────┬──────────────────┬───────────┘
                 │                  │
    ┌────────────▼───┐    ┌─────────▼─────────────┐
    │ Map Renderer   │    │   Report Generator     │
    │ D3.js topology │    │  Jinja2 + Chart.js     │
    │ SVG static map │    │  HTML interactive      │
    │ JSON export    │    │  JSON findings dump    │
    └────────────────┘    └───────────────────────┘
```

**Stage summary:**

1. **Auth** — Credential resolution (env vars, AWS profiles, instance metadata, Azure DefaultCredential, GCP ADC)
2. **Collect** — Async API fan-out across all services and providers
3. **Analyse** — Scanner orchestration: Prowler, ScoutSuite, Checkov, Trivy, Parliament
4. **Normalise** — All findings merged into Pydantic schema, deduplicated and scored
5. **Render** — topology.svg + findings.json + report.html generated simultaneously

---

## Asset Discovery: What the Agent Enumerates

### Compute
EC2/VMs/GCE instances, ECS/EKS/AKS clusters, Lambda/Cloud Functions, App Services, GKE node pools — with tags, instance types, running state, and AMI/image IDs.

### Networking
VPCs/VNets, subnets, route tables, internet/NAT gateways, peering connections, Transit Gateways, security groups/NSGs, NACLs, load balancers, CloudFront/CDN distributions.

### Storage
S3/Blob/GCS buckets — ACLs, public access block settings, bucket policies, encryption status, versioning, lifecycle rules, CORS configuration.

### Databases
RDS/Aurora/Azure SQL/Cloud SQL instances — engine, version, multi-AZ, encryption-at-rest, public accessibility flag, backup windows.

### Secrets & Keys
KMS keys (rotation status, age), Secrets Manager / Key Vault / Secret Manager — metadata only, never values. TLS certificate expiry from ACM/Key Vault.

### Logging & Monitoring
CloudTrail / Diagnostic Settings / Cloud Audit Logs — enabled state, multi-region, log file validation, S3 access logging, VPC flow logs.

---

## IAM Analysis

IAM is where most breaches originate. The agent uses dedicated tools to surface privilege escalation paths, over-permissioned roles, and dormant identities.

| Tool | Role |
|---|---|
| **Policy Sentry** | Generates least-privilege policies; scores how over-permissioned existing policies are |
| **Parliament (Duo Labs)** | Lints policies for wildcard abuse, logical errors, unused conditions |
| **Cartography** | Builds Neo4j graph of principal → role → policy → resource. Enables Cypher attack-path queries |
| **Prowler IAM checks** | 80+ checks: root usage, MFA, key age, cross-account trust, access analyser findings |
| **Azure Entra ID SDK** | Enumerate app registrations, service principals, role assignments at subscription scope |

**Key findings produced:**

- **Privilege escalation paths** — graph query finds roles with `iam:PassRole` + `ec2:RunInstances` (and similar chains). Rendered as highlighted edges on the topology map.
- **Stale identities** — users/service accounts with no activity in 90+ days, scored by risk level.
- **Cross-account trust** — roles with `Principal: *` or external account IDs surface as high-severity findings.
- **Access key hygiene** — keys older than 90 days, multiple active keys per user, keys never rotated — from IAM Credential Report.

---

## Network Mapping

The agent builds a directed reachability graph based on security group rules, NACLs, and routing tables.

**Analysis approach:**
1. Build a directed graph: nodes = resources, edges = allowed traffic flows (src IP/SG → dst port range)
2. Find all nodes reachable from `0.0.0.0/0` — mark as "internet-exposed"
3. From each internet-exposed node, BFS to find all internally-reachable resources — the "blast radius"
4. Cross-reference with resource type: internet-exposed RDS = critical; internet-exposed ALB = expected
5. CloudMapper (Duo Labs) called as subprocess to supplement the graph with additional context

**Network findings:**

| Finding | Severity |
|---|---|
| Security groups with `0.0.0.0/0` on SSH/RDP/DB ports | CRITICAL |
| RDS/Cloud SQL with `publicly_accessible=true` or reachable via SG chain | CRITICAL |
| VPCs without flow logging enabled | HIGH |
| Security groups with unrestricted egress (`0.0.0.0/0` all ports) | MEDIUM |

---

## Security Scanning

The agent orchestrates four best-in-class scanners, merges their JSON output, deduplicates, and scores by severity. No custom security checks written from scratch.

### Prowler — Primary CSPM Engine
500+ checks across AWS, Azure, GCP, and Kubernetes. Covers CIS, NIST 800-53, PCI-DSS, GDPR, HIPAA, SOC2. Called via `prowler aws --output-formats json-asff` and parsed with the Prowler Python SDK. Findings arrive as structured ASFF JSON — directly ingestible.

```bash
pip install prowler
prowler aws --output-formats json-asff --output-directory ./findings
```

### ScoutSuite — Multi-Cloud Configuration Audit
NCC Group's auditor uses cloud APIs to collect configuration state and produce a rule-based assessment. Invoked as `scout aws --report-dir ./output`. The `scoutsuite-report.js` output is parsed to extract service-level findings. Particularly strong for Azure and GCP coverage.

```bash
pip install scoutsuite
scout aws --profile default --report-dir ./output
```

### Checkov — IaC Static Analysis
Scans Terraform, CloudFormation, ARM templates, Kubernetes manifests for misconfigurations. Run against the IaC directory if provided. Identifies drift between IaC definition and live state.

```bash
pip install checkov
checkov -d ./infrastructure --output json > checkov-findings.json
```

### Trivy — Container & CVE Scanning
Scans container images in ECR/ACR/GCR for CVEs, misconfigurations, and exposed secrets. Results are joined to compute resources in the graph, so the map shows which running instances carry which CVEs.

```bash
trivy image --format json 123456789.dkr.ecr.us-east-1.amazonaws.com/myapp:latest
```

---

## Package Stack

### Collection Libraries

| Package | Install | Purpose |
|---|---|---|
| `aioboto3` | `pip install aioboto3` | Async AWS SDK — concurrent multi-service calls |
| `azure-mgmt-compute` + `azure-identity` | `pip install azure-mgmt-compute azure-identity` | Azure Management SDK with DefaultAzureCredential |
| `google-cloud-asset` | `pip install google-cloud-asset` | GCP Asset Inventory — batch-dumps entire org |
| `cartography` | `pip install cartography` | CNCF graph tool: multi-cloud assets → Neo4j |
| `networkx` | `pip install networkx` | In-memory graph for lightweight mode + reachability BFS |
| `steampipe` | `steampipe plugin install aws` | SQL interface to 140+ cloud APIs via psycopg2 |
| `cloudquery` | `cloudquery sync config.yml` | Syncs cloud assets to PostgreSQL/DuckDB for historical drift |
| `pydantic` (v2) | `pip install pydantic` | Normalisation backbone — all schema definitions |

### Security Scanning Libraries

| Package | Install | Purpose |
|---|---|---|
| `prowler` | `pip install prowler` | 500+ CSPM checks, ASFF JSON output |
| `scoutsuite` | `pip install scoutsuite` | Multi-cloud audit, strong Azure/GCP coverage |
| `checkov` | `pip install checkov` | IaC static analysis, SARIF/JSON output |
| `trivy` | `brew install trivy` | Container CVE + secrets scanning, subprocess call |
| `parliament` | `pip install parliament` | IAM policy linter — wildcards, logical errors |
| `policy-sentry` | `pip install policy-sentry` | Least-privilege scoring for IAM policies |
| `c7n` (Cloud Custodian) | `pip install c7n` | Rules engine for efficiency + governance checks |
| `cloudsploit` | `npm install -g @aqua-security/cloudsploit` | Additional CSPM checks for AWS/Azure/GCP/OCI |

### Visualisation Libraries

| Package | Install | Purpose |
|---|---|---|
| `D3.js v7` | CDN | Interactive topology map — force-directed graph |
| `Cytoscape.js` | `npm install cytoscape` | Alternative graph layout, hierarchical VPC view |
| `diagrams` | `pip install diagrams` | Diagram-as-code → Graphviz SVG with cloud icons |
| `svgwrite` | `pip install svgwrite` | Programmatic SVG for annotations + overlays |
| `Chart.js 4` | CDN | Severity charts, compliance scorecards |
| `Jinja2` | `pip install jinja2` | HTML report templating |
| `WeasyPrint` (optional) | `pip install weasyprint` | HTML → PDF conversion |

---

## Output Formats

All three outputs are generated from the same normalised data object in a single pipeline run.

### topology.svg
Static architecture map showing:
- VPC/subnet/region boundaries as nested containers
- Resources as typed nodes (EC2, RDS, S3, Lambda, etc.)
- Security group edges — internet-exposed nodes highlighted red
- IAM trust relationship edges as dashed lines
- Severity colour overlays (critical/high/medium badges)
- Legend and key

### findings.json
Machine-readable export containing:
- Full asset inventory with metadata
- All findings normalised to a common schema (id, resource_arn, severity, title, description, evidence, remediation, compliance_frameworks)
- Relationship graph as `{nodes: [...], edges: [...]}`
- CVSS / severity scores
- Compliance framework mappings (CIS, NIST, PCI-DSS, GDPR)

### report.html
Self-contained interactive report (no CDN dependency) containing:
- Interactive D3.js topology map with zoom/pan/click-to-detail
- Filterable findings table (by severity, service, compliance framework)
- Severity distribution donut chart
- Resource type breakdown bar chart
- IAM privilege graph sub-view
- Compliance scorecard per framework
- Per-finding detail panel with remediation steps
- Export button that downloads findings.json

---

## Findings Catalogue

### Security Misconfigurations

| Finding | Severity | Source Tool |
|---|---|---|
| Public S3 buckets (ACL or bucket policy) | CRITICAL | Prowler `s3_bucket_public_access` |
| Root account used in last 30 days / no MFA | CRITICAL | Prowler IAM checks |
| Unencrypted EBS volumes / RDS / SQS | HIGH | Prowler, ScoutSuite |
| Stale IAM access keys (90+ days, no rotation) | HIGH | Prowler + Credential Report |
| Wildcard IAM policies (`Action: *` or `Resource: *`) | HIGH | Parliament linter |
| CloudTrail disabled or misconfigured | HIGH | Prowler CloudTrail checks |
| Security groups open to world on SSH/RDP/DB ports | CRITICAL | Agent reachability graph |
| Public RDS / Cloud SQL instances | CRITICAL | Prowler + reachability graph |
| Missing VPC flow logs | HIGH | Prowler |
| Insecure TLS policies on load balancers | MEDIUM | Prowler, ScoutSuite |
| Container images with CRITICAL/HIGH CVEs | HIGH | Trivy |
| Secrets / API keys in container images | HIGH | Trivy secret scanning |
| IaC misconfigurations (Terraform/CFN) | VARIES | Checkov |
| Cross-account role trust with external accounts | HIGH | Cartography + Prowler |

### Efficiency & Governance

| Finding | Severity | Source Tool |
|---|---|---|
| Unattached EBS volumes | MEDIUM | Cloud Custodian |
| Idle load balancers (0 healthy targets) | MEDIUM | Cloud Custodian |
| Stopped EC2 instances (30+ days) | MEDIUM | Cloud Custodian |
| Unused Elastic IPs | LOW | Cloud Custodian |
| Untagged resources (Owner, Environment, CostCentre) | MEDIUM | Cloud Custodian |
| Oversized instances (<5% CPU over 14 days) | MEDIUM | CloudWatch metrics via boto3 |
| On-demand usage coverable by Reserved Instances | LOW | Cost Explorer via boto3 |

---

## Build Phases

### Phase 1 — Credential Resolution + Basic Inventory (Week 1–2)
- Implement `CredentialResolver` — reads from env vars, AWS profiles, instance metadata, Azure DefaultCredential, GCP ADC
- Stand up async collection workers: `AsyncAWSCollector`, `AzureCollector`, `GCPCollector`
- Define Pydantic v2 schema: `CloudAsset`, `NetworkEdge`, `Finding`, `ComplianceResult`
- Collect EC2, S3, RDS, VPCs, Security Groups, IAM users/roles/policies — inventory to JSON
- Unit tests with `moto` (AWS mocking) for all collectors
- CLI entrypoint: `cloudmapper collect --provider aws --account-id 123456`

### Phase 2 — Graph Build + Network Reachability (Week 3–4)
- Implement `GraphBuilder` — converts collected assets to NetworkX directed graph
- Add security group reachability analysis: BFS from `0.0.0.0/0`, mark internet-exposed nodes
- Integrate Cartography for optional Neo4j persistence
- Compute graph metrics: degree centrality, betweenness centrality for blast-radius scoring
- Generate topology JSON for D3.js: `{nodes: [...], links: [...]}`
- Static SVG output using `diagrams` library + `svgwrite` for annotations

### Phase 3 — Security Scanner Integration (Week 5–6)
- Integrate Prowler via Python SDK — run checks, parse ASFF JSON, map to `Finding` schema
- Integrate ScoutSuite — subprocess call, parse `scoutsuite-report.js` JSON
- Integrate Checkov — run against IaC directory, parse SARIF/JSON output
- Integrate Trivy — subprocess call against ECR/ACR image list, join findings to compute graph nodes
- Add IAM linting: Parliament + policy-sentry scoring per policy document
- Deduplicate findings across scanners (same resource + same check = single finding with source list)
- Severity scoring: CVSS for CVEs, custom rubric for misconfigurations

### Phase 4 — Efficiency + Governance Checks (Week 7)
- Implement Cloud Custodian policies: unattached EBS, idle ELBs, unused EIPs, stopped instances, untagged resources
- Pull AWS Cost Explorer data to annotate resources with monthly cost estimates
- Right-sizing checks: flag instances at <5% CPU utilisation over 14 days
- Reserved Instance coverage analysis
- Cross-AZ data transfer cost identification

### Phase 5 — HTML Report + Interactive Map (Week 8–9)
- Build Jinja2 report template: sidebar nav, findings table with severity filters, compliance scorecard
- D3.js force-directed topology map: nodes coloured by risk score, edges by relationship type, zoom/pan/click
- Chart.js dashboards: severity distribution donut, resource type bar chart, compliance framework heatmap
- Per-finding detail panel: resource ARN, description, evidence, remediation, compliance references
- IAM privilege graph sub-view
- Self-contained report (inline JS/CSS) — single file, no CDN dependency for delivery

### Phase 6 — CI/CD Integration + Scheduling (Week 10)
- Docker image: `python:3.11-slim` + all dependencies + Node.js (for Trivy/CloudSploit)
- GitHub Actions workflow: runs on schedule and on PR, uploads report to S3/artifact storage
- Slack notification webhook: post summary (critical count, new findings delta) on each run
- Delta mode: compare current findings against previous run JSON, surface only new/resolved issues
- Checkov scan on changed IaC files in PRs — annotate PR with findings

---

## Directory Structure (Suggested)

```
cloud-mapper/
├── cloudmapper/
│   ├── __init__.py
│   ├── cli.py                  # Click CLI entrypoint
│   ├── credentials.py          # CredentialResolver
│   ├── collectors/
│   │   ├── aws.py              # AsyncAWSCollector
│   │   ├── azure.py            # AzureCollector
│   │   └── gcp.py              # GCPCollector
│   ├── scanners/
│   │   ├── prowler.py          # Prowler SDK wrapper
│   │   ├── scoutsuite.py       # ScoutSuite subprocess + parser
│   │   ├── checkov.py          # Checkov subprocess + parser
│   │   ├── trivy.py            # Trivy subprocess + parser
│   │   └── iam_linter.py       # Parliament + policy-sentry
│   ├── graph/
│   │   ├── builder.py          # NetworkX graph construction
│   │   ├── reachability.py     # BFS reachability analysis
│   │   └── cartography.py      # Neo4j persistence bridge
│   ├── schema/
│   │   └── models.py           # Pydantic v2 models
│   ├── normaliser.py           # Merges + deduplicates all findings
│   └── renderers/
│       ├── svg.py              # diagrams + svgwrite static map
│       ├── json_export.py      # findings.json generator
│       └── html_report.py      # Jinja2 HTML report
├── templates/
│   └── report.html.j2          # Jinja2 report template (D3 + Chart.js)
├── policies/
│   └── custodian.yml           # Cloud Custodian efficiency policies
├── tests/
│   ├── test_collectors.py      # moto-mocked AWS tests
│   └── test_normaliser.py
├── Dockerfile
├── .github/workflows/
│   └── cloudmapper.yml         # CI/CD workflow
└── pyproject.toml
```

---

## Environment Variables Reference

```bash
# AWS
AWS_PROFILE=my-profile
AWS_DEFAULT_REGION=us-east-1
# or use IAM role on EC2/Lambda (no creds needed)

# Azure
AZURE_SUBSCRIPTION_ID=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
AZURE_TENANT_ID=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
AZURE_CLIENT_ID=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
AZURE_CLIENT_SECRET=...

# GCP
GOOGLE_APPLICATION_CREDENTIALS=/path/to/service-account.json
GOOGLE_CLOUD_PROJECT=my-project-id

# Neo4j (optional)
NEO4J_URI=bolt://localhost:7687
NEO4J_USERNAME=neo4j
NEO4J_PASSWORD=...

# Output
OUTPUT_DIR=./reports
SLACK_WEBHOOK_URL=https://hooks.slack.com/services/...
```

---

*Generated by Antigravity Goggles Build Planner · April 2026*