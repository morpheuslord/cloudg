<p align="center">
  <img src="https://raw.githubusercontent.com/morpheuslord/cloudg/main/assets/cloudg_animated_logo.gif" width="480" alt="cloudg animated logo">
</p>

# cloudg reference

cloudg (cloud graphing) maps AWS, Azure and GCP infrastructure into a graph, runs security scanners over that inventory, and merges every finding into one deduplicated, compliance-mapped result set. It can also skip the scanning entirely and aggregate outputs you already have.

This is the complete reference: every CLI command, the exact input and output formats, the data models, the full Python API with integration examples, configuration, plugins and authentication. Release history lives in the [changelog](https://github.com/morpheuslord/cloudg/blob/main/CHANGELOG.md).

The inventory mapper (`cloudg map`, `cloudg deps`, `cloudg.inventory`) has three deeper companion documents:

- [Inventory reference](INVENTORY_REFERENCE.md): the structure of every return value and exported file, field by field, with annotated examples (`CloudAsset`, `NetworkEdge`, relation objects, `InventoryResult`, `summary`, coverage records, dependency trees, blast radius, security coverage, `inventory-map.json`, `inventory-graph.json`, GraphML, `inventory-organization.json`, `asset-map.json`, `compliance-map.json`, `cloudg deps --json`).
- [Inventory catalog](INVENTORY_CATALOG.md): all 156 asset types with the native resource types mapped to each, the metadata keys and relations each one carries, and the full relationship matrix.
- [Inventory internals](INVENTORY_INTERNALS.md): how a mapping run works, every module, the 133 AWS collector tasks, the linker's resolution rules, the Azure and GCP extractor frameworks, dependency semantics, catalogs, and recipes for adding collectors, extractors and asset types.

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

Alongside the pipeline sits an independent function: [inventory mapping](#cloudg-map) (`cloudg map` / `CloudGEngine.map_inventory()`). It runs no scanners at all. It deep-collects everything deployed or default in the account, sweeps every service for whatever the dedicated collectors miss, and links the lot into one map. Scanner findings can be merged into that map later.

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

### cloudg map

Scanner-independent inventory mapping: everything deployed or default, linked into one map of typed interdependencies. No scanner runs and none needs to be installed.

```bash
cloudg map -p aws --regions all
cloudg map -p all --regions all
cloudg map -p aws --org --regions all                       # every account in the Organization / Control Tower
cloudg map -p aws --org --ou Workloads --exclude-account 111122223333
cloudg map -p aws --services containers,serverless,security  # narrow the run
cloudg map -p aws --findings ./reports/raw-findings.json     # merge scanner output
```

| Flag | Meaning |
|---|---|
| `-p, --provider` | `aws`, `azure`, `gcp` or `all`; repeatable |
| `--regions` | `all` for auto-discovery, or a comma-separated list |
| `--profile` | AWS CLI profile |
| `--accounts`, `--role-name` | AWS: explicit account list and the role to assume in each |
| `--org / --no-org` | AWS: discover and map every account of the Organization (run from the management account or a delegated administrator) |
| `--org-role` | AWS: role assumed in member accounts; defaults to `AWSControlTowerExecution` |
| `--ou` | AWS: only accounts under this OU (ID, ARN or name, nested OUs included); repeatable |
| `--exclude-account` | AWS: skip an account; repeatable |
| `--ct-home-region` | AWS: Control Tower home region, auto-detected when omitted |
| `--services`, `--exclude-services` | service families or collector names, comma-separated (see below) |
| `--kubernetes / --no-kubernetes` | map workloads inside EKS clusters through the Kubernetes API |
| `--cloud-control / --no-cloud-control` | AWS Cloud Control breadth sweep, on by default |
| `--subscription-id`, `--project-id` | Azure / GCP identity |
| `--findings` | existing cloudg findings JSON (`raw-findings.json` or a report); repeatable |
| `--sweep / --no-sweep` | catch-all sweep, on by default |
| `-o, --output` | output directory |

Coverage comes in four layers.

1. Dedicated deep collectors. On AWS, 133 collectors grouped into service families you can select with `--services` / `--exclude-services` (family or collector names):

   | Family | Collected |
   |---|---|
   | `network` | VPCs, subnets, security groups, route tables, internet / NAT / egress-only gateways, ENIs, Elastic IPs, NACLs, VPC peering, transit gateways, attachments, route tables and peering, VPC endpoints and endpoint services (PrivateLink, allowed principals, consumers), managed prefix lists, ALB/NLB listeners, rules, certificates and target groups, classic ELB, CloudFront (origins, aliases, certificates, Lambda@Edge, functions, OAC, logging), Global Accelerator, VPC Lattice |
   | `hybrid` | site-to-site VPN, customer and virtual private gateways, Direct Connect connections, VIFs and gateways, Cloud WAN / Network Manager |
   | `compute` | EC2, Auto Scaling groups, launch templates, AMIs (with sharing), Batch, App Runner, Elastic Beanstalk |
   | `containers` | ECR (+ public), ECS clusters, services, task definitions, capacity providers, container instances, Cloud Map, EKS clusters, nodegroups, Fargate profiles, addons, access entries, pod identity |
   | `kubernetes` | inside EKS clusters: namespaces, Deployments, StatefulSets, DaemonSets, CronJobs, Services, Ingresses, ServiceAccounts |
   | `serverless` | Lambda (triggers, URLs, images, layers, DLQs, aliases), API Gateway REST / HTTP APIs, authorizers, VPC links and custom domains, Step Functions |
   | `integration` | SQS, SNS, EventBridge buses, rules, archives, API destinations, Scheduler, Pipes, Kinesis, Firehose, MSK, Amazon MQ |
   | `storage` | S3 (notifications, replication, logging, account and bucket Block Public Access), access points and multi-region access points, EBS volumes and snapshots, EFS, FSx, Transfer Family, DataSync |
   | `data` | RDS, Aurora, proxies, global clusters, manual snapshot sharing, DynamoDB (KMS, streams, replicas, PITR, policies), ElastiCache, MemoryDB, DAX, OpenSearch (+ Serverless), Redshift (+ Serverless) |
   | `analytics`, `ml` | Glue, Lake Formation permissions, EMR (+ Serverless), Athena; SageMaker, Bedrock agents, knowledge bases, guardrails and invocation logging |
   | `identity` | the IAM graph (users, groups, roles, trust, grants, instance profiles, OIDC and SAML providers, access key metadata), IAM Identity Center (instances, permission sets, assignments, users, groups), Roles Anywhere, Cognito user and identity pools, KMS (aliases, rotation, key policy and grant principals), Secrets Manager, ACM |
   | `governance` | RAM resource shares, Service Catalog portfolios and provisioned products (Account Factory), CloudFormation StackSets |
   | `security` | GuardDuty, Security Hub, Inspector (per-resource coverage), Macie, AWS Config, IAM Access Analyzer, Detective, WAF, Network Firewall, Shield Advanced |
   | `logging`, `operations`, `backup` | CloudTrail, flow logs, log groups, subscription filters and destinations, cross-account observability (OAM); CloudWatch alarms, SSM parameters (metadata only), managed instances, documents, associations, maintenance windows; AWS Backup plans, selections and vaults |
   | `dns`, `iac`, `cicd` | Route 53 zones and records, Resolver endpoints, rules and DNS Firewall; CloudFormation stacks and the resources they manage; CodePipeline, CodeBuild, CodeDeploy, CodeConnections |

   Account-wide services are collected once per account, in the primary region, so `--regions all` does not repeat them. Security services that are not enabled appear as placeholder nodes with `enabled: false`, so detection gaps show on the map. Values that could be secret (parameter values, environment variables, passwords, VPN pre-shared keys, Direct Connect auth keys) are never collected.

   Azure is collected through Azure Resource Graph (`azure-mgmt-resourcegraph`, in the `azure` extra) with every resource's full properties, so PaaS services get real relationships: managed identities and role assignments (principal → scope, with role names), private endpoints, AKS node pools, kubelet identity and ACR pulls, App Service plans, VNet integration and container images, Container Apps, subnets, peering, NICs, disks and disk encryption sets, firewalls and route-table next hops, Application Gateway and Front Door backends and WAF policies, Key Vault access policies, storage and SQL network rules, Defender for Cloud plans per subscription. Every Enabled subscription is collected when none are configured (`azure.all_subscriptions`), and the management group → subscription → resource group hierarchy, Azure Landing Zone archetypes and Azure Policy assignments and exemptions are mapped (`azure.map_management_groups`). Without the Resource Graph SDK, cloudg falls back to the per-service SDK collectors plus the ARM sweep. Permissions: Reader at the tenant root management group (Resource Graph scopes to what the credential can read).

   GCP is collected through Cloud Asset Inventory `list_assets` with the full resource JSON, once at `organizations/<organization_id>` when that is set (`gcp.collection_scope`), otherwise per project. Relations cover instances (service accounts, subnets, disks, external IPs), firewall semantics (target tags and service accounts, source ranges, priorities), the load-balancing chain down to NEGs and Cloud Armor, managed instance groups and templates, GKE clusters and node pools with Workload Identity, Cloud Run and Functions v2 (service accounts, images in Artifact Registry, secrets, VPC connectors, triggers), Pub/Sub (subscriptions, push endpoints, dead-letter and export targets), Eventarc, logging sinks, CMEK keys, Shared VPC, Cloud SQL / Redis / Filestore networks and DNS zones. IAM bindings resolve to service accounts or to principal nodes (users, groups, workload identity pools); only `allUsers` / `allAuthenticatedUsers` mark a resource internet-exposed. With an organization ID, the organization → folder → project tree, organization policies and VPC Service Controls perimeters are mapped too (`gcp.map_hierarchy`, `org_policies`, `vpc_service_controls`). Permissions: `roles/cloudasset.viewer` on the organization (or each project) and the Cloud Asset API enabled on the quota project.
2. Breadth sweeps, so services without a dedicated collector still appear on the map.
   - AWS Cloud Control API: every CloudFormation resource type with a list handler (800+ types) is listed, tagged or not. Types already mapped by a deep collector are skipped, account-wide types run once per account, types that need a parent identifier or fail are skipped and counted in coverage (`cloud_control_skipped_types`). The listable-type catalogue is discovered once and cached for a week (`$CLOUDG_CACHE_DIR`, default `~/.cache/cloudg`). Secret-bearing properties (passwords, tokens, SSM parameter values, environment variables, user data) are never copied. Turn it off with `--no-cloud-control`, or narrow it with `inventory.cloud_control_types` / `cloud_control_exclude` (type names or prefixes such as `AWS::Glue::`).
   - AWS Resource Groups Tagging API: tagged resources only (AWS never returns resources that were never tagged), kept for tag enrichment.
   - Azure Resource Manager's full `resources.list()` and GCP Cloud Asset Inventory enumerate their scopes.

   Precedence when the same resource is found twice: dedicated collector, then Cloud Control, then the tagging API.
3. The relationship linker. Collectors declare what each asset talks to; the linker resolves those identifiers across services, regions and accounts into typed edges, then applies provider rules and a generic reference pass. See [Relationships](#relationships) below.
4. Account hierarchy. Every account gets a `CLOUD_ACCOUNT` node that contains its top-level resources. With `--org`, accounts hang under the OU tree, next to SCPs, the Control Tower landing zone and its enabled controls.

Outputs: `inventory-map.json` (assets, edges, unresolved references, and a summary covering services, types, regions, accounts, relationship counts, cross-account edges, external accounts, security service gaps, internet exposure and unlinked assets), `inventory-map.graphml`, `inventory-graph.json` (D3, with account and relationship attributes), `inventory-dependencies.json` (most shared dependencies, largest blast radius, cross-account edges, security coverage including workloads no vulnerability scanner covers and internet-facing endpoints without a WAF), and with `--org` `inventory-organization.json`. With `--findings`, additionally `asset-map.json` (per-asset finding counts and severity breakdowns, riskiest first) and `compliance-map.json` (framework → findings and affected assets). The map does not depend on the scanners; findings from any earlier run merge in whenever they exist.

#### Relationships

Every edge has a coarse `edge_type` and, when known, a fine-grained `relationship` (an ontology relation name) plus `properties`. Direction always reads "source verb target".

| Edge type | Example |
|---|---|
| `INVOKES` | S3 bucket → Lambda (notification), SQS → Lambda (`TRIGGERED_BY`, event source mapping), SNS → SQS (`STREAMS_TO`), EventBridge rule → target, API Gateway → Lambda, Step Functions → anything its definition calls |
| `USES_IMAGE` | task definition / Kubernetes workload / Lambda → ECR repository |
| `ASSUMES_ROLE` | Lambda, task definition, nodegroup, Kubernetes service account (IRSA or Pod Identity), instance profile → IAM role |
| `IAM_TRUST` | principal / external account / OIDC provider → role it may assume (`CROSS_ACCOUNT_TRUST` across accounts) |
| `GRANTS_ACCESS` | principal → resource its policy names; principal → EKS cluster (access entry, with access policies); bucket / queue / repository policy grants |
| `IAM_POLICY_ATTACHMENT` | user, group or role → managed policy |
| `PROTECTS` | WAF → ALB / API Gateway / CloudFront, Network Firewall → VPC, Shield → resource |
| `MONITORS` | Inspector → each scanned EC2 / ECR / Lambda, GuardDuty / Config / CloudTrail / Macie → account, Security Hub → the services it ingests from, flow log → VPC/subnet/ENI |
| `MANAGES` | CloudFormation stack → resource, ASG → instance, nodegroup → ASG, landing zone → OUs and shared accounts |
| `GOVERNS` | SCP / RCP / tag policy and Control Tower control or baseline → OU or account |
| `LOGS_TO` | trail, flow log, load balancer, API stage, task definition, function → log destination |
| `LOAD_BALANCER_TARGET` | load balancer → target group → instance / IP / Lambda, Kubernetes Service → workload |
| `ROUTE` | route table → gateway, DNS record → load balancer / distribution, transit gateway → attached VPC, Ingress → Service |
| `CONTAINS`, `ATTACHED_TO`, `PEERING`, `REFERENCES` | containment, security-group attachment, VPC peering, everything else (KMS keys, secrets, DLQs, layers, ...) |

Identifier resolution is scoped: an ambiguous name such as `default` resolves within the referencing asset's account and region, and is left unresolved rather than guessed when it could belong to several accounts. References into accounts that were not mapped become `CLOUD_ACCOUNT` nodes with `external: true`, so a role trusted by a vendor account or a bucket replicating to another account stays visible. References that resolve to nothing (a deleted queue still configured as a DLQ) are listed under `unresolved_references`.

### cloudg deps

Interdependency queries over a saved map; no cloud access needed.

```bash
cloudg deps arn:aws:iam::123456789012:role/app-role        # both directions
cloudg deps jobs-queue --direction down --depth 5           # blast radius
cloudg deps --map ./reports                                 # overview
cloudg deps my-function --direction up --json               # machine-readable
```

Each edge is read as "dependent needs dependency": a function needs its role, image, key and the queue that triggers it; an ALB needs the WAF protecting it; a resource needs the stack managing it. `--direction up` shows what an asset needs, `down` what needs it (what breaks or changes with it), `both` the two trees. Without an asset, `deps` prints the most shared dependencies (one KMS key behind forty resources), the largest blast radius, and every cross-account edge. Assets are matched by ARN or resource ID, internal ID, or a unique name.

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
| `inventory-map.json`, `inventory-map.graphml`, `inventory-graph.json` | scanner-independent inventory map: assets, interconnections, summary (`cloudg map`) |
| `inventory-dependencies.json` | shared dependencies, blast radius, cross-account edges, security service coverage (`cloudg map`) |
| `inventory-organization.json` | AWS Organization / Control Tower topology (`cloudg map --org`) |
| `asset-map.json`, `compliance-map.json` | inventory overlaid with scanner findings (`cloudg map --findings`) |

The inventory files are specified field by field in the [inventory reference](INVENTORY_REFERENCE.md).

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
| `asset_type` | `AssetType` | 156-value taxonomy covering compute, networking, storage, databases, IAM and identity federation, keys and secrets, logging, containers and Kubernetes, integration, data and ML platforms, DNS and deployment, security services and scanners, organization and governance, hybrid networking, `OTHER`; the full list with what maps to each is in the [inventory catalog](INVENTORY_CATALOG.md#asset-types-by-category) |
| `provider` | `CloudProvider` | `AWS`, `AZURE`, `GCP` |
| `region` | `str` | `"global"` for regionless resources |
| `account_id` | `str \| None` | |
| `tags` | `dict[str, str]` | |
| `metadata` | `dict[str, Any]` | normalised extra attributes; inventory assets also carry declared `relations` and identifier `aliases` |
| `collected_at` | `datetime` | when the asset was built |
| `is_internet_exposed` | `bool` | set by the collector or the graph analysis |
| `raw_data` | `dict[str, Any]` | raw API payload, never serialised |
| `display_id` | computed `str` | `arn` or `id` |

`id` is regenerated on every run; correlate assets across runs by `arn`.

### NetworkEdge

Directed edge between two asset IDs (`source_id`, `target_id`); direction always reads "source verb target".

| Field | Type | Notes |
|---|---|---|
| `id` | `str` | auto UUID |
| `source_id`, `target_id` | `str` | asset IDs; the far side of a network rule edge can be a CIDR (or an Azure service tag) instead of an asset ID |
| `edge_type` | `EdgeType` | coarse class, below |
| `relationship` | `str \| None` | fine-grained ontology relation (`TRIGGERED_BY`, `RUNS_ON`, `CROSS_ACCOUNT_TRUST`, `ENCRYPTED_BY_KMS`, ...) |
| `properties` | `dict[str, Any]` | relation detail: trust conditions, granted actions, EKS access policies, notification events, `cross_account`, `external_reference`, `hierarchy` |
| `description` | `str \| None` | human-readable explanation |
| `ports`, `port_range`, `protocol`, `cidr`, `direction` | | network rule edges |

`edge_type` values:

| Group | Values |
|---|---|
| Network | `SECURITY_GROUP_RULE`, `NACL_RULE`, `ROUTE`, `PEERING`, `LOAD_BALANCER_TARGET`, `INTERNET_EXPOSED` |
| Structure | `CONTAINS`, `ATTACHED_TO`, `REFERENCES` |
| Identity | `IAM_TRUST`, `IAM_POLICY_ATTACHMENT`, `ASSUMES_ROLE`, `GRANTS_ACCESS` |
| Workload | `INVOKES`, `USES_IMAGE`, `LOGS_TO` |
| Security and governance | `PROTECTS`, `MONITORS`, `MANAGES`, `GOVERNS` |

What each one means, its typical endpoints and how it counts for dependency analysis is in the [inventory reference](INVENTORY_REFERENCE.md#6-edge-types-and-direction); every observed source type → relationship → target type combination is in the [relationship matrix](INVENTORY_CATALOG.md#relationship-matrix).

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
  organization:                 # AWS Organizations / Control Tower (cloudg map)
    enabled: false
    role_name: null             # default AWSControlTowerExecution
    include_ous: []             # IDs, ARNs or names; nested OUs included
    exclude_accounts: []
    include_management_account: true
    include_suspended: false
    use_governed_regions: true  # regions [all] -> Control Tower governed regions
    control_tower: true
    home_region: null           # auto-detected
    map_structure: true         # org, OU, account, SCP, control nodes

azure:
  subscription_ids: []
  tenant_id: null
  client_id: null
  client_secret: null
  certificate_path: null
  federated_token_file: null
  use_managed_identity: false
  all_subscriptions: true       # every Enabled subscription when subscription_ids is empty
  map_management_groups: true   # management groups, subscriptions, Azure Policy
  regions: [ALL]

gcp:
  project_ids: []
  organization_id: null         # set to collect org-wide and map folders / org policy
  collection_scope: auto        # auto | organization | project
  skip_asset_types: [...]       # high-churn types (Pods, ReplicaSets, Events, ...) by default
  iam_policies: true
  map_hierarchy: true
  org_policies: true
  vpc_service_controls: true
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

inventory:
  tagging_sweep: true           # AWS catch-all sweep (Resource Groups Tagging API)
  link_references: true         # generic cross-service REFERENCES edges
  services: [all]               # families or collector names (see cloudg map)
  exclude_services: []
  kubernetes: true              # workloads inside EKS clusters
  kubernetes_timeout: 10
  iam_resource_edges: true      # principal -> granted resource edges
  max_images_per_repository: 20
  stack_resources: true         # CloudFormation stack -> resource edges
  account_hierarchy: true       # account nodes containing top-level resources
  cloud_control: true           # AWS breadth sweep over every listable resource type
  cloud_control_types: []       # only these CloudFormation types / prefixes
  cloud_control_exclude: []
  cloud_control_concurrency: 6

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

`CloudGEngine` in `cloudg.api` is the integration entry point: async-first, sync wrappers included, built for embedding in larger systems (SIEM pipelines, orchestration platforms, command extensions such as [hol-guard](https://github.com/hashgraph-online/hol-guard)). The package root re-exports the essentials: `CloudGEngine`, `CloudGConfig`, `load_config`, `PipelineResult`, `CollectionResult`, `AnalysisResult`, `InventoryMapper`, `InventoryResult`.

The CLI is a thin layer; nearly everything cloudg does is public, importable API. Beyond the engine itself, the [inventory mapping API](#inventory-mapping-api) and the [deeper toolkit](#the-deeper-toolkit) below are designed to be used directly from code.

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

`map_inventory(output_dir=None, findings=None, tagging_sweep=None) -> InventoryResult` and `map_inventory_sync(...)` run the scanner-independent inventory mapping: deep collection across all configured providers, catch-all sweeps, and relationship linking. Passing `output_dir` exports the map files; passing `findings` as well exports the merged asset and compliance maps.

### Inventory mapping API

`cloudg.inventory` is a standalone package; the engine is optional:

```python
from cloudg import CloudGConfig
from cloudg.inventory import InventoryMapper, RelationshipLinker

config = CloudGConfig(providers=["aws", "azure", "gcp"])
mapper = InventoryMapper(config)

inventory = mapper.map_inventory_sync()      # InventoryResult
print(inventory.summary)                     # services, types, regions, exposure
inventory.export("./reports")                # inventory-map.json / .graphml / graph
```

`InventoryResult` carries `assets`, `edges`, `coverage`, `providers`, `regions`, `organization` (the discovered topology, when mapped) and `unresolved_references`, plus a computed `summary` (totals, per-service/type/region/account breakdowns, edge types and relationships, cross-account edges, external accounts, security service gaps, internet-exposed and unlinked counts). `export(dir)` writes `inventory-map.json`, `inventory-map.graphml`, `inventory-graph.json`, `inventory-dependencies.json` and, for an organization, `inventory-organization.json`; `InventoryResult.load(dir_or_file)` reads a map back.

Interdependency questions go through `DependencyGraph`:

```python
graph = inventory.dependency_graph()
role = graph.find("arn:aws:iam::123456789012:role/app-role")
needs = graph.depends_on(role.id)           # upstream, breadth-first
needed_by = graph.dependents(role.id)       # downstream: blast radius
view = graph.tree(role.id, direction="both", max_depth=3)
graph.shared_dependencies(top=25)
graph.blast_radius(top=25)
inventory.analysis()                        # everything above + coverage
```

Organizations and Control Tower discovery is usable on its own:

```python
import boto3
from cloudg.inventory import discover_organization

topology = discover_organization(boto3.Session())
topology.governed_regions, topology.shared_accounts      # Control Tower
topology.target_accounts(include_ous=["Workloads"])     # nested OUs included
assets = topology.to_assets()                            # org, OUs, accounts, SCPs, controls
```

Merging scanner findings (from `scan()`, `ingest_reports()`, or a saved `raw-findings.json`) happens after the fact, so the mapper never touches the scanners:

```python
asset_map = mapper.build_asset_map(inventory, findings)         # asset -> findings/severity
compliance_map = mapper.build_compliance_map(inventory, findings)  # framework -> assets
mapper.export_merged(inventory, findings, "./reports")          # asset-map.json + compliance-map.json
```

`RelationshipLinker` works on any `list[CloudAsset]`, whoever collected them:

```python
linker = RelationshipLinker(assets)
linker.seed_existing(existing_edges)   # don't duplicate edges you already have
edges = linker.link()                  # typed edges, see Relationships
linker.external_assets                 # placeholder nodes for unmapped accounts
linker.unresolved                      # declared references that resolved to nothing
```

Reference data lives in YAML catalogs under `cloudg/inventory/catalogs/` rather than in code: `aws_cloudcontrol.yaml` (types the deep collectors already cover, account-wide types, CloudFormation type → asset type, per-type secret fields), `aws_arn_types.yaml` (ARN → asset type for sweep hits), `azure_arm_types.yaml` (ARM resource type → asset type) and `gcp_asset_types.yaml` (Cloud Asset Inventory type → asset type). Point `$CLOUDG_CATALOG_DIR` at a directory holding files of the same names to extend or override them without touching cloudg: mappings merge key by key, lists are extended. Unknown asset type names are rejected at load time.

Your own collectors can declare relationships the same way the built-in ones do, by listing them in `metadata["relations"]`: `{"target": <any identifier>, "edge": "INVOKES", "relationship": "TRIGGERED_BY", "reverse": false}`.

The deep collectors are public too, when you want single-region, single-account control: `AWSDeepInventoryCollector(session, region="us-east-1", account_id=None, tagging_sweep=True, **options)` (keyword options `is_primary_region`, `services`, `exclude_services`, `kubernetes`, `kubernetes_timeout`, `iam_resource_edges`, `max_images_per_repository`, `stack_resources`, `cloud_control`, `cloud_control_types`, `cloud_control_exclude`, `cloud_control_concurrency`; an unknown option raises `TypeError`), `AzureDeepInventoryCollector(credential, subscription_id, graph_client_factory=None, use_resource_graph=True)` and `GCPDeepInventoryCollector(project_id, credentials=None, **options)` (keyword options `organization_id`, `scope`, `project_filter`, `skip_asset_types`, `page_size`, `include_iam`, `client`, `coverage`, `timeout`, `link_locally`) all implement the standard `collect()` / `collect_edges()` / `run()` collector interface. Their assets carry declared relations; pass them through `RelationshipLinker` for the typed edges.

Every structure above, from `summary` to the dependency tree, is specified field by field in the [inventory reference](INVENTORY_REFERENCE.md).

### The deeper toolkit

Modules the pipeline uses internally that are equally useful standalone:

| Module | Class | What it does from code |
|---|---|---|
| `cloudg.graph.builder` | `GraphBuilder` | `build(assets, edges)` → NetworkX DiGraph; `find_attack_paths(src, dst)`, `find_lateral_movement_paths()`, `compute_centrality()` for blast-radius scoring; `to_d3_json()`, `to_cytoscape_json()`, `save_graphml()` / `load_graphml()` |
| `cloudg.graph.reachability` | `ReachabilityAnalyzer` | BFS from the internet node over a built graph; `generate_findings()` returns exposure findings |
| `cloudg.graph.ontology` | `CloudOntology` | `build(assets, edges, findings)` infers ~62 typed RDF relations; `save(path, fmt)` writes Turtle/JSON-LD/XML; query the graph with SPARQL via rdflib |
| `cloudg.graph.rag_export` | `RAGExporter` | `export_all(...)` chunks the infrastructure three ways (entity, community, relation group) into JSONL for retrieval pipelines |
| `cloudg.renderers.terraform_export` | `TerraformExporter` | `export(assets, edges)` recreates live infrastructure as `.tf.json` plus an `import.sh`; `preview(assets)` reports mappable coverage first |
| `cloudg.normaliser` | `FindingsNormaliser` | the full dedupe / cross-scanner merge / CVSS rescore / compliance mapping pass, on any `list[Finding]` |
| `cloudg.ingest` | `parse_report`, `ingest_reports` | every scanner's parser, standalone; no engine, no credentials |
| `cloudg.coverage` | `CollectionCoverage` | per-service success/failure/asset-count records every collector produces |
| `cloudg.inventory.dependencies` | `DependencyGraph`, `cross_account_edges`, `security_coverage` | dependency walks, shared dependencies, blast radius, cross-account edges and security service coverage over any assets and edges |
| `cloudg.inventory.linker` | `RelationshipLinker` | resolve declared relations and identifiers across services, regions and accounts into typed edges |
| `cloudg.inventory.organization` | `discover_organization`, `OrganizationTopology` | AWS Organizations and Control Tower discovery, account selection, map nodes |
| `cloudg.inventory.kubernetes` | `collect_eks_workloads`, `KubernetesReader` | read-only Kubernetes object mapping for EKS clusters |
| `cloudg.inventory.catalogs` | `load_catalog`, `asset_type_map` | the YAML reference catalogs with `$CLOUDG_CATALOG_DIR` overlays |
| `cloudg.registry` | `PluginRegistry` | entry-point discovery of collector and scanner plugins |

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

### Map the inventory, overlay findings later

Inventory mapping needs read credentials and nothing else. Scanners can run elsewhere (CI, a schedule, another host) and merge in whenever their output arrives:

```python
from cloudg import CloudGConfig, CloudGEngine
from cloudg.inventory import InventoryMapper

config = CloudGConfig(providers=["aws"])
config.aws.regions = ["ALL"]

engine = CloudGEngine(config)
inventory = engine.map_inventory_sync(output_dir="./reports")   # no scanners

print(inventory.summary["assets_by_service"])   # what exists
print(inventory.summary["internet_exposed"])    # what faces the internet
print(inventory.summary["unlinked_assets"])     # what nothing points at

# hours or days later, when scanner output exists:
findings = engine.ingest_reports({"prowler": ["./ci-prowler-output/"]})
mapper = InventoryMapper(config)
mapper.export_merged(inventory, findings, "./reports")
# -> asset-map.json (asset -> risk), compliance-map.json (framework -> assets)
```

### Link relationships into someone else's inventory

The linker is pure post-processing. Feed it assets from any source that produces `CloudAsset` objects (a plugin collector, a CMDB import, a previous run):

```python
from cloudg.inventory import RelationshipLinker
from cloudg.graph.builder import GraphBuilder

edges = RelationshipLinker(assets).link()
graph = GraphBuilder().build(assets, edges)
print(graph.number_of_nodes(), graph.number_of_edges())
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

After `pip install`, the name is available in `scanners.enabled` and `--scanners`. Collectors follow the base interface in `cloudg/collectors/base.py`. A collector plugin's assets join the inventory map like the built-in ones: declare what each asset talks to in `metadata["relations"]` and extra identifiers in `metadata["aliases"]`, and the relationship linker resolves them (see [Inventory internals](INVENTORY_INTERNALS.md#156-declare-relations-from-your-own-collector-or-plugin)). If your scanner emits a stable check ID in `source_finding_id`, you can add it to `rules/check_equivalence.yaml` so its findings merge with equivalent checks from other tools.

## Authentication

Every provider supports several methods, resolved in a fixed priority order, so the same config works on a laptop, in CI and on cloud compute.

AWS, in priority order: direct keys (`--aws-key`, `--aws-secret`, `--aws-session-token` or the standard env vars); OIDC web identity federation (`--aws-role-arn` with `--aws-web-identity-token-file`, the GitHub Actions, GitLab CI and EKS pattern with no long-lived keys); a named CLI profile via `--profile`, SSO included; or nothing, letting the default chain pick up env vars, cached SSO or the instance role. On top of any of these, STS role assumption with `--aws-role-arn` and, for the third-party auditor pattern, `--aws-external-id`. Multi-account fan-out uses `accounts` plus `role_name` in the config, assuming that role in each account before collecting; the caller's own account is collected with the base credentials.

AWS Organizations and Control Tower: run `cloudg map --org` with credentials for the management account (Organizations APIs also work from a delegated administrator; the Control Tower APIs need the management account). cloudg lists the org read-only (`organizations:Describe*`/`List*`, `controltower:List*`/`Get*`) and then assumes the member role in each selected account. `AWSControlTowerExecution` exists in every account Control Tower enrolled, but it carries administrator permissions; the `aws-controltower-ReadOnlyExecutionRole` cannot be used directly because it only trusts a Lambda-only role in the audit account. For production, deploy a dedicated read-only role (for example `cloudg-readonly` with the `SecurityAudit` and `ViewOnlyAccess` managed policies, trusting the management account) to all accounts with a service-managed CloudFormation StackSet targeting your OUs, and pass it with `--org-role cloudg-readonly`. Mapping Kubernetes workloads additionally needs an EKS access entry for that role with `AmazonEKSViewPolicy`.

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
