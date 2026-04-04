# CloudMapper — Current Limitations Analysis

## 1. Scalability Bottlenecks

### Single-Region, Single-Account Collection
- **AWS**: Collector instantiates with one `region` and one `account_id`. Cannot iterate over all enabled regions or multiple accounts in an AWS Organization. For a real-world environment with 10+ regions and many member accounts, the user must invoke the CLI separately per region/account.
- **Azure**: Bound to a single `subscription_id`. Cannot enumerate subscriptions within a tenant or management group.
- **GCP**: Bound to a single `project_id`. Cannot enumerate projects within an organization or folder hierarchy.

### No Pagination Safety for Large Fleets
- Azure and GCP collectors call `.list_all()` / `.list()` without explicit pagination handling — these are iterator-based but all results are accumulated into a single in-memory list. For accounts with 10k+ resources, this risks OOM.
- AWS uses paginators correctly, but port list generation (`range(from_port, to_port+1, 100)`) in SG edge collection can create massive lists for wide port ranges (e.g., 0-65535).

### In-Memory Graph Only
- The entire NetworkX graph lives in memory. For enterprise environments (50k+ nodes, 200k+ edges), this becomes impractical. No support for incremental loading, graph databases (Neo4j/TinkerPop), or disk-backed graph storage.

### Sequential Scanner Execution
- Scanners (Prowler, ScoutSuite, Checkov, Trivy) run sequentially via `subprocess`. Prowler alone can take 30-60 min. No parallel scanner orchestration, no streaming of partial results, no ability to cancel/resume individual scanners.

### No State / Caching / Delta Scanning
- Every run performs a full re-collection and re-scan from scratch. No local cache, no DynamoDB/S3-backed state store, no diff-based "what changed since last scan" capability.

---

## 2. Adaptability Gaps

### Hardcoded Resource Type Coverage
- **AWS**: Only collects EC2, S3, RDS, VPC, Subnets, SGs, IAM Users/Roles, Lambda, ELBv2. Missing: ECS/EKS/Fargate, CloudFront, DynamoDB, ElastiCache, SNS/SQS, Route53, API Gateway, CloudTrail, GuardDuty, Config Rules, Secrets Manager, KMS.
- **Azure**: Only VMs, VNets, NSGs, Storage, SQL, Key Vaults. Missing: AKS, App Services, CosmosDB, Front Door, Application Gateway, Azure Firewall, Policy, RBAC roles.
- **GCP**: Uses Asset Inventory API (good breadth), but firewall rule parsing is naive — it treats all firewall assets as 0.0.0.0/0 ingress without inspecting `allowed` ports/protocols, `sourceRanges`, or `targetTags` vs `targetServiceAccounts`.

### No Plugin / Extension Architecture
- Scanner and collector registration is hardcoded in [cli.py](file:///run/media/morpheuslord/Personal_Files/Projects/cloudmapper/cloudmapper/cli.py). No plugin discovery (e.g., `entry_points`), no dynamic scanner registration, no user-defined custom collectors.

### Azure/GCP Edge Collection is Shallow
- **Azure**: NSG edges only — no Application Gateway rules, Azure Firewall rules, Private Endpoints, or Service Endpoints.
- **GCP**: Firewall edges are oversimplified (all tagged as 0.0.0.0/0 without source range analysis). No VPC peering edges, no Private Service Connect edges.

### Static Compliance Mapping
- `_FRAMEWORK_RULES` in [normaliser.py](file:///run/media/morpheuslord/Personal_Files/Projects/cloudmapper/tests/test_normaliser.py) uses regex pattern matching on finding titles/descriptions. This is fragile — a finding titled "S3 bucket is public" matches, but "Object-level public access on storage" does not. No integration with official CIS Benchmark IDs from the scanner tools themselves.

### No Cross-Account / Cross-Cloud Graph
- The graph builder treats each provider run independently. No ability to build a unified multi-cloud topology showing AWS VPN ↔ Azure ExpressRoute ↔ GCP Interconnect relationships, or cross-account VPC peering.

---

## 3. Security & Reliability Gaps

### Broad Exception Swallowing
- Every collector method wraps API calls in `except Exception as exc: logger.error(...)` and returns an empty list. This means partial failures are silently ignored — if one API call in a batch of 10 fails, the user sees no warning in the final report that coverage is incomplete.

### No Rate Limiting / Backoff
- AWS API calls via `aioboto3` lack explicit retry/backoff configuration. Under heavy load (10+ concurrent service collectors), AWS throttling (`ThrottlingException`) will cause silent failures. Azure and GCP collectors similarly lack retry policies.

### No Credential Validation
- [CredentialResolver](file:///run/media/morpheuslord/Personal_Files/Projects/cloudmapper/cloudmapper/credentials.py#39-178) creates sessions/credentials but never validates them (e.g., `sts.get_caller_identity()`). Invalid credentials produce confusing downstream errors during collection.

### Scanner Output Parsing is Brittle
- Prowler ASFF parser assumes a specific JSON structure. Version differences (Prowler v3 vs v4) change the output schema.
- ScoutSuite parser uses regex to strip JS variable assignment — any change in ScoutSuite's output format breaks parsing.

---

## 4. Rendering & UX Limitations

### SVG Layout is Simplistic
- Uses a circular group layout, which produces overlapping nodes for large graphs. No hierarchical VPC/Subnet/Resource nesting. No force-directed simulation. No support for custom layout algorithms.

### HTML Report CDN Dependencies
- The Jinja2 template loads Chart.js and D3.js from CDN (`cdn.jsdelivr.net`). In air-gapped or offline environments, the report's topology map and charts won't render. No bundled fallback.

### No Incremental / Live Reporting
- Reports are generated as a one-shot post-processing step. No WebSocket/SSE-based live dashboard, no streaming findings to a SIEM (Splunk/Elastic), no webhook notifications.

---

## 5. Missing Infrastructure

| Missing Feature | Impact |
|---|---|
| Multi-region iteration | Must run CLI N times for N regions |
| AWS Organizations / Azure Tenant / GCP Org enumeration | No org-wide visibility |
| Graph database backend (Neo4j) | Memory-bound, no persistent queries |
| Result persistence (SQLite/PostgreSQL) | No historical trend analysis |
| Webhook / SIEM integration | Findings stay local |
| Config file (YAML) for scan profiles | All config via CLI flags only |
| Log file output | Only console logging |
| Progress bars / ETA | No progress indication during long scans |
| Cost tagging / FinOps integration | Governance gaps not covered |
| Terraform/Pulumi state file ingestion | Only live API collection |

---

## 6. Dependency & Runtime Constraints

- Requires Python **3.11+** — excludes older enterprise environments.
- `aioboto3` is pinned but has known issues with `aiohttp` version conflicts.
- Azure SDK packages (`azure-mgmt-*`) each have independent release cycles; version drift can cause `ImportError` at runtime.
- [parliament](file:///run/media/morpheuslord/Personal_Files/Projects/cloudmapper/cloudmapper/scanners/iam_linter.py#81-114) (IAM linter) is unmaintained and may produce false positives on newer IAM features (resource-based policies, permission boundaries).
- System-level tools (Trivy, Graphviz) require separate installation outside pip.
