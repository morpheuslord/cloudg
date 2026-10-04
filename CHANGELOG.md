# Changelog

Notable changes per release. Patch releases are folded into the major entry they belong to.

## 0.5.2 (2026-10-04)

A documentation release: the inventory mapper's return structures, asset types and internals are now documented in full. No code changes.

Documentation:

- [Inventory reference](docs/INVENTORY_REFERENCE.md): every return structure and exported file of the inventory mapper, field by field, with annotated examples.
- [Inventory catalog](docs/INVENTORY_CATALOG.md): all 156 asset types with the native types mapped to each, their metadata keys, declared relations and the relationship matrix.
- [Inventory internals](docs/INVENTORY_INTERNALS.md): architecture, code map, the collector task registry, linker resolution rules, Azure and GCP extractor frameworks, dependency semantics, recipes for extending the mapper, security rules and testing.
- The feature reference and handbook describe the full `AssetType` and `EdgeType` sets and the new models' fields.
- The handbook changelog lists 0.5.0 and 0.5.1 as separate releases.

## 0.5.1 (2026-10-04)

A much deeper inventory map. `cloudg map` now follows workloads into containers and Kubernetes, through serverless and event wiring, across the IAM graph and the security services watching it all, and across every account of an AWS Organization / Control Tower landing zone. Edges say what they mean, and `cloudg deps` answers what an asset needs and what breaks with it.

Added:

- Deep AWS service collectors in `cloudg.inventory.aws_services`, composed into `AWSDeepInventoryCollector` and grouped into service families selectable with `--services` / `--exclude-services` (`inventory.services`, `inventory.exclude_services`):
  - containers: ECR repositories (image sample, scan findings summary, registry scan mode, repository policy grants), ECS services and task definitions (images, task and execution roles, secrets, log groups, target groups, subnets), EKS clusters, nodegroups, Fargate profiles, addons, access entries and pod identity associations;
  - Kubernetes: namespaces, Deployments, StatefulSets, DaemonSets, CronJobs, Services, Ingresses and ServiceAccounts read from inside EKS clusters with a read-only EKS token (`cloudg.inventory.kubernetes`, no new dependency; `--kubernetes/--no-kubernetes`);
  - serverless and integration: Lambda event source mappings, resource-policy invokers, function URLs, container images, layers, DLQs and EFS mounts; API Gateway REST and HTTP APIs; SQS; SNS subscriptions; EventBridge buses, rules and targets; Step Functions; Kinesis;
  - data, DNS and deployment: deep S3 (real region, notifications, replication, access logging, policy grants), ALB/NLB listeners, certificates and target groups, classic ELB, Auto Scaling groups, launch templates, deep RDS and Aurora, EFS, ElastiCache, OpenSearch, Redshift, Route 53 records, CloudFormation stacks and the resources they manage, log groups, ACM in-use-by, VPC endpoints, flow logs, transit gateway attachments;
  - security services and scanners: GuardDuty, Security Hub, Inspector (per-resource coverage), Macie, AWS Config, IAM Access Analyzer, Detective, WAFv2, Network Firewall, Shield Advanced, CloudTrail. Services that are not enabled appear as `enabled: false` placeholders;
  - identity: the full IAM graph from `GetAccountAuthorizationDetails`: trust policies (cross-account, OIDC / IRSA / GitHub), managed policy attachments, group membership, instance profiles, admin detection, and principal → resource grants.
- AWS Organizations and Control Tower: `cloudg map --org` (`aws.organization` config) discovers the OU tree, every member account, SCPs/RCPs and other org policies, delegated administrators and, when present, the Control Tower landing zone (version, drift, governed regions, log archive / audit / config / backup accounts), enabled controls and baselines, then maps every selected account by assuming `--org-role` (default `AWSControlTowerExecution`). Filters: `--ou`, `--exclude-account`; governed regions replace `--regions all`. `cloudg.inventory.discover_organization()` / `OrganizationTopology` are public.
- Typed relationships: new `EdgeType` values `INVOKES`, `USES_IMAGE`, `ASSUMES_ROLE`, `GRANTS_ACCESS`, `LOGS_TO`, `PROTECTS`, `MONITORS`, `MANAGES`, `GOVERNS`; `NetworkEdge.relationship` (ontology relation name) and `NetworkEdge.properties`. Collectors declare relationships in `metadata["relations"]`, which the linker resolves.
- Dependency analysis: `cloudg.inventory.DependencyGraph` (`depends_on`, `dependents`, `tree`, `shared_dependencies`, `blast_radius`), cross-account edges and security coverage (gaps, workloads without vulnerability scanning, internet-facing endpoints without WAF); `InventoryResult.dependency_graph()`, `analysis()`, `load()`; `inventory-dependencies.json` and `inventory-organization.json` exports; the `cloudg deps` command.
- 47 new `AssetType` values covering containers, Kubernetes, messaging, data, DNS, IaC, security services and organization structure, mapped to new OWL classes; richer Azure ARM and GCP Cloud Asset Inventory type maps.
- `cloudg map` flags: `--accounts`, `--role-name`, `--org`, `--org-role`, `--ou`, `--exclude-account`, `--ct-home-region`, `--services`, `--exclude-services`, `--kubernetes/--no-kubernetes`.
- `inventory` config: `services`, `exclude_services`, `kubernetes`, `kubernetes_timeout`, `iam_resource_edges`, `max_images_per_repository`, `stack_resources`, `account_hierarchy`.
- Coverage expansion after a full audit of every AWS, Azure and GCP service against what cloudg enumerated:
  - AWS breadth: a Cloud Control API sweep lists every resource type with a list handler, tagged or not (the tagging API never returns resources that were never tagged), skipping types a dedicated collector covers. `--cloud-control/--no-cloud-control`, `inventory.cloud_control*`.
  - AWS depth, 133 collectors in all (`cloudg.inventory.aws_services.{governance,network_ext,application,data_ml}`): IAM Identity Center (permission sets, assignments, users, groups, provisioned roles), RAM shares, Service Catalog / Account Factory, StackSets, SAML providers, access key metadata, Roles Anywhere, Cognito, deep KMS / Secrets Manager / DynamoDB, snapshot and AMI sharing, S3 access points and account Block Public Access; VPN, customer and virtual private gateways, transit gateway route tables and peering, PrivateLink services, prefix lists, egress-only gateways, API Gateway authorizers / VPC links / custom domains, deep CloudFront, Route 53 Resolver, Direct Connect, Global Accelerator, listener rules, VPC Lattice, Cloud WAN; CodePipeline / CodeBuild / CodeDeploy / CodeConnections, SSM, CloudWatch alarms, AWS Backup, ECS capacity providers and container instances, Cloud Map, Lambda aliases, Scheduler, Pipes, API destinations, archives, Firehose, log subscriptions and destinations, OAM, Batch, App Runner, Elastic Beanstalk; MSK, Amazon MQ, SageMaker, Bedrock, OpenSearch Serverless, Redshift Serverless, RDS proxies and global clusters, MemoryDB, DAX, Glue, Lake Formation, EMR, Athena, Transfer Family, DataSync, FSx, ECR Public.
  - Azure: collection through Azure Resource Graph with full properties (`azure-mgmt-resourcegraph` added to the `azure` extra; SDK fallback without it), typed relationships for managed identities, role assignments, private endpoints, AKS, App Service, Container Apps, networking, Key Vault, storage, SQL and Defender plans; every Enabled subscription; management groups, Azure Landing Zone archetypes and Azure Policy (`cloudg.inventory.azure_hierarchy`, `azure.all_subscriptions`, `azure.map_management_groups`).
  - GCP: collection through Cloud Asset Inventory `list_assets` with full resource JSON, org-wide when `gcp.organization_id` is set; typed relationships across compute, firewalls, load balancing, GKE / Workload Identity, Cloud Run, Functions, Pub/Sub, Eventarc, logging sinks, CMEK and Shared VPC (`cloudg.inventory.gcp_relations`); IAM bindings to service accounts and principal nodes; organization → folder → project hierarchy, organization policies and VPC Service Controls (`cloudg.inventory.gcp_hierarchy`); new `gcp` options `collection_scope`, `skip_asset_types`, `iam_policies`, `map_hierarchy`, `org_policies`, `vpc_service_controls`.
  - 62 further `AssetType` values (identity federation, provisioning, hybrid networking, operations, data processing, ML), 156 in all.
- Reference catalogs: type maps and skip lists moved out of code into YAML under `cloudg/inventory/catalogs/` (`aws_cloudcontrol`, `aws_arn_types`, `azure_arm_types`, `gcp_asset_types`), validated at load and extensible through `$CLOUDG_CATALOG_DIR` overlays.

Changed:

- The relationship linker resolves identifiers with account/region scope, normalises image tags, Lambda qualifiers, S3 object ARNs, `:*` log-group ARNs, assumed-role sessions and DNS names, creates `CLOUD_ACCOUNT` placeholders (`external: true`) for references into unmapped accounts, and records `unresolved` references.
- Execution roles of Lambda functions and instance profiles are now `ASSUMES_ROLE` edges (were `REFERENCES`); security-group attachments carry `relationship: PROTECTED_BY_SG`.
- Every account gets a `CLOUD_ACCOUNT` node containing its top-level resources (`inventory.account_hierarchy`); the summary adds accounts, relationship counts, cross-account edges, external accounts, security service gaps and unresolved references.
- `AsyncAWSCollector._service_tasks()` returns collector callables instead of coroutine objects, so subclasses can prune tasks without leaving unawaited coroutines.
- `MultiAccountCollector` passes `is_primary_region` to collectors that support region scoping, and collects the caller's own account with the base credentials instead of assuming the member role there.
- GraphML / D3 exports carry `account_id` on nodes and `relationship` / `description` on edges; the ontology uses each edge's declared relationship.
- `AWSDeepInventoryCollector` and `GCPCollector` take their options as keyword arguments validated by `DeepInventoryOptions` / `GCPCollectorOptions`: an unknown option name raises `TypeError` instead of being ignored. `tagging_sweep` stays the fourth positional parameter of `AWSDeepInventoryCollector`.
- Large inventory modules were split into packages and focused modules (`aws_services/*`, `azure_graph/`, `gcp_relations/`, `mapper_result`, `linker_index`, `aws_deep_tasks`, `organization_assets`); the previous import paths keep re-exporting the same names.
- URL and host checks in the collectors and the linker (SQS queue URLs, ECR and ACR registry hosts, S3 endpoints) parse the URL and match the host with anchored expressions instead of substring tests.

Fixed:

- Global services (IAM, S3, CloudFront) were collected once per region, so `--regions all` produced the same role or bucket many times under different IDs. They are now collected once per account, and the mapper deduplicates anything seen twice.
- Ambiguous names (for example security groups called `default`) could link to a resource in another account.
- Per-service collection failures inside an AWS account/region were hidden behind an overall SUCCESS; they are now reported, and the run is marked PARTIAL.
- AWS: KMS rotation was always reported off; ACM listed only RSA-2048 certificates; SQS stopped at 1,000 queues; organization CloudTrail trails made every member account look unaudited; WAF associations missed App Runner, Verified Access and Amplify; event buses and classic load balancers were not paginated; S3 made one location call per bucket; Network Firewalls attached to transit gateways had no edge; API Gateway stages, S3 access points and WAF IP sets were classified as APIs, buckets and web ACLs.
- Azure: a single NSG rule using plural address prefixes or application security groups raised during edge collection and discarded the whole subscription; Key Vault details were always empty; only the first subscription was collected (and, with azure-mgmt-resource 26, none could be listed); collection blocked the event loop.
- GCP: a string `state` crashed resource mapping and silently truncated every project; IAM members became external placeholder nodes that marked entire projects internet-exposed; firewall edges were fabricated from network tags; subnet containment used the wrong parent; collection blocked the event loop.

## 0.5.0 (2026-09-30)

Inventory mapping. A dedicated, scanner-independent function that maps everything deployed (or default) in a cloud estate and how it interlinks. It answers what exists and how it is wired together; the scanners keep answering what is wrong.

Added:

- `cloudg map` CLI command: deep-collects the complete infrastructure across AWS, Azure and GCP without running any scanner, links it into an interconnected map, and writes `inventory-map.json`, `inventory-map.graphml` and `inventory-graph.json`. `--findings` merges previously generated scanner findings into `asset-map.json` (asset → risk) and `compliance-map.json` (framework → affected assets).
- `cloudg.inventory` package, all public API:
  - `AWSDeepInventoryCollector` adds route tables, internet/NAT gateways, network interfaces, EBS volumes, Elastic IPs, NACLs, VPC peering, transit gateways and customer-managed IAM policies on top of the standard collector, plus a catch-all sweep of the Resource Groups Tagging API so every taggable resource appears on the map.
  - `AzureDeepInventoryCollector` adds NICs, public IPs, managed disks, load balancers and route tables, plus a full-subscription ARM `resources.list()` sweep covering every service.
  - `GCPDeepInventoryCollector` brings a richer Cloud Asset Inventory type taxonomy and IAM policy bindings as attachment edges.
  - `RelationshipLinker` derives interconnection edges purely from asset metadata (attachment, containment, routing, peering, and a generic cross-service reference pass) and works on any `list[CloudAsset]`.
  - `InventoryMapper` / `InventoryResult`: orchestration, summaries, exports, and the `build_asset_map()` / `build_compliance_map()` / `export_merged()` merge helpers.
- `CloudGEngine.map_inventory()` / `map_inventory_sync()` for embedders.
- `inventory:` config section (`tagging_sweep`, `link_references`).
- New schema values: `AssetType.NETWORK_INTERFACE`, `EdgeType.ATTACHED_TO`, `EdgeType.REFERENCES`.
- `MultiAccountCollector` accepts per-provider collector class overrides.
- Documentation: inventory mapping is covered in the README, the handbook (`cloudg map`, the inventory mapping API) and the docs site; a new "deeper toolkit" chapter documents the standalone programmatic APIs (GraphBuilder, CloudOntology, RAGExporter, TerraformExporter, FindingsNormaliser, parsers).

Fixed (pre-release hardening, folded in before publish):

- The engine's Checkov path passed `framework=` to a constructor that takes `frameworks=` (a list) and raised TypeError; it now forwards the configured framework list.
- The GCP identifier checks in the inventory linker and mapper are anchored regexes, so `.googleapis.com` inside an unrelated ARN no longer classifies an asset as GCP (CodeQL py/incomplete-url-substring-sanitization).
- The Pages deploy artifact carries the run attempt in its name; re-running the workflow no longer fails on "Multiple artifacts named github-pages".
- install.sh no longer uses `A && B || C` as if-then-else anywhere; every step is an explicit if/else, with a `pip_tool` helper for the repeated pip installs.
- Dockerfile pins parliament to 1.6.4.
- Codacy complexity findings: the long CLI commands (`run`, `scan`, `ingest`), the engine phases (`scan`, `analyze`, `run_pipeline`), the SVG/HTML renderers, the ontology relation inference, the RAG exporters, credentials, registry discovery and the Prowler/IAM-linter scanners were split into focused helpers; behavior is unchanged and the CLI `run` command no longer takes 27 named parameters.
- Codacy file-length findings: the four oversized modules were split along their natural seams, with every import path preserved — the CLI helpers moved to `cli_helpers.py` / `cli_run_helpers.py` and the `run` command to `cli_commands.py`; the AWS per-service collectors moved to `aws_services.py` / `aws_services_extended.py` mixins; the ontology relation-inference layer moved to `ontology_rules.py` (re-exported from `ontology`); the SVG hierarchical layout moved to `svg_layout.py`. The SVG output is byte-identical and the whole suite passes unchanged.

## 0.4.1 (2026-09-29)

Security hardening pass over the Checkov and Codacy findings.

- The Docker image now runs as a non-root `cloudg` user and carries a HEALTHCHECK.
- `install.sh` no longer pipes curl output straight into bash; installer scripts are downloaded to a temp file first (Homebrew, NodeSource, Azure CLI).
- Third-party GitHub Actions are pinned to full commit SHAs across all workflows.
- Plugin loading validates the `module:Class` path shape before `importlib.import_module`.
- Retry jitter uses the system RNG.
- Silent `except: pass` handlers now log at debug level, so swallowed errors are traceable.
- Log messages no longer put words like "credentials" next to runtime values.
- The vulnerability-report email moved out of SECURITY.md in favour of GitHub private reporting.
- A `.codacy.yml` scopes analysis to shipped code and documents suppressed false positives (pytest asserts, taxonomy names such as `AssetType.SECRET`).

## 0.4.0 (2026-09-29)

Ingest mode. cloudg can now work entirely from scanner outputs you already have, with no cloud credentials and no scanner binaries on the machine.

Added:

- `cloudg ingest` CLI command. Takes `--prowler`, `--scoutsuite`, `--checkov` and `--trivy` paths (file or directory, each repeatable, any combination), runs the normaliser and the check-equivalence merge over them, and renders the HTML and JSON reports.
- `parse_report(path)` classmethods on `ProwlerScanner`, `ScoutSuiteScanner`, `CheckovScanner` and `TrivyScanner`. Each parses the tool's native output format directly. Trivy image and filesystem reports are told apart by the `ArtifactType` field.
- `cloudg.ingest` module with `parse_report(tool, path)` and `ingest_reports(mapping)`.
- `CloudGEngine.ingest_reports()`, `CloudGEngine.normalise_findings()` and `CloudGEngine.run_from_reports()` / `run_from_reports_sync()` for embedders.
- Feature documentation: `docs/DOCUMENTATION.md`, a rendered handbook at `docs/index.html`, and this changelog.

Fixed:

- The publish workflow now sets an explicit least-privilege `permissions` block (CodeQL `actions/missing-workflow-permissions`).

## 0.3.0 (2026-09-26)

The rebrand release: the project, package, CLI, Docker image, installers and CI became cloudg (cloud graphing).

- Renamed everything to cloudg; classes follow as `CloudGConfig` and `CloudGEngine`.
- Multi-cloud authentication: OIDC web identity federation, STS role assumption with external IDs and multi-account fan-out on AWS; workload identity federation, service principals, managed identity on Azure; credential files and service account impersonation on GCP.
- Expanded compliance rulesets, generated from Prowler's public compliance data: 28 frameworks, 4,166 controls, 10,236 check mappings across AWS, Azure and GCP.
- uv-based packaging and a PyPI publish workflow using trusted publishing (OIDC), plus a Docker image on GHCR bundling all four scanner binaries.
- MIT license and community standards files.

Patch releases folded in:

- 0.3.1 (2026-09-26): the IaC scanners no longer fall back to silently scanning the current working directory; they target configured directories or the Terraform recreation of the live infrastructure, and are skipped otherwise.
- 0.3.2 (2026-09-28): finding deduplication is keyed on scanner check IDs with the `rules/check_equivalence.yaml` cross-scanner map, instead of resource and title alone. The CLI moved to a dedicated Rich UI layer.

## Before 0.3.0

The pre-rebrand history (April 2026): the async AWS collector grew ECS, DynamoDB, CloudFront, Secrets Manager and KMS support with adaptive retries; scanners moved to parallel execution under a thread pool; the Terraform export renderer and live-streaming Prowler output landed; the Click CLI took shape.
