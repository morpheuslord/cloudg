# cloudg inventory internals

A developer guide to the inventory mapper (`cloudg map`, `cloudg deps`, `cloudg.inventory`):
how a mapping run flows, what every module does, how collectors declare relationships, how the
linker resolves them, how dependencies are analysed, and how to extend each part. It is written
for people changing cloudg or building on its internals.

Companion documents:

- [INVENTORY_REFERENCE.md](INVENTORY_REFERENCE.md): the exact structure of every return value
  and exported file.
- [INVENTORY_CATALOG.md](INVENTORY_CATALOG.md): per-asset-type metadata keys, declared relations,
  and the relationship matrix.
- [DOCUMENTATION.md](DOCUMENTATION.md): user-facing CLI, configuration and Python API.

## Contents

1. [Design principles](#1-design-principles)
2. [Architecture and data flow](#2-architecture-and-data-flow)
3. [Code map](#3-code-map)
4. [A mapping run, step by step](#4-a-mapping-run-step-by-step)
5. [The AWS deep collector](#5-the-aws-deep-collector)
6. [AWS Organizations and Control Tower](#6-aws-organizations-and-control-tower)
7. [The relationship linker](#7-the-relationship-linker)
8. [Azure](#8-azure)
9. [GCP](#9-gcp)
10. [Hierarchies beyond AWS](#10-hierarchies-beyond-aws)
11. [Post-processing](#11-post-processing)
12. [Dependency analysis](#12-dependency-analysis)
13. [Reference catalogs](#13-reference-catalogs)
14. [Graph, ontology and viewer integration](#14-graph-ontology-and-viewer-integration)
15. [Recipes](#15-recipes)
16. [Security rules for collectors](#16-security-rules-for-collectors)
17. [Code quality constraints](#17-code-quality-constraints)
18. [Testing](#18-testing)
19. [Public API and compatibility](#19-public-api-and-compatibility)

---

## 1. Design principles

1. **Declare, don't resolve.** A collector knows only the *identifier* of what an asset talks to
   (a role ARN, a queue URL, an image URI, a subnet ID). It records that identifier as a relation
   on the asset. Resolution into an edge happens once, in the linker, over the whole inventory,
   so a function in account A that reads a queue in account B in another region links correctly
   no matter which collector ran first.
2. **No scanner, no writes.** Mapping runs only read-only `Describe*` / `List*` / `Get*` calls
   (plus the Kubernetes API `GET`s and the Resource Graph / Cloud Asset Inventory queries). It
   never runs a security scanner; findings can be overlaid later.
3. **Breadth with precedence.** Deep collectors produce detailed assets; breadth sweeps (AWS
   Cloud Control and Tagging API, Azure ARM sweep, GCP Cloud Asset Inventory) make sure nothing
   is missing; deduplication keeps the richest copy.
4. **Absence is data.** A security service that is not enabled becomes a placeholder asset with
   `enabled: false`; a reference to an unmapped account becomes an external account node; a
   reference to nothing is listed as unresolved. Gaps show on the map instead of disappearing.
5. **No secret ever enters the inventory.** Values that could be secret are dropped at
   collection time, not filtered at export time.
6. **One model for three clouds.** AWS, Azure and GCP produce the same `CloudAsset` /
   `NetworkEdge` model, the same relation objects, and go through the same linker.

## 2. Architecture and data flow

```
              ┌───────────────────────────── InventoryMapper.map_inventory() ─────────────────────────────┐
              │                                                                                           │
 config ──►   │ 1 _discover_aws_organization ──► OrganizationTopology ──► target accounts, member role,    │
              │                                                          governed regions                 │
              │ 2 _discover_hierarchies ───────► Azure management groups / policy, GCP org / folders      │
              │                                                                                           │
              │ 3 MultiAccountCollector.collect_all()                                                     │
              │      AWS   accounts × regions ─► AWSDeepInventoryCollector (133 tasks, mixins)            │
              │                                    ├─ dedicated collectors      (relations declared)      │
              │                                    ├─ Kubernetes API (EKS)                                │
              │                                    ├─ Cloud Control sweep        discovered_via           │
              │                                    └─ Tagging API sweep          discovered_via           │
              │      Azure subscriptions ──────► AzureDeepInventoryCollector (Resource Graph | SDK)       │
              │      GCP   org or projects ────► GCPDeepInventoryCollector (Cloud Asset Inventory + IAM)  │
              │                                                                                           │
              │ 4 topology.to_assets() + hierarchy assets + collected assets                              │
              │                                                                                           │
              │ 5 _link: deduplicate ─► merge_gcp_principals ─► RelationshipLinker.link()                 │
              │          ─► + external account placeholders ─► add_account_hierarchy                      │
              │                                                                                           │
              └──► InventoryResult(assets, edges, coverage, providers, regions, organization, unresolved) │
                        │                                                                                 
                        ├─ summary, analysis() ─► DependencyGraph, cross_account_edges, security_coverage
                        └─ export() ─► inventory-map.json, .graphml, inventory-graph.json,
                                       inventory-dependencies.json, inventory-organization.json
```

## 3. Code map

### 3.1 Inventory package (`cloudg/inventory/`)

| Module | Responsibility |
|---|---|
| `__init__.py` | Public exports: `InventoryMapper`, `InventoryResult`, `RelationshipLinker`, `DependencyGraph`, the three deep collectors, `OrganizationTopology`, `discover_organization`. |
| `mapper.py` | `InventoryMapper` (orchestration, discovery, linking, findings overlay), `deduplicate`, `add_account_hierarchy`. |
| `mapper_result.py` | `InventoryResult` (summary, analysis, export, load) and `_service_of`. |
| `linker_index.py` | `IdentifierIndex`: identifier registration, scoped resolution, identifier variants, foreign-account detection. |
| `linker.py` | `RelationshipLinker(RuleLinksMixin, IdentifierIndex)`: the three linking passes, external placeholders, unresolved bookkeeping. |
| `linker_rules.py` | `RuleLinksMixin`: the provider-aware rules of pass 2 (`_link_rules`). |
| `dependencies.py` | `AssetIndex` (the asset matcher shared with the ontology and RAG export), `DEPENDENCY_DIRECTION`, `DependencyGraph`, `DependencyLink`, `cross_account_edges`, `security_coverage`. |
| `aws_deep.py` | `AWSDeepInventoryCollector`, `DeepInventoryOptions`, network fabric collectors, Tagging API sweep, three-tier dedupe in `collect()`. |
| `aws_deep_tasks.py` | `SERVICE_FAMILIES`, `GLOBAL_TASKS`, `DEEP_TASK_METHODS`, `select_tasks`, `asset_type_from_arn`. |
| `aws_services/` | The AWS service collector mixins ([5.6](#56-aws-service-modules)). |
| `kubernetes.py` | EKS token, read-only Kubernetes client, cluster object mapper. |
| `organization.py` | `OrganizationTopology` and its dataclasses, Organizations / Control Tower discovery, account selection. |
| `organization_assets.py` | Topology → map assets (`topology_assets`, `account_ref`). |
| `azure_deep.py` | `AzureDeepInventoryCollector`: Resource Graph path with SDK fallback. |
| `azure_graph/` | Resource Graph queries, `AzureAssetBuilder`, `_Draft`, extractor registry and per-area extractors ([8](#8-azure)). |
| `azure_hierarchy.py` | Management groups, subscriptions, Azure Policy assignments / exemptions. |
| `gcp_deep.py` | `GCPDeepInventoryCollector`: deep type map, IAM policy search. |
| `gcp_relations/` | GCP extraction framework, name normalisation, per-area extractors, IAM principals ([9](#9-gcp)). |
| `gcp_hierarchy.py` | Organization, folders, projects, org policies, VPC Service Controls. |
| `catalogs/` | YAML reference data and its loader ([13](#13-reference-catalogs)). |
| `_util.py` | `image_repository(image)`, `walk_strings(value, max_depth=12)`. |

### 3.2 Outside the package

| Module | Responsibility for the inventory |
|---|---|
| `cloudg/collectors/aws.py` | `AsyncAWSCollector`: lazy task registry, per-task coverage, security group and VPC containment edges. |
| `cloudg/collectors/aws_services.py`, `aws_services_extended.py` | Base AWS service collectors the deep collector inherits (EC2, VPC, subnets, security groups, ...). |
| `cloudg/collectors/azure.py` | `AzureCollector` (SDK path), NSG rule edges, subscription listing. |
| `cloudg/collectors/gcp.py`, `gcp_assets.py` | `GCPCollector` (Cloud Asset Inventory), record → asset building, firewall evaluation, internet edges. |
| `cloudg/collectors/multi.py` | `MultiAccountCollector`: providers × accounts × regions, role assumption, primary region, coverage. |
| `cloudg/cli_inventory.py` | `cloudg map` and `cloudg deps`, registered in `cloudg/cli.py`. |
| `cloudg/api.py` | `CloudGEngine.map_inventory()` / `map_inventory_sync()`. The engine's scanner runs live in `cloudg/api_scanners.py`. |
| `cloudg/config.py` | `InventoryConfig`, `AWSOrganizationConfig`, Azure / GCP inventory options. |
| `cloudg/schema/models.py` | `AssetType`, `EdgeType`, `CloudAsset`, `NetworkEdge`. |
| `cloudg/coverage.py` | `CollectionCoverage`, `ServiceCoverage`, `ServiceStatus`. |
| `cloudg/graph/builder.py` | NetworkX graph, D3 / GraphML export. |
| `cloudg/graph/ontology.py`, `ontology_rules.py` | `RelationType` vocabulary; declared relationships feed the ontology. |
| `docs/viewer.html` | Offline viewer for `inventory-graph.json`. |

## 4. A mapping run, step by step

`InventoryMapper(config, tagging_sweep=None).map_inventory()`:

1. **Copy the configuration.** `config.model_copy(deep=True)`; discovery may rewrite the AWS
   account list, role and regions, and the caller's config object is never mutated.
2. **AWS Organization discovery** (`aws.organization.enabled`). Runs in a worker thread:
   - builds a session in `home_region` or the primary region with the base credentials;
   - `discover_organization()` ([6](#6-aws-organizations-and-control-tower));
   - `target_accounts()` with the OU / exclusion / management / suspended filters, intersected
     with `aws.accounts` when that is also set;
   - sets `cfg.aws.accounts` to the selection and `cfg.aws.role_name` to
     `organization.role_name`, else `aws.role_name`, else `AWSControlTowerExecution`;
   - with `use_governed_regions` and `regions: [all]`, replaces the regions with the Control
     Tower governed regions.
   Failure is recorded as coverage (`organizations: FAILED`) and the run continues with the
   caller's account only.
3. **Other hierarchies.** Azure management groups and policy (`azure.map_management_groups`),
   GCP organization / folders / policies (`gcp.organization_id` and `gcp.map_hierarchy`).
4. **Collection.** `MultiAccountCollector(cfg, collector_overrides=…)` with the deep collectors:
   - AWS: one task per account × region, limited by `concurrency_limit`. The account-wide
     services run only in the primary region (`us-east-1` when collected, else the first
     region), passed as `is_primary_region` to collectors that declare
     `supports_region_scoping`. The caller's own account is collected with the base
     credentials, because member roles such as `AWSControlTowerExecution` do not exist in the
     management account. A failed role assumption records `sts_assume_role` and skips that
     account and region.
   - Azure: every configured subscription, or every Enabled subscription
     (`azure.all_subscriptions`), one credential for the run. Resource Graph returns all
     locations, so there is no per-region loop.
   - GCP: one Cloud Asset Inventory listing at `organizations/<id>` (with `project_ids` as a
     filter) when `collection_scope` allows it, else one per project.
   - Each unit runs `collect()` then `collect_edges()` and records coverage.
   The deep collector options from `InventoryConfig` are bound through a small subclass
   (`_ConfiguredAWS`) that keeps the `(session, region, account_id)` constructor the orchestrator
   expects.
5. **Merge discovery assets.** `topology.to_assets()` (with `map_structure`) and the Azure / GCP
   hierarchy assets are prepended to the collected assets.
6. **Link** (`_link`):
   1. `deduplicate()`: one asset per `arn`, relations and aliases merged, edges re-pointed.
   2. `merge_gcp_principals()` (GCP only): folds per-project service-account placeholders into
      the real service accounts.
   3. `RelationshipLinker(assets)`, `seed_existing(edges)`, `link(include_generic=link_references)`.
   4. External account placeholders appended to the assets.
   5. `add_account_hierarchy()` (with `inventory.account_hierarchy`).
7. **Result.** `InventoryResult` with the discovery coverage first, the resolved regions,
   `topology.to_dict()` and the linker's unresolved references.

`CloudGEngine.map_inventory()` wraps this and additionally exports the files (and the findings
overlay) when `output_dir` is given. `cloudg map` adds the console output and `--findings`.

## 5. The AWS deep collector

### 5.1 Composition

`AWSDeepInventoryCollector` is a stack of mixins on top of `AsyncAWSCollector`:

```python
class AWSDeepInventoryCollector(
    GovernanceCollectorsMixin,
    NetworkExtCollectorsMixin,
    ApplicationCollectorsMixin,
    DataMLCollectorsMixin,
    IdentityCollectorsMixin,
    ContainerCollectorsMixin,
    ServerlessCollectorsMixin,
    SecurityCollectorsMixin,
    PlatformCollectorsMixin,
    CloudControlCollectorsMixin,
    AsyncAWSCollector,
): ...
```

Rules that follow from the MRO:

- **Mixins come before `AsyncAWSCollector`.** A mixin's `_collect_s3` overrides the base
  collector's. `AWSServiceMixin` declares `_region`, `_account_id` and `_aio_config` as
  annotations only; it must never define stubs for `AsyncAWSCollector` methods, or it would
  shadow them.
- **Method names are global across all mixins.** Two mixins defining the same helper silently
  shadow each other (the one earlier in the MRO wins). Prefix package-private helpers (the
  data/ML package uses `_dm_role_ref` for that reason) and check with
  `grep -rn "def <name>" cloudg/inventory/aws_services` before adding one.
- Package mixins are themselves compositions (`ApplicationCollectorsMixin` combines twelve
  per-area mixins), so each package keeps one place in the MRO.

Constructor: `AWSDeepInventoryCollector(session, region="us-east-1", account_id=None,
tagging_sweep=True, **options)`. `tagging_sweep` stays the fourth positional parameter for
0.5.0 compatibility; every other option is keyword-only and validated by the
`DeepInventoryOptions` dataclass, so an unknown option name raises `TypeError`.

| Option | Default | Effect |
|---|---|---|
| `tagging_sweep` | `True` | Run the Tagging API sweep. |
| `is_primary_region` | `True` | Collect account-wide tasks here. |
| `services` | all | Families / task names to include. |
| `exclude_services` | none | Families / task names to skip (wins over `services`). |
| `kubernetes` | `True` | Map in-cluster objects of EKS clusters. Also requires that `kubernetes` is not excluded and that `all`, `kubernetes`, `containers` or `eks` is selected. |
| `kubernetes_timeout` | `10` | Kubernetes API timeout, seconds. |
| `iam_resource_edges` | `True` | Link principals to resources their identity policies name. |
| `max_images_per_repository` | `20` | ECR images sampled per repository (for tags, scan findings). |
| `stack_resources` | `True` | Link CloudFormation stacks to their resources. |
| `cloud_control` | `True` | Run the Cloud Control sweep. |
| `cloud_control_types` | all | Only these CloudFormation types or prefixes. |
| `cloud_control_exclude` | none | Skip these types or prefixes. |
| `cloud_control_concurrency` | `6` | Types listed in parallel per region. |

### 5.2 The task registry

`collect()` runs every task returned by `_service_tasks()` concurrently, each wrapped by
`_run_service_collector(name, coroutine)` which records a `ServiceCoverage` entry (`SUCCESS`
with the asset count, or `FAILED` with the error) and turns a failure into an empty list. One
failing service never stops the others.

`_service_tasks()` is built lazily, so excluded tasks never create coroutines:

1. `AsyncAWSCollector._service_tasks()`: the base tasks (`ec2`, `s3`, `rds`, `vpc`, `subnets`,
   `security_groups`, `iam_users`, `iam_roles`, `lambda`, `elbv2`, `ecs`, `dynamodb`,
   `cloudfront`, `secretsmanager`, `kms`), each a bound `_collect_*` method. Mixins override
   most of them with deeper implementations of the same name.
2. `iam_users` and `iam_roles` are dropped: `_collect_iam` maps the whole IAM graph in one task.
3. `DEEP_TASK_METHODS` adds the network fabric and the original deep tasks
   (`route_tables`, `internet_gateways`, …, `cloudtrail`) by method name.
4. `_merge_registries()` adds the registries of the newer mixin packages. Each registry is a
   method returning `{task_name: (callable, family, is_global)}`:
   `_governance_tasks()`, `_network_ext_tasks()`, `_application_tasks()`, `_data_ml_tasks()`,
   `_cloudcontrol_tasks()`. The family is registered in `SERVICE_FAMILIES` (without overwriting
   an existing entry) and global tasks are added to the global set.
5. `tagging_sweep` is added when enabled.
6. Outside the primary region every global task is removed (`GLOBAL_TASKS` plus registry tasks
   with `is_global=True`).
7. `select_tasks(names, services, exclude_services)` filters by task name or family.
   `kubernetes` is a pseudo-family: including it keeps the `eks` task.

### 5.3 Service families and tasks

The 133 tasks, their family (the value `--services` / `--exclude-services` accept besides task
names), the module that implements them, and whether they run once per account (in the primary
region) rather than in every region.

| Family | Task | Implemented in | Once per account |
|---|---|---|---|
| `analytics` | `athena` | `cloudg.inventory.aws_services.data_ml.analytics` |  |
| `analytics` | `emr` | `cloudg.inventory.aws_services.data_ml.analytics` |  |
| `analytics` | `emr_serverless` | `cloudg.inventory.aws_services.data_ml.analytics` |  |
| `analytics` | `glue` | `cloudg.inventory.aws_services.data_ml.glue` |  |
| `analytics` | `lakeformation` | `cloudg.inventory.aws_services.data_ml.lakeformation` |  |
| `backup` | `backup_plans` | `cloudg.inventory.aws_services.application.backup` |  |
| `backup` | `backup_vaults` | `cloudg.inventory.aws_services.application.backup` |  |
| `cicd` | `codebuild` | `cloudg.inventory.aws_services.application.build_deploy` |  |
| `cicd` | `codeconnections` | `cloudg.inventory.aws_services.application.cicd` |  |
| `cicd` | `codedeploy` | `cloudg.inventory.aws_services.application.build_deploy` |  |
| `cicd` | `codepipeline` | `cloudg.inventory.aws_services.application.cicd` |  |
| `compute` | `apprunner` | `cloudg.inventory.aws_services.application.compute` |  |
| `compute` | `autoscaling` | `cloudg.inventory.aws_services.platform.compute_fabric` |  |
| `compute` | `batch` | `cloudg.inventory.aws_services.application.batch` |  |
| `compute` | `ec2` | `cloudg.collectors.aws_services` |  |
| `compute` | `elasticbeanstalk` | `cloudg.inventory.aws_services.application.compute` |  |
| `compute` | `launch_templates` | `cloudg.inventory.aws_services.platform.compute_fabric` |  |
| `compute` | `machine_images` | `cloudg.inventory.aws_services.governance.sharing` |  |
| `containers` | `cloudmap` | `cloudg.inventory.aws_services.application.containers_ext` |  |
| `containers` | `ecr` | `cloudg.inventory.aws_services.containers.ecr` |  |
| `containers` | `ecr_public` | `cloudg.inventory.aws_services.data_ml.registry` | yes |
| `containers` | `ecs` | `cloudg.inventory.aws_services.containers.ecs` |  |
| `containers` | `ecs_capacity_providers` | `cloudg.inventory.aws_services.application.containers_ext` |  |
| `containers` | `ecs_container_instances` | `cloudg.inventory.aws_services.application.containers_ext` |  |
| `containers` | `eks` | `cloudg.inventory.aws_services.containers.eks` |  |
| `data` | `dax` | `cloudg.inventory.aws_services.data_ml.databases` |  |
| `data` | `dynamodb` | `cloudg.inventory.aws_services.governance.data_protection` |  |
| `data` | `elasticache` | `cloudg.inventory.aws_services.platform.data` |  |
| `data` | `memorydb` | `cloudg.inventory.aws_services.data_ml.databases` |  |
| `data` | `opensearch` | `cloudg.inventory.aws_services.platform.data` |  |
| `data` | `opensearch_serverless` | `cloudg.inventory.aws_services.data_ml.serverless_data` |  |
| `data` | `rds` | `cloudg.inventory.aws_services.platform.data` |  |
| `data` | `rds_global_clusters` | `cloudg.inventory.aws_services.data_ml.databases` | yes |
| `data` | `rds_proxies` | `cloudg.inventory.aws_services.data_ml.databases` |  |
| `data` | `rds_snapshots` | `cloudg.inventory.aws_services.governance.sharing` |  |
| `data` | `redshift` | `cloudg.inventory.aws_services.platform.data` |  |
| `data` | `redshift_serverless` | `cloudg.inventory.aws_services.data_ml.serverless_data` |  |
| `dns` | `route53` | `cloudg.inventory.aws_services.platform.dns_iac_ops` | yes |
| `dns` | `route53_resolver` | `cloudg.inventory.aws_services.network_ext.resolver` |  |
| `governance` | `ram_shares` | `cloudg.inventory.aws_services.governance.ram` |  |
| `governance` | `service_catalog` | `cloudg.inventory.aws_services.governance.service_catalog` |  |
| `governance` | `stack_sets` | `cloudg.inventory.aws_services.governance.stack_sets` |  |
| `hybrid` | `direct_connect` | `cloudg.inventory.aws_services.network_ext.direct_connect` |  |
| `hybrid` | `direct_connect_gateways` | `cloudg.inventory.aws_services.network_ext.direct_connect` | yes |
| `hybrid` | `network_manager` | `cloudg.inventory.aws_services.network_ext.network_manager` | yes |
| `hybrid` | `vpn` | `cloudg.inventory.aws_services.network_ext.vpn` |  |
| `iac` | `cloudformation` | `cloudg.inventory.aws_services.platform.dns_iac_ops` |  |
| `identity` | `acm` | `cloudg.inventory.aws_services.platform.dns_iac_ops` |  |
| `identity` | `cognito_identity_pools` | `cloudg.inventory.aws_services.governance.cognito` |  |
| `identity` | `cognito_user_pools` | `cloudg.inventory.aws_services.governance.cognito` |  |
| `identity` | `iam` | `cloudg.inventory.aws_services.identity` | yes |
| `identity` | `iam_access_keys` | `cloudg.inventory.aws_services.governance.iam_extras` | yes |
| `identity` | `iam_saml_providers` | `cloudg.inventory.aws_services.governance.iam_extras` | yes |
| `identity` | `identity_center` | `cloudg.inventory.aws_services.governance.identity_center` | yes |
| `identity` | `kms` | `cloudg.inventory.aws_services.governance.data_protection` |  |
| `identity` | `rolesanywhere` | `cloudg.inventory.aws_services.governance.iam_extras` |  |
| `identity` | `secretsmanager` | `cloudg.inventory.aws_services.governance.data_protection` |  |
| `integration` | `amazon_mq` | `cloudg.inventory.aws_services.data_ml.messaging` |  |
| `integration` | `eventbridge` | `cloudg.inventory.aws_services.serverless.messaging` |  |
| `integration` | `eventbridge_api_destinations` | `cloudg.inventory.aws_services.application.integration` |  |
| `integration` | `eventbridge_archives` | `cloudg.inventory.aws_services.application.integration` |  |
| `integration` | `firehose` | `cloudg.inventory.aws_services.application.firehose` |  |
| `integration` | `kinesis` | `cloudg.inventory.aws_services.serverless.messaging` |  |
| `integration` | `msk` | `cloudg.inventory.aws_services.data_ml.messaging` |  |
| `integration` | `pipes` | `cloudg.inventory.aws_services.application.integration` |  |
| `integration` | `scheduler` | `cloudg.inventory.aws_services.application.integration` |  |
| `integration` | `sns` | `cloudg.inventory.aws_services.serverless.messaging` |  |
| `integration` | `sqs` | `cloudg.inventory.aws_services.serverless.messaging` |  |
| `logging` | `cloudtrail` | `cloudg.inventory.aws_services.security.posture` |  |
| `logging` | `flow_logs` | `cloudg.inventory.aws_services.platform.compute_fabric` |  |
| `logging` | `log_destinations` | `cloudg.inventory.aws_services.application.logs` |  |
| `logging` | `log_groups` | `cloudg.inventory.aws_services.platform.dns_iac_ops` |  |
| `logging` | `log_subscriptions` | `cloudg.inventory.aws_services.application.logs` |  |
| `logging` | `oam` | `cloudg.inventory.aws_services.application.logs` |  |
| `ml` | `bedrock` | `cloudg.inventory.aws_services.data_ml.bedrock` |  |
| `ml` | `sagemaker` | `cloudg.inventory.aws_services.data_ml.sagemaker` |  |
| `network` | `cloudfront` | `cloudg.inventory.aws_services.network_ext` | yes |
| `network` | `egress_only_igw` | `cloudg.inventory.aws_services.network_ext.privatelink` |  |
| `network` | `elastic_ips` | `cloudg.inventory.aws_deep` |  |
| `network` | `elb_classic` | `cloudg.inventory.aws_services.platform.load_balancing` |  |
| `network` | `elb_rules` | `cloudg.inventory.aws_services.network_ext.elb_rules` |  |
| `network` | `elbv2` | `cloudg.inventory.aws_services.platform.load_balancing` |  |
| `network` | `endpoint_services` | `cloudg.inventory.aws_services.network_ext.privatelink` |  |
| `network` | `global_accelerator` | `cloudg.inventory.aws_services.network_ext.global_accelerator` | yes |
| `network` | `internet_gateways` | `cloudg.inventory.aws_deep` |  |
| `network` | `nacls` | `cloudg.inventory.aws_deep` |  |
| `network` | `nat_gateways` | `cloudg.inventory.aws_deep` |  |
| `network` | `network_interfaces` | `cloudg.inventory.aws_deep` |  |
| `network` | `prefix_lists` | `cloudg.inventory.aws_services.network_ext.privatelink` |  |
| `network` | `route_tables` | `cloudg.inventory.aws_deep` |  |
| `network` | `security_groups` | `cloudg.collectors.aws_services` |  |
| `network` | `subnets` | `cloudg.collectors.aws_services` |  |
| `network` | `tgw_routing` | `cloudg.inventory.aws_services.network_ext.tgw` |  |
| `network` | `transit_gateways` | `cloudg.inventory.aws_deep` |  |
| `network` | `vpc` | `cloudg.collectors.aws_services` |  |
| `network` | `vpc_endpoints` | `cloudg.inventory.aws_services.platform.compute_fabric` |  |
| `network` | `vpc_lattice` | `cloudg.inventory.aws_services.network_ext.lattice` |  |
| `network` | `vpc_peering` | `cloudg.inventory.aws_deep` |  |
| `operations` | `cloudwatch_alarms` | `cloudg.inventory.aws_services.application.alarms` |  |
| `operations` | `ssm_associations` | `cloudg.inventory.aws_services.application.operations` |  |
| `operations` | `ssm_documents` | `cloudg.inventory.aws_services.application.operations` |  |
| `operations` | `ssm_maintenance_windows` | `cloudg.inventory.aws_services.application.operations` |  |
| `operations` | `ssm_managed_instances` | `cloudg.inventory.aws_services.application.operations` |  |
| `operations` | `ssm_parameters` | `cloudg.inventory.aws_services.application.operations` |  |
| `security` | `access_analyzer` | `cloudg.inventory.aws_services.security.posture` |  |
| `security` | `config` | `cloudg.inventory.aws_services.security.posture` |  |
| `security` | `detective` | `cloudg.inventory.aws_services.security.detection` |  |
| `security` | `guardduty` | `cloudg.inventory.aws_services.security.detection` |  |
| `security` | `inspector2` | `cloudg.inventory.aws_services.security.detection` |  |
| `security` | `macie` | `cloudg.inventory.aws_services.security.detection` |  |
| `security` | `network_firewall` | `cloudg.inventory.aws_services.security.network_protection` |  |
| `security` | `securityhub` | `cloudg.inventory.aws_services.security.detection` |  |
| `security` | `shield` | `cloudg.inventory.aws_services.security.network_protection` | yes |
| `security` | `wafv2` | `cloudg.inventory.aws_services.security.network_protection` |  |
| `serverless` | `apigateway` | `cloudg.inventory.aws_services.serverless.apigateway` |  |
| `serverless` | `apigateway_authorizers` | `cloudg.inventory.aws_services.network_ext.apigateway` |  |
| `serverless` | `apigateway_domains` | `cloudg.inventory.aws_services.network_ext.apigateway` |  |
| `serverless` | `apigateway_vpc_links` | `cloudg.inventory.aws_services.network_ext.apigateway` |  |
| `serverless` | `apigatewayv2` | `cloudg.inventory.aws_services.serverless.apigateway` |  |
| `serverless` | `lambda` | `cloudg.inventory.aws_services.serverless.functions` |  |
| `serverless` | `lambda_aliases` | `cloudg.inventory.aws_services.application.serverless_ext` |  |
| `serverless` | `stepfunctions` | `cloudg.inventory.aws_services.serverless.messaging` |  |
| `storage` | `datasync` | `cloudg.inventory.aws_services.data_ml.transfer` |  |
| `storage` | `ebs_snapshots` | `cloudg.inventory.aws_services.governance.sharing` |  |
| `storage` | `ebs_volumes` | `cloudg.inventory.aws_deep` |  |
| `storage` | `efs` | `cloudg.inventory.aws_services.platform.storage` |  |
| `storage` | `fsx` | `cloudg.inventory.aws_services.data_ml.transfer` |  |
| `storage` | `s3` | `cloudg.inventory.aws_services.platform.storage` | yes |
| `storage` | `s3_access_points` | `cloudg.inventory.aws_services.governance.s3_access_points` |  |
| `storage` | `s3_multi_region_access_points` | `cloudg.inventory.aws_services.governance.s3_access_points` | yes |
| `storage` | `transfer_family` | `cloudg.inventory.aws_services.data_ml.transfer` |  |
| `sweep` | `cloud_control` | `cloudg.inventory.aws_services.cloudcontrol` |  |
| `sweep` | `tagging_sweep` | `cloudg.inventory.aws_deep` |  |

133 tasks.

### 5.4 collect() and sweep precedence

`AWSDeepInventoryCollector.collect()` calls the base `collect()` and then deduplicates the
breadth sweeps against the dedicated collectors in three tiers:

| Tier | Source | `metadata.discovered_via` |
|---|---|---|
| 0 | dedicated collectors | absent |
| 1 | Cloud Control sweep | `cloud-control` |
| 2 | Tagging API sweep | `tagging-api` |

Tiers are processed in order. A tier 1 or 2 asset is dropped when its `arn` or any of its
`aliases` was already seen in a higher tier; every kept asset adds its `arn` and aliases to the
seen set. The cross-region / cross-collector deduplication in `deduplicate()` happens later, in
the mapper.

### 5.5 Shared helpers (`aws_services/_base.py`)

Module functions:

| Function | Purpose |
|---|---|
| `rel(target, edge, relationship=None, *, reverse=False, description=None, **properties)` | Build a relation object ([reference](INVENTORY_REFERENCE.md#7-the-relation-object-metadatarelations)); `None` for an empty target. |
| `tag_dict(tags)` | Normalise `[{"Key","Value"}]`, `[{"key","value"}]` and `{k: v}` tag shapes. |
| `policy_document(doc)` | Decode a policy given as a dict, JSON or URL-encoded JSON (IAM returns the latter). |
| `as_list(value)` | `None` → `[]`, scalar → `[scalar]`. |
| `policy_statements(doc)` | Statement list of a policy, tolerant of a single statement object. |
| `policy_principals(statement)` | `{"AWS": [...], "Service": [...], "Federated": [...]}`; `"*"` becomes `{"AWS": ["*"]}`. |
| `condition_values(statement, *keys)` | Values of condition keys across all operators, case-insensitive. |
| `account_principal(p)` / `principal_ref(p)` | Account IDs and `:root` ARNs → canonical `arn:aws:iam::<id>:root`. |
| `arns_in(value, limit=200)` | Every ARN inside a nested value (state machine definitions, pipeline configurations). |
| `identifier_refs(env)` | Identifier-shaped values (ARNs, SQS queue URLs verified on the parsed host) of an environment map. Everything else is dropped, so secrets kept in environment variables never reach the map. |
| `resource_policy_relations(policy, account_id)` | Relations from a resource policy: service principals with an `aws:SourceArn` condition become `INVOKES / TRIGGERED_BY` from the source (reverse); AWS principals become `GRANTS_ACCESS / POLICY_ALLOWS_ACTION` (reverse, `cross_account` flagged). Returns `(relations, public)`; `public` is true for an unconditional `*`. |
| `gather_limited(factories, limit=8)` | Run coroutine factories with bounded concurrency; a failing item becomes `None`. Use it for per-item describe calls. |
| `error_code(exc)` | The AWS error code of an exception, or its class name. |

`AWSServiceMixin` methods:

| Method | Purpose |
|---|---|
| `_client(service, region=None)` | Async client context manager with the collector's retry config. |
| `_paginate(client, operation, result_key, **kwargs)` | Async iterator over a botocore paginator. |
| `_pages(call, result_key, cursor_param="NextToken", cursor_key=None, max_pages=1000, **kwargs)` | Manual cursor pagination for operations without a paginator (`_paginate` would raise `OperationNotPageableError`). `cursor_param` is the request parameter, `cursor_key` the response key when it differs. |
| `_arn(service, resource, region=None)` | `arn:aws:<service>:<region>:<account>:<resource>`; pass `region=""` for regionless ARNs. |
| `_account_ref()` | `arn:aws:iam::<account>:root`. |
| `_asset(*, arn, name, asset_type, region=None, tags=None, metadata=None, relations=(), raw=None, exposed=False, aliases=())` | Build an AWS `CloudAsset`: drops empty relations and aliases, normalises tags, fills provider / region / account. Use it for every new asset. |
| `_disabled_asset(service, asset_type, label, reason="not enabled")` | The not-enabled placeholder for a security service ([5.10](#510-security-services-and-coverage-gaps)). |
| `_security_alias(service)` | `aws-security:<service>:<region>:<account>`. |

Each package also has a `_common.py` with shared helpers for its modules (for example
`application/_common.py`: `_host`, `_clean_url` which strips credentials and query strings from
repository URLs, `_bucket_arn`, `_ecr_repo`, `_env_names`, `_vpc_config`, `_role_rel`,
`ApplicationBase._secret_or_param_ref` which reduces a Secrets Manager reference to the secret ARN
without its JSON key / version suffix).

### 5.6 AWS service modules

What each module collects, the asset types it creates, and the `(edge, relationship)` pairs it
declares (`none` = no asset type or no relationship). Generated from the source; see the
[catalog](INVENTORY_CATALOG.md) for the metadata keys of each type.

**`aws_services (top level)`**

| Module | `_collect_*` methods | Asset types | Declared edge / relationship |
|---|---|---|---|
| `aws_services._base` | helpers | none | `GRANTS_ACCESS`/`POLICY_ALLOWS_ACTION`, `INVOKES`/`TRIGGERED_BY` |
| `aws_services._policy_grants` | helpers | none | `GRANTS_ACCESS`/`READS_FROM` |
| `aws_services.identity` | `iam` | `IAM_GROUP`, `IAM_POLICY`, `IAM_ROLE`, `IAM_USER`, `IDENTITY_PROVIDER`, `INSTANCE_PROFILE` | `ASSUMES_ROLE`/`RUNS_ON`, `CONTAINS`, `GRANTS_ACCESS`/`POLICY_ALLOWS_ACTION`, `IAM_POLICY_ATTACHMENT`, `IAM_TRUST`/`CROSS_ACCOUNT_TRUST`, `IAM_TRUST`/`ROLE_ASSUMES_ROLE`, `REFERENCES`/`PERMISSION_BOUNDARY_LIMITS` |
| `aws_services.cloudcontrol` | `cloud_control` | `OTHER` | none |

**`application`**

| Module | `_collect_*` methods | Asset types | Declared edge / relationship |
|---|---|---|---|
| `aws_services.application._common` | helpers | none | `ASSUMES_ROLE`/`RUNS_ON`, `GRANTS_ACCESS`/`POLICY_ALLOWS_ACTION`, `REFERENCES`/`DEPENDS_ON`, `REFERENCES`/`READS_FROM` |
| `aws_services.application.alarms` | `cloudwatch_alarms` | `ALARM` | `INVOKES`/`INVOKES`, `INVOKES`/`SCALES_WITH`, `MONITORS`/`MONITORED_BY`, `REFERENCES`/`DEPENDS_ON` |
| `aws_services.application.backup` | `backup_plans`, `backup_vaults` | `BACKUP_PLAN`, `BACKUP_VAULT` | `MANAGES`/`BACKUP_TO`, `REFERENCES`/`BACKUP_TO`, `REFERENCES`/`ENCRYPTED_BY_KMS` |
| `aws_services.application.batch` | `batch` | `BATCH_ENVIRONMENT`, `JOB_DEFINITION`, `JOB_QUEUE` | `LOGS_TO`/`LOGS_TO`, `MANAGES`, `REFERENCES`/`DEPENDS_ON`, `REFERENCES`/`RUNS_ON`, `USES_IMAGE`/`RUNS_ON` |
| `aws_services.application.build_deploy` | `codebuild`, `codedeploy` | `BUILD_PROJECT`, `DEPLOYMENT_GROUP` | `INVOKES`/`INVOKES`, `LOGS_TO`/`LOGS_TO`, `MANAGES`, `REFERENCES`/`ENCRYPTED_BY_KMS`, `REFERENCES`/`MONITORED_BY`, `REFERENCES`/`READS_FROM`, `REFERENCES`/`SERVES_TRAFFIC_TO`, `REFERENCES`/`WRITES_TO`, `USES_IMAGE`/`RUNS_ON` |
| `aws_services.application.cicd` | `codepipeline`, `codeconnections` | `CI_PIPELINE`, `SOURCE_CONNECTION` | `ASSUMES_ROLE`/`RUNS_ON`, `INVOKES`/`INVOKES`, `MANAGES`, `REFERENCES`, `REFERENCES`/`DEPENDS_ON`, `REFERENCES`/`ENCRYPTED_BY_KMS`, `REFERENCES`/`READS_FROM`, `REFERENCES`/`WRITES_TO` |
| `aws_services.application.compute` | `apprunner`, `elasticbeanstalk` | `APP_SERVICE`, `VPC_LINK` | `CONTAINS`, `LOGS_TO`/`LOGS_TO`, `MANAGES`, `REFERENCES`/`DEPENDS_ON`, `REFERENCES`/`ENCRYPTED_BY_KMS`, `REFERENCES`/`READS_FROM`, `REFERENCES`/`RUNS_ON`, `USES_IMAGE`/`RUNS_ON` |
| `aws_services.application.containers_ext` | `ecs_capacity_providers`, `ecs_container_instances`, `cloudmap` | `CAPACITY_PROVIDER`, `DNS_RECORD`, `DNS_ZONE`, `ECS_CLUSTER`, `SERVICE_REGISTRY` | `ASSUMES_ROLE`/`RUNS_ON`, `CONTAINS`, `MANAGES`/`SCALES_WITH`, `REFERENCES`/`DNS_RESOLVED`, `REFERENCES`/`RUNS_ON`, `REFERENCES`/`SCALES_WITH` |
| `aws_services.application.firehose` | `firehose` | `DELIVERY_STREAM` | `INVOKES`/`INVOKES`, `INVOKES`/`STREAMS_TO`, `INVOKES`/`TRIGGERED_BY`, `LOGS_TO`/`LOGS_TO`, `REFERENCES`/`BACKUP_TO`, `REFERENCES`/`ENCRYPTED_BY_KMS`, `REFERENCES`/`READS_FROM` |
| `aws_services.application.integration` | `scheduler`, `pipes`, `eventbridge_api_destinations`, `eventbridge_archives` | `API_DESTINATION`, `EVENT_ARCHIVE`, `EVENT_PIPE`, `SCHEDULE` | `INVOKES`/`INVOKES`, `INVOKES`/`TRIGGERED_BY`, `LOGS_TO`/`LOGS_TO`, `REFERENCES`/`DEPENDS_ON`, `REFERENCES`/`ENCRYPTED_BY_KMS`, `REFERENCES`/`READS_FROM`, `REFERENCES`/`WRITES_TO` |
| `aws_services.application.logs` | `log_subscriptions`, `log_destinations`, `oam` | `IAM_POLICY`, `LOG_SINK` | `INVOKES`/`STREAMS_TO`, `REFERENCES`/`DEPENDS_ON`, `REFERENCES`/`WRITES_TO` |
| `aws_services.application.operations` | `ssm_parameters`, `ssm_managed_instances`, `ssm_documents`, `ssm_associations`, `ssm_maintenance_windows` | `OTHER`, `PARAMETER`, `RUNBOOK`, `SCHEDULE`, `VIRTUAL_MACHINE` | `GRANTS_ACCESS`/`POLICY_ALLOWS_ACTION`, `INVOKES`/`INVOKES`, `LOGS_TO`/`LOGS_TO`, `MANAGES`, `MANAGES`/`SCHEDULED_BY`, `REFERENCES`/`DEPENDS_ON`, `REFERENCES`/`ENCRYPTED_BY_KMS` |
| `aws_services.application.serverless_ext` | `lambda_aliases` | `LAMBDA_FUNCTION` | `REFERENCES`/`DEPENDS_ON` |

**`containers`**

| Module | `_collect_*` methods | Asset types | Declared edge / relationship |
|---|---|---|---|
| `aws_services.containers.ecr` | `ecr` | `CONTAINER_REGISTRY` | `REFERENCES`/`ENCRYPTED_BY_KMS` |
| `aws_services.containers.ecs` | `ecs` | `CONTAINER_SERVICE`, `ECS_CLUSTER`, `TASK_DEFINITION` | `ASSUMES_ROLE`/`DEPENDS_ON`, `ASSUMES_ROLE`/`RUNS_ON`, `CONTAINS`/`CLUSTER_CONTAINS_SERVICE`, `CONTAINS`/`SUBNET_CONTAINS_INSTANCE`, `LOAD_BALANCER_TARGET`/`LOAD_BALANCED_BY`, `LOGS_TO`/`LOGS_TO`, `MANAGES`/`SCHEDULED_BY`, `REFERENCES`/`DEPENDS_ON`, `REFERENCES`/`DNS_RESOLVED`, `REFERENCES`/`READS_FROM`, `USES_IMAGE`/`RUNS_ON` |
| `aws_services.containers.eks` | `eks`, `eks_cluster` | `CLUSTER_ADDON`, `EKS_CLUSTER`, `FARGATE_PROFILE`, `K8S_SERVICE_ACCOUNT`, `NODE_GROUP` | `ASSUMES_ROLE`/`ROLE_ASSUMES_ROLE`, `ASSUMES_ROLE`/`RUNS_ON`, `ATTACHED_TO`/`PROTECTED_BY_SG`, `CONTAINS`, `CONTAINS`/`CLUSTER_CONTAINS_SERVICE`, `CONTAINS`/`SUBNET_CONTAINS_INSTANCE`, `GRANTS_ACCESS`/`POLICY_ALLOWS_ACTION`, `MANAGES`/`SCALES_WITH`, `REFERENCES`/`DEPENDS_ON`, `REFERENCES`/`ENCRYPTED_BY_KMS` |

**`data_ml`**

| Module | `_collect_*` methods | Asset types | Declared edge / relationship |
|---|---|---|---|
| `aws_services.data_ml._common` | helpers | none | `CONTAINS`/`SUBNET_CONTAINS_INSTANCE`, `GRANTS_ACCESS`/`POLICY_ALLOWS_ACTION` |
| `aws_services.data_ml.analytics` | `emr`, `emr_serverless`, `athena` | `BIG_DATA_CLUSTER`, `QUERY_WORKGROUP` | `ASSUMES_ROLE`/`RUNS_ON`, `LOGS_TO`/`LOGS_TO`, `REFERENCES`/`ENCRYPTED_BY_KMS`, `REFERENCES`/`RUNS_ON`, `REFERENCES`/`WRITES_TO`, `USES_IMAGE`/`RUNS_ON` |
| `aws_services.data_ml.bedrock` | `bedrock` | `AI_AGENT`, `AI_GUARDRAIL`, `KNOWLEDGE_BASE`, `LOG_SINK` | `ASSUMES_ROLE`/`RUNS_ON`, `INVOKES`/`INVOKES`, `LOGS_TO`/`LOGS_TO`, `PROTECTS`, `REFERENCES`/`ENCRYPTED_BY_KMS`, `REFERENCES`/`READS_FROM`, `REFERENCES`/`WRITES_TO` |
| `aws_services.data_ml.databases` | `rds_proxies`, `rds_global_clusters`, `memorydb`, `dax` | `AURORA_CLUSTER`, `CACHE_CLUSTER`, `DATABASE_PROXY` | `ASSUMES_ROLE`/`RUNS_ON`, `CONTAINS`, `LOAD_BALANCER_TARGET`/`SERVES_TRAFFIC_TO`, `REFERENCES`/`ENCRYPTED_BY_KMS`, `REFERENCES`/`READS_FROM`, `REFERENCES`/`REPLICATES_TO`, `REFERENCES`/`WRITES_TO` |
| `aws_services.data_ml.glue` | `glue` | `DATA_CATALOG` | `CONTAINS`, `REFERENCES`/`DEPENDS_ON`, `REFERENCES`/`ENCRYPTED_BY_KMS` |
| `aws_services.data_ml.glue_etl` | helpers | `DATA_CATALOG`, `ETL_JOB`, `EVENT_RULE` | `ASSUMES_ROLE`/`RUNS_ON`, `INVOKES`/`INVOKES`, `INVOKES`/`TRIGGERED_BY`, `LOGS_TO`/`LOGS_TO`, `REFERENCES`/`DEPENDS_ON`, `REFERENCES`/`ENCRYPTED_BY_KMS`, `REFERENCES`/`READS_FROM`, `REFERENCES`/`WRITES_TO` |
| `aws_services.data_ml.lakeformation` | `lakeformation` | `DATA_CATALOG` | `ASSUMES_ROLE`/`RUNS_ON`, `GOVERNS`/`COMPLIANCE_GOVERNS`, `GRANTS_ACCESS`/`POLICY_ALLOWS_ACTION` |
| `aws_services.data_ml.messaging` | `msk`, `amazon_mq` | `MESSAGE_BROKER` | `LOGS_TO`/`LOGS_TO`, `REFERENCES`/`ENCRYPTED_BY_KMS`, `REFERENCES`/`REPLICATES_TO` |
| `aws_services.data_ml.registry` | `ecr_public` | `CONTAINER_REGISTRY` | none |
| `aws_services.data_ml.sagemaker` | `sagemaker` | `ML_ENDPOINT`, `ML_MODEL`, `ML_WORKSPACE` | `ASSUMES_ROLE`/`RUNS_ON`, `ATTACHED_TO`, `REFERENCES`/`DEPENDS_ON`, `REFERENCES`/`ENCRYPTED_BY_KMS`, `REFERENCES`/`READS_FROM`, `REFERENCES`/`WRITES_TO`, `USES_IMAGE`/`RUNS_ON` |
| `aws_services.data_ml.serverless_data` | `opensearch_serverless`, `redshift_serverless` | `DATA_WAREHOUSE`, `SEARCH_DOMAIN` | `ASSUMES_ROLE`/`RUNS_ON`, `REFERENCES`/`CERTIFICATE_SECURES`, `REFERENCES`/`DEPENDS_ON`, `REFERENCES`/`ENCRYPTED_BY_KMS`, `REFERENCES`/`READS_FROM` |
| `aws_services.data_ml.transfer` | `transfer_family`, `datasync`, `fsx` | `DATA_TRANSFER`, `FILE_SYSTEM`, `IDENTITY_USER` | `ASSUMES_ROLE`/`RUNS_ON`, `ATTACHED_TO`, `CONTAINS`, `INVOKES`/`INVOKES`, `LOGS_TO`/`LOGS_TO`, `REFERENCES`/`CERTIFICATE_SECURES`, `REFERENCES`/`DEPENDS_ON`, `REFERENCES`/`ENCRYPTED_BY_KMS`, `REFERENCES`/`READS_FROM`, `REFERENCES`/`WRITES_TO` |

**`governance`**

| Module | `_collect_*` methods | Asset types | Declared edge / relationship |
|---|---|---|---|
| `aws_services.governance._common` | helpers | none | `GRANTS_ACCESS` |
| `aws_services.governance.cognito` | `cognito_user_pools`, `cognito_identity_pools` | `IDENTITY_POOL`, `USER_POOL` | `ASSUMES_ROLE`/`ROLE_ASSUMES_ROLE`, `ASSUMES_ROLE`/`RUNS_ON`, `INVOKES`/`INVOKES`, `REFERENCES`/`DEPENDS_ON`, `REFERENCES`/`ENCRYPTED_BY_KMS` |
| `aws_services.governance.data_protection` | `kms`, `secrets_manager`, `dynamodb` | `DYNAMODB_TABLE`, `KMS_KEY`, `SECRET` | `GRANTS_ACCESS`, `INVOKES`/`ROTATES_SECRET`, `REFERENCES`/`DEPENDS_ON`, `REFERENCES`/`ENCRYPTED_BY_KMS`, `REFERENCES`/`REPLICATES_TO`, `REFERENCES`/`STREAMS_TO` |
| `aws_services.governance.iam_extras` | `iam_saml_providers`, `iam_access_keys`, `rolesanywhere` | `ACCESS_KEY`, `IDENTITY_PROVIDER`, `PERMISSION_SET` | `ASSUMES_ROLE`/`ROLE_ASSUMES_ROLE`, `CONTAINS`, `IAM_POLICY_ATTACHMENT`/`ROLE_HAS_POLICY`, `IAM_TRUST`/`ROLE_ASSUMES_ROLE`, `REFERENCES`/`DEPENDS_ON` |
| `aws_services.governance.identity_center` | `identity_center` | `IDENTITY_GROUP`, `IDENTITY_PROVIDER`, `IDENTITY_USER`, `PERMISSION_SET` | `ASSUMES_ROLE`/`ROLE_ASSUMES_ROLE`, `CONTAINS`, `GRANTS_ACCESS`, `IAM_POLICY_ATTACHMENT`/`ROLE_HAS_POLICY`, `MANAGES`/`OWNED_BY`, `REFERENCES`/`PERMISSION_BOUNDARY_LIMITS` |
| `aws_services.governance.ram` | `ram_shares` | `RESOURCE_SHARE` | `GRANTS_ACCESS`, `GRANTS_ACCESS`/`DEPENDS_ON`, `MANAGES`/`OWNED_BY` |
| `aws_services.governance.s3_access_points` | `s3_access_points`, `s3_multi_region_access_points` | `ACCESS_POINT` | `ATTACHED_TO`, `REFERENCES`/`CROSS_ACCOUNT_TRUST`, `REFERENCES`/`READS_FROM` |
| `aws_services.governance.service_catalog` | `service_catalog` | `PRODUCT_PORTFOLIO`, `PROVISIONED_PRODUCT` | `ASSUMES_ROLE`/`RUNS_ON`, `GRANTS_ACCESS`/`CROSS_ACCOUNT_TRUST`, `GRANTS_ACCESS`/`POLICY_ALLOWS_ACTION`, `MANAGES`/`OWNED_BY`, `REFERENCES`/`DEPENDS_ON` |
| `aws_services.governance.sharing` | `ebs_snapshots`, `machine_images`, `rds_snapshots` | `MACHINE_IMAGE`, `SNAPSHOT` | `GRANTS_ACCESS`, `REFERENCES`, `REFERENCES`/`DEPENDS_ON`, `REFERENCES`/`ENCRYPTED_BY_KMS` |
| `aws_services.governance.stack_sets` | `stack_sets` | `STACK_SET` | `ASSUMES_ROLE`/`RUNS_ON`, `MANAGES`/`OWNED_BY`, `REFERENCES`/`DEPENDS_ON` |

**`network_ext`**

| Module | `_collect_*` methods | Asset types | Declared edge / relationship |
|---|---|---|---|
| `aws_services.network_ext.__init__` | `cloudfront` | none | none |
| `aws_services.network_ext.apigateway` | `apigateway_authorizers`, `apigateway_vpc_links`, `apigateway_domains` | `AUTHORIZER`, `CUSTOM_DOMAIN`, `VPC_LINK` | `ASSUMES_ROLE`/`RUNS_ON`, `CONTAINS`/`SUBNET_CONTAINS_INSTANCE`, `INVOKES`/`INVOKES`, `LOAD_BALANCER_TARGET`/`SERVES_TRAFFIC_TO`, `REFERENCES`/`CERTIFICATE_SECURES`, `REFERENCES`/`DEPENDS_ON`, `ROUTE`/`SERVES_TRAFFIC_TO` |
| `aws_services.network_ext.cloudfront` | `cloudfront_deep` | `CLOUDFRONT`, `EDGE_FUNCTION` | `INVOKES`/`INVOKES`, `LOGS_TO`/`LOGS_TO`, `REFERENCES`/`CERTIFICATE_SECURES`, `ROUTE`/`SERVES_TRAFFIC_TO` |
| `aws_services.network_ext.direct_connect` | `direct_connect`, `direct_connect_gateways` | `DIRECT_CONNECT` | `ATTACHED_TO`, `CONTAINS`, `ROUTE`/`TRANSIT_ROUTED` |
| `aws_services.network_ext.elb_rules` | `elb_rules` | `CERTIFICATE`, `LB_LISTENER` | `CONTAINS`, `REFERENCES`/`CERTIFICATE_SECURES`, `REFERENCES`/`DEPENDS_ON`, `ROUTE`/`SERVES_TRAFFIC_TO` |
| `aws_services.network_ext.global_accelerator` | `global_accelerator` | `GLOBAL_ACCELERATOR` | `LOAD_BALANCER_TARGET`/`SERVES_TRAFFIC_TO` |
| `aws_services.network_ext.lattice` | `vpc_lattice` | `ENDPOINT_SERVICE`, `SERVICE_NETWORK`, `TARGET_GROUP` | `ATTACHED_TO`, `CONTAINS`, `LOAD_BALANCER_TARGET`/`LB_TARGETS_INSTANCE`, `LOAD_BALANCER_TARGET`/`LOAD_BALANCED_BY`, `REFERENCES`/`CERTIFICATE_SECURES` |
| `aws_services.network_ext.network_manager` | `network_manager` | `SERVICE_NETWORK` | `CONTAINS`, `MONITORS`/`MONITORED_BY`, `ROUTE`/`TRANSIT_ROUTED` |
| `aws_services.network_ext.privatelink` | `egress_only_igw`, `prefix_lists`, `endpoint_services` | `ENDPOINT_SERVICE`, `INTERNET_GATEWAY`, `PREFIX_LIST` | `ATTACHED_TO`, `GRANTS_ACCESS`/`POLICY_ALLOWS_ACTION`, `LOAD_BALANCER_TARGET`/`SERVES_TRAFFIC_TO`, `ROUTE`/`SERVES_TRAFFIC_TO` |
| `aws_services.network_ext.resolver` | `route53_resolver` | `DNS_RESOLVER`, `LOG_SINK`, `NETWORK_FIREWALL` | `ATTACHED_TO`/`DNS_RESOLVED`, `CONTAINS`, `CONTAINS`/`SUBNET_CONTAINS_INSTANCE`, `LOGS_TO`/`LOGS_TO`, `PROTECTS`/`PROTECTED_BY_NACL`, `ROUTE`/`DNS_RESOLVED` |
| `aws_services.network_ext.tgw` | `tgw_routing` | `PEERING_CONNECTION`, `ROUTE_TABLE` | `CONTAINS`, `PEERING`/`TRANSIT_ROUTED`, `ROUTE`/`TRANSIT_ROUTED` |
| `aws_services.network_ext.vpn` | `vpn` | `CUSTOMER_GATEWAY`, `VPN_CONNECTION`, `VPN_GATEWAY` | `ATTACHED_TO`, `ATTACHED_TO`/`TRANSIT_ROUTED`, `REFERENCES`/`CERTIFICATE_SECURES`, `REFERENCES`/`DEPENDS_ON`, `ROUTE`/`TRANSIT_ROUTED` |

**`platform`**

| Module | `_collect_*` methods | Asset types | Declared edge / relationship |
|---|---|---|---|
| `aws_services.platform.compute_fabric` | `autoscaling`, `launch_templates`, `vpc_endpoints`, `flow_logs` | `AUTOSCALING_GROUP`, `FLOW_LOG`, `LAUNCH_TEMPLATE`, `VPC_ENDPOINT` | `ASSUMES_ROLE`/`RUNS_ON`, `CONTAINS`, `CONTAINS`/`SUBNET_CONTAINS_INSTANCE`, `LOAD_BALANCER_TARGET`/`LOAD_BALANCED_BY`, `LOGS_TO`/`LOGS_TO`, `MANAGES`/`SCALES_WITH`, `MONITORS`/`MONITORED_BY`, `REFERENCES`/`DEPENDS_ON`, `ROUTE`/`SERVES_TRAFFIC_TO`, `ROUTE`/`TRANSIT_ROUTED` |
| `aws_services.platform.data` | `rds`, `elasticache`, `opensearch`, `redshift` | `AURORA_CLUSTER`, `CACHE_CLUSTER`, `DATA_WAREHOUSE`, `RDS_INSTANCE`, `SEARCH_DOMAIN` | `ASSUMES_ROLE`/`RUNS_ON`, `CONTAINS`, `CONTAINS`/`SUBNET_CONTAINS_INSTANCE`, `LOGS_TO`/`LOGS_TO`, `REFERENCES`/`ENCRYPTED_BY_KMS`, `REFERENCES`/`READS_FROM`, `REFERENCES`/`REPLICATES_TO` |
| `aws_services.platform.dns_iac_ops` | `route53`, `cloudformation`, `log_groups`, `acm` | `CERTIFICATE`, `DNS_RECORD`, `DNS_ZONE`, `IAC_STACK`, `LOG_GROUP` | `ASSUMES_ROLE`/`RUNS_ON`, `ATTACHED_TO`/`DNS_RESOLVED`, `CONTAINS`, `MANAGES`/`OWNED_BY`, `REFERENCES`/`CERTIFICATE_SECURES`, `REFERENCES`/`ENCRYPTED_BY_KMS`, `ROUTE`/`DNS_RESOLVED` |
| `aws_services.platform.load_balancing` | `elbv2`, `elb_classic` | `LOAD_BALANCER`, `TARGET_GROUP` | `CONTAINS`/`SUBNET_CONTAINS_INSTANCE`, `LOAD_BALANCER_TARGET`/`LB_TARGETS_INSTANCE`, `LOAD_BALANCER_TARGET`/`LOAD_BALANCED_BY`, `LOGS_TO`/`LOGS_TO`, `REFERENCES`/`CERTIFICATE_SECURES` |
| `aws_services.platform.storage` | `s3`, `efs` | `FILE_SYSTEM`, `S3_BUCKET` | `ASSUMES_ROLE`/`RUNS_ON`, `CONTAINS`/`SUBNET_CONTAINS_INSTANCE`, `INVOKES`/`INVOKES`, `LOGS_TO`/`LOGS_TO`, `REFERENCES`/`ENCRYPTED_BY_KMS`, `REFERENCES`/`REPLICATES_TO` |

**`security`**

| Module | `_collect_*` methods | Asset types | Declared edge / relationship |
|---|---|---|---|
| `aws_services.security._common` | helpers | none | `MONITORS`/`MONITORED_BY` |
| `aws_services.security.detection` | `guardduty`, `securityhub`, `inspector2`, `macie`, `detective` | `DATA_SECURITY_SCANNER`, `SECURITY_HUB`, `THREAT_DETECTOR`, `VULNERABILITY_SCANNER` | `ASSUMES_ROLE`/`RUNS_ON`, `MONITORS`/`MONITORED_BY`, `MONITORS`/`READS_FROM` |
| `aws_services.security.network_protection` | `wafv2`, `network_firewall`, `shield` | `DDOS_PROTECTION`, `NETWORK_FIREWALL`, `WAF_WEB_ACL` | `CONTAINS`/`SUBNET_CONTAINS_INSTANCE`, `PROTECTS`/`PROTECTED_BY_NACL`, `PROTECTS`/`PROTECTED_BY_WAF`, `REFERENCES`/`DEPENDS_ON` |
| `aws_services.security.posture` | `config`, `access_analyzer`, `cloudtrail` | `ACCESS_ANALYZER`, `CLOUDTRAIL`, `CONFIG_RECORDER` | `ASSUMES_ROLE`/`RUNS_ON`, `LOGS_TO`/`LOGS_TO`, `LOGS_TO`/`STREAMS_TO`, `REFERENCES`/`ENCRYPTED_BY_KMS` |

**`serverless`**

| Module | `_collect_*` methods | Asset types | Declared edge / relationship |
|---|---|---|---|
| `aws_services.serverless.apigateway` | `apigateway`, `apigatewayv2` | `API_GATEWAY` | `ASSUMES_ROLE`/`RUNS_ON`, `INVOKES`/`INVOKES`, `LOGS_TO`/`LOGS_TO`, `PROTECTS`/`PROTECTED_BY_WAF`, `ROUTE`/`SERVES_TRAFFIC_TO` |
| `aws_services.serverless.functions` | `lambda` | `LAMBDA_FUNCTION` | `ASSUMES_ROLE`/`RUNS_ON`, `INVOKES`/`TRIGGERED_BY`, `LOGS_TO`/`LOGS_TO`, `REFERENCES`/`DEPENDS_ON`, `REFERENCES`/`ENCRYPTED_BY_KMS`, `REFERENCES`/`READS_FROM`, `REFERENCES`/`WRITES_TO`, `USES_IMAGE`/`RUNS_ON` |
| `aws_services.serverless.messaging` | `sqs`, `sns`, `eventbridge`, `stepfunctions`, `kinesis` | `DATA_STREAM`, `EVENT_BUS`, `EVENT_RULE`, `MESSAGE_QUEUE`, `NOTIFICATION_TOPIC`, `STATE_MACHINE` | `ASSUMES_ROLE`/`RUNS_ON`, `CONTAINS`, `INVOKES`/`INVOKES`, `INVOKES`/`STREAMS_TO`, `LOGS_TO`/`LOGS_TO`, `REFERENCES`/`ENCRYPTED_BY_KMS`, `REFERENCES`/`WRITES_TO` |

**`mapper-level modules`**

| Module | `_collect_*` methods | Asset types | Declared edge / relationship |
|---|---|---|---|
| `aws_deep` | `route_tables`, `internet_gateways`, `nat_gateways`, `network_interfaces`, `ebs_volumes`, `elastic_ips`, `nacls`, `vpc_peering`, `transit_gateways`, `tagging_sweep` | `EBS_VOLUME`, `ELASTIC_IP`, `INTERNET_GATEWAY`, `NACL`, `NAT_GATEWAY`, `NETWORK_INTERFACE`, `PEERING_CONNECTION`, `ROUTE_TABLE`, `TRANSIT_GATEWAY` | `ROUTE`/`TRANSIT_ROUTED` |
| `kubernetes` | helpers | `K8S_INGRESS`, `K8S_NAMESPACE`, `K8S_SERVICE`, `K8S_SERVICE_ACCOUNT`, `K8S_WORKLOAD` | `ASSUMES_ROLE`/`RUNS_ON`, `CONTAINS`/`CLUSTER_CONTAINS_SERVICE`, `LOAD_BALANCER_TARGET`/`SERVES_TRAFFIC_TO`, `REFERENCES`/`RUNS_ON`, `ROUTE`/`LOAD_BALANCED_BY`, `ROUTE`/`SERVES_TRAFFIC_TO`, `USES_IMAGE`/`RUNS_ON` |
| `organization_assets` | helpers | `CLOUD_ACCOUNT`, `GUARDRAIL`, `LANDING_ZONE`, `ORGANIZATION`, `ORG_POLICY`, `ORG_UNIT` | `CONTAINS`, `CONTAINS`/`ORG_CONTAINS_ACCOUNT`, `GOVERNS`/`COMPLIANCE_GOVERNS`, `GOVERNS`/`SCP_RESTRICTS`, `MANAGES`/`COMPLIANCE_GOVERNS`, `MANAGES`/`OWNED_BY` |

### 5.7 The Cloud Control sweep (`aws_services/cloudcontrol.py`)

1. **Discover listable types.** `_cc_listable_types()` lists every CloudFormation resource type
   (`cloudformation:ListTypes`, public and AWS-provided) and describes its schema to keep only
   types with a `list` handler, noting types whose list handler requires a parent identifier.
   The result is cached in memory and on disk for 7 days in `$CLOUDG_CACHE_DIR`
   (default `~/.cache/cloudg`), so a multi-region run discovers once.
2. **Select.** Skip types that need a parent identifier, types in the catalog's `covered_types`
   (a deep collector maps them better), global types outside the primary region
   (`global_prefixes`), and types filtered by `cloud_control_types` / `cloud_control_exclude`
   (exact names or prefixes like `AWS::Glue::`).
3. **List.** `ListResources` per type with `cloud_control_concurrency` types in parallel, up to
   5000 resources per type.
4. **Build assets.** `_cc_asset()`: the ARN comes from the model's `Arn` or `<Type>Arn`, or the
   identifier when it is an ARN, else a `cloudcontrol:` synthetic identifier. The asset type
   comes from the catalog's `asset_types`, then `asset_type_from_arn`, then `OTHER`. Metadata:
   `discovered_via: "cloud-control"`, `resource_type`, `identifier`, `service`, and the
   **redacted** model as `properties`. The identifier becomes an alias.
5. **Redaction.** `redact()` drops, at any depth, keys matching the secret pattern (password,
   secret, token, private key, credential, API key, authorization, connection string,
   certificate body, key material, environment variables, user data) and the per-type
   `sensitive_fields` of the catalog (for example SSM parameter `Value`).
6. **Coverage.** Types that failed to list are counted per error code in the
   `cloud_control_skipped_types` coverage entry.

### 5.8 The Tagging API sweep

`_collect_tagging_sweep()` pages through `resourcegroupstaggingapi:GetResources`, which returns
every *tagged* resource of the region (AWS never returns resources that were never tagged). Each
becomes an asset classified by `asset_type_from_arn()` with `discovered_via: "tagging-api"` and
`service`. Its value is enrichment and a safety net; the Cloud Control sweep is what finds
untagged resources.

`asset_type_from_arn(arn)` reads `service` and the resource type from the ARN
(`_arn_resource_type`: the first path / colon segment, except WAFv2 which uses the segment after
the scope, API Gateway which uses the path shape `restapis` / `restapis/stages`, and S3 where the
bare `s3` entry only matches bucket ARNs) and looks up `service:type`, then `service`, in
`catalogs/aws_arn_types.yaml`.

### 5.9 Kubernetes (`kubernetes.py`)

For each `ACTIVE` EKS cluster with an endpoint (when Kubernetes mapping is enabled), the EKS
collector calls `collect_eks_workloads()` in a worker thread and records a
`kubernetes:<cluster>` coverage entry (`SUCCESS` with the object count, or `FAILED` with the
error, typically an unreachable private endpoint or a missing access entry):

- **Authentication** without a Kubernetes client: `eks_token()` presigns an STS
  `GetCallerIdentity` URL with the `x-k8s-aws-id` header, exactly like `aws eks get-token`, and
  sends it as a bearer token. TLS is verified against the cluster CA from `DescribeCluster`.
- **Reads only**: `KubernetesReader` issues `GET`s, pages with `limit` / `continue` (500 per
  page) and stops at 5000 objects per list. Secrets are never read.
- **Mapping** (`_ClusterMapper`): namespaces, service accounts (IRSA annotation → role),
  Deployments / StatefulSets / DaemonSets / CronJobs (images → repositories, service account,
  privileged containers, host network), Services (selector → workloads, load balancer
  hostnames → the ELB by DNS name), Ingresses (backends → services, hostnames → the ALB).
  Identifiers: `k8s://<cluster ARN>/<namespace>/<Kind>/<name>`.
- **Permissions**: the identity cloudg runs as needs network reach to the endpoint and read
  access in the cluster; an access entry with `AmazonEKSViewPolicy` is enough. A failure does
  not affect the rest of the EKS collection.

### 5.10 Security services and coverage gaps

Security collectors (GuardDuty, Security Hub, Inspector, Macie, Config, Access Analyzer,
Detective, CloudTrail, WAF, Network Firewall, Shield) produce, per account and region:

- when enabled, an asset with `metadata.security_service`, `enabled: true`, the alias
  `aws-security:<service>:<region>:<account>`, and `MONITORS` / `PROTECTS` relations to what it
  covers (Inspector: every scanned instance, repository and function from its coverage list;
  GuardDuty / Config / CloudTrail / Macie: the account; Security Hub: the services it ingests
  from; WAF: the associated resources);
- when not enabled (or access is denied), `_disabled_asset()`: a placeholder with
  `enabled: false` and the same alias, so other relations that target "the GuardDuty of this
  account" still resolve and the gap is visible.

`security_coverage()` and `summary.security_service_gaps` are computed from these assets.

## 6. AWS Organizations and Control Tower

`discover_organization(session, control_tower=True, home_region=None)` (blocking, read-only):

1. `sts:GetCallerIdentity` (caller account), `organizations:DescribeOrganization` (ID, ARN,
   management account, feature set). Failure raises `RuntimeError`: the caller is not in an
   organization or lacks access.
2. `ListRoots`; for each root, a recursive walk with `ListAccountsForParent` and
   `ListOrganizationalUnitsForParent`, recording every account's parent and OU path.
3. Policies of each policy type enabled on the root (`ListPolicies`, `ListTargetsForPolicy`).
4. Trusted service access (`ListAWSServiceAccessForOrganization`) and delegated administrators
   for the security services (`ListDelegatedAdministrators`); an access denial stops that loop.
5. With `control_tower`, `discover_control_tower()` probes regions in order (the hint, the
   session region, then the usual home regions) with `controltower:ListLandingZones`. On the
   first landing zone: `GetLandingZone` (the manifest is parsed for governed regions and shared
   accounts, both the 3.x and 4.x layouts, and then dropped), `ListEnabledControls` (falling back
   to per-OU queries on older API revisions) and `ListEnabledBaselines`.

Account selection happens in `OrganizationTopology.target_accounts()`; the mapper wires it to
`aws.organization` ([step 2](#4-a-mapping-run-step-by-step)). The map nodes come from
`organization_assets.topology_assets()`
([reference](INVENTORY_REFERENCE.md#18-organization-assets-on-the-map)).

Permissions: run from the management account or a delegated administrator for Organizations
(`organizations:Describe*`, `List*`; `controltower:List*`, `Get*`). Member accounts need a role
cloudg can assume; the default `AWSControlTowerExecution` has administrator access, so the
recommended setup is a dedicated read-only role (`SecurityAudit` + `ViewOnlyAccess`) deployed
to every account with a service-managed StackSet and passed with `--org-role`.

## 7. The relationship linker

`RelationshipLinker(assets, materialize_external=True)` subclasses `IdentifierIndex`.

### 7.1 The identifier index

Every asset is registered under:

- its `arn` and its `name`;
- the native short ID: the last `/` or `:` segment of `arn` (not for `k8s://`, `k8s-gke://`,
  `gcp-principal:`, `entra:`, `loganalytics:` identifiers, whose tails are not IDs);
- known self-ID metadata keys: `group_id`, `route_table_id`, `internet_gateway_id`,
  `nat_gateway_id`, `network_interface_id`, `volume_id`, `allocation_id`, `network_acl_id`,
  `peering_connection_id`, `transit_gateway_id`, `vpc_endpoint_id`, `launch_template_id`,
  `file_system_id`, `queue_url`, `repository_uri`, `zone_id`;
- every entry of `metadata.aliases`;
- type-specific keys: `vpc_id` (VPC / VNet), `subnet_id` (subnet), `public_ip` (Elastic IP,
  EC2), `account_id` (account nodes);
- names other services use by domain: `<bucket>.s3.amazonaws.com`, a load balancer's
  `dns_name` (as-is and lower-cased without the trailing dot), a distribution's `domain_name`.

An identifier that starts with `/subscriptions/` or `/providers/`, or contains a dot and no
slash (host names), is also registered lower-cased, so Azure IDs and DNS names match
case-insensitively.

### 7.2 Resolution

`resolve(identifier, context=None)` returns an asset `id` or `None`:

1. Exact lookup.
2. Each **variant** of the identifier (`_variants`), in order: trimmed of whitespace, trailing
   `.` and `/`; lower-cased; without a `dualstack.` prefix; without a trailing `:*`; a Lambda ARN
   without its version / alias qualifier; an S3 object ARN reduced to the bucket ARN; an image
   reference reduced to its repository (for ECR hosts, matched by a full-match regular
   expression on the parsed registry host, and for any `host/repo:tag`); an API Gateway stage
   ARN reduced to the API; an Azure Container Registry image reduced to the registry login
   server.
3. A role ARN that missed (built from a bare role name, while the real role has a path):
   the role with that name in that account.
4. An STS assumed-role ARN: the role with that name in that account.

When several assets share an identifier, `_pick` chooses:

1. drop placeholders when a real asset is among the candidates;
2. a single candidate wins;
3. globally unique identifier schemes (`arn:`, `/subscriptions/`, `/providers/`, `//`,
   `k8s://`, `cloudg:`, `aws-security:`, `azure-security:`, `entra:`, `loganalytics:`,
   `gcp-principal:`, `k8s-gke://`) take the first candidate;
4. without context, the first candidate;
5. a candidate in the referencing asset's account **and** region;
6. a candidate in the same account;
7. exactly one candidate in region `global`;
8. otherwise **no match**: an ambiguous name such as `default` that exists in several accounts
   is left unresolved rather than guessed.

### 7.3 External accounts and unresolved references

When a declared target does not resolve, `_external_account()` checks whether it belongs to an
account that was not mapped: an AWS ARN with an account field, a bare 12-digit account ID, an
Azure ID under `/subscriptions/<guid>`, a GCP name under `//….googleapis.com/projects/<id>`. If
the account differs from the referencing asset's, a `CLOUD_ACCOUNT` placeholder with
`external: true` is created once per account (and indexed, so later references reuse it), and
the edge points there with `properties.external_reference` set to the original identifier.
AWS-owned references (account `aws`, as in AWS managed policies) are not externalised.

Anything else is recorded in `unresolved` (up to 2000 entries).

### 7.4 The three passes

`link(include_generic=True)` runs, each pass wrapped so that one malformed asset cannot stop the
run (failures are logged at debug level):

1. **Declared relations** (`_link_declared`). For each relation: parse `edge` (unknown →
   `REFERENCES`), resolve `target` with the asset as context, fall back to an external account,
   else record as unresolved. `reverse` swaps source and target. Properties are copied.
2. **Provider rules** (`_link_rules`, in `linker_rules.py`), for metadata conventions that predate declared relations
   or are shared by many collectors:
   - `security_groups[]`, `nsg_id`, `vpc_config.SecurityGroupIds` → `ATTACHED_TO / PROTECTED_BY_SG`;
   - `subnet_id`, `vpc_config.SubnetIds` → subnet `CONTAINS / SUBNET_CONTAINS_INSTANCE`;
   - `raw_data.Role` or `role_arn` → `ASSUMES_ROLE / RUNS_ON` for functions and state machines,
     `REFERENCES` otherwise; `raw_data.IamInstanceProfile.Arn` → `ASSUMES_ROLE / RUNS_ON`;
   - `kms_key_id` → `REFERENCES / ENCRYPTED_BY_KMS`;
   - CloudFront `origins` → `REFERENCES / SERVES_TRAFFIC_TO` (bucket origins resolved through
     their `.s3` host; skipped when a typed relation already links the pair); `web_acl_id` →
     WAF `PROTECTS / PROTECTED_BY_WAF`;
   - route tables: each route's gateway / NAT / transit gateway / peering / ENI target →
     `ROUTE` (`NAT_TRANSLATED` or `TRANSIT_ROUTED`); associations → subnet `ATTACHED_TO`;
   - `attachments[].VpcId` → `ATTACHED_TO`; `attached_instance_id(s)`, `network_interface_id` →
     `ATTACHED_TO`;
   - peering connections → requester and accepter VPCs `PEERING / VPC_PEERED`;
   - Azure `network_interfaces` → NIC `ATTACHED_TO` VM;
   - GCP `parent_full_resource_name` → parent `CONTAINS`.
   Then the **SSO role rule** (`_link_sso_roles`): an Identity Center permission set with
   `provisioned_role_prefix` `MANAGES / OWNED_BY` every IAM role under
   `/aws-reserved/sso.amazonaws.com/` named `<prefix><16 hex characters>`.
3. **Generic references** (`_link_generic`, with `include_generic`, from
   `inventory.link_references`). Walks every string in the asset's metadata (depth 6), except
   `relations`, `aliases`, `assume_role_policy` and the self-ID keys. A string that looks like an
   identifier (`arn:…`, `/subscriptions/…`, a GCP full resource name, or an AWS short ID such as
   `vpc-…`, `sg-…`, `snap-…`) and resolves to another asset becomes `REFERENCES`, unless the pair
   is already linked in either direction. This catches relationships no rule knows about.

Deduplication: one edge per `(source, target, edge_type)` across all passes and seeded edges;
self-loops are dropped.

## 8. Azure

### 8.1 Collection paths

`AzureDeepInventoryCollector(credential, subscription_id, graph_client_factory=None,
use_resource_graph=True)`:

- **Resource Graph** (default, needs `azure-mgmt-resourcegraph`):
  `collect_subscription_graph(client, subscription_id, *, role_assignments=True,
  defender=True, errors=None)` runs four queries through `run_query()` (paging with skip tokens,
  throttling back-off): `resources` (every resource with full `properties`; must succeed),
  `resourcecontainers` (resource groups and the subscription), `authorizationresources` (role
  assignments, joined with role definitions for names), and `securityresources` (Defender for
  Cloud pricings). The last three are best-effort; failures land in `errors` and coverage.
  `collection_mode` becomes `"resource-graph"`.
- **SDK fallback** (Resource Graph unavailable or the `resources` query failed): the base
  `AzureCollector` per-service collectors, the network fabric fetchers (NICs, public IPs, load
  balancers, route tables, NAT gateways, private endpoints, application gateways, firewalls,
  disks, scale sets, disk encryption sets), an ARM `resources.list()` sweep
  (`discovered_via: "arm-sweep"`, no properties), resource groups and the subscription, all fed
  through the same `AzureAssetBuilder`. `collection_mode` becomes `"sdk"`.

### 8.2 AzureAssetBuilder and drafts

`AzureAssetBuilder(subscription_id, discovered_via="resource-graph")` turns ARM-shaped rows into
assets:

1. `add_row(row)` creates a `_Draft`: `id`, lower-cased ARM `type`, `name`, `props`
   (`properties`), `asset_type` (`asset_type_from_arm`: the catalog plus kind overrides such as
   function apps → `CLOUD_FUNCTION`), `region`, `account_id`, `tags`, and the base metadata
   (`resource_type`, `kind`, `sku`, `resource_group`, `collected_via`, `zones`, `plan`).
2. `_extract(draft)` runs the **common extractors** for every row, then the extractors
   registered for the draft's type.
3. `build()` resolves role assignments into `GRANTS_ACCESS / POLICY_ALLOWS_ACTION` relations on
   the principal (or an Entra placeholder), applies deferred relations, and emits assets
   (`properties` sanitised, relations de-duplicated, aliases unique).

`_Draft` API used by extractors:

| Member | Purpose |
|---|---|
| `d.row`, `d.props`, `d.type`, `d.id`, `d.name`, `d.region`, `d.account_id`, `d.tags` | The row and its parsed fields. |
| `d.md` | Metadata dictionary to fill. |
| `d.add(*relations)` | Add relations (`rel(...)` results); `None` and self-references are ignored. |
| `d.alias(*values)` | Add identifiers (host names, principal refs, workspace IDs). |
| `d.exposed` | Set `True` for internet exposure. |

Builder hooks: `b.register_principal(principal_id, draft)` (the draft owns this managed
identity), `b.note_principal(id, type)`, `b.register_kubelet(object_id, draft)` (AKS kubelet
identity, used to derive `AcrPull` image pulls), `b.defer(owner_id, relation)` (add a relation
to another draft after all rows are processed).

Common extractors (`registry._COMMON`): managed identity (system-assigned principal as alias,
user-assigned identities as `ASSUMES_ROLE / RUNS_ON`), `managedBy` (`MANAGES / OWNED_BY`, or the
attached VM for disks), parent containment (nested type → parent with `VPC_CONTAINS_SUBNET` /
`CLUSTER_CONTAINS_SERVICE`, else resource group, else subscription), private endpoint
connections, diagnostic workspace references (`LOGS_TO`). Helpers for extractors: `_set_exposure`
(public network access without a deny default action), `_network_rule_grants` (VNet and resource
instance rules → `GRANTS_ACCESS` with `network_rule`), `_keyvault_key_ref` (customer-managed keys
→ `ENCRYPTED_BY_KMS` to the vault host).

### 8.3 Registered ARM types

Extractors are registered with `@extractor("microsoft.<ns>/<type>", ...)` (lower case) in five
modules:

| Module | Area | ARM types |
|---|---|---|
| `azure_graph/compute.py` | virtual machines, scale sets, disks, disk encryption sets, AKS clusters and agent pools | `microsoft.compute/diskencryptionsets`, `microsoft.compute/disks`, `microsoft.compute/virtualmachines`, `microsoft.compute/virtualmachinescalesets`, `microsoft.containerservice/managedclusters`, `microsoft.containerservice/managedclusters/agentpools` |
| `azure_graph/network.py` | VNets, subnets, NSGs, NICs, public IPs, route tables, NAT gateways, private endpoints and link services, connections, firewall policies, private DNS links, flow logs | `microsoft.network/connections`, `microsoft.network/firewallpolicies`, `microsoft.network/natgateways`, `microsoft.network/networkinterfaces`, `microsoft.network/networksecuritygroups`, `microsoft.network/networkwatchers/flowlogs`, `microsoft.network/privatednszones/virtualnetworklinks`, `microsoft.network/privateendpoints`, `microsoft.network/privatelinkservices`, `microsoft.network/publicipaddresses`, `microsoft.network/routetables`, `microsoft.network/virtualnetworks`, `microsoft.network/virtualnetworks/subnets` |
| `azure_graph/edge.py` | load balancers, application gateways, Azure Firewall, VNet gateways, Bastion, Front Door and CDN endpoints, origins, custom domains, security policies | `microsoft.cdn/profiles/afdendpoints`, `microsoft.cdn/profiles/customdomains`, `microsoft.cdn/profiles/endpoints`, `microsoft.cdn/profiles/origingroups/origins`, `microsoft.cdn/profiles/securitypolicies`, `microsoft.network/applicationgateways`, `microsoft.network/azurefirewalls`, `microsoft.network/bastionhosts`, `microsoft.network/frontdoors`, `microsoft.network/loadbalancers`, `microsoft.network/virtualnetworkgateways` |
| `azure_graph/data_security.py` | Key Vault, storage, SQL and open-source databases, Cosmos DB, messaging, Event Grid, cognitive services, Redis, search, App Configuration, ML, Synapse, Data Factory, Databricks, Log Analytics, Application Insights, managed identities, backup vaults | `microsoft.appconfiguration/configurationstores`, `microsoft.cache/redis`, `microsoft.cognitiveservices/accounts`, `microsoft.databricks/workspaces`, `microsoft.datafactory/factories`, `microsoft.dataprotection/backupvaults`, `microsoft.dbformariadb/servers`, `microsoft.dbformysql/flexibleservers`, `microsoft.dbformysql/servers`, `microsoft.dbforpostgresql/flexibleservers`, `microsoft.dbforpostgresql/servers`, `microsoft.documentdb/databaseaccounts`, `microsoft.eventgrid/domains`, `microsoft.eventgrid/systemtopics`, `microsoft.eventgrid/systemtopics/eventsubscriptions`, `microsoft.eventgrid/topics`, `microsoft.eventgrid/topics/eventsubscriptions`, `microsoft.eventhub/namespaces`, `microsoft.insights/components`, `microsoft.keyvault/vaults`, `microsoft.machinelearningservices/workspaces`, `microsoft.managedidentity/userassignedidentities`, `microsoft.operationalinsights/workspaces`, `microsoft.recoveryservices/vaults`, `microsoft.search/searchservices`, `microsoft.servicebus/namespaces`, `microsoft.signalrservice/signalr`, `microsoft.sql/servers`, `microsoft.sql/servers/databases`, `microsoft.storage/storageaccounts`, `microsoft.synapse/workspaces` |
| `azure_graph/web_containers.py` | ACR, App Service sites / slots / plans / environments, Container Apps and jobs, managed environments, container instances, API Management | `microsoft.apimanagement/service`, `microsoft.app/containerapps`, `microsoft.app/jobs`, `microsoft.app/managedenvironments`, `microsoft.containerinstance/containergroups`, `microsoft.containerregistry/registries`, `microsoft.web/hostingenvironments`, `microsoft.web/serverfarms`, `microsoft.web/sites`, `microsoft.web/sites/slots` |

71 ARM types have dedicated extractors; every other type still gets the common extractors and a catalog classification.

Role assignments: one `GRANTS_ACCESS / POLICY_ALLOWS_ACTION` relation per assignment, from the
principal to the scope, with `role`, `role_definition_id`, `privileged` (Owner, Contributor,
User Access Administrator, `*Administrator`, `*Data Owner`), `principal_type`, `assignment_id`
and `condition`. Principals that are managed identities of collected resources resolve to those
resources; others become `entra:principal/<id>` placeholders. An AKS kubelet identity holding
`AcrPull` on a registry adds `USES_IMAGE / RUNS_ON` from the cluster to the registry.

Defender for Cloud: one `THREAT_DETECTOR` per plan, `security_service: "defender-<plan>"`,
`enabled` when the tier is Standard, `MONITORS` the subscription when enabled.

## 9. GCP

### 9.1 Collection

`GCPCollector(project_id, credentials=None, **options)` (`GCPCollectorOptions`:
`organization_id`, `scope`, `project_filter`, `skip_asset_types`, `page_size`, `include_iam`,
`client`, `coverage`, `timeout`, `link_locally`):

1. `ListAssets` with `content_type=RESOURCE` at the scope (`projects/<id>` or
   `organizations/<id>`), full resource JSON and ancestors, `skip_asset_types` filtered, blocking
   gRPC calls in worker threads with retries. At organization scope `project_filter` keeps only
   the listed projects (org- and folder-level resources are always kept).
2. If `ListAssets` is denied: `SearchAllResources` (summary fields only, `summary_only: true`),
   recorded `PARTIAL`.
3. Each record → `MappedRecord` → `extract(GCPContext)` → `build_cloud_asset()` (base metadata,
   extractor metadata / relations / aliases, the selfLink as alias, exposure entries).
4. Firewall evaluation (`apply_firewalls`): ingress rules matched to instances by network,
   target tags and target service accounts, priority order; rules open to the internet mark the
   instance exposed.
5. `_enrich()` (deep collector): `SearchAllIamPolicies` → `apply_iam_policies()`.
6. `collect_edges()`: `internet_edges()`, one edge per exposure entry.

`GCPDeepInventoryCollector` adds the deep type map (`gcp_asset_types.yaml` `deep` over `base`)
and IAM, and does not link locally: the mapper's linker does it for every provider at once.

### 9.2 The extraction framework (`gcp_relations/context.py`)

```python
@_extractor("compute.googleapis.com/Instance")
def _instance(ctx: GCPContext, out: Extracted) -> None: ...
```

`GCPContext`: `name` (full resource name), `asset_type`, `data` (resource JSON), `project_id`,
`project_number`, `location`, `ancestors`; `ctx.region` (a zone reduced to its region) and
`ctx.default_sa()` (the project's default compute service account).

`Extracted` methods:

| Method | Purpose |
|---|---|
| `out.add(target, edge, relationship=None, **kwargs)` | Declare a relation (`reverse`, `description`, properties as for `rel`); empty targets and repeats are dropped. |
| `out.sa(ref, ctx, description=None, **props)` | The asset runs as a service account (`"default"` → the default compute SA); `ASSUMES_ROLE / RUNS_ON` to `serviceAccount:<email>`. Returns the email. |
| `out.in_subnet(ref)` | Subnet (or network) `CONTAINS` the asset. |
| `out.alias(*values)` | Extra identifiers. |
| `out.expose(reason, protocol=None, ports=(), kind="INTERNET_EXPOSED")` | Mark internet exposure; becomes `exposure_reasons`, `internet_ingress` and an internet edge. |
| `out.metadata` | Metadata to merge. |

`extract(ctx)` runs the registered extractor (an exception is caught and recorded as
`extraction_error`), then the generic CMEK scan: every Cloud KMS key name anywhere in the JSON
becomes `kms_keys` and an `ENCRYPTED_BY_KMS` relation.

### 9.3 Name normalisation (`gcp_relations/names.py`)

GCP references come as compute selfLinks
(`https://www.googleapis.com/compute/v1/projects/p/...`), other API URLs, relative names
(`projects/p/locations/l/...`), short names and emails. `full_name(value, service=None)`
normalises all of them to the Cloud Asset Inventory form `//<service>.googleapis.com/<relative
name>`, which is what assets are indexed under; it returns `None` for values it cannot
normalise (and `rel()` / `Extracted.add()` drop empty targets, so a bad reference simply
declares nothing). Service accounts are referenced as `serviceAccount:<email>` (`sa_ref`), an alias of
every service account asset. `url_alias()` keeps only `scheme://host` of URLs, because paths and
queries can carry tokens.

### 9.4 Registered asset types

| Module | Area | Cloud Asset Inventory types |
|---|---|---|
| `gcp_relations/compute.py` | instances, disks, snapshots, images, templates, instance groups, autoscalers | `compute.googleapis.com/Autoscaler`, `compute.googleapis.com/Disk`, `compute.googleapis.com/Image`, `compute.googleapis.com/Instance`, `compute.googleapis.com/InstanceGroup`, `compute.googleapis.com/InstanceGroupManager`, `compute.googleapis.com/InstanceTemplate`, `compute.googleapis.com/MachineImage`, `compute.googleapis.com/RegionAutoscaler`, `compute.googleapis.com/RegionDisk`, `compute.googleapis.com/RegionInstanceGroup`, `compute.googleapis.com/RegionInstanceGroupManager`, `compute.googleapis.com/RegionInstanceTemplate`, `compute.googleapis.com/Snapshot` |
| `gcp_relations/network.py` | networks, subnets, firewalls and firewall policies, routes, routers / NAT, VPN, interconnect, PSC, addresses, Shared VPC, DNS, Serverless VPC Access, NCC, Managed Kafka | `compute.googleapis.com/Address`, `compute.googleapis.com/Firewall`, `compute.googleapis.com/FirewallPolicy`, `compute.googleapis.com/GlobalAddress`, `compute.googleapis.com/InterconnectAttachment`, `compute.googleapis.com/Network`, `compute.googleapis.com/NetworkFirewallPolicy`, `compute.googleapis.com/Project`, `compute.googleapis.com/RegionNetworkFirewallPolicy`, `compute.googleapis.com/Route`, `compute.googleapis.com/Router`, `compute.googleapis.com/ServiceAttachment`, `compute.googleapis.com/Subnetwork`, `compute.googleapis.com/TargetVpnGateway`, `compute.googleapis.com/VpnGateway`, `compute.googleapis.com/VpnTunnel`, `dns.googleapis.com/ManagedZone`, `dns.googleapis.com/Policy`, `dns.googleapis.com/ResponsePolicy`, `managedkafka.googleapis.com/Cluster`, `networkconnectivity.googleapis.com/Spoke`, `vpcaccess.googleapis.com/Connector` |
| `gcp_relations/load_balancing.py` | forwarding rules, target proxies, URL maps, backend services and buckets, target pools, NEGs, Cloud Armor, SSL certificates | `compute.googleapis.com/BackendBucket`, `compute.googleapis.com/BackendService`, `compute.googleapis.com/ForwardingRule`, `compute.googleapis.com/GlobalForwardingRule`, `compute.googleapis.com/GlobalNetworkEndpointGroup`, `compute.googleapis.com/NetworkEndpointGroup`, `compute.googleapis.com/RegionBackendService`, `compute.googleapis.com/RegionNetworkEndpointGroup`, `compute.googleapis.com/RegionSecurityPolicy`, `compute.googleapis.com/RegionSslCertificate`, `compute.googleapis.com/RegionTargetHttpProxy`, `compute.googleapis.com/RegionTargetHttpsProxy`, `compute.googleapis.com/RegionTargetTcpProxy`, `compute.googleapis.com/RegionUrlMap`, `compute.googleapis.com/SecurityPolicy`, `compute.googleapis.com/SslCertificate`, `compute.googleapis.com/TargetGrpcProxy`, `compute.googleapis.com/TargetHttpProxy`, `compute.googleapis.com/TargetHttpsProxy`, `compute.googleapis.com/TargetInstance`, `compute.googleapis.com/TargetPool`, `compute.googleapis.com/TargetSslProxy`, `compute.googleapis.com/TargetTcpProxy`, `compute.googleapis.com/UrlMap` |
| `gcp_relations/gke.py` | GKE clusters and node pools, Kubernetes workloads, services, ingresses, service accounts, RBAC bindings | `apps.k8s.io/DaemonSet`, `apps.k8s.io/Deployment`, `apps.k8s.io/StatefulSet`, `batch.k8s.io/CronJob`, `batch.k8s.io/Job`, `container.googleapis.com/Cluster`, `container.googleapis.com/NodePool`, `extensions.k8s.io/Ingress`, `k8s.io/Pod`, `k8s.io/Service`, `k8s.io/ServiceAccount`, `networking.k8s.io/Ingress`, `rbac.authorization.k8s.io/ClusterRoleBinding`, `rbac.authorization.k8s.io/RoleBinding` |
| `gcp_relations/serverless.py` | Cloud Run, Cloud Functions, App Engine, Workflows, Cloud Tasks, API Gateway, Eventarc | `apigateway.googleapis.com/Api`, `apigateway.googleapis.com/ApiConfig`, `apigateway.googleapis.com/Gateway`, `appengine.googleapis.com/Application`, `appengine.googleapis.com/Service`, `cloudfunctions.googleapis.com/CloudFunction`, `cloudfunctions.googleapis.com/Function`, `cloudtasks.googleapis.com/Queue`, `eventarc.googleapis.com/Trigger`, `run.googleapis.com/Job`, `run.googleapis.com/Service`, `workflows.googleapis.com/Workflow` |
| `gcp_relations/messaging.py` | Pub/Sub topics and subscriptions | `pubsub.googleapis.com/Subscription`, `pubsub.googleapis.com/Topic` |
| `gcp_relations/data_logging.py` | log sinks and buckets, Cloud SQL, Redis, Memcache, Filestore, AlloyDB, BigQuery, Cloud Storage, Cloud KMS keys, Secret Manager, Artifact Registry | `alloydb.googleapis.com/Cluster`, `alloydb.googleapis.com/Instance`, `artifactregistry.googleapis.com/Repository`, `bigquery.googleapis.com/Dataset`, `cloudkms.googleapis.com/CryptoKey`, `file.googleapis.com/Instance`, `logging.googleapis.com/LogBucket`, `logging.googleapis.com/LogSink`, `memcache.googleapis.com/Instance`, `redis.googleapis.com/Cluster`, `redis.googleapis.com/Instance`, `secretmanager.googleapis.com/Secret`, `sqladmin.googleapis.com/Instance`, `storage.googleapis.com/Bucket` |
| `gcp_relations/iam.py` | service accounts and keys, workload / workforce identity providers, custom roles, API keys | `apikeys.googleapis.com/Key`, `iam.googleapis.com/Role`, `iam.googleapis.com/ServiceAccount`, `iam.googleapis.com/ServiceAccountKey`, `iam.googleapis.com/WorkforcePoolProvider`, `iam.googleapis.com/WorkloadIdentityPoolProvider` |
| `gcp_relations/pipelines.py` | Composer, Dataproc, Dataflow, Vertex AI endpoints and models, notebooks, Cloud Build triggers, Cloud Deploy | `aiplatform.googleapis.com/Endpoint`, `aiplatform.googleapis.com/Model`, `cloudbuild.googleapis.com/BuildTrigger`, `clouddeploy.googleapis.com/DeliveryPipeline`, `clouddeploy.googleapis.com/Target`, `composer.googleapis.com/Environment`, `dataflow.googleapis.com/Job`, `dataproc.googleapis.com/Cluster`, `notebooks.googleapis.com/Instance`, `notebooks.googleapis.com/Runtime` |
| `gcp_relations/resource_manager.py` | organization, folders, projects, organization policies, VPC Service Controls perimeters | `accesscontextmanager.googleapis.com/ServicePerimeter`, `cloudresourcemanager.googleapis.com/Folder`, `cloudresourcemanager.googleapis.com/Organization`, `cloudresourcemanager.googleapis.com/Project`, `orgpolicy.googleapis.com/Policy` |

123 asset types have dedicated extractors; every other type still gets the generic CMEK scan, parent containment and a catalog classification.

### 9.5 IAM bindings and principals (`gcp_relations/iam.py`)

`apply_iam_policies(assets, policies)` turns each binding into relations on the principal:

- service accounts that were collected carry the relation themselves;
- other members become principal assets: `gcp-principal:<member>` (users, groups, domains,
  workforce / workload identity principals) or `k8s-gke://<pool project>/<ns>/<ksa>` for GKE
  Workload Identity, typed `IDENTITY_USER`, `IDENTITY_GROUP`, `SERVICE_PRINCIPAL` or
  `K8S_SERVICE_ACCOUNT`;
- roles that let the member act as a service account (token creator, service account user,
  workload identity user) become `ASSUMES_ROLE / ROLE_ASSUMES_ROLE`; everything else
  `GRANTS_ACCESS / POLICY_ALLOWS_ACTION` with the role;
- `allUsers` / `allAuthenticatedUsers` mark the resource internet-exposed and create no
  principal.

`merge_gcp_principals(assets, edges)` runs in the mapper after deduplication: per-project
placeholders created for a service account referenced before its project was seen are folded
into the real service-account asset, and edges are re-pointed.

## 10. Hierarchies beyond AWS

**Azure** (`discover_azure_hierarchy(credential, graph_client_factory=None, *,
include_policies=True, errors=None)`): one Resource Graph query over `resourcecontainers`
returns the management group tree and every subscription with its ancestor chain; one over
`policyresources` returns policy assignments and exemptions at every scope.

- Management groups: `ORG_UNIT`, `/providers/Microsoft.Management/managementGroups/<name>`,
  `is_tenant_root`, `landing_zone` when named after an Azure Landing Zones archetype.
- Subscriptions: `CLOUD_ACCOUNT`, `/subscriptions/<id>` (the same identifier the subscription
  collector uses, so they deduplicate), contained by their management group.
- Policy assignments and exemptions: `GUARDRAIL` that `GOVERNS / COMPLIANCE_GOVERNS` its scope.

**GCP** (`discover_gcp_hierarchy(credentials, organization_id, client=None, *, coverage=None,
org_policies=True, access_policies=True)`): the organization (`ORGANIZATION`), folders
(`ORG_UNIT`) and projects (`CLOUD_ACCOUNT`, aliases `projects/<number>`, `<number>`,
`projects/<id>`) with `CONTAINS`; organization policies as `ORG_POLICY` that `GOVERN` their
resource; VPC Service Controls perimeters as `GUARDRAIL` that `GOVERN` their member projects and
networks.

## 11. Post-processing

- **`deduplicate(assets, edges)`**: keyed on `arn`. The first copy is kept unless it came from a
  sweep / placeholder (`discovered_via`) and the new one did not, in which case they swap.
  `relations` and `aliases` are unioned onto the kept copy, `is_internet_exposed` is OR-ed, and
  edges are re-pointed to the kept copy. An edge is dropped only when it became a self-loop or an
  exact repeat of an earlier one: same endpoints, `edge_type`, `port_range`, `ports`,
  `protocol`, `cidr` and `direction`. Parallel security group, NACL and internet-exposure rules
  for different ports or protocols are kept. This is what merges an S3 bucket seen
  from every region, an account seen as an organization member and as a trust principal, or an
  Azure subscription seen by the hierarchy and by the subscription collector.
- **`add_account_hierarchy(assets, edges)`**: one `CLOUD_ACCOUNT` per `(provider, account_id)`,
  reusing an existing node with the canonical identifier (`arn:aws:iam::<id>:root`,
  `/subscriptions/<id>`, `//cloudresourcemanager.googleapis.com/projects/<id>`); every asset
  that nothing `CONTAINS` gets an account `CONTAINS / ACCOUNT_CONTAINS_REGION` edge with
  `properties.hierarchy: true`. Hierarchy-type assets are never contained this way.

## 12. Dependency analysis

`DependencyGraph` turns each edge into `dependent → dependency` with `DEPENDENCY_DIRECTION`
([reference table](INVENTORY_REFERENCE.md#6-edge-types-and-direction)). The rule of thumb: for
"uses" edges (references, attachment, routes, images, roles, logs, targets, grants, trust) the
source needs the target; for "acts on" edges (contains, invokes, protects, monitors, manages,
governs) the target needs the source. So a function needs its role, its image, its key, its log
group, and the queue that triggers it; an ALB needs the WAF protecting it; a resource needs the
stack managing it; an account needs the SCPs governing it.

- `depends_on(x)` walks upstream, `dependents(x)` downstream (the blast radius).
- Hierarchy containment is excluded by default (it says where, not what breaks).
- Security group rule, NACL rule and internet exposure edges carry no dependency meaning and
  are ignored.

This is an availability / change-impact view. Compromise propagation goes the other way along
identity edges (a compromised function exposes its role); for that, walk `IAM_TRUST`,
`ASSUMES_ROLE` and `GRANTS_ACCESS` edges directly, or use the attack path analysis of
`GraphBuilder`.

To change how an edge type participates, edit `DEPENDENCY_DIRECTION`; a new `EdgeType` without
an entry is ignored by dependency analysis until you add one.

## 13. Reference catalogs

Reference data lives in YAML under `cloudg/inventory/catalogs/`, loaded by
`load_catalog(name)` (cached per process):

| File | Keys | Used by |
|---|---|---|
| `aws_cloudcontrol.yaml` | `covered_types` (mapping of group → CloudFormation types a deep collector already covers), `global_prefixes` (types listed once per account), `asset_types` (CloudFormation type → AssetType), `sensitive_fields` (type → top-level properties to drop) | Cloud Control sweep |
| `aws_arn_types.yaml` | `arn_types` (`service:resource-type` or `service` → AssetType) | `asset_type_from_arn` (Tagging API and Cloud Control hits) |
| `azure_arm_types.yaml` | `arm_types` (lower-case ARM type → AssetType) | `asset_type_from_arm` |
| `gcp_asset_types.yaml` | `base` (standard collector), `deep` (inventory, overrides `base`) | GCP collectors |

Overlays: put a file with the same name in `$CLOUDG_CATALOG_DIR`; mappings merge key by key
(recursively), lists are extended without duplicates. AssetType names are validated by
`asset_type_map()` at import time, so a typo fails loudly with the catalog, key and value.
Because catalogs are read when the modules are imported, set `$CLOUDG_CATALOG_DIR` before
importing cloudg.

When you add a deep collector for a resource type that Cloud Control also lists, add the type
to `covered_types` so the sweep skips it.

## 14. Graph, ontology and viewer integration

- `GraphBuilder.build(assets, edges)` adds `account_id` to node attributes and `relationship` /
  `description` to edge attributes; endpoints that are not assets become `EXTERNAL` nodes. The
  graph keeps one edge per source and target: parallel `SECURITY_GROUP_RULE`, `NACL_RULE` and
  `INTERNET_EXPOSED` edges with the same `cidr` and `direction` are merged (ports and protocols
  become comma lists, descriptions are joined with `"; "`), and any other parallel edge replaces
  the earlier one. Graph exports therefore have fewer edges than the map
  ([reference](INVENTORY_REFERENCE.md#15-inventory-graphjson)).
- The ontology (`cloudg/graph/ontology.py`) creates OWL classes for every asset type
  automatically and uses an edge's declared `relationship` first. On `CONTAINS`, `ATTACHED_TO`
  and the typed edges (`INVOKES`, `REFERENCES`, `PROTECTS` and the rest) the declared relation
  replaces inference; on `SECURITY_GROUP_RULE`, `IAM_TRUST`, `IAM_POLICY_ATTACHMENT`,
  `LOAD_BALANCER_TARGET`, `ROUTE`, `PEERING` and `INTERNET_EXPOSED` edges the inferred relations
  are added after it. Inferred containment relations check both endpoint types (a
  `VPC_CONTAINS_SUBNET` needs a VPC or VNet and a subnet; anything that matches no specific
  relation is plain `CONTAINS`), and port relations come from the parsed port ranges
  (`cloudg.graph.ports`). New relationship values must therefore be
  `RelationType` names; add a new name to `ontology_rules.RelationType` (and its group) before
  using it.
- `docs/viewer.html` reads `inventory-graph.json`: node `type`, `account_id`, `is_external`
  and link `type` / `relationship` drive its colouring and filters.

## 15. Recipes

### 15.1 Add an AWS service collector

1. Pick the package by domain (`application`, `containers`, `data_ml`, `governance`,
   `network_ext`, `platform`, `security`, `serverless`) and add a module, or extend one that has
   room under the size limits ([17](#17-code-quality-constraints)).
2. Write a mixin with one `_collect_<task>` coroutine per task, built only from the helpers:

   ```python
   from cloudg.inventory.aws_services._base import AWSServiceMixin, gather_limited, rel
   from cloudg.schema.models import AssetType, CloudAsset, EdgeType


   class WidgetCollectorsMixin(AWSServiceMixin):
       async def _collect_widgets(self) -> list[CloudAsset]:
           assets: list[CloudAsset] = []
           async with self._client("widgets") as client:
               async for w in self._paginate(client, "list_widgets", "Widgets"):
                   assets.append(
                       self._asset(
                           arn=w["WidgetArn"],
                           name=w["Name"],
                           asset_type=AssetType.OTHER,
                           tags=w.get("Tags"),
                           metadata={"status": w.get("Status")},
                           relations=[
                               rel(
                                   w.get("RoleArn"),
                                   EdgeType.ASSUMES_ROLE,
                                   "RUNS_ON",
                                   description="widget role",
                               ),
                               rel(w.get("KmsKeyId"), EdgeType.REFERENCES, "ENCRYPTED_BY_KMS"),
                               rel(
                                   w.get("SourceQueueArn"),
                                   EdgeType.INVOKES,
                                   "TRIGGERED_BY",
                                   reverse=True,
                               ),
                           ],
                       )
                   )
           return assets
   ```

   Use `_pages()` when the operation has no paginator, `gather_limited()` for per-item describe
   calls, `_disabled_asset()` for security services that can be off.
3. Add the mixin to the package's composite mixin and register the task in the package registry:
   `"widgets": (self._collect_widgets, "<family>", <is_global>)`.
4. If Cloud Control lists the type, add it to `covered_types` in `aws_cloudcontrol.yaml`.
5. If the ARN shape is new, add it to `aws_arn_types.yaml`.
6. Test with moto when it supports the service, otherwise with a stubbed client
   ([18](#18-testing)). Assert on the asset and on the linked edge.
7. Add the task to the family table in DOCUMENTATION.md if it is user-visible.

### 15.2 Add a service family

Use the new family name in the registry entries; `SERVICE_FAMILIES` picks it up and
`--services <family>` works immediately. Document it in the family table.

### 15.3 Add an Azure extractor

```python
from cloudg.inventory.aws_services._base import rel
from cloudg.inventory.azure_graph.helpers import _get, _rid
from cloudg.inventory.azure_graph.registry import _Draft, _set_exposure, extractor
from cloudg.schema.models import EdgeType


@extractor("microsoft.widgets/widgets")
def _widget(d: _Draft, b) -> None:
    d.md["tier"] = _get(d.props, "tier")
    d.add(
        rel(
            _rid(_get(d.props, "subnet")),
            EdgeType.CONTAINS,
            "SUBNET_CONTAINS_INSTANCE",
            reverse=True,
        )
    )
    _set_exposure(d)
```

Put it in the module for its area (the module must be imported by `azure_graph/__init__.py`),
add the ARM type to `azure_arm_types.yaml`, and test it with a recorded Resource Graph row passed
through `build_assets(rows, subscription_id)`.

### 15.4 Add a GCP extractor

```python
from cloudg.inventory.gcp_relations.context import Extracted, GCPContext, _extractor
from cloudg.inventory.gcp_relations.names import full_name
from cloudg.schema.models import EdgeType


@_extractor("widgets.googleapis.com/Widget")
def _widget(ctx: GCPContext, out: Extracted) -> None:
    out.sa(ctx.data.get("serviceAccount"), ctx)
    out.add(full_name(ctx.data.get("network"), "compute"), EdgeType.ATTACHED_TO)
    if ctx.data.get("publicAccess"):
        out.expose("public widget endpoint", protocol="tcp", ports=["443"])
```

Add the type to `gcp_asset_types.yaml` (`deep`), and test with a recorded `list_assets` record.

### 15.5 Add an asset type

1. Add the value to `AssetType` in `cloudg/schema/models.py`, in the right section, with a
   comment naming the native resources it covers.
2. Map native types to it in the catalogs.
3. If it is a security service, give its assets `security_service` / `enabled`.
4. If it should be scanned or protected, review `security_coverage()`.
5. Regenerate [INVENTORY_CATALOG.md](INVENTORY_CATALOG.md) entries by hand or with the capture
   procedure in [18.4](#184-capturing-real-shapes).

### 15.6 Declare relations from your own collector or plugin

Any asset that reaches the linker can declare relations; no cloudg code change is needed:

```python
asset.metadata["relations"] = [
    {
        "target": "arn:aws:iam::123456789012:role/app",
        "edge": "ASSUMES_ROLE",
        "relationship": "RUNS_ON",
    },
    {"target": "sg-0123456789abcdef0", "edge": "ATTACHED_TO", "relationship": "PROTECTED_BY_SG"},
]
asset.metadata["aliases"] = ["my-internal-id-42"]
edges = RelationshipLinker(all_assets).link()
```

### 15.7 Extend the catalogs without code

```bash
export CLOUDG_CATALOG_DIR=/etc/cloudg/catalogs
cat > $CLOUDG_CATALOG_DIR/aws_cloudcontrol.yaml <<'EOF'
asset_types:
  AWS::MyCorp::Widget: OTHER
covered_types:
  internal:
    - AWS::MyCorp::Gadget
EOF
cloudg map -p aws --regions all
```

## 16. Security rules for collectors

These rules are enforced in review and by CodeQL; follow them in every collector:

1. **Never collect secret values.** Record names, ARNs and metadata, never values: no SSM
   parameter values, no environment variable values (`environment_keys` and `identifier_refs`
   only), no passwords, pre-shared keys, auth keys, webhook secrets, connection strings, user
   data. Cloud Control properties go through `redact()`.
2. **Never log secrets or secret names in a way that looks like one.** Log identifiers and error
   codes; do not interpolate values that came from secret-bearing fields.
3. **Strip credentials from URLs.** Use `_clean_url()` / `url_alias()`; repository URLs can
   embed tokens, and query strings can carry signatures.
4. **Judge URLs on the parsed host.** Use `urlsplit()` and an anchored, full-match regular
   expression on the host (as `_is_sqs_queue_url` and `_image_registry_host` do), never
   substring checks on the whole string.
5. **No regular expressions with nested quantifiers** on attacker-influenced input (resource
   names, tags, policy documents). Prefer splitting and parsing.
6. **Read-only calls only.** No `Create*`, `Put*`, `Update*`, `Delete*`, and in Kubernetes only
   `GET`.
7. **Do not widen permissions in docs or defaults.** Recommend read-only roles.

## 17. Code quality constraints

The repository is checked by Codacy and CodeQL on every pull request. Code that passes them:

| Limit | Value |
|---|---|
| Function length | at most 50 lines of code (NLOC) |
| Parameters per function | at most 8 (use an options dataclass or `**options` validated by a dataclass, as `AWSDeepInventoryCollector` and `GCPCollector` do) |
| File length | at most 500 lines of code; split a package module before it grows past it |
| Cyclomatic complexity | at most 15 per function (move branches into helpers or lookup tables) |
| Duplication | no cloned blocks; factor shared shapes into the package `_common.py` |
| Re-exports | names imported only to re-export must be listed in `__all__` |
| Hard-coded binds | no `0.0.0.0` literals in code (use a constant from an existing module) |
| Names | no variables or keyword arguments named like credentials (`token`, `password`) holding non-secrets; Bandit flags them |

Formatting and linting: `ruff format` and `ruff check` must be clean.

## 18. Testing

### 18.1 Layout

| File | Covers |
|---|---|
| `tests/test_inventory.py` | Mapper, linker, dependency analysis, exports, organization discovery (moto). |
| `tests/test_inventory_deep.py` | Deep AWS collectors: containers, serverless, security, identity, Kubernetes mapping. |
| `tests/test_aws_application.py`, `test_aws_data_ml.py`, `test_aws_governance.py`, `test_aws_network_ext.py` | The newer AWS packages, with moto or stubbed clients. |
| `tests/test_catalogs_cloudcontrol.py` | Catalog loading, overlays, Cloud Control selection and redaction. |
| `tests/test_azure_inventory.py` | Resource Graph rows → assets and relations, hierarchy, SDK fallback. |
| `tests/test_gcp_inventory.py` | Cloud Asset Inventory records → assets, extractors, IAM, firewall evaluation, hierarchy. |

### 18.2 moto and aiobotocore

`tests/conftest.py` has three autouse fixtures that make moto work with the async collectors:

- `patch_aiobotocore_for_moto` replaces aiobotocore's `convert_to_response_dict` with a version
  that accepts moto's synchronous response bodies;
- `skip_ddb_crc32_under_moto` disables DynamoDB's CRC32 response check, which awaits a
  synchronous body under moto;
- `isolate_cloudcontrol_cache` points `$CLOUDG_CACHE_DIR` at a temporary directory and resets
  the in-process Cloud Control type cache, so tests never read or write the user's cache.

A typical deep collector test:

```python
import asyncio

import boto3
from moto import mock_aws

from cloudg.inventory import AWSDeepInventoryCollector, RelationshipLinker


@mock_aws
def test_function_runs_as_role():
    iam = boto3.client("iam", region_name="us-east-1")
    role = iam.create_role(RoleName="r", AssumeRolePolicyDocument="{}")["Role"]
    ...  # create the function with that role
    collector = AWSDeepInventoryCollector(
        boto3.Session(region_name="us-east-1"),
        "us-east-1",
        "123456789012",
        tagging_sweep=False,
        services=["identity", "serverless"],
        cloud_control=False,
    )
    assets = asyncio.run(collector.collect())
    edges = RelationshipLinker(assets).link()
    ...  # assert on the ASSUMES_ROLE edge
```

Narrow `services` and disable `cloud_control` / `tagging_sweep` to keep tests fast and focused.
For services moto does not implement, patch `_client` with a stub that returns recorded
responses.

### 18.3 Azure and GCP

No live cloud is needed: Azure tests feed Resource Graph rows (dicts shaped like ARM resources)
into `build_assets()` or inject a `graph_client_factory`; GCP tests inject a fake
`AssetServiceClient` through the `client` option returning recorded `list_assets` /
`search_all_iam_policies` pages.

### 18.4 Capturing real shapes

[INVENTORY_CATALOG.md](INVENTORY_CATALOG.md) was produced by running the suite with a small
pytest plugin that wraps `CloudAsset.__init__` (recording type, provider, metadata keys and
value types, declared relations) and `RelationshipLinker._add` (recording the source type, edge
type, relationship and target type of each linked edge), plus an end-to-end map of a simulated
Organization. Rerun the same procedure after large collector changes to refresh the catalog.

### 18.5 Before opening a pull request

```bash
ruff format --check .
ruff check .
pytest -q
```

## 19. Public API and compatibility

Kept stable across 0.6.x (breaking them needs a minor version bump and a changelog entry):

- `cloudg.inventory` exports and their constructor signatures:
  `AWSDeepInventoryCollector(session, region="us-east-1", account_id=None, tagging_sweep=True, **options)`,
  `AzureDeepInventoryCollector(credential, subscription_id, graph_client_factory=None, use_resource_graph=True)`,
  `GCPDeepInventoryCollector(project_id, credentials=None, **options)`,
  `InventoryMapper(config, tagging_sweep=None)`, `RelationshipLinker(assets, materialize_external=True)`,
  `DependencyGraph(assets, edges, include_hierarchy=False)`,
  `discover_organization(session, control_tower=True, home_region=None)`.
- `InventoryResult` fields, methods and the exported file formats
  ([reference](INVENTORY_REFERENCE.md#22-stability-and-compatibility)).
- Module paths that were split keep re-exporting the old names (for example
  `cloudg.inventory.mapper` re-exports `InventoryResult`, `cloudg.inventory.linker` re-exports
  `IdentifierIndex`, `cloudg.inventory.aws_deep` re-exports the task catalog), declared in each
  module's `__all__`.
- Options are validated: unknown keyword options raise `TypeError` rather than being ignored.

Internal (may change without notice): anything prefixed with `_`, the per-package module
layout under `aws_services/`, `azure_graph/` and `gcp_relations/`, and the exact metadata keys of
each asset type.
