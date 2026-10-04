# cloudg inventory catalog

Per-asset-type reference for the inventory map: what every `asset_type` means, which providers
produce it, the metadata keys it carries, the relations its collectors declare, and the edges
the linker produces from and to it. Companion to [INVENTORY_REFERENCE.md](INVENTORY_REFERENCE.md)
(structures of every output) and [INVENTORY_INTERNALS.md](INVENTORY_INTERNALS.md) (how it works).

> **How this catalog was built.** The metadata keys, value types, declared relations and edge
> patterns below were recorded from real collector output: every `CloudAsset` and every linked
> edge created while the full test suite ran (moto-backed AWS, recorded Azure Resource Graph rows,
> recorded GCP Cloud Asset Inventory responses) plus an end-to-end map of a simulated multi-account
> AWS Organization. It is therefore a description of observed shapes, not an exhaustive schema:
> a collector can add a key that a fixture never triggered (for example a field only set when an
> optional feature is enabled), and keys whose value was `None` in every observation show type
> `null`. Types listed as *not exercised* exist in the taxonomy and are produced by collectors or
> catalogs, but no fixture created one.

Value types: `str`, `int`, `float`, `bool`, `null`, `list`, `object` (a JSON object). A key with
several types (`null | str`) was observed with each.

## Contents

1. [Common metadata keys](#common-metadata-keys)
2. [Asset types by category](#asset-types-by-category)
3. [Per-type reference](#per-type-reference)
4. [Relationship matrix](#relationship-matrix)
5. [Relationship vocabulary](#relationship-vocabulary)

## Common metadata keys

Keys that mean the same thing on every asset type that carries them.

| Key | Type | Meaning |
|---|---|---|
| `relations` | `list[object]` | Relationships the collector declared; resolved into edges by the linker. Each entry is a relation object (see INVENTORY_REFERENCE.md, *Relation object*). Kept on the asset after linking, so the map records what was declared even when the target never resolved. |
| `aliases` | `list[str]` | Extra identifiers other services use for this asset (short IDs, names, endpoints, image repositories, `aws-security:` / `azure-security:` keys, Entra principal refs, `serviceAccount:` emails, selfLinks). Every alias is registered in the linker's identifier index. |
| `discovered_via` | `str` | How a non-collector asset was found; absent on assets built by a dedicated collector. Breadth sweeps: `tagging-api`, `cloud-control`, `arm-sweep`. Placeholders built from a reference: `cross-account reference` (external account), `entra-principal-reference` (Entra principal), `iam_policy` and `workload_reference` (GCP principals), `eks-pod-identity` (role named by an EKS Pod Identity association), `ecs container instances` (EC2 instances seen as ECS container instances), `ram-incoming` (resource shared into the account through RAM). Scope nodes: `azure-subscription`, `collection scope` (GCP project / folder the listing ran at), `configured organization_id` (GCP organization node). In deduplication a copy without `discovered_via` always wins. |
| `collected_via` | `str` | Azure: `resource-graph` or `sdk`, the collection path that produced the asset. |
| `security_service` | `str` | Security service name (AWS: `guardduty`, `securityhub`, `inspector2`, `macie`, `config`, `accessanalyzer`, `detective`, `wafv2`, `network-firewall`, `shield`, `cloudtrail`; Azure: `defender-<plan>`). Present on security-service assets and their not-enabled placeholders; feeds `security_coverage`. |
| `enabled` | `bool` | With `security_service`: whether the service runs in this account and region. `false` marks a coverage gap (counted in `summary.security_service_gaps`). |
| `status` | `str` | Native lifecycle or status value of the resource (`ACTIVE`, `available`, `Enabled`, ...); on not-enabled placeholders the reason (`not enabled`). |
| `external` | `bool` | On `CLOUD_ACCOUNT`: `true` for accounts, subscriptions or projects that were referenced but not mapped; `false` for mapped ones. |
| `placeholder` | `bool` | `true` on identity nodes synthesised from a reference (Entra principals, GCP per-project service-account placeholders). Real assets win over placeholders during resolution. |
| `account_id` | `str` | On `CLOUD_ACCOUNT`: the account / subscription / project ID (also indexed as an identifier). |
| `properties` | `object` | Azure: the resource's ARM `properties`, sanitised. AWS Cloud Control: the resource model with secret-bearing fields redacted. |
| `resource_type` | `str` | Native type string: ARM type for Azure, CloudFormation type for Cloud Control hits. |
| `gcp_asset_type` | `str` | GCP: Cloud Asset Inventory asset type (`compute.googleapis.com/Instance`). |
| `project, project_id, project_number, folders, organization, location` | `str / list` | GCP: owning project, ancestor folders, organization and location from Cloud Asset Inventory. |
| `parent_full_resource_name` | `str` | GCP: parent resource; the linker adds a parent `CONTAINS` edge. |
| `kms_keys` | `list[str]` | GCP: every Cloud KMS key referenced anywhere in the resource (CMEK); each becomes an `ENCRYPTED_BY_KMS` relation. |
| `exposure_reasons, internet_ingress` | `list` | GCP: why the asset is internet-exposed (`firewall`, `allUsers`, external IP, ...) and the ingress entries (`via`, `kind`, `protocol`, `ports`) behind the `INTERNET_EXPOSED` edges. |
| `security_groups` | `list[str]` | AWS: attached security groups; the linker adds `ATTACHED_TO` / `PROTECTED_BY_SG` edges. |
| `subnet_id, subnets, vpc_id, vpc_config` | `str / list / object` | AWS placement. `subnet_id` adds a `SUBNET_CONTAINS_INSTANCE` edge; `vpc_config` (`SubnetIds`, `SecurityGroupIds`) adds subnet containment and SG attachment. |
| `kms_key_id` | `str` | AWS: KMS key reference; the linker adds `REFERENCES / ENCRYPTED_BY_KMS`. |
| `role_arn` | `str` | AWS: execution / service role; `ASSUMES_ROLE / RUNS_ON` for Lambda and Step Functions, `REFERENCES` otherwise. |
| `web_acl_id` | `str` | AWS: WAF web ACL; the linker adds `PROTECTS / PROTECTED_BY_WAF` from the ACL. |
| `origins` | `list[str]` | CloudFront origins; resolved to buckets / load balancers as `SERVES_TRAFFIC_TO` unless a typed relation already links the pair. |
| `attached_instance_id, attached_instance_ids, network_interface_id` | `str / list` | AWS attachment of volumes, ENIs and Elastic IPs; `ATTACHED_TO` edges. |
| `provisioned_role_prefix` | `str` | IAM Identity Center permission set: prefix of the `AWSReservedSSO_<name>_<hash>` roles it creates; drives the SSO `MANAGES / OWNED_BY` rule. |
| `cluster_arn, namespace, kind` | `str` | Kubernetes objects mapped from EKS: owning cluster, namespace and object kind. |
| `environment_keys` | `list[str]` | Names of environment variables only. Values are never collected. |
| `extraction_error` | `str` | GCP: an extractor raised on this resource; the asset is kept with its base metadata. |
| `summary_only` | `bool` | GCP: built from a `searchAllResources` summary rather than the full resource JSON. |

## Asset types by category

`AssetType` has 156 values. The category is the section of `cloudg/schema/models.py` the value is defined in.

| Category | Types |
|---|---|
| Compute | [`EC2`](#ec2), [`VIRTUAL_MACHINE`](#virtual_machine), [`GCE_INSTANCE`](#gce_instance), [`LAMBDA_FUNCTION`](#lambda_function), [`CLOUD_FUNCTION`](#cloud_function), [`ECS_CLUSTER`](#ecs_cluster), [`EKS_CLUSTER`](#eks_cluster), [`AKS_CLUSTER`](#aks_cluster), [`GKE_CLUSTER`](#gke_cluster), [`APP_SERVICE`](#app_service) |
| Networking | [`VPC`](#vpc), [`VNET`](#vnet), [`SUBNET`](#subnet), [`SECURITY_GROUP`](#security_group), [`NSG`](#nsg), [`NACL`](#nacl), [`ROUTE_TABLE`](#route_table), [`INTERNET_GATEWAY`](#internet_gateway), [`NAT_GATEWAY`](#nat_gateway), [`LOAD_BALANCER`](#load_balancer), [`CLOUDFRONT`](#cloudfront), [`CDN`](#cdn), [`TRANSIT_GATEWAY`](#transit_gateway), [`PEERING_CONNECTION`](#peering_connection), [`ELASTIC_IP`](#elastic_ip), [`NETWORK_INTERFACE`](#network_interface) |
| Storage | [`S3_BUCKET`](#s3_bucket), [`BLOB_STORAGE`](#blob_storage), [`GCS_BUCKET`](#gcs_bucket), [`EBS_VOLUME`](#ebs_volume), [`ACCESS_POINT`](#access_point) |
| Database | [`RDS_INSTANCE`](#rds_instance), [`AURORA_CLUSTER`](#aurora_cluster), [`AZURE_SQL`](#azure_sql), [`CLOUD_SQL`](#cloud_sql), [`DYNAMODB_TABLE`](#dynamodb_table) |
| IAM | [`IAM_USER`](#iam_user), [`IAM_ROLE`](#iam_role), [`IAM_POLICY`](#iam_policy), [`IAM_GROUP`](#iam_group), [`SERVICE_PRINCIPAL`](#service_principal) |
| Secrets / Keys | [`KMS_KEY`](#kms_key), [`SECRET`](#secret), [`CERTIFICATE`](#certificate), [`KEY_VAULT`](#key_vault) |
| Logging | [`CLOUDTRAIL`](#cloudtrail), [`FLOW_LOG`](#flow_log), [`LOG_GROUP`](#log_group) |
| Containers / Kubernetes | [`CONTAINER_REGISTRY`](#container_registry), [`CONTAINER_SERVICE`](#container_service), [`TASK_DEFINITION`](#task_definition), [`NODE_GROUP`](#node_group), [`FARGATE_PROFILE`](#fargate_profile), [`CLUSTER_ADDON`](#cluster_addon), [`K8S_NAMESPACE`](#k8s_namespace), [`K8S_WORKLOAD`](#k8s_workload), [`K8S_SERVICE`](#k8s_service), [`K8S_INGRESS`](#k8s_ingress), [`K8S_SERVICE_ACCOUNT`](#k8s_service_account) |
| Compute fabric | [`AUTOSCALING_GROUP`](#autoscaling_group), [`LAUNCH_TEMPLATE`](#launch_template), [`TARGET_GROUP`](#target_group), [`API_GATEWAY`](#api_gateway), [`VPC_ENDPOINT`](#vpc_endpoint), [`INSTANCE_PROFILE`](#instance_profile), [`IDENTITY_PROVIDER`](#identity_provider) |
| Integration / messaging | [`MESSAGE_QUEUE`](#message_queue), [`NOTIFICATION_TOPIC`](#notification_topic), [`EVENT_BUS`](#event_bus), [`EVENT_RULE`](#event_rule), [`STATE_MACHINE`](#state_machine), [`DATA_STREAM`](#data_stream) |
| Data services | [`CACHE_CLUSTER`](#cache_cluster), [`SEARCH_DOMAIN`](#search_domain), [`DATA_WAREHOUSE`](#data_warehouse), [`FILE_SYSTEM`](#file_system) |
| DNS / deployment | [`DNS_ZONE`](#dns_zone), [`DNS_RECORD`](#dns_record), [`IAC_STACK`](#iac_stack) |
| Security services and scanners | [`WAF_WEB_ACL`](#waf_web_acl), [`NETWORK_FIREWALL`](#network_firewall), [`DDOS_PROTECTION`](#ddos_protection), [`THREAT_DETECTOR`](#threat_detector), [`SECURITY_HUB`](#security_hub), [`VULNERABILITY_SCANNER`](#vulnerability_scanner), [`DATA_SECURITY_SCANNER`](#data_security_scanner), [`CONFIG_RECORDER`](#config_recorder), [`ACCESS_ANALYZER`](#access_analyzer) |
| Organization / governance | [`ORGANIZATION`](#organization), [`ORG_UNIT`](#org_unit), [`CLOUD_ACCOUNT`](#cloud_account), [`ORG_POLICY`](#org_policy), [`LANDING_ZONE`](#landing_zone), [`GUARDRAIL`](#guardrail), [`RESOURCE_GROUP`](#resource_group) |
| Identity federation and access | [`PERMISSION_SET`](#permission_set), [`IDENTITY_USER`](#identity_user), [`IDENTITY_GROUP`](#identity_group), [`ACCESS_KEY`](#access_key), [`USER_POOL`](#user_pool), [`IDENTITY_POOL`](#identity_pool), [`RESOURCE_SHARE`](#resource_share) |
| Deployment / provisioning | [`STACK_SET`](#stack_set), [`PROVISIONED_PRODUCT`](#provisioned_product), [`PRODUCT_PORTFOLIO`](#product_portfolio), [`CI_PIPELINE`](#ci_pipeline), [`BUILD_PROJECT`](#build_project), [`DEPLOYMENT_GROUP`](#deployment_group) |
| Images, snapshots, backups | [`MACHINE_IMAGE`](#machine_image), [`SNAPSHOT`](#snapshot), [`BACKUP_PLAN`](#backup_plan), [`BACKUP_VAULT`](#backup_vault) |
| Hybrid and edge networking | [`VPN_CONNECTION`](#vpn_connection), [`VPN_GATEWAY`](#vpn_gateway), [`CUSTOMER_GATEWAY`](#customer_gateway), [`DIRECT_CONNECT`](#direct_connect), [`ROUTER`](#router), [`PREFIX_LIST`](#prefix_list), [`ENDPOINT_SERVICE`](#endpoint_service), [`VPC_LINK`](#vpc_link), [`CUSTOM_DOMAIN`](#custom_domain), [`DNS_RESOLVER`](#dns_resolver), [`GLOBAL_ACCELERATOR`](#global_accelerator), [`SERVICE_NETWORK`](#service_network) |
| Application integration and operations | [`SCHEDULE`](#schedule), [`EVENT_PIPE`](#event_pipe), [`API_DESTINATION`](#api_destination), [`ALARM`](#alarm), [`DELIVERY_STREAM`](#delivery_stream), [`LOG_SINK`](#log_sink), [`PARAMETER`](#parameter), [`CAPACITY_PROVIDER`](#capacity_provider), [`SERVICE_REGISTRY`](#service_registry), [`EVENT_ARCHIVE`](#event_archive), [`RUNBOOK`](#runbook), [`SOURCE_CONNECTION`](#source_connection), [`LB_LISTENER`](#lb_listener), [`AUTHORIZER`](#authorizer), [`EDGE_FUNCTION`](#edge_function) |
| Platforms and data processing | [`MESSAGE_BROKER`](#message_broker), [`BATCH_ENVIRONMENT`](#batch_environment), [`JOB_QUEUE`](#job_queue), [`JOB_DEFINITION`](#job_definition), [`DATABASE_PROXY`](#database_proxy), [`DATA_CATALOG`](#data_catalog), [`ETL_JOB`](#etl_job), [`BIG_DATA_CLUSTER`](#big_data_cluster), [`QUERY_WORKGROUP`](#query_workgroup), [`DATA_TRANSFER`](#data_transfer), [`ML_WORKSPACE`](#ml_workspace), [`ML_ENDPOINT`](#ml_endpoint), [`ML_MODEL`](#ml_model), [`AI_AGENT`](#ai_agent), [`KNOWLEDGE_BASE`](#knowledge_base), [`AI_GUARDRAIL`](#ai_guardrail) |
| Generic | [`OTHER`](#other) |

## Per-type reference

For each type: what it represents, the providers that produced it in the observations, the
metadata keys (beyond `relations` and `aliases`), the relations its collectors declare
(`edge` / `relationship`, ← for `reverse: true`), and the linked edges observed leaving and
entering it. Edge lists read `edge / relationship → other type` (outgoing) or
`edge / relationship ← other type` (incoming).

### Compute

#### EC2

Catalog entries that classify native resources as this type:

- AWS ARN: `ec2:instance`

- **Providers:** AWS
- **Also discovered via:** `tagging-api`
- **Can be internet-exposed:** yes (`is_internet_exposed` observed `true`)
- **Metadata keys:** `discovered_via` (str), `image_id` (str), `instance_type` (str), `private_ip` (str), `public_ip` (null \| str), `security_groups` (list), `service` (str), `state` (str), `subnet_id` (str), `vpc_id` (str)
- **Edges out:**<br>`ATTACHED_TO` / `PROTECTED_BY_SG` → `SECURITY_GROUP`<br>`REFERENCES` → `VPC`
- **Edges in:**<br>`ATTACHED_TO` ← `EBS_VOLUME`, `NETWORK_INTERFACE`<br>`CONTAINS` ← `ECS_CLUSTER`<br>`CONTAINS` / `SUBNET_CONTAINS_INSTANCE` ← `SUBNET`<br>`LOAD_BALANCER_TARGET` / `LB_TARGETS_INSTANCE` ← `TARGET_GROUP`<br>`MANAGES` ← `APP_SERVICE`, `OTHER`<br>`MANAGES` / `SCHEDULED_BY` ← `SCHEDULE`

#### VIRTUAL_MACHINE

Catalog entries that classify native resources as this type:

- Azure ARM: `microsoft.compute/virtualmachines`, `microsoft.hybridcompute/machines`

- **Providers:** AWS, AZURE
- **Metadata keys:** `activation_id` (null), `agent_version` (null), `collected_via` (str), `computer_name` (null \| str), `hybrid` (bool), `identity` (object), `instance_id` (str), `kind` (null), `network_interfaces` (list), `os_type` (str), `ping_status` (str), `platform_name` (null), `platform_type` (str), `platform_version` (null), `power_state` (null), `private_ip` (str), `properties` (object), `provisioning_state` (null), `resource_group` (str), `resource_type` (null \| str), `service` (str), `sku` (null), `source_id` (null), `source_type` (null), `vm_size` (str)
- **Carries `aliases`:** yes
- **Declared relations:** `ASSUMES_ROLE` / `RUNS_ON`, `ATTACHED_TO` ←, `CONTAINS` ←
- **Edges out:**<br>`ASSUMES_ROLE` / `RUNS_ON` → `IAM_ROLE`<br>`GRANTS_ACCESS` / `POLICY_ALLOWS_ACTION` → `KEY_VAULT`
- **Edges in:**<br>`ATTACHED_TO` ← `EBS_VOLUME`, `NETWORK_INTERFACE`<br>`CONTAINS` ← `RESOURCE_GROUP`<br>`MANAGES` ← `OTHER`

#### GCE_INSTANCE

Catalog entries that classify native resources as this type:

- GCP Cloud Asset Inventory: `compute.googleapis.com/Instance`

- **Providers:** GCP
- **Metadata keys:** `can_ip_forward` (bool), `confidential_compute` (bool), `create_time` (null), `deletion_protection` (bool), `description` (null \| str), `folders` (list), `gcp_asset_type` (str), `location` (str), `metadata_keys` (list), `network_tags` (list), `networks` (list), `organization` (null \| str), `parent_asset_type` (null \| str), `parent_full_resource_name` (null \| str), `private_ips` (list), `project` (str), `project_id` (str), `project_number` (str), `public_ips` (list), `service_account_emails` (list), `shielded_vm` (object), `state` (str), `summary_only` (bool)
- **Carries `aliases`:** yes
- **Declared relations:** `ASSUMES_ROLE` / `RUNS_ON`, `ATTACHED_TO` ←, `CONTAINS` / `SUBNET_CONTAINS_INSTANCE` ←
- **Edges out:**<br>`ASSUMES_ROLE` / `RUNS_ON` → `SERVICE_PRINCIPAL`<br>`ATTACHED_TO` / `PROTECTED_BY_SG` → `SECURITY_GROUP`<br>`REFERENCES` → `VPC`
- **Edges in:**<br>`ATTACHED_TO` ← `EBS_VOLUME`<br>`CONTAINS` ← `CLOUD_ACCOUNT`<br>`CONTAINS` / `SUBNET_CONTAINS_INSTANCE` ← `SUBNET`

#### LAMBDA_FUNCTION

Catalog entries that classify native resources as this type:

- AWS ARN: `lambda:function`

- **Providers:** AWS
- **Metadata keys:** `alias` (bool), `alias_name` (str), `architectures` (list), `description` (str), `environment_keys` (list), `event_sources` (list), `function_arn` (str), `function_name` (str), `function_url` (null), `function_url_auth` (null), `function_version` (str), `handler` (str), `image_uri` (null), `last_modified` (str), `layers` (list), `memory_size` (int), `package_type` (str), `policy_allows_public` (bool), `role_arn` (str), `routing_weights` (object), `runtime` (str), `timeout` (int), `tracing` (str), `versions` (list), `vpc_config` (null)
- **Carries `aliases`:** yes
- **Declared relations:** `ASSUMES_ROLE` / `RUNS_ON`, `INVOKES` ←, `INVOKES` / `TRIGGERED_BY` ←, `LOGS_TO` / `LOGS_TO`, `REFERENCES`, `REFERENCES` / `DEPENDS_ON`
- **Edges out:**<br>`ASSUMES_ROLE` / `RUNS_ON` → `IAM_ROLE`<br>`LOGS_TO` / `LOGS_TO` → `LOG_GROUP`<br>`REFERENCES` / `DEPENDS_ON` → `LAMBDA_FUNCTION`, `MESSAGE_QUEUE`
- **Edges in:**<br>`INVOKES` ← `DYNAMODB_TABLE`, `EVENT_RULE`, `MESSAGE_QUEUE`<br>`INVOKES` / `INVOKES` ← `AUTHORIZER`, `EVENT_PIPE`, `EVENT_RULE`, `S3_BUCKET`, `SCHEDULE`, `USER_POOL`<br>`INVOKES` / `ROTATES_SECRET` ← `SECRET`<br>`INVOKES` / `STREAMS_TO` ← `LOG_SINK`<br>`INVOKES` / `TRIGGERED_BY` ← `MESSAGE_QUEUE`, `NOTIFICATION_TOPIC`<br>`MONITORS` / `MONITORED_BY` ← `ALARM`<br>`REFERENCES` / `DEPENDS_ON` ← `LAMBDA_FUNCTION`

#### CLOUD_FUNCTION

Catalog entries that classify native resources as this type:

- Azure ARM: `microsoft.web/sites/functions`
- GCP Cloud Asset Inventory: `cloudfunctions.googleapis.com/CloudFunction`, `cloudfunctions.googleapis.com/Function`

- **Providers:** AZURE
- **Also discovered via:** `arm-sweep`
- **Can be internet-exposed:** yes (`is_internet_exposed` observed `true`)
- **Metadata keys:** `collected_via` (str), `default_host_name` (null \| str), `discovered_via` (str), `https_only` (null), `identity` (object), `kind` (str), `properties` (object), `public_network_access` (null), `resource_group` (str), `resource_type` (str), `role` (str), `sku` (null), `state` (null), `vnet_integration_subnet` (null)
- **Carries `aliases`:** yes
- **Declared relations:** `CONTAINS` ←, `CONTAINS` / `CLUSTER_CONTAINS_SERVICE` ←
- **Edges in:**<br>`CONTAINS` ← `RESOURCE_GROUP`<br>`CONTAINS` / `CLUSTER_CONTAINS_SERVICE` ← `APP_SERVICE`

#### ECS_CLUSTER

Catalog entries that classify native resources as this type:

- AWS ARN: `ecs:cluster`
- Azure ARM: `microsoft.app/managedenvironments`

- **Providers:** AWS
- **Also discovered via:** `ecs container instances`
- **Metadata keys:** `active_services` (int), `capacity_providers` (list), `container_insights` (bool), `container_instance_ids` (list), `container_instances` (int), `discovered_via` (str), `pending_tasks` (int), `running_tasks` (int), `standalone_task_definitions` (list), `status` (str)
- **Carries `aliases`:** yes
- **Declared relations:** `CONTAINS`
- **Edges out:**<br>`CONTAINS` → `EC2`<br>`CONTAINS` / `CLUSTER_CONTAINS_SERVICE` → `CONTAINER_SERVICE`<br>`REFERENCES` / `SCALES_WITH` → `CAPACITY_PROVIDER`

#### EKS_CLUSTER

Catalog entries that classify native resources as this type:

- AWS ARN: `eks:cluster`

- **Providers:** AWS
- **Metadata keys:** `access_entries` (list), `authentication_mode` (null), `endpoint` (str), `endpoint_private_access` (bool), `endpoint_public_access` (bool), `logging_enabled` (list), `oidc_issuer` (str), `platform_version` (str), `public_access_cidrs` (list), `secrets_encrypted` (bool), `security_groups` (list), `status` (str), `subnets` (list), `version` (str), `vpc_id` (null)
- **Declared relations:** `ASSUMES_ROLE` / `RUNS_ON`, `CONTAINS` / `SUBNET_CONTAINS_INSTANCE` ←, `REFERENCES` / `DEPENDS_ON`
- **Edges out:**<br>`ASSUMES_ROLE` / `RUNS_ON` → `IAM_ROLE`<br>`ATTACHED_TO` / `PROTECTED_BY_SG` → `SECURITY_GROUP`<br>`CONTAINS` / `CLUSTER_CONTAINS_SERVICE` → `FARGATE_PROFILE`, `K8S_NAMESPACE`, `NODE_GROUP`
- **Edges in:**<br>`CONTAINS` / `SUBNET_CONTAINS_INSTANCE` ← `SUBNET`

#### AKS_CLUSTER

Catalog entries that classify native resources as this type:

- Azure ARM: `microsoft.containerservice/managedclusters`

- **Providers:** AZURE
- **Can be internet-exposed:** yes (`is_internet_exposed` observed `true`)
- **Metadata keys:** `aad_managed` (null), `api_server_authorized_ip_ranges` (list), `azure_rbac` (null), `collected_via` (str), `fqdn` (str), `identity` (object), `kind` (null), `kubelet_identity` (object), `kubernetes_version` (str), `local_accounts_disabled` (null), `network_plugin` (null), `network_policy` (null), `node_resource_group` (str), `outbound_type` (null), `private_cluster` (bool), `private_fqdn` (null), `properties` (object), `rbac_enabled` (null), `resource_group` (str), `resource_type` (str), `sku` (null)
- **Carries `aliases`:** yes
- **Declared relations:** `ASSUMES_ROLE` / `RUNS_ON`, `CONTAINS` ←, `LOGS_TO` / `LOGS_TO`, `MANAGES` / `OWNED_BY`, `USES_IMAGE` / `RUNS_ON`
- **Edges out:**<br>`ASSUMES_ROLE` / `RUNS_ON` → `SERVICE_PRINCIPAL`<br>`CONTAINS` / `CLUSTER_CONTAINS_SERVICE` → `NODE_GROUP`<br>`LOGS_TO` / `LOGS_TO` → `LOG_GROUP`<br>`MANAGES` / `OWNED_BY` → `RESOURCE_GROUP`<br>`REFERENCES` → `SUBNET`<br>`USES_IMAGE` / `RUNS_ON` → `CONTAINER_REGISTRY`
- **Edges in:**<br>`CONTAINS` ← `RESOURCE_GROUP`

#### GKE_CLUSTER

Catalog entries that classify native resources as this type:

- GCP Cloud Asset Inventory: `container.googleapis.com/Cluster`

- **Providers:** GCP
- **Metadata keys:** `autopilot` (bool), `create_time` (null), `description` (null), `folders` (list), `gcp_asset_type` (str), `kms_keys` (list), `legacy_abac` (bool), `location` (str), `master_authorized_networks` (list), `master_authorized_networks_enabled` (bool), `network` (str), `network_policy` (bool), `network_tags` (list), `organization` (str), `parent_asset_type` (null), `parent_full_resource_name` (str), `private_nodes` (bool), `project` (str), `project_id` (str), `project_number` (str), `public_endpoint` (bool), `secrets_encryption` (str), `shielded_nodes` (bool), `state` (null), `subnetwork` (str), `workload_pool` (str)
- **Carries `aliases`:** yes
- **Declared relations:** `ASSUMES_ROLE` / `RUNS_ON`, `CONTAINS` / `SUBNET_CONTAINS_INSTANCE` ←, `REFERENCES` / `ENCRYPTED_BY_KMS`
- **Edges out:**<br>`ASSUMES_ROLE` / `RUNS_ON` → `SERVICE_PRINCIPAL`<br>`CONTAINS` / `CLUSTER_CONTAINS_SERVICE` → `NODE_GROUP`<br>`REFERENCES` → `VPC`<br>`REFERENCES` / `ENCRYPTED_BY_KMS` → `KMS_KEY`
- **Edges in:**<br>`CONTAINS` ← `CLOUD_ACCOUNT`<br>`CONTAINS` / `SUBNET_CONTAINS_INSTANCE` ← `SUBNET`

#### APP_SERVICE

Catalog entries that classify native resources as this type:

- AWS ARN: `apprunner:service`, `elasticbeanstalk:application`, `elasticbeanstalk:environment`
- AWS CloudFormation (Cloud Control): `AWS::AppRunner::Service`, `AWS::ElasticBeanstalk::Environment`
- Azure ARM: `microsoft.web/hostingenvironments`, `microsoft.web/serverfarms`, `microsoft.web/sites`, `microsoft.web/sites/slots`, `microsoft.web/staticsites`
- GCP Cloud Asset Inventory: `appengine.googleapis.com/Application`, `appengine.googleapis.com/Service`

- **Providers:** AWS, AZURE
- **Can be internet-exposed:** yes (`is_internet_exposed` observed `true`)
- **Metadata keys:** `application` (str), `auto_deployments` (null), `cname` (str), `collected_via` (str), `configuration_templates` (list), `cpu` (null), `default_host_name` (str), `egress_type` (str), `elb_scheme` (str), `endpoint` (null \| str), `environment_id` (str), `environment_type` (null), `environment_variable_names` (list), `health` (str), `https_only` (null), `identity` (object), `image` (str), `image_repository_type` (str), `images` (list), `instance_profile` (null \| str), `kind` (str), `load_balancer_type` (null), `managed_resources` (object), `memory` (null), `platform` (str), `properties` (object), `public_network_access` (null), `publicly_accessible` (bool), `repository_url` (null), `resource_group` (str), `resource_type` (str), `role` (str), `secret_names` (list), `security_groups` (list), `service` (str), `service_role` (null \| str), `service_url` (str), `site_count` (int), `sku` (null \| str), `solution_stack` (str), `source_type` (str), `state` (null), `status` (str), `tier` (str), `version_label` (null \| str), `versions` (int), `vnet_integration_subnet` (str), `vpc_config` (null \| object), `vpc_id` (null), `workers` (null)
- **Carries `aliases`:** yes
- **Declared relations:** `ASSUMES_ROLE` / `RUNS_ON`, `ATTACHED_TO`, `CONTAINS` ←, `CONTAINS` / `CLUSTER_CONTAINS_SERVICE` ←, `LOGS_TO` / `LOGS_TO`, `MANAGES`, `REFERENCES` / `DEPENDS_ON`, `REFERENCES` / `READS_FROM`, `REFERENCES` / `RUNS_ON`, `USES_IMAGE` / `RUNS_ON`
- **Edges out:**<br>`ASSUMES_ROLE` / `RUNS_ON` → `IAM_ROLE`, `SERVICE_PRINCIPAL`<br>`ATTACHED_TO` → `SUBNET`<br>`CONTAINS` → `APP_SERVICE`<br>`CONTAINS` / `CLUSTER_CONTAINS_SERVICE` → `APP_SERVICE`, `CLOUD_FUNCTION`<br>`MANAGES` → `AUTOSCALING_GROUP`, `EC2`, `LOAD_BALANCER`<br>`REFERENCES` / `DEPENDS_ON` → `VPC_LINK`<br>`REFERENCES` / `READS_FROM` → `SECRET`<br>`REFERENCES` / `RUNS_ON` → `INSTANCE_PROFILE`<br>`USES_IMAGE` / `RUNS_ON` → `CONTAINER_REGISTRY`
- **Edges in:**<br>`CONTAINS` ← `APP_SERVICE`, `RESOURCE_GROUP`<br>`CONTAINS` / `CLUSTER_CONTAINS_SERVICE` ← `APP_SERVICE`<br>`CONTAINS` / `SUBNET_CONTAINS_INSTANCE` ← `SUBNET`<br>`LOAD_BALANCER_TARGET` / `SERVES_TRAFFIC_TO` ← `LOAD_BALANCER`

### Networking

#### VPC

Catalog entries that classify native resources as this type:

- AWS ARN: `ec2:vpc`
- GCP Cloud Asset Inventory: `compute.googleapis.com/Network`

- **Providers:** AWS, GCP
- **Metadata keys:** `cidr_block` (str), `create_time` (null), `description` (null), `folders` (list), `gcp_asset_type` (str), `is_default` (bool), `location` (str), `network_tags` (list), `organization` (str), `parent_asset_type` (null), `parent_full_resource_name` (str), `project` (str), `project_id` (str), `project_number` (str), `state` (null \| str), `vpc_id` (str)
- **Carries `aliases`:** yes
- **Declared relations:** `REFERENCES`
- **Edges out:**<br>`CONTAINS` → `DNS_RESOLVER`, `SUBNET`<br>`CONTAINS` / `VPC_CONTAINS_SUBNET` → `SUBNET`<br>`LOGS_TO` / `LOGS_TO` → `LOG_SINK`<br>`PEERING` / `VPC_PEERED` → `PEERING_CONNECTION`<br>`REFERENCES` → `CLOUD_ACCOUNT`
- **Edges in:**<br>`ATTACHED_TO` ← `ACCESS_POINT`, `CLOUD_SQL`, `INTERNET_GATEWAY`, `SECURITY_GROUP`, `SERVICE_NETWORK`, `VPC_LINK`, `VPN_GATEWAY`<br>`ATTACHED_TO` / `DNS_RESOLVED` ← `DNS_RESOLVER`<br>`CONTAINS` ← `CLOUD_ACCOUNT`<br>`MONITORS` / `MONITORED_BY` ← `FLOW_LOG`<br>`PEERING` / `VPC_PEERED` ← `PEERING_CONNECTION`<br>`PROTECTS` / `PROTECTED_BY_NACL` ← `NETWORK_FIREWALL`<br>`REFERENCES` ← `EC2`, `GCE_INSTANCE`, `GKE_CLUSTER`, `LOAD_BALANCER`, `NACL`, `ROUTE_TABLE`, `SECURITY_GROUP`, `SUBNET`, `TARGET_GROUP`<br>`ROUTE` / `TRANSIT_ROUTED` ← `ROUTE_TABLE`, `TRANSIT_GATEWAY`

#### VNET

Catalog entries that classify native resources as this type:

- Azure ARM: `microsoft.network/virtualnetworks`

- **Providers:** AZURE
- **Metadata keys:** `address_space` (list), `collected_via` (str), `kind` (null), `properties` (object), `resource_group` (str), `resource_type` (str), `sku` (null), `subnet_ids` (list)
- **Declared relations:** `CONTAINS` ←, `PEERING` / `VPC_PEERED`
- **Edges out:**<br>`CONTAINS` / `VPC_CONTAINS_SUBNET` → `SUBNET`<br>`PEERING` / `VPC_PEERED` → `CLOUD_ACCOUNT`, `VNET`
- **Edges in:**<br>`CONTAINS` ← `RESOURCE_GROUP`<br>`PEERING` / `VPC_PEERED` ← `VNET`

#### SUBNET

Catalog entries that classify native resources as this type:

- AWS ARN: `ec2:subnet`
- Azure ARM: `microsoft.network/virtualnetworks/subnets`
- GCP Cloud Asset Inventory: `compute.googleapis.com/Subnetwork`

- **Providers:** AWS, AZURE, GCP
- **Metadata keys:** `address_prefix` (str), `address_prefixes` (list), `availability_zone` (str), `cidr_block` (str), `collected_via` (str), `create_time` (null), `delegations` (list), `description` (null), `flow_logs_enabled` (bool), `folders` (list), `gcp_asset_type` (str), `ip_cidr_range` (str), `kind` (null), `location` (str), `map_public_ip` (bool), `nat_gateway` (null), `network` (str), `network_tags` (list), `nsg_id` (null \| str), `organization` (str), `parent_asset_type` (null), `parent_full_resource_name` (str), `parent_resource` (str), `private_endpoint_ids` (list), `private_endpoint_network_policies` (null), `project` (str), `project_id` (str), `project_number` (str), `properties` (object), `resource_group` (str), `resource_type` (str), `route_table` (null \| str), `secondary_ranges` (list), `service_endpoints` (list), `sku` (null), `state` (null), `subnet_id` (str), `vnet_id` (str), `vpc_id` (str)
- **Carries `aliases`:** yes
- **Declared relations:** `ATTACHED_TO` ←, `CONTAINS` / `VPC_CONTAINS_SUBNET` ←
- **Edges out:**<br>`ATTACHED_TO` / `PROTECTED_BY_SG` → `NSG`<br>`CONTAINS` / `SUBNET_CONTAINS_INSTANCE` → `APP_SERVICE`, `BIG_DATA_CLUSTER`, `CACHE_CLUSTER`, `CONTAINER_SERVICE`, `DATABASE_PROXY`, `DATA_CATALOG`, `DATA_WAREHOUSE`, `DNS_RESOLVER`, `EC2`, `EKS_CLUSTER`, `FARGATE_PROFILE`, `FILE_SYSTEM`, `GCE_INSTANCE`, `GKE_CLUSTER`, `LOAD_BALANCER`, `MESSAGE_BROKER`, `ML_MODEL`, `ML_WORKSPACE`, `NAT_GATEWAY`, `NETWORK_FIREWALL`, `NETWORK_INTERFACE`, `NODE_GROUP`, `RDS_INSTANCE`, `VPC_ENDPOINT`, `VPC_LINK`<br>`GRANTS_ACCESS` / `POLICY_ALLOWS_ACTION` → `KEY_VAULT`<br>`REFERENCES` → `VPC`
- **Edges in:**<br>`ATTACHED_TO` ← `APP_SERVICE`, `ROUTE_TABLE`<br>`CONTAINS` ← `CLOUD_ACCOUNT`, `VPC`<br>`CONTAINS` / `VPC_CONTAINS_SUBNET` ← `VNET`, `VPC`<br>`GRANTS_ACCESS` / `DEPENDS_ON` ← `RESOURCE_SHARE`<br>`REFERENCES` ← `AKS_CLUSTER`, `NACL`

#### SECURITY_GROUP

Catalog entries that classify native resources as this type:

- AWS ARN: `ec2:security-group`
- Azure ARM: `microsoft.network/applicationsecuritygroups`
- GCP Cloud Asset Inventory: `compute.googleapis.com/Firewall`, `compute.googleapis.com/FirewallPolicy`, `compute.googleapis.com/NetworkFirewallPolicy`, `compute.googleapis.com/RegionNetworkFirewallPolicy`

- **Providers:** AWS, AZURE, GCP
- **Metadata keys:** `action` (str), `allows_internet_ingress` (bool), `collected_via` (str), `create_time` (null), `description` (null \| str), `direction` (str), `disabled` (bool), `egress_rules` (list), `folders` (list), `gcp_asset_type` (str), `group_id` (str), `ingress_rules` (list), `internet_source` (bool), `kind` (null), `location` (str), `logging_enabled` (bool), `network` (str), `network_tags` (list), `organization` (str), `parent_asset_type` (null), `parent_full_resource_name` (str), `priority` (int), `project` (str), `project_id` (str), `project_number` (str), `properties` (object), `resource_group` (str), `resource_type` (str), `sku` (null), `source_ranges` (list), `state` (null), `target_service_accounts` (list), `target_tags` (list), `vpc_id` (str)
- **Carries `aliases`:** yes
- **Declared relations:** `ATTACHED_TO`, `CONTAINS` ←
- **Edges out:**<br>`ATTACHED_TO` → `VPC`<br>`REFERENCES` → `SECURITY_GROUP`, `VPC`
- **Edges in:**<br>`ATTACHED_TO` / `PROTECTED_BY_SG` ← `BIG_DATA_CLUSTER`, `CACHE_CLUSTER`, `CONTAINER_SERVICE`, `DATABASE_PROXY`, `DATA_CATALOG`, `DATA_WAREHOUSE`, `DNS_RESOLVER`, `EC2`, `EKS_CLUSTER`, `GCE_INSTANCE`, `LAUNCH_TEMPLATE`, `LOAD_BALANCER`, `MESSAGE_BROKER`, `ML_MODEL`, `ML_WORKSPACE`, `NETWORK_INTERFACE`, `RDS_INSTANCE`, `VPC_LINK`<br>`CONTAINS` ← `CLOUD_ACCOUNT`, `RESOURCE_GROUP`<br>`MANAGES` ← `IAC_STACK`<br>`REFERENCES` ← `SECURITY_GROUP`

#### NSG

Catalog entries that classify native resources as this type:

- Azure ARM: `microsoft.network/networksecuritygroups`

- **Providers:** AZURE
- **Metadata keys:** `collected_via` (str), `egress_rules` (list), `ingress_rules` (list), `kind` (null), `network_interface_ids` (list), `properties` (object), `resource_group` (str), `resource_type` (str), `sku` (null), `subnet_ids` (list)
- **Declared relations:** `CONTAINS` ←
- **Edges in:**<br>`ATTACHED_TO` / `PROTECTED_BY_SG` ← `NETWORK_INTERFACE`, `SUBNET`<br>`CONTAINS` ← `RESOURCE_GROUP`

#### NACL

Catalog entries that classify native resources as this type:

- AWS ARN: `ec2:network-acl`

- **Providers:** AWS
- **Metadata keys:** `associations` (list), `entries` (list), `is_default` (bool), `network_acl_id` (str), `vpc_id` (str)
- **Edges out:**<br>`REFERENCES` → `SUBNET`, `VPC`

#### ROUTE_TABLE

Catalog entries that classify native resources as this type:

- AWS ARN: `ec2:route-table`, `ec2:transit-gateway-route-table`
- AWS CloudFormation (Cloud Control): `AWS::EC2::TransitGatewayRouteTable`
- Azure ARM: `microsoft.network/routetables`
- GCP Cloud Asset Inventory: `compute.googleapis.com/Route`

- **Providers:** AWS, AZURE
- **Metadata keys:** `associated_attachments` (list), `associations` (list), `bgp_route_propagation_disabled` (null), `collected_via` (str), `default_association` (bool), `default_propagation` (bool), `kind` (null), `propagating_attachments` (list), `properties` (object), `resource_group` (str), `resource_kind` (str), `resource_type` (str), `route_table_id` (str), `routes` (list), `sku` (null), `state` (str), `subnet_ids` (list), `tgw_id` (str), `tgw_route_table_id` (str), `tgw_routes` (list), `tgw_routes_truncated` (bool), `vpc_id` (str)
- **Carries `aliases`:** yes
- **Declared relations:** `ATTACHED_TO`, `CONTAINS` ←, `ROUTE` / `TRANSIT_ROUTED`
- **Edges out:**<br>`ATTACHED_TO` → `SUBNET`<br>`REFERENCES` → `PEERING_CONNECTION`, `VPC`<br>`ROUTE` / `TRANSIT_ROUTED` → `INTERNET_GATEWAY`, `NETWORK_FIREWALL`, `VPC`
- **Edges in:**<br>`CONTAINS` ← `RESOURCE_GROUP`, `TRANSIT_GATEWAY`

#### INTERNET_GATEWAY

Catalog entries that classify native resources as this type:

- AWS ARN: `ec2:egress-only-internet-gateway`, `ec2:internet-gateway`
- AWS CloudFormation (Cloud Control): `AWS::EC2::EgressOnlyInternetGateway`

- **Providers:** AWS
- **Can be internet-exposed:** yes (`is_internet_exposed` observed `true`)
- **Metadata keys:** `attached_vpcs` (list), `attachments` (list), `egress_only` (bool), `internet_gateway_id` (str), `ip_version` (str)
- **Carries `aliases`:** yes
- **Declared relations:** `ATTACHED_TO`
- **Edges out:**<br>`ATTACHED_TO` → `VPC`
- **Edges in:**<br>`ROUTE` / `TRANSIT_ROUTED` ← `ROUTE_TABLE`

#### NAT_GATEWAY

Catalog entries that classify native resources as this type:

- AWS ARN: `ec2:natgateway`
- Azure ARM: `microsoft.network/natgateways`

- **Providers:** AWS
- **Metadata keys:** `connectivity_type` (null), `nat_gateway_id` (str), `state` (str), `subnet_id` (str), `vpc_id` (str)
- **Edges in:**<br>`CONTAINS` / `SUBNET_CONTAINS_INSTANCE` ← `SUBNET`

#### LOAD_BALANCER

Catalog entries that classify native resources as this type:

- AWS ARN: `elasticloadbalancing:loadbalancer`
- Azure ARM: `microsoft.network/applicationgateways`, `microsoft.network/loadbalancers`, `microsoft.network/trafficmanagerprofiles`
- GCP Cloud Asset Inventory: `compute.googleapis.com/BackendBucket`, `compute.googleapis.com/BackendService`, `compute.googleapis.com/ForwardingRule`, `compute.googleapis.com/GlobalForwardingRule`, `compute.googleapis.com/RegionBackendService`, `compute.googleapis.com/RegionTargetHttpProxy`, `compute.googleapis.com/RegionTargetHttpsProxy`, `compute.googleapis.com/RegionTargetTcpProxy`, `compute.googleapis.com/RegionUrlMap`, `compute.googleapis.com/TargetGrpcProxy`, `compute.googleapis.com/TargetHttpProxy`, `compute.googleapis.com/TargetHttpsProxy`, `compute.googleapis.com/TargetSslProxy`, `compute.googleapis.com/TargetTcpProxy`, `compute.googleapis.com/UrlMap`

- **Providers:** AWS, AZURE, GCP
- **Also discovered via:** `tagging-api`
- **Can be internet-exposed:** yes (`is_internet_exposed` observed `true`)
- **Metadata keys:** `backend_addresses` (list), `backend_network_interfaces` (list), `cdn_enabled` (bool), `collected_via` (str), `create_time` (null), `deletion_protection` (bool), `description` (null), `discovered_via` (str), `dns_name` (str), `drops_invalid_headers` (bool), `folders` (list), `frontend_public_ip_ids` (list), `gcp_asset_type` (str), `hosts` (list), `iap_enabled` (bool), `ip_address` (str), `ip_protocol` (str), `kind` (null), `listeners` (list), `load_balancing_scheme` (str), `location` (str), `logging_enabled` (bool), `network_tags` (list), `organization` (str), `parent_asset_type` (null), `parent_full_resource_name` (str), `ports` (list), `project` (str), `project_id` (str), `project_number` (str), `properties` (object), `psc` (bool), `resource_group` (str), `resource_type` (str), `scheme` (null \| str), `security_groups` (list), `security_policy` (str), `service` (str), `sku` (null \| str), `state` (null \| str), `type` (str), `vpc_id` (str), `waf_enabled` (bool)
- **Carries `aliases`:** yes
- **Declared relations:** `ATTACHED_TO` ←, `CONTAINS` ←, `CONTAINS` / `SUBNET_CONTAINS_INSTANCE` ←, `LOAD_BALANCER_TARGET` / `LB_TARGETS_INSTANCE`, `LOAD_BALANCER_TARGET` / `SERVES_TRAFFIC_TO`, `PROTECTS` / `PROTECTED_BY_WAF` ←, `REFERENCES` / `CERTIFICATE_SECURES` ←, `ROUTE` / `SERVES_TRAFFIC_TO`
- **Edges out:**<br>`ATTACHED_TO` / `PROTECTED_BY_SG` → `SECURITY_GROUP`<br>`CONTAINS` → `LB_LISTENER`<br>`LOAD_BALANCER_TARGET` / `LB_TARGETS_INSTANCE` → `AUTOSCALING_GROUP`, `NETWORK_FIREWALL`, `NETWORK_INTERFACE`, `TARGET_GROUP`<br>`LOAD_BALANCER_TARGET` / `LOAD_BALANCED_BY` → `TARGET_GROUP`<br>`LOAD_BALANCER_TARGET` / `SERVES_TRAFFIC_TO` → `APP_SERVICE`, `GCS_BUCKET`<br>`REFERENCES` → `VPC`<br>`ROUTE` / `LOAD_BALANCED_BY` → `K8S_SERVICE`<br>`ROUTE` / `SERVES_TRAFFIC_TO` → `LOAD_BALANCER`
- **Edges in:**<br>`ATTACHED_TO` ← `ELASTIC_IP`<br>`CONTAINS` ← `CLOUD_ACCOUNT`, `RESOURCE_GROUP`<br>`CONTAINS` / `SUBNET_CONTAINS_INSTANCE` ← `SUBNET`<br>`LOAD_BALANCER_TARGET` / `SERVES_TRAFFIC_TO` ← `ENDPOINT_SERVICE`, `GLOBAL_ACCELERATOR`, `VPC_LINK`<br>`MANAGES` ← `APP_SERVICE`<br>`PROTECTS` / `PROTECTED_BY_WAF` ← `WAF_WEB_ACL`<br>`REFERENCES` / `CERTIFICATE_SECURES` ← `CERTIFICATE`<br>`ROUTE` / `DNS_RESOLVED` ← `DNS_RECORD`<br>`ROUTE` / `SERVES_TRAFFIC_TO` ← `CLOUDFRONT`, `LOAD_BALANCER`

#### CLOUDFRONT

Catalog entries that classify native resources as this type:

- AWS ARN: `cloudfront:distribution`

- **Providers:** AWS
- **Can be internet-exposed:** yes (`is_internet_exposed` observed `true`)
- **Metadata keys:** `cache_behaviors` (list), `cnames` (list), `comment` (str), `distribution_id` (str), `domain_name` (str), `edge_functions` (list), `enabled` (bool), `geo_restriction` (str), `http_version` (str), `ipv6` (bool), `logging_bucket` (null \| str), `logging_enabled` (bool), `origin_details` (list), `origin_groups` (list), `origins` (list), `price_class` (str), `realtime_log_config_arn` (str), `staging` (null), `status` (str), `viewer_certificate` (object), `viewer_protocol_policy` (str), `web_acl_id` (str)
- **Carries `aliases`:** yes
- **Declared relations:** `LOGS_TO` / `LOGS_TO`, `REFERENCES` / `CERTIFICATE_SECURES`, `ROUTE` / `SERVES_TRAFFIC_TO`
- **Edges out:**<br>`LOGS_TO` / `LOGS_TO` → `S3_BUCKET`<br>`REFERENCES` / `CERTIFICATE_SECURES` → `CERTIFICATE`<br>`ROUTE` / `SERVES_TRAFFIC_TO` → `LOAD_BALANCER`, `S3_BUCKET`
- **Edges in:**<br>`ROUTE` / `DNS_RESOLVED` ← `DNS_RECORD`

#### CDN

Catalog entries that classify native resources as this type:

- Azure ARM: `microsoft.cdn/profiles`, `microsoft.cdn/profiles/afdendpoints`, `microsoft.cdn/profiles/endpoints`, `microsoft.network/frontdoors`

*Not exercised by the fixtures.* Produced by collectors or catalogs for resources the
test estates do not contain; carries the common keys above plus collector-specific fields.

#### TRANSIT_GATEWAY

Catalog entries that classify native resources as this type:

- AWS ARN: `ec2:transit-gateway`
- Azure ARM: `microsoft.network/virtualhubs`

- **Providers:** AWS
- **Metadata keys:** `owner_id` (str), `state` (str), `transit_gateway_id` (str)
- **Edges out:**<br>`CONTAINS` → `ROUTE_TABLE`<br>`PEERING` / `TRANSIT_ROUTED` → `PEERING_CONNECTION`<br>`ROUTE` / `TRANSIT_ROUTED` → `VPC`
- **Edges in:**<br>`ROUTE` / `TRANSIT_ROUTED` ← `DIRECT_CONNECT`

#### PEERING_CONNECTION

Catalog entries that classify native resources as this type:

- AWS ARN: `ec2:vpc-peering-connection`
- GCP Cloud Asset Inventory: `networkconnectivity.googleapis.com/Spoke`

- **Providers:** AWS
- **Metadata keys:** `accepter` (object), `accepter_vpc_id` (str), `cross_account` (bool), `cross_region` (bool), `dynamic_routing` (null), `peering_connection_id` (str), `requester` (object), `requester_vpc_id` (str), `resource_kind` (str), `state` (str), `status` (null \| str), `tgw_attachment_id` (str)
- **Carries `aliases`:** yes
- **Declared relations:** `PEERING` / `TRANSIT_ROUTED`, `PEERING` / `TRANSIT_ROUTED` ←
- **Edges out:**<br>`PEERING` / `TRANSIT_ROUTED` → `CLOUD_ACCOUNT`<br>`PEERING` / `VPC_PEERED` → `VPC`
- **Edges in:**<br>`PEERING` / `TRANSIT_ROUTED` ← `TRANSIT_GATEWAY`<br>`PEERING` / `VPC_PEERED` ← `VPC`<br>`REFERENCES` ← `ROUTE_TABLE`

#### ELASTIC_IP

Catalog entries that classify native resources as this type:

- AWS ARN: `ec2:elastic-ip`
- Azure ARM: `microsoft.network/publicipaddresses`
- GCP Cloud Asset Inventory: `compute.googleapis.com/Address`, `compute.googleapis.com/GlobalAddress`

- **Providers:** AWS, AZURE, GCP
- **Can be internet-exposed:** yes (`is_internet_exposed` observed `true`)
- **Metadata keys:** `address` (str), `address_type` (str), `allocation_id` (str), `allocation_method` (null), `attached_instance_id` (str), `collected_via` (str), `create_time` (null), `description` (null), `folders` (list), `fqdn` (null), `gcp_asset_type` (str), `kind` (null), `location` (str), `network_interface_id` (str), `network_tags` (list), `organization` (str), `parent_asset_type` (null), `parent_full_resource_name` (str), `project` (str), `project_id` (str), `project_number` (str), `properties` (object), `public_ip` (str), `resource_group` (str), `resource_type` (str), `sku` (null), `state` (null)
- **Carries `aliases`:** yes
- **Declared relations:** `ATTACHED_TO`, `CONTAINS` ←
- **Edges out:**<br>`ATTACHED_TO` → `LOAD_BALANCER`, `NETWORK_FIREWALL`, `NETWORK_INTERFACE`
- **Edges in:**<br>`CONTAINS` ← `CLOUD_ACCOUNT`, `RESOURCE_GROUP`

#### NETWORK_INTERFACE

Catalog entries that classify native resources as this type:

- AWS ARN: `ec2:network-interface`
- Azure ARM: `microsoft.network/networkinterfaces`

- **Providers:** AWS, AZURE
- **Can be internet-exposed:** yes (`is_internet_exposed` observed `true`)
- **Metadata keys:** `attached_instance_id` (null \| str), `collected_via` (str), `description` (str), `interface_type` (str), `ip_forwarding` (bool), `kind` (null), `mac_address` (null), `network_interface_id` (str), `nsg_id` (str), `private_endpoint_id` (null), `private_ip` (str), `private_ips` (list), `properties` (object), `public_ip` (null \| str), `public_ip_id` (str), `public_ip_ids` (list), `resource_group` (str), `resource_type` (str), `security_groups` (list), `sku` (null), `subnet_id` (str), `subnet_ids` (list), `vpc_id` (str)
- **Carries `aliases`:** yes
- **Declared relations:** `ATTACHED_TO` ←, `CONTAINS` ←, `LOAD_BALANCER_TARGET` / `LB_TARGETS_INSTANCE` ←
- **Edges out:**<br>`ATTACHED_TO` → `EC2`, `VIRTUAL_MACHINE`<br>`ATTACHED_TO` / `PROTECTED_BY_SG` → `NSG`, `SECURITY_GROUP`
- **Edges in:**<br>`ATTACHED_TO` ← `ELASTIC_IP`<br>`CONTAINS` ← `RESOURCE_GROUP`<br>`CONTAINS` / `SUBNET_CONTAINS_INSTANCE` ← `SUBNET`<br>`LOAD_BALANCER_TARGET` / `LB_TARGETS_INSTANCE` ← `LOAD_BALANCER`

### Storage

#### S3_BUCKET

Catalog entries that classify native resources as this type:

- AWS ARN: `s3`

- **Providers:** AWS
- **Can be internet-exposed:** yes (`is_internet_exposed` observed `true`)
- **Metadata keys:** `access_logging_target` (null), `account_public_access_block` (null \| object), `acl_grants` (int), `creation_date` (str), `encryption` (bool), `eventbridge_notifications` (bool), `kms_key_id` (null), `policy_allows_public` (bool), `public_access_block` (null), `replication_rules` (int), `sse_algorithm` (null)
- **Carries `aliases`:** yes
- **Declared relations:** `INVOKES` / `INVOKES`
- **Edges out:**<br>`INVOKES` / `INVOKES` → `LAMBDA_FUNCTION`, `MESSAGE_QUEUE`
- **Edges in:**<br>`INVOKES` / `STREAMS_TO` ← `DELIVERY_STREAM`<br>`LOGS_TO` / `LOGS_TO` ← `BIG_DATA_CLUSTER`, `CLOUDFRONT`, `LOG_SINK`<br>`REFERENCES` ← `CLOUDTRAIL`<br>`REFERENCES` / `BACKUP_TO` ← `DELIVERY_STREAM`<br>`REFERENCES` / `DEPENDS_ON` ← `DATA_CATALOG`, `DATA_TRANSFER`<br>`REFERENCES` / `READS_FROM` ← `ACCESS_POINT`, `BUILD_PROJECT`, `ETL_JOB`, `IDENTITY_USER`, `KNOWLEDGE_BASE`, `ML_MODEL`<br>`REFERENCES` / `WRITES_TO` ← `CI_PIPELINE`, `DATA_TRANSFER`, `ETL_JOB`, `QUERY_WORKGROUP`<br>`ROUTE` / `SERVES_TRAFFIC_TO` ← `CLOUDFRONT`

#### BLOB_STORAGE

Catalog entries that classify native resources as this type:

- Azure ARM: `microsoft.storage/storageaccounts`

- **Providers:** AZURE
- **Metadata keys:** `access_tier` (null), `collected_via` (str), `hns_enabled` (null), `https_only` (null), `kind` (str), `min_tls_version` (null), `network_default_action` (str), `properties` (object), `provisioning_state` (null), `public_blob_access` (bool), `public_network_access` (str), `resource_group` (str), `resource_type` (str), `shared_key_access` (null), `sku` (str)
- **Carries `aliases`:** yes
- **Declared relations:** `CONTAINS` ←, `REFERENCES`, `REFERENCES` / `ENCRYPTED_BY_KMS`
- **Edges out:**<br>`REFERENCES` / `ENCRYPTED_BY_KMS` → `KEY_VAULT`
- **Edges in:**<br>`CONTAINS` ← `RESOURCE_GROUP`<br>`REFERENCES` / `DEPENDS_ON` ← `VPC_ENDPOINT`

#### GCS_BUCKET

Catalog entries that classify native resources as this type:

- GCP Cloud Asset Inventory: `storage.googleapis.com/Bucket`

- **Providers:** GCP
- **Metadata keys:** `create_time` (null), `description` (null), `folders` (list), `gcp_asset_type` (str), `location` (str), `network_tags` (list), `organization` (str), `parent_asset_type` (null), `parent_full_resource_name` (str), `project` (str), `project_id` (str), `project_number` (str), `public_acl` (list), `retention_locked` (bool), `state` (null), `uniform_bucket_level_access` (bool), `versioning` (bool), `website` (bool)
- **Edges in:**<br>`CONTAINS` ← `CLOUD_ACCOUNT`<br>`LOAD_BALANCER_TARGET` / `SERVES_TRAFFIC_TO` ← `LOAD_BALANCER`<br>`LOGS_TO` / `LOGS_TO` ← `LOG_SINK`

#### EBS_VOLUME

Catalog entries that classify native resources as this type:

- AWS ARN: `ec2:volume`
- Azure ARM: `microsoft.compute/disks`
- GCP Cloud Asset Inventory: `compute.googleapis.com/Disk`, `compute.googleapis.com/RegionDisk`

- **Providers:** AWS, AZURE, GCP
- **Metadata keys:** `attached_instance_id` (str), `attached_instance_ids` (list), `collected_via` (str), `create_time` (null), `description` (null), `disk_encryption_set` (str), `encrypted` (bool), `encryption` (str), `folders` (list), `gcp_asset_type` (str), `kind` (null), `kms_keys` (list), `location` (str), `managed_by` (str), `network_access_policy` (null), `network_tags` (list), `organization` (str), `parent_asset_type` (null), `parent_full_resource_name` (str), `project` (str), `project_id` (str), `project_number` (str), `properties` (object), `resource_group` (str), `resource_type` (str), `size_gb` (int), `sku` (null), `state` (null \| str), `volume_id` (str), `volume_type` (str)
- **Carries `aliases`:** yes
- **Declared relations:** `ATTACHED_TO`, `CONTAINS` ←, `REFERENCES` / `ENCRYPTED_BY_KMS`
- **Edges out:**<br>`ATTACHED_TO` → `EC2`, `GCE_INSTANCE`, `VIRTUAL_MACHINE`<br>`REFERENCES` / `ENCRYPTED_BY_KMS` → `KMS_KEY`
- **Edges in:**<br>`CONTAINS` ← `CLOUD_ACCOUNT`, `RESOURCE_GROUP`<br>`REFERENCES` ← `SNAPSHOT`

#### ACCESS_POINT

S3 (multi-region) access point, EFS access point.

Catalog entries that classify native resources as this type:

- AWS ARN: `elasticfilesystem:access-point`, `s3:accesspoint`, `s3:mrap`

- **Providers:** AWS
- **Metadata keys:** `account_public_access_block` (object), `alias` (str), `bucket` (str), `bucket_account_id` (null), `buckets` (list), `created` (str), `data_source_type` (null), `endpoint_kind` (str), `network_origin` (str), `policy_public` (null), `public_access_block` (object), `regions` (list), `restricted_by_public_access_block` (bool), `status` (str), `vpc_id` (str)
- **Carries `aliases`:** yes
- **Declared relations:** `ATTACHED_TO`, `REFERENCES` / `READS_FROM`
- **Edges out:**<br>`ATTACHED_TO` → `VPC`<br>`REFERENCES` / `READS_FROM` → `S3_BUCKET`

### Database

#### RDS_INSTANCE

Catalog entries that classify native resources as this type:

- AWS ARN: `rds:db`

- **Providers:** AWS
- **Metadata keys:** `cluster` (null), `deletion_protection` (bool), `endpoint` (str), `engine` (str), `engine_version` (str), `instance_class` (str), `kms_key_id` (null \| str), `multi_az` (bool), `publicly_accessible` (bool), `security_groups` (list), `storage_encrypted` (bool), `subnet_id` (str), `vpc_id` (null)
- **Carries `aliases`:** yes
- **Edges out:**<br>`ATTACHED_TO` / `PROTECTED_BY_SG` → `SECURITY_GROUP`
- **Edges in:**<br>`CONTAINS` / `SUBNET_CONTAINS_INSTANCE` ← `SUBNET`<br>`LOAD_BALANCER_TARGET` / `SERVES_TRAFFIC_TO` ← `DATABASE_PROXY`<br>`REFERENCES` ← `SNAPSHOT`

#### AURORA_CLUSTER

Catalog entries that classify native resources as this type:

- AWS ARN: `rds:cluster`
- AWS CloudFormation (Cloud Control): `AWS::DocDB::DBCluster`, `AWS::Neptune::DBCluster`
- GCP Cloud Asset Inventory: `alloydb.googleapis.com/Cluster`

- **Providers:** AWS
- **Metadata keys:** `deletion_protection` (bool), `endpoint` (str), `engine` (str), `engine_version` (str), `kind` (str), `kms_key_id` (str), `members` (list), `security_groups` (list), `service` (str), `status` (str), `storage_encrypted` (bool), `writer` (str)
- **Carries `aliases`:** yes
- **Declared relations:** `CONTAINS`, `REFERENCES` / `ENCRYPTED_BY_KMS`, `REFERENCES` / `REPLICATES_TO` ←
- **Edges out:**<br>`CONTAINS` → `AURORA_CLUSTER`<br>`REFERENCES` / `REPLICATES_TO` → `AURORA_CLUSTER`
- **Edges in:**<br>`CONTAINS` ← `AURORA_CLUSTER`<br>`REFERENCES` ← `SNAPSHOT`<br>`REFERENCES` / `REPLICATES_TO` ← `AURORA_CLUSTER`

#### AZURE_SQL

Catalog entries that classify native resources as this type:

- Azure ARM: `microsoft.dbformariadb/servers`, `microsoft.dbformysql/flexibleservers`, `microsoft.dbformysql/servers`, `microsoft.dbforpostgresql/flexibleservers`, `microsoft.dbforpostgresql/servergroupsv2`, `microsoft.dbforpostgresql/servers`, `microsoft.sql/managedinstances`, `microsoft.sql/servers`, `microsoft.sql/servers/databases`, `microsoft.sql/servers/elasticpools`

- **Providers:** AZURE
- **Can be internet-exposed:** yes (`is_internet_exposed` observed `true`)
- **Metadata keys:** `allow_azure_services` (bool), `collected_via` (str), `edition` (str), `entra_only_auth` (null), `firewall_rules` (list), `fqdn` (str), `kind` (null), `minimal_tls_version` (null), `parent_resource` (str), `properties` (object), `public_network_access` (str), `resource_group` (str), `resource_type` (str), `role` (str), `server_id` (str), `server_name` (str), `sku` (null \| str), `status` (str), `version` (null)
- **Carries `aliases`:** yes
- **Declared relations:** `CONTAINS` ←
- **Edges out:**<br>`CONTAINS` → `AZURE_SQL`
- **Edges in:**<br>`CONTAINS` ← `AZURE_SQL`, `RESOURCE_GROUP`

#### CLOUD_SQL

Catalog entries that classify native resources as this type:

- GCP Cloud Asset Inventory: `alloydb.googleapis.com/Instance`, `spanner.googleapis.com/Instance`, `sqladmin.googleapis.com/Instance`

- **Providers:** GCP
- **Metadata keys:** `authorized_networks` (list), `backups_enabled` (bool), `create_time` (null), `database_version` (str), `description` (null), `folders` (list), `gcp_asset_type` (str), `location` (str), `network_tags` (list), `organization` (str), `parent_asset_type` (null), `parent_full_resource_name` (str), `project` (str), `project_id` (str), `project_number` (str), `public_ip_enabled` (bool), `public_ips` (list), `state` (null)
- **Carries `aliases`:** yes
- **Declared relations:** `ATTACHED_TO`
- **Edges out:**<br>`ATTACHED_TO` → `VPC`
- **Edges in:**<br>`CONTAINS` ← `CLOUD_ACCOUNT`<br>`REFERENCES` / `DEPENDS_ON` ← `CONTAINER_SERVICE`

#### DYNAMODB_TABLE

Catalog entries that classify native resources as this type:

- AWS ARN: `dynamodb:table`
- AWS CloudFormation (Cloud Control): `AWS::Cassandra::Keyspace`
- Azure ARM: `microsoft.documentdb/databaseaccounts`
- GCP Cloud Asset Inventory: `bigtableadmin.googleapis.com/Instance`, `firestore.googleapis.com/Database`

- **Providers:** AWS
- **Metadata keys:** `billing_mode` (str), `deletion_protection` (bool), `encryption` (str), `external_accounts` (list), `global_table_version` (null \| str), `indexes` (list), `item_count` (int), `kinesis_destinations` (list), `kms_key_id` (null \| str), `pitr_enabled` (bool), `pitr_recovery_days` (int \| null), `policy_principals` (list), `public_policy` (bool), `replica_regions` (list), `size_bytes` (int), `sse_type` (null \| str), `status` (str), `stream_arn` (null \| str), `stream_enabled` (bool), `stream_view_type` (null \| str), `table_class` (null)
- **Carries `aliases`:** yes
- **Declared relations:** `GRANTS_ACCESS` / `CROSS_ACCOUNT_TRUST` ←, `REFERENCES` / `ENCRYPTED_BY_KMS`, `REFERENCES` / `REPLICATES_TO`, `REFERENCES` / `STREAMS_TO`
- **Edges out:**<br>`INVOKES` → `LAMBDA_FUNCTION`<br>`REFERENCES` / `BACKUP_TO` → `BACKUP_VAULT`<br>`REFERENCES` / `ENCRYPTED_BY_KMS` → `KMS_KEY`<br>`REFERENCES` / `REPLICATES_TO` → `DYNAMODB_TABLE`<br>`REFERENCES` / `STREAMS_TO` → `DATA_STREAM`
- **Edges in:**<br>`GRANTS_ACCESS` / `CROSS_ACCOUNT_TRUST` ← `CLOUD_ACCOUNT`<br>`MANAGES` / `BACKUP_TO` ← `BACKUP_PLAN`<br>`REFERENCES` / `REPLICATES_TO` ← `DYNAMODB_TABLE`

### IAM

#### IAM_USER

Catalog entries that classify native resources as this type:

- AWS ARN: `iam:user`

- **Providers:** AWS
- **Metadata keys:** `attached_policies` (list), `create_date` (str), `groups` (list), `inline_policies` (list), `is_admin` (bool), `password_last_used` (str), `user_id` (str)
- **Declared relations:** `CONTAINS` ←
- **Edges out:**<br>`CONTAINS` → `ACCESS_KEY`<br>`GRANTS_ACCESS` / `POLICY_ALLOWS_ACTION` → `KMS_KEY`
- **Edges in:**<br>`CONTAINS` ← `IAM_GROUP`

#### IAM_ROLE

Catalog entries that classify native resources as this type:

- AWS ARN: `iam:role`
- GCP Cloud Asset Inventory: `iam.googleapis.com/Role`, `rbac.authorization.k8s.io/ClusterRole`, `rbac.authorization.k8s.io/Role`

- **Providers:** AWS
- **Metadata keys:** `assume_role_policy` (object), `attached_policies` (list), `inline_policies` (list), `is_admin` (bool), `last_used` (str), `last_used_region` (null), `max_session_duration` (int), `path` (str), `publicly_assumable` (bool), `role_id` (str), `service_linked` (bool), `trusted_external_accounts` (list), `trusted_federated` (list), `trusted_services` (list)
- **Declared relations:** `GRANTS_ACCESS` / `POLICY_ALLOWS_ACTION`, `IAM_POLICY_ATTACHMENT` / `ROLE_HAS_POLICY`, `IAM_TRUST` ←, `IAM_TRUST` / `CROSS_ACCOUNT_TRUST` ←, `IAM_TRUST` / `ROLE_ASSUMES_ROLE` ←
- **Edges out:**<br>`GRANTS_ACCESS` / `POLICY_ALLOWS_ACTION` → `DATA_CATALOG`, `MESSAGE_QUEUE`, `PRODUCT_PORTFOLIO`, `SEARCH_DOMAIN`<br>`IAM_POLICY_ATTACHMENT` / `ROLE_HAS_POLICY` → `IAM_POLICY`<br>`IAM_TRUST` / `CROSS_ACCOUNT_TRUST` → `IAM_ROLE`
- **Edges in:**<br>`ASSUMES_ROLE` / `ROLE_ASSUMES_ROLE` ← `IDENTITY_POOL`, `PERMISSION_SET`<br>`ASSUMES_ROLE` / `RUNS_ON` ← `AI_AGENT`, `APP_SERVICE`, `BACKUP_PLAN`, `BATCH_ENVIRONMENT`, `BIG_DATA_CLUSTER`, `BUILD_PROJECT`, `CACHE_CLUSTER`, `CI_PIPELINE`, `DATABASE_PROXY`, `DATA_TRANSFER`, `DATA_WAREHOUSE`, `DELIVERY_STREAM`, `DEPLOYMENT_GROUP`, `EKS_CLUSTER`, `ETL_JOB`, `EVENT_PIPE`, `FARGATE_PROFILE`, `FLOW_LOG`, `IDENTITY_USER`, `INSTANCE_PROFILE`, `JOB_DEFINITION`, `K8S_SERVICE_ACCOUNT`, `KNOWLEDGE_BASE`, `LAMBDA_FUNCTION`, `LOG_SINK`, `ML_MODEL`, `ML_WORKSPACE`, `NODE_GROUP`, `PROVISIONED_PRODUCT`, `SCHEDULE`, `TASK_DEFINITION`, `VIRTUAL_MACHINE`<br>`IAM_TRUST` ← `CLOUD_ACCOUNT`<br>`IAM_TRUST` / `CROSS_ACCOUNT_TRUST` ← `CLOUD_ACCOUNT`, `IAM_ROLE`<br>`IAM_TRUST` / `ROLE_ASSUMES_ROLE` ← `IDENTITY_PROVIDER`<br>`MANAGES` / `OWNED_BY` ← `PERMISSION_SET`

#### IAM_POLICY

Catalog entries that classify native resources as this type:

- AWS ARN: `iam:policy`
- GCP Cloud Asset Inventory: `rbac.authorization.k8s.io/ClusterRoleBinding`, `rbac.authorization.k8s.io/RoleBinding`

- **Providers:** AWS
- **Metadata keys:** `attachment_count` (int), `default_version` (str), `grants_admin` (bool), `path` (str), `policy_id` (null)
- **Edges in:**<br>`IAM_POLICY_ATTACHMENT` / `ROLE_HAS_POLICY` ← `IAM_ROLE`

#### IAM_GROUP

Catalog entries that classify native resources as this type:

- AWS ARN: `iam:group`

- **Providers:** AWS
- **Metadata keys:** `attached_policies` (list), `group_id` (str), `inline_policies` (list), `is_admin` (bool)
- **Edges out:**<br>`CONTAINS` → `IAM_USER`

#### SERVICE_PRINCIPAL

Catalog entries that classify native resources as this type:

- Azure ARM: `microsoft.managedidentity/userassignedidentities`
- GCP Cloud Asset Inventory: `iam.googleapis.com/ServiceAccount`

- **Providers:** AZURE, GCP
- **Also discovered via:** `entra-principal-reference`, `iam_policy`, `workload_reference`
- **Metadata keys:** `client_id` (null \| str), `collected_via` (str), `create_time` (null), `description` (null), `disabled` (bool), `discovered_via` (str), `email` (str), `folders` (list), `gcp_asset_type` (str), `google_managed` (bool), `home_project` (str), `kind` (null), `location` (str), `member` (str), `network_tags` (list), `organization` (str), `parent_asset_type` (null), `parent_full_resource_name` (str), `placeholder` (bool), `principal_id` (str), `principal_type` (str), `project` (str), `project_id` (str), `project_number` (str), `properties` (object), `resource_group` (str), `resource_type` (str), `sku` (null), `state` (null), `unique_id` (str)
- **Carries `aliases`:** yes
- **Declared relations:** `CONTAINS` ←, `GRANTS_ACCESS` / `POLICY_ALLOWS_ACTION`
- **Edges out:**<br>`GRANTS_ACCESS` / `POLICY_ALLOWS_ACTION` → `CLOUD_ACCOUNT`, `CONTAINER_REGISTRY`, `KEY_VAULT`
- **Edges in:**<br>`ASSUMES_ROLE` / `ROLE_ASSUMES_ROLE` ← `IDENTITY_USER`, `K8S_SERVICE_ACCOUNT`<br>`ASSUMES_ROLE` / `RUNS_ON` ← `AKS_CLUSTER`, `APP_SERVICE`, `CONTAINER_SERVICE`, `GCE_INSTANCE`, `GKE_CLUSTER`, `MESSAGE_QUEUE`, `NODE_GROUP`<br>`CONTAINS` ← `CLOUD_ACCOUNT`, `RESOURCE_GROUP`

### Secrets / Keys

#### KMS_KEY

Catalog entries that classify native resources as this type:

- AWS ARN: `kms:key`
- Azure ARM: `microsoft.compute/diskencryptionsets`, `microsoft.keyvault/managedhsms`
- GCP Cloud Asset Inventory: `cloudkms.googleapis.com/CryptoKey`

- **Providers:** AWS, AZURE, GCP
- **Metadata keys:** `collected_via` (str), `create_time` (null), `created` (str), `custom_key_store_id` (null), `deletion_date` (null), `description` (null \| str), `enabled` (bool), `external_accounts` (list), `folders` (list), `gcp_asset_type` (str), `grant_count` (int), `grantees` (list), `key_manager` (str), `key_spec` (str), `key_state` (str), `key_url` (str), `key_usage` (null \| str), `kind` (null), `location` (str), `multi_region` (bool), `multi_region_type` (null), `network_tags` (list), `next_rotation` (null), `organization` (str), `origin` (str), `parent_asset_type` (null), `parent_full_resource_name` (str), `pending_deletion` (bool), `policy_principals` (list), `project` (str), `project_id` (str), `project_number` (str), `properties` (object), `public_policy` (bool), `purpose` (str), `resource_group` (str), `resource_type` (str), `rotation_enabled` (bool), `rotation_period_days` (null), `sku` (null), `state` (null)
- **Carries `aliases`:** yes
- **Declared relations:** `CONTAINS` ←, `GRANTS_ACCESS` / `CROSS_ACCOUNT_TRUST` ←, `GRANTS_ACCESS` / `POLICY_ALLOWS_ACTION` ←, `REFERENCES` / `ENCRYPTED_BY_KMS`
- **Edges out:**<br>`REFERENCES` → `CLOUD_ACCOUNT`<br>`REFERENCES` / `ENCRYPTED_BY_KMS` → `KEY_VAULT`
- **Edges in:**<br>`CONTAINS` ← `CLOUD_ACCOUNT`, `RESOURCE_GROUP`<br>`GRANTS_ACCESS` / `CROSS_ACCOUNT_TRUST` ← `CLOUD_ACCOUNT`<br>`GRANTS_ACCESS` / `POLICY_ALLOWS_ACTION` ← `IAM_USER`<br>`REFERENCES` / `ENCRYPTED_BY_KMS` ← `BACKUP_VAULT`, `DYNAMODB_TABLE`, `EBS_VOLUME`, `GKE_CLUSTER`, `MESSAGE_QUEUE`, `SECRET`

#### SECRET

Catalog entries that classify native resources as this type:

- AWS ARN: `secretsmanager:secret`
- GCP Cloud Asset Inventory: `secretmanager.googleapis.com/Secret`

- **Providers:** AWS, GCP
- **Metadata keys:** `create_time` (null), `created` (str), `deleted_date` (null), `description` (null \| str), `external_accounts` (list), `folders` (list), `gcp_asset_type` (str), `kms_key_id` (str), `last_accessed` (str), `last_rotated` (str), `location` (str), `network_tags` (list), `next_rotation` (null \| str), `organization` (str), `owning_service` (null), `parent_asset_type` (null), `parent_full_resource_name` (str), `policy_principals` (list), `primary_region` (null), `project` (str), `project_id` (str), `project_number` (str), `public_policy` (bool), `replica_regions` (list), `replication` (str), `rotation` (bool), `rotation_days` (int \| null), `rotation_enabled` (bool), `rotation_lambda` (null \| str), `rotation_schedule` (null), `state` (null)
- **Carries `aliases`:** yes
- **Declared relations:** `GRANTS_ACCESS` / `CROSS_ACCOUNT_TRUST` ←, `INVOKES` / `ROTATES_SECRET`, `REFERENCES` / `ENCRYPTED_BY_KMS`, `REFERENCES` / `REPLICATES_TO`
- **Edges out:**<br>`INVOKES` / `ROTATES_SECRET` → `LAMBDA_FUNCTION`<br>`REFERENCES` / `ENCRYPTED_BY_KMS` → `KMS_KEY`
- **Edges in:**<br>`CONTAINS` ← `CLOUD_ACCOUNT`<br>`GRANTS_ACCESS` / `CROSS_ACCOUNT_TRUST` ← `CLOUD_ACCOUNT`<br>`REFERENCES` / `READS_FROM` ← `APP_SERVICE`, `CONTAINER_SERVICE`, `DATABASE_PROXY`

#### CERTIFICATE

Catalog entries that classify native resources as this type:

- AWS ARN: `acm:certificate`
- Azure ARM: `microsoft.web/certificates`
- GCP Cloud Asset Inventory: `certificatemanager.googleapis.com/Certificate`, `compute.googleapis.com/RegionSslCertificate`, `compute.googleapis.com/SslCertificate`, `privateca.googleapis.com/CertificateAuthority`

- **Providers:** AWS, GCP
- **Metadata keys:** `certificate_type` (str), `create_time` (null), `description` (null), `domains` (list), `folders` (list), `gcp_asset_type` (str), `in_use_by` (list), `key_algorithm` (str), `location` (str), `network_tags` (list), `not_after` (str), `organization` (str), `parent_asset_type` (null), `parent_full_resource_name` (str), `project` (str), `project_id` (str), `project_number` (str), `renewal_eligibility` (str), `state` (null), `status` (str), `subject_alternative_names` (list), `type` (str)
- **Carries `aliases`:** yes
- **Edges out:**<br>`REFERENCES` / `CERTIFICATE_SECURES` → `LOAD_BALANCER`
- **Edges in:**<br>`CONTAINS` ← `CLOUD_ACCOUNT`<br>`REFERENCES` / `CERTIFICATE_SECURES` ← `CLOUDFRONT`, `CUSTOM_DOMAIN`

#### KEY_VAULT

Catalog entries that classify native resources as this type:

- Azure ARM: `microsoft.keyvault/vaults`
- GCP Cloud Asset Inventory: `cloudkms.googleapis.com/KeyRing`

- **Providers:** AZURE
- **Can be internet-exposed:** yes (`is_internet_exposed` observed `true`)
- **Metadata keys:** `access_policies` (list), `collected_via` (str), `kind` (null), `network_default_action` (str), `properties` (object), `public_network_access` (str), `purge_protection` (null), `rbac_authorization` (bool), `resource_group` (str), `resource_type` (str), `sku` (null), `soft_delete` (null), `vault_uri` (str)
- **Carries `aliases`:** yes
- **Declared relations:** `CONTAINS` ←, `GRANTS_ACCESS` / `POLICY_ALLOWS_ACTION` ←
- **Edges in:**<br>`CONTAINS` ← `RESOURCE_GROUP`<br>`GRANTS_ACCESS` / `POLICY_ALLOWS_ACTION` ← `SERVICE_PRINCIPAL`, `SUBNET`, `VIRTUAL_MACHINE`<br>`REFERENCES` / `ENCRYPTED_BY_KMS` ← `BLOB_STORAGE`, `KMS_KEY`

### Logging

#### CLOUDTRAIL

Catalog entries that classify native resources as this type:

- AWS ARN: `cloudtrail:trail`

- **Providers:** AWS
- **Metadata keys:** `enabled` (bool), `log_destination` (str), `note` (str), `security_service` (str), `status` (str)
- **Carries `aliases`:** yes
- **Edges out:**<br>`REFERENCES` → `S3_BUCKET`

#### FLOW_LOG

Catalog entries that classify native resources as this type:

- AWS ARN: `ec2:vpc-flow-log`
- Azure ARM: `microsoft.network/networkwatchers/flowlogs`

- **Providers:** AWS
- **Metadata keys:** `destination_type` (str), `flow_log_id` (str), `monitored_resource` (str), `status` (str), `traffic_type` (str)
- **Declared relations:** `ASSUMES_ROLE` / `RUNS_ON`, `LOGS_TO` / `LOGS_TO`, `MONITORS` / `MONITORED_BY`
- **Edges out:**<br>`ASSUMES_ROLE` / `RUNS_ON` → `IAM_ROLE`<br>`LOGS_TO` / `LOGS_TO` → `LOG_GROUP`<br>`MONITORS` / `MONITORED_BY` → `VPC`

#### LOG_GROUP

Catalog entries that classify native resources as this type:

- AWS ARN: `logs:log-group`
- Azure ARM: `microsoft.insights/components`, `microsoft.operationalinsights/workspaces`
- GCP Cloud Asset Inventory: `logging.googleapis.com/LogBucket`

- **Providers:** AWS, AZURE
- **Metadata keys:** `collected_via` (str), `customer_id` (str), `kind` (null), `kms_key_id` (null), `log_class` (null), `properties` (object), `resource_group` (str), `resource_type` (str), `retention_days` (null), `sku` (null), `stored_bytes` (int)
- **Carries `aliases`:** yes
- **Declared relations:** `CONTAINS` ←
- **Edges out:**<br>`INVOKES` / `STREAMS_TO` → `LOG_SINK`
- **Edges in:**<br>`CONTAINS` ← `RESOURCE_GROUP`<br>`LOGS_TO` / `LOGS_TO` ← `AKS_CLUSTER`, `FLOW_LOG`, `LAMBDA_FUNCTION`, `LOG_SINK`

### Containers / Kubernetes

#### CONTAINER_REGISTRY

ECR repository, ACR, Artifact Registry.

Catalog entries that classify native resources as this type:

- AWS ARN: `ecr-public:repository`, `ecr:repository`
- Azure ARM: `microsoft.containerregistry/registries`
- GCP Cloud Asset Inventory: `artifactregistry.googleapis.com/Repository`

- **Providers:** AWS, AZURE, GCP
- **Can be internet-exposed:** yes (`is_internet_exposed` observed `true`)
- **Metadata keys:** `admin_user_enabled` (null), `collected_via` (str), `create_time` (null), `created_at` (str), `description` (null), `encryption_type` (str), `folders` (list), `format` (str), `gcp_asset_type` (str), `image_count_sampled` (int), `image_findings` (object), `image_tag_mutability` (str), `immutable_tags` (bool), `kind` (null), `kms_key_id` (null), `latest_images` (list), `location` (str), `login_server` (str), `network_tags` (list), `organization` (str), `parent_asset_type` (null), `parent_full_resource_name` (str), `policy_allows_public` (bool), `project` (str), `project_id` (str), `project_number` (str), `properties` (object), `public` (bool), `public_network_access` (str), `registry` (str), `registry_id` (str), `registry_scan_type` (str), `replication_destinations` (list), `repository_uri` (str), `resource_group` (str), `resource_type` (str), `scan_on_push` (bool), `service` (str), `sku` (null), `state` (null)
- **Carries `aliases`:** yes
- **Declared relations:** `CONTAINS` ←
- **Edges in:**<br>`CONTAINS` ← `CLOUD_ACCOUNT`, `RESOURCE_GROUP`<br>`GRANTS_ACCESS` / `POLICY_ALLOWS_ACTION` ← `SERVICE_PRINCIPAL`<br>`USES_IMAGE` ← `TASK_DEFINITION`<br>`USES_IMAGE` / `RUNS_ON` ← `AKS_CLUSTER`, `APP_SERVICE`, `BUILD_PROJECT`, `CONTAINER_SERVICE`, `JOB_DEFINITION`, `K8S_WORKLOAD`, `ML_MODEL`, `TASK_DEFINITION`

#### CONTAINER_SERVICE

ECS service, Azure Container App.

Catalog entries that classify native resources as this type:

- AWS ARN: `ecs:service`
- Azure ARM: `microsoft.app/containerapps`, `microsoft.containerinstance/containergroups`
- GCP Cloud Asset Inventory: `run.googleapis.com/Service`

- **Providers:** AWS, GCP
- **Metadata keys:** `assign_public_ip` (bool), `cluster_arn` (str), `create_time` (null), `description` (null), `desired_count` (int), `folders` (list), `gcp_asset_type` (str), `images` (list), `ingress` (str), `launch_type` (str), `location` (str), `network_tags` (list), `organization` (str), `parent_asset_type` (null), `parent_full_resource_name` (str), `platform` (str), `project` (str), `project_id` (str), `project_number` (str), `running_count` (int), `scheduling_strategy` (str), `security_groups` (list), `state` (null), `status` (str), `subnets` (list), `task_definition` (str), `url` (str)
- **Carries `aliases`:** yes
- **Declared relations:** `ASSUMES_ROLE` / `RUNS_ON`, `CONTAINS` / `CLUSTER_CONTAINS_SERVICE` ←, `CONTAINS` / `SUBNET_CONTAINS_INSTANCE` ←, `REFERENCES` / `DEPENDS_ON`, `REFERENCES` / `DNS_RESOLVED`, `REFERENCES` / `READS_FROM`, `ROUTE` / `TRANSIT_ROUTED`, `USES_IMAGE` / `RUNS_ON`
- **Edges out:**<br>`ASSUMES_ROLE` / `RUNS_ON` → `SERVICE_PRINCIPAL`<br>`ATTACHED_TO` / `PROTECTED_BY_SG` → `SECURITY_GROUP`<br>`REFERENCES` / `DEPENDS_ON` → `CLOUD_SQL`, `TASK_DEFINITION`<br>`REFERENCES` / `DNS_RESOLVED` → `DNS_RECORD`<br>`REFERENCES` / `READS_FROM` → `SECRET`<br>`ROUTE` / `TRANSIT_ROUTED` → `VPC_LINK`<br>`USES_IMAGE` / `RUNS_ON` → `CONTAINER_REGISTRY`
- **Edges in:**<br>`CONTAINS` ← `CLOUD_ACCOUNT`<br>`CONTAINS` / `CLUSTER_CONTAINS_SERVICE` ← `ECS_CLUSTER`<br>`CONTAINS` / `SUBNET_CONTAINS_INSTANCE` ← `SUBNET`<br>`GRANTS_ACCESS` / `POLICY_ALLOWS_ACTION` ← `IDENTITY_PROVIDER`<br>`INVOKES` / `INVOKES` ← `MESSAGE_QUEUE`<br>`LOAD_BALANCER_TARGET` / `SERVES_TRAFFIC_TO` ← `TARGET_GROUP`<br>`MANAGES` ← `DEPLOYMENT_GROUP`

#### TASK_DEFINITION

ECS task definition.

Catalog entries that classify native resources as this type:

- AWS ARN: `ecs:task-definition`

- **Providers:** AWS
- **Metadata keys:** `compatibilities` (list), `containers` (list), `cpu` (null), `execution_role_arn` (null \| str), `family` (str), `images` (list), `memory` (null), `network_mode` (str), `revision` (int), `status` (str), `task_role_arn` (str)
- **Declared relations:** `ASSUMES_ROLE` / `DEPENDS_ON`, `ASSUMES_ROLE` / `RUNS_ON`, `LOGS_TO` / `LOGS_TO`, `USES_IMAGE`, `USES_IMAGE` / `RUNS_ON`
- **Edges out:**<br>`ASSUMES_ROLE` / `RUNS_ON` → `IAM_ROLE`<br>`USES_IMAGE` → `CONTAINER_REGISTRY`<br>`USES_IMAGE` / `RUNS_ON` → `CONTAINER_REGISTRY`
- **Edges in:**<br>`REFERENCES` / `DEPENDS_ON` ← `CONTAINER_SERVICE`

#### NODE_GROUP

EKS nodegroup, AKS agent pool, GKE node pool.

Catalog entries that classify native resources as this type:

- AWS ARN: `eks:nodegroup`
- Azure ARM: `microsoft.containerservice/managedclusters/agentpools`
- GCP Cloud Asset Inventory: `container.googleapis.com/NodePool`

- **Providers:** AWS, AZURE, GCP
- **Metadata keys:** `ami_type` (str), `auto_scaling_groups` (list), `autoscaling` (bool), `capacity_type` (str), `cluster_arn` (str), `cluster_id` (str), `collected_via` (str), `count` (int), `create_time` (null), `description` (null), `folders` (list), `gcp_asset_type` (str), `instance_types` (list), `kind` (null), `location` (str), `mode` (str), `network_tags` (list), `node_role` (str), `organization` (str), `os_type` (null), `parent_asset_type` (null), `parent_full_resource_name` (str), `parent_resource` (str), `pod_subnet_id` (null), `project` (str), `project_id` (str), `project_number` (str), `properties` (object), `public_node_ips` (null), `release_version` (str), `resource_group` (str), `resource_type` (str), `scaling` (object), `sku` (null), `state` (null), `status` (str), `vm_size` (str), `vnet_subnet_id` (str)
- **Carries `aliases`:** yes
- **Declared relations:** `ASSUMES_ROLE` / `RUNS_ON`, `ATTACHED_TO` / `PROTECTED_BY_SG`, `CONTAINS` / `CLUSTER_CONTAINS_SERVICE` ←, `CONTAINS` / `SUBNET_CONTAINS_INSTANCE` ←, `MANAGES` / `SCALES_WITH`
- **Edges out:**<br>`ASSUMES_ROLE` / `RUNS_ON` → `IAM_ROLE`, `SERVICE_PRINCIPAL`<br>`MANAGES` / `SCALES_WITH` → `AUTOSCALING_GROUP`
- **Edges in:**<br>`CONTAINS` ← `CLOUD_ACCOUNT`<br>`CONTAINS` / `CLUSTER_CONTAINS_SERVICE` ← `AKS_CLUSTER`, `EKS_CLUSTER`, `GKE_CLUSTER`<br>`CONTAINS` / `SUBNET_CONTAINS_INSTANCE` ← `SUBNET`

#### FARGATE_PROFILE

Catalog entries that classify native resources as this type:

- AWS ARN: `eks:fargateprofile`

- **Providers:** AWS
- **Metadata keys:** `cluster_arn` (str), `selectors` (list), `status` (str)
- **Declared relations:** `ASSUMES_ROLE` / `RUNS_ON`, `CONTAINS` / `CLUSTER_CONTAINS_SERVICE` ←, `CONTAINS` / `SUBNET_CONTAINS_INSTANCE` ←
- **Edges out:**<br>`ASSUMES_ROLE` / `RUNS_ON` → `IAM_ROLE`
- **Edges in:**<br>`CONTAINS` / `CLUSTER_CONTAINS_SERVICE` ← `EKS_CLUSTER`<br>`CONTAINS` / `SUBNET_CONTAINS_INSTANCE` ← `SUBNET`

#### CLUSTER_ADDON

Catalog entries that classify native resources as this type:

- AWS ARN: `eks:addon`

*Not exercised by the fixtures.* Produced by collectors or catalogs for resources the
test estates do not contain; carries the common keys above plus collector-specific fields.

#### K8S_NAMESPACE

Catalog entries that classify native resources as this type:

- GCP Cloud Asset Inventory: `k8s.io/Namespace`

- **Providers:** AWS
- **Metadata keys:** `cluster_arn` (str), `kind` (str), `namespace` (str), `phase` (str)
- **Declared relations:** `CONTAINS` / `CLUSTER_CONTAINS_SERVICE` ←
- **Edges out:**<br>`CONTAINS` / `CLUSTER_CONTAINS_SERVICE` → `K8S_INGRESS`, `K8S_SERVICE`, `K8S_SERVICE_ACCOUNT`, `K8S_WORKLOAD`
- **Edges in:**<br>`CONTAINS` / `CLUSTER_CONTAINS_SERVICE` ← `EKS_CLUSTER`

#### K8S_WORKLOAD

Deployment, StatefulSet, DaemonSet, CronJob.

Catalog entries that classify native resources as this type:

- GCP Cloud Asset Inventory: `apps.k8s.io/DaemonSet`, `apps.k8s.io/Deployment`, `apps.k8s.io/StatefulSet`, `batch.k8s.io/CronJob`, `batch.k8s.io/Job`, `k8s.io/Pod`

- **Providers:** AWS
- **Metadata keys:** `cluster_arn` (str), `host_network` (bool), `images` (list), `kind` (str), `namespace` (str), `node_selector` (object), `privileged_containers` (list), `ready_replicas` (null), `replicas` (int), `schedule` (null), `service_account` (str)
- **Declared relations:** `CONTAINS` / `CLUSTER_CONTAINS_SERVICE` ←, `REFERENCES` / `RUNS_ON`, `USES_IMAGE` / `RUNS_ON`
- **Edges out:**<br>`REFERENCES` / `RUNS_ON` → `K8S_SERVICE_ACCOUNT`<br>`USES_IMAGE` / `RUNS_ON` → `CONTAINER_REGISTRY`
- **Edges in:**<br>`CONTAINS` / `CLUSTER_CONTAINS_SERVICE` ← `K8S_NAMESPACE`<br>`LOAD_BALANCER_TARGET` / `SERVES_TRAFFIC_TO` ← `K8S_SERVICE`

#### K8S_SERVICE

Catalog entries that classify native resources as this type:

- GCP Cloud Asset Inventory: `k8s.io/Service`

- **Providers:** AWS
- **Can be internet-exposed:** yes (`is_internet_exposed` observed `true`)
- **Metadata keys:** `cluster_arn` (str), `internal` (bool), `kind` (str), `load_balancer_hostnames` (list), `namespace` (str), `ports` (list), `service_type` (str)
- **Declared relations:** `CONTAINS` / `CLUSTER_CONTAINS_SERVICE` ←, `LOAD_BALANCER_TARGET` / `SERVES_TRAFFIC_TO`, `ROUTE` / `LOAD_BALANCED_BY` ←
- **Edges out:**<br>`LOAD_BALANCER_TARGET` / `SERVES_TRAFFIC_TO` → `K8S_WORKLOAD`
- **Edges in:**<br>`CONTAINS` / `CLUSTER_CONTAINS_SERVICE` ← `K8S_NAMESPACE`<br>`ROUTE` / `LOAD_BALANCED_BY` ← `LOAD_BALANCER`<br>`ROUTE` / `SERVES_TRAFFIC_TO` ← `K8S_INGRESS`

#### K8S_INGRESS

Catalog entries that classify native resources as this type:

- GCP Cloud Asset Inventory: `extensions.k8s.io/Ingress`, `networking.k8s.io/Ingress`

- **Providers:** AWS
- **Metadata keys:** `backends` (list), `cluster_arn` (str), `hosts` (list), `ingress_class` (null), `kind` (str), `load_balancer_hostnames` (list), `namespace` (str), `tls` (bool)
- **Declared relations:** `CONTAINS` / `CLUSTER_CONTAINS_SERVICE` ←, `ROUTE` / `SERVES_TRAFFIC_TO`
- **Edges out:**<br>`ROUTE` / `SERVES_TRAFFIC_TO` → `K8S_SERVICE`
- **Edges in:**<br>`CONTAINS` / `CLUSTER_CONTAINS_SERVICE` ← `K8S_NAMESPACE`

#### K8S_SERVICE_ACCOUNT

Catalog entries that classify native resources as this type:

- GCP Cloud Asset Inventory: `k8s.io/ServiceAccount`

- **Providers:** AWS, GCP
- **Also discovered via:** `iam_policy`
- **Metadata keys:** `cluster_arn` (str), `discovered_via` (str), `irsa_role_arn` (str), `kind` (str), `member` (str), `namespace` (str), `placeholder` (bool), `principal_type` (str), `workload_pool_project` (str)
- **Carries `aliases`:** yes
- **Declared relations:** `ASSUMES_ROLE` / `RUNS_ON`, `CONTAINS` / `CLUSTER_CONTAINS_SERVICE` ←
- **Edges out:**<br>`ASSUMES_ROLE` / `ROLE_ASSUMES_ROLE` → `SERVICE_PRINCIPAL`<br>`ASSUMES_ROLE` / `RUNS_ON` → `IAM_ROLE`
- **Edges in:**<br>`CONTAINS` / `CLUSTER_CONTAINS_SERVICE` ← `K8S_NAMESPACE`<br>`REFERENCES` / `RUNS_ON` ← `K8S_WORKLOAD`

### Compute fabric

#### AUTOSCALING_GROUP

Catalog entries that classify native resources as this type:

- AWS ARN: `autoscaling:autoScalingGroup`
- Azure ARM: `microsoft.compute/virtualmachinescalesets`
- GCP Cloud Asset Inventory: `compute.googleapis.com/InstanceGroup`, `compute.googleapis.com/InstanceGroupManager`, `compute.googleapis.com/RegionInstanceGroup`, `compute.googleapis.com/RegionInstanceGroupManager`

- **Providers:** AWS, AZURE, GCP
- **Metadata keys:** `capacity` (null), `collected_via` (str), `create_time` (null), `description` (null), `folders` (list), `gcp_asset_type` (str), `kind` (null), `location` (str), `named_ports` (list), `network_tags` (list), `organization` (str), `parent_asset_type` (null), `parent_full_resource_name` (str), `project` (str), `project_id` (str), `project_number` (str), `properties` (object), `resource_group` (str), `resource_type` (str), `size` (str), `sku` (null), `state` (null)
- **Carries `aliases`:** yes
- **Declared relations:** `CONTAINS` ←, `MANAGES` / `SCALES_WITH`, `REFERENCES` / `DEPENDS_ON`
- **Edges out:**<br>`MANAGES` / `SCALES_WITH` → `AUTOSCALING_GROUP`
- **Edges in:**<br>`CONTAINS` ← `CLOUD_ACCOUNT`, `RESOURCE_GROUP`<br>`INVOKES` / `SCALES_WITH` ← `ALARM`<br>`LOAD_BALANCER_TARGET` / `LB_TARGETS_INSTANCE` ← `LOAD_BALANCER`<br>`MANAGES` ← `APP_SERVICE`, `DEPLOYMENT_GROUP`<br>`MANAGES` / `SCALES_WITH` ← `AUTOSCALING_GROUP`, `CAPACITY_PROVIDER`, `NODE_GROUP`<br>`MONITORS` / `MONITORED_BY` ← `ALARM`

#### LAUNCH_TEMPLATE

Catalog entries that classify native resources as this type:

- AWS ARN: `ec2:launch-template`
- GCP Cloud Asset Inventory: `compute.googleapis.com/InstanceTemplate`, `compute.googleapis.com/RegionInstanceTemplate`

- **Providers:** AWS
- **Metadata keys:** `image_id` (str), `imdsv2_required` (bool), `instance_type` (str), `latest_version` (int), `launch_template_id` (str), `security_groups` (list)
- **Carries `aliases`:** yes
- **Declared relations:** `ASSUMES_ROLE` / `RUNS_ON`
- **Edges out:**<br>`ASSUMES_ROLE` / `RUNS_ON` → `INSTANCE_PROFILE`<br>`ATTACHED_TO` / `PROTECTED_BY_SG` → `SECURITY_GROUP`

#### TARGET_GROUP

Catalog entries that classify native resources as this type:

- AWS ARN: `elasticloadbalancing:targetgroup`
- GCP Cloud Asset Inventory: `compute.googleapis.com/GlobalNetworkEndpointGroup`, `compute.googleapis.com/NetworkEndpointGroup`, `compute.googleapis.com/RegionNetworkEndpointGroup`, `compute.googleapis.com/TargetInstance`, `compute.googleapis.com/TargetPool`

- **Providers:** AWS, GCP
- **Metadata keys:** `create_time` (null), `description` (null), `folders` (list), `gcp_asset_type` (str), `location` (str), `network_endpoint_type` (str), `network_tags` (list), `organization` (str), `parent_asset_type` (null), `parent_full_resource_name` (str), `port` (int), `project` (str), `project_id` (str), `project_number` (str), `protocol` (str), `state` (null), `target_type` (str), `targets` (list), `vpc_id` (str)
- **Carries `aliases`:** yes
- **Declared relations:** `LOAD_BALANCER_TARGET` / `LB_TARGETS_INSTANCE`, `LOAD_BALANCER_TARGET` / `LOAD_BALANCED_BY` ←, `LOAD_BALANCER_TARGET` / `SERVES_TRAFFIC_TO`
- **Edges out:**<br>`LOAD_BALANCER_TARGET` / `LB_TARGETS_INSTANCE` → `EC2`<br>`LOAD_BALANCER_TARGET` / `SERVES_TRAFFIC_TO` → `CONTAINER_SERVICE`<br>`REFERENCES` → `VPC`
- **Edges in:**<br>`CONTAINS` ← `CLOUD_ACCOUNT`<br>`LOAD_BALANCER_TARGET` / `LB_TARGETS_INSTANCE` ← `LOAD_BALANCER`<br>`LOAD_BALANCER_TARGET` / `LOAD_BALANCED_BY` ← `LOAD_BALANCER`<br>`MANAGES` ← `DEPLOYMENT_GROUP`<br>`ROUTE` / `SERVES_TRAFFIC_TO` ← `LB_LISTENER`

#### API_GATEWAY

Catalog entries that classify native resources as this type:

- AWS ARN: `apigateway:apis`, `apigateway:restapis`
- AWS CloudFormation (Cloud Control): `AWS::AppSync::GraphQLApi`
- Azure ARM: `microsoft.apimanagement/service`
- GCP Cloud Asset Inventory: `apigateway.googleapis.com/Api`, `apigateway.googleapis.com/Gateway`

- **Providers:** AWS
- **Can be internet-exposed:** yes (`is_internet_exposed` observed `true`)
- **Metadata keys:** `api_id` (str), `api_type` (str), `default_endpoint_disabled` (bool), `endpoint` (str), `endpoint_types` (list), `integrations` (list), `stages` (list), `unauthenticated_methods` (int)
- **Carries `aliases`:** yes
- **Edges out:**<br>`REFERENCES` / `DEPENDS_ON` → `AUTHORIZER`
- **Edges in:**<br>`ROUTE` / `SERVES_TRAFFIC_TO` ← `CUSTOM_DOMAIN`

#### VPC_ENDPOINT

Catalog entries that classify native resources as this type:

- AWS ARN: `ec2:vpc-endpoint`
- Azure ARM: `microsoft.network/privateendpoints`

- **Providers:** AZURE
- **Metadata keys:** `collected_via` (str), `fqdns` (list), `kind` (null), `network_interfaces` (list), `private_link_targets` (list), `properties` (object), `resource_group` (str), `resource_type` (str), `sku` (null), `subnet_id` (str)
- **Declared relations:** `CONTAINS` ←, `REFERENCES` / `DEPENDS_ON`
- **Edges out:**<br>`REFERENCES` / `DEPENDS_ON` → `BLOB_STORAGE`
- **Edges in:**<br>`CONTAINS` ← `RESOURCE_GROUP`<br>`CONTAINS` / `SUBNET_CONTAINS_INSTANCE` ← `SUBNET`

#### INSTANCE_PROFILE

Catalog entries that classify native resources as this type:

- AWS ARN: `iam:instance-profile`

- **Providers:** AWS
- **Metadata keys:** `instance_profile_id` (str)
- **Declared relations:** `ASSUMES_ROLE` / `RUNS_ON`
- **Edges out:**<br>`ASSUMES_ROLE` / `RUNS_ON` → `IAM_ROLE`
- **Edges in:**<br>`ASSUMES_ROLE` / `RUNS_ON` ← `LAUNCH_TEMPLATE`<br>`REFERENCES` / `RUNS_ON` ← `APP_SERVICE`

#### IDENTITY_PROVIDER

Catalog entries that classify native resources as this type:

- AWS ARN: `iam:oidc-provider`, `iam:saml-provider`
- GCP Cloud Asset Inventory: `iam.googleapis.com/WorkforcePool`, `iam.googleapis.com/WorkforcePoolProvider`, `iam.googleapis.com/WorkloadIdentityPool`, `iam.googleapis.com/WorkloadIdentityPoolProvider`

- **Providers:** AWS, GCP
- **Also discovered via:** `iam_policy`
- **Metadata keys:** `acm_pca_arn` (null), `created` (null \| str), `discovered_via` (str), `enabled` (bool), `group_count` (int), `home_region` (str), `identity_center_managed` (bool), `identity_pool` (str), `identity_store_id` (str), `member` (str), `owner_account_id` (null \| str), `permission_set_count` (int), `placeholder` (bool), `principal_type` (str), `provider_type` (str), `source_type` (str), `status` (str), `trust_anchor_id` (str), `user_count` (int), `valid_until` (str)
- **Carries `aliases`:** yes
- **Declared relations:** `REFERENCES` / `DEPENDS_ON`
- **Edges out:**<br>`CONTAINS` → `IDENTITY_GROUP`, `IDENTITY_USER`, `PERMISSION_SET`<br>`GRANTS_ACCESS` / `POLICY_ALLOWS_ACTION` → `CONTAINER_SERVICE`<br>`IAM_TRUST` / `ROLE_ASSUMES_ROLE` → `IAM_ROLE`, `PERMISSION_SET`<br>`REFERENCES` / `DEPENDS_ON` → `CLOUD_ACCOUNT`

### Integration / messaging

#### MESSAGE_QUEUE

Catalog entries that classify native resources as this type:

- AWS ARN: `sqs`
- Azure ARM: `microsoft.servicebus/namespaces`
- GCP Cloud Asset Inventory: `cloudtasks.googleapis.com/Queue`, `pubsub.googleapis.com/Subscription`

- **Providers:** AWS, GCP
- **Metadata keys:** `create_time` (null), `dead_letter_target` (null \| str), `delivery` (str), `description` (null), `fifo` (bool), `folders` (list), `gcp_asset_type` (str), `kms_key_id` (null \| str), `location` (str), `network_tags` (list), `organization` (str), `parent_asset_type` (null), `parent_full_resource_name` (str), `policy_allows_public` (bool), `project` (str), `project_id` (str), `project_number` (str), `push_endpoint_host` (str), `queue_url` (str), `sse_sqs` (bool), `state` (null), `visibility_timeout` (str)
- **Carries `aliases`:** yes
- **Declared relations:** `ASSUMES_ROLE` / `RUNS_ON`, `INVOKES` / `INVOKES`, `INVOKES` / `STREAMS_TO` ←, `REFERENCES` / `ENCRYPTED_BY_KMS`, `REFERENCES` / `WRITES_TO`
- **Edges out:**<br>`ASSUMES_ROLE` / `RUNS_ON` → `SERVICE_PRINCIPAL`<br>`INVOKES` → `LAMBDA_FUNCTION`<br>`INVOKES` / `INVOKES` → `CONTAINER_SERVICE`<br>`INVOKES` / `TRIGGERED_BY` → `EVENT_PIPE`, `LAMBDA_FUNCTION`<br>`REFERENCES` / `ENCRYPTED_BY_KMS` → `KMS_KEY`<br>`REFERENCES` / `WRITES_TO` → `MESSAGE_QUEUE`
- **Edges in:**<br>`CONTAINS` ← `CLOUD_ACCOUNT`<br>`GRANTS_ACCESS` / `POLICY_ALLOWS_ACTION` ← `IAM_ROLE`<br>`INVOKES` / `INVOKES` ← `S3_BUCKET`<br>`INVOKES` / `STREAMS_TO` ← `NOTIFICATION_TOPIC`<br>`REFERENCES` ← `OTHER`<br>`REFERENCES` / `DEPENDS_ON` ← `LAMBDA_FUNCTION`<br>`REFERENCES` / `WRITES_TO` ← `MESSAGE_QUEUE`, `SCHEDULE`

#### NOTIFICATION_TOPIC

Catalog entries that classify native resources as this type:

- AWS ARN: `sns`
- Azure ARM: `microsoft.eventgrid/systemtopics`, `microsoft.eventgrid/topics`, `microsoft.insights/actiongroups`
- GCP Cloud Asset Inventory: `pubsub.googleapis.com/Topic`

- **Providers:** AWS, GCP
- **Also discovered via:** `tagging-api`
- **Metadata keys:** `create_time` (null), `description` (null), `discovered_via` (str), `fifo` (bool), `folders` (list), `gcp_asset_type` (str), `kms_key_id` (null), `location` (str), `network_tags` (list), `organization` (str), `parent_asset_type` (null), `parent_full_resource_name` (str), `policy_allows_public` (bool), `project` (str), `project_id` (str), `project_number` (str), `state` (null), `subscriptions_by_protocol` (object)
- **Carries `aliases`:** yes
- **Declared relations:** `INVOKES`, `INVOKES` / `STREAMS_TO`
- **Edges out:**<br>`INVOKES` / `STREAMS_TO` → `MESSAGE_QUEUE`<br>`INVOKES` / `TRIGGERED_BY` → `LAMBDA_FUNCTION`
- **Edges in:**<br>`CONTAINS` ← `CLOUD_ACCOUNT`<br>`INVOKES` / `INVOKES` ← `ALARM`, `DEPLOYMENT_GROUP`

#### EVENT_BUS

Catalog entries that classify native resources as this type:

- AWS ARN: `events:event-bus`
- Azure ARM: `microsoft.eventgrid/domains`, `microsoft.eventgrid/namespaces`
- GCP Cloud Asset Inventory: `eventarc.googleapis.com/Channel`

- **Providers:** AWS
- **Metadata keys:** `policy_allows_public` (bool)
- **Edges out:**<br>`CONTAINS` → `EVENT_RULE`
- **Edges in:**<br>`REFERENCES` / `READS_FROM` ← `EVENT_ARCHIVE`

#### EVENT_RULE

Catalog entries that classify native resources as this type:

- AWS ARN: `events:rule`, `glue:trigger`
- Azure ARM: `microsoft.eventgrid/systemtopics/eventsubscriptions`, `microsoft.eventgrid/topics/eventsubscriptions`, `microsoft.security/automations`
- GCP Cloud Asset Inventory: `eventarc.googleapis.com/Trigger`

- **Providers:** AWS
- **Metadata keys:** `event_bus` (str), `event_pattern` (null \| str), `kind` (str), `managed_by` (null \| str), `schedule` (null \| str), `service` (str), `state` (str), `targets` (list), `trigger_type` (str), `workflow` (null)
- **Declared relations:** `CONTAINS` ←, `INVOKES`, `INVOKES` / `INVOKES`
- **Edges out:**<br>`INVOKES` → `LAMBDA_FUNCTION`<br>`INVOKES` / `INVOKES` → `ETL_JOB`, `LAMBDA_FUNCTION`
- **Edges in:**<br>`CONTAINS` ← `EVENT_BUS`

#### STATE_MACHINE

Catalog entries that classify native resources as this type:

- AWS ARN: `states:stateMachine`
- Azure ARM: `microsoft.logic/workflows`
- GCP Cloud Asset Inventory: `workflows.googleapis.com/Workflow`

- **Providers:** AWS
- **Also discovered via:** `cloud-control`
- **Metadata keys:** `discovered_via` (str), `identifier` (str), `properties` (object), `resource_type` (str), `service` (str)

#### DATA_STREAM

Catalog entries that classify native resources as this type:

- AWS ARN: `kinesis:stream`
- Azure ARM: `microsoft.eventhub/namespaces`
- GCP Cloud Asset Inventory: `managedkafka.googleapis.com/Topic`

- **Providers:** AWS
- **Metadata keys:** `consumers` (null), `encryption` (str), `kms_key_id` (null), `mode` (str), `shards` (int), `status` (str)
- **Edges out:**<br>`INVOKES` / `TRIGGERED_BY` → `DELIVERY_STREAM`
- **Edges in:**<br>`REFERENCES` / `STREAMS_TO` ← `DYNAMODB_TABLE`

### Data services

#### CACHE_CLUSTER

Catalog entries that classify native resources as this type:

- AWS ARN: `dax:cache`, `elasticache:cluster`, `elasticache:replicationgroup`, `elasticache:serverlesscache`, `memorydb:cluster`
- AWS CloudFormation (Cloud Control): `AWS::DAX::Cluster`, `AWS::MemoryDB::Cluster`
- Azure ARM: `microsoft.cache/redis`, `microsoft.cache/redisenterprise`
- GCP Cloud Asset Inventory: `memcache.googleapis.com/Instance`, `redis.googleapis.com/Cluster`, `redis.googleapis.com/Instance`

- **Providers:** AWS
- **Metadata keys:** `acl` (str), `endpoint` (null \| str), `endpoint_encryption` (str), `engine` (null), `engine_version` (str), `kms_key_id` (null), `node_type` (str), `nodes` (int), `security_groups` (list), `service` (str), `shards` (int), `sse` (str), `status` (str), `subnet_group` (str), `tls_enabled` (bool), `vpc_id` (null \| str)
- **Carries `aliases`:** yes
- **Declared relations:** `ASSUMES_ROLE` / `RUNS_ON`, `CONTAINS` / `SUBNET_CONTAINS_INSTANCE` ←
- **Edges out:**<br>`ASSUMES_ROLE` / `RUNS_ON` → `IAM_ROLE`<br>`ATTACHED_TO` / `PROTECTED_BY_SG` → `SECURITY_GROUP`
- **Edges in:**<br>`CONTAINS` / `SUBNET_CONTAINS_INSTANCE` ← `SUBNET`

#### SEARCH_DOMAIN

Catalog entries that classify native resources as this type:

- AWS ARN: `aoss:collection`, `es:domain`
- AWS CloudFormation (Cloud Control): `AWS::OpenSearchServerless::Collection`
- Azure ARM: `microsoft.search/searchservices`

- **Providers:** AWS
- **Can be internet-exposed:** yes (`is_internet_exposed` observed `true`)
- **Metadata keys:** `aws_owned_key` (bool), `collection_id` (str), `dashboard_endpoint` (null), `endpoint` (null), `kms_key_id` (null), `network_policies` (list), `public_access` (list), `service` (str), `source_vpc_endpoints` (list), `standby_replicas` (null), `status` (null), `type` (null)
- **Carries `aliases`:** yes
- **Declared relations:** `GRANTS_ACCESS` / `POLICY_ALLOWS_ACTION` ←
- **Edges in:**<br>`GRANTS_ACCESS` / `POLICY_ALLOWS_ACTION` ← `IAM_ROLE`<br>`REFERENCES` / `READS_FROM` ← `KNOWLEDGE_BASE`

#### DATA_WAREHOUSE

Catalog entries that classify native resources as this type:

- AWS ARN: `redshift-serverless:namespace`, `redshift-serverless:workgroup`, `redshift:cluster`
- AWS CloudFormation (Cloud Control): `AWS::RedshiftServerless::Workgroup`, `AWS::Timestream::Database`
- Azure ARM: `microsoft.kusto/clusters`, `microsoft.synapse/workspaces`
- GCP Cloud Asset Inventory: `bigquery.googleapis.com/Dataset`

- **Providers:** AWS, GCP
- **Can be internet-exposed:** yes (`is_internet_exposed` observed `true`)
- **Metadata keys:** `access_entry_count` (int), `base_capacity` (null), `create_time` (null), `custom_domain` (null), `db_name` (null), `description` (null), `endpoint` (str), `enhanced_vpc_routing` (null), `folders` (list), `gcp_asset_type` (str), `iam_roles` (list), `kind` (str), `kms_key_id` (null), `location` (str), `log_exports` (list), `namespace` (str), `namespace_id` (str), `network_tags` (list), `organization` (str), `parent_asset_type` (null), `parent_full_resource_name` (str), `project` (str), `project_id` (str), `project_number` (str), `publicly_accessible` (bool), `security_groups` (list), `service` (str), `state` (null), `status` (null), `vpc_endpoints` (list), `workgroup_id` (str)
- **Carries `aliases`:** yes
- **Declared relations:** `ASSUMES_ROLE` / `RUNS_ON`, `CONTAINS` / `SUBNET_CONTAINS_INSTANCE` ←, `REFERENCES` / `DEPENDS_ON`
- **Edges out:**<br>`ASSUMES_ROLE` / `RUNS_ON` → `IAM_ROLE`<br>`ATTACHED_TO` / `PROTECTED_BY_SG` → `SECURITY_GROUP`<br>`REFERENCES` / `DEPENDS_ON` → `DATA_WAREHOUSE`
- **Edges in:**<br>`CONTAINS` ← `CLOUD_ACCOUNT`<br>`CONTAINS` / `SUBNET_CONTAINS_INSTANCE` ← `SUBNET`<br>`LOGS_TO` / `LOGS_TO` ← `LOG_SINK`<br>`REFERENCES` / `DEPENDS_ON` ← `DATA_WAREHOUSE`

#### FILE_SYSTEM

Catalog entries that classify native resources as this type:

- AWS ARN: `elasticfilesystem:file-system`, `fsx:file-system`
- AWS CloudFormation (Cloud Control): `AWS::FSx::FileSystem`
- Azure ARM: `microsoft.netapp/netappaccounts`, `microsoft.storage/storageaccounts/fileservices`
- GCP Cloud Asset Inventory: `file.googleapis.com/Instance`

- **Providers:** AWS
- **Metadata keys:** `active_directory_id` (null), `deployment_type` (str), `dns_name` (str), `file_system_id` (str), `file_system_type` (str), `kms_key_id` (null), `lifecycle` (null), `security_groups` (list), `self_managed_ad_domain` (null), `service` (str), `storage_capacity_gb` (int), `vpc_id` (null)
- **Carries `aliases`:** yes
- **Declared relations:** `CONTAINS` / `SUBNET_CONTAINS_INSTANCE` ←
- **Edges in:**<br>`CONTAINS` / `SUBNET_CONTAINS_INSTANCE` ← `SUBNET`

### DNS / deployment

#### DNS_ZONE

Catalog entries that classify native resources as this type:

- AWS ARN: `route53:hostedzone`
- Azure ARM: `microsoft.network/dnszones`, `microsoft.network/privatednszones`
- GCP Cloud Asset Inventory: `dns.googleapis.com/ManagedZone`

- **Providers:** AWS
- **Metadata keys:** `hosted_zone_id` (str), `http_name` (null), `kind` (str), `namespace_id` (str), `namespace_type` (str), `owner` (null), `private` (bool), `record_count` (int), `service` (str), `service_count` (null), `zone_id` (str)
- **Carries `aliases`:** yes
- **Declared relations:** `REFERENCES` / `DNS_RESOLVED`
- **Edges out:**<br>`CONTAINS` → `DNS_RECORD`

#### DNS_RECORD

- **Providers:** AWS
- **Can be internet-exposed:** yes (`is_internet_exposed` observed `true`)
- **Metadata keys:** `alias` (bool), `dns_records` (list), `health_check` (null), `instance_count` (null), `kind` (str), `namespace_id` (str), `private_zone` (bool), `record_type` (str), `routing_policy` (null \| str), `service` (str), `service_id` (str), `service_type` (null), `values` (list)
- **Carries `aliases`:** yes
- **Declared relations:** `CONTAINS` ←, `ROUTE` / `DNS_RESOLVED`
- **Edges out:**<br>`ROUTE` / `DNS_RESOLVED` → `CLOUDFRONT`, `CUSTOM_DOMAIN`, `LOAD_BALANCER`
- **Edges in:**<br>`CONTAINS` ← `DNS_ZONE`<br>`REFERENCES` / `DNS_RESOLVED` ← `CONTAINER_SERVICE`

#### IAC_STACK

CloudFormation stack.

Catalog entries that classify native resources as this type:

- AWS ARN: `cloudformation:stack`

- **Providers:** AWS
- **Metadata keys:** —
- **Declared relations:** `MANAGES`
- **Edges out:**<br>`MANAGES` → `SECURITY_GROUP`
- **Edges in:**<br>`MANAGES` / `OWNED_BY` ← `PROVISIONED_PRODUCT`, `STACK_SET`

### Security services and scanners

#### WAF_WEB_ACL

Catalog entries that classify native resources as this type:

- AWS ARN: `wafv2:webacl`
- Azure ARM: `microsoft.cdn/cdnwebapplicationfirewallpolicies`, `microsoft.network/applicationgatewaywebapplicationfirewallpolicies`, `microsoft.network/frontdoorwebapplicationfirewallpolicies`
- GCP Cloud Asset Inventory: `compute.googleapis.com/NetworkEdgeSecurityService`, `compute.googleapis.com/RegionSecurityPolicy`, `compute.googleapis.com/SecurityPolicy`

- **Providers:** AWS, AZURE, GCP
- **Metadata keys:** `adaptive_protection` (bool), `collected_via` (str), `create_time` (null), `description` (null), `folders` (list), `gcp_asset_type` (str), `kind` (null), `location` (str), `network_tags` (list), `organization` (str), `parent_asset_type` (null), `parent_full_resource_name` (str), `project` (str), `project_id` (str), `project_number` (str), `properties` (object), `resource_group` (str), `resource_type` (str), `rule_count` (int), `sku` (null), `state` (null)
- **Carries `aliases`:** yes
- **Declared relations:** `CONTAINS` ←
- **Edges out:**<br>`PROTECTS` / `PROTECTED_BY_WAF` → `LOAD_BALANCER`
- **Edges in:**<br>`CONTAINS` ← `CLOUD_ACCOUNT`, `RESOURCE_GROUP`

#### NETWORK_FIREWALL

Catalog entries that classify native resources as this type:

- AWS ARN: `network-firewall:firewall`
- Azure ARM: `microsoft.network/azurefirewalls`, `microsoft.network/firewallpolicies`

- **Providers:** AWS, AZURE
- **Can be internet-exposed:** yes (`is_internet_exposed` observed `true`)
- **Metadata keys:** `associations` (list), `collected_via` (str), `kind` (null), `owner_id` (str), `private_ip` (str), `properties` (object), `resource_group` (str), `resource_kind` (str), `resource_type` (str), `share_status` (null), `sku` (null)
- **Carries `aliases`:** yes
- **Declared relations:** `ATTACHED_TO` ←, `CONTAINS` ←, `CONTAINS` / `SUBNET_CONTAINS_INSTANCE` ←, `PROTECTS` / `PROTECTED_BY_NACL`
- **Edges out:**<br>`PROTECTS` / `PROTECTED_BY_NACL` → `VPC`
- **Edges in:**<br>`ATTACHED_TO` ← `ELASTIC_IP`<br>`CONTAINS` ← `RESOURCE_GROUP`<br>`CONTAINS` / `SUBNET_CONTAINS_INSTANCE` ← `SUBNET`<br>`LOAD_BALANCER_TARGET` / `LB_TARGETS_INSTANCE` ← `LOAD_BALANCER`<br>`ROUTE` / `TRANSIT_ROUTED` ← `ROUTE_TABLE`

#### DDOS_PROTECTION

Catalog entries that classify native resources as this type:

- Azure ARM: `microsoft.network/ddosprotectionplans`

- **Providers:** AWS
- **Metadata keys:** `auto_renew` (str), `enabled` (bool), `proactive_engagement` (str), `protections` (int), `security_service` (str)

#### THREAT_DETECTOR

GuardDuty, Detective.

Catalog entries that classify native resources as this type:

- AWS ARN: `guardduty:detector`
- Azure ARM: `microsoft.security/pricings`, `microsoft.securityinsights/settings`

- **Providers:** AWS, AZURE
- **Metadata keys:** `administrator_account` (null), `enabled` (bool), `features` (object), `finding_frequency` (str), `pricing_tier` (str), `resource_type` (str), `security_service` (str), `status` (str), `sub_plan` (null \| str)
- **Carries `aliases`:** yes
- **Declared relations:** `MONITORS` / `MONITORED_BY`
- **Edges out:**<br>`MONITORS` / `MONITORED_BY` → `CLOUD_ACCOUNT`

#### SECURITY_HUB

Catalog entries that classify native resources as this type:

- AWS ARN: `securityhub:hub`

- **Providers:** AWS
- **Metadata keys:** `enabled` (bool), `security_service` (str), `status` (str)
- **Carries `aliases`:** yes

#### VULNERABILITY_SCANNER

Inspector.

- **Providers:** AWS
- **Metadata keys:** `enabled` (bool), `security_service` (str), `status` (str)
- **Carries `aliases`:** yes

#### DATA_SECURITY_SCANNER

Macie.

- **Providers:** AWS
- **Metadata keys:** `enabled` (bool), `finding_frequency` (str), `security_service` (str), `service_role` (str)
- **Carries `aliases`:** yes
- **Declared relations:** `ASSUMES_ROLE` / `RUNS_ON`, `MONITORS` / `MONITORED_BY`
- **Edges out:**<br>`MONITORS` / `MONITORED_BY` → `CLOUD_ACCOUNT`

#### CONFIG_RECORDER

- **Providers:** AWS
- **Metadata keys:** `enabled` (bool), `security_service` (str), `status` (str)
- **Carries `aliases`:** yes

#### ACCESS_ANALYZER

Catalog entries that classify native resources as this type:

- AWS ARN: `access-analyzer:analyzer`

*Not exercised by the fixtures.* Produced by collectors or catalogs for resources the
test estates do not contain; carries the common keys above plus collector-specific fields.

### Organization / governance

#### ORGANIZATION

Catalog entries that classify native resources as this type:

- GCP Cloud Asset Inventory: `cloudresourcemanager.googleapis.com/Organization`

- **Providers:** AWS, GCP
- **Metadata keys:** `control_tower` (bool), `create_time` (null), `delegated_administrators` (object), `description` (null), `directory_customer_id_present` (bool), `display_name` (str), `enabled_services` (list), `feature_set` (str), `folders` (list), `gcp_asset_type` (str), `location` (str), `management_account_id` (str), `network_tags` (list), `organization` (str), `organization_id` (str), `parent_asset_type` (null), `parent_full_resource_name` (str), `project` (null), `project_id` (null), `project_number` (null), `state` (null)
- **Carries `aliases`:** yes
- **Declared relations:** `MANAGES` / `OWNED_BY` ←
- **Edges out:**<br>`CONTAINS` → `ORG_UNIT`<br>`CONTAINS` / `ORG_CONTAINS_ACCOUNT` → `CLOUD_ACCOUNT`, `ORG_UNIT`
- **Edges in:**<br>`CONTAINS` ← `CLOUD_ACCOUNT`<br>`MANAGES` / `COMPLIANCE_GOVERNS` ← `LANDING_ZONE`<br>`MANAGES` / `OWNED_BY` ← `CLOUD_ACCOUNT`

#### ORG_UNIT

Catalog entries that classify native resources as this type:

- Azure ARM: `microsoft.management/managementgroups`
- GCP Cloud Asset Inventory: `cloudresourcemanager.googleapis.com/Folder`

- **Providers:** AWS, AZURE, GCP
- **Metadata keys:** `alz_archetype` (str), `ancestors` (list), `create_time` (null), `description` (null), `display_name` (str), `folders` (list), `gcp_asset_type` (str), `is_root` (bool), `is_tenant_root` (bool), `landing_zone` (bool), `location` (str), `management_group_id` (str), `network_tags` (list), `organization` (str), `ou_id` (str), `parent_asset_type` (null), `parent_full_resource_name` (str), `parent_management_group` (str), `path` (list), `project` (null), `project_id` (null), `project_number` (null), `resource_type` (str), `state` (null), `tenant_id` (str)
- **Carries `aliases`:** yes
- **Declared relations:** `CONTAINS` ←, `CONTAINS` / `ORG_CONTAINS_ACCOUNT` ←
- **Edges out:**<br>`CONTAINS` → `ORG_UNIT`<br>`CONTAINS` / `ORG_CONTAINS_ACCOUNT` → `CLOUD_ACCOUNT`, `ORG_UNIT`<br>`GRANTS_ACCESS` / `CROSS_ACCOUNT_TRUST` → `RESOURCE_SHARE`
- **Edges in:**<br>`CONTAINS` ← `ORGANIZATION`, `ORG_UNIT`<br>`CONTAINS` / `ORG_CONTAINS_ACCOUNT` ← `ORGANIZATION`, `ORG_UNIT`<br>`GOVERNS` / `COMPLIANCE_GOVERNS` ← `GUARDRAIL`, `ORG_POLICY`<br>`GOVERNS` / `SCP_RESTRICTS` ← `ORG_POLICY`

#### CLOUD_ACCOUNT

Catalog entries that classify native resources as this type:

- Azure ARM: `microsoft.resources/subscriptions`
- GCP Cloud Asset Inventory: `cloudresourcemanager.googleapis.com/Project`

- **Providers:** AWS, AZURE, GCP
- **Also discovered via:** `azure-subscription`, `collection scope`, `cross-account reference`
- **Metadata keys:** `account_id` (str), `control_tower_role` (null \| str), `create_time` (null), `delegated_admin_for` (list), `description` (null), `discovered_via` (str), `display_name` (null \| str), `email` (str), `external` (bool), `folders` (list), `gcp_asset_type` (str), `joined` (str), `joined_method` (str), `lifecycle_state` (str), `location` (str), `management_account` (bool), `management_group_path` (list), `network_tags` (list), `organization` (str), `ou_path` (list), `parent_asset_type` (null), `parent_full_resource_name` (str), `parent_management_group` (str), `project` (str), `project_id` (str), `project_number` (str), `resource_type` (str), `state` (null \| str), `status` (str), `subscription_id` (str), `tenant_id` (null \| str)
- **Carries `aliases`:** yes
- **Declared relations:** `CONTAINS` / `ORG_CONTAINS_ACCOUNT` ←
- **Edges out:**<br>`CONTAINS` → `AUTOSCALING_GROUP`, `CERTIFICATE`, `CLOUD_SQL`, `CONTAINER_REGISTRY`, `CONTAINER_SERVICE`, `DATA_WAREHOUSE`, `EBS_VOLUME`, `ELASTIC_IP`, `GCE_INSTANCE`, `GCS_BUCKET`, `GKE_CLUSTER`, `KMS_KEY`, `LOAD_BALANCER`, `LOG_SINK`, `MESSAGE_QUEUE`, `NODE_GROUP`, `NOTIFICATION_TOPIC`, `ORGANIZATION`, `ORG_POLICY`, `SECRET`, `SECURITY_GROUP`, `SERVICE_PRINCIPAL`, `SUBNET`, `TARGET_GROUP`, `VPC`, `VPC_LINK`, `WAF_WEB_ACL`<br>`CONTAINS` / `ACCOUNT_CONTAINS_REGION` → `RESOURCE_GROUP`<br>`GRANTS_ACCESS` / `CROSS_ACCOUNT_TRUST` → `DYNAMODB_TABLE`, `KMS_KEY`, `MACHINE_IMAGE`, `RESOURCE_SHARE`, `SECRET`, `SNAPSHOT`<br>`GRANTS_ACCESS` / `POLICY_ALLOWS_ACTION` → `BACKUP_VAULT`, `DATA_CATALOG`, `ENDPOINT_SERVICE`, `LOG_SINK`, `MESSAGE_BROKER`, `RUNBOOK`<br>`IAM_TRUST` → `IAM_ROLE`<br>`IAM_TRUST` / `CROSS_ACCOUNT_TRUST` → `IAM_ROLE`<br>`MANAGES` / `OWNED_BY` → `ORGANIZATION`, `RESOURCE_SHARE`<br>`ROUTE` / `SERVES_TRAFFIC_TO` → `ENDPOINT_SERVICE`
- **Edges in:**<br>`ASSUMES_ROLE` / `RUNS_ON` ← `CI_PIPELINE`<br>`CONTAINS` / `ORG_CONTAINS_ACCOUNT` ← `ORGANIZATION`, `ORG_UNIT`<br>`GOVERNS` / `COMPLIANCE_GOVERNS` ← `GUARDRAIL`, `ORG_POLICY`<br>`GOVERNS` / `SCP_RESTRICTS` ← `ORG_POLICY`<br>`GRANTS_ACCESS` / `DEPENDS_ON` ← `RESOURCE_SHARE`<br>`GRANTS_ACCESS` / `POLICY_ALLOWS_ACTION` ← `IDENTITY_GROUP`, `IDENTITY_USER`, `SERVICE_PRINCIPAL`<br>`INVOKES` / `STREAMS_TO` ← `LOG_SINK`<br>`MANAGES` / `OWNED_BY` ← `LANDING_ZONE`, `PERMISSION_SET`, `PROVISIONED_PRODUCT`, `STACK_SET`<br>`MONITORS` / `MONITORED_BY` ← `DATA_SECURITY_SCANNER`, `THREAT_DETECTOR`<br>`PEERING` / `TRANSIT_ROUTED` ← `PEERING_CONNECTION`<br>`PEERING` / `VPC_PEERED` ← `VNET`<br>`REFERENCES` ← `KMS_KEY`, `VPC`<br>`REFERENCES` / `BACKUP_TO` ← `BACKUP_PLAN`<br>`REFERENCES` / `DEPENDS_ON` ← `IDENTITY_PROVIDER`<br>`ROUTE` / `TRANSIT_ROUTED` ← `DIRECT_CONNECT`

#### ORG_POLICY

SCP, RCP, tag/backup policy.

Catalog entries that classify native resources as this type:

- GCP Cloud Asset Inventory: `orgpolicy.googleapis.com/Policy`

- **Providers:** AWS, GCP
- **Metadata keys:** `attached_to` (str), `aws_managed` (bool), `constraint` (str), `create_time` (null), `description` (null), `dry_run` (bool), `enforced` (bool), `folders` (list), `gcp_asset_type` (str), `location` (str), `network_tags` (list), `organization` (str), `parent_asset_type` (null), `parent_full_resource_name` (str), `policy_id` (str), `policy_type` (str), `project` (str), `project_id` (str), `project_number` (str), `rules` (list), `state` (null), `target_count` (int)
- **Carries `aliases`:** yes
- **Declared relations:** `GOVERNS` / `COMPLIANCE_GOVERNS`, `GOVERNS` / `SCP_RESTRICTS`
- **Edges out:**<br>`GOVERNS` / `COMPLIANCE_GOVERNS` → `CLOUD_ACCOUNT`, `ORG_UNIT`<br>`GOVERNS` / `SCP_RESTRICTS` → `CLOUD_ACCOUNT`, `ORG_UNIT`
- **Edges in:**<br>`CONTAINS` ← `CLOUD_ACCOUNT`

#### LANDING_ZONE

- **Providers:** AWS
- **Metadata keys:** `drift_status` (null), `governed_regions` (list), `home_region` (str), `latest_available_version` (null), `shared_accounts` (object), `status` (str), `version` (str)
- **Declared relations:** `MANAGES` / `COMPLIANCE_GOVERNS`, `MANAGES` / `OWNED_BY`
- **Edges out:**<br>`MANAGES` / `COMPLIANCE_GOVERNS` → `ORGANIZATION`<br>`MANAGES` / `OWNED_BY` → `CLOUD_ACCOUNT`

#### GUARDRAIL

Control Tower control / baseline, policy assignment, perimeter.

Catalog entries that classify native resources as this type:

- Azure ARM: `microsoft.authorization/policyassignments`, `microsoft.authorization/policyexemptions`
- GCP Cloud Asset Inventory: `accesscontextmanager.googleapis.com/ServicePerimeter`

- **Providers:** AWS, AZURE, GCP
- **Metadata keys:** `access_levels` (list), `access_policy` (str), `assignment_identity` (str), `control_identifier` (str), `drift_status` (null), `dry_run_restricted_services` (list), `egress_policy_count` (int), `enforced` (bool), `enforcement_mode` (str), `exemption` (bool), `exemption_category` (str), `gcp_asset_type` (str), `guardrail_kind` (str), `ingress_policy_count` (int), `initiative` (bool), `kind` (str), `member_count` (int), `not_scopes` (list), `perimeter_type` (str), `policy_assignment_id` (str), `policy_definition_id` (str), `resource_type` (str), `restricted_services` (list), `scope` (str), `status` (str), `title` (str), `uses_dry_run_spec` (bool), `vpc_accessible_services_restricted` (bool), `vpc_allowed_services` (list)
- **Carries `aliases`:** yes
- **Declared relations:** `GOVERNS` / `COMPLIANCE_GOVERNS`, `REFERENCES` / `DEPENDS_ON`
- **Edges out:**<br>`GOVERNS` / `COMPLIANCE_GOVERNS` → `CLOUD_ACCOUNT`, `ORG_UNIT`, `RESOURCE_GROUP`<br>`REFERENCES` → `RESOURCE_GROUP`<br>`REFERENCES` / `DEPENDS_ON` → `GUARDRAIL`
- **Edges in:**<br>`REFERENCES` / `DEPENDS_ON` ← `GUARDRAIL`

#### RESOURCE_GROUP

Azure resource group.

Catalog entries that classify native resources as this type:

- Azure ARM: `microsoft.resources/resourcegroups`, `microsoft.resources/subscriptions/resourcegroups`

- **Providers:** AZURE
- **Also discovered via:** `arm-sweep`
- **Metadata keys:** `collected_via` (str), `discovered_via` (str), `kind` (null), `managed_by` (str), `properties` (object), `resource_group` (str), `resource_type` (str), `sku` (null)
- **Declared relations:** `CONTAINS` / `ACCOUNT_CONTAINS_REGION` ←, `MANAGES` / `OWNED_BY` ←
- **Edges out:**<br>`CONTAINS` → `AKS_CLUSTER`, `APP_SERVICE`, `AUTOSCALING_GROUP`, `AZURE_SQL`, `BLOB_STORAGE`, `CLOUD_FUNCTION`, `CONTAINER_REGISTRY`, `EBS_VOLUME`, `ELASTIC_IP`, `KEY_VAULT`, `KMS_KEY`, `LOAD_BALANCER`, `LOG_GROUP`, `NETWORK_FIREWALL`, `NETWORK_INTERFACE`, `NSG`, `ROUTE_TABLE`, `SECURITY_GROUP`, `SERVICE_PRINCIPAL`, `VIRTUAL_MACHINE`, `VNET`, `VPC_ENDPOINT`, `WAF_WEB_ACL`
- **Edges in:**<br>`CONTAINS` / `ACCOUNT_CONTAINS_REGION` ← `CLOUD_ACCOUNT`<br>`GOVERNS` / `COMPLIANCE_GOVERNS` ← `GUARDRAIL`<br>`MANAGES` / `OWNED_BY` ← `AKS_CLUSTER`<br>`REFERENCES` ← `GUARDRAIL`

### Identity federation and access

#### PERMISSION_SET

IAM Identity Center.

Catalog entries that classify native resources as this type:

- AWS ARN: `sso:permissionSet`
- AWS CloudFormation (Cloud Control): `AWS::SSO::PermissionSet`

- **Providers:** AWS
- **Metadata keys:** `accept_role_session_name` (null), `assignment_count` (int), `created` (str), `customer_managed_policies` (list), `description` (null), `duration_seconds` (null), `enabled` (bool), `has_inline_policy` (bool), `has_session_policy` (bool), `instance_arn` (str), `is_admin` (bool), `managed_policies` (list), `managed_policy_arns` (list), `permissions_boundary` (null), `principal_count` (int), `profile_id` (str), `profile_type` (str), `provisioned_accounts` (list), `provisioned_role_path` (str), `provisioned_role_prefix` (str), `require_instance_properties` (null), `role_arns` (list), `session_duration` (int)
- **Carries `aliases`:** yes
- **Declared relations:** `ASSUMES_ROLE` / `ROLE_ASSUMES_ROLE`, `ASSUMES_ROLE` / `ROLE_ASSUMES_ROLE` ←, `CONTAINS` ←, `IAM_POLICY_ATTACHMENT` / `ROLE_HAS_POLICY`, `IAM_TRUST` / `ROLE_ASSUMES_ROLE` ←, `MANAGES` / `OWNED_BY`
- **Edges out:**<br>`ASSUMES_ROLE` / `ROLE_ASSUMES_ROLE` → `IAM_ROLE`<br>`MANAGES` / `OWNED_BY` → `CLOUD_ACCOUNT`, `IAM_ROLE`
- **Edges in:**<br>`ASSUMES_ROLE` / `ROLE_ASSUMES_ROLE` ← `IDENTITY_GROUP`<br>`CONTAINS` ← `IDENTITY_PROVIDER`<br>`IAM_TRUST` / `ROLE_ASSUMES_ROLE` ← `IDENTITY_PROVIDER`

#### IDENTITY_USER

Identity Center / Entra / workforce user.

- **Providers:** AWS, AZURE, GCP
- **Also discovered via:** `entra-principal-reference`, `iam_policy`
- **Metadata keys:** `assigned_accounts` (list), `discovered_via` (str), `display_name` (str), `external_issuers` (list), `has_session_policy` (bool), `home_directory` (str), `home_directory_type` (null), `identity_store_id` (str), `member` (str), `placeholder` (bool), `principal_id` (str), `principal_type` (str), `server_id` (str), `service` (str), `ssh_key_count` (int), `user_id` (str), `user_name` (str), `user_type` (null)
- **Carries `aliases`:** yes
- **Declared relations:** `ASSUMES_ROLE` / `RUNS_ON`, `CONTAINS` ←, `REFERENCES` / `READS_FROM`
- **Edges out:**<br>`ASSUMES_ROLE` / `ROLE_ASSUMES_ROLE` → `SERVICE_PRINCIPAL`<br>`ASSUMES_ROLE` / `RUNS_ON` → `IAM_ROLE`<br>`GRANTS_ACCESS` / `POLICY_ALLOWS_ACTION` → `CLOUD_ACCOUNT`<br>`REFERENCES` / `READS_FROM` → `S3_BUCKET`
- **Edges in:**<br>`CONTAINS` ← `DATA_TRANSFER`, `IDENTITY_GROUP`, `IDENTITY_PROVIDER`

#### IDENTITY_GROUP

- **Providers:** AWS, GCP
- **Also discovered via:** `iam_policy`
- **Metadata keys:** `assigned_accounts` (list), `description` (null), `discovered_via` (str), `external_issuers` (list), `group_id` (str), `identity_store_id` (str), `member` (str), `member_count` (int), `placeholder` (bool), `principal_type` (str)
- **Carries `aliases`:** yes
- **Declared relations:** `CONTAINS` ←, `GRANTS_ACCESS` / `POLICY_ALLOWS_ACTION`
- **Edges out:**<br>`ASSUMES_ROLE` / `ROLE_ASSUMES_ROLE` → `PERMISSION_SET`<br>`CONTAINS` → `IDENTITY_USER`<br>`GRANTS_ACCESS` / `POLICY_ALLOWS_ACTION` → `CLOUD_ACCOUNT`
- **Edges in:**<br>`CONTAINS` ← `IDENTITY_PROVIDER`

#### ACCESS_KEY

IAM access key, service account key.

Catalog entries that classify native resources as this type:

- GCP Cloud Asset Inventory: `apikeys.googleapis.com/Key`, `iam.googleapis.com/ServiceAccountKey`

- **Providers:** AWS
- **Metadata keys:** `access_key_id` (str), `age_days` (int), `created` (str), `last_used` (null), `last_used_region` (str), `last_used_service` (str), `never_used` (bool), `stale` (bool), `status` (str), `user_arn` (str), `user_name` (str)
- **Declared relations:** `CONTAINS` ←
- **Edges in:**<br>`CONTAINS` ← `IAM_USER`

#### USER_POOL

Cognito user pool, B2C.

Catalog entries that classify native resources as this type:

- AWS ARN: `cognito-idp:userpool`
- AWS CloudFormation (Cloud Control): `AWS::Cognito::UserPool`

- **Providers:** AWS
- **Can be internet-exposed:** yes (`is_internet_exposed` observed `true`)
- **Metadata keys:** `advanced_security` (null), `app_client_count` (int), `created` (str), `custom_domain` (null), `deletion_protection` (null), `domain` (null), `estimated_users` (int), `identity_providers` (list), `lambda_triggers` (object), `mfa` (str), `self_signup_enabled` (bool), `status` (null), `tier` (null), `user_pool_id` (str)
- **Carries `aliases`:** yes
- **Declared relations:** `INVOKES` / `INVOKES`
- **Edges out:**<br>`INVOKES` / `INVOKES` → `LAMBDA_FUNCTION`
- **Edges in:**<br>`REFERENCES` / `DEPENDS_ON` ← `IDENTITY_POOL`

#### IDENTITY_POOL

Catalog entries that classify native resources as this type:

- AWS ARN: `cognito-identity:identitypool`
- AWS CloudFormation (Cloud Control): `AWS::Cognito::IdentityPool`

- **Providers:** AWS
- **Can be internet-exposed:** yes (`is_internet_exposed` observed `true`)
- **Metadata keys:** `allow_classic_flow` (null), `allow_unauthenticated` (bool), `authenticated_role` (null \| str), `cognito_providers` (list), `developer_provider` (null), `identity_pool_id` (str), `login_providers` (list), `unauthenticated_role` (null \| str)
- **Carries `aliases`:** yes
- **Declared relations:** `ASSUMES_ROLE` / `ROLE_ASSUMES_ROLE`, `REFERENCES` / `DEPENDS_ON`
- **Edges out:**<br>`ASSUMES_ROLE` / `ROLE_ASSUMES_ROLE` → `IAM_ROLE`<br>`REFERENCES` / `DEPENDS_ON` → `USER_POOL`

#### RESOURCE_SHARE

AWS RAM.

Catalog entries that classify native resources as this type:

- AWS ARN: `ram:resource-share`
- AWS CloudFormation (Cloud Control): `AWS::RAM::ResourceShare`

- **Providers:** AWS
- **Also discovered via:** `ram-incoming`
- **Metadata keys:** `allow_external_principals` (bool \| null), `created` (null), `direction` (str), `discovered_via` (str), `external_principals` (bool), `feature_set` (null), `owning_account_id` (str), `principals` (list), `resource_count` (int), `resource_types` (list), `status` (str)
- **Declared relations:** `GRANTS_ACCESS` / `CROSS_ACCOUNT_TRUST` ←, `GRANTS_ACCESS` / `DEPENDS_ON`, `MANAGES` / `OWNED_BY` ←
- **Edges out:**<br>`GRANTS_ACCESS` / `DEPENDS_ON` → `CLOUD_ACCOUNT`, `SUBNET`
- **Edges in:**<br>`GRANTS_ACCESS` / `CROSS_ACCOUNT_TRUST` ← `CLOUD_ACCOUNT`, `ORG_UNIT`<br>`MANAGES` / `OWNED_BY` ← `CLOUD_ACCOUNT`

### Deployment / provisioning

#### STACK_SET

Catalog entries that classify native resources as this type:

- AWS ARN: `cloudformation:stackset`
- AWS CloudFormation (Cloud Control): `AWS::CloudFormation::StackSet`

- **Providers:** AWS
- **Metadata keys:** `accounts` (list), `administration_role` (str), `auto_deployment` (bool), `call_as` (str), `capabilities` (list), `control_tower` (bool), `description` (null), `drift_status` (null), `execution_role_name` (str), `instance_count` (int), `instance_status` (object), `organizational_unit_ids` (list), `permission_model` (str), `regions` (list), `retain_on_account_removal` (null), `stack_set_id` (str), `status` (str)
- **Carries `aliases`:** yes
- **Declared relations:** `ASSUMES_ROLE` / `RUNS_ON`, `MANAGES` / `OWNED_BY`
- **Edges out:**<br>`MANAGES` / `OWNED_BY` → `CLOUD_ACCOUNT`, `IAC_STACK`

#### PROVISIONED_PRODUCT

Service Catalog / Account Factory.

Catalog entries that classify native resources as this type:

- AWS ARN: `servicecatalog:stack`
- AWS CloudFormation (Cloud Control): `AWS::ServiceCatalog::CloudFormationProvisionedProduct`

- **Providers:** AWS
- **Metadata keys:** `control_tower_account_factory` (bool), `created` (null), `launch_role` (str), `output_keys` (list), `physical_id` (str), `product_id` (str), `product_name` (str), `provisioned_by` (null), `provisioned_product_id` (str), `provisioning_artifact` (null), `status` (str), `type` (str), `vended_account_id` (str)
- **Carries `aliases`:** yes
- **Declared relations:** `ASSUMES_ROLE` / `RUNS_ON`, `MANAGES` / `OWNED_BY`, `REFERENCES` / `DEPENDS_ON`
- **Edges out:**<br>`ASSUMES_ROLE` / `RUNS_ON` → `IAM_ROLE`<br>`MANAGES` / `OWNED_BY` → `CLOUD_ACCOUNT`, `IAC_STACK`<br>`REFERENCES` / `DEPENDS_ON` → `PRODUCT_PORTFOLIO`

#### PRODUCT_PORTFOLIO

Catalog entries that classify native resources as this type:

- AWS ARN: `catalog:portfolio`
- AWS CloudFormation (Cloud Control): `AWS::ServiceCatalog::Portfolio`

- **Providers:** AWS
- **Metadata keys:** `control_tower` (bool), `created` (null), `description` (null), `portfolio_id` (str), `principals` (list), `products` (list), `provider` (str), `shared_accounts` (list)
- **Carries `aliases`:** yes
- **Declared relations:** `GRANTS_ACCESS` / `POLICY_ALLOWS_ACTION` ←
- **Edges in:**<br>`GRANTS_ACCESS` / `POLICY_ALLOWS_ACTION` ← `IAM_ROLE`<br>`REFERENCES` / `DEPENDS_ON` ← `PROVISIONED_PRODUCT`

#### CI_PIPELINE

Catalog entries that classify native resources as this type:

- AWS ARN: `codepipeline`
- AWS CloudFormation (Cloud Control): `AWS::CodePipeline::Pipeline`
- GCP Cloud Asset Inventory: `clouddeploy.googleapis.com/DeliveryPipeline`

- **Providers:** AWS
- **Metadata keys:** `artifact_buckets` (list), `cross_account_actions` (int), `execution_mode` (null), `pipeline_type` (null), `providers` (list), `service` (str), `stages` (list), `trigger_providers` (list), `updated` (str), `variable_names` (list), `version` (int)
- **Declared relations:** `ASSUMES_ROLE` / `RUNS_ON`, `INVOKES` / `INVOKES`, `REFERENCES` / `READS_FROM`, `REFERENCES` / `WRITES_TO`
- **Edges out:**<br>`ASSUMES_ROLE` / `RUNS_ON` → `CLOUD_ACCOUNT`, `IAM_ROLE`<br>`INVOKES` / `INVOKES` → `BUILD_PROJECT`<br>`REFERENCES` / `READS_FROM` → `SOURCE_CONNECTION`<br>`REFERENCES` / `WRITES_TO` → `S3_BUCKET`

#### BUILD_PROJECT

Catalog entries that classify native resources as this type:

- AWS ARN: `codebuild:project`
- AWS CloudFormation (Cloud Control): `AWS::CodeBuild::Project`
- GCP Cloud Asset Inventory: `cloudbuild.googleapis.com/BuildTrigger`

- **Providers:** AWS
- **Metadata keys:** `badge_enabled` (bool), `compute_type` (str), `concurrent_build_limit` (null), `encryption_key` (str), `environment_type` (str), `environment_variable_names` (list), `environment_variable_types` (object), `image` (str), `image_pull_credentials` (null), `privileged_mode` (bool), `secondary_sources` (list), `service` (str), `service_role` (str), `source_location` (str), `source_type` (str), `timeout_minutes` (int), `visibility` (null), `vpc_config` (null), `vpc_id` (null), `webhook_enabled` (bool), `webhook_filter_groups` (int)
- **Declared relations:** `ASSUMES_ROLE` / `RUNS_ON`, `LOGS_TO` / `LOGS_TO`, `REFERENCES` / `ENCRYPTED_BY_KMS`, `REFERENCES` / `READS_FROM`, `REFERENCES` / `WRITES_TO`, `USES_IMAGE` / `RUNS_ON`
- **Edges out:**<br>`ASSUMES_ROLE` / `RUNS_ON` → `IAM_ROLE`<br>`REFERENCES` / `READS_FROM` → `PARAMETER`, `S3_BUCKET`<br>`USES_IMAGE` / `RUNS_ON` → `CONTAINER_REGISTRY`
- **Edges in:**<br>`INVOKES` / `INVOKES` ← `CI_PIPELINE`

#### DEPLOYMENT_GROUP

Catalog entries that classify native resources as this type:

- AWS ARN: `codedeploy:deploymentgroup`
- AWS CloudFormation (Cloud Control): `AWS::CodeDeploy::DeploymentGroup`
- GCP Cloud Asset Inventory: `clouddeploy.googleapis.com/Target`

- **Providers:** AWS
- **Metadata keys:** `application_name` (str), `auto_rollback` (bool), `auto_scaling_groups` (list), `compute_platform` (str), `deployment_config` (null), `deployment_group_id` (str), `deployment_style` (null), `ecs_services` (list), `github_repository` (null), `last_successful_deployment` (null), `revision_type` (null), `service` (str), `tag_filters` (list)
- **Carries `aliases`:** yes
- **Declared relations:** `ASSUMES_ROLE` / `RUNS_ON`, `INVOKES` / `INVOKES`, `MANAGES`, `REFERENCES` / `MONITORED_BY`
- **Edges out:**<br>`ASSUMES_ROLE` / `RUNS_ON` → `IAM_ROLE`<br>`INVOKES` / `INVOKES` → `NOTIFICATION_TOPIC`<br>`MANAGES` → `AUTOSCALING_GROUP`, `CONTAINER_SERVICE`, `TARGET_GROUP`<br>`REFERENCES` / `MONITORED_BY` → `ALARM`

### Images, snapshots, backups

#### MACHINE_IMAGE

Catalog entries that classify native resources as this type:

- AWS ARN: `ec2:image`
- AWS CloudFormation (Cloud Control): `AWS::EC2::Image`
- Azure ARM: `microsoft.compute/galleries/images`, `microsoft.compute/galleries/images/versions`, `microsoft.compute/images`
- GCP Cloud Asset Inventory: `compute.googleapis.com/Image`, `compute.googleapis.com/MachineImage`

- **Providers:** AWS
- **Metadata keys:** `architecture` (str), `created` (str), `deprecation_time` (null), `encrypted` (bool), `image_id` (str), `imds_support` (null), `last_launched` (null), `platform` (str), `public` (bool), `root_device_type` (str), `shared_accounts` (list), `shared_organizations` (list), `sharing_known` (bool), `snapshots` (list), `source_image_id` (null), `state` (str)
- **Carries `aliases`:** yes
- **Declared relations:** `GRANTS_ACCESS` / `CROSS_ACCOUNT_TRUST` ←, `REFERENCES`, `REFERENCES` / `DEPENDS_ON`
- **Edges out:**<br>`REFERENCES` / `DEPENDS_ON` → `SNAPSHOT`
- **Edges in:**<br>`GRANTS_ACCESS` / `CROSS_ACCOUNT_TRUST` ← `CLOUD_ACCOUNT`

#### SNAPSHOT

Catalog entries that classify native resources as this type:

- AWS ARN: `ec2:snapshot`, `rds:cluster-snapshot`, `rds:snapshot`
- AWS CloudFormation (Cloud Control): `AWS::EC2::Snapshot`
- Azure ARM: `microsoft.compute/snapshots`
- GCP Cloud Asset Inventory: `compute.googleapis.com/Snapshot`, `file.googleapis.com/Backup`, `pubsub.googleapis.com/Snapshot`

- **Providers:** AWS
- **Can be internet-exposed:** yes (`is_internet_exposed` observed `true`)
- **Metadata keys:** `created` (str), `description` (null \| str), `encrypted` (bool), `engine` (str), `engine_version` (str), `kms_key_id` (null \| str), `public` (bool), `shared_accounts` (list), `sharing_known` (bool), `size_gb` (int), `snapshot_id` (str), `snapshot_type` (str), `source_identifier` (str), `source_volume_id` (str), `started` (str), `state` (str), `status` (str), `storage_tier` (str), `vpc_id` (null)
- **Carries `aliases`:** yes
- **Declared relations:** `GRANTS_ACCESS` / `CROSS_ACCOUNT_TRUST` ←, `REFERENCES`, `REFERENCES` / `ENCRYPTED_BY_KMS`
- **Edges out:**<br>`REFERENCES` → `AURORA_CLUSTER`, `EBS_VOLUME`, `RDS_INSTANCE`
- **Edges in:**<br>`GRANTS_ACCESS` / `CROSS_ACCOUNT_TRUST` ← `CLOUD_ACCOUNT`<br>`REFERENCES` / `DEPENDS_ON` ← `MACHINE_IMAGE`

#### BACKUP_PLAN

Catalog entries that classify native resources as this type:

- AWS ARN: `backup:backup-plan`
- AWS CloudFormation (Cloud Control): `AWS::Backup::BackupPlan`
- GCP Cloud Asset Inventory: `compute.googleapis.com/ResourcePolicy`

- **Providers:** AWS
- **Metadata keys:** `advanced_settings` (list), `last_execution` (null), `plan_id` (str), `rules` (list), `selections` (list), `service` (str), `version_id` (null \| str)
- **Carries `aliases`:** yes
- **Declared relations:** `ASSUMES_ROLE` / `RUNS_ON`, `MANAGES` / `BACKUP_TO`, `REFERENCES` / `BACKUP_TO`
- **Edges out:**<br>`ASSUMES_ROLE` / `RUNS_ON` → `IAM_ROLE`<br>`MANAGES` / `BACKUP_TO` → `DYNAMODB_TABLE`<br>`REFERENCES` / `BACKUP_TO` → `BACKUP_VAULT`, `CLOUD_ACCOUNT`

#### BACKUP_VAULT

Catalog entries that classify native resources as this type:

- AWS ARN: `backup:backup-vault`
- AWS CloudFormation (Cloud Control): `AWS::Backup::BackupVault`
- Azure ARM: `microsoft.dataprotection/backupvaults`, `microsoft.recoveryservices/vaults`

- **Providers:** AWS
- **Metadata keys:** `has_access_policy` (bool), `kms_key_id` (null \| str), `lock_date` (null), `locked` (bool), `max_retention_days` (null), `min_retention_days` (null), `policy_allows_public` (bool), `protected_resource_types` (list), `protected_resources` (int), `recovery_points` (int \| null), `service` (str), `state` (null), `vault_type` (null)
- **Declared relations:** `GRANTS_ACCESS` / `POLICY_ALLOWS_ACTION` ←, `REFERENCES` / `BACKUP_TO` ←, `REFERENCES` / `ENCRYPTED_BY_KMS`
- **Edges out:**<br>`REFERENCES` / `ENCRYPTED_BY_KMS` → `KMS_KEY`
- **Edges in:**<br>`GRANTS_ACCESS` / `POLICY_ALLOWS_ACTION` ← `CLOUD_ACCOUNT`<br>`REFERENCES` / `BACKUP_TO` ← `BACKUP_PLAN`, `DYNAMODB_TABLE`

### Hybrid and edge networking

#### VPN_CONNECTION

VPN connection / tunnel.

Catalog entries that classify native resources as this type:

- AWS ARN: `ec2:vpn-connection`
- AWS CloudFormation (Cloud Control): `AWS::EC2::VPNConnection`
- Azure ARM: `microsoft.network/connections`
- GCP Cloud Asset Inventory: `compute.googleapis.com/VpnTunnel`

- **Providers:** AWS
- **Metadata keys:** `acceleration` (null), `category` (null), `core_network_arn` (null), `customer_gateway_id` (str), `local_ipv4_cidr` (null), `outside_ip_type` (null), `remote_ipv4_cidr` (null), `state` (str), `static_routes` (list), `static_routes_only` (null), `tgw_id` (null), `tunnels` (list), `tunnels_up` (int), `type` (str), `vpn_connection_id` (str), `vpn_gateway_id` (str)
- **Carries `aliases`:** yes
- **Declared relations:** `ATTACHED_TO` / `TRANSIT_ROUTED`, `ROUTE` / `TRANSIT_ROUTED`
- **Edges out:**<br>`ATTACHED_TO` / `TRANSIT_ROUTED` → `VPN_GATEWAY`<br>`ROUTE` / `TRANSIT_ROUTED` → `CUSTOMER_GATEWAY`

#### VPN_GATEWAY

VGW, Azure VNet gateway, GCP target VPN gateway.

Catalog entries that classify native resources as this type:

- AWS ARN: `ec2:vpn-gateway`
- AWS CloudFormation (Cloud Control): `AWS::EC2::VPNGateway`
- Azure ARM: `microsoft.network/virtualnetworkgateways`, `microsoft.network/vpngateways`
- GCP Cloud Asset Inventory: `compute.googleapis.com/TargetVpnGateway`, `compute.googleapis.com/VpnGateway`

- **Providers:** AWS
- **Metadata keys:** `amazon_side_asn` (null), `state` (str), `type` (str), `vpc_attachments` (list), `vpn_gateway_id` (str)
- **Carries `aliases`:** yes
- **Declared relations:** `ATTACHED_TO`
- **Edges out:**<br>`ATTACHED_TO` → `VPC`
- **Edges in:**<br>`ATTACHED_TO` / `TRANSIT_ROUTED` ← `VPN_CONNECTION`<br>`ROUTE` / `TRANSIT_ROUTED` ← `DIRECT_CONNECT`

#### CUSTOMER_GATEWAY

CGW, local network gateway, external VPN gateway.

Catalog entries that classify native resources as this type:

- AWS ARN: `ec2:customer-gateway`
- AWS CloudFormation (Cloud Control): `AWS::EC2::CustomerGateway`
- Azure ARM: `microsoft.network/localnetworkgateways`
- GCP Cloud Asset Inventory: `compute.googleapis.com/ExternalVpnGateway`

- **Providers:** AWS
- **Metadata keys:** `bgp_asn` (str), `customer_gateway_id` (str), `device_name` (null), `ip_address` (str), `state` (str), `type` (str)
- **Carries `aliases`:** yes
- **Edges in:**<br>`ROUTE` / `TRANSIT_ROUTED` ← `VPN_CONNECTION`

#### DIRECT_CONNECT

DX connection / VIF / gateway, ExpressRoute, Interconnect.

Catalog entries that classify native resources as this type:

- AWS ARN: `directconnect`
- AWS CloudFormation (Cloud Control): `AWS::DirectConnect::Connection`
- Azure ARM: `microsoft.network/expressroutecircuits`, `microsoft.network/expressroutegateways`
- GCP Cloud Asset Inventory: `compute.googleapis.com/Interconnect`, `compute.googleapis.com/InterconnectAttachment`

- **Providers:** AWS
- **Metadata keys:** `address_family` (null), `allows_hosted_connections` (null), `amazon_side_asn` (int \| null), `asn` (null), `associations` (list), `aws_device` (null), `bandwidth` (str), `bgp_peers` (list), `connection_id` (str), `connections_bandwidth` (null), `dx_gateway_id` (str), `encryption_mode` (null), `has_logical_redundancy` (null), `interface_type` (str), `jumbo_frames` (null), `lag_id` (str), `location` (null \| str), `macsec_capable` (null), `member_connections` (list), `minimum_links` (null), `mtu` (null), `number_of_connections` (null), `owner_account` (str), `partner_name` (null), `port_encryption_status` (null), `provider_name` (null), `resource_kind` (str), `route_filter_prefixes` (int), `site_link` (null), `state` (str), `vgw_id` (null), `vif_attachments` (list), `virtual_interface_id` (str), `vlan` (null)
- **Carries `aliases`:** yes
- **Declared relations:** `ATTACHED_TO`, `CONTAINS` ←, `ROUTE` / `TRANSIT_ROUTED`, `ROUTE` / `TRANSIT_ROUTED` ←
- **Edges out:**<br>`ATTACHED_TO` → `DIRECT_CONNECT`<br>`CONTAINS` → `DIRECT_CONNECT`<br>`ROUTE` / `TRANSIT_ROUTED` → `CLOUD_ACCOUNT`, `DIRECT_CONNECT`, `TRANSIT_GATEWAY`, `VPN_GATEWAY`
- **Edges in:**<br>`ATTACHED_TO` ← `DIRECT_CONNECT`<br>`CONTAINS` ← `DIRECT_CONNECT`<br>`ROUTE` / `TRANSIT_ROUTED` ← `DIRECT_CONNECT`

#### ROUTER

GCP Cloud Router, Azure virtual hub router.

Catalog entries that classify native resources as this type:

- GCP Cloud Asset Inventory: `compute.googleapis.com/Router`

*Not exercised by the fixtures.* Produced by collectors or catalogs for resources the
test estates do not contain; carries the common keys above plus collector-specific fields.

#### PREFIX_LIST

Catalog entries that classify native resources as this type:

- AWS ARN: `ec2:prefix-list`
- AWS CloudFormation (Cloud Control): `AWS::EC2::PrefixList`
- Azure ARM: `microsoft.network/ipgroups`, `microsoft.network/publicipprefixes`

- **Providers:** AWS
- **Metadata keys:** `address_family` (str), `entries` (list), `entry_count` (int), `max_entries` (int), `owner_id` (str), `prefix_list_id` (str), `state` (str), `version` (int)
- **Carries `aliases`:** yes

#### ENDPOINT_SERVICE

PrivateLink service, private link service, PSC attachment.

Catalog entries that classify native resources as this type:

- AWS ARN: `ec2:vpc-endpoint-service`
- AWS CloudFormation (Cloud Control): `AWS::EC2::VPCEndpointService`
- Azure ARM: `microsoft.network/privatelinkservices`
- GCP Cloud Asset Inventory: `compute.googleapis.com/ServiceAttachment`

- **Providers:** AWS
- **Can be internet-exposed:** yes (`is_internet_exposed` observed `true`)
- **Metadata keys:** `acceptance_required` (bool), `allowed_principals` (list), `allows_any_principal` (bool), `auth_policy_public` (bool), `auth_policy_state` (str), `auth_type` (str), `availability_zones` (list), `base_endpoint_dns_names` (list), `consumer_count` (int), `consumers` (list), `custom_domain_name` (str), `dns_name` (str), `listeners` (list), `private_dns_name` (null \| str), `private_dns_verification` (null), `resource_kind` (str), `service_id` (str), `service_name` (str), `service_types` (list), `state` (null \| str), `status` (str), `supported_regions` (list), `unauthenticated` (bool)
- **Carries `aliases`:** yes
- **Declared relations:** `GRANTS_ACCESS` / `POLICY_ALLOWS_ACTION` ←, `LOAD_BALANCER_TARGET` / `SERVES_TRAFFIC_TO`, `ROUTE` / `SERVES_TRAFFIC_TO` ←
- **Edges out:**<br>`LOAD_BALANCER_TARGET` / `SERVES_TRAFFIC_TO` → `LOAD_BALANCER`
- **Edges in:**<br>`CONTAINS` ← `SERVICE_NETWORK`<br>`GRANTS_ACCESS` / `POLICY_ALLOWS_ACTION` ← `CLOUD_ACCOUNT`<br>`ROUTE` / `SERVES_TRAFFIC_TO` ← `CLOUD_ACCOUNT`

#### VPC_LINK

Catalog entries that classify native resources as this type:

- AWS ARN: `apigateway:vpclinks`
- AWS CloudFormation (Cloud Control): `AWS::ApiGateway::VpcLink`, `AWS::ApiGatewayV2::VpcLink`
- GCP Cloud Asset Inventory: `vpcaccess.googleapis.com/Connector`

- **Providers:** AWS, GCP
- **Metadata keys:** `api_type` (str), `create_time` (null), `description` (null), `folders` (list), `gcp_asset_type` (str), `kind` (str), `location` (str), `network` (str), `network_tags` (list), `organization` (str), `parent_asset_type` (null), `parent_full_resource_name` (str), `project` (str), `project_id` (str), `project_number` (str), `revision` (null), `security_groups` (list), `service` (str), `state` (null), `status` (null \| str), `subnet_ids` (list), `target_arns` (list), `version` (str), `vpc_config` (object), `vpc_link_id` (str)
- **Carries `aliases`:** yes
- **Declared relations:** `ATTACHED_TO`, `CONTAINS` / `SUBNET_CONTAINS_INSTANCE` ←, `LOAD_BALANCER_TARGET` / `SERVES_TRAFFIC_TO`
- **Edges out:**<br>`ATTACHED_TO` → `VPC`<br>`ATTACHED_TO` / `PROTECTED_BY_SG` → `SECURITY_GROUP`<br>`LOAD_BALANCER_TARGET` / `SERVES_TRAFFIC_TO` → `LOAD_BALANCER`
- **Edges in:**<br>`CONTAINS` ← `CLOUD_ACCOUNT`<br>`CONTAINS` / `SUBNET_CONTAINS_INSTANCE` ← `SUBNET`<br>`REFERENCES` / `DEPENDS_ON` ← `APP_SERVICE`<br>`ROUTE` / `TRANSIT_ROUTED` ← `CONTAINER_SERVICE`

#### CUSTOM_DOMAIN

Catalog entries that classify native resources as this type:

- AWS ARN: `apigateway:domainnames`
- AWS CloudFormation (Cloud Control): `AWS::ApiGateway::DomainName`, `AWS::ApiGatewayV2::DomainName`
- Azure ARM: `microsoft.cdn/profiles/customdomains`
- GCP Cloud Asset Inventory: `run.googleapis.com/DomainMapping`

- **Providers:** AWS
- **Can be internet-exposed:** yes (`is_internet_exposed` observed `true`)
- **Metadata keys:** `api_mappings` (list), `distribution_domain_name` (str), `endpoint_types` (list), `mutual_tls` (bool), `private` (bool), `regional_domain_name` (str), `security_policy` (null), `status` (null \| str)
- **Carries `aliases`:** yes
- **Declared relations:** `REFERENCES` / `CERTIFICATE_SECURES`, `ROUTE` / `SERVES_TRAFFIC_TO`
- **Edges out:**<br>`REFERENCES` / `CERTIFICATE_SECURES` → `CERTIFICATE`<br>`ROUTE` / `SERVES_TRAFFIC_TO` → `API_GATEWAY`
- **Edges in:**<br>`ROUTE` / `DNS_RESOLVED` ← `DNS_RECORD`

#### DNS_RESOLVER

Catalog entries that classify native resources as this type:

- AWS ARN: `route53resolver:resolver-endpoint`, `route53resolver:resolver-rule`
- AWS CloudFormation (Cloud Control): `AWS::Route53Resolver::ResolverEndpoint`, `AWS::Route53Resolver::ResolverRule`
- Azure ARM: `microsoft.network/dnsresolvers`
- GCP Cloud Asset Inventory: `dns.googleapis.com/Policy`, `dns.googleapis.com/ResponsePolicy`

- **Providers:** AWS
- **Metadata keys:** `associated_vpcs` (list), `direction` (str), `domain_name` (str), `endpoint_type` (null), `ip_addresses` (list), `ip_count` (int), `outpost_arn` (null), `owner_id` (str), `protocols` (list), `resolver_endpoint_id` (null \| str), `resource_kind` (str), `rule_type` (str), `security_groups` (list), `share_status` (str), `shared_from_other_account` (bool), `status` (null \| str), `target_ips` (list), `vpc_id` (str)
- **Carries `aliases`:** yes
- **Declared relations:** `ATTACHED_TO` / `DNS_RESOLVED`, `CONTAINS` ←, `CONTAINS` / `SUBNET_CONTAINS_INSTANCE` ←, `ROUTE` / `DNS_RESOLVED`
- **Edges out:**<br>`ATTACHED_TO` / `DNS_RESOLVED` → `VPC`<br>`ATTACHED_TO` / `PROTECTED_BY_SG` → `SECURITY_GROUP`<br>`ROUTE` / `DNS_RESOLVED` → `DNS_RESOLVER`
- **Edges in:**<br>`CONTAINS` ← `VPC`<br>`CONTAINS` / `SUBNET_CONTAINS_INSTANCE` ← `SUBNET`<br>`ROUTE` / `DNS_RESOLVED` ← `DNS_RESOLVER`

#### GLOBAL_ACCELERATOR

Catalog entries that classify native resources as this type:

- AWS ARN: `globalaccelerator`
- AWS CloudFormation (Cloud Control): `AWS::GlobalAccelerator::Accelerator`

- **Providers:** AWS
- **Can be internet-exposed:** yes (`is_internet_exposed` observed `true`)
- **Metadata keys:** `accelerator_type` (str), `dns_name` (str), `dual_stack_dns_name` (null), `enabled` (bool), `endpoint_groups` (list), `endpoints` (list), `ip_address_type` (null), `ip_addresses` (list), `listeners` (list), `status` (str)
- **Carries `aliases`:** yes
- **Declared relations:** `LOAD_BALANCER_TARGET` / `SERVES_TRAFFIC_TO`
- **Edges out:**<br>`LOAD_BALANCER_TARGET` / `SERVES_TRAFFIC_TO` → `LOAD_BALANCER`

#### SERVICE_NETWORK

VPC Lattice, Cloud WAN, NCC hub.

Catalog entries that classify native resources as this type:

- AWS ARN: `networkmanager`, `vpc-lattice:servicenetwork`
- AWS CloudFormation (Cloud Control): `AWS::NetworkManager::CoreNetwork`, `AWS::VpcLattice::ServiceNetwork`
- Azure ARM: `microsoft.network/networkmanagers`, `microsoft.network/virtualwans`
- GCP Cloud Asset Inventory: `networkconnectivity.googleapis.com/Hub`

- **Providers:** AWS
- **Metadata keys:** `associated_vpcs` (list), `auth_policy_public` (bool), `auth_policy_state` (null), `auth_type` (str), `description` (str), `global_network_id` (str), `network_attachments` (list), `owner_account` (str), `registered_transit_gateways` (list), `resource_kind` (str), `segments` (list), `services` (list), `state` (str), `unauthenticated` (bool)
- **Carries `aliases`:** yes
- **Declared relations:** `ATTACHED_TO`, `CONTAINS`, `CONTAINS` ←
- **Edges out:**<br>`ATTACHED_TO` → `VPC`<br>`CONTAINS` → `ENDPOINT_SERVICE`, `SERVICE_NETWORK`
- **Edges in:**<br>`CONTAINS` ← `SERVICE_NETWORK`

### Application integration and operations

#### SCHEDULE

Catalog entries that classify native resources as this type:

- AWS ARN: `scheduler:schedule`
- AWS CloudFormation (Cloud Control): `AWS::Scheduler::Schedule`
- Azure ARM: `microsoft.automation/automationaccounts`

- **Providers:** AWS
- **Metadata keys:** `action_after_completion` (null), `association_id` (str), `cutoff_hours` (int), `document` (str), `document_version` (null), `duration_hours` (int), `enabled` (bool), `expression` (str), `flexible_window` (str), `group` (str), `kind` (str), `last_execution` (null), `next_execution` (null), `retry_attempts` (int), `schedule` (str), `service` (str), `state` (str), `status` (null), `target_api` (null), `target_arn` (str), `targets` (list), `tasks` (list), `timezone` (null \| str), `vpc_config` (null), `window_id` (str)
- **Carries `aliases`:** yes
- **Declared relations:** `ASSUMES_ROLE` / `RUNS_ON`, `INVOKES` / `INVOKES`, `MANAGES` / `SCHEDULED_BY`, `REFERENCES` / `DEPENDS_ON`, `REFERENCES` / `WRITES_TO`
- **Edges out:**<br>`ASSUMES_ROLE` / `RUNS_ON` → `IAM_ROLE`<br>`INVOKES` / `INVOKES` → `LAMBDA_FUNCTION`<br>`MANAGES` / `SCHEDULED_BY` → `EC2`<br>`REFERENCES` / `DEPENDS_ON` → `RUNBOOK`<br>`REFERENCES` / `WRITES_TO` → `MESSAGE_QUEUE`

#### EVENT_PIPE

Catalog entries that classify native resources as this type:

- AWS ARN: `pipes:pipe`
- AWS CloudFormation (Cloud Control): `AWS::Pipes::Pipe`

- **Providers:** AWS
- **Metadata keys:** `current_state` (str), `desired_state` (str), `enrichment` (null), `has_filter` (bool), `log_level` (null), `service` (str), `source` (str), `source_type` (null), `target` (str), `vpc_config` (null)
- **Declared relations:** `ASSUMES_ROLE` / `RUNS_ON`, `INVOKES` / `INVOKES`, `INVOKES` / `TRIGGERED_BY` ←
- **Edges out:**<br>`ASSUMES_ROLE` / `RUNS_ON` → `IAM_ROLE`<br>`INVOKES` / `INVOKES` → `LAMBDA_FUNCTION`
- **Edges in:**<br>`INVOKES` / `TRIGGERED_BY` ← `MESSAGE_QUEUE`

#### API_DESTINATION

Catalog entries that classify native resources as this type:

- AWS ARN: `events:api-destination`
- AWS CloudFormation (Cloud Control): `AWS::Events::ApiDestination`

- **Providers:** AWS
- **Metadata keys:** `authorization_type` (str), `endpoint_host` (str), `http_method` (str), `kind` (str), `private` (bool), `rate_limit_per_second` (null), `secret_arn` (str), `service` (str), `state` (str)
- **Declared relations:** `REFERENCES` / `DEPENDS_ON`, `REFERENCES` / `READS_FROM`
- **Edges out:**<br>`REFERENCES` / `DEPENDS_ON` → `API_DESTINATION`
- **Edges in:**<br>`REFERENCES` / `DEPENDS_ON` ← `API_DESTINATION`

#### ALARM

Catalog entries that classify native resources as this type:

- AWS ARN: `cloudwatch:alarm`
- AWS CloudFormation (Cloud Control): `AWS::CloudWatch::Alarm`, `AWS::CloudWatch::CompositeAlarm`
- Azure ARM: `microsoft.insights/activitylogalerts`, `microsoft.insights/metricalerts`, `microsoft.insights/scheduledqueryrules`
- GCP Cloud Asset Inventory: `monitoring.googleapis.com/AlertPolicy`

- **Providers:** AWS
- **Metadata keys:** `actions_enabled` (bool \| null), `alarm_rule` (null \| str), `alarm_type` (str), `comparison` (null \| str), `dimensions` (object), `ec2_actions` (list), `evaluation_periods` (int \| null), `metric` (null \| str), `monitored_identifiers` (list), `namespace` (null \| str), `service` (str), `state` (null \| str), `statistic` (null \| str), `threshold` (float \| null)
- **Declared relations:** `INVOKES` / `INVOKES`, `INVOKES` / `SCALES_WITH`, `MONITORS` / `MONITORED_BY`, `REFERENCES` / `DEPENDS_ON`
- **Edges out:**<br>`INVOKES` / `INVOKES` → `NOTIFICATION_TOPIC`<br>`INVOKES` / `SCALES_WITH` → `AUTOSCALING_GROUP`<br>`MONITORS` / `MONITORED_BY` → `AUTOSCALING_GROUP`, `LAMBDA_FUNCTION`<br>`REFERENCES` / `DEPENDS_ON` → `ALARM`
- **Edges in:**<br>`REFERENCES` / `DEPENDS_ON` ← `ALARM`<br>`REFERENCES` / `MONITORED_BY` ← `DEPLOYMENT_GROUP`

#### DELIVERY_STREAM

Firehose.

Catalog entries that classify native resources as this type:

- AWS ARN: `firehose:deliverystream`
- AWS CloudFormation (Cloud Control): `AWS::KinesisFirehose::DeliveryStream`

- **Providers:** AWS
- **Metadata keys:** `destinations` (list), `encryption` (null), `encryption_key_type` (null), `service` (str), `source_database_host` (null), `source_type` (str), `status` (str), `vpc_config` (null)
- **Declared relations:** `ASSUMES_ROLE` / `RUNS_ON`, `INVOKES` / `STREAMS_TO`, `INVOKES` / `TRIGGERED_BY` ←, `REFERENCES` / `BACKUP_TO`
- **Edges out:**<br>`ASSUMES_ROLE` / `RUNS_ON` → `IAM_ROLE`<br>`INVOKES` / `STREAMS_TO` → `S3_BUCKET`<br>`REFERENCES` / `BACKUP_TO` → `S3_BUCKET`
- **Edges in:**<br>`INVOKES` / `TRIGGERED_BY` ← `DATA_STREAM`

#### LOG_SINK

Subscription filter, logging sink, diagnostic setting.

Catalog entries that classify native resources as this type:

- AWS CloudFormation (Cloud Control): `AWS::Logs::SubscriptionFilter`
- Azure ARM: `microsoft.insights/datacollectionrules`, `microsoft.insights/diagnosticsettings`
- GCP Cloud Asset Inventory: `logging.googleapis.com/LogSink`

- **Providers:** AWS, GCP
- **Metadata keys:** `allowed_org_ids` (list), `association_count` (int), `create_time` (null), `description` (null), `destination` (str), `destination_arn` (str), `disabled` (bool), `distribution` (str), `embedding` (null), `exclusion_count` (int), `filter` (str), `filter_pattern` (str), `folders` (list), `gcp_asset_type` (str), `image` (null), `include_children` (bool), `kind` (str), `location` (str), `log_group` (null \| str), `logged_vpcs` (list), `monitoring_account` (bool), `monitoring_account_id` (str), `network_tags` (list), `org_condition` (list), `organization` (str), `owner_id` (str), `parent_asset_type` (null), `parent_full_resource_name` (str), `policy_allows_public` (bool), `project` (null \| str), `project_id` (null \| str), `project_number` (null \| str), `resource_kind` (str), `resource_types` (list), `s3_bucket` (str), `service` (str), `share_status` (str), `sink_arn` (str), `state` (null), `status` (str), `target_arn` (str), `text` (bool), `video` (null), `writer_identity` (str)
- **Carries `aliases`:** yes
- **Declared relations:** `ASSUMES_ROLE` / `RUNS_ON`, `GRANTS_ACCESS` / `POLICY_ALLOWS_ACTION` ←, `INVOKES` / `STREAMS_TO`, `INVOKES` / `STREAMS_TO` ←, `LOGS_TO` / `LOGS_TO`, `LOGS_TO` / `LOGS_TO` ←
- **Edges out:**<br>`ASSUMES_ROLE` / `RUNS_ON` → `IAM_ROLE`<br>`INVOKES` / `STREAMS_TO` → `CLOUD_ACCOUNT`, `LAMBDA_FUNCTION`<br>`LOGS_TO` / `LOGS_TO` → `DATA_WAREHOUSE`, `GCS_BUCKET`, `LOG_GROUP`, `S3_BUCKET`
- **Edges in:**<br>`CONTAINS` ← `CLOUD_ACCOUNT`<br>`GRANTS_ACCESS` / `POLICY_ALLOWS_ACTION` ← `CLOUD_ACCOUNT`<br>`INVOKES` / `STREAMS_TO` ← `LOG_GROUP`<br>`LOGS_TO` / `LOGS_TO` ← `VPC`

#### PARAMETER

SSM parameter, app configuration.

Catalog entries that classify native resources as this type:

- AWS ARN: `ssm:parameter`
- AWS CloudFormation (Cloud Control): `AWS::SSM::Parameter`
- Azure ARM: `microsoft.appconfiguration/configurationstores`

- **Providers:** AWS
- **Metadata keys:** `data_type` (str), `description` (null), `has_policies` (bool), `kms_key_id` (str), `last_modified` (str), `last_modified_user` (str), `secure` (bool), `service` (str), `tier` (str), `type` (str), `version` (int)
- **Declared relations:** `REFERENCES` / `ENCRYPTED_BY_KMS`
- **Edges in:**<br>`REFERENCES` / `READS_FROM` ← `BUILD_PROJECT`

#### CAPACITY_PROVIDER

Catalog entries that classify native resources as this type:

- AWS ARN: `ecs:capacity-provider`
- AWS CloudFormation (Cloud Control): `AWS::ECS::CapacityProvider`

- **Providers:** AWS
- **Metadata keys:** `clusters` (list), `managed_draining` (null), `managed_scaling` (str), `managed_termination_protection` (null), `service` (str), `status` (str), `target_capacity` (int), `type` (null), `vpc_config` (null)
- **Declared relations:** `MANAGES` / `SCALES_WITH`, `REFERENCES` / `SCALES_WITH` ←
- **Edges out:**<br>`MANAGES` / `SCALES_WITH` → `AUTOSCALING_GROUP`
- **Edges in:**<br>`REFERENCES` / `SCALES_WITH` ← `ECS_CLUSTER`

#### SERVICE_REGISTRY

Cloud Map namespace / service.

Catalog entries that classify native resources as this type:

- AWS ARN: `servicediscovery:namespace`, `servicediscovery:service`

*Not exercised by the fixtures.* Produced by collectors or catalogs for resources the
test estates do not contain; carries the common keys above plus collector-specific fields.

#### EVENT_ARCHIVE

Catalog entries that classify native resources as this type:

- AWS ARN: `events:archive`

- **Providers:** AWS
- **Metadata keys:** `event_count` (int), `event_source` (str), `kind` (str), `retention_days` (int), `service` (str), `size_bytes` (int), `state` (str)
- **Declared relations:** `REFERENCES` / `READS_FROM`
- **Edges out:**<br>`REFERENCES` / `READS_FROM` → `EVENT_BUS`

#### RUNBOOK

SSM document, automation runbook.

Catalog entries that classify native resources as this type:

- AWS ARN: `ssm:document`

- **Providers:** AWS
- **Metadata keys:** `document_format` (str), `document_type` (str), `document_version` (str), `kind` (str), `platform_types` (list), `public` (bool), `service` (str), `shared_with_accounts` (list), `target_type` (null)
- **Declared relations:** `GRANTS_ACCESS` / `POLICY_ALLOWS_ACTION` ←
- **Edges in:**<br>`GRANTS_ACCESS` / `POLICY_ALLOWS_ACTION` ← `CLOUD_ACCOUNT`<br>`REFERENCES` / `DEPENDS_ON` ← `SCHEDULE`

#### SOURCE_CONNECTION

CodeConnections / CodeStar connection.

Catalog entries that classify native resources as this type:

- AWS ARN: `codeconnections:connection`, `codestar-connections:connection`

- **Providers:** AWS
- **Metadata keys:** `cross_account` (bool), `kind` (str), `owner_account_id` (str), `provider_type` (str), `service` (str), `status` (str)
- **Carries `aliases`:** yes
- **Edges in:**<br>`REFERENCES` / `READS_FROM` ← `CI_PIPELINE`

#### LB_LISTENER

Catalog entries that classify native resources as this type:

- AWS ARN: `elasticloadbalancing:listener`

- **Providers:** AWS
- **Can be internet-exposed:** yes (`is_internet_exposed` observed `true`)
- **Metadata keys:** `alpn_policy` (list), `auth_types` (list), `authenticated` (bool), `default_actions` (list), `lb_type` (str), `load_balancer` (str), `mutual_tls_mode` (null), `port` (int), `protocol` (str), `redirects_to_https` (bool), `resource_kind` (str), `rule_count` (int), `rules` (list), `scheme` (str), `ssl_policy` (str), `target_groups` (list)
- **Declared relations:** `CONTAINS` ←, `ROUTE` / `SERVES_TRAFFIC_TO`
- **Edges out:**<br>`ROUTE` / `SERVES_TRAFFIC_TO` → `TARGET_GROUP`
- **Edges in:**<br>`CONTAINS` ← `LOAD_BALANCER`

#### AUTHORIZER

API Gateway authorizer.

- **Providers:** AWS
- **Metadata keys:** `api_id` (str), `api_type` (str), `auth_type` (null), `authorizer_type` (str), `identity_source` (null \| str), `jwt_audience_count` (int), `jwt_issuer` (null \| str), `resource_kind` (str), `result_ttl` (int \| null), `route_count` (int), `routes` (list)
- **Declared relations:** `INVOKES` / `INVOKES`, `REFERENCES` / `DEPENDS_ON`, `REFERENCES` / `DEPENDS_ON` ←
- **Edges out:**<br>`INVOKES` / `INVOKES` → `LAMBDA_FUNCTION`
- **Edges in:**<br>`REFERENCES` / `DEPENDS_ON` ← `API_GATEWAY`

#### EDGE_FUNCTION

CloudFront Function, Lambda@Edge association.

Catalog entries that classify native resources as this type:

- AWS ARN: `cloudfront:function`

*Not exercised by the fixtures.* Produced by collectors or catalogs for resources the
test estates do not contain; carries the common keys above plus collector-specific fields.

### Platforms and data processing

#### MESSAGE_BROKER

MSK, Amazon MQ, Event Hubs Kafka, Managed Kafka.

Catalog entries that classify native resources as this type:

- AWS ARN: `kafka:cluster`, `mq:broker`
- AWS CloudFormation (Cloud Control): `AWS::AmazonMQ::Broker`, `AWS::MSK::Cluster`
- Azure ARM: `microsoft.devices/iothubs`
- GCP Cloud Asset Inventory: `managedkafka.googleapis.com/Cluster`

- **Providers:** AWS
- **Can be internet-exposed:** yes (`is_internet_exposed` observed `true`)
- **Metadata keys:** `audit_logs` (bool), `auth_iam` (bool), `auth_scram` (bool), `auth_tls` (bool), `authentication_strategy` (null), `aws_owned_key` (bool), `broker_id` (str), `broker_nodes` (int), `cluster_type` (str), `configuration_arn` (str), `deployment_mode` (str), `encryption_in_transit` (null), `endpoints` (list), `engine` (str), `engine_version` (str), `general_logs` (bool), `instance_type` (str), `kafka_version` (str), `kms_key_id` (null), `ldap_hosts` (list), `policy_allows_public` (bool), `public_access` (str), `publicly_accessible` (bool), `security_groups` (list), `service` (str), `state` (str), `unauthenticated_access` (bool), `user_count` (int)
- **Carries `aliases`:** yes
- **Declared relations:** `CONTAINS` / `SUBNET_CONTAINS_INSTANCE` ←, `GRANTS_ACCESS` / `POLICY_ALLOWS_ACTION` ←, `LOGS_TO` / `LOGS_TO`
- **Edges out:**<br>`ATTACHED_TO` / `PROTECTED_BY_SG` → `SECURITY_GROUP`
- **Edges in:**<br>`CONTAINS` / `SUBNET_CONTAINS_INSTANCE` ← `SUBNET`<br>`GRANTS_ACCESS` / `POLICY_ALLOWS_ACTION` ← `CLOUD_ACCOUNT`

#### BATCH_ENVIRONMENT

Catalog entries that classify native resources as this type:

- AWS ARN: `batch:compute-environment`
- AWS CloudFormation (Cloud Control): `AWS::Batch::ComputeEnvironment`
- Azure ARM: `microsoft.batch/batchaccounts`

- **Providers:** AWS
- **Metadata keys:** `allocation_strategy` (null), `ec2_key_pair` (null), `image_id` (null), `instance_types` (list), `max_vcpus` (null), `orchestration` (null), `resource_type` (null), `service` (str), `state` (null), `status` (str), `type` (str), `vpc_config` (null)
- **Declared relations:** `ASSUMES_ROLE` / `RUNS_ON`, `MANAGES`
- **Edges out:**<br>`ASSUMES_ROLE` / `RUNS_ON` → `IAM_ROLE`
- **Edges in:**<br>`REFERENCES` / `RUNS_ON` ← `JOB_QUEUE`

#### JOB_QUEUE

Catalog entries that classify native resources as this type:

- AWS ARN: `batch:job-queue`
- AWS CloudFormation (Cloud Control): `AWS::Batch::JobQueue`

- **Providers:** AWS
- **Metadata keys:** `priority` (int), `queue_type` (null), `service` (str), `state` (str), `status` (str)
- **Declared relations:** `REFERENCES` / `RUNS_ON`
- **Edges out:**<br>`REFERENCES` / `RUNS_ON` → `BATCH_ENVIRONMENT`

#### JOB_DEFINITION

Catalog entries that classify native resources as this type:

- AWS ARN: `batch:job-definition`
- AWS CloudFormation (Cloud Control): `AWS::Batch::JobDefinition`
- Azure ARM: `microsoft.app/jobs`
- GCP Cloud Asset Inventory: `run.googleapis.com/Job`

- **Providers:** AWS
- **Metadata keys:** `active_revisions` (int), `containers` (list), `orchestration` (null), `parameter_names` (list), `platform_capabilities` (list), `revision` (int), `service` (str), `service_account` (null), `type` (str)
- **Carries `aliases`:** yes
- **Declared relations:** `ASSUMES_ROLE` / `RUNS_ON`, `USES_IMAGE` / `RUNS_ON`
- **Edges out:**<br>`ASSUMES_ROLE` / `RUNS_ON` → `IAM_ROLE`<br>`USES_IMAGE` / `RUNS_ON` → `CONTAINER_REGISTRY`

#### DATABASE_PROXY

Catalog entries that classify native resources as this type:

- AWS ARN: `rds:db-proxy`
- AWS CloudFormation (Cloud Control): `AWS::RDS::DBProxy`

- **Providers:** AWS
- **Metadata keys:** `endpoint` (str), `engine_family` (str), `iam_auth` (list), `require_tls` (null), `security_groups` (list), `service` (str), `status` (str), `targets` (list), `vpc_id` (str)
- **Carries `aliases`:** yes
- **Declared relations:** `ASSUMES_ROLE` / `RUNS_ON`, `CONTAINS` / `SUBNET_CONTAINS_INSTANCE` ←, `LOAD_BALANCER_TARGET` / `SERVES_TRAFFIC_TO`, `REFERENCES` / `READS_FROM`
- **Edges out:**<br>`ASSUMES_ROLE` / `RUNS_ON` → `IAM_ROLE`<br>`ATTACHED_TO` / `PROTECTED_BY_SG` → `SECURITY_GROUP`<br>`LOAD_BALANCER_TARGET` / `SERVES_TRAFFIC_TO` → `RDS_INSTANCE`<br>`REFERENCES` / `READS_FROM` → `SECRET`
- **Edges in:**<br>`CONTAINS` / `SUBNET_CONTAINS_INSTANCE` ← `SUBNET`

#### DATA_CATALOG

Glue database/catalog, Purview.

Catalog entries that classify native resources as this type:

- AWS ARN: `glue:database`
- AWS CloudFormation (Cloud Control): `AWS::Glue::Database`
- Azure ARM: `microsoft.purview/accounts`
- GCP Cloud Asset Inventory: `dataplex.googleapis.com/Lake`

- **Providers:** AWS
- **Metadata keys:** `admins` (list), `authentication_type` (null), `availability_zone` (null), `connection_password_encryption` (bool), `connection_type` (null), `data_location_grants` (list), `database_count` (int), `encryption_mode` (str), `enforce_ssl` (null), `external_data_filtering` (bool \| null), `federated` (null), `hosts` (list), `iam_allowed_principals_default` (bool), `kind` (str), `kms_key_id` (null), `location` (str), `permission_count` (int), `permissions_capped` (bool), `read_only_admins` (list), `registered_locations` (list), `resource_link` (bool), `security_groups` (list), `service` (str), `status` (str), `table_count` (int), `table_count_capped` (bool), `trusted_resource_owners` (list)
- **Declared relations:** `CONTAINS` ←, `CONTAINS` / `SUBNET_CONTAINS_INSTANCE` ←, `GOVERNS` / `COMPLIANCE_GOVERNS`, `GRANTS_ACCESS` / `POLICY_ALLOWS_ACTION` ←, `REFERENCES` / `DEPENDS_ON`, `REFERENCES` / `READS_FROM`
- **Edges out:**<br>`ATTACHED_TO` / `PROTECTED_BY_SG` → `SECURITY_GROUP`<br>`CONTAINS` → `DATA_CATALOG`<br>`GOVERNS` / `COMPLIANCE_GOVERNS` → `DATA_CATALOG`<br>`REFERENCES` / `DEPENDS_ON` → `S3_BUCKET`
- **Edges in:**<br>`CONTAINS` ← `DATA_CATALOG`<br>`CONTAINS` / `SUBNET_CONTAINS_INSTANCE` ← `SUBNET`<br>`GOVERNS` / `COMPLIANCE_GOVERNS` ← `DATA_CATALOG`<br>`GRANTS_ACCESS` / `POLICY_ALLOWS_ACTION` ← `CLOUD_ACCOUNT`, `IAM_ROLE`<br>`REFERENCES` / `DEPENDS_ON` ← `ETL_JOB`<br>`REFERENCES` / `WRITES_TO` ← `ETL_JOB`

#### ETL_JOB

Glue job/crawler, Data Factory pipeline, Dataflow.

Catalog entries that classify native resources as this type:

- AWS ARN: `glue:crawler`, `glue:job`
- AWS CloudFormation (Cloud Control): `AWS::Glue::Crawler`, `AWS::Glue::Job`
- Azure ARM: `microsoft.datafactory/factories`, `microsoft.streamanalytics/streamingjobs`
- GCP Cloud Asset Inventory: `composer.googleapis.com/Environment`, `dataflow.googleapis.com/Job`, `datafusion.googleapis.com/Instance`

- **Providers:** AWS
- **Metadata keys:** `command` (str), `connections` (list), `database` (str), `glue_version` (null), `kind` (str), `lake_formation_credentials` (null), `schedule` (null), `script_location` (str), `security_configuration` (null), `service` (str), `source_control` (null), `state` (str), `target_types` (list), `worker_type` (null), `workers` (null)
- **Declared relations:** `ASSUMES_ROLE` / `RUNS_ON`, `REFERENCES` / `DEPENDS_ON`, `REFERENCES` / `READS_FROM`, `REFERENCES` / `WRITES_TO`
- **Edges out:**<br>`ASSUMES_ROLE` / `RUNS_ON` → `IAM_ROLE`<br>`REFERENCES` / `DEPENDS_ON` → `DATA_CATALOG`<br>`REFERENCES` / `READS_FROM` → `S3_BUCKET`<br>`REFERENCES` / `WRITES_TO` → `DATA_CATALOG`, `S3_BUCKET`
- **Edges in:**<br>`INVOKES` / `INVOKES` ← `EVENT_RULE`

#### BIG_DATA_CLUSTER

EMR, Dataproc, HDInsight, Databricks.

Catalog entries that classify native resources as this type:

- AWS ARN: `elasticmapreduce:cluster`
- AWS CloudFormation (Cloud Control): `AWS::EMR::Cluster`
- Azure ARM: `microsoft.databricks/workspaces`, `microsoft.hdinsight/clusters`
- GCP Cloud Asset Inventory: `dataproc.googleapis.com/Cluster`

- **Providers:** AWS
- **Can be internet-exposed:** yes (`is_internet_exposed` observed `true`)
- **Metadata keys:** `applications` (list), `cluster_id` (str), `kerberos` (bool), `key_name` (null), `kms_key_id` (null), `log_uri` (str), `master_public_dns` (str), `release_label` (str), `security_configuration` (null), `security_groups` (list), `service` (str), `state` (str), `termination_protected` (bool)
- **Carries `aliases`:** yes
- **Declared relations:** `ASSUMES_ROLE` / `RUNS_ON`, `CONTAINS` / `SUBNET_CONTAINS_INSTANCE` ←, `LOGS_TO` / `LOGS_TO`
- **Edges out:**<br>`ASSUMES_ROLE` / `RUNS_ON` → `IAM_ROLE`<br>`ATTACHED_TO` / `PROTECTED_BY_SG` → `SECURITY_GROUP`<br>`LOGS_TO` / `LOGS_TO` → `S3_BUCKET`
- **Edges in:**<br>`CONTAINS` / `SUBNET_CONTAINS_INSTANCE` ← `SUBNET`

#### QUERY_WORKGROUP

Athena.

Catalog entries that classify native resources as this type:

- AWS ARN: `athena:workgroup`
- AWS CloudFormation (Cloud Control): `AWS::Athena::WorkGroup`

- **Providers:** AWS
- **Metadata keys:** `bytes_scanned_cutoff` (null), `encryption` (null), `enforce_workgroup_configuration` (bool), `engine_version` (str), `identity_center` (null), `kms_key_id` (null), `managed_query_results` (null), `output_location` (null \| str), `service` (str), `state` (str)
- **Declared relations:** `REFERENCES` / `WRITES_TO`
- **Edges out:**<br>`REFERENCES` / `WRITES_TO` → `S3_BUCKET`

#### DATA_TRANSFER

DataSync task, Transfer Family server.

Catalog entries that classify native resources as this type:

- AWS ARN: `datasync:task`, `transfer:server`
- AWS CloudFormation (Cloud Control): `AWS::DataSync::Task`, `AWS::Transfer::Server`

- **Providers:** AWS
- **Can be internet-exposed:** yes (`is_internet_exposed` observed `true`)
- **Metadata keys:** `destination` (str), `directory_id` (null), `domain` (str), `endpoint_type` (str), `host` (null \| str), `identity_provider_type` (str), `kind` (str), `location_type` (str), `location_uri` (str), `protocols` (list), `schedule` (null), `security_groups` (list), `security_policy` (null), `server_id` (str), `service` (str), `source` (str), `state` (null), `status` (str), `task_mode` (null), `user_count` (null), `verify_mode` (null), `vpc_id` (null), `workflows` (list)
- **Carries `aliases`:** yes
- **Declared relations:** `ASSUMES_ROLE` / `RUNS_ON`, `INVOKES` / `INVOKES`, `REFERENCES` / `DEPENDS_ON`, `REFERENCES` / `READS_FROM`, `REFERENCES` / `WRITES_TO`
- **Edges out:**<br>`ASSUMES_ROLE` / `RUNS_ON` → `IAM_ROLE`<br>`CONTAINS` → `IDENTITY_USER`<br>`REFERENCES` / `DEPENDS_ON` → `S3_BUCKET`<br>`REFERENCES` / `READS_FROM` → `DATA_TRANSFER`<br>`REFERENCES` / `WRITES_TO` → `DATA_TRANSFER`, `S3_BUCKET`
- **Edges in:**<br>`REFERENCES` / `READS_FROM` ← `DATA_TRANSFER`<br>`REFERENCES` / `WRITES_TO` ← `DATA_TRANSFER`

#### ML_WORKSPACE

SageMaker domain/notebook, Vertex workbench, AML workspace.

Catalog entries that classify native resources as this type:

- AWS ARN: `sagemaker:domain`, `sagemaker:notebook-instance`
- AWS CloudFormation (Cloud Control): `AWS::SageMaker::Domain`, `AWS::SageMaker::NotebookInstance`
- Azure ARM: `microsoft.machinelearningservices/workspaces`
- GCP Cloud Asset Inventory: `notebooks.googleapis.com/Instance`, `notebooks.googleapis.com/Runtime`

- **Providers:** AWS
- **Can be internet-exposed:** yes (`is_internet_exposed` observed `true`)
- **Metadata keys:** `app_network_access` (str), `auth_mode` (str), `direct_internet_access` (bool), `domain_id` (str), `imds_min_version` (null), `instance_type` (str), `kind` (str), `kms_key_id` (null), `lifecycle_config` (null), `root_access` (null), `security_groups` (list), `service` (str), `status` (str), `url` (str), `vpc_id` (str)
- **Carries `aliases`:** yes
- **Declared relations:** `ASSUMES_ROLE` / `RUNS_ON`, `CONTAINS` / `SUBNET_CONTAINS_INSTANCE` ←, `REFERENCES` / `WRITES_TO`
- **Edges out:**<br>`ASSUMES_ROLE` / `RUNS_ON` → `IAM_ROLE`<br>`ATTACHED_TO` / `PROTECTED_BY_SG` → `SECURITY_GROUP`
- **Edges in:**<br>`CONTAINS` / `SUBNET_CONTAINS_INSTANCE` ← `SUBNET`

#### ML_ENDPOINT

Catalog entries that classify native resources as this type:

- AWS ARN: `sagemaker:endpoint`
- AWS CloudFormation (Cloud Control): `AWS::SageMaker::Endpoint`
- Azure ARM: `microsoft.cognitiveservices/accounts`, `microsoft.machinelearningservices/workspaces/onlineendpoints`
- GCP Cloud Asset Inventory: `aiplatform.googleapis.com/Endpoint`

- **Providers:** AWS
- **Metadata keys:** `data_capture` (bool), `endpoint_config` (str), `instance_types` (list), `kms_key_id` (null), `models` (list), `network_isolation` (null), `security_groups` (list), `serverless` (bool), `service` (str), `status` (str)
- **Declared relations:** `REFERENCES` / `DEPENDS_ON`
- **Edges out:**<br>`REFERENCES` / `DEPENDS_ON` → `ML_MODEL`

#### ML_MODEL

Catalog entries that classify native resources as this type:

- AWS ARN: `sagemaker:model`
- AWS CloudFormation (Cloud Control): `AWS::SageMaker::Model`
- GCP Cloud Asset Inventory: `aiplatform.googleapis.com/Model`

- **Providers:** AWS
- **Metadata keys:** `images` (list), `in_vpc` (bool), `network_isolation` (bool), `security_groups` (list), `service` (str)
- **Declared relations:** `ASSUMES_ROLE` / `RUNS_ON`, `CONTAINS` / `SUBNET_CONTAINS_INSTANCE` ←, `REFERENCES` / `READS_FROM`, `USES_IMAGE` / `RUNS_ON`
- **Edges out:**<br>`ASSUMES_ROLE` / `RUNS_ON` → `IAM_ROLE`<br>`ATTACHED_TO` / `PROTECTED_BY_SG` → `SECURITY_GROUP`<br>`REFERENCES` / `READS_FROM` → `S3_BUCKET`<br>`USES_IMAGE` / `RUNS_ON` → `CONTAINER_REGISTRY`
- **Edges in:**<br>`CONTAINS` / `SUBNET_CONTAINS_INSTANCE` ← `SUBNET`<br>`REFERENCES` / `DEPENDS_ON` ← `ML_ENDPOINT`

#### AI_AGENT

Bedrock agent.

Catalog entries that classify native resources as this type:

- AWS ARN: `bedrock:agent`
- AWS CloudFormation (Cloud Control): `AWS::Bedrock::Agent`

- **Providers:** AWS
- **Metadata keys:** `action_group_lambdas` (list), `action_groups` (list), `agent_id` (str), `collaboration` (null), `foundation_model` (str), `guardrail` (str), `kms_key_id` (null), `knowledge_bases` (list), `orchestration` (null), `service` (str), `status` (null)
- **Carries `aliases`:** yes
- **Declared relations:** `ASSUMES_ROLE` / `RUNS_ON`, `INVOKES` / `INVOKES`, `PROTECTS` ←, `REFERENCES` / `READS_FROM`
- **Edges out:**<br>`ASSUMES_ROLE` / `RUNS_ON` → `IAM_ROLE`<br>`REFERENCES` / `READS_FROM` → `KNOWLEDGE_BASE`
- **Edges in:**<br>`PROTECTS` ← `AI_GUARDRAIL`

#### KNOWLEDGE_BASE

Catalog entries that classify native resources as this type:

- AWS ARN: `bedrock:knowledge-base`
- AWS CloudFormation (Cloud Control): `AWS::Bedrock::KnowledgeBase`

- **Providers:** AWS
- **Metadata keys:** `data_sources` (list), `embedding_model` (null), `knowledge_base_id` (str), `service` (str), `status` (null), `storage_type` (str), `type` (null), `vector_store_endpoints` (list)
- **Carries `aliases`:** yes
- **Declared relations:** `ASSUMES_ROLE` / `RUNS_ON`, `REFERENCES` / `READS_FROM`
- **Edges out:**<br>`ASSUMES_ROLE` / `RUNS_ON` → `IAM_ROLE`<br>`REFERENCES` / `READS_FROM` → `S3_BUCKET`, `SEARCH_DOMAIN`
- **Edges in:**<br>`REFERENCES` / `READS_FROM` ← `AI_AGENT`

#### AI_GUARDRAIL

Catalog entries that classify native resources as this type:

- AWS ARN: `bedrock:guardrail`
- AWS CloudFormation (Cloud Control): `AWS::Bedrock::Guardrail`

- **Providers:** AWS
- **Metadata keys:** `content_policy` (bool), `contextual_grounding_policy` (bool), `cross_region_profile` (null), `guardrail_id` (str), `kms_key_id` (null), `sensitive_information_policy` (bool), `service` (str), `status` (str), `topic_policy` (bool), `version` (str), `word_policy` (bool)
- **Carries `aliases`:** yes
- **Edges out:**<br>`PROTECTS` → `AI_AGENT`

### Generic

#### OTHER

Catalog entries that classify native resources as this type:

- AWS CloudFormation (Cloud Control): `AWS::IoT::Thing`
- GCP Cloud Asset Inventory: `apigateway.googleapis.com/ApiConfig`, `bigquery.googleapis.com/Table`

- **Providers:** AWS
- **Also discovered via:** `cloud-control`
- **Metadata keys:** `discovered_via` (str), `hybrid_nodes` (int), `identifier` (str), `kind` (str), `managed_instances` (int), `outdated_agents` (int), `ping_status` (object), `platforms` (object), `properties` (object), `resource_type` (str), `service` (str)
- **Carries `aliases`:** yes
- **Declared relations:** `MANAGES`
- **Edges out:**<br>`MANAGES` → `EC2`, `VIRTUAL_MACHINE`<br>`REFERENCES` → `MESSAGE_QUEUE`

## Relationship matrix

Every `(source type, edge type, relationship, target type)` combination the linker produced in
the observations, grouped by edge type. `—` means the edge carries no fine-grained relationship.
Edges added outside the linker (`SECURITY_GROUP_RULE`, `INTERNET_EXPOSED` and other collector
edges, and the account `CONTAINS` hierarchy) are described in INVENTORY_REFERENCE.md.

### ASSUMES_ROLE

| Source type | Relationship | Target type |
|---|---|---|
| `AI_AGENT` | `RUNS_ON` | `IAM_ROLE` |
| `AKS_CLUSTER` | `RUNS_ON` | `SERVICE_PRINCIPAL` |
| `APP_SERVICE` | `RUNS_ON` | `IAM_ROLE` |
| `APP_SERVICE` | `RUNS_ON` | `SERVICE_PRINCIPAL` |
| `BACKUP_PLAN` | `RUNS_ON` | `IAM_ROLE` |
| `BATCH_ENVIRONMENT` | `RUNS_ON` | `IAM_ROLE` |
| `BIG_DATA_CLUSTER` | `RUNS_ON` | `IAM_ROLE` |
| `BUILD_PROJECT` | `RUNS_ON` | `IAM_ROLE` |
| `CACHE_CLUSTER` | `RUNS_ON` | `IAM_ROLE` |
| `CI_PIPELINE` | `RUNS_ON` | `CLOUD_ACCOUNT` |
| `CI_PIPELINE` | `RUNS_ON` | `IAM_ROLE` |
| `CONTAINER_SERVICE` | `RUNS_ON` | `SERVICE_PRINCIPAL` |
| `DATABASE_PROXY` | `RUNS_ON` | `IAM_ROLE` |
| `DATA_TRANSFER` | `RUNS_ON` | `IAM_ROLE` |
| `DATA_WAREHOUSE` | `RUNS_ON` | `IAM_ROLE` |
| `DELIVERY_STREAM` | `RUNS_ON` | `IAM_ROLE` |
| `DEPLOYMENT_GROUP` | `RUNS_ON` | `IAM_ROLE` |
| `EKS_CLUSTER` | `RUNS_ON` | `IAM_ROLE` |
| `ETL_JOB` | `RUNS_ON` | `IAM_ROLE` |
| `EVENT_PIPE` | `RUNS_ON` | `IAM_ROLE` |
| `FARGATE_PROFILE` | `RUNS_ON` | `IAM_ROLE` |
| `FLOW_LOG` | `RUNS_ON` | `IAM_ROLE` |
| `GCE_INSTANCE` | `RUNS_ON` | `SERVICE_PRINCIPAL` |
| `GKE_CLUSTER` | `RUNS_ON` | `SERVICE_PRINCIPAL` |
| `IDENTITY_GROUP` | `ROLE_ASSUMES_ROLE` | `PERMISSION_SET` |
| `IDENTITY_POOL` | `ROLE_ASSUMES_ROLE` | `IAM_ROLE` |
| `IDENTITY_USER` | `ROLE_ASSUMES_ROLE` | `SERVICE_PRINCIPAL` |
| `IDENTITY_USER` | `RUNS_ON` | `IAM_ROLE` |
| `INSTANCE_PROFILE` | `RUNS_ON` | `IAM_ROLE` |
| `JOB_DEFINITION` | `RUNS_ON` | `IAM_ROLE` |
| `K8S_SERVICE_ACCOUNT` | `ROLE_ASSUMES_ROLE` | `SERVICE_PRINCIPAL` |
| `K8S_SERVICE_ACCOUNT` | `RUNS_ON` | `IAM_ROLE` |
| `KNOWLEDGE_BASE` | `RUNS_ON` | `IAM_ROLE` |
| `LAMBDA_FUNCTION` | `RUNS_ON` | `IAM_ROLE` |
| `LAUNCH_TEMPLATE` | `RUNS_ON` | `INSTANCE_PROFILE` |
| `LOG_SINK` | `RUNS_ON` | `IAM_ROLE` |
| `MESSAGE_QUEUE` | `RUNS_ON` | `SERVICE_PRINCIPAL` |
| `ML_MODEL` | `RUNS_ON` | `IAM_ROLE` |
| `ML_WORKSPACE` | `RUNS_ON` | `IAM_ROLE` |
| `NODE_GROUP` | `RUNS_ON` | `IAM_ROLE` |
| `NODE_GROUP` | `RUNS_ON` | `SERVICE_PRINCIPAL` |
| `PERMISSION_SET` | `ROLE_ASSUMES_ROLE` | `IAM_ROLE` |
| `PROVISIONED_PRODUCT` | `RUNS_ON` | `IAM_ROLE` |
| `SCHEDULE` | `RUNS_ON` | `IAM_ROLE` |
| `TASK_DEFINITION` | `RUNS_ON` | `IAM_ROLE` |
| `VIRTUAL_MACHINE` | `RUNS_ON` | `IAM_ROLE` |

### ATTACHED_TO

| Source type | Relationship | Target type |
|---|---|---|
| `ACCESS_POINT` | — | `VPC` |
| `APP_SERVICE` | — | `SUBNET` |
| `BIG_DATA_CLUSTER` | `PROTECTED_BY_SG` | `SECURITY_GROUP` |
| `CACHE_CLUSTER` | `PROTECTED_BY_SG` | `SECURITY_GROUP` |
| `CLOUD_SQL` | — | `VPC` |
| `CONTAINER_SERVICE` | `PROTECTED_BY_SG` | `SECURITY_GROUP` |
| `DATABASE_PROXY` | `PROTECTED_BY_SG` | `SECURITY_GROUP` |
| `DATA_CATALOG` | `PROTECTED_BY_SG` | `SECURITY_GROUP` |
| `DATA_WAREHOUSE` | `PROTECTED_BY_SG` | `SECURITY_GROUP` |
| `DIRECT_CONNECT` | — | `DIRECT_CONNECT` |
| `DNS_RESOLVER` | `DNS_RESOLVED` | `VPC` |
| `DNS_RESOLVER` | `PROTECTED_BY_SG` | `SECURITY_GROUP` |
| `EBS_VOLUME` | — | `EC2` |
| `EBS_VOLUME` | — | `GCE_INSTANCE` |
| `EBS_VOLUME` | — | `VIRTUAL_MACHINE` |
| `EC2` | `PROTECTED_BY_SG` | `SECURITY_GROUP` |
| `EKS_CLUSTER` | `PROTECTED_BY_SG` | `SECURITY_GROUP` |
| `ELASTIC_IP` | — | `LOAD_BALANCER` |
| `ELASTIC_IP` | — | `NETWORK_FIREWALL` |
| `ELASTIC_IP` | — | `NETWORK_INTERFACE` |
| `GCE_INSTANCE` | `PROTECTED_BY_SG` | `SECURITY_GROUP` |
| `INTERNET_GATEWAY` | — | `VPC` |
| `LAUNCH_TEMPLATE` | `PROTECTED_BY_SG` | `SECURITY_GROUP` |
| `LOAD_BALANCER` | `PROTECTED_BY_SG` | `SECURITY_GROUP` |
| `MESSAGE_BROKER` | `PROTECTED_BY_SG` | `SECURITY_GROUP` |
| `ML_MODEL` | `PROTECTED_BY_SG` | `SECURITY_GROUP` |
| `ML_WORKSPACE` | `PROTECTED_BY_SG` | `SECURITY_GROUP` |
| `NETWORK_INTERFACE` | — | `EC2` |
| `NETWORK_INTERFACE` | — | `VIRTUAL_MACHINE` |
| `NETWORK_INTERFACE` | `PROTECTED_BY_SG` | `NSG` |
| `NETWORK_INTERFACE` | `PROTECTED_BY_SG` | `SECURITY_GROUP` |
| `RDS_INSTANCE` | `PROTECTED_BY_SG` | `SECURITY_GROUP` |
| `ROUTE_TABLE` | — | `SUBNET` |
| `SECURITY_GROUP` | — | `VPC` |
| `SERVICE_NETWORK` | — | `VPC` |
| `SUBNET` | `PROTECTED_BY_SG` | `NSG` |
| `VPC_LINK` | — | `VPC` |
| `VPC_LINK` | `PROTECTED_BY_SG` | `SECURITY_GROUP` |
| `VPN_CONNECTION` | `TRANSIT_ROUTED` | `VPN_GATEWAY` |
| `VPN_GATEWAY` | — | `VPC` |

### CONTAINS

| Source type | Relationship | Target type |
|---|---|---|
| `AKS_CLUSTER` | `CLUSTER_CONTAINS_SERVICE` | `NODE_GROUP` |
| `APP_SERVICE` | — | `APP_SERVICE` |
| `APP_SERVICE` | `CLUSTER_CONTAINS_SERVICE` | `APP_SERVICE` |
| `APP_SERVICE` | `CLUSTER_CONTAINS_SERVICE` | `CLOUD_FUNCTION` |
| `AURORA_CLUSTER` | — | `AURORA_CLUSTER` |
| `AZURE_SQL` | — | `AZURE_SQL` |
| `CLOUD_ACCOUNT` | — | `AUTOSCALING_GROUP` |
| `CLOUD_ACCOUNT` | — | `CERTIFICATE` |
| `CLOUD_ACCOUNT` | — | `CLOUD_SQL` |
| `CLOUD_ACCOUNT` | — | `CONTAINER_REGISTRY` |
| `CLOUD_ACCOUNT` | — | `CONTAINER_SERVICE` |
| `CLOUD_ACCOUNT` | — | `DATA_WAREHOUSE` |
| `CLOUD_ACCOUNT` | — | `EBS_VOLUME` |
| `CLOUD_ACCOUNT` | — | `ELASTIC_IP` |
| `CLOUD_ACCOUNT` | — | `GCE_INSTANCE` |
| `CLOUD_ACCOUNT` | — | `GCS_BUCKET` |
| `CLOUD_ACCOUNT` | — | `GKE_CLUSTER` |
| `CLOUD_ACCOUNT` | — | `KMS_KEY` |
| `CLOUD_ACCOUNT` | — | `LOAD_BALANCER` |
| `CLOUD_ACCOUNT` | — | `LOG_SINK` |
| `CLOUD_ACCOUNT` | — | `MESSAGE_QUEUE` |
| `CLOUD_ACCOUNT` | — | `NODE_GROUP` |
| `CLOUD_ACCOUNT` | — | `NOTIFICATION_TOPIC` |
| `CLOUD_ACCOUNT` | — | `ORGANIZATION` |
| `CLOUD_ACCOUNT` | — | `ORG_POLICY` |
| `CLOUD_ACCOUNT` | — | `SECRET` |
| `CLOUD_ACCOUNT` | — | `SECURITY_GROUP` |
| `CLOUD_ACCOUNT` | — | `SERVICE_PRINCIPAL` |
| `CLOUD_ACCOUNT` | — | `SUBNET` |
| `CLOUD_ACCOUNT` | — | `TARGET_GROUP` |
| `CLOUD_ACCOUNT` | — | `VPC` |
| `CLOUD_ACCOUNT` | — | `VPC_LINK` |
| `CLOUD_ACCOUNT` | — | `WAF_WEB_ACL` |
| `CLOUD_ACCOUNT` | `ACCOUNT_CONTAINS_REGION` | `RESOURCE_GROUP` |
| `DATA_CATALOG` | — | `DATA_CATALOG` |
| `DATA_TRANSFER` | — | `IDENTITY_USER` |
| `DIRECT_CONNECT` | — | `DIRECT_CONNECT` |
| `DNS_ZONE` | — | `DNS_RECORD` |
| `ECS_CLUSTER` | — | `EC2` |
| `ECS_CLUSTER` | `CLUSTER_CONTAINS_SERVICE` | `CONTAINER_SERVICE` |
| `EKS_CLUSTER` | `CLUSTER_CONTAINS_SERVICE` | `FARGATE_PROFILE` |
| `EKS_CLUSTER` | `CLUSTER_CONTAINS_SERVICE` | `K8S_NAMESPACE` |
| `EKS_CLUSTER` | `CLUSTER_CONTAINS_SERVICE` | `NODE_GROUP` |
| `EVENT_BUS` | — | `EVENT_RULE` |
| `GKE_CLUSTER` | `CLUSTER_CONTAINS_SERVICE` | `NODE_GROUP` |
| `IAM_GROUP` | — | `IAM_USER` |
| `IAM_USER` | — | `ACCESS_KEY` |
| `IDENTITY_GROUP` | — | `IDENTITY_USER` |
| `IDENTITY_PROVIDER` | — | `IDENTITY_GROUP` |
| `IDENTITY_PROVIDER` | — | `IDENTITY_USER` |
| `IDENTITY_PROVIDER` | — | `PERMISSION_SET` |
| `K8S_NAMESPACE` | `CLUSTER_CONTAINS_SERVICE` | `K8S_INGRESS` |
| `K8S_NAMESPACE` | `CLUSTER_CONTAINS_SERVICE` | `K8S_SERVICE` |
| `K8S_NAMESPACE` | `CLUSTER_CONTAINS_SERVICE` | `K8S_SERVICE_ACCOUNT` |
| `K8S_NAMESPACE` | `CLUSTER_CONTAINS_SERVICE` | `K8S_WORKLOAD` |
| `LOAD_BALANCER` | — | `LB_LISTENER` |
| `ORGANIZATION` | — | `ORG_UNIT` |
| `ORGANIZATION` | `ORG_CONTAINS_ACCOUNT` | `CLOUD_ACCOUNT` |
| `ORGANIZATION` | `ORG_CONTAINS_ACCOUNT` | `ORG_UNIT` |
| `ORG_UNIT` | — | `ORG_UNIT` |
| `ORG_UNIT` | `ORG_CONTAINS_ACCOUNT` | `CLOUD_ACCOUNT` |
| `ORG_UNIT` | `ORG_CONTAINS_ACCOUNT` | `ORG_UNIT` |
| `RESOURCE_GROUP` | — | `AKS_CLUSTER` |
| `RESOURCE_GROUP` | — | `APP_SERVICE` |
| `RESOURCE_GROUP` | — | `AUTOSCALING_GROUP` |
| `RESOURCE_GROUP` | — | `AZURE_SQL` |
| `RESOURCE_GROUP` | — | `BLOB_STORAGE` |
| `RESOURCE_GROUP` | — | `CLOUD_FUNCTION` |
| `RESOURCE_GROUP` | — | `CONTAINER_REGISTRY` |
| `RESOURCE_GROUP` | — | `EBS_VOLUME` |
| `RESOURCE_GROUP` | — | `ELASTIC_IP` |
| `RESOURCE_GROUP` | — | `KEY_VAULT` |
| `RESOURCE_GROUP` | — | `KMS_KEY` |
| `RESOURCE_GROUP` | — | `LOAD_BALANCER` |
| `RESOURCE_GROUP` | — | `LOG_GROUP` |
| `RESOURCE_GROUP` | — | `NETWORK_FIREWALL` |
| `RESOURCE_GROUP` | — | `NETWORK_INTERFACE` |
| `RESOURCE_GROUP` | — | `NSG` |
| `RESOURCE_GROUP` | — | `ROUTE_TABLE` |
| `RESOURCE_GROUP` | — | `SECURITY_GROUP` |
| `RESOURCE_GROUP` | — | `SERVICE_PRINCIPAL` |
| `RESOURCE_GROUP` | — | `VIRTUAL_MACHINE` |
| `RESOURCE_GROUP` | — | `VNET` |
| `RESOURCE_GROUP` | — | `VPC_ENDPOINT` |
| `RESOURCE_GROUP` | — | `WAF_WEB_ACL` |
| `SERVICE_NETWORK` | — | `ENDPOINT_SERVICE` |
| `SERVICE_NETWORK` | — | `SERVICE_NETWORK` |
| `SUBNET` | `SUBNET_CONTAINS_INSTANCE` | `APP_SERVICE` |
| `SUBNET` | `SUBNET_CONTAINS_INSTANCE` | `BIG_DATA_CLUSTER` |
| `SUBNET` | `SUBNET_CONTAINS_INSTANCE` | `CACHE_CLUSTER` |
| `SUBNET` | `SUBNET_CONTAINS_INSTANCE` | `CONTAINER_SERVICE` |
| `SUBNET` | `SUBNET_CONTAINS_INSTANCE` | `DATABASE_PROXY` |
| `SUBNET` | `SUBNET_CONTAINS_INSTANCE` | `DATA_CATALOG` |
| `SUBNET` | `SUBNET_CONTAINS_INSTANCE` | `DATA_WAREHOUSE` |
| `SUBNET` | `SUBNET_CONTAINS_INSTANCE` | `DNS_RESOLVER` |
| `SUBNET` | `SUBNET_CONTAINS_INSTANCE` | `EC2` |
| `SUBNET` | `SUBNET_CONTAINS_INSTANCE` | `EKS_CLUSTER` |
| `SUBNET` | `SUBNET_CONTAINS_INSTANCE` | `FARGATE_PROFILE` |
| `SUBNET` | `SUBNET_CONTAINS_INSTANCE` | `FILE_SYSTEM` |
| `SUBNET` | `SUBNET_CONTAINS_INSTANCE` | `GCE_INSTANCE` |
| `SUBNET` | `SUBNET_CONTAINS_INSTANCE` | `GKE_CLUSTER` |
| `SUBNET` | `SUBNET_CONTAINS_INSTANCE` | `LOAD_BALANCER` |
| `SUBNET` | `SUBNET_CONTAINS_INSTANCE` | `MESSAGE_BROKER` |
| `SUBNET` | `SUBNET_CONTAINS_INSTANCE` | `ML_MODEL` |
| `SUBNET` | `SUBNET_CONTAINS_INSTANCE` | `ML_WORKSPACE` |
| `SUBNET` | `SUBNET_CONTAINS_INSTANCE` | `NAT_GATEWAY` |
| `SUBNET` | `SUBNET_CONTAINS_INSTANCE` | `NETWORK_FIREWALL` |
| `SUBNET` | `SUBNET_CONTAINS_INSTANCE` | `NETWORK_INTERFACE` |
| `SUBNET` | `SUBNET_CONTAINS_INSTANCE` | `NODE_GROUP` |
| `SUBNET` | `SUBNET_CONTAINS_INSTANCE` | `RDS_INSTANCE` |
| `SUBNET` | `SUBNET_CONTAINS_INSTANCE` | `VPC_ENDPOINT` |
| `SUBNET` | `SUBNET_CONTAINS_INSTANCE` | `VPC_LINK` |
| `TRANSIT_GATEWAY` | — | `ROUTE_TABLE` |
| `VNET` | `VPC_CONTAINS_SUBNET` | `SUBNET` |
| `VPC` | — | `DNS_RESOLVER` |
| `VPC` | — | `SUBNET` |
| `VPC` | `VPC_CONTAINS_SUBNET` | `SUBNET` |

### GOVERNS

| Source type | Relationship | Target type |
|---|---|---|
| `DATA_CATALOG` | `COMPLIANCE_GOVERNS` | `DATA_CATALOG` |
| `GUARDRAIL` | `COMPLIANCE_GOVERNS` | `CLOUD_ACCOUNT` |
| `GUARDRAIL` | `COMPLIANCE_GOVERNS` | `ORG_UNIT` |
| `GUARDRAIL` | `COMPLIANCE_GOVERNS` | `RESOURCE_GROUP` |
| `ORG_POLICY` | `COMPLIANCE_GOVERNS` | `CLOUD_ACCOUNT` |
| `ORG_POLICY` | `COMPLIANCE_GOVERNS` | `ORG_UNIT` |
| `ORG_POLICY` | `SCP_RESTRICTS` | `CLOUD_ACCOUNT` |
| `ORG_POLICY` | `SCP_RESTRICTS` | `ORG_UNIT` |

### GRANTS_ACCESS

| Source type | Relationship | Target type |
|---|---|---|
| `CLOUD_ACCOUNT` | `CROSS_ACCOUNT_TRUST` | `DYNAMODB_TABLE` |
| `CLOUD_ACCOUNT` | `CROSS_ACCOUNT_TRUST` | `KMS_KEY` |
| `CLOUD_ACCOUNT` | `CROSS_ACCOUNT_TRUST` | `MACHINE_IMAGE` |
| `CLOUD_ACCOUNT` | `CROSS_ACCOUNT_TRUST` | `RESOURCE_SHARE` |
| `CLOUD_ACCOUNT` | `CROSS_ACCOUNT_TRUST` | `SECRET` |
| `CLOUD_ACCOUNT` | `CROSS_ACCOUNT_TRUST` | `SNAPSHOT` |
| `CLOUD_ACCOUNT` | `POLICY_ALLOWS_ACTION` | `BACKUP_VAULT` |
| `CLOUD_ACCOUNT` | `POLICY_ALLOWS_ACTION` | `DATA_CATALOG` |
| `CLOUD_ACCOUNT` | `POLICY_ALLOWS_ACTION` | `ENDPOINT_SERVICE` |
| `CLOUD_ACCOUNT` | `POLICY_ALLOWS_ACTION` | `LOG_SINK` |
| `CLOUD_ACCOUNT` | `POLICY_ALLOWS_ACTION` | `MESSAGE_BROKER` |
| `CLOUD_ACCOUNT` | `POLICY_ALLOWS_ACTION` | `RUNBOOK` |
| `IAM_ROLE` | `POLICY_ALLOWS_ACTION` | `DATA_CATALOG` |
| `IAM_ROLE` | `POLICY_ALLOWS_ACTION` | `MESSAGE_QUEUE` |
| `IAM_ROLE` | `POLICY_ALLOWS_ACTION` | `PRODUCT_PORTFOLIO` |
| `IAM_ROLE` | `POLICY_ALLOWS_ACTION` | `SEARCH_DOMAIN` |
| `IAM_USER` | `POLICY_ALLOWS_ACTION` | `KMS_KEY` |
| `IDENTITY_GROUP` | `POLICY_ALLOWS_ACTION` | `CLOUD_ACCOUNT` |
| `IDENTITY_PROVIDER` | `POLICY_ALLOWS_ACTION` | `CONTAINER_SERVICE` |
| `IDENTITY_USER` | `POLICY_ALLOWS_ACTION` | `CLOUD_ACCOUNT` |
| `ORG_UNIT` | `CROSS_ACCOUNT_TRUST` | `RESOURCE_SHARE` |
| `RESOURCE_SHARE` | `DEPENDS_ON` | `CLOUD_ACCOUNT` |
| `RESOURCE_SHARE` | `DEPENDS_ON` | `SUBNET` |
| `SERVICE_PRINCIPAL` | `POLICY_ALLOWS_ACTION` | `CLOUD_ACCOUNT` |
| `SERVICE_PRINCIPAL` | `POLICY_ALLOWS_ACTION` | `CONTAINER_REGISTRY` |
| `SERVICE_PRINCIPAL` | `POLICY_ALLOWS_ACTION` | `KEY_VAULT` |
| `SUBNET` | `POLICY_ALLOWS_ACTION` | `KEY_VAULT` |
| `VIRTUAL_MACHINE` | `POLICY_ALLOWS_ACTION` | `KEY_VAULT` |

### IAM_POLICY_ATTACHMENT

| Source type | Relationship | Target type |
|---|---|---|
| `IAM_ROLE` | `ROLE_HAS_POLICY` | `IAM_POLICY` |

### IAM_TRUST

| Source type | Relationship | Target type |
|---|---|---|
| `CLOUD_ACCOUNT` | — | `IAM_ROLE` |
| `CLOUD_ACCOUNT` | `CROSS_ACCOUNT_TRUST` | `IAM_ROLE` |
| `IAM_ROLE` | `CROSS_ACCOUNT_TRUST` | `IAM_ROLE` |
| `IDENTITY_PROVIDER` | `ROLE_ASSUMES_ROLE` | `IAM_ROLE` |
| `IDENTITY_PROVIDER` | `ROLE_ASSUMES_ROLE` | `PERMISSION_SET` |

### INVOKES

| Source type | Relationship | Target type |
|---|---|---|
| `ALARM` | `INVOKES` | `NOTIFICATION_TOPIC` |
| `ALARM` | `SCALES_WITH` | `AUTOSCALING_GROUP` |
| `AUTHORIZER` | `INVOKES` | `LAMBDA_FUNCTION` |
| `CI_PIPELINE` | `INVOKES` | `BUILD_PROJECT` |
| `DATA_STREAM` | `TRIGGERED_BY` | `DELIVERY_STREAM` |
| `DELIVERY_STREAM` | `STREAMS_TO` | `S3_BUCKET` |
| `DEPLOYMENT_GROUP` | `INVOKES` | `NOTIFICATION_TOPIC` |
| `DYNAMODB_TABLE` | — | `LAMBDA_FUNCTION` |
| `EVENT_PIPE` | `INVOKES` | `LAMBDA_FUNCTION` |
| `EVENT_RULE` | — | `LAMBDA_FUNCTION` |
| `EVENT_RULE` | `INVOKES` | `ETL_JOB` |
| `EVENT_RULE` | `INVOKES` | `LAMBDA_FUNCTION` |
| `LOG_GROUP` | `STREAMS_TO` | `LOG_SINK` |
| `LOG_SINK` | `STREAMS_TO` | `CLOUD_ACCOUNT` |
| `LOG_SINK` | `STREAMS_TO` | `LAMBDA_FUNCTION` |
| `MESSAGE_QUEUE` | — | `LAMBDA_FUNCTION` |
| `MESSAGE_QUEUE` | `INVOKES` | `CONTAINER_SERVICE` |
| `MESSAGE_QUEUE` | `TRIGGERED_BY` | `EVENT_PIPE` |
| `MESSAGE_QUEUE` | `TRIGGERED_BY` | `LAMBDA_FUNCTION` |
| `NOTIFICATION_TOPIC` | `STREAMS_TO` | `MESSAGE_QUEUE` |
| `NOTIFICATION_TOPIC` | `TRIGGERED_BY` | `LAMBDA_FUNCTION` |
| `S3_BUCKET` | `INVOKES` | `LAMBDA_FUNCTION` |
| `S3_BUCKET` | `INVOKES` | `MESSAGE_QUEUE` |
| `SCHEDULE` | `INVOKES` | `LAMBDA_FUNCTION` |
| `SECRET` | `ROTATES_SECRET` | `LAMBDA_FUNCTION` |
| `USER_POOL` | `INVOKES` | `LAMBDA_FUNCTION` |

### LOAD_BALANCER_TARGET

| Source type | Relationship | Target type |
|---|---|---|
| `DATABASE_PROXY` | `SERVES_TRAFFIC_TO` | `RDS_INSTANCE` |
| `ENDPOINT_SERVICE` | `SERVES_TRAFFIC_TO` | `LOAD_BALANCER` |
| `GLOBAL_ACCELERATOR` | `SERVES_TRAFFIC_TO` | `LOAD_BALANCER` |
| `K8S_SERVICE` | `SERVES_TRAFFIC_TO` | `K8S_WORKLOAD` |
| `LOAD_BALANCER` | `LB_TARGETS_INSTANCE` | `AUTOSCALING_GROUP` |
| `LOAD_BALANCER` | `LB_TARGETS_INSTANCE` | `NETWORK_FIREWALL` |
| `LOAD_BALANCER` | `LB_TARGETS_INSTANCE` | `NETWORK_INTERFACE` |
| `LOAD_BALANCER` | `LB_TARGETS_INSTANCE` | `TARGET_GROUP` |
| `LOAD_BALANCER` | `LOAD_BALANCED_BY` | `TARGET_GROUP` |
| `LOAD_BALANCER` | `SERVES_TRAFFIC_TO` | `APP_SERVICE` |
| `LOAD_BALANCER` | `SERVES_TRAFFIC_TO` | `GCS_BUCKET` |
| `TARGET_GROUP` | `LB_TARGETS_INSTANCE` | `EC2` |
| `TARGET_GROUP` | `SERVES_TRAFFIC_TO` | `CONTAINER_SERVICE` |
| `VPC_LINK` | `SERVES_TRAFFIC_TO` | `LOAD_BALANCER` |

### LOGS_TO

| Source type | Relationship | Target type |
|---|---|---|
| `AKS_CLUSTER` | `LOGS_TO` | `LOG_GROUP` |
| `BIG_DATA_CLUSTER` | `LOGS_TO` | `S3_BUCKET` |
| `CLOUDFRONT` | `LOGS_TO` | `S3_BUCKET` |
| `FLOW_LOG` | `LOGS_TO` | `LOG_GROUP` |
| `LAMBDA_FUNCTION` | `LOGS_TO` | `LOG_GROUP` |
| `LOG_SINK` | `LOGS_TO` | `DATA_WAREHOUSE` |
| `LOG_SINK` | `LOGS_TO` | `GCS_BUCKET` |
| `LOG_SINK` | `LOGS_TO` | `LOG_GROUP` |
| `LOG_SINK` | `LOGS_TO` | `S3_BUCKET` |
| `VPC` | `LOGS_TO` | `LOG_SINK` |

### MANAGES

| Source type | Relationship | Target type |
|---|---|---|
| `AKS_CLUSTER` | `OWNED_BY` | `RESOURCE_GROUP` |
| `APP_SERVICE` | — | `AUTOSCALING_GROUP` |
| `APP_SERVICE` | — | `EC2` |
| `APP_SERVICE` | — | `LOAD_BALANCER` |
| `AUTOSCALING_GROUP` | `SCALES_WITH` | `AUTOSCALING_GROUP` |
| `BACKUP_PLAN` | `BACKUP_TO` | `DYNAMODB_TABLE` |
| `CAPACITY_PROVIDER` | `SCALES_WITH` | `AUTOSCALING_GROUP` |
| `CLOUD_ACCOUNT` | `OWNED_BY` | `ORGANIZATION` |
| `CLOUD_ACCOUNT` | `OWNED_BY` | `RESOURCE_SHARE` |
| `DEPLOYMENT_GROUP` | — | `AUTOSCALING_GROUP` |
| `DEPLOYMENT_GROUP` | — | `CONTAINER_SERVICE` |
| `DEPLOYMENT_GROUP` | — | `TARGET_GROUP` |
| `IAC_STACK` | — | `SECURITY_GROUP` |
| `LANDING_ZONE` | `COMPLIANCE_GOVERNS` | `ORGANIZATION` |
| `LANDING_ZONE` | `OWNED_BY` | `CLOUD_ACCOUNT` |
| `NODE_GROUP` | `SCALES_WITH` | `AUTOSCALING_GROUP` |
| `OTHER` | — | `EC2` |
| `OTHER` | — | `VIRTUAL_MACHINE` |
| `PERMISSION_SET` | `OWNED_BY` | `CLOUD_ACCOUNT` |
| `PERMISSION_SET` | `OWNED_BY` | `IAM_ROLE` |
| `PROVISIONED_PRODUCT` | `OWNED_BY` | `CLOUD_ACCOUNT` |
| `PROVISIONED_PRODUCT` | `OWNED_BY` | `IAC_STACK` |
| `SCHEDULE` | `SCHEDULED_BY` | `EC2` |
| `STACK_SET` | `OWNED_BY` | `CLOUD_ACCOUNT` |
| `STACK_SET` | `OWNED_BY` | `IAC_STACK` |

### MONITORS

| Source type | Relationship | Target type |
|---|---|---|
| `ALARM` | `MONITORED_BY` | `AUTOSCALING_GROUP` |
| `ALARM` | `MONITORED_BY` | `LAMBDA_FUNCTION` |
| `DATA_SECURITY_SCANNER` | `MONITORED_BY` | `CLOUD_ACCOUNT` |
| `FLOW_LOG` | `MONITORED_BY` | `VPC` |
| `THREAT_DETECTOR` | `MONITORED_BY` | `CLOUD_ACCOUNT` |

### PEERING

| Source type | Relationship | Target type |
|---|---|---|
| `PEERING_CONNECTION` | `TRANSIT_ROUTED` | `CLOUD_ACCOUNT` |
| `PEERING_CONNECTION` | `VPC_PEERED` | `VPC` |
| `TRANSIT_GATEWAY` | `TRANSIT_ROUTED` | `PEERING_CONNECTION` |
| `VNET` | `VPC_PEERED` | `CLOUD_ACCOUNT` |
| `VNET` | `VPC_PEERED` | `VNET` |
| `VPC` | `VPC_PEERED` | `PEERING_CONNECTION` |

### PROTECTS

| Source type | Relationship | Target type |
|---|---|---|
| `AI_GUARDRAIL` | — | `AI_AGENT` |
| `NETWORK_FIREWALL` | `PROTECTED_BY_NACL` | `VPC` |
| `WAF_WEB_ACL` | `PROTECTED_BY_WAF` | `LOAD_BALANCER` |

### REFERENCES

| Source type | Relationship | Target type |
|---|---|---|
| `ACCESS_POINT` | `READS_FROM` | `S3_BUCKET` |
| `AI_AGENT` | `READS_FROM` | `KNOWLEDGE_BASE` |
| `AKS_CLUSTER` | — | `SUBNET` |
| `ALARM` | `DEPENDS_ON` | `ALARM` |
| `API_DESTINATION` | `DEPENDS_ON` | `API_DESTINATION` |
| `API_GATEWAY` | `DEPENDS_ON` | `AUTHORIZER` |
| `APP_SERVICE` | `DEPENDS_ON` | `VPC_LINK` |
| `APP_SERVICE` | `READS_FROM` | `SECRET` |
| `APP_SERVICE` | `RUNS_ON` | `INSTANCE_PROFILE` |
| `AURORA_CLUSTER` | `REPLICATES_TO` | `AURORA_CLUSTER` |
| `BACKUP_PLAN` | `BACKUP_TO` | `BACKUP_VAULT` |
| `BACKUP_PLAN` | `BACKUP_TO` | `CLOUD_ACCOUNT` |
| `BACKUP_VAULT` | `ENCRYPTED_BY_KMS` | `KMS_KEY` |
| `BLOB_STORAGE` | `ENCRYPTED_BY_KMS` | `KEY_VAULT` |
| `BUILD_PROJECT` | `READS_FROM` | `PARAMETER` |
| `BUILD_PROJECT` | `READS_FROM` | `S3_BUCKET` |
| `CERTIFICATE` | `CERTIFICATE_SECURES` | `LOAD_BALANCER` |
| `CI_PIPELINE` | `READS_FROM` | `SOURCE_CONNECTION` |
| `CI_PIPELINE` | `WRITES_TO` | `S3_BUCKET` |
| `CLOUDFRONT` | `CERTIFICATE_SECURES` | `CERTIFICATE` |
| `CLOUDTRAIL` | — | `S3_BUCKET` |
| `CONTAINER_SERVICE` | `DEPENDS_ON` | `CLOUD_SQL` |
| `CONTAINER_SERVICE` | `DEPENDS_ON` | `TASK_DEFINITION` |
| `CONTAINER_SERVICE` | `DNS_RESOLVED` | `DNS_RECORD` |
| `CONTAINER_SERVICE` | `READS_FROM` | `SECRET` |
| `CUSTOM_DOMAIN` | `CERTIFICATE_SECURES` | `CERTIFICATE` |
| `DATABASE_PROXY` | `READS_FROM` | `SECRET` |
| `DATA_CATALOG` | `DEPENDS_ON` | `S3_BUCKET` |
| `DATA_TRANSFER` | `DEPENDS_ON` | `S3_BUCKET` |
| `DATA_TRANSFER` | `READS_FROM` | `DATA_TRANSFER` |
| `DATA_TRANSFER` | `WRITES_TO` | `DATA_TRANSFER` |
| `DATA_TRANSFER` | `WRITES_TO` | `S3_BUCKET` |
| `DATA_WAREHOUSE` | `DEPENDS_ON` | `DATA_WAREHOUSE` |
| `DELIVERY_STREAM` | `BACKUP_TO` | `S3_BUCKET` |
| `DEPLOYMENT_GROUP` | `MONITORED_BY` | `ALARM` |
| `DYNAMODB_TABLE` | `BACKUP_TO` | `BACKUP_VAULT` |
| `DYNAMODB_TABLE` | `ENCRYPTED_BY_KMS` | `KMS_KEY` |
| `DYNAMODB_TABLE` | `REPLICATES_TO` | `DYNAMODB_TABLE` |
| `DYNAMODB_TABLE` | `STREAMS_TO` | `DATA_STREAM` |
| `EBS_VOLUME` | `ENCRYPTED_BY_KMS` | `KMS_KEY` |
| `EC2` | — | `VPC` |
| `ECS_CLUSTER` | `SCALES_WITH` | `CAPACITY_PROVIDER` |
| `ETL_JOB` | `DEPENDS_ON` | `DATA_CATALOG` |
| `ETL_JOB` | `READS_FROM` | `S3_BUCKET` |
| `ETL_JOB` | `WRITES_TO` | `DATA_CATALOG` |
| `ETL_JOB` | `WRITES_TO` | `S3_BUCKET` |
| `EVENT_ARCHIVE` | `READS_FROM` | `EVENT_BUS` |
| `GCE_INSTANCE` | — | `VPC` |
| `GKE_CLUSTER` | — | `VPC` |
| `GKE_CLUSTER` | `ENCRYPTED_BY_KMS` | `KMS_KEY` |
| `GUARDRAIL` | — | `RESOURCE_GROUP` |
| `GUARDRAIL` | `DEPENDS_ON` | `GUARDRAIL` |
| `IDENTITY_POOL` | `DEPENDS_ON` | `USER_POOL` |
| `IDENTITY_PROVIDER` | `DEPENDS_ON` | `CLOUD_ACCOUNT` |
| `IDENTITY_USER` | `READS_FROM` | `S3_BUCKET` |
| `JOB_QUEUE` | `RUNS_ON` | `BATCH_ENVIRONMENT` |
| `K8S_WORKLOAD` | `RUNS_ON` | `K8S_SERVICE_ACCOUNT` |
| `KMS_KEY` | — | `CLOUD_ACCOUNT` |
| `KMS_KEY` | `ENCRYPTED_BY_KMS` | `KEY_VAULT` |
| `KNOWLEDGE_BASE` | `READS_FROM` | `S3_BUCKET` |
| `KNOWLEDGE_BASE` | `READS_FROM` | `SEARCH_DOMAIN` |
| `LAMBDA_FUNCTION` | `DEPENDS_ON` | `LAMBDA_FUNCTION` |
| `LAMBDA_FUNCTION` | `DEPENDS_ON` | `MESSAGE_QUEUE` |
| `LOAD_BALANCER` | — | `VPC` |
| `MACHINE_IMAGE` | `DEPENDS_ON` | `SNAPSHOT` |
| `MESSAGE_QUEUE` | `ENCRYPTED_BY_KMS` | `KMS_KEY` |
| `MESSAGE_QUEUE` | `WRITES_TO` | `MESSAGE_QUEUE` |
| `ML_ENDPOINT` | `DEPENDS_ON` | `ML_MODEL` |
| `ML_MODEL` | `READS_FROM` | `S3_BUCKET` |
| `NACL` | — | `SUBNET` |
| `NACL` | — | `VPC` |
| `OTHER` | — | `MESSAGE_QUEUE` |
| `PROVISIONED_PRODUCT` | `DEPENDS_ON` | `PRODUCT_PORTFOLIO` |
| `QUERY_WORKGROUP` | `WRITES_TO` | `S3_BUCKET` |
| `ROUTE_TABLE` | — | `PEERING_CONNECTION` |
| `ROUTE_TABLE` | — | `VPC` |
| `SCHEDULE` | `DEPENDS_ON` | `RUNBOOK` |
| `SCHEDULE` | `WRITES_TO` | `MESSAGE_QUEUE` |
| `SECRET` | `ENCRYPTED_BY_KMS` | `KMS_KEY` |
| `SECURITY_GROUP` | — | `SECURITY_GROUP` |
| `SECURITY_GROUP` | — | `VPC` |
| `SNAPSHOT` | — | `AURORA_CLUSTER` |
| `SNAPSHOT` | — | `EBS_VOLUME` |
| `SNAPSHOT` | — | `RDS_INSTANCE` |
| `SUBNET` | — | `VPC` |
| `TARGET_GROUP` | — | `VPC` |
| `VPC` | — | `CLOUD_ACCOUNT` |
| `VPC_ENDPOINT` | `DEPENDS_ON` | `BLOB_STORAGE` |

### ROUTE

| Source type | Relationship | Target type |
|---|---|---|
| `CLOUDFRONT` | `SERVES_TRAFFIC_TO` | `LOAD_BALANCER` |
| `CLOUDFRONT` | `SERVES_TRAFFIC_TO` | `S3_BUCKET` |
| `CLOUD_ACCOUNT` | `SERVES_TRAFFIC_TO` | `ENDPOINT_SERVICE` |
| `CONTAINER_SERVICE` | `TRANSIT_ROUTED` | `VPC_LINK` |
| `CUSTOM_DOMAIN` | `SERVES_TRAFFIC_TO` | `API_GATEWAY` |
| `DIRECT_CONNECT` | `TRANSIT_ROUTED` | `CLOUD_ACCOUNT` |
| `DIRECT_CONNECT` | `TRANSIT_ROUTED` | `DIRECT_CONNECT` |
| `DIRECT_CONNECT` | `TRANSIT_ROUTED` | `TRANSIT_GATEWAY` |
| `DIRECT_CONNECT` | `TRANSIT_ROUTED` | `VPN_GATEWAY` |
| `DNS_RECORD` | `DNS_RESOLVED` | `CLOUDFRONT` |
| `DNS_RECORD` | `DNS_RESOLVED` | `CUSTOM_DOMAIN` |
| `DNS_RECORD` | `DNS_RESOLVED` | `LOAD_BALANCER` |
| `DNS_RESOLVER` | `DNS_RESOLVED` | `DNS_RESOLVER` |
| `K8S_INGRESS` | `SERVES_TRAFFIC_TO` | `K8S_SERVICE` |
| `LB_LISTENER` | `SERVES_TRAFFIC_TO` | `TARGET_GROUP` |
| `LOAD_BALANCER` | `LOAD_BALANCED_BY` | `K8S_SERVICE` |
| `LOAD_BALANCER` | `SERVES_TRAFFIC_TO` | `LOAD_BALANCER` |
| `ROUTE_TABLE` | `TRANSIT_ROUTED` | `INTERNET_GATEWAY` |
| `ROUTE_TABLE` | `TRANSIT_ROUTED` | `NETWORK_FIREWALL` |
| `ROUTE_TABLE` | `TRANSIT_ROUTED` | `VPC` |
| `TRANSIT_GATEWAY` | `TRANSIT_ROUTED` | `VPC` |
| `VPN_CONNECTION` | `TRANSIT_ROUTED` | `CUSTOMER_GATEWAY` |

### USES_IMAGE

| Source type | Relationship | Target type |
|---|---|---|
| `AKS_CLUSTER` | `RUNS_ON` | `CONTAINER_REGISTRY` |
| `APP_SERVICE` | `RUNS_ON` | `CONTAINER_REGISTRY` |
| `BUILD_PROJECT` | `RUNS_ON` | `CONTAINER_REGISTRY` |
| `CONTAINER_SERVICE` | `RUNS_ON` | `CONTAINER_REGISTRY` |
| `JOB_DEFINITION` | `RUNS_ON` | `CONTAINER_REGISTRY` |
| `K8S_WORKLOAD` | `RUNS_ON` | `CONTAINER_REGISTRY` |
| `ML_MODEL` | `RUNS_ON` | `CONTAINER_REGISTRY` |
| `TASK_DEFINITION` | — | `CONTAINER_REGISTRY` |
| `TASK_DEFINITION` | `RUNS_ON` | `CONTAINER_REGISTRY` |

## Relationship vocabulary

`relationship` values are `RelationType` names from `cloudg/graph/ontology_rules.py`, so the
ontology export uses the declared relation instead of re-inferring one. The inventory uses:

| Relationship | Meaning |
|---|---|
| `ACCOUNT_CONTAINS_REGION` | Account (or subscription) contains a resource or resource group. Used for the hierarchy edges `add_account_hierarchy` adds (`properties.hierarchy: true`). |
| `BACKUP_TO` | Data is backed up to the target (backup plan → vault, Firehose backup bucket, ...). |
| `CERTIFICATE_SECURES` | A certificate secures the source endpoint (listener, distribution, custom domain). |
| `CLUSTER_CONTAINS_SERVICE` | A cluster contains a service, node group, namespace or workload (ECS, EKS, AKS, GKE, App Service plans). |
| `COMPLIANCE_GOVERNS` | A non-SCP organization policy, Control Tower control / baseline, Azure Policy or GCP org policy governs the target. |
| `CROSS_ACCOUNT_TRUST` | IAM trust that crosses an account boundary. |
| `DEPENDS_ON` | Generic functional dependency (environment references, private endpoint connections, Kubernetes services). |
| `DNS_RESOLVED` | A DNS record or namespace resolves to the target. |
| `ENCRYPTED_BY_KMS` | Encrypted with the target key (KMS, Key Vault key, Cloud KMS). |
| `INVOKES` | Calls or delivers to the target (notifications, rule targets, state machine tasks, integrations). |
| `LB_TARGETS_INSTANCE` | Load balancer / target group → registered target. |
| `LOAD_BALANCED_BY` | The source sits behind the target load balancer (often declared `reverse`). |
| `LOGS_TO` | Sends logs to the target destination. |
| `MONITORED_BY` | Monitored by the target (alarms, Inspector coverage, flow logs, Security Hub sources). |
| `NAT_TRANSLATED` | Route via a NAT gateway. |
| `ORG_CONTAINS_ACCOUNT` | OU / root contains an account; management group contains a subscription. |
| `OWNED_BY` | Ownership / management (stack → resource, landing zone → shared accounts, permission set → SSO role). |
| `POLICY_ALLOWS_ACTION` | A policy or role assignment grants the principal access to the target. |
| `PROTECTED_BY_NACL` | Subnet protected by a network ACL. |
| `PROTECTED_BY_SG` | Resource protected by a security group / NSG. |
| `PROTECTED_BY_WAF` | Resource protected by a WAF web ACL / Cloud Armor / WAF policy. |
| `READS_FROM` | Reads data from the target (sources, mounted volumes, secrets, parameters). |
| `REPLICATES_TO` | Replicates data to the target (S3 replication, DynamoDB replicas, secret replicas). |
| `ROLE_ASSUMES_ROLE` | A principal may assume or impersonate the target identity. |
| `ROTATES_SECRET` | A function rotates the target secret. |
| `RUNS_ON` | Runs as an identity, or on an image / compute platform. |
| `SCALES_WITH` | Scaling relationship (alarm → scaling policy, capacity provider → ASG). |
| `SCHEDULED_BY` | Scheduled by the target (maintenance windows, schedules). |
| `SCP_RESTRICTS` | A service control policy restricts the target OU or account. |
| `SERVES_TRAFFIC_TO` | Forwards client traffic to the target (origins, routes, backends, ingress backends). |
| `STREAMS_TO` | Streams records to the target (SNS → SQS, Firehose, log subscriptions). |
| `SUBNET_CONTAINS_INSTANCE` | Subnet (or network) contains the resource. |
| `TRANSIT_ROUTED` | Traffic routed via the target (route tables, transit gateway attachments). |
| `TRIGGERED_BY` | The target is triggered by the source (event source mappings, permissions with a SourceArn). |
| `VPC_CONTAINS_SUBNET` | VPC / VNet contains a subnet. |
| `VPC_PEERED` | VPC peering. |
| `WRITES_TO` | Writes data to the target (dead-letter queues, destinations, output locations). |
