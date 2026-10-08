# cloudg inventory reference: return structures

This document specifies every structure the inventory mapper returns or writes: the Python
objects (`CloudAsset`, `NetworkEdge`, relation objects, `InventoryResult`, `DependencyGraph`
results, `OrganizationTopology`, coverage records) and every exported file
(`inventory-map.json`, `inventory-graph.json`, `inventory-map.graphml`,
`inventory-dependencies.json`, `inventory-organization.json`, `asset-map.json`,
`compliance-map.json`) plus the `cloudg deps --json` output. Each structure has a field table
(name, type, nullability, meaning, how it is computed) and an annotated example.

Related documents:

- [INVENTORY_CATALOG.md](INVENTORY_CATALOG.md): every asset type, the metadata keys it carries,
  the relations it declares, and the full relationship matrix.
- [INVENTORY_INTERNALS.md](INVENTORY_INTERNALS.md): how the mapper, collectors and linker work, and
  how to extend them.
- [DOCUMENTATION.md](DOCUMENTATION.md): CLI flags, configuration and the rest of cloudg.

The examples are taken from a real `cloudg map --org` run against a simulated (moto) AWS
Organization with a management account, one member account in a nested OU, and one vendor
account trusted by a role. Long values are shortened with `…`; UUIDs are real values from that
run, so cross-references between the examples line up.

## Contents

1. [Conventions](#1-conventions)
2. [Where each structure comes from](#2-where-each-structure-comes-from)
3. [CloudAsset](#3-cloudasset)
4. [Identifier formats](#4-identifier-formats)
5. [NetworkEdge](#5-networkedge)
6. [Edge types and direction](#6-edge-types-and-direction)
7. [The relation object](#7-the-relation-object-metadatarelations)
8. [InventoryResult](#8-inventoryresult)
9. [summary](#9-summary)
10. [Coverage records](#10-coverage-records)
11. [Unresolved references](#11-unresolved-references)
12. [DependencyGraph results](#12-dependencygraph-results)
13. [analysis() and inventory-dependencies.json](#13-analysis-and-inventory-dependenciesjson)
14. [inventory-map.json](#14-inventory-mapjson)
15. [inventory-graph.json](#15-inventory-graphjson)
16. [inventory-map.graphml](#16-inventory-mapgraphml)
17. [OrganizationTopology and inventory-organization.json](#17-organizationtopology-and-inventory-organizationjson)
18. [Organization assets on the map](#18-organization-assets-on-the-map)
19. [asset-map.json and compliance-map.json](#19-asset-mapjson-and-compliance-mapjson)
20. [cloudg deps --json](#20-cloudg-deps---json)
21. [Lower-level return values](#21-lower-level-return-values)
22. [Stability and compatibility](#22-stability-and-compatibility)

---

## 1. Conventions

- **Types** are written as Python annotations. In JSON, `str | None` is a string or `null`,
  `datetime` is an ISO 8601 string without a timezone suffix (`"2026-10-04T15:34:54.643569"`,
  UTC), enums are their string value.
- **IDs vs identifiers.** Every asset has two keys:
  - `id`: an internal UUID generated when the asset is built. **It changes on every run.** Edges
    reference assets by `id`, so inside one map file `id` is the join key.
  - `arn`: the stable, cloud-native identifier (an AWS ARN, an Azure resource ID, a GCP full
    resource name, or a cloudg synthetic identifier, see [Identifier formats](#4-identifier-formats)).
    Use `arn` to correlate assets across runs.
- **Order.** Lists are in collection order unless a section says otherwise. Do not rely on the
  order of `assets` or `edges`.
- **Counts dictionaries** (`assets_by_type`, ...) map a key to an integer. Some are sorted by
  descending count; the field tables say which. JSON keeps insertion order, Python dicts too.

## 2. Where each structure comes from

| You call / run | You get | Section |
|---|---|---|
| `InventoryMapper(config).map_inventory()` / `map_inventory_sync()` | `InventoryResult` | [8](#8-inventoryresult) |
| `CloudGEngine.map_inventory(output_dir=None, findings=None, tagging_sweep=None)` | `InventoryResult` (and files when `output_dir` is set) | [8](#8-inventoryresult) |
| `InventoryResult.summary` | `dict` | [9](#9-summary) |
| `InventoryResult.analysis(top=25)` | `dict` | [13](#13-analysis-and-inventory-dependenciesjson) |
| `InventoryResult.dependency_graph(include_hierarchy=False)` | `DependencyGraph` | [12](#12-dependencygraph-results) |
| `InventoryResult.export(output_dir)` | `dict[str, Path]` and the files below | [8.3](#83-export) |
| `InventoryResult.load(path)` | `InventoryResult` | [8.4](#84-load) |
| `InventoryMapper.build_asset_map(result, findings)` | `dict` (= `asset-map.json`) | [19](#19-asset-mapjson-and-compliance-mapjson) |
| `InventoryMapper.build_compliance_map(result, findings)` | `dict` (= `compliance-map.json`) | [19](#19-asset-mapjson-and-compliance-mapjson) |
| `InventoryMapper.export_merged(result, findings, dir)` | `dict[str, Path]` | [19](#19-asset-mapjson-and-compliance-mapjson) |
| `discover_organization(session, control_tower=True, home_region=None)` | `OrganizationTopology` | [17](#17-organizationtopology-and-inventory-organizationjson) |
| `RelationshipLinker(assets).link(include_generic=True)` | `list[NetworkEdge]` (+ `external_assets`, `unresolved`) | [21.1](#211-relationshiplinker) |
| `AWSDeepInventoryCollector(...).run()` | `tuple[list[CloudAsset], list[NetworkEdge]]` | [21.2](#212-collectors) |
| `cloudg map` | the files in sections 14 to 19 | |
| `cloudg deps <asset> --json` / `cloudg deps --json` | a tree / an overview | [20](#20-cloudg-deps---json) |

---

## 3. CloudAsset

`cloudg.schema.models.CloudAsset`, a Pydantic v2 model (`extra="allow"`, `populate_by_name=True`).
One node of the map: a cloud resource, an identity, a security service (or its absence), an
account, an organization unit, a policy, or a Kubernetes object.

### 3.1 Fields

| Field | Type | Default | Meaning |
|---|---|---|---|
| `id` | `str` | new UUID4 | Internal ID, unique within one map, regenerated each run. Edge endpoints reference it. |
| `arn` | `str \| None` | `None` | Stable native or synthetic identifier ([formats](#4-identifier-formats)). Deduplication key: two assets with the same `arn` are merged. Every inventory asset sets it. |
| `name` | `str` | required | Display name: the `Name` tag, the resource name, or the identifier when the resource has no name. Not unique. |
| `asset_type` | `AssetType` | required | One of 156 values; see [INVENTORY_CATALOG.md](INVENTORY_CATALOG.md). Unclassifiable resources are `OTHER`. |
| `provider` | `CloudProvider` | required | `AWS`, `AZURE` or `GCP` (upper case). Kubernetes objects inside EKS are `AWS`, inside GKE `GCP`. |
| `region` | `str` | `"global"` | Region / location. `"global"` for account-wide resources (IAM, S3 buckets as listed, CloudFront, Route 53, organizations, accounts, Entra principals). Azure uses the ARM location (`eastus`), GCP the CAI location (`us-central1`, `us-central1-a`, `global`). |
| `account_id` | `str \| None` | `None` | AWS account ID, Azure subscription ID, or GCP project ID. `None` for tenant-wide identities (Entra principals) and GCP organization / folder level resources. |
| `tags` | `dict[str, str]` | `{}` | Tags / labels, values stringified. Kubernetes objects carry their labels here. |
| `metadata` | `dict[str, Any]` | `{}` | Normalised attributes. Contents depend on the type; see [Common metadata keys](INVENTORY_CATALOG.md#common-metadata-keys) and the per-type reference. Always JSON-serialisable. |
| `raw_data` | `dict[str, Any]` | `{}` | Raw API payload used during linking. **Excluded from serialisation** (`exclude=True`): never present in `model_dump()` or any file. |
| `collected_at` | `datetime` | now (UTC) | When the asset object was built. |
| `is_internet_exposed` | `bool` | `False` | Reachable from the internet according to the collector (public IP with an open security group, internet-facing load balancer, public bucket / function URL / API, GCP firewall open to `0.0.0.0/0`, `allUsers` bindings, Azure public network access without a deny ACL, Kubernetes `LoadBalancer` services and ingresses with a hostname, ...). |
| `display_id` | `str` (computed) | `arn or id` | Serialised by `model_dump()`; ignored by `InventoryResult.load()`. |

Because the model allows extra fields, a collector or plugin may attach additional top-level
fields; they survive `model_dump()` and `load()`.

### 3.2 Example

A Lambda function from the example run (`metadata` abridged to the keys that matter here):

```json
{
  "id": "60cac611-8a80-469e-bca6-ee3cf1cdc35b",
  "arn": "arn:aws:lambda:us-east-1:123456789012:function:orders-worker",
  "name": "orders-worker",
  "asset_type": "LAMBDA_FUNCTION",
  "provider": "AWS",
  "region": "us-east-1",
  "account_id": "123456789012",
  "tags": {},
  "metadata": {
    "runtime": "python3.12",
    "handler": "h.h",
    "package_type": "Zip",
    "image_uri": null,
    "memory_size": 128,
    "timeout": 3,
    "vpc_config": null,
    "role_arn": "arn:aws:iam::123456789012:role/orders-worker",
    "environment_keys": ["DB_PASSWORD", "QUEUE_URL"],
    "event_sources": ["arn:aws:sqs:us-east-1:123456789012:orders"],
    "function_url_auth": null,
    "policy_allows_public": false,
    "relations": [
      {"target": "arn:aws:iam::123456789012:role/orders-worker",
       "edge": "ASSUMES_ROLE", "relationship": "RUNS_ON", "description": "execution role"},
      {"target": "https://sqs.us-east-1.amazonaws.com/123456789012/orders",
       "edge": "REFERENCES", "relationship": "DEPENDS_ON", "description": "environment reference"},
      {"target": "arn:aws:logs:us-east-1:123456789012:log-group:/aws/lambda/orders-worker",
       "edge": "LOGS_TO", "relationship": "LOGS_TO"},
      {"target": "arn:aws:sqs:us-east-1:123456789012:orders",
       "edge": "INVOKES", "relationship": "TRIGGERED_BY", "reverse": true,
       "description": "event source mapping",
       "properties": {"state": "Enabled", "batch_size": 10}}
    ],
    "aliases": ["arn:aws:lambda:us-east-1:123456789012:function:orders-worker:$LATEST"]
  },
  "collected_at": "2026-10-04T15:34:54.643569",
  "is_internet_exposed": false,
  "display_id": "arn:aws:lambda:us-east-1:123456789012:function:orders-worker"
}
```

Things to notice:

- `environment_keys` lists variable **names**. Values are never collected. The queue URL in
  `QUEUE_URL` reached the map only as a relation target, because identifier-shaped values (ARNs,
  SQS queue URLs judged by their parsed host) are extracted as references and everything else is
  dropped.
- The relations are the collector's declarations. The linker turned four of them into edges
  except the log group one, which did not resolve (the log group did not exist) and therefore
  appears in `unresolved_references` ([section 11](#11-unresolved-references)).
- `reverse: true` on the event source mapping means the edge points from the queue to the
  function: `SQS INVOKES Lambda (TRIGGERED_BY)`.

### 3.3 Placeholder assets

Some assets stand for something that was referenced rather than collected:

| Kind | `arn` | `asset_type` | Distinguishing metadata |
|---|---|---|---|
| Security service not enabled (AWS) | `cloudg:aws:<service>:<region>:<account>:not-enabled` | the service's type (`VULNERABILITY_SCANNER`, `THREAT_DETECTOR`, ...) | `security_service`, `enabled: false`, `status: "not enabled"`, alias `aws-security:<service>:<region>:<account>` |
| Defender plan off (Azure) | the pricing resource ID | `THREAT_DETECTOR` | `security_service: "defender-<plan>"`, `enabled: false` |
| External account | `arn:aws:iam::<id>:root`, `/subscriptions/<id>`, `//cloudresourcemanager.googleapis.com/projects/<id>` | `CLOUD_ACCOUNT` | `external: true`, `discovered_via: "cross-account reference"` |
| Entra principal | `entra:principal/<objectId>` | `IDENTITY_USER`, `IDENTITY_GROUP` or `SERVICE_PRINCIPAL` | `placeholder: true`, `principal_type`, `discovered_via: "entra-principal-reference"` |
| GCP principal | `gcp-principal:<member>` or `k8s-gke://…` | `IDENTITY_USER`, `IDENTITY_GROUP`, `SERVICE_PRINCIPAL`, `K8S_SERVICE_ACCOUNT`, ... | `discovered_via: "iam_policy"` or `"workload_reference"` |

Example, Inspector not enabled:

```json
{
  "id": "07911321-f52d-438c-91b1-3be831c2451b",
  "arn": "cloudg:aws:inspector2:us-east-1:123456789012:not-enabled",
  "name": "Inspector (not enabled)",
  "asset_type": "VULNERABILITY_SCANNER",
  "provider": "AWS",
  "region": "us-east-1",
  "account_id": "123456789012",
  "tags": {},
  "metadata": {
    "security_service": "inspector2",
    "enabled": false,
    "status": "not enabled",
    "aliases": ["aws-security:inspector2:us-east-1:123456789012"]
  },
  "collected_at": "2026-10-04T15:34:07.879548",
  "is_internet_exposed": false,
  "display_id": "cloudg:aws:inspector2:us-east-1:123456789012:not-enabled"
}
```

Example, an external account created because a role trusts it:

```json
{
  "id": "277ef061-8a0c-4e1e-9451-a50aa57198f8",
  "arn": "arn:aws:iam::999999999999:root",
  "name": "external account 999999999999",
  "asset_type": "CLOUD_ACCOUNT",
  "provider": "AWS",
  "region": "global",
  "account_id": "999999999999",
  "metadata": {
    "account_id": "999999999999",
    "external": true,
    "discovered_via": "cross-account reference"
  },
  "is_internet_exposed": false
}
```

---

## 4. Identifier formats

What can appear in `arn`, in `metadata.aliases` and as a relation `target`. The linker
([INVENTORY_INTERNALS.md](INVENTORY_INTERNALS.md#7-the-relationship-linker)) resolves any of these.

| Format | Example | Used for |
|---|---|---|
| AWS ARN | `arn:aws:sqs:us-east-1:123456789012:orders` | every AWS resource that has an ARN; partitions `aws-cn`, `aws-us-gov` are accepted |
| AWS synthetic ARN | `arn:aws:ec2:us-east-1:123456789012:route-table/rtb-…` | EC2 sub-resources whose API returns no ARN; built the same way AWS would |
| AWS account node | `arn:aws:iam::123456789012:root` | `CLOUD_ACCOUNT` (mapped or external) and account principals (`"123456789012"` in a policy resolves here) |
| cloudg AWS synthetic | `cloudg:aws:<service>:<region>:<account>:<id>` | resources without any native identifier, not-enabled security services, the organization when its ARN is unknown (`cloudg:aws:organization:<id>`), the landing zone fallback (`cloudg:aws:controltower:landing-zone`) |
| Cloud Control synthetic | `cloudcontrol:<CFN type>:<region>:<account>:<identifier>` | Cloud Control hits whose model has no ARN |
| AWS security alias | `aws-security:<service>:<region>:<account>` | "the GuardDuty / Inspector / … deployment here", an alias on the real asset and on the placeholder |
| EKS Kubernetes object | `k8s://<cluster ARN>/<namespace>/<Kind>/<name>` | namespaces use namespace `_cluster`; e.g. `k8s://arn:aws:eks:…:cluster/prod/payments/Deployment/api` |
| Azure resource ID | `/subscriptions/<sub>/resourceGroups/<rg>/providers/<ns>/<type>/<name>` | every Azure resource; compared case-insensitively (lower-cased copies are indexed) |
| Azure subscription | `/subscriptions/<sub>` | subscription `CLOUD_ACCOUNT` |
| Azure management group | `/providers/Microsoft.Management/managementGroups/<name>` | management group `ORG_UNIT` |
| Entra principal | `entra:principal/<objectId>` | users, groups, service principals, managed identities (lower case) |
| Log Analytics | `loganalytics:<customerId>` | alias of a Log Analytics workspace, for references by workspace ID |
| Azure security alias | `azure-security:<service>:<subscription>` | Defender plan assets |
| Azure host names | `<name>.azurecr.io`, `<name>.vault.azure.net`, `<app>.azurewebsites.net` | lower-case aliases; image references resolve to their registry login server |
| GCP full resource name | `//compute.googleapis.com/projects/p/zones/z/instances/i` | every GCP resource (CAI `name`) |
| GCP project node | `//cloudresourcemanager.googleapis.com/projects/<id>` | project `CLOUD_ACCOUNT` / container |
| GCP service account ref | `serviceAccount:<email>` | alias of every service account; how relations name them |
| GCP principal | `gcp-principal:user:alice@example.com` | IAM members that are not collected resources |
| GKE Kubernetes SA | `k8s-gke://<pool project>/<namespace>/<ksa>` | Workload Identity Kubernetes service accounts |
| Short IDs and names | `vpc-0897edd53e9ac20d7`, `orders-worker`, `sg-…` | indexed for every asset (name, last ARN segment, known `*_id` metadata keys); resolved with account/region scoping |
| Endpoints | `https://sqs.us-east-1.amazonaws.com/1234…/orders`, `web-alb-1.us-east-1.elb.amazonaws.com`, `orders-uploads.s3.amazonaws.com`, `<repo URI>` | queue URLs, load balancer and CloudFront DNS names, bucket domains, ECR repository URIs |

---

## 5. NetworkEdge

`cloudg.schema.models.NetworkEdge`, a Pydantic v2 model (`extra="allow"`). A directed edge between
two assets.

### 5.1 Fields

| Field | Type | Default | Meaning |
|---|---|---|---|
| `id` | `str` | new UUID4 | Edge ID, regenerated each run. |
| `source_id` | `str` | required | Source endpoint. For edges produced by the inventory linker and mapper this is always an asset `id`. See [5.3](#53-collector-network-edges) for the exception. |
| `target_id` | `str` | required | Target endpoint, same rules. |
| `edge_type` | `EdgeType` | required | Coarse class; see [section 6](#6-edge-types-and-direction). |
| `relationship` | `str \| None` | `None` | Fine-grained relation, a `RelationType` name from the ontology (`TRIGGERED_BY`, `RUNS_ON`, `CROSS_ACCOUNT_TRUST`, ...). `None` when the edge class says it all. See the [vocabulary](INVENTORY_CATALOG.md#relationship-vocabulary). |
| `properties` | `dict[str, Any]` | `{}` | Relation-specific detail copied from the declaration (empty values dropped), plus linker annotations (below). |
| `description` | `str \| None` | `None` | Human-readable explanation (`"event source mapping"`, `"arn:aws:iam::999999999999:root can assume this role"`). |
| `ports` | `list[int]` | `[]` | Network edges only. |
| `port_range` | `str \| None` | `None` | Network edges only, `"80-443"`, `"0-65535"`. |
| `protocol` | `str \| None` | `None` | Network edges only: `TCP`, `UDP`, `ICMP`, `ALL`. |
| `cidr` | `str \| None` | `None` | Network edges only: `"0.0.0.0/0"`. |
| `direction` | `str` | `"ingress"` | `ingress` or `egress` for network rule edges. Relationship edges keep the default `"ingress"`, which carries no meaning for them. |

### 5.2 `properties` keys added by the linker and mapper

| Key | Added by | Meaning |
|---|---|---|
| `external_reference` | linker | The edge points at an external account placeholder; this is the identifier that was referenced (the specific role ARN or bucket in the unmapped account). |
| `hierarchy` | `add_account_hierarchy` | `true` on account → top-level resource `CONTAINS` edges. These edges are excluded from `unlinked_assets`, `cross_account_edges` and dependency walks. |

Every other key comes from the collector's declaration. Common ones: `cross_account`
(`true` when the grantee lives in another account), `conditions` (the IAM condition block of a
trust statement), `external_id_required`, `actions`, `access_policies` (EKS access entries),
`role`, `privileged`, `principal_type`, `assignment_id` (Azure role assignments), `events`
(S3 notification events), `batch_size`, `state`, `network_rule`, `status`, `key_uri`, `via`.

### 5.3 Collector network edges

The AWS collector's own `collect_edges()` adds two kinds of edges before linking:

- `SECURITY_GROUP_RULE`, one per rule and CIDR, between the CIDR string and the security
  group asset's `id`: ingress edges go `cidr → <sg asset id>`, egress edges
  `<sg asset id> → cidr`. The native group ID stays in the asset's `metadata.group_id` and
  `arn`. `ports`, `port_range`, `protocol`, `cidr` and `direction` are filled.
- `CONTAINS` VPC → subnet, between asset UUIDs.

The Azure collector's `collect_edges()` adds `SECURITY_GROUP_RULE` edges for NSG inbound rules,
from the rule's source address prefix (a CIDR, a service tag, `*`, or an application security
group's resource ID when it was collected) to the NSG asset, and `CONTAINS / VPC_CONTAINS_SUBNET`
edges from each VNet to its subnets.

The GCP collector adds one edge per internet ingress entry from `0.0.0.0/0` to the exposed asset:
`INTERNET_EXPOSED` for exposure found through IAM, external IPs or load balancers, and
`SECURITY_GROUP_RULE` for firewall rules, with `ports` / `protocol` from the firewall evaluation.

The security group / NSG side of a rule edge is always an asset `id`; the other side is
deliberately external. Consumers that join edges to assets must therefore expect a few endpoints
that are not asset IDs: CIDRs, Azure service tags and `*`, and the resource ID of an application
security group that was not collected. The graph exports turn them into nodes with `is_external: true`
([section 15](#15-inventory-graphjson)), and `DependencyGraph` ignores edges whose endpoints
are not assets.

```json
{
  "id": "8cbfec40-e9a8-4546-bf1f-2f47d542b8b3",
  "source_id": "0.0.0.0/0",
  "target_id": "6f0d2c8e-3b1a-4f57-9c2e-8a41d7e5b903",
  "edge_type": "SECURITY_GROUP_RULE",
  "ports": [443],
  "port_range": "443",
  "protocol": "TCP",
  "cidr": "0.0.0.0/0",
  "direction": "ingress",
  "description": null,
  "relationship": null,
  "properties": {}
}
```

### 5.4 Examples of linked edges

Cross-account trust, from the external vendor account to a role (the role's trust policy
requires an external ID):

```json
{
  "id": "d9c70eec-a4c4-4144-ab2f-27f67e00b6c5",
  "source_id": "277ef061-8a0c-4e1e-9451-a50aa57198f8",
  "target_id": "1bd88609-88f3-46d7-868e-ac65ece6b65a",
  "edge_type": "IAM_TRUST",
  "ports": [], "port_range": null, "protocol": null, "cidr": null,
  "direction": "ingress",
  "description": "arn:aws:iam::999999999999:root can assume this role",
  "relationship": "CROSS_ACCOUNT_TRUST",
  "properties": {
    "conditions": {"StringEquals": {"sts:ExternalId": "vendor-123"}},
    "external_id_required": true,
    "external_reference": "arn:aws:iam::999999999999:root"
  }
}
```

The external ID value shown is the one in the trust policy of the test fixture. Trust policy
conditions are copied as written, so treat `properties.conditions` with the same care as the
policy itself.

S3 event notification invoking a function (`arn:aws:s3:::orders-uploads` →
`…:function:orders-worker`):

```json
{
  "source_id": "2028991c-a3b7-4c55-afde-01ccac602552",
  "target_id": "60cac611-8a80-469e-bca6-ee3cf1cdc35b",
  "edge_type": "INVOKES",
  "description": "event notification",
  "relationship": "INVOKES",
  "properties": {"events": ["s3:ObjectCreated:*"]}
}
```

Account hierarchy:

```json
{
  "source_id": "95628cf7-805e-4b30-989c-189c6da80ef6",
  "target_id": "8d7d700b-7f64-4821-97b2-45577d1faf7a",
  "edge_type": "CONTAINS",
  "description": "account 123456789012 contains FullAWSAccess",
  "relationship": "ACCOUNT_CONTAINS_REGION",
  "properties": {"hierarchy": true}
}
```

---

## 6. Edge types and direction

Direction always reads **source verb target**. The dependency column is how `DependencyGraph`
turns the edge into a "dependent needs dependency" arrow
(`cloudg.inventory.dependencies.DEPENDENCY_DIRECTION`): *forward* means the source depends on the
target, *reverse* means the target depends on the source, *ignored* means the edge does not take
part in dependency analysis.

| `edge_type` | Reads as | Typical source → target | Dependency |
|---|---|---|---|
| `REFERENCES` | uses / points at | function → secret, table → KMS key, queue → DLQ, anything → anything (generic pass) | forward |
| `ATTACHED_TO` | is attached to | instance → security group, volume → instance, ENI → instance, IGW → VPC | forward |
| `ROUTE` | routes through / forwards to | route table → gateway, DNS record → load balancer, transit gateway → attachment, Ingress → Service | forward |
| `PEERING` | peers with | VPC → peering connection → VPC | forward |
| `USES_IMAGE` | runs the image of | task definition / workload / function / build project → container registry | forward |
| `ASSUMES_ROLE` | runs as | function, task, nodegroup, Kubernetes SA, instance profile, GCP workload → role / service account | forward |
| `LOGS_TO` | sends logs to | trail, flow log, LB, API stage, function → log destination | forward |
| `LOAD_BALANCER_TARGET` | sends traffic to | load balancer → target group → instance / IP / function; Kubernetes Service → workload | forward |
| `GRANTS_ACCESS` | is granted access to | principal → resource its policy names; principal → EKS cluster; Azure principal → scope | forward |
| `IAM_POLICY_ATTACHMENT` | has policy | user / group / role → managed policy | forward |
| `IAM_TRUST` | may assume | principal / account / provider → role | forward |
| `CONTAINS` | contains | VPC → subnet, subnet → instance, cluster → namespace, account → resource, OU → account | reverse |
| `INVOKES` | triggers / calls | bucket → function, queue → function, rule → target, topic → queue | reverse |
| `PROTECTS` | protects | WAF → ALB / API / distribution, firewall → VPC, Shield → resource | reverse |
| `MONITORS` | monitors | Inspector → instance / repository / function, GuardDuty → account, alarm → resource | reverse |
| `MANAGES` | manages | stack → resource, ASG → instance, landing zone → OU / account, permission set → SSO role | reverse |
| `GOVERNS` | governs | SCP / RCP / control / Azure Policy / GCP org policy → OU, account, folder, project | reverse |
| `SECURITY_GROUP_RULE` | allows traffic | CIDR → SG (ingress), SG → CIDR (egress) | ignored |
| `NACL_RULE` | allows traffic | network ACL rules | ignored |
| `INTERNET_EXPOSED` | exposes | `0.0.0.0/0` → exposed asset | ignored |

`CONTAINS` edges whose container is an `ORGANIZATION`, `ORG_UNIT` or `CLOUD_ACCOUNT` are skipped
by `DependencyGraph` unless it is built with `include_hierarchy=True`: they say where something
lives, not what breaks with it.

---

## 7. The relation object (`metadata["relations"]`)

Collectors never create edges between assets of different services directly. They declare what
an asset talks to, by identifier, in `metadata["relations"]`, and the linker resolves the
identifiers and creates the edges. Relations stay on the asset in the exported map.

Built by `cloudg.inventory.aws_services._base.rel()` (also used by the Azure and GCP extractors):

```python
rel(target, edge, relationship=None, *, reverse=False, description=None, **properties)
    -> dict | None
```

| Key | Type | Present | Meaning |
|---|---|---|---|
| `target` | `str` | always | Any identifier of the other asset ([formats](#4-identifier-formats)). `rel()` returns `None` (and callers drop it) for an empty or non-string target. |
| `edge` | `str` | always | An `EdgeType` value. An unknown value is linked as `REFERENCES`. |
| `relationship` | `str` | when given | A `RelationType` name. |
| `reverse` | `bool` | only when `true` | The edge goes from `target` to the declaring asset. Used when the declaring side is the passive one ("my queue triggers me", "this subnet contains me", "this principal is granted access to me"). |
| `description` | `str` | when given | Copied to the edge's `description`. |
| `properties` | `dict` | when any non-empty | Extra keyword arguments, with `None`, `""`, `[]` and `{}` values dropped. Copied to the edge's `properties`. |

Example, a resource policy grant declared on a queue: the account `555555555555` may send
messages. With `reverse: true`, the resulting edge is `account GRANTS_ACCESS queue`.

```json
{
  "target": "arn:aws:iam::555555555555:root",
  "edge": "GRANTS_ACCESS",
  "relationship": "POLICY_ALLOWS_ACTION",
  "reverse": true,
  "description": "resource policy grant",
  "properties": {"cross_account": true}
}
```

A relation that resolves to nothing is reported in `unresolved_references` unless its target is
in an account that was not mapped, in which case an external account placeholder is created and
the edge points there (`properties.external_reference` keeps the original target).

---

## 8. InventoryResult

`cloudg.inventory.InventoryResult` (defined in `cloudg/inventory/mapper_result.py`, re-exported
from `cloudg.inventory.mapper` and the package root). A dataclass.

### 8.1 Fields

| Field | Type | Meaning |
|---|---|---|
| `assets` | `list[CloudAsset]` | Every asset after deduplication and linking, including organization / hierarchy assets, external account placeholders and the account nodes added by `add_account_hierarchy`. |
| `edges` | `list[NetworkEdge]` | Collector edges, then linker edges, then hierarchy edges. Deduplicated on `(source_id, target_id, edge_type)`. |
| `coverage` | `list[CollectionCoverage]` | One record per discovery step and per provider × account × region collection run ([section 10](#10-coverage-records)). Not exported to any file. |
| `providers` | `list[str]` | The configured providers, lower case (`["aws", "gcp"]`). |
| `regions` | `dict[str, list[str]]` | Regions actually collected per provider after `all` expansion, e.g. `{"aws": ["us-east-1", "eu-west-1"]}`. |
| `duration_ms` | `int` | Wall-clock time of `map_inventory()`. `0` after `load()`. |
| `organization` | `dict \| None` | `OrganizationTopology.to_dict()` when an AWS Organization was mapped, else `None` ([section 17](#17-organizationtopology-and-inventory-organizationjson)). |
| `unresolved_references` | `list[dict]` | Declared relations whose target resolved to nothing, at most 2000 ([section 11](#11-unresolved-references)). |

### 8.2 Methods and properties

| Member | Returns | Notes |
|---|---|---|
| `summary` (property) | `dict[str, Any]` | Recomputed on every access. [Section 9](#9-summary). |
| `dependency_graph(include_hierarchy=False)` | `DependencyGraph` | A new graph each call. [Section 12](#12-dependencygraph-results). |
| `analysis(top=25)` | `dict[str, Any]` | [Section 13](#13-analysis-and-inventory-dependenciesjson). |
| `export(output_dir)` | `dict[str, Path]` | [8.3](#83-export). |
| `load(path)` (classmethod) | `InventoryResult` | [8.4](#84-load). |

### 8.3 export

`export(output_dir)` creates the directory and writes:

| Return key | File | Always |
|---|---|---|
| `map` | `inventory-map.json` | yes |
| `graphml` | `inventory-map.graphml` | yes |
| `graph` | `inventory-graph.json` | yes |
| `dependencies` | `inventory-dependencies.json` | yes |
| `organization` | `inventory-organization.json` | only when `organization` is set |

The values are `pathlib.Path` objects. JSON files are written with `indent=2` and
`default=str` (datetimes and other non-JSON values become strings).

### 8.4 load

`InventoryResult.load(path)` accepts `inventory-map.json` or the directory holding it.

- `assets` and `edges` are re-validated into models (`display_id` is dropped before validation).
- `providers` comes from the file's `providers`, or `summary.providers` for older files.
- `regions` and `unresolved_references` are read back.
- `organization` is read from `inventory-organization.json` next to the map, when present.
- `coverage` is empty and `duration_ms` is `0`: neither is stored in the files.
- `raw_data` is empty on every asset (it is never serialised). Linking rules that use raw
  payloads (instance profiles, Lambda roles from `Role`) therefore only work on fresh
  collections, not on loaded maps; the declared relations do work.

---

## 9. summary

`InventoryResult.summary`, also the `summary` object of `inventory-map.json`.

| Key | Type | How it is computed |
|---|---|---|
| `total_assets` | `int` | `len(assets)`. |
| `total_edges` | `int` | `len(edges)`, all edge kinds. |
| `providers` | `list[str]` | Same as `InventoryResult.providers`. |
| `assets_by_type` | `dict[str, int]` | Count per `asset_type`, sorted by descending count. |
| `assets_by_service` | `dict[str, int]` | Count per cloud service, sorted by descending count. The service is derived from the identifier: the third field of an ARN (`lambda`, `ec2`, `iam`), `kubernetes` for `k8s://` and `k8s-gke://`, `iam` for `gcp-principal:`, `entra` for `entra:`, the third field of a `cloudg:` identifier (`inspector2`), the lower-cased provider namespace for Azure (`microsoft.network`), the API host prefix for GCP (`compute`, `storage`), else `unknown` (Cloud Control synthetic identifiers land here). |
| `assets_by_region` | `dict[str, int]` | Count per `region`, in first-seen order. |
| `assets_by_account` | `dict[str, int]` | Count per `account_id`, `"unknown"` for `None`, first-seen order. External placeholders count under their account. |
| `edges_by_type` | `dict[str, int]` | Count per `edge_type`, first-seen order. |
| `edges_by_relationship` | `dict[str, int]` | Count per `relationship` (edges without one are not counted), descending. |
| `unlinked_assets` | `int` | Assets that are an endpoint of no edge except `hierarchy` edges, not counting `ORGANIZATION`, `ORG_UNIT` and `CLOUD_ACCOUNT`. A high number means many assets are only attached to their account. |
| `internet_exposed` | `int` | Assets with `is_internet_exposed`. |
| `accounts` | `int` | Distinct `account_id` values other than `unknown`, including external accounts. |
| `cross_account_edges` | `int` | Non-`hierarchy` edges whose two endpoints are assets in different accounts, excluding edges between two hierarchy-type assets. |
| `external_accounts` | `int` | `CLOUD_ACCOUNT` assets with `metadata.external` true. |
| `security_service_gaps` | `int` | Assets with `metadata.security_service` set and `metadata.enabled` exactly `False`. |
| `unresolved_references` | `int` | `len(unresolved_references)`; `2000` means the cap was hit. |
| `organization` | `dict` | Only when an organization was mapped: `{"id", "accounts", "ous", "control_tower", "governed_regions"}`, see below. |

`summary.organization`:

| Key | Type | Meaning |
|---|---|---|
| `id` | `str \| None` | Organization ID, `o-…`. |
| `accounts` | `int` | Accounts in the organization (all, not only the selected ones). |
| `ous` | `int` | Organizational units, roots not counted. |
| `control_tower` | `bool` | A landing zone was found. |
| `governed_regions` | `list[str]` | Control Tower governed regions, empty without Control Tower. |

Example (counts dictionaries shortened):

```json
{
  "total_assets": 2459,
  "total_edges": 2547,
  "providers": ["aws"],
  "assets_by_type": {"SNAPSHOT": 2354, "SUBNET": 14, "SECURITY_GROUP": 5, "ROUTE_TABLE": 5, "VPC": 4, "…": 0},
  "assets_by_service": {"ec2": 2395, "iam": 11, "organizations": 7, "elasticloadbalancing": 3, "ecs": 3, "…": 0},
  "assets_by_region": {"global": 21, "us-east-1": 2438},
  "assets_by_account": {"123456789012": 1252, "552289857375": 1206, "999999999999": 1},
  "edges_by_type": {"SECURITY_GROUP_RULE": 6, "CONTAINS": 2467, "MANAGES": 1, "GOVERNS": 13, "INVOKES": 4, "…": 0},
  "edges_by_relationship": {"ACCOUNT_CONTAINS_REGION": 2410, "SUBNET_CONTAINS_INSTANCE": 11, "RUNS_ON": 9, "…": 0},
  "unlinked_assets": 2372,
  "internet_exposed": 5,
  "accounts": 3,
  "cross_account_edges": 5,
  "external_accounts": 1,
  "security_service_gaps": 9,
  "unresolved_references": 2000,
  "organization": {
    "id": "o-1wietecbs4",
    "accounts": 2,
    "ous": 2,
    "control_tower": false,
    "governed_regions": []
  }
}
```

The 2354 snapshots and the capped `unresolved_references` are an artefact of the simulator,
which returns a large set of public EBS snapshots; a real account lists its own snapshots only.

---

## 10. Coverage records

`cloudg.coverage.CollectionCoverage`, one per collection unit. `InventoryResult.coverage` holds,
in order: the discovery records (AWS organization, Azure management groups, GCP hierarchy), then
one record per provider × account × region run.

### 10.1 CollectionCoverage

| Field | Type | Meaning |
|---|---|---|
| `provider` | `str` | `aws`, `azure` or `gcp`. |
| `region` | `str \| None` | Region of the run, `"global"` for discovery records, `None` for Azure / GCP runs. |
| `account_id` | `str \| None` | Account, subscription, project or organization the record covers. |
| `started_at` | `datetime` | Creation time. |
| `completed_at` | `datetime \| None` | Not set by the inventory collectors. |
| `services` | `list[ServiceCoverage]` | One entry per collector task / step. |

Properties: `total_services`, `successful_services`, `failed_services` (`int`) and
`coverage_pct` (`float`, successful / total × 100, one decimal). `to_summary()` returns
`{"provider", "region", "account_id", "total_services", "successful", "failed",
"coverage_pct", "failures": [{"service", "error"}]}`.

### 10.2 ServiceCoverage

| Field | Type | Meaning |
|---|---|---|
| `service` | `str` | Collector task or step name (table below). |
| `status` | `ServiceStatus` | `SUCCESS`, `FAILED`, `PARTIAL` or `SKIPPED`. |
| `asset_count` | `int` | Assets the task produced (for `cloud_control_skipped_types`: the number of skipped types). |
| `error` | `str \| None` | Error text, or a summary for `PARTIAL`. |
| `duration_ms` | `int \| None` | Task duration. |

### 10.3 Service names

| `service` | Record | Meaning |
|---|---|---|
| any task name (`lambda`, `ecr`, `eks`, `guardduty`, `codepipeline`, ...) | AWS account × region | One entry per deep-collector task that ran; see the task table in [INVENTORY_INTERNALS.md](INVENTORY_INTERNALS.md#53-service-families-and-tasks). A task that raised is `FAILED` with the exception text and produced no assets. |
| `tagging_sweep`, `cloud_control` | AWS account × region | The breadth sweeps. |
| `kubernetes:<cluster name>` | AWS account × region | In-cluster mapping of one EKS cluster: `SUCCESS` with the number of Kubernetes objects, or `FAILED` (endpoint unreachable, no access entry). |
| `cloud_control_skipped_types` | AWS account × region | `PARTIAL`: Cloud Control types that could not be listed; `asset_count` is the number of types, `error` the error codes with counts (`"AccessDeniedException: 3, UnsupportedActionException: 41"`). |
| `aws_full` | AWS account × region | Overall result. `PARTIAL` when any task failed or was partial, `FAILED` when the whole run raised. `asset_count` is the total. |
| `sts_assume_role` | AWS account × region | `FAILED` when the member-account role could not be assumed; nothing else is collected for that account and region. |
| `organizations` | AWS discovery | Organization discovery; `asset_count` is the number of accounts. `FAILED` means only the caller account was mapped. |
| `controltower` | AWS discovery | `PARTIAL` with the errors met while reading the landing zone. |
| `azure_full`, `azure_edges`, `azure_<service>` | Azure subscription | Overall result, edge collection, and individual SDK fallbacks / Resource Graph sub-queries that failed. |
| `management_groups` | Azure discovery | Management group / policy hierarchy. `SKIPPED` when the SDK is not installed. |
| `gcp_full`, `gcp_iam_policies` | GCP scope | Overall result, and the `searchAllIamPolicies` call (`PARTIAL` when it failed after returning some policies). |
| `organization_hierarchy` | GCP discovery | Organization / folder / policy hierarchy. |

The CLI prints the failed entries after a map run ("N collectors failed").

---

## 11. Unresolved references

`InventoryResult.unresolved_references` and the `unresolved_references` arrays of
`inventory-map.json` and `inventory-dependencies.json`. One entry per declared relation whose
target matched no asset and no unmapped account. Capped at 2000 entries per run.

| Key | Type | Meaning |
|---|---|---|
| `source` | `str` | `arn` of the declaring asset (its `id` when it has no `arn`). |
| `source_name` | `str` | `name` of the declaring asset. |
| `target` | `str` | The identifier that did not resolve. |
| `edge_type` | `str` | The edge type that would have been created. |

```json
[
  {
    "source": "arn:aws:lambda:us-east-1:123456789012:function:orders-worker",
    "source_name": "orders-worker",
    "target": "arn:aws:logs:us-east-1:123456789012:log-group:/aws/lambda/orders-worker",
    "edge_type": "LOGS_TO"
  }
]
```

Typical causes: a resource that was deleted but is still configured (a DLQ, a log group, a
role), a service family excluded with `--exclude-services`, a region not collected, or a
resource type no collector or sweep returns. Each one is worth a look: a deleted DLQ or a
missing log group is often a real misconfiguration.

---

## 12. DependencyGraph results

`cloudg.inventory.DependencyGraph(assets, edges, include_hierarchy=False)`. Every edge with a
known dependency direction ([section 6](#6-edge-types-and-direction)) whose endpoints are both
assets becomes one `dependent → dependency` arrow.

| Method | Returns |
|---|---|
| `find(ref)` | `CloudAsset \| None`. Tries, in order: internal `id`; exact `arn`; `name` when exactly one asset has it; the last `/` segment of `arn` when exactly one asset matches. |
| `depends_on(asset_id, max_depth=10)` | `list[DependencyLink]`, everything the asset needs, breadth-first. |
| `dependents(asset_id, max_depth=10)` | `list[DependencyLink]`, everything that needs the asset (its blast radius), breadth-first. |
| `direct_counts(asset_id)` | `tuple[int, int]`: `(direct dependencies, direct dependents)`, counting parallel edges. |
| `tree(asset_id, direction="both", max_depth=3)` | nested `dict`, [12.2](#122-tree). |
| `shared_dependencies(top=25)` | `list[dict]`, [12.3](#123-shared_dependencies). |
| `blast_radius(candidates=None, top=25)` | `list[dict]`, [12.4](#124-blast_radius). |

### 12.1 DependencyLink

| Field | Type | Meaning |
|---|---|---|
| `asset_id` | `str` | The asset reached. |
| `via_edge` | `str` | `edge_type` of the edge used. |
| `relationship` | `str \| None` | `relationship` of that edge. |
| `depth` | `int` | Hops from the start, starting at 1. |
| `parent_id` | `str` | The asset it was reached from. |

Each asset appears once per walk, at the depth and under the parent where the breadth-first
search first reached it.

### 12.2 tree

```python
graph.tree(asset_id, direction="both", max_depth=3) -> dict
```

| Key | Present | Type | Meaning |
|---|---|---|---|
| `asset` | always | asset descriptor | The starting asset. |
| `depends_on` | `direction` `up` or `both` | `list[node]` | What it needs. |
| `dependents` | `direction` `down` or `both` | `list[node]` | What needs it. |

An **asset descriptor** is `{"id", "name", "arn", "type", "account_id", "region"}` (`type` is
the `asset_type` value). A **node** is an asset descriptor plus:

| Key | Type | Meaning |
|---|---|---|
| `via` | `str` | Edge type that links this node to its parent. |
| `relationship` | `str \| None` | Relationship of that edge. |
| `children` | `list[node]` | The next level, empty at `max_depth`. |

Example, the role `orders-worker` from the example run, `direction="both"`, abridged:

```json
{
  "asset": {
    "id": "1bd88609-88f3-46d7-868e-ac65ece6b65a",
    "name": "orders-worker",
    "arn": "arn:aws:iam::123456789012:role/orders-worker",
    "type": "IAM_ROLE",
    "account_id": "123456789012",
    "region": "global"
  },
  "depends_on": [
    {
      "id": "f26a0b92-407e-44d7-8644-f73f462fa7e6",
      "name": "arn:aws:iam::123456789012:policy/orders-queue-access",
      "arn": "arn:aws:iam::123456789012:policy/orders-queue-access",
      "type": "IAM_POLICY",
      "account_id": "123456789012",
      "region": "global",
      "via": "IAM_POLICY_ATTACHMENT",
      "relationship": "ROLE_HAS_POLICY",
      "children": []
    },
    {
      "id": "c612cd24-42db-4260-b755-3ee3a24da24f",
      "name": "orders",
      "arn": "arn:aws:sqs:us-east-1:123456789012:orders",
      "type": "MESSAGE_QUEUE",
      "account_id": "123456789012",
      "region": "us-east-1",
      "via": "GRANTS_ACCESS",
      "relationship": "POLICY_ALLOWS_ACTION",
      "children": [
        {"name": "289e9c59-…", "type": "KMS_KEY", "via": "REFERENCES", "relationship": "ENCRYPTED_BY_KMS", "children": [], "…": "…"},
        {"name": "orders-dlq", "type": "MESSAGE_QUEUE", "via": "REFERENCES", "relationship": "WRITES_TO", "children": [], "…": "…"},
        {"name": "order-events", "type": "NOTIFICATION_TOPIC", "via": "INVOKES", "relationship": "STREAMS_TO", "children": [], "…": "…"}
      ]
    }
  ],
  "dependents": [
    {
      "id": "60cac611-8a80-469e-bca6-ee3cf1cdc35b",
      "name": "orders-worker",
      "arn": "arn:aws:lambda:us-east-1:123456789012:function:orders-worker",
      "type": "LAMBDA_FUNCTION",
      "account_id": "123456789012",
      "region": "us-east-1",
      "via": "ASSUMES_ROLE",
      "relationship": "RUNS_ON",
      "children": [
        {"name": "orders-api", "type": "CONTAINER_SERVICE", "via": "REFERENCES", "relationship": "DEPENDS_ON", "children": [], "…": "…"}
      ]
    }
  ]
}
```

Reading it: the role needs its attached policy and the queue its policy grants access to; the
queue in turn needs its KMS key and its DLQ, and depends on the topic that delivers into it
(`order-events INVOKES orders` is a reverse-direction edge, so the queue depends on the topic).
Downstream, the function runs as the role, and the ECS service references the function.

### 12.3 shared_dependencies

Assets that the most other assets depend on directly, ignoring `CONTAINS` and `PEERING`. Only
assets with at least two such dependents are listed; sorted by descending count.

| Key | Type | Meaning |
|---|---|---|
| asset descriptor keys | | `id`, `name`, `arn`, `type`, `account_id`, `region` |
| `direct_dependents` | `int` | Distinct assets with a direct functional dependency on it. |

```json
[
  {"id": "1bd88609-88f3-46d7-868e-ac65ece6b65a", "name": "orders-worker",
   "arn": "arn:aws:iam::123456789012:role/orders-worker", "type": "IAM_ROLE",
   "account_id": "123456789012", "region": "global", "direct_dependents": 8},
  {"id": "756b6990-690f-4136-98c1-69cfd2b7a71d", "name": "web",
   "arn": "arn:aws:ec2:us-east-1:123456789012:security-group/sg-05c9fb72915768cb5",
   "type": "SECURITY_GROUP", "account_id": "123456789012", "region": "us-east-1",
   "direct_dependents": 6}
]
```

### 12.4 blast_radius

The assets whose failure or change would affect the most others, transitively. Candidates are
the `4 × top` assets with the most direct dependents (or the `candidates` you pass); each is
walked with `dependents(max_depth=10)`. Assets with no dependents are dropped; sorted by
descending `transitive_dependents`.

| Key | Type | Meaning |
|---|---|---|
| asset descriptor keys | | `id`, `name`, `arn`, `type`, `account_id`, `region` |
| `transitive_dependents` | `int` | Assets that depend on it directly or indirectly (up to 10 hops). |
| `accounts_affected` | `int` | Distinct accounts among those dependents. |
| `internet_exposed_dependents` | `int` | Internet-exposed assets among them. |

```json
[
  {
    "id": "8d7d700b-7f64-4821-97b2-45577d1faf7a",
    "name": "FullAWSAccess",
    "arn": "arn:aws:organizations::123456789012:policy/o-1wietecbs4/service_control_policy/p-FullAWSAccess",
    "type": "ORG_POLICY",
    "account_id": "123456789012",
    "region": "global",
    "transitive_dependents": 38,
    "accounts_affected": 3,
    "internet_exposed_dependents": 4
  }
]
```

An SCP attached to the root topping the list is expected: everything in the governed accounts
depends on it.

---

## 13. analysis() and inventory-dependencies.json

`InventoryResult.analysis(top=25)` returns the dictionary that `export()` writes to
`inventory-dependencies.json`. It uses a dependency graph built with `include_hierarchy=False`.

| Key | Type | Content |
|---|---|---|
| `shared_dependencies` | `list[dict]` | `graph.shared_dependencies(top)`, [12.3](#123-shared_dependencies). |
| `largest_blast_radius` | `list[dict]` | `graph.blast_radius(top=top)`, [12.4](#124-blast_radius). |
| `cross_account_edges` | `list[dict]` | Every cross-account edge, [13.1](#131-cross_account_edges). |
| `security_coverage` | `dict` | [13.2](#132-security_coverage). |
| `unresolved_references` | `list[dict]` | Same list as the map, [section 11](#11-unresolved-references). |

### 13.1 cross_account_edges

`cloudg.inventory.dependencies.cross_account_edges(assets, edges)`. Edges between two assets
with different, non-empty `account_id`, except `CONTAINS` edges between two hierarchy assets
(OU → account). Unlike `summary.cross_account_edges`, `hierarchy`-flagged edges are not
filtered here, but they never cross accounts.

| Key | Type | Meaning |
|---|---|---|
| `source` | `str` | Source `arn` (or `id`). |
| `source_account` | `str` | Source account. |
| `target` | `str` | Target `arn` (or `id`). |
| `target_account` | `str` | Target account. |
| `edge_type` | `str` | Edge type. |
| `relationship` | `str \| None` | Relationship. |
| `external` | `bool` | Either endpoint is an external (unmapped) account placeholder. |

```json
[
  {
    "source": "arn:aws:organizations::123456789012:policy/o-1wietecbs4/service_control_policy/p-FullAWSAccess",
    "source_account": "123456789012",
    "target": "arn:aws:iam::552289857375:root",
    "target_account": "552289857375",
    "edge_type": "GOVERNS",
    "relationship": "SCP_RESTRICTS",
    "external": false
  },
  {
    "source": "arn:aws:iam::999999999999:root",
    "source_account": "999999999999",
    "target": "arn:aws:iam::123456789012:role/orders-worker",
    "target_account": "123456789012",
    "edge_type": "IAM_TRUST",
    "relationship": "CROSS_ACCOUNT_TRUST",
    "external": true
  }
]
```

### 13.2 security_coverage

`cloudg.inventory.dependencies.security_coverage(assets, edges)`.

| Key | Type | Meaning |
|---|---|---|
| `services_by_account_region` | `dict[account, dict[region, dict[service, bool]]]` | For every asset with `metadata.security_service`: whether that service is enabled in that account and region. A service is `true` when any of its assets there is enabled. Account-wide services appear under `global`. |
| `gaps` | `list[str]` | Every `false` cell as `"<account>/<region>: <service>"`, sorted. |
| `workloads_without_vulnerability_scanning` | `list[dict]` | `EC2`, `CONTAINER_REGISTRY` and `LAMBDA_FUNCTION` assets (any provider) that are not the target of a `MONITORS` edge from an enabled `VULNERABILITY_SCANNER`. Items: `{"name", "arn", "type", "account_id", "region"}`. |
| `internet_facing_without_waf` | `list[dict]` | Internet-exposed `LOAD_BALANCER`, `API_GATEWAY` and `CLOUDFRONT` assets that are not the target of any `PROTECTS` edge. Items: `{"name", "arn", "type", "account_id"}`. |

```json
{
  "services_by_account_region": {
    "123456789012": {
      "us-east-1": {"guardduty": true, "securityhub": false, "inspector2": false,
                    "macie": true, "config": false, "cloudtrail": false},
      "global": {"shield": true}
    },
    "552289857375": {
      "us-east-1": {"guardduty": false, "securityhub": false, "inspector2": false,
                    "macie": true, "config": false, "cloudtrail": false}
    }
  },
  "gaps": [
    "123456789012/us-east-1: cloudtrail",
    "123456789012/us-east-1: config",
    "123456789012/us-east-1: inspector2",
    "123456789012/us-east-1: securityhub",
    "552289857375/us-east-1: cloudtrail"
  ],
  "workloads_without_vulnerability_scanning": [
    {"name": "web-1", "arn": "arn:aws:ec2:us-east-1:123456789012:instance/i-2b95636493d3a307e",
     "type": "EC2", "account_id": "123456789012", "region": "us-east-1"}
  ],
  "internet_facing_without_waf": [
    {"name": "web-alb",
     "arn": "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/web-alb/2466d6929fc1473a",
     "type": "LOAD_BALANCER", "account_id": "123456789012"}
  ]
}
```

---

## 14. inventory-map.json

The self-contained map. Written by `export()`, read by `load()` and `cloudg deps`.

| Key | Type | Content |
|---|---|---|
| `summary` | `object` | [Section 9](#9-summary). |
| `providers` | `list[str]` | `InventoryResult.providers`. |
| `regions` | `object` | `InventoryResult.regions`. |
| `assets` | `list[object]` | `CloudAsset.model_dump(mode="json")` for every asset ([section 3](#3-cloudasset)), including `display_id`, excluding `raw_data`. |
| `edges` | `list[object]` | `NetworkEdge.model_dump(mode="json")` for every edge ([section 5](#5-networkedge)). |
| `unresolved_references` | `list[object]` | [Section 11](#11-unresolved-references). |

Skeleton:

```json
{
  "summary": {"total_assets": 2459, "total_edges": 2547, "…": "…"},
  "providers": ["aws"],
  "regions": {"aws": ["us-east-1"]},
  "assets": [
    {"id": "…", "arn": "…", "name": "…", "asset_type": "…", "provider": "AWS", "region": "…",
     "account_id": "…", "tags": {}, "metadata": {}, "collected_at": "…",
     "is_internet_exposed": false, "display_id": "…"}
  ],
  "edges": [
    {"id": "…", "source_id": "…", "target_id": "…", "edge_type": "…", "ports": [],
     "port_range": null, "protocol": null, "cidr": null, "direction": "ingress",
     "description": null, "relationship": null, "properties": {}}
  ],
  "unresolved_references": [
    {"source": "…", "source_name": "…", "target": "…", "edge_type": "…"}
  ]
}
```

Working with it from code without cloudg:

```python
import json

m = json.load(open("reports/inventory-map.json"))
by_id = {a["id"]: a for a in m["assets"]}

# every function and the role it runs as
for e in m["edges"]:
    if e["edge_type"] == "ASSUMES_ROLE":
        src, dst = by_id.get(e["source_id"]), by_id.get(e["target_id"])
        if src and dst and src["asset_type"] == "LAMBDA_FUNCTION":
            print(src["arn"], "->", dst["arn"])
```

Always look endpoints up with `.get()`: collector network edges can have endpoints that are not
asset IDs ([5.3](#53-collector-network-edges)).

---

## 15. inventory-graph.json

D3 force-layout data from `GraphBuilder.to_d3_json()`, built from the same assets and edges.
Consumed by `docs/viewer.html` and any D3 / vis.js / Cytoscape front end.

`nodes[]`:

| Key | Type | Meaning |
|---|---|---|
| `id` | `str` | Asset `id`, or the raw endpoint string for non-asset endpoints. |
| `name` | `str` | Asset `name`. |
| `type` | `str` | `asset_type`, or `EXTERNAL`. |
| `provider` | `str` | `AWS` / `AZURE` / `GCP`, or `EXTERNAL`. |
| `region` | `str` | Region, `""` for externals. |
| `arn` | `str` | Identifier, `""` when none. |
| `account_id` | `str` | Account, `""` when none. |
| `is_internet_exposed` | `bool` | From the asset. |
| `is_external` | `bool` | `true` for nodes created from non-asset endpoints (`0.0.0.0/0` and other CIDRs, Azure service tags). External *accounts* are real assets and have `is_external: false`; check `type == "CLOUD_ACCOUNT"` and the map's `metadata.external` for those. |

`links[]`:

| Key | Type | Meaning |
|---|---|---|
| `source`, `target` | `str` | Node IDs. |
| `type` | `str` | `edge_type`. |
| `relationship` | `str` | `relationship`, `""` when none. |
| `description` | `str` | `""` when none. |
| `direction`, `protocol`, `port_range`, `cidr` | `str` | Network attributes, `""` when none. |

`properties` and `ports` are not in the D3 export; use `inventory-map.json` for them.

```json
{
  "nodes": [
    {"id": "1f289833-14df-4772-a9b3-470736dfe58d", "name": "organization o-1wietecbs4",
     "type": "ORGANIZATION", "provider": "AWS", "region": "global",
     "arn": "arn:aws:organizations::123456789012:organization/o-1wietecbs4",
     "account_id": "123456789012", "is_internet_exposed": false, "is_external": false},
    {"id": "0.0.0.0/0", "name": "0.0.0.0/0", "type": "EXTERNAL", "provider": "EXTERNAL",
     "region": "", "arn": "", "account_id": "", "is_internet_exposed": false, "is_external": true}
  ],
  "links": [
    {"source": "1f289833-14df-4772-a9b3-470736dfe58d", "target": "a2fdd0e9-6feb-45c0-8cfe-ab092649fb3f",
     "type": "CONTAINS", "relationship": "", "description": "", "direction": "ingress",
     "protocol": "", "port_range": "", "cidr": ""}
  ]
}
```

---

## 16. inventory-map.graphml

The same graph as GraphML (NetworkX `write_graphml_xml`), for Gephi, yEd, Neo4j import or
`networkx.read_graphml`.

Node attributes: `name`, `asset_type`, `provider`, `region`, `arn`, `account_id`,
`tags` (the tag dictionary as a JSON string), `is_internet_exposed` (boolean). External
endpoint nodes have `name`, `asset_type="EXTERNAL"`, `provider="EXTERNAL"`, `is_external=true`.

Edge attributes: `edge_type`, `relationship`, `description`, `direction`, `protocol`,
`port_range`, `cidr` (empty strings when unset).

```python
import networkx as nx

g = nx.read_graphml("reports/inventory-map.graphml")
exposed = [d["name"] for _, d in g.nodes(data=True) if d.get("is_internet_exposed")]
```

---

## 17. OrganizationTopology and inventory-organization.json

`cloudg.inventory.organization.OrganizationTopology`, returned by `discover_organization()` and
available as `InventoryMapper.organization` after a run. `inventory-organization.json` and
`InventoryResult.organization` are `topology.to_dict()`: `dataclasses.asdict()` of the topology
plus `control_tower_enabled`.

### 17.1 Top-level fields

| Field | Type | Meaning |
|---|---|---|
| `organization_id` | `str \| None` | `o-…`. |
| `organization_arn` | `str \| None` | Organization ARN. |
| `management_account_id` | `str \| None` | Management account. |
| `caller_account_id` | `str \| None` | Account of the credentials that ran discovery (the management account or a delegated administrator). |
| `feature_set` | `str \| None` | `ALL` or `CONSOLIDATED_BILLING`. |
| `roots` | `list[OrgUnit]` | Organization roots (normally one). |
| `ous` | `dict[str, OrgUnit]` | Every OU by ID, at any depth. |
| `accounts` | `dict[str, OrgAccount]` | Every account by ID (before selection filters). |
| `policies` | `list[OrgPolicy]` | SCPs, RCPs, tag, backup and AI services opt-out policies of the policy types enabled on the root. |
| `delegated_administrators` | `dict[str, list[str]]` | Service short name (`guardduty`, `securityhub`, `inspector2`, `config`, `access-analyzer`, `macie`, `detective`, `fms`, `sso`) → delegated administrator account IDs. Only services that have one. |
| `enabled_services` | `list[str]` | Service principals with trusted access (`guardduty.amazonaws.com`, ...). |
| `landing_zone` | `dict \| None` | Control Tower `GetLandingZone` output without the manifest, or `None` without Control Tower ([17.3](#173-control-tower-fields)). |
| `governed_regions` | `list[str]` | Control Tower governed regions. |
| `shared_accounts` | `dict[str, str]` | Control Tower role → account ID: `log_archive`, `audit`, `config_aggregator`, `backup_admin`, `central_backup` (those present in the manifest). |
| `enabled_controls` | `list[dict]` | `ListEnabledControls` items ([17.3](#173-control-tower-fields)). |
| `enabled_baselines` | `list[dict]` | `ListEnabledBaselines` items. |
| `control_tower_region` | `str \| None` | Home region where the landing zone was found. |
| `errors` | `list[str]` | Non-fatal discovery errors (`"controltower:get_landing_zone: …"`). |
| `control_tower_enabled` | `bool` | `to_dict()` only: `landing_zone is not None`. |

### 17.2 OrgUnit, OrgAccount, OrgPolicy

`OrgUnit` (roots and OUs):

| Field | Type | Meaning |
|---|---|---|
| `id` | `str` | `r-…` or `ou-…`. |
| `name` | `str` | OU name, `Root` for roots. |
| `arn` | `str` | ARN. |
| `parent_id` | `str \| None` | Parent root / OU; `None` for roots. |
| `path` | `list[str]` | Names from the root down, including itself: `["Root", "Workloads", "Prod"]`. |
| `is_root` | `bool` | Root. |

`OrgAccount`:

| Field | Type | Meaning |
|---|---|---|
| `id` | `str` | Account ID. |
| `name` | `str` | Account name. |
| `arn` | `str` | Organizations account ARN (`arn:aws:organizations::<mgmt>:account/o-…/<id>`). |
| `status` | `str` | `ACTIVE`, `SUSPENDED`, `PENDING_CLOSURE`, ... (the `State` field, falling back to `Status`). |
| `parent_id` | `str` | Root or OU directly above. |
| `ou_path` | `list[str]` | Names of the parent's path: `["Root", "Workloads", "Prod"]`. |
| `email` | `str \| None` | Root user email. |
| `joined_method` | `str \| None` | `CREATED` or `INVITED`. |
| `joined` | `str \| None` | Join timestamp as a string. |

`OrgPolicy`:

| Field | Type | Meaning |
|---|---|---|
| `id` | `str` | `p-…`. |
| `name` | `str` | Policy name. |
| `arn` | `str` | ARN. |
| `type` | `str` | `SERVICE_CONTROL_POLICY`, `RESOURCE_CONTROL_POLICY`, `TAG_POLICY`, `BACKUP_POLICY`, `AISERVICES_OPT_OUT_POLICY`. |
| `aws_managed` | `bool` | AWS managed (`FullAWSAccess`). |
| `targets` | `list[str]` | Root, OU and account IDs it is attached to. |

### 17.3 Control Tower fields

`landing_zone` holds the `GetLandingZone` response fields other than `manifest`, typically
`arn`, `version`, `latestAvailableVersion`, `status`, `driftStatus` (`{"status": "IN_SYNC"}`).
When the call failed it is `{"arn": …}` and the error is in `errors`.

`enabled_controls` items are the raw API items: `arn`, `controlIdentifier`,
`targetIdentifier` (the OU ARN), `statusSummary` (`{"status": "SUCCEEDED"}`),
`driftStatusSummary` (`{"driftStatus": "IN_SYNC"}`). `enabled_baselines` items: `arn`,
`baselineIdentifier`, `baselineVersion`, `targetIdentifier`, `statusSummary`.

### 17.4 Methods

| Method | Returns | Meaning |
|---|---|---|
| `target_accounts(include_ous=None, exclude_accounts=None, include_management_account=True, include_suspended=False)` | `list[str]` (sorted) | Account IDs to collect. `include_ous` takes OU IDs, ARNs or names (case-insensitive) and includes nested OUs; an unmatched name logs a warning. Non-`ACTIVE` accounts are skipped unless `include_suspended`. |
| `to_assets()` | `list[CloudAsset]` | [Section 18](#18-organization-assets-on-the-map). |
| `to_dict()` | `dict` | The JSON form above. |
| `control_tower_enabled` (property) | `bool` | A landing zone was found. |

### 17.5 Example (abridged)

```json
{
  "organization_id": "o-1wietecbs4",
  "organization_arn": "arn:aws:organizations::123456789012:organization/o-1wietecbs4",
  "management_account_id": "123456789012",
  "caller_account_id": "123456789012",
  "feature_set": "ALL",
  "roots": [
    {"id": "r-7h3o", "name": "Root",
     "arn": "arn:aws:organizations::123456789012:root/o-1wietecbs4/r-7h3o",
     "parent_id": null, "path": ["Root"], "is_root": true}
  ],
  "ous": {
    "ou-7h3o-ljevwujv": {"id": "ou-7h3o-ljevwujv", "name": "Workloads", "arn": "…",
                         "parent_id": "r-7h3o", "path": ["Root", "Workloads"], "is_root": false},
    "ou-7h3o-bqhq9yxz": {"id": "ou-7h3o-bqhq9yxz", "name": "Prod", "arn": "…",
                         "parent_id": "ou-7h3o-ljevwujv", "path": ["Root", "Workloads", "Prod"],
                         "is_root": false}
  },
  "accounts": {
    "552289857375": {"id": "552289857375", "name": "prod-app", "arn": "…", "status": "ACTIVE",
                     "parent_id": "ou-7h3o-bqhq9yxz", "ou_path": ["Root", "Workloads", "Prod"],
                     "email": "…", "joined_method": "CREATED", "joined": "…"}
  },
  "policies": [
    {"id": "p-FullAWSAccess", "name": "FullAWSAccess", "arn": "…",
     "type": "SERVICE_CONTROL_POLICY", "aws_managed": true, "targets": ["r-7h3o"]}
  ],
  "delegated_administrators": {},
  "enabled_services": [],
  "landing_zone": null,
  "governed_regions": [],
  "shared_accounts": {},
  "enabled_controls": [],
  "enabled_baselines": [],
  "control_tower_region": null,
  "errors": [],
  "control_tower_enabled": false
}
```

With Control Tower the same file carries, for example:

```json
{
  "landing_zone": {"arn": "arn:aws:controltower:us-east-1:123456789012:landingzone/…",
                   "version": "3.3", "latestAvailableVersion": "3.3", "status": "ACTIVE",
                   "driftStatus": {"status": "IN_SYNC"}},
  "governed_regions": ["us-east-1", "eu-west-1"],
  "shared_accounts": {"log_archive": "222222222222", "audit": "333333333333"},
  "enabled_controls": [
    {"arn": "…", "controlIdentifier": "arn:aws:controltower:us-east-1::control/AWS-GR_RESTRICT_ROOT_USER",
     "targetIdentifier": "arn:aws:organizations::123456789012:ou/o-…/ou-…",
     "statusSummary": {"status": "SUCCEEDED"}, "driftStatusSummary": {"driftStatus": "IN_SYNC"}}
  ],
  "control_tower_region": "us-east-1",
  "control_tower_enabled": true
}
```

---

## 18. Organization assets on the map

`topology.to_assets()` (`organization_assets.topology_assets`) adds these assets to the map
(with `aws.organization.map_structure`, on by default). All are `provider: AWS`; unless noted,
`account_id` is the management account and `region` is `global`.

| Asset | `asset_type` | `arn` | Metadata | Declared relations |
|---|---|---|---|---|
| Organization | `ORGANIZATION` | organization ARN | `organization_id`, `feature_set`, `management_account_id`, `control_tower`, `enabled_services`, `delegated_administrators`; alias the org ID | management account `MANAGES / OWNED_BY` → organization (reverse) |
| Root | `ORG_UNIT` | root ARN | `ou_id`, `is_root: true`, `path: ["Root"]`; alias the root ID | organization `CONTAINS` → root (reverse) |
| OU | `ORG_UNIT` | OU ARN | `ou_id`, `is_root: false`, `path`; alias the OU ID | parent `CONTAINS` → OU (reverse) |
| Account | `CLOUD_ACCOUNT` | `arn:aws:iam::<id>:root` | `account_id`, `status`, `ou_path`, `email`, `joined_method`, `joined`, `management_account`, `control_tower_role`, `delegated_admin_for`; aliases the Organizations ARN and the ID. `account_id` is the account itself. | parent `CONTAINS / ORG_CONTAINS_ACCOUNT` → account (reverse) |
| Policy | `ORG_POLICY` | policy ARN | `policy_id`, `policy_type`, `aws_managed`, `target_count`; alias the policy ID | `GOVERNS / SCP_RESTRICTS` (SCPs) or `GOVERNS / COMPLIANCE_GOVERNS` (other types) → each target |
| Landing zone | `LANDING_ZONE` | landing zone ARN | `version`, `latest_available_version`, `status`, `drift_status`, `governed_regions`, `shared_accounts`, `home_region`; region is the home region | `MANAGES / COMPLIANCE_GOVERNS` → organization; `MANAGES / OWNED_BY` → each shared account (property `role`) |
| Control | `GUARDRAIL` | control ARN | `kind: "control"`, `control_identifier`, `status`, `drift_status`; region is the home region | `GOVERNS / COMPLIANCE_GOVERNS` → target OU |
| Baseline | `GUARDRAIL` | baseline ARN | `kind: "baseline"`, `baseline_identifier`, `baseline_version`, `status` | `GOVERNS / COMPLIANCE_GOVERNS` → target |

Because account nodes use `arn:aws:iam::<id>:root`, the same identifier IAM trust and resource
policies use for account principals, cross-account grants from any collected account land on
the organization's account nodes.

Azure management groups and GCP folders follow the same pattern (`ORG_UNIT`, `CLOUD_ACCOUNT`,
`GUARDRAIL` for Azure Policy assignments, exemptions, GCP organization policies and VPC Service
Controls perimeters); see [INVENTORY_INTERNALS.md](INVENTORY_INTERNALS.md#10-hierarchies-beyond-aws).

---

## 19. asset-map.json and compliance-map.json

Written by `cloudg map --findings …` or `InventoryMapper.export_merged(result, findings, dir)`,
which returns `{"asset_map": Path, "compliance_map": Path}`.

### 19.1 asset-map.json (`build_asset_map`)

A finding is matched to an asset when its `resource_arn` or `resource_id` equals the asset's
`id`, `arn` or `name`.

| Key | Type | Meaning |
|---|---|---|
| `total_assets` | `int` | Every inventory asset. |
| `assets_with_findings` | `int` | Assets with at least one finding. |
| `assets` | `list[object]` | One entry per asset, sorted by descending `finding_count`. |

`assets[]`:

| Key | Type | Meaning |
|---|---|---|
| `id`, `arn`, `name` | `str` | From the asset. |
| `type` | `str` | `asset_type`. |
| `provider`, `region`, `account_id` | `str` | From the asset. |
| `internet_exposed` | `bool` | `is_internet_exposed`. |
| `finding_count` | `int` | Matched findings. |
| `severity_breakdown` | `dict[str, int]` | Severity → count, only severities present. |
| `finding_ids` | `list[str]` | Matched `Finding.id` values. |

```json
{
  "total_assets": 2459,
  "assets_with_findings": 2,
  "assets": [
    {
      "id": "92649f95-d721-44b8-838a-2daa38b93b50",
      "arn": "arn:aws:ec2:us-east-1:123456789012:security-group/sg-b4e351810f4ebd730",
      "name": "default",
      "type": "SECURITY_GROUP",
      "provider": "AWS",
      "region": "us-east-1",
      "account_id": "123456789012",
      "internet_exposed": false,
      "finding_count": 1,
      "severity_breakdown": {"HIGH": 1},
      "finding_ids": ["c61c2f13-6054-4c5c-a019-64601657a104"]
    }
  ]
}
```

### 19.2 compliance-map.json (`build_compliance_map`)

| Key | Type | Meaning |
|---|---|---|
| `frameworks` | `dict[str, object]` | Framework name → entry, sorted by name. |
| `total_frameworks` | `int` | Number of frameworks. |
| `total_inventory_assets` | `int` | Every inventory asset. |

`frameworks[<name>]`:

| Key | Type | Meaning |
|---|---|---|
| `findings` | `int` | Findings tagged with the framework. |
| `severity_breakdown` | `dict[str, int]` | Severity → count. |
| `affected_assets` | `list[str]` | Sorted identifiers (`arn`, else `id`) of the inventory assets those findings hit; a finding whose resource is not in the inventory contributes its `resource_arn`. |
| `affected_asset_count` | `int` | `len(affected_assets)`. |

```json
{
  "frameworks": {
    "CIS": {
      "findings": 2,
      "severity_breakdown": {"HIGH": 2},
      "affected_assets": [
        "arn:aws:ec2:us-east-1:123456789012:security-group/sg-a1c39e0ced3e8f2c6",
        "arn:aws:ec2:us-east-1:123456789012:security-group/sg-b4e351810f4ebd730"
      ],
      "affected_asset_count": 2
    }
  },
  "total_frameworks": 2,
  "total_inventory_assets": 2459
}
```

---

## 20. cloudg deps --json

`cloudg deps` loads a saved map (`--map`, default `./reports`) and builds a dependency graph.

- With an ASSET argument, `--json` prints `graph.tree(asset, direction, depth)` exactly as in
  [12.2](#122-tree). `--direction` is `up`, `down` or `both` (default); `--depth` defaults to 3.
  The asset is matched with `find()` (internal ID, ARN, unique name, unique ARN tail); no unique
  match exits with status 1.
- Without an ASSET, `--json` prints the overview:

| Key | Type | Content |
|---|---|---|
| `shared_dependencies` | `list` | `graph.shared_dependencies(top)` ([12.3](#123-shared_dependencies)) |
| `largest_blast_radius` | `list` | `graph.blast_radius(top=top)` ([12.4](#124-blast_radius)) |
| `cross_account_edges` | `list` | `cross_account_edges(assets, edges)` ([13.1](#131-cross_account_edges)), every edge (`--top` only limits the table view) |

`--top` defaults to 15.

```bash
cloudg deps arn:aws:iam::123456789012:role/orders-worker --json > role-deps.json
cloudg deps --map ./reports --top 50 --json > overview.json
```

---

## 21. Lower-level return values

### 21.1 RelationshipLinker

```python
linker = RelationshipLinker(assets, materialize_external=True)
linker.seed_existing(edges)  # -> None
new_edges = linker.link(include_generic=True)  # -> list[NetworkEdge]
linker.external_assets  # list[CloudAsset]
linker.unresolved  # list[dict], max 2000
linker.resolve(identifier, context=None)  # -> str | None (asset id)
```

- `link()` returns only the edges it created. They are deduplicated on
  `(source_id, target_id, edge_type)` against each other and against seeded edges; the generic
  pass also skips a pair already linked in either direction.
- `external_assets` are the `CLOUD_ACCOUNT` placeholders it created; add them to your asset list,
  the new edges point at them.
- `unresolved` entries are [section 11](#11-unresolved-references) records.
- `resolve()` returns an asset `id` or `None`; `context` (the referencing asset) scopes
  ambiguous names.
- With `materialize_external=False` references into unmapped accounts are reported as unresolved
  instead.

### 21.2 Collectors

All inventory collectors implement the `BaseCollector` interface:

| Method | Returns |
|---|---|
| `await collect()` | `list[CloudAsset]` |
| `await collect_edges()` | `list[NetworkEdge]`, the collector network edges of [5.3](#53-collector-network-edges) (AWS security group rules and VPC → subnet, Azure NSG rules and VNet → subnet, GCP internet ingress) |
| `await run()` | `tuple[list[CloudAsset], list[NetworkEdge]]` |
| `coverage` attribute | `CollectionCoverage` with one `ServiceCoverage` per task (AWS) or step |

The assets carry declared relations but no relationship edges: run them through
`RelationshipLinker` (or `InventoryMapper._link`) to get the typed edges. `AWSDeepInventoryCollector.collect()`
also drops breadth-sweep hits that duplicate a deep-collected asset (by `arn` and aliases), so
its output has at most one asset per resource.

`AzureDeepInventoryCollector.collection_mode` is `"resource-graph"` or `"sdk"` after `collect()`.

### 21.3 Kubernetes

| Function | Returns |
|---|---|
| `eks_token(session, cluster_name, region)` | `str`, a `k8s-aws-v1.` bearer token (presigned STS `GetCallerIdentity`) |
| `KubernetesReader(endpoint, ca_data_b64, token, timeout=10).get(path, params=None)` | `dict`, the decoded JSON response |
| `KubernetesReader.list(path)` | iterator of `dict` items, following `continue` tokens, 500 per page, at most 5000 objects |
| `map_cluster_objects(reader, cluster_arn, region, account_id)` | `list[CloudAsset]`: `K8S_NAMESPACE`, `K8S_SERVICE_ACCOUNT`, `K8S_WORKLOAD`, `K8S_SERVICE`, `K8S_INGRESS` |
| `collect_eks_workloads(session, cluster, region, account_id, timeout=10)` | `list[CloudAsset]`, the above for one `DescribeCluster` result |

Kubernetes object assets carry `cluster_arn`, `namespace`, `kind` and, per kind:

| Kind | Metadata | Relations |
|---|---|---|
| Namespace | `phase` | cluster `CONTAINS / CLUSTER_CONTAINS_SERVICE` → namespace |
| ServiceAccount | `irsa_role_arn` | namespace contains it; `ASSUMES_ROLE / RUNS_ON` → IRSA role |
| Deployment, StatefulSet, DaemonSet, CronJob | `replicas`, `ready_replicas`, `schedule`, `images`, `service_account`, `host_network`, `privileged_containers`, `node_selector` | namespace contains it; `USES_IMAGE / RUNS_ON` → each image's repository; `REFERENCES / RUNS_ON` → its service account |
| Service | `service_type`, `ports`, `load_balancer_hostnames`, `internal` | namespace contains it; `LOAD_BALANCER_TARGET / SERVES_TRAFFIC_TO` → selected workloads; load balancer `ROUTE / LOAD_BALANCED_BY` → service (reverse); exposed when `LoadBalancer` with a hostname |
| Ingress | `ingress_class`, `hosts`, `backends`, `load_balancer_hostnames`, `tls` | namespace contains it; `ROUTE / SERVES_TRAFFIC_TO` → backend services; load balancer `ROUTE / LOAD_BALANCED_BY` → ingress; exposed when it has a hostname |

Pod Identity associations are collected by the EKS collector itself, not through the
Kubernetes API.

### 21.4 Catalogs

| Function | Returns |
|---|---|
| `load_catalog(name)` | `dict`, the packaged `<name>.yaml` merged with `$CLOUDG_CATALOG_DIR/<name>.yaml`; cached per process |
| `asset_type_map(mapping, catalog="")` | `dict[str, AssetType]`; raises `ValueError` naming the catalog, key and value for an unknown type |
| `flatten(groups)` | `list[str]` from a list or a mapping of group → list |
| `asset_type_from_arn(arn)` | `AssetType`, `OTHER` when unknown |
| `select_tasks(names, include=None, exclude=None)` | `list[str]` of task names kept |

### 21.5 Mapper helpers

| Function | Returns |
|---|---|
| `deduplicate(assets, edges)` | `tuple[list[CloudAsset], list[NetworkEdge]]`: one asset per `arn` (the deep-collected copy wins over sweep or placeholder copies; `relations` and `aliases` are merged; exposure is OR-ed); edges re-pointed and deduplicated on `(source, target, edge_type)`, self-loops dropped |
| `add_account_hierarchy(assets, edges)` | `tuple[list[CloudAsset], list[NetworkEdge]]`: an account node per `(provider, account_id)` (reusing organization / subscription / project nodes), and a `hierarchy` `CONTAINS` edge to every asset nothing else contains |

---

## 22. Stability and compatibility

What you can rely on across 0.5.x releases:

- The field names and types in this document. New fields and new metadata keys may be added;
  consumers should ignore keys they do not know.
- `asset_type`, `edge_type` and `relationship` values are never renamed within 0.5.x. New values
  may appear (a new collector can introduce a new asset type).
- The exported file names and their top-level keys.
- The public Python API: the signatures listed here and the package exports of
  `cloudg.inventory` (`InventoryMapper`, `InventoryResult`, `RelationshipLinker`,
  `DependencyGraph`, `AWSDeepInventoryCollector`, `AzureDeepInventoryCollector`,
  `GCPDeepInventoryCollector`, `OrganizationTopology`, `discover_organization`).

What you should not rely on:

- `id` values, which are random per run. Correlate on `arn`.
- The order of `assets`, `edges`, metadata keys and unsorted counts.
- The exact metadata keys of a type staying identical between versions; the
  [catalog](INVENTORY_CATALOG.md) shows what is produced today.
- Names starting with an underscore, even when re-exported for backwards compatibility.

Secrets are never part of any structure: parameter values, environment variable values,
passwords, VPN pre-shared keys, Direct Connect authentication keys, connection strings and
Cloud Control properties matching the secret pattern are dropped at collection time, and
GCP URL aliases keep only `scheme://host`. Trust policy conditions and resource policy
principals are kept, because they define the relationships.
