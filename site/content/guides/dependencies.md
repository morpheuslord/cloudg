---
title: Dependencies and blast radius
lede: "`cloudg deps` asks two questions of any asset on a saved map: what does it need, and what breaks with it?"
meta:
  - [Command, "`cloudg deps`"]
  - [Input, "`inventory-map.json` from `cloudg map`"]
source: cloudg/inventory/dependencies.py
---

A map from [`cloudg map`](/guides/inventory-mapping/) records edges the way you would describe them out loud: the queue invokes the function, the function assumes its role, the WAF protects the API. That is the right shape for drawing, but not for impact questions. To ask "what breaks if I rotate this KMS key?" you need every edge turned into one arrow that reads "dependent needs dependency". `cloudg deps` and the `DependencyGraph` class behind it do that conversion and then walk the result.

`cloudg deps` reads a saved `inventory-map.json` and nothing else. It makes no cloud calls, so you can run it on a laptop against a map someone produced in CI last night.

## How edges become dependencies

Each edge type has a fixed dependency direction. For "uses" edges the source needs the target. For "acts on" edges the target needs the source.

| Direction | Edge types | Reads as |
|---|---|---|
| forward: the source depends on the target | `REFERENCES`, `ATTACHED_TO`, `ROUTE`, `PEERING`, `USES_IMAGE`, `ASSUMES_ROLE`, `LOGS_TO`, `LOAD_BALANCER_TARGET`, `GRANTS_ACCESS`, `IAM_POLICY_ATTACHMENT`, `IAM_TRUST` | a function needs its role, image, key and log group; a principal needs what it is granted |
| reverse: the target depends on the source | `CONTAINS`, `INVOKES`, `PROTECTS`, `MONITORS`, `MANAGES`, `GOVERNS` | a function needs the queue that triggers it; an ALB needs the WAF in front of it; a resource needs the stack managing it; an account needs the SCPs governing it |
| ignored | `SECURITY_GROUP_RULE`, `NACL_RULE`, `INTERNET_EXPOSED` | traffic rules carry no dependency meaning |

Two more rules shape the graph. `CONTAINS` edges whose container is an organization, an OU or an account are dropped, because "this account contains this bucket" says where something lives, not what breaks with it. And an edge only counts when both of its ends are assets on the map, so edges to raw CIDR blocks never take part.

Here is a small map as `cloudg map` would record it:

```mermaid caption="A slice of a map, with edges in their natural direction"
flowchart LR
  WAF["orders-api-acl (WAF)"] -->|PROTECTS| API["orders-api (API Gateway)"]
  API -->|INVOKES| FN["orders-worker (Lambda)"]
  Q["orders (SQS)"] -->|INVOKES| FN
  Q -->|REFERENCES| DLQ["orders-dlq (SQS)"]
  Q -->|REFERENCES| KEY["orders-key (KMS)"]
  FN -->|ASSUMES_ROLE| ROLE["orders-worker (IAM role)"]
  FN -->|USES_IMAGE| REPO["orders-worker (ECR)"]
  FN -->|LOGS_TO| LOGS["/aws/lambda/orders-worker"]
  FN -->|REFERENCES| KEY
  DLQ -->|REFERENCES| KEY
  REPO -->|REFERENCES| KEY
  ROLE -->|GRANTS_ACCESS| TABLE["orders (DynamoDB)"]
  TABLE -->|REFERENCES| KEY
  EXT["account 999999999999"] -->|IAM_TRUST| ROLE
```

And the same slice after the conversion. Every arrow now points from the asset that needs something to the thing it needs. Note how the `INVOKES` and `PROTECTS` arrows flipped:

```mermaid caption="The same slice as dependency arrows. Walking with the arrows is depends_on (up); walking against them is dependents (down)."
flowchart LR
  FN["orders-worker (Lambda)"] --> API["orders-api (API Gateway)"]
  API --> WAF["orders-api-acl (WAF)"]
  FN --> Q["orders (SQS)"]
  Q --> DLQ["orders-dlq (SQS)"]
  Q --> KEY["orders-key (KMS)"]
  DLQ --> KEY
  FN --> ROLE["orders-worker (IAM role)"]
  FN --> REPO["orders-worker (ECR)"]
  FN --> LOGS["/aws/lambda/orders-worker"]
  FN --> KEY
  REPO --> KEY
  ROLE --> TABLE["orders (DynamoDB)"]
  TABLE --> KEY
  EXT["account 999999999999"] --> ROLE
```

Upstream of the function sits everything it needs to run, including the API and queue that feed it work. Downstream of the KMS key sits everything that stops working if the key is disabled.

This is an availability and change-impact view. Compromise runs the other way along identity edges: a compromised function exposes its role, not the reverse. For that question, walk the `IAM_TRUST`, `ASSUMES_ROLE` and `GRANTS_ACCESS` edges of the map directly, or use the attack path analysis in [GraphBuilder](/api/graphbuilder/).

## Query one asset

Give `cloudg deps` an asset and it prints two trees: what the asset depends on, and what depends on it.

```bash
cloudg deps arn:aws:sqs:us-east-1:123456789012:orders --map ./reports
```

The output below was produced by cloudg 0.6.0 against the map drawn above (the banner that cloudg prints first is left out here):

```console
$ cloudg deps arn:aws:sqs:us-east-1:123456789012:orders --map ./reports
orders MESSAGE_QUEUE arn:aws:sqs:us-east-1:123456789012:orders depends on
├── orders-key KMS_KEY · 123456789012/us-east-1 (ENCRYPTED_BY_KMS)
└── orders-dlq MESSAGE_QUEUE · 123456789012/us-east-1 (WRITES_TO)
orders MESSAGE_QUEUE arn:aws:sqs:us-east-1:123456789012:orders needed by (blast radius)
└── orders-worker LAMBDA_FUNCTION · 123456789012/us-east-1 (TRIGGERED_BY)
```

Each line is the asset name, its type, account and region, and in parentheses the edge's `relationship` (or its `edge_type` when no relationship is set). An empty tree prints `nothing`.

Asking about the function in one direction shows the walk going deeper:

```console
$ cloudg deps arn:aws:lambda:us-east-1:123456789012:function:orders-worker --direction up
orders-worker LAMBDA_FUNCTION arn:aws:lambda:us-east-1:123456789012:function:orders-worker depends on
├── orders-worker IAM_ROLE · 123456789012/global (RUNS_ON)
│   └── orders DYNAMODB_TABLE · 123456789012/us-east-1 (POLICY_ALLOWS_ACTION)
├── orders-worker CONTAINER_REGISTRY · 123456789012/us-east-1 (USES_IMAGE)
├── /aws/lambda/orders-worker LOG_GROUP · 123456789012/us-east-1 (LOGS_TO)
├── orders-key KMS_KEY · 123456789012/us-east-1 (ENCRYPTED_BY_KMS)
├── orders MESSAGE_QUEUE · 123456789012/us-east-1 (TRIGGERED_BY)
│   └── orders-dlq MESSAGE_QUEUE · 123456789012/us-east-1 (WRITES_TO)
└── orders-api API_GATEWAY · 123456789012/us-east-1 (INVOKES)
    └── orders-api-acl WAF_WEB_ACL · 123456789012/us-east-1 (PROTECTED_BY_WAF)
```

The walk is breadth-first and every asset appears once, at the shallowest depth where it was first reached. The DynamoDB table also needs `orders-key`, but the key already appeared one level up as a direct dependency of the function, so it isn't repeated under the table. When an asset seems to be missing from a branch, look higher in the tree.

### Direction, depth and top

| Option | Default | Effect |
|---|---|---|
| `ASSET` | none | The asset to query. Leave it out for the overview below. |
| `-m, --map` | `./reports` | `inventory-map.json`, or the directory holding it. |
| `-d, --direction` | `both` | `up` is what the asset depends on, `down` is what depends on it, `both` prints the two trees. |
| `--depth` | `3` | Levels to expand in the trees. |
| `--top` | `15` | Rows in the overview tables. |
| `--json` | off | Print JSON instead of tables and trees. |

`--depth` only limits the trees. The blast radius figures in the overview always walk up to 10 hops.

### How the asset is matched

The argument can be any of these, tried in order:

1. the internal asset ID (the UUID in `inventory-map.json`);
2. the ARN or resource ID;
3. the name, when exactly one asset has it;
4. the part of the ARN after the last `/`, when exactly one asset has it.

Names repeat more than you would expect. In the map above a role, a function and an ECR repository are all called `orders-worker`, so a bare name matches nothing:

```console
$ cloudg deps orders-worker
  ✗ No unique asset matches 'orders-worker'; use its ARN or resource ID
```

The command exits with status 1 in that case, which makes it safe in scripts. Pass the full ARN instead. `orders-key` works as a bare name because only one asset carries it.

## The overview

Without an asset, `cloudg deps` prints three tables for the whole map:

```console
$ cloudg deps --map ./reports --top 5
──────────────────────────────── Interdependencies ────────────────────────────────
                   Most shared dependencies
╭───────────────┬──────────┬──────────────┬───────────────────╮
│ Asset         │     Type │      Account │ Direct dependents │
├───────────────┼──────────┼──────────────┼───────────────────┤
│ orders-key    │  KMS_KEY │ 123456789012 │                 5 │
│ orders-worker │ IAM_ROLE │ 123456789012 │                 2 │
╰───────────────┴──────────┴──────────────┴───────────────────╯
                        Largest blast radius
╭────────────────┬────────────────┬────────────┬──────────┬─────────╮
│ Asset          │           Type │ Dependents │ Accounts │ Exposed │
├────────────────┼────────────────┼────────────┼──────────┼─────────┤
│ orders-key     │        KMS_KEY │          7 │        2 │       0 │
│ orders         │ DYNAMODB_TABLE │          3 │        2 │       0 │
│ orders-dlq     │  MESSAGE_QUEUE │          2 │        1 │       0 │
│ orders-worker  │       IAM_ROLE │          2 │        2 │       0 │
│ orders-api-acl │    WAF_WEB_ACL │          2 │        1 │       1 │
╰────────────────┴────────────────┴────────────┴──────────┴─────────╯
                                 Cross-account edges
╭────────────────────────────────┬─────────────────────┬────────────────────────────────┬──────────╮
│ Source                         │        Relationship │                         Target │ External │
├────────────────────────────────┼─────────────────────┼────────────────────────────────┼──────────┤
│ arn:aws:iam::999999999999:root │ CROSS_ACCOUNT_TRUST │ arn:aws:iam::123456789012:rol… │      yes │
╰────────────────────────────────┴─────────────────────┴────────────────────────────────┴──────────╯
```

A table with no rows is not printed at all.

### Shared dependencies

The assets that the most other assets depend on directly, the classic case being one KMS key behind forty resources. Containment and peering edges don't count, and an asset needs at least two distinct functional dependents to be listed. The count is of distinct assets, so a function with two edges to the same key counts once.

### Blast radius

The assets whose loss or change would reach the most others, counted transitively. cloudg takes the `4 × top` assets with the most direct dependents as candidates, walks each one downstream for up to 10 hops, and ranks them by how many assets it reached. Assets with no dependents are left out.

`Accounts` is how many distinct accounts those dependents live in. In the example the key reaches account `999999999999` because the role trusted by that external account sits downstream of the table the key encrypts. `Exposed` counts internet-exposed assets among the dependents: the WAF scores 1 because the API Gateway it protects faces the internet.

On a map made with `--org`, SCPs often rank high. Every account an SCP governs depends on it, so an SCP attached to many accounts collects many dependents even though nothing about it is broken.

### Cross-account edges

Every edge whose two ends carry different account IDs. `External` is `yes` when either end is a placeholder for an account that was not mapped, such as a vendor account trusted by one of your roles. Edges from an OU to an account are not listed, but on an organization map you will see an `SCP_RESTRICTS` row for every SCP attached directly to a member account, and AWS attaches `FullAWSAccess` to every account by default. Filter those out in JSON when you only care about workload traffic (see the Python example below).

## Coverage gaps

`cloudg deps` doesn't print the security coverage section; `cloudg map` writes it to `inventory-dependencies.json` under `security_coverage`:

| Key | What it holds |
|---|---|
| `services_by_account_region` | account to region to security service to enabled, for GuardDuty, Security Hub, Inspector, Macie, Config, CloudTrail and the others |
| `gaps` | every disabled cell as `"<account>/<region>: <service>"` |
| `workloads_without_vulnerability_scanning` | EC2 instances, container registries and Lambda functions that no enabled vulnerability scanner monitors |
| `internet_facing_without_waf` | internet-exposed load balancers, API Gateways and CloudFront distributions that no WAF protects |

The same file repeats the shared dependencies, blast radius (top 25), cross-account edges and the map's unresolved references.

```python title="coverage_gaps.py"
import json

with open("./reports/inventory-dependencies.json") as f:
    analysis = json.load(f)

coverage = analysis["security_coverage"]
for gap in coverage["gaps"]:
    print("disabled:", gap)
for item in coverage["internet_facing_without_waf"]:
    print("no WAF:", item["type"], item["name"], item["account_id"])
for item in coverage["workloads_without_vulnerability_scanning"]:
    print("not scanned:", item["type"], item["name"], item["region"])
```

## JSON output

`--json` prints the tree view (with an asset) or the overview (without one) as JSON. The tree has an `asset` descriptor and, depending on `--direction`, `depends_on` and `dependents` lists. Each node is a descriptor (`id`, `name`, `arn`, `type`, `account_id`, `region`) plus `via` (the edge type), `relationship` and `children`. The overview has `shared_dependencies`, `largest_blast_radius` and `cross_account_edges`; that last list is complete, since `--top` only trims the table view.

With `--json` the banner and log lines go to stderr, so you can redirect stdout straight to a file:

```bash
cloudg deps arn:aws:iam::123456789012:role/orders-worker --json > role-deps.json
cloudg deps --map ./reports --top 50 --json > overview.json
```

For anything more than a one-off, the Python API below returns the same structures without the files.

## Working in Python

`InventoryResult.load()` reads a saved map, and `dependency_graph()` builds the graph `cloudg deps` uses:

```python title="blast_radius.py"
from cloudg.inventory import InventoryResult

inventory = InventoryResult.load("./reports")    # the directory or inventory-map.json
graph = inventory.dependency_graph()

key = graph.find("orders-key")                    # ID, ARN, unique name or unique ARN tail
if key is None:
    raise SystemExit("no unique asset matches")

needs, needed_by = graph.direct_counts(key.id)
print(f"{key.name} ({key.asset_type.value}): needs {needs}, needed by {needed_by} directly")

for link in graph.dependents(key.id, max_depth=5):
    asset = graph.assets[link.asset_id]
    parent = graph.assets[link.parent_id]
    print(f"{'  ' * link.depth}{asset.name} [{asset.asset_type.value}] "
          f"via {link.relationship or link.via_edge} from {parent.name}")

for row in graph.shared_dependencies(top=5):
    print(row["name"], row["type"], row["direct_dependents"])

for row in graph.blast_radius(top=5):
    print(row["name"], row["transitive_dependents"], row["accounts_affected"],
          row["internet_exposed_dependents"])
```

`depends_on(asset_id, max_depth=10)` and `dependents(asset_id, max_depth=10)` return `DependencyLink` objects with `asset_id`, `via_edge`, `relationship`, `depth` (starting at 1) and `parent_id`. `tree(asset_id, direction="both", max_depth=3)` returns the nested dict that `--json` prints. `blast_radius()` also takes `candidates`, an iterable of asset IDs, when you want to score a specific set instead of the most-depended-on assets:

```python title="key_blast_radius.py"
from cloudg.inventory import InventoryResult
from cloudg.inventory.dependencies import cross_account_edges

inventory = InventoryResult.load("./reports")
graph = inventory.dependency_graph()

keys = [a.id for a in inventory.assets if a.asset_type.value == "KMS_KEY"]
for row in graph.blast_radius(candidates=keys, top=10):
    print(row["arn"], row["transitive_dependents"], row["accounts_affected"])

workload_edges = [
    e for e in cross_account_edges(inventory.assets, inventory.edges)
    if e["edge_type"] != "GOVERNS"
]
for e in workload_edges:
    print(e["source_account"], e["relationship"] or e["edge_type"], e["target_account"],
          "(external)" if e["external"] else "")
```

Build the graph with `inventory.dependency_graph(include_hierarchy=True)` if you want account and OU containment to count, for example to ask what depends on one OU.

### Resolving references with AssetIndex

`graph.find()` uses `AssetIndex`, the matcher cloudg also uses to attach scanner findings to assets. Use it directly when you have many references to resolve, such as every `resource_id` from a scanner export. Its `find()` takes two opt-in tiers for references `cloudg deps` won't accept: the ARN resource part (`function:orders-worker`, `db:orders`, `instance/i-0web1`) and a case-insensitive name.

```python title="resolve_refs.py"
from cloudg.inventory import InventoryResult
from cloudg.inventory.dependencies import AssetIndex

inventory = InventoryResult.load("./reports")
index = AssetIndex(inventory.assets)
by_id = {a.id: a for a in inventory.assets}

refs = [
    "arn:aws:sqs:us-east-1:123456789012:orders",   # exact ARN
    "orders-key",                                   # unique name
    "orders-worker",                                # three assets share this name
    "function:orders-worker",                       # ARN resource part, opt-in
    "ORDERS-KEY",                                   # case-folded name, opt-in
]
for ref in refs:
    strict = index.find(ref)
    loose = index.find(ref, arn_parts=True, casefold=True)
    print(f"{ref!r:48} strict={by_id[strict].asset_type.value if strict else None} "
          f"loose={by_id[loose].asset_type.value if loose else None}")
```

Against the example map, the ambiguous `orders-worker` stays unresolved in both modes, `function:orders-worker` and `ORDERS-KEY` resolve only with the opt-in tiers, and the other two resolve either way. The opt-in tiers never pick one of several assets that share an exact name. `index.resolve_finding(finding)` tries a finding's `resource_id` and `resource_arn` through the same tiers.

:::links
- [Inventory mapping](/guides/inventory-mapping/) Produce the map that `cloudg deps` reads.
- [cloudg deps](/cli/deps/) The command reference.
- [DependencyGraph](/api/dependencygraph/) Every method and return type.
- [InventoryResult](/api/inventoryresult/) Loading, analysis and export.
:::
