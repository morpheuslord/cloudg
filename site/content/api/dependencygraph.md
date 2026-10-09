---
object: [cloudg.inventory.dependencies.DependencyGraph, cloudg.inventory.dependencies.AssetIndex]
members:
  cloudg.inventory.dependencies.DependencyGraph: [find, depends_on, dependents, direct_counts, tree, shared_dependencies, blast_radius]
  cloudg.inventory.dependencies.AssetIndex: [add, find, resolve, resolve_finding]
lede: "What does this asset need, and what breaks if it goes away? `DependencyGraph` answers both over any set of assets and edges; `AssetIndex` is the matcher that finds the asset a reference or a finding is about."
---

## From edges to dependencies

Edges in an inventory map point in their natural direction: a function `ASSUMES_ROLE` a role, a queue `INVOKES` a function, a WAF `PROTECTS` an API. That direction is not always the direction of dependency. The function needs its role, so the arrow and the dependency agree. The function also needs the queue that triggers it, but the `INVOKES` arrow points from the queue to the function.

`DependencyGraph(assets, edges, include_hierarchy=False)` turns every edge into one `dependent -> dependency` arrow, using a fixed table (`cloudg.inventory.dependencies.DEPENDENCY_DIRECTION`):

| Direction | Edge types | Reads as |
|---|---|---|
| forward: the source depends on the target | `REFERENCES`, `ATTACHED_TO`, `ROUTE`, `PEERING`, `USES_IMAGE`, `ASSUMES_ROLE`, `LOGS_TO`, `LOAD_BALANCER_TARGET`, `GRANTS_ACCESS`, `IAM_POLICY_ATTACHMENT`, `IAM_TRUST` | a function depends on its role, its image, its key, its log group |
| reverse: the target depends on the source | `CONTAINS`, `INVOKES`, `PROTECTS`, `MONITORS`, `MANAGES`, `GOVERNS` | a function depends on the queue that triggers it, an API on the WAF in front of it, a resource on the stack that manages it |
| ignored | `SECURITY_GROUP_RULE`, `NACL_RULE`, `INTERNET_EXPOSED` | network rules are not dependencies |

```mermaid caption="Natural edges on the left, dependency arrows on the right"
flowchart LR
  subgraph natural ["inventory edges"]
    Q1["queue"] -->|INVOKES| F1["function"]
    F1 -->|ASSUMES_ROLE| R1["role"]
  end
  subgraph deps ["dependency view"]
    F2["function"] -->|needs| Q2["queue"]
    F2 -->|needs| R2["role"]
  end
```

On that view, `depends_on(x)` walks upstream (everything `x` needs) and `dependents(x)` walks downstream (everything that needs `x`, its blast radius). Both are breadth-first, visit each asset once, stop at `max_depth` (default 10) and return `DependencyLink` records with `asset_id`, `via_edge`, `relationship`, `depth` and `parent_id`, the asset one hop closer to the start.

Edges whose source or target is not in `assets` are skipped. With `include_hierarchy=False`, `CONTAINS` edges into `ORGANIZATION`, `ORG_UNIT` and `CLOUD_ACCOUNT` nodes are skipped too, because otherwise every account would top every blast radius list. `InventoryResult.dependency_graph()` builds the graph with this default.

This is an availability and change-impact view: what stops working when something is deleted, disabled or misconfigured. Compromise spreads differently. A stolen function credential exposes the role it assumes, which is the forward direction of `ASSUMES_ROLE` in the map itself, not a dependent of the role. For attack paths use the graph analysis in [`CloudGEngine.analyze()`](/api/cloudgengine/) or walk the identity edges directly.

### The reports

`tree(asset_id, direction="both", max_depth=3)` nests the two walks into a dict: `asset`, plus `depends_on` and/or `dependents` (pick with `"up"`, `"down"` or `"both"`), each node carrying `id`, `name`, `arn`, `type`, `account_id`, `region`, `via`, `relationship` and `children`. It is what `cloudg deps` prints.

`shared_dependencies(top=25)` ranks assets by how many distinct assets depend on them directly, ignoring `CONTAINS` and `PEERING` and anything with fewer than two dependents. One KMS key behind forty resources shows up here.

`blast_radius(candidates=None, top=25)` ranks assets by the size of their full transitive dependent set and adds `accounts_affected` and `internet_exposed_dependents`. Without `candidates` it looks at the `4 × top` assets with the most direct dependents, because walking from every asset in a large map is slow. Pass `candidates` (asset ids) to score exactly the assets you care about.

`find(ref)` looks up an asset by id, ARN, unique name or unique ARN tail and returns the `CloudAsset`, or `None`. It builds an `AssetIndex` on first use.

### AssetIndex

`AssetIndex(assets)` is the one matcher the ontology, the RAG export and the dependency graph share for "which asset is this string about". It tries, in order:

1. the internal `id`
2. the ARN or resource ID, or an alias registered with `add(..., aliases=[...])`; the first asset indexed under it wins
3. the name, if exactly one asset has it
4. the ARN tail after the last `/`, if exactly one asset has it
5. the ARN resource part and its last `:` or `/` segment (`db:orders`, `orders`), opt-in with `arn_parts=True`
6. the name ignoring case, opt-in with `casefold=True`

Ambiguous names and tails never match at their own tier. Tiers 5 and 6 are also skipped for a reference that is the exact name of more than one asset. `resolve_finding(finding)` tries both `finding.resource_id` and `finding.resource_arn` at every tier, which matters because scanners often put an ARN or a display name in `resource_id`.

## Examples

### Blast radius of a KMS key

Runs offline on six linked assets.

```python title="blast_radius.py"
from cloudg.inventory import RelationshipLinker
from cloudg.inventory.dependencies import DependencyGraph
from cloudg.schema.models import AssetType, CloudAsset, CloudProvider

ACCOUNT = "123456789012"
REGION = "eu-west-1"
KEY = f"arn:aws:kms:{REGION}:{ACCOUNT}:key/1111aaaa-22bb-33cc-44dd-555555eeeeee"
ROLE = f"arn:aws:iam::{ACCOUNT}:role/orders-worker-role"
QUEUE = f"arn:aws:sqs:{REGION}:{ACCOUNT}:orders-inbound"
TABLE = f"arn:aws:dynamodb:{REGION}:{ACCOUNT}:table/orders"
FUNCTION = f"arn:aws:lambda:{REGION}:{ACCOUNT}:function:orders-worker"
API = f"arn:aws:apigateway:{REGION}::/restapis/a1b2c3d4e5"


def aws(arn, name, asset_type, *relations, region=REGION, exposed=False):
    return CloudAsset(arn=arn, name=name, asset_type=asset_type, provider=CloudProvider.AWS,
                      region=region, account_id=ACCOUNT, is_internet_exposed=exposed,
                      metadata={"relations": list(relations)})


def rel(target, edge, relationship=None, reverse=False):
    return {"target": target, "edge": edge, "relationship": relationship, "reverse": reverse}


assets = [
    aws(KEY, "orders-key", AssetType.KMS_KEY),
    aws(ROLE, "orders-worker-role", AssetType.IAM_ROLE, region="global"),
    aws(QUEUE, "orders-inbound", AssetType.MESSAGE_QUEUE, rel(KEY, "REFERENCES", "ENCRYPTED_BY_KMS")),
    aws(TABLE, "orders", AssetType.DYNAMODB_TABLE, rel(KEY, "REFERENCES", "ENCRYPTED_BY_KMS")),
    aws(FUNCTION, "orders-worker", AssetType.LAMBDA_FUNCTION,
        rel(ROLE, "ASSUMES_ROLE", "RUNS_ON"),
        rel(TABLE, "REFERENCES", "WRITES_TO"),
        rel(QUEUE, "INVOKES", "TRIGGERED_BY", reverse=True)),
    aws(API, "orders-api", AssetType.API_GATEWAY, rel(FUNCTION, "INVOKES"), exposed=True),
]
edges = RelationshipLinker(assets).link()
graph = DependencyGraph(assets, edges)

key = graph.find("orders-key")         # ID, ARN, unique name or unique ARN tail
print("If", key.name, "is disabled:")
for link in graph.dependents(key.id):
    asset = graph.assets[link.asset_id]
    parent = graph.assets[link.parent_id].name
    print(f"  depth {link.depth}: {asset.name} ({asset.asset_type.value}) needs {parent} via {link.via_edge}")

worker = graph.find(FUNCTION)
print("orders-worker needs:", [graph.assets[l.asset_id].name for l in graph.depends_on(worker.id)])
print("direct (needs, needed by):", graph.direct_counts(worker.id))

for row in graph.blast_radius(top=3):
    print(f"{row['name']:20} {row['transitive_dependents']} dependents, "
          f"{row['internet_exposed_dependents']} internet-exposed")
```

```console
$ python blast_radius.py
If orders-key is disabled:
  depth 1: orders-inbound (MESSAGE_QUEUE) needs orders-key via REFERENCES
  depth 1: orders (DYNAMODB_TABLE) needs orders-key via REFERENCES
  depth 2: orders-worker (LAMBDA_FUNCTION) needs orders-inbound via INVOKES
orders-worker needs: ['orders-worker-role', 'orders', 'orders-inbound', 'orders-api', 'orders-key']
direct (needs, needed by): (4, 0)
orders-key           3 dependents, 0 internet-exposed
orders-api           1 dependents, 0 internet-exposed
orders               1 dependents, 0 internet-exposed
```

Two results are worth a second look. The function appears at depth 2 under the key, reached through the queue rather than through the table, because breadth-first search records the first path it finds. And `orders-api` is in the function's `depends_on` list: `INVOKES` is a reverse edge, so the function depends on whatever invokes it. Read that as "the function receives no traffic if the API goes away".

### Match findings to assets

```python title="match_findings.py"
from cloudg.inventory.dependencies import AssetIndex
from cloudg.schema.models import AssetType, CloudAsset, CloudProvider, Finding, Severity


def asset(arn, name, asset_type):
    return CloudAsset(arn=arn, name=name, asset_type=asset_type,
                      provider=CloudProvider.AWS, region="eu-west-1", account_id="123456789012")


assets = [
    asset("arn:aws:rds:eu-west-1:123456789012:db:orders", "orders", AssetType.RDS_INSTANCE),
    asset("arn:aws:dynamodb:eu-west-1:123456789012:table/orders", "orders", AssetType.DYNAMODB_TABLE),
    asset("arn:aws:lambda:eu-west-1:123456789012:function:Api-Handler", "Api-Handler",
          AssetType.LAMBDA_FUNCTION),
]
index = AssetIndex(assets)
names = {a.id: f"{a.asset_type.value}:{a.name}" for a in assets}


def finding(resource_id, resource_arn=None):
    return Finding(resource_id=resource_id, resource_arn=resource_arn, severity=Severity.MEDIUM,
                   title="example", description="example", source_tool="custom")


cases = [
    finding("x", "arn:aws:rds:eu-west-1:123456789012:db:orders"),   # exact ARN
    finding("orders"),                                              # name shared by two assets
    finding("db:orders"),                                           # ARN resource part
    finding("api-handler"),                                         # wrong letter case
]
for f in cases:
    default = index.resolve_finding(f)
    loose = index.resolve_finding(f, arn_parts=True, casefold=True)
    print(f"{f.resource_arn or f.resource_id:48} default={names.get(default)}  loose={names.get(loose)}")
```

```console
$ python match_findings.py
arn:aws:rds:eu-west-1:123456789012:db:orders     default=RDS_INSTANCE:orders  loose=RDS_INSTANCE:orders
orders                                           default=DYNAMODB_TABLE:orders  loose=DYNAMODB_TABLE:orders
db:orders                                        default=None  loose=RDS_INSTANCE:orders
api-handler                                      default=None  loose=LAMBDA_FUNCTION:Api-Handler
```

The second line shows the limit of tier 3. `orders` is the name of two assets, so the name tier refuses it, but the tail tier still matches: only the DynamoDB ARN ends in `/orders` (the RDS ARN uses `:`). If a reference can be a bare name in an estate where names repeat, check the asset type of what you got back.

## Notes

`DependencyGraph` keeps references to the assets you pass (`graph.assets` maps id to `CloudAsset`) and copies nothing. Build a new one after the map changes; there is no way to add edges to an existing graph.

`direct_counts()` counts edges, not assets. Two parallel edges between the same pair count twice. `shared_dependencies()` counts distinct assets.

`blast_radius()` drops candidates with no dependents at all, so the list can be shorter than `top`.

The module also has two functions that work on plain asset and edge lists: `cross_account_edges(assets, edges)` (every edge between two different accounts, hierarchy containment excluded) and `security_coverage(assets, edges)` (security services by account and region, the gaps, workloads without vulnerability scanning, internet-facing entry points without a WAF). `InventoryResult.analysis()` calls both.

## Related

:::links
- [Dependencies and blast radius](/guides/dependencies/) The guide, with `cloudg deps`.
- [cloudg deps](/cli/deps/) The CLI front end to `tree()`.
- [InventoryResult](/api/inventoryresult/) `dependency_graph()` and `analysis()`.
- [RelationshipLinker](/api/relationshiplinker/) Where the edges come from.
:::
