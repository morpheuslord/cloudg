---
title: ReachabilityAnalyzer
object:
  - cloudg.graph.reachability.ReachabilityAnalyzer
  - cloudg.graph.reachability.finding_id
  - cloudg.graph.reachability.network_flow_graph
members:
  cloudg.graph.reachability.ReachabilityAnalyzer: [internet_entry_points, find_internet_exposed, flow_hops, flow_successors, generate_findings, compute_blast_radius]
lede: Walks a `GraphBuilder` graph from the internet along the edges traffic can actually take, and reports what it reaches with stable finding ids.
since: "0.6.0"
---

`cloudg run` calls `ReachabilityAnalyzer(graph).generate_findings()` right after it builds the graph, and the results show up in `findings.json` with `source_tool` set to `cloudg-reachability`. The class answers two different questions, and they follow different edges:

- What can the internet reach? `find_internet_exposed()` walks network-flow edges only, with the rules below.
- What could a compromised resource reach? `compute_blast_radius(node)` follows every edge, identity included, and stops at the internet placeholders.

The analyzer works on the graph you pass in and changes it: `find_internet_exposed()` sets `is_internet_exposed=True` on every node it reaches. Pass `graph.copy()` if you need the original untouched (the MCP layer does).

## The network-flow walk

Release 0.6.0 changed the walk. Before it, the analysis followed every edge type out of an exposed node, so a database whose only link to the internet was an IAM role granted access to it came out as a CRITICAL "Internet-exposed RDS_INSTANCE". Now an edge is followed only when traffic can travel along it, and in the direction it travels.

```mermaid caption="Edges the exposure walk follows, in the direction traffic moves"
flowchart LR
  I["0.0.0.0/0, ::/0, Internet tag"] -->|"SG or NACL rule, ingress"| G["Security group, NSG, NACL"]
  G -->|"ATTACHED_TO, walked backwards"| R["Resource in the group"]
  I -->|"INTERNET_EXPOSED"| P["Public resource"]
  R -->|"LOAD_BALANCER_TARGET"| T["Target group"]
  T -->|"LOAD_BALANCER_TARGET"| W["Targets"]
  E["ENI or Elastic IP"] -->|"ATTACHED_TO"| V["Instance"]
  N["VPC, VNet, subnet"] -->|"CONTAINS"| M["Resource placed in it"]
  S["Route or peering source"] -->|"ROUTE, PEERING"| D["Destination"]
```

| Edge type | Followed | Direction |
|---|---|---|
| `INTERNET_EXPOSED`, `LOAD_BALANCER_TARGET`, `ROUTE`, `PEERING` | always | source to target |
| `SECURITY_GROUP_RULE`, `NACL_RULE` | unless `direction` is `egress` | source to target |
| `ATTACHED_TO` | when the target is a `SECURITY_GROUP`, `NSG` or `NACL`, or the edge's `relationship` is `PROTECTED_BY_SG` or `PROTECTED_BY_NACL` | backwards, from the group to the resource attached to it |
| `ATTACHED_TO` | when the source is a `NETWORK_INTERFACE` or `ELASTIC_IP` | source to target |
| `CONTAINS` | only from a `VPC`, `VNET` or `SUBNET` | parent to child |
| `IAM_TRUST`, `IAM_POLICY_ATTACHMENT`, `ASSUMES_ROLE`, `GRANTS_ACCESS`, `INVOKES`, `REFERENCES`, `USES_IMAGE`, `LOGS_TO`, `PROTECTS`, `MONITORS`, `MANAGES`, `GOVERNS` | never | |

The backwards `ATTACHED_TO` hop is the one people miss. Collectors and the linker write `web-1 ATTACHED_TO sg-web`, pointing from the resource to its group, while traffic flows the other way: whatever the group admits reaches `web-1`.

`INVOKES` is deliberately not followed, so a Lambda function behind a public API Gateway is not reported as exposed. The gateway is the exposed resource; the function is only invoked by it. Disk, route-table and gateway attachments are not traffic paths either, and organization, account, cluster and namespace containment are not traversed.

Where the walk starts: every node named `0.0.0.0/0` or `::/0`, plus the source of every non-egress edge whose `cidr` stands for the whole internet. That test (`cloudg.graph.ports.is_internet_source`) also accepts the Azure NSG service tags `Internet`, `Any` and `*` in any letter case. Private CIDRs such as `10.0.0.0/8`, unresolved references and a group with an egress rule to `0.0.0.0/0` are not entry points.

The walk over-approximates. It does not intersect ports across hops, and a rule whose source is another security group is followed like any other ingress rule, so a database whose group admits the web tier's group is reported exposed once the web tier is. Treat a finding as "there is a network path", then check the ports.

## What generate_findings() reports

| Rule (`finding_id` input) | Raised for | Severity | Frameworks |
|---|---|---|---|
| `internet-exposed-sensitive-asset` | a reached `RDS_INSTANCE`, `AURORA_CLUSTER`, `AZURE_SQL`, `CLOUD_SQL` or `DYNAMODB_TABLE` | CRITICAL | CIS, NIST-800-53 |
| `internet-exposed-unexpected-asset` | any other reached resource, except load balancers, CloudFront, CDNs and internet gateways | HIGH | none |
| `internet-open-sensitive-port:<port>` | a non-egress edge from an internet source whose ports include one of 22, 3389, 3306, 5432, 1433, 27017, 6379, 9200, 5601, 8080 or 8443 | CRITICAL | CIS, NIST-800-53, PCI-DSS |

Security groups, NSGs, NACLs and target groups are hops: the walk marks them exposed, but they get no exposure finding of their own. A group's open rules show up as open-port findings instead, with the group as `resource_id`, and a target group's exposure shows up on the targets behind it. Placeholder nodes (`is_external`) never get an exposure finding.

Ports are compared as numbers after `cloudg.graph.ports` parses `port_range`, so `0-65535` contains 22, `2200-2300` does not, and an Azure `*` covers all eleven ports. An edge yields at most one finding per sensitive port, however many of its merged rules overlap it.

### Deterministic ids

Each finding id is a UUID5 of the rule name and a stable key, so the same exposure gets the same id on every scan. You can dedupe, track and suppress reachability findings across runs.

```python
finding_id(rule, asset_key(graph, node_id))                     # exposure findings
finding_id(f"{RULE_OPEN_PORT}:{port}", f"{src_key}->{dst_key}") # open-port findings
```

The key is the node's ARN, or the node id when there is no ARN (CIDR placeholders). The graph node id itself would not do: collectors give assets a fresh random UUID on every collection. `Finding.resource_id` is still that per-run node id, so match findings to assets of a later run by `resource_arn`.

## Examples

### Exposure, findings and blast radius

Ten assets, fourteen edges, no credentials. The estate has a public load balancer in front of `web-1`, an SSH rule left open on the web tier's group, a database reachable only from a private subnet and through an IAM grant, and a Lambda function behind a public API Gateway.

```python title="exposure.py"
"""Internet exposure, flow hops, finding ids and blast radius on a small estate."""

from cloudg.graph.builder import GraphBuilder
from cloudg.graph.reachability import (
    RULE_UNEXPECTED_EXPOSURE,
    ReachabilityAnalyzer,
    asset_key,
    finding_id,
    network_flow_graph,
)
from cloudg.schema.models import AssetType, CloudAsset, CloudProvider, EdgeType, NetworkEdge

ACCOUNT = "123456789012"
REGION = "eu-west-1"


def asset(asset_id: str, asset_type: AssetType, arn: str) -> CloudAsset:
    return CloudAsset(
        id=asset_id,
        name=asset_id,
        asset_type=asset_type,
        provider=CloudProvider.AWS,
        region=REGION,
        account_id=ACCOUNT,
        arn=arn,
    )


assets = [
    asset("sg-alb", AssetType.SECURITY_GROUP, f"arn:aws:ec2:{REGION}:{ACCOUNT}:security-group/sg-alb"),
    asset("sg-web", AssetType.SECURITY_GROUP, f"arn:aws:ec2:{REGION}:{ACCOUNT}:security-group/sg-web"),
    asset("sg-db", AssetType.SECURITY_GROUP, f"arn:aws:ec2:{REGION}:{ACCOUNT}:security-group/sg-db"),
    asset("web-alb", AssetType.LOAD_BALANCER, f"arn:aws:elasticloadbalancing:{REGION}:{ACCOUNT}:loadbalancer/app/web-alb/1"),
    asset("web-tg", AssetType.TARGET_GROUP, f"arn:aws:elasticloadbalancing:{REGION}:{ACCOUNT}:targetgroup/web-tg/1"),
    asset("web-1", AssetType.EC2, f"arn:aws:ec2:{REGION}:{ACCOUNT}:instance/i-0web1"),
    asset("app-role", AssetType.IAM_ROLE, f"arn:aws:iam::{ACCOUNT}:role/app-role"),
    asset("orders-db", AssetType.RDS_INSTANCE, f"arn:aws:rds:{REGION}:{ACCOUNT}:db:orders-db"),
    asset("orders-api", AssetType.API_GATEWAY, f"arn:aws:apigateway:{REGION}::/restapis/a1b2c3"),
    asset("orders-fn", AssetType.LAMBDA_FUNCTION, f"arn:aws:lambda:{REGION}:{ACCOUNT}:function:orders-fn"),
]


def ingress(source: str, target: str, ports: str, cidr: str | None = None) -> NetworkEdge:
    return NetworkEdge(
        source_id=source,
        target_id=target,
        edge_type=EdgeType.SECURITY_GROUP_RULE,
        port_range=ports,
        protocol="TCP",
        cidr=cidr,
        direction="ingress",
    )


def edge(source: str, target: str, edge_type: EdgeType, **extra) -> NetworkEdge:
    return NetworkEdge(source_id=source, target_id=target, edge_type=edge_type, **extra)


edges = [
    ingress("0.0.0.0/0", "sg-alb", "443", cidr="0.0.0.0/0"),
    ingress("0.0.0.0/0", "sg-web", "22", cidr="0.0.0.0/0"),  # SSH left open
    ingress("sg-alb", "sg-web", "8080"),
    ingress("10.0.1.0/24", "sg-db", "5432", cidr="10.0.1.0/24"),  # private source
    # The default egress rule points from the group to the internet
    edge("sg-web", "0.0.0.0/0", EdgeType.SECURITY_GROUP_RULE, port_range="0-65535",
         protocol="ALL", cidr="0.0.0.0/0", direction="egress"),
    edge("web-alb", "sg-alb", EdgeType.ATTACHED_TO, relationship="PROTECTED_BY_SG"),
    edge("web-1", "sg-web", EdgeType.ATTACHED_TO, relationship="PROTECTED_BY_SG"),
    edge("orders-db", "sg-db", EdgeType.ATTACHED_TO, relationship="PROTECTED_BY_SG"),
    edge("web-alb", "web-tg", EdgeType.LOAD_BALANCER_TARGET),
    edge("web-tg", "web-1", EdgeType.LOAD_BALANCER_TARGET),
    edge("web-1", "app-role", EdgeType.ASSUMES_ROLE),
    edge("app-role", "orders-db", EdgeType.GRANTS_ACCESS),
    edge("0.0.0.0/0", "orders-api", EdgeType.INTERNET_EXPOSED, cidr="0.0.0.0/0"),
    edge("orders-api", "orders-fn", EdgeType.INVOKES),
]

graph = GraphBuilder().build(assets, edges)
analyzer = ReachabilityAnalyzer(graph)

print("entry points:", sorted(analyzer.internet_entry_points()))
print("exposed:", sorted(analyzer.find_internet_exposed()))

print("hops out of sg-web:")
for nxt, data, walked_back in analyzer.flow_hops("sg-web"):
    print(f"  -> {nxt} via {data['edge_type']}{' (reversed)' if walked_back else ''}")

for finding in analyzer.generate_findings():
    print(f"{finding.severity.value:8} {finding.title}  id={finding.id[:8]}")

# The id can be recomputed from the rule name and the asset's ARN
expected = finding_id(RULE_UNEXPECTED_EXPOSURE, asset_key(graph, "web-1"))
print("web-1 exposure id:", expected[:8])

flow = network_flow_graph(graph)
print("flow edges:", flow.number_of_edges(), "of", graph.number_of_edges())
print("flow reversed:", sorted((u, v) for u, v, d in flow.edges(data=True) if d["reversed"]))

radius = analyzer.compute_blast_radius("web-1")
print("blast radius of web-1:", sorted(radius["reachable_nodes"]),
      "depth", radius["depth"], "risk", radius["risk_score"])
```

```console
$ python exposure.py
entry points: ['0.0.0.0/0']
exposed: ['orders-api', 'sg-alb', 'sg-web', 'web-1', 'web-alb', 'web-tg']
hops out of sg-web:
  -> web-1 via ATTACHED_TO (reversed)
HIGH     Unexpected internet-exposed resource: orders-api  id=b5fbe235
HIGH     Unexpected internet-exposed resource: web-1  id=4ec3a339
CRITICAL Security group allows SSH (port 22) from 0.0.0.0/0  id=17cd5168
web-1 exposure id: 4ec3a339
flow edges: 10 of 14
flow reversed: [('sg-alb', 'web-alb'), ('sg-db', 'orders-db'), ('sg-web', 'web-1')]
blast radius of web-1: ['0.0.0.0/0', 'app-role', 'orders-db', 'sg-db', 'sg-web'] depth 3 risk 4.5
```

What the output shows:

- `10.0.1.0/24` and the group with the egress rule are not entry points. `orders-db` is not exposed: its only inbound rule comes from a private CIDR, and the IAM path through `app-role` does not count.
- `orders-fn` is not exposed, because `INVOKES` is not a network hop. The API Gateway is reported instead.
- `web-alb` is reached but gets no finding (load balancers are expected to face the internet), and the groups and the target group are hops only.
- The ids are the same on every run. Run the script twice and compare.
- The only edge leaving `sg-web` in the graph is its egress rule, which the walk skips. Its one flow hop is the attachment from `web-1`, walked backwards.

The blast radius is a different, wider question. From `web-1` it follows every edge type, so the IAM edges lead it to `orders-db`. It also follows the egress rule to the `0.0.0.0/0` placeholder but stops there: being able to send traffic to the internet does not put everything the internet reaches in the blast radius. Read it as an upper bound all the same.

### Flow-aware paths with NetworkX

`network_flow_graph()` returns a new `DiGraph` with an edge `u -> v` exactly where the exposure walk would hop, so ordinary NetworkX path functions follow traffic. Save this next to `exposure.py`; the import runs that script first, so its output is printed too.

```python title="flow_paths.py"
import networkx as nx

from cloudg.graph.reachability import network_flow_graph
from exposure import graph

flow = network_flow_graph(graph)
for path in nx.all_simple_paths(flow, "0.0.0.0/0", "web-1", cutoff=6):
    hops = [flow.edges[u, v]["edge_type"] + (" (rev)" if flow.edges[u, v]["reversed"] else "")
            for u, v in zip(path, path[1:])]
    print(" -> ".join(path), "|", ", ".join(hops))
```

```console
$ python flow_paths.py
...
0.0.0.0/0 -> sg-alb -> sg-web -> web-1 | SECURITY_GROUP_RULE, SECURITY_GROUP_RULE, ATTACHED_TO (rev)
0.0.0.0/0 -> sg-alb -> web-alb -> web-tg -> web-1 | SECURITY_GROUP_RULE, ATTACHED_TO (rev), LOAD_BALANCER_TARGET, LOAD_BALANCER_TARGET
0.0.0.0/0 -> sg-web -> web-1 | SECURITY_GROUP_RULE, ATTACHED_TO (rev)
```

The first path is the over-approximation at work: `sg-alb` admits 443 from the internet and `sg-web` admits 8080 from `sg-alb`, and the walk does not check that the ports line up.

## Notes

- `compute_blast_radius()` returns `reachable_nodes` (every node a breadth-first walk over every edge type reaches), `depth` (the longest shortest-path distance) and `risk_score`: 0.5 per reachable node, plus 2.0 for each reachable `RDS_INSTANCE`, `AURORA_CLUSTER`, `AZURE_SQL`, `CLOUD_SQL` or `DYNAMODB_TABLE`, capped at 10.0. The walk reaches the internet placeholders `0.0.0.0/0` and `::/0` but does not continue through them; only a walk that starts at a placeholder follows its edges. An unknown node gives `{"reachable_nodes": [], "depth": 0, "risk_score": 0.0}`.
- `flow_hops()` can yield the same next node more than once when several edges lead there, and yields nothing for an unknown node. `flow_successors()` is the same walk without the edge data.
- `network_flow_graph()` copies every node with its attributes and leaves the input graph alone. Each edge carries `edge_type` and `reversed`.
- Graphs built by hand can carry a `ports` list on an edge, and the open-port check reads it next to `port_range`. `GraphBuilder` never copies `NetworkEdge.ports` onto the graph.
- The open-port title keeps the historical `0.0.0.0/0` wording for both `0.0.0.0/0` and `::/0`, and names the Azure tag as written (`Internet`, `Any`, `*`) otherwise.
- Stored findings from 0.5.x carry random ids. They will not match the 0.6.0 ids; re-baseline suppressions after upgrading.

## Related

:::links
- [GraphBuilder](/api/graphbuilder/) Builds the graph this class walks.
- [Dependencies and blast radius](/guides/dependencies/) The inventory-level blast radius behind `cloudg deps`.
- [DependencyGraph](/api/dependencygraph/) Dependency walks over a saved map.
- [Data models](/api/models/) The `Finding` model these results use.
- [Graph, ontology and RAG](/guides/graph-ontology-rag/) Where reachability sits in the analysis phase.
:::
