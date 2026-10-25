---
title: GraphBuilder
description: Turns a list of CloudAsset and NetworkEdge objects into a NetworkX DiGraph, then searches, scores and exports it.
---

Turns a list of `CloudAsset` and `NetworkEdge` objects into a NetworkX `DiGraph`, then searches, scores and exports it.
{ .lede }

**Last changed** [v0.6.0](../changelog.md#0.6.0)
{ .page-meta }

`GraphBuilder` is the first thing `cloudg run` does after collection, and `InventoryResult.export()` uses it to write `inventory-map.graphml` and `inventory-graph.json`. It needs no credentials and no network: hand it assets and edges from a collector, a saved `inventory-map.json` or your own code, and it gives you a plain `networkx.DiGraph` you can keep working on with the whole NetworkX library.

## What build() does

Each asset becomes a node keyed by `asset.id`. The node carries `name`, `asset_type`, `provider`, `region`, `arn` (an empty string when the asset has none), `account_id`, `tags` (the tag dict serialised as a JSON string, so GraphML can store it) and `is_internet_exposed`. Metadata and `raw_data` stay behind.

Each edge then joins `source_id` to `target_id`. Collectors write edges whose endpoints are not assets at all: a CIDR such as `0.0.0.0/0`, an Azure service tag or an unresolved reference. For those, `build()` creates a placeholder node with `asset_type` and `provider` set to `EXTERNAL` and `is_external=True`.

```mermaid
flowchart TD
  A["NetworkEdge"] --> B{"Endpoints are nodes?"}
  B -->|no| C["Add EXTERNAL placeholder"] --> D
  B -->|yes| D{"Edge already on this pair?"}
  D -->|no| E["Add edge"]
  D -->|yes| F{"Rule edge, same CIDR and direction?"}
  F -->|yes| G["Merge ports, protocols, descriptions"]
  F -->|no| H["Replace attributes"]
```
How build() places one NetworkEdge
{ .diagram-caption }

A `DiGraph` holds one edge per ordered pair. Collectors often emit several rules for one pair (two ingress rules from `0.0.0.0/0` to the same security group, for 22 and 443), so since 0.6.0 `SECURITY_GROUP_RULE`, `NACL_RULE` and `INTERNET_EXPOSED` edges on the same pair are merged when their `cidr` and `direction` match:

| Attribute | After merging rules for 22/TCP and 443/TCP | After merging 22/TCP and an ICMP rule |
|---|---|---|
| `port_range` | `"22,443"` | `"22"` (ICMP adds no ports) |
| `protocol` | `"TCP"` | `"TCP,ICMP"` |
| `description` | both descriptions joined with `"; "` | the same |

An empty port list on a TCP, UDP or all-protocol filter rule (GCP writes these) means every port, so it adds `0-65535` to the union. With mixed protocols the merged `port_range` says which ports are open from the source, but not which protocol each one is open for. Any other edge type that lands on an occupied pair replaces the earlier edge's attributes, which is what NetworkX does by default. Count edges in the `NetworkEdge` list, not in the graph, when you need the collector's numbers.

`NetworkEdge.ports` and `properties` are not copied onto the graph. Every edge attribute is a string (`""` when unset), which keeps the graph GraphML-safe.

## Examples

### Build, search and export a small estate

The script builds eight assets and eleven edges by hand, so it runs offline. It also groups the nodes into communities with python-louvain, which cloudg installs; the [RAG exporter](ragexporter.md) runs the same `best_partition` call for its community chunks.

```python title="build_graph.py"
--8<-- "graph/build_graph.py"
```

Output with cloudg 0.6.0 and python-louvain 0.16:

```console
$ python build_graph.py
9 nodes, 10 edges from 11 NetworkEdges
merged rule: 443,80 | HTTPS from anywhere; HTTP redirect
placeholder: EXTERNAL True
internet path: 0.0.0.0/0 -> sg-alb -> sg-web
identity path: web-1 -> app-role -> orders-db
lateral path: web-1 -> app-role
betweenness 0.080  web-1
betweenness 0.071  web-tg
betweenness 0.054  app-role
community 0: ['0.0.0.0/0', 'sg-alb']
community 1: ['sg-web', 'web-2']
community 2: ['app-role', 'orders-db', 'web-1']
community 3: ['web-alb', 'web-tg']
wrote ['estate-cytoscape.json', 'estate-d3.json', 'estate.graphml']
```

Eight assets plus the `0.0.0.0/0` placeholder make nine nodes, and the two rules into `sg-alb` became one edge. There is no internet path to `web-1` here even though the load balancer targets it: `alb -> sg-alb` is an `ATTACHED_TO` edge pointing from the resource to its group, and `find_attack_paths` walks edges only in the direction they are stored. The [reachability analysis](reachabilityanalyzer.md) knows which way traffic actually moves; walk `network_flow_graph(graph)` instead when you want flow-aware paths.

Leave out `random_state` and Louvain may number and split the communities differently from one run to the next.

### Graph a saved inventory map

`cloudg map` already writes `inventory-map.graphml`, but you can rebuild the graph from `inventory-map.json` to filter it first. `InventoryResult.load()` accepts the file or the directory holding it.

```python title="graph_from_map.py"
from cloudg.graph.builder import GraphBuilder
from cloudg.inventory import InventoryResult

result = InventoryResult.load("./reports")
aws_eu = [a for a in result.assets if a.region.startswith("eu-")]
keep = {a.id for a in aws_eu}
edges = [e for e in result.edges if e.source_id in keep or e.target_id in keep]

builder = GraphBuilder()
graph = builder.build(aws_eu, edges)
builder.save_graphml("./reports/eu-only.graphml")
print(graph.number_of_nodes(), "nodes,", graph.number_of_edges(), "edges")
```

Edges whose other end lies outside the filter bring that end back as an `EXTERNAL` placeholder, because `build()` adds a node for every endpoint it sees.

## Notes

- `build()` clears the graph first, so one builder can be reused, but `builder.graph` always holds the last build.
- Past `max_nodes_warn` assets (default 10,000) `build()` logs a warning about memory. `cloudg run` and `CloudGEngine` pass `graph.max_nodes_warn` from `config.yaml`; `GraphBuilder(max_nodes_warn=0)` turns the warning off.
- `find_attack_paths()` runs `nx.all_simple_paths` with a `cutoff` of `max_depth` (default 10). On a large, dense graph the number of simple paths explodes; pick specific endpoints and keep the depth low. An unknown node id gives `[]`, not an exception.
- `find_lateral_movement_paths()` collects paths of at most 8 hops from every node with `is_internet_exposed` or `is_external` set to the target of each `IAM_TRUST` edge, over every edge type, and stops after about 100 paths. Every placeholder counts as a starting point, private CIDRs included. `cloudg run` calls it when `graph.compute_attack_paths` is on and prints only the count.
- `compute_centrality()` returns normalised degree, in-degree, out-degree and betweenness per node. Betweenness is exact (`nx.betweenness_centrality`), so it is slow on graphs of tens of thousands of nodes.
- `subgraph(node_ids)` returns an independent copy, so changes to it do not touch `builder.graph`.
- `save_graphml()` creates missing parent directories and writes with `nx.write_graphml_xml` through `graphml_safe()`, a copy of the graph without `None` attributes and with lists and dicts stored as JSON strings. `builder.graph` itself is not changed. `load_graphml()` reads back through `nx.read_graphml`, which returns a `DiGraph` with string attributes; booleans such as `is_internet_exposed` come back as Python booleans because GraphML stores their type.
- The D3 export (`to_d3_json`, `to_json_str`) has `nodes` and `links`. Cytoscape's has `elements.nodes` and `elements.edges` with a smaller attribute set (no ARN or CIDR). The field reference for the D3 form is [inventory-graph.json](../reference/inventory/inventory-graph-json.md).

## Reference

::: cloudg.graph.builder.GraphBuilder
    options:
      members:
        - build
        - graph
        - find_attack_paths
        - find_lateral_movement_paths
        - compute_centrality
        - subgraph
        - to_d3_json
        - to_cytoscape_json
        - to_json_str
        - save_graphml
        - load_graphml

## Related

<div class="grid cards link-cards" markdown>

-   [**ReachabilityAnalyzer**](reachabilityanalyzer.md)

    Internet exposure, flow-aware walks and blast radius over this graph.

-   [**CloudOntology**](cloudontology.md)

    The same assets and edges as RDF triples.

-   [**RAGExporter**](ragexporter.md)

    Chunks built from the graph's communities.

-   [**Graph, ontology and RAG**](../guides/graph-ontology-rag.md)

    How the three analyses fit together.

-   [**inventory-map.graphml**](../reference/inventory/inventory-map-graphml.md)

    Node and edge attributes, field by field.

</div>
