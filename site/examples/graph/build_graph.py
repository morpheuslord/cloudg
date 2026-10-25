"""Build a graph from a hand-made estate and look at it from a few angles."""

import json
from pathlib import Path

import community as community_louvain  # python-louvain, a cloudg dependency

from cloudg.graph.builder import GraphBuilder
from cloudg.schema.models import AssetType, CloudAsset, CloudProvider, EdgeType, NetworkEdge

ACCOUNT = "123456789012"

def asset(asset_id: str, name: str, asset_type: AssetType, arn_suffix: str, **extra) -> CloudAsset:
    return CloudAsset(
        id=asset_id,
        name=name,
        asset_type=asset_type,
        provider=CloudProvider.AWS,
        region="eu-west-1",
        account_id=ACCOUNT,
        arn=f"arn:aws:{arn_suffix}",
        **extra,
    )

assets = [
    asset("sg-alb", "sg-alb", AssetType.SECURITY_GROUP, f"ec2:eu-west-1:{ACCOUNT}:security-group/sg-alb"),
    asset("sg-web", "sg-web", AssetType.SECURITY_GROUP, f"ec2:eu-west-1:{ACCOUNT}:security-group/sg-web"),
    asset("alb", "web-alb", AssetType.LOAD_BALANCER, f"elasticloadbalancing:eu-west-1:{ACCOUNT}:loadbalancer/app/web-alb/1"),
    asset("tg", "web-tg", AssetType.TARGET_GROUP, f"elasticloadbalancing:eu-west-1:{ACCOUNT}:targetgroup/web-tg/1"),
    asset("web-1", "web-1", AssetType.EC2, f"ec2:eu-west-1:{ACCOUNT}:instance/i-0web1", is_internet_exposed=True),
    asset("web-2", "web-2", AssetType.EC2, f"ec2:eu-west-1:{ACCOUNT}:instance/i-0web2"),
    asset("app-role", "app-role", AssetType.IAM_ROLE, f"iam::{ACCOUNT}:role/app-role"),
    asset("orders-db", "orders-db", AssetType.RDS_INSTANCE, f"rds:eu-west-1:{ACCOUNT}:db:orders-db"),
]

def rule(source: str, target: str, port: str, cidr: str = "", description: str = "") -> NetworkEdge:
    return NetworkEdge(
        source_id=source,
        target_id=target,
        edge_type=EdgeType.SECURITY_GROUP_RULE,
        port_range=port,
        protocol="TCP",
        cidr=cidr or None,
        direction="ingress",
        description=description or None,
    )

edges = [
    # Two rules on the same pair: GraphBuilder merges them into one edge
    rule("0.0.0.0/0", "sg-alb", "443", "0.0.0.0/0", "HTTPS from anywhere"),
    rule("0.0.0.0/0", "sg-alb", "80", "0.0.0.0/0", "HTTP redirect"),
    rule("sg-alb", "sg-web", "8080", description="ALB to web tier"),
    NetworkEdge(source_id="alb", target_id="sg-alb", edge_type=EdgeType.ATTACHED_TO, relationship="PROTECTED_BY_SG"),
    NetworkEdge(source_id="web-1", target_id="sg-web", edge_type=EdgeType.ATTACHED_TO, relationship="PROTECTED_BY_SG"),
    NetworkEdge(source_id="web-2", target_id="sg-web", edge_type=EdgeType.ATTACHED_TO, relationship="PROTECTED_BY_SG"),
    NetworkEdge(source_id="alb", target_id="tg", edge_type=EdgeType.LOAD_BALANCER_TARGET),
    NetworkEdge(source_id="tg", target_id="web-1", edge_type=EdgeType.LOAD_BALANCER_TARGET),
    NetworkEdge(source_id="tg", target_id="web-2", edge_type=EdgeType.LOAD_BALANCER_TARGET),
    NetworkEdge(source_id="web-1", target_id="app-role", edge_type=EdgeType.IAM_TRUST),
    NetworkEdge(source_id="app-role", target_id="orders-db", edge_type=EdgeType.GRANTS_ACCESS),
]

builder = GraphBuilder()
graph = builder.build(assets, edges)
print(f"{graph.number_of_nodes()} nodes, {graph.number_of_edges()} edges from {len(edges)} NetworkEdges")

merged = graph.edges["0.0.0.0/0", "sg-alb"]
print("merged rule:", merged["port_range"], "|", merged["description"])
print("placeholder:", graph.nodes["0.0.0.0/0"]["asset_type"], graph.nodes["0.0.0.0/0"]["is_external"])

def names(path: list[str]) -> str:
    return " -> ".join(graph.nodes[n]["name"] for n in path)

# Paths follow edges in their stored direction
for path in builder.find_attack_paths("0.0.0.0/0", "sg-web"):
    print("internet path:", names(path))
for path in builder.find_attack_paths("web-1", "orders-db"):
    print("identity path:", names(path))
for path in builder.find_lateral_movement_paths():
    print("lateral path:", names(path))

centrality = builder.compute_centrality()
top = sorted(centrality.items(), key=lambda kv: kv[1]["betweenness"], reverse=True)[:3]
for node_id, scores in top:
    print(f"betweenness {scores['betweenness']:.3f}  {graph.nodes[node_id]['name']}")

# Louvain works on undirected graphs; the RAG exporter does the same
partition = community_louvain.best_partition(graph.to_undirected(), random_state=42)
groups: dict[int, list[str]] = {}
for node_id, community_id in partition.items():
    groups.setdefault(community_id, []).append(graph.nodes[node_id]["name"])
for community_id, members in sorted(groups.items()):
    print(f"community {community_id}: {sorted(members)}")

out = Path("graph-out")
builder.save_graphml(out / "estate.graphml")
(out / "estate-d3.json").write_text(builder.to_json_str())
(out / "estate-cytoscape.json").write_text(json.dumps(builder.to_cytoscape_json(), indent=2))
print("wrote", sorted(p.name for p in out.iterdir()))
