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
