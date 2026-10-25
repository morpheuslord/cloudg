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
print("orders-worker needs:", [graph.assets[link.asset_id].name for link in graph.depends_on(worker.id)])
print("direct (needs, needed by):", graph.direct_counts(worker.id))

for row in graph.blast_radius(top=3):
    print(f"{row['name']:20} {row['transitive_dependents']} dependents, "
          f"{row['internet_exposed_dependents']} internet-exposed")
