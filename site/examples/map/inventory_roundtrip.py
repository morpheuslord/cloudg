from cloudg import InventoryResult
from cloudg.inventory import RelationshipLinker
from cloudg.schema.models import AssetType, CloudAsset, CloudProvider

ACCOUNT = "123456789012"
REGION = "eu-west-1"
KEY = f"arn:aws:kms:{REGION}:{ACCOUNT}:key/1111aaaa-22bb-33cc-44dd-555555eeeeee"
QUEUE = f"arn:aws:sqs:{REGION}:{ACCOUNT}:orders-inbound"
TABLE = f"arn:aws:dynamodb:{REGION}:{ACCOUNT}:table/orders"
FUNCTION = f"arn:aws:lambda:{REGION}:{ACCOUNT}:function:orders-worker"

def aws(arn, name, asset_type, **metadata):
    return CloudAsset(arn=arn, name=name, asset_type=asset_type, provider=CloudProvider.AWS,
                      region=REGION, account_id=ACCOUNT, metadata=metadata)

assets = [
    aws(KEY, "orders-key", AssetType.KMS_KEY),
    aws(QUEUE, "orders-inbound", AssetType.MESSAGE_QUEUE, kms_key_id=KEY),
    aws(TABLE, "orders", AssetType.DYNAMODB_TABLE, kms_key_id=KEY),
    aws(FUNCTION, "orders-worker", AssetType.LAMBDA_FUNCTION, kms_key_id=KEY, relations=[
        {"target": QUEUE, "edge": "INVOKES", "relationship": "TRIGGERED_BY", "reverse": True},
        {"target": TABLE, "edge": "REFERENCES", "relationship": "WRITES_TO"},
        {"target": "arn:aws:iam::999999999999:role/partner-reader", "edge": "ASSUMES_ROLE"},
    ]),
]

linker = RelationshipLinker(assets)
edges = linker.link()
inventory = InventoryResult(
    assets=assets + linker.external_assets,
    edges=edges,
    providers=["aws"],
    regions={"aws": [REGION]},
    unresolved_references=linker.unresolved,
)

paths = inventory.export("./inventory")
print(sorted(paths))

again = InventoryResult.load("./inventory")      # the directory or inventory-map.json
s = again.summary
print(s["total_assets"], s["total_edges"], s["edges_by_type"])
print("external accounts:", s["external_accounts"], "cross-account edges:", s["cross_account_edges"])

analysis = again.analysis(top=5)
print(list(analysis))
print([(d["name"], d["direct_dependents"]) for d in analysis["shared_dependencies"]])
print(analysis["cross_account_edges"])
