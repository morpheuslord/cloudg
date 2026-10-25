from cloudg import InventoryResult

inventory = InventoryResult.load("./inventory")
summary = inventory.summary

print(f"{summary['internet_exposed']} of {summary['total_assets']} assets face the internet")
for asset in inventory.assets:
    if asset.is_internet_exposed:
        print(f"  {asset.asset_type.value:16} {asset.account_id or '-':14} {asset.display_id}")

print("unresolved references:", summary["unresolved_references"])
for ref in inventory.unresolved_references[:10]:
    print(f"  {ref['source_name']} -> {ref['target']} ({ref['edge_type']})")
