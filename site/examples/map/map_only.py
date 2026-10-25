from cloudg import CloudGConfig, CloudGEngine

config = CloudGConfig(providers=["aws"])
config.aws.regions = ["ALL"]
config.inventory.exclude_services = ["kubernetes"]

engine = CloudGEngine(config)
inventory = engine.map_inventory_sync(output_dir="./inventory", tagging_sweep=False)

summary = inventory.summary
print(summary["total_assets"], "assets,", summary["total_edges"], "edges")
print("internet exposed:", summary["internet_exposed"])
print("top services:", list(summary["assets_by_service"].items())[:5])
