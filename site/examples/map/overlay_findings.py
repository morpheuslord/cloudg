from cloudg import CloudGConfig, InventoryMapper, InventoryResult
from cloudg.ingest import ingest_reports
from cloudg.normaliser import FindingsNormaliser

# A map written earlier by `cloudg map -o ./inventory` or InventoryResult.export()
inventory = InventoryResult.load("./inventory")

# Scanner output that arrived later, normalised so compliance mapping is filled in
raw = ingest_reports({"prowler": ["./prowler-output/"], "trivy": ["./trivy.json"]})
findings = FindingsNormaliser().normalise(raw).findings

mapper = InventoryMapper(CloudGConfig(providers=["aws"]))
paths = mapper.export_merged(inventory, findings, "./inventory")
print({name: str(path) for name, path in paths.items()})

compliance = mapper.build_compliance_map(inventory, findings)
for framework, entry in list(compliance["frameworks"].items())[:3]:
    print(framework, entry["findings"], entry["affected_assets"])

asset_map = mapper.build_asset_map(inventory, findings)
print(asset_map["total_assets"], "assets,", asset_map["assets_with_findings"], "with findings")
