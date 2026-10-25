"""Export RAG chunks for a small estate and reshape them for a vector store."""

import json
from pathlib import Path

from cloudg.graph.builder import GraphBuilder
from cloudg.graph.rag_export import RAGExporter
from cloudg.schema.models import (
    AssetType,
    CloudAsset,
    CloudProvider,
    EdgeType,
    Finding,
    NetworkEdge,
    Severity,
)

ACCOUNT = "123456789012"
REGION = "eu-west-1"

def asset(asset_id: str, asset_type: AssetType, arn: str, **extra) -> CloudAsset:
    return CloudAsset(
        id=asset_id,
        name=asset_id,
        asset_type=asset_type,
        provider=CloudProvider.AWS,
        region=REGION,
        account_id=ACCOUNT,
        arn=arn,
        **extra,
    )

assets = [
    asset("sg-web", AssetType.SECURITY_GROUP, f"arn:aws:ec2:{REGION}:{ACCOUNT}:security-group/sg-web"),
    asset("web-1", AssetType.EC2, f"arn:aws:ec2:{REGION}:{ACCOUNT}:instance/i-0web1",
          is_internet_exposed=True),
    asset("web-2", AssetType.EC2, f"arn:aws:ec2:{REGION}:{ACCOUNT}:instance/i-0web2"),
    asset("app-role", AssetType.IAM_ROLE, f"arn:aws:iam::{ACCOUNT}:role/app-role"),
    asset("orders-db", AssetType.RDS_INSTANCE, f"arn:aws:rds:{REGION}:{ACCOUNT}:db:orders-db"),
]
edges = [
    NetworkEdge(source_id="0.0.0.0/0", target_id="sg-web", edge_type=EdgeType.SECURITY_GROUP_RULE,
                port_range="443", protocol="TCP", cidr="0.0.0.0/0", direction="ingress"),
    NetworkEdge(source_id="web-1", target_id="sg-web", edge_type=EdgeType.ATTACHED_TO),
    NetworkEdge(source_id="web-2", target_id="sg-web", edge_type=EdgeType.ATTACHED_TO),
    NetworkEdge(source_id="web-1", target_id="app-role", edge_type=EdgeType.ASSUMES_ROLE),
    NetworkEdge(source_id="app-role", target_id="orders-db", edge_type=EdgeType.GRANTS_ACCESS),
]
findings = [
    Finding(
        resource_id="web-1",
        severity=Severity.HIGH,
        title="Instance metadata service v1 enabled",
        description="IMDSv2 is not enforced.",
        source_tool="prowler",
        compliance_frameworks=["CIS"],
    )
]

graph = GraphBuilder().build(assets, edges)
paths = RAGExporter().export_all(assets, edges, graph, findings, output_dir="rag-out")
print({kind: path.name for kind, path in paths.items()})

index = json.loads(paths["index"].read_text())
print({k: v for k, v in index.items() if k.endswith("chunks")})

chunks = [json.loads(line) for line in paths["chunks"].read_text().splitlines()]

# The content uses a few symbols; plain words embed and display more reliably
MARKERS = {
    "\N{WARNING SIGN}": "WARNING:",
    "\N{RIGHTWARDS ARROW}": "->",
    "\N{LEFTWARDS ARROW}": "<-",
    "\N{BULLET}": "-",
}

def clean(text: str) -> str:
    for symbol, word in MARKERS.items():
        text = text.replace(symbol, word)
    return text

def scalar(value):
    """Most vector stores accept only str, int, float and bool metadata."""
    if isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, list):
        return ",".join(map(str, value))
    return json.dumps(value, sort_keys=True)

records = [
    {
        "id": c["chunk_id"],
        "text": clean(c["content"]),
        "metadata": {"chunk_type": c["chunk_type"],
                     **{k: scalar(v) for k, v in c["metadata"].items()}},
    }
    for c in chunks
]
out = Path("rag-out") / "vector-records.jsonl"
out.write_text("".join(json.dumps(r) + "\n" for r in records))
print(len(records), "records ->", out)

web_1 = next(r for r in records if r["id"] == "entity::web-1")
print(web_1["text"])
print(web_1["metadata"])

# Pre-filter on metadata before any similarity search
urgent = [r["id"] for r in records if r["metadata"].get("severity_max") in ("CRITICAL", "HIGH")]
print("high or critical:", urgent)
