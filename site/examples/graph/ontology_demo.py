"""Build the RDF ontology for a small estate, save it and query it with SPARQL."""

from pathlib import Path

from rdflib import Graph

from cloudg.graph.ontology import CloudOntology, RelationGroup
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
KEY_ARN = f"arn:aws:kms:{REGION}:{ACCOUNT}:key/1111aaaa-22bb-33cc-44dd-555555eeeeee"

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
          tags={"owner": "payments"}),
    asset("orders-key", AssetType.KMS_KEY, KEY_ARN),
    asset("orders-db", AssetType.RDS_INSTANCE, f"arn:aws:rds:{REGION}:{ACCOUNT}:db:orders-db",
          metadata={"storage_encrypted": True, "kms_key_id": KEY_ARN}),
]

edges = [
    NetworkEdge(source_id="0.0.0.0/0", target_id="sg-web", edge_type=EdgeType.SECURITY_GROUP_RULE,
                port_range="22", protocol="TCP", cidr="0.0.0.0/0", direction="ingress"),
    NetworkEdge(source_id="web-1", target_id="sg-web", edge_type=EdgeType.ATTACHED_TO),
]

# A scanner finding that names the database by ARN, not by asset id
findings = [
    Finding(
        resource_id=f"arn:aws:rds:{REGION}:{ACCOUNT}:db:orders-db",
        severity=Severity.HIGH,
        title="RDS instance has no deletion protection",
        description="Deletion protection is disabled.",
        source_tool="prowler",
        compliance_frameworks=["CIS"],
    )
]

onto = CloudOntology()
onto.build(assets, edges, findings)
stats = onto.stats()
print(stats["total_triples"], "triples,", stats["classes_used"], "classes,",
      stats["individuals"], "individuals")
print("groups:", dict(sorted(stats["relation_group_counts"].items())))

# The graph binds the cm:, cmr: and cmp: prefixes, so queries can use them
rows = onto.query("""
    SELECT ?subject ?relation ?object WHERE {
        ?s ?p ?o .
        FILTER(STRSTARTS(STR(?p), STR(cmp:)))
        FILTER(!STRSTARTS(STR(?p), STR(cmp:has)))
        FILTER(?p != cmp:isInternetExposed)
        ?s cmp:hasName ?subject .
        OPTIONAL { ?o cmp:hasName ?oname }
        BIND(STRAFTER(STR(?p), STR(cmp:)) AS ?relation)
        BIND(COALESCE(?oname, STR(?o)) AS ?object)
    } ORDER BY ?subject ?relation
""")
for row in rows:
    print(f"  {row['subject']} {row['relation']} {row['object']}")

print("internet reachable:", [r["name"] for r in onto.query_internet_exposed()])
print("security group:", len(onto.query_by_relation_group(RelationGroup.SECURITY)), "triples")
print("compliance gaps:", [(r["severity"], r["resourceName"]) for r in onto.query_compliance_gaps()])

out = Path("ontology-out")
for fmt, name in [("turtle", "ontology.ttl"), ("json-ld", "ontology.jsonld"),
                  ("xml", "ontology.rdf"), ("nt", "ontology.nt")]:
    onto.save(out / name, fmt=fmt)

# Any RDF tool can read the files back; here rdflib itself
reloaded = Graph().parse(out / "ontology.ttl", format="turtle")
print("reloaded", len(reloaded), "triples from", sorted(p.name for p in out.iterdir()))
