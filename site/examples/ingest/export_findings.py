import json
from pathlib import Path

from cloudg.ingest import ingest_reports

findings = ingest_reports(
    {
        "prowler": ["./prowler-output/"],
        "checkov": ["./results_json.json"],
        "trivy": ["./trivy.json"],
    }
)
out = Path("./reports/raw-findings.json")
out.parent.mkdir(parents=True, exist_ok=True)
out.write_text(json.dumps([f.model_dump(mode="json") for f in findings], indent=2))
print(f"wrote {len(findings)} findings to {out}")
