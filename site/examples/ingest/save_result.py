import json
import sys
from pathlib import Path

from cloudg import CloudGConfig, CloudGEngine

result = CloudGEngine(CloudGConfig()).run_from_reports_sync(
    {"checkov": ["./results_json.json"], "trivy": ["./trivy.json"]},
    output_dir="./reports",
)

# Headline numbers: plain JSON types only, safe to json.dumps
summary = result.to_summary()
print(json.dumps(summary, indent=2))

# Everything else: dump the pydantic models and stringify the paths yourself
payload = {
    "summary": summary,
    "findings": [f.model_dump(mode="json") for f in result.findings],
    "compliance": [c.model_dump(mode="json") for c in result.scan_result.compliance]
    if result.scan_result
    else [],
    "report_paths": {kind: str(path) for kind, path in result.report_paths.items()},
}
Path("./reports/run-summary.json").write_text(json.dumps(payload, indent=2))

breakdown = result.severity_breakdown            # only severities that occur
blocking = breakdown.get("CRITICAL", 0) + breakdown.get("HIGH", 0)
if blocking:
    print(f"{blocking} critical/high findings, failing the build", file=sys.stderr)
    sys.exit(1)
