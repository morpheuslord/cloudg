import logging

from cloudg.ingest import SUPPORTED_TOOLS, ingest_reports, parse_report
from cloudg.normaliser import FindingsNormaliser

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")

print(SUPPORTED_TOOLS)
findings = parse_report("prowler", "./prowler-output/")
findings += parse_report("checkov", "./results_json.json")
print(len(findings), "findings from two reports")

# A typo'd tool name or a missing path is skipped by ingest_reports, not raised
more = ingest_reports({"trivy": ["./trivy.json", "./missing.json"], "trivvy": ["./trivy.json"]})
print(len(more), "findings from the batch")

try:
    parse_report("grype", "./trivy.json")
except ValueError as exc:
    print("ValueError:", exc)

scan_result = FindingsNormaliser().normalise(findings, more)
print(scan_result.summary["severity_breakdown"], len(scan_result.compliance), "control results")
