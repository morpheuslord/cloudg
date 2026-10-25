from cloudg import CloudGConfig, CloudGEngine

engine = CloudGEngine(CloudGConfig())
engine.on_phase_start = lambda phase: print("phase:", phase)

result = engine.run_from_reports_sync(
    {
        "prowler": ["./prowler-output/"],
        "checkov": ["./results_json.json"],
        "trivy": ["./trivy.json"],
    },
    output_dir="./reports",
)

print(result.total_findings, result.severity_breakdown)
print(result.report_paths)
for f in result.findings:
    print(f.severity.value, f.risk_score, f.source_tool, f.title)
