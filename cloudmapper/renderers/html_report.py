"""HTML interactive report generator using Jinja2."""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader, select_autoescape

from cloudmapper.schema.models import ScanResult

logger = logging.getLogger(__name__)

# Fallback template directory
_TEMPLATE_DIR = Path(__file__).parent.parent.parent / "templates"


class HTMLReportGenerator:
    """Generates a self-contained interactive HTML report.

    Features:
    - D3.js force-directed topology map
    - Filterable findings table
    - Chart.js severity and resource charts
    - Compliance scorecard
    - Per-finding detail panels
    """

    def __init__(
        self,
        template_dir: str | None = None,
        output_dir: str = ".",
    ) -> None:
        self._template_dir = Path(template_dir) if template_dir else _TEMPLATE_DIR
        self._output_dir = Path(output_dir)

    def generate(
        self,
        scan_result: ScanResult,
        graph_json: dict[str, Any] | None = None,
        filename: str = "report.html",
    ) -> Path:
        """Generate the HTML report.

        Args:
            scan_result: Normalised scan results.
            graph_json: D3.js graph data for topology visualisation.
            filename: Output filename.

        Returns:
            Path to the generated HTML file.
        """
        self._output_dir.mkdir(parents=True, exist_ok=True)
        output_path = self._output_dir / filename

        # Prepare template data
        template_data = self._prepare_data(scan_result, graph_json)

        # Render template
        if self._template_dir.exists():
            env = Environment(
                loader=FileSystemLoader(str(self._template_dir)),
                autoescape=select_autoescape(["html"]),
            )
            try:
                template = env.get_template("report.html.j2")
                html = template.render(**template_data)
            except Exception as exc:
                logger.warning("Template rendering failed, using fallback: %s", exc)
                html = self._fallback_report(template_data)
        else:
            logger.warning("Template directory not found, using fallback report")
            html = self._fallback_report(template_data)

        with open(output_path, "w") as f:
            f.write(html)

        logger.info("Generated HTML report at %s", output_path)
        return output_path

    def _prepare_data(
        self,
        scan_result: ScanResult,
        graph_json: dict[str, Any] | None,
    ) -> dict[str, Any]:
        """Prepare data for template rendering."""
        # Severity breakdown
        severity_counts: dict[str, int] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for finding in scan_result.findings:
            severity_counts[finding.severity.value] = (
                severity_counts.get(finding.severity.value, 0) + 1
            )

        # Resource type breakdown
        resource_types: dict[str, int] = {}
        for asset in scan_result.assets:
            resource_types[asset.asset_type.value] = (
                resource_types.get(asset.asset_type.value, 0) + 1
            )

        # Source tool breakdown
        source_tools: dict[str, int] = {}
        for finding in scan_result.findings:
            source_tools[finding.source_tool] = (
                source_tools.get(finding.source_tool, 0) + 1
            )

        # Compliance framework summary
        compliance_summary: dict[str, dict[str, int]] = {}
        for result in scan_result.compliance:
            if result.framework not in compliance_summary:
                compliance_summary[result.framework] = {"pass": 0, "fail": 0}
            if result.status.value == "PASS":
                compliance_summary[result.framework]["pass"] += 1
            else:
                compliance_summary[result.framework]["fail"] += 1

        return {
            "scan_id": scan_result.scan_id,
            "provider": scan_result.provider.value if scan_result.provider else "Multi-Cloud",
            "account_id": scan_result.account_id or "N/A",
            "started_at": str(scan_result.started_at),
            "completed_at": str(scan_result.completed_at),
            "total_assets": len(scan_result.assets),
            "total_findings": len(scan_result.findings),
            "severity_counts": severity_counts,
            "severity_counts_json": json.dumps(severity_counts),
            "resource_types": resource_types,
            "resource_types_json": json.dumps(resource_types),
            "source_tools": source_tools,
            "source_tools_json": json.dumps(source_tools),
            "compliance_summary": compliance_summary,
            "compliance_summary_json": json.dumps(compliance_summary),
            "findings": [f.model_dump(mode="json") for f in scan_result.findings],
            "findings_json": json.dumps(
                [f.model_dump(mode="json") for f in scan_result.findings],
                default=str,
            ),
            "assets": [a.model_dump(exclude={"raw_data"}, mode="json") for a in scan_result.assets],
            "assets_json": json.dumps(
                [a.model_dump(exclude={"raw_data"}, mode="json") for a in scan_result.assets],
                default=str,
            ),
            "graph_json": json.dumps(graph_json or {"nodes": [], "links": []}, default=str),
        }

    def _fallback_report(self, data: dict[str, Any]) -> str:
        """Generate a simple fallback HTML report if Jinja2 template is missing."""
        findings_rows = ""
        for f in data["findings"]:
            sev = f.get("severity", "INFO")
            sev_class = {
                "CRITICAL": "color:#E74C3C;font-weight:bold",
                "HIGH": "color:#E67E22;font-weight:bold",
                "MEDIUM": "color:#F1C40F",
                "LOW": "color:#3498DB",
                "INFO": "color:#95A5A6",
            }.get(sev, "")
            findings_rows += f"""
                <tr>
                    <td style="{sev_class}">{sev}</td>
                    <td>{f.get('title', '')}</td>
                    <td><code>{f.get('resource_arn', f.get('resource_id', ''))}</code></td>
                    <td>{f.get('source_tool', '')}</td>
                    <td>{f.get('remediation', '')[:100]}</td>
                </tr>"""

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>CloudMapper Security Report</title>
<style>
    * {{ margin: 0; padding: 0; box-sizing: border-box; }}
    body {{ font-family: 'Inter', -apple-system, sans-serif; background: #0F172A; color: #E2E8F0; }}
    .container {{ max-width: 1400px; margin: 0 auto; padding: 20px; }}
    h1 {{ color: #F8FAFC; margin-bottom: 8px; font-size: 28px; }}
    .subtitle {{ color: #94A3B8; margin-bottom: 30px; }}
    .cards {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 16px; margin-bottom: 30px; }}
    .card {{
        background: #1E293B; border-radius: 12px; padding: 20px;
        border: 1px solid #334155;
    }}
    .card h3 {{ color: #94A3B8; font-size: 12px; text-transform: uppercase; letter-spacing: 1px; }}
    .card .value {{ font-size: 36px; font-weight: 700; color: #F8FAFC; margin-top: 8px; }}
    .card.critical .value {{ color: #EF4444; }}
    .card.high .value {{ color: #F97316; }}
    .card.medium .value {{ color: #EAB308; }}
    table {{
        width: 100%; border-collapse: collapse; background: #1E293B;
        border-radius: 12px; overflow: hidden; margin-top: 20px;
    }}
    th {{ background: #334155; color: #94A3B8; padding: 12px 16px; text-align: left; font-size: 12px; text-transform: uppercase; letter-spacing: 1px; }}
    td {{ padding: 12px 16px; border-bottom: 1px solid #334155; font-size: 14px; }}
    tr:hover {{ background: #334155; }}
    code {{ background: #334155; padding: 2px 6px; border-radius: 4px; font-size: 12px; }}
    h2 {{ color: #F8FAFC; margin: 30px 0 10px; }}
</style>
</head>
<body>
<div class="container">
    <h1>☁️ CloudMapper Security Report</h1>
    <p class="subtitle">Scan ID: {data['scan_id']} | Provider: {data['provider']} | Account: {data['account_id']}</p>

    <div class="cards">
        <div class="card"><h3>Total Assets</h3><div class="value">{data['total_assets']}</div></div>
        <div class="card"><h3>Total Findings</h3><div class="value">{data['total_findings']}</div></div>
        <div class="card critical"><h3>Critical</h3><div class="value">{data['severity_counts'].get('CRITICAL', 0)}</div></div>
        <div class="card high"><h3>High</h3><div class="value">{data['severity_counts'].get('HIGH', 0)}</div></div>
        <div class="card medium"><h3>Medium</h3><div class="value">{data['severity_counts'].get('MEDIUM', 0)}</div></div>
    </div>

    <h2>Security Findings</h2>
    <table>
        <thead><tr><th>Severity</th><th>Title</th><th>Resource</th><th>Source</th><th>Remediation</th></tr></thead>
        <tbody>{findings_rows}</tbody>
    </table>
</div>
</body>
</html>"""
