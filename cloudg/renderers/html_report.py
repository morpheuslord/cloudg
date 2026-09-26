"""HTML interactive report generator using Jinja2."""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader, select_autoescape

from cloudg.schema.models import ScanResult

logger = logging.getLogger(__name__)

# Template directory candidates — the packaged directory ships in the
# wheel, the rest keep old checkouts and Docker layouts working
_TEMPLATE_DIR_CANDIDATES = [
    Path(__file__).parent.parent / "templates",  # packaged: cloudg/templates
    Path(__file__).parent.parent.parent / "templates",  # legacy repo-root layout
    Path("/app/templates"),  # legacy Docker runtime
    Path("./templates"),  # CWD fallback
]


def _resolve_template_dir() -> Path:
    """Find the first template directory that contains report.html.j2."""
    for candidate in _TEMPLATE_DIR_CANDIDATES:
        if (candidate / "report.html.j2").exists():
            return candidate
    # Fall back to first candidate (will trigger fallback report)
    return _TEMPLATE_DIR_CANDIDATES[0]


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
        self._template_dir = Path(template_dir) if template_dir else _resolve_template_dir()
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
        severity_counts: dict[str, int] = {
            "CRITICAL": 0,
            "HIGH": 0,
            "MEDIUM": 0,
            "LOW": 0,
            "INFO": 0,
        }
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
            source_tools[finding.source_tool] = source_tools.get(finding.source_tool, 0) + 1

        # Compliance framework summary
        compliance_summary: dict[str, dict[str, int]] = {}
        for result in scan_result.compliance:
            if result.framework not in compliance_summary:
                compliance_summary[result.framework] = {"pass": 0, "fail": 0}
            if result.status.value == "PASS":
                compliance_summary[result.framework]["pass"] += 1
            else:
                compliance_summary[result.framework]["fail"] += 1

        # Findings per resource (for topology badges)
        findings_per_resource: dict[str, dict[str, int]] = {}
        for finding in scan_result.findings:
            rid = finding.resource_id or finding.resource_arn or ""
            if rid not in findings_per_resource:
                findings_per_resource[rid] = {
                    "total": 0,
                    "CRITICAL": 0,
                    "HIGH": 0,
                    "MEDIUM": 0,
                    "LOW": 0,
                    "INFO": 0,
                }
            findings_per_resource[rid]["total"] += 1
            findings_per_resource[rid][finding.severity.value] += 1

        # Build hierarchical topology data
        hierarchy = self._build_hierarchy(scan_result, findings_per_resource)

        # Enrich graph with findings as nodes + ontology edges
        enriched_graph = self._enrich_graph_with_findings(
            graph_json or {"nodes": [], "links": []},
            scan_result,
        )

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
            "graph_json": json.dumps(enriched_graph, default=str),
            "hierarchy_json": json.dumps(hierarchy, default=str),
            "findings_per_resource_json": json.dumps(findings_per_resource, default=str),
        }

    def _build_hierarchy(
        self,
        scan_result: ScanResult,
        findings_per_resource: dict[str, dict[str, int]],
    ) -> dict[str, Any]:
        """Build hierarchical tree: Account → Region → VPC → Subnet → Resources."""
        from collections import defaultdict

        # Group assets by region → VPC → subnet
        regions: dict[str, dict[str, dict[str, list[dict[str, Any]]]]] = defaultdict(
            lambda: defaultdict(lambda: defaultdict(list))
        )
        ungrouped: list[dict[str, Any]] = []

        for asset in scan_result.assets:
            asset_data = {
                "id": asset.id,
                "name": asset.name,
                "type": asset.asset_type.value,
                "arn": asset.arn or "",
                "internet_exposed": asset.is_internet_exposed,
                "findings": findings_per_resource.get(
                    asset.id, findings_per_resource.get(asset.arn or "", {})
                ),
            }
            region = asset.region or "global"
            vpc_id = asset.metadata.get("vpc_id", "")
            subnet_id = asset.metadata.get("subnet_id", "")

            if asset.asset_type.value in ("VPC", "VNET"):
                vpc_id = asset.metadata.get("vpc_id", asset.name)
                regions[region][vpc_id]["_vpc_meta"] = []  # type: ignore[assignment]
                regions[region][vpc_id]["_vpc_meta"].append(asset_data)
            elif asset.asset_type.value == "SUBNET":
                regions[region][vpc_id or "_no_vpc"][subnet_id or asset.name].append(asset_data)
            elif vpc_id or subnet_id:
                regions[region][vpc_id or "_no_vpc"][subnet_id or "_no_subnet"].append(asset_data)
            else:
                ungrouped.append(asset_data)

        # Build tree structure
        tree: dict[str, Any] = {
            "name": scan_result.account_id or "Cloud Account",
            "type": "account",
            "children": [],
        }
        for region_name, vpcs in sorted(regions.items()):
            region_node: dict[str, Any] = {"name": region_name, "type": "region", "children": []}
            for vpc_name, subnets in sorted(vpcs.items()):
                vpc_node: dict[str, Any] = {"name": vpc_name, "type": "vpc", "children": []}
                for subnet_name, resources in sorted(subnets.items()):
                    if subnet_name == "_vpc_meta":
                        continue
                    subnet_node: dict[str, Any] = {
                        "name": subnet_name,
                        "type": "subnet",
                        "children": resources,
                    }
                    vpc_node["children"].append(subnet_node)
                region_node["children"].append(vpc_node)
            tree["children"].append(region_node)

        if ungrouped:
            tree["children"].append(
                {"name": "Global / Ungrouped", "type": "global", "children": ungrouped}
            )

        return tree

    def _enrich_graph_with_findings(
        self,
        graph: dict[str, Any],
        scan_result: ScanResult,
    ) -> dict[str, Any]:
        """Inject findings + compliance frameworks as visible nodes in the D3 graph.

        - Each finding becomes a SecurityFinding node linked to its resource via FINDING_AFFECTS
        - Each compliance framework becomes a ComplianceFramework node linked via COMPLIANCE_GOVERNS
        """
        nodes = list(graph.get("nodes", []))
        links = list(graph.get("links", []))
        existing_ids = {n.get("id") for n in nodes}

        # Map resource ARNs → node IDs for connecting findings
        arn_to_node_id: dict[str, str] = {}
        for n in nodes:
            if n.get("arn"):
                arn_to_node_id[n["arn"]] = n["id"]
            arn_to_node_id[n.get("id", "")] = n["id"]

        # Track compliance frameworks for dedup
        fw_nodes_added: set[str] = set()

        for finding in scan_result.findings:
            finding_id = f"finding_{finding.id}"
            if finding_id in existing_ids:
                continue

            # Finding node
            nodes.append(
                {
                    "id": finding_id,
                    "name": (finding.title or "")[:60],
                    "type": "SECURITY_FINDING",
                    "severity": finding.severity.value,
                    "source_tool": finding.source_tool,
                    "risk_score": finding.risk_score,
                    "is_external": False,
                    "is_internet_exposed": False,
                    "region": "",
                    "arn": "",
                }
            )
            existing_ids.add(finding_id)

            # FINDING_AFFECTS edge → resource
            target_id = arn_to_node_id.get(finding.resource_arn or "") or arn_to_node_id.get(
                finding.resource_id or ""
            )
            if target_id:
                links.append(
                    {
                        "source": finding_id,
                        "target": target_id,
                        "relation": "FINDING_AFFECTS",
                        "severity": finding.severity.value,
                    }
                )

            # Compliance framework nodes + COMPLIANCE_GOVERNS edges
            for fw in finding.compliance_frameworks or []:
                fw_id = f"compliance_{fw}"
                if fw_id not in fw_nodes_added:
                    nodes.append(
                        {
                            "id": fw_id,
                            "name": fw,
                            "type": "COMPLIANCE_FRAMEWORK",
                            "severity": "",
                            "source_tool": "",
                            "risk_score": 0,
                            "is_external": False,
                            "is_internet_exposed": False,
                            "region": "",
                            "arn": "",
                        }
                    )
                    fw_nodes_added.add(fw_id)
                    existing_ids.add(fw_id)

                # COMPLIANCE_GOVERNS → finding
                links.append(
                    {
                        "source": fw_id,
                        "target": finding_id,
                        "relation": "COMPLIANCE_GOVERNS",
                    }
                )

        return {"nodes": nodes, "links": links}

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
                    <td>{f.get("title", "")}</td>
                    <td><code>{f.get("resource_arn", f.get("resource_id", ""))}</code></td>
                    <td>{f.get("source_tool", "")}</td>
                    <td>{f.get("remediation", "")[:100]}</td>
                </tr>"""

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>CloudG Security Report</title>
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
    <h1>☁️ CloudG Security Report</h1>
    <p class="subtitle">Scan ID: {data["scan_id"]} | Provider: {data["provider"]} | Account: {data["account_id"]}</p>

    <div class="cards">
        <div class="card"><h3>Total Assets</h3><div class="value">{data["total_assets"]}</div></div>
        <div class="card"><h3>Total Findings</h3><div class="value">{data["total_findings"]}</div></div>
        <div class="card critical"><h3>Critical</h3><div class="value">{data["severity_counts"].get("CRITICAL", 0)}</div></div>
        <div class="card high"><h3>High</h3><div class="value">{data["severity_counts"].get("HIGH", 0)}</div></div>
        <div class="card medium"><h3>Medium</h3><div class="value">{data["severity_counts"].get("MEDIUM", 0)}</div></div>
    </div>

    <h2>Security Findings</h2>
    <table>
        <thead><tr><th>Severity</th><th>Title</th><th>Resource</th><th>Source</th><th>Remediation</th></tr></thead>
        <tbody>{findings_rows}</tbody>
    </table>
</div>
</body>
</html>"""
