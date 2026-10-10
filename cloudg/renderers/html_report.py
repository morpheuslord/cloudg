"""HTML interactive report generator using Jinja2."""

from __future__ import annotations

import json
import logging
from html import escape
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader

from cloudg.schema.models import ScanResult

logger = logging.getLogger(__name__)

# Template directory candidates: the packaged directory ships in the
# wheel, the rest keep old checkouts and Docker layouts working
_TEMPLATE_DIR_CANDIDATES = [
    Path(__file__).parent.parent / "templates",  # packaged: cloudg/templates
    Path(__file__).parent.parent.parent / "templates",  # legacy repo-root layout
    Path("/app/templates"),  # legacy Docker runtime
    Path("./templates"),  # CWD fallback
]


# JavaScript libraries the report uses. With inline_js (the default) the
# vendored copies in cloudg/templates/vendor are embedded in the page so it
# works offline; otherwise the page loads the same builds from the CDN,
# pinned and checked with Subresource Integrity. See vendor/NOTICE.
_VENDOR_DIR = Path(__file__).parent.parent / "templates" / "vendor"
VENDORED_LIBRARIES: dict[str, dict[str, str]] = {
    "chartjs": {
        "file": "chart.umd.js",
        "cdn": "https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.js",
        "integrity": "sha384-FcQlsUOd0TJjROrBxhJdUhXTUgNJQxTMcxZe6nHbaEfFL1zjQ+bq/uRoBQxb0KMo",
    },
    "d3": {
        "file": "d3.min.js",
        "cdn": "https://cdn.jsdelivr.net/npm/d3@7.9.0/dist/d3.min.js",
        "integrity": "sha384-CjloA8y00+1SDAUkjs099PVfnY2KmDC2BZnws9kh8D/lX1s46w6EPhpXdqMfjK6i",
    },
}


def script_json(value: Any) -> str:
    """JSON for embedding in an HTML ``<script>`` element.

    ``json.dumps`` leaves ``</script>`` and ``<!--`` as they are, so a
    finding title holding them would end the script element early and let
    the rest run as markup. ``<``, ``>``, ``&`` and ``'`` are written as
    ``\\u`` escapes instead, which JavaScript reads back as the same
    characters (the approach of Jinja's ``tojson`` filter).
    """
    return (
        json.dumps(value, default=str)
        .replace("<", "\\u003c")
        .replace(">", "\\u003e")
        .replace("&", "\\u0026")
        .replace("'", "\\u0027")
    )


def _load_vendored_scripts() -> dict[str, str] | None:
    """Source of every vendored library, or None when one cannot be inlined."""
    sources: dict[str, str] = {}
    for name, lib in VENDORED_LIBRARIES.items():
        path = _VENDOR_DIR / lib["file"]
        try:
            text = path.read_text(encoding="utf-8")
        except OSError as exc:
            logger.warning(
                "Vendored %s not found (%s); report.html will load it from the CDN", name, exc
            )
            return None
        lowered = text.lower()
        if "</script" in lowered or "<!--" in lowered:
            logger.warning(
                "Vendored %s cannot be inlined safely; report.html will load it from the CDN",
                name,
            )
            return None
        sources[name] = text
    return sources


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
        inline_js: bool = True,
    ) -> None:
        """
        Args:
            template_dir: Directory holding report.html.j2 (default: the
                packaged templates).
            output_dir: Where the report is written.
            inline_js: Embed Chart.js and D3 in the page so it works
                offline (report.inline_js). False loads them from
                cdn.jsdelivr.net instead, which makes the file about
                480 KB smaller.
        """
        self._template_dir = Path(template_dir) if template_dir else _resolve_template_dir()
        self._output_dir = Path(output_dir)
        self._inline_js = inline_js

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
        template_data.update(self._script_data())

        # Render template. Autoescape is on for every template: the file is
        # report.html.j2, which select_autoescape(["html"]) did not match.
        if self._template_dir.exists():
            env = Environment(
                loader=FileSystemLoader(str(self._template_dir)),
                autoescape=True,
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

        with open(output_path, "w", encoding="utf-8") as f:
            f.write(html)

        logger.info("Generated HTML report at %s", output_path)
        return output_path

    def _script_data(self) -> dict[str, Any]:
        """Template data for the Chart.js and D3 script elements."""
        sources = _load_vendored_scripts() if self._inline_js else None
        return {
            "inline_js": sources is not None,
            "vendored_js": sources or {},
            "cdn_js": VENDORED_LIBRARIES,
        }

    def _prepare_data(
        self,
        scan_result: ScanResult,
        graph_json: dict[str, Any] | None,
    ) -> dict[str, Any]:
        """Prepare data for template rendering."""
        # Severity breakdown
        severity_counts = self._count_severities(scan_result)

        # Resource type breakdown
        resource_types = self._count_resource_types(scan_result)

        # Source tool breakdown
        source_tools = self._count_source_tools(scan_result)

        # Compliance framework summary
        compliance_summary = self._summarise_compliance(scan_result)

        # Findings per resource (for topology badges)
        findings_per_resource = self._count_findings_per_resource(scan_result)

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
            "severity_counts_json": script_json(severity_counts),
            "resource_types": resource_types,
            "resource_types_json": script_json(resource_types),
            "source_tools": source_tools,
            "source_tools_json": script_json(source_tools),
            "compliance_summary": compliance_summary,
            "compliance_summary_json": script_json(compliance_summary),
            "findings": [f.model_dump(mode="json") for f in scan_result.findings],
            "findings_json": script_json([f.model_dump(mode="json") for f in scan_result.findings]),
            "assets": [a.model_dump(exclude={"raw_data"}, mode="json") for a in scan_result.assets],
            "assets_json": script_json(
                [a.model_dump(exclude={"raw_data"}, mode="json") for a in scan_result.assets]
            ),
            "graph_json": script_json(enriched_graph),
            "hierarchy_json": script_json(hierarchy),
            "findings_per_resource_json": script_json(findings_per_resource),
        }

    def _count_severities(self, scan_result: ScanResult) -> dict[str, int]:
        """Count findings per severity level."""
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
        return severity_counts

    def _count_resource_types(self, scan_result: ScanResult) -> dict[str, int]:
        """Count assets per resource type."""
        resource_types: dict[str, int] = {}
        for asset in scan_result.assets:
            resource_types[asset.asset_type.value] = (
                resource_types.get(asset.asset_type.value, 0) + 1
            )
        return resource_types

    def _count_source_tools(self, scan_result: ScanResult) -> dict[str, int]:
        """Count findings per source tool."""
        source_tools: dict[str, int] = {}
        for finding in scan_result.findings:
            source_tools[finding.source_tool] = source_tools.get(finding.source_tool, 0) + 1
        return source_tools

    def _summarise_compliance(self, scan_result: ScanResult) -> dict[str, dict[str, int]]:
        """Count pass/fail results per compliance framework."""
        compliance_summary: dict[str, dict[str, int]] = {}
        for result in scan_result.compliance:
            if result.framework not in compliance_summary:
                compliance_summary[result.framework] = {"pass": 0, "fail": 0}  # nosec B105 - status counters
            if result.status.value == "PASS":
                compliance_summary[result.framework]["pass"] += 1
            else:
                compliance_summary[result.framework]["fail"] += 1
        return compliance_summary

    def _count_findings_per_resource(self, scan_result: ScanResult) -> dict[str, dict[str, int]]:
        """Count findings per resource, broken down by severity."""
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
        return findings_per_resource

    def _build_hierarchy(
        self,
        scan_result: ScanResult,
        findings_per_resource: dict[str, dict[str, int]],
    ) -> dict[str, Any]:
        """Build hierarchical tree: Account → Region → VPC → Subnet → Resources."""
        # Group assets by region → VPC → subnet
        regions, ungrouped = self._group_assets_by_location(scan_result, findings_per_resource)

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

    def _group_assets_by_location(
        self,
        scan_result: ScanResult,
        findings_per_resource: dict[str, dict[str, int]],
    ) -> tuple[dict[str, dict[str, dict[str, list[dict[str, Any]]]]], list[dict[str, Any]]]:
        """Group assets by region → VPC → subnet, collecting ungrouped assets separately."""
        from collections import defaultdict

        regions: dict[str, dict[str, dict[str, list[dict[str, Any]]]]] = defaultdict(
            lambda: defaultdict(lambda: defaultdict(list))
        )
        ungrouped: list[dict[str, Any]] = []

        for asset in scan_result.assets:
            asset_data = self._asset_tree_data(asset, findings_per_resource)
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

        return regions, ungrouped

    def _asset_tree_data(
        self,
        asset: Any,
        findings_per_resource: dict[str, dict[str, int]],
    ) -> dict[str, Any]:
        """Shape one asset into the dict used by hierarchy tree leaves."""
        return {
            "id": asset.id,
            "name": asset.name,
            "type": asset.asset_type.value,
            "arn": asset.arn or "",
            "internet_exposed": asset.is_internet_exposed,
            "findings": findings_per_resource.get(
                asset.id, findings_per_resource.get(asset.arn or "", {})
            ),
        }

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

        arn_to_node_id = self._map_arns_to_node_ids(nodes)

        # Track compliance frameworks for dedup
        fw_nodes_added: set[str] = set()

        for finding in scan_result.findings:
            finding_id = f"finding_{finding.id}"
            if finding_id in existing_ids:
                continue

            # Finding node
            nodes.append(self._finding_node(finding_id, finding))
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
            self._add_framework_nodes(
                finding, finding_id, nodes, links, existing_ids, fw_nodes_added
            )

        return {"nodes": nodes, "links": links}

    def _map_arns_to_node_ids(self, nodes: list[dict[str, Any]]) -> dict[str, str]:
        """Map resource ARNs → node IDs for connecting findings."""
        arn_to_node_id: dict[str, str] = {}
        for n in nodes:
            if n.get("arn"):
                arn_to_node_id[n["arn"]] = n["id"]
            arn_to_node_id[n.get("id", "")] = n["id"]
        return arn_to_node_id

    def _finding_node(self, finding_id: str, finding: Any) -> dict[str, Any]:
        """Build a SecurityFinding node dict for the D3 graph."""
        return {
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

    def _add_framework_nodes(
        self,
        finding: Any,
        finding_id: str,
        nodes: list[dict[str, Any]],
        links: list[dict[str, Any]],
        existing_ids: set[str],
        fw_nodes_added: set[str],
    ) -> None:
        """Add ComplianceFramework nodes and COMPLIANCE_GOVERNS edges for a finding."""
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

    def _fallback_report(self, data: dict[str, Any]) -> str:
        """Generate a simple fallback HTML report if Jinja2 template is missing.

        Every value is HTML-escaped: titles, resource IDs and remediation
        text come from scanner output.
        """
        findings_rows = ""
        for f in data["findings"]:
            sev = str(f.get("severity", "INFO"))
            sev_class = {
                "CRITICAL": "color:#E74C3C;font-weight:bold",
                "HIGH": "color:#E67E22;font-weight:bold",
                "MEDIUM": "color:#F1C40F",
                "LOW": "color:#3498DB",
                "INFO": "color:#95A5A6",
            }.get(sev, "")
            resource = f.get("resource_arn") or f.get("resource_id") or ""
            remediation = str(f.get("remediation") or "")[:100]
            findings_rows += f"""
                <tr>
                    <td style="{sev_class}">{escape(sev)}</td>
                    <td>{escape(str(f.get("title") or ""))}</td>
                    <td><code>{escape(str(resource))}</code></td>
                    <td>{escape(str(f.get("source_tool") or ""))}</td>
                    <td>{escape(remediation)}</td>
                </tr>"""
        scan_id = escape(str(data["scan_id"]))
        provider = escape(str(data["provider"]))
        account_id = escape(str(data["account_id"]))

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
    <p class="subtitle">Scan ID: {scan_id} | Provider: {provider} | Account: {account_id}</p>

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
