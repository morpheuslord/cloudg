"""SVG topology map renderer using svgwrite."""

from __future__ import annotations

import logging
import math
from pathlib import Path
from typing import Any

import svgwrite
from svgwrite import Drawing

from cloudmapper.schema.models import AssetType, CloudAsset, NetworkEdge, Severity

logger = logging.getLogger(__name__)

# Colour palette
_COLOURS = {
    "vpc": "#4A90D9",
    "subnet": "#7EC8E3",
    "ec2": "#FF9900",
    "rds": "#3B48CC",
    "s3": "#569A31",
    "lambda": "#FF9900",
    "security_group": "#DD4B39",
    "iam": "#232F3E",
    "load_balancer": "#8C4FFF",
    "other": "#95A5A6",
    "internet": "#E74C3C",
    "exposed_border": "#FF0000",
    "normal_border": "#333333",
    "edge_normal": "#999999",
    "edge_internet": "#E74C3C",
    "edge_contains": "#CCCCCC",
}

_SEVERITY_BADGE_COLOURS = {
    Severity.CRITICAL: "#E74C3C",
    Severity.HIGH: "#E67E22",
    Severity.MEDIUM: "#F1C40F",
    Severity.LOW: "#3498DB",
    Severity.INFO: "#95A5A6",
}

_ASSET_TYPE_COLOURS: dict[AssetType, str] = {
    AssetType.VPC: _COLOURS["vpc"],
    AssetType.VNET: _COLOURS["vpc"],
    AssetType.SUBNET: _COLOURS["subnet"],
    AssetType.EC2: _COLOURS["ec2"],
    AssetType.VIRTUAL_MACHINE: _COLOURS["ec2"],
    AssetType.GCE_INSTANCE: _COLOURS["ec2"],
    AssetType.RDS_INSTANCE: _COLOURS["rds"],
    AssetType.AURORA_CLUSTER: _COLOURS["rds"],
    AssetType.AZURE_SQL: _COLOURS["rds"],
    AssetType.CLOUD_SQL: _COLOURS["rds"],
    AssetType.S3_BUCKET: _COLOURS["s3"],
    AssetType.BLOB_STORAGE: _COLOURS["s3"],
    AssetType.GCS_BUCKET: _COLOURS["s3"],
    AssetType.LAMBDA_FUNCTION: _COLOURS["lambda"],
    AssetType.CLOUD_FUNCTION: _COLOURS["lambda"],
    AssetType.SECURITY_GROUP: _COLOURS["security_group"],
    AssetType.NSG: _COLOURS["security_group"],
    AssetType.IAM_USER: _COLOURS["iam"],
    AssetType.IAM_ROLE: _COLOURS["iam"],
    AssetType.IAM_POLICY: _COLOURS["iam"],
    AssetType.LOAD_BALANCER: _COLOURS["load_balancer"],
}


class SVGRenderer:
    """Renders a topology SVG map from cloud assets and edges.

    Layout: Simple force-directed-like placement with VPC/subnet containers.
    """

    def __init__(self, output_dir: str = ".") -> None:
        self._output_dir = Path(output_dir)

    def render(
        self,
        assets: list[CloudAsset],
        edges: list[NetworkEdge],
        findings_by_resource: dict[str, list[dict[str, Any]]] | None = None,
        filename: str = "topology.svg",
        width: int = 1600,
        height: int = 1200,
    ) -> Path:
        """Render topology SVG.

        Args:
            assets: Cloud assets to render as nodes.
            edges: Network edges to render.
            findings_by_resource: Optional findings grouped by resource ID for badges.
            filename: Output filename.
            width: SVG canvas width.
            height: SVG canvas height.

        Returns:
            Path to generated SVG file.
        """
        self._output_dir.mkdir(parents=True, exist_ok=True)
        output_path = self._output_dir / filename

        dwg = svgwrite.Drawing(
            str(output_path),
            size=(f"{width}px", f"{height}px"),
            profile="full",
        )

        # Add styles
        dwg.defs.add(dwg.style(self._get_css()))

        # Background
        dwg.add(dwg.rect(insert=(0, 0), size=(width, height), fill="#FAFBFC"))

        # Title
        dwg.add(
            dwg.text(
                "Cloud Infrastructure Topology",
                insert=(width // 2, 40),
                text_anchor="middle",
                font_size="24px",
                font_family="Inter, Arial, sans-serif",
                font_weight="bold",
                fill="#2C3E50",
            )
        )

        # Calculate layout positions
        positions = self._calculate_layout(assets, width, height)

        # Draw edges first (behind nodes)
        edge_group = dwg.g(id="edges")
        asset_id_set = {a.id for a in assets}
        for edge in edges:
            src_pos = positions.get(edge.source_id)
            tgt_pos = positions.get(edge.target_id)
            if src_pos and tgt_pos:
                is_internet = edge.cidr in ("0.0.0.0/0", "::/0")
                edge_colour = _COLOURS["edge_internet"] if is_internet else _COLOURS["edge_normal"]
                stroke_width = 2 if is_internet else 1
                dash = "5,3" if edge.edge_type.value == "IAM_TRUST" else None

                line = dwg.line(
                    start=src_pos,
                    end=tgt_pos,
                    stroke=edge_colour,
                    stroke_width=stroke_width,
                    opacity=0.6,
                )
                if dash:
                    line["stroke-dasharray"] = dash
                edge_group.add(line)
        dwg.add(edge_group)

        # Draw nodes
        node_group = dwg.g(id="nodes")
        findings_map = findings_by_resource or {}

        for asset in assets:
            pos = positions.get(asset.id)
            if not pos:
                continue

            x, y = pos
            colour = _ASSET_TYPE_COLOURS.get(asset.asset_type, _COLOURS["other"])
            is_exposed = asset.is_internet_exposed
            border = _COLOURS["exposed_border"] if is_exposed else _COLOURS["normal_border"]
            border_width = 3 if is_exposed else 1

            # Node shape
            node_g = dwg.g(class_="node")

            # Circle node
            node_g.add(
                dwg.circle(
                    center=(x, y),
                    r=20,
                    fill=colour,
                    stroke=border,
                    stroke_width=border_width,
                    opacity=0.9,
                )
            )

            # Label
            label = asset.name[:20] + "..." if len(asset.name) > 20 else asset.name
            node_g.add(
                dwg.text(
                    label,
                    insert=(x, y + 35),
                    text_anchor="middle",
                    font_size="10px",
                    font_family="Inter, Arial, sans-serif",
                    fill="#333333",
                )
            )

            # Type badge
            node_g.add(
                dwg.text(
                    asset.asset_type.value,
                    insert=(x, y + 47),
                    text_anchor="middle",
                    font_size="8px",
                    font_family="Inter, Arial, sans-serif",
                    fill="#666666",
                )
            )

            # Severity badge if findings exist
            resource_findings = findings_map.get(asset.id, [])
            if resource_findings:
                max_severity = min(
                    resource_findings,
                    key=lambda f: list(Severity).index(
                        Severity(f.get("severity", "INFO"))
                    ),
                )
                badge_colour = _SEVERITY_BADGE_COLOURS.get(
                    Severity(max_severity.get("severity", "INFO")),
                    "#95A5A6",
                )
                node_g.add(
                    dwg.circle(
                        center=(x + 15, y - 15),
                        r=8,
                        fill=badge_colour,
                        stroke="white",
                        stroke_width=2,
                    )
                )
                node_g.add(
                    dwg.text(
                        str(len(resource_findings)),
                        insert=(x + 15, y - 12),
                        text_anchor="middle",
                        font_size="8px",
                        font_weight="bold",
                        fill="white",
                    )
                )

            node_group.add(node_g)

        dwg.add(node_group)

        # Legend
        self._draw_legend(dwg, width, height)

        dwg.save()
        logger.info("Rendered topology SVG to %s", output_path)
        return output_path

    def _calculate_layout(
        self,
        assets: list[CloudAsset],
        width: int,
        height: int,
    ) -> dict[str, tuple[float, float]]:
        """Calculate node positions using a simple circular/group layout."""
        positions: dict[str, tuple[float, float]] = {}

        if not assets:
            return positions

        # Group by asset type for clustering
        groups: dict[str, list[CloudAsset]] = {}
        for asset in assets:
            group_key = asset.asset_type.value
            groups.setdefault(group_key, []).append(asset)

        # Place groups in a ring
        margin = 120
        cx, cy = width / 2, height / 2
        group_radius = min(width, height) / 2 - margin - 60

        num_groups = len(groups)
        for g_idx, (group_name, group_assets) in enumerate(groups.items()):
            # Group center position on ring
            angle = (2 * math.pi * g_idx) / max(num_groups, 1)
            gx = cx + group_radius * math.cos(angle)
            gy = cy + group_radius * math.sin(angle)

            # Place assets in mini-ring around group center
            num_assets = len(group_assets)
            inner_radius = min(50, 15 * num_assets)

            for a_idx, asset in enumerate(group_assets):
                if num_assets == 1:
                    positions[asset.id] = (gx, gy)
                else:
                    a_angle = (2 * math.pi * a_idx) / num_assets
                    ax = gx + inner_radius * math.cos(a_angle)
                    ay = gy + inner_radius * math.sin(a_angle)
                    positions[asset.id] = (ax, ay)

        return positions

    def _draw_legend(self, dwg: Drawing, width: int, height: int) -> None:
        """Draw a legend showing asset type colours and severity badges."""
        legend_g = dwg.g(id="legend")
        x_start = 20
        y_start = height - 160

        # Background
        legend_g.add(
            dwg.rect(
                insert=(x_start - 10, y_start - 20),
                size=(200, 150),
                fill="white",
                stroke="#DDDDDD",
                rx=5,
                ry=5,
                opacity=0.95,
            )
        )

        legend_g.add(
            dwg.text(
                "Legend",
                insert=(x_start, y_start),
                font_size="12px",
                font_weight="bold",
                font_family="Inter, Arial, sans-serif",
                fill="#333333",
            )
        )

        items = [
            ("EC2/VM", _COLOURS["ec2"]),
            ("RDS/SQL", _COLOURS["rds"]),
            ("S3/Storage", _COLOURS["s3"]),
            ("VPC/VNet", _COLOURS["vpc"]),
            ("IAM", _COLOURS["iam"]),
            ("LB", _COLOURS["load_balancer"]),
            ("Internet-Exposed", _COLOURS["exposed_border"]),
        ]

        for i, (label, colour) in enumerate(items):
            y = y_start + 20 + i * 16
            legend_g.add(dwg.circle(center=(x_start + 6, y - 3), r=5, fill=colour))
            legend_g.add(
                dwg.text(
                    label,
                    insert=(x_start + 18, y),
                    font_size="10px",
                    font_family="Inter, Arial, sans-serif",
                    fill="#333333",
                )
            )

        dwg.add(legend_g)

    def _get_css(self) -> str:
        """Return CSS styles for the SVG."""
        return """
            .node circle { cursor: pointer; transition: opacity 0.2s; }
            .node:hover circle { opacity: 1; }
            .node text { pointer-events: none; }
        """
