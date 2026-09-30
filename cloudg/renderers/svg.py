"""SVG topology map renderer using svgwrite — hierarchical VPC/Subnet layout."""

from __future__ import annotations

import logging
import math
from pathlib import Path
from typing import Any

import svgwrite
from svgwrite import Drawing

from cloudg.schema.models import AssetType, CloudAsset, NetworkEdge, Severity

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
    "edge_sg": "#DD4B39",
    "bg": "#FAFBFC",
    "vpc_bg": "#EBF5FB",
    "subnet_bg": "#D5F5E3",
    "vpc_border": "#2980B9",
    "subnet_border": "#27AE60",
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

# Asset types that go into the VPC hierarchy
_NETWORK_TYPES = {
    AssetType.VPC,
    AssetType.VNET,
    AssetType.SUBNET,
    AssetType.EC2,
    AssetType.VIRTUAL_MACHINE,
    AssetType.RDS_INSTANCE,
    AssetType.AURORA_CLUSTER,
    AssetType.LAMBDA_FUNCTION,
}

# Asset types that appear in the sidebar (non-network)
_SIDEBAR_TYPES = {
    AssetType.IAM_USER,
    AssetType.IAM_ROLE,
    AssetType.IAM_POLICY,
    AssetType.SECURITY_GROUP,
    AssetType.NSG,
}


class SVGRenderer:
    """Renders a topology SVG map from cloud assets and edges.

    Layout: Hierarchical VPC → Subnet → Resources with sidebar panels.
    """

    def __init__(self, output_dir: str = ".") -> None:
        self._output_dir = Path(output_dir)

    def render(
        self,
        assets: list[CloudAsset],
        edges: list[NetworkEdge],
        findings_by_resource: dict[str, list[dict[str, Any]]] | None = None,
        filename: str = "topology.svg",
        width: int = 1800,
        height: int = 1400,
    ) -> Path:
        """Render topology SVG with hierarchical layout."""
        self._output_dir.mkdir(parents=True, exist_ok=True)
        output_path = self._output_dir / filename

        dwg = svgwrite.Drawing(
            str(output_path),
            size=(f"{width}px", f"{height}px"),
            profile="full",
        )

        dwg.defs.add(dwg.style(self._get_css()))

        # Background
        dwg.add(dwg.rect(insert=(0, 0), size=(width, height), fill=_COLOURS["bg"]))

        # Title
        dwg.add(
            dwg.text(
                "Cloud Infrastructure Topology",
                insert=(width // 2, 35),
                text_anchor="middle",
                font_size="22px",
                font_family="Inter, Arial, sans-serif",
                font_weight="bold",
                fill="#2C3E50",
            )
        )

        # Build hierarchy
        hierarchy = self._build_hierarchy(assets)

        # Calculate layout
        positions, containers = self._calculate_hierarchical_layout(
            assets, hierarchy, width, height
        )

        # Draw containers (VPC, Subnet boxes) FIRST
        container_group = dwg.g(id="containers")
        for container in containers:
            self._draw_container(dwg, container_group, container)
        dwg.add(container_group)

        # Draw edges (only between real assets)
        self._draw_edges(dwg, assets, edges, positions)

        # Draw nodes
        self._draw_nodes(dwg, assets, positions, findings_by_resource or {})

        # Legend
        self._draw_legend(dwg, width, height)

        dwg.save()
        logger.info("Rendered topology SVG to %s", output_path)
        return output_path

    # ------------------------------------------------------------------
    # Hierarchy building
    # ------------------------------------------------------------------

    def _build_hierarchy(self, assets: list[CloudAsset]) -> dict[str, Any]:
        """Build VPC → Subnet → Resource hierarchy from asset metadata."""
        vpcs: dict[str, dict[str, Any]] = {}
        # Index VPCs
        for a in assets:
            if a.asset_type in (AssetType.VPC, AssetType.VNET):
                vpc_id = a.metadata.get("vpc_id", a.id)
                vpcs[vpc_id] = {"asset": a, "subnets": {}, "loose": []}

        # Index Subnets into VPCs
        for a in assets:
            if a.asset_type == AssetType.SUBNET:
                vpc_id = a.metadata.get("vpc_id", "")
                subnet_id = a.metadata.get("subnet_id", a.id)
                if vpc_id in vpcs:
                    vpcs[vpc_id]["subnets"][subnet_id] = {"asset": a, "resources": []}

        # Index resources into subnets
        for a in assets:
            if a.asset_type in (
                AssetType.EC2,
                AssetType.VIRTUAL_MACHINE,
                AssetType.RDS_INSTANCE,
                AssetType.AURORA_CLUSTER,
                AssetType.LAMBDA_FUNCTION,
            ):
                subnet_id = a.metadata.get("subnet_id", "")
                vpc_id = a.metadata.get("vpc_id", "")
                placed = False
                if vpc_id in vpcs:
                    for sid, sdata in vpcs[vpc_id]["subnets"].items():
                        if sid == subnet_id:
                            sdata["resources"].append(a)
                            placed = True
                            break
                    if not placed:
                        vpcs[vpc_id]["loose"].append(a)

        return {"vpcs": vpcs}

    # ------------------------------------------------------------------
    # Layout calculation
    # ------------------------------------------------------------------

    def _calculate_hierarchical_layout(
        self,
        assets: list[CloudAsset],
        hierarchy: dict[str, Any],
        width: int,
        height: int,
    ) -> tuple[dict[str, tuple[float, float]], list[dict[str, Any]]]:
        """Calculate positions for a hierarchical VPC → Subnet → Resource layout."""
        positions: dict[str, tuple[float, float]] = {}
        containers: list[dict[str, Any]] = []

        vpcs = hierarchy["vpcs"]
        margin = 30

        # Separate assets into network (hierarchy) and sidebar categories
        sidebar_assets = self._collect_sidebar_assets(assets, vpcs)

        # ── Main area: VPCs ──
        # Leave right sidebar for non-network assets
        main_w = int(width * 0.70)
        sidebar_x = main_w + margin

        vpc_y = 70  # Start below title
        vpc_x = margin

        for vpc_data in vpcs.values():
            vpc_y = self._layout_vpc(vpc_data, vpc_x, vpc_y, main_w, margin, positions, containers)

        # ── Sidebar: non-network assets ──
        sidebar_w = width - sidebar_x - margin
        self._layout_sidebar(sidebar_assets, sidebar_x, sidebar_w, positions, containers)

        return positions, containers

    def _layout_sidebar(
        self,
        sidebar_assets: dict[str, list[CloudAsset]],
        sidebar_x: float,
        sidebar_w: float,
        positions: dict[str, tuple[float, float]],
        containers: list[dict[str, Any]],
    ) -> None:
        """Lay out sidebar groups of non-network assets top to bottom."""
        sy = 70
        groups_to_show = [
            ("LOAD_BALANCER", "Load Balancers", _COLOURS["load_balancer"]),
            ("S3_BUCKET", "S3 Buckets", _COLOURS["s3"]),
            ("SECURITY_GROUP", "Security Groups", _COLOURS["security_group"]),
            ("SECRET", "Secrets", _COLOURS["other"]),
            ("KMS_KEY", "KMS Keys", _COLOURS["other"]),
            ("IAM_ROLE", "IAM Roles", _COLOURS["iam"]),
            ("IAM_USER", "IAM Users", _COLOURS["iam"]),
            ("IAM_POLICY", "IAM Policies", _COLOURS["iam"]),
            ("LAMBDA_FUNCTION", "Lambda", _COLOURS["lambda"]),
        ]

        for type_key, group_label, colour in groups_to_show:
            group_assets = sidebar_assets.pop(type_key, [])
            if not group_assets:
                continue
            name = f"{group_label} ({len(group_assets)})"
            sy = self._layout_sidebar_group(
                name, colour, group_assets, sidebar_x, sidebar_w, sy, positions, containers
            )

        # Any remaining sidebar types
        for type_key, remaining in sidebar_assets.items():
            if not remaining:
                continue
            name = f"{type_key} ({len(remaining)})"
            sy = self._layout_sidebar_group(
                name, _COLOURS["other"], remaining, sidebar_x, sidebar_w, sy, positions, containers
            )

    def _collect_sidebar_assets(
        self,
        assets: list[CloudAsset],
        vpcs: dict[str, dict[str, Any]],
    ) -> dict[str, list[CloudAsset]]:
        """Group assets that are not placed in the VPC hierarchy by asset type."""
        sidebar_assets: dict[str, list[CloudAsset]] = {}
        for a in assets:
            if a.asset_type in (AssetType.VPC, AssetType.VNET, AssetType.SUBNET):
                continue
            # Check if this asset is placed in the hierarchy
            if not self._is_in_hierarchy(a, vpcs):
                key = a.asset_type.value
                sidebar_assets.setdefault(key, []).append(a)
        return sidebar_assets

    def _is_in_hierarchy(self, asset: CloudAsset, vpcs: dict[str, dict[str, Any]]) -> bool:
        """Return True if the asset sits in a VPC's loose list or a subnet's resources."""
        for vpc_data in vpcs.values():
            if any(r.id == asset.id for r in vpc_data["loose"]):
                return True
            for sdata in vpc_data["subnets"].values():
                if any(r.id == asset.id for r in sdata["resources"]):
                    return True
        return False

    def _layout_vpc(
        self,
        vpc_data: dict[str, Any],
        vpc_x: float,
        vpc_y: float,
        main_w: int,
        margin: int,
        positions: dict[str, tuple[float, float]],
        containers: list[dict[str, Any]],
    ) -> float:
        """Lay out one VPC (subnets + loose resources) and return the next vpc_y."""
        node_spacing = 55
        vpc_pad = 25
        header_h = 22

        vpc_asset = vpc_data["asset"]
        loose = vpc_data["loose"]

        # Calculate subnet boxes
        subnet_containers, max_subnet_bottom = self._layout_subnets(
            vpc_data["subnets"], vpc_x, vpc_y, main_w, margin, positions
        )

        # Place loose resources (in VPC but not in a subnet)
        if loose:
            for li, la in enumerate(loose):
                lx = vpc_x + vpc_pad + li * node_spacing + node_spacing / 2
                ly = max_subnet_bottom + 15 + node_spacing / 2
                positions[la.id] = (lx, ly)
            max_subnet_bottom += node_spacing + 15

        # VPC container
        vpc_w = max(main_w - 2 * margin, 400)
        vpc_h = max(max_subnet_bottom - vpc_y + vpc_pad, 100)

        containers.append(
            {
                "type": "vpc",
                "name": vpc_asset.name,
                "cidr": vpc_asset.metadata.get("cidr_block", ""),
                "x": vpc_x,
                "y": vpc_y,
                "w": vpc_w,
                "h": vpc_h,
            }
        )
        containers.extend(subnet_containers)

        positions[vpc_asset.id] = (vpc_x + vpc_w / 2, vpc_y + header_h / 2)
        return vpc_y + vpc_h + 20

    def _layout_subnets(
        self,
        subnets: dict[str, dict[str, Any]],
        vpc_x: float,
        vpc_y: float,
        main_w: int,
        margin: int,
        positions: dict[str, tuple[float, float]],
    ) -> tuple[list[dict[str, Any]], float]:
        """Size subnet boxes, place their resources, and return (containers, bottom y)."""
        node_spacing = 55
        subnet_pad = 20
        vpc_pad = 25
        header_h = 22

        subnet_containers: list[dict[str, Any]] = []
        sx = vpc_x + vpc_pad
        sy = vpc_y + vpc_pad + header_h

        max_subnet_bottom = sy

        for sdata in subnets.values():
            subnet_asset = sdata["asset"]
            resources = sdata["resources"]

            # Size the subnet box to fit its resources
            n_res = max(len(resources), 1)
            cols = min(n_res, 4)
            rows = math.ceil(n_res / cols) if n_res > 0 else 1
            sbox_w = cols * node_spacing + 2 * subnet_pad
            sbox_h = rows * node_spacing + 2 * subnet_pad + header_h

            # Check if it fits horizontally
            if sx + sbox_w > vpc_x + main_w - vpc_pad - margin:
                # Wrap to next row
                sx = vpc_x + vpc_pad
                sy = max_subnet_bottom + 10

            subnet_containers.append(
                {
                    "type": "subnet",
                    "name": subnet_asset.name,
                    "cidr": subnet_asset.metadata.get("cidr_block", ""),
                    "is_public": subnet_asset.metadata.get("map_public_ip", False),
                    "x": sx,
                    "y": sy,
                    "w": sbox_w,
                    "h": sbox_h,
                }
            )

            # Position the subnet asset label (center of box header)
            positions[subnet_asset.id] = (sx + sbox_w / 2, sy + header_h / 2)

            # Place resources inside subnet
            self._place_subnet_resources(resources, sx, sy, cols, positions)

            max_subnet_bottom = max(max_subnet_bottom, sy + sbox_h)
            sx += sbox_w + 10

        return subnet_containers, max_subnet_bottom

    def _place_subnet_resources(
        self,
        resources: list[CloudAsset],
        sx: float,
        sy: float,
        cols: int,
        positions: dict[str, tuple[float, float]],
    ) -> None:
        """Place resource nodes in a grid inside a subnet box."""
        node_spacing = 55
        subnet_pad = 20
        header_h = 22
        for ri, res in enumerate(resources):
            col = ri % cols
            row = ri // cols
            rx = sx + subnet_pad + col * node_spacing + node_spacing / 2
            ry = sy + header_h + subnet_pad + row * node_spacing + node_spacing / 2
            positions[res.id] = (rx, ry)

    def _layout_sidebar_group(
        self,
        name: str,
        colour: str,
        group_assets: list[CloudAsset],
        sidebar_x: float,
        sidebar_w: float,
        sy: float,
        positions: dict[str, tuple[float, float]],
        containers: list[dict[str, Any]],
    ) -> float:
        """Place one sidebar group header plus its assets and return the next y."""
        node_r = 18
        node_spacing = 55

        # Group header
        containers.append(
            {
                "type": "sidebar_group",
                "name": name,
                "x": sidebar_x,
                "y": sy,
                "w": sidebar_w,
                "h": 18,
                "colour": colour,
            }
        )
        sy += 22

        # Place assets in the sidebar
        cols = max(1, min(3, int(sidebar_w / node_spacing)))
        for ai, a in enumerate(group_assets):
            col = ai % cols
            row = ai // cols
            ax = sidebar_x + 15 + col * node_spacing + node_r
            ay = sy + row * (node_spacing - 10) + node_r
            positions[a.id] = (ax, ay)

        rows = math.ceil(len(group_assets) / cols)
        return sy + rows * (node_spacing - 10) + 15

    # ------------------------------------------------------------------
    # Drawing helpers
    # ------------------------------------------------------------------

    def _draw_edges(
        self,
        dwg: Drawing,
        assets: list[CloudAsset],
        edges: list[NetworkEdge],
        positions: dict[str, tuple[float, float]],
    ) -> None:
        """Draw network edges between positioned assets."""
        edge_group = dwg.g(id="edges")
        asset_ids = {a.id for a in assets}
        for edge in edges:
            src = positions.get(edge.source_id)
            tgt = positions.get(edge.target_id)
            if src and tgt and edge.source_id in asset_ids and edge.target_id in asset_ids:
                is_internet = edge.cidr in ("0.0.0.0/0", "::/0")
                colour = _COLOURS["edge_internet"] if is_internet else _COLOURS["edge_normal"]
                sw = 2 if is_internet else 1
                dash = "5,3" if edge.edge_type.value == "IAM_TRUST" else None
                line = dwg.line(start=src, end=tgt, stroke=colour, stroke_width=sw, opacity=0.5)
                if dash:
                    line["stroke-dasharray"] = dash
                edge_group.add(line)
        dwg.add(edge_group)

    def _draw_nodes(
        self,
        dwg: Drawing,
        assets: list[CloudAsset],
        positions: dict[str, tuple[float, float]],
        findings_map: dict[str, list[dict[str, Any]]],
    ) -> None:
        """Draw all resource nodes at their calculated positions."""
        node_group = dwg.g(id="nodes")
        for asset in assets:
            # Skip VPC and SUBNET — they're drawn as containers
            if asset.asset_type in (AssetType.VPC, AssetType.VNET, AssetType.SUBNET):
                continue
            pos = positions.get(asset.id)
            if not pos:
                continue
            self._draw_node(dwg, node_group, asset, pos, findings_map)
        dwg.add(node_group)

    def _draw_container(self, dwg: Drawing, group: Any, container: dict[str, Any]) -> None:
        """Draw a VPC or Subnet container rectangle."""
        ctype = container["type"]
        x, y = container["x"], container["y"]

        if ctype == "vpc":
            self._draw_vpc_container(dwg, group, container, x, y)
        elif ctype == "subnet":
            self._draw_subnet_container(dwg, group, container, x, y)
        elif ctype == "sidebar_group":
            self._draw_sidebar_group_header(dwg, group, container, x, y)

    def _draw_vpc_container(
        self, dwg: Drawing, group: Any, container: dict[str, Any], x: float, y: float
    ) -> None:
        """Draw a VPC container rectangle with its label."""
        group.add(
            dwg.rect(
                insert=(x, y),
                size=(container["w"], container["h"]),
                fill=_COLOURS["vpc_bg"],
                stroke=_COLOURS["vpc_border"],
                stroke_width=2,
                rx=8,
                ry=8,
                opacity=0.85,
                stroke_dasharray="8,4",
            )
        )
        label = f"VPC: {container['name']}"
        if container.get("cidr"):
            label += f"  ({container['cidr']})"
        group.add(
            dwg.text(
                label,
                insert=(x + 10, y + 16),
                font_size="13px",
                font_weight="bold",
                font_family="Inter, Arial, sans-serif",
                fill=_COLOURS["vpc_border"],
            )
        )

    def _draw_subnet_container(
        self, dwg: Drawing, group: Any, container: dict[str, Any], x: float, y: float
    ) -> None:
        """Draw a Subnet container rectangle with its label."""
        group.add(
            dwg.rect(
                insert=(x, y),
                size=(container["w"], container["h"]),
                fill=_COLOURS["subnet_bg"],
                stroke=_COLOURS["subnet_border"],
                stroke_width=1.5,
                rx=6,
                ry=6,
                opacity=0.7,
            )
        )
        label = container["name"]
        if container.get("cidr"):
            label += f"  ({container['cidr']})"
        if container.get("is_public"):
            label += "  🌐"
        group.add(
            dwg.text(
                label,
                insert=(x + 8, y + 14),
                font_size="10px",
                font_weight="600",
                font_family="Inter, Arial, sans-serif",
                fill=_COLOURS["subnet_border"],
            )
        )

    def _draw_sidebar_group_header(
        self, dwg: Drawing, group: Any, container: dict[str, Any], x: float, y: float
    ) -> None:
        """Draw a sidebar group heading with its underline."""
        colour = container.get("colour", _COLOURS["other"])
        group.add(
            dwg.text(
                container["name"],
                insert=(x, y + 13),
                font_size="11px",
                font_weight="bold",
                font_family="Inter, Arial, sans-serif",
                fill=colour,
            )
        )
        # Underline
        group.add(
            dwg.line(
                start=(x, y + 16),
                end=(x + container["w"], y + 16),
                stroke=colour,
                stroke_width=0.5,
                opacity=0.4,
            )
        )

    def _draw_node(
        self,
        dwg: Drawing,
        group: Any,
        asset: CloudAsset,
        pos: tuple[float, float],
        findings_map: dict[str, list[dict[str, Any]]],
    ) -> None:
        """Draw a single resource node as a circle with label."""
        x, y = pos
        colour = _ASSET_TYPE_COLOURS.get(asset.asset_type, _COLOURS["other"])
        is_exposed = asset.is_internet_exposed
        border = _COLOURS["exposed_border"] if is_exposed else _COLOURS["normal_border"]
        border_w = 3 if is_exposed else 1
        r = 16

        node_g = dwg.g(class_="node")

        node_g.add(
            dwg.circle(
                center=(x, y),
                r=r,
                fill=colour,
                stroke=border,
                stroke_width=border_w,
                opacity=0.9,
            )
        )

        self._draw_node_labels(dwg, node_g, asset, x, y, r)

        # Severity badge
        resource_findings = findings_map.get(asset.id, [])
        if resource_findings:
            self._draw_severity_badge(dwg, node_g, resource_findings, x, y, r)

        group.add(node_g)

    def _draw_node_labels(
        self, dwg: Drawing, node_g: Any, asset: CloudAsset, x: float, y: float, r: int
    ) -> None:
        """Draw the name label and type badge below a node."""
        # Label — truncate long names
        label = asset.name[:18] + "…" if len(asset.name) > 18 else asset.name
        node_g.add(
            dwg.text(
                label,
                insert=(x, y + r + 13),
                text_anchor="middle",
                font_size="9px",
                font_family="Inter, Arial, sans-serif",
                fill="#333333",
            )
        )

        # Type badge
        node_g.add(
            dwg.text(
                asset.asset_type.value,
                insert=(x, y + r + 23),
                text_anchor="middle",
                font_size="7px",
                font_family="Inter, Arial, sans-serif",
                fill="#888888",
            )
        )

    def _draw_severity_badge(
        self,
        dwg: Drawing,
        node_g: Any,
        resource_findings: list[dict[str, Any]],
        x: float,
        y: float,
        r: int,
    ) -> None:
        """Draw a finding-count badge coloured by the worst severity."""
        max_sev = min(
            resource_findings,
            key=lambda f: list(Severity).index(Severity(f.get("severity", "INFO"))),
        )
        badge_colour = _SEVERITY_BADGE_COLOURS.get(
            Severity(max_sev.get("severity", "INFO")), "#95A5A6"
        )
        node_g.add(
            dwg.circle(
                center=(x + r - 2, y - r + 2),
                r=7,
                fill=badge_colour,
                stroke="white",
                stroke_width=1.5,
            )
        )
        node_g.add(
            dwg.text(
                str(len(resource_findings)),
                insert=(x + r - 2, y - r + 5),
                text_anchor="middle",
                font_size="7px",
                font_weight="bold",
                fill="white",
            )
        )

    # ------------------------------------------------------------------
    # Legend & CSS
    # ------------------------------------------------------------------

    def _draw_legend(self, dwg: Drawing, width: int, height: int) -> None:
        """Draw a legend showing asset type colours."""
        legend_g = dwg.g(id="legend")
        x_start = 20
        y_start = height - 180

        legend_g.add(
            dwg.rect(
                insert=(x_start - 10, y_start - 20),
                size=(220, 170),
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
            ("Subnet", _COLOURS["subnet"]),
            ("IAM", _COLOURS["iam"]),
            ("Security Group", _COLOURS["security_group"]),
            ("Load Balancer", _COLOURS["load_balancer"]),
            ("Internet-Exposed", _COLOURS["exposed_border"]),
        ]

        for i, (label, colour) in enumerate(items):
            y = y_start + 18 + i * 15
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
