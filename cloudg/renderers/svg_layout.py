"""Hierarchical VPC/Subnet layout computation for the SVG topology renderer."""

from __future__ import annotations

import math
from typing import Any

from cloudg.schema.models import AssetType, CloudAsset

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


class HierarchicalLayoutMixin:
    """Provides hierarchical VPC → Subnet → Resource layout calculation."""

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
                (name, colour), group_assets, (sidebar_x, sidebar_w), sy, positions, containers
            )

        # Any remaining sidebar types
        for type_key, remaining in sidebar_assets.items():
            if not remaining:
                continue
            name = f"{type_key} ({len(remaining)})"
            sy = self._layout_sidebar_group(
                (name, _COLOURS["other"]),
                remaining,
                (sidebar_x, sidebar_w),
                sy,
                positions,
                containers,
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
        header: tuple[str, str],
        group_assets: list[CloudAsset],
        column: tuple[float, float],
        sy: float,
        positions: dict[str, tuple[float, float]],
        containers: list[dict[str, Any]],
    ) -> float:
        """Place one sidebar group header plus its assets and return the next y.

        ``header`` is the group's (name, colour), ``column`` the sidebar's (x, width).
        """
        name, colour = header
        sidebar_x, sidebar_w = column
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
