"""Site-to-site VPN: connections, virtual private gateways and customer
gateways. Tunnel options and customer gateway configuration (pre-shared
keys) are never collected."""

from __future__ import annotations

from typing import Any

from cloudg.inventory.aws_services._base import rel
from cloudg.inventory.aws_services.network_ext._common import (
    _GONE_STATES,
    NetworkExtBase,
    _name_tag,
    _unique,
    section,
)
from cloudg.schema.models import AssetType, CloudAsset, EdgeType

# (connection field, edge, relationship, description) per VPN endpoint
_VPN_ENDPOINTS = (
    ("CustomerGatewayId", EdgeType.ROUTE, "TRANSIT_ROUTED", "on-premises side (customer gateway)"),
    (
        "VpnGatewayId",
        EdgeType.ATTACHED_TO,
        "TRANSIT_ROUTED",
        "terminates on virtual private gateway",
    ),
    ("TransitGatewayId", EdgeType.ATTACHED_TO, "TRANSIT_ROUTED", "terminates on transit gateway"),
    (
        "CoreNetworkArn",
        EdgeType.ATTACHED_TO,
        "TRANSIT_ROUTED",
        "terminates on Cloud WAN core network",
    ),
    ("PreSharedKeyArn", EdgeType.REFERENCES, "DEPENDS_ON", "tunnel pre-shared key secret"),
)


def _vpn_tunnels(vpn: dict) -> list[dict]:
    return [
        {
            "outside_ip": t.get("OutsideIpAddress"),
            "status": t.get("Status"),
            "accepted_routes": t.get("AcceptedRouteCount"),
            "last_status_change": str(t.get("LastStatusChange") or ""),
        }
        for t in vpn.get("VgwTelemetry") or []
    ]


def _vpn_relations(vpn: dict) -> list[dict | None]:
    relations: list[dict | None] = [
        rel(vpn.get(field), edge, relationship, description=description)
        for field, edge, relationship, description in _VPN_ENDPOINTS
    ]
    relations += [
        rel(t.get("CertificateArn"), EdgeType.REFERENCES, "CERTIFICATE_SECURES")
        for t in vpn.get("VgwTelemetry") or []
    ]
    return relations


def _vpn_metadata(vpn: dict, tunnels: list[dict]) -> dict[str, Any]:
    opts = vpn.get("Options") or {}
    return {
        "vpn_connection_id": vpn["VpnConnectionId"],
        "state": vpn.get("State"),
        "type": vpn.get("Type"),
        "category": vpn.get("Category"),
        "customer_gateway_id": vpn.get("CustomerGatewayId"),
        "vpn_gateway_id": vpn.get("VpnGatewayId"),
        "tgw_id": vpn.get("TransitGatewayId"),
        "core_network_arn": vpn.get("CoreNetworkArn"),
        "static_routes_only": opts.get("StaticRoutesOnly"),
        "acceleration": opts.get("EnableAcceleration"),
        "outside_ip_type": opts.get("OutsideIpAddressType"),
        "local_ipv4_cidr": opts.get("LocalIpv4NetworkCidr"),
        "remote_ipv4_cidr": opts.get("RemoteIpv4NetworkCidr"),
        "tunnels": tunnels,
        "tunnels_up": sum(1 for t in tunnels if t["status"] == "UP"),
        "static_routes": [
            {
                "cidr": r.get("DestinationCidrBlock"),
                "source": r.get("Source"),
                "state": r.get("State"),
            }
            for r in vpn.get("Routes") or []
        ],
    }


class VpnCollectorsMixin(NetworkExtBase):
    async def _collect_vpn(self) -> list[CloudAsset]:
        async with self._client("ec2") as ec2:
            return await self._nx_sections(
                section("vpn_connections", self._vpn_connections, ec2),
                section("vpn_gateways", self._vpn_gateways, ec2),
                section("customer_gateways", self._customer_gateways, ec2),
            )

    async def _vpn_connections(self, ec2: Any) -> list[CloudAsset]:
        out = []
        for vpn in (await ec2.describe_vpn_connections()).get("VpnConnections", []) or []:
            if vpn.get("State") in _GONE_STATES:
                continue
            vid = vpn["VpnConnectionId"]
            out.append(
                self._asset(
                    arn=self._arn("ec2", f"vpn-connection/{vid}"),
                    name=_name_tag(vpn.get("Tags"), vid),
                    asset_type=AssetType.VPN_CONNECTION,
                    tags=vpn.get("Tags"),
                    metadata=_vpn_metadata(vpn, _vpn_tunnels(vpn)),
                    relations=_unique(_vpn_relations(vpn)),
                    aliases=[vid],
                )
            )
        return out

    async def _vpn_gateways(self, ec2: Any) -> list[CloudAsset]:
        out = []
        for gw in (await ec2.describe_vpn_gateways()).get("VpnGateways", []) or []:
            if gw.get("State") in _GONE_STATES:
                continue
            gid = gw["VpnGatewayId"]
            attachments = [
                {"vpc_id": a.get("VpcId"), "state": a.get("State")}
                for a in gw.get("VpcAttachments") or []
            ]
            out.append(
                self._asset(
                    arn=self._arn("ec2", f"vpn-gateway/{gid}"),
                    name=_name_tag(gw.get("Tags"), gid),
                    asset_type=AssetType.VPN_GATEWAY,
                    tags=gw.get("Tags"),
                    metadata={
                        "vpn_gateway_id": gid,
                        "state": gw.get("State"),
                        "type": gw.get("Type"),
                        "amazon_side_asn": gw.get("AmazonSideAsn"),
                        "vpc_attachments": attachments,
                    },
                    relations=[
                        rel(
                            a["vpc_id"],
                            EdgeType.ATTACHED_TO,
                            description="VPC attachment",
                            state=a["state"],
                        )
                        for a in attachments
                        if a["state"] in ("attached", "attaching")
                    ],
                    aliases=[gid],
                )
            )
        return out

    async def _customer_gateways(self, ec2: Any) -> list[CloudAsset]:
        out = []
        for cgw in (await ec2.describe_customer_gateways()).get("CustomerGateways", []) or []:
            if cgw.get("State") in _GONE_STATES:
                continue
            cid = cgw["CustomerGatewayId"]
            out.append(
                self._asset(
                    arn=self._arn("ec2", f"customer-gateway/{cid}"),
                    name=_name_tag(cgw.get("Tags"), cgw.get("DeviceName") or cid),
                    asset_type=AssetType.CUSTOMER_GATEWAY,
                    tags=cgw.get("Tags"),
                    metadata={
                        "customer_gateway_id": cid,
                        "ip_address": cgw.get("IpAddress"),
                        "bgp_asn": cgw.get("BgpAsnExtended") or cgw.get("BgpAsn"),
                        "device_name": cgw.get("DeviceName"),
                        "state": cgw.get("State"),
                        "type": cgw.get("Type"),
                    },
                    relations=[
                        rel(cgw.get("CertificateArn"), EdgeType.REFERENCES, "CERTIFICATE_SECURES")
                    ],
                    aliases=[cid],
                )
            )
        return out
