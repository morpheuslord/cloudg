"""Direct Connect: connections, LAGs, virtual interfaces, DX gateways and
their VGW / TGW associations. BGP auth keys and MACsec keys are never
collected."""

from __future__ import annotations

from typing import Any

from cloudg.inventory.aws_services._base import rel
from cloudg.inventory.aws_services.network_ext._common import (
    NetworkExtBase,
    _ec2_arn,
    _unique,
    logger,
    section,
)
from cloudg.schema.models import AssetType, CloudAsset, EdgeType


def _dx_link_md(c: dict) -> dict:
    return {
        "state": c.get("connectionState") or c.get("lagState"),
        "location": c.get("location"),
        "aws_device": c.get("awsDeviceV2") or c.get("awsDevice"),
        "jumbo_frames": c.get("jumboFrameCapable"),
        "has_logical_redundancy": c.get("hasLogicalRedundancy"),
        "provider_name": c.get("providerName"),
        "macsec_capable": c.get("macSecCapable"),
        "encryption_mode": c.get("encryptionMode"),
        "owner_account": c.get("ownerAccount"),
    }


def _dx_vif_metadata(v: dict) -> dict[str, Any]:
    return {
        "resource_kind": "dx_virtual_interface",
        "virtual_interface_id": v["virtualInterfaceId"],
        "interface_type": v.get("virtualInterfaceType"),
        "state": v.get("virtualInterfaceState"),
        "vlan": v.get("vlan"),
        "asn": v.get("asnLong") or v.get("asn"),
        "amazon_side_asn": v.get("amazonSideAsn"),
        "address_family": v.get("addressFamily"),
        "mtu": v.get("mtu"),
        "location": v.get("location"),
        "owner_account": v.get("ownerAccount"),
        "connection_id": v.get("connectionId"),
        "dx_gateway_id": v.get("directConnectGatewayId"),
        "vgw_id": v.get("virtualGatewayId"),
        "site_link": v.get("siteLinkEnabled"),
        "route_filter_prefixes": len(v.get("routeFilterPrefixes") or []),
        # BGP auth keys are never kept
        "bgp_peers": [
            {
                "asn": p.get("asnLong") or p.get("asn"),
                "state": p.get("bgpPeerState"),
                "status": p.get("bgpStatus"),
                "address_family": p.get("addressFamily"),
            }
            for p in v.get("bgpPeers") or []
        ],
    }


def _dx_vif_relations(v: dict) -> list[dict | None]:
    return [
        rel(v.get("connectionId"), EdgeType.ATTACHED_TO, description="runs over connection / LAG"),
        rel(
            v.get("virtualGatewayId"),
            EdgeType.ROUTE,
            "TRANSIT_ROUTED",
            description="private VIF to VGW",
        ),
        rel(
            v.get("directConnectGatewayId"),
            EdgeType.ROUTE,
            "TRANSIT_ROUTED",
            description="VIF to DX gateway",
        ),
    ]


def _dx_gateway_association(a: dict) -> tuple[dict, dict | None]:
    """(association metadata, relation) of one DX gateway association."""
    g = a.get("associatedGateway") or {}
    gtype = g.get("type") or ("virtualPrivateGateway" if a.get("virtualGatewayId") else None)
    gw_id = g.get("id") or a.get("virtualGatewayId")
    region = g.get("region") or a.get("virtualGatewayRegion")
    owner = g.get("ownerAccount") or a.get("virtualGatewayOwnerAccount")
    resource = "transit-gateway" if gtype == "transitGateway" else "vpn-gateway"
    core = (a.get("associatedCoreNetwork") or {}).get("id")
    md = {
        "gateway_id": gw_id or core,
        "type": gtype or ("coreNetwork" if core else None),
        "region": region,
        "owner": owner,
        "state": a.get("associationState"),
        "allowed_prefixes": [
            p.get("cidr") for p in a.get("allowedPrefixesToDirectConnectGateway") or []
        ],
    }
    relation = rel(
        _ec2_arn(region, owner, resource, gw_id) if gw_id else core,
        EdgeType.ROUTE,
        "TRANSIT_ROUTED",
        description=f"{gtype or 'core network'} association",
        state=a.get("associationState"),
    )
    return md, relation


class DirectConnectCollectorsMixin(NetworkExtBase):
    def _dx_arn(self, kind: str, rid: str, region: str | None, owner: str | None) -> str:
        return f"arn:aws:directconnect:{region or self._region}:{owner or self._account_id}:{kind}/{rid}"

    async def _collect_direct_connect(self) -> list[CloudAsset]:
        async with self._client("directconnect") as dx:
            return await self._nx_sections(
                section("connections", self._dx_connections, dx),
                section("lags", self._dx_lags, dx),
                section("virtual_interfaces", self._dx_virtual_interfaces, dx),
            )

    async def _dx_connections(self, dx: Any) -> list[CloudAsset]:
        out = []
        async for c in self._pages(dx.describe_connections, "connections", token_in="nextToken"):
            if c.get("connectionState") in ("deleted", "deleting", "rejected"):
                continue
            cid = c["connectionId"]
            out.append(
                self._asset(
                    arn=self._dx_arn("dxcon", cid, c.get("region"), c.get("ownerAccount")),
                    name=c.get("connectionName") or cid,
                    asset_type=AssetType.DIRECT_CONNECT,
                    tags=c.get("tags"),
                    metadata={
                        "resource_kind": "dx_connection",
                        "connection_id": cid,
                        "bandwidth": c.get("bandwidth"),
                        "vlan": c.get("vlan"),
                        "partner_name": c.get("partnerName"),
                        "lag_id": c.get("lagId"),
                        "port_encryption_status": c.get("portEncryptionStatus"),
                        **_dx_link_md(c),
                    },
                    relations=[
                        rel(
                            c.get("lagId"),
                            EdgeType.CONTAINS,
                            reverse=True,
                            description="LAG member",
                        )
                    ],
                    aliases=[cid],
                )
            )
        return out

    async def _dx_lags(self, dx: Any) -> list[CloudAsset]:
        out = []
        async for lag in self._pages(dx.describe_lags, "lags", token_in="nextToken"):
            if lag.get("lagState") in ("deleted", "deleting"):
                continue
            lid = lag["lagId"]
            out.append(
                self._asset(
                    arn=self._dx_arn("dxlag", lid, lag.get("region"), lag.get("ownerAccount")),
                    name=lag.get("lagName") or lid,
                    asset_type=AssetType.DIRECT_CONNECT,
                    tags=lag.get("tags"),
                    metadata={
                        "resource_kind": "dx_lag",
                        "lag_id": lid,
                        "connections_bandwidth": lag.get("connectionsBandwidth"),
                        "number_of_connections": lag.get("numberOfConnections"),
                        "minimum_links": lag.get("minimumLinks"),
                        "allows_hosted_connections": lag.get("allowsHostedConnections"),
                        "member_connections": [
                            c.get("connectionId") for c in lag.get("connections") or []
                        ],
                        **_dx_link_md(lag),
                    },
                    aliases=[lid],
                )
            )
        return out

    async def _dx_virtual_interfaces(self, dx: Any) -> list[CloudAsset]:
        out = []
        async for v in self._pages(
            dx.describe_virtual_interfaces, "virtualInterfaces", token_in="nextToken"
        ):
            if v.get("virtualInterfaceState") in ("deleted", "deleting", "rejected"):
                continue
            vid = v["virtualInterfaceId"]
            out.append(
                self._asset(
                    arn=self._dx_arn("dxvif", vid, v.get("region"), v.get("ownerAccount")),
                    name=v.get("virtualInterfaceName") or vid,
                    asset_type=AssetType.DIRECT_CONNECT,
                    tags=v.get("tags"),
                    metadata=_dx_vif_metadata(v),
                    relations=_unique(_dx_vif_relations(v)),
                    aliases=[vid],
                )
            )
        return out

    # ------------------------------------------------------------------
    # DX gateways (global)
    # ------------------------------------------------------------------

    async def _collect_direct_connect_gateways(self) -> list[CloudAsset]:
        """DX gateways are global resources: collected once per account."""
        async with self._client("directconnect") as dx:
            gws = [
                g
                async for g in self._paginate(
                    dx, "describe_direct_connect_gateways", "directConnectGateways"
                )
                if g.get("directConnectGatewayState") not in ("deleted", "deleting")
            ]
            return await self._nx_each(self._dx_gateway_asset, gws, dx)

    async def _dx_gateway_associations(
        self, dx: Any, gid: str, relations: list[dict | None]
    ) -> list[dict]:
        associations = []
        try:
            async for a in self._paginate(
                dx,
                "describe_direct_connect_gateway_associations",
                "directConnectGatewayAssociations",
                directConnectGatewayId=gid,
            ):
                md, relation = _dx_gateway_association(a)
                associations.append(md)
                relations.append(relation)
        except Exception as exc:
            logger.debug("DX gateway associations unavailable for %s: %s", gid, exc)
        return associations

    async def _dx_gateway_attachments(
        self, dx: Any, gid: str, relations: list[dict | None]
    ) -> list[dict]:
        attachments = []
        try:
            async for a in self._paginate(
                dx,
                "describe_direct_connect_gateway_attachments",
                "directConnectGatewayAttachments",
                directConnectGatewayId=gid,
            ):
                vif = a.get("virtualInterfaceId")
                if not vif:
                    continue
                region, owner = (
                    a.get("virtualInterfaceRegion"),
                    a.get("virtualInterfaceOwnerAccount"),
                )
                attachments.append(
                    {
                        "virtual_interface_id": vif,
                        "region": region,
                        "owner": owner,
                        "state": a.get("attachmentState"),
                        "type": a.get("attachmentType"),
                    }
                )
                relations.append(
                    rel(
                        self._dx_arn("dxvif", vif, region, owner),
                        EdgeType.ROUTE,
                        "TRANSIT_ROUTED",
                        reverse=True,
                        description="VIF attachment",
                    )
                )
        except Exception as exc:
            logger.debug("DX gateway attachments unavailable for %s: %s", gid, exc)
        return attachments

    async def _dx_gateway_asset(self, dx: Any, gw: dict) -> CloudAsset:
        gid = gw["directConnectGatewayId"]
        relations: list[dict | None] = []
        associations = await self._dx_gateway_associations(dx, gid, relations)
        attachments = await self._dx_gateway_attachments(dx, gid, relations)
        owner = gw.get("ownerAccount") or self._account_id
        return self._asset(
            arn=f"arn:aws:directconnect::{owner}:dx-gateway/{gid}",
            name=gw.get("directConnectGatewayName") or gid,
            asset_type=AssetType.DIRECT_CONNECT,
            region="global",
            tags=gw.get("tags"),
            metadata={
                "resource_kind": "dx_gateway",
                "dx_gateway_id": gid,
                "amazon_side_asn": gw.get("amazonSideAsn"),
                "state": gw.get("directConnectGatewayState"),
                "owner_account": owner,
                "associations": associations,
                "vif_attachments": attachments,
            },
            relations=_unique(relations),
            aliases=[gid],
        )
