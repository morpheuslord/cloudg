"""Transit Gateway depth: route tables (associations / propagations ->
attached resources, route sample) and peering attachments (cross-account
/ cross-region TGW peering)."""

from __future__ import annotations

from typing import Any

from cloudg.inventory.aws_services._base import rel
from cloudg.inventory.aws_services.network_ext._common import (
    _GONE_STATES,
    _MAX_TGW_ROUTES,
    NetworkExtBase,
    _ec2_arn,
    _name_tag,
    _unique,
    logger,
    section,
)
from cloudg.schema.models import AssetType, CloudAsset, EdgeType

# (operation, result key, link flag) of the route table attachment listings
_TGW_LINK_OPS = (
    ("get_transit_gateway_route_table_associations", "Associations", "associated"),
    (
        "get_transit_gateway_route_table_propagations",
        "TransitGatewayRouteTablePropagations",
        "propagated",
    ),
)


def _tgw_route_table_relations(t: dict, links: dict[str, dict[str, Any]]) -> list[dict | None]:
    relations: list[dict | None] = [
        rel(
            t.get("TransitGatewayId"),
            EdgeType.CONTAINS,
            reverse=True,
            description="transit gateway route table",
        ),
    ]
    for link in links.values():
        # Peering attachments are assets of their own; route to them.
        target = (
            link["attachment_id"] if link["resource_type"] == "peering" else link["resource_id"]
        )
        relations.append(
            rel(
                target,
                EdgeType.ROUTE,
                "TRANSIT_ROUTED",
                description=f"{link['resource_type']} attachment",
                attachment_id=link["attachment_id"],
                associated=link["associated"],
                propagated=link["propagated"],
            )
        )
    return relations


def _tgw_side(info: dict) -> str | None:
    if info.get("TransitGatewayId"):
        return _ec2_arn(
            info.get("Region"), info.get("OwnerId"), "transit-gateway", info["TransitGatewayId"]
        )
    return info.get("CoreNetworkId")


def _tgw_info_md(info: dict) -> dict:
    return {
        "tgw_id": info.get("TransitGatewayId"),
        "core_network_id": info.get("CoreNetworkId"),
        "owner_id": info.get("OwnerId"),
        "region": info.get("Region"),
    }


def _tgw_peering_metadata(p: dict, req: dict, acc: dict) -> dict[str, Any]:
    return {
        "resource_kind": "transit_gateway_peering",
        "tgw_attachment_id": p["TransitGatewayAttachmentId"],
        "state": p.get("State"),
        "status": (p.get("Status") or {}).get("Code"),
        "requester": _tgw_info_md(req),
        "accepter": _tgw_info_md(acc),
        "cross_account": bool(
            req.get("OwnerId") and acc.get("OwnerId") and req["OwnerId"] != acc["OwnerId"]
        ),
        "cross_region": bool(
            req.get("Region") and acc.get("Region") and req["Region"] != acc["Region"]
        ),
        "dynamic_routing": (p.get("Options") or {}).get("DynamicRouting"),
    }


class TransitGatewayCollectorsMixin(NetworkExtBase):
    async def _collect_tgw_routing(self) -> list[CloudAsset]:
        async with self._client("ec2") as ec2:
            return await self._nx_sections(
                section("route_tables", self._tgw_route_tables, ec2),
                section("peering_attachments", self._tgw_peering_attachments, ec2),
            )

    async def _tgw_route_tables(self, ec2: Any) -> list[CloudAsset]:
        tables = [
            t
            async for t in self._paginate(
                ec2, "describe_transit_gateway_route_tables", "TransitGatewayRouteTables"
            )
            if t.get("State") not in _GONE_STATES
        ]
        return await self._nx_each(self._tgw_route_table_asset, tables, ec2)

    async def _tgw_route_table_links(self, ec2: Any, rtb: str) -> dict[str, dict[str, Any]]:
        """Attachments associated with / propagating into a route table."""
        links: dict[str, dict[str, Any]] = {}
        for op, key, kind in _TGW_LINK_OPS:
            try:
                async for a in self._paginate(ec2, op, key, TransitGatewayRouteTableId=rtb):
                    att = a.get("TransitGatewayAttachmentId") or a.get("ResourceId")
                    if not att:
                        continue
                    entry = links.setdefault(
                        att,
                        {
                            "attachment_id": a.get("TransitGatewayAttachmentId"),
                            "resource_id": a.get("ResourceId"),
                            "resource_type": a.get("ResourceType"),
                            "associated": False,
                            "propagated": False,
                        },
                    )
                    entry[kind] = True
            except Exception as exc:
                logger.debug("%s failed for %s: %s", op, rtb, exc)
        return links

    async def _tgw_routes(self, ec2: Any, rtb: str) -> tuple[list[dict], bool]:
        """A sample of active / blackhole routes and whether it was cut."""
        routes: list[dict] = []
        truncated = False
        try:
            resp = await ec2.search_transit_gateway_routes(
                TransitGatewayRouteTableId=rtb,
                Filters=[{"Name": "state", "Values": ["active", "blackhole"]}],
                MaxResults=_MAX_TGW_ROUTES,
            )
            truncated = bool(resp.get("AdditionalRoutesAvailable"))
            for r in resp.get("Routes", []) or []:
                routes.append(
                    {
                        "destination": r.get("DestinationCidrBlock") or r.get("PrefixListId"),
                        "type": r.get("Type"),
                        "state": r.get("State"),
                        "via": [
                            x.get("ResourceId") for x in r.get("TransitGatewayAttachments") or []
                        ],
                    }
                )
        except Exception as exc:
            logger.debug("TGW route search failed for %s: %s", rtb, exc)
        return routes, truncated

    async def _tgw_route_table_asset(self, ec2: Any, t: dict) -> CloudAsset:
        rtb = t["TransitGatewayRouteTableId"]
        links = await self._tgw_route_table_links(ec2, rtb)
        routes, truncated = await self._tgw_routes(ec2, rtb)
        return self._asset(
            arn=self._arn("ec2", f"transit-gateway-route-table/{rtb}"),
            name=_name_tag(t.get("Tags"), rtb),
            asset_type=AssetType.ROUTE_TABLE,
            tags=t.get("Tags"),
            metadata={
                "resource_kind": "transit_gateway_route_table",
                "tgw_route_table_id": rtb,
                "tgw_id": t.get("TransitGatewayId"),
                "state": t.get("State"),
                "default_association": t.get("DefaultAssociationRouteTable"),
                "default_propagation": t.get("DefaultPropagationRouteTable"),
                "associated_attachments": [v for v in links.values() if v["associated"]],
                "propagating_attachments": [v for v in links.values() if v["propagated"]],
                "tgw_routes": routes,
                "tgw_routes_truncated": truncated,
            },
            relations=_unique(_tgw_route_table_relations(t, links)),
            aliases=[rtb],
        )

    async def _tgw_peering_attachments(self, ec2: Any) -> list[CloudAsset]:
        out = []
        async for p in self._paginate(
            ec2,
            "describe_transit_gateway_peering_attachments",
            "TransitGatewayPeeringAttachments",
        ):
            if p.get("State") in _GONE_STATES:
                continue
            out.append(self._tgw_peering_asset(p))
        return out

    def _tgw_peering_asset(self, p: dict) -> CloudAsset:
        aid = p["TransitGatewayAttachmentId"]
        req, acc = p.get("RequesterTgwInfo") or {}, p.get("AccepterTgwInfo") or {}
        return self._asset(
            arn=self._arn("ec2", f"transit-gateway-attachment/{aid}"),
            name=_name_tag(p.get("Tags"), aid),
            asset_type=AssetType.PEERING_CONNECTION,
            tags=p.get("Tags"),
            metadata=_tgw_peering_metadata(p, req, acc),
            relations=_unique(
                [
                    rel(
                        _tgw_side(req),
                        EdgeType.PEERING,
                        "TRANSIT_ROUTED",
                        reverse=True,
                        description="requester transit gateway",
                    ),
                    rel(
                        _tgw_side(acc),
                        EdgeType.PEERING,
                        "TRANSIT_ROUTED",
                        description="accepter transit gateway",
                    ),
                ]
            ),
            aliases=[aid],
        )
