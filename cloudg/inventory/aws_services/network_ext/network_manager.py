"""Network Manager / Cloud WAN (global; API homed in us-west-2): global
networks, core networks and their attachments, transit gateway
registrations."""

from __future__ import annotations

from typing import Any

from cloudg.inventory.aws_services._base import rel
from cloudg.inventory.aws_services.network_ext._common import (
    _MAX_LIST_METADATA,
    NetworkExtBase,
    _name_tag,
    _unique,
    logger,
    section,
)
from cloudg.schema.models import AssetType, CloudAsset, EdgeType


class NetworkManagerCollectorsMixin(NetworkExtBase):
    async def _collect_network_manager(self) -> list[CloudAsset]:
        async with self._client("networkmanager", region="us-west-2") as nm:
            return await self._nx_sections(
                section("global_networks", self._nm_global_networks, nm),
                section("core_networks", self._nm_core_networks, nm),
            )

    async def _nm_global_networks(self, nm: Any) -> list[CloudAsset]:
        items = [
            g
            async for g in self._paginate(nm, "describe_global_networks", "GlobalNetworks")
            if g.get("State") not in ("DELETING",)
        ]
        return await self._nx_each(self._nm_global_network_asset, items, nm)

    async def _nm_global_network_asset(self, nm: Any, g: dict) -> CloudAsset:
        gid = g["GlobalNetworkId"]
        tgws = []
        try:
            async for r in self._paginate(
                nm,
                "get_transit_gateway_registrations",
                "TransitGatewayRegistrations",
                GlobalNetworkId=gid,
            ):
                tgws.append(
                    {"arn": r.get("TransitGatewayArn"), "state": (r.get("State") or {}).get("Code")}
                )
        except Exception as exc:
            logger.debug("TGW registrations unavailable for %s: %s", gid, exc)
        return self._asset(
            arn=g.get("GlobalNetworkArn")
            or f"arn:aws:networkmanager::{self._account_id}:global-network/{gid}",
            name=_name_tag(g.get("Tags"), g.get("Description") or gid),
            asset_type=AssetType.SERVICE_NETWORK,
            region="global",
            tags=g.get("Tags"),
            metadata={
                "resource_kind": "global_network",
                "state": g.get("State"),
                "description": g.get("Description"),
                "registered_transit_gateways": tgws,
            },
            relations=_unique(
                [
                    rel(
                        t["arn"],
                        EdgeType.MONITORS,
                        "MONITORED_BY",
                        description="registered transit gateway",
                        state=t["state"],
                    )
                    for t in tgws
                ]
            ),
            aliases=[gid],
        )

    async def _nm_core_networks(self, nm: Any) -> list[CloudAsset]:
        items = [c async for c in self._paginate(nm, "list_core_networks", "CoreNetworks")]
        return await self._nx_each(self._nm_core_network_asset, items, nm)

    async def _nm_core_network_attachments(
        self, nm: Any, cid: str, relations: list[dict | None]
    ) -> list[dict]:
        attachments = []
        try:
            async for a in self._paginate(nm, "list_attachments", "Attachments", CoreNetworkId=cid):
                attachments.append(
                    {
                        "id": a.get("AttachmentId"),
                        "type": a.get("AttachmentType"),
                        "state": a.get("State"),
                        "segment": a.get("SegmentName"),
                        "edge_location": a.get("EdgeLocation"),
                        "resource_arn": a.get("ResourceArn"),
                        "owner": a.get("OwnerAccountId"),
                    }
                )
                relations.append(
                    rel(
                        a.get("ResourceArn"),
                        EdgeType.ROUTE,
                        "TRANSIT_ROUTED",
                        description=f"{a.get('AttachmentType')} attachment",
                        segment=a.get("SegmentName"),
                        edge_location=a.get("EdgeLocation"),
                        state=a.get("State"),
                    )
                )
        except Exception as exc:
            logger.debug("Core network attachments unavailable for %s: %s", cid, exc)
        return attachments

    async def _nm_core_network_asset(self, nm: Any, c: dict) -> CloudAsset:
        cid = c["CoreNetworkId"]
        relations: list[dict | None] = [
            rel(
                c.get("GlobalNetworkId"),
                EdgeType.CONTAINS,
                reverse=True,
                description="core network of global network",
            )
        ]
        attachments = await self._nm_core_network_attachments(nm, cid, relations)
        return self._asset(
            arn=c.get("CoreNetworkArn")
            or f"arn:aws:networkmanager::{self._account_id}:core-network/{cid}",
            name=_name_tag(c.get("Tags"), c.get("Description") or cid),
            asset_type=AssetType.SERVICE_NETWORK,
            region="global",
            tags=c.get("Tags"),
            metadata={
                "resource_kind": "core_network",
                "state": c.get("State"),
                "global_network_id": c.get("GlobalNetworkId"),
                "owner_account": c.get("OwnerAccountId"),
                "segments": sorted({a["segment"] for a in attachments if a["segment"]}),
                "network_attachments": attachments[:_MAX_LIST_METADATA],
            },
            relations=_unique(relations),
            aliases=[cid],
        )
