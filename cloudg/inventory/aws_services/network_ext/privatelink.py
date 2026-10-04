"""PrivateLink provider side (endpoint services -> NLB / GWLB, allowed
principals, consumer endpoints), egress-only internet gateways and
customer-managed prefix lists."""

from __future__ import annotations

from typing import Any

from cloudg.inventory.aws_services._base import principal_ref, rel
from cloudg.inventory.aws_services.network_ext._common import (
    _MAX_LIST_METADATA,
    _MAX_PREFIX_ENTRIES,
    NetworkExtBase,
    _name_tag,
    _unique,
    logger,
)
from cloudg.schema.models import AssetType, CloudAsset, EdgeType


def _endpoint_service_metadata(
    cfg: dict, principals: list[str], consumers: list[dict]
) -> dict[str, Any]:
    pdns = cfg.get("PrivateDnsNameConfiguration") or {}
    return {
        "service_id": cfg["ServiceId"],
        "service_name": cfg.get("ServiceName"),
        "service_types": [t.get("ServiceType") for t in cfg.get("ServiceType") or []],
        "state": cfg.get("ServiceState"),
        "acceptance_required": cfg.get("AcceptanceRequired"),
        "private_dns_name": cfg.get("PrivateDnsName"),
        "private_dns_verification": pdns.get("State"),
        "base_endpoint_dns_names": cfg.get("BaseEndpointDnsNames", []),
        "availability_zones": cfg.get("AvailabilityZones", []),
        "supported_regions": [r.get("Region") for r in cfg.get("SupportedRegions") or []],
        "allowed_principals": principals[:_MAX_LIST_METADATA],
        "allows_any_principal": "*" in principals,
        "consumers": consumers[:_MAX_LIST_METADATA],
        "consumer_count": len(consumers),
    }


class PrivateLinkCollectorsMixin(NetworkExtBase):
    async def _collect_egress_only_igw(self) -> list[CloudAsset]:
        assets: list[CloudAsset] = []
        async with self._client("ec2") as ec2:
            async for gw in self._paginate(
                ec2, "describe_egress_only_internet_gateways", "EgressOnlyInternetGateways"
            ):
                gid = gw["EgressOnlyInternetGatewayId"]
                vpcs = [
                    a.get("VpcId")
                    for a in gw.get("Attachments") or []
                    if a.get("State") in ("attached", "attaching")
                ]
                assets.append(
                    self._asset(
                        arn=self._arn("ec2", f"egress-only-internet-gateway/{gid}"),
                        name=_name_tag(gw.get("Tags"), gid),
                        asset_type=AssetType.INTERNET_GATEWAY,
                        tags=gw.get("Tags"),
                        metadata={"egress_only": True, "attached_vpcs": vpcs, "ip_version": "ipv6"},
                        relations=[
                            rel(v, EdgeType.ATTACHED_TO, description="egress-only IPv6 gateway")
                            for v in vpcs
                        ],
                        aliases=[gid],
                    )
                )
        return assets

    # ------------------------------------------------------------------
    # Customer-managed prefix lists
    # ------------------------------------------------------------------

    async def _collect_prefix_lists(self) -> list[CloudAsset]:
        async with self._client("ec2") as ec2:
            kwargs: dict[str, Any] = {}
            if self._account_id:
                kwargs["Filters"] = [{"Name": "owner-id", "Values": [self._account_id]}]
            lists = [
                pl
                async for pl in self._paginate(
                    ec2, "describe_managed_prefix_lists", "PrefixLists", **kwargs
                )
                if pl.get("OwnerId") != "AWS"
                and (not self._account_id or pl.get("OwnerId") == self._account_id)
            ]
            return await self._nx_each(self._prefix_list_asset, lists, ec2)

    async def _prefix_list_asset(self, ec2: Any, pl: dict) -> CloudAsset:
        pid = pl["PrefixListId"]
        entries: list[dict] = []
        count = 0
        try:
            async for e in self._paginate(
                ec2, "get_managed_prefix_list_entries", "Entries", PrefixListId=pid
            ):
                count += 1
                if len(entries) < _MAX_PREFIX_ENTRIES:
                    entries.append({"cidr": e.get("Cidr"), "description": e.get("Description")})
        except Exception as exc:
            logger.debug("Prefix list entries unavailable for %s: %s", pid, exc)
        return self._asset(
            arn=pl.get("PrefixListArn") or self._arn("ec2", f"prefix-list/{pid}"),
            name=pl.get("PrefixListName") or pid,
            asset_type=AssetType.PREFIX_LIST,
            tags=pl.get("Tags"),
            metadata={
                "prefix_list_id": pid,
                "address_family": pl.get("AddressFamily"),
                "state": pl.get("State"),
                "max_entries": pl.get("MaxEntries"),
                "version": pl.get("Version"),
                "owner_id": pl.get("OwnerId"),
                "entry_count": count,
                "entries": entries,
            },
            aliases=[pid],
        )

    # ------------------------------------------------------------------
    # PrivateLink endpoint services (provider side)
    # ------------------------------------------------------------------

    async def _collect_endpoint_services(self) -> list[CloudAsset]:
        async with self._client("ec2") as ec2:
            configs = [
                c
                async for c in self._paginate(
                    ec2, "describe_vpc_endpoint_service_configurations", "ServiceConfigurations"
                )
            ]
            if not configs:
                return []
            connections = await self._nx_group(
                ec2,
                ("describe_vpc_endpoint_connections", "VpcEndpointConnections"),
                "ServiceId",
                "Endpoint connection",
            )
            return await self._nx_each(self._endpoint_service_asset, configs, ec2, connections)

    async def _endpoint_service_principals(self, ec2: Any, sid: str) -> list[str]:
        principals: list[str] = []
        try:
            async for p in self._paginate(
                ec2,
                "describe_vpc_endpoint_service_permissions",
                "AllowedPrincipals",
                ServiceId=sid,
            ):
                if p.get("Principal"):
                    principals.append(p["Principal"])
        except Exception as exc:
            logger.debug("Endpoint service permissions unavailable for %s: %s", sid, exc)
        return principals

    def _endpoint_principal_relations(self, principals: list[str]) -> list[dict | None]:
        return [
            rel(
                ref,
                EdgeType.GRANTS_ACCESS,
                "POLICY_ALLOWS_ACTION",
                reverse=True,
                description="allowed to connect endpoints",
                cross_account=bool(self._account_id and f":{self._account_id}:" not in ref),
            )
            for ref in (principal_ref(p) for p in principals if p != "*")
        ]

    def _endpoint_consumers(self, conns: list[dict], relations: list[dict | None]) -> list[dict]:
        """Consumer endpoints of a service; records a relation per endpoint."""
        consumers = []
        for conn in conns:
            owner, eid = conn.get("VpcEndpointOwner"), conn.get("VpcEndpointId")
            region = conn.get("VpcEndpointRegion") or self._region
            target = f"arn:aws:ec2:{region}:{owner}:vpc-endpoint/{eid}" if owner and eid else eid
            consumers.append(
                {
                    "endpoint_id": eid,
                    "owner": owner,
                    "state": conn.get("VpcEndpointState"),
                    "region": region,
                }
            )
            relations.append(
                rel(
                    target,
                    EdgeType.ROUTE,
                    "SERVES_TRAFFIC_TO",
                    reverse=True,
                    description="interface endpoint consumer",
                    state=conn.get("VpcEndpointState"),
                    cross_account=bool(owner and owner != self._account_id),
                )
            )
        return consumers

    async def _endpoint_service_asset(
        self, ec2: Any, connections: dict[str, list[dict]], cfg: dict
    ) -> CloudAsset:
        sid = cfg["ServiceId"]
        principals = await self._endpoint_service_principals(ec2, sid)
        relations: list[dict | None] = [
            rel(
                lb,
                EdgeType.LOAD_BALANCER_TARGET,
                "SERVES_TRAFFIC_TO",
                description="PrivateLink service backend",
            )
            for lb in (cfg.get("NetworkLoadBalancerArns") or [])
            + (cfg.get("GatewayLoadBalancerArns") or [])
        ]
        relations += self._endpoint_principal_relations(principals)
        consumers = self._endpoint_consumers(connections.get(sid, []), relations)
        return self._asset(
            arn=self._arn("ec2", f"vpc-endpoint-service/{sid}"),
            name=_name_tag(cfg.get("Tags"), cfg.get("ServiceName") or sid),
            asset_type=AssetType.ENDPOINT_SERVICE,
            tags=cfg.get("Tags"),
            metadata=_endpoint_service_metadata(cfg, principals, consumers),
            relations=_unique(relations),
            exposed="*" in principals and not cfg.get("AcceptanceRequired"),
            aliases=[sid, cfg.get("ServiceName")],
        )
