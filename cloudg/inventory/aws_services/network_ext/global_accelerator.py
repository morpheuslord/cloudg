"""Global Accelerator (global; API homed in us-west-2): accelerators ->
listeners -> endpoint groups -> endpoints."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from cloudg.inventory.aws_services._base import rel
from cloudg.inventory.aws_services.network_ext._common import (
    _MAX_LIST_METADATA,
    NetworkExtBase,
    _unique,
    logger,
    section,
)
from cloudg.inventory.aws_services.platform import _dns
from cloudg.schema.models import AssetType, CloudAsset, EdgeType


@dataclass
class _AcceleratorWalk:
    """What a walk of one accelerator's listeners has found so far."""

    listeners: list[dict] = field(default_factory=list)
    groups: list[dict] = field(default_factory=list)
    endpoints: list[dict] = field(default_factory=list)
    relations: list[dict | None] = field(default_factory=list)

    def add_group(self, eg: dict) -> None:
        region = eg.get("EndpointGroupRegion")
        descs = eg.get("EndpointDescriptions") or []
        self.groups.append(
            {
                "region": region,
                "traffic_dial": eg.get("TrafficDialPercentage"),
                "health_check": eg.get("HealthCheckProtocol"),
                "health_check_port": eg.get("HealthCheckPort"),
                "endpoints": len(descs),
            }
        )
        for d in descs:
            eid = d.get("EndpointId")
            self.endpoints.append(
                {
                    "id": eid,
                    "region": region,
                    "weight": d.get("Weight"),
                    "health": d.get("HealthState"),
                    "client_ip_preservation": d.get("ClientIPPreservationEnabled"),
                }
            )
            self.relations.append(
                rel(
                    eid,
                    EdgeType.LOAD_BALANCER_TARGET,
                    "SERVES_TRAFFIC_TO",
                    region=region,
                    health=d.get("HealthState"),
                    weight=d.get("Weight"),
                )
            )


class GlobalAcceleratorCollectorsMixin(NetworkExtBase):
    async def _collect_global_accelerator(self) -> list[CloudAsset]:
        async with self._client("globalaccelerator", region="us-west-2") as ga:
            return await self._nx_sections(
                section("standard", self._ga_accelerators, ga, False),
                section("custom_routing", self._ga_accelerators, ga, True),
            )

    async def _ga_accelerators(self, ga: Any, custom: bool) -> list[CloudAsset]:
        op = "list_custom_routing_accelerators" if custom else "list_accelerators"
        accels = [a async for a in self._paginate(ga, op, "Accelerators")]
        return await self._nx_each(self._ga_accelerator_asset, accels, ga, custom)

    async def _ga_walk(self, ga: Any, arn: str, custom: bool) -> _AcceleratorWalk:
        listener_op = "list_custom_routing_listeners" if custom else "list_listeners"
        group_op = "list_custom_routing_endpoint_groups" if custom else "list_endpoint_groups"
        walk = _AcceleratorWalk()
        try:
            async for lst in self._paginate(ga, listener_op, "Listeners", AcceleratorArn=arn):
                walk.listeners.append(
                    {
                        "ports": [
                            f"{p.get('FromPort')}-{p.get('ToPort')}"
                            for p in lst.get("PortRanges") or []
                        ],
                        "protocol": lst.get("Protocol"),
                        "client_affinity": lst.get("ClientAffinity"),
                    }
                )
                async for eg in self._paginate(
                    ga, group_op, "EndpointGroups", ListenerArn=lst["ListenerArn"]
                ):
                    walk.add_group(eg)
        except Exception as exc:
            logger.debug("Accelerator walk incomplete for %s: %s", arn, exc)
        return walk

    async def _ga_accelerator_asset(self, ga: Any, custom: bool, accel: dict) -> CloudAsset:
        arn = accel["AcceleratorArn"]
        walk = await self._ga_walk(ga, arn, custom)
        ips = [ip for s in accel.get("IpSets") or [] for ip in s.get("IpAddresses") or []]
        return self._asset(
            arn=arn,
            name=accel.get("Name") or arn,
            asset_type=AssetType.GLOBAL_ACCELERATOR,
            region="global",
            metadata={
                "accelerator_type": "custom_routing" if custom else "standard",
                "status": accel.get("Status"),
                "enabled": accel.get("Enabled"),
                "ip_address_type": accel.get("IpAddressType"),
                "ip_addresses": ips,
                "dns_name": accel.get("DnsName"),
                "dual_stack_dns_name": accel.get("DualStackDnsName"),
                "listeners": walk.listeners,
                "endpoint_groups": walk.groups,
                "endpoints": walk.endpoints[:_MAX_LIST_METADATA],
            },
            relations=_unique(walk.relations),
            exposed=True,
            aliases=[_dns(accel.get("DnsName")), _dns(accel.get("DualStackDnsName"))],
        )
