"""VPC Lattice: service networks, services, target groups and auth
policies."""

from __future__ import annotations

from typing import Any

from cloudg.inventory.aws_services._base import error_code, rel
from cloudg.inventory.aws_services.network_ext._common import (
    _MAX_LIST_METADATA,
    NetworkExtBase,
    _policy_is_public,
    _unique,
    logger,
    section,
)
from cloudg.inventory.aws_services.platform import _dns
from cloudg.schema.models import AssetType, CloudAsset, EdgeType

# (operation, item -> associated id, edge, description, log label) of the
# service network association listings
_NETWORK_ASSOCIATIONS = (
    (
        "list_service_network_vpc_associations",
        lambda a: a.get("vpcId"),
        EdgeType.ATTACHED_TO,
        "VPC association",
        "Lattice VPC associations",
    ),
    (
        "list_service_network_service_associations",
        lambda a: a.get("serviceArn") or a.get("serviceId"),
        EdgeType.CONTAINS,
        "service association",
        "Lattice service associations",
    ),
)


class LatticeCollectorsMixin(NetworkExtBase):
    async def _collect_vpc_lattice(self) -> list[CloudAsset]:
        async with self._client("vpc-lattice") as vl:
            return await self._nx_sections(
                section("networks", self._lattice_networks, vl),
                section("services", self._lattice_services, vl),
                section("target_groups", self._lattice_target_groups, vl),
            )

    async def _lattice_auth_policy(self, vl: Any, resource: str) -> tuple[bool, str | None]:
        try:
            resp = await vl.get_auth_policy(resourceIdentifier=resource)
            return _policy_is_public(resp.get("policy")), resp.get("state")
        except Exception as exc:
            if "NotFound" not in error_code(exc):
                logger.debug("Lattice auth policy unavailable for %s: %s", resource, exc)
            return False, None

    # ------------------------------------------------------------------
    # Service networks
    # ------------------------------------------------------------------

    async def _lattice_networks(self, vl: Any) -> list[CloudAsset]:
        items = [n async for n in self._paginate(vl, "list_service_networks", "items")]
        return await self._nx_each(self._lattice_network_asset, items, vl)

    async def _lattice_network_associations(
        self, vl: Any, nid: str, relations: list[dict | None]
    ) -> list[list[Any]]:
        """Associated VPCs and services of a service network, in that order."""
        found: list[list[Any]] = []
        for op, ident, edge, description, label in _NETWORK_ASSOCIATIONS:
            ids: list[Any] = []
            found.append(ids)
            try:
                async for a in self._paginate(vl, op, "items", serviceNetworkIdentifier=nid):
                    ids.append(ident(a))
                    relations.append(
                        rel(ident(a), edge, description=description, status=a.get("status"))
                    )
            except Exception as exc:
                logger.debug("%s unavailable for %s: %s", label, nid, exc)
        return found

    async def _lattice_network_asset(self, vl: Any, n: dict) -> CloudAsset:
        nid, arn = n["id"], n["arn"]
        auth_type = None
        try:
            auth_type = (await vl.get_service_network(serviceNetworkIdentifier=nid)).get("authType")
        except Exception as exc:
            logger.debug("Lattice service network detail unavailable for %s: %s", nid, exc)
        relations: list[dict | None] = []
        vpcs, services = await self._lattice_network_associations(vl, nid, relations)
        public, policy_state = await self._lattice_auth_policy(vl, arn)
        return self._asset(
            arn=arn,
            name=n.get("name") or nid,
            asset_type=AssetType.SERVICE_NETWORK,
            metadata={
                "resource_kind": "lattice_service_network",
                "auth_type": auth_type,
                "unauthenticated": auth_type == "NONE",
                "auth_policy_public": public,
                "auth_policy_state": policy_state,
                "associated_vpcs": vpcs,
                "services": services[:_MAX_LIST_METADATA],
            },
            relations=_unique(relations),
            exposed=public,
            aliases=[nid],
        )

    # ------------------------------------------------------------------
    # Services
    # ------------------------------------------------------------------

    async def _lattice_services(self, vl: Any) -> list[CloudAsset]:
        items = [s async for s in self._paginate(vl, "list_services", "items")]
        return await self._nx_each(self._lattice_service_asset, items, vl)

    async def _lattice_listeners(self, vl: Any, sid: str) -> list[dict]:
        listeners = []
        try:
            async for lst in self._paginate(vl, "list_listeners", "items", serviceIdentifier=sid):
                listeners.append(
                    {
                        "name": lst.get("name"),
                        "protocol": lst.get("protocol"),
                        "port": lst.get("port"),
                    }
                )
        except Exception as exc:
            logger.debug("Lattice listeners unavailable for %s: %s", sid, exc)
        return listeners

    async def _lattice_service_asset(self, vl: Any, s: dict) -> CloudAsset:
        sid, arn = s["id"], s["arn"]
        svc: dict = {}
        try:
            svc = await vl.get_service(serviceIdentifier=sid)
        except Exception as exc:
            logger.debug("Lattice service detail unavailable for %s: %s", sid, exc)
        listeners = await self._lattice_listeners(vl, sid)
        public, policy_state = await self._lattice_auth_policy(vl, arn)
        dns = (s.get("dnsEntry") or svc.get("dnsEntry") or {}).get("domainName")
        custom = s.get("customDomainName") or svc.get("customDomainName")
        auth_type = svc.get("authType")
        return self._asset(
            arn=arn,
            name=s.get("name") or sid,
            asset_type=AssetType.ENDPOINT_SERVICE,
            metadata={
                "resource_kind": "lattice_service",
                "status": s.get("status"),
                "dns_name": dns,
                "custom_domain_name": custom,
                "auth_type": auth_type,
                "unauthenticated": auth_type == "NONE",
                "auth_policy_public": public,
                "auth_policy_state": policy_state,
                "listeners": listeners,
            },
            relations=[rel(svc.get("certificateArn"), EdgeType.REFERENCES, "CERTIFICATE_SECURES")],
            exposed=public,
            aliases=[sid, _dns(dns), _dns(custom)],
        )

    # ------------------------------------------------------------------
    # Target groups
    # ------------------------------------------------------------------

    async def _lattice_target_groups(self, vl: Any) -> list[CloudAsset]:
        items = [t async for t in self._paginate(vl, "list_target_groups", "items")]
        return await self._nx_each(self._lattice_target_group_asset, items, vl)

    async def _lattice_targets(self, vl: Any, tg: dict, relations: list[dict | None]) -> list[dict]:
        tid = tg["id"]
        targets = []
        try:
            async for t in self._paginate(vl, "list_targets", "items", targetGroupIdentifier=tid):
                targets.append(
                    {"id": t.get("id"), "port": t.get("port"), "status": t.get("status")}
                )
                if tg.get("type") != "IP":
                    relations.append(
                        rel(
                            t.get("id"),
                            EdgeType.LOAD_BALANCER_TARGET,
                            "LB_TARGETS_INSTANCE",
                            health=t.get("status"),
                        )
                    )
        except Exception as exc:
            logger.debug("Lattice targets unavailable for %s: %s", tid, exc)
        return targets

    async def _lattice_target_group_asset(self, vl: Any, tg: dict) -> CloudAsset:
        tid = tg["id"]
        relations: list[dict | None] = [
            rel(s, EdgeType.LOAD_BALANCER_TARGET, "LOAD_BALANCED_BY", reverse=True)
            for s in tg.get("serviceArns") or []
        ]
        targets = await self._lattice_targets(vl, tg, relations)
        return self._asset(
            arn=tg["arn"],
            name=tg.get("name") or tid,
            asset_type=AssetType.TARGET_GROUP,
            metadata={
                "resource_kind": "lattice_target_group",
                "target_type": tg.get("type"),
                "protocol": tg.get("protocol"),
                "port": tg.get("port"),
                "vpc_id": tg.get("vpcIdentifier"),
                "status": tg.get("status"),
                "targets": targets[:_MAX_LIST_METADATA],
            },
            relations=_unique(relations),
            aliases=[tid],
        )
