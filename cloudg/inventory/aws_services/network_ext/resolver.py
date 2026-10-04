"""Route 53 Resolver: endpoints, forwarding rules + VPC associations, DNS
Firewall rule group associations and query logging configurations."""

from __future__ import annotations

from typing import Any

from cloudg.inventory.aws_services._base import rel
from cloudg.inventory.aws_services.network_ext._common import (
    NetworkExtBase,
    _unique,
    logger,
    section,
)
from cloudg.inventory.aws_services.platform import _dns
from cloudg.schema.models import AssetType, CloudAsset, EdgeType


def _resolver_rule_relations(r: dict, vpcs: list[dict]) -> list[dict | None]:
    relations: list[dict | None] = [
        rel(
            r.get("ResolverEndpointId"),
            EdgeType.ROUTE,
            "DNS_RESOLVED",
            description="forwards via outbound endpoint",
        ),
    ]
    relations += [
        rel(
            a.get("VPCId"),
            EdgeType.ATTACHED_TO,
            "DNS_RESOLVED",
            description="rule associated with VPC",
            status=a.get("Status"),
        )
        for a in vpcs
    ]
    return relations


def _dns_firewall_metadata(g: dict, assoc: list[dict]) -> dict[str, Any]:
    return {
        "resource_kind": "dns_firewall_rule_group",
        "owner_id": g.get("OwnerId"),
        "share_status": g.get("ShareStatus"),
        "associations": [
            {
                "vpc_id": a.get("VpcId"),
                "priority": a.get("Priority"),
                "status": a.get("Status"),
                "mutation_protection": a.get("MutationProtection"),
                "managed_by": a.get("ManagedOwnerName"),
            }
            for a in assoc
        ],
    }


def _query_log_relations(c: dict, linked: list[dict]) -> list[dict | None]:
    relations: list[dict | None] = [rel(c.get("DestinationArn"), EdgeType.LOGS_TO, "LOGS_TO")]
    relations += [
        rel(
            a.get("ResourceId"),
            EdgeType.LOGS_TO,
            "LOGS_TO",
            reverse=True,
            description="Resolver query logging",
            status=a.get("Status"),
        )
        for a in linked
    ]
    return relations


class ResolverCollectorsMixin(NetworkExtBase):
    async def _collect_route53_resolver(self) -> list[CloudAsset]:
        async with self._client("route53resolver") as r53r:
            return await self._nx_sections(
                section("endpoints", self._resolver_endpoints, r53r),
                section("rules", self._resolver_rules, r53r),
                section("dns_firewall", self._dns_firewall, r53r),
                section("query_logging", self._resolver_query_logging, r53r),
            )

    # ------------------------------------------------------------------
    # Endpoints
    # ------------------------------------------------------------------

    async def _resolver_endpoints(self, r53r: Any) -> list[CloudAsset]:
        eps = [
            e async for e in self._paginate(r53r, "list_resolver_endpoints", "ResolverEndpoints")
        ]
        return await self._nx_each(self._resolver_endpoint_asset, eps, r53r)

    async def _resolver_endpoint_ips(self, r53r: Any, eid: str) -> list[dict]:
        ips: list[dict] = []
        try:
            async for ip in self._paginate(
                r53r, "list_resolver_endpoint_ip_addresses", "IpAddresses", ResolverEndpointId=eid
            ):
                ips.append(
                    {
                        "ip": ip.get("Ip"),
                        "ipv6": ip.get("Ipv6"),
                        "subnet_id": ip.get("SubnetId"),
                        "status": ip.get("Status"),
                    }
                )
        except Exception as exc:
            logger.debug("Resolver endpoint IPs unavailable for %s: %s", eid, exc)
        return ips

    async def _resolver_endpoint_asset(self, r53r: Any, ep: dict) -> CloudAsset:
        ips = await self._resolver_endpoint_ips(r53r, ep["Id"])
        subnets = list(dict.fromkeys(i["subnet_id"] for i in ips if i["subnet_id"]))
        relations: list[dict | None] = [rel(ep.get("HostVPCId"), EdgeType.CONTAINS, reverse=True)]
        relations += [
            rel(s, EdgeType.CONTAINS, "SUBNET_CONTAINS_INSTANCE", reverse=True) for s in subnets
        ]
        return self._asset(
            arn=ep.get("Arn") or self._arn("route53resolver", f"resolver-endpoint/{ep['Id']}"),
            name=ep.get("Name") or ep["Id"],
            asset_type=AssetType.DNS_RESOLVER,
            metadata={
                "resource_kind": "resolver_endpoint",
                "direction": ep.get("Direction"),
                "vpc_id": ep.get("HostVPCId"),
                "security_groups": ep.get("SecurityGroupIds", []),
                "ip_addresses": ips,
                "ip_count": ep.get("IpAddressCount"),
                "status": ep.get("Status"),
                "endpoint_type": ep.get("ResolverEndpointType"),
                "protocols": ep.get("Protocols", []),
                "outpost_arn": ep.get("OutpostArn"),
            },
            relations=_unique(relations),
            aliases=[ep["Id"]],
        )

    # ------------------------------------------------------------------
    # Forwarding rules
    # ------------------------------------------------------------------

    async def _resolver_rules(self, r53r: Any) -> list[CloudAsset]:
        found = [
            r
            async for r in self._paginate(r53r, "list_resolver_rules", "ResolverRules")
            if not str(r.get("Id", "")).startswith("rslvr-autodefined")
        ]
        assocs = await self._nx_group(
            r53r,
            ("list_resolver_rule_associations", "ResolverRuleAssociations"),
            "ResolverRuleId",
            "Resolver rule association",
        )
        return [self._resolver_rule_asset(r, assocs.get(r["Id"], [])) for r in found]

    def _resolver_rule_asset(self, r: dict, vpcs: list[dict]) -> CloudAsset:
        rid = r["Id"]
        owner = r.get("OwnerId")
        return self._asset(
            arn=r.get("Arn") or self._arn("route53resolver", f"resolver-rule/{rid}"),
            name=r.get("Name") or _dns(r.get("DomainName")) or rid,
            asset_type=AssetType.DNS_RESOLVER,
            metadata={
                "resource_kind": "resolver_rule",
                "domain_name": _dns(r.get("DomainName")),
                "rule_type": r.get("RuleType"),
                "status": r.get("Status"),
                "target_ips": [
                    f"{t.get('Ip') or t.get('Ipv6')}:{t.get('Port', 53)}"
                    for t in r.get("TargetIps") or []
                ],
                "resolver_endpoint_id": r.get("ResolverEndpointId"),
                "owner_id": owner,
                "share_status": r.get("ShareStatus"),
                "shared_from_other_account": bool(
                    owner and self._account_id and owner != self._account_id
                ),
                "associated_vpcs": [a.get("VPCId") for a in vpcs],
            },
            relations=_unique(_resolver_rule_relations(r, vpcs)),
            aliases=[rid],
        )

    # ------------------------------------------------------------------
    # DNS Firewall
    # ------------------------------------------------------------------

    async def _dns_firewall(self, r53r: Any) -> list[CloudAsset]:
        groups: dict[str, dict] = {}
        try:
            async for g in self._paginate(r53r, "list_firewall_rule_groups", "FirewallRuleGroups"):
                groups[g["Id"]] = g
        except Exception as exc:
            logger.debug("DNS Firewall rule group listing failed: %s", exc)
        by_group: dict[str, list[dict]] = {}
        async for a in self._paginate(
            r53r, "list_firewall_rule_group_associations", "FirewallRuleGroupAssociations"
        ):
            by_group.setdefault(a.get("FirewallRuleGroupId") or "", []).append(a)
        return [
            self._dns_firewall_asset(gid, groups.get(gid, {}), by_group.get(gid, []))
            for gid in dict.fromkeys(list(groups) + list(by_group))
            if gid
        ]

    def _dns_firewall_asset(self, gid: str, g: dict, assoc: list[dict]) -> CloudAsset:
        return self._asset(
            arn=g.get("Arn") or self._arn("route53resolver", f"firewall-rule-group/{gid}"),
            name=g.get("Name") or gid,
            asset_type=AssetType.NETWORK_FIREWALL,
            metadata=_dns_firewall_metadata(g, assoc),
            relations=_unique(
                [
                    rel(
                        a.get("VpcId"),
                        EdgeType.PROTECTS,
                        "PROTECTED_BY_NACL",
                        description="DNS Firewall",
                        priority=a.get("Priority"),
                    )
                    for a in assoc
                ]
            ),
            aliases=[gid],
        )

    # ------------------------------------------------------------------
    # Query logging
    # ------------------------------------------------------------------

    async def _resolver_query_logging(self, r53r: Any) -> list[CloudAsset]:
        configs = [
            c
            async for c in self._paginate(
                r53r, "list_resolver_query_log_configs", "ResolverQueryLogConfigs"
            )
        ]
        assocs = await self._nx_group(
            r53r,
            (
                "list_resolver_query_log_config_associations",
                "ResolverQueryLogConfigAssociations",
            ),
            "ResolverQueryLogConfigId",
            "Query log association",
        )
        return [self._query_log_asset(c, assocs.get(c["Id"], [])) for c in configs]

    def _query_log_asset(self, c: dict, linked: list[dict]) -> CloudAsset:
        cid = c["Id"]
        return self._asset(
            arn=c.get("Arn") or self._arn("route53resolver", f"resolver-query-log-config/{cid}"),
            name=c.get("Name") or cid,
            asset_type=AssetType.LOG_SINK,
            metadata={
                "resource_kind": "resolver_query_log_config",
                "destination_arn": c.get("DestinationArn"),
                "status": c.get("Status"),
                "owner_id": c.get("OwnerId"),
                "share_status": c.get("ShareStatus"),
                "association_count": c.get("AssociationCount"),
                "logged_vpcs": [a.get("ResourceId") for a in linked],
            },
            relations=_unique(_query_log_relations(c, linked)),
            aliases=[cid],
        )
