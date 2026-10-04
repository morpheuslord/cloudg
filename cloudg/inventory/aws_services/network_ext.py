"""Extended network fabric: hybrid connectivity, edge, PrivateLink, DNS
resolution and service networking.

- Site-to-site VPN: connections (-> customer gateway, VGW / TGW / Cloud
  WAN, tunnel status, static routes), virtual private gateways (-> VPCs),
  customer gateways (public IP, BGP ASN).
- Egress-only internet gateways and customer-managed prefix lists.
- Transit Gateway depth: route tables (associations / propagations ->
  attached resources, route sample) and peering attachments (cross-account
  / cross-region TGW peering).
- PrivateLink provider side: endpoint services -> NLB / GWLB, allowed
  principals, consumer endpoints (and their accounts).
- API Gateway depth: authorizers (-> Lambda / Cognito), VPC links
  (-> NLBs, subnets, SGs), custom domains (-> APIs, certificates; their
  regional / CloudFront names are aliases so Route 53 records resolve).
- CloudFront (deep, overrides the shallow base collector): CNAMEs,
  certificates, typed origins (S3 / ALB / API / VPC origins), OAC / OAI,
  Lambda@Edge and CloudFront Functions, access-log bucket, WAF.
- Route 53 Resolver: endpoints, forwarding rules + VPC associations, DNS
  Firewall rule group associations, query logging configurations.
- Direct Connect: connections, LAGs, virtual interfaces, DX gateways and
  their VGW / TGW associations.
- Global Accelerator: accelerators -> listeners -> endpoint groups ->
  endpoints.
- ELBv2 listeners and listener rules (forward / authenticate / redirect).
- VPC Lattice: service networks, services, target groups, auth policies.
- Network Manager / Cloud WAN: global networks, core networks and their
  attachments, transit gateway registrations.

Secrets are never collected: VPN tunnel options and customer gateway
configuration (pre-shared keys), Direct Connect BGP auth keys and MACsec
keys, OIDC client secrets and CloudFront origin custom header values are
all dropped.
"""

from __future__ import annotations

import logging
import re
from typing import Any, Awaitable, Callable

from cloudg.inventory.aws_services._base import (
    AWSServiceMixin,
    error_code,
    gather_limited,
    policy_principals,
    policy_statements,
    principal_ref,
    rel,
)
from cloudg.inventory.aws_services.platform import _dns
from cloudg.schema.models import AssetType, CloudAsset, EdgeType

logger = logging.getLogger(__name__)

_MAX_TGW_ROUTES = 200
_MAX_PREFIX_ENTRIES = 50
_MAX_RULES_PER_LISTENER = 100
_MAX_LIST_METADATA = 100

_LAMBDA_URI_RE = re.compile(r"functions/(arn:aws[^/]+)/invocations")
_S3_ORIGIN_RE = re.compile(r"^([a-z0-9][a-z0-9.\-]*?)\.s3(?:[.-][a-z0-9-]+)*\.amazonaws\.com$")
_EXECUTE_API_RE = re.compile(r"^([a-z0-9]{10})\.execute-api\.[a-z0-9-]+\.amazonaws\.com$")
_COGNITO_ISSUER_RE = re.compile(r"^https://cognito-idp\.[a-z0-9-]+\.amazonaws\.com/([\w-]+_[0-9A-Za-z]+)")
_S3_URI_RE = re.compile(r"^s3://([^/]+)")

_GONE_STATES = {"deleted", "deleting"}


def _unique(relations: list[dict | None]) -> list[dict]:
    """Drop empty and duplicate (target, edge, direction) relations."""
    seen: set[tuple[Any, ...]] = set()
    out: list[dict] = []
    for r in relations:
        if not r:
            continue
        key = (r["target"], r["edge"], r.get("reverse", False))
        if key in seen:
            continue
        seen.add(key)
        out.append(r)
    return out


def _name_tag(tags: Any, default: str) -> str:
    for t in tags or []:
        if isinstance(t, dict) and t.get("Key") == "Name" and t.get("Value"):
            return str(t["Value"])
    return default


def _policy_is_public(policy: Any) -> bool:
    """True when an Allow statement grants ``*`` without any condition."""
    for st in policy_statements(policy):
        if st.get("Effect") != "Allow" or st.get("Condition"):
            continue
        if "*" in policy_principals(st).get("AWS", []):
            return True
    return False


def _bucket_from_domain(domain: str) -> str | None:
    m = _S3_ORIGIN_RE.match(_dns(domain))
    return m.group(1) if m else None


def _ec2_arn(region: str | None, owner: str | None, resource: str, rid: str | None) -> str | None:
    """Full EC2 ARN for a resource in a (possibly other) account/region, so
    the linker can resolve it or materialise the external account."""
    if not rid:
        return None
    if region and owner and owner.isdigit():
        return f"arn:aws:ec2:{region}:{owner}:{resource}/{rid}"
    return rid


class NetworkExtCollectorsMixin(AWSServiceMixin):
    def _network_ext_tasks(self) -> dict[str, tuple[Any, str, bool]]:
        """name -> (collector callable, service family, is_global)."""
        return {
            "vpn": (self._collect_vpn, "hybrid", False),
            "egress_only_igw": (self._collect_egress_only_igw, "network", False),
            "prefix_lists": (self._collect_prefix_lists, "network", False),
            "tgw_routing": (self._collect_tgw_routing, "network", False),
            "endpoint_services": (self._collect_endpoint_services, "network", False),
            "apigateway_authorizers": (self._collect_apigateway_authorizers, "serverless", False),
            "apigateway_vpc_links": (self._collect_apigateway_vpc_links, "serverless", False),
            "apigateway_domains": (self._collect_apigateway_domains, "serverless", False),
            "route53_resolver": (self._collect_route53_resolver, "dns", False),
            "direct_connect": (self._collect_direct_connect, "hybrid", False),
            "direct_connect_gateways": (self._collect_direct_connect_gateways, "hybrid", True),
            "global_accelerator": (self._collect_global_accelerator, "network", True),
            "elb_rules": (self._collect_elb_rules, "network", False),
            "vpc_lattice": (self._collect_vpc_lattice, "network", False),
            "network_manager": (self._collect_network_manager, "hybrid", True),
        }

    async def _nx_sections(self, *sections: Callable[[], Awaitable[list[CloudAsset] | None]]) -> list[CloudAsset]:
        """Run independent listing sections of one collector.

        A failing section is logged and skipped; the collector only fails
        (raises) when every section failed, so coverage reports it.
        """
        assets: list[CloudAsset] = []
        errors: list[BaseException] = []
        for section in sections:
            try:
                assets.extend(await section() or [])
            except Exception as exc:
                errors.append(exc)
                logger.info("%s skipped: %s", getattr(section, "__name__", "section"), error_code(exc))
        if errors and len(errors) == len(sections):
            raise errors[0]
        return assets

    # ------------------------------------------------------------------
    # Site-to-site VPN, egress-only IGWs, prefix lists
    # ------------------------------------------------------------------

    async def _collect_vpn(self) -> list[CloudAsset]:
        async with self._client("ec2") as ec2:

            async def vpn_connections() -> list[CloudAsset]:
                out = []
                for vpn in (await ec2.describe_vpn_connections()).get("VpnConnections", []) or []:
                    if vpn.get("State") in _GONE_STATES:
                        continue
                    vid = vpn["VpnConnectionId"]
                    opts = vpn.get("Options") or {}
                    tunnels = [
                        {
                            "outside_ip": t.get("OutsideIpAddress"),
                            "status": t.get("Status"),
                            "accepted_routes": t.get("AcceptedRouteCount"),
                            "last_status_change": str(t.get("LastStatusChange") or ""),
                        }
                        for t in vpn.get("VgwTelemetry") or []
                    ]
                    relations: list[dict | None] = [
                        rel(vpn.get("CustomerGatewayId"), EdgeType.ROUTE, "TRANSIT_ROUTED",
                            description="on-premises side (customer gateway)"),
                        rel(vpn.get("VpnGatewayId"), EdgeType.ATTACHED_TO, "TRANSIT_ROUTED",
                            description="terminates on virtual private gateway"),
                        rel(vpn.get("TransitGatewayId"), EdgeType.ATTACHED_TO, "TRANSIT_ROUTED",
                            description="terminates on transit gateway"),
                        rel(vpn.get("CoreNetworkArn"), EdgeType.ATTACHED_TO, "TRANSIT_ROUTED",
                            description="terminates on Cloud WAN core network"),
                        rel(vpn.get("PreSharedKeyArn"), EdgeType.REFERENCES, "DEPENDS_ON",
                            description="tunnel pre-shared key secret"),
                    ]
                    relations += [rel(t.get("CertificateArn"), EdgeType.REFERENCES, "CERTIFICATE_SECURES")
                                  for t in vpn.get("VgwTelemetry") or []]
                    out.append(
                        self._asset(
                            arn=self._arn("ec2", f"vpn-connection/{vid}"),
                            name=_name_tag(vpn.get("Tags"), vid),
                            asset_type=AssetType.VPN_CONNECTION,
                            tags=vpn.get("Tags"),
                            metadata={
                                "vpn_connection_id": vid,
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
                                    {"cidr": r.get("DestinationCidrBlock"), "source": r.get("Source"), "state": r.get("State")}
                                    for r in vpn.get("Routes") or []
                                ],
                            },
                            relations=_unique(relations),
                            aliases=[vid],
                        )
                    )
                return out

            async def vpn_gateways() -> list[CloudAsset]:
                out = []
                for gw in (await ec2.describe_vpn_gateways()).get("VpnGateways", []) or []:
                    if gw.get("State") in _GONE_STATES:
                        continue
                    gid = gw["VpnGatewayId"]
                    attachments = [{"vpc_id": a.get("VpcId"), "state": a.get("State")} for a in gw.get("VpcAttachments") or []]
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
                                rel(a["vpc_id"], EdgeType.ATTACHED_TO, description="VPC attachment", state=a["state"])
                                for a in attachments
                                if a["state"] in ("attached", "attaching")
                            ],
                            aliases=[gid],
                        )
                    )
                return out

            async def customer_gateways() -> list[CloudAsset]:
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
                            relations=[rel(cgw.get("CertificateArn"), EdgeType.REFERENCES, "CERTIFICATE_SECURES")],
                            aliases=[cid],
                        )
                    )
                return out

            return await self._nx_sections(vpn_connections, vpn_gateways, customer_gateways)

    async def _collect_egress_only_igw(self) -> list[CloudAsset]:
        assets: list[CloudAsset] = []
        async with self._client("ec2") as ec2:
            async for gw in self._paginate(ec2, "describe_egress_only_internet_gateways", "EgressOnlyInternetGateways"):
                gid = gw["EgressOnlyInternetGatewayId"]
                vpcs = [a.get("VpcId") for a in gw.get("Attachments") or [] if a.get("State") in ("attached", "attaching")]
                assets.append(
                    self._asset(
                        arn=self._arn("ec2", f"egress-only-internet-gateway/{gid}"),
                        name=_name_tag(gw.get("Tags"), gid),
                        asset_type=AssetType.INTERNET_GATEWAY,
                        tags=gw.get("Tags"),
                        metadata={"egress_only": True, "attached_vpcs": vpcs, "ip_version": "ipv6"},
                        relations=[rel(v, EdgeType.ATTACHED_TO, description="egress-only IPv6 gateway") for v in vpcs],
                        aliases=[gid],
                    )
                )
        return assets

    async def _collect_prefix_lists(self) -> list[CloudAsset]:
        async with self._client("ec2") as ec2:
            kwargs: dict[str, Any] = {}
            if self._account_id:
                kwargs["Filters"] = [{"Name": "owner-id", "Values": [self._account_id]}]
            lists = [
                pl async for pl in self._paginate(ec2, "describe_managed_prefix_lists", "PrefixLists", **kwargs)
                if pl.get("OwnerId") != "AWS" and (not self._account_id or pl.get("OwnerId") == self._account_id)
            ]

            async def detail(pl: dict) -> CloudAsset:
                pid = pl["PrefixListId"]
                entries: list[dict] = []
                count = 0
                try:
                    async for e in self._paginate(ec2, "get_managed_prefix_list_entries", "Entries", PrefixListId=pid):
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

            results = await gather_limited([lambda pl=pl: detail(pl) for pl in lists])
            return [a for a in results if a]

    # ------------------------------------------------------------------
    # Transit Gateway route tables and peering
    # ------------------------------------------------------------------

    async def _collect_tgw_routing(self) -> list[CloudAsset]:
        async with self._client("ec2") as ec2:

            async def route_tables() -> list[CloudAsset]:
                tables = [
                    t async for t in self._paginate(ec2, "describe_transit_gateway_route_tables", "TransitGatewayRouteTables")
                    if t.get("State") not in _GONE_STATES
                ]

                async def detail(t: dict) -> CloudAsset:
                    rtb = t["TransitGatewayRouteTableId"]
                    links: dict[str, dict[str, Any]] = {}
                    for op, key, kind in (
                        ("get_transit_gateway_route_table_associations", "Associations", "associated"),
                        ("get_transit_gateway_route_table_propagations", "TransitGatewayRouteTablePropagations", "propagated"),
                    ):
                        try:
                            async for a in self._paginate(ec2, op, key, TransitGatewayRouteTableId=rtb):
                                att = a.get("TransitGatewayAttachmentId") or a.get("ResourceId")
                                if not att:
                                    continue
                                entry = links.setdefault(att, {
                                    "attachment_id": a.get("TransitGatewayAttachmentId"),
                                    "resource_id": a.get("ResourceId"),
                                    "resource_type": a.get("ResourceType"),
                                    "associated": False,
                                    "propagated": False,
                                })
                                entry[kind] = True
                        except Exception as exc:
                            logger.debug("%s failed for %s: %s", op, rtb, exc)
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
                            routes.append({
                                "destination": r.get("DestinationCidrBlock") or r.get("PrefixListId"),
                                "type": r.get("Type"),
                                "state": r.get("State"),
                                "via": [x.get("ResourceId") for x in r.get("TransitGatewayAttachments") or []],
                            })
                    except Exception as exc:
                        logger.debug("TGW route search failed for %s: %s", rtb, exc)

                    relations: list[dict | None] = [
                        rel(t.get("TransitGatewayId"), EdgeType.CONTAINS, reverse=True, description="transit gateway route table"),
                    ]
                    for link in links.values():
                        # Peering attachments are assets of their own; route to them.
                        target = link["attachment_id"] if link["resource_type"] == "peering" else link["resource_id"]
                        relations.append(
                            rel(target, EdgeType.ROUTE, "TRANSIT_ROUTED",
                                description=f"{link['resource_type']} attachment",
                                attachment_id=link["attachment_id"],
                                associated=link["associated"],
                                propagated=link["propagated"])
                        )
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
                        relations=_unique(relations),
                        aliases=[rtb],
                    )

                results = await gather_limited([lambda t=t: detail(t) for t in tables])
                return [a for a in results if a]

            async def peering_attachments() -> list[CloudAsset]:
                out = []
                async for p in self._paginate(ec2, "describe_transit_gateway_peering_attachments", "TransitGatewayPeeringAttachments"):
                    if p.get("State") in _GONE_STATES:
                        continue
                    aid = p["TransitGatewayAttachmentId"]
                    req, acc = p.get("RequesterTgwInfo") or {}, p.get("AccepterTgwInfo") or {}

                    def side(info: dict) -> str | None:
                        if info.get("TransitGatewayId"):
                            return _ec2_arn(info.get("Region"), info.get("OwnerId"), "transit-gateway", info["TransitGatewayId"])
                        return info.get("CoreNetworkId")

                    def info_md(info: dict) -> dict:
                        return {"tgw_id": info.get("TransitGatewayId"), "core_network_id": info.get("CoreNetworkId"),
                                "owner_id": info.get("OwnerId"), "region": info.get("Region")}

                    out.append(
                        self._asset(
                            arn=self._arn("ec2", f"transit-gateway-attachment/{aid}"),
                            name=_name_tag(p.get("Tags"), aid),
                            asset_type=AssetType.PEERING_CONNECTION,
                            tags=p.get("Tags"),
                            metadata={
                                "resource_kind": "transit_gateway_peering",
                                "tgw_attachment_id": aid,
                                "state": p.get("State"),
                                "status": (p.get("Status") or {}).get("Code"),
                                "requester": info_md(req),
                                "accepter": info_md(acc),
                                "cross_account": bool(req.get("OwnerId") and acc.get("OwnerId") and req["OwnerId"] != acc["OwnerId"]),
                                "cross_region": bool(req.get("Region") and acc.get("Region") and req["Region"] != acc["Region"]),
                                "dynamic_routing": (p.get("Options") or {}).get("DynamicRouting"),
                            },
                            relations=_unique([
                                rel(side(req), EdgeType.PEERING, "TRANSIT_ROUTED", reverse=True, description="requester transit gateway"),
                                rel(side(acc), EdgeType.PEERING, "TRANSIT_ROUTED", description="accepter transit gateway"),
                            ]),
                            aliases=[aid],
                        )
                    )
                return out

            return await self._nx_sections(route_tables, peering_attachments)

    # ------------------------------------------------------------------
    # PrivateLink (provider side)
    # ------------------------------------------------------------------

    async def _collect_endpoint_services(self) -> list[CloudAsset]:
        async with self._client("ec2") as ec2:
            configs = [
                c async for c in self._paginate(ec2, "describe_vpc_endpoint_service_configurations", "ServiceConfigurations")
            ]
            if not configs:
                return []
            connections: dict[str, list[dict]] = {}
            try:
                async for c in self._paginate(ec2, "describe_vpc_endpoint_connections", "VpcEndpointConnections"):
                    connections.setdefault(c.get("ServiceId") or "", []).append(c)
            except Exception as exc:
                logger.debug("Endpoint connection listing failed: %s", exc)

            async def detail(cfg: dict) -> CloudAsset:
                sid = cfg["ServiceId"]
                principals: list[str] = []
                try:
                    async for p in self._paginate(ec2, "describe_vpc_endpoint_service_permissions", "AllowedPrincipals", ServiceId=sid):
                        if p.get("Principal"):
                            principals.append(p["Principal"])
                except Exception as exc:
                    logger.debug("Endpoint service permissions unavailable for %s: %s", sid, exc)
                relations: list[dict | None] = [
                    rel(lb, EdgeType.LOAD_BALANCER_TARGET, "SERVES_TRAFFIC_TO", description="PrivateLink service backend")
                    for lb in (cfg.get("NetworkLoadBalancerArns") or []) + (cfg.get("GatewayLoadBalancerArns") or [])
                ]
                public = "*" in principals
                for p in principals:
                    if p == "*":
                        continue
                    ref = principal_ref(p)
                    relations.append(
                        rel(ref, EdgeType.GRANTS_ACCESS, "POLICY_ALLOWS_ACTION", reverse=True,
                            description="allowed to connect endpoints",
                            cross_account=bool(self._account_id and f":{self._account_id}:" not in ref))
                    )
                consumers = []
                for conn in connections.get(sid, []):
                    owner, eid = conn.get("VpcEndpointOwner"), conn.get("VpcEndpointId")
                    region = conn.get("VpcEndpointRegion") or self._region
                    target = f"arn:aws:ec2:{region}:{owner}:vpc-endpoint/{eid}" if owner and eid else eid
                    consumers.append({"endpoint_id": eid, "owner": owner, "state": conn.get("VpcEndpointState"), "region": region})
                    relations.append(
                        rel(target, EdgeType.ROUTE, "SERVES_TRAFFIC_TO", reverse=True,
                            description="interface endpoint consumer", state=conn.get("VpcEndpointState"),
                            cross_account=bool(owner and owner != self._account_id))
                    )
                pdns = cfg.get("PrivateDnsNameConfiguration") or {}
                return self._asset(
                    arn=self._arn("ec2", f"vpc-endpoint-service/{sid}"),
                    name=_name_tag(cfg.get("Tags"), cfg.get("ServiceName") or sid),
                    asset_type=AssetType.ENDPOINT_SERVICE,
                    tags=cfg.get("Tags"),
                    metadata={
                        "service_id": sid,
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
                        "allows_any_principal": public,
                        "consumers": consumers[:_MAX_LIST_METADATA],
                        "consumer_count": len(consumers),
                    },
                    relations=_unique(relations),
                    exposed=public and not cfg.get("AcceptanceRequired"),
                    aliases=[sid, cfg.get("ServiceName")],
                )

            results = await gather_limited([lambda c=c: detail(c) for c in configs])
            return [a for a in results if a]

    # ------------------------------------------------------------------
    # API Gateway: authorizers, VPC links, custom domains
    # ------------------------------------------------------------------

    async def _collect_apigateway_authorizers(self) -> list[CloudAsset]:

        async def rest() -> list[CloudAsset]:
            out: list[CloudAsset] = []
            async with self._client("apigateway") as apigw:
                apis = [a async for a in self._paginate(apigw, "get_rest_apis", "items")]

                async def per_api(api: dict) -> list[CloudAsset]:
                    api_id = api["id"]
                    api_arn = f"arn:aws:apigateway:{self._region}::/restapis/{api_id}"
                    found = []
                    async for auth in self._paginate(apigw, "get_authorizers", "items", restApiId=api_id):
                        m = _LAMBDA_URI_RE.search(auth.get("authorizerUri") or "")
                        relations: list[dict | None] = [
                            rel(api_arn, EdgeType.REFERENCES, "DEPENDS_ON", reverse=True, description="API authorizer"),
                            rel(m.group(1) if m else None, EdgeType.INVOKES, "INVOKES", description="Lambda authorizer"),
                            rel(auth.get("authorizerCredentials"), EdgeType.ASSUMES_ROLE, "RUNS_ON"),
                        ]
                        relations += [rel(p, EdgeType.REFERENCES, "DEPENDS_ON", description="Cognito user pool")
                                      for p in auth.get("providerARNs") or []]
                        found.append(
                            self._asset(
                                arn=f"{api_arn}/authorizers/{auth['id']}",
                                name=f"{api.get('name', api_id)}/{auth.get('name', auth['id'])}",
                                asset_type=AssetType.AUTHORIZER,
                                metadata={
                                    "resource_kind": "apigateway_authorizer",
                                    "api_id": api_id,
                                    "api_type": "REST",
                                    "authorizer_type": auth.get("type"),
                                    "auth_type": auth.get("authType"),
                                    "identity_source": auth.get("identitySource"),
                                    "result_ttl": auth.get("authorizerResultTtlInSeconds"),
                                },
                                relations=_unique(relations),
                            )
                        )
                    return found

                for res in await gather_limited([lambda a=a: per_api(a) for a in apis]):
                    out.extend(res or [])
            return out

        async def http() -> list[CloudAsset]:
            out: list[CloudAsset] = []
            async with self._client("apigatewayv2") as apigw:
                apis = [a async for a in self._paginate(apigw, "get_apis", "Items")]

                async def per_api(api: dict) -> list[CloudAsset]:
                    api_id = api["ApiId"]
                    api_arn = f"arn:aws:apigateway:{self._region}::/apis/{api_id}"
                    auths = [a async for a in self._paginate(apigw, "get_authorizers", "Items", ApiId=api_id)]
                    if not auths:
                        return []
                    routes_by_auth: dict[str, list[str]] = {}
                    try:
                        async for route in self._paginate(apigw, "get_routes", "Items", ApiId=api_id):
                            if route.get("AuthorizerId"):
                                routes_by_auth.setdefault(route["AuthorizerId"], []).append(route.get("RouteKey"))
                    except Exception as exc:
                        logger.debug("HTTP API route listing failed for %s: %s", api_id, exc)
                    found = []
                    for auth in auths:
                        aid = auth["AuthorizerId"]
                        m = _LAMBDA_URI_RE.search(auth.get("AuthorizerUri") or "")
                        issuer = (auth.get("JwtConfiguration") or {}).get("Issuer") or ""
                        pool = _COGNITO_ISSUER_RE.match(issuer)
                        routes = routes_by_auth.get(aid, [])
                        found.append(
                            self._asset(
                                arn=f"{api_arn}/authorizers/{aid}",
                                name=f"{api.get('Name', api_id)}/{auth.get('Name', aid)}",
                                asset_type=AssetType.AUTHORIZER,
                                metadata={
                                    "resource_kind": "apigateway_authorizer",
                                    "api_id": api_id,
                                    "api_type": api.get("ProtocolType"),
                                    "authorizer_type": auth.get("AuthorizerType"),
                                    "jwt_issuer": issuer or None,
                                    "jwt_audience_count": len((auth.get("JwtConfiguration") or {}).get("Audience") or []),
                                    "identity_source": auth.get("IdentitySource"),
                                    "result_ttl": auth.get("AuthorizerResultTtlInSeconds"),
                                    "route_count": len(routes),
                                    "routes": routes[:_MAX_LIST_METADATA],
                                },
                                relations=_unique([
                                    rel(api_arn, EdgeType.REFERENCES, "DEPENDS_ON", reverse=True, description="API authorizer"),
                                    rel(m.group(1) if m else None, EdgeType.INVOKES, "INVOKES", description="Lambda authorizer"),
                                    rel(auth.get("AuthorizerCredentialsArn"), EdgeType.ASSUMES_ROLE, "RUNS_ON"),
                                    rel(pool.group(1) if pool else None, EdgeType.REFERENCES, "DEPENDS_ON",
                                        description="Cognito user pool (JWT issuer)"),
                                ]),
                            )
                        )
                    return found

                for res in await gather_limited([lambda a=a: per_api(a) for a in apis]):
                    out.extend(res or [])
            return out

        return await self._nx_sections(rest, http)

    async def _collect_apigateway_vpc_links(self) -> list[CloudAsset]:

        async def rest() -> list[CloudAsset]:
            out = []
            async with self._client("apigateway") as apigw:
                async for link in self._paginate(apigw, "get_vpc_links", "items"):
                    lid = link["id"]
                    out.append(
                        self._asset(
                            arn=f"arn:aws:apigateway:{self._region}::/vpclinks/{lid}",
                            name=link.get("name", lid),
                            asset_type=AssetType.VPC_LINK,
                            tags=link.get("tags"),
                            metadata={"vpc_link_id": lid, "api_type": "REST", "status": link.get("status"),
                                      "target_arns": link.get("targetArns", [])},
                            relations=[rel(t, EdgeType.LOAD_BALANCER_TARGET, "SERVES_TRAFFIC_TO", description="VPC link target")
                                       for t in link.get("targetArns") or []],
                            aliases=[lid],
                        )
                    )
            return out

        async def http() -> list[CloudAsset]:
            out = []
            async with self._client("apigatewayv2") as apigw:
                async for link in self._pages(apigw.get_vpc_links, "Items"):
                    lid = link["VpcLinkId"]
                    out.append(
                        self._asset(
                            arn=f"arn:aws:apigateway:{self._region}::/vpclinks/{lid}",
                            name=link.get("Name", lid),
                            asset_type=AssetType.VPC_LINK,
                            tags=link.get("Tags"),
                            metadata={
                                "vpc_link_id": lid,
                                "api_type": "HTTP",
                                "status": link.get("VpcLinkStatus"),
                                "version": link.get("VpcLinkVersion"),
                                "subnet_ids": link.get("SubnetIds", []),
                                "security_groups": link.get("SecurityGroupIds", []),
                            },
                            relations=[rel(s, EdgeType.CONTAINS, "SUBNET_CONTAINS_INSTANCE", reverse=True)
                                       for s in link.get("SubnetIds") or []],
                            aliases=[lid],
                        )
                    )
            return out

        return await self._nx_sections(rest, http)

    async def _collect_apigateway_domains(self) -> list[CloudAsset]:
        """Custom domain names of REST and HTTP/WebSocket APIs, merged per
        domain (both API generations share the same domain namespace)."""
        domains: dict[str, dict[str, Any]] = {}

        def entry(key: str, name: str, arn: str | None) -> dict[str, Any]:
            e = domains.setdefault(key, {
                "name": name,
                "arn": arn or f"arn:aws:apigateway:{self._region}::/domainnames/{name}",
                "aliases": [],
                "relations": [],
                "tags": {},
                "mappings": [],
                "endpoint_types": set(),
                "metadata": {},
            })
            return e

        async def rest() -> None:
            async with self._client("apigateway") as apigw:
                async for d in self._paginate(apigw, "get_domain_names", "items"):
                    name = d["domainName"]
                    key = f"{name}+{d['domainNameId']}" if d.get("domainNameId") else name
                    e = entry(key.lower(), name, d.get("domainNameArn"))
                    e["tags"].update(d.get("tags") or {})
                    cfg = d.get("endpointConfiguration") or {}
                    e["endpoint_types"].update(cfg.get("types") or [])
                    e["aliases"] += [_dns(d.get("regionalDomainName")), _dns(d.get("distributionDomainName"))]
                    for cert in (d.get("certificateArn"), d.get("regionalCertificateArn")):
                        e["relations"].append(rel(cert, EdgeType.REFERENCES, "CERTIFICATE_SECURES"))
                    e["relations"] += [rel(v, EdgeType.ROUTE, "SERVES_TRAFFIC_TO", reverse=True, description="private domain endpoint")
                                       for v in cfg.get("vpcEndpointIds") or []]
                    mtls = d.get("mutualTlsAuthentication") or {}
                    bucket = _S3_URI_RE.match(mtls.get("truststoreUri") or "")
                    if bucket:
                        e["relations"].append(rel(f"arn:aws:s3:::{bucket.group(1)}", EdgeType.REFERENCES, "DEPENDS_ON",
                                                  description="mTLS truststore"))
                    e["metadata"].update({
                        "status": d.get("domainNameStatus"),
                        "security_policy": d.get("securityPolicy"),
                        "regional_domain_name": d.get("regionalDomainName"),
                        "distribution_domain_name": d.get("distributionDomainName"),
                        "mutual_tls": bool(mtls.get("truststoreUri")),
                        "private": bool(d.get("domainNameId")),
                    })
                    kwargs = {"domainName": name}
                    if d.get("domainNameId"):
                        kwargs["domainNameId"] = d["domainNameId"]
                    try:
                        async for m in self._paginate(apigw, "get_base_path_mappings", "items", **kwargs):
                            e["mappings"].append({"path": m.get("basePath"), "api_id": m.get("restApiId"), "stage": m.get("stage")})
                            e["relations"].append(
                                rel(f"arn:aws:apigateway:{self._region}::/restapis/{m.get('restApiId')}" if m.get("restApiId") else None,
                                    EdgeType.ROUTE, "SERVES_TRAFFIC_TO", base_path=m.get("basePath"), stage=m.get("stage"))
                            )
                    except Exception as exc:
                        logger.debug("Base path mappings unavailable for %s: %s", name, exc)

        async def http() -> None:
            async with self._client("apigatewayv2") as apigw:
                async for d in self._paginate(apigw, "get_domain_names", "Items"):
                    name = d["DomainName"]
                    e = entry(name.lower(), name, d.get("DomainNameArn"))
                    e["tags"].update(d.get("Tags") or {})
                    for cfg in d.get("DomainNameConfigurations") or []:
                        e["endpoint_types"].add(cfg.get("EndpointType"))
                        e["aliases"].append(_dns(cfg.get("ApiGatewayDomainName")))
                        e["relations"].append(rel(cfg.get("CertificateArn"), EdgeType.REFERENCES, "CERTIFICATE_SECURES"))
                        e["metadata"].setdefault("security_policy", cfg.get("SecurityPolicy"))
                        e["metadata"].setdefault("status", cfg.get("DomainNameStatus"))
                    mtls = d.get("MutualTlsAuthentication") or {}
                    bucket = _S3_URI_RE.match(mtls.get("TruststoreUri") or "")
                    if bucket:
                        e["relations"].append(rel(f"arn:aws:s3:::{bucket.group(1)}", EdgeType.REFERENCES, "DEPENDS_ON",
                                                  description="mTLS truststore"))
                        e["metadata"]["mutual_tls"] = True
                    try:
                        async for m in self._pages(apigw.get_api_mappings, "Items", DomainName=name):
                            e["mappings"].append({"path": m.get("ApiMappingKey"), "api_id": m.get("ApiId"), "stage": m.get("Stage")})
                            # The API ID matches REST and HTTP API assets alike
                            e["relations"].append(rel(m.get("ApiId"), EdgeType.ROUTE, "SERVES_TRAFFIC_TO",
                                                      base_path=m.get("ApiMappingKey"), stage=m.get("Stage")))
                    except Exception as exc:
                        logger.debug("API mappings unavailable for %s: %s", name, exc)

        await self._nx_sections(rest, http)
        assets = []
        for e in domains.values():
            types = sorted(t for t in e["endpoint_types"] if t)
            seen_maps: set[tuple] = set()
            mappings = []
            for m in e["mappings"]:
                k = (m["path"], m["api_id"], m["stage"])
                if k not in seen_maps:
                    seen_maps.add(k)
                    mappings.append(m)
            assets.append(
                self._asset(
                    arn=e["arn"],
                    name=e["name"],
                    asset_type=AssetType.CUSTOM_DOMAIN,
                    tags=e["tags"],
                    metadata={"endpoint_types": types, "api_mappings": mappings[:_MAX_LIST_METADATA], **e["metadata"]},
                    relations=_unique(e["relations"]),
                    exposed="PRIVATE" not in types,
                    aliases=list(dict.fromkeys(a for a in e["aliases"] if a)),
                )
            )
        return assets

    # ------------------------------------------------------------------
    # CloudFront (global; overrides the shallow base collector)
    # ------------------------------------------------------------------

    def _cf_origin_target(self, origin: dict, vpc_origins: dict[str, dict]) -> tuple[str, str | None]:
        """(origin kind, identifier of what the origin resolves to)."""
        vpc_id = (origin.get("VpcOriginConfig") or {}).get("VpcOriginId")
        if vpc_id:
            vo = vpc_origins.get(vpc_id) or {}
            return "vpc", vo.get("endpoint") or vo.get("arn") or vpc_id
        domain = _dns(origin.get("DomainName"))
        bucket = _bucket_from_domain(domain)
        if bucket:
            return "s3", f"arn:aws:s3:::{bucket}"
        api = _EXECUTE_API_RE.match(domain)
        if api:
            return "apigateway", api.group(1)
        return "custom", domain or None

    async def _collect_cloudfront(self) -> list[CloudAsset]:
        async with self._client("cloudfront", region="us-east-1") as cf:
            dists: list[dict] = []
            async for page in cf.get_paginator("list_distributions").paginate():
                dists.extend((page.get("DistributionList") or {}).get("Items", []) or [])

            oacs: dict[str, dict] = {}
            try:
                async for page in cf.get_paginator("list_origin_access_controls").paginate():
                    for o in (page.get("OriginAccessControlList") or {}).get("Items", []) or []:
                        oacs[o["Id"]] = {"name": o.get("Name"), "signing_behavior": o.get("SigningBehavior"),
                                         "origin_type": o.get("OriginAccessControlOriginType")}
            except Exception as exc:
                logger.debug("Origin access control listing failed: %s", exc)

            vpc_origins: dict[str, dict] = {}
            uses_vpc_origins = any((o.get("VpcOriginConfig") or {}).get("VpcOriginId")
                                   for d in dists for o in (d.get("Origins") or {}).get("Items", []) or [])
            if uses_vpc_origins:
                try:
                    marker = None
                    for _ in range(100):
                        resp = await cf.list_vpc_origins(**({"Marker": marker} if marker else {}))
                        lst = resp.get("VpcOriginList") or {}
                        for v in lst.get("Items", []) or []:
                            vpc_origins[v["Id"]] = {"arn": v.get("Arn"), "endpoint": v.get("OriginEndpointArn"), "name": v.get("Name")}
                        marker = lst.get("NextMarker")
                        if not marker:
                            break
                except Exception as exc:
                    logger.debug("VPC origin listing failed: %s", exc)

            functions: list[CloudAsset] = []
            try:
                marker = None
                for _ in range(100):
                    kwargs: dict[str, Any] = {"Stage": "LIVE"}
                    if marker:
                        kwargs["Marker"] = marker
                    lst = (await cf.list_functions(**kwargs)).get("FunctionList") or {}
                    for fn in lst.get("Items", []) or []:
                        meta = fn.get("FunctionMetadata") or {}
                        if not meta.get("FunctionARN"):
                            continue
                        functions.append(
                            self._asset(
                                arn=meta["FunctionARN"],
                                name=fn.get("Name", meta["FunctionARN"]),
                                asset_type=AssetType.EDGE_FUNCTION,
                                region="global",
                                metadata={
                                    "resource_kind": "cloudfront_function",
                                    "runtime": (fn.get("FunctionConfig") or {}).get("Runtime"),
                                    "status": fn.get("Status"),
                                    "stage": meta.get("Stage"),
                                },
                            )
                        )
                    marker = lst.get("NextMarker")
                    if not marker:
                        break
            except Exception as exc:
                logger.debug("CloudFront function listing failed: %s", exc)

            async def detail(dist: dict) -> CloudAsset:
                logging_cfg: dict = {}
                try:
                    cfg = (await cf.get_distribution_config(Id=dist["Id"])).get("DistributionConfig") or {}
                    logging_cfg = cfg.get("Logging") or {}
                except Exception as exc:
                    logger.debug("Distribution config unavailable for %s: %s", dist.get("Id"), exc)
                return self._cloudfront_asset(dist, oacs, vpc_origins, logging_cfg)

            results = await gather_limited([lambda d=d: detail(d) for d in dists])
            return [a for a in results if a] + functions

    def _cloudfront_asset(
        self, dist: dict, oacs: dict[str, dict], vpc_origins: dict[str, dict], logging_cfg: dict
    ) -> CloudAsset:
        origins = (dist.get("Origins") or {}).get("Items", []) or []
        relations: list[dict | None] = []
        origin_md = []
        for o in origins:
            kind, target = self._cf_origin_target(o, vpc_origins)
            relations.append(rel(target, EdgeType.ROUTE, "SERVES_TRAFFIC_TO",
                                 description=f"origin {o.get('Id')}", origin_id=o.get("Id"), origin_type=kind))
            oac_id = o.get("OriginAccessControlId") or None
            custom = o.get("CustomOriginConfig") or {}
            origin_md.append({
                "id": o.get("Id"),
                "domain": o.get("DomainName"),
                "type": kind,
                "path": o.get("OriginPath") or None,
                "origin_access_control": oac_id,
                "oac_signing": (oacs.get(oac_id or "") or {}).get("signing_behavior"),
                "origin_access_identity": bool((o.get("S3OriginConfig") or {}).get("OriginAccessIdentity")),
                "protocol_policy": custom.get("OriginProtocolPolicy"),
                "vpc_origin": (o.get("VpcOriginConfig") or {}).get("VpcOriginId"),
                "origin_shield": bool((o.get("OriginShield") or {}).get("Enabled")),
                # header names only: values are often shared secrets
                "custom_header_names": [h.get("HeaderName") for h in (o.get("CustomHeaders") or {}).get("Items", []) or []],
            })

        default = dist.get("DefaultCacheBehavior") or {}
        behaviors = [dict(default, PathPattern="*")] + list((dist.get("CacheBehaviors") or {}).get("Items", []) or [])
        behavior_md = []
        edge_functions = []
        for b in behaviors:
            for assoc in (b.get("LambdaFunctionAssociations") or {}).get("Items", []) or []:
                relations.append(rel(assoc.get("LambdaFunctionARN"), EdgeType.INVOKES, "INVOKES",
                                     description="Lambda@Edge", event_type=assoc.get("EventType")))
                edge_functions.append({"arn": assoc.get("LambdaFunctionARN"), "event_type": assoc.get("EventType"),
                                       "kind": "lambda_edge", "path": b.get("PathPattern")})
            for assoc in (b.get("FunctionAssociations") or {}).get("Items", []) or []:
                relations.append(rel(assoc.get("FunctionARN"), EdgeType.INVOKES, "INVOKES",
                                     description="CloudFront Function", event_type=assoc.get("EventType")))
                edge_functions.append({"arn": assoc.get("FunctionARN"), "event_type": assoc.get("EventType"),
                                       "kind": "cloudfront_function", "path": b.get("PathPattern")})
            behavior_md.append({
                "path": b.get("PathPattern"),
                "target_origin": b.get("TargetOriginId"),
                "viewer_protocol_policy": b.get("ViewerProtocolPolicy"),
                "trusted_key_groups": bool((b.get("TrustedKeyGroups") or {}).get("Enabled")),
            })

        cert = dist.get("ViewerCertificate") or {}
        relations.append(rel(cert.get("ACMCertificateArn"), EdgeType.REFERENCES, "CERTIFICATE_SECURES"))
        log_bucket = None
        if logging_cfg.get("Enabled") and logging_cfg.get("Bucket"):
            log_bucket = _bucket_from_domain(logging_cfg["Bucket"]) or logging_cfg["Bucket"].split(".s3", 1)[0]
            relations.append(rel(f"arn:aws:s3:::{log_bucket}", EdgeType.LOGS_TO, "LOGS_TO", description="standard access logs"))

        cnames = [_dns(a) for a in (dist.get("Aliases") or {}).get("Items", []) or []]
        geo = (dist.get("Restrictions") or {}).get("GeoRestriction") or {}
        raw = {k: v for k, v in dist.items() if k != "Origins"}
        return self._asset(
            arn=dist.get("ARN", ""),
            name=dist.get("DomainName", dist.get("Id", "")),
            asset_type=AssetType.CLOUDFRONT,
            region="global",
            metadata={
                # keys kept from the shallow collector
                "status": dist.get("Status"),
                "domain_name": dist.get("DomainName"),
                "origins": [o.get("DomainName") for o in origins],
                "web_acl_id": dist.get("WebACLId", ""),
                "viewer_protocol_policy": default.get("ViewerProtocolPolicy"),
                # deep detail
                "distribution_id": dist.get("Id"),
                "enabled": dist.get("Enabled"),
                "staging": dist.get("Staging"),
                "comment": dist.get("Comment"),
                "cnames": cnames,
                "price_class": dist.get("PriceClass"),
                "http_version": dist.get("HttpVersion"),
                "ipv6": dist.get("IsIPV6Enabled"),
                "origin_details": origin_md,
                "origin_groups": [
                    {"id": g.get("Id"), "members": [m.get("OriginId") for m in (g.get("Members") or {}).get("Items", []) or []]}
                    for g in (dist.get("OriginGroups") or {}).get("Items", []) or []
                ],
                "cache_behaviors": behavior_md[:_MAX_LIST_METADATA],
                "edge_functions": edge_functions[:_MAX_LIST_METADATA],
                "viewer_certificate": {
                    "default_certificate": bool(cert.get("CloudFrontDefaultCertificate")),
                    "acm_certificate_arn": cert.get("ACMCertificateArn"),
                    "iam_certificate_id": cert.get("IAMCertificateId"),
                    "minimum_protocol_version": cert.get("MinimumProtocolVersion"),
                    "ssl_support_method": cert.get("SSLSupportMethod"),
                },
                "geo_restriction": geo.get("RestrictionType"),
                "logging_enabled": bool(logging_cfg.get("Enabled")),
                "logging_bucket": log_bucket,
                "realtime_log_config_arn": default.get("RealtimeLogConfigArn"),
            },
            relations=_unique(relations),
            raw=raw,
            exposed=True,
            aliases=cnames + [_dns(dist.get("DomainName"))],
        )

    # ------------------------------------------------------------------
    # Route 53 Resolver
    # ------------------------------------------------------------------

    async def _collect_route53_resolver(self) -> list[CloudAsset]:
        async with self._client("route53resolver") as r53r:

            async def endpoints() -> list[CloudAsset]:
                eps = [e async for e in self._paginate(r53r, "list_resolver_endpoints", "ResolverEndpoints")]

                async def detail(ep: dict) -> CloudAsset:
                    ips: list[dict] = []
                    try:
                        async for ip in self._paginate(r53r, "list_resolver_endpoint_ip_addresses", "IpAddresses",
                                                       ResolverEndpointId=ep["Id"]):
                            ips.append({"ip": ip.get("Ip"), "ipv6": ip.get("Ipv6"), "subnet_id": ip.get("SubnetId"),
                                        "status": ip.get("Status")})
                    except Exception as exc:
                        logger.debug("Resolver endpoint IPs unavailable for %s: %s", ep["Id"], exc)
                    subnets = list(dict.fromkeys(i["subnet_id"] for i in ips if i["subnet_id"]))
                    relations: list[dict | None] = [rel(ep.get("HostVPCId"), EdgeType.CONTAINS, reverse=True)]
                    relations += [rel(s, EdgeType.CONTAINS, "SUBNET_CONTAINS_INSTANCE", reverse=True) for s in subnets]
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

                results = await gather_limited([lambda e=e: detail(e) for e in eps])
                return [a for a in results if a]

            async def rules() -> list[CloudAsset]:
                found = [r async for r in self._paginate(r53r, "list_resolver_rules", "ResolverRules")
                         if not str(r.get("Id", "")).startswith("rslvr-autodefined")]
                assocs: dict[str, list[dict]] = {}
                try:
                    async for a in self._paginate(r53r, "list_resolver_rule_associations", "ResolverRuleAssociations"):
                        assocs.setdefault(a.get("ResolverRuleId") or "", []).append(a)
                except Exception as exc:
                    logger.debug("Resolver rule association listing failed: %s", exc)
                out = []
                for r in found:
                    rid = r["Id"]
                    vpcs = assocs.get(rid, [])
                    relations: list[dict | None] = [
                        rel(r.get("ResolverEndpointId"), EdgeType.ROUTE, "DNS_RESOLVED", description="forwards via outbound endpoint"),
                    ]
                    relations += [rel(a.get("VPCId"), EdgeType.ATTACHED_TO, "DNS_RESOLVED", description="rule associated with VPC",
                                      status=a.get("Status")) for a in vpcs]
                    owner = r.get("OwnerId")
                    out.append(
                        self._asset(
                            arn=r.get("Arn") or self._arn("route53resolver", f"resolver-rule/{rid}"),
                            name=r.get("Name") or _dns(r.get("DomainName")) or rid,
                            asset_type=AssetType.DNS_RESOLVER,
                            metadata={
                                "resource_kind": "resolver_rule",
                                "domain_name": _dns(r.get("DomainName")),
                                "rule_type": r.get("RuleType"),
                                "status": r.get("Status"),
                                "target_ips": [f"{t.get('Ip') or t.get('Ipv6')}:{t.get('Port', 53)}" for t in r.get("TargetIps") or []],
                                "resolver_endpoint_id": r.get("ResolverEndpointId"),
                                "owner_id": owner,
                                "share_status": r.get("ShareStatus"),
                                "shared_from_other_account": bool(owner and self._account_id and owner != self._account_id),
                                "associated_vpcs": [a.get("VPCId") for a in vpcs],
                            },
                            relations=_unique(relations),
                            aliases=[rid],
                        )
                    )
                return out

            async def dns_firewall() -> list[CloudAsset]:
                groups: dict[str, dict] = {}
                try:
                    async for g in self._paginate(r53r, "list_firewall_rule_groups", "FirewallRuleGroups"):
                        groups[g["Id"]] = g
                except Exception as exc:
                    logger.debug("DNS Firewall rule group listing failed: %s", exc)
                by_group: dict[str, list[dict]] = {}
                async for a in self._paginate(r53r, "list_firewall_rule_group_associations", "FirewallRuleGroupAssociations"):
                    by_group.setdefault(a.get("FirewallRuleGroupId") or "", []).append(a)
                out = []
                for gid in dict.fromkeys(list(groups) + list(by_group)):
                    if not gid:
                        continue
                    g = groups.get(gid, {})
                    assoc = by_group.get(gid, [])
                    out.append(
                        self._asset(
                            arn=g.get("Arn") or self._arn("route53resolver", f"firewall-rule-group/{gid}"),
                            name=g.get("Name") or gid,
                            asset_type=AssetType.NETWORK_FIREWALL,
                            metadata={
                                "resource_kind": "dns_firewall_rule_group",
                                "owner_id": g.get("OwnerId"),
                                "share_status": g.get("ShareStatus"),
                                "associations": [
                                    {"vpc_id": a.get("VpcId"), "priority": a.get("Priority"), "status": a.get("Status"),
                                     "mutation_protection": a.get("MutationProtection"), "managed_by": a.get("ManagedOwnerName")}
                                    for a in assoc
                                ],
                            },
                            relations=_unique([
                                rel(a.get("VpcId"), EdgeType.PROTECTS, "PROTECTED_BY_NACL", description="DNS Firewall",
                                    priority=a.get("Priority"))
                                for a in assoc
                            ]),
                            aliases=[gid],
                        )
                    )
                return out

            async def query_logging() -> list[CloudAsset]:
                configs = [c async for c in self._paginate(r53r, "list_resolver_query_log_configs", "ResolverQueryLogConfigs")]
                assocs: dict[str, list[dict]] = {}
                try:
                    async for a in self._paginate(r53r, "list_resolver_query_log_config_associations",
                                                  "ResolverQueryLogConfigAssociations"):
                        assocs.setdefault(a.get("ResolverQueryLogConfigId") or "", []).append(a)
                except Exception as exc:
                    logger.debug("Query log association listing failed: %s", exc)
                out = []
                for c in configs:
                    cid = c["Id"]
                    linked = assocs.get(cid, [])
                    relations: list[dict | None] = [rel(c.get("DestinationArn"), EdgeType.LOGS_TO, "LOGS_TO")]
                    relations += [rel(a.get("ResourceId"), EdgeType.LOGS_TO, "LOGS_TO", reverse=True,
                                      description="Resolver query logging", status=a.get("Status")) for a in linked]
                    out.append(
                        self._asset(
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
                            relations=_unique(relations),
                            aliases=[cid],
                        )
                    )
                return out

            return await self._nx_sections(endpoints, rules, dns_firewall, query_logging)

    # ------------------------------------------------------------------
    # Direct Connect
    # ------------------------------------------------------------------

    def _dx_arn(self, kind: str, rid: str, region: str | None, owner: str | None) -> str:
        return f"arn:aws:directconnect:{region or self._region}:{owner or self._account_id}:{kind}/{rid}"

    async def _collect_direct_connect(self) -> list[CloudAsset]:
        async with self._client("directconnect") as dx:

            def link_md(c: dict) -> dict:
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

            async def connections() -> list[CloudAsset]:
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
                                **link_md(c),
                            },
                            relations=[rel(c.get("lagId"), EdgeType.CONTAINS, reverse=True, description="LAG member")],
                            aliases=[cid],
                        )
                    )
                return out

            async def lags() -> list[CloudAsset]:
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
                                "member_connections": [c.get("connectionId") for c in lag.get("connections") or []],
                                **link_md(lag),
                            },
                            aliases=[lid],
                        )
                    )
                return out

            async def virtual_interfaces() -> list[CloudAsset]:
                out = []
                async for v in self._pages(dx.describe_virtual_interfaces, "virtualInterfaces", token_in="nextToken"):
                    if v.get("virtualInterfaceState") in ("deleted", "deleting", "rejected"):
                        continue
                    vid = v["virtualInterfaceId"]
                    out.append(
                        self._asset(
                            arn=self._dx_arn("dxvif", vid, v.get("region"), v.get("ownerAccount")),
                            name=v.get("virtualInterfaceName") or vid,
                            asset_type=AssetType.DIRECT_CONNECT,
                            tags=v.get("tags"),
                            metadata={
                                "resource_kind": "dx_virtual_interface",
                                "virtual_interface_id": vid,
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
                                    {"asn": p.get("asnLong") or p.get("asn"), "state": p.get("bgpPeerState"),
                                     "status": p.get("bgpStatus"), "address_family": p.get("addressFamily")}
                                    for p in v.get("bgpPeers") or []
                                ],
                            },
                            relations=_unique([
                                rel(v.get("connectionId"), EdgeType.ATTACHED_TO, description="runs over connection / LAG"),
                                rel(v.get("virtualGatewayId"), EdgeType.ROUTE, "TRANSIT_ROUTED", description="private VIF to VGW"),
                                rel(v.get("directConnectGatewayId"), EdgeType.ROUTE, "TRANSIT_ROUTED", description="VIF to DX gateway"),
                            ]),
                            aliases=[vid],
                        )
                    )
                return out

            return await self._nx_sections(connections, lags, virtual_interfaces)

    async def _collect_direct_connect_gateways(self) -> list[CloudAsset]:
        """DX gateways are global resources: collected once per account."""
        async with self._client("directconnect") as dx:
            gws = [g async for g in self._paginate(dx, "describe_direct_connect_gateways", "directConnectGateways")
                   if g.get("directConnectGatewayState") not in ("deleted", "deleting")]

            async def detail(gw: dict) -> CloudAsset:
                gid = gw["directConnectGatewayId"]
                relations: list[dict | None] = []
                associations, attachments = [], []
                try:
                    async for a in self._paginate(dx, "describe_direct_connect_gateway_associations",
                                                  "directConnectGatewayAssociations", directConnectGatewayId=gid):
                        g = a.get("associatedGateway") or {}
                        gtype = g.get("type") or ("virtualPrivateGateway" if a.get("virtualGatewayId") else None)
                        gw_id = g.get("id") or a.get("virtualGatewayId")
                        region = g.get("region") or a.get("virtualGatewayRegion")
                        owner = g.get("ownerAccount") or a.get("virtualGatewayOwnerAccount")
                        resource = "transit-gateway" if gtype == "transitGateway" else "vpn-gateway"
                        core = (a.get("associatedCoreNetwork") or {}).get("id")
                        associations.append({"gateway_id": gw_id or core, "type": gtype or ("coreNetwork" if core else None),
                                             "region": region, "owner": owner, "state": a.get("associationState"),
                                             "allowed_prefixes": [p.get("cidr") for p in a.get("allowedPrefixesToDirectConnectGateway") or []]})
                        relations.append(rel(_ec2_arn(region, owner, resource, gw_id) if gw_id else core,
                                             EdgeType.ROUTE, "TRANSIT_ROUTED", description=f"{gtype or 'core network'} association",
                                             state=a.get("associationState")))
                except Exception as exc:
                    logger.debug("DX gateway associations unavailable for %s: %s", gid, exc)
                try:
                    async for a in self._paginate(dx, "describe_direct_connect_gateway_attachments",
                                                  "directConnectGatewayAttachments", directConnectGatewayId=gid):
                        vif = a.get("virtualInterfaceId")
                        if not vif:
                            continue
                        attachments.append({"virtual_interface_id": vif, "region": a.get("virtualInterfaceRegion"),
                                            "owner": a.get("virtualInterfaceOwnerAccount"), "state": a.get("attachmentState"),
                                            "type": a.get("attachmentType")})
                        relations.append(rel(self._dx_arn("dxvif", vif, a.get("virtualInterfaceRegion"),
                                                          a.get("virtualInterfaceOwnerAccount")),
                                             EdgeType.ROUTE, "TRANSIT_ROUTED", reverse=True, description="VIF attachment"))
                except Exception as exc:
                    logger.debug("DX gateway attachments unavailable for %s: %s", gid, exc)
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

            results = await gather_limited([lambda g=g: detail(g) for g in gws])
            return [a for a in results if a]

    # ------------------------------------------------------------------
    # Global Accelerator (global; API homed in us-west-2)
    # ------------------------------------------------------------------

    async def _collect_global_accelerator(self) -> list[CloudAsset]:
        async with self._client("globalaccelerator", region="us-west-2") as ga:

            async def walk(accel: dict, custom: bool) -> CloudAsset:
                arn = accel["AcceleratorArn"]
                listener_op = "list_custom_routing_listeners" if custom else "list_listeners"
                group_op = "list_custom_routing_endpoint_groups" if custom else "list_endpoint_groups"
                relations: list[dict | None] = []
                listeners, groups, endpoints = [], [], []
                try:
                    async for lst in self._paginate(ga, listener_op, "Listeners", AcceleratorArn=arn):
                        listeners.append({
                            "ports": [f"{p.get('FromPort')}-{p.get('ToPort')}" for p in lst.get("PortRanges") or []],
                            "protocol": lst.get("Protocol"),
                            "client_affinity": lst.get("ClientAffinity"),
                        })
                        async for eg in self._paginate(ga, group_op, "EndpointGroups", ListenerArn=lst["ListenerArn"]):
                            region = eg.get("EndpointGroupRegion")
                            descs = eg.get("EndpointDescriptions") or []
                            groups.append({"region": region, "traffic_dial": eg.get("TrafficDialPercentage"),
                                           "health_check": eg.get("HealthCheckProtocol"), "health_check_port": eg.get("HealthCheckPort"),
                                           "endpoints": len(descs)})
                            for d in descs:
                                eid = d.get("EndpointId")
                                endpoints.append({"id": eid, "region": region, "weight": d.get("Weight"),
                                                  "health": d.get("HealthState"),
                                                  "client_ip_preservation": d.get("ClientIPPreservationEnabled")})
                                relations.append(rel(eid, EdgeType.LOAD_BALANCER_TARGET, "SERVES_TRAFFIC_TO",
                                                     region=region, health=d.get("HealthState"), weight=d.get("Weight")))
                except Exception as exc:
                    logger.debug("Accelerator walk incomplete for %s: %s", arn, exc)
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
                        "listeners": listeners,
                        "endpoint_groups": groups,
                        "endpoints": endpoints[:_MAX_LIST_METADATA],
                    },
                    relations=_unique(relations),
                    exposed=True,
                    aliases=[_dns(accel.get("DnsName")), _dns(accel.get("DualStackDnsName"))],
                )

            async def standard() -> list[CloudAsset]:
                accels = [a async for a in self._paginate(ga, "list_accelerators", "Accelerators")]
                results = await gather_limited([lambda a=a: walk(a, False) for a in accels])
                return [a for a in results if a]

            async def custom_routing() -> list[CloudAsset]:
                accels = [a async for a in self._paginate(ga, "list_custom_routing_accelerators", "Accelerators")]
                results = await gather_limited([lambda a=a: walk(a, True) for a in accels])
                return [a for a in results if a]

            return await self._nx_sections(standard, custom_routing)

    # ------------------------------------------------------------------
    # ELBv2 listeners and listener rules
    # ------------------------------------------------------------------

    @staticmethod
    def _elb_actions(actions: list[dict], where: str, relations: list[dict | None]) -> list[dict]:
        """Summarise listener / rule actions (no secrets) and record the
        target groups, user pools and redirects they lead to."""
        out = []
        for a in sorted(actions or [], key=lambda x: x.get("Order") or 0):
            atype = a.get("Type")
            item: dict[str, Any] = {"type": atype}
            tgs = [a.get("TargetGroupArn")] + [t.get("TargetGroupArn") for t in (a.get("ForwardConfig") or {}).get("TargetGroups") or []]
            tgs = list(dict.fromkeys(t for t in tgs if t))
            if tgs:
                item["target_groups"] = tgs
                relations.extend(rel(t, EdgeType.ROUTE, "SERVES_TRAFFIC_TO", description=f"forward ({where})") for t in tgs)
            cognito = a.get("AuthenticateCognitoConfig") or {}
            if cognito:
                item["user_pool"] = cognito.get("UserPoolArn")
                item["on_unauthenticated"] = cognito.get("OnUnauthenticatedRequest")
                relations.append(rel(cognito.get("UserPoolArn"), EdgeType.REFERENCES, "DEPENDS_ON",
                                     description=f"authenticate-cognito ({where})"))
            oidc = a.get("AuthenticateOidcConfig") or {}
            if oidc:
                item["issuer"] = oidc.get("Issuer")
                item["on_unauthenticated"] = oidc.get("OnUnauthenticatedRequest")
            redirect = a.get("RedirectConfig") or {}
            if redirect:
                item["redirect"] = {k.lower(): redirect.get(k) for k in ("Protocol", "Host", "Port", "Path", "StatusCode")}
            fixed = a.get("FixedResponseConfig") or {}
            if fixed:
                item["status_code"] = fixed.get("StatusCode")
            out.append(item)
        return out

    @staticmethod
    def _elb_conditions(conditions: list[dict]) -> dict[str, Any]:
        out: dict[str, Any] = {}
        for c in conditions or []:
            field = c.get("Field")
            if field == "host-header":
                out["hosts"] = (c.get("HostHeaderConfig") or {}).get("Values") or c.get("Values") or []
            elif field == "path-pattern":
                out["paths"] = (c.get("PathPatternConfig") or {}).get("Values") or c.get("Values") or []
            elif field == "http-header":
                out.setdefault("headers", []).append((c.get("HttpHeaderConfig") or {}).get("HttpHeaderName"))
            elif field == "http-request-method":
                out["methods"] = (c.get("HttpRequestMethodConfig") or {}).get("Values") or []
            elif field == "source-ip":
                out["source_ips"] = (c.get("SourceIpConfig") or {}).get("Values") or []
            elif field == "query-string":
                out["query_conditions"] = len((c.get("QueryStringConfig") or {}).get("Values") or [])
        return out

    async def _collect_elb_rules(self) -> list[CloudAsset]:
        """One asset per ALB/NLB/GWLB listener carrying its (rule-level)
        routing: forward targets, authentication, redirects, mTLS."""
        async with self._client("elbv2") as elb:

            async def listeners() -> list[CloudAsset]:
                lbs = [lb async for lb in self._paginate(elb, "describe_load_balancers", "LoadBalancers")]

                async def per_lb(lb: dict) -> list[CloudAsset]:
                    lb_arn = lb["LoadBalancerArn"]
                    out = []
                    async for listener in self._paginate(elb, "describe_listeners", "Listeners", LoadBalancerArn=lb_arn):
                        out.append(await self._elb_listener_asset(elb, lb, listener))
                    return out

                found: list[CloudAsset] = []
                for res in await gather_limited([lambda lb=lb: per_lb(lb) for lb in lbs]):
                    found.extend(res or [])
                return found

            async def trust_stores() -> list[CloudAsset]:
                out = []
                async for ts in self._paginate(elb, "describe_trust_stores", "TrustStores"):
                    out.append(
                        self._asset(
                            arn=ts["TrustStoreArn"],
                            name=ts.get("Name") or ts["TrustStoreArn"],
                            asset_type=AssetType.CERTIFICATE,
                            metadata={
                                "resource_kind": "elb_trust_store",
                                "status": ts.get("Status"),
                                "ca_certificates": ts.get("NumberOfCaCertificates"),
                                "revoked_entries": ts.get("TotalRevokedEntries"),
                            },
                        )
                    )
                return out

            return await self._nx_sections(listeners, trust_stores)

    async def _elb_listener_asset(self, elb: Any, lb: dict, listener: dict) -> CloudAsset:
        arn = listener["ListenerArn"]
        lb_arn = lb["LoadBalancerArn"]
        relations: list[dict | None] = [rel(lb_arn, EdgeType.CONTAINS, reverse=True, description="load balancer listener")]
        default_actions = self._elb_actions(listener.get("DefaultActions") or [], "default", relations)
        rules: list[dict] = []
        if lb.get("Type") == "application":
            try:
                async for r in self._paginate(elb, "describe_rules", "Rules", ListenerArn=arn):
                    if r.get("IsDefault"):
                        continue
                    if len(rules) >= _MAX_RULES_PER_LISTENER:
                        break
                    rules.append({
                        "priority": r.get("Priority"),
                        **self._elb_conditions(r.get("Conditions") or []),
                        "actions": self._elb_actions(r.get("Actions") or [], f"rule {r.get('Priority')}", relations),
                    })
            except Exception as exc:
                logger.debug("Listener rules unavailable for %s: %s", arn, exc)
        for cert in listener.get("Certificates") or []:
            relations.append(rel(cert.get("CertificateArn"), EdgeType.REFERENCES, "CERTIFICATE_SECURES"))
        mtls = listener.get("MutualAuthentication") or {}
        relations.append(rel(mtls.get("TrustStoreArn"), EdgeType.REFERENCES, "DEPENDS_ON", description="mTLS trust store"))

        all_actions = default_actions + [a for r in rules for a in r["actions"]]
        auth_types = sorted({a["type"] for a in all_actions if str(a.get("type", "")).startswith("authenticate-")})
        target_groups = list(dict.fromkeys(t for a in all_actions for t in a.get("target_groups", [])))
        https_redirect = any(a.get("type") == "redirect" and (a.get("redirect") or {}).get("protocol") == "HTTPS"
                             for a in default_actions)
        port = listener.get("Port")
        return self._asset(
            arn=arn,
            name=f"{lb.get('LoadBalancerName', lb_arn)}:{port}" if port else f"{lb.get('LoadBalancerName', lb_arn)}:listener",
            asset_type=AssetType.LB_LISTENER,
            metadata={
                "resource_kind": "lb_listener",
                "load_balancer": lb.get("LoadBalancerName"),
                "lb_type": lb.get("Type"),
                "scheme": lb.get("Scheme"),
                "port": port,
                "protocol": listener.get("Protocol"),
                "ssl_policy": listener.get("SslPolicy"),
                "alpn_policy": listener.get("AlpnPolicy", []),
                "mutual_tls_mode": mtls.get("Mode"),
                "default_actions": default_actions,
                "rules": rules,
                "rule_count": len(rules),
                "authenticated": bool(auth_types),
                "auth_types": auth_types,
                "redirects_to_https": https_redirect,
                "target_groups": target_groups,
            },
            relations=_unique(relations),
            exposed=lb.get("Scheme") == "internet-facing",
        )

    # ------------------------------------------------------------------
    # VPC Lattice
    # ------------------------------------------------------------------

    async def _collect_vpc_lattice(self) -> list[CloudAsset]:
        async with self._client("vpc-lattice") as vl:

            async def auth_policy(resource: str) -> tuple[bool, str | None]:
                try:
                    resp = await vl.get_auth_policy(resourceIdentifier=resource)
                    return _policy_is_public(resp.get("policy")), resp.get("state")
                except Exception as exc:
                    if "NotFound" not in error_code(exc):
                        logger.debug("Lattice auth policy unavailable for %s: %s", resource, exc)
                    return False, None

            async def networks() -> list[CloudAsset]:
                items = [n async for n in self._paginate(vl, "list_service_networks", "items")]

                async def detail(n: dict) -> CloudAsset:
                    nid, arn = n["id"], n["arn"]
                    auth_type = None
                    try:
                        auth_type = (await vl.get_service_network(serviceNetworkIdentifier=nid)).get("authType")
                    except Exception as exc:
                        logger.debug("Lattice service network detail unavailable for %s: %s", nid, exc)
                    relations: list[dict | None] = []
                    vpcs, services = [], []
                    try:
                        async for a in self._paginate(vl, "list_service_network_vpc_associations", "items",
                                                      serviceNetworkIdentifier=nid):
                            vpcs.append(a.get("vpcId"))
                            relations.append(rel(a.get("vpcId"), EdgeType.ATTACHED_TO, description="VPC association",
                                                 status=a.get("status")))
                    except Exception as exc:
                        logger.debug("Lattice VPC associations unavailable for %s: %s", nid, exc)
                    try:
                        async for a in self._paginate(vl, "list_service_network_service_associations", "items",
                                                      serviceNetworkIdentifier=nid):
                            services.append(a.get("serviceArn") or a.get("serviceId"))
                            relations.append(rel(a.get("serviceArn") or a.get("serviceId"), EdgeType.CONTAINS,
                                                 description="service association", status=a.get("status")))
                    except Exception as exc:
                        logger.debug("Lattice service associations unavailable for %s: %s", nid, exc)
                    public, policy_state = await auth_policy(arn)
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

                results = await gather_limited([lambda n=n: detail(n) for n in items])
                return [a for a in results if a]

            async def services() -> list[CloudAsset]:
                items = [s async for s in self._paginate(vl, "list_services", "items")]

                async def detail(s: dict) -> CloudAsset:
                    sid, arn = s["id"], s["arn"]
                    svc: dict = {}
                    try:
                        svc = await vl.get_service(serviceIdentifier=sid)
                    except Exception as exc:
                        logger.debug("Lattice service detail unavailable for %s: %s", sid, exc)
                    listeners = []
                    try:
                        async for lst in self._paginate(vl, "list_listeners", "items", serviceIdentifier=sid):
                            listeners.append({"name": lst.get("name"), "protocol": lst.get("protocol"), "port": lst.get("port")})
                    except Exception as exc:
                        logger.debug("Lattice listeners unavailable for %s: %s", sid, exc)
                    public, policy_state = await auth_policy(arn)
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

                results = await gather_limited([lambda s=s: detail(s) for s in items])
                return [a for a in results if a]

            async def target_groups() -> list[CloudAsset]:
                items = [t async for t in self._paginate(vl, "list_target_groups", "items")]

                async def detail(tg: dict) -> CloudAsset:
                    tid = tg["id"]
                    relations: list[dict | None] = [
                        rel(s, EdgeType.LOAD_BALANCER_TARGET, "LOAD_BALANCED_BY", reverse=True)
                        for s in tg.get("serviceArns") or []
                    ]
                    targets = []
                    try:
                        async for t in self._paginate(vl, "list_targets", "items", targetGroupIdentifier=tid):
                            targets.append({"id": t.get("id"), "port": t.get("port"), "status": t.get("status")})
                            if tg.get("type") != "IP":
                                relations.append(rel(t.get("id"), EdgeType.LOAD_BALANCER_TARGET, "LB_TARGETS_INSTANCE",
                                                     health=t.get("status")))
                    except Exception as exc:
                        logger.debug("Lattice targets unavailable for %s: %s", tid, exc)
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

                results = await gather_limited([lambda t=t: detail(t) for t in items])
                return [a for a in results if a]

            return await self._nx_sections(networks, services, target_groups)

    # ------------------------------------------------------------------
    # Network Manager / Cloud WAN (global; API homed in us-west-2)
    # ------------------------------------------------------------------

    async def _collect_network_manager(self) -> list[CloudAsset]:
        async with self._client("networkmanager", region="us-west-2") as nm:

            async def global_networks() -> list[CloudAsset]:
                items = [g async for g in self._paginate(nm, "describe_global_networks", "GlobalNetworks")
                         if g.get("State") not in ("DELETING",)]

                async def detail(g: dict) -> CloudAsset:
                    gid = g["GlobalNetworkId"]
                    tgws = []
                    try:
                        async for r in self._paginate(nm, "get_transit_gateway_registrations", "TransitGatewayRegistrations",
                                                      GlobalNetworkId=gid):
                            tgws.append({"arn": r.get("TransitGatewayArn"), "state": (r.get("State") or {}).get("Code")})
                    except Exception as exc:
                        logger.debug("TGW registrations unavailable for %s: %s", gid, exc)
                    return self._asset(
                        arn=g.get("GlobalNetworkArn") or f"arn:aws:networkmanager::{self._account_id}:global-network/{gid}",
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
                        relations=_unique([rel(t["arn"], EdgeType.MONITORS, "MONITORED_BY",
                                               description="registered transit gateway", state=t["state"]) for t in tgws]),
                        aliases=[gid],
                    )

                results = await gather_limited([lambda g=g: detail(g) for g in items])
                return [a for a in results if a]

            async def core_networks() -> list[CloudAsset]:
                items = [c async for c in self._paginate(nm, "list_core_networks", "CoreNetworks")]

                async def detail(c: dict) -> CloudAsset:
                    cid = c["CoreNetworkId"]
                    relations: list[dict | None] = [rel(c.get("GlobalNetworkId"), EdgeType.CONTAINS, reverse=True,
                                                        description="core network of global network")]
                    attachments = []
                    try:
                        async for a in self._paginate(nm, "list_attachments", "Attachments", CoreNetworkId=cid):
                            attachments.append({
                                "id": a.get("AttachmentId"), "type": a.get("AttachmentType"), "state": a.get("State"),
                                "segment": a.get("SegmentName"), "edge_location": a.get("EdgeLocation"),
                                "resource_arn": a.get("ResourceArn"), "owner": a.get("OwnerAccountId"),
                            })
                            relations.append(rel(a.get("ResourceArn"), EdgeType.ROUTE, "TRANSIT_ROUTED",
                                                 description=f"{a.get('AttachmentType')} attachment",
                                                 segment=a.get("SegmentName"), edge_location=a.get("EdgeLocation"),
                                                 state=a.get("State")))
                    except Exception as exc:
                        logger.debug("Core network attachments unavailable for %s: %s", cid, exc)
                    return self._asset(
                        arn=c.get("CoreNetworkArn") or f"arn:aws:networkmanager::{self._account_id}:core-network/{cid}",
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

                results = await gather_limited([lambda c=c: detail(c) for c in items])
                return [a for a in results if a]

            return await self._nx_sections(global_networks, core_networks)
