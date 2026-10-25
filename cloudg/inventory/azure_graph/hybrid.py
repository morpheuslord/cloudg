"""Extractors for hybrid and edge networking, DNS, WAF and Virtual Network Manager.

- Virtual WAN, virtual hubs, hub VNet connections, hub route tables and
  routing intent (``TRANSIT_ROUTED`` to VNets, firewalls and NVAs),
  ExpressRoute circuits / gateways / ports, vWAN VPN gateways and sites,
  point-to-site gateways, local network gateways, Route Server BGP peers.
- IP groups and public IP prefixes.
- Public and private DNS record sets (``DNS_RESOLVED`` to alias targets,
  IPs and CNAME hosts), DNS Private Resolver endpoints, forwarding
  rulesets, rules and VNet links, Traffic Manager endpoints.
- WAF policies (mode, managed rule sets, the gateways / listeners / Front
  Door endpoints they protect), Front Door (Standard / Premium) routes,
  origin groups, rule sets and rules, secrets and custom domain TLS.
- Application Gateway listeners as ``LB_LISTENER`` assets serving traffic
  to the backends their routing rules reach.
- Private Link service visibility and auto-approval (``GRANTS_ACCESS``).
- Virtual Network Manager: network groups and members, connectivity
  configurations (hub-and-spoke / mesh ``TRANSIT_ROUTED``), security admin
  rule collections (``PROTECTS / PROTECTED_BY_NACL`` the groups).
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from cloudg.inventory.aws_services._base import rel
from cloudg.inventory.azure_graph.helpers import (
    _get,
    _list,
    _lower,
    _path,
    _props,
    _rid,
    _rids,
    host_of,
    owner_resource_id,
    parent_resource_id,
    subscription_ref,
)
from cloudg.inventory.azure_graph.registry import _Draft, extractor, relation_row
from cloudg.schema.models import EdgeType

if TYPE_CHECKING:
    from cloudg.inventory.azure_graph.builder import AzureAssetBuilder


def _contained_by(d: _Draft, parent: Any, description: str | None = None) -> None:
    d.add(rel(_rid(parent), EdgeType.CONTAINS, reverse=True, description=description))


def _transit(d: _Draft, target: Any, description: str, **props: Any) -> None:
    d.add(rel(target, EdgeType.ROUTE, "TRANSIT_ROUTED", description=description, **props))


# ── Virtual WAN ──


@extractor("microsoft.network/virtualwans")
def _x_vwan(d: _Draft, b: "AzureAssetBuilder") -> None:
    p = d.props
    d.md.update(
        {
            "wan_type": _get(p, "type"),
            "branch_to_branch": _get(p, "allowBranchToBranchTraffic"),
            "hub_count": len(_list(_get(p, "virtualHubs"))),
        }
    )
    for hub in _rids(_get(p, "virtualHubs")):
        d.add(rel(hub, EdgeType.CONTAINS, description="virtual hub"))


@extractor("microsoft.network/virtualhubs")
def _x_virtual_hub(d: _Draft, b: "AzureAssetBuilder") -> None:
    p = d.props
    wan = _rid(_get(p, "virtualWan"))
    route_server = not wan and bool(_get(p, "virtualRouterIps"))
    d.md.update(
        {
            "address_prefix": _get(p, "addressPrefix"),
            "route_server": route_server,
            "routing_state": _get(p, "routingState"),
            "hub_routing_preference": _get(p, "hubRoutingPreference"),
            "virtual_router_ips": _list(_get(p, "virtualRouterIps")),
            "virtual_router_asn": _get(p, "virtualRouterAsn"),
        }
    )
    d.alias(*_list(_get(p, "virtualRouterIps")))
    _contained_by(d, wan, "virtual WAN")
    for key in ("azureFirewall", "vpnGateway", "expressRouteGateway", "p2SVpnGateway"):
        d.add(rel(_rid(_get(p, key)), EdgeType.CONTAINS, description=key))
    for conn in _list(_get(p, "virtualNetworkConnections")):  # legacy embedded connections
        _transit(d, _rid(_get(_props(conn), "remoteVirtualNetwork")), "hub VNet connection")
    d.add(rel(_rid(_get(p, "routeTable")), EdgeType.ATTACHED_TO, description="hub route table"))


@extractor("microsoft.network/virtualhubs/hubvirtualnetworkconnections")
def _x_hub_connection(d: _Draft, b: "AzureAssetBuilder") -> None:
    p = d.props
    vnet = _rid(_get(p, "remoteVirtualNetwork"))
    routing = _get(p, "routingConfiguration") or {}
    d.md.update(
        {
            "remote_virtual_network": vnet,
            "internet_security": _get(p, "enableInternetSecurity"),
            "allow_hub_to_remote_vnet_transit": _get(p, "allowHubToRemoteVnetTransit"),
        }
    )
    _transit(d, vnet, "hub VNet connection")
    d.add(
        rel(
            _rid(_get(routing, "associatedRouteTable")),
            EdgeType.ATTACHED_TO,
            description="associated route table",
        )
    )
    for rt in _rids(_path(routing, "propagatedRouteTables", "ids")):
        d.add(rel(rt, EdgeType.REFERENCES, "DEPENDS_ON", description="propagates to"))
    hub = parent_resource_id(d.id)
    if hub and vnet:
        b.defer(hub, rel(vnet, EdgeType.ROUTE, "TRANSIT_ROUTED", description="hub VNet connection"))


def _route_targets(d: _Draft, routes: Any) -> list[dict[str, Any]]:
    out = []
    for route in _list(routes):
        rp = _props(route)
        next_hop = _get(rp, "nextHop")
        entry = {
            "name": _get(route, "name"),
            "destinations": _list(_get(rp, "destinations")),
            "destination_type": _get(rp, "destinationType"),
            "next_hop_type": _get(rp, "nextHopType"),
            "next_hop": next_hop,
        }
        out.append(entry)
        _transit(
            d,
            next_hop if isinstance(next_hop, str) else None,
            f"route {','.join(map(str, entry['destinations']))} via next hop",
            destinations=entry["destinations"],
        )
    return out


@extractor("microsoft.network/virtualhubs/hubroutetables")
def _x_hub_route_table(d: _Draft, b: "AzureAssetBuilder") -> None:
    p = d.props
    d.md["routes"] = _route_targets(d, _get(p, "routes"))
    d.md["labels"] = _list(_get(p, "labels"))
    for conn in _list(_get(p, "associatedConnections")):
        d.add(rel(conn, EdgeType.ATTACHED_TO, description="associated connection"))


@extractor("microsoft.network/virtualhubs/routingintent")
def _x_routing_intent(d: _Draft, b: "AzureAssetBuilder") -> None:
    policies = []
    hub = parent_resource_id(d.id)
    for policy in _list(_get(d.props, "routingPolicies")):
        next_hop = _get(policy, "nextHop")
        destinations = _list(_get(policy, "destinations"))
        policies.append({"name": _get(policy, "name"), "destinations": destinations})
        _transit(d, next_hop, f"routing intent {destinations}", destinations=destinations)
        if hub and isinstance(next_hop, str):
            b.defer(
                hub,
                rel(
                    next_hop,
                    EdgeType.ROUTE,
                    "TRANSIT_ROUTED",
                    description="routing intent next hop",
                    destinations=destinations,
                ),
            )
    d.md["routing_policies"] = policies
    d.md["inspects_internet"] = any("Internet" in p["destinations"] for p in policies)
    d.md["inspects_private"] = any("PrivateTraffic" in p["destinations"] for p in policies)


@extractor("microsoft.network/virtualhubs/bgpconnections")
def _x_bgp_connection(d: _Draft, b: "AzureAssetBuilder") -> None:
    p = d.props
    peer = _get(p, "peerIp")
    d.md.update(
        {"peer_ip": peer, "peer_asn": _get(p, "peerAsn"), "state": _get(p, "connectionState")}
    )
    _transit(d, peer, "BGP peer", peer_asn=_get(p, "peerAsn"))
    d.add(rel(_rid(_get(p, "hubVirtualNetworkConnection")), EdgeType.REFERENCES, "DEPENDS_ON"))


@extractor("microsoft.network/virtualhubs/ipconfigurations")
def _x_hub_ip_configuration(d: _Draft, b: "AzureAssetBuilder") -> None:
    p = d.props
    d.add(rel(_rid(_get(p, "subnet")), EdgeType.CONTAINS, "SUBNET_CONTAINS_INSTANCE", reverse=True))
    d.add(rel(_rid(_get(p, "publicIPAddress")), EdgeType.ATTACHED_TO, reverse=True))
    d.alias(_get(p, "privateIPAddress"))


# ── ExpressRoute, VPN ──


@extractor("microsoft.network/expressroutecircuits")
def _x_er_circuit(d: _Draft, b: "AzureAssetBuilder") -> None:
    p = d.props
    provider = _get(p, "serviceProviderProperties") or {}
    peerings = []
    for peering in _list(_get(p, "peerings")):
        pp = _props(peering)
        peerings.append(
            {
                "name": _get(peering, "name"),
                "type": _get(pp, "peeringType"),
                "peer_asn": _get(pp, "peerASN"),
                "vlan": _get(pp, "vlanId"),
                "state": _get(pp, "state"),
            }
        )
        for conn in _list(_get(pp, "connections")):  # Global Reach
            other = _rid(_get(_props(conn), "peerExpressRouteCircuitPeering"))
            _transit(d, owner_resource_id(other), "Global Reach")
    d.md.update(
        {
            "provider": _get(provider, "serviceProviderName"),
            "peering_location": _get(provider, "peeringLocation"),
            "bandwidth_mbps": _get(provider, "bandwidthInMbps"),
            "peerings": peerings,
            "provider_state": _get(p, "serviceProviderProvisioningState"),
            "global_reach": _get(p, "globalReachEnabled"),
            "authorization_count": len(_list(_get(p, "authorizations"))),
        }
    )
    d.add(rel(_rid(_get(p, "expressRoutePort")), EdgeType.ATTACHED_TO, reverse=True))


@extractor("microsoft.network/expressroutegateways")
def _x_er_gateway(d: _Draft, b: "AzureAssetBuilder") -> None:
    p = d.props
    _contained_by(d, _get(p, "virtualHub"), "virtual hub")
    for conn in _list(_get(p, "expressRouteConnections")):
        peering = _rid(_get(_props(conn), "expressRouteCircuitPeering"))
        _transit(d, owner_resource_id(peering), "ExpressRoute connection")


@extractor("microsoft.network/vpngateways", "microsoft.network/p2svpngateways")
def _x_vwan_vpn_gateway(d: _Draft, b: "AzureAssetBuilder") -> None:
    p = d.props
    _contained_by(d, _get(p, "virtualHub"), "virtual hub")
    for conn in _list(_get(p, "connections")):
        _transit(d, _rid(_get(_props(conn), "remoteVpnSite")), "site-to-site connection")
    for cfg in _list(_get(p, "ipConfigurations")):
        d.alias(_get(cfg, "publicIpAddress"), _get(cfg, "privateIpAddress"))
    d.add(rel(_rid(_get(p, "vpnServerConfiguration")), EdgeType.REFERENCES, "DEPENDS_ON"))
    if _get(p, "p2SConnectionConfigurations"):
        d.exposed = True
    d.md["bgp_asn"] = _path(p, "bgpSettings", "asn")


@extractor("microsoft.network/vpnsites")
def _x_vpn_site(d: _Draft, b: "AzureAssetBuilder") -> None:
    p = d.props
    d.alias(_get(p, "ipAddress"))
    for link in _list(_get(p, "vpnSiteLinks")):
        lp = _props(link)
        d.alias(_get(lp, "ipAddress"), host_of(_get(lp, "fqdn")))
    d.md["address_space"] = _list(_path(p, "addressSpace", "addressPrefixes"))
    d.md["device_vendor"] = _path(p, "deviceProperties", "deviceVendor")
    _contained_by(d, _get(p, "virtualWan"), "virtual WAN")


@extractor("microsoft.network/localnetworkgateways")
def _x_local_gateway(d: _Draft, b: "AzureAssetBuilder") -> None:
    p = d.props
    d.alias(_get(p, "gatewayIpAddress"), host_of(_get(p, "fqdn")))
    d.md.update(
        {
            "gateway_ip": _get(p, "gatewayIpAddress"),
            "fqdn": _get(p, "fqdn"),
            "address_space": _list(_path(p, "localNetworkAddressSpace", "addressPrefixes")),
            "bgp_asn": _path(p, "bgpSettings", "asn"),
            "bgp_peering_address": _path(p, "bgpSettings", "bgpPeeringAddress"),
        }
    )


@extractor("microsoft.network/virtualnetworkgateways")
def _x_vnet_gateway_detail(d: _Draft, b: "AzureAssetBuilder") -> None:
    p = d.props
    client = _get(p, "vpnClientConfiguration") or {}
    d.md.update(
        {
            "gateway_type": _get(p, "gatewayType"),
            "vpn_type": _get(p, "vpnType"),
            "active_active": _get(p, "activeActive"),
            "bgp_enabled": _get(p, "enableBgp"),
            "bgp_asn": _path(p, "bgpSettings", "asn"),
            "point_to_site": bool(client),
            "vpn_client_protocols": _list(_get(client, "vpnClientProtocols")),
            "vpn_client_aad_tenant": _get(client, "aadTenant"),
        }
    )


# ── IP groups, prefixes ──


@extractor("microsoft.network/ipgroups")
def _x_ip_group(d: _Draft, b: "AzureAssetBuilder") -> None:
    d.md["ip_addresses"] = _list(_get(d.props, "ipAddresses"))[:500]
    for user in _rids(_get(d.props, "firewalls")) + _rids(_get(d.props, "firewallPolicies")):
        d.add(rel(user, EdgeType.REFERENCES, "DEPENDS_ON", reverse=True, description="IP group"))


@extractor("microsoft.network/publicipprefixes")
def _x_pip_prefix(d: _Draft, b: "AzureAssetBuilder") -> None:
    d.exposed = True
    d.md["ip_prefix"] = _get(d.props, "ipPrefix")
    d.md["prefix_length"] = _get(d.props, "prefixLength")
    for pip in _rids(_get(d.props, "publicIPAddresses")):
        d.add(rel(pip, EdgeType.CONTAINS, description="address from prefix"))
    d.add(rel(_rid(_get(d.props, "natGateway")), EdgeType.ATTACHED_TO))


# ── DNS ──

DNS_RECORD_TYPES = ("a", "aaaa", "cname", "mx", "ns", "txt", "srv", "caa", "ptr", "soa", "ds")
DNS_RECORD_ARM_TYPES = tuple(
    f"microsoft.network/{zone}/{rec}"
    for zone in ("dnszones", "privatednszones")
    for rec in DNS_RECORD_TYPES
)


@extractor("microsoft.network/dnszones", "microsoft.network/privatednszones")
def _x_dns_zone(d: _Draft, b: "AzureAssetBuilder") -> None:
    p = d.props
    private = d.type.endswith("privatednszones")
    d.md.update(
        {
            "zone_name": d.name,
            "private": private,
            "record_set_count": _get(p, "numberOfRecordSets"),
            "name_servers": _list(_get(p, "nameServers")),
            "vnet_link_count": _get(p, "numberOfVirtualNetworkLinks"),
        }
    )
    for vnet in _rids(_get(p, "registrationVirtualNetworks")) + _rids(
        _get(p, "resolutionVirtualNetworks")
    ):
        d.add(rel(vnet, EdgeType.REFERENCES, "DNS_RESOLVED"))


@extractor(*DNS_RECORD_ARM_TYPES)
def _x_dns_record(d: _Draft, b: "AzureAssetBuilder") -> None:
    p = d.props
    rtype = d.type.rsplit("/", 1)[-1].upper()
    fqdn = str(_get(p, "fqdn") or "").rstrip(".").lower() or None
    values: list[str] = []
    for rec in _list(_get(p, "ARecords")) + _list(_get(p, "aRecords")):
        values.append(_get(rec, "ipv4Address"))
    for rec in _list(_get(p, "AAAARecords")) + _list(_get(p, "aaaaRecords")):
        values.append(_get(rec, "ipv6Address"))
    cname = _get(_get(p, "CNAMERecord") or _get(p, "cnameRecord") or {}, "cname")
    if cname:
        values.append(str(cname).rstrip(".").lower())
    for rec in _list(_get(p, "MXRecords")) + _list(_get(p, "mxRecords")):
        values.append(str(_get(rec, "exchange") or "").rstrip(".").lower())
    for rec in _list(_get(p, "NSRecords")) + _list(_get(p, "nsRecords")):
        values.append(str(_get(rec, "nsdname") or "").rstrip(".").lower())
    values = [v for v in dict.fromkeys(values) if v]
    if fqdn:
        d.name = fqdn
    target = _rid(_get(p, "targetResource"))
    d.md.update(
        {
            "record_type": rtype,
            "fqdn": fqdn,
            "ttl": _get(p, "TTL") or _get(p, "ttl"),
            "values": values[:50],
            "alias_target": target,
            "private_zone": "/privatednszones/" in d.id.lower(),
        }
    )
    d.add(rel(target, EdgeType.ROUTE, "DNS_RESOLVED", description="alias record"))
    if rtype in ("A", "AAAA", "CNAME"):
        for value in values:
            d.add(rel(value, EdgeType.ROUTE, "DNS_RESOLVED", description=f"{rtype} record"))
    if rtype == "SOA" or (rtype == "NS" and str(d.row.get("name")) == "@"):
        d.md["zone_apex"] = True


@extractor("microsoft.network/dnsresolvers")
def _x_dns_resolver(d: _Draft, b: "AzureAssetBuilder") -> None:
    d.add(rel(_rid(_get(d.props, "virtualNetwork")), EdgeType.REFERENCES, "DNS_RESOLVED"))


@extractor(
    "microsoft.network/dnsresolvers/inboundendpoints",
    "microsoft.network/dnsresolvers/outboundendpoints",
)
def _x_dns_resolver_endpoint(d: _Draft, b: "AzureAssetBuilder") -> None:
    p = d.props
    d.md["direction"] = "inbound" if d.type.endswith("inboundendpoints") else "outbound"
    subnets = [_rid(_get(c, "subnet")) for c in _list(_get(p, "ipConfigurations"))]
    subnets.append(_rid(_get(p, "subnet")))
    for subnet in subnets:
        d.add(rel(subnet, EdgeType.CONTAINS, "SUBNET_CONTAINS_INSTANCE", reverse=True))
    for cfg in _list(_get(p, "ipConfigurations")):
        d.alias(_get(cfg, "privateIpAddress"))


@extractor("microsoft.network/dnsforwardingrulesets")
def _x_forwarding_ruleset(d: _Draft, b: "AzureAssetBuilder") -> None:
    for ep in _rids(_get(d.props, "dnsResolverOutboundEndpoints")):
        d.add(rel(ep, EdgeType.REFERENCES, "DEPENDS_ON", description="outbound endpoint"))


@extractor("microsoft.network/dnsforwardingrulesets/forwardingrules")
def _x_forwarding_rule(d: _Draft, b: "AzureAssetBuilder") -> None:
    p = d.props
    targets = [_get(t, "ipAddress") for t in _list(_get(p, "targetDnsServers"))]
    d.md.update(
        {
            "domain_name": _get(p, "domainName"),
            "state": _get(p, "forwardingRuleState"),
            "target_dns_servers": [t for t in targets if t],
        }
    )
    for ip in targets:
        d.add(
            rel(ip, EdgeType.ROUTE, "DNS_RESOLVED", description=f"forward {_get(p, 'domainName')}")
        )


@relation_row("microsoft.network/dnsforwardingrulesets/virtualnetworklinks")
def _ruleset_vnet_link(row: dict[str, Any], b: "AzureAssetBuilder") -> None:
    vnet = _rid(_get(row.get("properties") or {}, "virtualNetwork"))
    b.defer(
        parent_resource_id(row.get("id")),
        rel(vnet, EdgeType.REFERENCES, "DNS_RESOLVED", description="ruleset VNet link"),
    )


@extractor("microsoft.network/trafficmanagerprofiles")
def _x_traffic_manager(d: _Draft, b: "AzureAssetBuilder") -> None:
    p = d.props
    fqdn = _path(p, "dnsConfig", "fqdn")
    d.alias(fqdn.lower() if isinstance(fqdn, str) else None)
    d.exposed = _lower(_get(p, "profileStatus") or "enabled") == "enabled"
    endpoints = []
    for ep in _list(_get(p, "endpoints")):
        ep_props = _props(ep)
        target = _get(ep_props, "targetResourceId") or (
            str(_get(ep_props, "target") or "").lower() or None
        )
        endpoints.append({"name": _get(ep, "name"), "target": target})
        d.add(
            rel(
                target,
                EdgeType.LOAD_BALANCER_TARGET,
                "SERVES_TRAFFIC_TO",
                description=f"{_get(ep, 'type') or 'endpoint'}",
                status=_get(ep_props, "endpointStatus"),
            )
        )
    d.md.update(
        {
            "fqdn": fqdn,
            "routing_method": _get(p, "trafficRoutingMethod"),
            "endpoints": endpoints,
        }
    )


# ── WAF policies ──


def _waf_settings(d: _Draft) -> None:
    p = d.props
    settings = _get(p, "policySettings") or {}
    managed = _list(_path(p, "managedRules", "managedRuleSets"))
    custom = _path(p, "customRules", "rules") or _get(p, "customRules")
    mode = _get(settings, "mode")
    d.md.update(
        {
            "waf_mode": mode,
            "waf_enabled": _lower(_get(settings, "enabledState") or _get(settings, "state"))
            != "disabled",
            "detection_only": _lower(mode) == "detection",
            "managed_rule_sets": [
                f"{_get(m, 'ruleSetType')} {_get(m, 'ruleSetVersion')}".strip() for m in managed
            ],
            "custom_rule_count": len(_list(custom)) if isinstance(custom, list) else None,
        }
    )


@extractor(
    "microsoft.network/frontdoorwebapplicationfirewallpolicies",
    "microsoft.network/applicationgatewaywebapplicationfirewallpolicies",
    "microsoft.cdn/cdnwebapplicationfirewallpolicies",
)
def _x_waf_policy(d: _Draft, b: "AzureAssetBuilder") -> None:
    p = d.props
    _waf_settings(d)
    protected = _rids(_get(p, "applicationGateways")) + _rids(_get(p, "httpListeners"))
    protected += [owner_resource_id(x) for x in _rids(_get(p, "pathBasedRules"))]
    protected += [owner_resource_id(x) for x in _rids(_get(p, "frontendEndpointLinks"))]
    protected += [owner_resource_id(x) for x in _rids(_get(p, "endpointLinks"))]
    for target in dict.fromkeys(t for t in protected if t):
        d.add(rel(target, EdgeType.PROTECTS, "PROTECTED_BY_WAF", description="WAF policy"))
    for link in _rids(_get(p, "securityPolicyLinks")):
        d.add(rel(link, EdgeType.REFERENCES, "DEPENDS_ON", reverse=True))


# ── Front Door Standard / Premium children ──


@extractor("microsoft.cdn/profiles")
def _x_cdn_profile(d: _Draft, b: "AzureAssetBuilder") -> None:
    sku = d.row.get("sku")
    d.md["sku"] = _get(sku, "name") if isinstance(sku, dict) else sku
    d.alias(_get(d.props, "frontDoorId"))


@extractor("microsoft.cdn/profiles/afdendpoints/routes")
def _x_afd_route(d: _Draft, b: "AzureAssetBuilder") -> None:
    p = d.props
    group = _rid(_get(p, "originGroup"))
    d.md.update(
        {
            "patterns": _list(_get(p, "patternsToMatch")),
            "forwarding_protocol": _get(p, "forwardingProtocol"),
            "https_redirect": _get(p, "httpsRedirect"),
            "supported_protocols": _list(_get(p, "supportedProtocols")),
            "link_to_default_domain": _get(p, "linkToDefaultDomain"),
            "caching": bool(_get(p, "cacheConfiguration")),
        }
    )
    d.add(
        rel(group, EdgeType.LOAD_BALANCER_TARGET, "SERVES_TRAFFIC_TO", description="origin group")
    )
    for domain in _rids(_get(p, "customDomains")):
        d.add(rel(domain, EdgeType.REFERENCES, "DEPENDS_ON", description="custom domain"))
    for rs in _rids(_get(p, "ruleSets")):
        d.add(rel(rs, EdgeType.REFERENCES, "DEPENDS_ON", description="rule set"))
    endpoint = parent_resource_id(d.id)
    if endpoint and group:
        b.defer(
            endpoint,
            rel(group, EdgeType.LOAD_BALANCER_TARGET, "SERVES_TRAFFIC_TO", description="route"),
        )


@extractor("microsoft.cdn/profiles/origingroups")
def _x_afd_origin_group(d: _Draft, b: "AzureAssetBuilder") -> None:
    p = d.props
    d.md["health_probe"] = _get(p, "healthProbeSettings")
    d.md["session_affinity"] = _get(p, "sessionAffinityState")


@extractor("microsoft.cdn/profiles/rulesets/rules")
def _x_afd_rule(d: _Draft, b: "AzureAssetBuilder") -> None:
    p = d.props
    actions = []
    for action in _list(_get(p, "actions")):
        name = _get(action, "name")
        actions.append(name)
        params = _get(action, "parameters") or {}
        group = _rid(_path(params, "originGroupOverride", "originGroup"))
        d.add(rel(group, EdgeType.LOAD_BALANCER_TARGET, "SERVES_TRAFFIC_TO", description=name))
    d.md["actions"] = actions
    d.md["conditions"] = [_get(c, "name") for c in _list(_get(p, "conditions"))]
    d.md["order"] = _get(p, "order")


@extractor("microsoft.cdn/profiles/secrets")
def _x_afd_secret(d: _Draft, b: "AzureAssetBuilder") -> None:
    source = _path(d.props, "parameters", "secretSource", "id")
    d.md["secret_type"] = _path(d.props, "parameters", "type")
    vault = None
    if isinstance(source, str) and "/providers/microsoft.keyvault/vaults/" in source.lower():
        vault = owner_resource_id(source)
    d.add(
        rel(
            vault,
            EdgeType.REFERENCES,
            "CERTIFICATE_SECURES",
            description="certificate from Key Vault",
            key_vault_secret=source,
        )
    )


@extractor("microsoft.cdn/profiles/customdomains")
def _x_afd_custom_domain_tls(d: _Draft, b: "AzureAssetBuilder") -> None:
    p = d.props
    tls = _get(p, "tlsSettings") or {}
    d.md["certificate_type"] = _get(tls, "certificateType")
    d.md["minimum_tls_version"] = _get(tls, "minimumTlsVersion")
    d.md["validation_state"] = _get(p, "domainValidationState")
    d.add(rel(_rid(_get(tls, "secret")), EdgeType.REFERENCES, "CERTIFICATE_SECURES", reverse=True))
    d.add(rel(_rid(_get(p, "azureDnsZone")), EdgeType.REFERENCES, "DNS_RESOLVED"))


# ── Application Gateway listeners ──


def _appgw_pool_targets(p: dict[str, Any]) -> dict[str, list[tuple[str, str]]]:
    """Backend pool id (lowercase) -> [(target, relationship)]."""
    pools: dict[str, list[tuple[str, str]]] = {}
    for pool in _list(_get(p, "backendAddressPools")):
        pid = _rid(pool)
        if not pid:
            continue
        pp = _props(pool)
        targets: list[tuple[str, str]] = []
        for ipc in _rids(_get(pp, "backendIPConfigurations")):
            owner = owner_resource_id(ipc)
            if owner:
                targets.append((owner, "LB_TARGETS_INSTANCE"))
        for addr in _list(_get(pp, "backendAddresses")):
            target = _get(addr, "fqdn") or _get(addr, "ipAddress")
            if target:
                targets.append((str(target).lower(), "SERVES_TRAFFIC_TO"))
        pools[pid.lower()] = targets
    return pools


def _listener_pools(p: dict[str, Any]) -> dict[str, list[str]]:
    """Listener id (lowercase) -> backend pool ids reached by its routing rules."""
    path_maps: dict[str, list[str]] = {}
    for upm in _list(_get(p, "urlPathMaps")):
        up = _props(upm)
        pools = [_rid(_get(up, "defaultBackendAddressPool"))]
        pools += [_rid(_get(_props(r), "backendAddressPool")) for r in _list(_get(up, "pathRules"))]
        path_maps[str(_rid(upm)).lower()] = [x for x in pools if x]
    out: dict[str, list[str]] = {}
    for rule in _list(_get(p, "requestRoutingRules")):
        rp = _props(rule)
        listener = _rid(_get(rp, "httpListener"))
        if not listener:
            continue
        pools = [_rid(_get(rp, "backendAddressPool"))]
        pools += path_maps.get(str(_rid(_get(rp, "urlPathMap"))).lower(), [])
        out.setdefault(listener.lower(), []).extend(x for x in pools if x)
    return out


def _public_frontends(p: dict[str, Any]) -> set[str]:
    return {
        str(_rid(fe)).lower()
        for fe in _list(_get(p, "frontendIPConfigurations"))
        if _rid(_get(_props(fe), "publicIPAddress"))
    }


@extractor("microsoft.network/applicationgateways")
def _x_appgw_listeners(d: _Draft, b: "AzureAssetBuilder") -> None:
    p = d.props
    pools = _appgw_pool_targets(p)
    reached = _listener_pools(p)
    public = _public_frontends(p)
    ports = {
        str(_rid(fp)).lower(): _get(_props(fp), "port") for fp in _list(_get(p, "frontendPorts"))
    }
    certs = {
        str(_rid(c)).lower(): _get(_props(c), "keyVaultSecretId")
        for c in _list(_get(p, "sslCertificates"))
    }
    listeners = []
    for listener in _list(_get(p, "httpListeners")):
        lid = _rid(listener)
        if not lid:
            continue
        lp = _props(listener)
        listeners.append(_get(listener, "name"))
        targets: list[tuple[str, str]] = []
        for pool in reached.get(lid.lower(), []):
            targets.extend(pools.get(pool.lower(), []))
        b.add_row(
            {
                "id": lid,
                "name": _get(listener, "name") or lid.rsplit("/", 1)[-1],
                "type": "microsoft.network/applicationgateways/httplisteners",
                "location": d.region,
                "subscriptionId": d.account_id,
                "properties": {
                    **lp,
                    "_frontendPort": ports.get(str(_rid(_get(lp, "frontendPort"))).lower()),
                    "_public": str(_rid(_get(lp, "frontendIPConfiguration"))).lower() in public,
                    "_targets": [list(t) for t in dict.fromkeys(targets)],
                    "_certificate": certs.get(str(_rid(_get(lp, "sslCertificate"))).lower()),
                },
            },
            synthetic=True,
        )
    d.md["listeners"] = listeners


@extractor("microsoft.network/applicationgateways/httplisteners")
def _x_appgw_listener(d: _Draft, b: "AzureAssetBuilder") -> None:
    p = d.props
    hosts = [h for h in [_get(p, "hostName")] + _list(_get(p, "hostNames")) if h]
    d.md.update(
        {
            "protocol": _get(p, "protocol"),
            "port": _get(p, "_frontendPort"),
            "host_names": hosts,
            "public": bool(_get(p, "_public")),
            "require_sni": _get(p, "requireServerNameIndication"),
        }
    )
    d.exposed = bool(_get(p, "_public"))
    for target, relationship in _get(p, "_targets") or []:
        d.add(rel(target, EdgeType.LOAD_BALANCER_TARGET, relationship, description="routing rule"))
    d.add(
        rel(
            _rid(_get(p, "firewallPolicy")),
            EdgeType.PROTECTS,
            "PROTECTED_BY_WAF",
            reverse=True,
            description="listener WAF policy",
        )
    )
    cert = _get(p, "_certificate")
    d.add(rel(host_of(cert), EdgeType.REFERENCES, "CERTIFICATE_SECURES", key_vault_secret=cert))
    d.props = {k: v for k, v in p.items() if not k.startswith("_")}


# ── private endpoint DNS ──


@extractor("microsoft.network/privateendpoints")
def _x_private_endpoint_ips(d: _Draft, b: "AzureAssetBuilder") -> None:
    """Private IPs of an endpoint, so private DNS A records resolve to it."""
    for cfg in _list(_get(d.props, "customDnsConfigs")):
        d.alias(*[str(ip) for ip in _list(_get(cfg, "ipAddresses"))])
    for cfg in _list(_get(d.props, "ipConfigurations")):
        d.alias(_get(_props(cfg), "privateIPAddress"))


# ── Private Link service visibility ──


@extractor("microsoft.network/privatelinkservices")
def _x_pls_visibility(d: _Draft, b: "AzureAssetBuilder") -> None:
    p = d.props
    visible = [str(s) for s in _list(_path(p, "visibility", "subscriptions"))]
    auto = {str(s).lower() for s in _list(_path(p, "autoApproval", "subscriptions"))}
    d.md["visibility"] = visible
    d.md["auto_approval"] = sorted(auto)
    d.md["fqdns"] = _list(_get(p, "fqdns"))
    d.alias(*[str(f).lower() for f in _list(_get(p, "fqdns"))])
    if "*" in visible:
        d.md["public_visibility"] = True
    for sub in visible:
        if sub == "*":
            continue
        d.add(
            rel(
                subscription_ref(sub),
                EdgeType.GRANTS_ACCESS,
                "POLICY_ALLOWS_ACTION",
                reverse=True,
                description="may connect private endpoints",
                auto_approved=sub.lower() in auto or None,
                cross_account=sub.lower() != d.account_id.lower() or None,
            )
        )


# ── Virtual Network Manager ──


@extractor("microsoft.network/networkmanagers")
def _x_network_manager(d: _Draft, b: "AzureAssetBuilder") -> None:
    p = d.props
    scopes = _get(p, "networkManagerScopes") or {}
    d.md["scope_accesses"] = _list(_get(p, "networkManagerScopeAccesses"))
    for sub in _list(_get(scopes, "subscriptions")):
        d.add(rel(sub, EdgeType.GOVERNS, "COMPLIANCE_GOVERNS", description="network manager scope"))
    for mg in _list(_get(scopes, "managementGroups")):
        d.add(rel(mg, EdgeType.GOVERNS, "COMPLIANCE_GOVERNS", description="network manager scope"))


@extractor("microsoft.network/networkmanagers/networkgroups")
def _x_network_group(d: _Draft, b: "AzureAssetBuilder") -> None:
    d.md["member_type"] = _get(d.props, "memberType")


@relation_row("microsoft.network/networkmanagers/networkgroups/staticmembers")
def _static_member(row: dict[str, Any], b: "AzureAssetBuilder") -> None:
    member = _get(row.get("properties") or {}, "resourceId")
    b.defer(
        parent_resource_id(row.get("id")),
        rel(member, EdgeType.CONTAINS, description="static member"),
    )


@extractor("microsoft.network/networkmanagers/connectivityconfigurations")
def _x_connectivity_config(d: _Draft, b: "AzureAssetBuilder") -> None:
    p = d.props
    topology = _get(p, "connectivityTopology")
    d.md.update(
        {
            "topology": topology,
            "global_mesh": _get(p, "isGlobal"),
            "delete_existing_peering": _get(p, "deleteExistingPeering"),
        }
    )
    for hub in _list(_get(p, "hubs")):
        _transit(d, _get(hub, "resourceId"), f"{topology} hub")
    for group in _list(_get(p, "appliesToGroups")):
        d.add(
            rel(
                _get(group, "networkGroupId"),
                EdgeType.ROUTE,
                "TRANSIT_ROUTED",
                description=f"{topology} member group",
                use_hub_gateway=_get(group, "useHubGateway"),
                direct_connectivity=_get(group, "groupConnectivity"),
            )
        )


@extractor("microsoft.network/networkmanagers/securityadminconfigurations/rulecollections")
def _x_admin_rule_collection(d: _Draft, b: "AzureAssetBuilder") -> None:
    for group in _list(_get(d.props, "appliesToGroups")):
        d.add(
            rel(
                _get(group, "networkGroupId"),
                EdgeType.PROTECTS,
                "PROTECTED_BY_NACL",
                description="security admin rules",
            )
        )


@relation_row("microsoft.network/networkmanagers/securityadminconfigurations/rulecollections/rules")
def _admin_rule(row: dict[str, Any], b: "AzureAssetBuilder") -> None:
    p = row.get("properties") or {}
    collection = parent_resource_id(row.get("id"))
    if not collection:
        return
    b.state.setdefault("admin_rules", {}).setdefault(collection.lower(), []).append(
        {
            "name": row.get("name"),
            "access": _get(p, "access"),
            "direction": _get(p, "direction"),
            "priority": _get(p, "priority"),
            "protocol": _get(p, "protocol"),
            "sources": [_get(s, "addressPrefix") for s in _list(_get(p, "sources"))],
            "destination_ports": _list(_get(p, "destinationPortRanges")),
        }
    )
    b.at_build(_attach_admin_rules)


def _attach_admin_rules(b: "AzureAssetBuilder") -> None:
    for collection, rules in (b.state.get("admin_rules") or {}).items():
        d = b.draft(collection)
        if d is not None:
            d.md["rules"] = rules[:200]
            d.md["denies"] = any(_lower(r.get("access")) == "deny" for r in rules)


__all__ = ["DNS_RECORD_ARM_TYPES"]
