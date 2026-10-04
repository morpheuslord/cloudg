"""Extractors for virtual networking: VNets, subnets, NICs, NSGs, routing."""

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
    owner_resource_id,
    parent_resource_id,
)
from cloudg.inventory.azure_graph.registry import (
    _Draft,
    extractor,
)
from cloudg.schema.models import EdgeType

if TYPE_CHECKING:
    from cloudg.inventory.azure_graph.builder import AzureAssetBuilder


def _nsg_rule(rule: dict[str, Any], default: bool) -> dict[str, Any]:
    p = _props(rule)
    sources = [
        s for s in [_get(p, "sourceAddressPrefix")] + _list(_get(p, "sourceAddressPrefixes")) if s
    ]
    dests = [
        s
        for s in [_get(p, "destinationAddressPrefix")]
        + _list(_get(p, "destinationAddressPrefixes"))
        if s
    ]
    ports = [
        s for s in [_get(p, "destinationPortRange")] + _list(_get(p, "destinationPortRanges")) if s
    ]
    src_ports = [s for s in [_get(p, "sourcePortRange")] + _list(_get(p, "sourcePortRanges")) if s]
    return {
        "name": _get(rule, "name"),
        "priority": _get(p, "priority"),
        "direction": _get(p, "direction"),
        "access": _get(p, "access"),
        "protocol": _get(p, "protocol"),
        "source_address_prefix": _get(p, "sourceAddressPrefix"),
        "source_address_prefixes": sources,
        "source_application_security_groups": _rids(_get(p, "sourceApplicationSecurityGroups")),
        "destination_address_prefix": _get(p, "destinationAddressPrefix"),
        "destination_address_prefixes": dests,
        "destination_application_security_groups": _rids(
            _get(p, "destinationApplicationSecurityGroups")
        ),
        "destination_port_range": _get(p, "destinationPortRange"),
        "destination_port_ranges": ports,
        "source_port_ranges": src_ports,
        "default": default,
    }


@extractor("microsoft.network/networksecuritygroups")
def _x_nsg(d: _Draft, b: "AzureAssetBuilder") -> None:
    ingress: list[dict[str, Any]] = []
    egress: list[dict[str, Any]] = []
    for key, default in (("securityRules", False), ("defaultSecurityRules", True)):
        for rule in _list(_get(d.props, key)):
            if not isinstance(rule, dict):
                continue
            data = _nsg_rule(rule, default)
            (ingress if _lower(data["direction"]) == "inbound" else egress).append(data)
    d.md["ingress_rules"] = ingress
    d.md["egress_rules"] = egress
    d.md["subnet_ids"] = _rids(_get(d.props, "subnets"))
    d.md["network_interface_ids"] = _rids(_get(d.props, "networkInterfaces"))


@extractor("microsoft.network/virtualnetworks")
def _x_vnet(d: _Draft, b: "AzureAssetBuilder") -> None:
    d.md["address_space"] = _list(_path(d.props, "addressSpace", "addressPrefixes"))
    ddos = _rid(_get(d.props, "ddosProtectionPlan"))
    d.add(rel(ddos, EdgeType.PROTECTS, reverse=True, description="DDoS protection plan"))
    subnet_ids: list[str] = []
    for sn in _list(_get(d.props, "subnets")):
        sid = _rid(sn)
        if not sid:
            continue
        subnet_ids.append(sid)
        b.add_row(
            {
                "id": sid,
                "name": _get(sn, "name") or sid.rsplit("/", 1)[-1],
                "type": "microsoft.network/virtualnetworks/subnets",
                "location": d.region,
                "subscriptionId": d.account_id,
                "properties": _props(sn),
            },
            synthetic=True,
            vnet_id=d.id,
        )
    d.md["subnet_ids"] = subnet_ids
    for peering in _list(_get(d.props, "virtualNetworkPeerings")):
        p = _props(peering)
        remote = _rid(_get(p, "remoteVirtualNetwork"))
        d.add(
            rel(
                remote,
                EdgeType.PEERING,
                "VPC_PEERED",
                description=f"peering {_get(peering, 'name')}",
                peering_state=_get(p, "peeringState"),
                allow_forwarded_traffic=_get(p, "allowForwardedTraffic"),
                allow_gateway_transit=_get(p, "allowGatewayTransit"),
                use_remote_gateways=_get(p, "useRemoteGateways"),
            )
        )
    # subnets become their own assets; keep the VNet bag small
    d.props = {k: v for k, v in d.props.items() if k != "subnets"}


@extractor("microsoft.network/virtualnetworks/subnets")
def _x_subnet(d: _Draft, b: "AzureAssetBuilder") -> None:
    prefixes = [
        p for p in [_get(d.props, "addressPrefix")] + _list(_get(d.props, "addressPrefixes")) if p
    ]
    d.md["address_prefix"] = prefixes[0] if prefixes else None
    d.md["address_prefixes"] = list(dict.fromkeys(prefixes))
    vnet = d.md.get("vnet_id") or parent_resource_id(d.id)
    d.md["vnet_id"] = vnet
    d.md["nsg_id"] = _rid(_get(d.props, "networkSecurityGroup"))
    rt = _rid(_get(d.props, "routeTable"))
    nat = _rid(_get(d.props, "natGateway"))
    d.md["route_table"] = rt
    d.md["nat_gateway"] = nat
    d.add(rel(rt, EdgeType.ATTACHED_TO, reverse=True, description="route table association"))
    d.add(rel(nat, EdgeType.ATTACHED_TO, "NAT_TRANSLATED", reverse=True, description="NAT gateway"))
    d.md["service_endpoints"] = [
        _get(se, "service")
        for se in _list(_get(d.props, "serviceEndpoints"))
        if _get(se, "service")
    ]
    d.md["delegations"] = [
        _get(_props(dl), "serviceName")
        for dl in _list(_get(d.props, "delegations"))
        if _get(_props(dl), "serviceName")
    ]
    d.md["private_endpoint_ids"] = _rids(_get(d.props, "privateEndpoints"))
    d.md["private_endpoint_network_policies"] = _get(d.props, "privateEndpointNetworkPolicies")
    # ipConfigurations lists every NIC in the subnet; NICs link themselves
    d.props = {
        k: v for k, v in d.props.items() if k not in ("ipConfigurations", "ipConfigurationProfiles")
    }


def _nic_pool_targets(d: _Draft, p: dict[str, Any]) -> None:
    """Load balancer / application gateway backend pools of a NIC ipConfiguration."""
    lb_pools = _rids(_get(p, "loadBalancerBackendAddressPools")) + _rids(
        _get(p, "loadBalancerInboundNatRules")
    )
    for pool in lb_pools + _rids(_get(p, "applicationGatewayBackendAddressPools")):
        d.add(
            rel(
                owner_resource_id(pool),
                EdgeType.LOAD_BALANCER_TARGET,
                "LB_TARGETS_INSTANCE",
                reverse=True,
                backend_pool=pool,
            )
        )


def _nic_ip_config(
    d: _Draft, cfg: Any, subnets: list[str], private_ips: list[str], public_ips: list[str]
) -> None:
    p = _props(cfg)
    d.alias(_rid(cfg))
    subnet = _rid(_get(p, "subnet"))
    if subnet and subnet not in subnets:
        subnets.append(subnet)
    ip = _get(p, "privateIPAddress")
    if ip:
        private_ips.append(ip)
    pip = _rid(_get(p, "publicIPAddress"))
    if pip:
        public_ips.append(pip)
        d.add(rel(pip, EdgeType.ATTACHED_TO, reverse=True, description="public IP"))
    _nic_pool_targets(d, p)
    for asg in _rids(_get(p, "applicationSecurityGroups")):
        if asg not in d.md.setdefault("security_groups", []):
            d.md["security_groups"].append(asg)


@extractor("microsoft.network/networkinterfaces")
def _x_nic(d: _Draft, b: "AzureAssetBuilder") -> None:
    subnets: list[str] = []
    private_ips: list[str] = []
    public_ips: list[str] = []
    for cfg in _list(_get(d.props, "ipConfigurations")):
        _nic_ip_config(d, cfg, subnets, private_ips, public_ips)
    for extra in subnets[1:]:
        d.add(rel(extra, EdgeType.CONTAINS, "SUBNET_CONTAINS_INSTANCE", reverse=True))
    vm = _rid(_get(d.props, "virtualMachine"))
    pe = _rid(_get(d.props, "privateEndpoint"))
    d.md.update(
        {
            "attached_instance_id": vm,
            "nsg_id": _rid(_get(d.props, "networkSecurityGroup")),
            "subnet_id": subnets[0] if subnets else None,
            "subnet_ids": subnets,
            "private_ip": private_ips[0] if private_ips else None,
            "private_ips": private_ips,
            "public_ip_id": public_ips[0] if public_ips else None,
            "public_ip_ids": public_ips,
            "private_endpoint_id": pe,
            "ip_forwarding": bool(_get(d.props, "enableIPForwarding")),
            "mac_address": _get(d.props, "macAddress"),
        }
    )
    if pe:
        d.add(rel(pe, EdgeType.ATTACHED_TO, description="private endpoint interface"))
    if d.md["ip_forwarding"]:
        d.alias(*private_ips)  # NVA next hops resolve to this interface
    if public_ips:
        d.exposed = True


@extractor("microsoft.network/publicipaddresses")
def _x_pip(d: _Draft, b: "AzureAssetBuilder") -> None:
    d.exposed = True
    fqdn = _path(d.props, "dnsSettings", "fqdn")
    d.md.update(
        {
            "public_ip": _get(d.props, "ipAddress"),
            "allocation_method": _get(d.props, "publicIPAllocationMethod"),
            "fqdn": fqdn,
        }
    )
    d.alias(fqdn.lower() if isinstance(fqdn, str) else None)
    ipc = _rid(_get(d.props, "ipConfiguration"))
    d.add(rel(owner_resource_id(ipc), EdgeType.ATTACHED_TO, description="public IP association"))
    d.add(
        rel(
            _rid(_get(d.props, "natGateway")),
            EdgeType.ATTACHED_TO,
            description="NAT gateway public IP",
        )
    )


@extractor("microsoft.network/firewallpolicies")
def _x_firewall_policy(d: _Draft, b: "AzureAssetBuilder") -> None:
    d.add(
        rel(
            _rid(_get(d.props, "basePolicy")),
            EdgeType.REFERENCES,
            "DEPENDS_ON",
            description="base policy",
        )
    )


@extractor("microsoft.network/routetables")
def _x_route_table(d: _Draft, b: "AzureAssetBuilder") -> None:
    routes = []
    for route in _list(_get(d.props, "routes")):
        p = _props(route)
        entry = {
            "name": _get(route, "name"),
            "address_prefix": _get(p, "addressPrefix"),
            "next_hop_type": _get(p, "nextHopType"),
            "next_hop_ip": _get(p, "nextHopIpAddress"),
        }
        routes.append(entry)
        if entry["next_hop_ip"]:
            d.add(
                rel(
                    entry["next_hop_ip"],
                    EdgeType.ROUTE,
                    "TRANSIT_ROUTED",
                    description=f"route {entry['address_prefix']} via {entry['next_hop_ip']}",
                    address_prefix=entry["address_prefix"],
                    next_hop_type=entry["next_hop_type"],
                )
            )
        if _lower(entry["next_hop_type"]) == "internet" and entry["address_prefix"] in (
            "0.0.0.0/0",
            "::/0",
        ):
            d.md["default_route_to_internet"] = True
    d.md["routes"] = routes
    d.md["subnet_ids"] = _rids(_get(d.props, "subnets"))
    for sn in d.md["subnet_ids"]:
        d.add(rel(sn, EdgeType.ATTACHED_TO, description="route table association"))
    d.md["bgp_route_propagation_disabled"] = _get(d.props, "disableBgpRoutePropagation")


@extractor("microsoft.network/natgateways")
def _x_nat(d: _Draft, b: "AzureAssetBuilder") -> None:
    for pip in _rids(_get(d.props, "publicIpAddresses")) + _rids(_get(d.props, "publicIpPrefixes")):
        d.add(rel(pip, EdgeType.ATTACHED_TO, reverse=True, description="NAT gateway public IP"))
    for sn in _rids(_get(d.props, "subnets")):
        d.add(rel(sn, EdgeType.ATTACHED_TO, "NAT_TRANSLATED", description="NAT gateway"))


@extractor("microsoft.network/privateendpoints")
def _x_private_endpoint(d: _Draft, b: "AzureAssetBuilder") -> None:
    subnet = _rid(_get(d.props, "subnet"))
    d.md["subnet_id"] = subnet
    d.md["network_interfaces"] = _rids(_get(d.props, "networkInterfaces"))
    targets = []
    for key in ("privateLinkServiceConnections", "manualPrivateLinkServiceConnections"):
        for conn in _list(_get(d.props, key)):
            p = _props(conn)
            target = _get(p, "privateLinkServiceId")
            groups = _list(_get(p, "groupIds"))
            if target:
                targets.append({"target": target, "group_ids": groups})
            d.add(
                rel(
                    target,
                    EdgeType.REFERENCES,
                    "DEPENDS_ON",
                    description="private link",
                    group_ids=groups,
                    manual=key.startswith("manual"),
                    status=_path(p, "privateLinkServiceConnectionState", "status"),
                )
            )
    d.md["private_link_targets"] = targets
    fqdns = [_get(c, "fqdn") for c in _list(_get(d.props, "customDnsConfigs")) if _get(c, "fqdn")]
    d.md["fqdns"] = fqdns


@extractor("microsoft.network/privatelinkservices")
def _x_pls(d: _Draft, b: "AzureAssetBuilder") -> None:
    for fe in _rids(_get(d.props, "loadBalancerFrontendIpConfigurations")):
        d.add(
            rel(
                owner_resource_id(fe),
                EdgeType.REFERENCES,
                "SERVES_TRAFFIC_TO",
                description="load balancer frontend",
            )
        )
    for cfg in _list(_get(d.props, "ipConfigurations")):
        d.add(
            rel(
                _rid(_get(_props(cfg), "subnet")),
                EdgeType.CONTAINS,
                "SUBNET_CONTAINS_INSTANCE",
                reverse=True,
            )
        )


@extractor("microsoft.network/connections")
def _x_connection(d: _Draft, b: "AzureAssetBuilder") -> None:
    for key in ("virtualNetworkGateway1", "virtualNetworkGateway2", "localNetworkGateway2"):
        d.add(rel(_rid(_get(d.props, key)), EdgeType.ATTACHED_TO, "TRANSIT_ROUTED"))
    d.add(rel(_rid(_get(d.props, "peer")), EdgeType.ATTACHED_TO, "TRANSIT_ROUTED"))
    d.md["connection_type"] = _get(d.props, "connectionType")


@extractor("microsoft.network/privatednszones/virtualnetworklinks")
def _x_dns_link(d: _Draft, b: "AzureAssetBuilder") -> None:
    d.add(
        rel(
            _rid(_get(d.props, "virtualNetwork")),
            EdgeType.REFERENCES,
            "DNS_RESOLVED",
            registration_enabled=_get(d.props, "registrationEnabled"),
        )
    )


@extractor("microsoft.network/networkwatchers/flowlogs")
def _x_flow_log(d: _Draft, b: "AzureAssetBuilder") -> None:
    d.add(
        rel(
            _get(d.props, "targetResourceId"),
            EdgeType.MONITORS,
            "MONITORED_BY",
            description="flow logging",
        )
    )
    d.add(rel(_get(d.props, "storageId"), EdgeType.LOGS_TO, "LOGS_TO"))
    ws = _path(
        d.props,
        "flowAnalyticsConfiguration",
        "networkWatcherFlowAnalyticsConfiguration",
        "workspaceResourceId",
    )
    d.add(rel(ws, EdgeType.LOGS_TO, "LOGS_TO", description="traffic analytics"))
