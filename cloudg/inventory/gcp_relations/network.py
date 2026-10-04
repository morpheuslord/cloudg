"""Networking: VPCs, firewalls, routes, VPN, addresses, DNS and connectivity."""

from __future__ import annotations

from typing import Any

from cloudg.inventory.gcp_relations.context import Extracted, GCPContext, _extractor
from cloudg.inventory.gcp_relations.names import (
    INTERNET_CIDRS,
    _list,
    _num,
    dig,
    full_name,
    network_ref,
    subnet_ref,
)
from cloudg.schema.models import EdgeType

# ---------------------------------------------------------------------------
# Networking
# ---------------------------------------------------------------------------


def _on_network(out: Extracted, d: dict[str, Any], description: str | None = None) -> None:
    """The resource is attached to the VPC network named in ``d["network"]``."""
    out.add(full_name(d.get("network"), "compute"), EdgeType.ATTACHED_TO, description=description)


@_extractor("compute.googleapis.com/Network")
def _network(ctx: GCPContext, out: Extracted) -> None:
    d = ctx.data
    for peering in _list(d.get("peerings")):
        if isinstance(peering, dict):
            out.add(
                full_name(peering.get("network"), "compute"),
                EdgeType.PEERING,
                "VPC_PEERED",
                description=f"VPC peering {peering.get('name', '')}",
                state=peering.get("state"),
                export_custom_routes=peering.get("exportCustomRoutes"),
                import_custom_routes=peering.get("importCustomRoutes"),
            )
    out.metadata.update(
        auto_create_subnetworks=d.get("autoCreateSubnetworks"),
        routing_mode=dig(d, "routingConfig", "routingMode"),
        mtu=_num(d.get("mtu")),
    )


@_extractor("compute.googleapis.com/Subnetwork")
def _subnetwork(ctx: GCPContext, out: Extracted) -> None:
    d = ctx.data
    out.add(
        full_name(d.get("network"), "compute"),
        EdgeType.CONTAINS,
        "VPC_CONTAINS_SUBNET",
        reverse=True,
    )
    out.metadata.update(
        network=full_name(d.get("network"), "compute"),
        ip_cidr_range=d.get("ipCidrRange"),
        secondary_ranges=[
            r.get("ipCidrRange") for r in _list(d.get("secondaryIpRanges")) if isinstance(r, dict)
        ],
        private_ip_google_access=d.get("privateIpGoogleAccess"),
        flow_logs_enabled=bool(dig(d, "logConfig", "enable") or d.get("enableFlowLogs")),
        purpose=d.get("purpose"),
    )


def _fw_entries(entries: Any) -> list[dict[str, Any]]:
    out = []
    for e in _list(entries):
        if isinstance(e, dict):
            out.append(
                {
                    "protocol": e.get("IPProtocol") or e.get("ipProtocol") or "all",
                    "ports": list(e.get("ports") or []),
                }
            )
    return out


@_extractor("compute.googleapis.com/Firewall")
def _firewall(ctx: GCPContext, out: Extracted) -> None:
    d = ctx.data
    network = full_name(d.get("network"), "compute")
    out.add(network, EdgeType.ATTACHED_TO, description="firewall rule of network")
    direction = (d.get("direction") or "INGRESS").upper()
    allowed, denied = _fw_entries(d.get("allowed")), _fw_entries(d.get("denied"))
    action = "allow" if allowed or not denied else "deny"
    rule = {
        "direction": direction,
        "action": action,
        "priority": int(float(d.get("priority", 1000))),
        "disabled": bool(d.get("disabled")),
        "protocols": allowed or denied,
        "source_ranges": list(d.get("sourceRanges") or []),
        "destination_ranges": list(d.get("destinationRanges") or []),
        "source_tags": list(d.get("sourceTags") or []),
        "source_service_accounts": [s.lower() for s in d.get("sourceServiceAccounts") or []],
        "target_tags": list(d.get("targetTags") or []),
        "target_service_accounts": [s.lower() for s in d.get("targetServiceAccounts") or []],
    }
    internet = direction == "INGRESS" and any(r in INTERNET_CIDRS for r in rule["source_ranges"])
    out.metadata.update(
        network=network,
        direction=direction,
        action=action,
        priority=rule["priority"],
        disabled=rule["disabled"],
        target_tags=rule["target_tags"],
        target_service_accounts=rule["target_service_accounts"],
        source_ranges=rule["source_ranges"],
        ingress_rules=[rule] if direction == "INGRESS" else [],
        egress_rules=[rule] if direction == "EGRESS" else [],
        internet_source=internet,
        allows_internet_ingress=internet and action == "allow" and not rule["disabled"],
        logging_enabled=bool(dig(d, "logConfig", "enable")),
    )


@_extractor(
    "compute.googleapis.com/FirewallPolicy",
    "compute.googleapis.com/NetworkFirewallPolicy",
    "compute.googleapis.com/RegionNetworkFirewallPolicy",
)
def _firewall_policy(ctx: GCPContext, out: Extracted) -> None:
    d = ctx.data
    rules = []
    for r in _list(d.get("rules")):
        if not isinstance(r, dict):
            continue
        match = r.get("match") or {}
        rules.append(
            {
                "direction": r.get("direction"),
                "action": r.get("action"),
                "priority": _num(r.get("priority")),
                "disabled": bool(r.get("disabled")),
                "source_ranges": list(match.get("srcIpRanges") or []),
                "destination_ranges": list(match.get("destIpRanges") or []),
                "protocols": [
                    {"protocol": c.get("ipProtocol"), "ports": c.get("ports") or []}
                    for c in _list(match.get("layer4Configs"))
                    if isinstance(c, dict)
                ],
            }
        )
    for assoc in _list(d.get("associations")):
        if isinstance(assoc, dict):
            target = assoc.get("attachmentTarget")
            out.add(
                full_name(target, "compute") or full_name(target),
                EdgeType.GOVERNS,
                "COMPLIANCE_GOVERNS",
            )
    out.metadata.update(
        ingress_rules=[r for r in rules if r.get("direction") == "INGRESS"],
        egress_rules=[r for r in rules if r.get("direction") == "EGRESS"],
        rule_count=len(rules),
    )


@_extractor("compute.googleapis.com/Route")
def _route(ctx: GCPContext, out: Extracted) -> None:
    d = ctx.data
    _on_network(out, d, "route of network")
    hops = {
        "instance": d.get("nextHopInstance"),
        "vpn_tunnel": d.get("nextHopVpnTunnel"),
        "ilb": d.get("nextHopIlb") if "/" in str(d.get("nextHopIlb") or "") else None,
        "peering": None,
    }
    for kind, hop in hops.items():
        out.add(
            full_name(hop, "compute"),
            EdgeType.ROUTE,
            "TRANSIT_ROUTED",
            description=f"next hop {kind}",
            destination=d.get("destRange"),
        )
    gw = d.get("nextHopGateway") or ""
    out.metadata.update(
        dest_range=d.get("destRange"),
        priority=_num(d.get("priority")),
        to_internet=str(gw).endswith("default-internet-gateway"),
        next_hop_ip=d.get("nextHopIp"),
        next_hop_peering=d.get("nextHopPeering"),
        network_tags=list(d.get("tags") or []),
    )


@_extractor("compute.googleapis.com/Router")
def _router(ctx: GCPContext, out: Extracted) -> None:
    d = ctx.data
    _on_network(out, d, "Cloud Router of network")
    nats = []
    for nat in _list(d.get("nats")):
        if not isinstance(nat, dict):
            continue
        nats.append(
            {
                "name": nat.get("name"),
                "source_ranges": nat.get("sourceSubnetworkIpRangesToNat"),
                "ip_allocation": nat.get("natIpAllocateOption"),
                "logging": bool(dig(nat, "logConfig", "enable")),
            }
        )
        for sn in _list(nat.get("subnetworks")):
            if isinstance(sn, dict):
                out.add(
                    full_name(sn.get("name"), "compute"),
                    EdgeType.ROUTE,
                    "NAT_TRANSLATED",
                    reverse=True,
                    description="egress via Cloud NAT",
                )
        for ip in _list(nat.get("natIps")):
            out.add(full_name(ip, "compute"), EdgeType.ATTACHED_TO, reverse=True)
    for iface in _list(d.get("interfaces")):
        if isinstance(iface, dict):
            out.add(
                full_name(iface.get("linkedVpnTunnel"), "compute"), EdgeType.ROUTE, "TRANSIT_ROUTED"
            )
            out.add(
                full_name(iface.get("linkedInterconnectAttachment"), "compute"),
                EdgeType.ROUTE,
                "TRANSIT_ROUTED",
            )
    out.metadata.update(
        nat=nats,
        nat_enabled=bool(nats),
        bgp_asn=_num(dig(d, "bgp", "asn")),
        bgp_peer_count=len(_list(d.get("bgpPeers"))),
    )


@_extractor("compute.googleapis.com/VpnGateway", "compute.googleapis.com/TargetVpnGateway")
def _vpn_gateway(ctx: GCPContext, out: Extracted) -> None:
    d = ctx.data
    _on_network(out, d)
    for t in _list(d.get("tunnels")):
        out.add(full_name(t, "compute"), EdgeType.ROUTE, "TRANSIT_ROUTED")
    out.metadata["interface_ips"] = [
        i.get("ipAddress") for i in _list(d.get("vpnInterfaces")) if isinstance(i, dict)
    ]


@_extractor("compute.googleapis.com/VpnTunnel")
def _vpn_tunnel(ctx: GCPContext, out: Extracted) -> None:
    d = ctx.data
    out.add(
        full_name(d.get("vpnGateway") or d.get("targetVpnGateway"), "compute"), EdgeType.ATTACHED_TO
    )
    out.add(full_name(d.get("peerExternalGateway"), "compute"), EdgeType.ROUTE, "TRANSIT_ROUTED")
    out.add(full_name(d.get("peerGcpGateway"), "compute"), EdgeType.ROUTE, "TRANSIT_ROUTED")
    out.add(full_name(d.get("router"), "compute"), EdgeType.REFERENCES, "DEPENDS_ON")
    out.metadata.update(
        peer_ip=d.get("peerIp"), ike_version=_num(d.get("ikeVersion")), status=d.get("status")
    )


@_extractor("compute.googleapis.com/InterconnectAttachment")
def _interconnect_attachment(ctx: GCPContext, out: Extracted) -> None:
    d = ctx.data
    out.add(full_name(d.get("router"), "compute"), EdgeType.ATTACHED_TO)
    out.add(full_name(d.get("interconnect"), "compute"), EdgeType.ROUTE, "TRANSIT_ROUTED")
    out.metadata.update(attachment_type=d.get("type"), encryption=d.get("encryption"))


@_extractor("compute.googleapis.com/ServiceAttachment")
def _service_attachment(ctx: GCPContext, out: Extracted) -> None:
    d = ctx.data
    out.add(
        full_name(d.get("targetService") or d.get("producerForwardingRule"), "compute"),
        EdgeType.ROUTE,
        "SERVES_TRAFFIC_TO",
    )
    for sn in _list(d.get("natSubnets")):
        out.add(full_name(sn, "compute"), EdgeType.REFERENCES, "DEPENDS_ON")
    out.metadata.update(
        connection_preference=d.get("connectionPreference"),
        consumer_accept_lists=[
            a.get("projectIdOrNum") or a.get("networkUrl")
            for a in _list(d.get("consumerAcceptLists"))
            if isinstance(a, dict)
        ],
        connected_endpoint_count=len(_list(d.get("connectedEndpoints"))),
    )


@_extractor("compute.googleapis.com/Address", "compute.googleapis.com/GlobalAddress")
def _address(ctx: GCPContext, out: Extracted) -> None:
    d = ctx.data
    external = (d.get("addressType") or "EXTERNAL") == "EXTERNAL"
    for user in _list(d.get("users")):
        out.add(full_name(user, "compute"), EdgeType.ATTACHED_TO, description="address in use")
    if not external:
        out.in_subnet(full_name(d.get("subnetwork") or d.get("network"), "compute"))
    if external and d.get("address"):
        out.alias(d["address"])
        out.metadata["public_ip"] = d["address"]
    out.metadata.update(
        address=d.get("address"), address_type=d.get("addressType"), purpose=d.get("purpose")
    )


@_extractor("compute.googleapis.com/Project")
def _compute_project(ctx: GCPContext, out: Extracted) -> None:
    d = ctx.data
    out.metadata.update(
        shared_vpc_host=d.get("xpnProjectStatus") == "HOST",
        xpn_project_status=d.get("xpnProjectStatus"),
        default_service_account=d.get("defaultServiceAccount"),
        common_metadata_keys=[
            i.get("key")
            for i in dig(d, "commonInstanceMetadata", "items", default=[])
            if isinstance(i, dict)
        ],
    )
    if ctx.project_id:
        out.add(
            f"//cloudresourcemanager.googleapis.com/projects/{ctx.project_id}",
            EdgeType.REFERENCES,
            "DEPENDS_ON",
        )


# ---------------------------------------------------------------------------
# DNS, connectivity
# ---------------------------------------------------------------------------


def _dns_bindings(out: Extracted, networks: Any, clusters: Any) -> None:
    """VPC networks and GKE clusters a private zone / DNS policy applies to."""
    for n in _list(networks):
        if isinstance(n, dict):
            out.add(full_name(n.get("networkUrl"), "compute"), EdgeType.ATTACHED_TO, "DNS_RESOLVED")
    for c in _list(clusters):
        if isinstance(c, dict):
            out.add(
                full_name(c.get("gkeClusterName"), "container"),
                EdgeType.ATTACHED_TO,
                "DNS_RESOLVED",
            )


@_extractor("dns.googleapis.com/ManagedZone")
def _dns_zone(ctx: GCPContext, out: Extracted) -> None:
    d = ctx.data
    _dns_bindings(
        out,
        dig(d, "privateVisibilityConfig", "networks"),
        dig(d, "privateVisibilityConfig", "gkeClusters"),
    )
    out.add(
        full_name(dig(d, "peeringConfig", "targetNetwork", "networkUrl"), "compute"),
        EdgeType.ROUTE,
        "DNS_RESOLVED",
    )
    out.metadata.update(
        dns_name=d.get("dnsName"),
        visibility=d.get("visibility") or "public",
        dnssec=dig(d, "dnssecConfig", "state"),
        forwarding_targets=[
            t.get("ipv4Address")
            for t in _list(dig(d, "forwardingConfig", "targetNameServers"))
            if isinstance(t, dict)
        ],
    )


@_extractor("dns.googleapis.com/Policy", "dns.googleapis.com/ResponsePolicy")
def _dns_policy(ctx: GCPContext, out: Extracted) -> None:
    d = ctx.data
    _dns_bindings(out, d.get("networks"), d.get("gkeClusters"))
    out.metadata["inbound_forwarding"] = d.get("enableInboundForwarding")


@_extractor("vpcaccess.googleapis.com/Connector")
def _vpc_connector(ctx: GCPContext, out: Extracted) -> None:
    d = ctx.data
    pid = ctx.project_id
    out.add(network_ref(d.get("network"), pid), EdgeType.ATTACHED_TO)
    sub = d.get("subnet") or {}
    if sub.get("name"):
        out.in_subnet(subnet_ref(sub["name"], sub.get("projectId") or pid, ctx.region))
    out.metadata.update(
        ip_cidr_range=d.get("ipCidrRange"), network=network_ref(d.get("network"), pid)
    )


@_extractor("networkconnectivity.googleapis.com/Spoke")
def _ncc_spoke(ctx: GCPContext, out: Extracted) -> None:
    d = ctx.data
    out.add(full_name(d.get("hub"), "networkconnectivity"), EdgeType.ATTACHED_TO)
    out.add(
        full_name(dig(d, "linkedVpcNetwork", "uri"), "compute"), EdgeType.ROUTE, "TRANSIT_ROUTED"
    )
    for key in ("linkedVpnTunnels", "linkedInterconnectAttachments"):
        for uri in _list(dig(d, key, "uris")):
            out.add(full_name(uri, "compute"), EdgeType.ROUTE, "TRANSIT_ROUTED")
    for inst in _list(dig(d, "linkedRouterApplianceInstances", "instances")):
        if isinstance(inst, dict):
            out.add(
                full_name(inst.get("virtualMachine"), "compute"), EdgeType.ROUTE, "TRANSIT_ROUTED"
            )


@_extractor("managedkafka.googleapis.com/Cluster")
def _kafka(ctx: GCPContext, out: Extracted) -> None:
    for nc in _list(dig(ctx.data, "gcpConfig", "accessConfig", "networkConfigs")):
        if isinstance(nc, dict):
            out.in_subnet(full_name(nc.get("subnet"), "compute"))
