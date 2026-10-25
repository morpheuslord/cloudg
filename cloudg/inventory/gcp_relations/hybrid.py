"""Hybrid connectivity and compute extras: NCC, Interconnect, external VPN
gateways, PSC accept lists, packet mirroring, sole-tenant nodes and
resource policies (snapshot and instance schedules)."""

from __future__ import annotations

from typing import Any

from cloudg.inventory.gcp_relations._refs import crm_ref, parent_of
from cloudg.inventory.gcp_relations.context import Extracted, GCPContext, _extractor
from cloudg.inventory.gcp_relations.names import _list, _num, _short, dig, full_name, network_ref
from cloudg.schema.models import EdgeType

_C = "//compute.googleapis.com/"
NODE_GROUP_AFFINITY_KEY = "compute.googleapis.com/node-group-name"


# ---------------------------------------------------------------------------
# Network Connectivity Center
# ---------------------------------------------------------------------------


@_extractor("networkconnectivity.googleapis.com/Hub")
def _ncc_hub(ctx: GCPContext, out: Extracted) -> None:
    d = ctx.data
    for vpc in _list(d.get("routingVpcs")):
        if isinstance(vpc, dict):
            out.add(
                full_name(vpc.get("uri"), "compute"),
                EdgeType.ROUTE,
                "TRANSIT_ROUTED",
                description="hub routing VPC",
            )
    counts = {
        str(c.get("spokeType")): _num(c.get("count"))
        for c in _list(dig(d, "spokeSummary", "spokeTypeCounts"))
        if isinstance(c, dict)
    }
    out.metadata.update(
        policy_mode=d.get("policyMode"),
        preset_topology=d.get("presetTopology"),
        export_psc=d.get("exportPsc"),
        spoke_type_counts=counts or None,
    )


@_extractor(
    "networkconnectivity.googleapis.com/RouteTable", "networkconnectivity.googleapis.com/Group"
)
def _ncc_hub_child(ctx: GCPContext, out: Extracted) -> None:
    hub = parent_of(ctx.name, "routeTables") or parent_of(ctx.name, "groups")
    out.add(hub, EdgeType.CONTAINS, reverse=True, description="hub contains")
    out.metadata["auto_accept_projects"] = list(
        dig(ctx.data, "autoAccept", "autoAcceptProjects", default=[]) or []
    )


@_extractor("networkconnectivity.googleapis.com/InternalRange")
def _internal_range(ctx: GCPContext, out: Extracted) -> None:
    d = ctx.data
    out.add(network_ref(d.get("network"), ctx.project_id), EdgeType.ATTACHED_TO)
    out.metadata.update(
        ip_cidr_range=d.get("ipCidrRange"), usage=d.get("usage"), peering=d.get("peering")
    )


@_extractor("networkconnectivity.googleapis.com/PolicyBasedRoute")
def _policy_route(ctx: GCPContext, out: Extracted) -> None:
    d = ctx.data
    out.add(network_ref(d.get("network"), ctx.project_id), EdgeType.ATTACHED_TO)
    out.add(d.get("nextHopIlbIp"), EdgeType.ROUTE, "TRANSIT_ROUTED", description="next hop ILB")
    out.metadata.update(
        next_hop_ilb_ip=d.get("nextHopIlbIp"),
        next_hop_other_routes=d.get("nextHopOtherRoutes"),
        priority=_num(d.get("priority")),
        filter=d.get("filter"),
    )


@_extractor("networkconnectivity.googleapis.com/RegionalEndpoint")
def _regional_endpoint(ctx: GCPContext, out: Extracted) -> None:
    d = ctx.data
    out.add(network_ref(d.get("network"), ctx.project_id), EdgeType.ATTACHED_TO)
    out.in_subnet(full_name(d.get("subnetwork"), "compute"))
    out.alias(d.get("address"))
    out.metadata.update(
        target_google_api=d.get("targetGoogleApi"),
        access_type=d.get("accessType"),
        address=d.get("address"),
    )


# ---------------------------------------------------------------------------
# Interconnect, external VPN gateways, VPN peers
# ---------------------------------------------------------------------------


@_extractor("compute.googleapis.com/Interconnect")
def _interconnect(ctx: GCPContext, out: Extracted) -> None:
    d = ctx.data
    attachments = _list(d.get("interconnectAttachments"))
    for att in attachments:
        out.add(full_name(att, "compute"), EdgeType.CONTAINS, description="VLAN attachment")
    out.metadata.update(
        interconnect_type=d.get("interconnectType"),
        link_type=d.get("linkType"),
        location=_short(d.get("location")),
        provisioned_link_count=_num(d.get("provisionedLinkCount")),
        operational_status=d.get("operationalStatus"),
        macsec_enabled=bool(d.get("macsecEnabled")),
        admin_enabled=d.get("adminEnabled"),
        attachment_count=len(attachments),
    )


@_extractor("compute.googleapis.com/ExternalVpnGateway")
def _external_vpn_gateway(ctx: GCPContext, out: Extracted) -> None:
    d = ctx.data
    ips = [
        i.get("ipAddress") or i.get("ipv6Address")
        for i in _list(d.get("interfaces"))
        if isinstance(i, dict)
    ]
    ips = [ip for ip in ips if ip]
    out.alias(*ips)
    out.metadata.update(redundancy_type=d.get("redundancyType"), peer_ips=ips)


@_extractor("compute.googleapis.com/VpnTunnel")
def _vpn_tunnel_peer(ctx: GCPContext, out: Extracted) -> None:
    """Classic VPN tunnels name their peer only by IP: link the external gateway with that IP."""
    d = ctx.data
    if d.get("peerExternalGateway") or d.get("peerGcpGateway"):
        return
    out.add(d.get("peerIp"), EdgeType.ROUTE, "TRANSIT_ROUTED", description="VPN peer address")


# ---------------------------------------------------------------------------
# Private Service Connect accept lists
# ---------------------------------------------------------------------------


@_extractor("compute.googleapis.com/ServiceAttachment")
def _psc_accept_lists(ctx: GCPContext, out: Extracted) -> None:
    """Consumer projects / networks on the accept list may connect (GRANTS_ACCESS)."""
    d = ctx.data
    for entry in _list(d.get("consumerAcceptLists")):
        if not isinstance(entry, dict):
            continue
        consumer = crm_ref(entry.get("projectIdOrNum")) or full_name(
            entry.get("networkUrl"), "compute"
        )
        out.add(
            consumer,
            EdgeType.GRANTS_ACCESS,
            "CROSS_ACCOUNT_TRUST",
            reverse=True,
            description="PSC consumer accept list",
            connection_limit=_num(entry.get("connectionLimit")),
        )
    for ep in _list(d.get("connectedEndpoints")):
        if isinstance(ep, dict):
            out.add(
                full_name(ep.get("endpoint"), "compute"),
                EdgeType.ROUTE,
                "SERVES_TRAFFIC_TO",
                reverse=True,
                description="connected PSC endpoint",
                status=ep.get("status"),
            )
    out.metadata["consumer_reject_lists"] = list(d.get("consumerRejectLists") or [])


# ---------------------------------------------------------------------------
# Packet mirroring
# ---------------------------------------------------------------------------


@_extractor("compute.googleapis.com/PacketMirroring")
def _packet_mirroring(ctx: GCPContext, out: Extracted) -> None:
    d = ctx.data
    out.add(full_name(dig(d, "network", "url"), "compute"), EdgeType.ATTACHED_TO)
    out.add(
        full_name(dig(d, "collectorIlb", "url"), "compute"),
        EdgeType.INVOKES,
        "STREAMS_TO",
        description="mirrored traffic collector",
    )
    mirrored = d.get("mirroredResources") or {}
    for key in ("subnetworks", "instances"):
        for item in _list(mirrored.get(key)):
            if isinstance(item, dict):
                out.add(
                    full_name(item.get("url"), "compute"),
                    EdgeType.MONITORS,
                    "MONITORED_BY",
                    description="traffic mirrored",
                )
    out.metadata.update(
        enable=d.get("enable"),
        mirrored_tags=list(mirrored.get("tags") or []),
        filter=d.get("filter"),
    )


# ---------------------------------------------------------------------------
# Sole-tenant nodes
# ---------------------------------------------------------------------------


@_extractor("compute.googleapis.com/NodeTemplate")
def _node_template(ctx: GCPContext, out: Extracted) -> None:
    d = ctx.data
    out.metadata.update(
        node_type=d.get("nodeType"),
        server_binding=dig(d, "serverBinding", "type"),
        cpu_overcommit=d.get("cpuOvercommitType"),
    )


@_extractor("compute.googleapis.com/NodeGroup")
def _node_group(ctx: GCPContext, out: Extracted) -> None:
    d = ctx.data
    out.add(full_name(d.get("nodeTemplate"), "compute"), EdgeType.REFERENCES, "DEPENDS_ON")
    share = d.get("shareSettings") or {}
    for project in (share.get("projectMap") or {}).keys():
        out.add(
            crm_ref(project),
            EdgeType.GRANTS_ACCESS,
            "CROSS_ACCOUNT_TRUST",
            reverse=True,
            description="node group shared with project",
        )
    out.metadata.update(
        size=_num(d.get("size")),
        autoscaling_mode=dig(d, "autoscalingPolicy", "mode"),
        maintenance_policy=d.get("maintenancePolicy"),
        share_type=share.get("shareType"),
    )


@_extractor("compute.googleapis.com/Instance")
def _instance_extras(ctx: GCPContext, out: Extracted) -> None:
    """Numeric-id aliases, sole-tenant placement and attached resource policies."""
    d = ctx.data
    zone = ctx.location
    vm_id = _num(d.get("id"))
    if vm_id and zone:
        for project in {ctx.project_id, ctx.project_number} - {None}:
            out.alias(f"{_C}projects/{project}/zones/{zone}/instances/{vm_id}")
    if vm_id and ctx.project_id:
        out.alias(f"gcp-instance-id:{ctx.project_id}/{vm_id}")
    for aff in _list(dig(d, "scheduling", "nodeAffinities")):
        if not isinstance(aff, dict) or aff.get("key") != NODE_GROUP_AFFINITY_KEY:
            continue
        if aff.get("operator") not in (None, "IN"):
            continue
        for group in _list(aff.get("values")):
            if ctx.project_id and zone and isinstance(group, str):
                out.add(
                    f"{_C}projects/{ctx.project_id}/zones/{zone}/nodeGroups/{group}",
                    EdgeType.REFERENCES,
                    "RUNS_ON",
                    description="sole-tenant node group",
                )
    policies = [p for p in (full_name(r, "compute") for r in _list(d.get("resourcePolicies"))) if p]
    if policies:
        out.metadata["resource_policies"] = policies
    if vm_id:
        out.metadata["instance_id"] = vm_id


# ---------------------------------------------------------------------------
# Resource policies: snapshot schedules, instance schedules, placement
# ---------------------------------------------------------------------------


def resource_policy_kind(d: dict[str, Any]) -> str:
    for key, kind in (
        ("snapshotSchedulePolicy", "snapshot_schedule"),
        ("instanceSchedulePolicy", "instance_schedule"),
        ("groupPlacementPolicy", "group_placement"),
        ("diskConsistencyGroupPolicy", "disk_consistency_group"),
        ("workloadPolicy", "workload"),
    ):
        if d.get(key) is not None:
            return kind
    return "other"


def _schedule_summary(schedule: dict[str, Any]) -> str | None:
    for key in ("hourlySchedule", "dailySchedule", "weeklySchedule"):
        s = schedule.get(key)
        if isinstance(s, dict):
            return key.removesuffix("Schedule")
    return None


@_extractor("compute.googleapis.com/ResourcePolicy")
def _resource_policy(ctx: GCPContext, out: Extracted) -> None:
    d = ctx.data
    kind = resource_policy_kind(d)
    md: dict[str, Any] = {"policy_kind": kind}
    snap = d.get("snapshotSchedulePolicy") or {}
    if snap:
        md.update(
            schedule=_schedule_summary(snap.get("schedule") or {}),
            retention_days=_num(dig(snap, "retentionPolicy", "maxRetentionDays")),
            on_source_disk_delete=dig(snap, "retentionPolicy", "onSourceDiskDelete"),
            storage_locations=list(dig(snap, "snapshotProperties", "storageLocations", default=[])),
            guest_flush=dig(snap, "snapshotProperties", "guestFlush"),
        )
    sched = d.get("instanceSchedulePolicy") or {}
    if sched:
        md.update(
            vm_start=dig(sched, "vmStartSchedule", "schedule"),
            vm_stop=dig(sched, "vmStopSchedule", "schedule"),
            time_zone=sched.get("timeZone"),
        )
    out.metadata.update(md)


@_extractor("compute.googleapis.com/Disk", "compute.googleapis.com/RegionDisk")
def _disk_policies(ctx: GCPContext, out: Extracted) -> None:
    """A disk only takes snapshot schedule policies: the policy backs it up."""
    for ref in _list(ctx.data.get("resourcePolicies")):
        out.add(
            full_name(ref, "compute"),
            EdgeType.MANAGES,
            "BACKUP_TO",
            reverse=True,
            description="snapshot schedule",
        )
