"""Compute: instances, disks, templates, groups."""

from __future__ import annotations

from typing import Any

from cloudg.inventory.gcp_relations.context import Extracted, GCPContext, _extractor
from cloudg.inventory.gcp_relations.names import (
    _list,
    _num,
    _short,
    dig,
    full_name,
)
from cloudg.schema.models import EdgeType


def _instance_nics(d: dict[str, Any], out: Extracted) -> tuple[list[str], list[str], list[str]]:
    """(public IPs, private IPs, networks) of an instance; declares subnet containment."""
    public_ips, private_ips, networks = [], [], []
    for nic in _list(d.get("networkInterfaces")):
        if not isinstance(nic, dict):
            continue
        net = full_name(nic.get("network"), "compute")
        sub = full_name(nic.get("subnetwork"), "compute")
        if net and net not in networks:
            networks.append(net)
        out.in_subnet(sub or net)
        if nic.get("networkIP"):
            private_ips.append(nic["networkIP"])
        for ac in _list(nic.get("accessConfigs")) + _list(nic.get("ipv6AccessConfigs")):
            if isinstance(ac, dict):
                ip = ac.get("natIP") or ac.get("externalIpv6")
                if ip:
                    public_ips.append(ip)
    return public_ips, private_ips, networks


@_extractor("compute.googleapis.com/Instance")
def _instance(ctx: GCPContext, out: Extracted) -> None:
    d = ctx.data
    emails = []
    for sa in _list(d.get("serviceAccounts")):
        if isinstance(sa, dict):
            email = out.sa(
                sa.get("email"), ctx, "instance service account", scopes=sa.get("scopes")
            )
            if email:
                emails.append(email)
    public_ips, private_ips, networks = _instance_nics(d, out)
    for disk in _list(d.get("disks")):
        if isinstance(disk, dict):
            out.add(
                full_name(disk.get("source"), "compute"),
                EdgeType.ATTACHED_TO,
                reverse=True,
                description="disk attached to instance",
                boot=disk.get("boot") or None,
            )
    md_items = dig(d, "metadata", "items", default=[])
    out.metadata.update(
        network_tags=list(dig(d, "tags", "items", default=[]) or []),
        service_account_emails=emails,
        networks=networks,
        public_ips=public_ips,
        private_ips=private_ips,
        machine_type=_short(d.get("machineType")),
        can_ip_forward=bool(d.get("canIpForward")),
        deletion_protection=bool(d.get("deletionProtection")),
        shielded_vm=dig(d, "shieldedInstanceConfig", default={}),
        confidential_compute=bool(
            dig(d, "confidentialInstanceConfig", "enableConfidentialCompute")
        ),
        metadata_keys=[i.get("key") for i in md_items if isinstance(i, dict)],
    )
    for ip in public_ips:
        out.alias(ip)


@_extractor("compute.googleapis.com/Disk", "compute.googleapis.com/RegionDisk")
def _disk(ctx: GCPContext, out: Extracted) -> None:
    d = ctx.data
    for user in _list(d.get("users")):
        out.add(
            full_name(user, "compute"),
            EdgeType.ATTACHED_TO,
            description="disk attached to instance",
        )
    out.add(full_name(d.get("sourceImage"), "compute"), EdgeType.REFERENCES, "DEPENDS_ON")
    out.add(full_name(d.get("sourceSnapshot"), "compute"), EdgeType.REFERENCES, "DEPENDS_ON")
    out.metadata.update(size_gb=_num(d.get("sizeGb")), disk_type=_short(d.get("type")))


@_extractor("compute.googleapis.com/Snapshot")
def _snapshot(ctx: GCPContext, out: Extracted) -> None:
    out.add(
        full_name(ctx.data.get("sourceDisk"), "compute"),
        EdgeType.REFERENCES,
        "BACKUP_TO",
        reverse=True,
    )


@_extractor("compute.googleapis.com/Image")
def _image(ctx: GCPContext, out: Extracted) -> None:
    d = ctx.data
    out.add(full_name(d.get("sourceDisk"), "compute"), EdgeType.REFERENCES, "DEPENDS_ON")
    out.add(full_name(d.get("sourceImage"), "compute"), EdgeType.REFERENCES, "DEPENDS_ON")
    out.metadata["family"] = d.get("family")


@_extractor("compute.googleapis.com/MachineImage")
def _machine_image(ctx: GCPContext, out: Extracted) -> None:
    out.add(
        full_name(ctx.data.get("sourceInstance"), "compute"),
        EdgeType.REFERENCES,
        "BACKUP_TO",
        reverse=True,
    )


@_extractor(
    "compute.googleapis.com/InstanceTemplate", "compute.googleapis.com/RegionInstanceTemplate"
)
def _instance_template(ctx: GCPContext, out: Extracted) -> None:
    props = ctx.data.get("properties") or {}
    for sa in _list(props.get("serviceAccounts")):
        if isinstance(sa, dict):
            out.sa(sa.get("email"), ctx, "template service account")
    for nic in _list(props.get("networkInterfaces")):
        if isinstance(nic, dict):
            out.add(
                full_name(nic.get("subnetwork") or nic.get("network"), "compute"),
                EdgeType.REFERENCES,
                "DEPENDS_ON",
            )
    for disk in _list(props.get("disks")):
        if isinstance(disk, dict):
            out.add(
                full_name(dig(disk, "initializeParams", "sourceImage"), "compute"),
                EdgeType.USES_IMAGE,
                "RUNS_ON",
            )
    out.metadata.update(
        network_tags=list(dig(props, "tags", "items", default=[]) or []),
        machine_type=props.get("machineType"),
    )


@_extractor(
    "compute.googleapis.com/InstanceGroupManager",
    "compute.googleapis.com/RegionInstanceGroupManager",
)
def _igm(ctx: GCPContext, out: Extracted) -> None:
    d = ctx.data
    templates = [d.get("instanceTemplate")] + [
        v.get("instanceTemplate") for v in _list(d.get("versions")) if isinstance(v, dict)
    ]
    for t in templates:
        out.add(
            full_name(t, "compute"),
            EdgeType.REFERENCES,
            "DEPENDS_ON",
            description="instance template",
        )
    out.add(full_name(d.get("instanceGroup"), "compute"), EdgeType.MANAGES, "SCALES_WITH")
    for pool in _list(d.get("targetPools")):
        out.add(
            full_name(pool, "compute"),
            EdgeType.LOAD_BALANCER_TARGET,
            "LB_TARGETS_INSTANCE",
            reverse=True,
        )
    for hc in _list(d.get("autoHealingPolicies")):
        if isinstance(hc, dict):
            out.add(full_name(hc.get("healthCheck"), "compute"), EdgeType.REFERENCES, "DEPENDS_ON")
    out.metadata.update(
        target_size=_num(d.get("targetSize")), base_instance_name=d.get("baseInstanceName")
    )


@_extractor("compute.googleapis.com/Autoscaler", "compute.googleapis.com/RegionAutoscaler")
def _autoscaler(ctx: GCPContext, out: Extracted) -> None:
    out.add(full_name(ctx.data.get("target"), "compute"), EdgeType.MANAGES, "SCALES_WITH")


@_extractor("compute.googleapis.com/InstanceGroup", "compute.googleapis.com/RegionInstanceGroup")
def _instance_group(ctx: GCPContext, out: Extracted) -> None:
    d = ctx.data
    out.in_subnet(full_name(d.get("subnetwork") or d.get("network"), "compute"))
    out.metadata.update(size=_num(d.get("size")), named_ports=d.get("namedPorts") or [])
