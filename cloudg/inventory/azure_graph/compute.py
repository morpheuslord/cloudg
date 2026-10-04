"""Extractors for compute: VMs, scale sets, disks and AKS."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from cloudg.inventory.aws_services._base import rel
from cloudg.inventory.azure_graph.helpers import (
    _get,
    _list,
    _path,
    _props,
    _rid,
    _rids,
    owner_resource_id,
    parent_resource_id,
)
from cloudg.inventory.azure_graph.registry import (
    _Draft,
    _keyvault_key_ref,
    extractor,
)
from cloudg.schema.models import EdgeType

if TYPE_CHECKING:
    from cloudg.inventory.azure_graph.builder import AzureAssetBuilder


@extractor("microsoft.compute/virtualmachines")
def _x_vm(d: _Draft, b: "AzureAssetBuilder") -> None:
    storage = _get(d.props, "storageProfile") or {}
    os_disk = _get(storage, "osDisk") or {}
    d.md.update(
        {
            "vm_size": _path(d.props, "hardwareProfile", "vmSize"),
            "os_type": _get(os_disk, "osType"),
            "provisioning_state": _get(d.props, "provisioningState"),
            "network_interfaces": _rids(_path(d.props, "networkProfile", "networkInterfaces")),
            "computer_name": _path(d.props, "osProfile", "computerName"),
            "power_state": _path(d.props, "extended", "instanceView", "powerState", "code"),
        }
    )
    disks = [_rid(_get(os_disk, "managedDisk"))] + [
        _rid(_get(dd, "managedDisk")) for dd in _list(_get(storage, "dataDisks"))
    ]
    for disk in disks:
        d.add(rel(disk, EdgeType.ATTACHED_TO, reverse=True, description="managed disk"))
    image = _rid(_get(storage, "imageReference"))
    d.add(rel(image, EdgeType.USES_IMAGE, "RUNS_ON", description="VM image"))
    d.add(rel(_rid(_get(d.props, "availabilitySet")), EdgeType.CONTAINS, reverse=True))
    d.add(
        rel(
            _rid(_get(d.props, "virtualMachineScaleSet")),
            EdgeType.CONTAINS,
            "SCALES_WITH",
            reverse=True,
        )
    )
    d.add(rel(_rid(_get(d.props, "proximityPlacementGroup")), EdgeType.REFERENCES, "DEPENDS_ON"))


@extractor("microsoft.compute/virtualmachinescalesets")
def _x_vmss(d: _Draft, b: "AzureAssetBuilder") -> None:
    profile = _get(d.props, "virtualMachineProfile") or {}
    for nic_cfg in _list(_path(profile, "networkProfile", "networkInterfaceConfigurations")):
        np = _props(nic_cfg)
        d.add(rel(_rid(_get(np, "networkSecurityGroup")), EdgeType.ATTACHED_TO, "PROTECTED_BY_SG"))
        for ipc in _list(_get(np, "ipConfigurations")):
            p = _props(ipc)
            d.add(
                rel(
                    _rid(_get(p, "subnet")),
                    EdgeType.CONTAINS,
                    "SUBNET_CONTAINS_INSTANCE",
                    reverse=True,
                )
            )
            for pool in _rids(_get(p, "loadBalancerBackendAddressPools")) + _rids(
                _get(p, "applicationGatewayBackendAddressPools")
            ):
                d.add(
                    rel(
                        owner_resource_id(pool),
                        EdgeType.LOAD_BALANCER_TARGET,
                        "LB_TARGETS_INSTANCE",
                        reverse=True,
                    )
                )
            for asg in _rids(_get(p, "applicationSecurityGroups")):
                d.add(rel(asg, EdgeType.ATTACHED_TO, "PROTECTED_BY_SG"))
    d.add(
        rel(
            _rid(_path(profile, "storageProfile", "imageReference")), EdgeType.USES_IMAGE, "RUNS_ON"
        )
    )
    sku = d.row.get("sku")
    d.md["capacity"] = _get(sku, "capacity") if isinstance(sku, dict) else None


@extractor("microsoft.compute/disks")
def _x_disk(d: _Draft, b: "AzureAssetBuilder") -> None:
    enc = _get(d.props, "encryption") or {}
    des = _get(enc, "diskEncryptionSetId")
    d.md.update(
        {
            "size_gb": _get(d.props, "diskSizeGB"),
            "state": _get(d.props, "diskState"),
            "encryption": _get(enc, "type"),
            "disk_encryption_set": des,
            "network_access_policy": _get(d.props, "networkAccessPolicy"),
        }
    )
    d.md.setdefault("attached_instance_id", d.row.get("managedBy"))
    d.add(rel(des, EdgeType.REFERENCES, "ENCRYPTED_BY_KMS", description="disk encryption set"))
    d.add(
        rel(
            _path(d.props, "creationData", "sourceResourceId"),
            EdgeType.REFERENCES,
            "DEPENDS_ON",
            description="created from",
        )
    )


@extractor("microsoft.compute/diskencryptionsets")
def _x_des(d: _Draft, b: "AzureAssetBuilder") -> None:
    key = _get(d.props, "activeKey") or {}
    vault = _rid(_get(key, "sourceVault"))
    d.md["key_url"] = _get(key, "keyUrl")
    d.add(rel(vault, EdgeType.REFERENCES, "ENCRYPTED_BY_KMS", description="key vault key"))
    if not vault:
        _keyvault_key_ref(d, _get(key, "keyUrl"))


def _aks_kubelet(d: _Draft, b: "AzureAssetBuilder", p: dict[str, Any]) -> None:
    kubelet = _path(p, "identityProfile", "kubeletidentity") or {}
    kubelet_id = _get(kubelet, "resourceId")
    kubelet_oid = _get(kubelet, "objectId")
    d.md["kubelet_identity"] = {
        "resource_id": kubelet_id,
        "object_id": kubelet_oid,
        "client_id": _get(kubelet, "clientId"),
    }
    d.add(rel(kubelet_id, EdgeType.ASSUMES_ROLE, "RUNS_ON", description="kubelet identity"))
    if kubelet_oid:
        b.register_kubelet(kubelet_oid, d)


def _aks_addons(d: _Draft, p: dict[str, Any]) -> None:
    """Container Insights / Defender log sinks and the AGIC application gateway."""
    addons = _get(p, "addonProfiles") or {}
    oms = _get(addons, "omsagent") or _get(addons, "omsAgent") or {}
    ws = _get(_get(oms, "config") or {}, "logAnalyticsWorkspaceResourceID")
    if _get(oms, "enabled") is not False:
        d.add(rel(ws, EdgeType.LOGS_TO, "LOGS_TO", description="Container Insights"))
    ws2 = _path(p, "azureMonitorProfile", "containerInsights", "logAnalyticsWorkspaceResourceId")
    d.add(rel(ws2, EdgeType.LOGS_TO, "LOGS_TO", description="Container Insights"))
    defender_ws = _path(p, "securityProfile", "defender", "logAnalyticsWorkspaceResourceId")
    d.add(rel(defender_ws, EdgeType.LOGS_TO, "LOGS_TO", description="Defender for Containers"))
    agic = _get(_get(addons, "ingressApplicationGateway") or {}, "config") or {}
    appgw = _get(agic, "effectiveApplicationGatewayId") or _get(agic, "applicationGatewayId")
    d.add(
        rel(
            appgw,
            EdgeType.REFERENCES,
            "SERVES_TRAFFIC_TO",
            reverse=True,
            description="AGIC ingress",
        )
    )


def _aks_node_resource_group(d: _Draft, p: dict[str, Any]) -> None:
    node_rg = _get(p, "nodeResourceGroup")
    if node_rg:
        d.md["node_resource_group"] = node_rg
        d.add(
            rel(
                f"/subscriptions/{d.account_id}/resourceGroups/{node_rg}",
                EdgeType.MANAGES,
                "OWNED_BY",
                description="node resource group",
            )
        )


def _aks_api_server(d: _Draft, p: dict[str, Any]) -> None:
    """Cluster settings, API server endpoints and their exposure."""
    api = _get(p, "apiServerAccessProfile") or {}
    private = bool(_get(api, "enablePrivateCluster"))
    authorized = _list(_get(api, "authorizedIPRanges"))
    d.md.update(
        {
            "kubernetes_version": _get(p, "kubernetesVersion")
            or _get(p, "currentKubernetesVersion"),
            "fqdn": _get(p, "fqdn"),
            "private_fqdn": _get(p, "privateFQDN"),
            "private_cluster": private,
            "api_server_authorized_ip_ranges": authorized,
            "network_plugin": _path(p, "networkProfile", "networkPlugin"),
            "network_policy": _path(p, "networkProfile", "networkPolicy"),
            "outbound_type": _path(p, "networkProfile", "outboundType"),
            "aad_managed": _path(p, "aadProfile", "managed"),
            "azure_rbac": _path(p, "aadProfile", "enableAzureRBAC"),
            "local_accounts_disabled": _get(p, "disableLocalAccounts"),
            "rbac_enabled": _get(p, "enableRBAC"),
        }
    )
    for host in (_get(p, "fqdn"), _get(p, "privateFQDN")):
        d.alias(host.lower() if isinstance(host, str) else None)
    if not private and _get(p, "fqdn"):
        d.exposed = True


def _aks_agent_pools(d: _Draft, b: "AzureAssetBuilder", p: dict[str, Any]) -> None:
    """Agent pool profiles become their own (synthetic) assets."""
    for pool in _list(_get(p, "agentPoolProfiles")):
        name = _get(pool, "name")
        if not name:
            continue
        b.add_row(
            {
                "id": f"{d.id}/agentPools/{name}",
                "name": name,
                "type": "microsoft.containerservice/managedclusters/agentpools",
                "location": d.region,
                "subscriptionId": d.account_id,
                "tags": _get(pool, "tags") or {},
                "properties": pool,
            },
            synthetic=True,
        )


@extractor("microsoft.containerservice/managedclusters")
def _x_aks(d: _Draft, b: "AzureAssetBuilder") -> None:
    p = d.props
    _aks_kubelet(d, b, p)
    _aks_addons(d, p)
    _aks_node_resource_group(d, p)
    _aks_api_server(d, p)
    for out_ip in _rids(_path(p, "networkProfile", "loadBalancerProfile", "effectiveOutboundIPs")):
        d.add(rel(out_ip, EdgeType.ATTACHED_TO, reverse=True, description="egress public IP"))
    _aks_agent_pools(d, b, p)


@extractor("microsoft.containerservice/managedclusters/agentpools")
def _x_agent_pool(d: _Draft, b: "AzureAssetBuilder") -> None:
    p = d.props
    subnet = _get(p, "vnetSubnetID")
    pod_subnet = _get(p, "podSubnetID")
    d.md.update(
        {
            "vm_size": _get(p, "vmSize"),
            "count": _get(p, "count"),
            "mode": _get(p, "mode"),
            "os_type": _get(p, "osType"),
            "vnet_subnet_id": subnet,
            "pod_subnet_id": pod_subnet,
            "public_node_ips": _get(p, "enableNodePublicIP"),
            "cluster_id": parent_resource_id(d.id),
        }
    )
    d.add(
        rel(
            subnet,
            EdgeType.CONTAINS,
            "SUBNET_CONTAINS_INSTANCE",
            reverse=True,
            description="node subnet",
        )
    )
    d.add(
        rel(
            pod_subnet,
            EdgeType.CONTAINS,
            "SUBNET_CONTAINS_INSTANCE",
            reverse=True,
            description="pod subnet",
        )
    )
    if _get(p, "enableNodePublicIP"):
        d.exposed = True
