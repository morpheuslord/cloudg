"""Deep Azure inventory collector — full-subscription resource enumeration.

Extends the standard :class:`AzureCollector` with:

- A catch-all sweep via the Azure Resource Manager ``resources.list()``
  API, which returns **every** resource of every service in the
  subscription — so services without a dedicated collector still appear
  on the map.
- The network fabric that interlinks everything: network interfaces,
  public IP addresses, managed disks, load balancers, and route tables,
  collected with full detail so the relationship linker can wire
  VM ↔ NIC ↔ subnet ↔ NSG ↔ public IP chains.
"""

from __future__ import annotations

import asyncio
import logging

from cloudg.collectors.azure import AzureCollector
from cloudg.schema.models import AssetType, CloudAsset, CloudProvider

logger = logging.getLogger(__name__)

# Maps lowercase ARM resource types to normalised AssetTypes for sweep hits.
_ARM_TYPE_MAP: dict[str, AssetType] = {
    "microsoft.compute/virtualmachines": AssetType.VIRTUAL_MACHINE,
    "microsoft.compute/disks": AssetType.EBS_VOLUME,
    "microsoft.network/virtualnetworks": AssetType.VNET,
    "microsoft.network/networksecuritygroups": AssetType.NSG,
    "microsoft.network/networkinterfaces": AssetType.NETWORK_INTERFACE,
    "microsoft.network/publicipaddresses": AssetType.ELASTIC_IP,
    "microsoft.network/loadbalancers": AssetType.LOAD_BALANCER,
    "microsoft.network/applicationgateways": AssetType.LOAD_BALANCER,
    "microsoft.network/routetables": AssetType.ROUTE_TABLE,
    "microsoft.network/natgateways": AssetType.NAT_GATEWAY,
    "microsoft.network/virtualnetworkgateways": AssetType.TRANSIT_GATEWAY,
    "microsoft.storage/storageaccounts": AssetType.BLOB_STORAGE,
    "microsoft.sql/servers": AssetType.AZURE_SQL,
    "microsoft.sql/servers/databases": AssetType.AZURE_SQL,
    "microsoft.dbforpostgresql/flexibleservers": AssetType.AZURE_SQL,
    "microsoft.dbformysql/flexibleservers": AssetType.AZURE_SQL,
    "microsoft.documentdb/databaseaccounts": AssetType.DYNAMODB_TABLE,
    "microsoft.keyvault/vaults": AssetType.KEY_VAULT,
    "microsoft.web/sites": AssetType.APP_SERVICE,
    "microsoft.web/serverfarms": AssetType.APP_SERVICE,
    "microsoft.containerservice/managedclusters": AssetType.AKS_CLUSTER,
    "microsoft.containerregistry/registries": AssetType.CONTAINER_REGISTRY,
    "microsoft.containerservice/managedclusters/agentpools": AssetType.NODE_GROUP,
    "microsoft.app/containerapps": AssetType.CONTAINER_SERVICE,
    "microsoft.app/managedenvironments": AssetType.ECS_CLUSTER,
    "microsoft.containerinstance/containergroups": AssetType.CONTAINER_SERVICE,
    "microsoft.compute/virtualmachinescalesets": AssetType.AUTOSCALING_GROUP,
    "microsoft.web/sites/functions": AssetType.CLOUD_FUNCTION,
    "microsoft.apimanagement/service": AssetType.API_GATEWAY,
    "microsoft.network/privateendpoints": AssetType.VPC_ENDPOINT,
    "microsoft.network/azurefirewalls": AssetType.NETWORK_FIREWALL,
    "microsoft.network/firewallpolicies": AssetType.NETWORK_FIREWALL,
    "microsoft.network/frontdoorwebapplicationfirewallpolicies": AssetType.WAF_WEB_ACL,
    "microsoft.network/applicationgatewaywebapplicationfirewallpolicies": AssetType.WAF_WEB_ACL,
    "microsoft.network/ddosprotectionplans": AssetType.DDOS_PROTECTION,
    "microsoft.network/dnszones": AssetType.DNS_ZONE,
    "microsoft.network/privatednszones": AssetType.DNS_ZONE,
    "microsoft.network/networkwatchers/flowlogs": AssetType.FLOW_LOG,
    "microsoft.servicebus/namespaces": AssetType.MESSAGE_QUEUE,
    "microsoft.eventhub/namespaces": AssetType.DATA_STREAM,
    "microsoft.eventgrid/topics": AssetType.NOTIFICATION_TOPIC,
    "microsoft.eventgrid/systemtopics": AssetType.NOTIFICATION_TOPIC,
    "microsoft.logic/workflows": AssetType.STATE_MACHINE,
    "microsoft.cache/redis": AssetType.CACHE_CLUSTER,
    "microsoft.search/searchservices": AssetType.SEARCH_DOMAIN,
    "microsoft.synapse/workspaces": AssetType.DATA_WAREHOUSE,
    "microsoft.storage/storageaccounts/fileservices": AssetType.FILE_SYSTEM,
    "microsoft.operationalinsights/workspaces": AssetType.LOG_GROUP,
    "microsoft.security/automations": AssetType.SECURITY_HUB,
    "microsoft.securityinsights/settings": AssetType.THREAT_DETECTOR,
    "microsoft.cdn/profiles": AssetType.CDN,
    "microsoft.insights/components": AssetType.OTHER,
    "microsoft.managedidentity/userassignedidentities": AssetType.SERVICE_PRINCIPAL,
}


def asset_type_from_arm(resource_type: str | None) -> AssetType:
    """Best-effort AssetType classification from an ARM resource type."""
    if not resource_type:
        return AssetType.OTHER
    return _ARM_TYPE_MAP.get(resource_type.lower(), AssetType.OTHER)


class AzureDeepInventoryCollector(AzureCollector):
    """Azure collector with a full-subscription ARM sweep plus detailed
    network-fabric enumeration for relationship linking."""

    # ------------------------------------------------------------------
    # Catch-all ARM sweep
    # ------------------------------------------------------------------

    async def _collect_resource_sweep(self) -> list[CloudAsset]:
        """Enumerate every resource in the subscription via ARM.

        Duplicates of dedicated collectors are dropped later (dedupe by
        resource ID in :meth:`collect`)."""
        assets: list[CloudAsset] = []
        try:
            from azure.mgmt.resource import ResourceManagementClient

            client = ResourceManagementClient(self._credential, self._subscription_id)
            for res in client.resources.list():
                assets.append(
                    CloudAsset(
                        arn=res.id,
                        name=res.name or (res.id or "").rsplit("/", 1)[-1],
                        asset_type=asset_type_from_arm(res.type),
                        provider=CloudProvider.AZURE,
                        region=res.location or "global",
                        account_id=self._subscription_id,
                        tags=res.tags or {},
                        metadata={
                            "discovered_via": "arm-sweep",
                            "resource_type": res.type,
                            "kind": getattr(res, "kind", None),
                            "sku": res.sku.name if getattr(res, "sku", None) else None,
                        },
                        raw_data={"id": res.id, "type": res.type},
                    )
                )
        except ImportError:
            logger.warning("azure-mgmt-resource not installed, skipping ARM sweep")
        except Exception as exc:
            logger.error("Azure ARM resource sweep failed: %s", exc)
        return assets

    # ------------------------------------------------------------------
    # Network fabric collectors
    # ------------------------------------------------------------------

    async def _collect_nics(self) -> list[CloudAsset]:
        assets: list[CloudAsset] = []
        try:
            from azure.mgmt.network import NetworkManagementClient

            client = NetworkManagementClient(self._credential, self._subscription_id)
            for nic in client.network_interfaces.list_all():
                ip_configs = nic.ip_configurations or []
                assets.append(
                    CloudAsset(
                        arn=nic.id,
                        name=nic.name,
                        asset_type=AssetType.NETWORK_INTERFACE,
                        provider=CloudProvider.AZURE,
                        region=nic.location or "global",
                        account_id=self._subscription_id,
                        tags=nic.tags or {},
                        metadata={
                            "attached_instance_id": (
                                nic.virtual_machine.id if nic.virtual_machine else None
                            ),
                            "nsg_id": (
                                nic.network_security_group.id
                                if nic.network_security_group
                                else None
                            ),
                            "subnet_id": (
                                ip_configs[0].subnet.id
                                if ip_configs and ip_configs[0].subnet
                                else None
                            ),
                            "private_ip": (
                                ip_configs[0].private_ip_address if ip_configs else None
                            ),
                            "public_ip_id": (
                                ip_configs[0].public_ip_address.id
                                if ip_configs and ip_configs[0].public_ip_address
                                else None
                            ),
                        },
                        raw_data={"id": nic.id, "name": nic.name},
                    )
                )
        except ImportError:
            logger.warning("azure-mgmt-network not installed, skipping NIC collection")
        except Exception as exc:
            logger.error("Failed to collect Azure NICs: %s", exc)
        return assets

    async def _collect_public_ips(self) -> list[CloudAsset]:
        assets: list[CloudAsset] = []
        try:
            from azure.mgmt.network import NetworkManagementClient

            client = NetworkManagementClient(self._credential, self._subscription_id)
            for pip in client.public_ip_addresses.list_all():
                assets.append(
                    CloudAsset(
                        arn=pip.id,
                        name=pip.name,
                        asset_type=AssetType.ELASTIC_IP,
                        provider=CloudProvider.AZURE,
                        region=pip.location or "global",
                        account_id=self._subscription_id,
                        tags=pip.tags or {},
                        is_internet_exposed=True,
                        metadata={
                            "public_ip": pip.ip_address,
                            "allocation_method": pip.public_ip_allocation_method,
                            "fqdn": (
                                pip.dns_settings.fqdn if pip.dns_settings else None
                            ),
                        },
                        raw_data={"id": pip.id, "name": pip.name},
                    )
                )
        except ImportError:
            logger.warning("azure-mgmt-network not installed, skipping public IP collection")
        except Exception as exc:
            logger.error("Failed to collect Azure public IPs: %s", exc)
        return assets

    async def _collect_disks(self) -> list[CloudAsset]:
        assets: list[CloudAsset] = []
        try:
            from azure.mgmt.compute import ComputeManagementClient

            client = ComputeManagementClient(self._credential, self._subscription_id)
            for disk in client.disks.list():
                assets.append(
                    CloudAsset(
                        arn=disk.id,
                        name=disk.name,
                        asset_type=AssetType.EBS_VOLUME,
                        provider=CloudProvider.AZURE,
                        region=disk.location or "global",
                        account_id=self._subscription_id,
                        tags=disk.tags or {},
                        metadata={
                            "size_gb": disk.disk_size_gb,
                            "state": disk.disk_state,
                            "attached_instance_id": disk.managed_by,
                            "encryption": (
                                disk.encryption.type if disk.encryption else None
                            ),
                        },
                        raw_data={"id": disk.id, "name": disk.name},
                    )
                )
        except ImportError:
            logger.warning("azure-mgmt-compute not installed, skipping disk collection")
        except Exception as exc:
            logger.error("Failed to collect Azure disks: %s", exc)
        return assets

    async def _collect_load_balancers(self) -> list[CloudAsset]:
        assets: list[CloudAsset] = []
        try:
            from azure.mgmt.network import NetworkManagementClient

            client = NetworkManagementClient(self._credential, self._subscription_id)
            for lb in client.load_balancers.list_all():
                backend_nics: list[str] = []
                for pool in lb.backend_address_pools or []:
                    for ip_config in pool.backend_ip_configurations or []:
                        # NIC id is the ip-config id minus its trailing segments
                        nic_id = (ip_config.id or "").split("/ipConfigurations/")[0]
                        if nic_id:
                            backend_nics.append(nic_id)
                assets.append(
                    CloudAsset(
                        arn=lb.id,
                        name=lb.name,
                        asset_type=AssetType.LOAD_BALANCER,
                        provider=CloudProvider.AZURE,
                        region=lb.location or "global",
                        account_id=self._subscription_id,
                        tags=lb.tags or {},
                        metadata={
                            "sku": lb.sku.name if lb.sku else None,
                            "backend_network_interfaces": backend_nics,
                            "frontend_public_ip_ids": [
                                fe.public_ip_address.id
                                for fe in (lb.frontend_ip_configurations or [])
                                if fe.public_ip_address
                            ],
                        },
                        raw_data={"id": lb.id, "name": lb.name},
                    )
                )
        except ImportError:
            logger.warning("azure-mgmt-network not installed, skipping LB collection")
        except Exception as exc:
            logger.error("Failed to collect Azure load balancers: %s", exc)
        return assets

    async def _collect_route_tables(self) -> list[CloudAsset]:
        assets: list[CloudAsset] = []
        try:
            from azure.mgmt.network import NetworkManagementClient

            client = NetworkManagementClient(self._credential, self._subscription_id)
            for rt in client.route_tables.list_all():
                assets.append(
                    CloudAsset(
                        arn=rt.id,
                        name=rt.name,
                        asset_type=AssetType.ROUTE_TABLE,
                        provider=CloudProvider.AZURE,
                        region=rt.location or "global",
                        account_id=self._subscription_id,
                        tags=rt.tags or {},
                        metadata={
                            "routes": [
                                {
                                    "name": r.name,
                                    "address_prefix": r.address_prefix,
                                    "next_hop_type": r.next_hop_type,
                                    "next_hop_ip": r.next_hop_ip_address,
                                }
                                for r in (rt.routes or [])
                            ],
                            "subnet_ids": [s.id for s in (rt.subnets or [])],
                        },
                        raw_data={"id": rt.id, "name": rt.name},
                    )
                )
        except ImportError:
            logger.warning("azure-mgmt-network not installed, skipping route table collection")
        except Exception as exc:
            logger.error("Failed to collect Azure route tables: %s", exc)
        return assets

    # ------------------------------------------------------------------
    # Main interface
    # ------------------------------------------------------------------

    async def collect(self) -> list[CloudAsset]:
        """Collect base assets, fabric detail, and the ARM sweep; dedupe by
        resource ID keeping the richer, detailed asset."""
        logger.info(
            "Starting deep Azure inventory for subscription %s", self._subscription_id
        )
        base = await super().collect()

        results = await asyncio.gather(
            self._collect_nics(),
            self._collect_public_ips(),
            self._collect_disks(),
            self._collect_load_balancers(),
            self._collect_route_tables(),
            self._collect_resource_sweep(),
            return_exceptions=True,
        )

        detailed = list(base)
        swept: list[CloudAsset] = []
        for result in results:
            if isinstance(result, Exception):
                logger.error("Deep Azure collector task failed: %s", result)
                continue
            for asset in result:
                if asset.metadata.get("discovered_via") == "arm-sweep":
                    swept.append(asset)
                else:
                    detailed.append(asset)

        # Dedupe: detailed assets win over sweep hits with the same resource ID
        known = {a.arn.lower() for a in detailed if a.arn}
        merged = detailed + [a for a in swept if a.arn and a.arn.lower() not in known]

        logger.info("Deep Azure inventory: %d assets", len(merged))
        self._cached_assets = merged
        return merged
