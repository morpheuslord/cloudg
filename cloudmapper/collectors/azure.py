"""Azure resource collector using azure-mgmt SDKs."""

from __future__ import annotations

import asyncio
import logging
from typing import Any

from cloudmapper.collectors.base import BaseCollector
from cloudmapper.schema.models import (
    AssetType,
    CloudAsset,
    CloudProvider,
    EdgeType,
    NetworkEdge,
)

logger = logging.getLogger(__name__)


class AzureCollector(BaseCollector):
    """Collects Azure resources using azure-mgmt-* SDKs.

    Enumerates: Virtual Machines, VNets, Subnets, NSGs, Storage Accounts,
    SQL Databases, Key Vaults, Load Balancers.
    """

    def __init__(
        self,
        credential: Any,
        subscription_id: str,
    ) -> None:
        self._credential = credential
        self._subscription_id = subscription_id
        self._cached_assets: list[CloudAsset] = []

    def _run_sync(self, coro: Any) -> Any:
        """Helper to run sync Azure SDK calls in executor."""
        return coro

    async def _collect_vms(self) -> list[CloudAsset]:
        """Collect Azure Virtual Machines."""
        assets: list[CloudAsset] = []
        try:
            from azure.mgmt.compute import ComputeManagementClient

            client = ComputeManagementClient(self._credential, self._subscription_id)
            vm_list = client.virtual_machines.list_all()

            for vm in vm_list:
                tags = vm.tags or {}
                assets.append(
                    CloudAsset(
                        arn=vm.id,
                        name=vm.name,
                        asset_type=AssetType.VIRTUAL_MACHINE,
                        provider=CloudProvider.AZURE,
                        region=vm.location,
                        account_id=self._subscription_id,
                        tags=tags,
                        metadata={
                            "vm_size": vm.hardware_profile.vm_size if vm.hardware_profile else None,
                            "os_type": (
                                vm.storage_profile.os_disk.os_type
                                if vm.storage_profile and vm.storage_profile.os_disk
                                else None
                            ),
                            "provisioning_state": vm.provisioning_state,
                            "network_interfaces": [
                                nic.id
                                for nic in (
                                    vm.network_profile.network_interfaces
                                    if vm.network_profile
                                    else []
                                )
                            ],
                        },
                        raw_data={"id": vm.id, "name": vm.name, "location": vm.location},
                    )
                )
        except ImportError:
            logger.warning("azure-mgmt-compute not installed, skipping VM collection")
        except Exception as exc:
            logger.error("Failed to collect Azure VMs: %s", exc)
        return assets

    async def _collect_vnets(self) -> list[CloudAsset]:
        """Collect Azure Virtual Networks and Subnets."""
        assets: list[CloudAsset] = []
        try:
            from azure.mgmt.network import NetworkManagementClient

            client = NetworkManagementClient(self._credential, self._subscription_id)
            vnet_list = client.virtual_networks.list_all()

            for vnet in vnet_list:
                tags = vnet.tags or {}
                assets.append(
                    CloudAsset(
                        arn=vnet.id,
                        name=vnet.name,
                        asset_type=AssetType.VNET,
                        provider=CloudProvider.AZURE,
                        region=vnet.location,
                        account_id=self._subscription_id,
                        tags=tags,
                        metadata={
                            "address_space": (
                                vnet.address_space.address_prefixes
                                if vnet.address_space
                                else []
                            ),
                            "provisioning_state": vnet.provisioning_state,
                        },
                        raw_data={"id": vnet.id, "name": vnet.name},
                    )
                )

                # Subnets within VNet
                for subnet in vnet.subnets or []:
                    assets.append(
                        CloudAsset(
                            arn=subnet.id,
                            name=subnet.name,
                            asset_type=AssetType.SUBNET,
                            provider=CloudProvider.AZURE,
                            region=vnet.location,
                            account_id=self._subscription_id,
                            metadata={
                                "address_prefix": subnet.address_prefix,
                                "vnet_id": vnet.id,
                                "nsg_id": subnet.network_security_group.id if subnet.network_security_group else None,
                            },
                            raw_data={"id": subnet.id, "name": subnet.name},
                        )
                    )
        except ImportError:
            logger.warning("azure-mgmt-network not installed, skipping VNet collection")
        except Exception as exc:
            logger.error("Failed to collect Azure VNets: %s", exc)
        return assets

    async def _collect_nsgs(self) -> list[CloudAsset]:
        """Collect Azure Network Security Groups."""
        assets: list[CloudAsset] = []
        try:
            from azure.mgmt.network import NetworkManagementClient

            client = NetworkManagementClient(self._credential, self._subscription_id)
            nsg_list = client.network_security_groups.list_all()

            for nsg in nsg_list:
                ingress_rules = []
                egress_rules = []
                for rule in nsg.security_rules or []:
                    rule_data = {
                        "name": rule.name,
                        "priority": rule.priority,
                        "direction": rule.direction,
                        "access": rule.access,
                        "protocol": rule.protocol,
                        "source_address_prefix": rule.source_address_prefix,
                        "destination_address_prefix": rule.destination_address_prefix,
                        "destination_port_range": rule.destination_port_range,
                    }
                    if rule.direction == "Inbound":
                        ingress_rules.append(rule_data)
                    else:
                        egress_rules.append(rule_data)

                assets.append(
                    CloudAsset(
                        arn=nsg.id,
                        name=nsg.name,
                        asset_type=AssetType.NSG,
                        provider=CloudProvider.AZURE,
                        region=nsg.location,
                        account_id=self._subscription_id,
                        tags=nsg.tags or {},
                        metadata={
                            "ingress_rules": ingress_rules,
                            "egress_rules": egress_rules,
                            "provisioning_state": nsg.provisioning_state,
                        },
                        raw_data={"id": nsg.id, "name": nsg.name},
                    )
                )
        except ImportError:
            logger.warning("azure-mgmt-network not installed, skipping NSG collection")
        except Exception as exc:
            logger.error("Failed to collect Azure NSGs: %s", exc)
        return assets

    async def _collect_storage(self) -> list[CloudAsset]:
        """Collect Azure Storage Accounts."""
        assets: list[CloudAsset] = []
        try:
            from azure.mgmt.storage import StorageManagementClient

            client = StorageManagementClient(self._credential, self._subscription_id)
            storage_list = client.storage_accounts.list()

            for account in storage_list:
                assets.append(
                    CloudAsset(
                        arn=account.id,
                        name=account.name,
                        asset_type=AssetType.BLOB_STORAGE,
                        provider=CloudProvider.AZURE,
                        region=account.location,
                        account_id=self._subscription_id,
                        tags=account.tags or {},
                        metadata={
                            "kind": account.kind,
                            "sku": account.sku.name if account.sku else None,
                            "https_only": account.enable_https_traffic_only,
                            "access_tier": account.access_tier,
                            "provisioning_state": account.provisioning_state,
                        },
                        raw_data={"id": account.id, "name": account.name},
                    )
                )
        except ImportError:
            logger.warning("azure-mgmt-storage not installed, skipping storage collection")
        except Exception as exc:
            logger.error("Failed to collect Azure storage accounts: %s", exc)
        return assets

    async def _collect_sql(self) -> list[CloudAsset]:
        """Collect Azure SQL databases."""
        assets: list[CloudAsset] = []
        try:
            from azure.mgmt.sql import SqlManagementClient
            from azure.mgmt.resource import ResourceManagementClient

            resource_client = ResourceManagementClient(
                self._credential, self._subscription_id
            )
            sql_client = SqlManagementClient(self._credential, self._subscription_id)

            # List resource groups first, then servers in each
            for rg in resource_client.resource_groups.list():
                try:
                    for server in sql_client.servers.list_by_resource_group(
                        rg.name
                    ):
                        for db in sql_client.databases.list_by_server(
                            rg.name, server.name
                        ):
                            assets.append(
                                CloudAsset(
                                    arn=db.id,
                                    name=db.name,
                                    asset_type=AssetType.AZURE_SQL,
                                    provider=CloudProvider.AZURE,
                                    region=db.location,
                                    account_id=self._subscription_id,
                                    metadata={
                                        "server_name": server.name,
                                        "resource_group": rg.name,
                                        "status": db.status,
                                        "edition": db.sku.tier if db.sku else None,
                                    },
                                    raw_data={"id": db.id, "name": db.name},
                                )
                            )
                except Exception:
                    continue
        except ImportError:
            logger.warning("azure-mgmt-sql not installed, skipping SQL collection")
        except Exception as exc:
            logger.error("Failed to collect Azure SQL: %s", exc)
        return assets

    async def _collect_keyvaults(self) -> list[CloudAsset]:
        """Collect Azure Key Vaults."""
        assets: list[CloudAsset] = []
        try:
            from azure.mgmt.keyvault import KeyVaultManagementClient

            client = KeyVaultManagementClient(self._credential, self._subscription_id)
            vault_list = client.vaults.list()

            for vault in vault_list:
                assets.append(
                    CloudAsset(
                        arn=vault.id,
                        name=vault.name,
                        asset_type=AssetType.KEY_VAULT,
                        provider=CloudProvider.AZURE,
                        region=vault.location if hasattr(vault, "location") else "unknown",
                        account_id=self._subscription_id,
                        metadata={
                            "vault_uri": getattr(vault, "properties", {})
                        },
                        raw_data={"id": vault.id, "name": vault.name},
                    )
                )
        except ImportError:
            logger.warning("azure-mgmt-keyvault not installed, skipping Key Vault collection")
        except Exception as exc:
            logger.error("Failed to collect Azure Key Vaults: %s", exc)
        return assets

    # ------------------------------------------------------------------
    # Main interface
    # ------------------------------------------------------------------

    async def collect(self) -> list[CloudAsset]:
        """Collect all Azure assets."""
        logger.info("Starting Azure asset collection for subscription %s", self._subscription_id)

        # Azure SDKs are sync, so we use asyncio tasks with run_in_executor pattern
        results = await asyncio.gather(
            self._collect_vms(),
            self._collect_vnets(),
            self._collect_nsgs(),
            self._collect_storage(),
            self._collect_sql(),
            self._collect_keyvaults(),
            return_exceptions=True,
        )

        all_assets: list[CloudAsset] = []
        for result in results:
            if isinstance(result, Exception):
                logger.error("Azure collector task failed: %s", result)
            elif isinstance(result, list):
                all_assets.extend(result)

        logger.info("Collected %d Azure assets", len(all_assets))
        self._cached_assets = all_assets
        return all_assets

    async def collect_edges(self) -> list[NetworkEdge]:
        """Collect Azure network edges from NSG rules."""
        assets = self._cached_assets or await self.collect()
        edges: list[NetworkEdge] = []

        nsg_assets = [a for a in assets if a.asset_type == AssetType.NSG]
        for nsg in nsg_assets:
            for rule in nsg.metadata.get("ingress_rules", []):
                if rule.get("access") == "Allow":
                    edges.append(
                        NetworkEdge(
                            source_id=rule.get("source_address_prefix", "*"),
                            target_id=nsg.id,
                            edge_type=EdgeType.SECURITY_GROUP_RULE,
                            port_range=rule.get("destination_port_range"),
                            protocol=rule.get("protocol", "ALL"),
                            cidr=rule.get("source_address_prefix"),
                            direction="ingress",
                        )
                    )

        # Containment edges: VNet contains Subnet
        vnet_assets = {
            a.arn: a.id for a in assets if a.asset_type == AssetType.VNET
        }
        for asset in assets:
            vnet_id = asset.metadata.get("vnet_id")
            if vnet_id and vnet_id in vnet_assets:
                edges.append(
                    NetworkEdge(
                        source_id=vnet_assets[vnet_id],
                        target_id=asset.id,
                        edge_type=EdgeType.CONTAINS,
                    )
                )

        logger.info("Collected %d Azure edges", len(edges))
        return edges
