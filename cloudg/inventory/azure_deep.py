"""Deep Azure inventory collector — full-subscription resource enumeration.

Primary path: **Azure Resource Graph** (``azure-mgmt-resourcegraph``). A few
paginated KQL queries per subscription return every resource with its full
``properties``, the resource groups, RBAC role assignments (with role
names) and Defender for Cloud plans. Rows are turned into linked assets by
:class:`cloudg.inventory.azure_graph.AzureAssetBuilder`.

Fallback path (Resource Graph SDK missing or the query failing): the
per-service SDK collectors of :class:`AzureCollector` plus the network
fabric (NICs, public IPs, disks, load balancers, route tables, NAT and
application gateways, firewalls, private endpoints, scale sets, disk
encryption sets), resource groups, and the ARM ``resources.list()``
catch-all sweep for everything else. Both paths feed the same row
pipeline, so assets carry the same metadata and relations.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any, Callable

from cloudg.collectors.azure import AzureCollector, subscription_client
from cloudg.inventory.azure_graph import (
    _ARM_TYPE_MAP,
    AzureAssetBuilder,
    asset_type_from_arm,
    collect_subscription_graph,
    default_graph_client_factory,
    to_rest,
)
from cloudg.schema.models import CloudAsset

logger = logging.getLogger(__name__)

__all__ = ["AzureDeepInventoryCollector", "asset_type_from_arm", "_ARM_TYPE_MAP"]


class AzureDeepInventoryCollector(AzureCollector):
    """Azure collector backed by Resource Graph, with an SDK fallback.

    Args:
        credential: azure-identity TokenCredential.
        subscription_id: Subscription to inventory.
        graph_client_factory: ``credential -> client`` building an object
            with ``resources(QueryRequest)`` (injectable for tests). Defaults
            to ``azure.mgmt.resourcegraph.ResourceGraphClient``.
        use_resource_graph: Set False to force the per-service SDK path.

    Attributes:
        collection_mode: ``"resource-graph"`` or ``"sdk"`` after :meth:`collect`.
    """

    graph_client_factory: Callable[[Any], Any] | None = None

    def __init__(
        self,
        credential: Any,
        subscription_id: str,
        graph_client_factory: Callable[[Any], Any] | None = None,
        use_resource_graph: bool = True,
    ) -> None:
        super().__init__(credential, subscription_id)
        if graph_client_factory is not None:
            self.graph_client_factory = graph_client_factory
        self._use_resource_graph = use_resource_graph
        self.collection_mode: str | None = None

    # ------------------------------------------------------------------
    # Resource Graph path
    # ------------------------------------------------------------------

    def _graph_builder(self) -> AzureAssetBuilder:
        factory = self.graph_client_factory or default_graph_client_factory
        client = factory(self._credential)  # ImportError when the SDK is absent
        return collect_subscription_graph(client, self._subscription_id, errors=self.service_errors)

    async def _collect_via_graph(self) -> list[CloudAsset]:
        builder = await asyncio.to_thread(self._graph_builder)
        return builder.build()

    # ------------------------------------------------------------------
    # SDK fallback: network fabric, containers and the ARM sweep
    # ------------------------------------------------------------------

    def _fetch_nics(self) -> list[dict[str, Any]]:
        return self._rows(
            self._client("network").network_interfaces.list_all(), "Microsoft.Network/networkInterfaces"
        )

    def _fetch_public_ips(self) -> list[dict[str, Any]]:
        return self._rows(
            self._client("network").public_ip_addresses.list_all(), "Microsoft.Network/publicIPAddresses"
        )

    def _fetch_load_balancers(self) -> list[dict[str, Any]]:
        return self._rows(
            self._client("network").load_balancers.list_all(), "Microsoft.Network/loadBalancers"
        )

    def _fetch_route_tables(self) -> list[dict[str, Any]]:
        return self._rows(self._client("network").route_tables.list_all(), "Microsoft.Network/routeTables")

    def _fetch_nat_gateways(self) -> list[dict[str, Any]]:
        return self._rows(self._client("network").nat_gateways.list_all(), "Microsoft.Network/natGateways")

    def _fetch_private_endpoints(self) -> list[dict[str, Any]]:
        return self._rows(
            self._client("network").private_endpoints.list_by_subscription(),
            "Microsoft.Network/privateEndpoints",
        )

    def _fetch_application_gateways(self) -> list[dict[str, Any]]:
        return self._rows(
            self._client("network").application_gateways.list_all(),
            "Microsoft.Network/applicationGateways",
        )

    def _fetch_firewalls(self) -> list[dict[str, Any]]:
        return self._rows(self._client("network").azure_firewalls.list_all(), "Microsoft.Network/azureFirewalls")

    def _fetch_disks(self) -> list[dict[str, Any]]:
        return self._rows(self._client("compute").disks.list(), "Microsoft.Compute/disks")

    def _fetch_scale_sets(self) -> list[dict[str, Any]]:
        return self._rows(
            self._client("compute").virtual_machine_scale_sets.list_all(),
            "Microsoft.Compute/virtualMachineScaleSets",
        )

    def _fetch_disk_encryption_sets(self) -> list[dict[str, Any]]:
        return self._rows(
            self._client("compute").disk_encryption_sets.list(), "Microsoft.Compute/diskEncryptionSets"
        )

    def _fetch_resource_sweep(self) -> list[dict[str, Any]]:
        """Every resource via ARM (id/type/kind/sku/identity/managedBy, no properties)."""
        return self._rows(self._client("resource").resources.list())

    def _fetch_resource_groups(self) -> list[dict[str, Any]]:
        return self._rows(
            self._client("resource").resource_groups.list(), "Microsoft.Resources/resourceGroups"
        )

    def _fetch_subscription(self) -> list[dict[str, Any]]:
        sub = subscription_client(self._credential).subscriptions.get(self._subscription_id)
        state = getattr(sub, "state", None)
        return [
            {
                "id": f"/subscriptions/{self._subscription_id}",
                "name": getattr(sub, "display_name", None),
                "type": "microsoft.resources/subscriptions",
                "tenantId": getattr(sub, "tenant_id", None),
                "tags": to_rest(getattr(sub, "tags", None)) or {},
                "properties": {"state": getattr(state, "value", state)},
            }
        ]

    def _fabric_fetchers(self) -> dict[str, Callable[[], list[dict[str, Any]]]]:
        return {
            "nics": self._fetch_nics,
            "public_ips": self._fetch_public_ips,
            "load_balancers": self._fetch_load_balancers,
            "route_tables": self._fetch_route_tables,
            "nat_gateways": self._fetch_nat_gateways,
            "private_endpoints": self._fetch_private_endpoints,
            "application_gateways": self._fetch_application_gateways,
            "azure_firewalls": self._fetch_firewalls,
            "disks": self._fetch_disks,
            "vm_scale_sets": self._fetch_scale_sets,
            "disk_encryption_sets": self._fetch_disk_encryption_sets,
        }

    async def _collect_via_sdk(self) -> list[CloudAsset]:
        detailed_task = self._gather_rows({**self._service_fetchers(), **self._fabric_fetchers()})
        detailed, sweep, groups, subscription = await asyncio.gather(
            detailed_task,
            self._run_service("arm_sweep", self._fetch_resource_sweep),
            self._run_service("resource_groups", self._fetch_resource_groups),
            self._run_service("subscription", self._fetch_subscription),
        )
        builder = AzureAssetBuilder(self._subscription_id, "sdk")
        builder.add_rows(detailed)  # detailed rows first: they win over sweep hits
        builder.add_rows(sweep, discovered_via="arm-sweep")
        builder.add_containers(groups)
        builder.include_subscription(subscription[0] if subscription else None)
        return builder.build()

    # ------------------------------------------------------------------
    # Main interface
    # ------------------------------------------------------------------

    async def collect(self) -> list[CloudAsset]:
        """Inventory the subscription via Resource Graph, else via the SDKs."""
        logger.info("Starting deep Azure inventory for subscription %s", self._subscription_id)
        self.service_errors = {}
        assets: list[CloudAsset] | None = None
        if self._use_resource_graph:
            try:
                assets = await self._collect_via_graph()
                self.collection_mode = "resource-graph"
            except ImportError:
                logger.info(
                    "azure-mgmt-resourcegraph not installed; using per-service Azure SDK collection"
                )
            except Exception as exc:
                logger.warning(
                    "Resource Graph inventory failed for %s (%s); falling back to the SDK collectors",
                    self._subscription_id,
                    exc,
                )
                self.service_errors["resource_graph"] = str(exc)
        if assets is None:
            assets = await self._collect_via_sdk()
            self.collection_mode = "sdk"

        logger.info("Deep Azure inventory (%s): %d assets", self.collection_mode, len(assets))
        self._cached_assets = assets
        return assets
