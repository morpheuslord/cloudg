"""Deep Azure inventory collector: full-subscription resource enumeration.

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

Depth beyond the breadth query (both paths, all best-effort, one coverage
record per task in :attr:`AzureDeepInventoryCollector.coverage`):

- more Resource Graph tables (policy, policy states, Defender assessments,
  alerts and secure score, backup items, Kubernetes configuration,
  Virtual Network Manager, guest configuration, maintenance, data
  collection rule associations), management group role assignments and
  role definitions (Resource Graph path only),
- child resources and subscription-level listings read through ARM REST
  (:mod:`cloudg.inventory.azure_graph.children`),
- AI Search and Synapse data-plane metadata,
- in-cluster AKS mapping (:mod:`cloudg.inventory.azure_kubernetes`).

``services`` / ``exclude_services`` select tasks by task or family name,
like the AWS deep collector (:mod:`cloudg.inventory.azure_graph.families`).
"""

from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass
from typing import Any, Callable

from cloudg.collectors.azure import AzureCollector, subscription_client
from cloudg.coverage import CollectionCoverage
from cloudg.inventory.azure_graph import (
    _ARM_TYPE_MAP,
    AzureAssetBuilder,
    asset_type_from_arm,
    collect_subscription_graph,
    default_graph_client_factory,
    to_rest,
)
from cloudg.inventory.azure_graph.children import CHILD_SPECS, fetch_children
from cloudg.inventory.azure_graph.dataplane import fetch_data_planes
from cloudg.inventory.azure_graph.families import (
    AZURE_TASK_FAMILIES,
    TaskRecorder,
    row_filter,
    select_azure_tasks,
)
from cloudg.inventory.azure_graph.rest import (
    default_arm_client_factory,
    default_dataplane_client_factory,
)
from cloudg.schema.models import CloudAsset

logger = logging.getLogger(__name__)

__all__ = [
    "AzureDeepInventoryCollector",
    "AzureDeepOptions",
    "asset_type_from_arm",
    "_ARM_TYPE_MAP",
]

# Tasks that need Resource Graph (skipped on the SDK fallback path)
_GRAPH_TASKS = (
    "role_assignments",
    "management_group_role_assignments",
    "role_definitions",
    "defender_pricings",
    "policy",
    "policy_states",
    "backup_items",
    "kubernetes_configuration",
    "network_resources",
    "guest_configuration",
    "maintenance",
    "insights",
    "security_assessments",
    "secure_score",
    "security_alerts",
)
_REST_TASKS = tuple(
    dict.fromkeys([s.task for s in CHILD_SPECS] + ["sentinel", "diagnostic_settings"])
)
_PLANE_TASKS = ("search_data_plane", "synapse_data_plane")


@dataclass
class AzureDeepOptions:
    """Depth options of :class:`AzureDeepInventoryCollector` (all on by default)."""

    services: list[str] | None = None
    exclude_services: list[str] | None = None
    child_resources: bool = True
    max_child_parents: int = 500
    diagnostic_settings: bool = True
    max_diagnostic_settings: int = 1000
    data_plane: bool = True
    kubernetes: bool = True
    kubernetes_timeout: int = 10
    rest_concurrency: int = 8


class AzureDeepInventoryCollector(AzureCollector):
    """Azure collector backed by Resource Graph, with an SDK fallback.

    Args:
        credential: azure-identity TokenCredential.
        subscription_id: Subscription to inventory.
        graph_client_factory: ``credential -> client`` building an object
            with ``resources(QueryRequest)`` (injectable for tests). Defaults
            to ``azure.mgmt.resourcegraph.ResourceGraphClient``.
        use_resource_graph: Set False to force the per-service SDK path.
        arm_client_factory: ``credential -> client`` with ``list(path,
            api_version, **params)``, ``get(...)`` and ``post(...)`` for ARM
            REST (injectable for tests). Defaults to
            :func:`~cloudg.inventory.azure_graph.rest.default_arm_client_factory`.
        dataplane_client_factory: ``(credential, base_url, scope) -> client``
            for the AI Search and Synapse data planes.
        options: :class:`AzureDeepOptions` (or keyword arguments of it).

    Attributes:
        collection_mode: ``"resource-graph"`` or ``"sdk"`` after :meth:`collect`.
        coverage: Per-task coverage records of the last :meth:`collect`.
    """

    graph_client_factory: Callable[[Any], Any] | None = None
    arm_client_factory: Callable[[Any], Any] | None = None
    dataplane_client_factory: Callable[[Any, str, str], Any] | None = None
    aks_reader_factory: Callable[..., Any] | None = None

    def __init__(
        self,
        credential: Any,
        subscription_id: str,
        graph_client_factory: Callable[[Any], Any] | None = None,
        use_resource_graph: bool = True,
        *,
        arm_client_factory: Callable[[Any], Any] | None = None,
        dataplane_client_factory: Callable[[Any, str, str], Any] | None = None,
        options: AzureDeepOptions | None = None,
        **option_kwargs: Any,
    ) -> None:
        super().__init__(credential, subscription_id)
        if graph_client_factory is not None:
            self.graph_client_factory = graph_client_factory
        if arm_client_factory is not None:
            self.arm_client_factory = arm_client_factory
        if dataplane_client_factory is not None:
            self.dataplane_client_factory = dataplane_client_factory
        self._use_resource_graph = use_resource_graph
        self.options = options or AzureDeepOptions(**option_kwargs)
        self.collection_mode: str | None = None
        self.coverage = CollectionCoverage(provider="azure", account_id=subscription_id)
        self._tasks = self._selected_tasks()

    def _selected_tasks(self) -> set[str]:
        opts = self.options
        names = [t for t in AZURE_TASK_FAMILIES if t != "entra"]
        return set(select_azure_tasks(names, opts.services, opts.exclude_services))

    # ------------------------------------------------------------------
    # Resource Graph path
    # ------------------------------------------------------------------

    def _graph_builder(self) -> AzureAssetBuilder:
        factory = self.graph_client_factory or default_graph_client_factory
        client = factory(self._credential)  # ImportError when the SDK is absent
        return collect_subscription_graph(
            client,
            self._subscription_id,
            errors=self.service_errors,
            tasks=self._tasks,
            recorder=TaskRecorder(self.coverage),
            keep_row=row_filter(self.options.services, self.options.exclude_services),
        )

    def _graph_and_depth(self) -> AzureAssetBuilder:
        builder = self._graph_builder()
        self._safe_depth(builder)
        return builder

    async def _collect_via_graph(self) -> list[CloudAsset]:
        builder = await asyncio.to_thread(self._graph_and_depth)
        return builder.build()

    # ------------------------------------------------------------------
    # Depth: ARM REST children, data planes, in-cluster AKS
    # ------------------------------------------------------------------

    def _depth(self, builder: AzureAssetBuilder) -> None:
        """Every selected REST / data-plane / Kubernetes task (best-effort)."""
        rec = TaskRecorder(self.coverage)
        opts = self.options
        selected = self._tasks
        for task in (*_REST_TASKS, *_PLANE_TASKS, "aks_kubernetes"):
            if task not in selected:
                rec.skip(task, "not selected (inventory.services)")
        rest_tasks = {t for t in _REST_TASKS if t in selected}
        if not opts.child_resources:
            for task in sorted(rest_tasks):
                rec.skip(task, "disabled (azure.child_resources)")
            rest_tasks = set()
        if not opts.diagnostic_settings and "diagnostic_settings" in rest_tasks:
            rec.skip("diagnostic_settings", "disabled (azure.diagnostic_settings)")
        arm = None
        if rest_tasks or "aks_kubernetes" in selected:
            try:
                arm = (self.arm_client_factory or default_arm_client_factory)(self._credential)
            except Exception as exc:
                for task in sorted(rest_tasks):
                    rec.record(task, "FAILED", error=f"ARM REST client: {exc}"[:300])
                rest_tasks = set()
        if arm is not None and rest_tasks:
            fetch_children(
                arm,
                builder,
                rest_tasks,
                rec,
                max_parents=opts.max_child_parents,
                concurrency=opts.rest_concurrency,
                diagnostic_settings=opts.diagnostic_settings,
                max_diagnostic_settings=opts.max_diagnostic_settings,
            )
        plane_tasks = {t for t in _PLANE_TASKS if t in selected}
        if plane_tasks and not opts.data_plane:
            for task in sorted(plane_tasks):
                rec.skip(task, "disabled (azure.data_plane)")
        elif plane_tasks:
            fetch_data_planes(
                self._credential,
                self.dataplane_client_factory or default_dataplane_client_factory,
                builder,
                plane_tasks,
                rec,
                max_parents=opts.max_child_parents,
            )
        if "aks_kubernetes" in selected:
            self._aks_workloads(builder, arm, rec)

    def _aks_workloads(self, builder: AzureAssetBuilder, arm: Any, rec: TaskRecorder) -> None:
        """In-cluster objects of every Entra-integrated AKS cluster."""
        from cloudg.inventory.azure_kubernetes import aks_mappable, collect_aks_workloads

        clusters = builder.drafts_of("microsoft.containerservice/managedclusters")
        if not self.options.kubernetes:
            rec.skip("aks_kubernetes", "disabled (inventory.kubernetes)")
            return
        if arm is None:
            rec.skip("aks_kubernetes", "no ARM REST client")
            return
        for d in clusters:
            task = f"kubernetes:{d.name}"
            reason = aks_mappable(d.row)
            if reason:
                rec.skip(task, reason)
                continue
            started = time.time()
            try:
                found = collect_aks_workloads(
                    self._credential,
                    arm,
                    {**d.row, "properties": d.props},
                    timeout=self.options.kubernetes_timeout,
                    reader_factory=self.aks_reader_factory,
                )
            except Exception as exc:
                logger.warning("Kubernetes API mapping skipped for %s: %s", d.name, exc)
                rec.record(task, "FAILED", error=str(exc)[:300], started=started)
                continue
            for asset in found:
                builder.add_extra(asset)
            rec.record(task, "SUCCESS", len(found), started=started)

    # ------------------------------------------------------------------
    # SDK fallback: network fabric, containers and the ARM sweep
    # ------------------------------------------------------------------

    def _fetch_nics(self) -> list[dict[str, Any]]:
        return self._rows(
            self._client("network").network_interfaces.list_all(),
            "Microsoft.Network/networkInterfaces",
        )

    def _fetch_public_ips(self) -> list[dict[str, Any]]:
        return self._rows(
            self._client("network").public_ip_addresses.list_all(),
            "Microsoft.Network/publicIPAddresses",
        )

    def _fetch_load_balancers(self) -> list[dict[str, Any]]:
        return self._rows(
            self._client("network").load_balancers.list_all(), "Microsoft.Network/loadBalancers"
        )

    def _fetch_route_tables(self) -> list[dict[str, Any]]:
        return self._rows(
            self._client("network").route_tables.list_all(), "Microsoft.Network/routeTables"
        )

    def _fetch_nat_gateways(self) -> list[dict[str, Any]]:
        return self._rows(
            self._client("network").nat_gateways.list_all(), "Microsoft.Network/natGateways"
        )

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
        return self._rows(
            self._client("network").azure_firewalls.list_all(), "Microsoft.Network/azureFirewalls"
        )

    def _fetch_disks(self) -> list[dict[str, Any]]:
        return self._rows(self._client("compute").disks.list(), "Microsoft.Compute/disks")

    def _fetch_scale_sets(self) -> list[dict[str, Any]]:
        return self._rows(
            self._client("compute").virtual_machine_scale_sets.list_all(),
            "Microsoft.Compute/virtualMachineScaleSets",
        )

    def _fetch_disk_encryption_sets(self) -> list[dict[str, Any]]:
        return self._rows(
            self._client("compute").disk_encryption_sets.list(),
            "Microsoft.Compute/diskEncryptionSets",
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
        keep = row_filter(self.options.services, self.options.exclude_services)
        if keep is not None:
            detailed = [r for r in detailed if keep(r)]
            sweep = [r for r in sweep if keep(r)]
        builder = AzureAssetBuilder(self._subscription_id, "sdk")
        builder.add_rows(detailed)  # detailed rows first: they win over sweep hits
        builder.add_rows(sweep, discovered_via="arm-sweep")
        builder.add_containers(groups)
        builder.include_subscription(subscription[0] if subscription else None)
        rec = TaskRecorder(self.coverage)
        rec.record("resources", "SUCCESS", len(detailed) + len(sweep), "per-service SDK fallback")
        for task in _GRAPH_TASKS:
            rec.skip(task, "Resource Graph unavailable (SDK fallback)")
        await asyncio.to_thread(self._safe_depth, builder)
        return builder.build()

    def _safe_depth(self, builder: AzureAssetBuilder) -> None:
        try:
            self._depth(builder)
        except Exception as exc:  # depth never costs the breadth inventory
            logger.warning("Azure depth collection failed for %s: %s", self._subscription_id, exc)
            TaskRecorder(self.coverage).record("depth", "FAILED", error=str(exc)[:300])

    # ------------------------------------------------------------------
    # Main interface
    # ------------------------------------------------------------------

    async def collect(self) -> list[CloudAsset]:
        """Inventory the subscription via Resource Graph, else via the SDKs."""
        logger.info("Starting deep Azure inventory for subscription %s", self._subscription_id)
        self.service_errors = {}
        self.coverage = CollectionCoverage(provider="azure", account_id=self._subscription_id)
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
            self.coverage = CollectionCoverage(provider="azure", account_id=self._subscription_id)
            assets = await self._collect_via_sdk()
            self.collection_mode = "sdk"

        logger.info("Deep Azure inventory (%s): %d assets", self.collection_mode, len(assets))
        self._cached_assets = assets
        return assets
