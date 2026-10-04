"""Azure resource collector using azure-mgmt SDKs.

Every per-service collector fetches SDK models in a worker thread
(``asyncio.to_thread``: the Azure SDKs are synchronous), serialises them
to their ARM REST shape and hands the rows to
:class:`cloudg.inventory.azure_graph.AzureAssetBuilder`, the same
row-to-asset pipeline the Resource Graph path of the deep inventory
collector uses. One failing service never discards the others.
"""

from __future__ import annotations

import asyncio
import json
import logging
import threading
from typing import Any, Callable

from cloudg.collectors.base import BaseCollector
from cloudg.schema.models import (
    AssetType,
    CloudAsset,
    EdgeType,
    NetworkEdge,
)

logger = logging.getLogger(__name__)

_ARM_ENDPOINT = "https://management.azure.com"


# ---------------------------------------------------------------------------
# SDK client helpers (azure-mgmt-resource >= 24 moved clients into
# sub-packages; older releases expose them at the package root)
# ---------------------------------------------------------------------------


def _resource_client_class() -> Any:
    try:
        from azure.mgmt.resource.resources import ResourceManagementClient
    except ImportError:
        from azure.mgmt.resource import ResourceManagementClient
    return ResourceManagementClient


def _subscription_client_class() -> Any:
    try:
        from azure.mgmt.resource.subscriptions import SubscriptionClient
    except ImportError:
        from azure.mgmt.resource import SubscriptionClient
    return SubscriptionClient


def resource_management_client(credential: Any, subscription_id: str) -> Any:
    return _resource_client_class()(credential, subscription_id)


def subscription_client(credential: Any) -> Any:
    return _subscription_client_class()(credential)


def _subscription_dict(sub: Any) -> dict[str, Any]:
    state = getattr(sub, "state", None)
    return {
        "subscription_id": getattr(sub, "subscription_id", None),
        "display_name": getattr(sub, "display_name", None),
        "state": getattr(state, "value", state),
        "tenant_id": getattr(sub, "tenant_id", None),
    }


def _list_subscriptions_rest(credential: Any) -> list[dict[str, Any]]:
    """ARM ``GET /subscriptions`` without azure-mgmt-resource subscriptions."""
    import urllib.request

    token = credential.get_token(f"{_ARM_ENDPOINT}/.default").token
    url: str | None = f"{_ARM_ENDPOINT}/subscriptions?api-version=2022-12-01"
    out: list[dict[str, Any]] = []
    pages = 0
    while url and pages < 100:
        pages += 1
        req = urllib.request.Request(url, headers={"Authorization": f"Bearer {token}"})
        with urllib.request.urlopen(req, timeout=30) as resp:  # nosec B310 - fixed https ARM endpoint
            data = json.load(resp)
        for s in data.get("value", []) or []:
            out.append(
                {
                    "subscription_id": s.get("subscriptionId"),
                    "display_name": s.get("displayName"),
                    "state": s.get("state"),
                    "tenant_id": s.get("tenantId"),
                }
            )
        url = data.get("nextLink")
        if url and not url.startswith(_ARM_ENDPOINT + "/"):
            break
    return out


def list_subscriptions(credential: Any, include_disabled: bool = False) -> list[dict[str, Any]]:
    """Subscriptions visible to the credential (only ``Enabled`` by default).

    Returns:
        Dicts with ``subscription_id``, ``display_name``, ``state``, ``tenant_id``.
    """
    try:
        client = subscription_client(credential)
        subs = [_subscription_dict(s) for s in client.subscriptions.list()]
    except ImportError:
        subs = _list_subscriptions_rest(credential)
    subs = [s for s in subs if s.get("subscription_id")]
    if include_disabled:
        return subs
    return [s for s in subs if str(s.get("state") or "").lower() == "enabled"]


def first_subscription_id(credential: Any) -> str | None:
    """The first subscription visible to the credential (legacy behaviour)."""
    subs = list_subscriptions(credential, include_disabled=False) or list_subscriptions(
        credential, include_disabled=True
    )
    return subs[0]["subscription_id"] if subs else None


def _resource_group_name(resource_id: str | None) -> str | None:
    parts = (resource_id or "").split("/")
    for i, part in enumerate(parts[:-1]):
        if part.lower() == "resourcegroups":
            return parts[i + 1]
    return None


class AzureCollector(BaseCollector):
    """Collects Azure resources using azure-mgmt-* SDKs.

    Enumerates: Virtual Machines, VNets (and their subnets), NSGs, Storage
    Accounts, SQL servers and databases, Key Vaults.

    Attributes:
        service_errors: Per-service failure messages of the last collection.
    """

    def __init__(
        self,
        credential: Any,
        subscription_id: str,
    ) -> None:
        self._credential = credential
        self._subscription_id = subscription_id
        self._cached_assets: list[CloudAsset] = []
        self.service_errors: dict[str, str] = {}
        self._clients: dict[str, Any] = {}
        self._client_lock = threading.Lock()

    # ------------------------------------------------------------------
    # Clients and plumbing
    # ------------------------------------------------------------------

    def _client(self, kind: str) -> Any:
        with self._client_lock:
            if kind in self._clients:
                return self._clients[kind]
            if kind == "compute":
                from azure.mgmt.compute import ComputeManagementClient as cls
            elif kind == "network":
                from azure.mgmt.network import NetworkManagementClient as cls
            elif kind == "storage":
                from azure.mgmt.storage import StorageManagementClient as cls
            elif kind == "sql":
                from azure.mgmt.sql import SqlManagementClient as cls
            elif kind == "keyvault":
                from azure.mgmt.keyvault import KeyVaultManagementClient as cls
            elif kind == "resource":
                client = resource_management_client(self._credential, self._subscription_id)
                self._clients[kind] = client
                return client
            else:  # pragma: no cover - programming error
                raise ValueError(kind)
            client = cls(self._credential, self._subscription_id)
            self._clients[kind] = client
            return client

    @staticmethod
    def _rows(items: Any, default_type: str | None = None) -> list[dict[str, Any]]:
        from cloudg.inventory.azure_graph import to_rest

        rows: list[dict[str, Any]] = []
        for item in items or []:
            row = to_rest(item)
            if not isinstance(row, dict) or not row.get("id"):
                continue
            if default_type and not row.get("type"):
                row["type"] = default_type
            rows.append(row)
        return rows

    async def _run_service(
        self, name: str, fetch: Callable[[], list[dict[str, Any]]]
    ) -> list[dict[str, Any]]:
        """Run one blocking fetcher in a worker thread; failures stay local."""
        try:
            return await asyncio.to_thread(fetch)
        except ImportError as exc:
            logger.warning("Azure %s collection skipped: SDK not installed (%s)", name, exc)
        except Exception as exc:
            logger.error("Failed to collect Azure %s: %s", name, exc)
            self.service_errors[name] = str(exc)
        return []

    async def _gather_rows(
        self, fetchers: dict[str, Callable[[], list[dict[str, Any]]]]
    ) -> list[dict[str, Any]]:
        results = await asyncio.gather(*(self._run_service(n, f) for n, f in fetchers.items()))
        return [row for rows in results for row in rows]

    def _build(self, rows: list[dict[str, Any]], via: str = "sdk") -> list[CloudAsset]:
        from cloudg.inventory.azure_graph import build_assets

        return build_assets(rows, self._subscription_id, discovered_via=via)

    # ------------------------------------------------------------------
    # Per-service fetchers (blocking; return ARM REST-shaped rows)
    # ------------------------------------------------------------------

    def _fetch_vms(self) -> list[dict[str, Any]]:
        return self._rows(
            self._client("compute").virtual_machines.list_all(), "Microsoft.Compute/virtualMachines"
        )

    def _fetch_vnets(self) -> list[dict[str, Any]]:
        return self._rows(
            self._client("network").virtual_networks.list_all(), "Microsoft.Network/virtualNetworks"
        )

    def _fetch_nsgs(self) -> list[dict[str, Any]]:
        return self._rows(
            self._client("network").network_security_groups.list_all(),
            "Microsoft.Network/networkSecurityGroups",
        )

    def _fetch_storage(self) -> list[dict[str, Any]]:
        return self._rows(
            self._client("storage").storage_accounts.list(), "Microsoft.Storage/storageAccounts"
        )

    def _fetch_sql(self) -> list[dict[str, Any]]:
        client = self._client("sql")
        rows: list[dict[str, Any]] = []
        for server in self._rows(client.servers.list(), "Microsoft.Sql/servers"):
            rg = _resource_group_name(server["id"])
            name = server.get("name") or server["id"].rsplit("/", 1)[-1]
            props = server.get("properties")
            if not isinstance(props, dict):
                props = server["properties"] = {}
            if rg:
                try:
                    props["firewallRules"] = self._rows(
                        client.firewall_rules.list_by_server(rg, name)
                    )
                except Exception as exc:
                    logger.debug("SQL firewall rules failed for %s: %s", name, exc)
                try:
                    props["virtualNetworkRules"] = self._rows(
                        client.virtual_network_rules.list_by_server(rg, name)
                    )
                except Exception as exc:
                    logger.debug("SQL VNet rules failed for %s: %s", name, exc)
            rows.append(server)
            if not rg:
                continue
            try:
                for db in self._rows(
                    client.databases.list_by_server(rg, name), "Microsoft.Sql/servers/databases"
                ):
                    if str(db.get("name", "")).lower() != "master":
                        rows.append(db)
            except Exception as exc:
                logger.debug("SQL databases failed for %s: %s", name, exc)
        return rows

    def _fetch_keyvaults(self) -> list[dict[str, Any]]:
        # vaults.list() returns bare TrackedResources; list_by_subscription()
        # returns full Vault objects (vaultUri, access policies, ACLs, ...)
        return self._rows(
            self._client("keyvault").vaults.list_by_subscription(), "Microsoft.KeyVault/vaults"
        )

    def _service_fetchers(self) -> dict[str, Callable[[], list[dict[str, Any]]]]:
        return {
            "vms": self._fetch_vms,
            "vnets": self._fetch_vnets,
            "nsgs": self._fetch_nsgs,
            "storage": self._fetch_storage,
            "sql": self._fetch_sql,
            "keyvaults": self._fetch_keyvaults,
        }

    # Per-service asset collectors (kept for callers that want one service)

    async def _collect_service(self, name: str) -> list[CloudAsset]:
        return self._build(await self._run_service(name, self._service_fetchers()[name]))

    async def _collect_vms(self) -> list[CloudAsset]:
        return await self._collect_service("vms")

    async def _collect_vnets(self) -> list[CloudAsset]:
        return await self._collect_service("vnets")

    async def _collect_nsgs(self) -> list[CloudAsset]:
        return await self._collect_service("nsgs")

    async def _collect_storage(self) -> list[CloudAsset]:
        return await self._collect_service("storage")

    async def _collect_sql(self) -> list[CloudAsset]:
        return await self._collect_service("sql")

    async def _collect_keyvaults(self) -> list[CloudAsset]:
        return await self._collect_service("keyvaults")

    # ------------------------------------------------------------------
    # Main interface
    # ------------------------------------------------------------------

    async def collect(self) -> list[CloudAsset]:
        """Collect all Azure assets (services run concurrently in threads)."""
        logger.info("Starting Azure asset collection for subscription %s", self._subscription_id)
        self.service_errors = {}
        rows = await self._gather_rows(self._service_fetchers())
        all_assets = self._build(rows)
        logger.info("Collected %d Azure assets", len(all_assets))
        self._cached_assets = all_assets
        return all_assets

    @staticmethod
    def _rule_edges(
        nsg: CloudAsset, rule: dict[str, Any], by_arn: dict[str, str]
    ) -> list[NetworkEdge]:
        if str(rule.get("access") or "").lower() != "allow":
            return []
        sources = [str(s) for s in rule.get("source_address_prefixes") or [] if s]
        if not sources and rule.get("source_address_prefix"):
            sources = [str(rule["source_address_prefix"])]
        asgs = [str(a) for a in rule.get("source_application_security_groups") or [] if a]
        ports = [str(p) for p in rule.get("destination_port_ranges") or [] if p]
        if not ports and rule.get("destination_port_range"):
            ports = [str(rule["destination_port_range"])]
        common: dict[str, Any] = {
            "target_id": nsg.id,
            "edge_type": EdgeType.SECURITY_GROUP_RULE,
            "port_range": ",".join(dict.fromkeys(ports)) or None,
            "protocol": str(rule.get("protocol") or "ALL"),
            "direction": "ingress",
            "description": f"NSG rule {rule.get('name')}"
            + (" (default)" if rule.get("default") else ""),
        }
        edges = [NetworkEdge(source_id=src, cidr=src, **common) for src in dict.fromkeys(sources)]
        for asg in dict.fromkeys(asgs):
            edges.append(
                NetworkEdge(
                    source_id=by_arn.get(asg.lower(), asg),
                    properties={"application_security_group": asg},
                    **common,
                )
            )
        if not edges:
            edges.append(NetworkEdge(source_id="*", cidr="*", **common))
        return edges

    async def collect_edges(self) -> list[NetworkEdge]:
        """Collect Azure network edges from NSG rules and VNet containment."""
        assets = self._cached_assets or await self.collect()
        edges: list[NetworkEdge] = []
        by_arn = {a.arn.lower(): a.id for a in assets if a.arn}

        for nsg in (a for a in assets if a.asset_type == AssetType.NSG):
            for rule in nsg.metadata.get("ingress_rules", []) or []:
                try:
                    edges.extend(self._rule_edges(nsg, rule, by_arn))
                except Exception:
                    logger.debug("Skipping NSG rule %s on %s", rule, nsg.name, exc_info=True)

        # Containment edges: VNet contains Subnet
        vnet_assets = {
            a.arn.lower(): a.id for a in assets if a.asset_type == AssetType.VNET and a.arn
        }
        for asset in assets:
            vnet_id = asset.metadata.get("vnet_id")
            if isinstance(vnet_id, str) and vnet_id.lower() in vnet_assets:
                edges.append(
                    NetworkEdge(
                        source_id=vnet_assets[vnet_id.lower()],
                        target_id=asset.id,
                        edge_type=EdgeType.CONTAINS,
                        relationship="VPC_CONTAINS_SUBNET",
                    )
                )

        logger.info("Collected %d Azure edges", len(edges))
        return edges
