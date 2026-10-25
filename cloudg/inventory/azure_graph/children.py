"""Child resources and subscription-level listings read through ARM REST.

Resource Graph returns tracked resources; most proxy resources (APIM APIs,
Service Bus queues, DNS record sets, function bindings, Data Factory
pipelines, diagnostic settings, ...) and several subscription-level
collections (deny assignments, locks, deployments, Lighthouse, activity
log export, PIM eligibility) only exist in ARM. ARM answers them with the
same ARM-shaped JSON Resource Graph uses, so returned rows go straight
into :class:`~.builder.AzureAssetBuilder` and through the extractors
registered for their types.

:data:`CHILD_SPECS` is the plan: each :class:`ChildSpec` names its task
(:mod:`.families`), the parent types it hangs off, the relative path and
API version, and optional nested specs applied to every returned child.
:func:`fetch_children` runs the selected specs with bounded concurrency
(the HTTP calls run in a thread pool; rows are applied to the builder on
the calling thread), and records one coverage record per task:
SUCCESS, PARTIAL when some calls were refused or throttled, FAILED when
every call failed, SKIPPED when the credential cannot issue ARM tokens.
"""

from __future__ import annotations

import logging
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Callable

from cloudg.exceptions import CredentialError
from cloudg.inventory.azure_graph.helpers import _get, _lower, subscription_ref
from cloudg.inventory.azure_graph.rest import AzureRestError

if TYPE_CHECKING:
    from cloudg.inventory.azure_graph.builder import AzureAssetBuilder
    from cloudg.inventory.azure_graph.registry import _Draft

logger = logging.getLogger("cloudg.inventory.azure_graph")

SUBSCRIPTION = "@subscription"
RESOURCE_GROUPS = "microsoft.resources/subscriptions/resourcegroups"


@dataclass(frozen=True)
class ChildSpec:
    """One kind of child resource (or subscription-level listing).

    Args:
        task: Coverage task name.
        parents: Lowercase ARM types of the parent drafts, or
            :data:`SUBSCRIPTION` for ``/subscriptions/<id>``.
        path: Path appended to the parent ID (``apis``,
            ``providers/Microsoft.Insights/diagnosticSettings``).
        api_version: ARM ``api-version``.
        child_type: Type set on rows that lack one.
        single: The path returns one object, not a ``value`` list.
        params: Extra query parameters.
        nested: Specs applied to every returned child.
        when: Predicate on the parent draft (SKU, kind, feature flag).
        force_type: Always set ``child_type``, even when rows carry a type.
    """

    task: str
    parents: tuple[str, ...]
    path: str
    api_version: str
    child_type: str | None = None
    single: bool = False
    params: tuple[tuple[str, str], ...] = ()
    nested: tuple["ChildSpec", ...] = ()
    when: Callable[["_Draft"], bool] | None = None
    force_type: bool = False


def _kind_has(word: str) -> Callable[["_Draft"], bool]:
    return lambda d: word in _lower(d.row.get("kind"))


def _sku_in(*names: str) -> Callable[["_Draft"], bool]:
    def check(d: "_Draft") -> bool:
        sku = d.row.get("sku")
        name = _lower(_get(sku, "name") if isinstance(sku, dict) else sku)
        return any(n in name for n in names)

    return check


def _prop_true(key: str) -> Callable[["_Draft"], bool]:
    return lambda d: bool(_get(d.props, key))


def _not_function(d: "_Draft") -> bool:
    return "functionapp" not in _lower(d.row.get("kind"))


_APIM = "microsoft.apimanagement/service"
_SITES = "microsoft.web/sites"
_ADF = "microsoft.datafactory/factories"
_AA = "microsoft.automation/automationaccounts"
_CDN = "microsoft.cdn/profiles"

CHILD_SPECS: tuple[ChildSpec, ...] = (
    # ── subscription-level listings ──
    ChildSpec(
        "deny_assignments",
        (SUBSCRIPTION,),
        "providers/Microsoft.Authorization/denyAssignments",
        "2022-04-01",
    ),
    ChildSpec("locks", (SUBSCRIPTION,), "providers/Microsoft.Authorization/locks", "2020-05-01"),
    ChildSpec(
        "pim_eligibility",
        (SUBSCRIPTION,),
        "providers/Microsoft.Authorization/roleEligibilityScheduleInstances",
        "2020-10-01",
        params=(("$filter", "atScope()"),),
    ),
    ChildSpec(
        "lighthouse",
        (SUBSCRIPTION,),
        "providers/Microsoft.ManagedServices/registrationAssignments",
        "2022-10-01",
        params=(("$expandRegistrationDefinition", "true"),),
    ),
    ChildSpec(
        "activity_log",
        (SUBSCRIPTION,),
        "providers/Microsoft.Insights/diagnosticSettings",
        "2021-05-01-preview",
    ),
    ChildSpec(
        "deployments",
        (SUBSCRIPTION, RESOURCE_GROUPS),
        "providers/Microsoft.Resources/deployments",
        "2024-03-01",
        params=(("$top", "50"),),
    ),
    ChildSpec(
        "deployment_stacks",
        (SUBSCRIPTION, RESOURCE_GROUPS),
        "providers/Microsoft.Resources/deploymentStacks",
        "2024-03-01",
    ),
    # ── identity ──
    ChildSpec(
        "managed_identity_credentials",
        ("microsoft.managedidentity/userassignedidentities",),
        "federatedIdentityCredentials",
        "2023-01-31",
    ),
    ChildSpec("key_vault_items", ("microsoft.keyvault/vaults",), "keys", "2023-07-01"),
    ChildSpec("key_vault_items", ("microsoft.keyvault/vaults",), "secrets", "2023-07-01"),
    # ── API Management ──
    ChildSpec(
        "apim",
        (_APIM,),
        "apis",
        "2022-08-01",
        params=(("$filter", "isCurrent eq true"),),
        nested=(ChildSpec("apim", (), "policies", "2022-08-01"),),
    ),
    ChildSpec("apim", (_APIM,), "backends", "2022-08-01"),
    ChildSpec(
        "apim",
        (_APIM,),
        "products",
        "2022-08-01",
        nested=(
            ChildSpec(
                "apim",
                (),
                "apis",
                "2022-08-01",
                child_type="microsoft.apimanagement/service/products/apis",
                force_type=True,
            ),
        ),
    ),
    ChildSpec("apim", (_APIM,), "namedValues", "2022-08-01"),
    ChildSpec("apim", (_APIM,), "gateways", "2022-08-01", when=_sku_in("premium", "developer")),
    ChildSpec("apim", (_APIM,), "authorizationServers", "2022-08-01"),
    ChildSpec("apim", (_APIM,), "openidConnectProviders", "2022-08-01"),
    ChildSpec("apim", (_APIM,), "policies", "2022-08-01"),
    # ── App Service, Functions, Static Web Apps ──
    ChildSpec("functions", (_SITES,), "functions", "2023-01-01", when=_kind_has("functionapp")),
    ChildSpec("web_apps", (_SITES,), "config/web", "2023-01-01", single=True),
    ChildSpec(
        "web_apps", (_SITES,), "sourcecontrols/web", "2023-01-01", single=True, when=_not_function
    ),
    ChildSpec("web_apps", (_SITES,), "basicPublishingCredentialsPolicies", "2023-01-01"),
    ChildSpec("static_sites", ("microsoft.web/staticsites",), "linkedBackends", "2023-01-01"),
    ChildSpec(
        "static_sites", ("microsoft.web/staticsites",), "userProvidedFunctionApps", "2023-01-01"
    ),
    # ── messaging ──
    ChildSpec("service_bus", ("microsoft.servicebus/namespaces",), "queues", "2021-11-01"),
    ChildSpec(
        "service_bus",
        ("microsoft.servicebus/namespaces",),
        "topics",
        "2021-11-01",
        nested=(ChildSpec("service_bus", (), "subscriptions", "2021-11-01"),),
    ),
    ChildSpec("event_hubs", ("microsoft.eventhub/namespaces",), "eventhubs", "2024-01-01"),
    ChildSpec(
        "stream_analytics", ("microsoft.streamanalytics/streamingjobs",), "inputs", "2020-03-01"
    ),
    ChildSpec(
        "stream_analytics", ("microsoft.streamanalytics/streamingjobs",), "outputs", "2020-03-01"
    ),
    # ── analytics ──
    ChildSpec("data_factory", (_ADF,), "linkedservices", "2018-06-01"),
    ChildSpec("data_factory", (_ADF,), "datasets", "2018-06-01"),
    ChildSpec("data_factory", (_ADF,), "integrationRuntimes", "2018-06-01"),
    ChildSpec("data_factory", (_ADF,), "pipelines", "2018-06-01"),
    ChildSpec("data_factory", (_ADF,), "triggers", "2018-06-01"),
    ChildSpec("synapse", ("microsoft.synapse/workspaces",), "sqlPools", "2021-06-01"),
    ChildSpec("synapse", ("microsoft.synapse/workspaces",), "bigDataPools", "2021-06-01"),
    ChildSpec("synapse", ("microsoft.synapse/workspaces",), "integrationRuntimes", "2021-06-01"),
    ChildSpec(
        "kusto",
        ("microsoft.kusto/clusters",),
        "databases",
        "2023-08-15",
        nested=(ChildSpec("kusto", (), "dataConnections", "2023-08-15"),),
    ),
    ChildSpec("kusto", ("microsoft.kusto/clusters",), "principalAssignments", "2023-08-15"),
    # ── data ──
    ChildSpec("sql", ("microsoft.sql/servers",), "failoverGroups", "2021-11-01"),
    ChildSpec("sql", ("microsoft.sql/servers",), "auditingSettings", "2021-11-01"),
    ChildSpec(
        "cosmos",
        ("microsoft.documentdb/databaseaccounts",),
        "sqlRoleAssignments",
        "2023-04-15",
        when=lambda d: _lower(d.row.get("kind")) in ("", "globaldocumentdb"),
    ),
    ChildSpec(
        "storage", ("microsoft.storage/storageaccounts",), "objectReplicationPolicies", "2023-01-01"
    ),
    ChildSpec(
        "storage",
        ("microsoft.storage/storageaccounts",),
        "localUsers",
        "2023-01-01",
        when=_prop_true("isSftpEnabled"),
    ),
    ChildSpec(
        "storage",
        ("microsoft.storage/storageaccounts",),
        "blobServices/default",
        "2023-01-01",
        single=True,
        child_type="microsoft.storage/storageaccounts/blobservices",
    ),
    # ── DNS ──
    ChildSpec("dns_records", ("microsoft.network/dnszones",), "all", "2018-05-01"),
    ChildSpec("dns_records", ("microsoft.network/privatednszones",), "ALL", "2020-06-01"),
    ChildSpec(
        "dns_resolver", ("microsoft.network/dnsresolvers",), "inboundEndpoints", "2022-07-01"
    ),
    ChildSpec(
        "dns_resolver", ("microsoft.network/dnsresolvers",), "outboundEndpoints", "2022-07-01"
    ),
    ChildSpec(
        "dns_resolver",
        ("microsoft.network/dnsforwardingrulesets",),
        "forwardingRules",
        "2022-07-01",
    ),
    ChildSpec(
        "dns_resolver",
        ("microsoft.network/dnsforwardingrulesets",),
        "virtualNetworkLinks",
        "2022-07-01",
    ),
    # ── hybrid ──
    ChildSpec(
        "virtual_wan",
        ("microsoft.network/virtualhubs",),
        "hubVirtualNetworkConnections",
        "2023-09-01",
    ),
    ChildSpec("virtual_wan", ("microsoft.network/virtualhubs",), "hubRouteTables", "2023-09-01"),
    ChildSpec("virtual_wan", ("microsoft.network/virtualhubs",), "routingIntent", "2023-09-01"),
    ChildSpec("virtual_wan", ("microsoft.network/virtualhubs",), "bgpConnections", "2023-09-01"),
    ChildSpec("virtual_wan", ("microsoft.network/virtualhubs",), "ipConfigurations", "2023-09-01"),
    ChildSpec(
        "network_manager",
        ("microsoft.network/networkmanagers",),
        "connectivityConfigurations",
        "2023-09-01",
    ),
    ChildSpec(
        "network_manager",
        ("microsoft.network/networkmanagers",),
        "networkGroups",
        "2023-09-01",
        nested=(ChildSpec("network_manager", (), "staticMembers", "2023-09-01"),),
    ),
    ChildSpec(
        "network_manager",
        ("microsoft.network/networkmanagers",),
        "securityAdminConfigurations",
        "2023-09-01",
        nested=(
            ChildSpec(
                "network_manager",
                (),
                "ruleCollections",
                "2023-09-01",
                nested=(ChildSpec("network_manager", (), "rules", "2023-09-01"),),
            ),
        ),
    ),
    # ── Front Door Standard / Premium ──
    ChildSpec(
        "front_door",
        (_CDN,),
        "afdEndpoints",
        "2023-05-01",
        when=_sku_in("azurefrontdoor"),
        nested=(ChildSpec("front_door", (), "routes", "2023-05-01"),),
    ),
    ChildSpec(
        "front_door",
        (_CDN,),
        "originGroups",
        "2023-05-01",
        when=_sku_in("azurefrontdoor"),
        nested=(ChildSpec("front_door", (), "origins", "2023-05-01"),),
    ),
    ChildSpec(
        "front_door",
        (_CDN,),
        "ruleSets",
        "2023-05-01",
        when=_sku_in("azurefrontdoor"),
        nested=(ChildSpec("front_door", (), "rules", "2023-05-01"),),
    ),
    ChildSpec("front_door", (_CDN,), "customDomains", "2023-05-01", when=_sku_in("azurefrontdoor")),
    ChildSpec(
        "front_door", (_CDN,), "securityPolicies", "2023-05-01", when=_sku_in("azurefrontdoor")
    ),
    ChildSpec("front_door", (_CDN,), "secrets", "2023-05-01", when=_sku_in("azurefrontdoor")),
    # ── containers ──
    ChildSpec(
        "acr",
        ("microsoft.containerregistry/registries",),
        "replications",
        "2023-07-01",
        when=_sku_in("premium"),
    ),
    ChildSpec("acr", ("microsoft.containerregistry/registries",), "webhooks", "2023-07-01"),
    ChildSpec("acr", ("microsoft.containerregistry/registries",), "tasks", "2019-06-01-preview"),
    ChildSpec("acr", ("microsoft.containerregistry/registries",), "scopeMaps", "2023-07-01"),
    ChildSpec("acr", ("microsoft.containerregistry/registries",), "tokens", "2023-07-01"),
    ChildSpec(
        "aks",
        ("microsoft.containerservice/managedclusters",),
        "trustedAccessRoleBindings",
        "2024-05-01",
    ),
    # ── AI and ML ──
    ChildSpec(
        "cognitive_services", ("microsoft.cognitiveservices/accounts",), "deployments", "2024-10-01"
    ),
    ChildSpec(
        "cognitive_services", ("microsoft.cognitiveservices/accounts",), "raiPolicies", "2024-10-01"
    ),
    ChildSpec(
        "machine_learning",
        ("microsoft.machinelearningservices/workspaces",),
        "datastores",
        "2024-04-01",
    ),
    ChildSpec(
        "machine_learning",
        ("microsoft.machinelearningservices/workspaces",),
        "connections",
        "2024-04-01",
    ),
    ChildSpec(
        "machine_learning",
        ("microsoft.machinelearningservices/workspaces",),
        "computes",
        "2024-04-01",
    ),
    ChildSpec(
        "machine_learning",
        ("microsoft.machinelearningservices/workspaces",),
        "onlineEndpoints",
        "2024-04-01",
        nested=(ChildSpec("machine_learning", (), "deployments", "2024-04-01"),),
    ),
    ChildSpec(
        "search", ("microsoft.search/searchservices",), "sharedPrivateLinkResources", "2023-11-01"
    ),
    # ── operations ──
    ChildSpec("automation", (_AA,), "schedules", "2023-11-01"),
    ChildSpec("automation", (_AA,), "jobSchedules", "2023-11-01"),
    ChildSpec(
        "automation",
        (_AA,),
        "hybridRunbookWorkerGroups",
        "2023-11-01",
        nested=(ChildSpec("automation", (), "hybridRunbookWorkers", "2023-11-01"),),
    ),
    ChildSpec("automation", (_AA,), "softwareUpdateConfigurations", "2019-06-01"),
    ChildSpec("automation", (_AA,), "webhooks", "2015-10-31"),
    ChildSpec(
        "monitor_private_link",
        ("microsoft.insights/privatelinkscopes",),
        "scopedResources",
        "2021-07-01-preview",
    ),
    ChildSpec("batch", ("microsoft.batch/batchaccounts",), "pools", "2024-02-01"),
    ChildSpec("spring_apps", ("microsoft.appplatform/spring",), "apps", "2023-12-01"),
    ChildSpec(
        "data_protection",
        ("microsoft.dataprotection/backupvaults",),
        "backupPolicies",
        "2024-04-01",
    ),
    ChildSpec("dev_center", ("microsoft.devcenter/devcenters",), "catalogs", "2024-02-01"),
    ChildSpec("dev_center", ("microsoft.devcenter/projects",), "environmentTypes", "2024-02-01"),
    ChildSpec(
        "app_configuration",
        ("microsoft.appconfiguration/configurationstores",),
        "replicas",
        "2023-03-01",
    ),
)

# Resource types whose diagnostic settings are read (task diagnostic_settings)
DIAGNOSTIC_TYPES: tuple[str, ...] = (
    "microsoft.keyvault/vaults",
    "microsoft.storage/storageaccounts",
    "microsoft.sql/servers/databases",
    "microsoft.network/networksecuritygroups",
    "microsoft.network/applicationgateways",
    "microsoft.network/azurefirewalls",
    "microsoft.network/frontdoors",
    "microsoft.cdn/profiles",
    "microsoft.network/publicipaddresses",
    "microsoft.network/virtualnetworkgateways",
    "microsoft.network/bastionhosts",
    "microsoft.apimanagement/service",
    "microsoft.containerservice/managedclusters",
    "microsoft.containerregistry/registries",
    "microsoft.web/sites",
    "microsoft.cognitiveservices/accounts",
    "microsoft.documentdb/databaseaccounts",
    "microsoft.eventhub/namespaces",
    "microsoft.servicebus/namespaces",
    "microsoft.logic/workflows",
    "microsoft.recoveryservices/vaults",
    "microsoft.datafactory/factories",
    "microsoft.synapse/workspaces",
    "microsoft.search/searchservices",
    "microsoft.cache/redis",
    "microsoft.dbforpostgresql/flexibleservers",
    "microsoft.dbformysql/flexibleservers",
    "microsoft.machinelearningservices/workspaces",
    "microsoft.kusto/clusters",
    "microsoft.app/managedenvironments",
    "microsoft.automation/automationaccounts",
)

# Sentinel children under a Log Analytics workspace
_SENTINEL = "providers/Microsoft.SecurityInsights"
SENTINEL_SPECS: tuple[ChildSpec, ...] = (
    ChildSpec("sentinel", (), f"{_SENTINEL}/dataConnectors", "2024-03-01"),
    ChildSpec("sentinel", (), f"{_SENTINEL}/alertRules", "2024-03-01"),
    ChildSpec("sentinel", (), f"{_SENTINEL}/automationRules", "2024-03-01"),
)


@dataclass
class _TaskStats:
    calls: int = 0
    rows: int = 0
    failures: list[str] = field(default_factory=list)
    started: float = field(default_factory=time.time)


class ChildFetcher:
    """Runs child specs against one builder.

    Args:
        client: ARM REST client (``list(path, api_version, **params)`` and
            ``get(path, api_version)``), e.g. :class:`~.rest.AzureRestClient`.
        builder: The subscription's builder.
        max_parents: Most parents queried per spec.
        concurrency: Concurrent HTTP calls.
    """

    def __init__(
        self,
        client: Any,
        builder: "AzureAssetBuilder",
        *,
        max_parents: int = 500,
        concurrency: int = 8,
    ) -> None:
        self.client = client
        self.b = builder
        self.max_parents = max_parents
        self.concurrency = max(1, concurrency)
        self.stats: dict[str, _TaskStats] = {}
        self.credential_error: str | None = None

    # ── one call ──

    def _call(self, parent_id: str, spec: ChildSpec) -> tuple[list[dict[str, Any]], str | None]:
        if self.credential_error:
            return [], self.credential_error
        path = f"{parent_id.rstrip('/')}/{spec.path}"
        params = dict(spec.params)
        try:
            if spec.single:
                row = self.client.get(path, spec.api_version, **params)
                return ([row] if isinstance(row, dict) and row.get("id") else []), None
            return self.client.list(path, spec.api_version, **params), None
        except CredentialError as exc:
            self.credential_error = str(exc)
            return [], self.credential_error
        except AzureRestError as exc:
            if exc.not_applicable:
                return [], None
            return [], f"{spec.path}: {exc}"
        except Exception as exc:  # network errors, malformed JSON
            return [], f"{spec.path}: {type(exc).__name__}: {str(exc)[:200]}"

    def _parents(self, spec: ChildSpec) -> list[tuple[str, "_Draft | None"]]:
        out: list[tuple[str, "_Draft | None"]] = []
        for kind in spec.parents:
            if kind == SUBSCRIPTION:
                out.append((subscription_ref(self.b.subscription_id), None))
                continue
            for d in self.b.drafts_of(kind):
                if spec.when is None or spec.when(d):
                    out.append((d.id, d))
        return out[: self.max_parents]

    def _apply(self, rows: list[dict[str, Any]], parent: "_Draft | None", spec: ChildSpec) -> list:
        """Feed rows to the builder; returns the drafts created (for nested specs)."""
        created = []
        for row in rows:
            if not isinstance(row, dict) or not row.get("id"):
                continue
            row = dict(row)
            if spec.child_type and (spec.force_type or spec.single or not row.get("type")):
                row["type"] = spec.child_type
            if parent is not None:
                row.setdefault("location", parent.region)
            row.setdefault("subscriptionId", self.b.subscription_id)
            draft = self.b.add_row(row, discovered_via="arm-rest")
            created.append((row["id"], draft))
        return created

    def run_spec(self, spec: ChildSpec, parents: list[tuple[str, "_Draft | None"]]) -> None:
        stats = self.stats.setdefault(spec.task, _TaskStats())
        if not parents:
            return
        with ThreadPoolExecutor(max_workers=min(self.concurrency, len(parents))) as pool:
            results = list(pool.map(lambda p: self._call(p[0], spec), parents))
        children: list[tuple[str, Any]] = []
        for (pid, parent), (rows, error) in zip(parents, results):
            stats.calls += 1
            if error:
                stats.failures.append(error)
                continue
            stats.rows += len(rows)
            created = self._apply(rows, parent, spec)
            children.extend(created)
        for nested in spec.nested:
            nested_parents = [
                (cid, draft)
                for cid, draft in children
                if nested.when is None or (draft and nested.when(draft))
            ][: self.max_parents]
            self.run_spec(nested, nested_parents)

    def run(self, specs: list[ChildSpec]) -> None:
        for spec in specs:
            self.run_spec(spec, self._parents(spec))

    def record(self, recorder: Any) -> None:
        for task, stats in self.stats.items():
            if self.credential_error and not stats.rows:
                recorder.record(
                    task, "SKIPPED", error=self.credential_error[:300], started=stats.started
                )
                continue
            recorder.outcome(task, stats.rows, stats.failures, stats.calls, stats.started)


def fetch_children(
    client: Any,
    builder: "AzureAssetBuilder",
    tasks: set[str],
    recorder: Any,
    *,
    max_parents: int = 500,
    concurrency: int = 8,
    diagnostic_settings: bool = True,
    max_diagnostic_settings: int = 1000,
) -> ChildFetcher:
    """Run every selected child spec, diagnostic settings and Sentinel."""
    fetcher = ChildFetcher(client, builder, max_parents=max_parents, concurrency=concurrency)
    fetcher.run([s for s in CHILD_SPECS if s.task in tasks])
    if "sentinel" in tasks:
        _sentinel(fetcher)
    if diagnostic_settings and "diagnostic_settings" in tasks:
        spec = ChildSpec(
            "diagnostic_settings",
            DIAGNOSTIC_TYPES,
            "providers/Microsoft.Insights/diagnosticSettings",
            "2021-05-01-preview",
        )
        parents = []
        for kind in DIAGNOSTIC_TYPES:
            parents.extend((d.id, d) for d in builder.drafts_of(kind))
        fetcher.run_spec(spec, parents[:max_diagnostic_settings])
    fetcher.record(recorder)
    return fetcher


def _sentinel(fetcher: ChildFetcher) -> None:
    """Sentinel onboarding per workspace, then its connectors and rules."""
    from cloudg.inventory.azure_graph.security import sentinel_placeholder

    b = fetcher.b
    workspaces = [(d.id, d) for d in b.drafts_of("microsoft.operationalinsights/workspaces")]
    onboarding = ChildSpec(
        "sentinel",
        (),
        f"{_SENTINEL}/onboardingStates",
        "2024-03-01",
        child_type="microsoft.securityinsights/onboardingstates",
    )
    fetcher.run_spec(onboarding, workspaces[: fetcher.max_parents])
    onboarded = {
        str(d.md.get("workspace_id") or "").lower()
        for d in b.drafts_of("microsoft.securityinsights/onboardingstates")
    }
    enabled = [(wid, d) for wid, d in workspaces if wid.lower() in onboarded]
    for spec in SENTINEL_SPECS:
        fetcher.run_spec(spec, enabled)
    fetcher.stats.setdefault("sentinel", _TaskStats())
    b.at_build(sentinel_placeholder)


__all__ = [
    "CHILD_SPECS",
    "DIAGNOSTIC_TYPES",
    "ChildFetcher",
    "ChildSpec",
    "SUBSCRIPTION",
    "fetch_children",
]
