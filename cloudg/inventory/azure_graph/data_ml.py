"""Extractors for data platforms and AI: pipelines, warehouses, replication, models.

- Data Factory and Synapse: linked services (``DEPENDS_ON`` the stores
  their endpoints name, and their integration runtime), datasets,
  pipelines (``READS_FROM`` / ``WRITES_TO`` datasets, ``INVOKES`` linked
  compute, other pipelines and HTTP hosts), triggers (``SCHEDULED_BY`` /
  ``TRIGGERED_BY``), integration runtimes, Git configuration.
- Synapse SQL and Spark pools, Data Explorer (Kusto) clusters, databases,
  data connections (``READS_FROM``) and principal assignments, HDInsight.
- SQL managed instances, elastic pools, geo-replicas and failover groups
  (``REPLICATES_TO``), auditing (``LOGS_TO``).
- Cosmos DB regions as replica assets (``REPLICATES_TO``) and data-plane
  role assignments (``GRANTS_ACCESS``).
- Storage object replication (``REPLICATES_TO``), SFTP local users,
  blob data protection settings; Azure NetApp Files volumes (replication,
  backup, snapshot policies).
- Azure OpenAI / AI Services deployments (``ML_MODEL``, protected by their
  content filter ``AI_GUARDRAIL``), Foundry projects, Azure ML online
  endpoints, deployments, compute and datastores, connections, AI Search
  shared private links and data-plane objects (data sources, indexers,
  indexes, skillsets), Purview.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, Any, Iterable

from cloudg.inventory._util import walk_strings
from cloudg.inventory.aws_services._base import rel
from cloudg.inventory.azure_graph.helpers import (
    _get,
    _list,
    _lower,
    _path,
    _rid,
    host_of,
    parent_resource_id,
    principal_ref,
)
from cloudg.inventory.azure_graph.registry import (
    _Draft,
    _keyvault_key_ref,
    _set_exposure,
    extractor,
    relation_row,
)
from cloudg.schema.models import EdgeType

if TYPE_CHECKING:
    from cloudg.inventory.azure_graph.builder import AzureAssetBuilder

_SERVER_RE = re.compile(
    r"(?:server|data source|host)\s*=\s*(?:tcp:)?([a-z0-9.-]+\.[a-z]{2,})", re.I
)
_ACCOUNT_RE = re.compile(r"accountname\s*=\s*([a-z0-9]+)", re.I)
_ENDPOINT_RE = re.compile(r"(?:endpoint|accountendpoint)\s*=\s*([a-z]+://[^;\s]+)", re.I)
_RESOURCE_ID_RE = re.compile(r"resourceid\s*=\s*(/subscriptions/[^;\s]+)", re.I)
_STORAGE_SUFFIX = {
    "azureblobstorage": "blob",
    "azureblobfs": "dfs",
    "azuredatalakestore": "dfs",
    "azuretablestorage": "table",
    "azurefilestorage": "file",
    "azureblob": "blob",
    "adlsgen2": "dfs",
    "azuretable": "table",
}


def endpoint_refs(value: Any, kind: str = "", limit: int = 10) -> list[str]:
    """Hosts / resource IDs named by a configuration value, never its secrets."""
    refs: list[str] = []
    suffix = _STORAGE_SUFFIX.get(_lower(kind), "blob")

    def add(ref: str | None) -> None:
        if ref and ref not in refs and len(refs) < limit:
            refs.append(ref)

    for text in walk_strings(value):
        if len(text) > 4000:
            continue
        for rid in _RESOURCE_ID_RE.findall(text):
            add(rid.rstrip("/"))
        for host in _SERVER_RE.findall(text):
            add(host.lower())
        for acct in _ACCOUNT_RE.findall(text):
            add(f"{acct.lower()}.{suffix}.core.windows.net")
        for url in _ENDPOINT_RE.findall(text):
            add(host_of(url))
        stripped = text.strip()
        if stripped.lower().startswith(("https://", "http://")) and "@" not in stripped:
            add(host_of(stripped))
        elif stripped.lower().startswith("/subscriptions/") and "/providers/" in stripped.lower():
            add(stripped.split("?", 1)[0])
    return refs


def _factory_of(child_id: str) -> str | None:
    """Data Factory / Synapse workspace of a pipeline, dataset, ... ID."""
    return parent_resource_id(child_id)


def _ref(owner: str | None, kind: str, item: Any) -> str | None:
    name = _get(item, "referenceName") if isinstance(item, dict) else item
    if not owner or not isinstance(name, str) or not name or "@" in name:
        return None
    return f"{owner}/{kind}/{name}"


# ── Data Factory / Synapse ──

_ADF = "microsoft.datafactory/factories"
_SYN = "microsoft.synapse/workspaces"


@extractor(f"{_ADF}/linkedservices", f"{_SYN}/linkedservices")
def _x_linked_service(d: _Draft, b: "AzureAssetBuilder") -> None:
    p = d.props
    owner = _factory_of(d.id)
    kind = _get(p, "type")
    tp = _get(p, "typeProperties") or {}
    refs = endpoint_refs(tp, str(kind or ""))
    d.md.update({"linked_service_type": kind, "endpoints": refs})
    for ref in refs:
        d.add(rel(ref, EdgeType.REFERENCES, "DEPENDS_ON", description=f"{kind} endpoint"))
    d.add(
        rel(
            _ref(owner, "integrationruntimes", _get(p, "connectVia")),
            EdgeType.REFERENCES,
            "RUNS_ON",
            description="integration runtime",
        )
    )
    for store in _key_vault_stores(tp):
        d.add(rel(_ref(owner, "linkedservices", store), EdgeType.REFERENCES, "READS_FROM"))
    d.props = {k: v for k, v in p.items() if _lower(k) != "typeproperties"}


def _key_vault_stores(value: Any, depth: int = 0) -> Iterable[Any]:
    if depth > 8:
        return
    if isinstance(value, dict):
        if _lower(_get(value, "type")) == "azurekeyvaultsecret":
            yield _get(value, "store")
        for v in value.values():
            yield from _key_vault_stores(v, depth + 1)
    elif isinstance(value, list):
        for v in value:
            yield from _key_vault_stores(v, depth + 1)


@extractor(f"{_ADF}/datasets", f"{_SYN}/datasets")
def _x_dataset(d: _Draft, b: "AzureAssetBuilder") -> None:
    p = d.props
    owner = _factory_of(d.id)
    location = _path(p, "typeProperties", "location") or {}
    d.md.update(
        {
            "dataset_type": _get(p, "type"),
            "container": _get(location, "container") or _get(location, "fileSystem"),
            "folder": _get(location, "folderPath"),
            "table": _path(p, "typeProperties", "tableName") or _path(p, "typeProperties", "table"),
        }
    )
    d.add(
        rel(
            _ref(owner, "linkedservices", _get(p, "linkedServiceName")),
            EdgeType.REFERENCES,
            "DEPENDS_ON",
        )
    )


def _activities(acts: Any) -> Iterable[dict[str, Any]]:
    stack = list(_list(acts))
    while stack:
        act = stack.pop()
        if not isinstance(act, dict):
            continue
        yield act
        tp = _get(act, "typeProperties") or {}
        for key in ("activities", "ifTrueActivities", "ifFalseActivities", "defaultActivities"):
            stack.extend(_list(_get(tp, key)))
        for case in _list(_get(tp, "cases")):
            stack.extend(_list(_get(case, "activities")))


def _activity_relations(d: _Draft, owner: str | None, act: dict[str, Any]) -> None:
    kind = _lower(_get(act, "type"))
    tp = _get(act, "typeProperties") or {}
    name = _get(act, "name")
    for ds in _list(_get(act, "inputs")):
        d.add(
            rel(
                _ref(owner, "datasets", ds),
                EdgeType.REFERENCES,
                "READS_FROM",
                description=f"{name} input",
            )
        )
    for ds in _list(_get(act, "outputs")):
        d.add(
            rel(
                _ref(owner, "datasets", ds),
                EdgeType.REFERENCES,
                "WRITES_TO",
                description=f"{name} output",
            )
        )
    d.add(rel(_ref(owner, "datasets", _get(tp, "dataset")), EdgeType.REFERENCES, "READS_FROM"))
    d.add(
        rel(
            _ref(owner, "linkedservices", _get(act, "linkedServiceName")),
            EdgeType.INVOKES,
            "INVOKES",
            description=f"{kind} activity",
        )
    )
    d.add(
        rel(
            _ref(owner, "pipelines", _get(tp, "pipeline")),
            EdgeType.INVOKES,
            "INVOKES",
            description="execute pipeline",
        )
    )
    url = _get(tp, "url")
    if kind in ("webactivity", "webhook") and isinstance(url, str) and "@" not in url:
        d.add(rel(host_of(url), EdgeType.INVOKES, "INVOKES", description=f"{name} call"))


@extractor(f"{_ADF}/pipelines", f"{_SYN}/pipelines")
def _x_pipeline(d: _Draft, b: "AzureAssetBuilder") -> None:
    owner = _factory_of(d.id)
    kinds = []
    for act in _activities(_get(d.props, "activities")):
        kinds.append(_get(act, "type"))
        _activity_relations(d, owner, act)
    d.md["activity_types"] = sorted({k for k in kinds if k})
    d.md["activity_count"] = len(kinds)
    d.props = {k: v for k, v in d.props.items() if _lower(k) != "activities"}


@extractor(f"{_ADF}/triggers", f"{_SYN}/triggers")
def _x_pipeline_trigger(d: _Draft, b: "AzureAssetBuilder") -> None:
    p = d.props
    owner = _factory_of(d.id)
    kind = _lower(_get(p, "type"))
    tp = _get(p, "typeProperties") or {}
    targets = [_get(x, "pipelineReference") for x in _list(_get(p, "pipelines"))]
    targets.append(_get(p, "pipeline") and _get(_get(p, "pipeline"), "pipelineReference"))
    scope = _get(tp, "scope")
    d.md.update(
        {
            "trigger_type": _get(p, "type"),
            "runtime_state": _get(p, "runtimeState"),
            "recurrence": _get(tp, "recurrence"),
            "event_scope": scope,
            "events": _list(_get(tp, "events")),
        }
    )
    for target in targets:
        pipeline = _ref(owner, "pipelines", target)
        if kind in ("scheduletrigger", "tumblingwindowtrigger"):
            d.add(rel(pipeline, EdgeType.MANAGES, "SCHEDULED_BY", description=_get(p, "type")))
        else:
            d.add(rel(pipeline, EdgeType.INVOKES, "INVOKES", description=_get(p, "type")))
            if pipeline and isinstance(scope, str):
                b.defer(
                    pipeline,
                    rel(
                        scope,
                        EdgeType.INVOKES,
                        "TRIGGERED_BY",
                        reverse=True,
                        description="event trigger",
                    ),
                )


@extractor(f"{_ADF}/integrationruntimes", f"{_SYN}/integrationruntimes")
def _x_integration_runtime(d: _Draft, b: "AzureAssetBuilder") -> None:
    p = d.props
    tp = _get(p, "typeProperties") or {}
    subnet = _path(tp, "computeProperties", "vNetProperties", "subnetId") or _path(
        tp, "ssisProperties", "vNetProperties", "subnetId"
    )
    d.md.update(
        {
            "runtime_type": _get(p, "type"),
            "managed_vnet": _path(p, "managedVirtualNetwork", "referenceName"),
            "self_hosted": _lower(_get(p, "type")) == "selfhosted",
            "location": _path(tp, "computeProperties", "location"),
        }
    )
    d.add(rel(subnet, EdgeType.CONTAINS, "SUBNET_CONTAINS_INSTANCE", reverse=True))


@extractor(_ADF)
def _x_factory_git(d: _Draft, b: "AzureAssetBuilder") -> None:
    from cloudg.inventory.azure_graph.integration import repository_ref

    repo = _get(d.props, "repoConfiguration") or {}
    kind = _lower(_get(repo, "type"))
    account, name = _get(repo, "accountName"), _get(repo, "repositoryName")
    url = None
    if account and name and "github" in kind:
        url = f"https://{_get(repo, 'hostName') or 'github.com'}/{account}/{name}".replace(
            "https://https://", "https://"
        )
    elif account and name:
        url = f"https://dev.azure.com/{account}/{_get(repo, 'projectName')}/_git/{name}"
    d.md["git_repository"] = url
    d.add(rel(repository_ref(b, url), EdgeType.REFERENCES, "READS_FROM", description="factory Git"))
    d.add(
        rel(
            _path(d.props, "purviewConfiguration", "purviewResourceId"),
            EdgeType.REFERENCES,
            "DEPENDS_ON",
        )
    )


@extractor(_SYN)
def _x_synapse_workspace(d: _Draft, b: "AzureAssetBuilder") -> None:
    p = d.props
    lake = _get(p, "defaultDataLakeStorage") or {}
    d.add(
        rel(
            host_of(_get(lake, "accountUrl")),
            EdgeType.REFERENCES,
            "READS_FROM",
            description="default data lake",
        )
    )
    d.add(
        rel(
            _get(lake, "resourceId"),
            EdgeType.REFERENCES,
            "READS_FROM",
            description="default data lake",
        )
    )
    for endpoint in (_get(p, "connectivityEndpoints") or {}).values():
        d.alias(host_of(endpoint))
    d.md["managed_vnet"] = _get(p, "managedVirtualNetwork")
    d.md["sql_admin"] = _get(p, "sqlAdministratorLogin")
    d.add(
        rel(
            _path(p, "virtualNetworkProfile", "computeSubnetId"),
            EdgeType.CONTAINS,
            "SUBNET_CONTAINS_INSTANCE",
            reverse=True,
        )
    )
    _keyvault_key_ref(d, _path(p, "encryption", "cmk", "key", "keyVaultUrl"))


@extractor(f"{_SYN}/sqlpools", f"{_SYN}/bigdatapools")
def _x_synapse_pool(d: _Draft, b: "AzureAssetBuilder") -> None:
    p = d.props
    d.md.update(
        {
            "status": _get(p, "status"),
            "node_size": _get(p, "nodeSize"),
            "spark_version": _get(p, "sparkVersion"),
        }
    )


# ── Data Explorer, HDInsight ──


@extractor("microsoft.kusto/clusters")
def _x_kusto(d: _Draft, b: "AzureAssetBuilder") -> None:
    p = d.props
    for key in ("uri", "dataIngestionUri"):
        d.alias(host_of(_get(p, key)))
    d.add(
        rel(
            _path(p, "virtualNetworkConfiguration", "subnetId"),
            EdgeType.CONTAINS,
            "SUBNET_CONTAINS_INSTANCE",
            reverse=True,
        )
    )
    _keyvault_key_ref(d, _path(p, "keyVaultProperties", "keyVaultUri"))
    tenants = [_get(t, "value") for t in _list(_get(p, "trustedExternalTenants"))]
    d.md.update(
        {
            "trusted_external_tenants": tenants,
            "any_tenant_trusted": "*" in tenants,
            "restrict_outbound": _get(p, "restrictOutboundNetworkAccess"),
            "allowed_fqdns": _list(_get(p, "allowedFqdnList")),
        }
    )
    _set_exposure(d)


@relation_row("microsoft.kusto/clusters/databases/dataconnections")
def _kusto_data_connection(row: dict[str, Any], b: "AzureAssetBuilder") -> None:
    p = row.get("properties") or {}
    db = parent_resource_id(row.get("id"))
    for key in (
        "eventHubResourceId",
        "iotHubResourceId",
        "storageAccountResourceId",
        "cosmosDbAccountResourceId",
        "eventGridResourceId",
    ):
        b.defer(
            db,
            rel(
                _get(p, key),
                EdgeType.REFERENCES,
                "READS_FROM",
                description=f"{row.get('kind')} data connection",
            ),
        )


@relation_row(
    "microsoft.kusto/clusters/principalassignments",
    "microsoft.kusto/clusters/databases/principalassignments",
)
def _kusto_principal(row: dict[str, Any], b: "AzureAssetBuilder") -> None:
    p = row.get("properties") or {}
    pid = _get(p, "principalId")
    if not pid:
        return
    b.note_principal(pid, _get(p, "principalType"))
    role = _get(p, "role")
    b.defer(
        parent_resource_id(row.get("id")),
        rel(
            principal_ref(pid),
            EdgeType.GRANTS_ACCESS,
            "POLICY_ALLOWS_ACTION",
            reverse=True,
            description=f"Data Explorer {role}",
            role=role,
            privileged="admin" in _lower(role) or None,
            tenant_id=_get(p, "tenantId"),
        ),
    )


@extractor("microsoft.hdinsight/clusters")
def _x_hdinsight(d: _Draft, b: "AzureAssetBuilder") -> None:
    p = d.props
    for role in _list(_path(p, "computeProfile", "roles")):
        subnet = _path(role, "virtualNetworkProfile", "subnet")
        d.add(rel(subnet, EdgeType.CONTAINS, "SUBNET_CONTAINS_INSTANCE", reverse=True))
    for acct in _list(_path(p, "storageProfile", "storageaccounts")):
        d.add(
            rel(
                _get(acct, "resourceId") or str(_get(acct, "name") or "").lower() or None,
                EdgeType.REFERENCES,
                "READS_FROM",
                description="cluster storage",
            )
        )
        d.add(rel(_get(acct, "msiResourceId"), EdgeType.ASSUMES_ROLE, "RUNS_ON"))
    _keyvault_key_ref(d, _path(p, "diskEncryptionProperties", "vaultUri"))
    endpoints = [_get(e, "location") for e in _list(_get(p, "connectivityEndpoints"))]
    for host in endpoints:
        d.alias(str(host).lower() if host else None)
    d.md.update(
        {
            "cluster_kind": _path(p, "clusterDefinition", "kind"),
            "cluster_version": _get(p, "clusterVersion"),
            "esp_domain": _path(p, "securityProfile", "domain"),
            "public_network": _path(p, "networkProperties", "publicNetworkAccess"),
        }
    )
    if _lower(_path(p, "networkProperties", "resourceProviderConnection")) != "outbound":
        d.exposed = any(str(h or "").endswith(".azurehdinsight.net") for h in endpoints)
    d.add(rel(_path(p, "securityProfile", "aaddsResourceId"), EdgeType.REFERENCES, "DEPENDS_ON"))


# ── SQL ──


@extractor("microsoft.sql/managedinstances")
def _x_sql_mi(d: _Draft, b: "AzureAssetBuilder") -> None:
    p = d.props
    fqdn = _get(p, "fullyQualifiedDomainName")
    d.alias(fqdn.lower() if isinstance(fqdn, str) else None)
    d.add(rel(_get(p, "subnetId"), EdgeType.CONTAINS, "SUBNET_CONTAINS_INSTANCE", reverse=True))
    public = bool(_get(p, "publicDataEndpointEnabled"))
    d.md.update(
        {
            "fqdn": fqdn,
            "public_data_endpoint": public,
            "proxy_override": _get(p, "proxyOverride"),
            "minimal_tls_version": _get(p, "minimalTlsVersion"),
        }
    )
    if public:
        d.exposed = True
    admins = _get(p, "administrators") or {}
    sid = _get(admins, "sid")
    if sid:
        b.note_principal(sid, _get(admins, "principalType"))
        d.add(
            rel(
                principal_ref(sid),
                EdgeType.GRANTS_ACCESS,
                "POLICY_ALLOWS_ACTION",
                reverse=True,
                description="Entra administrator",
                privileged=True,
            )
        )
    _keyvault_key_ref(d, _get(p, "keyId"))


@extractor("microsoft.sql/servers/elasticpools")
def _x_elastic_pool(d: _Draft, b: "AzureAssetBuilder") -> None:
    sku = d.row.get("sku") or {}
    d.md.update(
        {
            "role": "elastic pool",
            "edition": _get(sku, "tier"),
            "zone_redundant": _get(d.props, "zoneRedundant"),
            "max_size_bytes": _get(d.props, "maxSizeBytes"),
        }
    )


@extractor("microsoft.sql/servers/databases")
def _x_sql_geo_replica(d: _Draft, b: "AzureAssetBuilder") -> None:
    p = d.props
    source = _get(p, "sourceDatabaseId")
    secondary = _get(p, "secondaryType")
    d.md["secondary_type"] = secondary
    if source and (secondary or _lower(_get(p, "createMode")) in ("secondary", "onlinesecondary")):
        d.add(
            rel(
                source,
                EdgeType.REFERENCES,
                "REPLICATES_TO",
                reverse=True,
                description=f"{secondary or 'geo'} replica",
            )
        )


@relation_row("microsoft.sql/servers/failovergroups")
def _sql_failover_group(row: dict[str, Any], b: "AzureAssetBuilder") -> None:
    p = row.get("properties") or {}
    server = parent_resource_id(row.get("id"))
    for partner in _list(_get(p, "partnerServers")):
        b.defer(
            server,
            rel(
                _rid(partner),
                EdgeType.REFERENCES,
                "REPLICATES_TO",
                description=f"failover group {row.get('name')}",
                role=_get(partner, "replicationRole"),
            ),
        )
    for db in _list(_get(p, "databases")):
        for partner in _list(_get(p, "partnerServers")):
            b.defer(
                db,
                rel(
                    _rid(partner),
                    EdgeType.REFERENCES,
                    "REPLICATES_TO",
                    description="failover group database",
                ),
            )


@relation_row("microsoft.sql/locations/instancefailovergroups")
def _mi_failover_group(row: dict[str, Any], b: "AzureAssetBuilder") -> None:
    for pair in _list(_get(row.get("properties") or {}, "managedInstancePairs")):
        b.defer(
            _get(pair, "primaryManagedInstanceId"),
            rel(
                _get(pair, "partnerManagedInstanceId"),
                EdgeType.REFERENCES,
                "REPLICATES_TO",
                description="instance failover group",
            ),
        )


@relation_row("microsoft.sql/servers/auditingsettings")
def _sql_auditing(row: dict[str, Any], b: "AzureAssetBuilder") -> None:
    from cloudg.inventory.azure_graph.integration import _set_md_later

    p = row.get("properties") or {}
    server = parent_resource_id(row.get("id"))
    enabled = _lower(_get(p, "state")) == "enabled"
    _set_md_later(
        b,
        server,
        {
            "auditing_enabled": enabled,
            "audit_to_azure_monitor": _get(p, "isAzureMonitorTargetEnabled"),
        },
    )
    if enabled:
        b.defer(
            server,
            rel(
                host_of(_get(p, "storageEndpoint")),
                EdgeType.LOGS_TO,
                "LOGS_TO",
                description="SQL auditing",
            ),
        )


# ── Cosmos DB ──


@extractor("microsoft.documentdb/databaseaccounts")
def _x_cosmos_regions(d: _Draft, b: "AzureAssetBuilder") -> None:
    p = d.props
    locations = [
        x
        for x in _list(_get(p, "locations")) or _list(_get(p, "readLocations"))
        if isinstance(x, dict)
    ]
    d.md.update(
        {
            "multi_region_writes": _get(p, "enableMultipleWriteLocations"),
            "consistency": _path(p, "consistencyPolicy", "defaultConsistencyLevel"),
            "backup_policy": _path(p, "backupPolicy", "type"),
            "regions": [_get(x, "locationName") for x in locations],
        }
    )
    for loc in locations:
        if not _get(loc, "failoverPriority"):
            continue  # the write region is the account itself
        region = str(_get(loc, "locationName") or "").replace(" ", "").lower()
        if not region:
            continue
        rid = f"{d.id}/regions/{region}"
        b.add_row(
            {
                "id": rid,
                "name": f"{d.name} ({_get(loc, 'locationName')})",
                "type": "microsoft.documentdb/databaseaccounts/regions",
                "location": region,
                "subscriptionId": d.account_id,
                "properties": {
                    "failoverPriority": _get(loc, "failoverPriority"),
                    "isZoneRedundant": _get(loc, "isZoneRedundant"),
                },
            },
            synthetic=True,
        )
        d.add(
            rel(
                rid,
                EdgeType.REFERENCES,
                "REPLICATES_TO",
                description="Cosmos DB region replica",
                failover_priority=_get(loc, "failoverPriority"),
            )
        )


@relation_row(
    "microsoft.documentdb/databaseaccounts/sqlroleassignments",
    "microsoft.documentdb/databaseaccounts/mongodbroleassignments",
)
def _cosmos_role_assignment(row: dict[str, Any], b: "AzureAssetBuilder") -> None:
    p = row.get("properties") or {}
    pid = _get(p, "principalId")
    if not pid:
        return
    b.note_principal(pid, None)
    b.defer(
        parent_resource_id(row.get("id")),
        rel(
            principal_ref(pid),
            EdgeType.GRANTS_ACCESS,
            "POLICY_ALLOWS_ACTION",
            reverse=True,
            description="Cosmos DB data-plane role",
            role_definition_id=_get(p, "roleDefinitionId"),
            scope=_get(p, "scope"),
            data_plane=True,
        ),
    )


# ── Storage, NetApp ──


@relation_row("microsoft.storage/storageaccounts/objectreplicationpolicies")
def _object_replication(row: dict[str, Any], b: "AzureAssetBuilder") -> None:
    p = row.get("properties") or {}
    source = _get(p, "sourceAccount") or parent_resource_id(row.get("id"))
    dest = _get(p, "destinationAccount")
    owner = (
        source
        if isinstance(source, str) and source.startswith("/")
        else parent_resource_id(row.get("id"))
    )
    if isinstance(dest, str) and dest and owner and dest.lower() != str(owner).lower():
        b.defer(
            owner,
            rel(
                dest,
                EdgeType.REFERENCES,
                "REPLICATES_TO",
                description="object replication",
                containers=[_get(r, "sourceContainer") for r in _list(_get(p, "rules"))],
            ),
        )


@extractor("microsoft.storage/storageaccounts/localusers")
def _x_storage_local_user(d: _Draft, b: "AzureAssetBuilder") -> None:
    p = d.props
    account = parent_resource_id(d.id)
    scopes = [
        {
            "service": _get(s, "service"),
            "resource": _get(s, "resourceName"),
            "permissions": _get(s, "permissions"),
        }
        for s in _list(_get(p, "permissionScopes"))
    ]
    d.md.update(
        {
            "sftp_user": True,
            "has_ssh_key": _get(p, "hasSshKey"),
            "has_ssh_password": _get(p, "hasSshPassword"),
            "has_shared_key": _get(p, "hasSharedKey"),
            "home_directory": _get(p, "homeDirectory"),
            "permission_scopes": scopes,
        }
    )
    d.add(
        rel(
            account,
            EdgeType.GRANTS_ACCESS,
            "POLICY_ALLOWS_ACTION",
            description="SFTP local user",
            permissions=[s["permissions"] for s in scopes],
        )
    )
    d.props = {k: v for k, v in p.items() if _lower(k) not in ("sshauthorizedkeys", "sshpassword")}


@relation_row("microsoft.storage/storageaccounts/blobservices")
def _blob_service(row: dict[str, Any], b: "AzureAssetBuilder") -> None:
    from cloudg.inventory.azure_graph.integration import _set_md_later

    p = row.get("properties") or {}
    _set_md_later(
        b,
        parent_resource_id(row.get("id")),
        {
            "blob_soft_delete": _path(p, "deleteRetentionPolicy", "enabled"),
            "container_soft_delete": _path(p, "containerDeleteRetentionPolicy", "enabled"),
            "versioning": _get(p, "isVersioningEnabled"),
            "change_feed": _path(p, "changeFeed", "enabled"),
            "point_in_time_restore": _path(p, "restorePolicy", "enabled"),
        },
    )


@extractor("microsoft.storage/storageaccounts")
def _x_storage_replication(d: _Draft, b: "AzureAssetBuilder") -> None:
    p = d.props
    sku = d.row.get("sku")
    name = str(_get(sku, "name") if isinstance(sku, dict) else sku or "")
    d.md.update(
        {
            "sftp_enabled": _get(p, "isSftpEnabled"),
            "local_users_enabled": _get(p, "isLocalUserEnabled"),
            "geo_replicated": "grs" in name.lower() or "gzrs" in name.lower(),
            "secondary_location": _get(p, "secondaryLocation"),
            "immutable_storage": _path(p, "immutableStorageWithVersioning", "enabled"),
        }
    )


@extractor("microsoft.netapp/netappaccounts/capacitypools/volumes")
def _x_netapp_volume(d: _Draft, b: "AzureAssetBuilder") -> None:
    p = d.props
    d.add(rel(_get(p, "subnetId"), EdgeType.CONTAINS, "SUBNET_CONTAINS_INSTANCE", reverse=True))
    for target in _list(_get(p, "mountTargets")):
        d.alias(_get(target, "ipAddress"))
    dp = _get(p, "dataProtection") or {}
    replication = _get(dp, "replication") or {}
    remote = _get(replication, "remoteVolumeResourceId")
    is_destination = _lower(_get(replication, "endpointType")) == "dst"
    d.add(
        rel(
            remote,
            EdgeType.REFERENCES,
            "REPLICATES_TO",
            reverse=is_destination,
            description="cross-region replication",
            schedule=_get(replication, "replicationSchedule"),
        )
    )
    backup = _get(dp, "backup") or {}
    d.add(
        rel(
            _get(backup, "backupVaultId"),
            EdgeType.REFERENCES,
            "BACKUP_TO",
            description="NetApp backup",
        )
    )
    d.add(
        rel(
            _get(backup, "backupPolicyId"),
            EdgeType.REFERENCES,
            "DEPENDS_ON",
            description="backup policy",
        )
    )
    snap_policy = _path(dp, "snapshot", "snapshotPolicyId")
    if snap_policy:
        b.defer(
            snap_policy, rel(d.id, EdgeType.MANAGES, "SCHEDULED_BY", description="snapshot policy")
        )
    rules = _list(_path(p, "exportPolicy", "rules"))
    d.md.update(
        {
            "protocols": _list(_get(p, "protocolTypes")),
            "export_clients": [_get(r, "allowedClients") for r in rules],
            "open_export": any(
                str(_get(r, "allowedClients") or "").strip() in ("0.0.0.0/0", "*") for r in rules
            ),
        }
    )


# ── AI and ML ──


@extractor("microsoft.cognitiveservices/accounts")
def _x_cognitive_account(d: _Draft, b: "AzureAssetBuilder") -> None:
    p = d.props
    for endpoint in (_get(p, "endpoints") or {}).values():
        d.alias(host_of(endpoint))
    sub = _get(p, "customSubDomainName")
    d.md.update(
        {
            "ai_kind": d.row.get("kind"),
            "custom_subdomain": sub,
            "local_auth_disabled": _get(p, "disableLocalAuth"),
            "restrict_outbound": _get(p, "restrictOutboundNetworkAccess"),
            "allowed_fqdns": _list(_get(p, "allowedFqdnList")),
        }
    )
    for store in _list(_get(p, "userOwnedStorage")):
        d.add(
            rel(
                _get(store, "resourceId"),
                EdgeType.REFERENCES,
                "DEPENDS_ON",
                description="user-owned storage",
            )
        )


@extractor("microsoft.cognitiveservices/accounts/deployments")
def _x_ai_deployment(d: _Draft, b: "AzureAssetBuilder") -> None:
    p = d.props
    model = _get(p, "model") or {}
    account = parent_resource_id(d.id)
    rai = _get(p, "raiPolicyName")
    sku = d.row.get("sku") or {}
    d.md.update(
        {
            "model_name": _get(model, "name"),
            "model_version": _get(model, "version"),
            "model_format": _get(model, "format"),
            "content_filter": rai,
            "capacity": _get(sku, "capacity") if isinstance(sku, dict) else None,
            "deployment_type": _get(sku, "name") if isinstance(sku, dict) else None,
        }
    )
    if rai and account:
        d.add(
            rel(
                f"{account}/raiPolicies/{rai}",
                EdgeType.PROTECTS,
                reverse=True,
                description="content filter",
            )
        )


@extractor("microsoft.cognitiveservices/accounts/raipolicies")
def _x_rai_policy(d: _Draft, b: "AzureAssetBuilder") -> None:
    p = d.props
    filters = [
        {
            "name": _get(f, "name"),
            "source": _get(f, "source"),
            "blocking": _get(f, "blocking"),
            "enabled": _get(f, "enabled"),
            "threshold": _get(f, "severityThreshold") or _get(f, "allowedContentLevel"),
        }
        for f in _list(_get(p, "contentFilters"))
    ]
    d.md.update(
        {
            "mode": _get(p, "mode"),
            "base_policy": _get(p, "basePolicyName"),
            "content_filters": filters,
            "blocklists": [_get(x, "blocklistName") for x in _list(_get(p, "customBlocklists"))],
        }
    )


@extractor(
    "microsoft.cognitiveservices/accounts/projects", "microsoft.machinelearningservices/workspaces"
)
def _x_ai_project(d: _Draft, b: "AzureAssetBuilder") -> None:
    p = d.props
    d.md["workspace_kind"] = d.row.get("kind")
    d.md["isolation_mode"] = _path(p, "managedNetwork", "isolationMode")
    d.add(rel(_get(p, "hubResourceId"), EdgeType.CONTAINS, reverse=True, description="AI hub"))


@extractor(
    "microsoft.machinelearningservices/workspaces/onlineendpoints",
    "microsoft.machinelearningservices/workspaces/serverlessendpoints",
)
def _x_ml_endpoint(d: _Draft, b: "AzureAssetBuilder") -> None:
    p = d.props
    for key in ("scoringUri", "swaggerUri", "inferenceEndpoint"):
        value = _get(p, key)
        d.alias(host_of(_get(value, "uri") if isinstance(value, dict) else value))
    d.md.update({"auth_mode": _get(p, "authMode"), "traffic": _get(p, "traffic")})
    if _lower(_get(p, "publicNetworkAccess") or "enabled") == "enabled":
        d.exposed = True


@extractor("microsoft.machinelearningservices/workspaces/onlineendpoints/deployments")
def _x_ml_deployment(d: _Draft, b: "AzureAssetBuilder") -> None:
    p = d.props
    d.md.update(
        {
            "model": _get(p, "model"),
            "instance_type": _get(p, "instanceType"),
            "egress_public": _get(p, "egressPublicNetworkAccess"),
        }
    )


@extractor("microsoft.machinelearningservices/workspaces/computes")
def _x_ml_compute(d: _Draft, b: "AzureAssetBuilder") -> None:
    p = d.props
    inner = _get(p, "properties") or {}
    d.md.update(
        {
            "compute_type": _get(p, "computeType"),
            "vm_size": _get(inner, "vmSize"),
            "node_public_ip": _get(inner, "enableNodePublicIp"),
        }
    )
    d.add(
        rel(
            _path(inner, "subnet", "id"),
            EdgeType.CONTAINS,
            "SUBNET_CONTAINS_INSTANCE",
            reverse=True,
        )
    )
    d.add(
        rel(_get(p, "resourceId"), EdgeType.REFERENCES, "RUNS_ON", description="attached compute")
    )
    d.exposed = bool(_get(inner, "enableNodePublicIp"))


@extractor("microsoft.machinelearningservices/workspaces/datastores")
def _x_ml_datastore(d: _Draft, b: "AzureAssetBuilder") -> None:
    p = d.props
    kind = _lower(_get(p, "datastoreType"))
    account = _lower(_get(p, "accountName"))
    suffix = {"azuredatalakegen2": "dfs", "azurefile": "file"}.get(kind, "blob")
    target = f"{account}.{suffix}.{_get(p, 'endpoint') or 'core.windows.net'}" if account else None
    if kind == "azuredatalakegen1":
        target = f"{_lower(_get(p, 'storeName'))}.azuredatalakestore.net"
    d.md.update(
        {
            "datastore_type": _get(p, "datastoreType"),
            "container": _get(p, "containerName") or _get(p, "filesystem"),
            "credential_type": _path(p, "credentials", "credentialsType"),
        }
    )
    d.add(rel(target, EdgeType.REFERENCES, "READS_FROM", description="datastore"))
    ws = parent_resource_id(d.id)
    if ws and target:
        b.defer(
            ws, rel(target, EdgeType.REFERENCES, "READS_FROM", description=f"datastore {d.name}")
        )
    d.props = {k: v for k, v in p.items() if _lower(k) != "credentials"}


@extractor(
    "microsoft.machinelearningservices/workspaces/connections",
    "microsoft.cognitiveservices/accounts/connections",
    "microsoft.cognitiveservices/accounts/projects/connections",
)
def _x_ai_connection(d: _Draft, b: "AzureAssetBuilder") -> None:
    p = d.props
    target = _get(p, "target")
    d.md.update(
        {"category": _get(p, "category"), "auth_type": _get(p, "authType"), "target": target}
    )
    d.add(
        rel(
            host_of(target) if isinstance(target, str) and "://" in target else target,
            EdgeType.REFERENCES,
            "DEPENDS_ON",
            description=f"{_get(p, 'category')} connection",
        )
    )
    d.add(rel(_path(p, "metadata", "ResourceId"), EdgeType.REFERENCES, "DEPENDS_ON"))
    d.props = {k: v for k, v in p.items() if _lower(k) not in ("credentials",)}


@relation_row("microsoft.search/searchservices/sharedprivatelinkresources")
def _search_shared_link(row: dict[str, Any], b: "AzureAssetBuilder") -> None:
    p = row.get("properties") or {}
    b.defer(
        parent_resource_id(row.get("id")),
        rel(
            _get(p, "privateLinkResourceId"),
            EdgeType.REFERENCES,
            "DEPENDS_ON",
            description="shared private link",
            status=_get(p, "status"),
        ),
    )


@extractor("microsoft.search/searchservices")
def _x_search_service(d: _Draft, b: "AzureAssetBuilder") -> None:
    p = d.props
    d.alias(f"{d.name.lower()}.search.windows.net")
    d.md.update(
        {
            "local_auth_disabled": _get(p, "disableLocalAuth"),
            "auth_options": list((_get(p, "authOptions") or {}).keys()),
            "semantic_search": _get(p, "semanticSearch"),
        }
    )


@extractor("microsoft.search/searchservices/datasources")
def _x_search_datasource(d: _Draft, b: "AzureAssetBuilder") -> None:
    p = d.props
    kind = _get(p, "type")
    refs = endpoint_refs(_get(p, "credentials") or {}, str(kind or ""))
    d.md.update(
        {"datasource_type": kind, "container": _path(p, "container", "name"), "endpoints": refs}
    )
    for ref in refs:
        d.add(rel(ref, EdgeType.REFERENCES, "READS_FROM", description=f"{kind} data source"))
    d.props = {k: v for k, v in p.items() if _lower(k) != "credentials"}


@extractor("microsoft.search/searchservices/indexers")
def _x_search_indexer(d: _Draft, b: "AzureAssetBuilder") -> None:
    p = d.props
    svc = parent_resource_id(d.id)
    d.md["schedule"] = _path(p, "schedule", "interval")
    d.add(
        rel(_ref(svc, "datasources", _get(p, "dataSourceName")), EdgeType.REFERENCES, "READS_FROM")
    )
    d.add(rel(_ref(svc, "indexes", _get(p, "targetIndexName")), EdgeType.REFERENCES, "WRITES_TO"))
    d.add(rel(_ref(svc, "skillsets", _get(p, "skillsetName")), EdgeType.REFERENCES, "DEPENDS_ON"))


@extractor("microsoft.search/searchservices/indexes")
def _x_search_index(d: _Draft, b: "AzureAssetBuilder") -> None:
    p = d.props
    vectorizers = _list(_path(p, "vectorSearch", "vectorizers"))
    d.md.update(
        {
            "field_count": len(_list(_get(p, "fields"))),
            "vector_search": bool(_get(p, "vectorSearch")),
        }
    )
    for v in vectorizers:
        uri = _path(v, "azureOpenAIParameters", "resourceUri") or _path(
            v, "customWebApiParameters", "uri"
        )
        d.add(rel(host_of(uri), EdgeType.INVOKES, "INVOKES", description="vectorizer"))
    d.props = {k: v for k, v in p.items() if _lower(k) not in ("fields",)}


@extractor("microsoft.search/searchservices/skillsets")
def _x_search_skillset(d: _Draft, b: "AzureAssetBuilder") -> None:
    skills = _list(_get(d.props, "skills"))
    d.md["skills"] = [_get(s, "@odata.type") for s in skills]
    for s in skills:
        uri = _get(s, "uri") or _get(s, "resourceUri")
        d.add(
            rel(host_of(uri), EdgeType.INVOKES, "INVOKES", description=str(_get(s, "@odata.type")))
        )
    d.props = {k: v for k, v in d.props.items() if _lower(k) not in ("cognitiveservices",)}


@extractor("microsoft.purview/accounts")
def _x_purview(d: _Draft, b: "AzureAssetBuilder") -> None:
    p = d.props
    for endpoint in (_get(p, "endpoints") or {}).values():
        d.alias(host_of(endpoint))
    for key, target in (_get(p, "managedResources") or {}).items():
        d.add(rel(target, EdgeType.MANAGES, "OWNED_BY", description=f"managed {key}"))
    _set_exposure(d)


__all__ = ["endpoint_refs"]
