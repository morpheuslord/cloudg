"""Extractors for data stores, Key Vault, identities, monitoring and eventing."""

from __future__ import annotations

import ipaddress

from typing import TYPE_CHECKING, Any

from cloudg.inventory.aws_services._base import rel
from cloudg.inventory.azure_graph.helpers import (
    LOG_ANALYTICS_PREFIX,
    _get,
    _list,
    _lower,
    _path,
    _props,
    _rid,
    host_of,
    parent_resource_id,
    principal_ref,
    resource_group_name,
)
from cloudg.inventory.azure_graph.registry import (
    _Draft,
    _keyvault_key_ref,
    _network_rule_grant,
    _network_rule_grants,
    _set_exposure,
    extractor,
)
from cloudg.schema.models import EdgeType


def _is_unspecified(address: Any) -> bool:
    """True for 0.0.0.0, which Azure SQL uses for "allow Azure services"."""
    try:
        return ipaddress.ip_address(str(address)).is_unspecified
    except ValueError:
        return False


if TYPE_CHECKING:
    from cloudg.inventory.azure_graph.builder import AzureAssetBuilder


@extractor("microsoft.keyvault/vaults")
def _x_key_vault(d: _Draft, b: "AzureAssetBuilder") -> None:
    p = d.props
    uri = _get(p, "vaultUri")
    host = host_of(uri)
    d.alias(host, uri, uri.rstrip("/") if isinstance(uri, str) else None)
    d.md.update(
        {
            "vault_uri": uri,
            "rbac_authorization": _get(p, "enableRbacAuthorization"),
            "soft_delete": _get(p, "enableSoftDelete"),
            "purge_protection": _get(p, "enablePurgeProtection"),
        }
    )
    policies = []
    for ap in _list(_get(p, "accessPolicies")):
        oid = _get(ap, "objectId")
        perms = _get(ap, "permissions") or {}
        policies.append({"object_id": oid, "permissions": perms})
        principal = principal_ref(oid)
        if principal:
            b.note_principal(oid, None)
            d.add(
                rel(
                    principal,
                    EdgeType.GRANTS_ACCESS,
                    "POLICY_ALLOWS_ACTION",
                    reverse=True,
                    description="Key Vault access policy",
                    keys=_get(perms, "keys"),
                    secrets=_get(perms, "secrets"),
                    certificates=_get(perms, "certificates"),
                )
            )
    d.md["access_policies"] = policies
    _network_rule_grants(d, _get(p, "networkAcls"))
    _set_exposure(d, default_public=True)


@extractor("microsoft.storage/storageaccounts")
def _x_storage(d: _Draft, b: "AzureAssetBuilder") -> None:
    p = d.props
    sku = d.row.get("sku")
    d.md.update(
        {
            "kind": d.row.get("kind"),
            "sku": _get(sku, "name") if isinstance(sku, dict) else sku,
            "https_only": _get(p, "supportsHttpsTrafficOnly"),
            "access_tier": _get(p, "accessTier"),
            "provisioning_state": _get(p, "provisioningState"),
            "public_blob_access": _get(p, "allowBlobPublicAccess"),
            "shared_key_access": _get(p, "allowSharedKeyAccess"),
            "min_tls_version": _get(p, "minimumTlsVersion"),
            "hns_enabled": _get(p, "isHnsEnabled"),
        }
    )
    for endpoint in (_get(p, "primaryEndpoints") or {}).values():
        d.alias(host_of(endpoint))
    _network_rule_grants(d, _get(p, "networkAcls"))
    enc = _get(p, "encryption") or {}
    if _lower(_get(enc, "keySource")) == "microsoft.keyvault":
        _keyvault_key_ref(d, _path(enc, "keyvaultproperties", "keyvaulturi"))
    uai = _path(enc, "identity", "userAssignedIdentity")
    d.add(rel(uai, EdgeType.ASSUMES_ROLE, "RUNS_ON", description="encryption identity"))
    _set_exposure(d, default_public=True)
    if _get(p, "allowBlobPublicAccess"):
        d.md["anonymous_access_possible"] = True


def _sql_firewall_rules(d: _Draft, fw: list[Any]) -> list[dict[str, Any]]:
    """Internet-facing SQL firewall rules (0.0.0.0-0.0.0.0 means Azure services)."""
    internet_rules = []
    for rule in fw:
        rp = _props(rule)
        start, end = _get(rp, "startIpAddress"), _get(rp, "endIpAddress")
        if _is_unspecified(start) and _is_unspecified(end):
            d.md["allow_azure_services"] = True
        elif start:
            internet_rules.append({"name": _get(rule, "name"), "start": start, "end": end})
    if fw:
        d.md["firewall_rules"] = internet_rules
    return internet_rules


@extractor("microsoft.sql/servers")
def _x_sql_server(d: _Draft, b: "AzureAssetBuilder") -> None:
    p = d.props
    fqdn = _get(p, "fullyQualifiedDomainName")
    d.alias(fqdn.lower() if isinstance(fqdn, str) else None)
    admins = _get(p, "administrators") or {}
    d.md.update(
        {
            "role": "server",
            "server_name": d.name,
            "resource_group": resource_group_name(d.id),
            "fqdn": fqdn,
            "version": _get(p, "version"),
            "minimal_tls_version": _get(p, "minimalTlsVersion"),
            "entra_only_auth": _get(admins, "azureADOnlyAuthentication"),
        }
    )
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
                role="SQL Entra admin",
                privileged=True,
            )
        )
    _keyvault_key_ref(d, _get(p, "keyId"))
    # firewall / vnet rules (present on the SDK fallback path)
    fw = _list(_get(p, "firewallRules"))
    internet_rules = _sql_firewall_rules(d, fw)
    for vr in _list(_get(p, "virtualNetworkRules")):
        subnet = _get(_props(vr), "virtualNetworkSubnetId")
        d.add(_network_rule_grant(subnet, "virtual network rule"))
    pna = _get(p, "publicNetworkAccess")
    d.md["public_network_access"] = pna
    if internet_rules:
        d.exposed = True
    elif not fw and _lower(pna) == "enabled":
        # no firewall data (Resource Graph path): a public endpoint is enabled
        d.exposed = True


@extractor("microsoft.sql/servers/databases")
def _x_sql_db(d: _Draft, b: "AzureAssetBuilder") -> None:
    p = d.props
    sku = d.row.get("sku") or {}
    server = parent_resource_id(d.id)
    d.md.update(
        {
            "role": "database",
            "server_name": server.rsplit("/", 1)[-1] if server else None,
            "server_id": server,
            "resource_group": resource_group_name(d.id),
            "status": _get(p, "status"),
            "edition": _get(sku, "tier") if isinstance(sku, dict) else None,
        }
    )
    d.add(
        rel(_get(p, "elasticPoolId"), EdgeType.CONTAINS, reverse=True, description="elastic pool")
    )


@extractor(
    "microsoft.dbforpostgresql/flexibleservers",
    "microsoft.dbformysql/flexibleservers",
    "microsoft.dbforpostgresql/servers",
    "microsoft.dbformysql/servers",
    "microsoft.dbformariadb/servers",
)
def _x_oss_db(d: _Draft, b: "AzureAssetBuilder") -> None:
    p = d.props
    fqdn = _get(p, "fullyQualifiedDomainName")
    d.alias(fqdn.lower() if isinstance(fqdn, str) else None)
    net = _get(p, "network") or {}
    d.add(
        rel(
            _get(net, "delegatedSubnetResourceId"),
            EdgeType.CONTAINS,
            "SUBNET_CONTAINS_INSTANCE",
            reverse=True,
        )
    )
    d.add(rel(_get(net, "privateDnsZoneArmResourceId"), EdgeType.REFERENCES, "DNS_RESOLVED"))
    pna = _get(net, "publicNetworkAccess") or _get(p, "publicNetworkAccess")
    d.md["public_network_access"] = pna
    d.md["fqdn"] = fqdn
    if _lower(pna) == "enabled":
        d.exposed = True


@extractor("microsoft.documentdb/databaseaccounts")
def _x_cosmos(d: _Draft, b: "AzureAssetBuilder") -> None:
    p = d.props
    d.alias(host_of(_get(p, "documentEndpoint")))
    for vr in _list(_get(p, "virtualNetworkRules")):
        d.add(_network_rule_grant(_rid(vr)))
    _keyvault_key_ref(d, _get(p, "keyVaultKeyUri"))
    ip_rules = [_get(r, "ipAddressOrRange") for r in _list(_get(p, "ipRules"))]
    d.md["ip_rules"] = [r for r in ip_rules if r]
    d.md["vnet_filter"] = _get(p, "isVirtualNetworkFilterEnabled")
    d.md["local_auth_disabled"] = _get(p, "disableLocalAuth")
    pna = _get(p, "publicNetworkAccess")
    d.md["public_network_access"] = pna
    if (
        _lower(pna or "enabled") == "enabled"
        and not _get(p, "isVirtualNetworkFilterEnabled")
        and not d.md["ip_rules"]
    ):
        d.exposed = True


@extractor(
    "microsoft.eventhub/namespaces",
    "microsoft.servicebus/namespaces",
    "microsoft.cognitiveservices/accounts",
    "microsoft.cache/redis",
    "microsoft.search/searchservices",
    "microsoft.appconfiguration/configurationstores",
    "microsoft.eventgrid/topics",
    "microsoft.eventgrid/domains",
    "microsoft.signalrservice/signalr",
    "microsoft.machinelearningservices/workspaces",
    "microsoft.synapse/workspaces",
    "microsoft.datafactory/factories",
)
def _x_paas_endpoint(d: _Draft, b: "AzureAssetBuilder") -> None:
    p = d.props
    for key in ("serviceBusEndpoint", "endpoint", "hostName", "discoveryUrl"):
        d.alias(host_of(_get(p, key)))
    _keyvault_key_ref(
        d,
        _path(p, "encryption", "keyVaultProperties", "keyVaultUri")
        or _path(p, "encryption", "keyVaultProperties", "keyIdentifier"),
    )
    _network_rule_grants(d, _get(p, "networkAcls") or _get(p, "networkRuleSet"))
    d.add(rel(_get(p, "subnetId"), EdgeType.CONTAINS, "SUBNET_CONTAINS_INSTANCE", reverse=True))
    for key in ("keyVault", "storageAccount", "applicationInsights", "containerRegistry"):
        target = _get(p, key)
        if isinstance(target, str) and target.lower().startswith("/subscriptions/"):
            d.add(rel(target, EdgeType.REFERENCES, "DEPENDS_ON", description=key))
    managed_rg = _get(p, "managedResourceGroupName")
    if managed_rg:
        d.add(
            rel(
                f"/subscriptions/{d.account_id}/resourceGroups/{managed_rg}",
                EdgeType.MANAGES,
                "OWNED_BY",
            )
        )
    _set_exposure(d)


@extractor("microsoft.databricks/workspaces")
def _x_databricks(d: _Draft, b: "AzureAssetBuilder") -> None:
    p = d.props
    d.add(
        rel(
            _get(p, "managedResourceGroupId"),
            EdgeType.MANAGES,
            "OWNED_BY",
            description="managed resource group",
        )
    )
    params = _get(p, "parameters") or {}
    vnet = _get(_get(params, "customVirtualNetworkId") or {}, "value")
    d.add(rel(vnet, EdgeType.ATTACHED_TO, description="VNet injection"))
    d.alias(host_of(_get(p, "workspaceUrl")))
    _set_exposure(d)


@extractor("microsoft.operationalinsights/workspaces")
def _x_log_analytics(d: _Draft, b: "AzureAssetBuilder") -> None:
    customer = _get(d.props, "customerId")
    if isinstance(customer, str):
        d.alias(f"{LOG_ANALYTICS_PREFIX}{customer.lower()}")
        d.md["customer_id"] = customer
    d.md["retention_days"] = _get(d.props, "retentionInDays")


@extractor("microsoft.managedidentity/userassignedidentities")
def _x_uami(d: _Draft, b: "AzureAssetBuilder") -> None:
    pid = _get(d.props, "principalId")
    d.md["principal_id"] = pid
    d.md["client_id"] = _get(d.props, "clientId")
    if pid:
        d.alias(principal_ref(pid))
        b.register_principal(pid, d)


@extractor("microsoft.eventgrid/systemtopics")
def _x_system_topic(d: _Draft, b: "AzureAssetBuilder") -> None:
    source = _get(d.props, "source")
    d.md["topic_type"] = _get(d.props, "topicType")
    d.add(rel(source, EdgeType.INVOKES, "TRIGGERED_BY", reverse=True, description="event source"))


@extractor(
    "microsoft.eventgrid/systemtopics/eventsubscriptions",
    "microsoft.eventgrid/topics/eventsubscriptions",
)
def _x_event_subscription(d: _Draft, b: "AzureAssetBuilder") -> None:
    dest = _get(d.props, "destination") or {}
    target = _path(dest, "properties", "resourceId") or host_of(
        _path(dest, "properties", "endpointUrl")
    )
    d.md["endpoint_type"] = _get(dest, "endpointType")
    d.add(rel(target, EdgeType.INVOKES, "INVOKES", description="event delivery"))
    parent = parent_resource_id(d.id)
    if parent and target:
        b.defer(
            parent,
            rel(target, EdgeType.INVOKES, "INVOKES", description=f"event subscription {d.name}"),
        )


@extractor("microsoft.insights/components")
def _x_app_insights(d: _Draft, b: "AzureAssetBuilder") -> None:
    d.md["app_id"] = _get(d.props, "AppId")


@extractor("microsoft.recoveryservices/vaults", "microsoft.dataprotection/backupvaults")
def _x_backup_vault(d: _Draft, b: "AzureAssetBuilder") -> None:
    _set_exposure(d)
