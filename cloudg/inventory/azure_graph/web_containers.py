"""Extractors for container registries, App Service, Container Apps, ACI and APIM."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Iterable

from cloudg.inventory.aws_services._base import rel
from cloudg.inventory.azure_graph.helpers import (
    LOG_ANALYTICS_PREFIX,
    _docker_image,
    _get,
    _list,
    _lower,
    _path,
    _props,
    _rid,
    _rids,
    host_of,
    registry_host,
)
from cloudg.inventory.azure_graph.registry import (
    _Draft,
    _keyvault_key_ref,
    _set_exposure,
    extractor,
)
from cloudg.schema.models import EdgeType

if TYPE_CHECKING:
    from cloudg.inventory.azure_graph.builder import AzureAssetBuilder


@extractor("microsoft.containerregistry/registries")
def _x_acr(d: _Draft, b: "AzureAssetBuilder") -> None:
    login = _get(d.props, "loginServer")
    if isinstance(login, str):
        d.alias(login.lower())
        d.md["login_server"] = login.lower()
    d.md["admin_user_enabled"] = _get(d.props, "adminUserEnabled")
    _set_exposure(d, default_public=True)
    enc = _path(d.props, "encryption", "keyVaultProperties", "keyIdentifier")
    _keyvault_key_ref(d, enc)


def _image_relations(d: _Draft, images: Iterable[Any]) -> None:
    seen: list[str] = []
    for image in images:
        host = registry_host(image)
        if host and host not in seen:
            seen.append(host)
            d.add(
                rel(host, EdgeType.USES_IMAGE, "RUNS_ON", description=f"runs {image}", image=image)
            )
    if seen or images:
        d.md["images"] = [i for i in images if i]


def _site_images(d: _Draft, p: dict[str, Any]) -> None:
    """Container images of a web app (``DOCKER|`` linux/windows FX versions)."""
    fx: list[Any] = []
    site_config = _get(p, "siteConfig") or {}
    fx += [_get(site_config, "linuxFxVersion"), _get(site_config, "windowsFxVersion")]
    for item in _list(_path(p, "siteProperties", "properties")):
        if _lower(_get(item, "name")) in ("linuxfxversion", "windowsfxversion"):
            fx.append(_get(item, "value"))
    images = [i for i in (_docker_image(v) for v in fx) if i]
    _image_relations(d, list(dict.fromkeys(images)))


def _site_hosts(d: _Draft, p: dict[str, Any]) -> None:
    """Host name aliases and public exposure of a web app."""
    hosts = (
        [_get(p, "defaultHostName")]
        + _list(_get(p, "enabledHostNames"))
        + _list(_get(p, "hostNames"))
    )
    for host in hosts:
        d.alias(host.lower() if isinstance(host, str) else None)
    d.md["default_host_name"] = _get(p, "defaultHostName")
    d.md["https_only"] = _get(p, "httpsOnly")
    d.md["state"] = _get(p, "state")
    pna = _get(p, "publicNetworkAccess")
    d.md["public_network_access"] = pna
    if _lower(pna) != "disabled":
        d.exposed = True


@extractor("microsoft.web/sites", "microsoft.web/sites/slots")
def _x_site(d: _Draft, b: "AzureAssetBuilder") -> None:
    p = d.props
    kind = _lower(d.row.get("kind"))
    d.md["role"] = (
        "function" if "functionapp" in kind else ("workflow" if "workflowapp" in kind else "web")
    )
    d.add(
        rel(
            _get(p, "serverFarmId"),
            EdgeType.CONTAINS,
            "CLUSTER_CONTAINS_SERVICE",
            reverse=True,
            description="App Service plan",
        )
    )
    subnet = _get(p, "virtualNetworkSubnetId")
    d.md["vnet_integration_subnet"] = subnet
    d.add(rel(subnet, EdgeType.ATTACHED_TO, description="VNet integration"))
    d.add(rel(_rid(_get(p, "hostingEnvironmentProfile")), EdgeType.CONTAINS, reverse=True))
    _site_images(d, p)
    kv_identity = _get(p, "keyVaultReferenceIdentity")
    if isinstance(kv_identity, str) and kv_identity.lower().startswith("/subscriptions/"):
        d.add(
            rel(
                kv_identity,
                EdgeType.ASSUMES_ROLE,
                "RUNS_ON",
                description="Key Vault reference identity",
            )
        )
    _site_hosts(d, p)


@extractor("microsoft.web/serverfarms")
def _x_plan(d: _Draft, b: "AzureAssetBuilder") -> None:
    sku = d.row.get("sku") or {}
    d.md.update(
        {
            "role": "plan",
            "tier": _get(sku, "tier") if isinstance(sku, dict) else None,
            "workers": _get(d.props, "numberOfWorkers")
            or (_get(sku, "capacity") if isinstance(sku, dict) else None),
            "site_count": _get(d.props, "numberOfSites"),
        }
    )
    d.add(rel(_rid(_get(d.props, "hostingEnvironmentProfile")), EdgeType.CONTAINS, reverse=True))


@extractor("microsoft.web/hostingenvironments")
def _x_ase(d: _Draft, b: "AzureAssetBuilder") -> None:
    d.md["role"] = "environment"
    subnet = _rid(_path(d.props, "virtualNetwork")) or _path(d.props, "virtualNetwork", "id")
    d.add(rel(subnet, EdgeType.CONTAINS, "SUBNET_CONTAINS_INSTANCE", reverse=True))


def _configured_registry(d: _Draft, server: Any) -> None:
    """Registry login server a workload is configured to pull from."""
    if isinstance(server, str):
        d.add(
            rel(server.lower(), EdgeType.USES_IMAGE, "RUNS_ON", description="configured registry")
        )


@extractor("microsoft.app/containerapps", "microsoft.app/jobs")
def _x_container_app(d: _Draft, b: "AzureAssetBuilder") -> None:
    p = d.props
    env = _get(p, "managedEnvironmentId") or _get(p, "environmentId")
    d.add(
        rel(
            env,
            EdgeType.CONTAINS,
            "CLUSTER_CONTAINS_SERVICE",
            reverse=True,
            description="Container Apps environment",
        )
    )
    template = _get(p, "template") or {}
    images = [
        _get(c, "image")
        for c in _list(_get(template, "containers")) + _list(_get(template, "initContainers"))
    ]
    _image_relations(d, [i for i in images if i])
    config = _get(p, "configuration") or {}
    for reg in _list(_get(config, "registries")):
        _configured_registry(d, _get(reg, "server"))
        ident = _get(reg, "identity")
        if isinstance(ident, str) and ident.lower().startswith("/subscriptions/"):
            d.add(
                rel(ident, EdgeType.ASSUMES_ROLE, "RUNS_ON", description="registry pull identity")
            )
    ingress = _get(config, "ingress") or {}
    fqdn = _get(ingress, "fqdn") or _get(p, "latestRevisionFqdn")
    d.alias(fqdn.lower() if isinstance(fqdn, str) else None)
    d.md["ingress_external"] = _get(ingress, "external")
    if _get(ingress, "external"):
        d.exposed = True


@extractor("microsoft.app/managedenvironments")
def _x_container_env(d: _Draft, b: "AzureAssetBuilder") -> None:
    vnet = _get(d.props, "vnetConfiguration") or {}
    d.add(
        rel(
            _get(vnet, "infrastructureSubnetId"),
            EdgeType.CONTAINS,
            "SUBNET_CONTAINS_INSTANCE",
            reverse=True,
        )
    )
    d.md["internal"] = _get(vnet, "internal")
    customer = _path(d.props, "appLogsConfiguration", "logAnalyticsConfiguration", "customerId")
    if customer:
        d.add(rel(f"{LOG_ANALYTICS_PREFIX}{customer.lower()}", EdgeType.LOGS_TO, "LOGS_TO"))
    domain = _get(d.props, "defaultDomain")
    d.md["default_domain"] = domain
    d.md["static_ip"] = _get(d.props, "staticIp")


@extractor("microsoft.containerinstance/containergroups")
def _x_aci(d: _Draft, b: "AzureAssetBuilder") -> None:
    images = [_get(_props(c), "image") for c in _list(_get(d.props, "containers"))]
    _image_relations(d, [i for i in images if i])
    for cred in _list(_get(d.props, "imageRegistryCredentials")):
        _configured_registry(d, _get(cred, "server"))
    for sn in _rids(_get(d.props, "subnetIds")):
        d.add(rel(sn, EdgeType.CONTAINS, "SUBNET_CONTAINS_INSTANCE", reverse=True))
    ip = _get(d.props, "ipAddress") or {}
    if _lower(_get(ip, "type")) == "public":
        d.exposed = True
        d.md["public_ip"] = _get(ip, "ip")
        fqdn = _get(ip, "fqdn")
        d.alias(fqdn.lower() if isinstance(fqdn, str) else None)
    ws = _path(d.props, "diagnostics", "logAnalytics", "workspaceResourceId")
    d.add(rel(ws, EdgeType.LOGS_TO, "LOGS_TO"))
    cust = _path(d.props, "diagnostics", "logAnalytics", "workspaceId")
    if cust:
        d.add(rel(f"{LOG_ANALYTICS_PREFIX}{str(cust).lower()}", EdgeType.LOGS_TO, "LOGS_TO"))


@extractor("microsoft.apimanagement/service")
def _x_apim(d: _Draft, b: "AzureAssetBuilder") -> None:
    p = d.props
    subnet = _path(p, "virtualNetworkConfiguration", "subnetResourceId")
    d.add(rel(subnet, EdgeType.CONTAINS, "SUBNET_CONTAINS_INSTANCE", reverse=True))
    d.add(rel(_get(p, "publicIpAddressId"), EdgeType.ATTACHED_TO, reverse=True))
    vnet_type = _get(p, "virtualNetworkType")
    d.md["virtual_network_type"] = vnet_type
    for url in (_get(p, "gatewayUrl"), _get(p, "developerPortalUrl"), _get(p, "managementApiUrl")):
        d.alias(host_of(url))
    for hc in _list(_get(p, "hostnameConfigurations")):
        d.alias(host_of(_get(hc, "hostName")))
        kv = host_of(_get(hc, "keyVaultId"))
        d.add(
            rel(
                kv,
                EdgeType.REFERENCES,
                "CERTIFICATE_SECURES",
                description="custom domain certificate",
            )
        )
    if (
        _lower(vnet_type) != "internal"
        and _lower(_get(p, "publicNetworkAccess") or "enabled") != "disabled"
    ):
        d.exposed = True
