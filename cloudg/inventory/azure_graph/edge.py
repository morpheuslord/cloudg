"""Extractors for traffic entry points: load balancers, gateways, firewalls, Front Door, CDN."""

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
    host_of,
    owner_resource_id,
)
from cloudg.inventory.azure_graph.registry import (
    _Draft,
    extractor,
)
from cloudg.schema.models import EdgeType

if TYPE_CHECKING:
    from cloudg.inventory.azure_graph.builder import AzureAssetBuilder


def _pool_target(d: _Draft, target: Any, relationship: str, pool: Any) -> None:
    d.add(rel(target, EdgeType.LOAD_BALANCER_TARGET, relationship, backend_pool=_get(pool, "name")))


def _pool_nic_targets(d: _Draft, pool: Any, p: dict[str, Any], backend_nics: list[str]) -> None:
    """Backend NICs of a load balancer pool (``backendIPConfigurations``)."""
    for ipc in _rids(_get(p, "backendIPConfigurations")):
        owner = owner_resource_id(ipc)
        if owner and owner not in backend_nics:
            backend_nics.append(owner)
            _pool_target(d, owner, "LB_TARGETS_INSTANCE", pool)


def _pool_address_targets(d: _Draft, pool: Any, p: dict[str, Any], backend_ips: list[str]) -> None:
    """IP-based load balancer and application gateway backend addresses."""
    for addr in _list(_get(p, "loadBalancerBackendAddresses")):
        ap = _props(addr)
        ipc = _rid(_get(ap, "networkInterfaceIPConfiguration"))
        if ipc:
            _pool_target(d, owner_resource_id(ipc), "LB_TARGETS_INSTANCE", pool)
        ip = _get(ap, "ipAddress")
        if ip:
            backend_ips.append(ip)
            _pool_target(d, ip, "LB_TARGETS_INSTANCE", pool)
    for addr in _list(_get(p, "backendAddresses")):  # application gateway
        target = _get(addr, "fqdn") or _get(addr, "ipAddress")
        if target:
            backend_ips.append(target)
            ref = target.lower() if _get(addr, "fqdn") else target
            _pool_target(d, ref, "SERVES_TRAFFIC_TO", pool)


def _backend_targets(d: _Draft, pools: Any, waf: bool = False) -> None:
    backend_nics: list[str] = []
    backend_ips: list[str] = []
    for pool in _list(pools):
        p = _props(pool)
        d.alias(_rid(pool))
        _pool_nic_targets(d, pool, p, backend_nics)
        _pool_address_targets(d, pool, p, backend_ips)
    d.md["backend_network_interfaces"] = backend_nics
    d.md["backend_addresses"] = backend_ips


def _frontends(d: _Draft, configs: Any) -> None:
    public: list[str] = []
    for fe in _list(configs):
        p = _props(fe)
        d.alias(_rid(fe))
        pip = _rid(_get(p, "publicIPAddress"))
        if pip:
            public.append(pip)
            d.add(rel(pip, EdgeType.ATTACHED_TO, reverse=True, description="frontend public IP"))
        subnet = _rid(_get(p, "subnet"))
        d.add(rel(subnet, EdgeType.CONTAINS, "SUBNET_CONTAINS_INSTANCE", reverse=True))
        ip = _get(p, "privateIPAddress")
        if ip:
            d.alias(ip)
    d.md["frontend_public_ip_ids"] = public
    if public:
        d.exposed = True


@extractor("microsoft.network/loadbalancers")
def _x_lb(d: _Draft, b: "AzureAssetBuilder") -> None:
    sku = d.row.get("sku")
    d.md["sku"] = _get(sku, "name") if isinstance(sku, dict) else sku
    _frontends(d, _get(d.props, "frontendIPConfigurations"))
    _backend_targets(d, _get(d.props, "backendAddressPools"))
    for rule in _list(_get(d.props, "inboundNatRules")):
        d.alias(_rid(rule))


@extractor("microsoft.network/applicationgateways")
def _x_appgw(d: _Draft, b: "AzureAssetBuilder") -> None:
    _frontends(d, _get(d.props, "frontendIPConfigurations"))
    for gw in _list(_get(d.props, "gatewayIPConfigurations")):
        d.add(
            rel(
                _rid(_get(_props(gw), "subnet")),
                EdgeType.CONTAINS,
                "SUBNET_CONTAINS_INSTANCE",
                reverse=True,
            )
        )
    _backend_targets(d, _get(d.props, "backendAddressPools"))
    policy = _rid(_get(d.props, "firewallPolicy"))
    d.add(
        rel(policy, EdgeType.PROTECTS, "PROTECTED_BY_WAF", reverse=True, description="WAF policy")
    )
    waf = _get(d.props, "webApplicationFirewallConfiguration")
    d.md["waf_enabled"] = bool(policy) or bool(_get(waf, "enabled"))
    for cert in _list(_get(d.props, "sslCertificates")):
        secret = _get(_props(cert), "keyVaultSecretId")
        host = host_of(secret)
        d.add(
            rel(
                host,
                EdgeType.REFERENCES,
                "CERTIFICATE_SECURES",
                description="TLS certificate from Key Vault",
            )
        )


def _gateway_ip_configs(
    d: _Draft, configs: list[Any], pip_description: str | None = None, private_ip: bool = False
) -> None:
    """Subnet + public IP of gateway-style ``ipConfigurations`` (firewalls, VPN, Bastion)."""
    for cfg in configs:
        p = _props(cfg)
        d.alias(_rid(cfg))
        d.add(
            rel(
                _rid(_get(p, "subnet")), EdgeType.CONTAINS, "SUBNET_CONTAINS_INSTANCE", reverse=True
            )
        )
        pip = _rid(_get(p, "publicIPAddress"))
        if pip:
            d.exposed = True
            d.add(rel(pip, EdgeType.ATTACHED_TO, reverse=True, description=pip_description))
        if private_ip and _get(p, "privateIPAddress"):
            d.alias(_get(p, "privateIPAddress"))
            d.md["private_ip"] = _get(p, "privateIPAddress")


@extractor("microsoft.network/azurefirewalls")
def _x_firewall(d: _Draft, b: "AzureAssetBuilder") -> None:
    configs = _list(_get(d.props, "ipConfigurations")) + _list(
        _get(d.props, "managementIpConfiguration")
    )
    _gateway_ip_configs(d, configs, "firewall public IP", private_ip=True)
    hub_ip = _path(d.props, "hubIPAddresses", "privateIPAddress")
    d.alias(hub_ip)
    d.add(
        rel(
            _rid(_get(d.props, "firewallPolicy")),
            EdgeType.REFERENCES,
            "DEPENDS_ON",
            description="firewall policy",
        )
    )
    d.add(rel(_rid(_get(d.props, "virtualHub")), EdgeType.CONTAINS, reverse=True))


@extractor("microsoft.network/virtualnetworkgateways", "microsoft.network/bastionhosts")
def _x_vnet_gateway(d: _Draft, b: "AzureAssetBuilder") -> None:
    _gateway_ip_configs(d, _list(_get(d.props, "ipConfigurations")))


@extractor("microsoft.network/frontdoors")
def _x_front_door_classic(d: _Draft, b: "AzureAssetBuilder") -> None:
    d.exposed = True
    for fe in _list(_get(d.props, "frontendEndpoints")):
        p = _props(fe)
        d.alias(_get(p, "hostName").lower() if isinstance(_get(p, "hostName"), str) else None)
        waf = _rid(_get(p, "webApplicationFirewallPolicyLink"))
        d.add(rel(waf, EdgeType.PROTECTS, "PROTECTED_BY_WAF", reverse=True))
    for pool in _list(_get(d.props, "backendPools")):
        for backend in _list(_get(_props(pool), "backends")):
            addr = _get(backend, "address")
            d.add(
                rel(
                    addr.lower() if isinstance(addr, str) else None,
                    EdgeType.LOAD_BALANCER_TARGET,
                    "SERVES_TRAFFIC_TO",
                    backend_pool=_get(pool, "name"),
                )
            )
            d.add(
                rel(
                    _get(backend, "privateLinkResourceId"),
                    EdgeType.LOAD_BALANCER_TARGET,
                    "SERVES_TRAFFIC_TO",
                )
            )


@extractor(
    "microsoft.cdn/profiles/afdendpoints",
    "microsoft.cdn/profiles/endpoints",
    "microsoft.cdn/profiles/customdomains",
)
def _x_cdn_endpoint(d: _Draft, b: "AzureAssetBuilder") -> None:
    d.exposed = True
    host = _get(d.props, "hostName")
    d.alias(host.lower() if isinstance(host, str) else None)
    for origin in _list(_get(d.props, "origins")):  # classic CDN endpoint
        oh = _get(_props(origin), "hostName")
        d.add(
            rel(
                oh.lower() if isinstance(oh, str) else None,
                EdgeType.LOAD_BALANCER_TARGET,
                "SERVES_TRAFFIC_TO",
            )
        )


@extractor("microsoft.cdn/profiles/origingroups/origins")
def _x_afd_origin(d: _Draft, b: "AzureAssetBuilder") -> None:
    host = _get(d.props, "hostName")
    target = _rid(_get(d.props, "azureOrigin")) or (host.lower() if isinstance(host, str) else None)
    d.add(
        rel(
            target,
            EdgeType.LOAD_BALANCER_TARGET,
            "SERVES_TRAFFIC_TO",
            description="Front Door origin",
        )
    )


@extractor("microsoft.cdn/profiles/securitypolicies")
def _x_afd_security_policy(d: _Draft, b: "AzureAssetBuilder") -> None:
    params = _get(d.props, "parameters") or {}
    waf = _rid(_get(params, "wafPolicy"))
    d.add(rel(waf, EdgeType.REFERENCES, "DEPENDS_ON"))
    for assoc in _list(_get(params, "associations")):
        for domain in _rids(_get(assoc, "domains")):
            d.add(rel(domain, EdgeType.PROTECTS, "PROTECTED_BY_WAF"))
            if waf:
                b.defer(
                    waf,
                    rel(
                        domain, EdgeType.PROTECTS, "PROTECTED_BY_WAF", description="Front Door WAF"
                    ),
                )
