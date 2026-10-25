"""Network security and network services: Cloud NGFW endpoints, security
profiles, TLS policies, Cloud IDS, Secure Web Proxy / service mesh gateways
and routes, and Media CDN."""

from __future__ import annotations

from cloudg.inventory.gcp_relations._refs import (
    backend_service_ref,
    gcs_ref,
    host_target,
    secret_version_ref,
)
from cloudg.inventory.gcp_relations.context import Extracted, GCPContext, _extractor
from cloudg.inventory.gcp_relations.names import _list, dig, full_name, network_ref
from cloudg.schema.models import EdgeType

_NS = "networksecurity"
_NSV = "networkservices"


# ---------------------------------------------------------------------------
# Cloud NGFW and Cloud IDS
# ---------------------------------------------------------------------------


@_extractor("networksecurity.googleapis.com/FirewallEndpoint")
def _firewall_endpoint(ctx: GCPContext, out: Extracted) -> None:
    d = ctx.data
    for net in _list(d.get("associatedNetworks")):
        out.add(
            full_name(net, "compute"),
            EdgeType.PROTECTS,
            "PROTECTED_BY_NACL",
            description="Cloud NGFW endpoint inspects the network",
        )
    for assoc in _list(d.get("associations")):
        if isinstance(assoc, dict):
            out.add(
                full_name(assoc.get("network"), "compute"), EdgeType.PROTECTS, "PROTECTED_BY_NACL"
            )
    out.metadata.update(
        billing_project=d.get("billingProjectId"), endpoint_type=d.get("type"), state=d.get("state")
    )


@_extractor("networksecurity.googleapis.com/FirewallEndpointAssociation")
def _firewall_endpoint_association(ctx: GCPContext, out: Extracted) -> None:
    d = ctx.data
    out.add(
        full_name(d.get("network"), "compute"),
        EdgeType.PROTECTS,
        "PROTECTED_BY_NACL",
        description="network traffic inspected by Cloud NGFW",
        disabled=d.get("disabled") or None,
    )
    out.add(full_name(d.get("firewallEndpoint"), _NS), EdgeType.REFERENCES, "DEPENDS_ON")
    out.add(full_name(d.get("tlsInspectionPolicy"), _NS), EdgeType.REFERENCES, "DEPENDS_ON")
    out.metadata["disabled"] = bool(d.get("disabled"))


@_extractor("networksecurity.googleapis.com/SecurityProfileGroup")
def _security_profile_group(ctx: GCPContext, out: Extracted) -> None:
    d = ctx.data
    for key in (
        "threatPreventionProfile",
        "urlFilteringProfile",
        "customMirroringProfile",
        "customInterceptProfile",
    ):
        out.add(full_name(d.get(key), _NS), EdgeType.REFERENCES, "DEPENDS_ON", profile=key)


@_extractor("networksecurity.googleapis.com/SecurityProfile")
def _security_profile(ctx: GCPContext, out: Extracted) -> None:
    d = ctx.data
    tp = d.get("threatPreventionProfile") or {}
    out.metadata.update(
        profile_type=d.get("type"),
        severity_overrides=len(_list(tp.get("severityOverrides"))),
        threat_overrides=len(_list(tp.get("threatOverrides"))),
    )


@_extractor("networksecurity.googleapis.com/TlsInspectionPolicy")
def _tls_inspection(ctx: GCPContext, out: Extracted) -> None:
    d = ctx.data
    out.add(full_name(d.get("caPool"), "privateca"), EdgeType.REFERENCES, "DEPENDS_ON")
    out.add(
        full_name(d.get("trustConfig"), "certificatemanager"), EdgeType.REFERENCES, "DEPENDS_ON"
    )
    out.metadata.update(
        min_tls_version=d.get("minTlsVersion"),
        exclude_public_ca_set=d.get("excludePublicCaSet"),
    )


@_extractor(
    "networksecurity.googleapis.com/ServerTlsPolicy",
    "networksecurity.googleapis.com/ClientTlsPolicy",
)
def _tls_policy(ctx: GCPContext, out: Extracted) -> None:
    d = ctx.data
    mtls = d.get("mtlsPolicy") or {}
    out.add(
        full_name(mtls.get("clientValidationTrustConfig"), "certificatemanager"),
        EdgeType.REFERENCES,
        "DEPENDS_ON",
    )
    out.metadata.update(
        allow_open=d.get("allowOpen"),
        mtls_mode=mtls.get("clientValidationMode"),
        sni=d.get("sni"),
    )


@_extractor(
    "networksecurity.googleapis.com/AuthorizationPolicy",
    "networksecurity.googleapis.com/AuthzPolicy",
)
def _authorization_policy(ctx: GCPContext, out: Extracted) -> None:
    d = ctx.data
    for res in _list(dig(d, "target", "resources")):
        out.add(
            full_name(res, "compute"),
            EdgeType.PROTECTS,
            "PROTECTED_BY_WAF",
            description="L7 authorization policy",
        )
    ext = dig(d, "customProvider", "authzExtension", "resources", default=[])
    for res in _list(ext):
        out.add(full_name(res, _NSV), EdgeType.INVOKES, "INVOKES", description="authz extension")
    out.metadata.update(
        action=d.get("action"),
        rule_count=len(_list(d.get("rules")) or _list(d.get("httpRules"))),
        load_balancing_scheme=dig(d, "target", "loadBalancingScheme"),
    )


@_extractor("networksecurity.googleapis.com/AddressGroup")
def _address_group(ctx: GCPContext, out: Extracted) -> None:
    d = ctx.data
    out.metadata.update(
        group_type=d.get("type"),
        item_count=len(_list(d.get("items"))),
        capacity=d.get("capacity"),
        purpose=list(d.get("purpose") or []),
    )


@_extractor(
    "compute.googleapis.com/FirewallPolicy",
    "compute.googleapis.com/NetworkFirewallPolicy",
    "compute.googleapis.com/RegionNetworkFirewallPolicy",
)
def _firewall_policy_profiles(ctx: GCPContext, out: Extracted) -> None:
    """Rules that hand traffic to Cloud NGFW name a security profile group."""
    for rule in _list(ctx.data.get("rules")):
        if isinstance(rule, dict) and rule.get("securityProfileGroup"):
            out.add(
                full_name(rule["securityProfileGroup"], _NS),
                EdgeType.REFERENCES,
                "DEPENDS_ON",
                description="rule applies a security profile group",
                priority=rule.get("priority"),
            )


@_extractor("ids.googleapis.com/Endpoint")
def _ids_endpoint(ctx: GCPContext, out: Extracted) -> None:
    d = ctx.data
    out.add(
        full_name(d.get("network"), "compute"),
        EdgeType.PROTECTS,
        "PROTECTED_BY_NACL",
        description="Cloud IDS inspects mirrored traffic",
        severity=d.get("severity"),
    )
    # Packet mirroring policies send traffic to this forwarding rule
    out.alias(full_name(d.get("endpointForwardingRule"), "compute"))
    out.alias(d.get("endpointIp"))
    out.metadata.update(
        severity=d.get("severity"),
        traffic_logs=bool(d.get("trafficLogs")),
        threat_exceptions=list(d.get("threatExceptions") or []),
        endpoint_ip=d.get("endpointIp"),
        security_service="cloud-ids",
    )


# ---------------------------------------------------------------------------
# Network Services: gateways, meshes and routes
# ---------------------------------------------------------------------------


@_extractor("networkservices.googleapis.com/Gateway")
def _ns_gateway(ctx: GCPContext, out: Extracted) -> None:
    d = ctx.data
    out.add(network_ref(d.get("network"), ctx.project_id), EdgeType.ATTACHED_TO)
    out.in_subnet(full_name(d.get("subnetwork"), "compute"))
    for cert in _list(d.get("certificateUrls")):
        out.add(full_name(cert, "certificatemanager"), EdgeType.REFERENCES, "CERTIFICATE_SECURES")
    out.add(full_name(d.get("serverTlsPolicy"), _NS), EdgeType.REFERENCES, "DEPENDS_ON")
    out.add(
        full_name(d.get("gatewaySecurityPolicy"), _NS),
        EdgeType.PROTECTS,
        "PROTECTED_BY_WAF",
        reverse=True,
        description="Secure Web Proxy policy",
    )
    out.alias(*[a for a in _list(d.get("addresses")) if isinstance(a, str)])
    out.metadata.update(
        gateway_type=d.get("type"),
        ports=list(d.get("ports") or []),
        scope=d.get("scope"),
        addresses=list(d.get("addresses") or []),
    )


@_extractor("networkservices.googleapis.com/Mesh")
def _ns_mesh(ctx: GCPContext, out: Extracted) -> None:
    out.metadata["interception_port"] = ctx.data.get("interceptionPort")


@_extractor(
    "networkservices.googleapis.com/HttpRoute",
    "networkservices.googleapis.com/GrpcRoute",
    "networkservices.googleapis.com/TcpRoute",
    "networkservices.googleapis.com/TlsRoute",
)
def _ns_route(ctx: GCPContext, out: Extracted) -> None:
    d = ctx.data
    for gw in _list(d.get("gateways")):
        out.add(full_name(gw, _NSV), EdgeType.ATTACHED_TO, description="route on gateway")
    for mesh in _list(d.get("meshes")):
        out.add(full_name(mesh, _NSV), EdgeType.ATTACHED_TO, description="route on mesh")
    for rule in _list(d.get("rules")):
        if not isinstance(rule, dict):
            continue
        for dest in _list(dig(rule, "action", "destinations")):
            if isinstance(dest, dict):
                out.add(
                    backend_service_ref(dest.get("serviceName")),
                    EdgeType.ROUTE,
                    "SERVES_TRAFFIC_TO",
                    weight=dest.get("weight"),
                )
    out.metadata["hostnames"] = list(d.get("hostnames") or [])


@_extractor("networkservices.googleapis.com/ServiceBinding")
def _ns_service_binding(ctx: GCPContext, out: Extracted) -> None:
    out.add(
        full_name(ctx.data.get("service"), "servicedirectory"), EdgeType.REFERENCES, "DEPENDS_ON"
    )


@_extractor("networkservices.googleapis.com/EndpointPolicy")
def _ns_endpoint_policy(ctx: GCPContext, out: Extracted) -> None:
    d = ctx.data
    for key in ("authorizationPolicy", "serverTlsPolicy", "clientTlsPolicy"):
        out.add(full_name(d.get(key), _NS), EdgeType.REFERENCES, "DEPENDS_ON")
    out.metadata["policy_type"] = d.get("type")


# ---------------------------------------------------------------------------
# Media CDN
# ---------------------------------------------------------------------------


@_extractor("networkservices.googleapis.com/EdgeCacheService")
def _edge_cache_service(ctx: GCPContext, out: Extracted) -> None:
    d = ctx.data
    routing = d.get("routing") or {}
    for matcher in _list(routing.get("pathMatchers")):
        for rule in _list(dig(matcher, "routeRules")) if isinstance(matcher, dict) else []:
            if isinstance(rule, dict):
                out.add(full_name(rule.get("origin"), _NSV), EdgeType.ROUTE, "SERVES_TRAFFIC_TO")
    hosts = [
        h
        for hr in _list(routing.get("hostRules"))
        if isinstance(hr, dict)
        for h in hr.get("hosts", [])
    ]
    for host in hosts:
        out.alias(host_target(host))
    out.add(
        full_name(d.get("edgeSecurityPolicy"), "compute"),
        EdgeType.PROTECTS,
        "PROTECTED_BY_WAF",
        reverse=True,
    )
    for cert in _list(d.get("edgeSslCertificates")):
        out.add(full_name(cert, "certificatemanager"), EdgeType.REFERENCES, "CERTIFICATE_SECURES")
    out.alias(*[ip for ip in _list(d.get("ipv4Addresses")) + _list(d.get("ipv6Addresses")) if ip])
    out.expose("Media CDN edge cache service", protocol="tcp", ports=["80", "443"])
    out.metadata.update(
        hosts=hosts,
        logging=bool(dig(d, "logConfig", "enable")),
        require_tls=d.get("requireTls"),
        disable_quic=d.get("disableQuic"),
    )


@_extractor("networkservices.googleapis.com/EdgeCacheOrigin")
def _edge_cache_origin(ctx: GCPContext, out: Extracted) -> None:
    d = ctx.data
    addr = d.get("originAddress")
    target = (
        gcs_ref(addr) if isinstance(addr, str) and addr.startswith("gs://") else host_target(addr)
    )
    out.add(target, EdgeType.ROUTE, "SERVES_TRAFFIC_TO", description="origin address")
    out.add(full_name(d.get("failoverOrigin"), _NSV), EdgeType.REFERENCES, "DEPENDS_ON")
    out.add(
        secret_version_ref(dig(d, "awsV4Authentication", "secretAccessKeyVersion")),
        EdgeType.REFERENCES,
        "READS_FROM",
        description="origin credentials",
    )
    out.metadata.update(origin_address=addr, protocol=d.get("protocol"))


@_extractor("networkservices.googleapis.com/EdgeCacheKeyset")
def _edge_cache_keyset(ctx: GCPContext, out: Extracted) -> None:
    d = ctx.data
    for key in _list(d.get("validationSharedKeys")):
        if isinstance(key, dict):
            out.add(secret_version_ref(key.get("secretVersion")), EdgeType.REFERENCES, "READS_FROM")
    out.metadata["public_key_count"] = len(_list(d.get("publicKeys")))


@_extractor("networkservices.googleapis.com/ServiceLbPolicy")
def _service_lb_policy(ctx: GCPContext, out: Extracted) -> None:
    out.metadata["load_balancing_algorithm"] = ctx.data.get("loadBalancingAlgorithm")


@_extractor("compute.googleapis.com/NetworkEdgeSecurityService")
def _edge_security_service(ctx: GCPContext, out: Extracted) -> None:
    """Regional Cloud Armor network edge security for the project's external IPs."""
    out.add(
        full_name(ctx.data.get("securityPolicy"), "compute"),
        EdgeType.REFERENCES,
        "DEPENDS_ON",
        description="advanced network DDoS protection policy",
    )
