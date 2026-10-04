"""Load balancing: forwarding rules, proxies, URL maps, backends, Cloud Armor."""

from __future__ import annotations

from cloudg.inventory.gcp_relations.context import Extracted, GCPContext, _extractor
from cloudg.inventory.gcp_relations.names import (
    _list,
    dig,
    full_name,
)
from cloudg.schema.models import EdgeType

# ---------------------------------------------------------------------------
# Load balancing
# ---------------------------------------------------------------------------

_EXTERNAL_SCHEMES = {"EXTERNAL", "EXTERNAL_MANAGED"}


@_extractor("compute.googleapis.com/ForwardingRule", "compute.googleapis.com/GlobalForwardingRule")
def _forwarding_rule(ctx: GCPContext, out: Extracted) -> None:
    d = ctx.data
    out.add(
        full_name(d.get("target"), "compute"),
        EdgeType.ROUTE,
        "SERVES_TRAFFIC_TO",
        description="forwarding rule target",
    )
    out.add(full_name(d.get("backendService"), "compute"), EdgeType.ROUTE, "SERVES_TRAFFIC_TO")
    scheme = d.get("loadBalancingScheme") or ""
    ip = d.get("IPAddress") or d.get("ipAddress")
    ports = list(d.get("ports") or ([d["portRange"]] if d.get("portRange") else []))
    protocol = d.get("IPProtocol") or d.get("ipProtocol")
    if isinstance(ip, str) and "/" in ip:
        out.add(full_name(ip, "compute"), EdgeType.ATTACHED_TO, reverse=True)
    elif ip and scheme in _EXTERNAL_SCHEMES:
        out.add(ip, EdgeType.ATTACHED_TO, reverse=True, description="static external address")
        out.alias(ip)
    if scheme not in _EXTERNAL_SCHEMES:
        out.in_subnet(full_name(d.get("subnetwork") or d.get("network"), "compute"))
    psc = bool(d.get("pscConnectionId")) or "serviceAttachments" in str(d.get("target") or "")
    if scheme in _EXTERNAL_SCHEMES and not psc:
        out.expose(f"external load balancer ({scheme})", protocol=protocol, ports=ports)
    out.metadata.update(
        ip_address=ip,
        load_balancing_scheme=scheme,
        ip_protocol=protocol,
        ports=ports,
        network_tier=d.get("networkTier"),
        psc=psc,
    )


@_extractor(
    "compute.googleapis.com/TargetHttpProxy",
    "compute.googleapis.com/TargetHttpsProxy",
    "compute.googleapis.com/RegionTargetHttpProxy",
    "compute.googleapis.com/RegionTargetHttpsProxy",
    "compute.googleapis.com/TargetGrpcProxy",
    "compute.googleapis.com/TargetSslProxy",
    "compute.googleapis.com/TargetTcpProxy",
    "compute.googleapis.com/RegionTargetTcpProxy",
)
def _target_proxy(ctx: GCPContext, out: Extracted) -> None:
    d = ctx.data
    out.add(full_name(d.get("urlMap"), "compute"), EdgeType.ROUTE, "SERVES_TRAFFIC_TO")
    out.add(full_name(d.get("service"), "compute"), EdgeType.ROUTE, "SERVES_TRAFFIC_TO")
    for cert in _list(d.get("sslCertificates")):
        out.add(
            full_name(cert, "compute") or full_name(cert, "certificatemanager"),
            EdgeType.REFERENCES,
            "CERTIFICATE_SECURES",
            reverse=True,
        )
    out.add(
        full_name(d.get("certificateMap"), "certificatemanager"),
        EdgeType.REFERENCES,
        "CERTIFICATE_SECURES",
        reverse=True,
    )
    out.add(full_name(d.get("sslPolicy"), "compute"), EdgeType.REFERENCES, "DEPENDS_ON")
    out.metadata["quic_override"] = d.get("quicOverride")


@_extractor("compute.googleapis.com/UrlMap", "compute.googleapis.com/RegionUrlMap")
def _url_map(ctx: GCPContext, out: Extracted) -> None:
    d = ctx.data
    services = [d.get("defaultService")]
    services += [
        w.get("backendService")
        for w in _list(dig(d, "defaultRouteAction", "weightedBackendServices"))
        if isinstance(w, dict)
    ]
    for pm in _list(d.get("pathMatchers")):
        if not isinstance(pm, dict):
            continue
        services.append(pm.get("defaultService"))
        for pr in _list(pm.get("pathRules")):
            if isinstance(pr, dict):
                services.append(pr.get("service"))
        for rr in _list(pm.get("routeRules")):
            if isinstance(rr, dict):
                services.append(rr.get("service"))
                services += [
                    w.get("backendService")
                    for w in _list(dig(rr, "routeAction", "weightedBackendServices"))
                    if isinstance(w, dict)
                ]
    for svc in services:
        out.add(full_name(svc, "compute"), EdgeType.ROUTE, "SERVES_TRAFFIC_TO")
    out.metadata["hosts"] = sorted(
        {
            h
            for hr in _list(d.get("hostRules"))
            if isinstance(hr, dict)
            for h in hr.get("hosts") or []
        }
    )[:50]


@_extractor("compute.googleapis.com/BackendService", "compute.googleapis.com/RegionBackendService")
def _backend_service(ctx: GCPContext, out: Extracted) -> None:
    d = ctx.data
    for b in _list(d.get("backends")):
        if isinstance(b, dict):
            out.add(
                full_name(b.get("group"), "compute"),
                EdgeType.LOAD_BALANCER_TARGET,
                "LB_TARGETS_INSTANCE",
                balancing_mode=b.get("balancingMode"),
            )
    for hc in _list(d.get("healthChecks")):
        out.add(full_name(hc, "compute"), EdgeType.REFERENCES, "DEPENDS_ON")
    for key in ("securityPolicy", "edgeSecurityPolicy"):
        out.add(
            full_name(d.get(key), "compute"),
            EdgeType.PROTECTS,
            "PROTECTED_BY_WAF",
            reverse=True,
            description="Cloud Armor policy",
        )
    out.add(full_name(d.get("network"), "compute"), EdgeType.REFERENCES, "DEPENDS_ON")
    out.metadata.update(
        load_balancing_scheme=d.get("loadBalancingScheme"),
        protocol=d.get("protocol"),
        iap_enabled=bool(dig(d, "iap", "enabled")),
        cdn_enabled=bool(d.get("enableCDN")),
        logging_enabled=bool(dig(d, "logConfig", "enable")),
        security_policy=full_name(d.get("securityPolicy"), "compute"),
    )


@_extractor("compute.googleapis.com/BackendBucket")
def _backend_bucket(ctx: GCPContext, out: Extracted) -> None:
    d = ctx.data
    if d.get("bucketName"):
        out.add(
            f"//storage.googleapis.com/{d['bucketName']}",
            EdgeType.LOAD_BALANCER_TARGET,
            "SERVES_TRAFFIC_TO",
        )
    out.add(
        full_name(d.get("edgeSecurityPolicy"), "compute"),
        EdgeType.PROTECTS,
        "PROTECTED_BY_WAF",
        reverse=True,
    )
    out.metadata["cdn_enabled"] = bool(d.get("enableCdn"))


@_extractor("compute.googleapis.com/TargetPool")
def _target_pool(ctx: GCPContext, out: Extracted) -> None:
    d = ctx.data
    for inst in _list(d.get("instances")):
        out.add(full_name(inst, "compute"), EdgeType.LOAD_BALANCER_TARGET, "LB_TARGETS_INSTANCE")
    for hc in _list(d.get("healthChecks")):
        out.add(full_name(hc, "compute"), EdgeType.REFERENCES, "DEPENDS_ON")
    out.add(full_name(d.get("backupPool"), "compute"), EdgeType.REFERENCES, "DEPENDS_ON")


@_extractor("compute.googleapis.com/TargetInstance")
def _target_instance(ctx: GCPContext, out: Extracted) -> None:
    out.add(
        full_name(ctx.data.get("instance"), "compute"),
        EdgeType.LOAD_BALANCER_TARGET,
        "LB_TARGETS_INSTANCE",
    )


@_extractor(
    "compute.googleapis.com/NetworkEndpointGroup",
    "compute.googleapis.com/GlobalNetworkEndpointGroup",
    "compute.googleapis.com/RegionNetworkEndpointGroup",
)
def _neg(ctx: GCPContext, out: Extracted) -> None:
    d = ctx.data
    pid, region = ctx.project_id, ctx.region
    run_svc = dig(d, "cloudRun", "service")
    if run_svc and pid and region:
        out.add(
            f"//run.googleapis.com/projects/{pid}/locations/{region}/services/{run_svc}",
            EdgeType.LOAD_BALANCER_TARGET,
            "SERVES_TRAFFIC_TO",
        )
    fn = dig(d, "cloudFunction", "function")
    if fn and pid and region:
        out.add(
            f"//cloudfunctions.googleapis.com/projects/{pid}/locations/{region}/functions/{fn}",
            EdgeType.LOAD_BALANCER_TARGET,
            "SERVES_TRAFFIC_TO",
        )
    ae = dig(d, "appEngine", "service")
    if ae and pid:
        out.add(
            f"//appengine.googleapis.com/apps/{pid}/services/{ae}",
            EdgeType.LOAD_BALANCER_TARGET,
            "SERVES_TRAFFIC_TO",
        )
    psc = d.get("pscTargetService")
    if isinstance(psc, str) and "/" in psc:
        out.add(full_name(psc, "compute"), EdgeType.ROUTE, "SERVES_TRAFFIC_TO")
    out.in_subnet(full_name(d.get("subnetwork") or d.get("network"), "compute"))
    out.metadata["network_endpoint_type"] = d.get("networkEndpointType")


@_extractor("compute.googleapis.com/SecurityPolicy", "compute.googleapis.com/RegionSecurityPolicy")
def _security_policy(ctx: GCPContext, out: Extracted) -> None:
    d = ctx.data
    out.metadata.update(
        policy_type=d.get("type"),
        rule_count=len(_list(d.get("rules"))),
        adaptive_protection=bool(
            dig(d, "adaptiveProtectionConfig", "layer7DdosDefenseConfig", "enable")
        ),
    )


@_extractor("compute.googleapis.com/SslCertificate", "compute.googleapis.com/RegionSslCertificate")
def _ssl_cert(ctx: GCPContext, out: Extracted) -> None:
    d = ctx.data
    out.metadata.update(
        certificate_type=d.get("type"),
        domains=list(
            dig(d, "managed", "domains", default=[]) or d.get("subjectAlternativeNames") or []
        ),
        expire_time=d.get("expireTime"),
    )
