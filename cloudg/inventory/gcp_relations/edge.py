"""Edge: Cloud DNS record sets, Certificate Manager, Certificate Authority
Service, Cloud Run domain mappings and Identity Platform (the issuer of
Firebase / Identity Platform ID tokens)."""

from __future__ import annotations

from typing import Any

from cloudg.inventory.gcp_relations._refs import host_target, parent_of, url_target
from cloudg.inventory.gcp_relations.context import Extracted, GCPContext, _extractor
from cloudg.inventory.gcp_relations.names import _list, _num, dig, full_name, relative_name
from cloudg.schema.models import EdgeType

_CM = "certificatemanager"
_MAX_RRDATAS = 50


# ---------------------------------------------------------------------------
# Cloud DNS record sets (read from the Cloud DNS API)
# ---------------------------------------------------------------------------


def _routing_rrdatas(policy: Any) -> list[str]:
    """Answers of a routing policy (weighted, geo, primary / backup, health-checked ILBs)."""
    if not isinstance(policy, dict):
        return []
    out: list[str] = []

    def targets(block: Any) -> None:
        if not isinstance(block, dict):
            return
        out.extend(str(r) for r in _list(block.get("rrdatas")))
        hc = block.get("healthCheckedTargets") or {}
        for lb in _list(hc.get("internalLoadBalancers")):
            if isinstance(lb, dict) and lb.get("ipAddress"):
                out.append(str(lb["ipAddress"]))
        out.extend(str(e) for e in _list(hc.get("externalEndpoints")))

    for key in ("wrr", "geo"):
        for item in _list(dig(policy, key, "items")):
            targets(item)
    pb = policy.get("primaryBackup") or {}
    targets(pb.get("primaryTargets"))
    for item in _list(dig(pb, "backupGeoTargets", "items")):
        targets(item)
    return out


@_extractor("dns.googleapis.com/ResourceRecordSet")
def _dns_record(ctx: GCPContext, out: Extracted) -> None:
    """A record set: the zone contains it and it resolves to IPs / hosts (DNS_RESOLVED)."""
    d = ctx.data
    out.add(d.get("managedZone"), EdgeType.CONTAINS, reverse=True, description="zone record")
    rtype = str(d.get("type") or "").upper()
    answers = [str(r) for r in _list(d.get("rrdatas"))] + _routing_rrdatas(d.get("routingPolicy"))
    for answer in dict.fromkeys(answers[:_MAX_RRDATAS]):
        if rtype in ("A", "AAAA"):
            target = answer
        elif rtype in ("CNAME", "ALIAS"):
            target = host_target(answer.rstrip("."))
        else:
            continue
        out.add(target, EdgeType.ROUTE, "DNS_RESOLVED", record_type=rtype)
    out.metadata.update(
        fqdn=str(d.get("name") or "").rstrip(".") or None,
        record_type=rtype,
        ttl=_num(d.get("ttl")),
        rrdatas=answers[:_MAX_RRDATAS],
        routing_policy=sorted((d.get("routingPolicy") or {}).keys()) or None,
    )


# ---------------------------------------------------------------------------
# Certificate Manager
# ---------------------------------------------------------------------------


@_extractor("certificatemanager.googleapis.com/Certificate")
def _cm_certificate(ctx: GCPContext, out: Extracted) -> None:
    d = ctx.data
    managed = d.get("managed") or {}
    for auth in _list(managed.get("dnsAuthorizations")):
        out.add(
            full_name(auth, _CM), EdgeType.REFERENCES, "DEPENDS_ON", description="DNS authorization"
        )
    out.add(
        full_name(managed.get("issuanceConfig"), _CM),
        EdgeType.REFERENCES,
        "DEPENDS_ON",
        description="issuance config",
    )
    out.metadata.update(
        domains=list(managed.get("domains") or d.get("sanDnsnames") or []),
        managed=bool(managed),
        managed_state=managed.get("state"),
        scope=d.get("scope"),
        expire_time=d.get("expireTime"),
    )


@_extractor("certificatemanager.googleapis.com/CertificateMap")
def _cm_map(ctx: GCPContext, out: Extracted) -> None:
    for target in _list(ctx.data.get("gclbTargets")):
        if not isinstance(target, dict):
            continue
        for key in ("targetHttpsProxy", "targetSslProxy"):
            out.add(
                full_name(target.get(key), "compute"),
                EdgeType.REFERENCES,
                "CERTIFICATE_SECURES",
                reverse=True,
                description="load balancer uses the certificate map",
            )


@_extractor("certificatemanager.googleapis.com/CertificateMapEntry")
def _cm_map_entry(ctx: GCPContext, out: Extracted) -> None:
    d = ctx.data
    out.add(parent_of(ctx.name, "certificateMapEntries"), EdgeType.CONTAINS, reverse=True)
    for cert in _list(d.get("certificates")):
        out.add(full_name(cert, _CM), EdgeType.REFERENCES, "CERTIFICATE_SECURES")
    out.metadata.update(hostname=d.get("hostname"), matcher=d.get("matcher"))


@_extractor("certificatemanager.googleapis.com/DnsAuthorization")
def _cm_dns_auth(ctx: GCPContext, out: Extracted) -> None:
    d = ctx.data
    out.metadata.update(
        domain=d.get("domain"),
        dns_record=dig(d, "dnsResourceRecord", "name"),
        auth_type=d.get("type"),
    )


@_extractor("certificatemanager.googleapis.com/CertificateIssuanceConfig")
def _cm_issuance(ctx: GCPContext, out: Extracted) -> None:
    d = ctx.data
    out.add(
        full_name(
            dig(d, "certificateAuthorityConfig", "certificateAuthorityServiceConfig", "caPool"),
            "privateca",
        ),
        EdgeType.REFERENCES,
        "DEPENDS_ON",
        description="issuing CA pool",
    )
    out.metadata.update(lifetime=d.get("lifetime"), key_algorithm=d.get("keyAlgorithm"))


@_extractor("certificatemanager.googleapis.com/TrustConfig")
def _cm_trust_config(ctx: GCPContext, out: Extracted) -> None:
    d = ctx.data
    out.metadata.update(
        trust_store_count=len(_list(d.get("trustStores"))),
        allowlisted_certificate_count=len(_list(d.get("allowlistedCertificates"))),
    )


# ---------------------------------------------------------------------------
# Certificate Authority Service
# ---------------------------------------------------------------------------


@_extractor("privateca.googleapis.com/CertificateAuthority")
def _ca(ctx: GCPContext, out: Extracted) -> None:
    d = ctx.data
    out.add(parent_of(ctx.name, "certificateAuthorities"), EdgeType.CONTAINS, reverse=True)
    out.add(
        full_name(dig(d, "subordinateConfig", "certificateAuthority"), "privateca"),
        EdgeType.REFERENCES,
        "DEPENDS_ON",
        description="issuing CA",
    )
    bucket = d.get("gcsBucket")
    if bucket:
        out.add(
            f"//storage.googleapis.com/{bucket}",
            EdgeType.REFERENCES,
            "WRITES_TO",
            description="CA certificate and CRL publishing",
        )
    out.metadata.update(
        ca_type=d.get("type"), tier=d.get("tier"), key_algorithm=dig(d, "keySpec", "algorithm")
    )


@_extractor("privateca.googleapis.com/CaPool")
def _ca_pool(ctx: GCPContext, out: Extracted) -> None:
    d = ctx.data
    out.metadata.update(
        tier=d.get("tier"),
        publish_ca_cert=dig(d, "publishingOptions", "publishCaCert"),
        publish_crl=dig(d, "publishingOptions", "publishCrl"),
    )


# ---------------------------------------------------------------------------
# Cloud Run domain mappings
# ---------------------------------------------------------------------------


@_extractor("run.googleapis.com/DomainMapping")
def _run_domain_mapping(ctx: GCPContext, out: Extracted) -> None:
    d = ctx.data
    meta = d.get("metadata") or {}
    domain = meta.get("name") or ctx.name.rsplit("/", 1)[-1]
    route = dig(d, "spec", "routeName")
    pid = ctx.project_id or meta.get("namespace")
    if route and pid and ctx.location:
        out.add(
            f"//run.googleapis.com/projects/{pid}/locations/{ctx.location}/services/{route}",
            EdgeType.ROUTE,
            "SERVES_TRAFFIC_TO",
            description=f"{domain} serves the service",
        )
    out.alias(host_target(domain))
    records = [
        {"name": r.get("name"), "type": r.get("type"), "rrdata": r.get("rrdata")}
        for r in _list(dig(d, "status", "resourceRecords"))
        if isinstance(r, dict)
    ]
    out.metadata.update(
        domain=domain,
        route=route,
        certificate_mode=dig(d, "spec", "certificateMode"),
        resource_records=records,
    )


# ---------------------------------------------------------------------------
# Identity Platform
# ---------------------------------------------------------------------------


@_extractor("identitytoolkit.googleapis.com/Config")
def _idp_config(ctx: GCPContext, out: Extracted) -> None:
    d = ctx.data
    parts = relative_name(ctx.name).split("/")
    pid = ctx.project_id or (parts[1] if len(parts) > 1 and parts[0] == "projects" else None)
    if pid:
        # The issuer of the ID tokens this project's users carry
        out.alias(f"https://securetoken.google.com/{pid}", f"securetoken.google.com/{pid}")
    triggers = dig(d, "blockingFunctions", "triggers", default={}) or {}
    for event, trig in triggers.items():
        if isinstance(trig, dict):
            out.add(
                url_target(trig.get("functionUri")),
                EdgeType.INVOKES,
                "INVOKES",
                description=f"blocking function {event}",
            )
    sign_in = d.get("signIn") or {}
    out.metadata.update(
        email_sign_in=bool(dig(sign_in, "email", "enabled")),
        phone_sign_in=bool(dig(sign_in, "phoneNumber", "enabled")),
        anonymous_sign_in=bool(dig(sign_in, "anonymous", "enabled")),
        mfa_state=dig(d, "mfa", "state"),
        authorized_domains=list(d.get("authorizedDomains") or []),
        multi_tenant=bool(dig(d, "multiTenant", "allowTenants")),
    )


@_extractor("identitytoolkit.googleapis.com/Tenant")
def _idp_tenant(ctx: GCPContext, out: Extracted) -> None:
    d = ctx.data
    project = parent_of(ctx.name, "tenants")
    if project:
        out.add(f"{project}/config", EdgeType.CONTAINS, reverse=True, description="tenant")
    out.metadata.update(
        mfa_state=dig(d, "mfaConfig", "state"),
        allow_password_signup=d.get("allowPasswordSignup"),
        enable_anonymous_user=d.get("enableAnonymousUser"),
    )


@_extractor(
    "identitytoolkit.googleapis.com/InboundSamlConfig",
    "identitytoolkit.googleapis.com/OauthIdpConfig",
    "identitytoolkit.googleapis.com/DefaultSupportedIdpConfig",
)
def _idp_provider(ctx: GCPContext, out: Extracted) -> None:
    d = ctx.data
    owner = None
    for seg in ("inboundSamlConfigs", "oauthIdpConfigs", "defaultSupportedIdpConfigs"):
        owner = owner or parent_of(ctx.name, seg)
    if owner and "/tenants/" not in owner:
        owner = f"{owner}/config"
    out.add(owner, EdgeType.CONTAINS, reverse=True, description="sign-in provider")
    out.metadata.update(
        enabled=d.get("enabled"),
        issuer=d.get("issuer") or dig(d, "idpConfig", "idpEntityId"),
    )
