"""APIs: Apigee organizations, instances, environments and proxies, and the
JWT providers and backends inside API Gateway configs."""

from __future__ import annotations

import base64
import binascii
import json
from typing import Any

import yaml

from cloudg.inventory.gcp_relations._refs import crm_ref, host_target, parent_of, url_target
from cloudg.inventory.gcp_relations.context import Extracted, GCPContext, _extractor
from cloudg.inventory.gcp_relations.names import _list, dig, full_name, network_ref, sa_email
from cloudg.schema.models import EdgeType

_MAX_DOC_BYTES = 512 * 1024


# ---------------------------------------------------------------------------
# Apigee
# ---------------------------------------------------------------------------


@_extractor("apigee.googleapis.com/Organization")
def _apigee_org(ctx: GCPContext, out: Extracted) -> None:
    d = ctx.data
    project = d.get("projectId") or ctx.project_id
    out.add(
        network_ref(d.get("authorizedNetwork"), project),
        EdgeType.ATTACHED_TO,
        description="Apigee runtime peered network",
    )
    out.add(crm_ref(project), EdgeType.REFERENCES, "DEPENDS_ON", description="Apigee host project")
    out.metadata.update(
        runtime_type=d.get("runtimeType"),
        billing_type=d.get("billingType"),
        disable_vpc_peering=d.get("disableVpcPeering"),
        analytics_region=d.get("analyticsRegion"),
        apigee_org=ctx.name.rsplit("/", 1)[-1],
    )


@_extractor("apigee.googleapis.com/Instance")
def _apigee_instance(ctx: GCPContext, out: Extracted) -> None:
    d = ctx.data
    out.add(parent_of(ctx.name, "instances"), EdgeType.CONTAINS, reverse=True)
    out.add(
        full_name(d.get("serviceAttachment"), "compute"),
        EdgeType.REFERENCES,
        "DEPENDS_ON",
        description="runtime PSC service attachment",
    )
    for project in _list(d.get("consumerAcceptList")):
        out.add(
            crm_ref(project),
            EdgeType.GRANTS_ACCESS,
            "CROSS_ACCOUNT_TRUST",
            reverse=True,
            description="PSC consumer accept list",
        )
    out.alias(d.get("host"))
    out.metadata.update(host=d.get("host"), peering_cidr_range=d.get("peeringCidrRange"))


@_extractor("apigee.googleapis.com/Environment")
def _apigee_env(ctx: GCPContext, out: Extracted) -> None:
    d = ctx.data
    out.add(parent_of(ctx.name, "environments"), EdgeType.CONTAINS, reverse=True)
    out.metadata.update(
        deployment_type=d.get("deploymentType"),
        api_proxy_type=d.get("apiProxyType"),
        environment_type=d.get("type"),
    )


@_extractor("apigee.googleapis.com/ApiProxy")
def _apigee_proxy(ctx: GCPContext, out: Extracted) -> None:
    d = ctx.data
    out.add(parent_of(ctx.name, "apis"), EdgeType.CONTAINS, reverse=True)
    out.metadata.update(
        latest_revision=d.get("latestRevisionId"), revisions=list(d.get("revision") or [])
    )


@_extractor("apigee.googleapis.com/ApiProxyRevision")
def _apigee_proxy_revision(ctx: GCPContext, out: Extracted) -> None:
    d = ctx.data
    out.add(parent_of(ctx.name, "revisions"), EdgeType.CONTAINS, reverse=True)
    out.metadata.update(
        target_servers=list(d.get("targetServers") or []),
        target_endpoints=list(d.get("targetEndpoints") or []),
        proxy_endpoints=list(d.get("proxyEndpoints") or []),
        policies=list(d.get("policies") or [])[:100],
    )


@_extractor("apigee.googleapis.com/TargetServer")
def _apigee_target_server(ctx: GCPContext, out: Extracted) -> None:
    """Target servers come from the Apigee API (not Cloud Asset Inventory)."""
    d = ctx.data
    out.add(parent_of(ctx.name, "targetservers"), EdgeType.CONTAINS, reverse=True)
    out.add(
        host_target(d.get("host")),
        EdgeType.ROUTE,
        "SERVES_TRAFFIC_TO",
        description="Apigee target server",
        port=d.get("port"),
    )
    out.metadata.update(
        host=d.get("host"),
        port=d.get("port"),
        protocol=d.get("protocol"),
        tls_enabled=bool(dig(d, "sSLInfo", "enabled")),
        enabled=d.get("isEnabled"),
    )


# ---------------------------------------------------------------------------
# API Gateway configs: JWT providers (authorizers) and backends
# ---------------------------------------------------------------------------


def _decode_document(doc: Any) -> dict[str, Any] | None:
    """An OpenAPI / service config file's ``contents`` (base64 YAML or JSON) as a dict."""
    if not isinstance(doc, dict):
        return None
    contents = doc.get("contents")
    if not isinstance(contents, str) or not contents or len(contents) > _MAX_DOC_BYTES:
        return None
    try:
        text = base64.b64decode(contents, validate=False).decode("utf-8", "replace")
    except (binascii.Error, ValueError):
        text = contents
    for loader in (json.loads, yaml.safe_load):
        try:
            parsed = loader(text)
        except Exception:  # nosec B112 -- try the next parser; untrusted, partial docs are normal
            continue
        if isinstance(parsed, dict):
            return parsed
    return None


def _openapi_providers(spec: dict[str, Any]) -> list[dict[str, Any]]:
    """``securityDefinitions`` (OpenAPI 2) / ``components.securitySchemes`` with x-google-issuer."""
    schemes = dict(spec.get("securityDefinitions") or {})
    schemes.update(dig(spec, "components", "securitySchemes", default={}) or {})
    out = []
    for name, scheme in schemes.items():
        if not isinstance(scheme, dict) or not scheme.get("x-google-issuer"):
            continue
        out.append(
            {
                "name": str(name),
                "issuer": scheme.get("x-google-issuer"),
                "jwks_uri": scheme.get("x-google-jwks_uri"),
                "audiences": [
                    a.strip() for a in str(scheme.get("x-google-audiences") or "").split(",") if a
                ],
            }
        )
    return out


def _service_config_providers(cfg: dict[str, Any]) -> list[dict[str, Any]]:
    """``authentication.providers`` of a gRPC service config."""
    out = []
    for p in _list(dig(cfg, "authentication", "providers")):
        if isinstance(p, dict) and p.get("issuer"):
            out.append(
                {
                    "name": str(p.get("id") or p["issuer"]),
                    "issuer": p.get("issuer"),
                    "jwks_uri": p.get("jwksUri") or p.get("jwks_uri"),
                    "audiences": [a.strip() for a in str(p.get("audiences") or "").split(",") if a],
                }
            )
    return out


def _openapi_backends(spec: dict[str, Any]) -> list[str]:
    backends = []
    top = dig(spec, "x-google-backend", "address")
    if top:
        backends.append(top)
    for ops in (spec.get("paths") or {}).values():
        if not isinstance(ops, dict):
            continue
        for op in ops.values():
            addr = dig(op, "x-google-backend", "address") if isinstance(op, dict) else None
            if addr and addr not in backends:
                backends.append(addr)
    return backends


def _service_config_backends(cfg: dict[str, Any]) -> list[str]:
    return [
        r["address"]
        for r in _list(dig(cfg, "backend", "rules"))
        if isinstance(r, dict) and r.get("address")
    ]


def jwt_issuer_target(issuer: Any) -> str | None:
    """What a JWT issuer names: a service account, Identity Platform project or host."""
    if not isinstance(issuer, str) or not issuer:
        return None
    email = sa_email(issuer)
    if email:
        return f"serviceAccount:{email}"
    if issuer.startswith("https://securetoken.google.com/"):
        return issuer.rstrip("/")
    return host_target(issuer)


@_extractor("apigateway.googleapis.com/ApiConfig")
def _api_config_documents(ctx: GCPContext, out: Extracted) -> None:
    d = ctx.data
    providers: list[dict[str, Any]] = []
    backends: list[str] = []
    for item in _list(d.get("openapiDocuments")):
        spec = _decode_document(dig(item, "document") if isinstance(item, dict) else None)
        if spec:
            providers += _openapi_providers(spec)
            backends += _openapi_backends(spec)
    for item in _list(d.get("managedServiceConfigs")):
        cfg = _decode_document(item)
        if cfg:
            providers += _service_config_providers(cfg)
            backends += _service_config_backends(cfg)
    for addr in dict.fromkeys(backends):
        out.add(url_target(addr), EdgeType.ROUTE, "SERVES_TRAFFIC_TO", description="API backend")
    if providers:
        out.metadata["jwt_providers"] = providers
    if backends:
        out.metadata["backends"] = [url_target(b) for b in dict.fromkeys(backends)]


@_extractor("apigateway.googleapis.com/Authorizer")
def _api_authorizer(ctx: GCPContext, out: Extracted) -> None:
    """JWT authorizer of an API config (built from the config's documents)."""
    d = ctx.data
    out.add(parent_of(ctx.name, "authorizers"), EdgeType.CONTAINS, reverse=True)
    out.add(jwt_issuer_target(d.get("issuer")), EdgeType.REFERENCES, "DEPENDS_ON")
    out.metadata.update(issuer=d.get("issuer"), audiences=list(d.get("audiences") or []))
