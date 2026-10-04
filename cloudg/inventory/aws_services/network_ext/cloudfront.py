"""Deep CloudFront (global): CNAMEs, certificates, typed origins (S3 / ALB /
API / VPC origins), OAC / OAI, Lambda@Edge and CloudFront Functions,
access-log bucket, WAF. Origin custom header values are never kept.

The package's ``NetworkExtCollectorsMixin._collect_cloudfront`` delegates
here, overriding the shallow base collector."""

from __future__ import annotations

from typing import Any, AsyncIterator, Callable

from cloudg.inventory.aws_services._base import gather_limited, rel
from cloudg.inventory.aws_services.network_ext._common import (
    _EXECUTE_API_RE,
    _MAX_LIST_METADATA,
    NetworkExtBase,
    _bucket_from_domain,
    _unique,
    logger,
)
from cloudg.inventory.aws_services.platform import _dns
from cloudg.schema.models import AssetType, CloudAsset, EdgeType

# (behavior key, function ARN key, relation description, metadata kind)
_CF_EDGE_ASSOCIATIONS = (
    ("LambdaFunctionAssociations", "LambdaFunctionARN", "Lambda@Edge", "lambda_edge"),
    ("FunctionAssociations", "FunctionARN", "CloudFront Function", "cloudfront_function"),
)


def _items(container: Any) -> list:
    """``Items`` of a CloudFront ``{"Quantity": n, "Items": [...]}`` list."""
    return (container or {}).get("Items", []) or []


async def _cf_marker_items(
    call: Callable[..., Any], list_key: str, **kwargs: Any
) -> AsyncIterator[dict]:
    """Items across ``Marker`` pages of a CloudFront list call (max 100)."""
    marker = None
    for _ in range(100):
        params = dict(kwargs)
        if marker:
            params["Marker"] = marker
        lst = (await call(**params)).get(list_key) or {}
        for item in lst.get("Items", []) or []:
            yield item
        marker = lst.get("NextMarker")
        if not marker:
            break


def _cf_origin_md(o: dict, kind: str, oacs: dict[str, dict]) -> dict[str, Any]:
    oac_id = o.get("OriginAccessControlId") or None
    custom = o.get("CustomOriginConfig") or {}
    return {
        "id": o.get("Id"),
        "domain": o.get("DomainName"),
        "type": kind,
        "path": o.get("OriginPath") or None,
        "origin_access_control": oac_id,
        "oac_signing": (oacs.get(oac_id or "") or {}).get("signing_behavior"),
        "origin_access_identity": bool((o.get("S3OriginConfig") or {}).get("OriginAccessIdentity")),
        "protocol_policy": custom.get("OriginProtocolPolicy"),
        "vpc_origin": (o.get("VpcOriginConfig") or {}).get("VpcOriginId"),
        "origin_shield": bool((o.get("OriginShield") or {}).get("Enabled")),
        # header names only: values are often shared secrets
        "custom_header_names": [h.get("HeaderName") for h in _items(o.get("CustomHeaders"))],
    }


def _cf_behaviors(dist: dict, relations: list[dict | None]) -> tuple[list[dict], list[dict]]:
    """(cache behavior summaries, edge function associations); records a
    relation per associated edge function."""
    default = dist.get("DefaultCacheBehavior") or {}
    behaviors = [dict(default, PathPattern="*")] + list(_items(dist.get("CacheBehaviors")))
    behavior_md, edge_functions = [], []
    for b in behaviors:
        for key, arn_key, description, kind in _CF_EDGE_ASSOCIATIONS:
            for assoc in _items(b.get(key)):
                relations.append(
                    rel(
                        assoc.get(arn_key),
                        EdgeType.INVOKES,
                        "INVOKES",
                        description=description,
                        event_type=assoc.get("EventType"),
                    )
                )
                edge_functions.append(
                    {
                        "arn": assoc.get(arn_key),
                        "event_type": assoc.get("EventType"),
                        "kind": kind,
                        "path": b.get("PathPattern"),
                    }
                )
        behavior_md.append(
            {
                "path": b.get("PathPattern"),
                "target_origin": b.get("TargetOriginId"),
                "viewer_protocol_policy": b.get("ViewerProtocolPolicy"),
                "trusted_key_groups": bool((b.get("TrustedKeyGroups") or {}).get("Enabled")),
            }
        )
    return behavior_md, edge_functions


def _cf_log_bucket(logging_cfg: dict) -> str | None:
    if logging_cfg.get("Enabled") and logging_cfg.get("Bucket"):
        return (
            _bucket_from_domain(logging_cfg["Bucket"]) or logging_cfg["Bucket"].split(".s3", 1)[0]
        )
    return None


def _cf_viewer_certificate(cert: dict) -> dict[str, Any]:
    return {
        "default_certificate": bool(cert.get("CloudFrontDefaultCertificate")),
        "acm_certificate_arn": cert.get("ACMCertificateArn"),
        "iam_certificate_id": cert.get("IAMCertificateId"),
        "minimum_protocol_version": cert.get("MinimumProtocolVersion"),
        "ssl_support_method": cert.get("SSLSupportMethod"),
    }


def _cf_metadata(dist: dict, detail: dict[str, Any]) -> dict[str, Any]:
    """Distribution metadata; ``detail`` carries the derived parts."""
    default = dist.get("DefaultCacheBehavior") or {}
    logging_cfg = detail["logging_cfg"]
    return {
        # keys kept from the shallow collector
        "status": dist.get("Status"),
        "domain_name": dist.get("DomainName"),
        "origins": [o.get("DomainName") for o in _items(dist.get("Origins"))],
        "web_acl_id": dist.get("WebACLId", ""),
        "viewer_protocol_policy": default.get("ViewerProtocolPolicy"),
        # deep detail
        "distribution_id": dist.get("Id"),
        "enabled": dist.get("Enabled"),
        "staging": dist.get("Staging"),
        "comment": dist.get("Comment"),
        "cnames": detail["cnames"],
        "price_class": dist.get("PriceClass"),
        "http_version": dist.get("HttpVersion"),
        "ipv6": dist.get("IsIPV6Enabled"),
        "origin_details": detail["origin_md"],
        "origin_groups": [
            {"id": g.get("Id"), "members": [m.get("OriginId") for m in _items(g.get("Members"))]}
            for g in _items(dist.get("OriginGroups"))
        ],
        "cache_behaviors": detail["behavior_md"][:_MAX_LIST_METADATA],
        "edge_functions": detail["edge_functions"][:_MAX_LIST_METADATA],
        "viewer_certificate": _cf_viewer_certificate(dist.get("ViewerCertificate") or {}),
        "geo_restriction": ((dist.get("Restrictions") or {}).get("GeoRestriction") or {}).get(
            "RestrictionType"
        ),
        "logging_enabled": bool(logging_cfg.get("Enabled")),
        "logging_bucket": detail["log_bucket"],
        "realtime_log_config_arn": default.get("RealtimeLogConfigArn"),
    }


class CloudFrontCollectorsMixin(NetworkExtBase):
    def _cf_origin_target(
        self, origin: dict, vpc_origins: dict[str, dict]
    ) -> tuple[str, str | None]:
        """(origin kind, identifier of what the origin resolves to)."""
        vpc_id = (origin.get("VpcOriginConfig") or {}).get("VpcOriginId")
        if vpc_id:
            vo = vpc_origins.get(vpc_id) or {}
            return "vpc", vo.get("endpoint") or vo.get("arn") or vpc_id
        domain = _dns(origin.get("DomainName"))
        bucket = _bucket_from_domain(domain)
        if bucket:
            return "s3", f"arn:aws:s3:::{bucket}"
        api = _EXECUTE_API_RE.match(domain)
        if api:
            return "apigateway", api.group(1)
        return "custom", domain or None

    async def _collect_cloudfront_deep(self) -> list[CloudAsset]:
        async with self._client("cloudfront", region="us-east-1") as cf:
            dists: list[dict] = []
            async for page in cf.get_paginator("list_distributions").paginate():
                dists.extend(_items(page.get("DistributionList")))
            oacs = await self._cf_origin_access_controls(cf)
            vpc_origins = await self._cf_vpc_origins(cf, dists)
            functions = await self._cf_functions(cf)
            results = await gather_limited(
                [lambda d=d: self._cf_distribution(cf, d, oacs, vpc_origins) for d in dists]
            )
            return [a for a in results if a] + functions

    async def _cf_origin_access_controls(self, cf: Any) -> dict[str, dict]:
        oacs: dict[str, dict] = {}
        try:
            async for page in cf.get_paginator("list_origin_access_controls").paginate():
                for o in _items(page.get("OriginAccessControlList")):
                    oacs[o["Id"]] = {
                        "name": o.get("Name"),
                        "signing_behavior": o.get("SigningBehavior"),
                        "origin_type": o.get("OriginAccessControlOriginType"),
                    }
        except Exception as exc:
            logger.debug("Origin access control listing failed: %s", exc)
        return oacs

    async def _cf_vpc_origins(self, cf: Any, dists: list[dict]) -> dict[str, dict]:
        """VPC origins, listed only when a distribution uses one."""
        vpc_origins: dict[str, dict] = {}
        uses_vpc_origins = any(
            (o.get("VpcOriginConfig") or {}).get("VpcOriginId")
            for d in dists
            for o in _items(d.get("Origins"))
        )
        if not uses_vpc_origins:
            return vpc_origins
        try:
            async for v in _cf_marker_items(cf.list_vpc_origins, "VpcOriginList"):
                vpc_origins[v["Id"]] = {
                    "arn": v.get("Arn"),
                    "endpoint": v.get("OriginEndpointArn"),
                    "name": v.get("Name"),
                }
        except Exception as exc:
            logger.debug("VPC origin listing failed: %s", exc)
        return vpc_origins

    async def _cf_functions(self, cf: Any) -> list[CloudAsset]:
        functions: list[CloudAsset] = []
        try:
            async for fn in _cf_marker_items(cf.list_functions, "FunctionList", Stage="LIVE"):
                meta = fn.get("FunctionMetadata") or {}
                if not meta.get("FunctionARN"):
                    continue
                functions.append(
                    self._asset(
                        arn=meta["FunctionARN"],
                        name=fn.get("Name", meta["FunctionARN"]),
                        asset_type=AssetType.EDGE_FUNCTION,
                        region="global",
                        metadata={
                            "resource_kind": "cloudfront_function",
                            "runtime": (fn.get("FunctionConfig") or {}).get("Runtime"),
                            "status": fn.get("Status"),
                            "stage": meta.get("Stage"),
                        },
                    )
                )
        except Exception as exc:
            logger.debug("CloudFront function listing failed: %s", exc)
        return functions

    async def _cf_distribution(
        self, cf: Any, dist: dict, oacs: dict[str, dict], vpc_origins: dict[str, dict]
    ) -> CloudAsset:
        logging_cfg: dict = {}
        try:
            cfg = (await cf.get_distribution_config(Id=dist["Id"])).get("DistributionConfig") or {}
            logging_cfg = cfg.get("Logging") or {}
        except Exception as exc:
            logger.debug("Distribution config unavailable for %s: %s", dist.get("Id"), exc)
        return self._cloudfront_asset(dist, oacs, vpc_origins, logging_cfg)

    def _cf_origins(
        self, dist: dict, oacs: dict[str, dict], vpc_origins: dict[str, dict]
    ) -> tuple[list[dict | None], list[dict]]:
        """(origin relations, origin metadata) of a distribution."""
        relations: list[dict | None] = []
        origin_md = []
        for o in _items(dist.get("Origins")):
            kind, target = self._cf_origin_target(o, vpc_origins)
            relations.append(
                rel(
                    target,
                    EdgeType.ROUTE,
                    "SERVES_TRAFFIC_TO",
                    description=f"origin {o.get('Id')}",
                    origin_id=o.get("Id"),
                    origin_type=kind,
                )
            )
            origin_md.append(_cf_origin_md(o, kind, oacs))
        return relations, origin_md

    def _cloudfront_asset(
        self, dist: dict, oacs: dict[str, dict], vpc_origins: dict[str, dict], logging_cfg: dict
    ) -> CloudAsset:
        relations, origin_md = self._cf_origins(dist, oacs, vpc_origins)
        behavior_md, edge_functions = _cf_behaviors(dist, relations)
        cert = dist.get("ViewerCertificate") or {}
        relations.append(
            rel(cert.get("ACMCertificateArn"), EdgeType.REFERENCES, "CERTIFICATE_SECURES")
        )
        log_bucket = _cf_log_bucket(logging_cfg)
        if log_bucket is not None:
            relations.append(
                rel(
                    f"arn:aws:s3:::{log_bucket}",
                    EdgeType.LOGS_TO,
                    "LOGS_TO",
                    description="standard access logs",
                )
            )
        cnames = [_dns(a) for a in _items(dist.get("Aliases"))]
        detail = {
            "logging_cfg": logging_cfg,
            "log_bucket": log_bucket,
            "cnames": cnames,
            "origin_md": origin_md,
            "behavior_md": behavior_md,
            "edge_functions": edge_functions,
        }
        return self._asset(
            arn=dist.get("ARN", ""),
            name=dist.get("DomainName", dist.get("Id", "")),
            asset_type=AssetType.CLOUDFRONT,
            region="global",
            metadata=_cf_metadata(dist, detail),
            relations=_unique(relations),
            raw={k: v for k, v in dist.items() if k != "Origins"},
            exposed=True,
            aliases=cnames + [_dns(dist.get("DomainName"))],
        )
