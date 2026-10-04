"""API Gateway depth: authorizers (-> Lambda / Cognito), VPC links (-> NLBs,
subnets, SGs) and custom domains (-> APIs, certificates; their regional /
CloudFront names are aliases so Route 53 records resolve). OIDC client
secrets are never collected."""

from __future__ import annotations

from typing import Any

from cloudg.inventory.aws_services._base import rel
from cloudg.inventory.aws_services.network_ext._common import (
    _COGNITO_ISSUER_RE,
    _LAMBDA_URI_RE,
    _MAX_LIST_METADATA,
    _S3_URI_RE,
    NetworkExtBase,
    _unique,
    logger,
    section,
)
from cloudg.inventory.aws_services.platform import _dns
from cloudg.schema.models import AssetType, CloudAsset, EdgeType


def _authorizer_relations(
    api_arn: str, uri: str | None, credentials: str | None, *extra: dict | None
) -> list[dict | None]:
    """Relations shared by REST and HTTP API authorizers, plus the
    generation-specific identity provider ones in ``extra``."""
    m = _LAMBDA_URI_RE.search(uri or "")
    return [
        rel(api_arn, EdgeType.REFERENCES, "DEPENDS_ON", reverse=True, description="API authorizer"),
        rel(
            m.group(1) if m else None,
            EdgeType.INVOKES,
            "INVOKES",
            description="Lambda authorizer",
        ),
        rel(credentials, EdgeType.ASSUMES_ROLE, "RUNS_ON"),
        *extra,
    ]


def _truststore_rel(uri: str | None) -> dict | None:
    """Relation to the S3 bucket of an mTLS truststore URI (None if not S3)."""
    bucket = _S3_URI_RE.match(uri or "")
    if not bucket:
        return None
    return rel(
        f"arn:aws:s3:::{bucket.group(1)}",
        EdgeType.REFERENCES,
        "DEPENDS_ON",
        description="mTLS truststore",
    )


def _add_mapping(e: dict[str, Any], target: str | None, mapping: dict[str, Any]) -> None:
    """Record an API mapping of a custom domain and route it to ``target``."""
    e["mappings"].append(mapping)
    e["relations"].append(
        rel(
            target,
            EdgeType.ROUTE,
            "SERVES_TRAFFIC_TO",
            base_path=mapping["path"],
            stage=mapping["stage"],
        )
    )


def _unique_mappings(mappings: list[dict]) -> list[dict]:
    seen: set[tuple] = set()
    out = []
    for m in mappings:
        k = (m["path"], m["api_id"], m["stage"])
        if k not in seen:
            seen.add(k)
            out.append(m)
    return out


def _http_authorizer_metadata(api: dict, auth: dict, routes: list[str]) -> dict[str, Any]:
    jwt = auth.get("JwtConfiguration") or {}
    return {
        "resource_kind": "apigateway_authorizer",
        "api_id": api["ApiId"],
        "api_type": api.get("ProtocolType"),
        "authorizer_type": auth.get("AuthorizerType"),
        "jwt_issuer": jwt.get("Issuer") or None,
        "jwt_audience_count": len(jwt.get("Audience") or []),
        "identity_source": auth.get("IdentitySource"),
        "result_ttl": auth.get("AuthorizerResultTtlInSeconds"),
        "route_count": len(routes),
        "routes": routes[:_MAX_LIST_METADATA],
    }


class ApiGatewayCollectorsMixin(NetworkExtBase):
    # ------------------------------------------------------------------
    # Authorizers
    # ------------------------------------------------------------------

    async def _collect_apigateway_authorizers(self) -> list[CloudAsset]:
        return await self._nx_sections(
            section("rest", self._rest_authorizers), section("http", self._http_authorizers)
        )

    async def _rest_authorizers(self) -> list[CloudAsset]:
        async with self._client("apigateway") as apigw:
            apis = [a async for a in self._paginate(apigw, "get_rest_apis", "items")]
            return await self._nx_each_flat(self._rest_api_authorizers, apis, apigw)

    async def _rest_api_authorizers(self, apigw: Any, api: dict) -> list[CloudAsset]:
        api_id = api["id"]
        api_arn = f"arn:aws:apigateway:{self._region}::/restapis/{api_id}"
        found = []
        async for auth in self._paginate(apigw, "get_authorizers", "items", restApiId=api_id):
            relations = _authorizer_relations(
                api_arn,
                auth.get("authorizerUri"),
                auth.get("authorizerCredentials"),
                *(
                    rel(p, EdgeType.REFERENCES, "DEPENDS_ON", description="Cognito user pool")
                    for p in auth.get("providerARNs") or []
                ),
            )
            found.append(
                self._asset(
                    arn=f"{api_arn}/authorizers/{auth['id']}",
                    name=f"{api.get('name', api_id)}/{auth.get('name', auth['id'])}",
                    asset_type=AssetType.AUTHORIZER,
                    metadata={
                        "resource_kind": "apigateway_authorizer",
                        "api_id": api_id,
                        "api_type": "REST",
                        "authorizer_type": auth.get("type"),
                        "auth_type": auth.get("authType"),
                        "identity_source": auth.get("identitySource"),
                        "result_ttl": auth.get("authorizerResultTtlInSeconds"),
                    },
                    relations=_unique(relations),
                )
            )
        return found

    async def _http_authorizers(self) -> list[CloudAsset]:
        async with self._client("apigatewayv2") as apigw:
            apis = [a async for a in self._paginate(apigw, "get_apis", "Items")]
            return await self._nx_each_flat(self._http_api_authorizers, apis, apigw)

    async def _http_routes_by_authorizer(self, apigw: Any, api_id: str) -> dict[str, list[str]]:
        routes_by_auth: dict[str, list[str]] = {}
        try:
            async for route in self._paginate(apigw, "get_routes", "Items", ApiId=api_id):
                if route.get("AuthorizerId"):
                    routes_by_auth.setdefault(route["AuthorizerId"], []).append(
                        route.get("RouteKey")
                    )
        except Exception as exc:
            logger.debug("HTTP API route listing failed for %s: %s", api_id, exc)
        return routes_by_auth

    async def _http_api_authorizers(self, apigw: Any, api: dict) -> list[CloudAsset]:
        api_id = api["ApiId"]
        api_arn = f"arn:aws:apigateway:{self._region}::/apis/{api_id}"
        auths = [a async for a in self._paginate(apigw, "get_authorizers", "Items", ApiId=api_id)]
        if not auths:
            return []
        routes_by_auth = await self._http_routes_by_authorizer(apigw, api_id)
        found = []
        for auth in auths:
            aid = auth["AuthorizerId"]
            issuer = (auth.get("JwtConfiguration") or {}).get("Issuer") or ""
            pool = _COGNITO_ISSUER_RE.match(issuer)
            relations = _authorizer_relations(
                api_arn,
                auth.get("AuthorizerUri"),
                auth.get("AuthorizerCredentialsArn"),
                rel(
                    pool.group(1) if pool else None,
                    EdgeType.REFERENCES,
                    "DEPENDS_ON",
                    description="Cognito user pool (JWT issuer)",
                ),
            )
            found.append(
                self._asset(
                    arn=f"{api_arn}/authorizers/{aid}",
                    name=f"{api.get('Name', api_id)}/{auth.get('Name', aid)}",
                    asset_type=AssetType.AUTHORIZER,
                    metadata=_http_authorizer_metadata(api, auth, routes_by_auth.get(aid, [])),
                    relations=_unique(relations),
                )
            )
        return found

    # ------------------------------------------------------------------
    # VPC links
    # ------------------------------------------------------------------

    async def _collect_apigateway_vpc_links(self) -> list[CloudAsset]:
        return await self._nx_sections(
            section("rest", self._rest_vpc_links), section("http", self._http_vpc_links)
        )

    async def _rest_vpc_links(self) -> list[CloudAsset]:
        out = []
        async with self._client("apigateway") as apigw:
            async for link in self._paginate(apigw, "get_vpc_links", "items"):
                lid = link["id"]
                out.append(
                    self._asset(
                        arn=f"arn:aws:apigateway:{self._region}::/vpclinks/{lid}",
                        name=link.get("name", lid),
                        asset_type=AssetType.VPC_LINK,
                        tags=link.get("tags"),
                        metadata={
                            "vpc_link_id": lid,
                            "api_type": "REST",
                            "status": link.get("status"),
                            "target_arns": link.get("targetArns", []),
                        },
                        relations=[
                            rel(
                                t,
                                EdgeType.LOAD_BALANCER_TARGET,
                                "SERVES_TRAFFIC_TO",
                                description="VPC link target",
                            )
                            for t in link.get("targetArns") or []
                        ],
                        aliases=[lid],
                    )
                )
        return out

    async def _http_vpc_links(self) -> list[CloudAsset]:
        out = []
        async with self._client("apigatewayv2") as apigw:
            async for link in self._pages(apigw.get_vpc_links, "Items"):
                lid = link["VpcLinkId"]
                out.append(
                    self._asset(
                        arn=f"arn:aws:apigateway:{self._region}::/vpclinks/{lid}",
                        name=link.get("Name", lid),
                        asset_type=AssetType.VPC_LINK,
                        tags=link.get("Tags"),
                        metadata={
                            "vpc_link_id": lid,
                            "api_type": "HTTP",
                            "status": link.get("VpcLinkStatus"),
                            "version": link.get("VpcLinkVersion"),
                            "subnet_ids": link.get("SubnetIds", []),
                            "security_groups": link.get("SecurityGroupIds", []),
                        },
                        relations=[
                            rel(s, EdgeType.CONTAINS, "SUBNET_CONTAINS_INSTANCE", reverse=True)
                            for s in link.get("SubnetIds") or []
                        ],
                        aliases=[lid],
                    )
                )
        return out

    # ------------------------------------------------------------------
    # Custom domains
    # ------------------------------------------------------------------

    async def _collect_apigateway_domains(self) -> list[CloudAsset]:
        """Custom domain names of REST and HTTP/WebSocket APIs, merged per
        domain (both API generations share the same domain namespace)."""
        domains: dict[str, dict[str, Any]] = {}
        await self._nx_sections(
            section("rest", self._rest_domains, domains),
            section("http", self._http_domains, domains),
        )
        return [self._custom_domain_asset(e) for e in domains.values()]

    def _domain_entry(
        self, domains: dict[str, dict[str, Any]], key: str, name: str, arn: str | None
    ) -> dict[str, Any]:
        return domains.setdefault(
            key,
            {
                "name": name,
                "arn": arn or f"arn:aws:apigateway:{self._region}::/domainnames/{name}",
                "aliases": [],
                "relations": [],
                "tags": {},
                "mappings": [],
                "endpoint_types": set(),
                "metadata": {},
            },
        )

    async def _rest_domains(self, domains: dict[str, dict[str, Any]]) -> None:
        async with self._client("apigateway") as apigw:
            async for d in self._paginate(apigw, "get_domain_names", "items"):
                name = d["domainName"]
                key = f"{name}+{d['domainNameId']}" if d.get("domainNameId") else name
                e = self._domain_entry(domains, key.lower(), name, d.get("domainNameArn"))
                self._merge_rest_domain(e, d)
                await self._rest_base_path_mappings(apigw, e, d)

    @staticmethod
    def _merge_rest_domain(e: dict[str, Any], d: dict) -> None:
        e["tags"].update(d.get("tags") or {})
        cfg = d.get("endpointConfiguration") or {}
        e["endpoint_types"].update(cfg.get("types") or [])
        e["aliases"] += [_dns(d.get("regionalDomainName")), _dns(d.get("distributionDomainName"))]
        for cert in (d.get("certificateArn"), d.get("regionalCertificateArn")):
            e["relations"].append(rel(cert, EdgeType.REFERENCES, "CERTIFICATE_SECURES"))
        e["relations"] += [
            rel(
                v,
                EdgeType.ROUTE,
                "SERVES_TRAFFIC_TO",
                reverse=True,
                description="private domain endpoint",
            )
            for v in cfg.get("vpcEndpointIds") or []
        ]
        mtls = d.get("mutualTlsAuthentication") or {}
        e["relations"].append(_truststore_rel(mtls.get("truststoreUri")))
        e["metadata"].update(
            {
                "status": d.get("domainNameStatus"),
                "security_policy": d.get("securityPolicy"),
                "regional_domain_name": d.get("regionalDomainName"),
                "distribution_domain_name": d.get("distributionDomainName"),
                "mutual_tls": bool(mtls.get("truststoreUri")),
                "private": bool(d.get("domainNameId")),
            }
        )

    async def _rest_base_path_mappings(self, apigw: Any, e: dict[str, Any], d: dict) -> None:
        name = d["domainName"]
        kwargs = {"domainName": name}
        if d.get("domainNameId"):
            kwargs["domainNameId"] = d["domainNameId"]
        try:
            async for m in self._paginate(apigw, "get_base_path_mappings", "items", **kwargs):
                api_id = m.get("restApiId")
                _add_mapping(
                    e,
                    f"arn:aws:apigateway:{self._region}::/restapis/{api_id}" if api_id else None,
                    {"path": m.get("basePath"), "api_id": api_id, "stage": m.get("stage")},
                )
        except Exception as exc:
            logger.debug("Base path mappings unavailable for %s: %s", name, exc)

    async def _http_domains(self, domains: dict[str, dict[str, Any]]) -> None:
        async with self._client("apigatewayv2") as apigw:
            async for d in self._paginate(apigw, "get_domain_names", "Items"):
                name = d["DomainName"]
                e = self._domain_entry(domains, name.lower(), name, d.get("DomainNameArn"))
                self._merge_http_domain(e, d)
                await self._http_api_mappings(apigw, e, name)

    @staticmethod
    def _merge_http_domain(e: dict[str, Any], d: dict) -> None:
        e["tags"].update(d.get("Tags") or {})
        for cfg in d.get("DomainNameConfigurations") or []:
            e["endpoint_types"].add(cfg.get("EndpointType"))
            e["aliases"].append(_dns(cfg.get("ApiGatewayDomainName")))
            e["relations"].append(
                rel(cfg.get("CertificateArn"), EdgeType.REFERENCES, "CERTIFICATE_SECURES")
            )
            e["metadata"].setdefault("security_policy", cfg.get("SecurityPolicy"))
            e["metadata"].setdefault("status", cfg.get("DomainNameStatus"))
        mtls = d.get("MutualTlsAuthentication") or {}
        truststore = _truststore_rel(mtls.get("TruststoreUri"))
        if truststore:
            e["relations"].append(truststore)
            e["metadata"]["mutual_tls"] = True

    async def _http_api_mappings(self, apigw: Any, e: dict[str, Any], name: str) -> None:
        try:
            async for m in self._pages(apigw.get_api_mappings, "Items", DomainName=name):
                # The API ID matches REST and HTTP API assets alike
                _add_mapping(
                    e,
                    m.get("ApiId"),
                    {
                        "path": m.get("ApiMappingKey"),
                        "api_id": m.get("ApiId"),
                        "stage": m.get("Stage"),
                    },
                )
        except Exception as exc:
            logger.debug("API mappings unavailable for %s: %s", name, exc)

    def _custom_domain_asset(self, e: dict[str, Any]) -> CloudAsset:
        types = sorted(t for t in e["endpoint_types"] if t)
        return self._asset(
            arn=e["arn"],
            name=e["name"],
            asset_type=AssetType.CUSTOM_DOMAIN,
            tags=e["tags"],
            metadata={
                "endpoint_types": types,
                "api_mappings": _unique_mappings(e["mappings"])[:_MAX_LIST_METADATA],
                **e["metadata"],
            },
            relations=_unique(e["relations"]),
            exposed="PRIVATE" not in types,
            aliases=list(dict.fromkeys(a for a in e["aliases"] if a)),
        )
