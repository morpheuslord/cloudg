"""API Gateway REST and HTTP APIs -> Lambda / HTTP / VPC-link integrations."""

from __future__ import annotations

import logging
import re
from typing import Any

from cloudg.inventory.aws_services._base import (
    AWSServiceMixin,
    rel,
    resource_policy_relations,
)
from cloudg.schema.models import AssetType, CloudAsset, EdgeType

logger = logging.getLogger(__package__)  # the package logger, as before the split

_APIGW_LAMBDA_RE = re.compile(r"functions/(arn:aws[^/]+)/invocations")


def _vpc_link_rel(connection_id: str) -> dict[str, Any] | None:
    return rel(connection_id, EdgeType.ROUTE, "SERVES_TRAFFIC_TO", description="VPC link")


def _rest_method(res: dict, method: str, spec: dict | None) -> tuple[list[dict | None], dict]:
    """Relations and the integration summary of one REST API method."""
    integ = (spec or {}).get("methodIntegration") or {}
    uri = integ.get("uri") or ""
    m = _APIGW_LAMBDA_RE.search(uri)
    target = m.group(1) if m else None
    relations: list[dict | None] = []
    if target:
        relations.append(
            rel(target, EdgeType.INVOKES, "INVOKES", description=f"{method} {res.get('path')}")
        )
    if integ.get("connectionId"):
        relations.append(_vpc_link_rel(integ["connectionId"]))
    summary = {
        "path": res.get("path"),
        "method": method,
        "type": integ.get("type"),
        "auth": (spec or {}).get("authorizationType"),
        "target": target or (uri if uri.startswith("http") else None),
    }
    return relations, summary


def _http_integration_relations(integ: dict) -> list[dict | None]:
    uri = integ.get("IntegrationUri") or ""
    m = _APIGW_LAMBDA_RE.search(uri)
    target = m.group(1) if m else uri
    relations: list[dict | None] = []
    if target.startswith("arn:"):
        relations.append(
            rel(target, EdgeType.INVOKES, "INVOKES", description=integ.get("IntegrationType"))
        )
    if integ.get("ConnectionId"):
        relations.append(_vpc_link_rel(integ["ConnectionId"]))
    relations.append(rel(integ.get("CredentialsArn"), EdgeType.ASSUMES_ROLE, "RUNS_ON"))
    return relations


class ApiGatewayCollectorsMixin(AWSServiceMixin):
    async def _collect_apigateway(self) -> list[CloudAsset]:
        assets: list[CloudAsset] = []
        async with self._client("apigateway") as apigw:
            apis = [a async for a in self._paginate(apigw, "get_rest_apis", "items")]
            for api in apis:
                assets.append(await self._rest_api_asset(apigw, api))
        return assets

    async def _rest_api_asset(self, apigw: Any, api: dict) -> CloudAsset:
        api_id = api["id"]
        relations: list[dict | None] = []
        integrations = await self._rest_api_integrations(apigw, api_id, relations)
        stages = await self._rest_api_stages(apigw, api_id, relations)
        endpoint_types = (api.get("endpointConfiguration") or {}).get("types", [])
        pol_rels, _ = resource_policy_relations(api.get("policy"), self._account_id)
        return self._asset(
            arn=f"arn:aws:apigateway:{self._region}::/restapis/{api_id}",
            name=api.get("name", api_id),
            asset_type=AssetType.API_GATEWAY,
            tags=api.get("tags"),
            metadata={
                "api_type": "REST",
                "api_id": api_id,
                "endpoint_types": endpoint_types,
                "stages": stages,
                "integrations": integrations[:200],
                "unauthenticated_methods": sum(1 for i in integrations if i.get("auth") == "NONE"),
            },
            relations=relations + pol_rels,
            exposed="PRIVATE" not in endpoint_types,
            aliases=[api_id],
        )

    async def _rest_api_integrations(
        self, apigw: Any, api_id: str, relations: list[dict | None]
    ) -> list[dict]:
        """Every method's integration; Lambda targets and VPC links become relations."""
        integrations: list[dict] = []
        try:
            async for res in self._paginate(
                apigw, "get_resources", "items", restApiId=api_id, embed=["methods"]
            ):
                for method, spec in (res.get("resourceMethods") or {}).items():
                    method_rels, summary = _rest_method(res, method, spec)
                    relations.extend(method_rels)
                    integrations.append(summary)
        except Exception as exc:
            logger.debug("API Gateway resource listing failed for %s: %s", api_id, exc)
        return integrations

    async def _rest_api_stages(
        self, apigw: Any, api_id: str, relations: list[dict | None]
    ) -> list[str]:
        """Stage names; each stage's WAF ACL and access log destination."""
        stages: list[str] = []
        try:
            resp = await apigw.get_stages(restApiId=api_id)
            for stage in resp.get("item", []):
                stages.append(stage.get("stageName"))
                relations.append(
                    rel(stage.get("webAclArn"), EdgeType.PROTECTS, "PROTECTED_BY_WAF", reverse=True)
                )
                dest = (stage.get("accessLogSettings") or {}).get("destinationArn")
                relations.append(rel(dest, EdgeType.LOGS_TO, "LOGS_TO"))
        except Exception as exc:
            logger.debug("API Gateway stage listing failed for %s: %s", api_id, exc)
        return stages

    async def _collect_apigatewayv2(self) -> list[CloudAsset]:
        assets: list[CloudAsset] = []
        async with self._client("apigatewayv2") as apigw:
            apis = [a async for a in self._paginate(apigw, "get_apis", "Items")]
            for api in apis:
                api_id = api["ApiId"]
                relations: list[dict | None] = []
                try:
                    async for integ in self._paginate(
                        apigw, "get_integrations", "Items", ApiId=api_id
                    ):
                        relations.extend(_http_integration_relations(integ))
                except Exception as exc:
                    logger.debug("HTTP API integration listing failed for %s: %s", api_id, exc)
                assets.append(
                    self._asset(
                        arn=f"arn:aws:apigateway:{self._region}::/apis/{api_id}",
                        name=api.get("Name", api_id),
                        asset_type=AssetType.API_GATEWAY,
                        tags=api.get("Tags"),
                        metadata={
                            "api_type": api.get("ProtocolType"),
                            "api_id": api_id,
                            "endpoint": api.get("ApiEndpoint"),
                            "default_endpoint_disabled": api.get(
                                "DisableExecuteApiEndpoint", False
                            ),
                        },
                        relations=relations,
                        exposed=not api.get("DisableExecuteApiEndpoint", False),
                        aliases=[api_id, api.get("ApiEndpoint")],
                    )
                )
        return assets
