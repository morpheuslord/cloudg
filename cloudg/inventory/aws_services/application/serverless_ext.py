"""Lambda aliases: routing weights, alias function URLs and alias-scoped
resource-policy invokers."""

from __future__ import annotations

from typing import Any

from cloudg.inventory.aws_services._base import error_code, gather_limited, rel
from cloudg.inventory.aws_services._base import (
    resource_policy_relations as _resource_policy_relations,
)
from cloudg.inventory.aws_services.application._common import ApplicationBase, logger
from cloudg.schema.models import AssetType, CloudAsset, EdgeType


class LambdaAliasCollectorsMixin(ApplicationBase):
    """Lambda alias collector."""

    async def _lambda_alias_urls(
        self, lam: Any, fname: str, aliases: list[dict]
    ) -> dict[str, dict]:
        """Function URL configs keyed by the (alias) ARN they belong to."""
        urls: dict[str, dict] = {}
        try:
            async for u in self._paginate(
                lam, "list_function_url_configs", "FunctionUrlConfigs", FunctionName=fname
            ):
                urls[u.get("FunctionArn", "")] = u
        except Exception as exc:
            logger.debug("list_function_url_configs failed for %s: %s", fname, exc)
            for a in aliases:
                try:
                    u = await lam.get_function_url_config(FunctionName=fname, Qualifier=a["Name"])
                    urls[a.get("AliasArn", "")] = u
                except Exception as inner:
                    if error_code(inner) != "ResourceNotFoundException":
                        logger.debug(
                            "Alias URL lookup failed for %s:%s: %s", fname, a.get("Name"), inner
                        )
        return urls

    async def _lambda_alias_policy(self, lam: Any, fname: str, aname: str) -> tuple[list, bool]:
        """Alias-scoped resource-policy grants and whether they are public."""
        try:
            pol = await lam.get_policy(FunctionName=fname, Qualifier=aname)
            return _resource_policy_relations(pol.get("Policy"), self._account_id)
        except Exception as exc:
            if error_code(exc) != "ResourceNotFoundException":
                logger.debug("Alias policy read failed for %s:%s: %s", fname, aname, exc)
        return [], False

    async def _lambda_alias_asset(
        self, lam: Any, fn: dict, a: dict, urls: dict[str, dict]
    ) -> CloudAsset:
        fname, farn = fn.get("FunctionName", ""), fn.get("FunctionArn", "")
        aname = a.get("Name", "")
        aarn = a.get("AliasArn") or f"{farn}:{aname}"
        relations: list[dict | None] = [
            rel(farn, EdgeType.REFERENCES, "DEPENDS_ON", description=f"alias of {fname}")
        ]
        pol_rels, public_policy = await self._lambda_alias_policy(lam, fname, aname)
        relations.extend(pol_rels)
        url = urls.get(aarn) or {}
        weights = (a.get("RoutingConfig") or {}).get("AdditionalVersionWeights") or {}
        return self._asset(
            arn=aarn,
            name=f"{fname}:{aname}",
            asset_type=AssetType.LAMBDA_FUNCTION,
            metadata={
                "alias": True,
                "alias_name": aname,
                "function_name": fname,
                "function_arn": farn,
                "function_version": a.get("FunctionVersion"),
                "routing_weights": {str(k): v for k, v in weights.items()},
                "versions": sorted(
                    {a.get("FunctionVersion", ""), *(str(k) for k in weights)} - {""}
                ),
                "description": a.get("Description"),
                "function_url": url.get("FunctionUrl"),
                "function_url_auth": url.get("AuthType"),
                "policy_allows_public": public_policy,
            },
            relations=relations,
            exposed=url.get("AuthType") == "NONE" or public_policy,
            aliases=[url.get("FunctionUrl")],
        )

    async def _lambda_function_aliases(self, lam: Any, fn: dict) -> list[CloudAsset]:
        fname = fn.get("FunctionName", "")
        aliases = [
            a async for a in self._paginate(lam, "list_aliases", "Aliases", FunctionName=fname)
        ]
        if not aliases:
            return []
        urls = await self._lambda_alias_urls(lam, fname, aliases)
        return [await self._lambda_alias_asset(lam, fn, a, urls) for a in aliases]

    async def _collect_lambda_aliases(self) -> list[CloudAsset]:
        async with self._client("lambda") as lam:
            functions = [f async for f in self._paginate(lam, "list_functions", "Functions")]
            results = await gather_limited(
                [lambda f=f: self._lambda_function_aliases(lam, f) for f in functions]
            )
        return [a for r in results for a in (r or [])]
