"""Service Catalog portfolios and provisioned products (Control Tower
Account Factory): product MANAGES the vended account and its stack."""

from __future__ import annotations

from typing import Any

from cloudg.inventory.aws_services._base import AWSServiceMixin, gather_limited, rel
from cloudg.inventory.aws_services.governance._common import (
    _ACCOUNT_RE,
    _CT_ACCOUNT_FACTORY_PRODUCT,
    _root,
    _ts,
    logger,
)
from cloudg.schema.models import AssetType, CloudAsset, EdgeType


def _portfolio_relations(principals: list[dict], shared: list[str]) -> list[dict | None]:
    relations: list[dict | None] = [
        rel(
            p.get("PrincipalARN"),
            EdgeType.GRANTS_ACCESS,
            "POLICY_ALLOWS_ACTION",
            reverse=True,
            description="portfolio principal",
            principal_type=p.get("PrincipalType"),
        )
        for p in principals
        if "*" not in str(p.get("PrincipalARN", ""))
    ]
    relations += [
        rel(
            _root(a),
            EdgeType.GRANTS_ACCESS,
            "CROSS_ACCOUNT_TRUST",
            reverse=True,
            description="portfolio share",
        )
        for a in shared
        if _ACCOUNT_RE.match(str(a))
    ]
    return relations


def _provisioned_product_relations(
    pp: dict[str, Any],
    outputs: tuple[list[str], str | None, list[str]],
    launch_role: str | None,
    portfolios_by_product: dict[str, list[str]],
) -> list[dict | None]:
    _, vended_account, output_refs = outputs
    physical = pp.get("PhysicalId") or ""
    stack_arn = physical if physical.startswith("arn:aws:cloudformation:") else None
    relations: list[dict | None] = [
        rel(
            _root(vended_account) if vended_account else None,
            EdgeType.MANAGES,
            "OWNED_BY",
            description="vended account",
        ),
        rel(stack_arn, EdgeType.MANAGES, "OWNED_BY", description="provisioned stack"),
        rel(launch_role, EdgeType.ASSUMES_ROLE, "RUNS_ON", description="launch constraint role"),
    ]
    relations += [
        rel(r, EdgeType.REFERENCES, "DEPENDS_ON", description="product output")
        for r in output_refs[:20]
    ]
    relations += [
        rel(pf, EdgeType.REFERENCES, "DEPENDS_ON", description="launched from portfolio")
        for pf in portfolios_by_product.get(pp.get("ProductId", ""), [])
    ]
    return relations


class ServiceCatalogCollectorsMixin(AWSServiceMixin):
    """Service Catalog portfolio and provisioned product collectors."""

    async def _portfolio_access(self, sc: Any, pid: str) -> tuple[list[dict], list[str]]:
        """Principals of a portfolio and the accounts it is shared with."""
        principals: list[dict] = []
        shared: list[str] = []
        try:
            principals = [
                p
                async for p in self._paginate(
                    sc, "list_principals_for_portfolio", "Principals", PortfolioId=pid
                )
            ]
        except Exception as exc:
            logger.debug("Portfolio %s principals failed: %s", pid, exc)
        try:
            shared = [
                a
                async for a in self._pages(
                    sc.list_portfolio_access,
                    "AccountIds",
                    token_in="PageToken",
                    token_out="NextPageToken",
                    PortfolioId=pid,
                )
            ]
        except Exception as exc:
            logger.debug("Portfolio %s access failed: %s", pid, exc)
        return principals, shared

    async def _portfolio_products(self, sc: Any, pid: str) -> tuple[set[str], list[str]]:
        product_ids: set[str] = set()
        product_names: list[str] = []
        try:
            async for p in self._paginate(
                sc, "search_products_as_admin", "ProductViewDetails", PortfolioId=pid
            ):
                summary = p.get("ProductViewSummary") or {}
                if summary.get("ProductId"):
                    product_ids.add(summary["ProductId"])
                if summary.get("Name"):
                    product_names.append(summary["Name"])
        except Exception as exc:
            logger.debug("Portfolio %s products failed: %s", pid, exc)
        return product_ids, product_names

    async def _portfolio_asset(self, sc: Any, pf: dict[str, Any]) -> tuple[CloudAsset, set[str]]:
        pid = pf.get("Id", "")
        principals, shared = await self._portfolio_access(sc, pid)
        product_ids, product_names = await self._portfolio_products(sc, pid)
        name = pf.get("DisplayName") or pid
        asset = self._asset(
            arn=pf.get("ARN") or self._arn("catalog", f"portfolio/{pid}"),
            name=name,
            asset_type=AssetType.PRODUCT_PORTFOLIO,
            metadata={
                "portfolio_id": pid,
                "provider": pf.get("ProviderName"),
                "description": pf.get("Description"),
                "created": _ts(pf.get("CreatedTime")),
                "principals": [p.get("PrincipalARN") for p in principals],
                "shared_accounts": shared,
                "products": sorted(product_names),
                "control_tower": "Control Tower" in name
                or _CT_ACCOUNT_FACTORY_PRODUCT in product_names,
            },
            relations=_portfolio_relations(principals, shared),
            aliases=[pid],
        )
        return asset, product_ids

    async def _provisioned_product_outputs(
        self, sc: Any, pp_id: str
    ) -> tuple[list[str], str | None, list[str]]:
        """Output keys, the vended account ID and ARN-valued outputs."""
        output_keys: list[str] = []
        vended_account = None
        output_refs: list[str] = []
        try:
            async for o in self._pages(
                sc.get_provisioned_product_outputs,
                "Outputs",
                token_in="PageToken",
                token_out="NextPageToken",
                ProvisionedProductId=pp_id,
            ):
                key = o.get("OutputKey") or ""
                value = str(o.get("OutputValue") or "")
                output_keys.append(key)
                # Only identifiers are kept; arbitrary output values are not.
                if key.lower() == "accountid" and _ACCOUNT_RE.match(value):
                    vended_account = value
                elif value.startswith("arn:aws"):
                    output_refs.append(value)
        except Exception as exc:
            logger.debug("Provisioned product %s outputs failed: %s", pp_id, exc)
        return output_keys, vended_account, output_refs

    async def _provisioned_product_asset(
        self, sc: Any, pp: dict[str, Any], portfolios_by_product: dict[str, list[str]]
    ) -> CloudAsset:
        pp_id = pp.get("Id", "")
        launch_role = None
        try:
            detail = (await sc.describe_provisioned_product(Id=pp_id)).get(
                "ProvisionedProductDetail"
            ) or {}
            launch_role = detail.get("LaunchRoleArn")
        except Exception as exc:
            logger.debug("Provisioned product %s describe failed: %s", pp_id, exc)
        outputs = await self._provisioned_product_outputs(sc, pp_id)
        return self._asset(
            arn=pp.get("Arn")
            or self._arn("servicecatalog", f"stack/{pp.get('Name', pp_id)}/{pp_id}"),
            name=pp.get("Name") or pp_id,
            asset_type=AssetType.PROVISIONED_PRODUCT,
            tags=pp.get("Tags"),
            metadata={
                "provisioned_product_id": pp_id,
                "type": pp.get("Type"),
                "status": pp.get("Status"),
                "product_id": pp.get("ProductId"),
                "product_name": pp.get("ProductName"),
                "provisioning_artifact": pp.get("ProvisioningArtifactName"),
                "created": _ts(pp.get("CreatedTime")),
                "provisioned_by": pp.get("UserArn"),
                "physical_id": pp.get("PhysicalId") or "",
                "launch_role": launch_role,
                "output_keys": outputs[0],
                "vended_account_id": outputs[1],
                "control_tower_account_factory": pp.get("ProductName")
                == _CT_ACCOUNT_FACTORY_PRODUCT,
            },
            relations=_provisioned_product_relations(
                pp, outputs, launch_role, portfolios_by_product
            ),
            aliases=[pp_id],
        )

    async def _collect_service_catalog(self) -> list[CloudAsset]:
        assets: list[CloudAsset] = []
        failures: list[BaseException] = []
        portfolios_by_product: dict[str, list[str]] = {}
        async with self._client("servicecatalog") as sc:
            try:
                portfolios = [
                    p async for p in self._paginate(sc, "list_portfolios", "PortfolioDetails")
                ]
                results = await gather_limited(
                    [lambda p=p: self._portfolio_asset(sc, p) for p in portfolios], limit=4
                )
                for res in results:
                    if not res:
                        continue
                    asset, product_ids = res
                    assets.append(asset)
                    for prod in product_ids:
                        portfolios_by_product.setdefault(prod, []).append(asset.arn or "")
            except Exception as exc:
                failures.append(exc)
                logger.debug("Service Catalog portfolio listing failed: %s", exc)
            try:
                assets.extend(await self._provisioned_product_assets(sc, portfolios_by_product))
            except Exception as exc:
                failures.append(exc)
                logger.debug("Service Catalog provisioned product search failed: %s", exc)
        if len(failures) == 2:
            raise failures[0]
        return assets

    async def _provisioned_product_assets(
        self, sc: Any, portfolios_by_product: dict[str, list[str]]
    ) -> list[CloudAsset]:
        products = [
            p
            async for p in self._pages(
                sc.search_provisioned_products,
                "ProvisionedProducts",
                token_in="PageToken",
                token_out="NextPageToken",
                AccessLevelFilter={"Key": "Account", "Value": "self"},
            )
        ]
        results = await gather_limited(
            [
                lambda p=p: self._provisioned_product_asset(sc, p, portfolios_by_product)
                for p in products
            ],
            limit=4,
        )
        return [a for a in results if a]
