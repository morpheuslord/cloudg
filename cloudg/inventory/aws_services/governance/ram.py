"""AWS RAM resource shares (owned and received): principal -> share ->
shared resource (GRANTS_ACCESS)."""

from __future__ import annotations

from typing import Any

from cloudg.inventory.aws_services._base import AWSServiceMixin, rel
from cloudg.inventory.aws_services.governance._common import (
    _arn_account,
    _principal_target,
    _root,
    _trust_kind,
    _ts,
    logger,
)
from cloudg.schema.models import AssetType, CloudAsset, EdgeType


def _shared_resource_relations(shared: list[dict]) -> list[dict | None]:
    return [
        rel(
            r.get("arn"),
            EdgeType.GRANTS_ACCESS,
            "DEPENDS_ON",
            description="shared resource",
            resource_type=r.get("type"),
            status=r.get("status"),
            region_scope=r.get("resourceRegionScope"),
        )
        for r in shared
    ]


def _share_principal_relations(prins: list[dict], owning: Any) -> tuple[list[dict | None], bool]:
    """Principal relations of a share, plus whether any principal is external."""
    relations: list[dict | None] = []
    external = False
    for p in prins:
        pid = str(p.get("id", ""))
        target = _principal_target(pid)
        acct = _arn_account(target or "")
        other = (
            bool(p.get("external"))
            or (acct is not None and acct != owning)
            or ":organizations:" in pid
        )
        external = external or bool(p.get("external"))
        relations.append(
            rel(
                target,
                EdgeType.GRANTS_ACCESS,
                _trust_kind(other),
                reverse=True,
                description="resource share principal",
                external=p.get("external"),
            )
        )
    return relations, external


class RamCollectorsMixin(AWSServiceMixin):
    """AWS RAM resource share collector."""

    async def _collect_ram_shares(self) -> list[CloudAsset]:
        assets: list[CloudAsset] = []
        async with self._client("ram") as ram:
            for owner in ("SELF", "OTHER-ACCOUNTS"):
                try:
                    shares = [
                        s
                        async for s in self._paginate(
                            ram, "get_resource_shares", "resourceShares", resourceOwner=owner
                        )
                    ]
                except Exception:
                    if owner == "SELF":
                        raise
                    logger.debug("RAM shares received from other accounts unavailable")
                    continue
                if not shares:
                    continue
                resources, principals = await self._ram_share_members(ram, owner)
                for share in shares:
                    assets.append(self._ram_share_asset(share, owner, resources, principals))
        return assets

    async def _ram_share_members(
        self, ram: Any, owner: str
    ) -> tuple[dict[str, list[dict]], dict[str, list[dict]]]:
        """Shared resources and principals, keyed by share ARN."""
        resources: dict[str, list[dict]] = {}
        principals: dict[str, list[dict]] = {}
        try:
            async for r in self._paginate(ram, "list_resources", "resources", resourceOwner=owner):
                resources.setdefault(r.get("resourceShareArn", ""), []).append(r)
        except Exception as exc:
            logger.debug("RAM resource listing (%s) failed: %s", owner, exc)
        try:
            async for p in self._paginate(
                ram, "list_principals", "principals", resourceOwner=owner
            ):
                principals.setdefault(p.get("resourceShareArn", ""), []).append(p)
        except Exception as exc:
            logger.debug("RAM principal listing (%s) failed: %s", owner, exc)
        return resources, principals

    def _ram_share_asset(
        self,
        share: dict[str, Any],
        owner: str,
        resources: dict[str, list[dict]],
        principals: dict[str, list[dict]],
    ) -> CloudAsset:
        arn = share.get("resourceShareArn", "")
        owning = share.get("owningAccountId") or self._account_id
        incoming = owner != "SELF"
        shared = resources.get(arn, [])
        prins = principals.get(arn, [])
        principal_rels, external = _share_principal_relations(prins, owning)
        relations = _shared_resource_relations(shared) + principal_rels
        if incoming and owning:
            relations.append(
                rel(
                    _root(owning),
                    EdgeType.MANAGES,
                    "OWNED_BY",
                    reverse=True,
                    description="share owner",
                )
            )
        # Received shares stay attributed to the observing account; the owner
        # is recorded in metadata and linked (MANAGES) so it materialises.
        return self._asset(
            arn=arn,
            name=share.get("name") or arn.rsplit("/", 1)[-1],
            asset_type=AssetType.RESOURCE_SHARE,
            tags=share.get("tags"),
            metadata={
                "direction": "incoming" if incoming else "outgoing",
                "owning_account_id": owning,
                "status": share.get("status"),
                "allow_external_principals": share.get("allowExternalPrincipals"),
                "feature_set": share.get("featureSet"),
                "created": _ts(share.get("creationTime")),
                "resource_count": len(shared),
                "resource_types": sorted({r.get("type") for r in shared if r.get("type")}),
                "principals": sorted({str(p.get("id")) for p in prins if p.get("id")})[:100],
                "external_principals": external,
                **({"discovered_via": "ram-incoming"} if incoming else {}),
            },
            relations=relations,
            raw={k: v for k, v in share.items() if k != "tags"},
        )
