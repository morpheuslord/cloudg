"""S3 access points and Multi-Region Access Points."""

from __future__ import annotations

from typing import Any

from cloudg.inventory.aws_services._base import error_code, gather_limited, rel
from cloudg.inventory.aws_services.governance._common import (
    GovernanceHelpersMixin,
    _pab,
    _root,
    _ts,
    logger,
)
from cloudg.schema.models import AssetType, CloudAsset, EdgeType


def _access_point_view(ap: dict[str, Any], info: dict[str, Any]) -> dict[str, Any]:
    """Fields read from the listing entry, falling back to the describe call."""
    return {
        "origin": ap.get("NetworkOrigin") or info.get("NetworkOrigin"),
        "vpc_id": (ap.get("VpcConfiguration") or info.get("VpcConfiguration") or {}).get("VpcId"),
        "bucket": ap.get("Bucket") or info.get("Bucket"),
        "bucket_account": ap.get("BucketAccountId") or info.get("BucketAccountId"),
        "alias": ap.get("Alias") or info.get("Alias"),
    }


def _access_point_relations(
    view: dict[str, Any], acct: str, policy_rels: list[dict]
) -> list[dict | None]:
    bucket = view["bucket"]
    bucket_account = view["bucket_account"]
    relations: list[dict | None] = [
        rel(
            f"arn:aws:s3:::{bucket}" if bucket else None,
            EdgeType.REFERENCES,
            "READS_FROM",
            description="access point bucket",
            bucket_account=bucket_account,
        ),
        rel(view["vpc_id"], EdgeType.ATTACHED_TO, description="VPC-restricted access point"),
        *policy_rels,
    ]
    if bucket_account and bucket_account != acct:
        relations.append(
            rel(
                _root(bucket_account),
                EdgeType.REFERENCES,
                "CROSS_ACCOUNT_TRUST",
                description="cross-account bucket owner",
            )
        )
    return relations


class S3AccessPointCollectorsMixin(GovernanceHelpersMixin):
    """S3 access point and Multi-Region Access Point collectors."""

    async def _account_public_access_block(self, s3c: Any) -> dict[str, bool] | None:
        try:
            resp = await s3c.get_public_access_block(AccountId=self._account_id)
            return _pab(resp.get("PublicAccessBlockConfiguration") or {})
        except Exception as exc:
            if error_code(exc) == "NoSuchPublicAccessBlockConfiguration":
                return _pab({})
            logger.debug("Account public access block lookup failed: %s", exc)
            return None

    async def _collect_s3_access_points(self) -> list[CloudAsset]:
        if not self._account_id:
            raise ValueError("account_id is required for S3 Control")
        acct = self._account_id
        async with self._client("s3control") as s3c:
            account_pab = await self._account_public_access_block(s3c)
            points = [
                p
                async for p in self._pages(
                    s3c.list_access_points, "AccessPointList", AccountId=acct
                )
            ]
            results = await gather_limited(
                [lambda p=p: self._access_point_asset(s3c, p, account_pab) for p in points]
            )
        return [a for a in results if a]

    async def _access_point_status(
        self, s3c: Any, acct: str, name: str
    ) -> tuple[dict[str, Any], bool | None]:
        """Access point description and whether its policy is public."""
        info: dict[str, Any] = {}
        try:
            info = await s3c.get_access_point(AccountId=acct, Name=name)
        except Exception as exc:
            logger.debug("Access point %s describe failed: %s", name, exc)
        policy_public = None
        try:
            status = await s3c.get_access_point_policy_status(AccountId=acct, Name=name)
            policy_public = bool((status.get("PolicyStatus") or {}).get("IsPublic"))
        except Exception as exc:
            logger.debug("Access point %s policy status failed: %s", name, exc)
        return info, policy_public

    async def _access_point_asset(
        self, s3c: Any, ap: dict, account_pab: dict[str, bool] | None
    ) -> CloudAsset:
        acct = self._account_id or ""
        name = ap["Name"]
        info, policy_public = await self._access_point_status(s3c, acct, name)
        policy_rels, policy_info = await self._policy_access(
            lambda: s3c.get_access_point_policy(AccountId=acct, Name=name),
            "Policy",
            ("Access point %s policy failed: %s", name),
            quiet_code="NoSuchAccessPointPolicy",
        )
        ap_pab = _pab(info.get("PublicAccessBlockConfiguration"))
        view = _access_point_view(ap, info)
        restricted = any(p and p.get("RestrictPublicBuckets") for p in (account_pab, ap_pab))
        public = bool(
            view["origin"] == "Internet" and (policy_public or policy_info.get("public_policy"))
        )
        return self._asset(
            arn=ap.get("AccessPointArn") or self._arn("s3", f"accesspoint/{name}"),
            name=name,
            asset_type=AssetType.ACCESS_POINT,
            metadata={
                "endpoint_kind": "s3_access_point",
                "bucket": view["bucket"],
                "bucket_account_id": view["bucket_account"],
                "network_origin": view["origin"],
                "vpc_id": view["vpc_id"],
                "alias": view["alias"],
                "data_source_type": ap.get("DataSourceType"),
                "policy_public": policy_public,
                "public_access_block": ap_pab,
                "account_public_access_block": account_pab,
                "restricted_by_public_access_block": restricted,
                "created": _ts(info.get("CreationDate")),
                **policy_info,
            },
            relations=_access_point_relations(view, acct, policy_rels),
            raw=ap,
            exposed=public and not restricted,
            aliases=[view["alias"]],
        )

    async def _collect_s3_multi_region_access_points(self) -> list[CloudAsset]:
        if not self._account_id:
            raise ValueError("account_id is required for S3 Control")
        acct = self._account_id
        # The Multi-Region Access Point control plane lives in us-west-2
        async with self._client("s3control", region="us-west-2") as s3c:
            points = [
                p
                async for p in self._pages(
                    s3c.list_multi_region_access_points, "AccessPoints", AccountId=acct
                )
            ]
        return [self._multi_region_access_point_asset(acct, p) for p in points]

    def _multi_region_access_point_asset(self, acct: str, p: dict[str, Any]) -> CloudAsset:
        alias = p.get("Alias") or p.get("Name", "")
        regions = p.get("Regions") or []
        return self._asset(
            arn=f"arn:aws:s3::{acct}:accesspoint/{alias}",
            name=p.get("Name") or alias,
            asset_type=AssetType.ACCESS_POINT,
            region="global",
            metadata={
                "endpoint_kind": "s3_multi_region_access_point",
                "alias": alias,
                "status": p.get("Status"),
                "created": _ts(p.get("CreatedAt")),
                "public_access_block": _pab(p.get("PublicAccessBlock")),
                "regions": [r.get("Region") for r in regions],
                "buckets": [r.get("Bucket") for r in regions],
            },
            relations=[
                rel(
                    f"arn:aws:s3:::{r['Bucket']}",
                    EdgeType.REFERENCES,
                    "READS_FROM",
                    description="Multi-Region Access Point bucket",
                    region=r.get("Region"),
                    bucket_account=r.get("BucketAccountId"),
                )
                for r in regions
                if r.get("Bucket")
            ],
            raw=p,
            aliases=[alias],
        )
