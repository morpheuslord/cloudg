"""IAM extras: SAML providers, access keys (metadata only) and IAM Roles
Anywhere trust anchors and profiles."""

from __future__ import annotations

from typing import Any

from cloudg.inventory.aws_services._base import AWSServiceMixin, gather_limited, rel
from cloudg.inventory.aws_services.governance._common import (
    _MAX_ACCESS_KEY_USERS,
    _STALE_KEY_DAYS,
    _age_days,
    _take,
    _ts,
    logger,
)
from cloudg.schema.models import AssetType, CloudAsset, EdgeType


class IamExtrasCollectorsMixin(AWSServiceMixin):
    """SAML provider, access key and Roles Anywhere collectors."""

    async def _collect_iam_saml_providers(self) -> list[CloudAsset]:
        async with self._client("iam", region="us-east-1") as iam:
            resp = await iam.list_saml_providers()
        assets = []
        for p in resp.get("SAMLProviderList", []) or []:
            arn = p.get("Arn", "")
            name = arn.split("saml-provider/", 1)[-1]
            assets.append(
                self._asset(
                    arn=arn,
                    name=name,
                    asset_type=AssetType.IDENTITY_PROVIDER,
                    region="global",
                    metadata={
                        "provider_type": "saml",
                        "valid_until": _ts(p.get("ValidUntil")),
                        "created": _ts(p.get("CreateDate")),
                        "identity_center_managed": name.startswith("AWSSSO_"),
                    },
                    raw={k: str(v) for k, v in p.items()},
                )
            )
        return assets

    async def _collect_iam_access_keys(self) -> list[CloudAsset]:
        async with self._client("iam", region="us-east-1") as iam:
            users = await _take(self._paginate(iam, "list_users", "Users"), _MAX_ACCESS_KEY_USERS)
            if len(users) >= _MAX_ACCESS_KEY_USERS:
                logger.warning("Access key collection truncated at %d users", _MAX_ACCESS_KEY_USERS)
            results = await gather_limited(
                [lambda u=u: self._user_access_keys(iam, u) for u in users]
            )
        return [a for res in results if res for a in res]

    async def _user_access_keys(self, iam: Any, user: dict) -> list[CloudAsset]:
        out = []
        async for k in self._paginate(
            iam, "list_access_keys", "AccessKeyMetadata", UserName=user["UserName"]
        ):
            key_id = k.get("AccessKeyId")
            if not key_id:
                continue
            last: dict[str, Any] = {}
            try:
                last = (await iam.get_access_key_last_used(AccessKeyId=key_id)).get(
                    "AccessKeyLastUsed"
                ) or {}
            except Exception as exc:
                logger.debug("Last-used lookup for %s failed: %s", key_id, exc)
            out.append(self._access_key_asset(user, k, last))
        return out

    def _access_key_asset(self, user: dict, k: dict[str, Any], last: dict[str, Any]) -> CloudAsset:
        key_id = k["AccessKeyId"]
        last_date = last.get("LastUsedDate")
        unused_days = _age_days(last_date) if last_date else _age_days(k.get("CreateDate"))
        active = k.get("Status") == "Active"
        return self._asset(
            arn=f"cloudg:aws:iam::{self._account_id}:access-key/{key_id}",
            name=key_id,
            asset_type=AssetType.ACCESS_KEY,
            region="global",
            metadata={
                "access_key_id": key_id,
                "user_name": user["UserName"],
                "user_arn": user.get("Arn"),
                "status": k.get("Status"),
                "created": _ts(k.get("CreateDate")),
                "age_days": _age_days(k.get("CreateDate")),
                "last_used": _ts(last_date),
                "last_used_service": last.get("ServiceName"),
                "last_used_region": last.get("Region"),
                "never_used": last_date is None,
                "stale": bool(active and unused_days is not None and unused_days > _STALE_KEY_DAYS),
            },
            relations=[
                rel(
                    user.get("Arn"),
                    EdgeType.CONTAINS,
                    reverse=True,
                    description="access key of user",
                )
            ],
        )

    async def _collect_rolesanywhere(self) -> list[CloudAsset]:
        async with self._client("rolesanywhere") as ra:
            anchors = [a async for a in self._paginate(ra, "list_trust_anchors", "trustAnchors")]
            profiles = [p async for p in self._paginate(ra, "list_profiles", "profiles")]
        assets = [self._trust_anchor_asset(a) for a in anchors]
        enabled_anchors = [a.get("trustAnchorArn") for a in anchors if a.get("enabled")]
        assets += [self._rolesanywhere_profile_asset(p, enabled_anchors) for p in profiles]
        return assets

    def _trust_anchor_asset(self, a: dict[str, Any]) -> CloudAsset:
        source = a.get("source") or {}
        pca = (source.get("sourceData") or {}).get("acmPcaArn")
        return self._asset(
            arn=a.get("trustAnchorArn", ""),
            name=a.get("name") or a.get("trustAnchorId", ""),
            asset_type=AssetType.IDENTITY_PROVIDER,
            metadata={
                "provider_type": "x509_trust_anchor",
                "trust_anchor_id": a.get("trustAnchorId"),
                "enabled": a.get("enabled"),
                "source_type": source.get("sourceType"),
                "acm_pca_arn": pca,
                "created": _ts(a.get("createdAt")),
            },
            relations=[
                rel(pca, EdgeType.REFERENCES, "DEPENDS_ON", description="issuing private CA")
            ],
            aliases=[a.get("trustAnchorId")],
        )

    def _rolesanywhere_profile_asset(
        self, p: dict[str, Any], enabled_anchors: list[Any]
    ) -> CloudAsset:
        relations: list[dict | None] = [
            rel(
                r,
                EdgeType.ASSUMES_ROLE,
                "ROLE_ASSUMES_ROLE",
                description="Roles Anywhere profile role",
            )
            for r in p.get("roleArns") or []
        ]
        relations += [
            rel(
                m,
                EdgeType.IAM_POLICY_ATTACHMENT,
                "ROLE_HAS_POLICY",
                description="session policy",
            )
            for m in p.get("managedPolicyArns") or []
        ]
        if p.get("enabled"):
            relations += [
                rel(
                    anchor,
                    EdgeType.IAM_TRUST,
                    "ROLE_ASSUMES_ROLE",
                    reverse=True,
                    description="certificates from this trust anchor can use the profile",
                )
                for anchor in enabled_anchors[:50]
            ]
        return self._asset(
            arn=p.get("profileArn", ""),
            name=p.get("name") or p.get("profileId", ""),
            asset_type=AssetType.PERMISSION_SET,
            metadata={
                "profile_type": "rolesanywhere",
                "profile_id": p.get("profileId"),
                "enabled": p.get("enabled"),
                "role_arns": p.get("roleArns") or [],
                "managed_policy_arns": p.get("managedPolicyArns") or [],
                "has_session_policy": bool(p.get("sessionPolicy")),
                "duration_seconds": p.get("durationSeconds"),
                "require_instance_properties": p.get("requireInstanceProperties"),
                "accept_role_session_name": p.get("acceptRoleSessionName"),
            },
            relations=relations,
            aliases=[p.get("profileId")],
        )
