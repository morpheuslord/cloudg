"""Cognito user pools (Lambda triggers, SMS role) and identity pools
(authenticated / unauthenticated roles)."""

from __future__ import annotations

from typing import Any

from cloudg.inventory.aws_services._base import AWSServiceMixin, arns_in, gather_limited, rel
from cloudg.inventory.aws_services.governance._common import (
    _COGNITO_TRIGGERS,
    _COGNITO_VERSIONED_TRIGGERS,
    _ts,
    logger,
)
from cloudg.schema.models import AssetType, CloudAsset, EdgeType


def _user_pool_triggers(lambdas: dict[str, Any]) -> dict[str, str]:
    """Trigger name -> Lambda ARN, including the versioned trigger configs."""
    triggers: dict[str, str] = {k: lambdas[k] for k in _COGNITO_TRIGGERS if lambdas.get(k)}
    for k in _COGNITO_VERSIONED_TRIGGERS:
        fn = (lambdas.get(k) or {}).get("LambdaArn")
        if fn:
            triggers[k] = fn
    return triggers


def _user_pool_relations(
    pool: dict[str, Any], lambdas: dict[str, Any], triggers: dict[str, str]
) -> list[dict | None]:
    sms = pool.get("SmsConfiguration") or {}
    email = pool.get("EmailConfiguration") or {}
    relations: list[dict | None] = [
        rel(
            fn,
            EdgeType.INVOKES,
            "INVOKES",
            description=f"{trigger} trigger",
            trigger=trigger,
        )
        for trigger, fn in triggers.items()
    ]
    relations += [
        rel(
            sms.get("SnsCallerArn"),
            EdgeType.ASSUMES_ROLE,
            "RUNS_ON",
            description="SMS sender role",
        ),
        rel(lambdas.get("KMSKeyID"), EdgeType.REFERENCES, "ENCRYPTED_BY_KMS"),
        rel(
            email.get("SourceArn"),
            EdgeType.REFERENCES,
            "DEPENDS_ON",
            description="SES identity",
        ),
    ]
    return relations


def _identity_pool_relations(
    pool: dict[str, Any], roles: dict[str, Any], mapping_roles: list[str]
) -> list[dict | None]:
    relations: list[dict | None] = [
        rel(
            roles.get("authenticated"),
            EdgeType.ASSUMES_ROLE,
            "ROLE_ASSUMES_ROLE",
            description="authenticated identities role",
            identity_type="authenticated",
        ),
        rel(
            roles.get("unauthenticated"),
            EdgeType.ASSUMES_ROLE,
            "ROLE_ASSUMES_ROLE",
            description="unauthenticated (guest) identities role",
            identity_type="unauthenticated",
        ),
    ]
    relations += [
        rel(r, EdgeType.ASSUMES_ROLE, "ROLE_ASSUMES_ROLE", description="role mapping rule")
        for r in mapping_roles[:50]
    ]
    relations += [
        rel(
            provider.get("ProviderName"),
            EdgeType.REFERENCES,
            "DEPENDS_ON",
            description="Cognito user pool provider",
            client_id=provider.get("ClientId"),
        )
        for provider in pool.get("CognitoIdentityProviders") or []
    ]
    relations += [
        rel(p, EdgeType.REFERENCES, "DEPENDS_ON", description="federated identity provider")
        for p in (pool.get("OpenIdConnectProviderARNs") or [])
        + (pool.get("SamlProviderARNs") or [])
    ]
    return relations


class CognitoCollectorsMixin(AWSServiceMixin):
    """Cognito user pool and identity pool collectors."""

    async def _collect_cognito_user_pools(self) -> list[CloudAsset]:
        async with self._client("cognito-idp") as idp:
            pools = [
                p async for p in self._paginate(idp, "list_user_pools", "UserPools", MaxResults=60)
            ]
            results = await gather_limited(
                [lambda p=p: self._user_pool_asset(idp, p) for p in pools], limit=4
            )
        return [a for a in results if a]

    async def _user_pool_clients(self, idp: Any, pool_id: str) -> tuple[int, list[dict]]:
        """App client count and federated identity providers of a user pool."""
        clients = 0
        try:
            async for _ in self._paginate(
                idp, "list_user_pool_clients", "UserPoolClients", UserPoolId=pool_id
            ):
                clients += 1
        except Exception as exc:
            logger.debug("User pool %s clients failed: %s", pool_id, exc)
        providers: list[dict] = []
        try:
            providers = [
                p
                async for p in self._paginate(
                    idp, "list_identity_providers", "Providers", UserPoolId=pool_id
                )
            ]
        except Exception as exc:
            logger.debug("User pool %s identity providers failed: %s", pool_id, exc)
        return clients, providers

    async def _user_pool_asset(self, idp: Any, summary: dict) -> CloudAsset:
        pool_id = summary["Id"]
        pool = (await idp.describe_user_pool(UserPoolId=pool_id)).get("UserPool") or {}
        clients, providers = await self._user_pool_clients(idp, pool_id)
        lambdas = pool.get("LambdaConfig") or summary.get("LambdaConfig") or {}
        triggers = _user_pool_triggers(lambdas)
        arn = pool.get("Arn") or self._arn("cognito-idp", f"userpool/{pool_id}")
        admin_only = (pool.get("AdminCreateUserConfig") or {}).get("AllowAdminCreateUserOnly")
        return self._asset(
            arn=arn,
            name=pool.get("Name") or summary.get("Name") or pool_id,
            asset_type=AssetType.USER_POOL,
            tags=pool.get("UserPoolTags"),
            metadata={
                "user_pool_id": pool_id,
                "status": pool.get("Status"),
                "mfa": pool.get("MfaConfiguration"),
                "deletion_protection": pool.get("DeletionProtection"),
                "estimated_users": pool.get("EstimatedNumberOfUsers"),
                "self_signup_enabled": admin_only is False,
                "advanced_security": (pool.get("UserPoolAddOns") or {}).get("AdvancedSecurityMode"),
                "domain": pool.get("Domain"),
                "custom_domain": pool.get("CustomDomain"),
                "tier": pool.get("UserPoolTier"),
                "lambda_triggers": triggers,
                "app_client_count": clients,
                "identity_providers": [
                    {"name": p.get("ProviderName"), "type": p.get("ProviderType")}
                    for p in providers
                ],
                "created": _ts(pool.get("CreationDate")),
            },
            relations=_user_pool_relations(pool, lambdas, triggers),
            exposed=bool(admin_only is False),
            aliases=[pool_id, f"cognito-idp.{self._region}.amazonaws.com/{pool_id}"],
        )

    async def _collect_cognito_identity_pools(self) -> list[CloudAsset]:
        async with self._client("cognito-identity") as ci:
            pools = [
                p
                async for p in self._paginate(
                    ci, "list_identity_pools", "IdentityPools", MaxResults=60
                )
            ]
            results = await gather_limited(
                [lambda p=p: self._identity_pool_asset(ci, p) for p in pools], limit=4
            )
        return [a for a in results if a]

    async def _identity_pool_asset(self, ci: Any, summary: dict) -> CloudAsset:
        pool_id = summary["IdentityPoolId"]
        pool = await ci.describe_identity_pool(IdentityPoolId=pool_id)
        roles: dict[str, Any] = {}
        mapping_roles: list[str] = []
        try:
            resp = await ci.get_identity_pool_roles(IdentityPoolId=pool_id)
            roles = resp.get("Roles") or {}
            mapping_roles = [a for a in arns_in(resp.get("RoleMappings") or {}) if ":role/" in a]
        except Exception as exc:
            logger.debug("Identity pool %s roles failed: %s", pool_id, exc)
        unauth = bool(pool.get("AllowUnauthenticatedIdentities"))
        unauth_role = roles.get("unauthenticated")
        return self._asset(
            arn=self._arn("cognito-identity", f"identitypool/{pool_id}"),
            name=pool.get("IdentityPoolName") or summary.get("IdentityPoolName") or pool_id,
            asset_type=AssetType.IDENTITY_POOL,
            tags=pool.get("IdentityPoolTags"),
            metadata={
                "identity_pool_id": pool_id,
                "allow_unauthenticated": unauth,
                "allow_classic_flow": pool.get("AllowClassicFlow"),
                "authenticated_role": roles.get("authenticated"),
                "unauthenticated_role": unauth_role,
                "login_providers": sorted((pool.get("SupportedLoginProviders") or {}).keys()),
                "developer_provider": pool.get("DeveloperProviderName"),
                "cognito_providers": [
                    p.get("ProviderName") for p in pool.get("CognitoIdentityProviders") or []
                ],
            },
            relations=_identity_pool_relations(pool, roles, mapping_roles),
            exposed=bool(unauth and unauth_role),
            aliases=[pool_id],
        )
