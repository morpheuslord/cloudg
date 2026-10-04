"""Network protection: WAFv2 web ACLs (-> PROTECTS ALBs, API Gateway stages,
CloudFront), Network Firewall (-> PROTECTS VPC / subnets) and Shield
Advanced protections."""

from __future__ import annotations

from typing import Any

from cloudg.inventory.aws_services._base import rel
from cloudg.inventory.aws_services.security._common import (
    SecurityServiceMixin,
    _not_enabled,
    logger,
)
from cloudg.schema.models import AssetType, CloudAsset, EdgeType

_WAF_RESOURCE_TYPES = (
    "APPLICATION_LOAD_BALANCER",
    "API_GATEWAY",
    "APPSYNC",
    "COGNITO_USER_POOL",
    "APP_RUNNER_SERVICE",
    "VERIFIED_ACCESS_INSTANCE",
    "AMPLIFY",
)


def _firewall_relations(firewall: dict) -> list[dict | None]:
    relations: list[dict | None] = [
        rel(firewall.get("VpcId"), EdgeType.PROTECTS, "PROTECTED_BY_NACL"),
        rel(
            firewall.get("TransitGatewayId"),
            EdgeType.PROTECTS,
            "PROTECTED_BY_NACL",
            description="transit gateway attached firewall",
        ),
        rel(firewall.get("FirewallPolicyArn"), EdgeType.REFERENCES, "DEPENDS_ON"),
    ]
    for m in firewall.get("SubnetMappings", []) or []:
        relations.append(
            rel(m.get("SubnetId"), EdgeType.CONTAINS, "SUBNET_CONTAINS_INSTANCE", reverse=True)
        )
    return relations


class NetworkProtectionCollectorsMixin(SecurityServiceMixin):
    async def _collect_wafv2(self) -> list[CloudAsset]:
        assets = await self._waf_acls("REGIONAL", self._region)
        if self._is_primary_region:
            try:
                assets.extend(await self._waf_acls("CLOUDFRONT", "us-east-1"))
            except Exception as exc:
                logger.debug("CloudFront-scope WAF listing failed: %s", exc)
        return assets

    async def _waf_acls(self, scope: str, region: str) -> list[CloudAsset]:
        assets: list[CloudAsset] = []
        async with self._client("wafv2", region=region) as waf:
            for acl in await self._waf_list_acls(waf, scope):
                default_action, rules = await self._waf_acl_rules(waf, acl, scope)
                relations = await self._waf_acl_targets(waf, acl) if scope == "REGIONAL" else []
                assets.append(
                    self._asset(
                        arn=acl["ARN"],
                        name=acl["Name"],
                        asset_type=AssetType.WAF_WEB_ACL,
                        region="global" if scope == "CLOUDFRONT" else region,
                        metadata={
                            "security_service": "wafv2",
                            "enabled": True,
                            "scope": scope,
                            "default_action": default_action,
                            "rules": rules,
                        },
                        relations=relations,
                        aliases=[acl.get("Id")],
                    )
                )
        return assets

    @staticmethod
    async def _waf_list_acls(waf: Any, scope: str) -> list[dict]:
        """Every web ACL of a scope (list_web_acls has no paginator)."""
        marker = None
        acls: list[dict] = []
        while True:
            kwargs: dict[str, Any] = {"Scope": scope, "Limit": 100}
            if marker:
                kwargs["NextMarker"] = marker
            resp = await waf.list_web_acls(**kwargs)
            acls.extend(resp.get("WebACLs", []))
            marker = resp.get("NextMarker")
            if not marker or not resp.get("WebACLs"):
                return acls

    @staticmethod
    async def _waf_acl_rules(waf: Any, acl: dict, scope: str) -> tuple[str | None, list[str]]:
        """The ACL's default action and its rule (or managed rule group) names."""
        rules: list[str] = []
        default_action = None
        try:
            detail = (await waf.get_web_acl(Name=acl["Name"], Scope=scope, Id=acl["Id"]))["WebACL"]
            default_action = next(iter(detail.get("DefaultAction") or {}), None)
            for r in detail.get("Rules", []) or []:
                managed = ((r.get("Statement") or {}).get("ManagedRuleGroupStatement") or {}).get(
                    "Name"
                )
                rules.append(managed or r.get("Name", ""))
        except Exception as exc:
            logger.debug("get_web_acl failed for %s: %s", acl.get("Name"), exc)
        return default_action, rules

    @staticmethod
    async def _waf_acl_targets(waf: Any, acl: dict) -> list[dict | None]:
        """PROTECTS relations to every regional resource the ACL is attached to."""
        relations: list[dict | None] = []
        for rtype in _WAF_RESOURCE_TYPES:
            try:
                res = await waf.list_resources_for_web_acl(WebACLArn=acl["ARN"], ResourceType=rtype)
                for arn in res.get("ResourceArns", []):
                    target = arn.split("/stages/", 1)[0] if rtype == "API_GATEWAY" else arn
                    relations.append(rel(target, EdgeType.PROTECTS, "PROTECTED_BY_WAF"))
            except Exception as exc:
                logger.debug("WAF resources (%s) unavailable: %s", rtype, exc)
        return relations

    async def _collect_network_firewall(self) -> list[CloudAsset]:
        assets: list[CloudAsset] = []
        async with self._client("network-firewall") as nfw:
            firewalls = [f async for f in self._paginate(nfw, "list_firewalls", "Firewalls")]
            for fw in firewalls:
                d = await nfw.describe_firewall(FirewallArn=fw["FirewallArn"])
                firewall = d.get("Firewall") or {}
                assets.append(
                    self._asset(
                        arn=fw["FirewallArn"],
                        name=fw.get("FirewallName", ""),
                        asset_type=AssetType.NETWORK_FIREWALL,
                        tags=firewall.get("Tags"),
                        metadata={
                            "security_service": "network-firewall",
                            "enabled": True,
                            "vpc_id": firewall.get("VpcId"),
                            "policy_arn": firewall.get("FirewallPolicyArn"),
                            "delete_protection": firewall.get("DeleteProtection"),
                        },
                        relations=_firewall_relations(firewall),
                    )
                )
        return assets

    async def _collect_shield(self) -> list[CloudAsset]:
        async with self._client("shield", region="us-east-1") as shield:
            try:
                sub = (await shield.describe_subscription()).get("Subscription") or {}
            except Exception as exc:
                if _not_enabled(exc):
                    return []  # Shield Standard only: nothing to map
                raise
            relations = [
                rel(
                    p.get("ResourceArn"),
                    EdgeType.PROTECTS,
                    "PROTECTED_BY_WAF",
                    description=f"Shield protection {p.get('Name')}",
                )
                async for p in self._paginate(shield, "list_protections", "Protections")
            ]
            return [
                self._asset(
                    arn=sub.get("SubscriptionArn")
                    or f"arn:aws:shield::{self._account_id}:subscription",
                    name="shield-advanced",
                    asset_type=AssetType.DDOS_PROTECTION,
                    region="global",
                    metadata={
                        "security_service": "shield",
                        "enabled": True,
                        "auto_renew": sub.get("AutoRenew"),
                        "proactive_engagement": sub.get("ProactiveEngagementStatus"),
                        "protections": len(relations),
                    },
                    relations=relations,
                )
            ]
