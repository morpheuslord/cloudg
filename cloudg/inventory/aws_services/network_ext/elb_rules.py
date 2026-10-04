"""ELBv2 listeners and listener rules (forward / authenticate / redirect)
plus mTLS trust stores. OIDC client secrets are never collected."""

from __future__ import annotations

from typing import Any

from cloudg.inventory.aws_services._base import rel
from cloudg.inventory.aws_services.network_ext._common import (
    _MAX_RULES_PER_LISTENER,
    NetworkExtBase,
    _unique,
    logger,
    section,
)
from cloudg.schema.models import AssetType, CloudAsset, EdgeType


def _listener_routing(default_actions: list[dict], rules: list[dict]) -> dict[str, Any]:
    """Authentication, forward targets and HTTPS redirect of a listener."""
    all_actions = default_actions + [a for r in rules for a in r["actions"]]
    auth_types = sorted(
        {a["type"] for a in all_actions if str(a.get("type", "")).startswith("authenticate-")}
    )
    return {
        "authenticated": bool(auth_types),
        "auth_types": auth_types,
        "redirects_to_https": any(
            a.get("type") == "redirect" and (a.get("redirect") or {}).get("protocol") == "HTTPS"
            for a in default_actions
        ),
        "target_groups": list(
            dict.fromkeys(t for a in all_actions for t in a.get("target_groups", []))
        ),
    }


class ElbRulesCollectorsMixin(NetworkExtBase):
    @staticmethod
    def _elb_actions(actions: list[dict], where: str, relations: list[dict | None]) -> list[dict]:
        """Summarise listener / rule actions (no secrets) and record the
        target groups, user pools and redirects they lead to."""
        out = []
        for a in sorted(actions or [], key=lambda x: x.get("Order") or 0):
            atype = a.get("Type")
            item: dict[str, Any] = {"type": atype}
            tgs = [a.get("TargetGroupArn")] + [
                t.get("TargetGroupArn")
                for t in (a.get("ForwardConfig") or {}).get("TargetGroups") or []
            ]
            tgs = list(dict.fromkeys(t for t in tgs if t))
            if tgs:
                item["target_groups"] = tgs
                relations.extend(
                    rel(t, EdgeType.ROUTE, "SERVES_TRAFFIC_TO", description=f"forward ({where})")
                    for t in tgs
                )
            cognito = a.get("AuthenticateCognitoConfig") or {}
            if cognito:
                item["user_pool"] = cognito.get("UserPoolArn")
                item["on_unauthenticated"] = cognito.get("OnUnauthenticatedRequest")
                relations.append(
                    rel(
                        cognito.get("UserPoolArn"),
                        EdgeType.REFERENCES,
                        "DEPENDS_ON",
                        description=f"authenticate-cognito ({where})",
                    )
                )
            oidc = a.get("AuthenticateOidcConfig") or {}
            if oidc:
                item["issuer"] = oidc.get("Issuer")
                item["on_unauthenticated"] = oidc.get("OnUnauthenticatedRequest")
            redirect = a.get("RedirectConfig") or {}
            if redirect:
                item["redirect"] = {
                    k.lower(): redirect.get(k)
                    for k in ("Protocol", "Host", "Port", "Path", "StatusCode")
                }
            fixed = a.get("FixedResponseConfig") or {}
            if fixed:
                item["status_code"] = fixed.get("StatusCode")
            out.append(item)
        return out

    @staticmethod
    def _elb_conditions(conditions: list[dict]) -> dict[str, Any]:
        out: dict[str, Any] = {}
        for c in conditions or []:
            field = c.get("Field")
            if field == "host-header":
                out["hosts"] = (
                    (c.get("HostHeaderConfig") or {}).get("Values") or c.get("Values") or []
                )
            elif field == "path-pattern":
                out["paths"] = (
                    (c.get("PathPatternConfig") or {}).get("Values") or c.get("Values") or []
                )
            elif field == "http-header":
                out.setdefault("headers", []).append(
                    (c.get("HttpHeaderConfig") or {}).get("HttpHeaderName")
                )
            elif field == "http-request-method":
                out["methods"] = (c.get("HttpRequestMethodConfig") or {}).get("Values") or []
            elif field == "source-ip":
                out["source_ips"] = (c.get("SourceIpConfig") or {}).get("Values") or []
            elif field == "query-string":
                out["query_conditions"] = len(
                    (c.get("QueryStringConfig") or {}).get("Values") or []
                )
        return out

    async def _collect_elb_rules(self) -> list[CloudAsset]:
        """One asset per ALB/NLB/GWLB listener carrying its (rule-level)
        routing: forward targets, authentication, redirects, mTLS."""
        async with self._client("elbv2") as elb:
            return await self._nx_sections(
                section("listeners", self._elb_listeners, elb),
                section("trust_stores", self._elb_trust_stores, elb),
            )

    async def _elb_listeners(self, elb: Any) -> list[CloudAsset]:
        lbs = [lb async for lb in self._paginate(elb, "describe_load_balancers", "LoadBalancers")]
        return await self._nx_each_flat(self._elb_lb_listeners, lbs, elb)

    async def _elb_lb_listeners(self, elb: Any, lb: dict) -> list[CloudAsset]:
        out = []
        async for listener in self._paginate(
            elb, "describe_listeners", "Listeners", LoadBalancerArn=lb["LoadBalancerArn"]
        ):
            out.append(await self._elb_listener_asset(elb, lb, listener))
        return out

    async def _elb_trust_stores(self, elb: Any) -> list[CloudAsset]:
        out = []
        async for ts in self._paginate(elb, "describe_trust_stores", "TrustStores"):
            out.append(
                self._asset(
                    arn=ts["TrustStoreArn"],
                    name=ts.get("Name") or ts["TrustStoreArn"],
                    asset_type=AssetType.CERTIFICATE,
                    metadata={
                        "resource_kind": "elb_trust_store",
                        "status": ts.get("Status"),
                        "ca_certificates": ts.get("NumberOfCaCertificates"),
                        "revoked_entries": ts.get("TotalRevokedEntries"),
                    },
                )
            )
        return out

    async def _elb_listener_rules(
        self, elb: Any, arn: str, relations: list[dict | None]
    ) -> list[dict]:
        """Non-default rules of an ALB listener (capped)."""
        rules: list[dict] = []
        try:
            async for r in self._paginate(elb, "describe_rules", "Rules", ListenerArn=arn):
                if r.get("IsDefault"):
                    continue
                if len(rules) >= _MAX_RULES_PER_LISTENER:
                    break
                rules.append(
                    {
                        "priority": r.get("Priority"),
                        **self._elb_conditions(r.get("Conditions") or []),
                        "actions": self._elb_actions(
                            r.get("Actions") or [], f"rule {r.get('Priority')}", relations
                        ),
                    }
                )
        except Exception as exc:
            logger.debug("Listener rules unavailable for %s: %s", arn, exc)
        return rules

    async def _elb_listener_asset(self, elb: Any, lb: dict, listener: dict) -> CloudAsset:
        arn = listener["ListenerArn"]
        lb_arn = lb["LoadBalancerArn"]
        relations: list[dict | None] = [
            rel(lb_arn, EdgeType.CONTAINS, reverse=True, description="load balancer listener")
        ]
        default_actions = self._elb_actions(
            listener.get("DefaultActions") or [], "default", relations
        )
        rules: list[dict] = []
        if lb.get("Type") == "application":
            rules = await self._elb_listener_rules(elb, arn, relations)
        relations += [
            rel(cert.get("CertificateArn"), EdgeType.REFERENCES, "CERTIFICATE_SECURES")
            for cert in listener.get("Certificates") or []
        ]
        mtls = listener.get("MutualAuthentication") or {}
        relations.append(
            rel(
                mtls.get("TrustStoreArn"),
                EdgeType.REFERENCES,
                "DEPENDS_ON",
                description="mTLS trust store",
            )
        )
        port = listener.get("Port")
        lb_name = lb.get("LoadBalancerName", lb_arn)
        return self._asset(
            arn=arn,
            name=f"{lb_name}:{port}" if port else f"{lb_name}:listener",
            asset_type=AssetType.LB_LISTENER,
            metadata={
                "resource_kind": "lb_listener",
                "load_balancer": lb.get("LoadBalancerName"),
                "lb_type": lb.get("Type"),
                "scheme": lb.get("Scheme"),
                "port": port,
                "protocol": listener.get("Protocol"),
                "ssl_policy": listener.get("SslPolicy"),
                "alpn_policy": listener.get("AlpnPolicy", []),
                "mutual_tls_mode": mtls.get("Mode"),
                "default_actions": default_actions,
                "rules": rules,
                "rule_count": len(rules),
                **_listener_routing(default_actions, rules),
            },
            relations=_unique(relations),
            exposed=lb.get("Scheme") == "internet-facing",
        )
