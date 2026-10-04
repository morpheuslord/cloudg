"""Constants and helpers shared by the governance collector mixins."""

from __future__ import annotations

import logging
import re
from datetime import datetime, timezone
from typing import Any, AsyncIterator, Awaitable, Callable

from cloudg.inventory.aws_services._base import (
    AWSServiceMixin,
    as_list,
    error_code,
    policy_principals,
    policy_statements,
    principal_ref,
    rel,
)
from cloudg.schema.models import EdgeType

# One logger for the whole package, named as the original single module was.
logger = logging.getLogger(__name__.rpartition(".")[0])

# Identity Center lives in one home region; probed in this order after the
# collector's own region.
_SSO_FALLBACK_REGIONS = (
    "us-east-1",
    "us-east-2",
    "us-west-2",
    "eu-west-1",
    "eu-central-1",
    "eu-west-2",
    "eu-north-1",
    "ap-southeast-1",
    "ap-southeast-2",
    "ap-northeast-1",
    "ap-south-1",
    "ca-central-1",
    "sa-east-1",
)
_MAX_IDENTITY_USERS = 5000
_MAX_IDENTITY_GROUPS = 5000
_MAX_MEMBERSHIPS = 50000
_MAX_PS_ACCOUNTS = 1000
_MAX_POLICY_REFS = 200
_MAX_POLICY_PRINCIPALS = 100
_MAX_GRANTS = 100
_MAX_SNAPSHOTS = 2000
_MAX_IMAGES = 2000
_MAX_STACK_INSTANCES = 2000
_MAX_ACCESS_KEY_USERS = 5000
_STALE_KEY_DAYS = 90
_ACCOUNT_RE = re.compile(r"^\d{12}$")

_CT_ACCOUNT_FACTORY_PRODUCT = "AWS Control Tower Account Factory"
_SSO_ROLE_PATH = "/aws-reserved/sso.amazonaws.com/"
_COGNITO_TRIGGERS = (
    "PreSignUp",
    "CustomMessage",
    "PostConfirmation",
    "PreAuthentication",
    "PostAuthentication",
    "DefineAuthChallenge",
    "CreateAuthChallenge",
    "VerifyAuthChallengeResponse",
    "PreTokenGeneration",
    "UserMigration",
)
_COGNITO_VERSIONED_TRIGGERS = ("PreTokenGenerationConfig", "CustomSMSSender", "CustomEmailSender")


def _root(account: str) -> str:
    return f"arn:aws:iam::{account}:root"


def _arn_account(ref: str) -> str | None:
    parts = ref.split(":")
    if ref.startswith("arn:") and len(parts) > 4 and _ACCOUNT_RE.match(parts[4]):
        return parts[4]
    return None


def _ts(value: Any) -> str | None:
    return str(value) if value not in (None, "") else None


def _age_days(value: Any) -> int | None:
    if not isinstance(value, datetime):
        return None
    when = value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    return max(0, (datetime.now(timezone.utc) - when).days)


def _principal_target(principal: str) -> str | None:
    """Resolvable reference for a sharing principal (account ID, IAM ARN,
    organization / OU ARN); service principals and wildcards return None."""
    if not principal or "*" in principal:
        return None
    if _ACCOUNT_RE.match(principal) or principal.startswith("arn:"):
        return principal_ref(principal)
    return None


def _pab(config: dict[str, Any] | None) -> dict[str, bool] | None:
    if config is None:
        return None
    return {
        k: bool(config.get(k))
        for k in (
            "BlockPublicAcls",
            "IgnorePublicAcls",
            "BlockPublicPolicy",
            "RestrictPublicBuckets",
        )
    }


def _trust_kind(cross: bool) -> str:
    """Relationship name for an access grant, by whether it crosses accounts."""
    return "CROSS_ACCOUNT_TRUST" if cross else "POLICY_ALLOWS_ACTION"


async def _take(items: AsyncIterator[Any], limit: int, out: list[Any] | None = None) -> list[Any]:
    """Consume ``items`` into ``out`` until ``limit`` are collected; callers
    detect truncation by ``len(result) >= limit``. Passing ``out`` keeps the
    items gathered before a mid-listing failure."""
    out = [] if out is None else out
    async for item in items:
        out.append(item)
        if len(out) >= limit:
            break
    return out


class GovernanceHelpersMixin(AWSServiceMixin):
    """Resource-policy helpers shared by the data-protection and access
    point collectors."""

    def _resource_policy_access(self, policy: Any) -> tuple[list[dict], dict[str, Any]]:
        """GRANTS_ACCESS relations (principal -> resource) from a resource
        policy, plus summary metadata. The own account's root (delegation to
        IAM) is summarised but not linked."""
        grants: dict[str, dict[str, Any]] = {}
        principals: set[str] = set()
        external: set[str] = set()
        public = False
        for st in policy_statements(policy):
            if st.get("Effect") != "Allow":
                continue
            actions = [str(a) for a in as_list(st.get("Action"))]
            for p in policy_principals(st).get("AWS", []):
                if p == "*":
                    public = public or not st.get("Condition")
                    continue
                ref = principal_ref(p)
                principals.add(ref)
                acct = _arn_account(ref)
                cross = bool(acct and self._account_id and acct != self._account_id)
                if cross:
                    external.add(acct)  # type: ignore[arg-type]
                if ref == self._account_ref():
                    continue
                entry = grants.setdefault(ref, {"actions": set(), "cross": cross})
                entry["actions"].update(actions)
        rels = [
            rel(
                ref,
                EdgeType.GRANTS_ACCESS,
                _trust_kind(entry["cross"]),
                reverse=True,
                description="granted by resource policy",
                actions=sorted(entry["actions"])[:25],
            )
            for ref, entry in list(grants.items())[:_MAX_POLICY_PRINCIPALS]
        ]
        info = {
            "policy_principals": sorted(principals)[:_MAX_POLICY_PRINCIPALS],
            "external_accounts": sorted(external),
            "public_policy": public,
        }
        return [r for r in rels if r], info

    async def _policy_access(
        self,
        call: Callable[[], Awaitable[dict[str, Any]]],
        key: str,
        failure: str,
        quiet_code: str | None = None,
        skip_empty: bool = True,
    ) -> tuple[list[dict], dict[str, Any]]:
        """Fetch a resource policy (``call()[key]``) and summarise it with
        :meth:`_resource_policy_access`. Failures are logged under the
        ``failure`` label (no secret material) unless their error code is ``quiet_code``;
        an absent policy is skipped unless ``skip_empty`` is False."""
        try:
            policy = (await call()).get(key)
            if policy or not skip_empty:
                return self._resource_policy_access(policy)
        except Exception as exc:
            if error_code(exc) != quiet_code:
                logger.debug("%s failed: %s", failure, exc)
        return [], {}
