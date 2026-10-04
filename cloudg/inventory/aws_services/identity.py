"""IAM: the identity graph that glues services and accounts together.

One paginated ``GetAccountAuthorizationDetails`` call returns every user,
group, role, instance profile and customer-managed policy with its policy
documents, so the whole access graph is mapped without per-principal calls:

- role trust policies -> IAM_TRUST edges (principal -> role), including
  cross-account principals and OIDC providers (EKS IRSA, GitHub Actions)
- managed policy attachments -> IAM_POLICY_ATTACHMENT edges
- group membership, instance profile -> role
- concrete resource ARNs granted by Allow statements -> GRANTS_ACCESS edges
"""

from __future__ import annotations

import logging
from typing import Any

from cloudg.inventory.aws_services._base import (
    AWSServiceMixin,
    as_list,
    condition_values,
    policy_document,
    policy_principals,
    policy_statements,
    principal_ref,
    rel,
)
from cloudg.schema.models import AssetType, CloudAsset, EdgeType

logger = logging.getLogger(__name__)

_MAX_GRANTS_PER_PRINCIPAL = 200
_ADMIN_POLICY_ARNS = {
    "arn:aws:iam::aws:policy/AdministratorAccess",
    "arn:aws:iam::aws:policy/PowerUserAccess",
}


def _grant_target(resource: str) -> str | None:
    """Turn a policy Resource into a resolvable identifier, or None if it is a
    wildcard that does not name one resource."""
    if not resource.startswith("arn:") or resource == "*":
        return None
    trimmed = resource
    for suffix in ("/*", ":*"):
        if trimmed.endswith(suffix):
            trimmed = trimmed[: -len(suffix)]
    if "*" in trimmed or "?" in trimmed or "${" in trimmed:
        return None
    return trimmed


def _federated_subjects(statement: dict[str, Any]) -> list[str]:
    """``...:sub`` condition values (e.g. ``system:serviceaccount:ns:sa`` for
    EKS IRSA, ``repo:org/name:ref:...`` for GitHub OIDC)."""
    keys = [
        key
        for block in (statement.get("Condition") or {}).values()
        if isinstance(block, dict)
        for key in block
        if key.endswith(":sub")
    ]
    return condition_values(statement, *keys) if keys else []


def _is_admin_statement(statement: dict[str, Any]) -> bool:
    if statement.get("Effect") != "Allow":
        return False
    actions = [str(a) for a in as_list(statement.get("Action"))]
    resources = [str(r) for r in as_list(statement.get("Resource"))]
    return "*" in actions and "*" in resources


def _principal_docs(entity: dict, inline_key: str, policy_docs: dict[str, Any]) -> list[Any]:
    """Inline policy documents plus attached customer-managed ones."""
    docs = [p.get("PolicyDocument") for p in entity.get(inline_key, [])]
    for att in entity.get("AttachedManagedPolicies", []):
        if att.get("PolicyArn") in policy_docs:
            docs.append(policy_docs[att["PolicyArn"]])
    return docs


def _attachment_relations(entity: dict, relationship: str) -> list[dict]:
    out = []
    for att in entity.get("AttachedManagedPolicies", []):
        out.append(
            rel(
                att.get("PolicyArn"),
                EdgeType.IAM_POLICY_ATTACHMENT,
                relationship,
                description=f"has policy {att.get('PolicyName')}",
            )
        )
    boundary = (entity.get("PermissionsBoundary") or {}).get("PermissionsBoundaryArn")
    if boundary:
        out.append(rel(boundary, EdgeType.REFERENCES, "PERMISSION_BOUNDARY_LIMITS"))
    return [r for r in out if r]


def _policy_summary(entity: dict, inline_key: str, admin: bool) -> dict[str, Any]:
    """Attached / inline policy names and the admin flag of a principal."""
    attached = entity.get("AttachedManagedPolicies", [])
    return {
        "attached_policies": [a.get("PolicyName", "") for a in attached],
        "inline_policies": [p.get("PolicyName") for p in entity.get(inline_key, [])],
        "is_admin": admin or any(a.get("PolicyArn") in _ADMIN_POLICY_ARNS for a in attached),
    }


def _default_policy_document(pol: dict) -> Any:
    return next(
        (v.get("Document") for v in pol.get("PolicyVersionList", []) if v.get("IsDefaultVersion")),
        None,
    )


def _federated_trust_relation(statement: dict[str, Any], fed: str) -> dict | None:
    return rel(
        fed,
        EdgeType.IAM_TRUST,
        "ROLE_ASSUMES_ROLE",
        reverse=True,
        description=f"Federated identities from {fed} can assume this role",
        subjects=_federated_subjects(statement),
    )


class IdentityCollectorsMixin(AWSServiceMixin):
    """Deep IAM collection (global service: runs in the primary region only)."""

    _iam_resource_edges: bool = True

    def _grant_relations(self, documents: list[Any]) -> tuple[list[dict], bool]:
        """GRANTS_ACCESS relations for every concrete resource, plus admin flag."""
        grants: dict[str, set[str]] = {}
        is_admin = False
        for doc in documents:
            for st in policy_statements(doc):
                if _is_admin_statement(st):
                    is_admin = True
                if st.get("Effect") != "Allow" or not self._iam_resource_edges:
                    continue
                actions = [str(a) for a in as_list(st.get("Action"))]
                for res in as_list(st.get("Resource")):
                    target = _grant_target(str(res))
                    if target:
                        grants.setdefault(target, set()).update(actions)
        rels = [
            rel(
                target,
                EdgeType.GRANTS_ACCESS,
                "POLICY_ALLOWS_ACTION",
                actions=sorted(actions)[:25],
            )
            for target, actions in list(grants.items())[:_MAX_GRANTS_PER_PRINCIPAL]
        ]
        return [r for r in rels if r], is_admin

    def _aws_trust_relations(
        self, st: dict[str, Any], principals: list[str], external_accounts: set[str]
    ) -> tuple[list[dict | None], bool]:
        """IAM_TRUST relations for the AWS principals of one statement
        (recording cross-account ones), plus whether ``*`` is trusted."""
        conditions = st.get("Condition") or None
        rels: list[dict | None] = []
        wildcard = False
        for p in principals:
            if p == "*":
                wildcard = True
                continue
            ref = principal_ref(p)
            acct = ref.split(":")[4] if ref.startswith("arn:") else ""
            cross = bool(acct and self._account_id and acct != self._account_id)
            if cross:
                external_accounts.add(acct)
            rels.append(
                rel(
                    ref,
                    EdgeType.IAM_TRUST,
                    "CROSS_ACCOUNT_TRUST" if cross else "ROLE_ASSUMES_ROLE",
                    reverse=True,
                    description=f"{p} can assume this role",
                    conditions=conditions,
                    external_id_required=bool(condition_values(st, "sts:ExternalId")),
                )
            )
        return rels, wildcard

    def _trust_relations(self, trust_doc: Any) -> tuple[list[dict], dict[str, Any]]:
        """IAM_TRUST relations (principal -> role) from a trust policy."""
        rels: list[dict | None] = []
        services: set[str] = set()
        federated: set[str] = set()
        external_accounts: set[str] = set()
        public = False
        for st in policy_statements(trust_doc):
            if st.get("Effect") != "Allow":
                continue
            principals = policy_principals(st)
            aws_rels, wildcard = self._aws_trust_relations(
                st, principals.get("AWS", []), external_accounts
            )
            if wildcard:
                public = not (st.get("Condition") or None)
            services.update(principals.get("Service", []))
            federated.update(principals.get("Federated", []))
            rels += aws_rels
            rels += [_federated_trust_relation(st, fed) for fed in principals.get("Federated", [])]
        info = {
            "trusted_services": sorted(services),
            "trusted_federated": sorted(federated),
            "trusted_external_accounts": sorted(external_accounts),
            "publicly_assumable": public,
        }
        return [r for r in rels if r], info

    async def _collect_iam(self) -> list[CloudAsset]:
        """Users, groups, roles, instance profiles and local policies."""
        async with self._client("iam", region="us-east-1") as iam:
            users, groups, roles, policies = await self._iam_authorization_details(iam)
            oidc_assets = await self._oidc_provider_assets(iam)

        # Default version document of every customer-managed policy
        policy_docs = {pol.get("Arn", ""): _default_policy_document(pol) for pol in policies}
        assets = [self._iam_policy_asset(pol, _default_policy_document(pol)) for pol in policies]
        assets += [self._iam_group_asset(group, policy_docs) for group in groups]
        group_arns = {g.get("GroupName"): g.get("Arn") for g in groups}
        assets += [self._iam_user_asset(user, group_arns, policy_docs) for user in users]
        assets += [self._iam_role_asset(role, policy_docs) for role in roles]
        assets += self._instance_profile_assets(roles)
        return assets + oidc_assets

    async def _iam_authorization_details(
        self, iam: Any
    ) -> tuple[list[dict], list[dict], list[dict], list[dict]]:
        """Users, groups, roles and local policies in one paginated call."""
        users: list[dict] = []
        groups: list[dict] = []
        roles: list[dict] = []
        policies: list[dict] = []
        paginator = iam.get_paginator("get_account_authorization_details")
        async for page in paginator.paginate(
            Filter=["User", "Role", "Group", "LocalManagedPolicy"]
        ):
            users.extend(page.get("UserDetailList", []))
            groups.extend(page.get("GroupDetailList", []))
            roles.extend(page.get("RoleDetailList", []))
            policies.extend(page.get("Policies", []))
        return users, groups, roles, policies

    async def _oidc_provider_assets(self, iam: Any) -> list[CloudAsset]:
        oidc_assets: list[CloudAsset] = []
        try:
            resp = await iam.list_open_id_connect_providers()
            for p in resp.get("OpenIDConnectProviderList", []):
                arn = p.get("Arn", "")
                url = arn.split("oidc-provider/", 1)[-1]
                oidc_assets.append(
                    self._asset(
                        arn=arn,
                        name=url,
                        asset_type=AssetType.IDENTITY_PROVIDER,
                        region="global",
                        metadata={"provider_type": "oidc", "url": url},
                        aliases=[f"https://{url}"],
                    )
                )
        except Exception as exc:
            logger.debug("OIDC provider listing failed: %s", exc)
        return oidc_assets

    def _iam_policy_asset(self, pol: dict, doc: Any) -> CloudAsset:
        arn = pol.get("Arn", "")
        admin = any(_is_admin_statement(st) for st in policy_statements(doc))
        return self._asset(
            arn=arn,
            name=pol.get("PolicyName", arn),
            asset_type=AssetType.IAM_POLICY,
            region="global",
            metadata={
                "policy_id": pol.get("PolicyId"),
                "attachment_count": pol.get("AttachmentCount", 0),
                "default_version": pol.get("DefaultVersionId"),
                "grants_admin": admin,
                "path": pol.get("Path"),
            },
            raw={k: v for k, v in pol.items() if k != "PolicyVersionList"},
        )

    def _iam_group_asset(self, group: dict, policy_docs: dict[str, Any]) -> CloudAsset:
        grants, admin = self._grant_relations(
            _principal_docs(group, "GroupPolicyList", policy_docs)
        )
        return self._asset(
            arn=group.get("Arn", ""),
            name=group.get("GroupName", ""),
            asset_type=AssetType.IAM_GROUP,
            region="global",
            metadata={
                "group_id": group.get("GroupId"),
                **_policy_summary(group, "GroupPolicyList", admin),
            },
            relations=_attachment_relations(group, "GROUP_HAS_POLICY") + grants,
        )

    def _iam_user_asset(
        self, user: dict, group_arns: dict[Any, Any], policy_docs: dict[str, Any]
    ) -> CloudAsset:
        grants, admin = self._grant_relations(_principal_docs(user, "UserPolicyList", policy_docs))
        membership = [
            rel(
                group_arns.get(g, g),
                EdgeType.CONTAINS,
                reverse=True,
                description=f"member of {g}",
            )
            for g in user.get("GroupList", [])
        ]
        return self._asset(
            arn=user.get("Arn", ""),
            name=user.get("UserName", ""),
            asset_type=AssetType.IAM_USER,
            region="global",
            tags=user.get("Tags"),
            metadata={
                "user_id": user.get("UserId"),
                "create_date": str(user.get("CreateDate", "")),
                "groups": user.get("GroupList", []),
                **_policy_summary(user, "UserPolicyList", admin),
            },
            relations=membership + _attachment_relations(user, "USER_HAS_POLICY") + grants,
        )

    def _iam_role_asset(self, role: dict, policy_docs: dict[str, Any]) -> CloudAsset:
        trust, trust_info = self._trust_relations(role.get("AssumeRolePolicyDocument"))
        grants, admin = self._grant_relations(_principal_docs(role, "RolePolicyList", policy_docs))
        path = role.get("Path", "/")
        last_used = role.get("RoleLastUsed") or {}
        return self._asset(
            arn=role.get("Arn", ""),
            name=role.get("RoleName", ""),
            asset_type=AssetType.IAM_ROLE,
            region="global",
            tags=role.get("Tags"),
            metadata={
                "role_id": role.get("RoleId"),
                "path": path,
                "assume_role_policy": policy_document(role.get("AssumeRolePolicyDocument")),
                "service_linked": path.startswith("/aws-service-role/"),
                **_policy_summary(role, "RolePolicyList", admin),
                "last_used": str(last_used.get("LastUsedDate", "")),
                "last_used_region": last_used.get("Region"),
                **trust_info,
            },
            relations=trust + _attachment_relations(role, "ROLE_HAS_POLICY") + grants,
            exposed=trust_info["publicly_assumable"],
        )

    def _instance_profile_assets(self, roles: list[dict]) -> list[CloudAsset]:
        profiles: dict[str, dict] = {}
        for role in roles:
            for prof in role.get("InstanceProfileList", []):
                profiles.setdefault(prof.get("Arn", ""), {"profile": prof, "roles": set()})
                profiles[prof.get("Arn", "")]["roles"].add(role.get("Arn", ""))
        assets: list[CloudAsset] = []
        for arn, entry in profiles.items():
            prof = entry["profile"]
            assets.append(
                self._asset(
                    arn=arn,
                    name=prof.get("InstanceProfileName", arn),
                    asset_type=AssetType.INSTANCE_PROFILE,
                    region="global",
                    metadata={"instance_profile_id": prof.get("InstanceProfileId")},
                    relations=[
                        rel(
                            r, EdgeType.ASSUMES_ROLE, "RUNS_ON", description="instance profile role"
                        )
                        for r in sorted(entry["roles"])
                    ],
                )
            )
        return assets
