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

    def _trust_relations(self, trust_doc: Any) -> tuple[list[dict], dict[str, Any]]:
        """IAM_TRUST relations (principal -> role) from a trust policy."""
        rels: list[dict] = []
        services: set[str] = set()
        federated: set[str] = set()
        external_accounts: set[str] = set()
        public = False
        for st in policy_statements(trust_doc):
            if st.get("Effect") != "Allow":
                continue
            principals = policy_principals(st)
            conditions = st.get("Condition") or None
            for p in principals.get("AWS", []):
                if p == "*":
                    public = not conditions
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
            for svc in principals.get("Service", []):
                services.add(svc)
            for fed in principals.get("Federated", []):
                federated.add(fed)
                rels.append(
                    rel(
                        fed,
                        EdgeType.IAM_TRUST,
                        "ROLE_ASSUMES_ROLE",
                        reverse=True,
                        description=f"Federated identities from {fed} can assume this role",
                        subjects=_federated_subjects(st),
                    )
                )
        info = {
            "trusted_services": sorted(services),
            "trusted_federated": sorted(federated),
            "trusted_external_accounts": sorted(external_accounts),
            "publicly_assumable": public,
        }
        return [r for r in rels if r], info

    async def _collect_iam(self) -> list[CloudAsset]:
        """Users, groups, roles, instance profiles and local policies."""
        users: list[dict] = []
        groups: list[dict] = []
        roles: list[dict] = []
        policies: list[dict] = []
        async with self._client("iam", region="us-east-1") as iam:
            paginator = iam.get_paginator("get_account_authorization_details")
            async for page in paginator.paginate(
                Filter=["User", "Role", "Group", "LocalManagedPolicy"]
            ):
                users.extend(page.get("UserDetailList", []))
                groups.extend(page.get("GroupDetailList", []))
                roles.extend(page.get("RoleDetailList", []))
                policies.extend(page.get("Policies", []))

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

        # Default version document of every customer-managed policy
        policy_docs: dict[str, Any] = {}
        assets: list[CloudAsset] = []
        for pol in policies:
            arn = pol.get("Arn", "")
            doc = next(
                (v.get("Document") for v in pol.get("PolicyVersionList", []) if v.get("IsDefaultVersion")),
                None,
            )
            policy_docs[arn] = doc
            admin = any(_is_admin_statement(st) for st in policy_statements(doc))
            assets.append(
                self._asset(
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
            )

        def principal_docs(entity: dict, inline_key: str) -> list[Any]:
            docs = [p.get("PolicyDocument") for p in entity.get(inline_key, [])]
            for att in entity.get("AttachedManagedPolicies", []):
                if att.get("PolicyArn") in policy_docs:
                    docs.append(policy_docs[att["PolicyArn"]])
            return docs

        def attachment_relations(entity: dict, relationship: str) -> list[dict]:
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
                out.append(
                    rel(boundary, EdgeType.REFERENCES, "PERMISSION_BOUNDARY_LIMITS")
                )
            return [r for r in out if r]

        def managed_names(entity: dict) -> list[str]:
            return [a.get("PolicyName", "") for a in entity.get("AttachedManagedPolicies", [])]

        def has_admin_managed(entity: dict) -> bool:
            return any(
                a.get("PolicyArn") in _ADMIN_POLICY_ARNS
                for a in entity.get("AttachedManagedPolicies", [])
            )

        group_arns = {g.get("GroupName"): g.get("Arn") for g in groups}

        for group in groups:
            grants, admin = self._grant_relations(principal_docs(group, "GroupPolicyList"))
            assets.append(
                self._asset(
                    arn=group.get("Arn", ""),
                    name=group.get("GroupName", ""),
                    asset_type=AssetType.IAM_GROUP,
                    region="global",
                    metadata={
                        "group_id": group.get("GroupId"),
                        "attached_policies": managed_names(group),
                        "inline_policies": [p.get("PolicyName") for p in group.get("GroupPolicyList", [])],
                        "is_admin": admin or has_admin_managed(group),
                    },
                    relations=attachment_relations(group, "GROUP_HAS_POLICY") + grants,
                )
            )

        for user in users:
            grants, admin = self._grant_relations(principal_docs(user, "UserPolicyList"))
            membership = [
                rel(group_arns.get(g, g), EdgeType.CONTAINS, reverse=True, description=f"member of {g}")
                for g in user.get("GroupList", [])
            ]
            assets.append(
                self._asset(
                    arn=user.get("Arn", ""),
                    name=user.get("UserName", ""),
                    asset_type=AssetType.IAM_USER,
                    region="global",
                    tags=user.get("Tags"),
                    metadata={
                        "user_id": user.get("UserId"),
                        "create_date": str(user.get("CreateDate", "")),
                        "groups": user.get("GroupList", []),
                        "attached_policies": managed_names(user),
                        "inline_policies": [p.get("PolicyName") for p in user.get("UserPolicyList", [])],
                        "is_admin": admin or has_admin_managed(user),
                    },
                    relations=membership + attachment_relations(user, "USER_HAS_POLICY") + grants,
                )
            )

        profiles: dict[str, dict] = {}
        for role in roles:
            role_arn = role.get("Arn", "")
            trust, trust_info = self._trust_relations(role.get("AssumeRolePolicyDocument"))
            grants, admin = self._grant_relations(principal_docs(role, "RolePolicyList"))
            for prof in role.get("InstanceProfileList", []):
                profiles.setdefault(prof.get("Arn", ""), {"profile": prof, "roles": set()})
                profiles[prof.get("Arn", "")]["roles"].add(role_arn)
            path = role.get("Path", "/")
            last_used = role.get("RoleLastUsed") or {}
            assets.append(
                self._asset(
                    arn=role_arn,
                    name=role.get("RoleName", ""),
                    asset_type=AssetType.IAM_ROLE,
                    region="global",
                    tags=role.get("Tags"),
                    metadata={
                        "role_id": role.get("RoleId"),
                        "path": path,
                        "assume_role_policy": policy_document(role.get("AssumeRolePolicyDocument")),
                        "service_linked": path.startswith("/aws-service-role/"),
                        "attached_policies": managed_names(role),
                        "inline_policies": [p.get("PolicyName") for p in role.get("RolePolicyList", [])],
                        "is_admin": admin or has_admin_managed(role),
                        "last_used": str(last_used.get("LastUsedDate", "")),
                        "last_used_region": last_used.get("Region"),
                        **trust_info,
                    },
                    relations=trust + attachment_relations(role, "ROLE_HAS_POLICY") + grants,
                    exposed=trust_info["publicly_assumable"],
                )
            )

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
                        rel(r, EdgeType.ASSUMES_ROLE, "RUNS_ON", description="instance profile role")
                        for r in sorted(entry["roles"])
                    ],
                )
            )

        return assets + oidc_assets
