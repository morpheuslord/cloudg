"""Identity beyond allow bindings: identity pools, IAM deny policies,
Principal Access Boundary policies and bindings, Privileged Access Manager
entitlements, Cloud Identity groups and role permission sets.

Principals named here are referenced by their
:func:`~cloudg.inventory.gcp_relations.iam.principal_identifier`; the deep
collector creates placeholder assets for the ones that were not collected.
"""

from __future__ import annotations

from typing import Any
from urllib.parse import unquote

from cloudg.inventory.gcp_relations._refs import crm_ref, parent_of
from cloudg.inventory.gcp_relations.context import Extracted, GCPContext, _extractor
from cloudg.inventory.gcp_relations.iam import (
    has_policy_relationship,
    principal_identifier,
    role_ref,
)
from cloudg.inventory.gcp_relations.names import (
    PRINCIPAL_PREFIX,
    PUBLIC_MEMBERS,
    _list,
    dig,
    full_name,
    relative_name,
    sa_ref,
)
from cloudg.schema.models import EdgeType

_MAX_PERMISSIONS = 200

_V2_PREFIXES = (
    ("principal://goog/subject/", "user:"),
    ("principalSet://goog/group/", "group:"),
    ("principal://iam.googleapis.com/projects/-/serviceAccounts/", "serviceAccount:"),
    (
        "principalSet://goog/cloudIdentityCustomerId/",
        "principalSet://goog/cloudIdentityCustomerId/",
    ),
)


def v1_member(principal: Any) -> str | None:
    """IAM v2 principal identifier (deny policies) as a v1 member string.

    ``principalSet://goog/public:all`` becomes ``allUsers``; workforce and
    workload identity principals are kept as they are.
    """
    if not isinstance(principal, str) or not principal:
        return None
    if principal == "principalSet://goog/public:all":
        return "allUsers"
    for prefix, member in _V2_PREFIXES:
        if principal.startswith(prefix):
            rest = principal[len(prefix) :]
            return member + rest if member.endswith(":") else principal
    return principal


def principal_target(member: Any) -> str | None:
    """Relation target for an IAM member (None for public members)."""
    if not isinstance(member, str) or not member or member in PUBLIC_MEMBERS:
        return None
    if member.startswith("serviceAccount:") and "[" not in member:
        return sa_ref(member.split(":", 1)[1])
    return principal_identifier(member)


# ---------------------------------------------------------------------------
# Identity pools and OAuth clients
# ---------------------------------------------------------------------------


@_extractor("iam.googleapis.com/WorkforcePool")
def _workforce_pool(ctx: GCPContext, out: Extracted) -> None:
    d = ctx.data
    out.add(crm_ref(d.get("parent")), EdgeType.CONTAINS, reverse=True)
    out.alias(relative_name(ctx.name))
    out.metadata.update(
        disabled=bool(d.get("disabled")),
        session_duration=d.get("sessionDuration"),
        access_restricted=bool(d.get("accessRestrictions")),
        pool_kind="workforce",
    )


@_extractor("iam.googleapis.com/WorkloadIdentityPool")
def _workload_pool(ctx: GCPContext, out: Extracted) -> None:
    d = ctx.data
    out.alias(relative_name(ctx.name))
    out.metadata.update(disabled=bool(d.get("disabled")), mode=d.get("mode"), pool_kind="workload")


@_extractor(
    "iam.googleapis.com/WorkloadIdentityPoolNamespace",
    "iam.googleapis.com/WorkloadIdentityPoolManagedIdentity",
    "iam.googleapis.com/WorkforcePoolProviderKey",
    "iam.googleapis.com/WorkloadIdentityPoolProviderKey",
    "iam.googleapis.com/OauthClientCredential",
)
def _pool_child(ctx: GCPContext, out: Extracted) -> None:
    for seg in ("managedIdentities", "namespaces", "keys", "credentials"):
        parent = parent_of(ctx.name, seg)
        if parent:
            out.add(parent, EdgeType.CONTAINS, reverse=True)
            return


@_extractor("iam.googleapis.com/OauthClient")
def _oauth_client(ctx: GCPContext, out: Extracted) -> None:
    d = ctx.data
    out.metadata.update(
        client_type=d.get("clientType"),
        allowed_grant_types=list(d.get("allowedGrantTypes") or []),
        allowed_scopes=list(d.get("allowedScopes") or []),
        redirect_uri_count=len(_list(d.get("allowedRedirectUris"))),
        disabled=bool(d.get("disabled")),
    )


@_extractor("iam.googleapis.com/Role")
def _role_permissions(ctx: GCPContext, out: Extracted) -> None:
    """Permission list of a custom or (Roles API) predefined role."""
    perms = [p for p in _list(ctx.data.get("includedPermissions")) if isinstance(p, str)]
    out.alias(relative_name(ctx.name))
    if perms:
        out.metadata["included_permissions"] = perms[:_MAX_PERMISSIONS]
        out.metadata["permissions_truncated"] = len(perms) > _MAX_PERMISSIONS or None
    out.metadata["predefined"] = relative_name(ctx.name).startswith("roles/")


# ---------------------------------------------------------------------------
# IAM deny policies (iam.googleapis.com/PolicyV2)
# ---------------------------------------------------------------------------


def deny_attachment_point(name: str) -> str | None:
    """``policies/<encoded attachment point>/denypolicies/x`` -> attachment full name."""
    rel_name = relative_name(name)
    if not rel_name.startswith("policies/"):
        return None
    encoded = rel_name.split("/", 2)[1]
    point = unquote(encoded)
    return f"//{point}" if point and not point.startswith("//") else point or None


@_extractor("iam.googleapis.com/PolicyV2", "iam.googleapis.com/DenyPolicy")
def _deny_policy(ctx: GCPContext, out: Extracted) -> None:
    d = ctx.data
    if d.get("kind") not in (None, "DenyPolicy", "denypolicies"):
        return
    attachment = deny_attachment_point(ctx.name)
    rules: list[dict[str, Any]] = []
    for rule in _list(d.get("rules")):
        deny = rule.get("denyRule") if isinstance(rule, dict) else None
        if not isinstance(deny, dict):
            continue
        principals = [v1_member(p) for p in _list(deny.get("deniedPrincipals"))]
        permissions = list(deny.get("deniedPermissions") or [])
        rules.append(
            {
                "denied_principals": principals,
                "exception_principals": [
                    v1_member(p) for p in _list(deny.get("exceptionPrincipals"))
                ],
                "denied_permissions": permissions,
                "exception_permissions": list(deny.get("exceptionPermissions") or []),
                "condition": dig(deny, "denialCondition", "expression"),
            }
        )
        for member in principals:
            out.add(
                principal_target(member),
                EdgeType.GOVERNS,
                "POLICY_DENIES_ACTION",
                description="IAM deny rule names this principal",
                denied_permissions=permissions[:50],
                attachment_point=attachment,
            )
    all_perms = sorted({p for r in rules for p in r["denied_permissions"]})
    out.add(
        attachment,
        EdgeType.GOVERNS,
        "POLICY_DENIES_ACTION",
        description="IAM deny policy attached here",
        denied_permissions=all_perms[:50],
    )
    out.metadata.update(
        policy_kind="deny",
        attachment_point=attachment,
        rules=rules,
        denies_public=any("allUsers" in r["denied_principals"] for r in rules) or None,
    )


# ---------------------------------------------------------------------------
# Principal Access Boundary
# ---------------------------------------------------------------------------


@_extractor("iam.googleapis.com/PrincipalAccessBoundaryPolicy")
def _pab_policy(ctx: GCPContext, out: Extracted) -> None:
    d = ctx.data
    details = d.get("details") or {}
    resources: list[str] = []
    for rule in _list(details.get("rules")):
        if isinstance(rule, dict) and rule.get("effect") in (None, "ALLOW"):
            resources += [r for r in _list(rule.get("resources")) if isinstance(r, str)]
    for res in dict.fromkeys(resources):
        out.add(
            full_name(res),
            EdgeType.GOVERNS,
            "PERMISSION_BOUNDARY_LIMITS",
            description="bound principals can only reach resources under this one",
        )
    out.metadata.update(
        policy_kind="principal_access_boundary",
        allowed_resources=list(dict.fromkeys(resources)),
        enforcement_version=details.get("enforcementVersion"),
    )


def binding_policy_ref(d: dict[str, Any]) -> str | None:
    policy = d.get("policy")
    if not isinstance(policy, str) or not policy:
        return None
    return policy if policy.startswith("//") else f"//iam.googleapis.com/{policy}"


@_extractor("iam.googleapis.com/PolicyBinding")
def _policy_binding(ctx: GCPContext, out: Extracted) -> None:
    """Binds a policy (Principal Access Boundary) to a principal set.

    The edge from the principal set to the policy is added on the policy
    asset by the deep collector, since a binding cannot declare it.
    """
    d = ctx.data
    target = dig(d, "target", "principalSet") or dig(d, "target", "resource")
    out.add(binding_policy_ref(d), EdgeType.REFERENCES, "DEPENDS_ON", description="bound policy")
    out.add(full_name(target), EdgeType.GOVERNS, "PERMISSION_BOUNDARY_LIMITS")
    out.metadata.update(
        policy_kind=d.get("policyKind"),
        policy=binding_policy_ref(d),
        target_principal_set=full_name(target),
        condition=dig(d, "condition", "expression"),
    )


# ---------------------------------------------------------------------------
# Privileged Access Manager
# ---------------------------------------------------------------------------


@_extractor("privilegedaccessmanager.googleapis.com/Entitlement")
def _pam_entitlement(ctx: GCPContext, out: Extracted) -> None:
    """Eligible principals may elevate to the entitlement's roles on its resource."""
    d = ctx.data
    access = dig(d, "privilegedAccess", "gcpIamAccess", default={}) or {}
    roles = [b.get("role") for b in _list(access.get("roleBindings")) if isinstance(b, dict)]
    roles = [r for r in roles if r]
    resource = full_name(access.get("resource"))
    out.add(
        resource,
        EdgeType.GRANTS_ACCESS,
        "POLICY_ALLOWS_ACTION",
        description="roles granted while an entitlement grant is active",
        roles=roles,
        role=roles[0] if roles else None,
        just_in_time=True,
    )
    for role in roles:
        out.add(role_ref(role), EdgeType.IAM_POLICY_ATTACHMENT, "ROLE_HAS_POLICY")
    eligible = [
        p
        for e in _list(d.get("eligibleUsers"))
        if isinstance(e, dict)
        for p in _list(e.get("principals"))
    ]
    for member in eligible:
        out.add(
            principal_target(member),
            EdgeType.ASSUMES_ROLE,
            "ROLE_ASSUMES_ROLE",
            reverse=True,
            description="eligible to request this entitlement",
        )
    approvers = [
        p
        for step in _list(dig(d, "approvalWorkflow", "manualApprovals", "steps"))
        if isinstance(step, dict)
        for a in _list(step.get("approvers"))
        if isinstance(a, dict)
        for p in _list(a.get("principals"))
    ]
    for member in approvers:
        out.add(principal_target(member), EdgeType.REFERENCES, "DEPENDS_ON", description="approver")
    out.metadata.update(
        roles=roles,
        resource=resource,
        resource_type=access.get("resourceType"),
        eligible_principals=eligible,
        approvers=approvers,
        approval_required=bool(approvers),
        max_request_duration=d.get("maxRequestDuration"),
        entitlement_state=d.get("state"),
    )


# ---------------------------------------------------------------------------
# Cloud Identity groups (from the Cloud Identity API)
# ---------------------------------------------------------------------------


@_extractor("cloudidentity.googleapis.com/Group")
def _cloud_identity_group(ctx: GCPContext, out: Extracted) -> None:
    """A Google group, its members (CONTAINS) and the IAM member string aliases."""
    d = ctx.data
    email = str(dig(d, "groupKey", "id") or "").lower()
    if email:
        out.alias(email, f"group:{email}", f"{PRINCIPAL_PREFIX}group:{email}")
    members: list[dict[str, Any]] = []
    for m in _list(d.get("memberships")):
        if not isinstance(m, dict):
            continue
        key = str(dig(m, "preferredMemberKey", "id") or "").lower()
        mtype = str(m.get("type") or "").upper()
        prefix = {"GROUP": "group", "SERVICE_ACCOUNT": "serviceAccount"}.get(mtype, "user")
        if not key:
            continue
        roles = [r.get("name") for r in _list(m.get("roles")) if isinstance(r, dict)]
        members.append({"member": f"{prefix}:{key}", "roles": roles})
        out.add(
            principal_target(f"{prefix}:{key}"),
            EdgeType.CONTAINS,
            description=f"member of {email or ctx.name}",
            roles=roles,
        )
    labels = d.get("labels") or {}
    out.metadata.update(
        email=email or None,
        principal_type="group",
        member_count=len(members),
        members=members[:500],
        security_group="cloudidentity.googleapis.com/groups.security" in labels,
        dynamic=bool(d.get("dynamicGroupMetadata")),
    )


__all__ = [
    "binding_policy_ref",
    "deny_attachment_point",
    "has_policy_relationship",
    "principal_target",
    "role_ref",
    "v1_member",
]
