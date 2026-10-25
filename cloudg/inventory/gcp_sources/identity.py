"""Identity sources: Cloud Identity groups and memberships, IAM deny
policies, Principal Access Boundary policies and bindings, Privileged
Access Manager entitlements and predefined-role permissions."""

from __future__ import annotations

from typing import Any
from urllib.parse import quote

from cloudg.inventory.gcp_sources.base import SourceContext, SourceRun, SourceSkipped, source
from cloudg.schema.models import CloudAsset

_CI = "https://cloudidentity.googleapis.com/v1"
_IAM = "https://iam.googleapis.com"
_PAM = "https://privilegedaccessmanager.googleapis.com/v1"
_CRM_API = "https://cloudresourcemanager.googleapis.com/v3"


def _customer_id(ctx: SourceContext, run: SourceRun) -> str | None:
    if ctx.options.customer_id:
        return ctx.options.customer_id.removeprefix("customers/")
    for a in ctx.by_type("cloudresourcemanager.googleapis.com/Organization"):
        cid = ((a.raw_data or {}).get("data") or {}).get("owner", {}).get("directoryCustomerId")
        if cid:
            return str(cid)
    org = ctx.organization()
    if org:
        body = ctx.get(run, f"{_CRM_API}/organizations/{org}", tolerate=True)
        if body and body.get("directoryCustomerId"):
            return str(body["directoryCustomerId"])
    return None


@source("cloud_identity", "identity", phase=0)
def cloud_identity_groups(ctx: SourceContext, run: SourceRun) -> list[CloudAsset]:
    """Google groups (Cloud Identity) with their memberships."""
    customer = _customer_id(ctx, run)
    if not customer:
        raise SourceSkipped(
            "no Cloud Identity customer ID: set gcp.cloud_identity_customer_id "
            "or map at organization scope"
        )
    opts = ctx.options
    groups = ctx.items(
        run,
        f"{_CI}/groups",
        "groups",
        params={"parent": f"customers/{customer}", "view": "FULL"},
        page_size=500,
        max_items=opts.max_groups,
    )
    out: list[CloudAsset] = []
    for group in groups:
        gname = group.get("name")
        if not isinstance(gname, str) or not gname.startswith("groups/"):
            continue
        members = ctx.items(
            run,
            f"{_CI}/{gname}/memberships",
            "memberships",
            params={"view": "FULL"},
            page_size=1000,
            max_items=opts.max_group_members,
        )
        data = {**group, "memberships": members}
        asset = ctx.build(
            f"//cloudidentity.googleapis.com/{gname}",
            "cloudidentity.googleapis.com/Group",
            data,
            source_name="cloud_identity",
            global_resource=True,
        )
        if asset is not None:
            asset.name = str((group.get("groupKey") or {}).get("id") or asset.name)
            out.append(asset)
    return out


def _attachment(parent: str) -> str:
    return quote(f"cloudresourcemanager.googleapis.com/{parent}", safe="")


@source("iam_deny", "identity")
def iam_deny_policies(ctx: SourceContext, run: SourceRun) -> list[CloudAsset]:
    """IAM deny policies attached to the organization, folders and projects."""
    out: list[CloudAsset] = []
    for parent in ctx.parents():
        listed = ctx.items(
            run, f"{_IAM}/v2/policies/{_attachment(parent)}/denypolicies", "policies"
        )
        for pol in listed:
            name = pol.get("name")
            if not isinstance(name, str):
                continue
            # The list omits rules; fetch each policy
            full = ctx.get(run, f"{_IAM}/v2/{name}") or pol
            project = parent.split("/", 1)[1] if parent.startswith("projects/") else None
            asset = ctx.build(
                f"//iam.googleapis.com/{name}",
                "iam.googleapis.com/PolicyV2",
                {**full, "kind": full.get("kind") or "DenyPolicy"},
                project=project,
                source_name="iam_deny",
                global_resource=project is None,
            )
            if asset is not None:
                out.append(asset)
    return out


@source("principal_access_boundary", "identity")
def principal_access_boundary(ctx: SourceContext, run: SourceRun) -> list[CloudAsset]:
    """Principal Access Boundary policies (organization) and their policy bindings."""
    out: list[CloudAsset] = []
    org = ctx.organization()
    if org:
        for pol in ctx.items(
            run,
            f"{_IAM}/v3/organizations/{org}/locations/global/principalAccessBoundaryPolicies",
            "principalAccessBoundaryPolicies",
        ):
            name = pol.get("name")
            if isinstance(name, str):
                asset = ctx.build(
                    f"//iam.googleapis.com/{name}",
                    "iam.googleapis.com/PrincipalAccessBoundaryPolicy",
                    pol,
                    source_name="principal_access_boundary",
                    global_resource=True,
                )
                if asset is not None:
                    out.append(asset)
    for parent in ctx.parents():
        for binding in ctx.items(
            run, f"{_IAM}/v3/{parent}/locations/global/policyBindings", "policyBindings"
        ):
            name = binding.get("name")
            if not isinstance(name, str):
                continue
            project = parent.split("/", 1)[1] if parent.startswith("projects/") else None
            asset = ctx.build(
                f"//iam.googleapis.com/{name}",
                "iam.googleapis.com/PolicyBinding",
                binding,
                project=project,
                source_name="principal_access_boundary",
                global_resource=project is None,
            )
            if asset is not None:
                out.append(asset)
    return out


@source("pam", "identity")
def pam_entitlements(ctx: SourceContext, run: SourceRun) -> list[CloudAsset]:
    """Privileged Access Manager entitlements at every parent in scope."""
    out: list[CloudAsset] = []
    for parent in ctx.parents():
        for ent in ctx.items(run, f"{_PAM}/{parent}/locations/global/entitlements", "entitlements"):
            name = ent.get("name")
            if not isinstance(name, str):
                continue
            project = parent.split("/", 1)[1] if parent.startswith("projects/") else None
            asset = ctx.build(
                f"//privilegedaccessmanager.googleapis.com/{name}",
                "privilegedaccessmanager.googleapis.com/Entitlement",
                ent,
                project=project,
                source_name="pam",
                global_resource=project is None,
            )
            if asset is not None:
                out.append(asset)
    return out


def bound_roles(ctx: SourceContext) -> list[str]:
    """Predefined roles bound anywhere: IAM bindings and PAM entitlements."""
    roles: list[str] = list(ctx.state.get("iam_roles") or [])
    for a in ctx.by_type("privilegedaccessmanager.googleapis.com/Entitlement"):
        roles += [r for r in a.metadata.get("roles") or [] if isinstance(r, str)]
    return [r for r in dict.fromkeys(roles) if r.startswith("roles/")]


@source("iam_roles", "identity", phase=3, needs_rest=False)
def predefined_roles(ctx: SourceContext, run: SourceRun) -> list[CloudAsset]:
    """An IAM_ROLE asset per bound predefined role, with its permissions (Roles API)."""
    out: list[CloudAsset] = []
    expand = ctx.rest is not None and ctx.options.expand_predefined_roles
    budget = ctx.options.max_role_expansions
    for role in bound_roles(ctx):
        data: dict[str, Any] = {"name": role, "title": role}
        if expand and budget > 0:
            budget -= 1
            body = ctx.get(run, f"{_IAM}/v1/{role}")
            if body:
                data = {**body, "name": role}
        else:
            run.ok += 1
        asset = ctx.build(
            f"//iam.googleapis.com/{role}",
            "iam.googleapis.com/Role",
            data,
            source_name="iam_roles",
            global_resource=True,
        )
        if asset is not None:
            asset.name = role
            asset.metadata["permissions_expanded"] = "includedPermissions" in data
            out.append(asset)
    if not expand:
        run.notes.append("permissions not expanded (no REST transport or disabled)")
    return out
