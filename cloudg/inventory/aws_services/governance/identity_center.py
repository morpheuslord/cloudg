"""IAM Identity Center: instance, permission sets, account assignments and
the identity store (users, groups, memberships; no contact details)."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, AsyncIterator

from cloudg.inventory.aws_services._base import (
    AWSServiceMixin,
    error_code,
    gather_limited,
    rel,
)
from cloudg.inventory.aws_services.governance._common import (
    _MAX_IDENTITY_GROUPS,
    _MAX_IDENTITY_USERS,
    _MAX_MEMBERSHIPS,
    _MAX_POLICY_REFS,
    _MAX_PS_ACCOUNTS,
    _SSO_FALLBACK_REGIONS,
    _SSO_ROLE_PATH,
    _root,
    _take,
    _trust_kind,
    _ts,
    logger,
)
from cloudg.schema.models import AssetType, CloudAsset, EdgeType


@dataclass
class _IdentityCenterScope:
    """The instance being mapped, plus principal -> account -> permission
    set names accumulated while the permission sets are built."""

    inst_arn: str
    home: str
    store_id: str
    principal_grants: dict[str, dict[str, set[str]]] = field(default_factory=dict)


def _principal_arn(ptype: str | None, pid: str | None) -> str | None:
    if not pid:
        return None
    kind = "group" if ptype == "GROUP" else "user"
    return f"arn:aws:identitystore:::{kind}/{pid}"


def _issuers(entity: dict[str, Any]) -> list[str]:
    return sorted({e.get("Issuer") for e in entity.get("ExternalIds") or [] if e.get("Issuer")})


def _provisioning_relations(d: dict[str, Any], ps_name: str, inst_arn: str) -> list[dict | None]:
    """Instance containment, provisioned accounts and AWS-managed policies."""
    relations: list[dict | None] = [
        rel(
            inst_arn, EdgeType.CONTAINS, reverse=True, description="Identity Center permission set"
        ),
    ]
    relations += [
        rel(
            _root(acct),
            EdgeType.MANAGES,
            "OWNED_BY",
            description=f"provisions role AWSReservedSSO_{ps_name}_* in {acct}",
        )
        for acct in d["accounts"]
    ]
    relations += [
        rel(
            pol.get("Arn"),
            EdgeType.IAM_POLICY_ATTACHMENT,
            "ROLE_HAS_POLICY",
            description=f"has policy {pol.get('Name')}",
        )
        for pol in d["managed"]
    ]
    return relations


def _customer_policy_relations(d: dict[str, Any], accounts: list[str]) -> list[dict | None]:
    """Customer-managed policy references, resolved in every provisioned account."""
    out: list[dict | None] = []
    for cmp in d["customer"]:
        path = cmp.get("Path") or "/"
        for acct in accounts:
            if len(out) >= _MAX_POLICY_REFS:
                break
            out.append(
                rel(
                    f"arn:aws:iam::{acct}:policy{path}{cmp.get('Name')}",
                    EdgeType.IAM_POLICY_ATTACHMENT,
                    "ROLE_HAS_POLICY",
                    description=f"customer-managed policy {cmp.get('Name')}",
                )
            )
    return out


def _boundary_relations(
    boundary: dict[str, Any], accounts: list[str]
) -> tuple[list[dict | None], str | None]:
    """Permissions boundary relations and its display form."""
    if boundary.get("ManagedPolicyArn"):
        desc = boundary["ManagedPolicyArn"]
        return [rel(desc, EdgeType.REFERENCES, "PERMISSION_BOUNDARY_LIMITS")], desc
    if boundary.get("CustomerManagedPolicyReference"):
        ref = boundary["CustomerManagedPolicyReference"]
        desc = f"{ref.get('Path') or '/'}{ref.get('Name')}"
        return [
            rel(
                f"arn:aws:iam::{acct}:policy{desc}",
                EdgeType.REFERENCES,
                "PERMISSION_BOUNDARY_LIMITS",
            )
            for acct in accounts[:_MAX_POLICY_REFS]
        ], desc
    return [], None


def _assignment_relations(
    d: dict[str, Any], ps_name: str, scope: _IdentityCenterScope
) -> tuple[list[dict | None], int]:
    """Principal ASSUMES_ROLE relations for a permission set; also records
    each principal's account grants on ``scope``."""
    ps_principals: dict[str, set[str]] = {}
    for acct, ptype, pid in d["assignments"]:
        parn = _principal_arn(ptype, pid)
        if not parn:
            continue
        ps_principals.setdefault(parn, set()).add(acct)
        scope.principal_grants.setdefault(parn, {}).setdefault(acct, set()).add(ps_name)
    relations = [
        rel(
            parn,
            EdgeType.ASSUMES_ROLE,
            "ROLE_ASSUMES_ROLE",
            reverse=True,
            description=f"assigned permission set {ps_name}",
            accounts=sorted(accts)[:50],
        )
        for parn, accts in ps_principals.items()
    ]
    return relations, len(ps_principals)


class IdentityCenterCollectorsMixin(AWSServiceMixin):
    """IAM Identity Center collectors."""

    async def _find_sso_instance(self) -> tuple[dict[str, Any] | None, str | None]:
        """Locate the Identity Center instance and its home region."""
        regions = [self._region] + [r for r in _SSO_FALLBACK_REGIONS if r != self._region]
        last_exc: BaseException | None = None
        reachable = False
        for region in regions:
            try:
                async with self._client("sso-admin", region=region) as sso:
                    instances = [
                        i async for i in self._paginate(sso, "list_instances", "Instances")
                    ]
                reachable = True
            except Exception as exc:
                logger.debug("Identity Center probe in %s failed: %s", region, exc)
                last_exc = exc
                continue
            if instances:
                return instances[0], region
        if not reachable and last_exc is not None:
            raise last_exc
        return None, None

    async def _permission_set_detail(
        self, sso: Any, instance_arn: str, ps_arn: str
    ) -> dict[str, Any]:
        kw = {"InstanceArn": instance_arn, "PermissionSetArn": ps_arn}
        ps = (await sso.describe_permission_set(**kw)).get("PermissionSet", {})
        out: dict[str, Any] = {
            "arn": ps_arn,
            "ps": ps,
            "managed": [],
            "customer": [],
            "inline": False,
            "boundary": None,
            "accounts": [],
            "assignments": [],
            "tags": [],
        }
        await self._permission_set_policies(sso, kw, out)
        await self._permission_set_assignments(sso, kw, out)
        return out

    async def _permission_set_policies(
        self, sso: Any, kw: dict[str, str], out: dict[str, Any]
    ) -> None:
        """Managed / customer-managed / inline policies and the boundary."""
        ps_arn = kw["PermissionSetArn"]
        try:
            out["managed"] = [
                p
                async for p in self._paginate(
                    sso, "list_managed_policies_in_permission_set", "AttachedManagedPolicies", **kw
                )
            ]
        except Exception as exc:
            logger.debug("Managed policies for %s failed: %s", ps_arn, exc)
        try:
            out["customer"] = [
                p
                async for p in self._paginate(
                    sso,
                    "list_customer_managed_policy_references_in_permission_set",
                    "CustomerManagedPolicyReferences",
                    **kw,
                )
            ]
        except Exception as exc:
            logger.debug("Customer-managed policy refs for %s failed: %s", ps_arn, exc)
        try:
            out["inline"] = bool(
                (await sso.get_inline_policy_for_permission_set(**kw)).get("InlinePolicy")
            )
        except Exception as exc:
            logger.debug("Inline policy for %s failed: %s", ps_arn, exc)
        try:
            out["boundary"] = (await sso.get_permissions_boundary_for_permission_set(**kw)).get(
                "PermissionsBoundary"
            )
        except Exception as exc:
            if error_code(exc) != "ResourceNotFoundException":
                logger.debug("Permissions boundary for %s failed: %s", ps_arn, exc)

    async def _permission_set_assignments(
        self, sso: Any, kw: dict[str, str], out: dict[str, Any]
    ) -> None:
        """Tags, provisioned accounts and the account assignments in each."""
        ps_arn = kw["PermissionSetArn"]
        try:
            out["tags"] = [
                t
                async for t in self._paginate(
                    sso,
                    "list_tags_for_resource",
                    "Tags",
                    InstanceArn=kw["InstanceArn"],
                    ResourceArn=ps_arn,
                )
            ]
        except Exception as exc:
            logger.debug("Tags for %s failed: %s", ps_arn, exc)
        try:
            async for acct in self._paginate(
                sso, "list_accounts_for_provisioned_permission_set", "AccountIds", **kw
            ):
                out["accounts"].append(acct)
                if len(out["accounts"]) >= _MAX_PS_ACCOUNTS:
                    logger.warning("Permission set %s: provisioned accounts truncated", ps_arn)
                    break
        except Exception as exc:
            logger.debug("Provisioned accounts for %s failed: %s", ps_arn, exc)
        for acct in out["accounts"]:
            try:
                async for a in self._paginate(
                    sso, "list_account_assignments", "AccountAssignments", AccountId=acct, **kw
                ):
                    out["assignments"].append((acct, a.get("PrincipalType"), a.get("PrincipalId")))
            except Exception as exc:
                logger.debug("Assignments of %s in %s failed: %s", ps_arn, acct, exc)

    async def _identity_store(
        self, store_id: str, region: str
    ) -> tuple[list[dict], list[dict], dict[str, set[str]]]:
        """Users, groups and user -> groups memberships (no contact details)."""
        users: list[dict] = []
        groups: list[dict] = []
        async with self._client("identitystore", region=region) as ids:
            try:
                await _take(self._identity_users(ids, store_id), _MAX_IDENTITY_USERS, users)
                if len(users) >= _MAX_IDENTITY_USERS:
                    logger.warning("Identity store users truncated at %d", _MAX_IDENTITY_USERS)
            except Exception as exc:
                logger.debug("Identity store user listing failed: %s", exc)
            try:
                await _take(self._identity_groups(ids, store_id), _MAX_IDENTITY_GROUPS, groups)
                if len(groups) >= _MAX_IDENTITY_GROUPS:
                    logger.warning("Identity store groups truncated at %d", _MAX_IDENTITY_GROUPS)
            except Exception as exc:
                logger.debug("Identity store group listing failed: %s", exc)
            memberships = await self._identity_memberships(ids, store_id, groups)
        return users, groups, memberships

    async def _identity_users(self, ids: Any, store_id: str) -> AsyncIterator[dict]:
        async for u in self._paginate(ids, "list_users", "Users", IdentityStoreId=store_id):
            yield {
                "UserId": u.get("UserId"),
                "UserName": u.get("UserName"),
                "DisplayName": u.get("DisplayName"),
                "UserType": u.get("UserType"),
                "Issuers": _issuers(u),
            }

    async def _identity_groups(self, ids: Any, store_id: str) -> AsyncIterator[dict]:
        async for g in self._paginate(ids, "list_groups", "Groups", IdentityStoreId=store_id):
            yield {
                "GroupId": g.get("GroupId"),
                "DisplayName": g.get("DisplayName"),
                "Description": g.get("Description"),
                "Issuers": _issuers(g),
            }

    async def _identity_memberships(
        self, ids: Any, store_id: str, groups: list[dict]
    ) -> dict[str, set[str]]:
        """user -> group IDs, capped at ``_MAX_MEMBERSHIPS`` pairs."""

        async def members(group_id: str) -> tuple[str, list[str]]:
            found = [
                (m.get("MemberId") or {}).get("UserId")
                async for m in self._paginate(
                    ids,
                    "list_group_memberships",
                    "GroupMemberships",
                    IdentityStoreId=store_id,
                    GroupId=group_id,
                )
            ]
            return group_id, [f for f in found if f]

        results = await gather_limited(
            [lambda g=g: members(g["GroupId"]) for g in groups if g.get("GroupId")]
        )
        memberships: dict[str, set[str]] = {}
        total = 0
        for res in results:
            if not res:
                continue
            group_id, user_ids = res
            for uid in user_ids:
                if total >= _MAX_MEMBERSHIPS:
                    break
                memberships.setdefault(uid, set()).add(group_id)
                total += 1
        return memberships

    async def _collect_identity_center(self) -> list[CloudAsset]:
        instance, home = await self._find_sso_instance()
        if not instance or not home:
            return []
        scope = _IdentityCenterScope(
            inst_arn=instance["InstanceArn"],
            home=home,
            store_id=instance.get("IdentityStoreId") or "",
        )
        async with self._client("sso-admin", region=home) as sso:
            ps_arns = [
                p
                async for p in self._paginate(
                    sso, "list_permission_sets", "PermissionSets", InstanceArn=scope.inst_arn
                )
            ]
            details = await gather_limited(
                [lambda a=a: self._permission_set_detail(sso, scope.inst_arn, a) for a in ps_arns],
                limit=4,
            )

        users: list[dict] = []
        groups: list[dict] = []
        memberships: dict[str, set[str]] = {}
        if scope.store_id:
            try:
                users, groups, memberships = await self._identity_store(scope.store_id, home)
            except Exception as exc:
                logger.debug("Identity store collection failed: %s", exc)

        details = [d for d in details if d]
        assets = [self._permission_set_asset(d, scope) for d in details]
        assets += self._identity_group_assets(groups, memberships, scope)
        assets += self._identity_user_assets(users, memberships, scope)
        assets.append(self._identity_instance_asset(instance, scope, len(details), users, groups))
        return assets

    def _permission_set_asset(self, d: dict[str, Any], scope: _IdentityCenterScope) -> CloudAsset:
        ps = d["ps"]
        ps_arn = d["arn"]
        ps_name = ps.get("Name") or ps_arn.rsplit("/", 1)[-1]
        accounts: list[str] = d["accounts"]
        relations = _provisioning_relations(d, ps_name, scope.inst_arn)
        relations += _customer_policy_relations(d, accounts)
        boundary_rels, boundary_desc = _boundary_relations(d["boundary"] or {}, accounts)
        assignment_rels, principal_count = _assignment_relations(d, ps_name, scope)
        managed_arns = [p.get("Arn") for p in d["managed"] if p.get("Arn")]
        return self._asset(
            arn=ps_arn,
            name=ps_name,
            asset_type=AssetType.PERMISSION_SET,
            region=scope.home,
            tags=d["tags"],
            metadata={
                "description": ps.get("Description"),
                "session_duration": ps.get("SessionDuration"),
                "created": _ts(ps.get("CreatedDate")),
                "instance_arn": scope.inst_arn,
                "managed_policies": managed_arns,
                "customer_managed_policies": [
                    f"{c.get('Path') or '/'}{c.get('Name')}" for c in d["customer"]
                ],
                "has_inline_policy": d["inline"],
                "permissions_boundary": boundary_desc,
                "is_admin": "arn:aws:iam::aws:policy/AdministratorAccess" in managed_arns,
                "provisioned_accounts": accounts,
                "assignment_count": len(d["assignments"]),
                "principal_count": principal_count,
                "provisioned_role_prefix": f"AWSReservedSSO_{ps_name}_",
                "provisioned_role_path": _SSO_ROLE_PATH,
            },
            relations=relations + boundary_rels + assignment_rels,
            raw={k: v for k, v in ps.items() if k != "RelayState"},
        )

    def _identity_grant_relations(
        self, scope: _IdentityCenterScope, parn: str
    ) -> list[dict | None]:
        return [
            rel(
                _root(acct),
                EdgeType.GRANTS_ACCESS,
                _trust_kind(acct != self._account_id),
                description="Identity Center account assignment",
                permission_sets=sorted(names),
            )
            for acct, names in sorted(scope.principal_grants.get(parn, {}).items())
        ]

    def _identity_group_assets(
        self, groups: list[dict], memberships: dict[str, set[str]], scope: _IdentityCenterScope
    ) -> list[CloudAsset]:
        member_counts: dict[str, int] = {}
        for gids in memberships.values():
            for gid in gids:
                member_counts[gid] = member_counts.get(gid, 0) + 1
        assets: list[CloudAsset] = []
        for g in groups:
            garn = _principal_arn("GROUP", g.get("GroupId"))
            if not garn:
                continue
            assets.append(
                self._asset(
                    arn=garn,
                    name=g.get("DisplayName") or g["GroupId"],
                    asset_type=AssetType.IDENTITY_GROUP,
                    region=scope.home,
                    metadata={
                        "group_id": g["GroupId"],
                        "identity_store_id": scope.store_id,
                        "description": g.get("Description"),
                        "external_issuers": g["Issuers"],
                        "member_count": member_counts.get(g["GroupId"], 0),
                        "assigned_accounts": sorted(scope.principal_grants.get(garn, {})),
                    },
                    relations=[rel(scope.inst_arn, EdgeType.CONTAINS, reverse=True)]
                    + self._identity_grant_relations(scope, garn),
                )
            )
        return assets

    def _identity_user_assets(
        self, users: list[dict], memberships: dict[str, set[str]], scope: _IdentityCenterScope
    ) -> list[CloudAsset]:
        assets: list[CloudAsset] = []
        for u in users:
            uid = u.get("UserId")
            uarn = _principal_arn("USER", uid)
            if not uarn:
                continue
            membership = [
                rel(
                    _principal_arn("GROUP", gid),
                    EdgeType.CONTAINS,
                    reverse=True,
                    description="group member",
                )
                for gid in sorted(memberships.get(uid, set()))  # type: ignore[arg-type]
            ]
            assets.append(
                self._asset(
                    arn=uarn,
                    name=u.get("UserName") or uid,
                    asset_type=AssetType.IDENTITY_USER,
                    region=scope.home,
                    metadata={
                        "user_id": uid,
                        "user_name": u.get("UserName"),
                        "display_name": u.get("DisplayName"),
                        "user_type": u.get("UserType"),
                        "identity_store_id": scope.store_id,
                        "external_issuers": u["Issuers"],
                        "assigned_accounts": sorted(scope.principal_grants.get(uarn, {})),
                    },
                    relations=[rel(scope.inst_arn, EdgeType.CONTAINS, reverse=True)]
                    + membership
                    + self._identity_grant_relations(scope, uarn),
                )
            )
        return assets

    def _identity_instance_asset(
        self,
        instance: dict[str, Any],
        scope: _IdentityCenterScope,
        ps_count: int,
        users: list[dict],
        groups: list[dict],
    ) -> CloudAsset:
        return self._asset(
            arn=scope.inst_arn,
            name=instance.get("Name") or "IAM Identity Center",
            asset_type=AssetType.IDENTITY_PROVIDER,
            region=scope.home,
            metadata={
                "provider_type": "identity_center",
                "identity_store_id": scope.store_id,
                "home_region": scope.home,
                "owner_account_id": instance.get("OwnerAccountId"),
                "status": instance.get("Status"),
                "created": _ts(instance.get("CreatedDate")),
                "permission_set_count": ps_count,
                "user_count": len(users),
                "group_count": len(groups),
            },
            aliases=[scope.store_id],
        )
