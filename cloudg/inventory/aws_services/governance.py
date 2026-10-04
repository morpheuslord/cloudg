"""Governance, access-sharing and data-protection services.

Who can reach what across accounts, and how data is protected and shared:

- IAM Identity Center: instance, permission sets (managed / customer-managed
  policies, inline policy presence, permissions boundary), provisioned
  accounts and account assignments; identity-store users, groups and
  memberships. Principals GRANTS_ACCESS the accounts they are assigned to
  and ASSUMES_ROLE the permission sets.
- AWS RAM resource shares (owned and received): principal -> share ->
  shared resource (GRANTS_ACCESS).
- Service Catalog portfolios and provisioned products (Control Tower
  Account Factory): product MANAGES the vended account and its stack.
- CloudFormation StackSets: MANAGES every stack instance and target account.
- IAM SAML providers, access keys (metadata only) and IAM Roles Anywhere.
- KMS (aliases, rotation, key policy and grant principals), Secrets
  Manager (rotation function, KMS, resource policy, replicas) and DynamoDB
  (KMS, streams, replicas, PITR, resource policy, Kinesis destinations):
  these override the shallow base collectors and keep their metadata keys.
- EBS snapshots, AMIs and manual RDS snapshots with their sharing
  permissions (public -> exposed, accounts -> GRANTS_ACCESS).
- S3 access points and Multi-Region Access Points.
- Cognito user pools (Lambda triggers, SMS role) and identity pools
  (authenticated / unauthenticated roles).

No secret material is ever collected: no secret or parameter values, no
access-key secrets, no stack parameters or template bodies, and no
identity-store e-mail addresses or phone numbers.
"""

from __future__ import annotations

import logging
import re
from datetime import datetime, timezone
from typing import Any

from cloudg.inventory.aws_services._base import (
    AWSServiceMixin,
    arns_in,
    as_list,
    error_code,
    gather_limited,
    policy_principals,
    policy_statements,
    principal_ref,
    rel,
)
from cloudg.schema.models import AssetType, CloudAsset, EdgeType

logger = logging.getLogger(__name__)

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


class GovernanceCollectorsMixin(AWSServiceMixin):
    """Identity Center, RAM, Service Catalog, StackSets, data protection and
    sharing collectors."""

    def _governance_tasks(self) -> dict[str, tuple[Any, str, bool]]:
        """name -> (collector callable, service family, is_global)."""
        return {
            "identity_center": (self._collect_identity_center, "identity", True),
            "iam_saml_providers": (self._collect_iam_saml_providers, "identity", True),
            "iam_access_keys": (self._collect_iam_access_keys, "identity", True),
            "rolesanywhere": (self._collect_rolesanywhere, "identity", False),
            "cognito_user_pools": (self._collect_cognito_user_pools, "identity", False),
            "cognito_identity_pools": (self._collect_cognito_identity_pools, "identity", False),
            "ram_shares": (self._collect_ram_shares, "governance", False),
            "service_catalog": (self._collect_service_catalog, "governance", False),
            "stack_sets": (self._collect_stack_sets, "governance", False),
            "ebs_snapshots": (self._collect_ebs_snapshots, "storage", False),
            "machine_images": (self._collect_machine_images, "compute", False),
            "rds_snapshots": (self._collect_rds_snapshots, "data", False),
            "s3_access_points": (self._collect_s3_access_points, "storage", False),
            "s3_multi_region_access_points": (
                self._collect_s3_multi_region_access_points,
                "storage",
                True,
            ),
        }

    # ------------------------------------------------------------------
    # Shared helpers
    # ------------------------------------------------------------------

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
                "CROSS_ACCOUNT_TRUST" if entry["cross"] else "POLICY_ALLOWS_ACTION",
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

    def _share_relations(self, principals: list[str], permission: str) -> list[dict | None]:
        """Account / organization principals a snapshot or image is shared
        with -> GRANTS_ACCESS (principal -> resource)."""
        out: list[dict | None] = []
        for p in principals:
            target = _principal_target(p)
            acct = _arn_account(target or "")
            out.append(
                rel(
                    target,
                    EdgeType.GRANTS_ACCESS,
                    "CROSS_ACCOUNT_TRUST" if acct != self._account_id else "POLICY_ALLOWS_ACTION",
                    reverse=True,
                    description=f"shared via {permission}",
                    permission=permission,
                )
            )
        return out

    # ------------------------------------------------------------------
    # IAM Identity Center
    # ------------------------------------------------------------------

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
        try:
            out["tags"] = [
                t
                async for t in self._paginate(
                    sso,
                    "list_tags_for_resource",
                    "Tags",
                    InstanceArn=instance_arn,
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
        return out

    async def _identity_store(
        self, store_id: str, region: str
    ) -> tuple[list[dict], list[dict], dict[str, set[str]]]:
        """Users, groups and user -> groups memberships (no contact details)."""
        users: list[dict] = []
        groups: list[dict] = []
        memberships: dict[str, set[str]] = {}
        async with self._client("identitystore", region=region) as ids:
            try:
                async for u in self._paginate(ids, "list_users", "Users", IdentityStoreId=store_id):
                    users.append(
                        {
                            "UserId": u.get("UserId"),
                            "UserName": u.get("UserName"),
                            "DisplayName": u.get("DisplayName"),
                            "UserType": u.get("UserType"),
                            "Issuers": sorted(
                                {
                                    e.get("Issuer")
                                    for e in u.get("ExternalIds") or []
                                    if e.get("Issuer")
                                }
                            ),
                        }
                    )
                    if len(users) >= _MAX_IDENTITY_USERS:
                        logger.warning("Identity store users truncated at %d", _MAX_IDENTITY_USERS)
                        break
            except Exception as exc:
                logger.debug("Identity store user listing failed: %s", exc)
            try:
                async for g in self._paginate(
                    ids, "list_groups", "Groups", IdentityStoreId=store_id
                ):
                    groups.append(
                        {
                            "GroupId": g.get("GroupId"),
                            "DisplayName": g.get("DisplayName"),
                            "Description": g.get("Description"),
                            "Issuers": sorted(
                                {
                                    e.get("Issuer")
                                    for e in g.get("ExternalIds") or []
                                    if e.get("Issuer")
                                }
                            ),
                        }
                    )
                    if len(groups) >= _MAX_IDENTITY_GROUPS:
                        logger.warning(
                            "Identity store groups truncated at %d", _MAX_IDENTITY_GROUPS
                        )
                        break
            except Exception as exc:
                logger.debug("Identity store group listing failed: %s", exc)

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
        return users, groups, memberships

    async def _collect_identity_center(self) -> list[CloudAsset]:
        instance, home = await self._find_sso_instance()
        if not instance or not home:
            return []
        inst_arn = instance["InstanceArn"]
        store_id = instance.get("IdentityStoreId") or ""

        async with self._client("sso-admin", region=home) as sso:
            ps_arns = [
                p
                async for p in self._paginate(
                    sso, "list_permission_sets", "PermissionSets", InstanceArn=inst_arn
                )
            ]
            details = await gather_limited(
                [lambda a=a: self._permission_set_detail(sso, inst_arn, a) for a in ps_arns],
                limit=4,
            )

        users: list[dict] = []
        groups: list[dict] = []
        memberships: dict[str, set[str]] = {}
        if store_id:
            try:
                users, groups, memberships = await self._identity_store(store_id, home)
            except Exception as exc:
                logger.debug("Identity store collection failed: %s", exc)

        def principal_arn(ptype: str | None, pid: str | None) -> str | None:
            if not pid:
                return None
            kind = "group" if ptype == "GROUP" else "user"
            return f"arn:aws:identitystore:::{kind}/{pid}"

        # principal -> account -> permission set names
        principal_grants: dict[str, dict[str, set[str]]] = {}
        assets: list[CloudAsset] = []
        for d in details:
            if not d:
                continue
            ps = d["ps"]
            ps_arn = d["arn"]
            ps_name = ps.get("Name") or ps_arn.rsplit("/", 1)[-1]
            accounts: list[str] = d["accounts"]
            relations: list[dict | None] = [
                rel(
                    inst_arn,
                    EdgeType.CONTAINS,
                    reverse=True,
                    description="Identity Center permission set",
                ),
            ]
            for acct in accounts:
                relations.append(
                    rel(
                        _root(acct),
                        EdgeType.MANAGES,
                        "OWNED_BY",
                        description=f"provisions role AWSReservedSSO_{ps_name}_* in {acct}",
                    )
                )
            for pol in d["managed"]:
                relations.append(
                    rel(
                        pol.get("Arn"),
                        EdgeType.IAM_POLICY_ATTACHMENT,
                        "ROLE_HAS_POLICY",
                        description=f"has policy {pol.get('Name')}",
                    )
                )
            refs = 0
            for cmp in d["customer"]:
                path = cmp.get("Path") or "/"
                for acct in accounts:
                    if refs >= _MAX_POLICY_REFS:
                        break
                    refs += 1
                    relations.append(
                        rel(
                            f"arn:aws:iam::{acct}:policy{path}{cmp.get('Name')}",
                            EdgeType.IAM_POLICY_ATTACHMENT,
                            "ROLE_HAS_POLICY",
                            description=f"customer-managed policy {cmp.get('Name')}",
                        )
                    )
            boundary = d["boundary"] or {}
            boundary_desc = None
            if boundary.get("ManagedPolicyArn"):
                boundary_desc = boundary["ManagedPolicyArn"]
                relations.append(
                    rel(boundary_desc, EdgeType.REFERENCES, "PERMISSION_BOUNDARY_LIMITS")
                )
            elif boundary.get("CustomerManagedPolicyReference"):
                ref = boundary["CustomerManagedPolicyReference"]
                path = ref.get("Path") or "/"
                boundary_desc = f"{path}{ref.get('Name')}"
                for acct in accounts[:_MAX_POLICY_REFS]:
                    relations.append(
                        rel(
                            f"arn:aws:iam::{acct}:policy{boundary_desc}",
                            EdgeType.REFERENCES,
                            "PERMISSION_BOUNDARY_LIMITS",
                        )
                    )
            ps_principals: dict[str, set[str]] = {}
            for acct, ptype, pid in d["assignments"]:
                parn = principal_arn(ptype, pid)
                if not parn:
                    continue
                ps_principals.setdefault(parn, set()).add(acct)
                principal_grants.setdefault(parn, {}).setdefault(acct, set()).add(ps_name)
            for parn, accts in ps_principals.items():
                relations.append(
                    rel(
                        parn,
                        EdgeType.ASSUMES_ROLE,
                        "ROLE_ASSUMES_ROLE",
                        reverse=True,
                        description=f"assigned permission set {ps_name}",
                        accounts=sorted(accts)[:50],
                    )
                )
            managed_arns = [p.get("Arn") for p in d["managed"] if p.get("Arn")]
            assets.append(
                self._asset(
                    arn=ps_arn,
                    name=ps_name,
                    asset_type=AssetType.PERMISSION_SET,
                    region=home,
                    tags=d["tags"],
                    metadata={
                        "description": ps.get("Description"),
                        "session_duration": ps.get("SessionDuration"),
                        "created": _ts(ps.get("CreatedDate")),
                        "instance_arn": inst_arn,
                        "managed_policies": managed_arns,
                        "customer_managed_policies": [
                            f"{c.get('Path') or '/'}{c.get('Name')}" for c in d["customer"]
                        ],
                        "has_inline_policy": d["inline"],
                        "permissions_boundary": boundary_desc,
                        "is_admin": "arn:aws:iam::aws:policy/AdministratorAccess" in managed_arns,
                        "provisioned_accounts": accounts,
                        "assignment_count": len(d["assignments"]),
                        "principal_count": len(ps_principals),
                        "provisioned_role_prefix": f"AWSReservedSSO_{ps_name}_",
                        "provisioned_role_path": _SSO_ROLE_PATH,
                    },
                    relations=relations,
                    raw={k: v for k, v in ps.items() if k != "RelayState"},
                )
            )

        def grant_relations(parn: str) -> list[dict | None]:
            return [
                rel(
                    _root(acct),
                    EdgeType.GRANTS_ACCESS,
                    "CROSS_ACCOUNT_TRUST" if acct != self._account_id else "POLICY_ALLOWS_ACTION",
                    description="Identity Center account assignment",
                    permission_sets=sorted(names),
                )
                for acct, names in sorted(principal_grants.get(parn, {}).items())
            ]

        group_arns = {
            g["GroupId"]: principal_arn("GROUP", g["GroupId"]) for g in groups if g.get("GroupId")
        }
        member_counts: dict[str, int] = {}
        for gids in memberships.values():
            for gid in gids:
                member_counts[gid] = member_counts.get(gid, 0) + 1
        for g in groups:
            garn = group_arns.get(g.get("GroupId"))
            if not garn:
                continue
            assets.append(
                self._asset(
                    arn=garn,
                    name=g.get("DisplayName") or g["GroupId"],
                    asset_type=AssetType.IDENTITY_GROUP,
                    region=home,
                    metadata={
                        "group_id": g["GroupId"],
                        "identity_store_id": store_id,
                        "description": g.get("Description"),
                        "external_issuers": g["Issuers"],
                        "member_count": member_counts.get(g["GroupId"], 0),
                        "assigned_accounts": sorted(principal_grants.get(garn, {})),
                    },
                    relations=[rel(inst_arn, EdgeType.CONTAINS, reverse=True)]
                    + grant_relations(garn),
                )
            )
        for u in users:
            uid = u.get("UserId")
            uarn = principal_arn("USER", uid)
            if not uarn:
                continue
            membership = [
                rel(
                    group_arns.get(gid, principal_arn("GROUP", gid)),
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
                    region=home,
                    metadata={
                        "user_id": uid,
                        "user_name": u.get("UserName"),
                        "display_name": u.get("DisplayName"),
                        "user_type": u.get("UserType"),
                        "identity_store_id": store_id,
                        "external_issuers": u["Issuers"],
                        "assigned_accounts": sorted(principal_grants.get(uarn, {})),
                    },
                    relations=[rel(inst_arn, EdgeType.CONTAINS, reverse=True)]
                    + membership
                    + grant_relations(uarn),
                )
            )

        assets.append(
            self._asset(
                arn=inst_arn,
                name=instance.get("Name") or "IAM Identity Center",
                asset_type=AssetType.IDENTITY_PROVIDER,
                region=home,
                metadata={
                    "provider_type": "identity_center",
                    "identity_store_id": store_id,
                    "home_region": home,
                    "owner_account_id": instance.get("OwnerAccountId"),
                    "status": instance.get("Status"),
                    "created": _ts(instance.get("CreatedDate")),
                    "permission_set_count": len([d for d in details if d]),
                    "user_count": len(users),
                    "group_count": len(groups),
                },
                aliases=[store_id],
            )
        )
        return assets

    # ------------------------------------------------------------------
    # IAM extras: SAML providers, access keys, Roles Anywhere
    # ------------------------------------------------------------------

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
            users: list[dict] = []
            async for u in self._paginate(iam, "list_users", "Users"):
                users.append(u)
                if len(users) >= _MAX_ACCESS_KEY_USERS:
                    logger.warning(
                        "Access key collection truncated at %d users", _MAX_ACCESS_KEY_USERS
                    )
                    break

            async def keys_of(user: dict) -> list[CloudAsset]:
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
                    last_date = last.get("LastUsedDate")
                    unused_days = (
                        _age_days(last_date) if last_date else _age_days(k.get("CreateDate"))
                    )
                    active = k.get("Status") == "Active"
                    out.append(
                        self._asset(
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
                                "stale": bool(
                                    active
                                    and unused_days is not None
                                    and unused_days > _STALE_KEY_DAYS
                                ),
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
                    )
                return out

            results = await gather_limited([lambda u=u: keys_of(u) for u in users])
        return [a for res in results if res for a in res]

    async def _collect_rolesanywhere(self) -> list[CloudAsset]:
        async with self._client("rolesanywhere") as ra:
            anchors = [a async for a in self._paginate(ra, "list_trust_anchors", "trustAnchors")]
            profiles = [p async for p in self._paginate(ra, "list_profiles", "profiles")]
        assets: list[CloudAsset] = []
        enabled_anchors = []
        for a in anchors:
            source = a.get("source") or {}
            pca = (source.get("sourceData") or {}).get("acmPcaArn")
            if a.get("enabled"):
                enabled_anchors.append(a.get("trustAnchorArn"))
            assets.append(
                self._asset(
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
                        rel(
                            pca, EdgeType.REFERENCES, "DEPENDS_ON", description="issuing private CA"
                        )
                    ],
                    aliases=[a.get("trustAnchorId")],
                )
            )
        for p in profiles:
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
            assets.append(
                self._asset(
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
            )
        return assets

    # ------------------------------------------------------------------
    # AWS RAM
    # ------------------------------------------------------------------

    async def _collect_ram_shares(self) -> list[CloudAsset]:
        assets: list[CloudAsset] = []
        async with self._client("ram") as ram:
            for owner in ("SELF", "OTHER-ACCOUNTS"):
                try:
                    shares = [
                        s
                        async for s in self._paginate(
                            ram, "get_resource_shares", "resourceShares", resourceOwner=owner
                        )
                    ]
                except Exception:
                    if owner == "SELF":
                        raise
                    logger.debug("RAM shares received from other accounts unavailable")
                    continue
                if not shares:
                    continue
                resources: dict[str, list[dict]] = {}
                principals: dict[str, list[dict]] = {}
                try:
                    async for r in self._paginate(
                        ram, "list_resources", "resources", resourceOwner=owner
                    ):
                        resources.setdefault(r.get("resourceShareArn", ""), []).append(r)
                except Exception as exc:
                    logger.debug("RAM resource listing (%s) failed: %s", owner, exc)
                try:
                    async for p in self._paginate(
                        ram, "list_principals", "principals", resourceOwner=owner
                    ):
                        principals.setdefault(p.get("resourceShareArn", ""), []).append(p)
                except Exception as exc:
                    logger.debug("RAM principal listing (%s) failed: %s", owner, exc)
                for share in shares:
                    assets.append(self._ram_share_asset(share, owner, resources, principals))
        return assets

    def _ram_share_asset(
        self,
        share: dict[str, Any],
        owner: str,
        resources: dict[str, list[dict]],
        principals: dict[str, list[dict]],
    ) -> CloudAsset:
        arn = share.get("resourceShareArn", "")
        owning = share.get("owningAccountId") or self._account_id
        incoming = owner != "SELF"
        shared = resources.get(arn, [])
        prins = principals.get(arn, [])
        relations: list[dict | None] = []
        for r in shared:
            relations.append(
                rel(
                    r.get("arn"),
                    EdgeType.GRANTS_ACCESS,
                    "DEPENDS_ON",
                    description="shared resource",
                    resource_type=r.get("type"),
                    status=r.get("status"),
                    region_scope=r.get("resourceRegionScope"),
                )
            )
        external = False
        for p in prins:
            pid = str(p.get("id", ""))
            target = _principal_target(pid)
            acct = _arn_account(target or "")
            other = (
                bool(p.get("external"))
                or (acct is not None and acct != owning)
                or ":organizations:" in pid
            )
            external = external or bool(p.get("external"))
            relations.append(
                rel(
                    target,
                    EdgeType.GRANTS_ACCESS,
                    "CROSS_ACCOUNT_TRUST" if other else "POLICY_ALLOWS_ACTION",
                    reverse=True,
                    description="resource share principal",
                    external=p.get("external"),
                )
            )
        if incoming and owning:
            relations.append(
                rel(
                    _root(owning),
                    EdgeType.MANAGES,
                    "OWNED_BY",
                    reverse=True,
                    description="share owner",
                )
            )
        # Received shares stay attributed to the observing account; the owner
        # is recorded in metadata and linked (MANAGES) so it materialises.
        return self._asset(
            arn=arn,
            name=share.get("name") or arn.rsplit("/", 1)[-1],
            asset_type=AssetType.RESOURCE_SHARE,
            tags=share.get("tags"),
            metadata={
                "direction": "incoming" if incoming else "outgoing",
                "owning_account_id": owning,
                "status": share.get("status"),
                "allow_external_principals": share.get("allowExternalPrincipals"),
                "feature_set": share.get("featureSet"),
                "created": _ts(share.get("creationTime")),
                "resource_count": len(shared),
                "resource_types": sorted({r.get("type") for r in shared if r.get("type")}),
                "principals": sorted({str(p.get("id")) for p in prins if p.get("id")})[:100],
                "external_principals": external,
                **({"discovered_via": "ram-incoming"} if incoming else {}),
            },
            relations=relations,
            raw={k: v for k, v in share.items() if k != "tags"},
        )

    # ------------------------------------------------------------------
    # Service Catalog / Control Tower Account Factory
    # ------------------------------------------------------------------

    async def _portfolio_asset(self, sc: Any, pf: dict[str, Any]) -> tuple[CloudAsset, set[str]]:
        pid = pf.get("Id", "")
        principals: list[dict] = []
        shared: list[str] = []
        product_ids: set[str] = set()
        product_names: list[str] = []
        try:
            principals = [
                p
                async for p in self._paginate(
                    sc, "list_principals_for_portfolio", "Principals", PortfolioId=pid
                )
            ]
        except Exception as exc:
            logger.debug("Portfolio %s principals failed: %s", pid, exc)
        try:
            shared = [
                a
                async for a in self._pages(
                    sc.list_portfolio_access,
                    "AccountIds",
                    token_in="PageToken",
                    token_out="NextPageToken",
                    PortfolioId=pid,
                )
            ]
        except Exception as exc:
            logger.debug("Portfolio %s access failed: %s", pid, exc)
        try:
            async for p in self._paginate(
                sc, "search_products_as_admin", "ProductViewDetails", PortfolioId=pid
            ):
                summary = p.get("ProductViewSummary") or {}
                if summary.get("ProductId"):
                    product_ids.add(summary["ProductId"])
                if summary.get("Name"):
                    product_names.append(summary["Name"])
        except Exception as exc:
            logger.debug("Portfolio %s products failed: %s", pid, exc)
        relations: list[dict | None] = [
            rel(
                p.get("PrincipalARN"),
                EdgeType.GRANTS_ACCESS,
                "POLICY_ALLOWS_ACTION",
                reverse=True,
                description="portfolio principal",
                principal_type=p.get("PrincipalType"),
            )
            for p in principals
            if "*" not in str(p.get("PrincipalARN", ""))
        ]
        relations += [
            rel(
                _root(a),
                EdgeType.GRANTS_ACCESS,
                "CROSS_ACCOUNT_TRUST",
                reverse=True,
                description="portfolio share",
            )
            for a in shared
            if _ACCOUNT_RE.match(str(a))
        ]
        name = pf.get("DisplayName") or pid
        asset = self._asset(
            arn=pf.get("ARN") or self._arn("catalog", f"portfolio/{pid}"),
            name=name,
            asset_type=AssetType.PRODUCT_PORTFOLIO,
            metadata={
                "portfolio_id": pid,
                "provider": pf.get("ProviderName"),
                "description": pf.get("Description"),
                "created": _ts(pf.get("CreatedTime")),
                "principals": [p.get("PrincipalARN") for p in principals],
                "shared_accounts": shared,
                "products": sorted(product_names),
                "control_tower": "Control Tower" in name
                or _CT_ACCOUNT_FACTORY_PRODUCT in product_names,
            },
            relations=relations,
            aliases=[pid],
        )
        return asset, product_ids

    async def _provisioned_product_asset(
        self, sc: Any, pp: dict[str, Any], portfolios_by_product: dict[str, list[str]]
    ) -> CloudAsset:
        pp_id = pp.get("Id", "")
        launch_role = None
        try:
            detail = (await sc.describe_provisioned_product(Id=pp_id)).get(
                "ProvisionedProductDetail"
            ) or {}
            launch_role = detail.get("LaunchRoleArn")
        except Exception as exc:
            logger.debug("Provisioned product %s describe failed: %s", pp_id, exc)
        output_keys: list[str] = []
        vended_account = None
        output_refs: list[str] = []
        try:
            async for o in self._pages(
                sc.get_provisioned_product_outputs,
                "Outputs",
                token_in="PageToken",
                token_out="NextPageToken",
                ProvisionedProductId=pp_id,
            ):
                key = o.get("OutputKey") or ""
                value = str(o.get("OutputValue") or "")
                output_keys.append(key)
                # Only identifiers are kept; arbitrary output values are not.
                if key.lower() == "accountid" and _ACCOUNT_RE.match(value):
                    vended_account = value
                elif value.startswith("arn:aws"):
                    output_refs.append(value)
        except Exception as exc:
            logger.debug("Provisioned product %s outputs failed: %s", pp_id, exc)
        physical = pp.get("PhysicalId") or ""
        stack_arn = physical if physical.startswith("arn:aws:cloudformation:") else None
        is_account_factory = pp.get("ProductName") == _CT_ACCOUNT_FACTORY_PRODUCT
        relations: list[dict | None] = [
            rel(
                _root(vended_account) if vended_account else None,
                EdgeType.MANAGES,
                "OWNED_BY",
                description="vended account",
            ),
            rel(stack_arn, EdgeType.MANAGES, "OWNED_BY", description="provisioned stack"),
            rel(
                launch_role, EdgeType.ASSUMES_ROLE, "RUNS_ON", description="launch constraint role"
            ),
        ]
        relations += [
            rel(r, EdgeType.REFERENCES, "DEPENDS_ON", description="product output")
            for r in output_refs[:20]
        ]
        relations += [
            rel(pf, EdgeType.REFERENCES, "DEPENDS_ON", description="launched from portfolio")
            for pf in portfolios_by_product.get(pp.get("ProductId", ""), [])
        ]
        return self._asset(
            arn=pp.get("Arn")
            or self._arn("servicecatalog", f"stack/{pp.get('Name', pp_id)}/{pp_id}"),
            name=pp.get("Name") or pp_id,
            asset_type=AssetType.PROVISIONED_PRODUCT,
            tags=pp.get("Tags"),
            metadata={
                "provisioned_product_id": pp_id,
                "type": pp.get("Type"),
                "status": pp.get("Status"),
                "product_id": pp.get("ProductId"),
                "product_name": pp.get("ProductName"),
                "provisioning_artifact": pp.get("ProvisioningArtifactName"),
                "created": _ts(pp.get("CreatedTime")),
                "provisioned_by": pp.get("UserArn"),
                "physical_id": physical,
                "launch_role": launch_role,
                "output_keys": output_keys,
                "vended_account_id": vended_account,
                "control_tower_account_factory": is_account_factory,
            },
            relations=relations,
            aliases=[pp_id],
        )

    async def _collect_service_catalog(self) -> list[CloudAsset]:
        assets: list[CloudAsset] = []
        failures: list[BaseException] = []
        portfolios_by_product: dict[str, list[str]] = {}
        async with self._client("servicecatalog") as sc:
            try:
                portfolios = [
                    p async for p in self._paginate(sc, "list_portfolios", "PortfolioDetails")
                ]
                results = await gather_limited(
                    [lambda p=p: self._portfolio_asset(sc, p) for p in portfolios], limit=4
                )
                for res in results:
                    if not res:
                        continue
                    asset, product_ids = res
                    assets.append(asset)
                    for prod in product_ids:
                        portfolios_by_product.setdefault(prod, []).append(asset.arn or "")
            except Exception as exc:
                failures.append(exc)
                logger.debug("Service Catalog portfolio listing failed: %s", exc)
            try:
                products = [
                    p
                    async for p in self._pages(
                        sc.search_provisioned_products,
                        "ProvisionedProducts",
                        token_in="PageToken",
                        token_out="NextPageToken",
                        AccessLevelFilter={"Key": "Account", "Value": "self"},
                    )
                ]
                results = await gather_limited(
                    [
                        lambda p=p: self._provisioned_product_asset(sc, p, portfolios_by_product)
                        for p in products
                    ],
                    limit=4,
                )
                assets.extend(a for a in results if a)
            except Exception as exc:
                failures.append(exc)
                logger.debug("Service Catalog provisioned product search failed: %s", exc)
        if len(failures) == 2:
            raise failures[0]
        return assets

    # ------------------------------------------------------------------
    # CloudFormation StackSets
    # ------------------------------------------------------------------

    async def _stack_set_asset(self, cfn: Any, summary: dict[str, Any], call_as: str) -> CloudAsset:
        name = summary["StackSetName"]
        ss: dict[str, Any] = {}
        try:
            ss = (await cfn.describe_stack_set(StackSetName=name, CallAs=call_as)).get(
                "StackSet"
            ) or {}
        except Exception as exc:
            logger.debug("Stack set %s describe failed: %s", name, exc)
        instances: list[dict] = []
        try:
            async for inst in self._paginate(
                cfn, "list_stack_instances", "Summaries", StackSetName=name, CallAs=call_as
            ):
                instances.append(inst)
                if len(instances) >= _MAX_STACK_INSTANCES:
                    logger.warning("Stack set %s: instances truncated", name)
                    break
        except Exception as exc:
            logger.debug("Stack set %s instances failed: %s", name, exc)
        accounts = sorted({i.get("Account") for i in instances if i.get("Account")})
        regions = sorted(
            {i.get("Region") for i in instances if i.get("Region")} | set(ss.get("Regions") or [])
        )
        status_counts: dict[str, int] = {}
        relations: list[dict | None] = [
            rel(
                ss.get("AdministrationRoleARN"),
                EdgeType.ASSUMES_ROLE,
                "RUNS_ON",
                description="stack set administration role",
            ),
        ]
        for inst in instances:
            status = inst.get("Status") or "UNKNOWN"
            status_counts[status] = status_counts.get(status, 0) + 1
            relations.append(
                rel(
                    inst.get("StackId"),
                    EdgeType.MANAGES,
                    "OWNED_BY",
                    description="stack instance",
                    account=inst.get("Account"),
                    region=inst.get("Region"),
                    status=status,
                    drift_status=inst.get("DriftStatus"),
                )
            )
        for acct in accounts:
            relations.append(
                rel(
                    _root(acct),
                    EdgeType.MANAGES,
                    "OWNED_BY",
                    description="stack set target account",
                )
            )
        for ou in ss.get("OrganizationalUnitIds") or []:
            relations.append(
                rel(ou, EdgeType.REFERENCES, "DEPENDS_ON", description="deployment target OU")
            )
        exec_role = ss.get("ExecutionRoleName")
        if (
            exec_role
            and (ss.get("PermissionModel") or summary.get("PermissionModel")) == "SELF_MANAGED"
        ):
            for acct in accounts[:_MAX_POLICY_REFS]:
                relations.append(
                    rel(
                        f"arn:aws:iam::{acct}:role/{exec_role}",
                        EdgeType.ASSUMES_ROLE,
                        "RUNS_ON",
                        description="stack set execution role",
                    )
                )
        drift = ss.get("StackSetDriftDetectionDetails") or {}
        auto = ss.get("AutoDeployment") or summary.get("AutoDeployment") or {}
        stack_set_id = ss.get("StackSetId") or summary.get("StackSetId") or name
        return self._asset(
            arn=ss.get("StackSetARN") or self._arn("cloudformation", f"stackset/{stack_set_id}"),
            name=name,
            asset_type=AssetType.STACK_SET,
            tags=ss.get("Tags"),
            metadata={
                "stack_set_id": stack_set_id,
                "status": ss.get("Status") or summary.get("Status"),
                "description": ss.get("Description") or summary.get("Description"),
                "permission_model": ss.get("PermissionModel") or summary.get("PermissionModel"),
                "call_as": call_as,
                "auto_deployment": bool(auto.get("Enabled")),
                "retain_on_account_removal": auto.get("RetainStacksOnAccountRemoval"),
                "capabilities": ss.get("Capabilities") or [],
                "administration_role": ss.get("AdministrationRoleARN"),
                "execution_role_name": exec_role,
                "organizational_unit_ids": ss.get("OrganizationalUnitIds") or [],
                "regions": regions,
                "accounts": accounts,
                "instance_count": len(instances),
                "instance_status": status_counts,
                "drift_status": drift.get("DriftStatus") or summary.get("DriftStatus"),
                "control_tower": name.startswith("AWSControlTower"),
            },
            relations=relations,
            aliases=[stack_set_id],
        )

    async def _collect_stack_sets(self) -> list[CloudAsset]:
        assets: list[CloudAsset] = []
        seen: set[str] = set()
        errors: list[BaseException] = []
        async with self._client("cloudformation") as cfn:
            for call_as in ("SELF", "DELEGATED_ADMIN"):
                try:
                    summaries = [
                        s
                        async for s in self._paginate(
                            cfn, "list_stack_sets", "Summaries", Status="ACTIVE", CallAs=call_as
                        )
                    ]
                except Exception as exc:
                    # DELEGATED_ADMIN fails with ValidationError outside a
                    # delegated administrator account
                    logger.debug("StackSets as %s unavailable: %s", call_as, exc)
                    errors.append(exc)
                    continue
                todo = [
                    s
                    for s in summaries
                    if s.get("StackSetId") not in seen and s.get("StackSetName")
                ]
                seen.update(s.get("StackSetId") for s in todo)
                results = await gather_limited(
                    [lambda s=s, c=call_as: self._stack_set_asset(cfn, s, c) for s in todo], limit=4
                )
                assets.extend(a for a in results if a)
        if len(errors) == 2:
            raise errors[0]
        return assets

    # ------------------------------------------------------------------
    # KMS, Secrets Manager, DynamoDB (override the shallow base versions)
    # ------------------------------------------------------------------

    async def _collect_kms(self) -> list[CloudAsset]:  # type: ignore[override]
        async with self._client("kms") as kms:
            keys = [k async for k in self._paginate(kms, "list_keys", "Keys")]
            aliases: dict[str, list[dict]] = {}
            try:
                async for a in self._paginate(kms, "list_aliases", "Aliases"):
                    if a.get("TargetKeyId"):
                        aliases.setdefault(a["TargetKeyId"], []).append(a)
            except Exception as exc:
                logger.debug("KMS alias listing failed: %s", exc)

            async def detail(entry: dict) -> CloudAsset | None:
                key_id = entry["KeyId"]
                meta = (await kms.describe_key(KeyId=key_id)).get("KeyMetadata", {})
                if meta.get("KeyManager") == "AWS":
                    return None
                rotation: dict[str, Any] = {}
                if (
                    meta.get("KeySpec", "SYMMETRIC_DEFAULT") == "SYMMETRIC_DEFAULT"
                    and meta.get("Origin") != "EXTERNAL"
                ):
                    try:
                        rotation = await kms.get_key_rotation_status(KeyId=key_id)
                    except Exception as exc:
                        logger.debug("KMS rotation status for %s failed: %s", key_id, exc)
                policy_rels: list[dict] = []
                policy_info: dict[str, Any] = {}
                try:
                    policy = (await kms.get_key_policy(KeyId=key_id, PolicyName="default")).get(
                        "Policy"
                    )
                    policy_rels, policy_info = self._resource_policy_access(policy)
                except Exception as exc:
                    logger.debug("KMS key policy for %s failed: %s", key_id, exc)
                grants: dict[str, dict[str, Any]] = {}
                grant_count = 0
                try:
                    async for g in self._paginate(kms, "list_grants", "Grants", KeyId=key_id):
                        grant_count += 1
                        target = _principal_target(str(g.get("GranteePrincipal") or ""))
                        if target and len(grants) < _MAX_GRANTS:
                            entry_g = grants.setdefault(target, {"ops": set(), "names": set()})
                            entry_g["ops"].update(g.get("Operations") or [])
                            if g.get("Name"):
                                entry_g["names"].add(g["Name"])
                except Exception as exc:
                    logger.debug("KMS grants for %s failed: %s", key_id, exc)
                tags: list[dict] = []
                try:
                    tags = [
                        {"Key": t.get("TagKey"), "Value": t.get("TagValue")}
                        async for t in self._paginate(
                            kms, "list_resource_tags", "Tags", KeyId=key_id
                        )
                    ]
                except Exception as exc:
                    logger.debug("KMS tags for %s failed: %s", key_id, exc)
                key_aliases = aliases.get(key_id, [])
                mrc = meta.get("MultiRegionConfiguration") or {}
                primary = (mrc.get("PrimaryKey") or {}).get("Arn")
                is_replica = mrc.get("MultiRegionKeyType") == "REPLICA"
                relations: list[dict | None] = list(policy_rels)
                relations += [
                    rel(
                        target,
                        EdgeType.GRANTS_ACCESS,
                        "CROSS_ACCOUNT_TRUST"
                        if _arn_account(target) not in (None, self._account_id)
                        else "POLICY_ALLOWS_ACTION",
                        reverse=True,
                        description="KMS grant",
                        operations=sorted(g["ops"]),
                        grant_names=sorted(g["names"])[:10],
                    )
                    for target, g in grants.items()
                ]
                if is_replica and primary:
                    relations.append(
                        rel(
                            primary,
                            EdgeType.REFERENCES,
                            "REPLICATES_TO",
                            reverse=True,
                            description="multi-Region primary key",
                        )
                    )
                return self._asset(
                    arn=meta.get("Arn", ""),
                    name=meta.get("KeyId", key_id),
                    asset_type=AssetType.KMS_KEY,
                    tags=tags,
                    metadata={
                        "key_state": meta.get("KeyState"),
                        "key_usage": meta.get("KeyUsage"),
                        "key_manager": meta.get("KeyManager"),
                        "origin": meta.get("Origin"),
                        "rotation_enabled": bool(rotation.get("KeyRotationEnabled", False)),
                        "rotation_period_days": rotation.get("RotationPeriodInDays"),
                        "next_rotation": _ts(rotation.get("NextRotationDate")),
                        "key_spec": meta.get("KeySpec"),
                        "description": meta.get("Description"),
                        "enabled": meta.get("Enabled"),
                        "created": _ts(meta.get("CreationDate")),
                        "deletion_date": _ts(meta.get("DeletionDate")),
                        "pending_deletion": meta.get("KeyState") == "PendingDeletion",
                        "multi_region": meta.get("MultiRegion", False),
                        "multi_region_type": mrc.get("MultiRegionKeyType"),
                        "custom_key_store_id": meta.get("CustomKeyStoreId"),
                        "aliases": [a.get("AliasName") for a in key_aliases],
                        "grant_count": grant_count,
                        "grantees": sorted(grants)[:_MAX_GRANTS],
                        **policy_info,
                    },
                    relations=relations,
                    raw=meta,
                    exposed=bool(policy_info.get("public_policy")),
                    aliases=[a.get("AliasName") for a in key_aliases]
                    + [a.get("AliasArn") for a in key_aliases],
                )

            results = await gather_limited([lambda k=k: detail(k) for k in keys])
        return [a for a in results if a]

    async def _collect_secrets_manager(self) -> list[CloudAsset]:  # type: ignore[override]
        async with self._client("secretsmanager") as sm:
            secrets = [s async for s in self._paginate(sm, "list_secrets", "SecretList")]

            async def detail(secret: dict) -> CloudAsset:
                arn = secret.get("ARN", "")
                replicas: list[dict] = []
                try:
                    replicas = (await sm.describe_secret(SecretId=arn)).get(
                        "ReplicationStatus"
                    ) or []
                except Exception as exc:
                    logger.debug("Secret %s describe failed: %s", secret.get("Name"), exc)
                policy_rels: list[dict] = []
                policy_info: dict[str, Any] = {}
                try:
                    policy = (await sm.get_resource_policy(SecretId=arn)).get("ResourcePolicy")
                    if policy:
                        policy_rels, policy_info = self._resource_policy_access(policy)
                except Exception as exc:
                    logger.debug("Secret %s policy failed: %s", secret.get("Name"), exc)
                kms_key = secret.get("KmsKeyId", "")
                rotation_fn = secret.get("RotationLambdaARN")
                rules = secret.get("RotationRules") or {}
                primary_region = secret.get("PrimaryRegion")
                relations: list[dict | None] = [
                    rel(kms_key, EdgeType.REFERENCES, "ENCRYPTED_BY_KMS"),
                    rel(
                        rotation_fn,
                        EdgeType.INVOKES,
                        "ROTATES_SECRET",
                        description="rotation function",
                    ),
                    *policy_rels,
                ]
                for rep in replicas:
                    region = rep.get("Region")
                    if region and region != self._region:
                        relations.append(
                            rel(
                                arn.replace(f":{self._region}:", f":{region}:", 1),
                                EdgeType.REFERENCES,
                                "REPLICATES_TO",
                                description="secret replica",
                                status=rep.get("Status"),
                            )
                        )
                if primary_region and primary_region != self._region:
                    relations.append(
                        rel(
                            arn.replace(f":{self._region}:", f":{primary_region}:", 1),
                            EdgeType.REFERENCES,
                            "REPLICATES_TO",
                            reverse=True,
                            description="primary secret",
                        )
                    )
                return self._asset(
                    arn=arn,
                    name=secret.get("Name", ""),
                    asset_type=AssetType.SECRET,
                    tags=secret.get("Tags"),
                    metadata={
                        "description": secret.get("Description", ""),
                        "rotation_enabled": secret.get("RotationEnabled", False),
                        "last_accessed": str(secret.get("LastAccessedDate", "")),
                        "last_rotated": str(secret.get("LastRotatedDate", "")),
                        "kms_key_id": kms_key,
                        "rotation_lambda": rotation_fn,
                        "rotation_days": rules.get("AutomaticallyAfterDays"),
                        "rotation_schedule": rules.get("ScheduleExpression"),
                        "next_rotation": _ts(secret.get("NextRotationDate")),
                        "owning_service": secret.get("OwningService"),
                        "primary_region": primary_region,
                        "replica_regions": sorted(
                            r.get("Region") for r in replicas if r.get("Region")
                        ),
                        "created": _ts(secret.get("CreatedDate")),
                        "deleted_date": _ts(secret.get("DeletedDate")),
                        **policy_info,
                    },
                    relations=relations,
                    raw={k: v for k, v in secret.items() if k != "SecretVersionsToStages"},
                    exposed=bool(policy_info.get("public_policy")),
                )

            results = await gather_limited([lambda s=s: detail(s) for s in secrets])
        return [a for a in results if a]

    async def _collect_dynamodb(self) -> list[CloudAsset]:  # type: ignore[override]
        async with self._client("dynamodb") as ddb:
            names = [n async for n in self._paginate(ddb, "list_tables", "TableNames")]

            async def detail(table_name: str) -> CloudAsset:
                table = (await ddb.describe_table(TableName=table_name)).get("Table", {})
                arn = table.get("TableArn", "")
                pitr: dict[str, Any] = {}
                try:
                    pitr = (
                        (await ddb.describe_continuous_backups(TableName=table_name)).get(
                            "ContinuousBackupsDescription"
                        )
                        or {}
                    ).get("PointInTimeRecoveryDescription") or {}
                except Exception as exc:
                    logger.debug("PITR status for %s failed: %s", table_name, exc)
                policy_rels: list[dict] = []
                policy_info: dict[str, Any] = {}
                try:
                    policy = (await ddb.get_resource_policy(ResourceArn=arn)).get("Policy")
                    if policy:
                        policy_rels, policy_info = self._resource_policy_access(policy)
                except Exception as exc:
                    if error_code(exc) != "PolicyNotFoundException":
                        logger.debug("Resource policy for %s failed: %s", table_name, exc)
                destinations: list[dict] = []
                try:
                    destinations = (
                        await ddb.describe_kinesis_streaming_destination(TableName=table_name)
                    ).get("KinesisDataStreamDestinations") or []
                except Exception as exc:
                    logger.debug("Kinesis destinations for %s failed: %s", table_name, exc)
                tags: list[dict] = []
                try:
                    tags = [
                        t
                        async for t in self._paginate(
                            ddb, "list_tags_of_resource", "Tags", ResourceArn=arn
                        )
                    ]
                except Exception as exc:
                    logger.debug("Tags for %s failed: %s", table_name, exc)
                sse = table.get("SSEDescription") or {}
                stream = table.get("StreamSpecification") or {}
                replicas = [
                    r.get("RegionName") for r in table.get("Replicas") or [] if r.get("RegionName")
                ]
                restore = table.get("RestoreSummary") or {}
                relations: list[dict | None] = [
                    rel(sse.get("KMSMasterKeyArn"), EdgeType.REFERENCES, "ENCRYPTED_BY_KMS"),
                    *policy_rels,
                ]
                for region in replicas:
                    if region != self._region:
                        relations.append(
                            rel(
                                arn.replace(f":{self._region}:", f":{region}:", 1),
                                EdgeType.REFERENCES,
                                "REPLICATES_TO",
                                description="global table replica",
                            )
                        )
                for dest in destinations:
                    relations.append(
                        rel(
                            dest.get("StreamArn"),
                            EdgeType.REFERENCES,
                            "STREAMS_TO",
                            description="Kinesis streaming destination",
                            status=dest.get("DestinationStatus"),
                        )
                    )
                relations.append(
                    rel(
                        restore.get("SourceTableArn"),
                        EdgeType.REFERENCES,
                        "DEPENDS_ON",
                        description="restored from table",
                    )
                )
                index_arns = [
                    i.get("IndexArn")
                    for i in (table.get("GlobalSecondaryIndexes") or [])
                    + (table.get("LocalSecondaryIndexes") or [])
                    if i.get("IndexArn")
                ]
                return self._asset(
                    arn=arn,
                    name=table_name,
                    asset_type=AssetType.DYNAMODB_TABLE,
                    tags=tags,
                    metadata={
                        "status": table.get("TableStatus"),
                        "item_count": table.get("ItemCount", 0),
                        "size_bytes": table.get("TableSizeBytes", 0),
                        "billing_mode": (table.get("BillingModeSummary") or {}).get(
                            "BillingMode", "PROVISIONED"
                        ),
                        "encryption": sse.get("Status", "DISABLED"),
                        "sse_type": sse.get("SSEType"),
                        "kms_key_id": sse.get("KMSMasterKeyArn"),
                        "stream_enabled": bool(stream.get("StreamEnabled")),
                        "stream_view_type": stream.get("StreamViewType"),
                        "stream_arn": table.get("LatestStreamArn"),
                        "global_table_version": table.get("GlobalTableVersion"),
                        "replica_regions": replicas,
                        "pitr_enabled": pitr.get("PointInTimeRecoveryStatus") == "ENABLED",
                        "pitr_recovery_days": pitr.get("RecoveryPeriodInDays"),
                        "deletion_protection": table.get("DeletionProtectionEnabled", False),
                        "table_class": (table.get("TableClassSummary") or {}).get("TableClass"),
                        "indexes": [i.rsplit("/", 1)[-1] for i in index_arns],
                        "kinesis_destinations": [
                            d.get("StreamArn") for d in destinations if d.get("StreamArn")
                        ],
                        **policy_info,
                    },
                    relations=relations,
                    raw=table,
                    exposed=bool(policy_info.get("public_policy")),
                    aliases=[table.get("LatestStreamArn"), *index_arns[:20]],
                )

            results = await gather_limited([lambda n=n: detail(n) for n in names])
        return [a for a in results if a]

    # ------------------------------------------------------------------
    # Snapshots and machine images
    # ------------------------------------------------------------------

    async def _collect_ebs_snapshots(self) -> list[CloudAsset]:
        async with self._client("ec2") as ec2:
            snaps: list[dict] = []
            async for s in self._paginate(
                ec2, "describe_snapshots", "Snapshots", OwnerIds=["self"]
            ):
                snaps.append(s)
                if len(snaps) >= _MAX_SNAPSHOTS:
                    logger.warning(
                        "EBS snapshots truncated at %d in %s", _MAX_SNAPSHOTS, self._region
                    )
                    break

            async def perms(snap_id: str) -> tuple[str, list[dict]]:
                resp = await ec2.describe_snapshot_attribute(
                    Attribute="createVolumePermission", SnapshotId=snap_id
                )
                return snap_id, resp.get("CreateVolumePermissions") or []

            results = await gather_limited([lambda s=s: perms(s["SnapshotId"]) for s in snaps])
        permissions = {r[0]: r[1] for r in results if r}
        assets = []
        for s in snaps:
            snap_id = s["SnapshotId"]
            grants = permissions.get(snap_id, [])
            public = any(g.get("Group") == "all" for g in grants)
            accounts = [g["UserId"] for g in grants if g.get("UserId")]
            assets.append(
                self._asset(
                    arn=f"arn:aws:ec2:{self._region}::snapshot/{snap_id}",
                    name=snap_id,
                    asset_type=AssetType.SNAPSHOT,
                    tags=s.get("Tags"),
                    metadata={
                        "snapshot_type": "ebs",
                        "snapshot_id": snap_id,
                        "source_volume_id": s.get("VolumeId"),
                        "size_gb": s.get("VolumeSize"),
                        "state": s.get("State"),
                        "encrypted": s.get("Encrypted", False),
                        "kms_key_id": s.get("KmsKeyId"),
                        "started": _ts(s.get("StartTime")),
                        "storage_tier": s.get("StorageTier"),
                        "description": s.get("Description"),
                        "public": public,
                        "shared_accounts": accounts,
                        "sharing_known": snap_id in permissions,
                    },
                    relations=[
                        rel(
                            s.get("VolumeId"), EdgeType.REFERENCES, description="snapshot of volume"
                        ),
                        rel(s.get("KmsKeyId"), EdgeType.REFERENCES, "ENCRYPTED_BY_KMS"),
                        *self._share_relations(accounts, "createVolumePermission"),
                    ],
                    raw=s,
                    exposed=public,
                    aliases=[self._arn("ec2", f"snapshot/{snap_id}")],
                )
            )
        return assets

    async def _collect_machine_images(self) -> list[CloudAsset]:
        async with self._client("ec2") as ec2:
            images: list[dict] = []
            async for img in self._paginate(ec2, "describe_images", "Images", Owners=["self"]):
                images.append(img)
                if len(images) >= _MAX_IMAGES:
                    logger.warning("AMIs truncated at %d in %s", _MAX_IMAGES, self._region)
                    break

            async def perms(image_id: str) -> tuple[str, list[dict]]:
                resp = await ec2.describe_image_attribute(
                    Attribute="launchPermission", ImageId=image_id
                )
                return image_id, resp.get("LaunchPermissions") or []

            results = await gather_limited([lambda i=i: perms(i["ImageId"]) for i in images])
        permissions = {r[0]: r[1] for r in results if r}
        assets = []
        for img in images:
            image_id = img["ImageId"]
            grants = permissions.get(image_id, [])
            public = bool(img.get("Public")) or any(g.get("Group") == "all" for g in grants)
            accounts = [g["UserId"] for g in grants if g.get("UserId")]
            orgs = [
                g.get("OrganizationArn") or g.get("OrganizationalUnitArn")
                for g in grants
                if g.get("OrganizationArn") or g.get("OrganizationalUnitArn")
            ]
            ebs = [b["Ebs"] for b in img.get("BlockDeviceMappings") or [] if b.get("Ebs")]
            snapshots = [e["SnapshotId"] for e in ebs if e.get("SnapshotId")]
            kms_keys = sorted({e["KmsKeyId"] for e in ebs if e.get("KmsKeyId")})
            relations: list[dict | None] = [
                rel(
                    f"arn:aws:ec2:{self._region}::snapshot/{sid}",
                    EdgeType.REFERENCES,
                    "DEPENDS_ON",
                    description="AMI backing snapshot",
                )
                for sid in snapshots
            ]
            relations += [rel(k, EdgeType.REFERENCES, "ENCRYPTED_BY_KMS") for k in kms_keys]
            relations += self._share_relations(accounts + orgs, "launchPermission")
            relations.append(
                rel(
                    img.get("SourceInstanceId"),
                    EdgeType.REFERENCES,
                    description="created from instance",
                )
            )
            assets.append(
                self._asset(
                    arn=f"arn:aws:ec2:{self._region}::image/{image_id}",
                    name=img.get("Name") or image_id,
                    asset_type=AssetType.MACHINE_IMAGE,
                    tags=img.get("Tags"),
                    metadata={
                        "image_id": image_id,
                        "state": img.get("State"),
                        "public": public,
                        "platform": img.get("PlatformDetails") or img.get("Platform"),
                        "architecture": img.get("Architecture"),
                        "created": img.get("CreationDate"),
                        "deprecation_time": img.get("DeprecationTime"),
                        "last_launched": img.get("LastLaunchedTime"),
                        "root_device_type": img.get("RootDeviceType"),
                        "imds_support": img.get("ImdsSupport"),
                        "source_image_id": img.get("SourceImageId"),
                        "snapshots": snapshots,
                        "encrypted": bool(ebs) and all(e.get("Encrypted") for e in ebs),
                        "shared_accounts": accounts,
                        "shared_organizations": orgs,
                        "sharing_known": image_id in permissions,
                    },
                    relations=relations,
                    raw=img,
                    exposed=public,
                    aliases=[self._arn("ec2", f"image/{image_id}")],
                )
            )
        return assets

    async def _collect_rds_snapshots(self) -> list[CloudAsset]:
        async with self._client("rds") as rds:
            instance_snaps: list[dict] = []
            async for s in self._paginate(
                rds, "describe_db_snapshots", "DBSnapshots", SnapshotType="manual"
            ):
                instance_snaps.append(s)
                if len(instance_snaps) >= _MAX_SNAPSHOTS:
                    break
            cluster_snaps: list[dict] = []
            try:
                async for s in self._paginate(
                    rds,
                    "describe_db_cluster_snapshots",
                    "DBClusterSnapshots",
                    SnapshotType="manual",
                ):
                    cluster_snaps.append(s)
                    if len(cluster_snaps) >= _MAX_SNAPSHOTS:
                        break
            except Exception as exc:
                logger.debug("RDS cluster snapshot listing failed: %s", exc)

            async def instance_attrs(sid: str) -> tuple[str, list[dict]]:
                resp = await rds.describe_db_snapshot_attributes(DBSnapshotIdentifier=sid)
                return sid, (resp.get("DBSnapshotAttributesResult") or {}).get(
                    "DBSnapshotAttributes"
                ) or []

            async def cluster_attrs(sid: str) -> tuple[str, list[dict]]:
                resp = await rds.describe_db_cluster_snapshot_attributes(
                    DBClusterSnapshotIdentifier=sid
                )
                return sid, (resp.get("DBClusterSnapshotAttributesResult") or {}).get(
                    "DBClusterSnapshotAttributes"
                ) or []

            inst_results = await gather_limited(
                [lambda s=s: instance_attrs(s["DBSnapshotIdentifier"]) for s in instance_snaps]
            )
            cl_results = await gather_limited(
                [lambda s=s: cluster_attrs(s["DBClusterSnapshotIdentifier"]) for s in cluster_snaps]
            )
        attrs = {r[0]: r[1] for r in inst_results + cl_results if r}

        def restore_values(sid: str) -> list[str]:
            return [
                str(v)
                for a in attrs.get(sid, [])
                if a.get("AttributeName") == "restore"
                for v in a.get("AttributeValues") or []
            ]

        assets = []
        for s, cluster in [(s, False) for s in instance_snaps] + [(s, True) for s in cluster_snaps]:
            sid = s["DBClusterSnapshotIdentifier"] if cluster else s["DBSnapshotIdentifier"]
            source = s.get("DBClusterIdentifier") if cluster else s.get("DBInstanceIdentifier")
            source_arn = (
                self._arn("rds", f"{'cluster' if cluster else 'db'}:{source}") if source else None
            )
            values = restore_values(sid)
            public = "all" in values
            accounts = [v for v in values if _ACCOUNT_RE.match(v)]
            kms_key = s.get("KmsKeyId")
            arn = (
                s.get("DBClusterSnapshotArn") if cluster else s.get("DBSnapshotArn")
            ) or self._arn("rds", f"{'cluster-snapshot' if cluster else 'snapshot'}:{sid}")
            assets.append(
                self._asset(
                    arn=arn,
                    name=sid,
                    asset_type=AssetType.SNAPSHOT,
                    tags=s.get("TagList"),
                    metadata={
                        "snapshot_type": "rds_cluster" if cluster else "rds",
                        "source_identifier": source,
                        "engine": s.get("Engine"),
                        "engine_version": s.get("EngineVersion"),
                        "status": s.get("Status"),
                        "encrypted": s.get("StorageEncrypted") if cluster else s.get("Encrypted"),
                        "kms_key_id": kms_key,
                        "created": _ts(s.get("SnapshotCreateTime")),
                        "vpc_id": s.get("VpcId"),
                        "public": public,
                        "shared_accounts": accounts,
                        "sharing_known": sid in attrs,
                    },
                    relations=[
                        rel(source_arn, EdgeType.REFERENCES, description="snapshot of database"),
                        rel(kms_key, EdgeType.REFERENCES, "ENCRYPTED_BY_KMS"),
                        *self._share_relations(accounts, "restore"),
                    ],
                    raw={k: v for k, v in s.items() if k != "MasterUsername"},
                    exposed=public,
                )
            )
        return assets

    # ------------------------------------------------------------------
    # S3 access points
    # ------------------------------------------------------------------

    async def _account_public_access_block(self, s3c: Any) -> dict[str, bool] | None:
        try:
            resp = await s3c.get_public_access_block(AccountId=self._account_id)
            return _pab(resp.get("PublicAccessBlockConfiguration") or {})
        except Exception as exc:
            if error_code(exc) == "NoSuchPublicAccessBlockConfiguration":
                return _pab({})
            logger.debug("Account public access block lookup failed: %s", exc)
            return None

    async def _collect_s3_access_points(self) -> list[CloudAsset]:
        if not self._account_id:
            raise ValueError("account_id is required for S3 Control")
        acct = self._account_id
        async with self._client("s3control") as s3c:
            account_pab = await self._account_public_access_block(s3c)
            points = [
                p
                async for p in self._pages(
                    s3c.list_access_points, "AccessPointList", AccountId=acct
                )
            ]

            async def detail(ap: dict) -> CloudAsset:
                name = ap["Name"]
                info: dict[str, Any] = {}
                try:
                    info = await s3c.get_access_point(AccountId=acct, Name=name)
                except Exception as exc:
                    logger.debug("Access point %s describe failed: %s", name, exc)
                policy_public = None
                try:
                    policy_public = bool(
                        (
                            (
                                await s3c.get_access_point_policy_status(AccountId=acct, Name=name)
                            ).get("PolicyStatus")
                            or {}
                        ).get("IsPublic")
                    )
                except Exception as exc:
                    logger.debug("Access point %s policy status failed: %s", name, exc)
                policy_rels: list[dict] = []
                policy_info: dict[str, Any] = {}
                try:
                    policy = (await s3c.get_access_point_policy(AccountId=acct, Name=name)).get(
                        "Policy"
                    )
                    if policy:
                        policy_rels, policy_info = self._resource_policy_access(policy)
                except Exception as exc:
                    if error_code(exc) != "NoSuchAccessPointPolicy":
                        logger.debug("Access point %s policy failed: %s", name, exc)
                ap_pab = _pab(info.get("PublicAccessBlockConfiguration"))
                origin = ap.get("NetworkOrigin") or info.get("NetworkOrigin")
                vpc_id = (ap.get("VpcConfiguration") or info.get("VpcConfiguration") or {}).get(
                    "VpcId"
                )
                bucket = ap.get("Bucket") or info.get("Bucket")
                bucket_account = ap.get("BucketAccountId") or info.get("BucketAccountId")
                restricted = any(
                    p and p.get("RestrictPublicBuckets") for p in (account_pab, ap_pab)
                )
                public = bool(
                    origin == "Internet" and (policy_public or policy_info.get("public_policy"))
                )
                relations: list[dict | None] = [
                    rel(
                        f"arn:aws:s3:::{bucket}" if bucket else None,
                        EdgeType.REFERENCES,
                        "READS_FROM",
                        description="access point bucket",
                        bucket_account=bucket_account,
                    ),
                    rel(vpc_id, EdgeType.ATTACHED_TO, description="VPC-restricted access point"),
                    *policy_rels,
                ]
                if bucket_account and bucket_account != acct:
                    relations.append(
                        rel(
                            _root(bucket_account),
                            EdgeType.REFERENCES,
                            "CROSS_ACCOUNT_TRUST",
                            description="cross-account bucket owner",
                        )
                    )
                return self._asset(
                    arn=ap.get("AccessPointArn") or self._arn("s3", f"accesspoint/{name}"),
                    name=name,
                    asset_type=AssetType.ACCESS_POINT,
                    metadata={
                        "endpoint_kind": "s3_access_point",
                        "bucket": bucket,
                        "bucket_account_id": bucket_account,
                        "network_origin": origin,
                        "vpc_id": vpc_id,
                        "alias": ap.get("Alias") or info.get("Alias"),
                        "data_source_type": ap.get("DataSourceType"),
                        "policy_public": policy_public,
                        "public_access_block": ap_pab,
                        "account_public_access_block": account_pab,
                        "restricted_by_public_access_block": restricted,
                        "created": _ts(info.get("CreationDate")),
                        **policy_info,
                    },
                    relations=relations,
                    raw=ap,
                    exposed=public and not restricted,
                    aliases=[ap.get("Alias") or info.get("Alias")],
                )

            results = await gather_limited([lambda p=p: detail(p) for p in points])
        return [a for a in results if a]

    async def _collect_s3_multi_region_access_points(self) -> list[CloudAsset]:
        if not self._account_id:
            raise ValueError("account_id is required for S3 Control")
        acct = self._account_id
        # The Multi-Region Access Point control plane lives in us-west-2
        async with self._client("s3control", region="us-west-2") as s3c:
            points = [
                p
                async for p in self._pages(
                    s3c.list_multi_region_access_points, "AccessPoints", AccountId=acct
                )
            ]
        assets = []
        for p in points:
            alias = p.get("Alias") or p.get("Name", "")
            regions = p.get("Regions") or []
            pab = _pab(p.get("PublicAccessBlock"))
            assets.append(
                self._asset(
                    arn=f"arn:aws:s3::{acct}:accesspoint/{alias}",
                    name=p.get("Name") or alias,
                    asset_type=AssetType.ACCESS_POINT,
                    region="global",
                    metadata={
                        "endpoint_kind": "s3_multi_region_access_point",
                        "alias": alias,
                        "status": p.get("Status"),
                        "created": _ts(p.get("CreatedAt")),
                        "public_access_block": pab,
                        "regions": [r.get("Region") for r in regions],
                        "buckets": [r.get("Bucket") for r in regions],
                    },
                    relations=[
                        rel(
                            f"arn:aws:s3:::{r['Bucket']}",
                            EdgeType.REFERENCES,
                            "READS_FROM",
                            description="Multi-Region Access Point bucket",
                            region=r.get("Region"),
                            bucket_account=r.get("BucketAccountId"),
                        )
                        for r in regions
                        if r.get("Bucket")
                    ],
                    raw=p,
                    aliases=[alias],
                )
            )
        return assets

    # ------------------------------------------------------------------
    # Cognito
    # ------------------------------------------------------------------

    async def _collect_cognito_user_pools(self) -> list[CloudAsset]:
        async with self._client("cognito-idp") as idp:
            pools = [
                p async for p in self._paginate(idp, "list_user_pools", "UserPools", MaxResults=60)
            ]

            async def detail(summary: dict) -> CloudAsset:
                pool_id = summary["Id"]
                pool = (await idp.describe_user_pool(UserPoolId=pool_id)).get("UserPool") or {}
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
                lambdas = pool.get("LambdaConfig") or summary.get("LambdaConfig") or {}
                triggers: dict[str, str] = {
                    k: lambdas[k] for k in _COGNITO_TRIGGERS if lambdas.get(k)
                }
                for k in _COGNITO_VERSIONED_TRIGGERS:
                    fn = (lambdas.get(k) or {}).get("LambdaArn")
                    if fn:
                        triggers[k] = fn
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
                arn = pool.get("Arn") or self._arn("cognito-idp", f"userpool/{pool_id}")
                admin_only = (pool.get("AdminCreateUserConfig") or {}).get(
                    "AllowAdminCreateUserOnly"
                )
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
                        "advanced_security": (pool.get("UserPoolAddOns") or {}).get(
                            "AdvancedSecurityMode"
                        ),
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
                    relations=relations,
                    exposed=bool(admin_only is False),
                    aliases=[pool_id, f"cognito-idp.{self._region}.amazonaws.com/{pool_id}"],
                )

            results = await gather_limited([lambda p=p: detail(p) for p in pools], limit=4)
        return [a for a in results if a]

    async def _collect_cognito_identity_pools(self) -> list[CloudAsset]:
        async with self._client("cognito-identity") as ci:
            pools = [
                p
                async for p in self._paginate(
                    ci, "list_identity_pools", "IdentityPools", MaxResults=60
                )
            ]

            async def detail(summary: dict) -> CloudAsset:
                pool_id = summary["IdentityPoolId"]
                pool = await ci.describe_identity_pool(IdentityPoolId=pool_id)
                roles: dict[str, Any] = {}
                mapping_roles: list[str] = []
                try:
                    resp = await ci.get_identity_pool_roles(IdentityPoolId=pool_id)
                    roles = resp.get("Roles") or {}
                    mapping_roles = [
                        a for a in arns_in(resp.get("RoleMappings") or {}) if ":role/" in a
                    ]
                except Exception as exc:
                    logger.debug("Identity pool %s roles failed: %s", pool_id, exc)
                unauth = bool(pool.get("AllowUnauthenticatedIdentities"))
                unauth_role = roles.get("unauthenticated")
                relations: list[dict | None] = [
                    rel(
                        roles.get("authenticated"),
                        EdgeType.ASSUMES_ROLE,
                        "ROLE_ASSUMES_ROLE",
                        description="authenticated identities role",
                        identity_type="authenticated",
                    ),
                    rel(
                        unauth_role,
                        EdgeType.ASSUMES_ROLE,
                        "ROLE_ASSUMES_ROLE",
                        description="unauthenticated (guest) identities role",
                        identity_type="unauthenticated",
                    ),
                ]
                relations += [
                    rel(
                        r,
                        EdgeType.ASSUMES_ROLE,
                        "ROLE_ASSUMES_ROLE",
                        description="role mapping rule",
                    )
                    for r in mapping_roles[:50]
                ]
                for provider in pool.get("CognitoIdentityProviders") or []:
                    relations.append(
                        rel(
                            provider.get("ProviderName"),
                            EdgeType.REFERENCES,
                            "DEPENDS_ON",
                            description="Cognito user pool provider",
                            client_id=provider.get("ClientId"),
                        )
                    )
                relations += [
                    rel(
                        p,
                        EdgeType.REFERENCES,
                        "DEPENDS_ON",
                        description="federated identity provider",
                    )
                    for p in (pool.get("OpenIdConnectProviderARNs") or [])
                    + (pool.get("SamlProviderARNs") or [])
                ]
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
                        "login_providers": sorted(
                            (pool.get("SupportedLoginProviders") or {}).keys()
                        ),
                        "developer_provider": pool.get("DeveloperProviderName"),
                        "cognito_providers": [
                            p.get("ProviderName")
                            for p in pool.get("CognitoIdentityProviders") or []
                        ],
                    },
                    relations=relations,
                    exposed=bool(unauth and unauth_role),
                    aliases=[pool_id],
                )

            results = await gather_limited([lambda p=p: detail(p) for p in pools], limit=4)
        return [a for a in results if a]
