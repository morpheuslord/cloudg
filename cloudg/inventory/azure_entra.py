"""Microsoft Entra ID through Microsoft Graph: the identity layer of an Azure map.

Read once per tenant (not per subscription) with the azure-identity
credential cloudg already holds (``get_token("https://graph.microsoft.com/.default")``),
using only ``GET`` on Microsoft Graph v1.0. Every listing is best-effort:
a listing the credential may not read (missing Graph application
permissions such as ``Directory.Read.All``, ``Application.Read.All``,
``RoleManagement.Read.Directory``, ``RoleEligibilitySchedule.Read.Directory``)
becomes a FAILED coverage record and the rest is still mapped.

Mapped objects and relations:

- tenant (``ORGANIZATION``, ``entra:tenant/<id>``),
- users (``IDENTITY_USER``) and groups (``IDENTITY_GROUP``) with direct
  members (group ``CONTAINS`` member),
- app registrations (``APP_REGISTRATION``): credential counts and expiry
  (never values), owners (``MANAGES / OWNED_BY``), federated identity
  credentials (``IAM_TRUST`` from the issuer: ``CROSS_ACCOUNT_TRUST`` for
  external issuers), the API permissions they request; the app ``MANAGES /
  OWNED_BY`` its service principal,
- service principals (``SERVICE_PRINCIPAL``; managed identities are left
  to the resources that own them), owners, app-role assignments
  (principal ``GRANTS_ACCESS`` the resource service principal, with the
  role value, e.g. Microsoft Graph ``RoleManagement.ReadWrite.Directory``,
  and ``privileged``), delegated OAuth2 permission grants,
- directory roles (``IAM_POLICY``): active assignments and PIM eligible
  assignments (``IAM_POLICY_ATTACHMENT`` with ``USER_HAS_POLICY`` /
  ``GROUP_HAS_POLICY`` / ``ROLE_HAS_POLICY``, plus ``GRANTS_ACCESS`` the
  tenant with ``eligible`` set for PIM).

Principals use the identifier the subscription collectors use for role
assignment placeholders (``entra:principal/<objectId>``), so the two merge
and every Azure RBAC grant lands on the real Entra object.
"""

from __future__ import annotations

import logging
import time
from typing import Any, Callable, Iterable

from cloudg.coverage import CollectionCoverage
from cloudg.exceptions import CredentialError
from cloudg.inventory.aws_services._base import rel
from cloudg.inventory.azure_graph.families import TaskRecorder
from cloudg.inventory.azure_graph.helpers import principal_ref
from cloudg.inventory.azure_graph.rest import AzureRestError, default_msgraph_client_factory
from cloudg.schema.models import AssetType, CloudAsset, CloudProvider, EdgeType

logger = logging.getLogger(__name__)

_V1 = "/v1.0"
MICROSOFT_GRAPH_APP_ID = "00000003-0000-0000-c000-000000000000"

# Directory role template IDs that hand over the tenant (or most of it)
PRIVILEGED_DIRECTORY_ROLES = {
    "62e90394-69f5-4237-9190-012177145e10",  # Global Administrator
    "e8611ab8-c189-46e8-94e1-60213ab1f814",  # Privileged Role Administrator
    "7be44c8a-adaf-4e2a-84d6-ab2649e08a13",  # Privileged Authentication Administrator
    "9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3",  # Application Administrator
    "158c047a-c907-4556-b7ef-446551a6b5f7",  # Cloud Application Administrator
    "fe930be7-5e62-47db-91af-98c3a49a38b1",  # User Administrator
    "29232cdf-9323-42fd-ade2-1d097af3e4de",  # Exchange Administrator
    "194ae4cb-b126-40b2-bd5b-6091b380977d",  # Security Administrator
    "b1be1c3e-b65d-4f19-8427-f6fa0d97feb9",  # Conditional Access Administrator
    "c4e39bd9-1100-46d3-8c65-fb160da0071f",  # Authentication Administrator
    "729827e3-9c14-49f7-bb1b-9608f156bbb8",  # Helpdesk Administrator
    "966707d0-3269-4727-9be2-8c3a10f19b9d",  # Password Administrator
    "7698a772-787b-4ac8-901f-60d6b08affd2",  # Cloud Device Administrator
    "8ac3fc64-6eca-42ea-9e69-59f4c7b60eb2",  # Hybrid Identity Administrator
}

# Microsoft Graph application permissions that amount to tenant takeover
PRIVILEGED_GRAPH_ROLES = {
    "roledefinition.readwrite.directory",
    "rolemanagement.readwrite.directory",
    "approleassignment.readwrite.all",
    "application.readwrite.all",
    "directory.readwrite.all",
    "user.readwrite.all",
    "group.readwrite.all",
    "groupmember.readwrite.all",
    "serviceprincipalendpoint.readwrite.all",
    "policy.readwrite.conditionalaccess",
    "privilegedaccess.readwrite.azuread",
    "user.manageidentities.all",
}

_PRIVILEGED_SCOPES = {
    "directory.readwrite.all",
    "rolemanagement.readwrite.directory",
    "application.readwrite.all",
    "approleassignment.readwrite.all",
    "user.readwrite.all",
    "mail.readwrite",
    "files.readwrite.all",
    "sites.fullcontrol.all",
    "full_access_as_app",
}


def _asset(
    arn: str,
    name: str,
    asset_type: AssetType,
    tenant: str | None,
    metadata: dict[str, Any],
    relations: Iterable[dict[str, Any] | None] = (),
    aliases: Iterable[str | None] = (),
) -> CloudAsset:
    md = {k: v for k, v in metadata.items() if v not in (None, "", [], {})}
    md["collected_via"] = "microsoft-graph"
    md["tenant_id"] = tenant
    rels = [r for r in relations if r]
    if rels:
        md["relations"] = rels
    alias_list = list(dict.fromkeys(a for a in aliases if a and a != arn))
    if alias_list:
        md["aliases"] = alias_list
    return CloudAsset(
        arn=arn,
        name=name or arn,
        asset_type=asset_type,
        provider=CloudProvider.AZURE,
        region="global",
        account_id=None,
        metadata=md,
    )


def _credential_summary(creds: list[dict[str, Any]]) -> dict[str, Any]:
    ends = sorted(str(c.get("endDateTime") or "") for c in creds if c.get("endDateTime"))
    return {"count": len(creds), "latest_expiry": ends[-1] if ends else None}


class EntraCollector:
    """Maps one Entra tenant through Microsoft Graph.

    Args:
        client: Microsoft Graph REST client (``list(path, **params)``).
        recorder: Task coverage recorder.
        max_objects: Most objects read per listing.
        max_expansions: Most objects whose members / owners / credentials /
            assignments are read one by one.
    """

    def __init__(
        self,
        client: Any,
        recorder: TaskRecorder,
        *,
        max_objects: int = 10000,
        max_expansions: int = 1000,
    ) -> None:
        self.client = client
        self.rec = recorder
        self.max_objects = max_objects
        self.max_expansions = max_expansions
        self.tenant: str | None = None
        self.assets: dict[str, CloudAsset] = {}
        self.credential_error: str | None = None
        self._sp_by_app: dict[str, str] = {}
        self._app_roles: dict[str, dict[str, str]] = {}
        self._sp_names: dict[str, str] = {}

    # ── plumbing ──

    def _list(self, path: str, **params: Any) -> list[dict[str, Any]]:
        return self.client.list(f"{_V1}{path}", max_items=self.max_objects, **params)

    def _task(self, name: str, fn: Callable[[], int]) -> None:
        if self.credential_error:
            self.rec.skip(name, self.credential_error[:300])
            return
        started = time.time()
        try:
            count = fn()
        except CredentialError as exc:
            self.credential_error = str(exc)
            self.rec.skip(name, self.credential_error[:300])
            return
        except AzureRestError as exc:
            reason = "Graph permission missing: " if exc.forbidden else ""
            self.rec.record(name, "FAILED", error=f"{reason}{exc}"[:300], started=started)
            return
        except Exception as exc:
            self.rec.record(
                name, "FAILED", error=f"{type(exc).__name__}: {exc}"[:300], started=started
            )
            return
        self.rec.record(name, "SUCCESS", count, started=started)

    def _expand(self, name: str, ids: list[str], fn: Callable[[str], None]) -> None:
        """Per-object follow-up calls; some may fail (PARTIAL)."""
        if self.credential_error:
            self.rec.skip(name, self.credential_error[:300])
            return
        started = time.time()
        failures: list[str] = []
        done = 0
        for oid in ids[: self.max_expansions]:
            try:
                fn(oid)
                done += 1
            except CredentialError as exc:
                self.credential_error = str(exc)
                failures.append(str(exc))
                break
            except Exception as exc:
                failures.append(str(exc)[:200])
        self.rec.outcome(name, done, failures, min(len(ids), self.max_expansions), started)

    def _add(self, asset: CloudAsset) -> CloudAsset:
        existing = self.assets.get(asset.arn)
        if existing is None:
            self.assets[asset.arn] = asset
            return asset
        existing.metadata.setdefault("relations", []).extend(asset.metadata.get("relations", []))
        return existing

    def _relate(self, arn: str, *relations: dict[str, Any] | None) -> None:
        asset = self.assets.get(arn)
        if asset is not None:
            asset.metadata.setdefault("relations", []).extend(r for r in relations if r)

    def _tenant_ref(self) -> str | None:
        return f"entra:tenant/{self.tenant}" if self.tenant else None

    # ── listings ──

    def organization(self) -> int:
        orgs = self._list(
            "/organization", **{"$select": "id,displayName,tenantType,verifiedDomains"}
        )
        for org in orgs:
            self.tenant = org.get("id")
            domains = [d.get("name") for d in org.get("verifiedDomains") or [] if d.get("name")]
            self._add(
                _asset(
                    f"entra:tenant/{self.tenant}",
                    org.get("displayName") or f"tenant {self.tenant}",
                    AssetType.ORGANIZATION,
                    self.tenant,
                    {"tenant_type": org.get("tenantType"), "verified_domains": domains[:50]},
                )
            )
        return len(orgs)

    def users(self) -> int:
        users = self._list(
            "/users",
            **{
                "$select": "id,displayName,userPrincipalName,userType,accountEnabled,"
                "createdDateTime,externalUserState,onPremisesSyncEnabled",
                "$top": "999",
            },
        )
        for u in users:
            oid = str(u.get("id") or "").lower()
            if not oid:
                continue
            self._add(
                _asset(
                    principal_ref(oid) or oid,
                    u.get("displayName") or u.get("userPrincipalName") or oid,
                    AssetType.IDENTITY_USER,
                    self.tenant,
                    {
                        "principal_id": oid,
                        "principal_type": "User",
                        "user_principal_name": u.get("userPrincipalName"),
                        "user_type": u.get("userType"),
                        "guest": str(u.get("userType") or "").lower() == "guest",
                        "account_enabled": u.get("accountEnabled"),
                        "synced_from_on_premises": u.get("onPremisesSyncEnabled"),
                        "external_state": u.get("externalUserState"),
                    },
                    aliases=[
                        f"entra:upn/{str(u.get('userPrincipalName') or '').lower()}"
                        if u.get("userPrincipalName")
                        else None
                    ],
                )
            )
        return len(users)

    def groups(self) -> int:
        groups = self._list(
            "/groups",
            **{
                "$select": "id,displayName,securityEnabled,mailEnabled,groupTypes,"
                "isAssignableToRole,membershipRule,onPremisesSyncEnabled",
                "$top": "999",
            },
        )
        for g in groups:
            oid = str(g.get("id") or "").lower()
            if not oid:
                continue
            self._add(
                _asset(
                    principal_ref(oid) or oid,
                    g.get("displayName") or oid,
                    AssetType.IDENTITY_GROUP,
                    self.tenant,
                    {
                        "principal_id": oid,
                        "principal_type": "Group",
                        "security_enabled": g.get("securityEnabled"),
                        "role_assignable": g.get("isAssignableToRole"),
                        "dynamic": "DynamicMembership" in (g.get("groupTypes") or []),
                        "membership_rule": g.get("membershipRule"),
                        "synced_from_on_premises": g.get("onPremisesSyncEnabled"),
                    },
                )
            )
        return len(groups)

    def group_members(self, gid: str) -> None:
        members = self._list(f"/groups/{gid}/members", **{"$select": "id", "$top": "999"})
        self._relate(
            principal_ref(gid) or gid,
            *[
                rel(principal_ref(m.get("id")), EdgeType.CONTAINS, description="group member")
                for m in members
            ],
        )

    def applications(self) -> int:
        apps = self._list(
            "/applications",
            **{
                "$select": "id,appId,displayName,signInAudience,requiredResourceAccess,"
                "passwordCredentials,keyCredentials,publisherDomain,createdDateTime,web",
                "$top": "999",
            },
        )
        for app in apps:
            oid = str(app.get("id") or "").lower()
            app_id = str(app.get("appId") or "").lower()
            if not oid:
                continue
            requested = [
                {
                    "resource_app_id": r.get("resourceAppId"),
                    "count": len(r.get("resourceAccess") or []),
                }
                for r in app.get("requiredResourceAccess") or []
            ]
            redirect = ((app.get("web") or {}).get("redirectUris") or [])[:20]
            self._add(
                _asset(
                    f"entra:application/{oid}",
                    app.get("displayName") or app_id,
                    AssetType.APP_REGISTRATION,
                    self.tenant,
                    {
                        "object_id": oid,
                        "app_id": app_id,
                        "sign_in_audience": app.get("signInAudience"),
                        "multi_tenant": "multiple" in str(app.get("signInAudience") or "").lower()
                        or "personal" in str(app.get("signInAudience") or "").lower(),
                        "secrets": _credential_summary(app.get("passwordCredentials") or []),
                        "certificates": _credential_summary(app.get("keyCredentials") or []),
                        "requested_permissions": requested,
                        "redirect_uris": redirect,
                        "publisher_domain": app.get("publisherDomain"),
                    },
                    aliases=[f"entra:app/{app_id}" if app_id else None],
                )
            )
        return len(apps)

    def application_owners(self, oid: str) -> None:
        owners = self._list(f"/applications/{oid}/owners", **{"$select": "id"})
        self._relate(
            f"entra:application/{oid}",
            *[
                rel(
                    principal_ref(o.get("id")),
                    EdgeType.MANAGES,
                    "OWNED_BY",
                    reverse=True,
                    description="application owner",
                )
                for o in owners
            ],
        )

    def federated_credentials(self, oid: str) -> None:
        creds = self._list(f"/applications/{oid}/federatedIdentityCredentials")
        relations = []
        for c in creds:
            issuer = str(c.get("issuer") or "").rstrip("/")
            aks = "prod-aks.azure.com" in issuer.lower()
            relations.append(
                rel(
                    issuer,
                    EdgeType.IAM_TRUST,
                    "ROLE_ASSUMES_ROLE" if aks else "CROSS_ACCOUNT_TRUST",
                    reverse=True,
                    description=f"federated credential {c.get('name')}",
                    subject=c.get("subject"),
                    audiences=c.get("audiences"),
                )
            )
        asset = self.assets.get(f"entra:application/{oid}")
        if asset is not None and creds:
            asset.metadata["federated_credentials"] = [
                {"name": c.get("name"), "issuer": c.get("issuer"), "subject": c.get("subject")}
                for c in creds
            ]
        self._relate(f"entra:application/{oid}", *relations)

    def service_principals(self) -> int:
        sps = self._list(
            "/servicePrincipals",
            **{
                "$select": "id,appId,displayName,servicePrincipalType,appOwnerOrganizationId,"
                "accountEnabled,appRoleAssignmentRequired,appRoles,alternativeNames,publisherName",
                "$top": "999",
            },
        )
        count = 0
        for sp in sps:
            oid = str(sp.get("id") or "").lower()
            app_id = str(sp.get("appId") or "").lower()
            if not oid:
                continue
            self._sp_by_app[app_id] = oid
            self._sp_names[oid] = sp.get("displayName") or app_id
            self._app_roles[oid] = {
                str(r.get("id")).lower(): str(r.get("value") or r.get("displayName") or "")
                for r in sp.get("appRoles") or []
            }
            if str(sp.get("servicePrincipalType") or "").lower() == "managedidentity":
                continue  # represented by the resource / user-assigned identity that owns it
            owner_org = str(sp.get("appOwnerOrganizationId") or "").lower()
            external = bool(owner_org and self.tenant and owner_org != str(self.tenant).lower())
            count += 1
            self._add(
                _asset(
                    principal_ref(oid) or oid,
                    sp.get("displayName") or app_id,
                    AssetType.SERVICE_PRINCIPAL,
                    self.tenant,
                    {
                        "principal_id": oid,
                        "principal_type": "ServicePrincipal",
                        "app_id": app_id,
                        "service_principal_type": sp.get("servicePrincipalType"),
                        "app_owner_tenant_id": owner_org or None,
                        "external_application": external,
                        "microsoft_first_party": owner_org
                        == "f8cdef31-a31e-4b4a-93e4-5f571e91255a",
                        "enabled": sp.get("accountEnabled"),
                        "assignment_required": sp.get("appRoleAssignmentRequired"),
                        "publisher": sp.get("publisherName"),
                    },
                    aliases=[f"azure-client-id:{app_id}" if app_id else None],
                )
            )
        for asset in list(self.assets.values()):
            if asset.asset_type != AssetType.APP_REGISTRATION:
                continue
            sp = self._sp_by_app.get(str(asset.metadata.get("app_id") or ""))
            if sp:
                asset.metadata.setdefault("relations", []).append(
                    rel(
                        principal_ref(sp),
                        EdgeType.MANAGES,
                        "OWNED_BY",
                        description="service principal of this app",
                    )
                )
        return count

    def sp_owners(self, oid: str) -> None:
        owners = self._list(f"/servicePrincipals/{oid}/owners", **{"$select": "id"})
        self._relate(
            principal_ref(oid) or oid,
            *[
                rel(
                    principal_ref(o.get("id")),
                    EdgeType.MANAGES,
                    "OWNED_BY",
                    reverse=True,
                    description="service principal owner",
                )
                for o in owners
            ],
        )

    def app_role_assignments(self, resource_oid: str) -> None:
        assignments = self._list(
            f"/servicePrincipals/{resource_oid}/appRoleAssignedTo", **{"$top": "999"}
        )
        roles = self._app_roles.get(resource_oid, {})
        resource_name = self._sp_names.get(resource_oid, resource_oid)
        relations = []
        for a in assignments:
            value = roles.get(str(a.get("appRoleId") or "").lower()) or "default access"
            relations.append(
                rel(
                    principal_ref(a.get("principalId")),
                    EdgeType.GRANTS_ACCESS,
                    "POLICY_ALLOWS_ACTION",
                    reverse=True,
                    description=f"app role {value} on {resource_name}",
                    role=value,
                    principal_type=a.get("principalType"),
                    privileged=value.lower() in PRIVILEGED_GRAPH_ROLES or None,
                    application_permission=str(a.get("principalType") or "") == "ServicePrincipal"
                    or None,
                )
            )
        self._relate(principal_ref(resource_oid) or resource_oid, *relations)

    def oauth2_grants(self) -> int:
        grants = self._list("/oauth2PermissionGrants")
        for g in grants:
            client = str(g.get("clientId") or "").lower()
            scopes = [s for s in str(g.get("scope") or "").split() if s]
            all_users = str(g.get("consentType") or "") == "AllPrincipals"
            self._relate(
                principal_ref(client) or client,
                rel(
                    principal_ref(g.get("resourceId")),
                    EdgeType.GRANTS_ACCESS,
                    "POLICY_ALLOWS_ACTION",
                    description=f"delegated {', '.join(scopes[:5])}",
                    delegated=True,
                    scopes=scopes[:50],
                    consent_type=g.get("consentType"),
                    on_behalf_of=None if all_users else g.get("principalId"),
                    privileged=any(s.lower() in _PRIVILEGED_SCOPES for s in scopes)
                    and all_users
                    or None,
                ),
            )
        return len(grants)

    def directory_roles(self) -> int:
        definitions = self._list(
            "/roleManagement/directory/roleDefinitions",
            **{"$select": "id,displayName,isBuiltIn,templateId,description,rolePermissions"},
        )
        by_id = {str(d.get("id")).lower(): d for d in definitions}
        assignments = self._list(
            "/roleManagement/directory/roleAssignments",
            **{"$select": "id,principalId,roleDefinitionId,directoryScopeId"},
        )
        self._role_assignments(by_id, assignments, eligible=False)
        self._role_defs = by_id
        return len(assignments)

    def pim_eligibility(self) -> int:
        by_id = getattr(self, "_role_defs", {})
        schedules = self._list(
            "/roleManagement/directory/roleEligibilitySchedules",
            **{"$select": "id,principalId,roleDefinitionId,directoryScopeId,memberType"},
        )
        self._role_assignments(by_id, schedules, eligible=True)
        return len(schedules)

    def _role_asset(self, rid: str, definition: dict[str, Any]) -> str:
        arn = f"entra:directoryRole/{rid}"
        template = str(definition.get("templateId") or rid).lower()
        actions = [
            a
            for p in definition.get("rolePermissions") or []
            for a in p.get("allowedResourceActions") or []
        ]
        self._add(
            _asset(
                arn,
                definition.get("displayName") or rid,
                AssetType.IAM_POLICY,
                self.tenant,
                {
                    "directory_role": True,
                    "role_template_id": template,
                    "built_in": definition.get("isBuiltIn"),
                    "privileged": template in PRIVILEGED_DIRECTORY_ROLES,
                    "description": definition.get("description"),
                    "actions": actions[:200],
                },
            )
        )
        return arn

    def _role_assignments(
        self, by_id: dict[str, Any], rows: list[dict[str, Any]], *, eligible: bool
    ) -> None:
        for row in rows:
            rid = str(row.get("roleDefinitionId") or "").lower()
            pid = str(row.get("principalId") or "").lower()
            if not rid or not pid:
                continue
            definition = by_id.get(rid) or {"displayName": rid}
            role_arn = self._role_asset(rid, definition)
            principal = self.assets.get(principal_ref(pid) or "")
            kind = principal.asset_type if principal is not None else None
            relationship = {
                AssetType.IDENTITY_USER: "USER_HAS_POLICY",
                AssetType.IDENTITY_GROUP: "GROUP_HAS_POLICY",
            }.get(kind, "ROLE_HAS_POLICY")
            privileged = (
                str(definition.get("templateId") or rid).lower() in PRIVILEGED_DIRECTORY_ROLES
            )
            relations = [
                rel(
                    role_arn,
                    EdgeType.IAM_POLICY_ATTACHMENT,
                    relationship,
                    description=f"directory role {definition.get('displayName')}",
                    eligible=eligible or None,
                    directory_scope=row.get("directoryScopeId"),
                ),
                rel(
                    self._tenant_ref(),
                    EdgeType.GRANTS_ACCESS,
                    "POLICY_ALLOWS_ACTION",
                    description=f"{definition.get('displayName')} (directory role)",
                    role=definition.get("displayName"),
                    privileged=privileged or None,
                    eligible=eligible or None,
                    directory_scope=row.get("directoryScopeId"),
                ),
            ]
            if principal is not None:
                principal.metadata.setdefault("relations", []).extend(r for r in relations if r)
            else:
                # principal not listed (managed identity, or listing not permitted)
                self._add(
                    _asset(
                        principal_ref(pid) or pid,
                        f"Entra principal {pid}",
                        AssetType.SERVICE_PRINCIPAL,
                        self.tenant,
                        {
                            "principal_id": pid,
                            "placeholder": True,
                            "discovered_via": "entra-principal-reference",
                        },
                        relations,
                    )
                )

    # ── run ──

    def collect(self) -> list[CloudAsset]:
        self._task("entra_tenant", self.organization)
        self._task("entra_users", self.users)
        self._task("entra_groups", self.groups)
        self._task("entra_applications", self.applications)
        self._task("entra_service_principals", self.service_principals)
        groups = [
            a.metadata["principal_id"]
            for a in self.assets.values()
            if a.asset_type == AssetType.IDENTITY_GROUP
        ]
        apps = [
            a.metadata["object_id"]
            for a in self.assets.values()
            if a.asset_type == AssetType.APP_REGISTRATION
        ]
        sps = [
            a.metadata["principal_id"]
            for a in self.assets.values()
            if a.asset_type == AssetType.SERVICE_PRINCIPAL
        ]
        self._expand("entra_group_members", groups, self.group_members)
        self._expand("entra_application_owners", apps, self.application_owners)
        self._expand("entra_federated_credentials", apps, self.federated_credentials)
        self._expand(
            "entra_service_principal_owners",
            [s for s in sps if not self._is_first_party(s)],
            self.sp_owners,
        )
        resources = [oid for oid, roles in self._app_roles.items() if roles]
        resources.sort(key=lambda oid: oid != self._sp_by_app.get(MICROSOFT_GRAPH_APP_ID))
        self._expand("entra_app_role_assignments", resources, self.app_role_assignments)
        self._task("entra_oauth2_grants", self.oauth2_grants)
        self._task("entra_directory_roles", self.directory_roles)
        self._task("entra_pim_eligibility", self.pim_eligibility)
        return list(self.assets.values())

    def _is_first_party(self, oid: str) -> bool:
        asset = self.assets.get(principal_ref(oid) or "")
        return bool(asset and asset.metadata.get("microsoft_first_party"))


def discover_entra(
    credential: Any,
    client_factory: Callable[[Any], Any] | None = None,
    *,
    coverage: CollectionCoverage | None = None,
    max_objects: int = 10000,
    max_expansions: int = 1000,
) -> list[CloudAsset]:
    """Map the Entra tenant of ``credential`` (blocking; call via ``asyncio.to_thread``).

    Raises:
        CredentialError: No Microsoft Graph token could be obtained at all.
    """
    client = (client_factory or default_msgraph_client_factory)(credential)
    collector = EntraCollector(
        client,
        TaskRecorder(coverage),
        max_objects=max_objects,
        max_expansions=max_expansions,
    )
    assets = collector.collect()
    if collector.credential_error and not assets:
        raise CredentialError("azure", f"Microsoft Graph: {collector.credential_error}")
    logger.info("Entra ID: %d objects mapped", len(assets))
    return assets


__all__ = ["EntraCollector", "discover_entra"]
