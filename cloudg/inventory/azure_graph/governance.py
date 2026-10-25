"""Extractors for governance: policy, RBAC role definitions, locks, IaC, delegation.

- Policy assignments / exemptions (``policyresources``) become ``GUARDRAIL``
  assets that ``GOVERNS / COMPLIANCE_GOVERNS`` their scope, the same shape
  the tenant hierarchy builds, so both copies dedupe.
- Policy definitions and initiatives become ``ORG_POLICY`` assets. A
  definition whose effective effect is ``deny`` (or ``denyAction``) for an
  enforced assignment ``GOVERNS / SCP_RESTRICTS`` the assignment scope, the
  Azure analogue of an AWS service control policy.
- Non-compliant policy states: assignment ``GOVERNS / FINDING_AFFECTS`` the
  resource.
- RBAC role definitions become ``IAM_POLICY`` assets with their actions;
  each principal holding one gets ``IAM_POLICY_ATTACHMENT`` with
  ``ROLE_HAS_POLICY`` (service principals, managed identities),
  ``USER_HAS_POLICY`` or ``GROUP_HAS_POLICY``.
- Deny assignments ``GOVERNS / POLICY_DENIES_ACTION`` their scope and limit
  their principals (``PERMISSION_BOUNDARY_LIMITS``).
- Resource locks ``GOVERNS / POLICY_DENIES_ACTION`` the locked scope.
- ARM deployments, deployment stacks and managed applications ``MANAGES /
  OWNED_BY`` the resources they created; template specs are what they
  deploy (``DEPENDS_ON``).
- Azure Lighthouse delegations: the managing tenant's principals
  ``GRANTS_ACCESS / CROSS_ACCOUNT_TRUST`` the delegated scope.
- Galleries shared with other subscriptions or tenants, and the
  community gallery flag (``CROSS_ACCOUNT_TRUST``).
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from cloudg.inventory.aws_services._base import rel
from cloudg.inventory.azure_graph.helpers import (
    _GUID_TAIL_RE,
    _get,
    _list,
    _lower,
    _path,
    _props,
    _rid,
    normalize_scope,
    principal_ref,
    subscription_ref,
)
from cloudg.inventory.azure_graph.registry import _Draft, extractor, relation_row
from cloudg.schema.models import AssetType, CloudAsset, CloudProvider, EdgeType

if TYPE_CHECKING:
    from cloudg.inventory.azure_graph.builder import AzureAssetBuilder

_DENY_EFFECTS = {"deny", "denyaction"}
# Principal type -> the ontology relation of its role-definition attachment
_ATTACHMENT_RELATIONSHIP = {"user": "USER_HAS_POLICY", "group": "GROUP_HAS_POLICY"}
_MAX_STATE_RELATIONS = 500
_PRIVILEGED_ACTIONS = (
    "*",
    "microsoft.authorization/*",
    "microsoft.authorization/*/write",
    "microsoft.authorization/roleassignments/write",
    "microsoft.authorization/roledefinitions/write",
)


def extension_owner(extension_id: Any) -> str | None:
    """``<scope>/providers/<ns>/<type>/<name>`` -> ``<scope>`` (``/`` for root)."""
    rid = str(extension_id or "")
    cut = rid.lower().rfind("/providers/")
    if cut < 0:
        return None
    return normalize_scope(rid[:cut]) if cut > 0 else "/"


# ── Azure Policy ──


def _effect_of(definition: _Draft | None, params: dict[str, Any]) -> str | None:
    """Effective effect of a policy definition under an assignment's parameters."""
    if definition is None:
        return None
    effect = _path(definition.props, "policyRule", "then", "effect")
    if not isinstance(effect, str):
        return None
    text = effect.strip()
    if text.lower().startswith("[parameters("):
        name = text.split("'")[1] if "'" in text else ""
        value = _get(_get(params, name) or {}, "value")
        if value is None:
            value = _get(
                _get(_get(definition.props, "parameters") or {}, name) or {}, "defaultValue"
            )
        return str(value) if value is not None else None
    return text


def _assignment_effects(b: "AzureAssetBuilder", d: _Draft) -> list[str]:
    params = _get(d.props, "parameters") or {}
    definition_id = _get(d.props, "policyDefinitionId")
    definition = b.draft(definition_id)
    if definition is None:
        return []
    if definition.type == "microsoft.authorization/policysetdefinitions":
        effects = []
        for member in _list(_get(definition.props, "policyDefinitions")):
            effect = _effect_of(b.draft(_get(member, "policyDefinitionId")), params)
            if effect:
                effects.append(effect)
        return effects
    effect = _effect_of(definition, params)
    return [effect] if effect else []


def _policy_restrictions(b: "AzureAssetBuilder") -> None:
    """Deny-effect definitions restrict the scopes of their enforced assignments."""
    for d in b.drafts_of("microsoft.authorization/policyassignments"):
        effects = _assignment_effects(b, d)
        d.md["effects"] = sorted({e for e in effects if e})
        denies = any(_lower(e) in _DENY_EFFECTS for e in effects)
        d.md["denies"] = denies
        scope = d.md.get("scope")
        if not denies or not d.md.get("enforced", True) or not scope or scope == "/":
            continue
        definition = _get(d.props, "policyDefinitionId")
        b.defer(
            definition,
            rel(
                scope,
                EdgeType.GOVERNS,
                "SCP_RESTRICTS",
                description=f"deny policy assigned by {d.name}",
                assignment_id=d.id,
                not_scopes=d.md.get("not_scopes"),
            ),
        )
    counts = b.state.get("policy_noncompliant") or {}
    for key, n in counts.items():
        assignment = b.draft(key)
        if assignment is not None:
            assignment.md["non_compliant_resources"] = n


@extractor("microsoft.authorization/policyassignments")
def _x_policy_assignment(d: _Draft, b: "AzureAssetBuilder") -> None:
    p = d.props
    scope = normalize_scope(_get(p, "scope")) or extension_owner(d.id)
    definition = _get(p, "policyDefinitionId")
    enforcement = _get(p, "enforcementMode") or "Default"
    not_scopes = [normalize_scope(s) for s in _list(_get(p, "notScopes")) if s]
    d.name = _get(p, "displayName") or d.name
    d.md.update(
        {
            "guardrail_kind": "azure-policy-assignment",
            "scope": scope,
            "policy_definition_id": definition,
            "initiative": "/policysetdefinitions/" in _lower(definition),
            "enforcement_mode": enforcement,
            "enforced": _lower(enforcement) != "donotenforce",
            "not_scopes": not_scopes,
            "description": _get(p, "description"),
        }
    )
    if scope and scope != "/":
        d.add(
            rel(
                scope,
                EdgeType.GOVERNS,
                "COMPLIANCE_GOVERNS",
                description=f"policy {d.name}",
                enforcement_mode=enforcement,
                not_scopes=not_scopes,
            )
        )
    d.add(rel(definition, EdgeType.REFERENCES, "DEPENDS_ON", description="policy definition"))
    b.at_build(_policy_restrictions)


@extractor("microsoft.authorization/policyexemptions")
def _x_policy_exemption(d: _Draft, b: "AzureAssetBuilder") -> None:
    p = d.props
    scope = extension_owner(d.id)
    assignment = _get(p, "policyAssignmentId")
    category = _get(p, "exemptionCategory")
    d.name = _get(p, "displayName") or d.name
    d.md.update(
        {
            "guardrail_kind": "azure-policy-exemption",
            "exemption": True,
            "scope": scope,
            "policy_assignment_id": assignment,
            "exemption_category": category,
            "expires_on": _get(p, "expiresOn"),
        }
    )
    if scope:
        d.add(
            rel(
                scope,
                EdgeType.GOVERNS,
                "COMPLIANCE_GOVERNS",
                description=f"exemption {d.name}",
                exemption=True,
                category=category,
            )
        )
    d.add(
        rel(
            assignment.lower() if isinstance(assignment, str) else None,
            EdgeType.REFERENCES,
            "DEPENDS_ON",
            description="exempted assignment",
        )
    )


@extractor("microsoft.authorization/policydefinitions")
def _x_policy_definition(d: _Draft, b: "AzureAssetBuilder") -> None:
    p = d.props
    d.name = _get(p, "displayName") or d.name
    effect = _path(p, "policyRule", "then", "effect")
    d.md.update(
        {
            "policy_kind": "azure-policy-definition",
            "policy_type": _get(p, "policyType"),
            "mode": _get(p, "mode"),
            "category": _path(p, "metadata", "category"),
            "effect": effect,
            "default_effect": _effect_of(d, {}),
            "parameters": sorted((_get(p, "parameters") or {}).keys()),
        }
    )
    guid = _GUID_TAIL_RE.search(d.id)
    if guid:
        d.alias(f"azure-policy-definition:{guid.group(1).lower()}")


@extractor("microsoft.authorization/policysetdefinitions")
def _x_policy_set(d: _Draft, b: "AzureAssetBuilder") -> None:
    p = d.props
    d.name = _get(p, "displayName") or d.name
    members = [_get(m, "policyDefinitionId") for m in _list(_get(p, "policyDefinitions"))]
    d.md.update(
        {
            "policy_kind": "azure-policy-initiative",
            "policy_type": _get(p, "policyType"),
            "category": _path(p, "metadata", "category"),
            "member_count": len(members),
        }
    )
    for member in members[:500]:
        d.add(rel(member, EdgeType.REFERENCES, "DEPENDS_ON", description="initiative member"))


def add_policy_states(b: "AzureAssetBuilder", rows: list[dict[str, Any]]) -> int:
    """Non-compliant policy states: the assignment GOVERNS / FINDING_AFFECTS the resource."""
    counts: dict[str, int] = b.state.setdefault("policy_noncompliant", {})
    linked: dict[str, int] = {}
    for row in rows:
        assignment = row.get("policyAssignmentId") or _get(
            row.get("properties") or {}, "policyAssignmentId"
        )
        resource = row.get("resourceId") or _get(row.get("properties") or {}, "resourceId")
        if not assignment or not resource:
            continue
        key = str(assignment).lower()
        counts[key] = counts.get(key, 0) + 1
        if linked.get(key, 0) >= _MAX_STATE_RELATIONS:
            continue
        linked[key] = linked.get(key, 0) + 1
        b.defer(
            key,
            rel(
                resource,
                EdgeType.GOVERNS,
                "FINDING_AFFECTS",
                description="non-compliant resource",
                compliance_state=row.get("complianceState") or "NonCompliant",
                policy_definition_id=row.get("policyDefinitionId"),
                effect=row.get("policyDefinitionAction"),
            ),
        )
    b.at_build(_policy_restrictions)
    return len(rows)


# ── RBAC role definitions ──


def _role_privileged(actions: list[str]) -> bool:
    lowered = {a.lower() for a in actions}
    return any(a in lowered for a in _PRIVILEGED_ACTIONS)


def _role_definition_asset(guid: str, row: dict[str, Any], subscription_id: str) -> CloudAsset:
    props = row.get("properties") or {}
    perms = [p for p in _list(_get(props, "permissions")) if isinstance(p, dict)]
    actions = [a for p in perms for a in _list(_get(p, "actions")) if isinstance(a, str)]
    data_actions = [a for p in perms for a in _list(_get(p, "dataActions")) if isinstance(a, str)]
    custom = _lower(_get(props, "type")) == "customrole"
    rid = str(row.get("id") or "")
    arn = rid if custom else f"/providers/Microsoft.Authorization/roleDefinitions/{guid}"
    name = _get(props, "roleName") or guid
    return CloudAsset(
        arn=arn,
        name=name,
        asset_type=AssetType.IAM_POLICY,
        provider=CloudProvider.AZURE,
        region="global",
        account_id=subscription_id if custom else None,
        metadata={
            "resource_type": "microsoft.authorization/roledefinitions",
            "role_definition_id": guid,
            "role_name": name,
            "role_type": _get(props, "type"),
            "custom": custom,
            "description": _get(props, "description"),
            "actions": actions[:200],
            "not_actions": [a for p in perms for a in _list(_get(p, "notActions"))][:200],
            "data_actions": data_actions[:200],
            "not_data_actions": [a for p in perms for a in _list(_get(p, "notDataActions"))][:200],
            "assignable_scopes": _list(_get(props, "assignableScopes"))[:50],
            "privileged": _role_privileged(actions),
            "aliases": list(
                dict.fromkeys(
                    [
                        f"azure-role:{guid}",
                        f"{subscription_ref(subscription_id)}/providers/"
                        f"Microsoft.Authorization/roleDefinitions/{guid}",
                        rid,
                    ]
                )
            ),
        },
    )


def _custom_role_in_scope(row: dict[str, Any], subscription_id: str) -> bool:
    props = row.get("properties") or {}
    if _lower(_get(props, "type")) != "customrole":
        return False
    sub = subscription_ref(subscription_id).lower()
    scopes = [str(s).lower() for s in _list(_get(props, "assignableScopes"))]
    return any(s == sub or s.startswith(sub + "/") for s in scopes)


def role_definition_assets(
    b: "AzureAssetBuilder", definitions: dict[str, dict[str, Any]], role_rows: list[dict]
) -> None:
    """IAM_POLICY assets for assigned and in-scope custom roles, plus attachments."""
    used: dict[str, list[tuple[str, Any, str | None]]] = {}
    for ra in role_rows:
        props = ra.get("properties") or {}
        pid = ra.get("principalId") or _get(props, "principalId")
        rd = ra.get("roleDefinitionId") or _get(props, "roleDefinitionId") or ""
        m = _GUID_TAIL_RE.search(str(rd))
        guid = str(ra.get("roleGuid") or (m.group(1) if m else "")).lower()
        if pid and guid in definitions:
            ptype = ra.get("principalType") or _get(props, "principalType")
            scope = normalize_scope(ra.get("scope") or _get(props, "scope"))
            used.setdefault(guid, []).append((pid, ptype, scope))
    attachments: list[tuple[str, Any, dict[str, Any] | None]] = []
    for guid, row in definitions.items():
        if guid not in used and not _custom_role_in_scope(row, b.subscription_id):
            continue
        asset = _role_definition_asset(guid, row, b.subscription_id)
        b.add_extra(asset)
        seen: set[str] = set()
        for pid, ptype, scope in used.get(guid, []):
            if pid.lower() in seen:
                continue
            seen.add(pid.lower())
            relationship = _ATTACHMENT_RELATIONSHIP.get(_lower(ptype), "ROLE_HAS_POLICY")
            attachments.append(
                (
                    pid,
                    ptype,
                    rel(
                        f"azure-role:{guid}",
                        EdgeType.IAM_POLICY_ATTACHMENT,
                        relationship,
                        description=f"has role {asset.name}",
                        scope=scope,
                    ),
                )
            )
    b.state["role_attachments"] = attachments


# ── PIM eligible role assignments ──


@relation_row("microsoft.authorization/roleeligibilityscheduleinstances")
def _eligible_assignment(row: dict[str, Any], b: "AzureAssetBuilder") -> None:
    """A PIM eligible assignment: the same grant as an active one, marked eligible."""
    p = row.get("properties") or {}
    expanded = _get(p, "expandedProperties") or {}
    b.add_role_assignments(
        [
            {
                "id": row.get("id"),
                "roleDefinitionId": _get(p, "roleDefinitionId"),
                "roleName": _path(expanded, "roleDefinition", "displayName"),
                "principalId": _get(p, "principalId"),
                "principalType": _get(p, "principalType"),
                "scope": _get(p, "scope"),
                "properties": {"condition": _get(p, "condition")},
            }
        ],
        eligible=True,
    )


# ── deny assignments, locks ──


@extractor("microsoft.authorization/denyassignments")
def _x_deny_assignment(d: _Draft, b: "AzureAssetBuilder") -> None:
    p = d.props
    scope = normalize_scope(_get(p, "scope")) or extension_owner(d.id)
    d.name = _get(p, "denyAssignmentName") or d.name
    perms = [x for x in _list(_get(p, "permissions")) if isinstance(x, dict)]
    principals = [x for x in _list(_get(p, "principals")) if isinstance(x, dict)]
    excluded = [x for x in _list(_get(p, "excludePrincipals")) if isinstance(x, dict)]
    everyone = any(str(_get(x, "id")) == "00000000-0000-0000-0000-000000000000" for x in principals)
    d.md.update(
        {
            "guardrail_kind": "azure-deny-assignment",
            "scope": scope,
            "denied_actions": [a for x in perms for a in _list(_get(x, "actions"))][:200],
            "not_actions": [a for x in perms for a in _list(_get(x, "notActions"))][:200],
            "applies_to_everyone": everyone,
            "excluded_principals": [_get(x, "id") for x in excluded],
            "system_protected": _get(p, "isSystemProtected"),
            "applies_to_children": _get(p, "doNotApplyToChildScopes") is not True,
        }
    )
    if scope and scope != "/":
        d.add(
            rel(
                scope,
                EdgeType.GOVERNS,
                "POLICY_DENIES_ACTION",
                description=f"deny assignment {d.name}",
            )
        )
    for x in principals:
        pid = _get(x, "id")
        if not pid or everyone:
            continue
        b.note_principal(pid, _get(x, "type"))
        d.add(
            rel(
                principal_ref(pid),
                EdgeType.REFERENCES,
                "PERMISSION_BOUNDARY_LIMITS",
                reverse=True,
                description="actions denied by deny assignment",
            )
        )


@extractor("microsoft.authorization/locks")
def _x_lock(d: _Draft, b: "AzureAssetBuilder") -> None:
    level = _get(d.props, "level")
    scope = extension_owner(d.id)
    d.md.update(
        {
            "guardrail_kind": "azure-resource-lock",
            "lock_level": level,
            "scope": scope,
            "notes": _get(d.props, "notes"),
            "owners": [_get(o, "applicationId") for o in _list(_get(d.props, "owners"))],
        }
    )
    d.add(
        rel(
            scope,
            EdgeType.GOVERNS,
            "POLICY_DENIES_ACTION",
            description="delete blocked" if _lower(level) == "cannotdelete" else "read-only lock",
            lock_level=level,
        )
    )


# ── deployments, stacks, template specs, managed applications ──


def _managed_resources(d: _Draft, ids: list[Any], description: str) -> None:
    for rid in ids[:500]:
        d.add(rel(_rid(rid), EdgeType.MANAGES, "OWNED_BY", description=description))


@extractor("microsoft.resources/deployments")
def _x_deployment(d: _Draft, b: "AzureAssetBuilder") -> None:
    p = d.props
    link = _get(p, "templateLink") or {}
    d.md.update(
        {
            "iac_kind": "arm-deployment",
            "provisioning_state": _get(p, "provisioningState"),
            "timestamp": _get(p, "timestamp"),
            "mode": _get(p, "mode"),
            "template_hash": _get(p, "templateHash"),
            "template_uri": _get(link, "uri"),
            "duration": _get(p, "duration"),
        }
    )
    _managed_resources(d, _list(_get(p, "outputResources")), "deployed resource")
    d.add(rel(_get(link, "id"), EdgeType.REFERENCES, "DEPENDS_ON", description="template spec"))


@extractor("microsoft.resources/deploymentstacks")
def _x_deployment_stack(d: _Draft, b: "AzureAssetBuilder") -> None:
    p = d.props
    deny = _get(p, "denySettings") or {}
    mode = _get(deny, "mode")
    managed = [_get(r, "id") for r in _list(_get(p, "resources"))]
    d.md.update(
        {
            "iac_kind": "deployment-stack",
            "provisioning_state": _get(p, "provisioningState"),
            "deny_mode": mode,
            "action_on_unmanage": _get(p, "actionOnUnmanage"),
            "managed_resource_count": len(managed),
            "deployment_scope": _get(p, "deploymentScope"),
        }
    )
    _managed_resources(d, managed, "stack-managed resource")
    if _lower(mode) not in ("", "none"):
        for rid in managed[:500]:
            if isinstance(rid, str):
                d.add(
                    rel(
                        rid,
                        EdgeType.GOVERNS,
                        "POLICY_DENIES_ACTION",
                        description=f"deny settings {mode}",
                    )
                )
    d.add(rel(_get(p, "deploymentId"), EdgeType.REFERENCES, "DEPENDS_ON"))
    d.add(rel(_path(p, "templateLink", "id"), EdgeType.REFERENCES, "DEPENDS_ON"))


@extractor("microsoft.resources/templatespecs", "microsoft.resources/templatespecs/versions")
def _x_template_spec(d: _Draft, b: "AzureAssetBuilder") -> None:
    d.md["iac_kind"] = "template-spec"
    d.md["description"] = _get(d.props, "description")


@extractor("microsoft.solutions/applications")
def _x_managed_application(d: _Draft, b: "AzureAssetBuilder") -> None:
    p = d.props
    publisher = _get(p, "publisherTenantId")
    d.md.update(
        {
            "managed_resource_group": _get(p, "managedResourceGroupId"),
            "publisher_tenant_id": publisher,
            "application_definition_id": _get(p, "applicationDefinitionId"),
        }
    )
    d.add(
        rel(
            _get(p, "managedResourceGroupId"),
            EdgeType.MANAGES,
            "OWNED_BY",
            description="managed resource group",
        )
    )
    d.add(rel(_get(p, "applicationDefinitionId"), EdgeType.REFERENCES, "DEPENDS_ON"))
    for auth in _list(_get(p, "authorizations")) + _list(
        _path(p, "jitAccessPolicy", "jitApprovers")
    ):
        pid = _get(auth, "principalId") or _get(auth, "id")
        if not pid:
            continue
        b.note_principal(pid, None)
        d.add(
            rel(
                principal_ref(pid),
                EdgeType.GRANTS_ACCESS,
                "CROSS_ACCOUNT_TRUST",
                reverse=True,
                description="managed application publisher access",
                role_definition_id=_get(auth, "roleDefinitionId"),
                publisher_tenant_id=publisher,
            )
        )


@extractor("microsoft.solutions/applicationdefinitions")
def _x_managed_app_definition(d: _Draft, b: "AzureAssetBuilder") -> None:
    p = d.props
    d.md["lock_level"] = _get(p, "lockLevel")
    for auth in _list(_get(p, "authorizations")):
        pid = _get(auth, "principalId")
        if pid:
            b.note_principal(pid, None)
            d.add(
                rel(
                    principal_ref(pid),
                    EdgeType.GRANTS_ACCESS,
                    "CROSS_ACCOUNT_TRUST",
                    reverse=True,
                    description="publisher authorization on managed resource groups",
                    role_definition_id=_get(auth, "roleDefinitionId"),
                )
            )


# ── Azure Lighthouse ──


@extractor("microsoft.managedservices/registrationassignments")
def _x_lighthouse_assignment(d: _Draft, b: "AzureAssetBuilder") -> None:
    p = d.props
    definition = _get(p, "registrationDefinition") or {}
    dp = _props(definition)
    scope = extension_owner(d.id)
    tenant = _get(dp, "managedByTenantId")
    d.name = _get(dp, "registrationDefinitionName") or d.name
    authorizations = [a for a in _list(_get(dp, "authorizations")) if isinstance(a, dict)]
    eligible = [a for a in _list(_get(dp, "eligibleAuthorizations")) if isinstance(a, dict)]
    d.md.update(
        {
            "delegation_kind": "azure-lighthouse",
            "managed_by_tenant_id": tenant,
            "managed_by_tenant_name": _get(dp, "managedByTenantName"),
            "scope": scope,
            "registration_definition_id": _get(p, "registrationDefinitionId"),
            "authorization_count": len(authorizations),
            "eligible_authorization_count": len(eligible),
        }
    )
    d.add(
        rel(
            scope,
            EdgeType.GRANTS_ACCESS,
            "CROSS_ACCOUNT_TRUST",
            description=f"delegated to tenant {tenant}",
            managed_by_tenant_id=tenant,
        )
    )
    for auth, is_eligible in [(a, False) for a in authorizations] + [(a, True) for a in eligible]:
        pid = _get(auth, "principalId")
        if not pid:
            continue
        b.note_principal(pid, None)
        d.add(
            rel(
                principal_ref(pid),
                EdgeType.ASSUMES_ROLE,
                "CROSS_ACCOUNT_TRUST",
                reverse=True,
                description=_get(auth, "principalIdDisplayName") or "Lighthouse principal",
                role_definition_id=_get(auth, "roleDefinitionId"),
                managed_by_tenant_id=tenant,
                eligible=is_eligible or None,
            )
        )


# ── galleries ──


@extractor("microsoft.compute/galleries")
def _x_gallery(d: _Draft, b: "AzureAssetBuilder") -> None:
    sharing = _get(d.props, "sharingProfile") or {}
    permission = _get(sharing, "permissions")
    d.md["sharing"] = permission
    d.md["community"] = _get(sharing, "communityGalleryInfo") is not None
    if _lower(permission) == "community":
        d.exposed = True
    for group in _list(_get(sharing, "groups")):
        kind = _lower(_get(group, "type"))
        for gid in _list(_get(group, "ids")):
            target = subscription_ref(gid) if kind == "subscriptions" else f"entra:tenant/{gid}"
            d.add(
                rel(
                    target,
                    EdgeType.GRANTS_ACCESS,
                    "CROSS_ACCOUNT_TRUST",
                    reverse=True,
                    description=f"gallery shared with {kind}",
                )
            )


@extractor("microsoft.compute/galleries/images/versions")
def _x_gallery_image_version(d: _Draft, b: "AzureAssetBuilder") -> None:
    p = d.props
    source = _path(p, "storageProfile", "source", "id") or _path(
        p, "storageProfile", "osDiskImage", "source", "id"
    )
    regions = [_get(r, "name") for r in _list(_path(p, "publishingProfile", "targetRegions"))]
    d.md["target_regions"] = [r for r in regions if r]
    d.add(rel(source, EdgeType.REFERENCES, "DEPENDS_ON", description="image source"))


@extractor("microsoft.compute/snapshots", "microsoft.compute/disks")
def _x_disk_sharing(d: _Draft, b: "AzureAssetBuilder") -> None:
    """Snapshot source (the disk BACKUP_TO its snapshot) and disk / snapshot exposure."""
    p = d.props
    policy = _get(p, "networkAccessPolicy")
    d.md["network_access_policy"] = policy
    d.md["public_network_access"] = _get(p, "publicNetworkAccess")
    d.md["max_shares"] = _get(p, "maxShares")
    d.add(
        rel(_get(p, "diskAccessId"), EdgeType.REFERENCES, "DEPENDS_ON", description="disk access")
    )
    # AllowAll: anyone holding a SAS export URL can download the data
    d.md["export_open"] = (
        _lower(policy) == "allowall"
        and _lower(_get(p, "publicNetworkAccess") or "enabled") != "disabled"
    )
    if d.type == "microsoft.compute/snapshots":
        d.md["incremental"] = _get(p, "incremental")
        d.add(
            rel(
                _path(p, "creationData", "sourceResourceId"),
                EdgeType.REFERENCES,
                "BACKUP_TO",
                reverse=True,
                description="snapshot of",
            )
        )


__all__ = [
    "add_policy_states",
    "extension_owner",
    "role_definition_assets",
]
