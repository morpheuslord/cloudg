"""Tenant-level Azure hierarchy: management groups, subscriptions, policy.

One Resource Graph query over ``resourcecontainers`` returns the whole
management-group tree and every subscription with its ancestor chain; one
over ``policyresources`` returns Azure Policy assignments and exemptions
at every scope. The result is a list of CloudAssets with declared
relations (management group / subscription containment, policy
governance) ready for the relationship linker:

- management groups: ``ORG_UNIT``, arn
  ``/providers/Microsoft.Management/managementGroups/<name>``; the tenant
  root group is flagged ``is_tenant_root``; groups named after the standard
  Azure Landing Zones archetypes are flagged ``landing_zone``.
- subscriptions: ``CLOUD_ACCOUNT``, arn ``/subscriptions/<id>`` (the same
  identifier the per-subscription collector uses, so the two dedupe).
- policy assignments / exemptions: ``GUARDRAIL`` assets that ``GOVERNS``
  their scope.
"""

from __future__ import annotations

import logging
from typing import Any, Callable

from cloudg.inventory.aws_services._base import rel
from cloudg.inventory.azure_graph import (
    _get,
    _list,
    _lower,
    _tags,
    default_graph_client_factory,
    management_group_ref,
    normalize_scope,
    principal_ref,
    run_query,
    subscription_ref,
)
from cloudg.schema.models import AssetType, CloudAsset, CloudProvider, EdgeType

logger = logging.getLogger(__name__)

# Standard Azure Landing Zones (CAF / ALZ) management group archetypes
ALZ_ARCHETYPES = (
    "platform",
    "landingzones",
    "corp",
    "online",
    "connectivity",
    "identity",
    "management",
    "sandbox",
    "decommissioned",
)
_ALZ_DISPLAY = {
    "landing zones": "landingzones",
    "sandboxes": "sandbox",
    "decommissioned": "decommissioned",
}

HIERARCHY_QUERY = (
    "resourcecontainers "
    "| where type =~ 'microsoft.management/managementgroups' or type =~ 'microsoft.resources/subscriptions' "
    "| project id, name, type, tenantId, subscriptionId, tags, properties | order by id asc"
)
POLICY_QUERY = (
    "policyresources "
    "| where type =~ 'microsoft.authorization/policyassignments' "
    "or type =~ 'microsoft.authorization/policyexemptions' "
    "| project id, name, type, location, subscriptionId, resourceGroup, identity, properties | order by id asc"
)

_EXEMPTION_MARKER = "/providers/microsoft.authorization/policyexemptions/"


def alz_archetype(name: str | None, display_name: str | None = None) -> str | None:
    """ALZ archetype a management group name matches (``corp``, ...), if any."""
    for candidate in (name, display_name):
        value = _lower(candidate).strip()
        if not value:
            continue
        if value in _ALZ_DISPLAY:
            return _ALZ_DISPLAY[value]
        compact = value.replace(" ", "").replace("_", "-")
        for archetype in ALZ_ARCHETYPES:
            if compact == archetype or compact.endswith("-" + archetype):
                return archetype
    return None


def _asset(
    arn: str,
    name: str,
    asset_type: AssetType,
    metadata: dict[str, Any],
    relations: list[dict[str, Any] | None],
    aliases: list[str | None],
    account_id: str | None = None,
    tags: Any = None,
    region: str = "global",
) -> CloudAsset:
    md = {k: v for k, v in metadata.items() if v is not None}
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
        region=region or "global",
        account_id=account_id,
        tags=_tags(tags),
        metadata=md,
    )


def _management_group_assets(rows: list[dict[str, Any]]) -> tuple[list[CloudAsset], str | None]:
    assets: list[CloudAsset] = []
    root: str | None = None
    for row in rows:
        if _lower(row.get("type")) != "microsoft.management/managementgroups":
            continue
        name = row.get("name") or str(row.get("id", "")).rsplit("/", 1)[-1]
        if not name:
            continue
        props = row.get("properties") or {}
        details = _get(props, "details") or {}
        parent = _get(details, "parent") or {}
        parent_name = _get(parent, "name") or (str(_get(parent, "id") or "").rsplit("/", 1)[-1] or None)
        tenant = row.get("tenantId") or _get(props, "tenantId")
        is_root = not parent_name or (tenant is not None and name.lower() == str(tenant).lower())
        if is_root:
            root = name
        display = _get(props, "displayName") or name
        archetype = None if is_root else alz_archetype(name, display)
        arn = management_group_ref(name)
        assets.append(
            _asset(
                arn,
                display,
                AssetType.ORG_UNIT,
                {
                    "resource_type": "microsoft.management/managementgroups",
                    "management_group_id": name,
                    "display_name": display,
                    "tenant_id": tenant,
                    "is_tenant_root": is_root,
                    "parent_management_group": parent_name,
                    "landing_zone": archetype is not None,
                    "alz_archetype": archetype,
                    "ancestors": [
                        _get(a, "name") for a in _list(_get(details, "managementGroupAncestorsChain")) if _get(a, "name")
                    ],
                },
                [
                    rel(management_group_ref(parent_name), EdgeType.CONTAINS, "ORG_CONTAINS_ACCOUNT", reverse=True)
                    if parent_name and not is_root
                    else None
                ],
                [arn.lower(), row.get("id"), str(row.get("id") or "").lower() or None],
                tags=row.get("tags"),
            )
        )
    return assets, root


def _subscription_assets(rows: list[dict[str, Any]]) -> list[CloudAsset]:
    assets: list[CloudAsset] = []
    for row in rows:
        if _lower(row.get("type")) != "microsoft.resources/subscriptions":
            continue
        sub = row.get("subscriptionId") or str(row.get("id", "")).rsplit("/", 1)[-1]
        if not sub:
            continue
        props = row.get("properties") or {}
        chain = [_get(a, "name") for a in _list(_get(props, "managementGroupAncestorsChain")) if _get(a, "name")]
        parent = chain[0] if chain else None
        display = row.get("name") if row.get("name") and row.get("name") != sub else _get(props, "displayName")
        assets.append(
            _asset(
                subscription_ref(sub),
                display or f"subscription {sub}",
                AssetType.CLOUD_ACCOUNT,
                {
                    "account_id": sub,
                    "subscription_id": sub,
                    "display_name": display,
                    "state": _get(props, "state"),
                    "tenant_id": row.get("tenantId"),
                    "parent_management_group": parent,
                    "management_group_path": list(reversed(chain)),
                    "resource_type": "microsoft.resources/subscriptions",
                },
                [rel(management_group_ref(parent), EdgeType.CONTAINS, "ORG_CONTAINS_ACCOUNT", reverse=True)
                 if parent else None],
                [sub],
                account_id=sub,
                tags=row.get("tags"),
            )
        )
    return assets


def _policy_assets(rows: list[dict[str, Any]]) -> list[CloudAsset]:
    assets: list[CloudAsset] = []
    seen: set[str] = set()
    for row in rows:
        rid = row.get("id")
        if not rid or rid.lower() in seen:
            continue
        seen.add(rid.lower())
        rtype = _lower(row.get("type"))
        props = row.get("properties") or {}
        display = _get(props, "displayName") or row.get("name") or rid.rsplit("/", 1)[-1]
        sub = row.get("subscriptionId") or None
        if rtype == "microsoft.authorization/policyassignments":
            scope = normalize_scope(_get(props, "scope"))
            definition = _get(props, "policyDefinitionId")
            enforcement = _get(props, "enforcementMode") or "Default"
            not_scopes = [normalize_scope(s) for s in _list(_get(props, "notScopes")) if s]
            identity = row.get("identity") or {}
            principal = _get(identity, "principalId") if isinstance(identity, dict) else None
            assets.append(
                _asset(
                    rid,
                    display,
                    AssetType.GUARDRAIL,
                    {
                        "resource_type": row.get("type"),
                        "guardrail_kind": "azure-policy-assignment",
                        "scope": scope,
                        "policy_definition_id": definition,
                        "initiative": "/policysetdefinitions/" in _lower(definition),
                        "enforcement_mode": enforcement,
                        "enforced": _lower(enforcement) != "donotenforce",
                        "not_scopes": not_scopes,
                        "description": _get(props, "description"),
                        "assignment_identity": principal,
                    },
                    [
                        rel(scope, EdgeType.GOVERNS, "COMPLIANCE_GOVERNS", description=f"policy {display}",
                            enforcement_mode=enforcement, not_scopes=not_scopes)
                        if scope and scope != "/"
                        else None
                    ],
                    [rid.lower(), principal_ref(principal)],
                    account_id=sub,
                    region=row.get("location") or "global",
                )
            )
        elif rtype == "microsoft.authorization/policyexemptions":
            lowered = rid.lower()
            cut = lowered.find(_EXEMPTION_MARKER)
            scope = normalize_scope(rid[:cut]) if cut > 0 else None
            assignment = _get(props, "policyAssignmentId")
            category = _get(props, "exemptionCategory")
            assets.append(
                _asset(
                    rid,
                    display,
                    AssetType.GUARDRAIL,
                    {
                        "resource_type": row.get("type"),
                        "guardrail_kind": "azure-policy-exemption",
                        "exemption": True,
                        "scope": scope,
                        "policy_assignment_id": assignment,
                        "exemption_category": category,
                        "expires_on": _get(props, "expiresOn"),
                    },
                    [
                        rel(scope, EdgeType.GOVERNS, "COMPLIANCE_GOVERNS", description=f"exemption {display}",
                            exemption=True, category=category) if scope else None,
                        rel(assignment.lower() if isinstance(assignment, str) else None, EdgeType.REFERENCES,
                            "DEPENDS_ON", description="exempted assignment"),
                    ],
                    [rid.lower()],
                    account_id=sub,
                )
            )
    return assets


def discover_azure_hierarchy(
    credential: Any,
    graph_client_factory: Callable[[Any], Any] | None = None,
    *,
    include_policies: bool = True,
    errors: list[str] | None = None,
) -> list[CloudAsset]:
    """Discover the tenant's management groups, subscriptions and policy.

    Blocking (call via ``asyncio.to_thread`` from async code).

    Args:
        credential: azure-identity TokenCredential.
        graph_client_factory: ``credential -> ResourceGraph-like client``;
            defaults to ``azure.mgmt.resourcegraph.ResourceGraphClient``.
        include_policies: Also map policy assignments and exemptions.
        errors: Optional list receiving non-fatal failure messages.

    Returns:
        ORG_UNIT, CLOUD_ACCOUNT and GUARDRAIL assets with declared relations.

    Raises:
        ImportError: azure-mgmt-resourcegraph is not installed (and no
            factory was given).
        Exception: The management group / subscription query failed.
    """
    factory = graph_client_factory or default_graph_client_factory
    client = factory(credential)
    rows = run_query(client, HIERARCHY_QUERY)
    groups, root = _management_group_assets(rows)
    assets = groups + _subscription_assets(rows)
    if include_policies:
        policy_rows: list[dict[str, Any]] = []
        try:
            if root:
                policy_rows = run_query(client, POLICY_QUERY, management_groups=[root])
            else:
                policy_rows = run_query(client, POLICY_QUERY)
        except Exception as exc:
            logger.warning("Azure policy discovery at the tenant root failed: %s", exc)
            if errors is not None:
                errors.append(f"policyresources: {exc}")
            if root:
                try:
                    policy_rows = run_query(client, POLICY_QUERY)
                except Exception as exc2:
                    if errors is not None:
                        errors.append(f"policyresources (subscriptions): {exc2}")
        assets.extend(_policy_assets(policy_rows))
    logger.info(
        "Azure hierarchy: %d management groups, %d subscriptions, %d policy objects",
        len(groups),
        sum(1 for a in assets if a.asset_type == AssetType.CLOUD_ACCOUNT),
        sum(1 for a in assets if a.asset_type == AssetType.GUARDRAIL),
    )
    return assets
