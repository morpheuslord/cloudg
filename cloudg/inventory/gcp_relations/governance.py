"""Governance: Resource Manager tags and liens, custom organization policy
constraints, Assured Workloads, authorized organizations, Infrastructure
Manager and Deployment Manager deployments."""

from __future__ import annotations

from typing import Any

from cloudg.inventory.gcp_relations._refs import crm_ref, gcs_ref
from cloudg.inventory.gcp_relations.context import Extracted, GCPContext, _extractor
from cloudg.inventory.gcp_relations.names import _list, dig, full_name, relative_name
from cloudg.schema.models import EdgeType

_CRM = "//cloudresourcemanager.googleapis.com/"


# ---------------------------------------------------------------------------
# Tags and liens
# ---------------------------------------------------------------------------


@_extractor("cloudresourcemanager.googleapis.com/TagKey")
def _tag_key(ctx: GCPContext, out: Extracted) -> None:
    d = ctx.data
    out.add(crm_ref(d.get("parent")), EdgeType.CONTAINS, reverse=True)
    out.alias(relative_name(ctx.name), d.get("namespacedName"))
    out.add(
        full_name(dig(d, "purposeData", "network"), "compute"),
        EdgeType.ATTACHED_TO,
        description="firewall tag network",
    )
    out.metadata.update(
        short_name=d.get("shortName"),
        namespaced_name=d.get("namespacedName"),
        purpose=d.get("purpose"),
    )


@_extractor("cloudresourcemanager.googleapis.com/TagValue")
def _tag_value(ctx: GCPContext, out: Extracted) -> None:
    d = ctx.data
    parent = d.get("parent")
    out.add(
        f"{_CRM}{parent}" if isinstance(parent, str) and parent.startswith("tagKeys/") else None,
        EdgeType.CONTAINS,
        reverse=True,
    )
    out.alias(relative_name(ctx.name), d.get("namespacedName"))
    out.metadata.update(short_name=d.get("shortName"), namespaced_name=d.get("namespacedName"))


def tag_binding_parts(d: dict[str, Any]) -> tuple[str | None, str | None]:
    """(bound resource, tag value) full names of a tag binding."""
    value = d.get("tagValue")
    value_ref = (
        f"{_CRM}{value}" if isinstance(value, str) and value.startswith("tagValues/") else None
    )
    parent = d.get("parent")
    return (full_name(parent) if isinstance(parent, str) else None), value_ref


@_extractor("cloudresourcemanager.googleapis.com/TagBinding")
def _tag_binding(ctx: GCPContext, out: Extracted) -> None:
    """Folded into a TAGGED_WITH relation on the bound resource by the deep collector."""
    d = ctx.data
    resource, value = tag_binding_parts(d)
    out.metadata.update(
        bound_resource=resource,
        tag_value=value,
        tag_value_namespaced_name=d.get("tagValueNamespacedName"),
    )


@_extractor("cloudresourcemanager.googleapis.com/Lien")
def _lien(ctx: GCPContext, out: Extracted) -> None:
    d = ctx.data
    out.add(
        crm_ref(d.get("parent")),
        EdgeType.GOVERNS,
        "COMPLIANCE_GOVERNS",
        description="lien blocks deletion",
        restrictions=list(d.get("restrictions") or []),
    )
    out.metadata.update(
        restrictions=list(d.get("restrictions") or []),
        reason=d.get("reason"),
        origin=d.get("origin"),
    )


# ---------------------------------------------------------------------------
# Organization policy constraints, Assured Workloads, authorized orgs
# ---------------------------------------------------------------------------


@_extractor("orgpolicy.googleapis.com/CustomConstraint")
def _custom_constraint(ctx: GCPContext, out: Extracted) -> None:
    d = ctx.data
    out.alias(relative_name(ctx.name))
    out.metadata.update(
        resource_types=list(d.get("resourceTypes") or []),
        method_types=list(d.get("methodTypes") or []),
        condition=d.get("condition"),
        action_type=d.get("actionType"),
    )


@_extractor("orgpolicy.googleapis.com/Policy")
def _org_policy_custom(ctx: GCPContext, out: Extracted) -> None:
    """A policy enforcing a custom constraint depends on its definition."""
    short = relative_name(ctx.name).rsplit("/policies/", 1)[-1]
    if not short.startswith("custom."):
        return
    org = next((a for a in ctx.ancestors if str(a).startswith("organizations/")), None)
    if org:
        out.add(
            f"//orgpolicy.googleapis.com/{org}/customConstraints/{short}",
            EdgeType.REFERENCES,
            "DEPENDS_ON",
            description="custom constraint definition",
        )


@_extractor("assuredworkloads.googleapis.com/Workload")
def _assured_workload(ctx: GCPContext, out: Extracted) -> None:
    d = ctx.data
    for res in _list(d.get("resources")):
        if not isinstance(res, dict) or not res.get("resourceId"):
            continue
        kind = "folders" if "FOLDER" in str(res.get("resourceType")) else "projects"
        out.add(
            f"{_CRM}{kind}/{res['resourceId']}",
            EdgeType.GOVERNS,
            "COMPLIANCE_GOVERNS",
            description=f"{d.get('complianceRegime')} workload",
            resource_type=res.get("resourceType"),
        )
    out.metadata.update(
        compliance_regime=d.get("complianceRegime"),
        partner=d.get("partner"),
        violation_notifications=d.get("violationNotificationsEnabled"),
        acknowledged_violations=dig(d, "complianceStatus", "acknowledgedViolationCount"),
        active_violations=dig(d, "complianceStatus", "activeViolationCount"),
    )


@_extractor("accesscontextmanager.googleapis.com/AuthorizedOrgsDesc")
def _authorized_orgs(ctx: GCPContext, out: Extracted) -> None:
    d = ctx.data
    for org in _list(d.get("orgs")):
        out.add(
            crm_ref(org),
            EdgeType.GRANTS_ACCESS,
            "CROSS_ACCOUNT_TRUST",
            description=f"{d.get('authorizationType')} {d.get('assetType')}",
        )
    out.metadata.update(
        authorization_type=d.get("authorizationType"),
        authorization_direction=d.get("authorizationDirection"),
        authorized_asset_type=d.get("assetType"),
    )


@_extractor("accesscontextmanager.googleapis.com/ServicePerimeter")
def _perimeter_access_levels(ctx: GCPContext, out: Extracted) -> None:
    status = ctx.data.get("status") or {}
    for level in _list(status.get("accessLevels")):
        out.add(full_name(level, "accesscontextmanager"), EdgeType.REFERENCES, "DEPENDS_ON")


@_extractor("accesscontextmanager.googleapis.com/AccessLevel")
def _access_level(ctx: GCPContext, out: Extracted) -> None:
    d = ctx.data
    conditions = _list(dig(d, "basic", "conditions"))
    out.metadata.update(
        title=d.get("title"),
        combining_function=dig(d, "basic", "combiningFunction"),
        ip_subnetworks=sorted(
            {s for c in conditions if isinstance(c, dict) for s in c.get("ipSubnetworks") or []}
        ),
        regions=sorted(
            {r for c in conditions if isinstance(c, dict) for r in c.get("regions") or []}
        ),
        custom=bool(d.get("custom")),
    )


# ---------------------------------------------------------------------------
# Infrastructure Manager and Deployment Manager (MANAGES)
# ---------------------------------------------------------------------------


@_extractor("config.googleapis.com/Deployment")
def _infra_manager_deployment(ctx: GCPContext, out: Extracted) -> None:
    """Managed resources are listed by the deep collector (Infrastructure Manager API)."""
    d = ctx.data
    out.sa(d.get("serviceAccount"), ctx, "Terraform runner identity")
    blueprint = d.get("terraformBlueprint") or {}
    out.add(
        gcs_ref(blueprint.get("gcsSource")),
        EdgeType.REFERENCES,
        "READS_FROM",
        description="blueprint",
    )
    out.add(
        gcs_ref(d.get("artifactsGcsBucket")),
        EdgeType.REFERENCES,
        "WRITES_TO",
        description="artifacts",
    )
    out.add(full_name(d.get("workerPool"), "cloudbuild"), EdgeType.REFERENCES, "RUNS_ON")
    for res in _list(d.get("managedResources")):
        out.add(
            full_name(res), EdgeType.MANAGES, "OWNED_BY", description="Terraform-managed resource"
        )
    out.metadata.update(
        latest_revision=d.get("latestRevision"),
        git_repo=dig(blueprint, "gitSource", "repo"),
        deployment_state=d.get("state"),
        tf_version=d.get("tfVersion"),
        managed_resource_count=len(_list(d.get("managedResources"))) or None,
    )


@_extractor("config.googleapis.com/Preview")
def _infra_manager_preview(ctx: GCPContext, out: Extracted) -> None:
    out.add(full_name(ctx.data.get("deployment"), "config"), EdgeType.REFERENCES, "DEPENDS_ON")


@_extractor("deploymentmanager.googleapis.com/Deployment")
def _deployment_manager(ctx: GCPContext, out: Extracted) -> None:
    """Deployment Manager deployment and the resources it created (Deployment Manager API)."""
    d = ctx.data
    for res in _list(d.get("resources")):
        if isinstance(res, dict):
            out.add(
                full_name(res.get("url")),
                EdgeType.MANAGES,
                "OWNED_BY",
                description=f"Deployment Manager {res.get('type')}",
            )
    out.metadata.update(
        manifest=str(d.get("manifest") or "").rsplit("/", 1)[-1] or None,
        operation_status=dig(d, "operation", "status"),
        resource_count=len(_list(d.get("resources"))),
    )
