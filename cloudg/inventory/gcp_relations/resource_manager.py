"""Resource hierarchy, organization policies and VPC-SC perimeters."""

from __future__ import annotations

import re
from typing import Any

from cloudg.inventory.gcp_relations.context import Extracted, GCPContext, _extractor
from cloudg.inventory.gcp_relations.names import (
    _list,
    _num,
    dig,
    full_name,
    relative_name,
)
from cloudg.schema.models import EdgeType

# ---------------------------------------------------------------------------
# Resource hierarchy
# ---------------------------------------------------------------------------


def _crm_parent(parent: Any) -> str | None:
    if isinstance(parent, dict):
        ptype, pid = parent.get("type"), _num(parent.get("id"))
        if ptype and pid:
            return f"//cloudresourcemanager.googleapis.com/{ptype.rstrip('s')}s/{pid}"
        return None
    if isinstance(parent, str) and re.fullmatch(r"(organizations|folders|projects)/[^/]+", parent):
        return f"//cloudresourcemanager.googleapis.com/{parent}"
    return None


def _ancestor_parent(ctx: GCPContext) -> str | None:
    return _crm_parent(ctx.ancestors[1]) if len(ctx.ancestors) > 1 else None


def _crm_node(ctx: GCPContext, out: Extracted, display_name: Any) -> None:
    """Display name, lifecycle state and parent containment of a project or folder."""
    d = ctx.data
    out.metadata["display_name"] = display_name
    out.metadata["lifecycle_state"] = d.get("lifecycleState") or d.get("state")
    parent = _crm_parent(d.get("parent")) or _ancestor_parent(ctx)
    out.add(parent, EdgeType.CONTAINS, "ORG_CONTAINS_ACCOUNT", reverse=True)


@_extractor("cloudresourcemanager.googleapis.com/Project")
def _project(ctx: GCPContext, out: Extracted) -> None:
    d = ctx.data
    number = _num(d.get("projectNumber"))
    if not number and isinstance(d.get("name"), str) and d["name"].startswith("projects/"):
        number = d["name"].split("/", 1)[1]
    number = number or ctx.project_number or relative_name(ctx.name).split("/")[-1]
    pid = d.get("projectId") or ctx.project_id
    out.alias(f"projects/{number}", number)
    if pid:
        out.alias(
            f"projects/{pid}",
            pid,
            f"//cloudresourcemanager.googleapis.com/projects/{pid}",
        )
        out.metadata["account_id"] = pid
        out.metadata["project_id"] = pid
    out.alias(f"//cloudresourcemanager.googleapis.com/projects/{number}")
    out.metadata["project_number"] = number
    _crm_node(
        ctx,
        out,
        d.get("displayName")
        or (d.get("name") if not str(d.get("name", "")).startswith("projects/") else None),
    )


@_extractor("cloudresourcemanager.googleapis.com/Folder")
def _folder(ctx: GCPContext, out: Extracted) -> None:
    d = ctx.data
    rel_name = (
        d.get("name") if str(d.get("name", "")).startswith("folders/") else relative_name(ctx.name)
    )
    out.alias(rel_name)
    _crm_node(ctx, out, d.get("displayName"))


@_extractor("cloudresourcemanager.googleapis.com/Organization")
def _organization(ctx: GCPContext, out: Extracted) -> None:
    out.alias(relative_name(ctx.name))
    out.metadata["display_name"] = ctx.data.get("displayName")
    out.metadata["directory_customer_id_present"] = bool(
        dig(ctx.data, "owner", "directoryCustomerId")
    )
    out.metadata["lifecycle_state"] = ctx.data.get("lifecycleState") or ctx.data.get("state")


@_extractor("orgpolicy.googleapis.com/Policy")
def _org_policy_v2(ctx: GCPContext, out: Extracted) -> None:
    rel_name = relative_name(ctx.name)
    attached = rel_name.split("/policies/", 1)[0]
    out.add(
        full_name(attached), EdgeType.GOVERNS, "SCP_RESTRICTS", description="organization policy"
    )
    spec = ctx.data.get("spec") or {}
    rules = []
    for r in _list(spec.get("rules")):
        if not isinstance(r, dict):
            continue
        rules.append(
            {
                k: v
                for k, v in {
                    "enforce": r.get("enforce"),
                    "allow_all": r.get("allowAll"),
                    "deny_all": r.get("denyAll"),
                    "allowed_values": dig(r, "values", "allowedValues"),
                    "denied_values": dig(r, "values", "deniedValues"),
                    "condition": dig(r, "condition", "title") or dig(r, "condition", "expression"),
                }.items()
                if v not in (None, [], "")
            }
        )
    out.metadata.update(
        constraint="constraints/" + rel_name.rsplit("/policies/", 1)[-1],
        attached_to=full_name(attached),
        rules=rules,
        inherit_from_parent=spec.get("inheritFromParent"),
        reset=spec.get("reset"),
        dry_run=bool(ctx.data.get("dryRunSpec")),
    )


def perimeter_metadata(p: dict[str, Any]) -> tuple[dict[str, Any], list[tuple[str, bool]]]:
    """Metadata and governed resources ``(ref, dry_run)`` of a VPC-SC perimeter.

    Accepts both the proto (snake_case) and JSON (camelCase) shapes.
    """

    def g(d: Any, snake: str, camel: str) -> Any:
        if not isinstance(d, dict):
            return None
        return d.get(snake, d.get(camel))

    status = g(p, "status", "status") or {}
    spec = g(p, "spec", "spec") or {}
    dry_run = bool(g(p, "use_explicit_dry_run_spec", "useExplicitDryRunSpec"))
    ptype = g(p, "perimeter_type", "perimeterType")
    if isinstance(ptype, (int, float)):
        ptype = {0: "PERIMETER_TYPE_REGULAR", 1: "PERIMETER_TYPE_BRIDGE"}.get(
            int(ptype), str(ptype)
        )
    vpc = g(status, "vpc_accessible_services", "vpcAccessibleServices") or {}
    md = {
        "title": g(p, "title", "title"),
        "perimeter_type": ptype or "PERIMETER_TYPE_REGULAR",
        "restricted_services": list(g(status, "restricted_services", "restrictedServices") or []),
        "access_levels": list(g(status, "access_levels", "accessLevels") or []),
        "vpc_accessible_services_restricted": bool(
            g(vpc, "enable_restriction", "enableRestriction")
        ),
        "vpc_allowed_services": list(g(vpc, "allowed_services", "allowedServices") or []),
        "ingress_policy_count": len(g(status, "ingress_policies", "ingressPolicies") or []),
        "egress_policy_count": len(g(status, "egress_policies", "egressPolicies") or []),
        "uses_dry_run_spec": dry_run,
        "dry_run_restricted_services": list(
            g(spec, "restricted_services", "restrictedServices") or []
        ),
    }
    governed = [(r, False) for r in g(status, "resources", "resources") or []]
    governed += [
        (r, True) for r in g(spec, "resources", "resources") or [] if (r, False) not in governed
    ]
    return md, governed


@_extractor("accesscontextmanager.googleapis.com/ServicePerimeter")
def _perimeter(ctx: GCPContext, out: Extracted) -> None:
    md, governed = perimeter_metadata(ctx.data)
    out.metadata.update(md)
    for ref, dry in governed:
        out.add(ref, EdgeType.GOVERNS, "COMPLIANCE_GOVERNS", dry_run=dry or None)
