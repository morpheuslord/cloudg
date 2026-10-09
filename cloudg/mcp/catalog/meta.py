"""Meta tools: what this server can do and what cloudg's vocabulary means.

Static, tenant-free (PUBLIC) answers: the tool catalog by category with
recommended workflows, the schema enums (asset types, edge types,
severities, relation types and groups), and explanations of one asset type
or edge type: how cloudg classifies it, its ontology class, Terraform
mapping, dependency semantics and security relevance.
"""

from __future__ import annotations

import functools
import inspect
import re
from typing import Annotated, Any, Literal

from pydantic import Field

from cloudg.mcp.catalog._common import Catalog, parse_enum
from cloudg.mcp.core import Registry, Sensitivity
from cloudg.schema.models import (
    AssetType,
    CloudProvider,
    ComplianceStatus,
    EdgeType,
    Severity,
)

CATEGORY = "meta"

SchemaSection = Literal[
    "all",
    "asset_types",
    "edge_types",
    "severities",
    "relation_types",
    "relation_groups",
    "compliance_statuses",
    "providers",
]

EDGE_READS: dict[str, tuple[str, str]] = {
    "REFERENCES": ("uses / points at", "function -> secret, table -> KMS key, queue -> DLQ"),
    "ATTACHED_TO": (
        "is attached to",
        "instance -> security group, volume -> instance, ENI -> instance",
    ),
    "ROUTE": (
        "routes through / forwards to",
        "route table -> gateway, DNS record -> load balancer, ingress -> service",
    ),
    "PEERING": ("peers with", "VPC -> peering connection -> VPC"),
    "USES_IMAGE": ("runs the image of", "task definition / workload / function -> registry"),
    "ASSUMES_ROLE": (
        "runs as",
        "function, task, node group, instance profile -> role / service account",
    ),
    "LOGS_TO": ("sends logs to", "trail, flow log, LB, function -> log destination"),
    "LOAD_BALANCER_TARGET": ("sends traffic to", "load balancer -> target group -> instance"),
    "GRANTS_ACCESS": ("is granted access to", "principal -> resource its policy names"),
    "IAM_POLICY_ATTACHMENT": ("has policy", "user / group / role -> managed policy"),
    "IAM_TRUST": ("may assume", "principal / account / provider -> role"),
    "CONTAINS": ("contains", "VPC -> subnet, subnet -> instance, account -> resource"),
    "INVOKES": ("triggers / calls", "bucket -> function, queue -> function, rule -> target"),
    "PROTECTS": ("protects", "WAF -> ALB / API / distribution, firewall -> VPC"),
    "MONITORS": ("monitors", "Inspector -> instance, GuardDuty -> account, alarm -> resource"),
    "MANAGES": ("manages", "stack -> resource, ASG -> instance, landing zone -> account"),
    "GOVERNS": ("governs", "SCP / control / org policy -> OU, account, folder, project"),
    "SECURITY_GROUP_RULE": ("allows traffic", "CIDR -> SG (ingress), SG -> CIDR (egress)"),
    "NACL_RULE": ("allows traffic", "network ACL rules"),
    "INTERNET_EXPOSED": ("exposes", "0.0.0.0/0 -> exposed asset"),
}

# Edge types whose ontology relations come from a rule over the edge's
# details rather than a fixed list (cloudg.graph.ontology_rules).
RULE_RELATIONS: dict[str, str] = {
    "SECURITY_GROUP_RULE": "inferred from ports, protocol, CIDR and direction "
    "(INGRESS_ALLOWED / EGRESS_ALLOWED, ONLY_SSH, ONLY_HTTPS, ALL_TRAFFIC, "
    "INTERNET_REACHABLE...)",
    "CONTAINS": "inferred from both endpoint types (VPC_CONTAINS_SUBNET, "
    "SUBNET_CONTAINS_INSTANCE, CLUSTER_CONTAINS_SERVICE, ORG_CONTAINS_ACCOUNT), else the "
    "generic CONTAINS",
    "ATTACHED_TO": "PROTECTED_BY_SG when the target is a security group or NSG, "
    "PROTECTED_BY_NACL for a NACL, else DEPENDS_ON",
    "IAM_TRUST": "ROLE_ASSUMES_ROLE, plus CROSS_ACCOUNT_TRUST when the accounts differ",
    "NACL_RULE": "none; protection relations come from ATTACHED_TO edges",
    "IAM_POLICY_ATTACHMENT": "inferred from the principal type (USER_HAS_POLICY, "
    "ROLE_HAS_POLICY, GROUP_HAS_POLICY)",
}

WORKFLOWS = {
    "orient": ["workspace_status", "dataset_summary", "count_assets", "findings_summary"],
    "triage risk": ["top_risks", "get_asset", "findings_for_asset", "blast_radius"],
    "attack surface": [
        "internet_exposure",
        "attack_paths",
        "lateral_movement_paths",
        "find_paths(source='internet', target=...)",
    ],
    "change impact": ["dependents", "dependency_tree", "shared_dependencies", "blast_radius"],
    "compliance": ["compliance_summary", "list_controls", "control_status", "compliance_gaps"],
    "drift": ["snapshot_dataset", "map_inventory / load_dataset", "diff_datasets"],
    "semantic": ["ontology_stats", "relation_groups", "ontology_neighbourhood", "sparql_query"],
}


@functools.lru_cache(maxsize=1)
def enum_comments() -> dict[str, dict[str, str]]:
    """Section headings and inline comments of the AssetType / EdgeType
    enums, read from their source (they document the taxonomy)."""
    out: dict[str, dict[str, str]] = {"family": {}, "asset_note": {}, "edge_note": {}}
    for enum, note_key in ((AssetType, "asset_note"), (EdgeType, "edge_note")):
        try:
            src = inspect.getsource(enum)
        except (OSError, TypeError):  # pragma: no cover (source unavailable)
            continue
        section = "Other"
        for line in src.splitlines():
            s = line.strip()
            m = re.match(r"^#\s*(.+)$", s)
            if m and enum is AssetType:
                section = m.group(1).strip()
                continue
            m = re.match(r'^([A-Z_0-9]+)\s*=\s*\(?\s*"[A-Z_0-9]+"\s*\)?\s*(?:#\s*(.*))?$', s)
            if m:
                name, note = m.group(1), (m.group(2) or "").strip()
                note = re.sub(r"\s*nosec.*$|\s*nosemgrep.*$", "", note).strip(" -#")
                if enum is AssetType:
                    out["family"][name] = section
                if note:
                    out[note_key][name] = note
    return out


def _relation_types() -> dict[str, list[str]]:
    from cloudg.graph.ontology_rules import RelationGroup, get_relations_for_group

    return {g.value: [r.value for r in get_relations_for_group(g)] for g in RelationGroup}


CATALOG = Catalog()

_RO = dict(
    category=CATEGORY,
    sensitivity=Sensitivity.PUBLIC,
    capabilities=(),
    read_only=True,
    idempotent=True,
    open_world=False,
)


@CATALOG.tool(title="List capabilities", tags={"start-here"}, **_RO)
def list_capabilities(ctx: Any) -> dict:
    """What this server offers: every tool you may call grouped by
    category (with read-only / sensitivity / required capabilities), the
    resource and prompt counts, and recommended tool sequences for
    common jobs (orienting, risk triage, attack surface, change impact,
    compliance, drift, semantic queries)."""
    layer = ctx.layer
    cats: dict[str, list[dict[str, Any]]] = {}
    for spec in layer.list_tools(ctx.principal):
        cats.setdefault(spec.category, []).append(
            {
                "name": layer.exposed_name(spec.name),
                "title": spec.title,
                "read_only": spec.annotations.read_only,
                "open_world": spec.annotations.open_world,
                "sensitivity": spec.sensitivity.value,
                "capabilities": sorted(c.value for c in spec.capabilities),
                "summary": (spec.description.split(". ")[0].strip()[:160]),
            }
        )
    return {
        "server": layer.name,
        "version": layer.version,
        "categories": {k: sorted(v, key=lambda t: t["name"]) for k, v in sorted(cats.items())},
        "tool_count": sum(len(v) for v in cats.values()),
        "resources": len(layer.list_resources(ctx.principal)),
        "resource_templates": len(layer.list_resource_templates(ctx.principal)),
        "prompts": [layer.exposed_name(p.name) for p in layer.list_prompts(ctx.principal)],
        "workflows": WORKFLOWS,
        "conventions": {
            "dataset": "empty = active dataset",
            "ref": "asset id, ARN, unique name or unique ARN tail",
            "pagination": "pass next_cursor back as cursor; cursors expire when the "
            "dataset changes",
        },
    }


@CATALOG.tool(title="Describe schema", **_RO)
def describe_schema(ctx: Any, section: SchemaSection = "all") -> dict:
    """cloudg's vocabulary: asset types (grouped by family), edge types
    (with how each reads), severities, ontology relation types by group,
    compliance statuses and providers. Use these exact values in filters."""
    notes = enum_comments()
    out: dict[str, Any] = {}
    if section in ("all", "asset_types"):
        fam: dict[str, list[str]] = {}
        for t in AssetType:
            fam.setdefault(notes["family"].get(t.name, "Other"), []).append(t.value)
        out["asset_types"] = fam
    if section in ("all", "edge_types"):
        out["edge_types"] = {e.value: EDGE_READS.get(e.value, ("", ""))[0] for e in EdgeType}
    if section in ("all", "severities"):
        out["severities"] = [s.value for s in Severity]
    if section in ("all", "relation_types", "relation_groups"):
        rel = _relation_types()
        out["relation_groups"] = list(rel) if section == "relation_groups" else rel
    if section in ("all", "compliance_statuses"):
        out["compliance_statuses"] = [s.value for s in ComplianceStatus]
    if section in ("all", "providers"):
        out["providers"] = [p.value for p in CloudProvider]
    return out


@CATALOG.tool(title="Explain asset type", **_RO)
def explain_asset_type(
    ctx: Any,
    asset_type: Annotated[
        str, Field(min_length=1, description="An AssetType value, e.g. LAMBDA_FUNCTION.")
    ],
) -> dict:
    """How cloudg models one asset type: family, notes, OWL ontology
    class, Terraform resource type, whether it is a sensitive data store
    / crown jewel, whether internet exposure is expected, and how many
    the active dataset holds."""
    from cloudg.graph.ontology import _ASSET_TYPE_CLASSES
    from cloudg.graph.reachability import EXPECTED_EXPOSED_TYPES, SENSITIVE_ASSET_TYPES
    from cloudg.mcp.catalog.graph import CROWN_JEWELS
    from cloudg.renderers.terraform_export import _TF_RESOURCE_MAP

    t = parse_enum(asset_type, AssetType, "asset type")
    notes = enum_comments()
    out: dict[str, Any] = {
        "asset_type": t.value,
        "family": notes["family"].get(t.name, "Other"),
        "note": notes["asset_note"].get(t.name),
        "ontology_class": f"cm:{_ASSET_TYPE_CLASSES.get(t, 'CloudResource')}",
        "terraform_type": _TF_RESOURCE_MAP.get(t),
        "sensitive_data_store": t in SENSITIVE_ASSET_TYPES,
        "crown_jewel_weight": CROWN_JEWELS.get(t, 0),
        "internet_exposure_expected": t in EXPECTED_EXPOSED_TYPES,
    }
    ws = ctx.workspace
    if ws.active_name:
        ds = ws.get()
        out["in_active_dataset"] = sum(1 for a in ds.assets if a.asset_type == t)
    return out


@CATALOG.tool(title="Explain edge type", **_RO)
def explain_edge_type(
    ctx: Any,
    edge_type: Annotated[
        str, Field(min_length=1, description="An EdgeType value, e.g. ASSUMES_ROLE.")
    ],
) -> dict:
    """How to read one edge type: direction ("source verb target"),
    typical endpoints, its dependency direction (forward: source depends
    on target; reverse: target depends on source; none), and the
    ontology relations inferred from it."""
    from cloudg.graph.ontology_rules import _SIMPLE_EDGE_RELATIONS
    from cloudg.inventory.dependencies import DEPENDENCY_DIRECTION

    e = parse_enum(edge_type, EdgeType, "edge type")
    reads, typical = EDGE_READS.get(e.value, ("", ""))
    return {
        "edge_type": e.value,
        "reads_as": f"source {reads} target" if reads else None,
        "typical": typical or None,
        "note": enum_comments()["edge_note"].get(e.name),
        "dependency_direction": DEPENDENCY_DIRECTION.get(e.value, "none"),
        "ontology_relations": [r.value for r in _SIMPLE_EDGE_RELATIONS.get(e, [])]
        or RULE_RELATIONS.get(e.value, "none inferred from the edge type alone"),
    }


def register(reg: Registry) -> None:
    """Add this module's tools to ``reg``."""
    CATALOG.register(reg)
