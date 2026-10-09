"""Resources and resource templates.

Resources give clients addressable, cacheable views of the workspace.
The tool results link to them (``resource_link``) instead of inlining big
payloads:

=====================================  =======================================
``cloudg://workspace``                 loaded datasets, active one, roots
``cloudg://datasets``                  dataset listing
``cloudg://datasets/{dataset}/summary``  headline numbers of one dataset
``cloudg://assets/{+ref}``             one asset (detail)
``cloudg://assets/{+ref}/neighbors``   its edges and neighbours
``cloudg://assets/{+ref}/findings``    its findings
``cloudg://findings/summary``          finding counts by severity / tool
``cloudg://findings/{finding_id}``     one finding in full
``cloudg://findings/severity/{severity}``  findings of one severity (max 200)
``cloudg://compliance``                posture of every framework
``cloudg://compliance/{framework}``    one framework: controls and gaps
``cloudg://graph/d3``, ``/{format}``   whole graph as D3 / Cytoscape / GraphML
``cloudg://ontology/turtle``, ``/{format}``  ontology (turtle, json-ld, xml, nt)
``cloudg://schema/asset-types`` ...    vocabulary (public)
``cloudg://docs``, ``/{topic}``        cloudg documentation sections
=====================================  =======================================

Asset / dataset / framework / severity / topic variables have completions.
"""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any

from cloudg.mcp.catalog._common import (
    Catalog,
    asset_brief,
    edge_brief,
    finding_brief,
    ws_dataset,
)
from cloudg.mcp.catalog._resources import (
    GRAPH_FORMATS,
    ONTOLOGY_FORMATS,
    asset_detail,
    complete_asset,
    complete_asset_type,
    complete_dataset,
    complete_finding,
    complete_framework,
    complete_graph_format,
    complete_ontology_format,
    complete_severity,
    finding_detail,
    framework_detail,
)
from cloudg.mcp.core import Registry, Sensitivity, TextResourceContents
from cloudg.mcp.state import SEVERITY_RANK, ReferenceNotFoundError
from cloudg.schema.models import AssetType, EdgeType

DOC_TOPICS: dict[str, tuple[str, str, str]] = {
    # topic: (file, heading prefix, one-line description)
    "pipeline": ("DOCUMENTATION.md", "## The pipeline", "Phases of a cloudg run"),
    "cli": ("DOCUMENTATION.md", "## CLI reference", "cloudg command-line reference"),
    "inputs": ("DOCUMENTATION.md", "## Input requirements", "Scanner report formats"),
    "outputs": ("DOCUMENTATION.md", "## Output contract", "Files cloudg writes"),
    "data-models": ("DOCUMENTATION.md", "## Data models", "Finding / CloudAsset / NetworkEdge"),
    "configuration": ("DOCUMENTATION.md", "## Configuration", "config.yaml reference"),
    "python-api": ("DOCUMENTATION.md", "## Python API", "CloudGEngine and inventory API"),
    "recipes": ("DOCUMENTATION.md", "## Integration recipes", "Integration recipes"),
    "authentication": ("DOCUMENTATION.md", "## Authentication", "Cloud credentials"),
    "identifiers": (
        "INVENTORY_REFERENCE.md",
        "## 4. Identifier formats",
        "ARN / Azure / GCP / placeholder identifier formats",
    ),
    "edges": ("INVENTORY_REFERENCE.md", "## 5. NetworkEdge", "NetworkEdge fields"),
    "edge-types": (
        "INVENTORY_REFERENCE.md",
        "## 6. Edge types and direction",
        "Edge types, direction and dependency semantics",
    ),
    "relations": (
        "INVENTORY_REFERENCE.md",
        "## 7. The relation object",
        "Declared relations on assets",
    ),
    "inventory-summary": ("INVENTORY_REFERENCE.md", "## 9. summary", "InventoryResult.summary"),
    "dependencies": (
        "INVENTORY_REFERENCE.md",
        "## 12. DependencyGraph results",
        "depends_on / dependents / tree / blast radius",
    ),
    "inventory-map": (
        "INVENTORY_REFERENCE.md",
        "## 14. inventory-map.json",
        "inventory-map.json format",
    ),
    "organization": (
        "INVENTORY_REFERENCE.md",
        "## 17. OrganizationTopology",
        "Organization / Control Tower topology",
    ),
}

MCP_GUIDE = """\
# Using cloudg through MCP

1. `workspace_status` shows what is loaded. Load data with `load_dataset(path=...)`
   (inventory-map.json, findings.json, scanner output) or collect live with
   `map_inventory` (needs cloud credentials on the server).
2. Orient: `dataset_summary`, `count_assets(group_by=...)`, `findings_summary`.
3. Prioritise: `top_risks`, `internet_exposure`, `attack_paths`.
4. Drill down: `get_asset(ref)`, `findings_for_asset`, `neighbors`, `blast_radius`,
   `dependency_tree`, `find_paths`.
5. Compliance: `compliance_summary`, `list_controls`, `control_status`, `compliance_gaps`.
6. Semantics: `relation_groups`, `ontology_neighbourhood`, `sparql_query` (read-only).
7. Change tracking: `snapshot_dataset` before re-collecting, then `diff_datasets`.

Asset references accept ids, ARNs, unique names or unique ARN tails. List tools
are paginated: pass `next_cursor` back as `cursor`. Identifiers may be
pseudonymised by the server's privacy policy; pass them back unchanged.
Prompts (`security_posture_review`, `investigate_asset`, ...) package these
steps for common jobs.
"""


def docs_dir() -> Path | None:
    env = os.environ.get("CLOUDG_DOCS_DIR")
    candidates = [Path(env)] if env else []
    import cloudg

    pkg = Path(cloudg.__file__).resolve().parent
    # A source checkout keeps them in docs/; wheels ship them in cloudg/_docs
    candidates += [pkg.parent / "docs", pkg / "_docs"]
    for c in candidates:
        if c.is_dir():
            return c
    return None


def doc_section(topic: str) -> str:
    if topic == "mcp":
        return MCP_GUIDE
    if topic not in DOC_TOPICS:
        raise ReferenceNotFoundError(
            f"Unknown docs topic. Topics: mcp, {', '.join(DOC_TOPICS)}", data={"value": topic}
        )
    fname, heading, _ = DOC_TOPICS[topic]
    d = docs_dir()
    path = d / fname if d else None
    if path is None or not path.exists():
        return (
            f"# {topic}\n\nThe cloudg documentation files are not installed with this "
            "package. See https://morpheuslord.github.io/cloudg/ or read the 'mcp' topic."
        )
    lines = path.read_text().splitlines()
    start = next((i for i, ln in enumerate(lines) if ln.startswith(heading)), None)
    if start is None:
        return f"# {topic}\n\nSection '{heading}' not found in {fname}."
    level = len(heading) - len(heading.lstrip("#"))
    end = len(lines)
    for i in range(start + 1, len(lines)):
        m = re.match(r"^(#+)\s", lines[i])
        if m and len(m.group(1)) <= level and not _in_code(lines, i):
            end = i
            break
    text = "\n".join(lines[start:end]).strip()
    return text[:40_000]


def _in_code(lines: list[str], idx: int) -> bool:
    return sum(1 for ln in lines[:idx] if ln.startswith("```")) % 2 == 1


def complete_topic(ctx: Any, partial: str = "") -> list[str]:
    return [t for t in ["mcp", *DOC_TOPICS] if t.startswith(partial.lower())]


__all__ = [
    "CATALOG",
    "DOC_TOPICS",
    "GRAPH_FORMATS",
    "ONTOLOGY_FORMATS",
    "asset_detail",
    "complete_asset",
    "complete_asset_type",
    "complete_dataset",
    "complete_finding",
    "complete_framework",
    "complete_graph_format",
    "complete_ontology_format",
    "complete_severity",
    "complete_topic",
    "doc_section",
    "docs_dir",
    "finding_detail",
    "framework_detail",
    "register",
]

CATALOG = Catalog()

# -- workspace ------------------------------------------------------


@CATALOG.resource(
    "cloudg://workspace",
    title="Workspace",
    category="workspace",
    sensitivity=Sensitivity.INTERNAL,
    description="Loaded datasets, the active dataset and allowed directories.",
)
def workspace_resource(ctx: Any) -> dict:
    return ctx.workspace.status()


@CATALOG.resource(
    "cloudg://datasets",
    title="Datasets",
    category="workspace",
    sensitivity=Sensitivity.INTERNAL,
    description="Loaded datasets.",
)
def datasets_resource(ctx: Any) -> dict:
    ws = ctx.workspace
    return {"active_dataset": ws.active_name, "datasets": [d.describe() for d in ws.datasets()]}


@CATALOG.resource_template(
    "cloudg://datasets/{dataset}/summary",
    title="Dataset summary",
    category="workspace",
    sensitivity=Sensitivity.INTERNAL,
    description="Headline numbers of one dataset.",
    completions={"dataset": complete_dataset},
)
def dataset_summary_resource(ctx: Any, dataset: str) -> dict:
    return ctx.workspace.get(dataset).summary()


# -- assets ---------------------------------------------------------


@CATALOG.resource_template(
    "cloudg://assets/{+ref}",
    title="Asset",
    category="inventory",
    sensitivity=Sensitivity.CONFIDENTIAL,
    description="One asset of the active dataset (ref = id, ARN or unique name, URL-encoded).",
    completions={"ref": complete_asset},
)
def asset_resource(ctx: Any, ref: str) -> dict:
    return asset_detail(ws_dataset(ctx), ref)


@CATALOG.resource_template(
    "cloudg://assets/{+ref}/neighbors",
    title="Asset neighbours",
    category="graph",
    sensitivity=Sensitivity.CONFIDENTIAL,
    description="Edges and one-hop neighbours of an asset.",
    completions={"ref": complete_asset},
)
def asset_neighbors_resource(ctx: Any, ref: str) -> dict:
    ds = ws_dataset(ctx)
    node = ref if (ref in ds.graph and ref not in ds.by_id) else ds.resolve_asset(ref).id
    adj = ds.adjacency.get(node, [])[:500]
    others = list(dict.fromkeys(o for _, o, _ in adj))
    return {
        "asset": node,
        "edges": [edge_brief(ds, e) for e, _, _ in adj],
        "neighbors": [
            asset_brief(ds, ds.by_id[o]) if o in ds.by_id else {"id": o, "external": True}
            for o in others
        ],
    }


@CATALOG.resource_template(
    "cloudg://assets/{+ref}/findings",
    title="Asset findings",
    category="findings",
    sensitivity=Sensitivity.CONFIDENTIAL,
    description="Open findings of an asset.",
    completions={"ref": complete_asset},
)
def asset_findings_resource(ctx: Any, ref: str) -> dict:
    ds = ws_dataset(ctx)
    a = ds.resolve_asset(ref)
    fs = sorted(ds.open_findings(a.id), key=lambda f: -f.risk_score)
    return {"asset": asset_brief(ds, a), "findings": [finding_brief(ds, f) for f in fs]}


# -- findings -------------------------------------------------------


@CATALOG.resource(
    "cloudg://findings/summary",
    title="Findings summary",
    category="findings",
    sensitivity=Sensitivity.INTERNAL,
    description="Open finding counts by severity and tool (active dataset).",
)
def findings_summary_resource(ctx: Any) -> dict:
    ds = ws_dataset(ctx)
    by_tool: dict[str, int] = {}
    for f in ds.open_findings():
        by_tool[f.source_tool] = by_tool.get(f.source_tool, 0) + 1
    s = ds.summary()
    return {
        "dataset": ds.name,
        "open_findings": s["open_findings"],
        "suppressed": s["suppressed_findings"],
        "severity_breakdown": s["severity_breakdown"],
        "by_tool": by_tool,
    }


@CATALOG.resource_template(
    "cloudg://findings/{finding_id}",
    title="Finding",
    category="findings",
    sensitivity=Sensitivity.CONFIDENTIAL,
    description="One finding with evidence and remediation.",
    completions={"finding_id": complete_finding},
)
def finding_resource(ctx: Any, finding_id: str) -> dict:
    ds = ws_dataset(ctx)
    return finding_detail(ds, ds.get_finding(finding_id))


@CATALOG.resource_template(
    "cloudg://findings/severity/{severity}",
    title="Findings by severity",
    category="findings",
    sensitivity=Sensitivity.CONFIDENTIAL,
    description="Open findings of one severity (first 200, by risk).",
    completions={"severity": complete_severity},
)
def findings_by_severity_resource(ctx: Any, severity: str) -> dict:
    ds = ws_dataset(ctx)
    sev = severity.upper()
    if sev not in SEVERITY_RANK:
        raise ReferenceNotFoundError(
            f"Unknown severity; use one of {', '.join(SEVERITY_RANK)}", data={"value": severity}
        )
    fs = sorted(
        (f for f in ds.open_findings() if f.severity.value == sev), key=lambda f: -f.risk_score
    )
    return {
        "dataset": ds.name,
        "severity": sev,
        "total": len(fs),
        "truncated": len(fs) > 200,
        "findings": [finding_brief(ds, f) for f in fs[:200]],
    }


# -- compliance -----------------------------------------------------


@CATALOG.resource(
    "cloudg://compliance",
    title="Compliance posture",
    category="compliance",
    sensitivity=Sensitivity.INTERNAL,
    description="Posture of every compliance framework in the active dataset.",
)
def compliance_resource(ctx: Any) -> dict:
    from cloudg.mcp.catalog.compliance import framework_rollup

    ds = ws_dataset(ctx)
    return {"dataset": ds.name, "frameworks": framework_rollup(ds)}


@CATALOG.resource_template(
    "cloudg://compliance/{framework}",
    title="Framework posture",
    category="compliance",
    sensitivity=Sensitivity.INTERNAL,
    description="One framework: posture and failing controls.",
    completions={"framework": complete_framework},
)
def framework_resource(ctx: Any, framework: str) -> dict:
    return framework_detail(ws_dataset(ctx), framework)


# -- graph / ontology -----------------------------------------------


def _graph(ctx: Any, fmt: str) -> Any:
    """d3 / cytoscape as JSON objects (the layer transforms them key by key);
    graphml as text."""
    import networkx as nx

    ds = ws_dataset(ctx)
    if fmt == "d3":
        return ds.builder.to_d3_json()
    if fmt == "cytoscape":
        return ds.builder.to_cytoscape_json()
    if fmt == "graphml":
        return [
            TextResourceContents(
                f"cloudg://graph/{fmt}",
                "\n".join(nx.generate_graphml(ds.graph)),
                "application/graphml+xml",
            )
        ]
    raise ReferenceNotFoundError(
        f"Unknown graph format; use {', '.join(GRAPH_FORMATS)}", data={"value": fmt}
    )


@CATALOG.resource(
    "cloudg://graph/d3",
    title="Graph (D3)",
    category="graph",
    sensitivity=Sensitivity.CONFIDENTIAL,
    description="The active dataset's whole relationship graph as D3 JSON "
    "({nodes, links}). Large; prefer subgraph_export for parts.",
)
def graph_d3_resource(ctx: Any) -> Any:
    return _graph(ctx, "d3")


# RESTRICTED: serves GraphML, an opaque text export the privacy layer can
# only scan as free text, so strict ceilings hide it.
@CATALOG.resource_template(
    "cloudg://graph/{format}",
    title="Graph export",
    category="graph",
    sensitivity=Sensitivity.RESTRICTED,
    description="Whole graph as d3 or cytoscape (application/json) "
    "or graphml (application/graphml+xml); each read returns the "
    "format's own mimeType.",
    completions={"format": complete_graph_format},
)
def graph_resource(
    ctx: Any,
    format: str,  # pylint: disable=redefined-builtin  # URI variable
) -> Any:
    return _graph(ctx, format)


def _ontology(ctx: Any, fmt: str) -> list[TextResourceContents]:
    if fmt not in ONTOLOGY_FORMATS:
        raise ReferenceNotFoundError(
            f"Unknown ontology format; use {', '.join(ONTOLOGY_FORMATS)}", data={"value": fmt}
        )
    g = ws_dataset(ctx).ontology().graph
    return [
        TextResourceContents(
            f"cloudg://ontology/{fmt}", g.serialize(format=fmt), ONTOLOGY_FORMATS[fmt]
        )
    ]


# The RDF serialisations are opaque text: RESTRICTED (see graph/{format}).
@CATALOG.resource(
    "cloudg://ontology/turtle",
    title="Ontology (Turtle)",
    category="ontology",
    sensitivity=Sensitivity.RESTRICTED,
    mime_type="text/turtle",
    description="The active dataset's RDF ontology in Turtle.",
)
def ontology_turtle_resource(ctx: Any) -> list[TextResourceContents]:
    return _ontology(ctx, "turtle")


@CATALOG.resource_template(
    "cloudg://ontology/{format}",
    title="Ontology export",
    category="ontology",
    sensitivity=Sensitivity.RESTRICTED,
    mime_type="text/turtle",
    description="Ontology as turtle (text/turtle), json-ld "
    "(application/ld+json), xml (application/rdf+xml) or nt "
    "(application/n-triples); each read returns the format's own "
    "mimeType.",
    completions={"format": complete_ontology_format},
)
def ontology_resource(
    ctx: Any,
    format: str,  # pylint: disable=redefined-builtin  # URI variable
) -> list[TextResourceContents]:
    return _ontology(ctx, format)


# -- schema / docs (public) -----------------------------------------


@CATALOG.resource(
    "cloudg://schema/asset-types",
    title="Asset types",
    category="meta",
    sensitivity=Sensitivity.PUBLIC,
    description="Asset types by family.",
)
def asset_types_resource(ctx: Any) -> dict:
    from cloudg.mcp.catalog.meta import enum_comments

    fam: dict[str, list[str]] = {}
    for t in AssetType:
        fam.setdefault(enum_comments()["family"].get(t.name, "Other"), []).append(t.value)
    return fam


@CATALOG.resource_template(
    "cloudg://schema/asset-types/{asset_type}",
    title="Asset type",
    category="meta",
    sensitivity=Sensitivity.PUBLIC,
    description="How cloudg models one asset type.",
    completions={"asset_type": complete_asset_type},
)
def asset_type_resource(ctx: Any, asset_type: str) -> dict:
    from cloudg.graph.ontology import _ASSET_TYPE_CLASSES
    from cloudg.mcp.catalog.meta import enum_comments
    from cloudg.renderers.terraform_export import _TF_RESOURCE_MAP

    try:
        t = AssetType(asset_type.upper())
    except ValueError:
        raise ReferenceNotFoundError("Unknown asset type.", data={"value": asset_type}) from None
    return {
        "asset_type": t.value,
        "family": enum_comments()["family"].get(t.name),
        "note": enum_comments()["asset_note"].get(t.name),
        "ontology_class": f"cm:{_ASSET_TYPE_CLASSES.get(t, 'CloudResource')}",
        "terraform_type": _TF_RESOURCE_MAP.get(t),
    }


@CATALOG.resource(
    "cloudg://schema/edge-types",
    title="Edge types",
    category="meta",
    sensitivity=Sensitivity.PUBLIC,
    description="Edge types with direction and dependency semantics.",
)
def edge_types_resource(ctx: Any) -> dict:
    from cloudg.inventory.dependencies import DEPENDENCY_DIRECTION
    from cloudg.mcp.catalog.meta import EDGE_READS

    return {
        e.value: {
            "reads_as": EDGE_READS.get(e.value, ("", ""))[0],
            "typical": EDGE_READS.get(e.value, ("", ""))[1],
            "dependency_direction": DEPENDENCY_DIRECTION.get(e.value, "none"),
        }
        for e in EdgeType
    }


@CATALOG.resource(
    "cloudg://schema/relation-types",
    title="Ontology relation types",
    category="meta",
    sensitivity=Sensitivity.PUBLIC,
    description="Semantic relation types by relation group.",
)
def relation_types_resource(ctx: Any) -> dict:
    from cloudg.mcp.catalog.meta import _relation_types

    return _relation_types()


@CATALOG.resource(
    "cloudg://docs",
    title="Documentation topics",
    category="meta",
    sensitivity=Sensitivity.PUBLIC,
    description="Index of cloudg documentation topics (cloudg://docs/{topic}).",
)
def docs_index_resource(ctx: Any) -> dict:
    return {
        "available": docs_dir() is not None,
        "topics": {
            "mcp": "How to use cloudg through MCP",
            **{k: v[2] for k, v in DOC_TOPICS.items()},
        },
    }


@CATALOG.resource_template(
    "cloudg://docs/{topic}",
    title="Documentation",
    category="meta",
    sensitivity=Sensitivity.PUBLIC,
    mime_type="text/markdown",
    description="One cloudg documentation section (markdown).",
    completions={"topic": complete_topic},
)
def docs_resource(ctx: Any, topic: str) -> str:
    return doc_section(topic)


def register(reg: Registry) -> None:
    """Add this module's tools to ``reg``."""
    CATALOG.register(reg)
