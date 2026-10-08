"""Workspace tools: load, list, select, snapshot, diff and unload datasets.

A dataset is one inventory map / findings report / scanner output (or a
live collection) held in memory. Every other tool reads the active dataset
unless given ``dataset=``.
"""

from __future__ import annotations

from typing import Annotated, Any, Literal

from pydantic import Field

from cloudg.mcp.catalog._common import (
    Catalog,
    DatasetArg,
    DiffOut,
    SummaryOut,
    WorkspaceOut,
    schema,
    ws_dataset,
)
from cloudg.mcp.core import Capability, Registry, Sensitivity

CATEGORY = "workspace"
R, W, FS = Capability.READ_STATE, Capability.WRITE_STATE, Capability.READ_FS

CATALOG = Catalog()

@CATALOG.tool(
    title="Workspace status",
    category=CATEGORY,
    sensitivity=Sensitivity.INTERNAL,
    read_only=True,
    idempotent=True,
    open_world=False,
    output_schema=schema(WorkspaceOut),
    tags={"start-here"},
)
def workspace_status(ctx: Any) -> dict:
    """Show what is loaded: every dataset (asset / edge / finding counts,
    source, which analyses are cached), the active dataset, and the
    directories file tools may read and write. Call this first; if no
    dataset is loaded, use load_dataset or map_inventory."""
    status = ctx.workspace.status()
    if not status["datasets"]:
        status["next_steps"] = [
            "load_dataset(path='<dir with inventory-map.json or findings.json>')",
            "map_inventory(providers=['aws']) to collect live data (needs credentials)",
        ]
    else:
        ctx.link("cloudg://workspace", "workspace", title="Workspace status")
    return status

@CATALOG.tool(
    title="List datasets",
    category=CATEGORY,
    sensitivity=Sensitivity.INTERNAL,
    read_only=True,
    idempotent=True,
    open_world=False,
)
def list_datasets(ctx: Any) -> dict:
    """List loaded datasets with their size, kind (inventory, report,
    generic, live, snapshot, scanner name) and which one is active."""
    ws = ctx.workspace
    items = [{**d.describe(), "active": d.name == ws.active_name} for d in ws.datasets()]
    return {"active_dataset": ws.active_name, "datasets": items, "total": len(items)}

@CATALOG.tool(
    title="Load dataset",
    category=CATEGORY,
    sensitivity=Sensitivity.INTERNAL,
    capabilities={R, W, FS},
    read_only=False,
    destructive=False,
    idempotent=False,
    open_world=False,
)
def load_dataset(
    ctx: Any,
    path: Annotated[
        str,
        Field(
            min_length=1,
            description="File or directory inside an allowed root: inventory-map.json "
            "(or its directory), a cloudg findings.json report, a generic "
            "{assets, edges, findings} JSON, or native Prowler / ScoutSuite / Checkov / "
            "Trivy output.",
        ),
    ],
    name: Annotated[
        str, Field(description="Dataset name; default derives from the path.")
    ] = "",
    kind: Annotated[
        Literal[
            "auto", "inventory", "report", "generic", "prowler", "scoutsuite", "checkov",
            "trivy",
        ],
        Field(description="Content type; 'auto' detects it."),
    ] = "auto",
    activate: Annotated[bool, Field(description="Make it the active dataset.")] = True,
    replace: Annotated[bool, Field(description="Overwrite an existing dataset with the "
                                   "same name (otherwise a name clash is an error).")]
    = False,
) -> dict:
    """Load a file or directory into the workspace as a named dataset.
    An inventory directory that also holds findings.json gets those
    findings merged in. Scanner output is normalised (deduplicated and
    mapped to compliance frameworks); Prowler must be ASFF (-M json-asff),
    OCSF output is refused. Returns the dataset summary."""
    ds = ctx.workspace.load(path, name or None, kind=kind, activate=activate,
                            replace=replace)
    ctx.link(
        f"cloudg://datasets/{ds.name}/summary", f"{ds.name} summary", title="Dataset summary"
    )
    return {"loaded": ds.name, "active": ctx.workspace.active_name == ds.name, **ds.summary()}

@CATALOG.tool(
    title="Select dataset",
    category=CATEGORY,
    sensitivity=Sensitivity.INTERNAL,
    capabilities={R, W},
    read_only=False,
    destructive=False,
    idempotent=True,
    open_world=False,
)
def select_dataset(
    ctx: Any, name: Annotated[str, Field(min_length=1, description="Dataset to activate.")]
) -> dict:
    """Make a loaded dataset the active one (the default for every tool)."""
    ds = ctx.workspace.select(name)
    return {"active_dataset": ds.name, **ds.describe()}

@CATALOG.tool(
    title="Unload dataset",
    category=CATEGORY,
    sensitivity=Sensitivity.INTERNAL,
    capabilities={R, W},
    read_only=False,
    destructive=True,
    idempotent=True,
    open_world=False,
)
def unload_dataset(
    ctx: Any, name: Annotated[str, Field(min_length=1, description="Dataset to drop.")]
) -> dict:
    """Remove a dataset from memory (files on disk are untouched). Any
    suppressions or ingested findings held only in memory are lost."""
    ctx.workspace.remove(name)
    return {"unloaded": name, "active_dataset": ctx.workspace.active_name,
            "remaining": ctx.workspace.names()}

@CATALOG.tool(
    title="Snapshot dataset",
    category=CATEGORY,
    sensitivity=Sensitivity.INTERNAL,
    capabilities={R, W},
    read_only=False,
    destructive=False,
    idempotent=False,
    open_world=False,
)
def snapshot_dataset(
    ctx: Any,
    new_name: Annotated[str, Field(min_length=1, description="Name for the copy.")],
    dataset: DatasetArg = "",
    replace: Annotated[bool, Field(description="Overwrite an existing dataset named "
                                   "new_name (otherwise a name clash is an error).")]
    = False,
) -> dict:
    """Freeze a copy of a dataset under a new name (e.g. before ingesting
    new findings or re-collecting) so diff_datasets can compare later.
    The copy does not become active."""
    ds = ctx.workspace.snapshot(dataset or None, new_name, replace=replace)
    return {"snapshot": ds.name, **ds.describe()}

@CATALOG.tool(
    title="Diff datasets",
    category=CATEGORY,
    sensitivity=Sensitivity.CONFIDENTIAL,
    read_only=True,
    idempotent=True,
    open_world=False,
    output_schema=schema(DiffOut),
)
def diff_datasets(
    ctx: Any,
    base: Annotated[str, Field(min_length=1, description="Baseline dataset (before).")],
    target: Annotated[str, Field(description="Dataset to compare (after); empty = active.")]
    = "",
    limit: Annotated[int, Field(ge=1, le=500, description="Max items per section.")] = 50,
) -> dict:
    """Compare two datasets: assets added / removed / changed (matched
    on ARN), edges added / removed, findings new / resolved / changed
    severity, and assets that became internet-exposed. Use for drift and
    change review between two collections or reports."""
    return ctx.workspace.diff(base, target or None, limit=limit)

@CATALOG.tool(
    title="Dataset summary",
    category=CATEGORY,
    sensitivity=Sensitivity.INTERNAL,
    read_only=True,
    idempotent=True,
    open_world=False,
    output_schema=schema(SummaryOut),
)
def dataset_summary(ctx: Any, dataset: DatasetArg = "") -> dict:
    """Headline numbers for a dataset: asset / edge / finding counts,
    open findings by severity, accounts, regions, internet-exposed
    assets, cross-account edges, top asset types, compliance frameworks."""
    ds = ws_dataset(ctx, dataset)
    ctx.link(f"cloudg://datasets/{ds.name}/summary", f"{ds.name} summary")
    return ds.summary()


def register(reg: Registry) -> None:
    """Add this module's tools to ``reg``."""
    CATALOG.register(reg)
