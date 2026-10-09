"""Export tools: Terraform recreation preview / export and report files.

Every file is written under the workspace output directory (see
``workspace_status.output_dir``); paths that would escape it are refused.
"""

from __future__ import annotations

from typing import Annotated, Any, Literal

from pydantic import Field

from cloudg.mcp.catalog._common import Catalog, DatasetArg, parse_enums, ws_dataset
from cloudg.mcp.core import Capability, Registry, Sensitivity
from cloudg.mcp.state import Dataset
from cloudg.schema.models import AssetType, CloudAsset, ScanResult

CATEGORY = "export"
R, FS = Capability.READ_STATE, Capability.WRITE_FS

ReportFormat = Literal["json", "html", "inventory", "graphml", "asset_map"]
ReportFormatArg = Annotated[
    ReportFormat,
    Field(
        description=(
            "json: findings.json (assets, findings, compliance, D3 graph); html: interactive "
            "report.html; inventory: inventory-map.json + .graphml + graph + dependencies; "
            "graphml: the graph only; asset_map: asset-map.json + compliance-map.json "
            "(inventory x findings)."
        )
    ),
]
SubDir = Annotated[
    str,
    Field(
        pattern=r"^[A-Za-z0-9_.\-/]{0,200}$",
        description="Sub-directory of the workspace output directory ('' = the directory itself).",
    ),
]


def _select(ds: Dataset, refs: list[str] | None, asset_types: list[str] | None) -> list[CloudAsset]:
    types = parse_enums(asset_types, AssetType, "asset type")
    if refs:
        chosen = [ds.resolve_asset(r) for r in refs]
    else:
        chosen = list(ds.assets)
    return [a for a in chosen if not types or a.asset_type in types]


def _scan_result(ds: Dataset) -> ScanResult:
    return ScanResult(
        assets=ds.assets, edges=ds.edges, findings=ds.findings, compliance=ds.compliance
    )


CATALOG = Catalog()


@CATALOG.tool(
    title="Terraform preview",
    category=CATEGORY,
    sensitivity=Sensitivity.INTERNAL,
    read_only=True,
    idempotent=True,
    open_world=False,
)
def terraform_preview(
    ctx: Any,
    refs: Annotated[list[str] | None, Field(description="Only these assets (refs).")] = None,
    asset_types: list[str] | None = None,
    dataset: DatasetArg = "",
) -> dict:
    """What a Terraform recreation of the assets would contain: resource
    counts per Terraform type and the asset types that have no Terraform
    mapping. Writes nothing."""
    from cloudg.renderers.terraform_export import TerraformExporter

    ds = ws_dataset(ctx, dataset)
    assets = _select(ds, refs, asset_types)
    return {
        "dataset": ds.name,
        "assets_considered": len(assets),
        **TerraformExporter().preview(assets),
    }


@CATALOG.tool(
    title="Export Terraform",
    category=CATEGORY,
    sensitivity=Sensitivity.CONFIDENTIAL,
    capabilities={R, FS},
    read_only=False,
    destructive=False,
    idempotent=True,
    open_world=False,
)
def export_terraform(
    ctx: Any,
    subdir: SubDir = "terraform",
    refs: Annotated[list[str] | None, Field(description="Only these assets (refs).")] = None,
    asset_types: list[str] | None = None,
    dataset: DatasetArg = "",
) -> dict:
    """Write a Terraform (.tf.json) recreation of the assets (provider,
    variables, main and an import_commands.sh) into the output
    directory. Overwrites files of the same name there."""
    from cloudg.renderers.terraform_export import TerraformExporter

    ds = ws_dataset(ctx, dataset)
    assets = _select(ds, refs, asset_types)
    ids = {a.id for a in assets}
    out = ctx.workspace.output_path(subdir)
    paths = TerraformExporter(output_dir=out).export(
        assets, [e for e in ds.edges if e.source_id in ids or e.target_id in ids]
    )
    return {
        "dataset": ds.name,
        "output_dir": str(out),
        "resources": len(assets),
        "files": {k: str(v) for k, v in paths.items()},
    }


@CATALOG.tool(
    title="Export report",
    category=CATEGORY,
    sensitivity=Sensitivity.CONFIDENTIAL,
    capabilities={R, FS},
    read_only=False,
    destructive=False,
    idempotent=True,
    open_world=False,
)
def export_report(
    ctx: Any,
    format: ReportFormatArg = "json",  # pylint: disable=redefined-builtin  # MCP argument name
    subdir: SubDir = "",
    dataset: DatasetArg = "",
) -> dict:
    """Write the dataset as a cloudg report file set into the output
    directory and return the file paths."""
    ds = ws_dataset(ctx, dataset)
    out = ctx.workspace.output_path(subdir)
    out.mkdir(parents=True, exist_ok=True)
    files: dict[str, str] = {}
    if format == "json":
        from cloudg.renderers.json_export import JSONExporter

        p = JSONExporter(output_dir=str(out)).export(
            _scan_result(ds), graph_json=ds.builder.to_d3_json()
        )
        files["json"] = str(p)
    elif format == "html":
        from cloudg.renderers.html_report import HTMLReportGenerator

        p = HTMLReportGenerator(output_dir=str(out)).generate(
            _scan_result(ds), graph_json=ds.builder.to_d3_json()
        )
        files["html"] = str(p)
    elif format == "inventory":
        files.update({k: str(v) for k, v in ds.inventory_view().export(out).items()})
    elif format == "graphml":
        files["graphml"] = str(ds.builder.save_graphml(out / f"{ds.name}.graphml"))
    else:
        from cloudg.inventory.mapper import InventoryMapper

        mapper = InventoryMapper(ctx.workspace.config)
        files.update(
            {
                k: str(v)
                for k, v in mapper.export_merged(ds.inventory_view(), ds.findings, out).items()
            }
        )
    return {"dataset": ds.name, "format": format, "output_dir": str(out), "files": files}


def register(reg: Registry) -> None:
    """Add this module's tools to ``reg``."""
    CATALOG.register(reg)
