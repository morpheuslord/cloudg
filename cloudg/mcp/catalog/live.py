"""Live tools: collect from cloud APIs, run scanners, run the full pipeline.

These are the only tools that touch the outside world (``open_world``):
they call provider APIs with the configured credentials
(``cloud_access``) and, for scanners, spawn external binaries (``exec``).
They are long-running, report progress per pipeline phase, and land their
results in the workspace as a new dataset. The tool result is a summary
plus resource links, never the full dump.

The engine is looked up as ``cloudg.api.CloudGEngine`` at call time so it
can be swapped (tests monkeypatch it; embedders can subclass it).
"""

from __future__ import annotations

import asyncio
import time
from typing import Annotated, Any

from pydantic import BaseModel, Field

from cloudg.mcp.catalog._common import Catalog, DatasetArg, ws_dataset
from cloudg.mcp.catalog._live import (
    _CHECKS,
    FORCE_ROLES,
    PHASES,
    PROVIDERS,
    SCANNERS,
    LiveOperationRefused,
    LiveRun,
    ScanJob,
    _bypass,
    _check_aws,
    _check_azure,
    _check_gcp,
    _check_images,
    _config,
    _guarded,
    _latest_live_dataset,
    _name,
    _run_scan,
    _run_throttling,
    _scanner_config,
    _throttling_summary,
    engine_errors,
    live_scopes,
    run_live,
)
from cloudg.mcp.core import (
    Capability,
    MCPLayerError,
    Registry,
    Sensitivity,
)
from cloudg.mcp.state import Dataset

__all__ = [
    "CATALOG",
    "FORCE_ROLES",
    "PHASES",
    "PREFLIGHT_TIMEOUT_S",
    "PROVIDERS",
    "SCANNERS",
    "LiveOperationRefused",
    "PreflightError",
    "_check_aws",
    "_check_azure",
    "_check_gcp",
    "_latest_live_dataset",
    "_run_throttling",
    "_throttling_summary",
    "credential_problems",
    "live_scopes",
    "rate_limit_snapshot",
    "register",
]

CATEGORY = "live"
R, W, FS = Capability.READ_STATE, Capability.WRITE_STATE, Capability.WRITE_FS
CLOUD, EXEC = Capability.CLOUD_ACCESS, Capability.EXEC

Providers = Annotated[
    list[str] | None,
    Field(description="Subset of aws, azure, gcp; empty = the configured providers."),
]
Regions = Annotated[
    list[str] | None,
    Field(
        description="Regions to collect for every selected provider; empty = configured regions."
    ),
]
NameArg = Annotated[
    str, Field(description="Dataset name for the result; default '<tool>-<timestamp>'.")
]


class PreflightError(MCPLayerError):
    """The configured credentials for a provider cannot work, so a live
    collection would only burn minutes of failing API calls."""


# Bound on the whole credential check: the AWS default chain may probe the
# instance metadata service and Azure fetches one AAD token.
PREFLIGHT_TIMEOUT_S = 25.0


def credential_problems(cfg: Any) -> dict[str, str]:
    """Provider -> why its credentials cannot work, for every configured
    provider whose credentials fail a cheap local check (no cloud API
    calls beyond one Azure token request)."""
    problems: dict[str, str] = {}
    for provider in cfg.providers:
        check = _CHECKS.get(provider)
        if check is None:
            continue
        problem = check(getattr(cfg, provider))
        if problem:
            problems[provider] = problem
    return problems


async def _preflight(cfg: Any) -> None:
    """Fail fast instead of running every collector against credentials
    that cannot work (each one would retry, back off and fail)."""
    try:
        problems = await asyncio.wait_for(
            asyncio.to_thread(credential_problems, cfg), PREFLIGHT_TIMEOUT_S
        )
    except asyncio.TimeoutError:
        raise PreflightError(
            f"Credential check did not finish within {PREFLIGHT_TIMEOUT_S:.0f}s; the cloud "
            "identity endpoints look unreachable. Pass preflight=false to try anyway."
        ) from None
    if problems:
        detail = "; ".join(f"{p}: {msg}" for p, msg in problems.items())
        raise PreflightError(
            f"Cannot collect live data. {detail}. Fix the server's credentials, choose other "
            "providers, or work offline with load_dataset. Pass preflight=false to skip this "
            "check.",
            data={"providers": problems},
        )


Preflight = Annotated[
    bool,
    Field(
        description="Check the configured credentials before calling any cloud API, so a missing "
        "profile fails in seconds instead of after every collector has retried."
    ),
]


Force = Annotated[
    bool,
    Field(
        description="Skip the live cooldown for this call. Only honoured for callers with the "
        "admin or operator role; others get an access error."
    ),
]
Replace = Annotated[
    bool,
    Field(
        description="Overwrite an existing dataset with the same name (otherwise a name clash "
        "is an error, reported before any cloud call)."
    ),
]


CATALOG = Catalog()

_LIVE = dict(
    category=CATEGORY, read_only=False, destructive=False, idempotent=False, open_world=True
)


ServicesArg = Annotated[
    list[str] | None,
    Field(
        description="Service families: all, network, compute, containers, kubernetes, "
        "serverless, integration, data, storage, identity, security, dns, iac, logging."
    ),
]
TaggingArg = Annotated[
    bool | None,
    Field(description="AWS Resource Groups Tagging API sweep; default from config."),
]
ScannersArg = Annotated[
    list[str] | None,
    Field(description="Subset of prowler, scoutsuite, checkov, trivy, iam; empty = configured."),
]
IacArg = Annotated[str, Field(description="IaC directory for Checkov (inside an allowed root).")]
ImagesArg = Annotated[list[str] | None, Field(description="Container images for Trivy.")]
SubdirArg = Annotated[
    str,
    Field(pattern=r"^[A-Za-z0-9_.\-/]{0,200}$", description="Output sub-directory for reports."),
]


class MapInventoryArgs(BaseModel):
    """map_inventory arguments (the MCP wire schema)."""

    providers: Providers = None
    regions: Regions = None
    services: ServicesArg = None
    tagging_sweep: TaggingArg = None
    name: NameArg = ""
    replace: Replace = False
    preflight: Preflight = True
    force: Force = False


async def _admit(ctx: Any, cfg: Any, force: bool, preflight: bool) -> None:
    """Role check for force, then the credential preflight."""
    _bypass(ctx, force)
    if preflight:
        await _preflight(cfg)


@CATALOG.tool(
    title="Map inventory (live)",
    sensitivity=Sensitivity.CONFIDENTIAL,
    capabilities={R, W, CLOUD},
    timeout_seconds=3600,
    **_LIVE,
)
async def map_inventory(ctx: Any, args: MapInventoryArgs) -> dict:
    """Map the complete live inventory (no scanners) with read-only cloud
    API calls using the server's configured credentials: deep collectors,
    catch-all sweeps and relationship linking, across accounts when
    organization discovery is configured. Takes minutes. The result
    becomes the active dataset; this returns a summary and links.
    Guarded: identical concurrent calls share one run, a scope collected
    recently is refused with retry_after (use the existing dataset), and
    only a few live operations run at once."""
    started = time.monotonic()
    cfg = _config(ctx, args.providers, args.regions, services=args.services)
    ds_name = _name(ctx, args.name, "inventory", args.replace)
    await _admit(ctx, cfg, args.force, args.preflight)

    def extra_fields(result: Any, engine: Any, ds: Dataset) -> dict[str, Any]:
        cov = [c.to_summary() for c in ds.coverage]
        failures = [f for c in cov for f in c["failures"]][:20]
        return {"collection_failures": failures, "errors": engine_errors(engine)}

    run = LiveRun(
        "map_inventory",
        2.0,
        started,
        args.replace,
        call=lambda engine: engine.map_inventory(tagging_sweep=args.tagging_sweep),
        build=lambda result: Dataset.from_inventory(result, ds_name, source="live"),
        extra_fields=extra_fields,
        note="mapping inventory",
    )
    key = (args.regions, args.services, args.tagging_sweep)
    return await _guarded(
        ctx, "map", cfg, key, live_scopes(cfg), args.force, lambda: run_live(ctx, cfg, run)
    )


@CATALOG.tool(
    title="Collect assets (live)",
    sensitivity=Sensitivity.CONFIDENTIAL,
    capabilities={R, W, CLOUD},
    timeout_seconds=3600,
    **_LIVE,
)
async def collect_assets(
    ctx: Any,
    providers: Providers = None,
    regions: Regions = None,
    name: NameArg = "",
    replace: Replace = False,
    preflight: Preflight = True,
    force: Force = False,
) -> dict:
    """Run the standard multi-provider asset collection (the `cloudg
    collect` phase: core services, network edges, IAM). It is lighter than
    map_inventory. The result becomes the active dataset. Guarded like
    map_inventory (shared runs, per-scope cooldown, concurrency caps)."""
    started = time.monotonic()
    cfg = _config(ctx, providers, regions)
    ds_name = _name(ctx, name, "collect", replace)
    await _admit(ctx, cfg, force, preflight)
    run = LiveRun(
        "collect_assets",
        2.0,
        started,
        replace,
        call=lambda engine: engine.collect(),
        build=lambda result: Dataset.from_collection(result, ds_name),
        extra_fields=lambda result, engine, ds: {"errors": engine_errors(engine)},
    )
    return await _guarded(
        ctx, "collect", cfg, (regions,), live_scopes(cfg), force, lambda: run_live(ctx, cfg, run)
    )


@CATALOG.tool(
    title="Run scanners",
    sensitivity=Sensitivity.CONFIDENTIAL,
    capabilities={R, W, Capability.READ_FS, FS, CLOUD, EXEC},
    timeout_seconds=7200,
    **_LIVE,
)
async def run_scanners(
    ctx: Any,
    scanners: ScannersArg = None,
    iac_dir: IacArg = "",
    images: ImagesArg = None,
    normalise: bool = True,
    dataset: DatasetArg = "",
    preflight: Preflight = True,
    force: Force = False,
) -> dict:
    """Run security scanners (external binaries, cloud credentials)
    plus cloudg's reachability analysis against a dataset's assets and
    add the findings to it (deduplicated and compliance-mapped when
    normalise=true). Scanner output files go to <output_dir>/scans.
    Image references must not start with '-'. When Prowler or ScoutSuite
    run, the call is guarded like the collection tools (shared runs,
    per-scope cooldown, concurrency caps)."""
    started = time.monotonic()
    ds = ws_dataset(ctx, dataset)
    cfg = _scanner_config(ctx, scanners)
    _check_images(images)
    iac = ctx.workspace.check_path(iac_dir) if iac_dir else None
    scan = ScanJob(ds, cfg, iac, images, ctx.workspace.output_path("scans"), normalise, started)
    # Only the cloud scanners need credentials (and cloud scopes);
    # checkov / trivy / iam run offline
    cloud = bool({"prowler", "scoutsuite"} & {s.lower() for s in cfg.scanners.enabled})
    await _admit(ctx, cfg, force, preflight and cloud)
    key = (ds.name, sorted(cfg.scanners.enabled), str(iac) if iac else None, images, normalise)
    return await _guarded(
        ctx,
        "scan",
        cfg,
        key,
        live_scopes(cfg) if cloud else [],
        force,
        lambda: _run_scan(ctx, scan),
    )


@CATALOG.tool(
    title="Run full pipeline",
    sensitivity=Sensitivity.CONFIDENTIAL,
    capabilities={R, W, FS, CLOUD, EXEC},
    timeout_seconds=7200,
    **_LIVE,
)
async def run_pipeline(
    ctx: Any,
    providers: Providers = None,
    regions: Regions = None,
    subdir: SubdirArg = "pipeline",
    name: NameArg = "",
    replace: Replace = False,
    preflight: Preflight = True,
    force: Force = False,
) -> dict:
    """The complete cloudg pipeline: collect -> scan -> analyse (graph,
    ontology, RAG, Terraform) -> normalise -> JSON + HTML reports. The
    result becomes the active dataset; report paths are returned.
    Guarded like map_inventory (shared runs, per-scope cooldown,
    concurrency caps)."""
    started = time.monotonic()
    cfg = _config(ctx, providers, regions)
    ds_name = _name(ctx, name, "pipeline", replace)
    out_dir = ctx.workspace.output_path(subdir)
    await _admit(ctx, cfg, force, preflight)

    def extra_fields(result: Any, engine: Any, ds: Dataset) -> dict[str, Any]:
        return {
            "report_paths": {k: str(v) for k, v in result.report_paths.items()},
            "attack_paths_found": len(result.attack_paths),
            "errors": list(result.errors) + engine_errors(engine),
        }

    run = LiveRun(
        "run_pipeline",
        6.0,
        started,
        replace,
        call=lambda engine: engine.run_pipeline(output_dir=out_dir),
        build=lambda result: Dataset.from_pipeline(result, ds_name),
        extra_fields=extra_fields,
    )
    return await _guarded(
        ctx,
        "pipeline",
        cfg,
        (regions, subdir),
        live_scopes(cfg),
        force,
        lambda: run_live(ctx, cfg, run),
    )


@CATALOG.tool(
    title="Rate limit status",
    category=CATEGORY,
    sensitivity=Sensitivity.INTERNAL,
    capabilities={R},
    read_only=True,
    idempotent=True,
    open_world=False,
)
def rate_limit_status(ctx: Any) -> dict:
    """Live-operation guard and cloud API throttling state, without
    calling any cloud API: live operations in flight, scopes cooling
    down (seconds left before a new live collection is accepted), the
    cooldown and concurrency settings, and the throttling governor's
    tripped circuit breakers, slowed rate buckets and recent throttling.
    Check it before map_inventory / collect_assets to avoid a refusal."""
    return rate_limit_snapshot(ctx.workspace)


@CATALOG.resource(
    "cloudg://ratelimit",
    title="Rate limit status",
    category=CATEGORY,
    sensitivity=Sensitivity.INTERNAL,
    description="Live-operation guard and cloud API throttling state.",
)
def ratelimit_resource(ctx: Any) -> dict:
    return rate_limit_snapshot(ctx.workspace)


def rate_limit_snapshot(workspace: Any) -> dict[str, Any]:
    from cloudg.resilience import get_governor

    guard = workspace.live_guard
    return {
        "live_guard": {
            **guard.status(),
            "cooldown_seconds": guard.cooldown_seconds,
            "provider_cooldowns": dict(guard.provider_cooldowns),
            "max_concurrent_per_scope": guard.max_concurrent_per_scope,
            "max_concurrent_total": guard.max_concurrent_total,
            "caller_max_operations": guard.caller_max_operations,
        },
        "throttling": get_governor().summary(),
    }


def register(reg: Registry) -> None:
    """Add this module's tools to ``reg``."""
    CATALOG.register(reg)
