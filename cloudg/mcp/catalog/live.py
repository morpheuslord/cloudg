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

from pydantic import Field

from cloudg.mcp.catalog._common import Catalog, DatasetArg, ws_dataset
from cloudg.mcp.core import (
    AccessDeniedError,
    Capability,
    InvalidArgumentsError,
    MCPLayerError,
    RateLimitedError,
    Registry,
    Sensitivity,
)
from cloudg.mcp.state import Dataset
from cloudg.resilience import stats_scope

CATEGORY = "live"
R, W, FS = Capability.READ_STATE, Capability.WRITE_STATE, Capability.WRITE_FS
CLOUD, EXEC = Capability.CLOUD_ACCESS, Capability.EXEC
PROVIDERS = ("aws", "azure", "gcp")
SCANNERS = ("prowler", "scoutsuite", "checkov", "trivy", "iam")

Providers = Annotated[list[str] | None, Field(
    description="Subset of aws, azure, gcp; empty = the configured providers.")]
Regions = Annotated[list[str] | None, Field(
    description="Regions to collect for every selected provider; empty = configured regions.")]
NameArg = Annotated[str, Field(description="Dataset name for the result; default "
                               "'<tool>-<timestamp>'.")]

PHASES = {
    "inventory_mapping": 1,
    "collection": 1,
    "scanning": 2,
    "ingest": 2,
    "analysis": 3,
    "normalisation": 4,
    "reporting": 5,
}


def _engine(cfg: Any) -> Any:
    from cloudg import api

    return api.CloudGEngine(cfg)


def _config(ctx: Any, providers: list[str] | None, regions: list[str] | None, **inv: Any) -> Any:
    cfg = ctx.workspace.config.model_copy(deep=True)
    if providers:
        bad = [p for p in providers if p.lower() not in PROVIDERS]
        if bad:
            raise InvalidArgumentsError(
                f"Unknown provider(s) {', '.join(bad)}. Use aws, azure, gcp.")
        cfg.providers = [p.lower() for p in providers]
    if regions:
        for p in cfg.providers:
            sub = getattr(cfg, p, None)
            if sub is not None and hasattr(sub, "regions"):
                sub.regions = list(regions)
    for k, v in inv.items():
        if v is not None:
            setattr(cfg.inventory, k, v)
    return cfg


class PreflightError(MCPLayerError):
    """The configured credentials for a provider cannot work, so a live
    collection would only burn minutes of failing API calls."""


# Bound on the whole credential check: the AWS default chain may probe the
# instance metadata service and Azure fetches one AAD token.
PREFLIGHT_TIMEOUT_S = 25.0


def _check_aws(cfg: Any) -> str | None:
    import os

    try:
        import boto3
        from botocore.exceptions import BotoCoreError
    except ImportError:
        return "boto3 is not installed (pip install 'cloudg[aws]')"
    if cfg.access_key_id and cfg.secret_access_key:
        return None
    token_file = cfg.web_identity_token_file or os.environ.get("AWS_WEB_IDENTITY_TOKEN_FILE")
    if cfg.role_arn and token_file:
        return None if os.path.isfile(token_file) else (
            f"web identity token file {token_file} does not exist")
    try:
        session = boto3.Session(profile_name=cfg.profile) if cfg.profile else boto3.Session()
        creds = session.get_credentials()
    except BotoCoreError as exc:
        return str(exc)
    if creds is None:
        return ("no credentials found (set aws.profile / access keys in the cloudg config, "
                "AWS_PROFILE / AWS_ACCESS_KEY_ID in the server's environment, or run on a "
                "host with an instance role)")
    return None


def _check_azure(cfg: Any) -> str | None:
    try:
        from cloudg.credentials import build_azure_credential

        build_azure_credential(cfg).get_token("https://management.azure.com/.default")
    except ImportError:
        return "the Azure SDK is not installed (pip install 'cloudg[azure]')"
    except Exception as exc:  # azure.identity raises CredentialUnavailableError & co
        return f"{type(exc).__name__}: {str(exc).splitlines()[0][:300]}"
    return None


def _check_gcp(cfg: Any) -> str | None:
    try:
        from cloudg.credentials import build_gcp_credentials

        build_gcp_credentials(cfg)
    except ImportError:
        return "google-auth is not installed (pip install 'cloudg[gcp]')"
    except Exception as exc:  # google.auth.exceptions.DefaultCredentialsError
        return f"{type(exc).__name__}: {str(exc).splitlines()[0][:300]}"
    return None


_CHECKS = {"aws": _check_aws, "azure": _check_azure, "gcp": _check_gcp}


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
            asyncio.to_thread(credential_problems, cfg), PREFLIGHT_TIMEOUT_S)
    except asyncio.TimeoutError:
        raise PreflightError(
            f"Credential check did not finish within {PREFLIGHT_TIMEOUT_S:.0f}s; the cloud "
            "identity endpoints look unreachable. Pass preflight=false to try anyway.") from None
    if problems:
        detail = "; ".join(f"{p}: {msg}" for p, msg in problems.items())
        raise PreflightError(
            f"Cannot collect live data. {detail}. Fix the server's credentials, choose other "
            "providers, or work offline with load_dataset. Pass preflight=false to skip this "
            "check.", data={"providers": problems})


Preflight = Annotated[bool, Field(
    description="Check the configured credentials before calling any cloud API, so a missing "
    "profile fails in seconds instead of after every collector has retried.")]


def _hook_progress(ctx: Any, engine: Any, total: float) -> list[str]:
    """Wire the engine's phase hook to MCP progress notifications."""
    loop = asyncio.get_running_loop()
    phases: list[str] = []

    def on_phase(phase: str) -> None:
        phases.append(phase)
        step = min(float(PHASES.get(phase, len(phases))), total - 0.5)
        asyncio.run_coroutine_threadsafe(
            ctx.report_progress(step, total, f"phase: {phase}"), loop)

    errors: list[str] = []

    def on_error(phase: str, exc: Exception) -> None:
        errors.append(f"{phase}: {exc}")

    engine.on_phase_start = on_phase
    engine.on_error = on_error
    engine._mcp_errors = errors  # surfaced in the tool result
    return phases


async def _done(ctx: Any, total: float) -> None:
    """Let queued phase notifications go out, then report completion
    (MCP progress must increase, so 'done' has to be last)."""
    for _ in range(3):
        await asyncio.sleep(0)
    await ctx.report_progress(total, total, "done")


def _land(ctx: Any, ds: Dataset, tool: str, started: float, extra: dict[str, Any],
          replace: bool) -> dict:
    """Add a live result to the workspace and build the tool result. Runs
    inside the guarded operation, so callers joined by single-flight get
    this same result (and dataset) instead of a duplicate."""
    ctx.workspace.add(ds, activate=True, replace=replace)
    summary = ds.summary()
    out = {
        "dataset": ds.name,
        "active": True,
        "tool": tool,
        "duration_s": round(time.monotonic() - started, 1),
        "summary": {k: summary[k] for k in (
            "total_assets", "total_edges", "total_findings", "open_findings",
            "severity_breakdown", "accounts", "regions", "internet_exposed",
            "cross_account_edges", "assets_by_type", "providers")},
        **extra,
        "next_steps": ["dataset_summary", "find_assets", "top_risks", "attack_paths",
                       "export_report(format='inventory') to persist it"],
    }
    throttling = ds.metadata.get("throttling")
    if throttling:
        out["throttling"] = _throttling_summary(throttling)
    return out


def _run_throttling(result: Any, stats: Any) -> dict[str, Any] | None:
    """Throttling of one live run: the result's own report when it has one
    (InventoryResult.throttling), else the run's bound resilience stats."""
    throttling = getattr(result, "throttling", None)
    if throttling:
        return throttling
    if stats is not None and stats.eventful:
        from cloudg.resilience import get_governor

        return get_governor().summary(stats)
    return None


def _throttling_summary(throttling: dict[str, Any]) -> dict[str, Any]:
    return {
        "totals": throttling.get("totals", {}),
        "messages": list(throttling.get("messages", []))[:20],
        "skipped": throttling.get("skipped", {}),
    }


def _links(ctx: Any, out: dict[str, Any]) -> dict[str, Any]:
    ctx.link(f"cloudg://datasets/{out['dataset']}/summary", f"{out['dataset']} summary",
             title="Dataset summary", priority=1.0)
    ctx.link("cloudg://workspace", "workspace")
    return out


def _name(ctx: Any, name: str, prefix: str, replace: bool) -> str:
    """Validate (or generate) the result dataset's name before any cloud call."""
    if name:
        return ctx.workspace.check_name(name, replace=replace)
    return ctx.workspace.unique_name(f"{prefix}-{time.strftime('%Y%m%d-%H%M%S')}")


# ---------------------------------------------------------------------------
# Live operation guard (cloudg.resilience): single-flight, cooldowns, caps
# ---------------------------------------------------------------------------

FORCE_ROLES = {"admin", "operator"}


class LiveOperationRefused(RateLimitedError):
    """The live operation guard refused the call (cooldown, busy or caller
    quota). ``data`` carries the guard's reason, retry_after_seconds and
    scopes, plus the dataset to use instead."""


def live_scopes(cfg: Any) -> list[str]:
    """Guard scopes for the providers of ``cfg``: provider plus account /
    profile / subscription / project when the config names them, otherwise
    the bare provider."""
    scopes: list[str] = []
    for provider in cfg.providers:
        sub = getattr(cfg, provider, None)
        ids: list[str] = []
        if provider == "aws" and sub is not None:
            ids = list(sub.accounts or []) or ([f"profile:{sub.profile}"] if sub.profile else [])
        elif provider == "azure" and sub is not None:
            ids = list(sub.subscription_ids or [])
        elif provider == "gcp" and sub is not None:
            ids = list(sub.project_ids or []) or (
                [f"org:{sub.organization_id}"] if sub.organization_id else [])
        scopes += [f"{provider}/{i}" for i in ids] or [provider]
    return sorted(set(scopes))


def _latest_live_dataset(ctx: Any, providers: Any = None) -> str | None:
    """Newest live dataset that covers every provider in ``providers`` (all
    live datasets when none are given); None rather than a dataset of the
    wrong providers."""
    wanted = {str(p).lower() for p in providers or []}
    live = [
        d
        for d in ctx.workspace.datasets()
        if (d.source == "live" or d.kind == "live")
        and wanted <= {str(p).lower() for p in d.providers or []}
    ]
    live.sort(key=lambda d: d.loaded_at)
    return live[-1].name if live else None


def _bypass(ctx: Any, force: bool) -> bool:
    if not force:
        return False
    if not FORCE_ROLES & set(ctx.principal.roles):
        raise AccessDeniedError(
            "force=true (skip the live cooldown) needs the admin or operator role. Use the "
            "dataset from the last collection, or wait for the cooldown to end.")
    return True


async def _guarded(ctx: Any, op: str, cfg: Any, parts: tuple, scopes: list[str],
                   force: bool, factory: Any) -> dict[str, Any]:
    """Run ``factory`` under the workspace's live guard and map a refusal to
    a readable tool error. The returned dict says whether this call joined
    an identical operation that was already running."""
    from cloudg.resilience import LiveOperationRejected, operation_key

    guard = ctx.workspace.live_guard
    token = object()
    key = operation_key(op, sorted(cfg.providers), scopes, *parts)

    async def run() -> tuple[object, dict[str, Any]]:
        return token, await factory()

    try:
        owner, out = await guard.run(key, run, scopes=scopes, caller=ctx.principal.id,
                                     bypass_cooldown=_bypass(ctx, force))
    except LiveOperationRejected as exc:
        data = exc.to_dict()
        latest = _latest_live_dataset(ctx, getattr(cfg, "providers", None))
        msg = exc.message.rstrip(".") + "."
        if latest:
            data["use_dataset"] = latest
            msg += (f" The last live result is already loaded as dataset {latest!r}; query it "
                    "instead of collecting again.")
        else:
            msg += " Query an already loaded dataset (list_datasets) in the meantime."
        if data.get("reason") == "cooldown":
            msg += " An admin or operator can pass force=true to skip the cooldown."
        raise LiveOperationRefused(msg, data=data) from None
    out = dict(out)
    if owner is not token:
        out["joined"] = True
        out["note"] = ("An identical live operation was already running; this call shares its "
                       "result instead of collecting again.")
    return _links(ctx, out)


Force = Annotated[bool, Field(
    description="Skip the live cooldown for this call. Only honoured for callers with the "
    "admin or operator role; others get an access error.")]
Replace = Annotated[bool, Field(
    description="Overwrite an existing dataset with the same name (otherwise a name clash "
    "is an error, reported before any cloud call).")]

CATALOG = Catalog()

_LIVE = dict(category=CATEGORY, read_only=False, destructive=False, idempotent=False,
            open_world=True)
@CATALOG.tool(title="Map inventory (live)", sensitivity=Sensitivity.CONFIDENTIAL,
          capabilities={R, W, CLOUD}, timeout_seconds=3600, **_LIVE)
async def map_inventory(
    ctx: Any,
    providers: Providers = None,
    regions: Regions = None,
    services: Annotated[list[str] | None, Field(
        description="Service families: all, network, compute, containers, kubernetes, "
        "serverless, integration, data, storage, identity, security, dns, iac, logging.")]
    = None,
    tagging_sweep: Annotated[bool | None, Field(
        description="AWS Resource Groups Tagging API sweep; default from config.")] = None,
    name: NameArg = "",
    replace: Replace = False,
    preflight: Preflight = True,
    force: Force = False,
) -> dict:
    """Map the complete live inventory (no scanners) with read-only cloud
    API calls using the server's configured credentials: deep collectors,
    catch-all sweeps and relationship linking, across accounts when
    organization discovery is configured. Takes minutes. The result
    becomes the active dataset; this returns a summary and links.
    Guarded: identical concurrent calls share one run, a scope collected
    recently is refused with retry_after (use the existing dataset), and
    only a few live operations run at once."""
    started = time.monotonic()
    cfg = _config(ctx, providers, regions, services=services)
    ds_name = _name(ctx, name, "inventory", replace)
    _bypass(ctx, force)
    if preflight:
        await _preflight(cfg)
    scopes = live_scopes(cfg)

    async def op() -> dict[str, Any]:
        engine = _engine(cfg)
        _hook_progress(ctx, engine, 2.0)
        await ctx.report_progress(0.5, 2, "mapping inventory")
        with stats_scope() as stats:
            result = await engine.map_inventory(tagging_sweep=tagging_sweep)
        ds = Dataset.from_inventory(result, ds_name, source="live")
        throttling = _run_throttling(result, stats)
        if throttling:
            ds.metadata["throttling"] = throttling
        await _done(ctx, 2)
        cov = [c.to_summary() for c in ds.coverage]
        return _land(ctx, ds, "map_inventory", started, {
            "collection_failures": [f for c in cov for f in c["failures"]][:20],
            "errors": getattr(engine, "_mcp_errors", []),
        }, replace)

    return await _guarded(ctx, "map", cfg, (regions, services, tagging_sweep), scopes,
                          force, op)

@CATALOG.tool(title="Collect assets (live)", sensitivity=Sensitivity.CONFIDENTIAL,
          capabilities={R, W, CLOUD}, timeout_seconds=3600, **_LIVE)
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
    _bypass(ctx, force)
    if preflight:
        await _preflight(cfg)

    async def op() -> dict[str, Any]:
        engine = _engine(cfg)
        _hook_progress(ctx, engine, 2.0)
        with stats_scope() as stats:
            result = await engine.collect()
        ds = Dataset.from_collection(result, ds_name)
        throttling = _run_throttling(result, stats)
        if throttling:
            ds.metadata["throttling"] = throttling
        await _done(ctx, 2)
        return _land(ctx, ds, "collect_assets", started,
                     {"errors": getattr(engine, "_mcp_errors", [])}, replace)

    return await _guarded(ctx, "collect", cfg, (regions,), live_scopes(cfg), force, op)

@CATALOG.tool(title="Run scanners", sensitivity=Sensitivity.CONFIDENTIAL,
          capabilities={R, W, Capability.READ_FS, FS, CLOUD, EXEC}, timeout_seconds=7200,
          **_LIVE)
async def run_scanners(
    ctx: Any,
    scanners: Annotated[list[str] | None, Field(
        description="Subset of prowler, scoutsuite, checkov, trivy, iam; empty = "
        "configured.")] = None,
    iac_dir: Annotated[str, Field(description="IaC directory for Checkov (inside an "
                                  "allowed root).")] = "",
    images: Annotated[list[str] | None, Field(description="Container images for "
                                              "Trivy.")] = None,
    normalise: bool = True,
    dataset: DatasetArg = "",
    preflight: Preflight = True,
    force: Force = False,
) -> dict:
    """Run security scanners (external binaries, cloud credentials)
    plus cloudg's reachability analysis against a dataset's assets and
    add the findings to it (deduplicated and compliance-mapped when
    normalise=true). Scanner output files go to <output_dir>/scans.
    When Prowler or ScoutSuite run, the call is guarded like the
    collection tools (shared runs, per-scope cooldown, concurrency caps)."""
    started = time.monotonic()
    ds = ws_dataset(ctx, dataset)
    if scanners:
        bad = [s for s in scanners if s.lower() not in SCANNERS]
        if bad:
            raise InvalidArgumentsError(
                f"Unknown scanner(s) {', '.join(bad)}. Use: {', '.join(SCANNERS)}")
    cfg = _config(ctx, None, None)
    if scanners:
        cfg.scanners.enabled = [s.lower() for s in scanners]
    iac = str(ctx.workspace.check_path(iac_dir)) if iac_dir else None
    out_dir = ctx.workspace.output_path("scans")
    _bypass(ctx, force)
    # Only the cloud scanners need credentials (and cloud scopes);
    # checkov / trivy / iam run offline
    cloud = bool({"prowler", "scoutsuite"} & {s.lower() for s in cfg.scanners.enabled})
    if preflight and cloud:
        await _preflight(cfg)

    async def op() -> dict[str, Any]:
        engine = _engine(cfg)
        _hook_progress(ctx, engine, 3.0)
        with stats_scope() as stats:
            findings = await engine.scan(ds.assets, ds.edges, iac_dir=iac, images=images,
                                         output_dir=out_dir)
        before = len(ds.findings)
        if normalise:
            from cloudg.mcp.catalog.findings import renormalise

            await asyncio.to_thread(renormalise, ctx.workspace, ds, findings)
        else:
            ds.add_findings(findings)
        ctx.workspace.mutated(ds)
        await _done(ctx, 3)
        sev: dict[str, int] = {}
        for f in findings:
            sev[f.severity.value] = sev.get(f.severity.value, 0) + 1
        throttling = _run_throttling(None, stats)
        extra = {"throttling": _throttling_summary(throttling)} if throttling else {}
        return {**extra, "dataset": ds.name, "scanners": cfg.scanners.enabled,
                "new_findings": len(findings), "severity_breakdown": sev,
                "findings_before": before, "findings_after": len(ds.findings),
                "output_dir": str(out_dir),
                "duration_s": round(time.monotonic() - started, 1),
                "errors": getattr(engine, "_mcp_errors", []),
                "next_steps": ["top_risks", "list_findings(min_severity='HIGH')",
                               "compliance_summary"]}

    scopes = live_scopes(cfg) if cloud else []
    return await _guarded(ctx, "scan", cfg,
                          (ds.name, sorted(cfg.scanners.enabled), iac, images, normalise),
                          scopes, force, op)

@CATALOG.tool(title="Run full pipeline", sensitivity=Sensitivity.CONFIDENTIAL,
          capabilities={R, W, FS, CLOUD, EXEC}, timeout_seconds=7200, **_LIVE)
async def run_pipeline(
    ctx: Any,
    providers: Providers = None,
    regions: Regions = None,
    subdir: Annotated[str, Field(pattern=r"^[A-Za-z0-9_.\-/]{0,200}$",
                                 description="Output sub-directory for reports.")] = "pipeline",
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
    _bypass(ctx, force)
    if preflight:
        await _preflight(cfg)

    async def op() -> dict[str, Any]:
        engine = _engine(cfg)
        _hook_progress(ctx, engine, 6.0)
        with stats_scope() as stats:
            result = await engine.run_pipeline(output_dir=out_dir)
        ds = Dataset.from_pipeline(result, ds_name)
        throttling = _run_throttling(result, stats)
        if throttling:
            ds.metadata["throttling"] = throttling
        await _done(ctx, 6)
        return _land(ctx, ds, "run_pipeline", started, {
            "report_paths": {k: str(v) for k, v in result.report_paths.items()},
            "attack_paths_found": len(result.attack_paths),
            "errors": list(result.errors) + getattr(engine, "_mcp_errors", []),
        }, replace)

    return await _guarded(ctx, "pipeline", cfg, (regions, subdir), live_scopes(cfg),
                          force, op)

@CATALOG.tool(title="Rate limit status", category=CATEGORY, sensitivity=Sensitivity.INTERNAL,
          capabilities={R}, read_only=True, idempotent=True, open_world=False)
def rate_limit_status(ctx: Any) -> dict:
    """Live-operation guard and cloud API throttling state, without
    calling any cloud API: live operations in flight, scopes cooling
    down (seconds left before a new live collection is accepted), the
    cooldown and concurrency settings, and the throttling governor's
    tripped circuit breakers, slowed rate buckets and recent throttling.
    Check it before map_inventory / collect_assets to avoid a refusal."""
    return rate_limit_snapshot(ctx.workspace)

@CATALOG.resource("cloudg://ratelimit", title="Rate limit status", category=CATEGORY,
              sensitivity=Sensitivity.INTERNAL,
              description="Live-operation guard and cloud API throttling state.")
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
