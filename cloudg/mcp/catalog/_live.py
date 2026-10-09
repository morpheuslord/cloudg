"""Helpers behind the live tools: engine and config set-up, credential
checks, progress wiring, landing results, the live-operation guard and
the scanner job."""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass
from typing import Any, Awaitable, Callable

from cloudg.mcp.core import AccessDeniedError, InvalidArgumentsError, RateLimitedError
from cloudg.mcp.state import Dataset
from cloudg.resilience import stats_scope

PROVIDERS = ("aws", "azure", "gcp")
SCANNERS = ("prowler", "scoutsuite", "checkov", "trivy", "iam")

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
                f"Unknown provider(s) {', '.join(bad)}. Use aws, azure, gcp."
            )
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
        return (
            None
            if os.path.isfile(token_file)
            else (f"web identity token file {token_file} does not exist")
        )
    try:
        session = boto3.Session(profile_name=cfg.profile) if cfg.profile else boto3.Session()
        creds = session.get_credentials()
    except BotoCoreError as exc:
        return str(exc)
    if creds is None:
        return (
            "no credentials found (set aws.profile / access keys in the cloudg config, "
            "AWS_PROFILE / AWS_ACCESS_KEY_ID in the server's environment, or run on a "
            "host with an instance role)"
        )
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


def _hook_progress(ctx: Any, engine: Any, total: float) -> list[str]:
    """Wire the engine's phase hook to MCP progress notifications."""
    loop = asyncio.get_running_loop()
    phases: list[str] = []

    def on_phase(phase: str) -> None:
        phases.append(phase)
        step = min(float(PHASES.get(phase, len(phases))), total - 0.5)
        asyncio.run_coroutine_threadsafe(ctx.report_progress(step, total, f"phase: {phase}"), loop)

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


def _land(
    ctx: Any, ds: Dataset, tool: str, started: float, extra: dict[str, Any], replace: bool
) -> dict:
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
        "summary": {
            k: summary[k]
            for k in (
                "total_assets",
                "total_edges",
                "total_findings",
                "open_findings",
                "severity_breakdown",
                "accounts",
                "regions",
                "internet_exposed",
                "cross_account_edges",
                "assets_by_type",
                "providers",
            )
        },
        **extra,
        "next_steps": [
            "dataset_summary",
            "find_assets",
            "top_risks",
            "attack_paths",
            "export_report(format='inventory') to persist it",
        ],
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
    ctx.link(
        f"cloudg://datasets/{out['dataset']}/summary",
        f"{out['dataset']} summary",
        title="Dataset summary",
        priority=1.0,
    )
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


def _aws_scope_ids(sub: Any) -> list[str]:
    return list(sub.accounts or []) or ([f"profile:{sub.profile}"] if sub.profile else [])


def _azure_scope_ids(sub: Any) -> list[str]:
    return list(sub.subscription_ids or [])


def _gcp_scope_ids(sub: Any) -> list[str]:
    return list(sub.project_ids or []) or (
        [f"org:{sub.organization_id}"] if sub.organization_id else []
    )


_SCOPE_IDS = {"aws": _aws_scope_ids, "azure": _azure_scope_ids, "gcp": _gcp_scope_ids}


def live_scopes(cfg: Any) -> list[str]:
    """Guard scopes for the providers of ``cfg``: provider plus account /
    profile / subscription / project when the config names them, otherwise
    the bare provider."""
    scopes: list[str] = []
    for provider in cfg.providers:
        sub = getattr(cfg, provider, None)
        ids_of = _SCOPE_IDS.get(provider)
        ids = ids_of(sub) if ids_of is not None and sub is not None else []
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
            "dataset from the last collection, or wait for the cooldown to end."
        )
    return True


async def _guarded(
    ctx: Any, op: str, cfg: Any, parts: tuple, scopes: list[str], force: bool, factory: Any
) -> dict[str, Any]:
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
        owner, out = await guard.run(
            key, run, scopes=scopes, caller=ctx.principal.id, bypass_cooldown=_bypass(ctx, force)
        )
    except LiveOperationRejected as exc:
        data = exc.to_dict()
        latest = _latest_live_dataset(ctx, getattr(cfg, "providers", None))
        msg = exc.message.rstrip(".") + "."
        if latest:
            data["use_dataset"] = latest
            msg += (
                f" The last live result is already loaded as dataset {latest!r}; query it "
                "instead of collecting again."
            )
        else:
            msg += " Query an already loaded dataset (list_datasets) in the meantime."
        if data.get("reason") == "cooldown":
            msg += " An admin or operator can pass force=true to skip the cooldown."
        raise LiveOperationRefused(msg, data=data) from None
    out = dict(out)
    if owner is not token:
        out["joined"] = True
        out["note"] = (
            "An identical live operation was already running; this call shares its "
            "result instead of collecting again."
        )
    return _links(ctx, out)


@dataclass
class ScanJob:
    """Everything run_scanners hands to the guarded scan operation."""

    ds: Dataset
    cfg: Any
    iac_dir: Any
    images: list[str] | None
    out_dir: Any
    normalise: bool
    started: float


def _scanner_config(ctx: Any, scanners: list[str] | None) -> Any:
    if scanners:
        bad = [s for s in scanners if s.lower() not in SCANNERS]
        if bad:
            raise InvalidArgumentsError(
                f"Unknown scanner(s) {', '.join(bad)}. Use: {', '.join(SCANNERS)}"
            )
    cfg = _config(ctx, None, None)
    if scanners:
        cfg.scanners.enabled = [s.lower() for s in scanners]
    return cfg


def _check_images(images: list[str] | None) -> None:
    """Refuse image references that the scanner would read as options."""
    bad = [i for i in images or [] if not i.strip() or i.lstrip().startswith("-")]
    if bad:
        raise InvalidArgumentsError(
            "Container image references must be non-empty and must not start with '-' "
            "(they are passed to trivy on its command line).",
            data={"value": bad},
        )


async def _run_scan(ctx: Any, job: ScanJob) -> dict[str, Any]:
    ds, cfg = job.ds, job.cfg
    engine = _engine(cfg)
    _hook_progress(ctx, engine, 3.0)
    with stats_scope() as stats:
        findings = await engine.scan(
            ds.assets,
            ds.edges,
            iac_dir=str(job.iac_dir) if job.iac_dir else None,
            images=job.images,
            output_dir=job.out_dir,
        )
    before = len(ds.findings)
    if job.normalise:
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
    return {
        **extra,
        "dataset": ds.name,
        "scanners": cfg.scanners.enabled,
        "new_findings": len(findings),
        "severity_breakdown": sev,
        "findings_before": before,
        "findings_after": len(ds.findings),
        "output_dir": str(job.out_dir),
        "duration_s": round(time.monotonic() - job.started, 1),
        "errors": getattr(engine, "_mcp_errors", []),
        "next_steps": ["top_risks", "list_findings(min_severity='HIGH')", "compliance_summary"],
    }


@dataclass
class LiveRun:
    """One guarded live collection: how to call the engine, turn its
    result into a dataset, and what to add to the tool result."""

    tool: str
    total: float
    started: float
    replace: bool
    call: Callable[[Any], Awaitable[Any]]
    build: Callable[[Any], Dataset]
    extra: Callable[[Any, Any, Dataset], dict[str, Any]]
    note: str = ""


async def run_live(ctx: Any, cfg: Any, run: LiveRun) -> dict[str, Any]:
    """Run the engine for ``run`` and land the result as a dataset."""
    engine = _engine(cfg)
    _hook_progress(ctx, engine, run.total)
    if run.note:
        await ctx.report_progress(0.5, run.total, run.note)
    with stats_scope() as stats:
        result = await run.call(engine)
    ds = run.build(result)
    throttling = _run_throttling(result, stats)
    if throttling:
        ds.metadata["throttling"] = throttling
    await _done(ctx, run.total)
    return _land(ctx, ds, run.tool, run.started, run.extra(result, engine, ds), run.replace)


def engine_errors(engine: Any) -> list[str]:
    return getattr(engine, "_mcp_errors", [])
