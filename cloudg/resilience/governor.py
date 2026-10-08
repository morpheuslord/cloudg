"""The process-wide resilience governor.

One :class:`Governor` owns the shared state every provider integration
uses: the adaptive :class:`~cloudg.resilience.limiter.RateLimiter`, the
:class:`~cloudg.resilience.breaker.BreakerRegistry`, per-provider retry
settings and retry budgets, and lifetime
:class:`~cloudg.resilience.stats.ResilienceStats`.

It is process-wide on purpose: rates learned while one collection was
throttled keep protecting the next one (an MCP agent re-triggering a live
map must not start from full speed against an API that just pushed back).
Per-run numbers are isolated with :func:`~cloudg.resilience.stats.stats_scope`.

``get_governor()`` returns it; ``configure(config)`` applies a
:class:`~cloudg.config.CloudGConfig` (or its ``ratelimit`` section) and is
idempotent, so every entry point (``MultiAccountCollector``,
``InventoryMapper``) can call it.
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, replace
from typing import Any, Callable

from cloudg.resilience.breaker import BreakerRegistry
from cloudg.resilience import limiter as _limiter
from cloudg.resilience.limiter import (
    LimitSpec,
    ProviderLimits,
    RateLimiter,
    Scope,
    default_limits,
)
from cloudg.resilience.stats import ResilienceStats, current_ledger, current_stats

__all__ = [
    "Governor",
    "RetryBudget",
    "RetrySettings",
    "configure",
    "get_governor",
    "reset_governor",
]

PROVIDERS = ("aws", "azure", "gcp")


@dataclass(frozen=True)
class RetrySettings:
    """Retry bounds of cloudg-level retries for one provider."""

    max_retries: int = 8
    base_delay: float = 0.5
    max_backoff: float = 60.0
    deadline: float = 900.0
    retry_budget: int = 500
    budget_ratio: float = 0.1


class RetryBudget:
    """A per-provider retry budget (token bucket on retries, refilled by successes).

    Every retry costs one token; every success refunds ``ratio`` tokens up
    to ``capacity``. When a whole provider is degraded the budget runs dry
    and cloudg stops retrying instead of multiplying load (the "retry
    quota" of the AWS SDKs' standard mode, the retry budget of Finagle/gRPC).
    """

    def __init__(self, capacity: int, ratio: float = 0.1) -> None:
        self.capacity = float(max(0, capacity))
        self.ratio = ratio
        self._tokens = self.capacity
        self._lock = threading.Lock()

    def try_consume(self, cost: float = 1.0) -> bool:
        with self._lock:
            if self._tokens >= cost:
                self._tokens -= cost
                return True
            return False

    def refund(self) -> None:
        with self._lock:
            self._tokens = min(self.capacity, self._tokens + self.ratio)

    @property
    def remaining(self) -> float:
        with self._lock:
            return self._tokens


def _get(obj: Any, name: str, default: Any = None) -> Any:
    if obj is None:
        return default
    if isinstance(obj, dict):
        return obj.get(name, default)
    return getattr(obj, name, default)


def provider_limits_from_config(provider: str, pcfg: Any, enabled: bool = True) -> ProviderLimits:
    """Built-in defaults for ``provider`` overlaid with ``ratelimit.<provider>``."""
    base = default_limits(provider)
    if pcfg is None:
        return replace(base, enabled=enabled)
    services = dict(base.services)
    for name, svc in (_get(pcfg, "services") or {}).items():
        rate = _get(svc, "max_rps")
        if rate is None:
            continue
        per_op = _get(svc, "per_operation")
        if per_op is None:
            per_op = base.services.get(str(name), LimitSpec(0.0)).per_operation
        services[str(name)] = LimitSpec(float(rate), _get(svc, "burst"), bool(per_op))
    updates: dict[str, Any] = {
        "enabled": bool(enabled and _get(pcfg, "enabled", True)),
        "adaptive": bool(_get(pcfg, "adaptive", True)),
        "services": services,
    }
    for field_name, cfg_name in (
        ("max_rps", "max_rps"),
        ("burst", "burst"),
        ("account_max_rps", "account_max_rps"),
        ("account_burst", "account_burst"),
        ("global_max_rps", "global_max_rps"),
        ("global_burst", "global_burst"),
        ("min_rps", "min_rps"),
        ("max_concurrency", "max_concurrency"),
    ):
        value = _get(pcfg, cfg_name)
        if value is not None:
            updates[field_name] = value
    return replace(base, **updates)


class Governor:
    """Shared limiter + breakers + budgets + stats for every provider call."""

    def __init__(self, config: Any = None, *, clock: Callable[[], float] = time.monotonic) -> None:
        self.clock = clock
        self.stats = ResilienceStats()
        self.limiter = RateLimiter(clock=clock, on_event=self._limiter_event)
        self.breakers = BreakerRegistry(clock=clock)
        self.enabled = True
        self.aws_max_attempts = 10
        self.aws_retry_mode = "adaptive"
        self._retry: dict[str, RetrySettings] = {p: RetrySettings() for p in PROVIDERS}
        self._budgets: dict[str, RetryBudget] = {}
        self._lock = threading.Lock()
        # Serialises whole configure() calls, so two threads applying different
        # configs cannot leave the limiter of one and the breakers of the other
        self._configure_lock = threading.Lock()
        self.ratelimit: Any = None
        self.configure(config)

    # -- configuration -------------------------------------------------

    def configure(self, config: Any) -> "Governor":
        """Apply a CloudGConfig, a RateLimitConfig, or None (defaults)."""
        with self._configure_lock:
            self._apply(config)
        return self

    def _apply(self, config: Any) -> None:
        if config is None:
            ratelimit, aws_cfg = None, None
        elif _get(config, "providers") is not None or _get(config, "ratelimit") is not None:
            # CloudGConfig (or an object shaped like it)
            ratelimit, aws_cfg = _get(config, "ratelimit"), _get(config, "aws")
        else:
            # A bare RateLimitConfig / dict
            ratelimit, aws_cfg = config, None
        if aws_cfg is not None:
            attempts = _get(aws_cfg, "max_retries")
            mode = _get(aws_cfg, "retry_mode")
            if isinstance(attempts, int):
                self.aws_max_attempts = attempts
            if isinstance(mode, str) and mode in ("legacy", "standard", "adaptive"):
                self.aws_retry_mode = mode

        enabled = bool(_get(ratelimit, "enabled", True))
        limits: dict[str, ProviderLimits] = {}
        breaker_settings: dict[str, dict[str, Any]] = {}
        retry: dict[str, RetrySettings] = {}
        for provider in set(PROVIDERS) | set(_limiter.DEFAULT_LIMITS):
            pcfg = _get(ratelimit, provider)
            limits[provider] = provider_limits_from_config(provider, pcfg, enabled)
            breaker_settings[provider] = {
                "threshold": int(_get(pcfg, "breaker_threshold", 5) or 5),
                "cooldown": float(_get(pcfg, "breaker_cooldown_seconds", 60.0) or 0.0),
            }
            retry[provider] = RetrySettings(
                max_retries=int(_get(pcfg, "max_retries", 8)),
                max_backoff=float(_get(pcfg, "max_backoff_seconds", 60.0)),
                deadline=float(_get(pcfg, "deadline_seconds", 900.0)),
                retry_budget=int(_get(pcfg, "retry_budget", 500)),
            )
        with self._lock:
            self.enabled = enabled
            self.ratelimit = ratelimit
            if retry != self._retry:
                self._budgets.clear()
            self._retry = retry
        self.limiter.configure(limits)
        self.breakers.configure(breaker_settings)

    def retry_settings(self, provider: str) -> RetrySettings:
        with self._lock:
            return self._retry.get(provider) or RetrySettings()

    def budget(self, provider: str) -> RetryBudget:
        with self._lock:
            b = self._budgets.get(provider)
            if b is None:
                s = self._retry.get(provider) or RetrySettings()
                b = self._budgets[provider] = RetryBudget(s.retry_budget, s.budget_ratio)
            return b

    def provider_enabled(self, provider: str) -> bool:
        return self.enabled and self.limiter.enabled(provider)

    # -- stats fan-out -------------------------------------------------

    def _targets(self) -> list[ResilienceStats]:
        run = current_stats()
        return [self.stats, run] if run is not None and run is not self.stats else [self.stats]

    def _limiter_event(self, event: str, scope: Scope, value: float) -> None:
        scope = scope.service_scope
        for s in self._targets():
            if event == "wait":
                s.record_wait(scope, value)
            elif event == "rate":
                s.record_rate(scope, value)

    # Telemetry is aggregated per service scope (operations fold into it)

    def record_wait(self, scope: Scope, seconds: float) -> None:
        """Time a call in ``scope`` waited for a rate-limit token."""
        self._limiter_event("wait", scope, seconds)

    def record_call(self, scope: Scope) -> None:
        for s in self._targets():
            s.record_call(scope.service_scope)

    def record_retry(self, scope: Scope) -> None:
        for s in self._targets():
            s.record_retry(scope.service_scope)

    def record_transient(self, scope: Scope, error: str | None = None) -> None:
        for s in self._targets():
            s.record_transient(scope.service_scope, error)

    # -- the integration surface ---------------------------------------

    def check(self, scope: Scope) -> None:
        """Raise CircuitOpenError when ``scope``'s breaker is open."""
        if not self.provider_enabled(scope.provider):
            return
        target = self.breaker_scope(scope)
        breaker = self.breakers.get(target)
        try:
            breaker.check(target)
        except Exception as exc:
            reason = f"throttled: {exc}"
            for s in self._targets():
                s.record_rejected(scope.service_scope, reason)
            ledger = current_ledger()
            if ledger is not None:
                ledger.add_skipped(reason)
            raise

    def breaker_scope(self, scope: Scope) -> Scope:
        """The breaker's scope: same granularity as the scope's leaf rate
        bucket (per operation for EC2, per service otherwise), so one
        throttled API action does not block its siblings."""
        return self.limiter.leaf_scope(scope)

    def on_throttle(
        self, scope: Scope, retry_after: float | None = None, error: str | None = None
    ) -> float | None:
        """One throttled attempt: AIMD decrease, Retry-After pause, stats."""
        rate = (
            self.limiter.on_throttle(scope, retry_after)
            if self.provider_enabled(scope.provider)
            else None
        )
        for s in self._targets():
            s.record_throttle(scope.service_scope, rate, error)
        ledger = current_ledger()
        if ledger is not None:
            ledger.add_throttle()
        return rate

    def on_success(self, scope: Scope) -> None:
        if not self.provider_enabled(scope.provider):
            return
        self.limiter.on_success(scope)
        self.breakers.get(self.breaker_scope(scope)).record_success()
        self.budget(scope.provider).refund()

    def on_failure(self, scope: Scope) -> None:
        """A call failed (throttling / transient) after all its retries."""
        if not self.provider_enabled(scope.provider):
            return
        if self.breakers.get(self.breaker_scope(scope)).record_failure():
            for s in self._targets():
                s.record_breaker_trip(scope.service_scope)

    def try_retry(self, scope: Scope) -> bool:
        """Take one token from the provider's retry budget (False: retrying
        is no longer allowed). Always True when the provider is disabled."""
        if not self.provider_enabled(scope.provider):
            return True
        return self.budget(scope.provider).try_consume()

    def on_gave_up(self, scope: Scope, reason: str) -> None:
        """Throttling outlasted every retry: count it and open breakers if needed."""
        self.on_failure(scope)
        for s in self._targets():
            s.record_gave_up(scope.service_scope, reason)
        ledger = current_ledger()
        if ledger is not None:
            ledger.add_gave_up(reason)

    def summary(self, stats: ResilienceStats | None = None) -> dict[str, Any]:
        """Stats (the run's, or lifetime) plus tripped breakers and slowed buckets."""
        source = stats or self.stats
        out = source.summary()
        out["breakers"] = self.breakers.snapshot(only_tripped=True)
        out["slowed_buckets"] = {
            k: v
            for k, v in self.limiter.snapshot().items()
            if v["rate_rps"] < v["ceiling_rps"] or v["paused_for"] > 0
        }
        return out

    def reset(self) -> None:
        """Forget learned rates, breakers, budgets and lifetime stats."""
        self.limiter.reset()
        self.breakers.reset()
        with self._lock:
            self._budgets.clear()
        self.stats = ResilienceStats()


_GOVERNOR: Governor | None = None
_GOVERNOR_LOCK = threading.Lock()


def get_governor() -> Governor:
    """The process-wide governor (created with defaults on first use)."""
    global _GOVERNOR
    if _GOVERNOR is None:
        with _GOVERNOR_LOCK:
            if _GOVERNOR is None:
                _GOVERNOR = Governor()
    return _GOVERNOR


def configure(config: Any) -> Governor:
    """Apply ``config`` (CloudGConfig, RateLimitConfig or dict) to the process governor.

    Anything else (e.g. a test double standing in for a config) is ignored,
    leaving the governor as it is.
    """
    from cloudg.config import CloudGConfig, RateLimitConfig

    gov = get_governor()
    if config is None or isinstance(config, (CloudGConfig, RateLimitConfig, dict)):
        gov.configure(config)
    return gov


def reset_governor() -> Governor:
    """Replace the process governor with a fresh default one (tests)."""
    global _GOVERNOR
    with _GOVERNOR_LOCK:
        _GOVERNOR = Governor()
    return _GOVERNOR
