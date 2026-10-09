"""Cloud API resilience: throttling-aware rate limiting, retries and guards.

cloudg fans out hundreds of read-only API calls per map (every AWS deep
collector x region x account, ARM / Resource Graph per subscription, Cloud
Asset Inventory per project or org). This package keeps that polite and
stable under provider throttling:

- :mod:`.errors` - provider-aware ``classify(exc)`` (THROTTLED / TRANSIENT
  / FATAL) and ``retry_after(exc)``.
- :mod:`.limiter` - adaptive (AIMD), hierarchical token buckets per
  provider / account / region / service, and concurrency bulkheads.
- :mod:`.breaker` - circuit breakers per scope.
- :mod:`.retry` - ``call_with_resilience`` (async) / ``call_with_resilience_sync``.
- :mod:`.stats` - per-run throttle telemetry (``stats_scope``).
- :mod:`.guard` - ``LiveOperationGuard`` for on-demand (MCP) collections.
- :mod:`.governor` - the process-wide state tying it together.
- :mod:`.aws` / :mod:`.azure` / :mod:`.gcp` - SDK integrations.

Configuration lives in ``CloudGConfig.ratelimit`` (see
:class:`cloudg.config.RateLimitConfig`).
"""

from cloudg.resilience.breaker import BreakerRegistry, BreakerState, CircuitBreaker
from cloudg.resilience.errors import (
    CircuitOpenError,
    DeadlineExceededError,
    ErrorKind,
    ResilienceError,
    RetryBudgetExhaustedError,
    classify,
    classify_strict,
    describe_error,
    is_provider_answer,
    is_throttle,
    parse_retry_after,
    retry_after,
)
from cloudg.resilience.governor import (
    Governor,
    RetryBudget,
    RetrySettings,
    configure,
    get_governor,
    reset_governor,
)
from cloudg.resilience.guard import (
    CallerQuotaExceeded,
    CooldownActive,
    GuardSettings,
    LiveOperationBusy,
    LiveOperationGuard,
    LiveOperationRejected,
    LiveOperationTimeout,
    operation_key,
)
from cloudg.resilience.limiter import (
    DEFAULT_LIMITS,
    Bulkhead,
    LimitSpec,
    ProviderLimits,
    RateLimiter,
    Scope,
    TokenBucket,
)
from cloudg.resilience.retry import (
    RetryPolicy,
    call_with_resilience,
    call_with_resilience_sync,
    decorrelated_jitter,
    resilient,
)
from cloudg.resilience.stats import (
    ResilienceStats,
    ThrottleLedger,
    current_stats,
    stats_scope,
    throttle_ledger,
)

__all__ = [
    "BreakerRegistry",
    "BreakerState",
    "Bulkhead",
    "CallerQuotaExceeded",
    "CircuitBreaker",
    "CircuitOpenError",
    "CooldownActive",
    "DEFAULT_LIMITS",
    "DeadlineExceededError",
    "ErrorKind",
    "Governor",
    "GuardSettings",
    "LimitSpec",
    "LiveOperationBusy",
    "LiveOperationGuard",
    "LiveOperationRejected",
    "LiveOperationTimeout",
    "ProviderLimits",
    "RateLimiter",
    "ResilienceError",
    "ResilienceStats",
    "RetryBudget",
    "RetryBudgetExhaustedError",
    "RetryPolicy",
    "RetrySettings",
    "Scope",
    "ThrottleLedger",
    "TokenBucket",
    "call_with_resilience",
    "call_with_resilience_sync",
    "classify",
    "classify_strict",
    "configure",
    "current_stats",
    "decorrelated_jitter",
    "describe_error",
    "get_governor",
    "is_provider_answer",
    "is_throttle",
    "operation_key",
    "parse_retry_after",
    "reset_governor",
    "resilient",
    "retry_after",
    "stats_scope",
    "throttle_ledger",
]
