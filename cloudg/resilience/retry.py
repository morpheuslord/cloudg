"""Rate-limited, circuit-broken retries for individual cloud API calls.

:func:`call_with_resilience` (async) and :func:`call_with_resilience_sync`
(for blocking SDK calls run in worker threads: the Azure and GCP clients
are synchronous) wrap one call with, in order:

1. the scope's circuit breaker (fail fast with ``CircuitOpenError``),
2. the overall deadline (``DeadlineExceededError`` once it cannot be met),
3. a token from the adaptive rate limiter (waits, never spins),
4. the provider x account concurrency bulkhead,
5. the call itself; on failure the error is classified:

   - FATAL: re-raised at once, breaker untouched;
   - THROTTLED: the scope's rate is cut (AIMD) and paused for Retry-After;
   - TRANSIENT / THROTTLED: retried with decorrelated-jitter exponential
     backoff (``sleep = min(cap, uniform(base, 3 * previous))``, see the
     AWS Architecture Blog "Exponential Backoff And Jitter"), never sooner
     than the server's Retry-After, while attempts, the deadline and the
     provider's retry budget allow. Otherwise the original exception is
     re-raised and the breaker counts the failure.

Every step is recorded in the run's
:class:`~cloudg.resilience.stats.ResilienceStats`.
"""

from __future__ import annotations

import asyncio
import functools
import inspect
import logging
import random
import time
from dataclasses import dataclass
from typing import Any, Awaitable, Callable, NoReturn, TypeVar

from cloudg.resilience.errors import (
    DeadlineExceededError,
    ErrorKind,
    classify,
    retry_after,
)
from cloudg.resilience.governor import Governor, get_governor
from cloudg.resilience.limiter import Scope

__all__ = [
    "RetryPolicy",
    "backoff_delays",
    "call_with_resilience",
    "call_with_resilience_sync",
    "decorrelated_jitter",
    "resilient",
]

logger = logging.getLogger(__name__)

T = TypeVar("T")

# Jitter is not cryptographic; SystemRandom also satisfies Bandit B311
_rng = random.SystemRandom()


@dataclass(frozen=True)
class RetryPolicy:
    """Bounds of one resilient call (None fields fall back to the provider's settings)."""

    max_retries: int | None = None
    base_delay: float | None = None
    max_backoff: float | None = None
    deadline: float | None = None
    use_budget: bool = True
    retry_transient: bool = True


def decorrelated_jitter(
    previous: float, base: float, cap: float, rng: random.Random | None = None
) -> float:
    """Next delay of decorrelated-jitter backoff: ``min(cap, U(base, 3 * previous))``."""
    upper = max(base, previous * 3)
    return min(cap, (rng or _rng).uniform(base, upper))


def backoff_delays(
    retries: int, base: float = 0.5, cap: float = 60.0, rng: random.Random | None = None
) -> list[float]:
    """The first ``retries`` decorrelated-jitter delays (for inspection/tests)."""
    out, prev = [], base
    for _ in range(retries):
        prev = decorrelated_jitter(prev, base, cap, rng)
        out.append(prev)
    return out


class _Attempts:
    """Retry bookkeeping shared by the async and sync loops."""

    def __init__(
        self, gov: Governor, scope: Scope, policy: RetryPolicy, clock: Callable[[], float]
    ):
        settings = gov.retry_settings(scope.provider)
        self.gov = gov
        self.scope = scope
        self.policy = policy
        self.clock = clock
        self.max_retries = (
            settings.max_retries if policy.max_retries is None else policy.max_retries
        )
        self.base = settings.base_delay if policy.base_delay is None else policy.base_delay
        self.cap = settings.max_backoff if policy.max_backoff is None else policy.max_backoff
        deadline = settings.deadline if policy.deadline is None else policy.deadline
        self.deadline_at = clock() + deadline if deadline and deadline > 0 else None
        self.retries = 0
        self.previous = self.base

    def remaining(self) -> float | None:
        if self.deadline_at is None:
            return None
        return self.deadline_at - self.clock()

    def before_attempt(self) -> None:
        self.gov.check(self.scope)
        remaining = self.remaining()
        if remaining is not None and remaining <= 0:
            raise DeadlineExceededError(f"deadline exceeded for {self.scope}", scope=self.scope)

    def check_wait(self, wait: float) -> None:
        remaining = self.remaining()
        if remaining is not None and wait > remaining:
            raise DeadlineExceededError(
                f"rate limit wait of {wait:.1f}s for {self.scope} exceeds the deadline",
                retry_after=wait,
                scope=self.scope,
            )

    def on_error(self, exc: BaseException) -> float:
        """Classify ``exc``; return the delay before retrying, or re-raise it."""
        kind = classify(exc)
        if kind is ErrorKind.FATAL:
            raise exc
        hint = retry_after(exc)
        message = str(exc)[:300]
        if kind is ErrorKind.THROTTLED:
            self.gov.on_throttle(self.scope, hint, message)
        else:
            self.gov.record_transient(self.scope, message)
            if not self.policy.retry_transient:
                self.gov.on_failure(self.scope)
                raise exc
        if self.retries >= self.max_retries:
            self._give_up(kind, exc, "retries exhausted")
        if self.policy.use_budget and not self.gov.budget(self.scope.provider).try_consume():
            self._give_up(kind, exc, "retry budget exhausted")
        self.previous = decorrelated_jitter(self.previous, self.base, self.cap)
        delay = max(self.previous, hint or 0.0)
        remaining = self.remaining()
        if remaining is not None and delay > remaining:
            self._give_up(kind, exc, "deadline exceeded")
        self.retries += 1
        self.gov.record_retry(self.scope)
        logger.debug(
            "Retry %d/%d for %s in %.2fs (%s: %s)",
            self.retries, self.max_retries, self.scope, delay, kind.value, message,
        )  # fmt: skip
        return delay

    def _give_up(self, kind: ErrorKind, exc: BaseException, why: str) -> NoReturn:
        if kind is ErrorKind.THROTTLED:
            self.gov.on_gave_up(self.scope, f"throttled ({why}): {str(exc)[:200]}")
        else:
            self.gov.on_failure(self.scope)
        raise exc


async def call_with_resilience(
    fn: Callable[..., Awaitable[T]] | Callable[..., T],
    *args: Any,
    scope: Scope,
    policy: RetryPolicy | None = None,
    governor: Governor | None = None,
    sleep: Callable[[float], Awaitable[Any]] | None = None,
    clock: Callable[[], float] | None = None,
    **kwargs: Any,
) -> T:
    """Call ``fn(*args, **kwargs)`` (async, or sync run in a worker thread)
    under the scope's breaker, rate limit, bulkhead and retry policy."""
    gov = governor or get_governor()
    pol = policy or RetryPolicy()
    do_sleep = sleep or asyncio.sleep
    state = _Attempts(gov, scope, pol, clock or gov.clock)
    is_async = inspect.iscoroutinefunction(fn)
    if not gov.provider_enabled(scope.provider):
        result = fn(*args, **kwargs) if is_async else await asyncio.to_thread(fn, *args, **kwargs)
        return await result if inspect.isawaitable(result) else result  # type: ignore[return-value]
    while True:
        state.before_attempt()
        wait = gov.limiter.reserve(scope)
        if wait > 0:
            state.check_wait(wait)
            gov._limiter_event("wait", scope, wait)
            await do_sleep(wait)
        gov.record_call(scope)
        try:
            async with gov.limiter.bulkhead(scope).hold():
                if is_async:
                    result = await fn(*args, **kwargs)  # type: ignore[misc]
                else:
                    result = await asyncio.to_thread(fn, *args, **kwargs)
                    if inspect.isawaitable(result):
                        result = await result
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            delay = state.on_error(exc)
            await do_sleep(delay)
            continue
        gov.on_success(scope)
        return result  # type: ignore[return-value]


def call_with_resilience_sync(
    fn: Callable[..., T],
    *args: Any,
    scope: Scope,
    policy: RetryPolicy | None = None,
    governor: Governor | None = None,
    sleep: Callable[[float], Any] = time.sleep,
    clock: Callable[[], float] | None = None,
    **kwargs: Any,
) -> T:
    """Blocking variant of :func:`call_with_resilience` for worker threads."""
    gov = governor or get_governor()
    if not gov.provider_enabled(scope.provider):
        return fn(*args, **kwargs)
    state = _Attempts(gov, scope, policy or RetryPolicy(), clock or gov.clock)
    while True:
        state.before_attempt()
        wait = gov.limiter.reserve(scope)
        if wait > 0:
            state.check_wait(wait)
            gov._limiter_event("wait", scope, wait)
            sleep(wait)
        gov.record_call(scope)
        try:
            with gov.limiter.bulkhead(scope).hold_sync():
                result = fn(*args, **kwargs)
        except Exception as exc:
            sleep(state.on_error(exc))
            continue
        gov.on_success(scope)
        return result


def resilient(
    scope: Scope | Callable[..., Scope],
    policy: RetryPolicy | None = None,
) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    """Decorator form; ``scope`` may be a Scope or ``(*args, **kwargs) -> Scope``.

    Async functions get :func:`call_with_resilience`, sync functions
    :func:`call_with_resilience_sync`.
    """

    def resolve(args: tuple[Any, ...], kwargs: dict[str, Any]) -> Scope:
        return scope(*args, **kwargs) if callable(scope) and not isinstance(scope, Scope) else scope  # type: ignore[return-value]

    def decorator(fn: Callable[..., Any]) -> Callable[..., Any]:
        if inspect.iscoroutinefunction(fn):

            @functools.wraps(fn)
            async def async_wrapper(*args: Any, **kwargs: Any) -> Any:
                return await call_with_resilience(
                    fn, *args, scope=resolve(args, kwargs), policy=policy, **kwargs
                )

            return async_wrapper

        @functools.wraps(fn)
        def sync_wrapper(*args: Any, **kwargs: Any) -> Any:
            return call_with_resilience_sync(
                fn, *args, scope=resolve(args, kwargs), policy=policy, **kwargs
            )

        return sync_wrapper

    return decorator
