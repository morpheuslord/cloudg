"""Adaptive, hierarchical token-bucket rate limiting.

Every outgoing cloud API call is attributed to a :class:`Scope`
(provider / account / region / service [/ operation]) and must take a
token from up to three buckets before it is sent:

1. a provider-wide bucket (``global_max_rps``, off by default),
2. an account bucket (``account_max_rps``; on by default for Azure, whose
   Resource Manager limits are per subscription),
3. a leaf bucket per (account, region, service), or per operation when an
   ``"<service>.<Operation>"`` override exists or the service's spec is
   ``per_operation`` (EC2, which throttles each API action separately).

Buckets use *reservations*: taking a token never blocks under the lock, it
returns how long the caller must wait (the token balance may go negative,
which queues callers fairly). That makes one limiter usable from asyncio
(:meth:`RateLimiter.acquire`) and from worker threads
(:meth:`RateLimiter.acquire_sync`) at the same time.

Adaptive rate (AIMD): when a call in a scope is throttled the leaf bucket's
rate is multiplied by :data:`DECREASE_FACTOR` (at most once per
:data:`DECREASE_INTERVAL` seconds, so a burst of simultaneous throttles
counts as one congestion signal), its burst is drained and, when the
provider sent ``Retry-After``, the bucket is paused for that long. After
:data:`INCREASE_INTERVAL` seconds without throttling, each success adds
:data:`INCREASE_STEP` x ceiling back, until the configured rate is reached
again. This is the same congestion-control scheme TCP uses and the one
botocore's ``adaptive`` retry mode applies per client; here it is shared
by every client of the run.

Built-in defaults (:data:`DEFAULT_LIMITS`) sit at or just below the
providers' documented limits, so they only bind when the provider would
throttle anyway; all are overridable from ``ratelimit`` in the config.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import math
import threading
import time
from dataclasses import dataclass, field, replace
from typing import Any, AsyncIterator, Callable, Iterator, Mapping

__all__ = [
    "BUILTIN_LIMITS",
    "Bulkhead",
    "DEFAULT_LIMITS",
    "DECREASE_FACTOR",
    "INCREASE_STEP",
    "LimitSpec",
    "ProviderLimits",
    "RateLimiter",
    "Scope",
    "Slot",
    "TokenBucket",
]

logger = logging.getLogger(__name__)

#: Multiplicative decrease applied to a scope's rate on throttling
DECREASE_FACTOR = 0.5
#: Minimum seconds between two decreases of the same bucket
DECREASE_INTERVAL = 1.0
#: Additive increase, as a fraction of the configured ceiling
INCREASE_STEP = 0.05
#: Seconds of throttle-free traffic between two increases
INCREASE_INTERVAL = 5.0
#: Upper bound on a single Retry-After pause (protects against bogus headers)
MAX_PAUSE_SECONDS = 300.0


@dataclass(frozen=True)
class Scope:
    """Where a call goes: ``provider/account/region/service[/operation]``."""

    provider: str
    account: str | None = None
    region: str | None = None
    service: str | None = None
    operation: str | None = None

    def __str__(self) -> str:
        parts = [
            self.provider,
            self.account or "*",
            self.region or "*",
            self.service or "*",
        ]
        if self.operation:
            parts.append(self.operation)
        return "/".join(parts)

    @property
    def service_scope(self) -> "Scope":
        """This scope without the operation."""
        return replace(self, operation=None) if self.operation else self

    @property
    def account_scope(self) -> "Scope":
        return Scope(self.provider, self.account)


@dataclass(frozen=True)
class LimitSpec:
    """A token bucket: sustained ``rate`` per second, ``burst`` tokens.

    ``per_operation`` gives every API operation of the service its own
    bucket with this spec (EC2 throttles each API action separately).
    """

    rate: float
    burst: float | None = None
    per_operation: bool = False

    @property
    def capacity(self) -> float:
        return max(1.0, self.burst if self.burst is not None else self.rate * 2)


@dataclass
class ProviderLimits:
    """Rate limits of one provider (built from ``ratelimit.<provider>``)."""

    enabled: bool = True
    max_rps: float = 20.0
    burst: float | None = None
    account_max_rps: float | None = None
    account_burst: float | None = None
    global_max_rps: float | None = None
    global_burst: float | None = None
    min_rps: float = 0.2
    adaptive: bool = True
    max_concurrency: int = 64
    services: dict[str, LimitSpec] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Built-in defaults (per provider; leaf limits keyed by SDK service name)
# ---------------------------------------------------------------------------
#
# AWS - keys are botocore service names (session.client("<name>")); the leaf
# bucket is per account x region x service.
#   ec2        20 rps / 100 burst per API action: EC2 "non-mutating actions"
#              request token bucket (refill 20/s, capacity 100), evaluated per
#              action, per account per region.
#              https://docs.aws.amazon.com/ec2/latest/devguide/ec2-api-throttling.html
#   sts        50 rps: STS default request quota is 600 RPS per account per
#              region; cloudg stays far below it.
#              https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_iam-quotas.html
#   lambda     15 rps: "Rate of control plane API requests" quota (15/s,
#              excluding GetFunction/GetPolicy).
#              https://docs.aws.amazon.com/lambda/latest/dg/gettingstarted-limits.html
#   route53    5 rps: Route 53 API allows five requests per second per account.
#              https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/DNSLimitations.html
#   resourcegroupstaggingapi 5 rps: GetResources has a low per-account TPS
#              quota (Service Quotas; ~10 TPS commonly observed); half of it.
#              https://docs.aws.amazon.com/resourcegroupstagging/latest/APIReference/API_GetResources.html
#   organizations 5 rps, controltower 2 rps, cloudformation 5 rps, cloudcontrol
#              5 rps, iam 10 rps: control-plane APIs without published TPS
#              that throttle early (TooManyRequestsException / Throttling);
#              conservative, and AIMD adapts further on throttling.
#   default    20 rps / 40 burst per service.
#
# Azure - leaf key is the resource-provider namespace without "Microsoft."
# (network, compute, storage, ...), per subscription.
#   subscription aggregate 20 rps / 200 burst: ARM token bucket for
#              subscription reads is 250 tokens refilled at 25/s per region
#              per principal (2024 regional throttling); 20% headroom.
#              https://learn.microsoft.com/azure/azure-resource-manager/management/request-limits-and-throttling
#   network    30 rps: Microsoft.Network reads 10,000 per 5 minutes.
#   storage    0.33 rps / 20 burst: Storage RP list operations 100 per 5 minutes.
#   resourcegraph 3 rps / 15 burst: Resource Graph allows 15 queries per
#              5-second window per user (x-ms-user-quota-* headers).
#              https://learn.microsoft.com/azure/governance/resource-graph/concepts/guidance-for-throttled-requests
#
# GCP - leaf key is the API (cloudasset, cloudresourcemanager, ...).
#   cloudasset.ListAssets 1.5 rps / 10 burst: 100 requests per minute per
#              consumer project (800/min per organization).
#   cloudasset.SearchAllResources / SearchAllIamPolicies 6 rps / 20 burst:
#              400 requests per minute per consumer project.
#              https://cloud.google.com/asset-inventory/docs/quota
#   default    10 rps / 20 burst.
BUILTIN_LIMITS: dict[str, ProviderLimits] = {
    "aws": ProviderLimits(
        max_rps=20.0,
        burst=40.0,
        min_rps=0.2,
        max_concurrency=128,
        services={
            "ec2": LimitSpec(20.0, 100.0, per_operation=True),
            "iam": LimitSpec(10.0, 40.0),
            "sts": LimitSpec(50.0, 100.0),
            "organizations": LimitSpec(5.0, 10.0),
            "controltower": LimitSpec(2.0, 5.0),
            "route53": LimitSpec(5.0, 5.0),
            "resourcegroupstaggingapi": LimitSpec(5.0, 10.0),
            "cloudcontrol": LimitSpec(5.0, 10.0),
            "cloudformation": LimitSpec(5.0, 10.0),
            "lambda": LimitSpec(15.0, 15.0),
        },
    ),
    "azure": ProviderLimits(
        max_rps=15.0,
        burst=100.0,
        account_max_rps=20.0,
        account_burst=200.0,
        min_rps=0.1,
        max_concurrency=16,
        services={
            "network": LimitSpec(30.0, 200.0),
            "storage": LimitSpec(0.33, 20.0),
            "resourcegraph": LimitSpec(3.0, 15.0),
        },
    ),
    "gcp": ProviderLimits(
        max_rps=10.0,
        burst=20.0,
        min_rps=0.05,
        max_concurrency=16,
        services={
            "cloudasset.ListAssets": LimitSpec(1.5, 10.0),
            "cloudasset.SearchAllResources": LimitSpec(6.0, 20.0),
            "cloudasset.SearchAllIamPolicies": LimitSpec(6.0, 20.0),
        },
    ),
}


#: The defaults in effect (tests may swap this for a faster profile)
DEFAULT_LIMITS: dict[str, ProviderLimits] = BUILTIN_LIMITS


def default_limits(provider: str) -> ProviderLimits:
    base = DEFAULT_LIMITS.get(provider)
    if base is None:
        return ProviderLimits()
    return replace(base, services=dict(base.services))


# ---------------------------------------------------------------------------
# Token bucket
# ---------------------------------------------------------------------------


class TokenBucket:
    """A token bucket with reservation semantics and AIMD rate control.

    Not thread-safe on its own; :class:`RateLimiter` serialises access.
    """

    def __init__(
        self,
        spec: LimitSpec,
        *,
        now: float,
        min_rate: float = 0.1,
        adaptive: bool = True,
    ) -> None:
        self.spec = spec
        self.ceiling = float(spec.rate)
        self.rate = float(spec.rate)
        self.min_rate = min(float(min_rate), self.ceiling)
        self.adaptive = adaptive
        self._burst_ratio = spec.capacity / self.ceiling if self.ceiling > 0 else 1.0
        self.capacity = spec.capacity
        self.tokens = self.capacity
        self.last = now
        self.paused_until = -math.inf
        self.throttles = 0
        self._last_decrease = -math.inf
        self._last_increase = now

    def _refill(self, now: float) -> None:
        start = max(self.last, self.paused_until)
        if now > start:
            self.tokens = min(self.capacity, self.tokens + (now - start) * self.rate)
        self.last = max(self.last, now)

    def reserve(self, now: float, tokens: float = 1.0) -> float:
        """Take ``tokens``; returns the seconds to wait before using them."""
        self._refill(now)
        self.tokens -= tokens
        wait = 0.0
        if self.tokens < 0:
            wait = -self.tokens / self.rate
        if self.paused_until > now:
            wait += self.paused_until - now
        return wait

    def peek_wait(self, now: float) -> float:
        """Seconds until one token is available, without taking it."""
        self._refill(now)
        wait = max(0.0, (1.0 - self.tokens) / self.rate) if self.tokens < 1.0 else 0.0
        if self.paused_until > now:
            wait += self.paused_until - now
        return wait

    def _set_rate(self, rate: float) -> None:
        self.rate = max(self.min_rate, min(self.ceiling, rate))
        self.capacity = max(1.0, self.rate * self._burst_ratio)
        self.tokens = min(self.tokens, self.capacity)

    def on_throttle(self, now: float, retry_after: float | None = None) -> float:
        """Multiplicative decrease (+ Retry-After pause); returns the new rate."""
        self._refill(now)
        self.throttles += 1
        if self.adaptive and now - self._last_decrease >= DECREASE_INTERVAL:
            self._set_rate(self.rate * DECREASE_FACTOR)
            self._last_decrease = now
            self._last_increase = now
            self.tokens = min(self.tokens, 0.0)  # stop the burst
        if retry_after is not None and retry_after > 0:
            self.pause(now, retry_after)
        return self.rate

    def pause(self, now: float, seconds: float) -> None:
        """Hold every caller of this bucket for ``seconds``."""
        self._refill(now)
        until = now + min(float(seconds), MAX_PAUSE_SECONDS)
        if until > self.paused_until:
            self.paused_until = until
        self.tokens = min(self.tokens, 0.0)

    def on_success(self, now: float) -> float:
        """Additive increase toward the ceiling after a throttle-free interval."""
        if (
            self.adaptive
            and self.rate < self.ceiling
            and now - self._last_increase >= INCREASE_INTERVAL
            and now - self._last_decrease >= INCREASE_INTERVAL
        ):
            self._set_rate(self.rate + max(self.ceiling * INCREASE_STEP, 0.01))
            self._last_increase = now
        return self.rate

    def snapshot(self, now: float) -> dict[str, Any]:
        self._refill(now)
        return {
            "rate_rps": round(self.rate, 4),
            "ceiling_rps": round(self.ceiling, 4),
            "tokens": round(self.tokens, 3),
            "capacity": round(self.capacity, 3),
            "paused_for": round(max(0.0, self.paused_until - now), 3),
            "throttles": self.throttles,
        }


# ---------------------------------------------------------------------------
# Bulkhead
# ---------------------------------------------------------------------------


class Bulkhead:
    """Caps concurrent in-flight calls of one provider x account.

    One slot pool shared by asyncio tasks and threads: async callers await
    a free slot without blocking the loop, threads block. ``release`` is
    thread-safe and may be called from any thread (the AWS and Azure hooks
    release from response callbacks or garbage-collection finalizers).
    """

    def __init__(self, limit: int) -> None:
        self.limit = max(1, int(limit))
        self._in_use = 0
        self._lock = threading.Lock()
        self._cond = threading.Condition(self._lock)
        self._waiters: list[tuple[Any, asyncio.Future[None]]] = []

    @property
    def in_use(self) -> int:
        with self._lock:
            return self._in_use

    def try_acquire(self) -> bool:
        with self._lock:
            if self._in_use < self.limit:
                self._in_use += 1
                return True
            return False

    async def acquire(self) -> None:
        loop = asyncio.get_running_loop()
        while True:
            with self._lock:
                if self._in_use < self.limit:
                    self._in_use += 1
                    return
                fut: asyncio.Future[None] = loop.create_future()
                self._waiters.append((loop, fut))
            try:
                await fut
            finally:
                with self._lock:
                    if (loop, fut) in self._waiters:
                        self._waiters.remove((loop, fut))

    def acquire_sync(self) -> None:
        with self._cond:
            while self._in_use >= self.limit:
                self._cond.wait()
            self._in_use += 1

    def release(self) -> None:
        with self._lock:
            self._in_use = max(0, self._in_use - 1)
            waiters, self._waiters = self._waiters, []
            self._cond.notify()
        # Wake every async waiter; each re-checks for a free slot
        for loop, fut in waiters:
            try:
                loop.call_soon_threadsafe(_resolve, fut)
            except RuntimeError:  # loop closed: nobody is left to wake there
                logger.debug("Bulkhead waiter on a closed event loop dropped")

    @contextlib.asynccontextmanager
    async def hold(self) -> AsyncIterator[None]:
        await self.acquire()
        try:
            yield
        finally:
            self.release()

    @contextlib.contextmanager
    def hold_sync(self) -> Iterator[None]:
        self.acquire_sync()
        try:
            yield
        finally:
            self.release()


def _resolve(fut: "asyncio.Future[None]") -> None:
    if not fut.done():
        fut.set_result(None)


class Slot:
    """One acquired bulkhead slot, released exactly once.

    The SDK hooks keep it in the request context and release it on the
    response and error paths. When neither runs (a cancelled task, an
    exception raised between the SDK's events) the slot is released when
    the request context, and with it the Slot, is garbage collected.
    """

    __slots__ = ("_bulkhead", "_done", "_lock")

    def __init__(self, bulkhead: Bulkhead) -> None:
        self._bulkhead = bulkhead
        self._done = False
        self._lock = threading.Lock()

    @property
    def released(self) -> bool:
        return self._done

    def release(self) -> None:
        with self._lock:
            if self._done:
                return
            self._done = True
        self._bulkhead.release()

    def __del__(self) -> None:
        try:
            self.release()
        except Exception as exc:  # pragma: no cover - interpreter shutdown
            # A finalizer must not raise; the bulkhead dies with the process anyway
            logger.debug("Bulkhead slot not released during finalization: %r", exc)


# ---------------------------------------------------------------------------
# Limiter
# ---------------------------------------------------------------------------

StatsSink = Callable[[str, Scope, float], None]


class RateLimiter:
    """Thread-safe registry of adaptive token buckets keyed by :class:`Scope`.

    Args:
        limits: Per-provider limits (missing providers use :data:`DEFAULT_LIMITS`).
        clock: Monotonic clock (injectable for tests).
        on_event: Optional ``(event, scope, value)`` callback; events are
            ``"wait"`` (seconds) and ``"rate"`` (new rate after a change).
    """

    def __init__(
        self,
        limits: Mapping[str, ProviderLimits] | None = None,
        *,
        clock: Callable[[], float] = time.monotonic,
        on_event: StatsSink | None = None,
    ) -> None:
        self._clock = clock
        self._lock = threading.Lock()
        self._limits: dict[str, ProviderLimits] = {}
        self._buckets: dict[tuple[Any, ...], TokenBucket] = {}
        self._bulkheads: dict[tuple[Any, ...], Bulkhead] = {}
        self._on_event = on_event
        self.configure(limits or {})

    # -- configuration -------------------------------------------------

    def configure(self, limits: Mapping[str, ProviderLimits]) -> None:
        """Replace the limits; buckets whose spec changed are rebuilt."""
        with self._lock:
            merged = {p: default_limits(p) for p in DEFAULT_LIMITS}
            merged.update(dict(limits))
            changed = {p for p in merged if merged[p] != self._limits.get(p)}
            self._limits = merged
            if changed:
                self._buckets = {k: b for k, b in self._buckets.items() if k[0] not in changed}
                self._bulkheads = {k: b for k, b in self._bulkheads.items() if k[0] not in changed}

    def limits(self, provider: str) -> ProviderLimits:
        with self._lock:
            return self._limits.get(provider) or default_limits(provider)

    def enabled(self, provider: str) -> bool:
        return self.limits(provider).enabled

    # -- bucket resolution --------------------------------------------

    def _leaf(self, scope: Scope, pl: ProviderLimits) -> tuple[tuple[Any, ...], LimitSpec]:
        base = (scope.provider, scope.account, scope.region, scope.service)
        if scope.service and scope.operation:
            spec = pl.services.get(f"{scope.service}.{scope.operation}")
            if spec is not None:
                return base + (scope.operation,), spec
        spec = pl.services.get(scope.service or "") if scope.service else None
        if spec is None:
            return base, LimitSpec(pl.max_rps, pl.burst)
        if spec.per_operation and scope.operation:
            return base + (scope.operation,), spec
        return base, spec

    def _bucket(
        self, key: tuple[Any, ...], spec: LimitSpec, pl: ProviderLimits, now: float
    ) -> TokenBucket | None:
        if spec.rate is None or spec.rate <= 0:
            return None
        bucket = self._buckets.get(key)
        if bucket is None:
            bucket = self._buckets[key] = TokenBucket(
                spec, now=now, min_rate=pl.min_rps, adaptive=pl.adaptive
            )
        return bucket

    def _chain(self, scope: Scope, now: float) -> list[tuple[tuple[Any, ...], TokenBucket]]:
        """Buckets a call in ``scope`` must pass, most general first."""
        pl = self._limits.get(scope.provider) or default_limits(scope.provider)
        if not pl.enabled:
            return []
        chain: list[tuple[tuple[Any, ...], TokenBucket]] = []
        if pl.global_max_rps:
            key: tuple[Any, ...] = (scope.provider, "__global__")
            b = self._bucket(key, LimitSpec(pl.global_max_rps, pl.global_burst), pl, now)
            if b:
                chain.append((key, b))
        if pl.account_max_rps and scope.account:
            key = (scope.provider, "__account__", scope.account)
            b = self._bucket(key, LimitSpec(pl.account_max_rps, pl.account_burst), pl, now)
            if b:
                chain.append((key, b))
        if scope.service:
            key, spec = self._leaf(scope, pl)
            b = self._bucket(key, spec, pl, now)
            if b:
                chain.append((key, b))
        return chain

    def _adaptive_bucket(self, scope: Scope, now: float) -> TokenBucket | None:
        chain = self._chain(scope, now)
        return chain[-1][1] if chain else None

    def leaf_scope(self, scope: Scope) -> Scope:
        """``scope`` at the granularity of its leaf bucket: with the operation
        when the bucket is per operation, else the service scope."""
        with self._lock:
            pl = self._limits.get(scope.provider) or default_limits(scope.provider)
            key, _ = self._leaf(scope, pl)
        return scope if len(key) > 4 else scope.service_scope

    # -- acquiring -----------------------------------------------------

    def reserve(self, scope: Scope) -> float:
        """Take a token in every bucket of ``scope``; returns the wait in seconds."""
        with self._lock:
            now = self._clock()
            wait = 0.0
            for _, bucket in self._chain(scope, now):
                wait = max(wait, bucket.reserve(now))
        return wait

    def peek(self, scope: Scope) -> float:
        """Seconds until a call in ``scope`` could go out (no token taken)."""
        with self._lock:
            now = self._clock()
            return max((b.peek_wait(now) for _, b in self._chain(scope, now)), default=0.0)

    def _emit(self, event: str, scope: Scope, value: float) -> None:
        if self._on_event is not None:
            try:
                self._on_event(event, scope, value)
            except Exception as exc:  # telemetry never breaks a call
                logger.debug("Rate limiter telemetry hook failed for %s: %r", scope, exc)

    async def acquire(self, scope: Scope, *, sleep: Callable[[float], Any] | None = None) -> float:
        """Wait (asynchronously) for a token; returns the time waited."""
        wait = self.reserve(scope)
        if wait > 0:
            self._emit("wait", scope, wait)
            await (sleep or asyncio.sleep)(wait)
        return wait

    def acquire_sync(
        self,
        scope: Scope,
        *,
        sleep: Callable[[float], Any] = time.sleep,
        max_wait: float | None = None,
    ) -> float:
        """Block the current thread until a token is available.

        ``max_wait`` caps the sleep (the token is still consumed): used
        when the caller runs on an event loop thread and must not stall it.
        """
        wait = self.reserve(scope)
        if wait > 0:
            self._emit("wait", scope, wait)
            sleep(wait if max_wait is None else min(wait, max_wait))
        return wait

    # -- feedback ------------------------------------------------------

    def on_throttle(self, scope: Scope, retry_after: float | None = None) -> float | None:
        """Throttling seen in ``scope``: decrease its rate, honour Retry-After."""
        with self._lock:
            now = self._clock()
            bucket = self._adaptive_bucket(scope, now)
            if bucket is None:
                return None
            rate = bucket.on_throttle(now, retry_after)
        self._emit("rate", scope, rate)
        return rate

    def on_success(self, scope: Scope) -> None:
        with self._lock:
            now = self._clock()
            bucket = self._adaptive_bucket(scope, now)
            if bucket is None:
                return
            before = bucket.rate
            after = bucket.on_success(now)
        if after != before:
            self._emit("rate", scope, after)

    def pause(self, scope: Scope, seconds: float, *, level: str = "leaf") -> None:
        """Hold calls for ``seconds`` (quota-reset hints).

        ``level="leaf"`` pauses the scope's own (service / operation)
        bucket; ``level="account"`` pauses the account bucket, i.e. every
        call of that account / subscription, falling back to the leaf when
        the provider has no account limit.
        """
        with self._lock:
            now = self._clock()
            chain = self._chain(scope, now)
            if not chain:
                return
            bucket = chain[-1][1]
            if level == "account":
                for key, b in chain:
                    if len(key) > 1 and key[1] == "__account__":
                        bucket = b
                        break
            bucket.pause(now, seconds)

    def rate(self, scope: Scope) -> float | None:
        with self._lock:
            bucket = self._adaptive_bucket(scope, self._clock())
            return bucket.rate if bucket else None

    # -- concurrency ---------------------------------------------------

    def bulkhead(self, scope: Scope) -> Bulkhead:
        """Concurrency cap of ``scope``'s provider x account."""
        with self._lock:
            pl = self._limits.get(scope.provider) or default_limits(scope.provider)
            key = (scope.provider, scope.account)
            bh = self._bulkheads.get(key)
            if bh is None:
                bh = self._bulkheads[key] = Bulkhead(pl.max_concurrency)
            return bh

    # -- introspection -------------------------------------------------

    def snapshot(self) -> dict[str, dict[str, Any]]:
        with self._lock:
            now = self._clock()
            return {
                "/".join("*" if p is None else str(p) for p in key): b.snapshot(now)
                for key, b in sorted(self._buckets.items(), key=lambda kv: str(kv[0]))
            }

    def reset(self) -> None:
        """Forget every bucket (learned rates included)."""
        with self._lock:
            self._buckets.clear()
            self._bulkheads.clear()
