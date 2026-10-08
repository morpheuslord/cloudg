"""Guard rails for live (on-demand) cloud collections.

An agent (e.g. through the MCP layer) can trigger live collections far
more often than a human running ``cloudg map``. :class:`LiveOperationGuard`
keeps that polite:

- **Single-flight**: an identical live operation that is already running
  is joined, not repeated: every concurrent caller awaits the first
  caller's result (or exception).
- **Concurrency caps**: at most ``max_concurrent_per_scope`` live
  operations per scope (e.g. ``aws/123456789012``) and
  ``max_concurrent_total`` overall; extra callers get
  :class:`LiveOperationBusy` (or wait, with ``wait=True``).
- **Cooldown**: after a live operation touching a scope finishes, a new
  one for that scope is refused for ``cooldown_seconds`` with
  :class:`CooldownActive` (carrying ``retry_after``), so callers use the
  dataset they just got instead of hammering the provider again.
- **Per-caller quotas**: at most ``caller_max_operations`` new live
  operations per caller per ``caller_window_seconds``
  (:class:`CallerQuotaExceeded`).

Pure asyncio, no MCP or provider imports. All rejections subclass
:class:`LiveOperationRejected` and expose ``reason``, ``retry_after`` and
``to_dict()`` for a structured tool error.

Example::

    from cloudg.resilience import LiveOperationGuard, LiveOperationRejected, operation_key

    guard = LiveOperationGuard.from_config(config)   # CloudGConfig
    key = operation_key("map", providers, accounts, regions, services)
    try:
        result = await guard.run(
            key,
            lambda: InventoryMapper(config).map_inventory(),
            scopes=["aws/123456789012", "azure/<subscription-id>"],
            caller=client_id,
        )
    except LiveOperationRejected as exc:
        return {"error": exc.to_dict()}   # retry_after, reason, scopes
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import time
from collections import deque
from typing import Any, Awaitable, Callable, Hashable, Iterable, TypeVar

__all__ = [
    "CallerQuotaExceeded",
    "CooldownActive",
    "LiveOperationBusy",
    "LiveOperationGuard",
    "LiveOperationRejected",
    "operation_key",
]

T = TypeVar("T")


class LiveOperationRejected(Exception):
    """A live operation was refused; ``retry_after`` says when to try again."""

    reason = "rejected"

    def __init__(
        self,
        message: str,
        *,
        retry_after: float | None = None,
        scopes: Iterable[str] = (),
        caller: str | None = None,
    ) -> None:
        super().__init__(message)
        self.message = message
        self.retry_after = None if retry_after is None else max(0.0, float(retry_after))
        self.scopes = list(scopes)
        self.caller = caller

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {"reason": self.reason, "message": self.message}
        if self.retry_after is not None:
            out["retry_after_seconds"] = round(self.retry_after, 1)
        if self.scopes:
            out["scopes"] = self.scopes
        if self.caller:
            out["caller"] = self.caller
        return out


class CooldownActive(LiveOperationRejected):
    """The scope was collected live too recently; use the cached dataset."""

    reason = "cooldown"


class LiveOperationBusy(LiveOperationRejected):
    """Too many live operations are already running for the scope (or overall)."""

    reason = "busy"


class CallerQuotaExceeded(LiveOperationRejected):
    """The caller used up its live-operation quota for the current window."""

    reason = "quota"


def operation_key(*parts: Any) -> str:
    """A stable key for single-flight dedupe from arbitrary JSON-able parts."""
    blob = json.dumps(parts, sort_keys=True, default=str, separators=(",", ":"))
    return hashlib.sha256(blob.encode()).hexdigest()[:32]


def _provider_of(scope: str) -> str:
    for sep in ("/", ":"):
        if sep in scope:
            return scope.split(sep, 1)[0]
    return scope


class LiveOperationGuard:
    """Single-flight, concurrency caps, cooldowns and caller quotas for live operations.

    Args:
        cooldown_seconds: Minimum time between two live operations on a scope.
        max_concurrent_per_scope: Live operations allowed at once per scope.
        max_concurrent_total: Live operations allowed at once overall.
        caller_max_operations: New live operations per caller per window
            (0 = unlimited).
        caller_window_seconds: Length of the caller quota window.
        cooldown_after_failure: Also cool down after a failed operation
            (default True: a failure is often throttling).
        provider_cooldowns: Per-provider cooldown overrides (``{"aws": 300}``).
        clock: Monotonic clock (injectable for tests).
    """

    def __init__(
        self,
        *,
        cooldown_seconds: float = 120.0,
        max_concurrent_per_scope: int = 1,
        max_concurrent_total: int = 2,
        caller_max_operations: int = 0,
        caller_window_seconds: float = 3600.0,
        cooldown_after_failure: bool = True,
        provider_cooldowns: dict[str, float] | None = None,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.cooldown_seconds = max(0.0, float(cooldown_seconds))
        self.max_concurrent_per_scope = max(1, int(max_concurrent_per_scope))
        self.max_concurrent_total = max(1, int(max_concurrent_total))
        self.caller_max_operations = max(0, int(caller_max_operations))
        self.caller_window_seconds = max(1.0, float(caller_window_seconds))
        self.cooldown_after_failure = cooldown_after_failure
        self.provider_cooldowns = {k: float(v) for k, v in (provider_cooldowns or {}).items()}
        self._clock = clock
        self._inflight: dict[Hashable, asyncio.Task[Any]] = {}
        self._inflight_scopes: dict[Hashable, list[str]] = {}
        self._active: dict[str, int] = {}
        self._active_total = 0
        self._last_done: dict[str, float] = {}
        self._callers: dict[str, deque[float]] = {}
        self._cond: asyncio.Condition | None = None
        self._cond_loop: Any = None
        self.joined = 0
        self.started = 0

    @classmethod
    def from_config(cls, config: Any, **overrides: Any) -> "LiveOperationGuard":
        """Build from a CloudGConfig (``ratelimit`` section) or a RateLimitConfig."""
        rl = getattr(config, "ratelimit", config)
        kwargs: dict[str, Any] = {}
        if rl is not None:
            for name, attr in (
                ("cooldown_seconds", "live_cooldown_seconds"),
                ("max_concurrent_per_scope", "live_max_concurrent"),
                ("max_concurrent_total", "live_max_concurrent_total"),
                ("caller_max_operations", "live_caller_max_operations"),
                ("caller_window_seconds", "live_caller_window_seconds"),
            ):
                value = getattr(rl, attr, None)
                if value is not None:
                    kwargs[name] = value
            per_provider = {}
            for provider in ("aws", "azure", "gcp"):
                value = getattr(getattr(rl, provider, None), "live_cooldown_seconds", None)
                if value is not None:
                    per_provider[provider] = float(value)
            if per_provider:
                kwargs["provider_cooldowns"] = per_provider
        kwargs.update(overrides)
        return cls(**kwargs)

    # -- inspection ----------------------------------------------------

    def cooldown_for(self, scope: str) -> float:
        return self.provider_cooldowns.get(_provider_of(scope), self.cooldown_seconds)

    def cooldown_remaining(self, scope: Any) -> float:
        """Seconds until ``scope`` may be collected live again (0 when it may)."""
        key = str(scope)
        done = self._last_done.get(key)
        if done is None:
            return 0.0
        return max(0.0, done + self.cooldown_for(key) - self._clock())

    def in_flight(self, key: Hashable) -> bool:
        return key in self._inflight

    def status(self) -> dict[str, Any]:
        now = self._clock()
        return {
            "in_flight": len(self._inflight),
            "active_total": self._active_total,
            "active_by_scope": {k: v for k, v in self._active.items() if v},
            "cooling_down": {
                k: round(v + self.cooldown_for(k) - now, 1)
                for k, v in self._last_done.items()
                if v + self.cooldown_for(k) > now
            },
            "started": self.started,
            "joined": self.joined,
        }

    def reset(self, scope: Any = None) -> None:
        """Clear the cooldown of ``scope`` (or all cooldowns and quotas)."""
        if scope is None:
            self._last_done.clear()
            self._callers.clear()
        else:
            self._last_done.pop(str(scope), None)

    def mark_completed(self, scopes: Iterable[Any]) -> None:
        """Start the cooldown of ``scopes`` now (e.g. after an out-of-band collection)."""
        now = self._clock()
        for s in scopes:
            self._last_done[str(s)] = now

    # -- admission -----------------------------------------------------

    def _caller_retry_after(self, caller: str | None, now: float) -> float | None:
        if not caller or not self.caller_max_operations:
            return None
        window = self._callers.setdefault(caller, deque())
        while window and now - window[0] >= self.caller_window_seconds:
            window.popleft()
        if len(window) >= self.caller_max_operations:
            return window[0] + self.caller_window_seconds - now
        return None

    def check(
        self,
        scopes: Iterable[Any] = (),
        *,
        caller: str | None = None,
        bypass_cooldown: bool = False,
    ) -> None:
        """Raise the rejection a new operation on ``scopes`` would get now (no side effects)."""
        self._admit([str(s) for s in scopes], caller, bypass_cooldown, check_busy=True)

    def _admit(
        self, scopes: list[str], caller: str | None, bypass_cooldown: bool, check_busy: bool
    ) -> None:
        now = self._clock()
        quota_wait = self._caller_retry_after(caller, now)
        if quota_wait is not None:
            raise CallerQuotaExceeded(
                f"caller {caller!r} reached its quota of {self.caller_max_operations} live "
                f"operations per {self.caller_window_seconds:.0f}s; retry in {quota_wait:.0f}s "
                "or use the cached dataset",
                retry_after=quota_wait,
                scopes=scopes,
                caller=caller,
            )
        if not bypass_cooldown:
            cooling = {s: self.cooldown_remaining(s) for s in scopes}
            cooling = {s: w for s, w in cooling.items() if w > 0}
            if cooling:
                wait = max(cooling.values())
                raise CooldownActive(
                    "live collection of "
                    + ", ".join(sorted(cooling))
                    + f" ran recently; cooling down, retry in {wait:.0f}s or use the cached dataset",
                    retry_after=wait,
                    scopes=sorted(cooling),
                    caller=caller,
                )
        if check_busy:
            busy = [s for s in scopes if self._active.get(s, 0) >= self.max_concurrent_per_scope]
            if busy or self._active_total >= self.max_concurrent_total:
                what = ", ".join(busy) if busy else "all scopes"
                raise LiveOperationBusy(
                    f"a live operation is already running for {what}; retry when it finishes "
                    "or use the cached dataset",
                    scopes=busy,
                    caller=caller,
                )

    def _condition(self) -> asyncio.Condition:
        loop = asyncio.get_running_loop()
        if self._cond is None or self._cond_loop is not loop:
            self._cond, self._cond_loop = asyncio.Condition(), loop
        return self._cond

    def _has_capacity(self, scopes: list[str]) -> bool:
        return self._active_total < self.max_concurrent_total and all(
            self._active.get(s, 0) < self.max_concurrent_per_scope for s in scopes
        )

    # -- running -------------------------------------------------------

    async def run(
        self,
        key: Hashable,
        factory: Callable[[], Awaitable[T]],
        *,
        scopes: Iterable[Any] = (),
        caller: str | None = None,
        bypass_cooldown: bool = False,
        wait: bool = False,
    ) -> T:
        """Run ``factory()`` as live operation ``key`` under the guard's rules.

        Args:
            key: Identity of the operation; concurrent calls with an equal
                key share one execution (see :func:`operation_key`).
            factory: Zero-argument callable returning the awaitable to run.
            scopes: Provider/account scopes the operation touches
                (``"aws/123456789012"``); cooldowns and caps apply per scope.
            caller: Identity for per-caller quotas (None: no quota).
            bypass_cooldown: Skip the cooldown check (operator override).
            wait: Wait for a free slot instead of raising LiveOperationBusy.

        Raises:
            CooldownActive, LiveOperationBusy, CallerQuotaExceeded: refused;
            anything ``factory()`` raises, for every joined caller.
        """
        existing = self._inflight.get(key)
        if existing is not None:
            self.joined += 1
            return await asyncio.shield(existing)

        scope_list = [str(s) for s in scopes]
        self._admit(scope_list, caller, bypass_cooldown, check_busy=not wait)
        if wait and not self._has_capacity(scope_list):
            cond = self._condition()
            async with cond:
                while not self._has_capacity(scope_list):
                    existing = self._inflight.get(key)
                    if existing is not None:
                        break
                    await cond.wait()
            existing = self._inflight.get(key)
            if existing is not None:
                self.joined += 1
                return await asyncio.shield(existing)
            self._admit(scope_list, caller, bypass_cooldown, check_busy=False)

        # Admitted: account for it before the first await so racing callers see it
        if caller and self.caller_max_operations:
            self._callers.setdefault(caller, deque()).append(self._clock())
        for s in scope_list:
            self._active[s] = self._active.get(s, 0) + 1
        self._active_total += 1
        self.started += 1
        task = asyncio.ensure_future(self._execute(key, factory, scope_list))
        task.add_done_callback(_consume_exception)
        self._inflight[key] = task
        self._inflight_scopes[key] = scope_list
        return await asyncio.shield(task)

    async def _execute(
        self, key: Hashable, factory: Callable[[], Awaitable[T]], scopes: list[str]
    ) -> T:
        ok = False
        try:
            result = await factory()
            ok = True
            return result
        finally:
            for s in scopes:
                self._active[s] = max(0, self._active.get(s, 0) - 1)
                if ok or self.cooldown_after_failure:
                    self._last_done[s] = self._clock()
            self._active_total = max(0, self._active_total - 1)
            self._inflight.pop(key, None)
            self._inflight_scopes.pop(key, None)
            if self._cond is not None and self._cond_loop is asyncio.get_running_loop():
                async with self._cond:
                    self._cond.notify_all()


def _consume_exception(task: "asyncio.Task[Any]") -> None:
    """Mark a shared task's exception as retrieved (callers may all have gone)."""
    if not task.cancelled():
        task.exception()
