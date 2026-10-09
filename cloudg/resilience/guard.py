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
import functools
import hashlib
import json
import time
from collections import deque
from collections.abc import Hashable
from dataclasses import dataclass, fields, replace
from typing import Any, Awaitable, Callable, Iterable, Mapping, TypeVar

__all__ = [
    "CallerQuotaExceeded",
    "CooldownActive",
    "GuardSettings",
    "LiveOperationBusy",
    "LiveOperationGuard",
    "LiveOperationRejected",
    "LiveOperationTimeout",
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


class LiveOperationTimeout(LiveOperationRejected):
    """The live operation ran longer than ``operation_timeout_seconds`` and was cancelled."""

    reason = "timeout"


def operation_key(*parts: Any) -> str:
    """A stable key for single-flight dedupe from arbitrary JSON-able parts."""
    blob = json.dumps(parts, sort_keys=True, default=str, separators=(",", ":"))
    return hashlib.sha256(blob.encode()).hexdigest()[:32]


def _provider_of(scope: str) -> str:
    for sep in ("/", ":"):
        if sep in scope:
            return scope.split(sep, 1)[0]
    return scope


@dataclass(frozen=True)
class GuardSettings:
    """Limits of a :class:`LiveOperationGuard` (see its docstring for each field)."""

    cooldown_seconds: float = 120.0
    max_concurrent_per_scope: int = 1
    max_concurrent_total: int = 2
    caller_max_operations: int = 0
    caller_window_seconds: float = 3600.0
    cooldown_after_failure: bool = True
    provider_cooldowns: Mapping[str, float] | None = None
    operation_timeout_seconds: float | None = None


_SETTING_NAMES = frozenset(f.name for f in fields(GuardSettings))

#: Monotonic clock
Clock = Callable[[], float]


class LiveOperationGuard:
    """Single-flight, concurrency caps, cooldowns and caller quotas for live operations.

    Settings are passed as keyword arguments (or as one :class:`GuardSettings`,
    which the keyword arguments then override):

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
        operation_timeout_seconds: Cancel a live operation that runs longer
            (None: no limit); its callers get :class:`LiveOperationTimeout`.
        clock: Monotonic clock (injectable for tests).

    A running operation is also cancelled when every caller waiting for it
    has gone (each was cancelled, e.g. by a client or tool timeout), so an
    abandoned operation cannot keep its scopes busy.
    """

    def __init__(
        self,
        settings: GuardSettings | None = None,
        *,
        clock: Clock = time.monotonic,
        **overrides: Any,
    ) -> None:
        unknown = set(overrides) - _SETTING_NAMES
        if unknown:
            raise TypeError(
                "LiveOperationGuard() got unexpected keyword arguments: "
                + ", ".join(sorted(unknown))
            )
        cfg = replace(settings or GuardSettings(), **overrides)
        self.settings = cfg
        self.cooldown_seconds = max(0.0, float(cfg.cooldown_seconds))
        self.max_concurrent_per_scope = max(1, int(cfg.max_concurrent_per_scope))
        self.max_concurrent_total = max(1, int(cfg.max_concurrent_total))
        self.caller_max_operations = max(0, int(cfg.caller_max_operations))
        self.caller_window_seconds = max(1.0, float(cfg.caller_window_seconds))
        self.cooldown_after_failure = cfg.cooldown_after_failure
        self.provider_cooldowns = {k: float(v) for k, v in (cfg.provider_cooldowns or {}).items()}
        timeout = cfg.operation_timeout_seconds
        self.operation_timeout = float(timeout) if timeout and timeout > 0 else None
        self._clock = clock
        self._inflight: dict[Hashable, asyncio.Task[Any]] = {}
        self._inflight_scopes: dict[Hashable, list[str]] = {}
        self._waiting: dict[asyncio.Future[Any], int] = {}
        self._active: dict[str, int] = {}
        self._active_total = 0
        self._last_done: dict[str, float] = {}
        self._callers: dict[str, deque[float]] = {}
        # Set (and replaced) whenever a slot frees up; waiters re-check capacity
        self._freed: asyncio.Event | None = None
        self._freed_loop: Any = None
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
                ("operation_timeout_seconds", "live_operation_timeout_seconds"),
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

    def _freed_event(self) -> asyncio.Event:
        loop = asyncio.get_running_loop()
        if self._freed is None or self._freed_loop is not loop:
            self._freed, self._freed_loop = asyncio.Event(), loop
        return self._freed

    def _wake_waiters(self) -> None:
        event, self._freed = self._freed, None
        if event is None:
            return
        try:
            running = asyncio.get_running_loop()
        except RuntimeError:
            running = None
        if running is self._freed_loop:
            event.set()

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
        timeout: float | None = None,
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
            timeout: Seconds the operation may run (default:
                ``operation_timeout_seconds``); ignored when joining one
                that is already running.

        Raises:
            CooldownActive, LiveOperationBusy, CallerQuotaExceeded: refused;
            LiveOperationTimeout: the operation ran out of time;
            anything ``factory()`` raises, for every joined caller.
        """
        existing = self._inflight.get(key)
        if existing is None:
            scope_list = [str(s) for s in scopes]
            self._admit(scope_list, caller, bypass_cooldown, check_busy=not wait)
            if wait and not self._has_capacity(scope_list):
                await self._await_capacity(key, scope_list)
                existing = self._inflight.get(key)
                if existing is None:
                    self._admit(scope_list, caller, bypass_cooldown, check_busy=False)
        if existing is not None:
            self.joined += 1
            return await self._join(existing)
        return await self._join(self._start(key, factory, scope_list, caller, timeout))

    async def _await_capacity(self, key: Hashable, scopes: list[str]) -> None:
        """Wait until ``scopes`` have a free slot or operation ``key`` started."""
        while not self._has_capacity(scopes) and key not in self._inflight:
            await self._freed_event().wait()

    def _start(
        self,
        key: Hashable,
        factory: Callable[[], Awaitable[T]],
        scopes: list[str],
        caller: str | None,
        timeout: float | None,
    ) -> "asyncio.Future[T]":
        """Account for an admitted operation and start it as a shared task.

        Synchronous, so racing callers see the accounting before any await.
        """
        if caller and self.caller_max_operations:
            self._callers.setdefault(caller, deque()).append(self._clock())
        for s in scopes:
            self._active[s] = self._active.get(s, 0) + 1
        self._active_total += 1
        self.started += 1
        limit = self.operation_timeout if timeout is None else timeout
        task = asyncio.ensure_future(_await(factory, limit, scopes))
        # The release runs as a done callback, so the slots are freed even
        # when the task is cancelled before its first step (loop shutdown)
        task.add_done_callback(functools.partial(self._release, key, scopes))
        self._inflight[key] = task
        self._inflight_scopes[key] = scopes
        return task

    async def _join(self, task: "asyncio.Future[T]") -> T:
        """Await the shared ``task``; the last caller to give up cancels it."""
        self._waiting[task] = self._waiting.get(task, 0) + 1
        try:
            return await asyncio.shield(task)
        finally:
            left = self._waiting.pop(task, 1) - 1
            if left > 0:
                self._waiting[task] = left
            elif not task.done():
                task.cancel()  # nobody is waiting for the result any more

    def _release(self, key: Hashable, scopes: list[str], task: "asyncio.Task[Any]") -> None:
        """Free the slots of a finished operation and start its cooldown."""
        # Also marks the exception as retrieved: every caller may have gone
        ok = not task.cancelled() and task.exception() is None
        now = self._clock()
        for s in scopes:
            self._active[s] = max(0, self._active.get(s, 0) - 1)
            if ok or self.cooldown_after_failure:
                self._last_done[s] = now
        self._active_total = max(0, self._active_total - 1)
        if self._inflight.get(key) is task:
            del self._inflight[key]
            self._inflight_scopes.pop(key, None)
        self._wake_waiters()


async def _await(
    factory: Callable[[], Awaitable[T]], timeout: float | None, scopes: list[str]
) -> T:
    """Run ``factory()`` inside the task (so a factory that raises does so
    there), cancelled after ``timeout`` seconds."""
    if timeout is None:
        return await factory()
    try:
        return await asyncio.wait_for(factory(), timeout)
    except asyncio.TimeoutError:
        raise LiveOperationTimeout(
            f"live operation did not finish within {timeout:.0f}s and was cancelled; "
            "retry later or use the cached dataset",
            scopes=scopes,
        ) from None
