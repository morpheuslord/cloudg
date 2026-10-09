"""Per-run throttling telemetry.

:class:`ResilienceStats` counts, per scope (``aws/123456789012/us-east-1/ec2``),
how often calls were throttled, retried, delayed by the rate limiter,
rejected by an open circuit breaker, or given up on. ``summary()`` turns
that into a JSON-friendly report with human-readable lines such as
``aws/123456789012/us-east-1/ec2: throttled 14x, slowed to 3.0 rps``.

Runs are isolated with :func:`stats_scope`: it binds a fresh stats object
to a context variable, so concurrent mappings (e.g. two MCP-triggered
collections) do not mix their numbers. asyncio tasks and
``asyncio.to_thread`` workers inherit the binding.

:class:`ThrottleLedger` is the finer-grained, per-collector-task variant:
the AWS collector binds one around each service task so throttling that
was swallowed by per-item error handling still turns the task's coverage
entry PARTIAL with reason "throttled".
"""

from __future__ import annotations

import contextlib
import contextvars
import threading
from dataclasses import dataclass, field
from typing import Any, Iterator

__all__ = [
    "ResilienceStats",
    "ScopeStats",
    "ThrottleLedger",
    "current_ledger",
    "current_stats",
    "stats_scope",
    "throttle_ledger",
]


@dataclass
class ScopeStats:
    """Counters of one scope."""

    calls: int = 0
    throttled: int = 0
    transient: int = 0
    retries: int = 0
    gave_up: int = 0
    rejected: int = 0  # circuit open / deadline / budget: call never attempted
    breaker_trips: int = 0
    waits: int = 0
    wait_seconds: float = 0.0
    max_wait_seconds: float = 0.0
    min_rate: float | None = None
    rate: float | None = None
    last_error: str | None = None

    def as_dict(self) -> dict[str, Any]:
        out = {
            "calls": self.calls,
            "throttled": self.throttled,
            "transient_errors": self.transient,
            "retries": self.retries,
            "gave_up": self.gave_up,
            "rejected": self.rejected,
            "breaker_trips": self.breaker_trips,
            "waits": self.waits,
            "wait_seconds": round(self.wait_seconds, 3),
            "max_wait_seconds": round(self.max_wait_seconds, 3),
        }
        if self.rate is not None:
            out["rate_rps"] = round(self.rate, 3)
        if self.min_rate is not None:
            out["min_rate_rps"] = round(self.min_rate, 3)
        if self.last_error:
            out["last_error"] = self.last_error
        return out

    @property
    def eventful(self) -> bool:
        return bool(
            self.throttled
            or self.transient
            or self.gave_up
            or self.rejected
            or self.breaker_trips
            or self.wait_seconds >= 1.0
        )


class ResilienceStats:
    """Thread-safe throttling counters keyed by scope string."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._scopes: dict[str, ScopeStats] = {}
        self._skipped: dict[str, str] = {}

    def _get(self, scope: Any) -> ScopeStats:
        key = str(scope)
        entry = self._scopes.get(key)
        if entry is None:
            entry = self._scopes[key] = ScopeStats()
        return entry

    def record_call(self, scope: Any) -> None:
        with self._lock:
            self._get(scope).calls += 1

    def record_throttle(
        self, scope: Any, rate: float | None = None, error: str | None = None
    ) -> None:
        with self._lock:
            s = self._get(scope)
            s.throttled += 1
            if error:
                s.last_error = error[:300]
            self._note_rate(s, rate)

    def record_transient(self, scope: Any, error: str | None = None) -> None:
        with self._lock:
            s = self._get(scope)
            s.transient += 1
            if error:
                s.last_error = error[:300]

    def record_retry(self, scope: Any) -> None:
        with self._lock:
            self._get(scope).retries += 1

    def record_wait(self, scope: Any, seconds: float) -> None:
        if seconds <= 0:
            return
        with self._lock:
            s = self._get(scope)
            s.waits += 1
            s.wait_seconds += seconds
            s.max_wait_seconds = max(s.max_wait_seconds, seconds)

    def record_rate(self, scope: Any, rate: float) -> None:
        with self._lock:
            self._note_rate(self._get(scope), rate)

    @staticmethod
    def _note_rate(s: ScopeStats, rate: float | None) -> None:
        if rate is None:
            return
        s.rate = rate
        s.min_rate = rate if s.min_rate is None else min(s.min_rate, rate)

    def record_gave_up(self, scope: Any, reason: str | None = None) -> None:
        with self._lock:
            s = self._get(scope)
            s.gave_up += 1
            if reason:
                s.last_error = reason[:300]
                self._skipped[str(scope)] = reason[:300]

    def record_rejected(self, scope: Any, reason: str | None = None) -> None:
        with self._lock:
            s = self._get(scope)
            s.rejected += 1
            if reason:
                self._skipped[str(scope)] = reason[:300]

    def record_breaker_trip(self, scope: Any) -> None:
        with self._lock:
            self._get(scope).breaker_trips += 1

    def merge(self, other: "ResilienceStats") -> None:
        """Add another stats object's counters into this one."""
        with other._lock:
            items = [(k, ScopeStats(**vars(v))) for k, v in other._scopes.items()]
            skipped = dict(other._skipped)
        with self._lock:
            for key, src in items:
                dst = self._get(key)
                for name in (
                    "calls", "throttled", "transient", "retries", "gave_up",
                    "rejected", "breaker_trips", "waits",
                ):  # fmt: skip
                    setattr(dst, name, getattr(dst, name) + getattr(src, name))
                dst.wait_seconds += src.wait_seconds
                dst.max_wait_seconds = max(dst.max_wait_seconds, src.max_wait_seconds)
                self._note_rate(dst, src.min_rate)
                if src.rate is not None:
                    dst.rate = src.rate
                dst.last_error = src.last_error or dst.last_error
            self._skipped.update(skipped)

    # ------------------------------------------------------------------
    # Reporting
    # ------------------------------------------------------------------

    def scopes(self) -> dict[str, dict[str, Any]]:
        with self._lock:
            return {k: v.as_dict() for k, v in sorted(self._scopes.items())}

    @property
    def eventful(self) -> bool:
        with self._lock:
            return any(v.eventful for v in self._scopes.values())

    def totals(self) -> dict[str, Any]:
        with self._lock:
            vals = list(self._scopes.values())
        return {
            "calls": sum(v.calls for v in vals),
            "throttled": sum(v.throttled for v in vals),
            "transient_errors": sum(v.transient for v in vals),
            "retries": sum(v.retries for v in vals),
            "gave_up": sum(v.gave_up for v in vals),
            "rejected": sum(v.rejected for v in vals),
            "breaker_trips": sum(v.breaker_trips for v in vals),
            "wait_seconds": round(sum(v.wait_seconds for v in vals), 3),
        }

    def messages(self) -> list[str]:
        """One human-readable line per scope that saw throttling or delays."""
        lines = []
        with self._lock:
            items = sorted(self._scopes.items())
        for key, s in items:
            if not s.eventful:
                continue
            parts = []
            if s.throttled:
                parts.append(f"throttled {s.throttled}x")
            if s.min_rate is not None and s.throttled:
                parts.append(f"slowed to {s.min_rate:.1f} rps")
            if s.wait_seconds >= 1.0:
                parts.append(f"waited {s.wait_seconds:.1f}s for rate limit")
            if s.retries:
                parts.append(f"{s.retries} retries")
            if s.breaker_trips:
                parts.append(f"circuit opened {s.breaker_trips}x")
            if s.rejected:
                parts.append(f"{s.rejected} calls skipped")
            if s.gave_up:
                parts.append(f"{s.gave_up} calls gave up")
            if s.transient and not s.throttled:
                parts.append(f"{s.transient} transient errors")
            lines.append(f"{key}: " + ", ".join(parts))
        return lines

    def skipped(self) -> dict[str, str]:
        """Scopes where work was abandoned, with the reason."""
        with self._lock:
            return dict(sorted(self._skipped.items()))

    def summary(self) -> dict[str, Any]:
        """JSON-friendly report: totals, per-scope counters, messages, skipped."""
        return {
            "totals": self.totals(),
            "messages": self.messages(),
            "skipped": self.skipped(),
            "scopes": {k: v for k, v in self.scopes().items()},
        }


# ---------------------------------------------------------------------------
# Context binding
# ---------------------------------------------------------------------------

_CURRENT_STATS: contextvars.ContextVar[ResilienceStats | None] = contextvars.ContextVar(
    "cloudg_resilience_stats", default=None
)


def current_stats() -> ResilienceStats | None:
    """The stats object bound by the innermost :func:`stats_scope`, if any."""
    return _CURRENT_STATS.get()


@contextlib.contextmanager
def stats_scope(stats: ResilienceStats | None = None) -> Iterator[ResilienceStats]:
    """Bind a (fresh) :class:`ResilienceStats` for the duration of a run."""
    bound = stats if stats is not None else ResilienceStats()
    token = _CURRENT_STATS.set(bound)
    try:
        yield bound
    finally:
        _CURRENT_STATS.reset(token)


@dataclass
class ThrottleLedger:
    """Throttling that a single collector task ran into.

    ``gave_up`` counts calls that were sent and stayed throttled after their
    retries; ``skipped`` counts calls an open circuit breaker rejected
    without sending them.
    """

    gave_up: int = 0
    skipped: int = 0
    throttled: int = 0
    reasons: list[str] = field(default_factory=list)
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def _note(self, reason: str) -> None:
        if len(self.reasons) < 5 and reason not in self.reasons:
            self.reasons.append(reason)

    def add_gave_up(self, reason: str) -> None:
        with self._lock:
            self.gave_up += 1
            self._note(reason)

    def add_skipped(self, reason: str) -> None:
        with self._lock:
            self.skipped += 1
            self._note(reason)

    def add_throttle(self) -> None:
        with self._lock:
            self.throttled += 1

    @property
    def degraded(self) -> bool:
        """True when any call gave up or was skipped."""
        return bool(self.gave_up or self.skipped)

    def describe(self) -> str:
        parts = []
        if self.gave_up:
            parts.append(f"{self.gave_up} call(s) gave up after retries")
        if self.skipped:
            parts.append(f"{self.skipped} call(s) skipped (circuit open)")
        detail = "; ".join(self.reasons)
        return (
            "throttled: "
            + (", ".join(parts) or "no calls lost")
            + (f" ({detail})" if detail else "")
        )


_CURRENT_LEDGER: contextvars.ContextVar[ThrottleLedger | None] = contextvars.ContextVar(
    "cloudg_throttle_ledger", default=None
)


def current_ledger() -> ThrottleLedger | None:
    return _CURRENT_LEDGER.get()


@contextlib.contextmanager
def throttle_ledger() -> Iterator[ThrottleLedger]:
    """Bind a fresh :class:`ThrottleLedger` for one collector task."""
    ledger = ThrottleLedger()
    token = _CURRENT_LEDGER.set(ledger)
    try:
        yield ledger
    finally:
        _CURRENT_LEDGER.reset(token)
