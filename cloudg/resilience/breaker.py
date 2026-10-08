"""Circuit breakers per scope.

A breaker stops cloudg from hammering one throttled or failing service
while the rest of the map keeps going:

- CLOSED: calls flow; consecutive throttling / transient failures that
  survived the SDK's own retries are counted, any success resets the count.
- OPEN: after ``threshold`` consecutive failures calls are rejected
  immediately with :class:`~cloudg.resilience.errors.CircuitOpenError`
  (carrying ``retry_after``) for ``cooldown`` seconds.
- HALF_OPEN: after the cooldown one probe call is let through; success
  closes the breaker, failure re-opens it with the cooldown doubled (up to
  ``max_cooldown``). A probe that never reports back (cancelled, or ended
  by a FATAL error or a deadline before it was sent) is given up after
  one cooldown, so the breaker cannot stay half-open with no probe left.

FATAL errors (AccessDenied, validation) are not health signals and leave
the breaker untouched.
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass
from enum import Enum
from typing import Any, Callable

from cloudg.resilience.errors import CircuitOpenError

__all__ = ["BreakerRegistry", "BreakerState", "CircuitBreaker"]


class BreakerState(str, Enum):
    CLOSED = "closed"
    OPEN = "open"
    HALF_OPEN = "half_open"


@dataclass
class _BreakerSettings:
    threshold: int = 5
    cooldown: float = 60.0
    max_cooldown: float = 600.0
    half_open_probes: int = 1


class CircuitBreaker:
    """One closed / open / half-open breaker (thread-safe)."""

    def __init__(
        self,
        name: str = "",
        *,
        threshold: int = 5,
        cooldown: float = 60.0,
        max_cooldown: float = 600.0,
        half_open_probes: int = 1,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.name = name
        self.threshold = max(1, int(threshold))
        self.base_cooldown = max(0.0, float(cooldown))
        self.max_cooldown = max(self.base_cooldown, float(max_cooldown))
        self.half_open_probes = max(1, int(half_open_probes))
        self._clock = clock
        self._lock = threading.Lock()
        self._state = BreakerState.CLOSED
        self._failures = 0
        self._opened_at = 0.0
        self._cooldown = self.base_cooldown
        self._probes = 0
        self._probe_at = 0.0
        self.trips = 0

    # -- state ---------------------------------------------------------

    def _probe_lease(self) -> float:
        return max(self._cooldown, 1.0)

    def _probes_exhausted(self) -> bool:
        return self._state is BreakerState.HALF_OPEN and self._probes >= self.half_open_probes

    def _advance(self, now: float) -> None:
        if self._state is BreakerState.OPEN and now - self._opened_at >= self._cooldown:
            self._state = BreakerState.HALF_OPEN
            self._probes = 0
        elif self._probes_exhausted() and now - self._probe_at >= self._probe_lease():
            # The probes never reported a result: let a new one through
            self._probes = 0

    @property
    def state(self) -> BreakerState:
        with self._lock:
            self._advance(self._clock())
            return self._state

    def retry_after(self) -> float:
        """Seconds until the breaker lets a probe through (0 when closed)."""
        with self._lock:
            now = self._clock()
            self._advance(now)
            if self._state is BreakerState.OPEN:
                return max(0.0, self._opened_at + self._cooldown - now)
            if self._probes_exhausted():
                return max(0.0, self._probe_at + self._probe_lease() - now)
            return 0.0

    def allow(self) -> bool:
        """True when a call may go out now (consumes a half-open probe slot)."""
        with self._lock:
            now = self._clock()
            self._advance(now)
            if self._state is BreakerState.CLOSED:
                return True
            if self._state is BreakerState.HALF_OPEN and self._probes < self.half_open_probes:
                self._probes += 1
                self._probe_at = now
                return True
            return False

    def check(self, scope: Any = None) -> None:
        """Raise :class:`CircuitOpenError` unless a call may go out."""
        if not self.allow():
            wait = self.retry_after()
            raise CircuitOpenError(
                f"circuit open for {scope or self.name} after repeated throttling; "
                f"retry in {wait:.0f}s",
                retry_after=wait,
                scope=scope,
            )

    def record_success(self) -> None:
        with self._lock:
            self._failures = 0
            if self._state is not BreakerState.CLOSED:
                self._state = BreakerState.CLOSED
                self._cooldown = self.base_cooldown

    def record_failure(self) -> bool:
        """Count a throttling / transient failure; True when this opened the breaker."""
        with self._lock:
            now = self._clock()
            self._advance(now)
            if self._state is BreakerState.HALF_OPEN:
                self._cooldown = min(self.max_cooldown, max(self._cooldown * 2, 1.0))
                self._open(now)
                return True
            if self._state is BreakerState.OPEN:
                return False
            self._failures += 1
            if self._failures >= self.threshold:
                self._open(now)
                return True
            return False

    def _open(self, now: float) -> None:
        self._state = BreakerState.OPEN
        self._opened_at = now
        self._failures = 0
        self.trips += 1

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            now = self._clock()
            self._advance(now)
            return {
                "state": self._state.value,
                "consecutive_failures": self._failures,
                "trips": self.trips,
                "retry_after": round(
                    max(0.0, self._opened_at + self._cooldown - now)
                    if self._state is BreakerState.OPEN
                    else 0.0,
                    3,
                ),
            }


class BreakerRegistry:
    """Breakers keyed by scope string, with per-provider settings."""

    def __init__(
        self,
        settings: dict[str, dict[str, Any]] | None = None,
        *,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._clock = clock
        self._lock = threading.Lock()
        self._breakers: dict[str, CircuitBreaker] = {}
        self._settings: dict[str, _BreakerSettings] = {}
        self.configure(settings or {})

    def configure(self, settings: dict[str, dict[str, Any]]) -> None:
        with self._lock:
            new = {p: _BreakerSettings(**s) for p, s in settings.items()}
            if new != self._settings:
                self._settings = new
                self._breakers.clear()

    def get(self, scope: Any) -> CircuitBreaker:
        key = str(scope)
        provider = getattr(scope, "provider", key.split("/", 1)[0])
        with self._lock:
            br = self._breakers.get(key)
            if br is None:
                s = self._settings.get(provider) or _BreakerSettings()
                br = self._breakers[key] = CircuitBreaker(
                    key,
                    threshold=s.threshold,
                    cooldown=s.cooldown,
                    max_cooldown=s.max_cooldown,
                    half_open_probes=s.half_open_probes,
                    clock=self._clock,
                )
            return br

    def snapshot(self, only_tripped: bool = True) -> dict[str, dict[str, Any]]:
        with self._lock:
            items = list(self._breakers.items())
        out = {}
        for key, br in sorted(items):
            snap = br.snapshot()
            if only_tripped and not snap["trips"] and snap["state"] == "closed":
                continue
            out[key] = snap
        return out

    def reset(self) -> None:
        with self._lock:
            self._breakers.clear()
