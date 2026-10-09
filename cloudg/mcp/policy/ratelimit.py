"""Token-bucket rate limiting for policies (see :mod:`cloudg.mcp.policy`)."""

from __future__ import annotations

import math
import threading
import time
from typing import Any

from cloudg.mcp.core import RateLimitedError
from cloudg.mcp.policy.access import _Globs, _kind_matches
from cloudg.mcp.policy.config import RateLimitConfig

_PERIOD = {"second": 1.0, "minute": 60.0, "hour": 3600.0, "day": 86400.0}


class _Bucket:
    __slots__ = ("tokens", "last")

    def __init__(self, tokens: float, now: float) -> None:
        self.tokens = tokens
        self.last = now


class RateLimiter:
    """Buckets per (limit, scope key). :meth:`take` checks every applicable
    bucket first and only then takes one token from each, so a rejection by
    a later bucket costs nothing in earlier ones."""

    def __init__(self, lock: threading.RLock) -> None:
        self._lock = lock
        self._buckets: dict[tuple[Any, ...], _Bucket] = {}
        self._globs: dict[int, _Globs] = {}

    def reset(self) -> None:
        with self._lock:
            self._buckets.clear()

    def _applies(self, rl: RateLimitConfig, kind: str, idents: tuple[str, ...]) -> bool:
        if rl.kinds and not _kind_matches(kind, rl.kinds):
            return False
        globs = self._globs.get(id(rl))
        if globs is None:
            globs = self._globs[id(rl)] = _Globs(rl.tools)
        return globs.match(*idents)

    def take(
        self,
        limits: list[RateLimitConfig],
        call: tuple[str, str, tuple[str, ...]],
        pid: str,
    ) -> None:
        """``call`` is ``(kind, name, idents)``. Raises
        :class:`RateLimitedError` when a bucket is empty."""
        kind, name, idents = call
        now = time.monotonic()
        with self._lock:
            taken: list[_Bucket] = []
            for rl in limits:
                if not self._applies(rl, kind, idents):
                    continue
                scope_key: tuple[Any, ...] = {
                    "principal": (pid,),
                    "tool": (name,),
                    "principal_tool": (pid, name),
                    "global": (),
                }[rl.scope]
                b = self._refill(rl, (id(rl), *scope_key), now)
                if b.tokens < 1.0:
                    raise _limited(rl, kind, name, b)
                taken.append(b)
            for b in taken:
                b.tokens -= 1.0

    def _refill(self, rl: RateLimitConfig, key: tuple[Any, ...], now: float) -> _Bucket:
        capacity = float(rl.burst or max(1, math.ceil(rl.rate)))
        refill = rl.rate / _PERIOD[rl.per]
        b = self._buckets.get(key)
        if b is None:
            b = self._buckets[key] = _Bucket(capacity, now)
        b.tokens = min(capacity, b.tokens + max(0.0, now - b.last) * refill)
        b.last = now
        return b


def _limited(rl: RateLimitConfig, kind: str, name: str, b: _Bucket) -> RateLimitedError:
    retry = (1.0 - b.tokens) / (rl.rate / _PERIOD[rl.per])
    return RateLimitedError(
        f"Rate limit exceeded for {kind} '{name}' ({rl.rate:g}/{rl.per}); retry in {retry:.1f}s",
        data={
            "retry_after": round(retry, 2),
            "limit": f"{rl.rate:g}/{rl.per}",
            "scope": rl.scope,
        },
    )
