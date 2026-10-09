"""Built-in middleware for :class:`~cloudg.mcp.layer.CloudGMCPLayer`.

Middleware wraps every tool call, resource read and prompt render, whichever
server or transport the request came through::

    async def middleware(info: CallInfo, call_next) -> Any

``call_next(info)`` returns a :class:`~cloudg.mcp.core.ToolResult` for tools,
a list of resource contents for resources and a
:class:`~cloudg.mcp.core.PromptResult` for prompts. Raise an
:class:`~cloudg.mcp.core.MCPLayerError` to reject a call.

Provided here:

* :class:`AuditLogMiddleware`: a JSONL audit trail with timestamp, principal,
  kind, name, argument *keys* plus keyed hashes of the values (never the raw
  values, which may hold secrets or identifiers), duration, outcome and the
  transform report (what was redacted / pseudonymised).
* :class:`MetricsMiddleware` (alias :data:`TimingMiddleware`): per-primitive
  call counters and latency stats; :func:`register_metrics_resource` exposes
  them as a ``cloudg://metrics`` resource.
* :class:`CachingMiddleware`: a TTL + LRU cache for read-only, idempotent
  tools keyed by principal, tool and arguments; cleared on
  ``layer.notify_change`` and after any non-read-only tool call.
* :class:`ConcurrencyLimitMiddleware` caps concurrent calls (globally and
  per principal), rejecting with ``RateLimitedError`` after a queue timeout.
* :class:`RetryMiddleware` retries read-only idempotent tools after
  timeouts / transient errors.

Order matters: middleware passed to the layer runs outermost first. A
typical stack is ``[audit, metrics, concurrency, cache, retry]`` so the audit
log sees every call (including cache hits and rejections).
"""

from __future__ import annotations

import asyncio
import copy
import hashlib
import hmac
import json
import logging
import os
import secrets
import threading
import time
from collections import OrderedDict, deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import IO, TYPE_CHECKING, Any, Awaitable, Callable, Iterable

from cloudg.mcp.core import (
    AccessDeniedError,
    MCPLayerError,
    RateLimitedError,
    ResourceSpec,
    Sensitivity,
    ToolResult,
    ToolSpec,
)

if TYPE_CHECKING:  # pragma: no cover
    from cloudg.mcp.layer import CallInfo, CloudGMCPLayer

logger = logging.getLogger("cloudg.mcp.middleware")
audit_logger = logging.getLogger("cloudg.mcp.audit")

Next = Callable[["CallInfo"], Awaitable[Any]]

__all__ = [
    "AuditLogMiddleware",
    "CachingMiddleware",
    "ConcurrencyLimitMiddleware",
    "MetricsMiddleware",
    "RetryMiddleware",
    "TimingMiddleware",
    "is_cacheable_tool",
    "register_metrics_resource",
]


def _canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str, ensure_ascii=False)


def _transform_report(result: Any) -> dict[str, Any] | None:
    if isinstance(result, ToolResult):
        return result.meta.get("cloudg/transforms") or None
    if isinstance(result, list):
        merged: dict[str, Any] = {}
        for item in result:
            meta = getattr(item, "meta", None) or {}
            for k, v in (meta.get("cloudg/transforms") or {}).items():
                if isinstance(v, (int, float)) and isinstance(merged.get(k), (int, float)):
                    merged[k] += v
                else:
                    merged.setdefault(k, v)
        return merged or None
    return None


def _error_code(result: Any) -> Any:
    meta = getattr(result, "meta", None) or {}
    return meta.get("cloudg/error_code", meta.get("error_code"))


def _outcome(result: Any) -> str:
    if isinstance(result, ToolResult) and result.is_error:
        return "error"
    return "ok"


def _error_outcome(exc: BaseException) -> str:
    if isinstance(exc, AccessDeniedError):
        return "denied"
    if isinstance(exc, RateLimitedError):
        return "rate_limited"
    if isinstance(exc, MCPLayerError):
        return "rejected"
    if isinstance(exc, asyncio.CancelledError):
        return "cancelled"
    return "exception"


# ---------------------------------------------------------------------------
# Audit log
# ---------------------------------------------------------------------------


class AuditLogMiddleware:
    """Append one JSON line per call to an audit log.

    Argument values are never written. Each value is reduced to
    ``HMAC-SHA256(salt, canonical_json(value))`` truncated to 16 hex chars,
    so an auditor holding the salt can confirm "was asset X queried?"
    without the log itself disclosing identifiers or secrets.

    Args:
        path: JSONL file to append to (created ``0600``). ``None`` logs to
            the ``cloudg.mcp.audit`` Python logger instead.
        stream: Alternatively, an open text stream.
        salt: HMAC key for value hashes. Default:
            ``$CLOUDG_MCP_AUDIT_SALT`` or a random per-process key.
        hash_values: Set false to log argument keys only.
    """

    def __init__(
        self,
        path: str | Path | None = None,
        *,
        stream: IO[str] | None = None,
        salt: bytes | str | None = None,
        hash_values: bool = True,
    ) -> None:
        self.path = Path(path).expanduser() if path else None
        self._stream = stream
        env_salt = os.environ.get("CLOUDG_MCP_AUDIT_SALT")
        raw_salt = salt if salt is not None else env_salt
        if raw_salt is None:
            self._salt = secrets.token_bytes(32)
        else:
            self._salt = raw_salt.encode() if isinstance(raw_salt, str) else raw_salt
        self.hash_values = hash_values
        self._lock = threading.Lock()
        self._fh: IO[str] | None = None
        if self.path is not None:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
            self._fh = os.fdopen(fd, "a", encoding="utf-8", buffering=1)

    def hash_value(self, value: Any) -> str:
        digest = hmac.new(self._salt, _canonical(value).encode("utf-8"), hashlib.sha256)
        return digest.hexdigest()[:16]

    def record(
        self,
        info: "CallInfo",
        *,
        outcome: str,
        duration_ms: float,
        result: Any = None,
        error: BaseException | None = None,
    ) -> dict[str, Any]:
        args = info.arguments or {}
        entry: dict[str, Any] = {
            "ts": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
            "event": "mcp.call",
            "kind": info.kind,
            "name": info.name,
            "principal": {"id": info.principal.id, "roles": sorted(info.principal.roles)},
            "request_id": getattr(info.context, "request_id", None),
            "argument_keys": sorted(args),
            "duration_ms": round(duration_ms, 2),
            "outcome": outcome,
        }
        spec = info.spec
        if spec is not None:
            entry["sensitivity"] = getattr(getattr(spec, "sensitivity", None), "value", None)
        if self.hash_values and args:
            entry["argument_hashes"] = {k: self.hash_value(v) for k, v in sorted(args.items())}
        if error is not None:
            entry["error"] = {"type": type(error).__name__, "code": getattr(error, "code", None)}
        elif isinstance(result, ToolResult) and result.is_error:
            entry["error"] = {"code": _error_code(result)}
        report = _transform_report(result)
        if report:
            entry["transforms"] = report
        return entry

    def write(self, entry: dict[str, Any]) -> None:
        line = _canonical(entry)
        with self._lock:
            if self._fh is not None:
                self._fh.write(line + "\n")
                self._fh.flush()
            elif self._stream is not None:
                self._stream.write(line + "\n")
                self._stream.flush()
            else:
                audit_logger.info("%s", line)

    def close(self) -> None:
        with self._lock:
            if self._fh is not None:
                self._fh.close()
                self._fh = None

    async def __call__(self, info: "CallInfo", call_next: Next) -> Any:
        start = time.perf_counter()
        try:
            result = await call_next(info)
        except BaseException as exc:
            self._safe_write(info, _error_outcome(exc), start, error=exc)
            raise
        self._safe_write(info, _outcome(result), start, result=result)
        return result

    def _safe_write(
        self,
        info: "CallInfo",
        outcome: str,
        start: float,
        *,
        result: Any = None,
        error: BaseException | None = None,
    ) -> None:
        try:
            self.write(
                self.record(
                    info,
                    outcome=outcome,
                    duration_ms=(time.perf_counter() - start) * 1000,
                    result=result,
                    error=error,
                )
            )
        except Exception:  # auditing must never break a call
            logger.exception("audit log write failed")


# ---------------------------------------------------------------------------
# Metrics
# ---------------------------------------------------------------------------


@dataclass
class _Stats:
    calls: int = 0
    errors: int = 0
    rejected: int = 0
    total_ms: float = 0.0
    max_ms: float = 0.0
    last: str | None = None
    recent: deque[float] = field(default_factory=lambda: deque(maxlen=256))

    def as_dict(self) -> dict[str, Any]:
        recent = sorted(self.recent)
        p95 = recent[min(len(recent) - 1, int(len(recent) * 0.95))] if recent else 0.0
        return {
            "calls": self.calls,
            "errors": self.errors,
            "rejected": self.rejected,
            "avg_ms": round(self.total_ms / self.calls, 2) if self.calls else 0.0,
            "p95_ms": round(p95, 2),
            "max_ms": round(self.max_ms, 2),
            "last_call": self.last,
        }


class MetricsMiddleware:
    """Count calls, errors, rejections and latency per primitive.

    ``snapshot()`` returns a JSON-ready dict; :func:`register_metrics_resource`
    serves it as a resource.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._stats: dict[str, _Stats] = {}
        self.started = time.time()

    def _update(self, key: str, ms: float, outcome: str) -> None:
        with self._lock:
            st = self._stats.setdefault(key, _Stats())
            st.calls += 1
            st.total_ms += ms
            st.max_ms = max(st.max_ms, ms)
            st.recent.append(ms)
            st.last = datetime.now(timezone.utc).isoformat(timespec="seconds")
            if outcome in ("error", "exception"):
                st.errors += 1
            elif outcome not in ("ok",):
                st.rejected += 1

    async def __call__(self, info: "CallInfo", call_next: Next) -> Any:
        start = time.perf_counter()
        key = f"{info.kind}:{info.name}"
        try:
            result = await call_next(info)
        except BaseException as exc:
            self._update(key, (time.perf_counter() - start) * 1000, _error_outcome(exc))
            raise
        self._update(key, (time.perf_counter() - start) * 1000, _outcome(result))
        return result

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            items = {k: v.as_dict() for k, v in sorted(self._stats.items())}
        return {
            "uptime_seconds": round(time.time() - self.started, 1),
            "calls": sum(v["calls"] for v in items.values()),
            "errors": sum(v["errors"] for v in items.values()),
            "rejected": sum(v["rejected"] for v in items.values()),
            "by_primitive": items,
        }

    def reset(self) -> None:
        with self._lock:
            self._stats.clear()
            self.started = time.time()


TimingMiddleware = MetricsMiddleware


def register_metrics_resource(
    target: "CloudGMCPLayer | Any",
    metrics: MetricsMiddleware,
    *,
    uri: str = "cloudg://metrics",
    replace: bool = True,
) -> ResourceSpec:
    """Register ``metrics.snapshot()`` as a resource on a layer (or a
    :class:`~cloudg.mcp.core.Registry`)."""
    registry = getattr(target, "registry", target)

    def metrics_resource(ctx: Any) -> dict[str, Any]:
        """Call counts and latency of the MCP layer's tools, resources and prompts."""
        return metrics.snapshot()

    spec = ResourceSpec(
        name="metrics",
        handler=metrics_resource,
        uri=uri,
        title="MCP layer metrics",
        category="server",
        sensitivity=Sensitivity.INTERNAL,
    )
    registry.add(spec, replace=replace)
    return spec


# ---------------------------------------------------------------------------
# Caching
# ---------------------------------------------------------------------------


def is_cacheable_tool(spec: Any) -> bool:
    """Read-only *and* idempotent tools are safe to cache."""
    if not isinstance(spec, ToolSpec):
        return False
    ann = spec.annotations
    return bool(ann.read_only) and bool(ann.idempotent)


class CachingMiddleware:
    """TTL + LRU result cache for read-only idempotent tools.

    Keys are ``(principal id, roles, tool, canonical arguments)`` so a result
    transformed for one principal is never served to another. The cache is
    cleared whenever the layer reports a change and after any tool call that
    is not read-only. Completions (kind ``"completion"``) are never cached.

    A hit still runs ``policy.check_call`` first (normally done in the layer's
    terminal step, which a hit skips), so access rules, rate-limit tokens and
    the policy's own audit apply to cached answers exactly as to fresh ones;
    a rejection propagates like it would on a miss.

    Args:
        ttl: Seconds an entry stays fresh.
        maxsize: Maximum number of entries (least recently used evicted).
        predicate: ``fn(CallInfo) -> bool`` overriding which calls are cached.
        cache_resources: Also cache resource reads.
    """

    def __init__(
        self,
        ttl: float = 60.0,
        maxsize: int = 256,
        *,
        predicate: Callable[["CallInfo"], bool] | None = None,
        cache_resources: bool = False,
    ) -> None:
        self.ttl = ttl
        self.maxsize = maxsize
        self.predicate = predicate
        self.cache_resources = cache_resources
        self._data: OrderedDict[tuple[Any, ...], tuple[float, Any]] = OrderedDict()
        self._lock = threading.Lock()
        self.hits = 0
        self.misses = 0

    def attach(self, layer: "CloudGMCPLayer") -> "CachingMiddleware":
        """Invalidate on ``layer.notify_change``."""
        layer.on_change(lambda kind, uri: self.invalidate())
        return self

    def invalidate(self, *_: Any) -> None:
        with self._lock:
            self._data.clear()

    def _cacheable(self, info: "CallInfo") -> bool:
        if info.kind == "completion":
            return False
        if self.predicate is not None:
            return bool(self.predicate(info))
        if info.kind == "tool":
            return is_cacheable_tool(info.spec)
        return info.kind == "resource" and self.cache_resources

    @staticmethod
    def _key(info: "CallInfo") -> tuple[Any, ...]:
        return (
            info.principal.id,
            tuple(sorted(info.principal.roles)),
            info.kind,
            info.name,
            _canonical(info.arguments or {}),
        )

    async def __call__(self, info: "CallInfo", call_next: Next) -> Any:
        if not self._cacheable(info):
            result = await call_next(info)
            if info.kind == "tool" and not getattr(
                getattr(info.spec, "annotations", None), "read_only", False
            ):
                self.invalidate()
            return result
        key = self._key(info)
        now = time.monotonic()
        with self._lock:
            hit = self._data.get(key)
            if hit is not None and hit[0] > now:
                self._data.move_to_end(key)
                cached = copy.deepcopy(hit[1])
            else:
                if hit is not None:
                    self._data.pop(key, None)
                cached = None
        if cached is not None:
            layer = getattr(info.context, "layer", None)
            if layer is not None:
                layer.policy.check_call(info.spec, info.principal, info.arguments)
            self.hits += 1
            if isinstance(cached, ToolResult):
                cached.meta["cloudg/cache"] = "hit"
            return cached
        self.misses += 1
        result = await call_next(info)
        if isinstance(result, ToolResult) and result.is_error:
            return result
        with self._lock:
            self._data[key] = (time.monotonic() + self.ttl, copy.deepcopy(result))
            self._data.move_to_end(key)
            while len(self._data) > self.maxsize:
                self._data.popitem(last=False)
        return result

    def stats(self) -> dict[str, Any]:
        with self._lock:
            size = len(self._data)
        return {"size": size, "hits": self.hits, "misses": self.misses, "ttl": self.ttl}


# ---------------------------------------------------------------------------
# Concurrency limiting
# ---------------------------------------------------------------------------


class ConcurrencyLimitMiddleware:
    """Bound concurrent calls.

    Args:
        limit: Maximum calls in flight across all principals.
        per_principal: Optional cap per principal id.
        queue_timeout: Seconds a call may wait for a slot before being
            rejected with :class:`~cloudg.mcp.core.RateLimitedError`
            (``None`` waits forever).
        kinds: Which request kinds are limited. Completions count as reads:
            they are limited when ``"resource"`` (or ``"completion"``) is
            listed.
    """

    def __init__(
        self,
        limit: int = 8,
        *,
        per_principal: int | None = None,
        queue_timeout: float | None = 30.0,
        kinds: Iterable[str] = ("tool",),
    ) -> None:
        if limit < 1:
            raise ValueError("limit must be >= 1")
        self.limit = limit
        self.per_principal = per_principal
        self.queue_timeout = queue_timeout
        self.kinds = set(kinds)
        self._global: asyncio.Semaphore | None = None
        self._per: dict[str, asyncio.Semaphore] = {}
        self.in_flight = 0

    async def _acquire(self, sem: asyncio.Semaphore) -> None:
        try:
            if self.queue_timeout is None:
                await sem.acquire()
            else:
                await asyncio.wait_for(sem.acquire(), self.queue_timeout)
        except asyncio.TimeoutError:
            raise RateLimitedError("Server busy: too many concurrent MCP calls") from None

    def _limited(self, kind: str) -> bool:
        if kind == "completion":
            return "completion" in self.kinds or "resource" in self.kinds
        return kind in self.kinds

    async def __call__(self, info: "CallInfo", call_next: Next) -> Any:
        if not self._limited(info.kind):
            return await call_next(info)
        if self._global is None:
            self._global = asyncio.Semaphore(self.limit)
        sems = [self._global]
        if self.per_principal:
            sems.insert(
                0, self._per.setdefault(info.principal.id, asyncio.Semaphore(self.per_principal))
            )
        acquired: list[asyncio.Semaphore] = []
        try:
            for sem in sems:
                await self._acquire(sem)
                acquired.append(sem)
            self.in_flight += 1
            try:
                return await call_next(info)
            finally:
                self.in_flight -= 1
        finally:
            for sem in reversed(acquired):
                sem.release()


# ---------------------------------------------------------------------------
# Retry
# ---------------------------------------------------------------------------


class RetryMiddleware:
    """Retry read-only idempotent tools after transient failures.

    A call is retried when it raises one of ``retry_on`` or returns an error
    result whose ``error_code`` is in ``retry_codes`` (the layer reports
    timeouts as ``"timeout"``).
    """

    def __init__(
        self,
        retries: int = 2,
        *,
        backoff: float = 0.5,
        retry_on: tuple[type[BaseException], ...] = (ConnectionError, TimeoutError),
        retry_codes: Iterable[str] = ("timeout",),
    ) -> None:
        self.retries = max(0, retries)
        self.backoff = backoff
        self.retry_on = retry_on
        self.retry_codes = set(retry_codes)

    async def __call__(self, info: "CallInfo", call_next: Next) -> Any:
        if not (info.kind == "tool" and is_cacheable_tool(info.spec)):
            return await call_next(info)
        attempt = 0
        while True:
            try:
                result = await call_next(info)
            except self.retry_on:
                if attempt >= self.retries:
                    raise
            else:
                if not (
                    isinstance(result, ToolResult)
                    and result.is_error
                    and _error_code(result) in self.retry_codes
                    and attempt < self.retries
                ):
                    if attempt and isinstance(result, ToolResult):
                        result.meta["cloudg/retries"] = attempt
                    return result
            attempt += 1
            await asyncio.sleep(self.backoff * (2 ** (attempt - 1)))
