"""Tests for the built-in layer middleware (:mod:`cloudg.mcp.middleware`)."""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import io
import json
import os
import sys
from pathlib import Path
from typing import Any

import pytest

from cloudg.mcp.context import Principal
from cloudg.mcp.core import AccessDeniedError, RateLimitedError, ToolResult
from cloudg.mcp.middleware import (
    AuditLogMiddleware,
    CachingMiddleware,
    ConcurrencyLimitMiddleware,
    MetricsMiddleware,
    RetryMiddleware,
    TimingMiddleware,
    is_cacheable_tool,
    register_metrics_resource,
)
from tests.mcp._adapter_testkit import build_layer


class Counter:
    """Innermost middleware counting calls that reach the handler."""

    def __init__(self) -> None:
        self.calls: list[str] = []

    async def __call__(self, info: Any, call_next: Any) -> Any:
        self.calls.append(info.name)
        return await call_next(info)


def read_lines(path: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


# ---------------------------------------------------------------------------
# Audit
# ---------------------------------------------------------------------------


async def test_audit_log_hashes_values_and_records_outcomes(tmp_path: Path) -> None:
    log = tmp_path / "audit" / "mcp.jsonl"
    audit = AuditLogMiddleware(log, salt="pepper")
    layer = build_layer(middleware=[audit])
    analyst = Principal(id="alice", roles={"analyst"})

    await layer.call_tool("echo", {"text": "arn:aws:iam::123456789012:role/secret"},
                          principal=analyst)
    await layer.call_tool("fail", {})
    await layer.read_resource("test://items/alpha")
    await layer.get_prompt("greet", {"name": "Bob"})
    audit.close()

    raw = log.read_text()
    assert "123456789012" not in raw and "Bob" not in raw  # never raw values
    entries = read_lines(log)
    echo, fail, resource, prompt = entries
    assert echo["kind"] == "tool" and echo["name"] == "echo" and echo["outcome"] == "ok"
    assert echo["principal"] == {"id": "alice", "roles": ["analyst"]}
    assert echo["argument_keys"] == ["text"]
    expected = hmac.new(b"pepper", json.dumps("arn:aws:iam::123456789012:role/secret")
                        .encode(), hashlib.sha256).hexdigest()[:16]
    assert echo["argument_hashes"]["text"] == expected
    assert echo["sensitivity"] == "public" and echo["duration_ms"] >= 0
    assert fail["outcome"] == "error" and fail["error"]["code"] == "handler_error"
    assert resource["kind"] == "resource" and resource["argument_keys"] == ["item_id"]
    assert prompt["kind"] == "prompt" and prompt["outcome"] == "ok"
    if sys.platform != "win32":
        assert (os.stat(log).st_mode & 0o777) == 0o600


async def test_audit_denied_and_transform_report() -> None:
    stream = io.StringIO()
    audit = AuditLogMiddleware(stream=stream, hash_values=False)

    async def fake_transform(info: Any, call_next: Any) -> Any:
        result = await call_next(info)
        if isinstance(result, ToolResult):
            result.meta["cloudg/transforms"] = {"redacted": 2}
        return result

    layer = build_layer(middleware=[audit, fake_transform])

    def deny(spec: Any, principal: Any, arguments: Any = None) -> None:
        if spec.name == "stats":
            raise AccessDeniedError("nope")

    layer.policy.check_call = deny  # type: ignore[method-assign]
    await layer.call_tool("echo", {"text": "x"})
    denied = await layer.call_tool("stats", {})
    assert denied.is_error
    first, second = [json.loads(line) for line in stream.getvalue().splitlines()]
    assert first["transforms"] == {"redacted": 2} and "argument_hashes" not in first
    assert second["outcome"] == "denied" and second["error"]["type"] == "AccessDeniedError"


async def test_audit_to_python_logger(caplog: pytest.LogCaptureFixture) -> None:
    layer = build_layer(middleware=[AuditLogMiddleware()])
    with caplog.at_level("INFO", logger="cloudg.mcp.audit"):
        await layer.call_tool("echo", {"text": "x"})
    assert any('"event":"mcp.call"' in r.getMessage() for r in caplog.records)


# ---------------------------------------------------------------------------
# Metrics
# ---------------------------------------------------------------------------


async def test_metrics_counters_and_resource() -> None:
    metrics = MetricsMiddleware()
    assert TimingMiddleware is MetricsMiddleware
    layer = build_layer(middleware=[metrics])
    register_metrics_resource(layer, metrics)
    await layer.call_tool("echo", {"text": "a"})
    await layer.call_tool("echo", {"text": "b"})
    await layer.call_tool("fail", {})
    snap = metrics.snapshot()
    assert snap["calls"] == 3 and snap["errors"] == 1
    echo = snap["by_primitive"]["tool:echo"]
    assert echo["calls"] == 2 and echo["errors"] == 0 and echo["max_ms"] >= echo["avg_ms"]
    contents = await layer.read_resource("cloudg://metrics")
    data = json.loads(contents[0].text)
    assert data["by_primitive"]["tool:fail"]["errors"] == 1
    metrics.reset()
    assert metrics.snapshot()["calls"] == 0


# ---------------------------------------------------------------------------
# Caching
# ---------------------------------------------------------------------------


async def test_cache_hits_scoping_and_invalidation() -> None:
    cache = CachingMiddleware(ttl=60)
    counter = Counter()
    layer = build_layer(middleware=[cache, counter])
    cache.attach(layer)
    assert is_cacheable_tool(layer.registry.tools["echo"])
    assert not is_cacheable_tool(layer.registry.tools["slow"])

    first = await layer.call_tool("echo", {"text": "a"})
    second = await layer.call_tool("echo", {"text": "a"})
    assert counter.calls == ["echo"]
    assert second.structured == first.structured and second.meta["cloudg/cache"] == "hit"
    second.structured["text"] = "mutated"  # cached copy must be isolated
    assert (await layer.call_tool("echo", {"text": "a"})).structured == {"text": "a"}

    await layer.call_tool("echo", {"text": "b"})  # different arguments
    await layer.call_tool("echo", {"text": "a"}, principal=Principal(id="bob"))  # other caller
    assert counter.calls == ["echo", "echo", "echo"]

    layer.notify_change("resources")
    await layer.call_tool("echo", {"text": "a"})
    assert len(counter.calls) == 4

    await layer.call_tool("touch", {})  # not read-only -> clears the cache
    await layer.call_tool("echo", {"text": "a"})
    assert counter.calls.count("echo") == 5

    stats = cache.stats()
    assert stats["hits"] == 2 and stats["size"] >= 1


async def test_cache_hits_still_run_policy_checks() -> None:
    """A hit skips the layer's terminal step, so the cache itself must run
    policy.check_call: rate limits and denials apply to cached answers."""
    cache = CachingMiddleware(ttl=60)
    counter = Counter()
    layer = build_layer(middleware=[cache, counter])
    checks: list[str] = []

    def limited(spec: Any, principal: Any, arguments: Any = None) -> None:
        checks.append(spec.name)
        if len(checks) > 2:
            raise RateLimitedError("rate limit exceeded")

    layer.policy.check_call = limited  # type: ignore[method-assign]
    assert not (await layer.call_tool("echo", {"text": "a"})).is_error  # miss, token 1
    hit = await layer.call_tool("echo", {"text": "a"})  # hit, token 2
    assert not hit.is_error and hit.meta["cloudg/cache"] == "hit"
    limited_hit = await layer.call_tool("echo", {"text": "a"})  # hit, over the limit
    assert limited_hit.is_error and "rate limit" in limited_hit.content[0].text
    assert checks == ["echo", "echo", "echo"] and counter.calls == ["echo"]
    assert cache.stats()["hits"] == 1


def _completion_info(layer: Any) -> Any:
    from cloudg.mcp.layer import CallInfo

    principal = Principal(id="c")
    return CallInfo("completion", "greet", layer.registry.prompts["greet"],
                    {"argument": "name", "value": "secret-partial", "context": {}},
                    principal, layer.context(principal))


async def test_completion_calls_are_audited_metered_never_cached() -> None:
    layer = build_layer()
    stream = io.StringIO()
    audit = AuditLogMiddleware(stream=stream, salt="s")
    metrics = MetricsMiddleware()
    cache = CachingMiddleware(predicate=lambda info: True)
    limiter = ConcurrencyLimitMiddleware(1, queue_timeout=0.01, kinds=("tool", "resource"))
    calls: list[int] = []

    async def terminal(info: Any) -> Any:
        calls.append(1)
        return {"values": ["alpha"], "total": 1, "hasMore": False}

    info = _completion_info(layer)
    for _ in range(2):
        async def chain(i: Any) -> Any:
            return await audit(i, lambda a: metrics(a, lambda b: limiter(
                b, lambda c: cache(c, terminal))))

        assert (await chain(info))["values"] == ["alpha"]
    assert len(calls) == 2  # never served from cache
    entry = json.loads(stream.getvalue().splitlines()[0])
    assert entry["kind"] == "completion" and entry["outcome"] == "ok"
    assert "secret-partial" not in stream.getvalue()
    assert metrics.snapshot()["by_primitive"]["completion:greet"]["calls"] == 2
    assert limiter._limited("completion")
    assert not ConcurrencyLimitMiddleware(1)._limited("completion")  # tools-only default


async def test_cache_skips_errors_and_expires() -> None:
    cache = CachingMiddleware(ttl=0.05, maxsize=1)
    counter = Counter()
    layer = build_layer(middleware=[cache, counter])
    await layer.call_tool("echo", {"times": 99})  # invalid -> error, not cached
    await layer.call_tool("echo", {"times": 99})
    assert counter.calls == ["echo", "echo"]
    await layer.call_tool("echo", {"text": "x"})
    await asyncio.sleep(0.08)
    await layer.call_tool("echo", {"text": "x"})
    assert counter.calls.count("echo") == 4
    await layer.call_tool("echo", {"text": "y"})  # evicts x (maxsize=1)
    assert cache.stats()["size"] == 1


# ---------------------------------------------------------------------------
# Concurrency / retry
# ---------------------------------------------------------------------------


async def test_concurrency_limit_rejects_when_busy() -> None:
    limiter = ConcurrencyLimitMiddleware(1, queue_timeout=0.05)
    layer = build_layer(middleware=[limiter])
    slow = asyncio.create_task(layer.call_tool("sleepy", {"seconds": 0.4}))
    await asyncio.sleep(0.05)
    assert limiter.in_flight == 1
    busy = await layer.call_tool("echo", {"text": "x"})
    assert busy.is_error and "busy" in busy.content[0].text.lower()
    assert (await slow).structured == {"slept": 0.4}
    assert not (await layer.call_tool("echo", {"text": "x"})).is_error
    # resources are not limited by default
    await layer.read_resource("test://info")
    with pytest.raises(ValueError):
        ConcurrencyLimitMiddleware(0)


async def test_concurrency_per_principal() -> None:
    limiter = ConcurrencyLimitMiddleware(10, per_principal=1, queue_timeout=0.05)
    layer = build_layer(middleware=[limiter])
    a = Principal(id="a")
    slow = asyncio.create_task(layer.call_tool("sleepy", {"seconds": 0.3}, principal=a))
    await asyncio.sleep(0.05)
    assert (await layer.call_tool("echo", {"text": "x"}, principal=a)).is_error
    assert not (await layer.call_tool("echo", {"text": "x"}, principal=Principal(id="b"))).is_error
    await slow


async def test_retry_on_timeout_results() -> None:
    attempts: list[int] = []

    async def flaky(info: Any, call_next: Any) -> Any:
        attempts.append(1)
        if len(attempts) == 1:
            return ToolResult.error("timed out", **{"cloudg/error_code": "timeout"})
        return await call_next(info)

    layer = build_layer(middleware=[RetryMiddleware(retries=2, backoff=0), flaky])
    result = await layer.call_tool("echo", {"text": "r"})
    assert not result.is_error and result.meta["cloudg/retries"] == 1
    assert len(attempts) == 2

    attempts.clear()
    # non-idempotent tools are never retried
    layer2 = build_layer(middleware=[RetryMiddleware(retries=2, backoff=0), flaky])
    assert (await layer2.call_tool("slow", {"steps": 1})).is_error
    assert len(attempts) == 1


async def test_retry_gives_up() -> None:
    async def always_timeout(info: Any, call_next: Any) -> Any:
        return ToolResult.error("timed out", **{"cloudg/error_code": "timeout"})

    layer = build_layer(middleware=[RetryMiddleware(retries=1, backoff=0), always_timeout])
    assert (await layer.call_tool("echo", {"text": "x"})).is_error
