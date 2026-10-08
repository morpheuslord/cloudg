"""Tests for cloudg.resilience: throttling classification, adaptive rate
limiting, circuit breakers, retries, run telemetry, the live-operation
guard, and the provider integrations (AWS via moto, Azure / GCP fakes)."""

from __future__ import annotations

import asyncio
import email.utils
import random
import urllib.error
from types import SimpleNamespace

import pytest

from cloudg.config import CloudGConfig, RateLimitConfig
from cloudg.coverage import CollectionCoverage, ServiceStatus
from cloudg.resilience import (
    CallerQuotaExceeded,
    CircuitBreaker,
    CircuitOpenError,
    CooldownActive,
    ErrorKind,
    Governor,
    LimitSpec,
    LiveOperationBusy,
    LiveOperationGuard,
    ProviderLimits,
    RateLimiter,
    RetryPolicy,
    Scope,
    TokenBucket,
    call_with_resilience,
    call_with_resilience_sync,
    classify,
    configure,
    decorrelated_jitter,
    describe_error,
    get_governor,
    operation_key,
    parse_retry_after,
    resilient,
    retry_after,
    stats_scope,
)
from cloudg.resilience.breaker import BreakerState
from cloudg.resilience.governor import provider_limits_from_config
from cloudg.resilience.limiter import DECREASE_FACTOR, INCREASE_INTERVAL, INCREASE_STEP


@pytest.fixture(autouse=True)
def builtin_limits(monkeypatch):
    """Use the production defaults (conftest raises them for moto-heavy tests)."""
    from cloudg.resilience import limiter, reset_governor

    monkeypatch.setattr(limiter, "DEFAULT_LIMITS", limiter.BUILTIN_LIMITS)
    reset_governor()


class FakeClock:
    def __init__(self, t: float = 1000.0) -> None:
        self.t = t

    def __call__(self) -> float:
        return self.t

    def advance(self, seconds: float) -> None:
        self.t += seconds


def run(coro):
    return asyncio.run(coro)


# ---------------------------------------------------------------------------
# Error shapes
# ---------------------------------------------------------------------------


class AWSError(Exception):
    def __init__(self, code: str, message: str = "", status: int = 400, headers=None):
        super().__init__(f"An error occurred ({code}): {message}")
        self.response = {
            "Error": {"Code": code, "Message": message},
            "ResponseMetadata": {"HTTPStatusCode": status, "HTTPHeaders": headers or {}},
        }


class AzureError(Exception):
    """Shaped like azure.core.exceptions.HttpResponseError."""

    def __init__(self, status: int, headers=None, code: str | None = None, url: str = ""):
        super().__init__(f"({code or status}) azure error")
        self.status_code = status
        self.error = SimpleNamespace(code=code) if code else None
        self.response = SimpleNamespace(
            status_code=status, headers=headers or {}, request=SimpleNamespace(url=url)
        )


class TestClassification:
    @pytest.mark.parametrize(
        "code",
        [
            "Throttling",
            "ThrottlingException",
            "ThrottledException",
            "RequestThrottledException",
            "TooManyRequestsException",
            "ProvisionedThroughputExceededException",
            "RequestLimitExceeded",
            "BandwidthLimitExceeded",
            "RequestThrottled",
            "SlowDown",
            "EC2ThrottledException",
            "PriorRequestNotComplete",
        ],
    )
    def test_aws_throttle_codes(self, code):
        assert classify(AWSError(code, "Rate exceeded")) is ErrorKind.THROTTLED

    def test_aws_limit_exceeded_is_context_dependent(self):
        assert classify(AWSError("LimitExceededException", "Rate exceeded")) is ErrorKind.THROTTLED
        assert (
            classify(AWSError("LimitExceededException", "Cannot exceed quota for PoliciesPerRole"))
            is ErrorKind.FATAL
        )

    def test_aws_transient_and_fatal(self):
        assert classify(AWSError("InternalError", status=500)) is ErrorKind.TRANSIENT
        assert classify(AWSError("RequestTimeout")) is ErrorKind.TRANSIENT
        assert classify(AWSError("AccessDenied", "not authorized", 403)) is ErrorKind.FATAL
        assert classify(AWSError("ValidationException")) is ErrorKind.FATAL

    def test_real_botocore_errors(self):
        from botocore.exceptions import ClientError, EndpointConnectionError

        err = ClientError(
            {"Error": {"Code": "Throttling", "Message": "Rate exceeded"}}, "DescribeInstances"
        )
        assert classify(err) is ErrorKind.THROTTLED
        assert (
            classify(EndpointConnectionError(endpoint_url="https://ec2.x")) is ErrorKind.TRANSIENT
        )

    def test_azure_shapes(self):
        assert classify(AzureError(429, {"Retry-After": "7"})) is ErrorKind.THROTTLED
        assert classify(AzureError(503)) is ErrorKind.THROTTLED
        assert classify(AzureError(500)) is ErrorKind.TRANSIENT
        assert classify(AzureError(403, code="AuthorizationFailed")) is ErrorKind.FATAL
        # 429 that is a lock conflict, not a rate signal
        assert (
            classify(AzureError(429, code="RetryableErrorDueToAnotherOperation"))
            is ErrorKind.TRANSIENT
        )
        assert classify(AzureError(400, code="RateLimiting")) is ErrorKind.THROTTLED

    def test_gcp_api_core(self):
        from google.api_core import exceptions as gexc

        assert classify(gexc.ResourceExhausted("quota")) is ErrorKind.THROTTLED
        assert classify(gexc.TooManyRequests("slow")) is ErrorKind.THROTTLED
        assert classify(gexc.ServiceUnavailable("overloaded")) is ErrorKind.THROTTLED
        assert classify(gexc.DeadlineExceeded("late")) is ErrorKind.TRANSIENT
        assert classify(gexc.InternalServerError("oops")) is ErrorKind.TRANSIENT
        assert classify(gexc.PermissionDenied("no")) is ErrorKind.FATAL
        wrapped = gexc.RetryError("deadline", cause=gexc.ResourceExhausted("quota"))
        assert classify(wrapped) is ErrorKind.THROTTLED

    def test_urllib_and_aiohttp_shapes(self):
        err = urllib.error.HTTPError("https://x", 429, "Too Many", {"Retry-After": "4"}, None)
        assert classify(err) is ErrorKind.THROTTLED
        assert retry_after(err) == 4.0

        class ClientResponseError(Exception):
            status = 429
            headers = {"Retry-After": "2"}

        assert classify(ClientResponseError("x")) is ErrorKind.THROTTLED
        assert retry_after(ClientResponseError("x")) == 2.0

    def test_builtins_and_text(self):
        assert classify(ConnectionResetError()) is ErrorKind.TRANSIENT
        assert classify(TimeoutError()) is ErrorKind.TRANSIENT
        assert classify(ValueError("bad input")) is ErrorKind.FATAL
        assert classify(RuntimeError("Rate exceeded")) is ErrorKind.THROTTLED
        assert classify(CircuitOpenError("open")) is ErrorKind.THROTTLED

    def test_explicit_cause_only(self):
        try:
            try:
                raise AWSError("Throttling")
            except AWSError as inner:
                raise RuntimeError("wrapped") from inner
        except RuntimeError as outer:
            assert classify(outer) is ErrorKind.THROTTLED
        try:
            try:
                raise AWSError("Throttling")
            except AWSError:
                raise KeyError("unrelated")  # implicit context is not a cause
        except KeyError as unrelated:
            assert classify(unrelated) is ErrorKind.FATAL

    def test_describe_error(self):
        assert describe_error(AWSError("Throttling", "Rate exceeded")).startswith("throttled: ")
        assert describe_error(ValueError("bad")) == "bad"


class TestRetryAfter:
    def test_parse_values(self):
        assert parse_retry_after("120") == 120.0
        assert parse_retry_after("1.5") == 1.5
        assert parse_retry_after(3) == 3.0
        assert parse_retry_after("-4") == 0.0
        assert parse_retry_after("00:01:05") == 65.0
        assert parse_retry_after("1.00:00:01") == 86401.0
        assert parse_retry_after("garbage") is None
        assert parse_retry_after(None) is None
        assert parse_retry_after("") is None

    def test_parse_http_date(self):
        now = 1_800_000_000.0
        date = email.utils.formatdate(now + 30, usegmt=True)
        assert parse_retry_after(date, now=now) == pytest.approx(30.0, abs=1.0)
        past = email.utils.formatdate(now - 30, usegmt=True)
        assert parse_retry_after(past, now=now) == 0.0

    def test_header_shapes(self):
        assert retry_after(AzureError(429, {"Retry-After": "7"})) == 7.0
        assert retry_after(AzureError(429, {"retry-after-ms": "1500"})) == 1.5
        assert retry_after(AzureError(429, {"x-ms-retry-after-ms": "250"})) == 0.25
        assert retry_after(AWSError("Throttling", headers={"retry-after": "3"})) == 3.0
        assert retry_after(AWSError("Throttling")) is None

    def test_resource_graph_quota_headers(self):
        err = AzureError(
            429, {"x-ms-user-quota-remaining": "0", "x-ms-user-quota-resets-after": "00:00:03"}
        )
        assert retry_after(err) == 3.0
        healthy = AzureError(
            400, {"x-ms-user-quota-remaining": "9", "x-ms-user-quota-resets-after": "00:00:03"}
        )
        assert retry_after(healthy) is None

    def test_grpc_retry_info(self):
        class Quota(Exception):
            details = [SimpleNamespace(retry_delay=SimpleNamespace(seconds=2, nanos=500_000_000))]

        assert retry_after(Quota()) == 2.5

    def test_resilience_error_hint(self):
        assert retry_after(CircuitOpenError("open", retry_after=12.0)) == 12.0


# ---------------------------------------------------------------------------
# Token bucket / limiter
# ---------------------------------------------------------------------------


class TestTokenBucket:
    def test_burst_then_rate(self):
        clock = FakeClock()
        b = TokenBucket(LimitSpec(10.0, 5.0), now=clock())
        assert [b.reserve(clock()) for _ in range(5)] == [0.0] * 5
        assert b.reserve(clock()) == pytest.approx(0.1)
        assert b.reserve(clock()) == pytest.approx(0.2)
        clock.advance(10)
        assert b.reserve(clock()) == 0.0  # refilled (capped at capacity)

    def test_aimd_decrease_once_per_interval_and_floor(self):
        clock = FakeClock()
        b = TokenBucket(LimitSpec(8.0, 8.0), now=clock(), min_rate=1.5)
        assert b.on_throttle(clock()) == 8.0 * DECREASE_FACTOR
        assert b.on_throttle(clock()) == 4.0  # same congestion event
        clock.advance(1.0)
        assert b.on_throttle(clock()) == 2.0
        clock.advance(1.0)
        assert b.on_throttle(clock()) == 1.5  # floor
        assert b.tokens <= 0  # burst drained

    def test_additive_recovery_to_ceiling(self):
        clock = FakeClock()
        b = TokenBucket(LimitSpec(10.0, 10.0), now=clock(), min_rate=0.1)
        b.on_throttle(clock())
        assert b.rate == 5.0
        assert b.on_success(clock()) == 5.0  # not yet: inside the quiet interval
        for _ in range(40):
            clock.advance(INCREASE_INTERVAL)
            b.on_success(clock())
        assert b.rate == 10.0  # back at the ceiling, never above
        clock.advance(INCREASE_INTERVAL)
        b.on_throttle(clock())
        clock.advance(INCREASE_INTERVAL)
        assert b.on_success(clock()) == pytest.approx(5.0 + 10.0 * INCREASE_STEP)

    def test_retry_after_pause_staggers_waiters(self):
        clock = FakeClock()
        b = TokenBucket(LimitSpec(2.0, 2.0), now=clock(), adaptive=False)
        b.on_throttle(clock(), retry_after=3.0)
        waits = [b.reserve(clock()) for _ in range(3)]
        assert waits[0] == pytest.approx(3.0 + 0.5)
        assert waits[1] == pytest.approx(3.0 + 1.0)
        assert waits[2] == pytest.approx(3.0 + 1.5)
        assert b.rate == 2.0  # not adaptive: rate unchanged

    def test_not_adaptive_keeps_rate(self):
        clock = FakeClock()
        b = TokenBucket(LimitSpec(4.0), now=clock(), adaptive=False)
        assert b.on_throttle(clock()) == 4.0


class TestRateLimiter:
    def _limiter(self, clock, **aws):
        limits = {"aws": ProviderLimits(**({"max_rps": 10.0, "burst": 2.0} | aws))}
        return RateLimiter(limits, clock=clock)

    def test_scopes_are_independent(self):
        clock = FakeClock()
        lim = self._limiter(clock)
        ec2 = Scope("aws", "1", "us-east-1", "sqs")
        other_region = Scope("aws", "1", "eu-west-1", "sqs")
        assert [lim.reserve(ec2) for _ in range(2)] == [0.0, 0.0]
        assert lim.reserve(ec2) > 0
        assert lim.reserve(other_region) == 0.0

    def test_builtin_service_defaults(self):
        lim = RateLimiter(clock=FakeClock())
        assert lim.rate(Scope("aws", "1", "us-east-1", "route53")) == 5.0
        assert lim.rate(Scope("aws", "1", "us-east-1", "ec2")) == 20.0
        assert lim.rate(Scope("aws", "1", "us-east-1", "somethingelse")) == 20.0
        assert lim.rate(Scope("azure", None, None, "resourcegraph")) == 3.0
        assert lim.rate(Scope("gcp", "projects/p", None, "cloudasset", "ListAssets")) == 1.5
        assert lim.rate(Scope("gcp", "projects/p", None, "cloudasset", "Other")) == 10.0

    def test_operation_override_has_its_own_bucket(self):
        clock = FakeClock()
        lim = RateLimiter(clock=clock)
        list_assets = Scope("gcp", "projects/p", None, "cloudasset", "ListAssets")
        search = Scope("gcp", "projects/p", None, "cloudasset", "SearchAllResources")
        for _ in range(10):
            lim.reserve(list_assets)
        assert lim.reserve(list_assets) > 0
        assert lim.reserve(search) == 0.0

    def test_hierarchical_account_bucket(self):
        clock = FakeClock()
        limits = {
            "azure": ProviderLimits(
                max_rps=100.0, burst=100.0, account_max_rps=1.0, account_burst=3.0
            )
        }
        lim = RateLimiter(limits, clock=clock)
        net = Scope("azure", "sub", None, "network")
        comp = Scope("azure", "sub", None, "compute")
        waits = [lim.reserve(net), lim.reserve(comp), lim.reserve(net), lim.reserve(comp)]
        assert waits[:3] == [0.0, 0.0, 0.0]
        assert waits[3] == pytest.approx(1.0)  # the shared subscription bucket binds
        assert lim.reserve(Scope("azure", "other-sub", None, "network")) == 0.0

    def test_global_bucket(self):
        clock = FakeClock()
        lim = RateLimiter(
            {"aws": ProviderLimits(max_rps=100, burst=100, global_max_rps=1.0, global_burst=1.0)},
            clock=clock,
        )
        assert lim.reserve(Scope("aws", "1", "r1", "s3")) == 0.0
        assert lim.reserve(Scope("aws", "2", "r2", "sqs")) == pytest.approx(1.0)

    def test_disabled_provider_never_waits(self):
        lim = RateLimiter({"aws": ProviderLimits(enabled=False, max_rps=0.1)}, clock=FakeClock())
        scope = Scope("aws", "1", "r", "ec2")
        assert all(lim.reserve(scope) == 0.0 for _ in range(50))

    def test_throttle_feedback_and_pause(self):
        clock = FakeClock()
        lim = self._limiter(clock)
        scope = Scope("aws", "1", "us-east-1", "sqs", "ListQueues")
        assert lim.on_throttle(scope, retry_after=2.0) == 5.0
        assert lim.rate(scope) == 5.0
        assert lim.reserve(scope) == pytest.approx(2.0 + 0.2)
        assert lim.peek(scope) > 2.0
        snap = lim.snapshot()
        assert any(v["rate_rps"] == 5.0 for v in snap.values())

    def test_acquire_async_and_sync_report_waits(self):
        clock = FakeClock()
        events = []
        lim = RateLimiter(
            {"aws": ProviderLimits(max_rps=10.0, burst=1.0)},
            clock=clock,
            on_event=lambda e, s, v: events.append((e, v)),
        )
        scope = Scope("aws", "1", "r", "sqs")
        slept = []

        async def fake_sleep(s):
            slept.append(s)

        assert run(lim.acquire(scope, sleep=fake_sleep)) == 0.0
        assert run(lim.acquire(scope, sleep=fake_sleep)) == pytest.approx(0.1)
        lim.acquire_sync(scope, sleep=slept.append, max_wait=0.05)
        assert slept == [pytest.approx(0.1), 0.05]
        assert [e for e, _ in events] == ["wait", "wait"]

    def test_config_overrides_merge_with_builtins(self):
        rl = RateLimitConfig.model_validate(
            {"aws": {"max_rps": 7, "services": {"ec2": {"max_rps": 3, "burst": 6}}}}
        )
        pl = provider_limits_from_config("aws", rl.aws)
        assert pl.max_rps == 7
        assert pl.services["ec2"] == LimitSpec(3.0, 6.0, per_operation=True)  # inherited
        assert pl.services["route53"] == LimitSpec(5.0, 5.0)  # built-in kept

    def test_bulkhead_caps_concurrency(self):
        lim = RateLimiter({"aws": ProviderLimits(max_concurrency=2)}, clock=FakeClock())
        scope = Scope("aws", "1", "r", "ec2")
        active = {"now": 0, "max": 0}

        async def worker():
            async with lim.bulkhead(scope).hold():
                active["now"] += 1
                active["max"] = max(active["max"], active["now"])
                await asyncio.sleep(0.01)
                active["now"] -= 1

        async def main():
            await asyncio.gather(*(worker() for _ in range(8)))

        run(main())
        assert active["max"] == 2


# ---------------------------------------------------------------------------
# Circuit breaker
# ---------------------------------------------------------------------------


class TestCircuitBreaker:
    def test_state_machine(self):
        clock = FakeClock()
        br = CircuitBreaker("x", threshold=3, cooldown=10, clock=clock)
        assert not br.record_failure()
        assert not br.record_failure()
        assert br.state is BreakerState.CLOSED
        assert br.record_failure()
        assert br.state is BreakerState.OPEN
        assert not br.allow()
        with pytest.raises(CircuitOpenError) as info:
            br.check("aws/1/r/ec2")
        assert info.value.retry_after == pytest.approx(10.0)
        clock.advance(10)
        assert br.state is BreakerState.HALF_OPEN
        assert br.allow()  # one probe
        assert not br.allow()
        assert br.record_failure()  # probe failed: reopen with doubled cooldown
        assert br.retry_after() == pytest.approx(20.0)
        clock.advance(20)
        assert br.allow()
        br.record_success()
        assert br.state is BreakerState.CLOSED
        assert br.trips == 2

    def test_success_resets_consecutive_count(self):
        br = CircuitBreaker("x", threshold=2, clock=FakeClock())
        br.record_failure()
        br.record_success()
        assert not br.record_failure()
        assert br.state is BreakerState.CLOSED


# ---------------------------------------------------------------------------
# call_with_resilience
# ---------------------------------------------------------------------------


def _governor(clock, **aws):
    cfg = {"aws": {"breaker_threshold": 2, "breaker_cooldown_seconds": 30, **aws}}
    return Governor(RateLimitConfig.model_validate(cfg), clock=clock)


class Flaky:
    """Fails with the given errors, then returns 'ok'."""

    def __init__(self, *errors):
        self.errors = list(errors)
        self.calls = 0

    def __call__(self):
        self.calls += 1
        if self.errors:
            raise self.errors.pop(0)
        return "ok"

    async def coro(self):
        return self()


class TestCallWithResilience:
    def _sleeper(self, clock, log):
        async def sleep(s):
            log.append(s)
            clock.advance(s)

        return sleep

    def test_retries_throttling_and_honours_retry_after(self):
        clock = FakeClock()
        gov = _governor(clock)
        slept: list[float] = []
        fn = Flaky(AWSError("Throttling", headers={"retry-after": "5"}), AWSError("Throttling"))
        scope = Scope("aws", "1", "us-east-1", "sqs", "ListQueues")

        async def main():
            with stats_scope() as stats:
                result = await call_with_resilience(
                    fn.coro, scope=scope, governor=gov, sleep=self._sleeper(clock, slept),
                    clock=clock,
                )  # fmt: skip
                return result, stats

        result, stats = run(main())
        assert result == "ok" and fn.calls == 3
        assert max(slept) >= 5.0  # Retry-After honoured
        totals = stats.totals()
        assert totals["throttled"] == 2 and totals["retries"] == 2
        assert gov.limiter.rate(scope) < 20.0  # AIMD decrease
        assert any("throttled 2x" in m for m in stats.messages())

    def test_fatal_is_not_retried(self):
        clock = FakeClock()
        gov = _governor(clock)
        fn = Flaky(AWSError("AccessDenied", status=403))
        with pytest.raises(AWSError):
            run(
                call_with_resilience(
                    fn.coro,
                    scope=Scope("aws", "1", "r", "iam"),
                    governor=gov,
                    sleep=self._sleeper(clock, []),
                    clock=clock,
                )  # fmt: skip
            )
        assert fn.calls == 1
        assert gov.breakers.get(Scope("aws", "1", "r", "iam")).state is BreakerState.CLOSED

    def test_exhausted_retries_raise_original_and_open_breaker(self):
        clock = FakeClock()
        gov = _governor(clock, max_retries=1)
        scope = Scope("aws", "1", "r", "sqs")
        sleep = self._sleeper(clock, [])

        def always():
            raise AWSError("Throttling", "Rate exceeded")

        async def attempt():
            return await call_with_resilience(
                always, scope=scope, governor=gov, sleep=sleep, clock=clock
            )

        with stats_scope() as stats:
            for _ in range(2):
                with pytest.raises(AWSError):
                    run(attempt())
            assert gov.breakers.get(scope).state is BreakerState.OPEN
            calls = Flaky()
            with pytest.raises(CircuitOpenError) as info:
                run(call_with_resilience(calls.coro, scope=scope, governor=gov, clock=clock))
            assert calls.calls == 0  # rejected without calling the API
            assert info.value.retry_after == pytest.approx(30.0)
            summary = stats.summary()
        assert summary["totals"]["gave_up"] == 2
        assert summary["totals"]["breaker_trips"] == 1
        assert summary["totals"]["rejected"] == 1
        assert str(scope) in summary["skipped"]

    def test_retry_budget(self):
        clock = FakeClock()
        gov = _governor(clock, retry_budget=1)
        fn = Flaky(*(AWSError("Throttling") for _ in range(3)))
        with pytest.raises(AWSError):
            run(
                call_with_resilience(
                    fn.coro,
                    scope=Scope("aws", "1", "r", "sqs"),
                    governor=gov,
                    sleep=self._sleeper(clock, []),
                    clock=clock,
                )  # fmt: skip
            )
        assert fn.calls == 2  # one retry allowed by the budget

    def test_deadline(self):
        clock = FakeClock()
        gov = _governor(clock)
        fn = Flaky(AWSError("Throttling", headers={"retry-after": "60"}))
        with pytest.raises(AWSError):
            run(
                call_with_resilience(
                    fn.coro,
                    scope=Scope("aws", "1", "r", "sqs"),
                    governor=gov,
                    policy=RetryPolicy(deadline=10),
                    sleep=self._sleeper(clock, []),
                    clock=clock,
                )  # fmt: skip
            )
        assert fn.calls == 1  # Retry-After beyond the deadline: give up at once

    def test_transient_retried(self):
        clock = FakeClock()
        gov = _governor(clock)
        fn = Flaky(ConnectionResetError(), AzureError(500))
        result = run(
            call_with_resilience(
                fn,
                scope=Scope("azure", "s", None, "network"),
                governor=gov,
                sleep=self._sleeper(clock, []),
                clock=clock,
            )  # fmt: skip
        )
        assert result == "ok" and fn.calls == 3

    def test_sync_variant(self):
        clock = FakeClock()
        gov = _governor(clock)
        slept: list[float] = []

        def sleep(s):
            slept.append(s)
            clock.advance(s)

        fn = Flaky(AzureError(429, {"Retry-After": "2"}))
        scope = Scope("azure", "s", None, "compute")
        assert (
            call_with_resilience_sync(fn, scope=scope, governor=gov, sleep=sleep, clock=clock)
            == "ok"
        )
        assert fn.calls == 2 and max(slept) >= 2.0

    def test_disabled_provider_calls_directly(self):
        gov = Governor(RateLimitConfig(enabled=False))
        fn = Flaky(AWSError("Throttling"))
        with pytest.raises(AWSError):
            call_with_resilience_sync(fn, scope=Scope("aws", "1", "r", "sqs"), governor=gov)
        assert fn.calls == 1

    def test_decorator(self):
        calls = {"n": 0}
        fast = RetryPolicy(base_delay=0.001, max_backoff=0.001)

        @resilient(lambda name: Scope("gcp", "projects/p", None, "cloudasset", name), fast)
        def fetch(name):
            calls["n"] += 1
            if calls["n"] == 1:
                raise ConnectionResetError()
            return name.upper()

        assert fetch("list") == "LIST" and calls["n"] == 2
        assert get_governor().stats.totals()["retries"] == 1

        @resilient(Scope("gcp", "projects/p", None, "cloudasset"))
        async def afetch():
            return 42

        assert run(afetch()) == 42

    def test_decorrelated_jitter_bounds(self):
        rng = random.Random(7)
        prev = 0.5
        for _ in range(50):
            nxt = decorrelated_jitter(prev, 0.5, 20.0, rng)
            assert 0.5 <= nxt <= min(20.0, max(0.5, prev * 3))
            prev = nxt


# ---------------------------------------------------------------------------
# Live operation guard
# ---------------------------------------------------------------------------


class TestLiveOperationGuard:
    def test_single_flight(self):
        guard = LiveOperationGuard(cooldown_seconds=0)
        calls = {"n": 0}

        async def op():
            calls["n"] += 1
            await asyncio.sleep(0.02)
            return {"assets": 3}

        async def main():
            return await asyncio.gather(
                guard.run("k", op, scopes=["aws/1"]),
                guard.run("k", op, scopes=["aws/1"]),
                guard.run("k", op, scopes=["aws/1"]),
            )

        results = run(main())
        assert results == [{"assets": 3}] * 3
        assert calls["n"] == 1 and guard.joined == 2

    def test_single_flight_shares_exceptions(self):
        guard = LiveOperationGuard(cooldown_seconds=0)

        async def op():
            await asyncio.sleep(0.01)
            raise RuntimeError("boom")

        async def main():
            return await asyncio.gather(
                guard.run("k", op), guard.run("k", op), return_exceptions=True
            )

        results = run(main())
        assert all(isinstance(r, RuntimeError) for r in results)

    def test_cooldown(self):
        clock = FakeClock()
        guard = LiveOperationGuard(cooldown_seconds=120, clock=clock)

        async def op():
            return "fresh"

        assert run(guard.run("a", op, scopes=["aws/1"])) == "fresh"
        with pytest.raises(CooldownActive) as info:
            run(guard.run("b", op, scopes=["aws/1", "azure/s"]))
        assert info.value.retry_after == pytest.approx(120)
        assert info.value.scopes == ["aws/1"]
        payload = info.value.to_dict()
        assert payload["reason"] == "cooldown" and payload["retry_after_seconds"] == 120
        assert "cached dataset" in payload["message"]
        assert run(guard.run("c", op, scopes=["azure/s"])) == "fresh"  # other scope
        assert run(guard.run("d", op, scopes=["aws/1"], bypass_cooldown=True)) == "fresh"
        clock.advance(121)
        assert guard.cooldown_remaining("aws/1") == 0
        assert run(guard.run("e", op, scopes=["aws/1"])) == "fresh"

    def test_cooldown_after_failure_and_provider_override(self):
        clock = FakeClock()
        guard = LiveOperationGuard(
            cooldown_seconds=10, provider_cooldowns={"gcp": 300}, clock=clock
        )

        async def fail():
            raise RuntimeError("throttled")

        with pytest.raises(RuntimeError):
            run(guard.run("a", fail, scopes=["gcp/projects/p"]))
        assert guard.cooldown_remaining("gcp/projects/p") == pytest.approx(300)

    def test_concurrency_cap_and_wait(self):
        guard = LiveOperationGuard(cooldown_seconds=0, max_concurrent_per_scope=1)
        order = []

        async def slow(tag):
            order.append(f"start-{tag}")
            await asyncio.sleep(0.02)
            order.append(f"end-{tag}")
            return tag

        async def main():
            first = asyncio.ensure_future(guard.run("a", lambda: slow("a"), scopes=["aws/1"]))
            await asyncio.sleep(0)
            with pytest.raises(LiveOperationBusy):
                await guard.run("b", lambda: slow("b"), scopes=["aws/1"])
            waited = await guard.run("c", lambda: slow("c"), scopes=["aws/1"], wait=True)
            return await first, waited

        assert run(main()) == ("a", "c")
        assert order == ["start-a", "end-a", "start-c", "end-c"]

    def test_total_cap(self):
        guard = LiveOperationGuard(cooldown_seconds=0, max_concurrent_total=1)

        async def slow():
            await asyncio.sleep(0.02)
            return 1

        async def main():
            first = asyncio.ensure_future(guard.run("a", slow, scopes=["aws/1"]))
            await asyncio.sleep(0)
            with pytest.raises(LiveOperationBusy):
                await guard.run("b", slow, scopes=["azure/2"])
            return await first

        assert run(main()) == 1

    def test_caller_quota(self):
        clock = FakeClock()
        guard = LiveOperationGuard(
            cooldown_seconds=0, caller_max_operations=2, caller_window_seconds=60, clock=clock
        )

        async def op():
            return "ok"

        run(guard.run("a", op, caller="agent"))
        clock.advance(10)
        run(guard.run("b", op, caller="agent"))
        with pytest.raises(CallerQuotaExceeded) as info:
            run(guard.run("c", op, caller="agent"))
        assert info.value.retry_after == pytest.approx(50)
        assert run(guard.run("d", op, caller="other")) == "ok"
        clock.advance(51)
        assert run(guard.run("e", op, caller="agent")) == "ok"

    def test_from_config_and_status(self):
        cfg = CloudGConfig.model_validate(
            {
                "ratelimit": {
                    "live_cooldown_seconds": 30,
                    "live_max_concurrent_total": 4,
                    "live_caller_max_operations": 5,
                    "aws": {"live_cooldown_seconds": 600},
                }
            }
        )
        guard = LiveOperationGuard.from_config(cfg)
        assert guard.cooldown_seconds == 30
        assert guard.max_concurrent_total == 4
        assert guard.caller_max_operations == 5
        assert guard.cooldown_for("aws/1") == 600
        assert guard.cooldown_for("azure/s") == 30
        guard.mark_completed(["aws/1"])
        assert "aws/1" in guard.status()["cooling_down"]
        guard.reset("aws/1")
        assert guard.cooldown_remaining("aws/1") == 0
        guard.check(["aws/1"])  # no exception

    def test_operation_key_is_stable(self):
        a = operation_key("map", ["aws"], {"regions": ["us-east-1"], "x": 1})
        b = operation_key("map", ["aws"], {"x": 1, "regions": ["us-east-1"]})
        assert a == b and len(a) == 32
        assert a != operation_key("map", ["azure"])


# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------


class TestConfig:
    def test_defaults_are_additive(self):
        cfg = CloudGConfig()
        assert cfg.ratelimit.enabled is True
        assert cfg.ratelimit.aws.breaker_threshold == 5
        assert cfg.ratelimit.live_cooldown_seconds == 120
        assert cfg.aws.max_retries == 10 and cfg.aws.retry_mode == "adaptive"
        # Older configs without the section still load
        assert CloudGConfig.model_validate({"providers": ["aws"]}).ratelimit.gcp.enabled

    def test_aws_retry_settings_reach_botocore(self):
        from cloudg.collectors.aws import _get_aio_config
        from cloudg.resilience.aws import botocore_retries

        assert _get_aio_config().retries == {"mode": "adaptive", "max_attempts": 10}
        configure(
            CloudGConfig.model_validate({"aws": {"max_retries": 4, "retry_mode": "standard"}})
        )
        assert botocore_retries() == {"mode": "standard", "max_attempts": 4}
        assert _get_aio_config().retries == {"mode": "standard", "max_attempts": 4}
        assert _get_aio_config(max_attempts=2).retries["max_attempts"] == 2

    def test_configure_ignores_non_configs(self):
        before = get_governor()
        assert configure(SimpleNamespace(ratelimit="nonsense")) is before

    def test_example_config_parses(self):
        from pathlib import Path

        from cloudg.config import load_config

        path = Path(__file__).resolve().parent.parent / "config.yaml"
        cfg = load_config(path)
        assert cfg.ratelimit.aws.breaker_cooldown_seconds == 60


# ---------------------------------------------------------------------------
# Integrations
# ---------------------------------------------------------------------------


_THROTTLE_XML = (
    b"<Response><Errors><Error><Code>RequestLimitExceeded</Code>"
    b"<Message>Request limit exceeded.</Message></Error></Errors>"
    b"<RequestID>x</RequestID></Response>"
)


@pytest.fixture
def aws_env(monkeypatch):
    for key, value in {
        "AWS_ACCESS_KEY_ID": "testing",
        "AWS_SECRET_ACCESS_KEY": "testing",
        "AWS_SESSION_TOKEN": "testing",
        "AWS_DEFAULT_REGION": "us-east-1",
    }.items():
        monkeypatch.setenv(key, value)
    # botocore's own backoff would sleep for real between attempts
    from botocore.retries import standard

    monkeypatch.setattr(standard.ExponentialBackoff, "delay_amount", lambda self, ctx: 0)
    configure(CloudGConfig.model_validate({"aws": {"max_retries": 3, "retry_mode": "standard"}}))


def _throttle_operation(session, operation: str):
    """Make every ``operation`` call of an aioboto3 session return a throttling error."""
    from botocore.awsrequest import AWSResponse
    from moto.core.botocore_stubber import MockRawResponse

    hits = {"n": 0}

    def handler(request, **_):
        body = request.body.decode() if isinstance(request.body, bytes) else str(request.body)
        if f"Action={operation}" in body:
            hits["n"] += 1
            return AWSResponse(request.url, 400, {}, MockRawResponse(_THROTTLE_XML))
        return None

    session._session.get_component("event_emitter").register_first("before-send", handler)
    return hits


class TestAWSIntegration:
    def test_throttled_service_is_partial_not_fatal(self, aws_env):
        import boto3
        from moto import mock_aws

        from cloudg.collectors.aws import AsyncAWSCollector

        with mock_aws():
            boto3.client("ec2", region_name="us-east-1").create_vpc(CidrBlock="10.1.0.0/16")
            collector = AsyncAWSCollector(boto3.Session(), "us-east-1", "123456789012")
            hits = _throttle_operation(collector._get_aio_session(), "DescribeSubnets")

            async def main():
                with stats_scope() as stats:
                    vpcs = await collector._run_service_collector("vpc", collector._collect_vpcs())
                    subnets = await collector._run_service_collector(
                        "subnets", collector._collect_subnets()
                    )
                    return vpcs, subnets, stats

            vpcs, subnets, stats = run(main())

        assert hits["n"] == 4  # first attempt + aws.max_retries (3) retries
        assert len(vpcs) >= 1 and subnets == []
        status = {s.service: s for s in collector.coverage.services}
        assert status["vpc"].status is ServiceStatus.SUCCESS
        # The subnet collector swallows its errors; the ledger still flags it
        assert status["subnets"].status in (ServiceStatus.PARTIAL, ServiceStatus.FAILED)
        assert status["subnets"].error.startswith("throttled")
        summary = stats.summary()
        key = "aws/123456789012/us-east-1/ec2"
        assert summary["scopes"][key]["throttled"] == 4
        assert summary["scopes"][key]["retries"] == 3
        assert summary["scopes"][key]["gave_up"] == 1
        assert key in summary["skipped"]

    def test_circuit_opens_and_skips_service(self, aws_env):
        import boto3
        from moto import mock_aws

        from cloudg.collectors.aws import AsyncAWSCollector

        configure(
            CloudGConfig.model_validate(
                {
                    "aws": {"max_retries": 2, "retry_mode": "standard"},
                    "ratelimit": {"aws": {"breaker_threshold": 1, "breaker_cooldown_seconds": 600}},
                }
            )
        )
        with mock_aws():
            collector = AsyncAWSCollector(boto3.Session(), "us-east-1", "123456789012")
            hits = _throttle_operation(collector._get_aio_session(), "DescribeVpcs")

            async def main():
                await collector._run_service_collector("vpc", collector._collect_vpcs())
                await collector._run_service_collector("vpc_again", collector._collect_vpcs())

            run(main())
        assert hits["n"] == 3  # 1 + 2 retries; the second call never reached the API
        status = {s.service: s for s in collector.coverage.services}
        assert status["vpc_again"].error.startswith("throttled")
        assert "circuit open" in status["vpc_again"].error
        assert get_governor().summary()["breakers"]

    def test_sync_session_hooks(self, aws_env):
        import boto3
        from moto import mock_aws

        from cloudg.credentials import build_aws_session

        with mock_aws():
            session = build_aws_session(CloudGConfig().aws, "us-east-1")
            with stats_scope() as stats:
                session.client("sts").get_caller_identity()
        assert stats.scopes()["aws/*/us-east-1/sts"]["calls"] == 1
        retries = session._session.get_default_client_config().retries
        assert retries["mode"] == "standard"
        assert retries["total_max_attempts"] == 4  # botocore: 3 retries + the first attempt
        assert boto3  # imported for moto's patching


class TestAzureIntegration:
    def test_throttled_service_recorded_and_others_continue(self):
        from cloudg.collectors.azure import AzureCollector

        sub = "00000000-0000-0000-0000-000000000001"
        collector = AzureCollector(credential=None, subscription_id=sub)
        url = f"https://management.azure.com/subscriptions/{sub}/providers/Microsoft.Compute/virtualMachines"

        def vms():
            raise AzureError(429, {"Retry-After": "1"}, url=url)

        def vnets():
            return [{"id": f"/subscriptions/{sub}/x", "type": "Microsoft.Network/virtualNetworks"}]

        with stats_scope() as stats:
            rows = run(collector._gather_rows({"vms": vms, "vnets": vnets}))
        assert len(rows) == 1
        assert collector.service_errors["vms"].startswith("throttled: ")
        assert f"azure/{sub}/*/compute" in stats.skipped()

    def test_throttle_policy_feedback(self):
        from cloudg.resilience.azure import azure_scope, throttle_policy

        clock = FakeClock()
        gov = Governor(RateLimitConfig(), clock=clock)
        policy = throttle_policy("sub", gov)
        sub = "00000000-0000-0000-0000-000000000002"
        url = f"https://management.azure.com/subscriptions/{sub}/providers/Microsoft.Network/virtualNetworks"
        request = SimpleNamespace(http_request=SimpleNamespace(url=url), context={})
        policy.on_request(request)
        scope = request.context["cloudg_scope"]
        assert scope == azure_scope(url) == Scope("azure", sub, None, "network")
        throttled = SimpleNamespace(
            http_response=SimpleNamespace(status_code=429, headers={"Retry-After": "4"})
        )
        policy.on_response(request, throttled)
        assert gov.limiter.rate(scope) == 15.0  # 30 rps network default halved
        assert gov.limiter.peek(scope) >= 4.0  # paused for Retry-After

        graph_url = "https://management.azure.com/providers/Microsoft.ResourceGraph/resources"
        graph_req = SimpleNamespace(http_request=SimpleNamespace(url=graph_url), context={})
        policy.on_request(graph_req)
        assert graph_req.context["cloudg_scope"] == Scope("azure", None, None, "resourcegraph")
        exhausted = SimpleNamespace(
            http_response=SimpleNamespace(
                status_code=200,
                headers={
                    "x-ms-user-quota-remaining": "0",
                    "x-ms-user-quota-resets-after": "00:00:05",
                },
            )
        )
        policy.on_response(graph_req, exhausted)
        assert gov.limiter.peek(Scope("azure", None, None, "resourcegraph")) >= 5.0

    def test_real_sdk_client_gets_policy_and_retry_settings(self):
        from azure.core.pipeline.policies import RetryPolicy as AzureRetryPolicy

        from cloudg.collectors.azure import resource_management_client

        class Cred:
            def get_token(self, *a, **k):  # pragma: no cover - never called
                raise AssertionError

        client = resource_management_client(Cred(), "00000000-0000-0000-0000-000000000001")
        policies = client._client._pipeline._impl_policies
        names = [type(getattr(p, "_policy", p)).__name__ for p in policies]
        assert "AzureThrottlePolicy" in names
        retry = next(p for p in policies if isinstance(p, AzureRetryPolicy))
        assert retry.total_retries == 8 and retry.status_retries == 8
        assert names.index("AzureThrottlePolicy") > names.index(type(retry).__name__)

    def test_build_client_falls_back_for_strict_classes(self):
        from cloudg.resilience.azure import build_azure_client

        class Strict:
            def __init__(self, credential):
                self.credential = credential

        assert build_azure_client(Strict, "cred").credential == "cred"

    def test_resource_graph_honours_retry_after(self):
        from cloudg.inventory.azure_graph import run_query

        class Throttle(Exception):
            status_code = 429
            headers = {"x-ms-user-quota-remaining": "0", "x-ms-user-quota-resets-after": "00:00:07"}

        calls = {"n": 0}

        class Graph:
            def resources(self, request):
                calls["n"] += 1
                if calls["n"] == 1:
                    raise Throttle("RateLimiting")
                return SimpleNamespace(data=[{"id": "a"}], skip_token=None)

        slept: list[float] = []
        rows = run_query(Graph(), "resources", sleep=slept.append)
        assert rows == [{"id": "a"}]
        assert max(slept) >= 7.0


class TestGCPIntegration:
    def test_throttled_listing_is_reported_and_falls_back(self):
        from google.api_core import exceptions as gexc

        from cloudg.collectors.gcp import GCPCollector

        class Client:
            def list_assets(self, request=None, **kwargs):
                assert "retry" in kwargs
                raise gexc.ResourceExhausted("Quota exceeded for ListAssets")

            def search_all_resources(self, request=None, **kwargs):
                return iter([])

        cov = CollectionCoverage(provider="gcp")
        with stats_scope() as stats:
            run(GCPCollector("p1", client=Client(), coverage=cov).collect())
        status = {s.service: s for s in cov.services}
        assert status["gcp_list_assets"].status is ServiceStatus.FAILED
        assert status["gcp_list_assets"].error.startswith("throttled: ")
        assert "gcp/projects/p1/*/cloudasset" in stats.skipped()

    def test_pages_are_paced(self):
        from cloudg.resilience.gcp import gcp_scope, operation_name, paced

        clock = FakeClock()
        gov = Governor(RateLimitConfig(), clock=clock)
        scope = gcp_scope("organizations/1", "cloudasset", "ListAssets")
        assert scope == Scope("gcp", "organizations/1", None, "cloudasset", "ListAssets")

        def list_assets():  # pragma: no cover - only its name is used
            pass

        assert operation_name(list_assets) == "ListAssets"
        with stats_scope() as stats:
            items = list(paced(range(25), scope, 10, governor=gov))
        assert items == list(range(25))
        assert stats.scopes()["gcp/organizations/1/*/cloudasset"]["calls"] == 2

    def test_retry_reports_to_governor(self):
        from google.api_core import exceptions as gexc

        from cloudg.resilience.gcp import gcp_retry

        gov = Governor(RateLimitConfig(), clock=FakeClock())
        scope = Scope("gcp", "projects/p", None, "cloudasset", "ListAssets")
        retry = gcp_retry(scope, governor=gov)
        assert retry._maximum == 60.0 and retry._timeout == 900.0
        with stats_scope() as stats:
            retry._on_error(gexc.ResourceExhausted("quota"))
        assert stats.totals()["throttled"] == 1
        assert gov.limiter.rate(scope) == 0.75


class TestMapperTelemetry:
    def test_inventory_result_carries_throttling(self, tmp_path):
        from cloudg.inventory.mapper_result import InventoryResult

        plain = InventoryResult()
        assert "throttling" not in plain.summary
        info = {
            "totals": {"throttled": 3},
            "messages": ["aws/1/us-east-1/ec2: throttled 3x, slowed to 5.0 rps"],
            "skipped": {"aws/1/us-east-1/ec2": "throttled"},
            "scopes": {},
        }
        result = InventoryResult(throttling=info)
        assert result.summary["throttling"]["messages"] == info["messages"]
        result.export(tmp_path)
        assert InventoryResult.load(tmp_path).throttling == info

    def test_mapper_attaches_summary_when_throttled(self, monkeypatch):
        from cloudg.collectors import multi
        from cloudg.inventory.mapper import InventoryMapper

        async def fake_collect_all(self):
            get_governor().on_throttle(Scope("aws", "1", "us-east-1", "ec2"), None, "Throttling")
            return [], [], []

        monkeypatch.setattr(multi.MultiAccountCollector, "_collect_all", fake_collect_all)
        result = InventoryMapper(CloudGConfig(providers=["aws"])).map_inventory_sync()
        assert result.throttling["totals"]["throttled"] == 1
        assert result.summary["throttling"]["messages"]

        async def quiet(self):
            return [], [], []

        monkeypatch.setattr(multi.MultiAccountCollector, "_collect_all", quiet)
        assert (
            InventoryMapper(CloudGConfig(providers=["aws"])).map_inventory_sync().throttling is None
        )


# ---------------------------------------------------------------------------
# Follow-up: config keys, bulkheads, budgets, breaker granularity, telemetry
# ---------------------------------------------------------------------------


class TestConfigKeys:
    def test_global_and_account_burst_exposed(self):
        cfg = CloudGConfig.model_validate(
            {
                "ratelimit": {
                    "aws": {
                        "global_max_rps": 50,
                        "global_burst": 60,
                        "account_burst": 9,
                        "account_max_rps": 3,
                    }
                }
            }  # fmt: skip
        )
        limits = configure(cfg).limiter.limits("aws")
        assert (limits.global_max_rps, limits.global_burst) == (50, 60)
        assert (limits.account_max_rps, limits.account_burst) == (3, 9)

    def test_unknown_keys_warn_but_load(self, caplog):
        with caplog.at_level("WARNING", logger="cloudg.config"):
            cfg = CloudGConfig.model_validate(
                {
                    "ratelimit": {
                        "bogus": 1,
                        "aws": {"max_rpss": 3, "services": {"ec2": {"max_rps": 2, "brust": 1}}},
                    }
                }
            )
        text = caplog.text
        assert "ratelimit.bogus" in text
        assert "ratelimit.aws.max_rpss" in text
        assert "ratelimit.aws.services.ec2.brust" in text
        assert cfg.ratelimit.aws.services["ec2"].max_rps == 2


class TestBulkhead:
    def test_async_waiter_woken_by_release_from_thread(self):
        import threading

        from cloudg.resilience.limiter import Bulkhead

        bh = Bulkhead(1)
        assert bh.try_acquire() and not bh.try_acquire()

        async def main():
            threading.Timer(0.02, bh.release).start()
            await asyncio.wait_for(bh.acquire(), 2)
            return bh.in_use

        assert run(main()) == 1
        bh.release()
        assert bh.in_use == 0

    def test_cancelled_waiter_leaves_no_trace(self):
        from cloudg.resilience.limiter import Bulkhead

        bh = Bulkhead(1)
        bh.acquire_sync()

        async def main():
            task = asyncio.ensure_future(bh.acquire())
            await asyncio.sleep(0.01)
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task

        run(main())
        bh.release()
        assert bh.in_use == 0 and bh.try_acquire()

    def test_slot_released_once_and_on_gc(self):
        import gc

        from cloudg.resilience.limiter import Bulkhead, Slot

        bh = Bulkhead(2)
        bh.acquire_sync()
        slot = Slot(bh)
        slot.release()
        slot.release()
        assert bh.in_use == 0
        bh.acquire_sync()
        context = {"slot": Slot(bh)}
        del context
        gc.collect()
        assert bh.in_use == 0


def _aws_hooks(gov):
    from cloudg.resilience.aws import _AsyncHooks

    return _AsyncHooks("123456789012", "us-east-1", gov)


def _op(service="ec2", name="DescribeVpcs"):
    return SimpleNamespace(name=name, service_model=SimpleNamespace(service_name=service))


class TestAWSHookControls:
    def test_bulkhead_slot_held_for_call_and_released(self):
        gov = Governor(RateLimitConfig.model_validate({"aws": {"max_concurrency": 1}}))
        hooks = _aws_hooks(gov)
        scope = Scope("aws", "123456789012", "us-east-1", "ec2", "DescribeVpcs")
        bh = gov.limiter.bulkhead(scope)

        async def main():
            ok_ctx = {"client_region": "us-east-1"}
            await hooks.before_call(model=_op(), context=ok_ctx)
            assert bh.in_use == 1
            hooks.after_call(http_response=SimpleNamespace(status_code=200), parsed={},
                             context=ok_ctx)  # fmt: skip
            assert bh.in_use == 0
            err_ctx = {"client_region": "us-east-1"}
            await hooks.before_call(model=_op(), context=err_ctx)
            hooks.after_call_error(exception=ConnectionResetError(), context=err_ctx)
            assert bh.in_use == 0
            # A cancelled call: neither after-call event fires; the slot is
            # released when the request context goes away.
            lost_ctx = {"client_region": "us-east-1"}
            await hooks.before_call(model=_op(), context=lost_ctx)
            assert bh.in_use == 1
            del lost_ctx

        run(main())
        import gc

        gc.collect()
        assert bh.in_use == 0

    def test_bulkhead_blocks_extra_concurrent_calls(self):
        gov = Governor(RateLimitConfig.model_validate({"aws": {"max_concurrency": 1}}))
        hooks = _aws_hooks(gov)

        async def main():
            first = {"client_region": "us-east-1"}
            await hooks.before_call(model=_op(), context=first)
            second = {"client_region": "us-east-1"}
            waiter = asyncio.ensure_future(hooks.before_call(model=_op(), context=second))
            await asyncio.sleep(0.02)
            assert not waiter.done()
            hooks.after_call(http_response=SimpleNamespace(status_code=200), parsed={},
                             context=first)  # fmt: skip
            await asyncio.wait_for(waiter, 2)
            hooks.after_call(http_response=SimpleNamespace(status_code=200), parsed={},
                             context=second)  # fmt: skip

        run(main())

    def test_retry_budget_stops_botocore_retries(self):
        from cloudg.resilience import RetryBudgetExhaustedError

        gov = Governor(RateLimitConfig.model_validate({"aws": {"retry_budget": 1}}))
        hooks = _aws_hooks(gov)
        throttled = (
            SimpleNamespace(status_code=400),
            {"Error": {"Code": "Throttling", "Message": "Rate exceeded"}},
        )

        async def main():
            ctx = {"client_region": "us-east-1"}
            await hooks.before_call(model=_op("sqs", "ListQueues"), context=ctx)
            request_dict = {"context": ctx}
            await hooks.needs_retry(response=throttled, attempts=1, request_dict=request_dict)
            with pytest.raises(RetryBudgetExhaustedError):
                await hooks.needs_retry(response=throttled, attempts=2, request_dict=request_dict)
            hooks.after_call_error(exception=RetryBudgetExhaustedError("x"), context=ctx)

        with stats_scope() as stats:
            run(main())
        totals = stats.totals()
        assert totals["retries"] == 1 and totals["gave_up"] == 1

    def test_budget_exhaustion_end_to_end(self, aws_env):
        import boto3
        from moto import mock_aws

        from cloudg.collectors.aws import AsyncAWSCollector

        configure(
            CloudGConfig.model_validate(
                {
                    "aws": {"max_retries": 5, "retry_mode": "standard"},
                    "ratelimit": {"aws": {"retry_budget": 1}},
                }
            )
        )
        with mock_aws():
            collector = AsyncAWSCollector(boto3.Session(), "us-east-1", "123456789012")
            hits = _throttle_operation(collector._get_aio_session(), "DescribeVpcs")
            run(collector._run_service_collector("vpc", collector._collect_vpcs()))
        assert hits["n"] == 2  # first attempt + the single budgeted retry
        status = {s.service: s for s in collector.coverage.services}
        assert status["vpc"].error.startswith("throttled")
        assert "retry budget" in status["vpc"].error


class TestBreakerGranularity:
    def test_ec2_breaker_is_per_operation(self):
        gov = Governor(RateLimitConfig.model_validate({"aws": {"breaker_threshold": 1}}))
        vpcs = Scope("aws", "1", "us-east-1", "ec2", "DescribeVpcs")
        subnets = Scope("aws", "1", "us-east-1", "ec2", "DescribeSubnets")
        gov.on_gave_up(vpcs, "throttled")
        with pytest.raises(CircuitOpenError):
            gov.check(vpcs)
        gov.check(subnets)  # a sibling EC2 action is not blocked
        assert gov.breaker_scope(vpcs) == vpcs

    def test_other_services_break_per_service(self):
        gov = Governor(RateLimitConfig.model_validate({"aws": {"breaker_threshold": 1}}))
        send = Scope("aws", "1", "us-east-1", "sqs", "SendMessage")
        listq = Scope("aws", "1", "us-east-1", "sqs", "ListQueues")
        assert gov.breaker_scope(send) == send.service_scope
        gov.on_gave_up(send, "throttled")
        with pytest.raises(CircuitOpenError):
            gov.check(listq)

    def test_per_operation_override_follows_config(self):
        cfg = RateLimitConfig.model_validate(
            {"aws": {"services": {"sqs": {"max_rps": 5, "per_operation": True}}}}
        )
        gov = Governor(cfg)
        scope = Scope("aws", "1", "r", "sqs", "ListQueues")
        assert gov.breaker_scope(scope) == scope


class TestLedger:
    def test_describe_distinguishes_skipped_and_gave_up(self):
        from cloudg.resilience import ThrottleLedger

        ledger = ThrottleLedger()
        ledger.add_gave_up("throttled: DescribeVpcs")
        ledger.add_skipped("throttled: circuit open for aws/1/r/ec2/DescribeVpcs")
        ledger.add_skipped("throttled: circuit open for aws/1/r/ec2/DescribeVpcs")
        text = ledger.describe()
        assert "1 call(s) gave up after retries" in text
        assert "2 call(s) skipped (circuit open)" in text
        only_skipped = ThrottleLedger()
        only_skipped.add_skipped("x")
        assert "gave up" not in only_skipped.describe()
        assert only_skipped.degraded

    def test_open_circuit_marks_task_skipped(self):
        from cloudg.resilience import throttle_ledger

        gov = Governor(RateLimitConfig.model_validate({"aws": {"breaker_threshold": 1}}))
        scope = Scope("aws", "1", "r", "sqs", "ListQueues")
        gov.on_gave_up(scope, "throttled")
        with throttle_ledger() as ledger:
            with pytest.raises(CircuitOpenError):
                gov.check(scope)
        assert ledger.skipped == 1 and ledger.gave_up == 0
        assert "skipped (circuit open)" in ledger.describe()


class TestAzurePolicyControls:
    SUB = "00000000-0000-0000-0000-000000000003"

    def _request(self, provider="Network"):
        url = (
            f"https://management.azure.com/subscriptions/{self.SUB}/providers/"
            f"Microsoft.{provider}/things"
        )
        return SimpleNamespace(http_request=SimpleNamespace(url=url), context={})

    @staticmethod
    def _response(status, headers=None):
        return SimpleNamespace(
            http_response=SimpleNamespace(status_code=status, headers=headers or {})
        )

    def test_bulkhead_released_on_response_and_exception(self):
        from cloudg.resilience.azure import throttle_policy

        gov = Governor(RateLimitConfig.model_validate({"azure": {"max_concurrency": 1}}))
        policy = throttle_policy(self.SUB, gov)
        bh = gov.limiter.bulkhead(Scope("azure", self.SUB, None, "network"))
        req = self._request()
        policy.on_request(req)
        assert bh.in_use == 1
        policy.on_response(req, self._response(200))
        assert bh.in_use == 0
        req2 = self._request()
        policy.on_request(req2)
        policy.on_exception(req2)
        assert bh.in_use == 0

    def test_retry_budget_raises_to_stop_azure_retries(self):
        from cloudg.resilience import RetryBudgetExhaustedError
        from cloudg.resilience.azure import throttle_policy

        gov = Governor(RateLimitConfig.model_validate({"azure": {"retry_budget": 1}}))
        policy = throttle_policy(self.SUB, gov)
        req = self._request()
        policy.on_request(req)
        policy.on_response(req, self._response(429))  # budgeted retry
        req = self._request()
        policy.on_request(req)
        with pytest.raises(RetryBudgetExhaustedError):
            policy.on_response(req, self._response(500))
        assert gov.limiter.bulkhead(Scope("azure", self.SUB)).in_use == 0

    def test_low_remaining_reads_pauses_whole_subscription(self):
        from cloudg.resilience.azure import throttle_policy

        clock = FakeClock()
        gov = Governor(RateLimitConfig(), clock=clock)
        policy = throttle_policy(self.SUB, gov)
        req = self._request("Network")
        policy.on_request(req)
        policy.on_response(
            req, self._response(200, {"x-ms-ratelimit-remaining-subscription-reads": "3"})
        )
        # Another resource provider of the same subscription is held too
        compute = Scope("azure", self.SUB, None, "compute")
        assert gov.limiter.peek(compute) >= 1.0
        assert gov.limiter.peek(Scope("azure", "other-sub", None, "compute")) == 0.0

    def test_client_retry_policy_gets_deadline(self):
        from azure.core.pipeline.policies import RetryPolicy as AzureRetryPolicy

        from cloudg.collectors.azure import resource_management_client

        class Cred:
            def get_token(self, *a, **k):  # pragma: no cover - never called
                raise AssertionError

        configure(RateLimitConfig.model_validate({"azure": {"deadline_seconds": 120}}))
        client = resource_management_client(Cred(), self.SUB)
        retry = next(
            p for p in client._client._pipeline._impl_policies if isinstance(p, AzureRetryPolicy)
        )
        assert retry.timeout == 120


class TestGCPRetryControls:
    def test_max_consecutive_retries_and_reset_per_page(self):
        from google.api_core import exceptions as gexc

        from cloudg.resilience import RetryBudgetExhaustedError
        from cloudg.resilience.gcp import RetryCounter, gcp_retry, paced

        gov = Governor(RateLimitConfig.model_validate({"gcp": {"max_retries": 2}}))
        scope = Scope("gcp", "projects/p", None, "cloudasset", "ListAssets")
        counter = RetryCounter()
        retry = gcp_retry(scope, governor=gov, counter=counter)
        retry._on_error(gexc.ServiceUnavailable("x"))
        retry._on_error(gexc.ServiceUnavailable("x"))
        list(paced(range(3), scope, 2, governor=gov, counter=counter))  # pages arrived
        assert counter.count == 0
        retry._on_error(gexc.ServiceUnavailable("x"))
        retry._on_error(gexc.ServiceUnavailable("x"))
        with pytest.raises(RetryBudgetExhaustedError):
            retry._on_error(gexc.ServiceUnavailable("x"))

    def test_retry_budget(self):
        from google.api_core import exceptions as gexc

        from cloudg.resilience import RetryBudgetExhaustedError
        from cloudg.resilience.gcp import gcp_retry

        gov = Governor(RateLimitConfig.model_validate({"gcp": {"retry_budget": 1}}))
        retry = gcp_retry(Scope("gcp", "projects/p", None, "cloudasset"), governor=gov)
        retry._on_error(gexc.ResourceExhausted("q"))
        with pytest.raises(RetryBudgetExhaustedError):
            retry._on_error(gexc.ResourceExhausted("q"))


class TestLiveToolTelemetry:
    def test_run_throttling_prefers_result_then_stats(self):
        pytest.importorskip("cloudg.mcp.catalog.live")
        from cloudg.mcp.catalog.live import _run_throttling

        own = {"totals": {"throttled": 9}}
        assert _run_throttling(SimpleNamespace(throttling=own), None) is own
        with stats_scope() as stats:
            assert _run_throttling(object(), stats) is None  # nothing happened
            get_governor().on_throttle(Scope("aws", "1", "r", "ec2"), None, "Throttling")
        report = _run_throttling(object(), stats)
        assert report["totals"]["throttled"] == 1
        assert report["messages"]

    def test_mapper_reuses_bound_stats(self, monkeypatch):
        from cloudg.collectors import multi
        from cloudg.inventory.mapper import InventoryMapper

        async def fake_collect_all(self):
            get_governor().on_throttle(Scope("aws", "1", "us-east-1", "ec2"), None, "Throttling")
            return [], [], []

        monkeypatch.setattr(multi.MultiAccountCollector, "_collect_all", fake_collect_all)

        async def main():
            with stats_scope() as outer:
                await InventoryMapper(CloudGConfig(providers=["aws"])).map_inventory()
            return outer

        assert run(main()).totals()["throttled"] == 1


def test_refusal_suggests_dataset_covering_the_providers():
    pytest.importorskip("cloudg.mcp.catalog.live")
    from cloudg.mcp.catalog.live import _latest_live_dataset

    def ds(name, providers, at, source="live"):
        return SimpleNamespace(name=name, providers=providers, loaded_at=at, source=source,
                               kind="dataset")  # fmt: skip

    datasets = [
        ds("both", ["aws", "gcp"], 1),
        ds("gcp-only", ["gcp"], 2),
        ds("live-forced", ["aws"], 3),
        ds("file", ["gcp"], 4, source="/tmp/x.json"),
    ]
    ctx = SimpleNamespace(workspace=SimpleNamespace(datasets=lambda: datasets))
    assert _latest_live_dataset(ctx, ["gcp"]) == "gcp-only"
    assert _latest_live_dataset(ctx, ["AWS"]) == "live-forced"
    assert _latest_live_dataset(ctx, ["aws", "gcp"]) == "both"
    assert _latest_live_dataset(ctx, ["azure"]) is None  # none rather than a wrong one
    assert _latest_live_dataset(ctx) == "live-forced"
