"""Shared test fixtures.

moto's mock intercepts aiobotocore calls but hands back botocore's
synchronous AWSResponse, whose body is plain bytes. aiobotocore awaits the
body and crashes ("object bytes can't be used in 'await' expression").
The autouse fixture below replaces aiobotocore's convert_to_response_dict
with a version that copes with both sync and async response bodies.
Workaround tracked in https://github.com/aio-libs/aiobotocore/issues/755.
"""

from __future__ import annotations

import inspect
import io

import pytest


@pytest.fixture(autouse=True)
def patch_aiobotocore_for_moto(monkeypatch):
    try:
        import aiobotocore.endpoint
    except ImportError:
        yield
        return

    from botocore.response import StreamingBody

    async def _convert_to_response_dict(http_response, operation_model):
        content = http_response.content
        if inspect.isawaitable(content):
            content = await content

        headers = http_response.headers
        response_dict = {
            "headers": headers,
            "status_code": http_response.status_code,
            "context": {"operation_name": operation_model.name},
        }
        if response_dict["status_code"] >= 300:
            response_dict["body"] = content
        elif operation_model.has_event_stream_output:
            response_dict["body"] = http_response.raw
        elif operation_model.has_streaming_output:
            length = headers.get("content-length")
            response_dict["body"] = StreamingBody(io.BytesIO(content), length)
        else:
            response_dict["body"] = content
        return response_dict

    monkeypatch.setattr(
        aiobotocore.endpoint,
        "convert_to_response_dict",
        _convert_to_response_dict,
    )
    yield


@pytest.fixture(autouse=True)
def isolate_cloudcontrol_cache(monkeypatch, tmp_path):
    """Keep the Cloud Control type cache out of the user's home and reset
    the in-process cache between tests."""
    monkeypatch.setenv("CLOUDG_CACHE_DIR", str(tmp_path / "cloudg-cache"))
    try:
        from cloudg.inventory.aws_services import cloudcontrol
    except ImportError:
        yield
        return
    monkeypatch.setattr(cloudcontrol, "_types_cache", None)
    yield


@pytest.fixture(autouse=True)
def skip_ddb_crc32_under_moto(monkeypatch):
    """DynamoDB responses carry x-amz-crc32; aiobotocore awaits moto's
    synchronous body to verify it and fails. Skip the check in tests."""
    try:
        from aiobotocore import retryhandler
        from aiobotocore.retries import special
    except ImportError:
        yield
        return

    async def _no_check(self, attempt_number, response):
        return None

    async def _not_retryable(self, context):
        return False

    monkeypatch.setattr(retryhandler.AioCRC32Checker, "_check_response", _no_check)
    monkeypatch.setattr(special.AioRetryDDBChecksumError, "is_retryable", _not_retryable)
    yield


@pytest.fixture(autouse=True)
def fresh_resilience_governor(monkeypatch):
    """Each test starts with full rate-limit buckets, closed circuit breakers
    and empty throttle stats (the governor is process-wide state).

    moto never throttles, and its fixtures (hundreds of default AMIs and
    snapshots) would make the production per-service rates the bottleneck of
    the suite, so the built-in limits are raised for tests. The hooks,
    limiter, breakers and telemetry still run on every call; the resilience
    tests restore the real defaults (``limiter.BUILTIN_LIMITS``).
    """
    try:
        from dataclasses import replace

        from cloudg.resilience import limiter, reset_governor
    except ImportError:
        yield
        return

    fast = 1_000_000.0
    profile = {
        provider: replace(
            limits,
            max_rps=fast,
            burst=fast,
            account_max_rps=fast if limits.account_max_rps else None,
            account_burst=fast if limits.account_max_rps else None,
            services={
                name: replace(spec, rate=fast, burst=fast) for name, spec in limits.services.items()
            },
        )
        for provider, limits in limiter.BUILTIN_LIMITS.items()
    }
    monkeypatch.setattr(limiter, "DEFAULT_LIMITS", profile)
    reset_governor()
    yield
    reset_governor()
