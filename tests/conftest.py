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
