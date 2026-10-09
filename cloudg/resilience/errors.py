"""Provider-aware classification of throttling and transient errors.

:func:`classify` sorts any exception raised by a cloud SDK (or plain HTTP
client) into :class:`ErrorKind`:

- ``THROTTLED``: the provider asked us to slow down (AWS throttling codes,
  HTTP 429, Azure ``RateLimiting`` / ``TooManyRequests``, GCP
  ``RESOURCE_EXHAUSTED``, HTTP 503 "slow down" / overloaded).
- ``TRANSIENT``: worth retrying, but not a rate signal (timeouts,
  connection resets, HTTP 500/502/504/408).
- ``FATAL``: retrying will not help (AccessDenied, validation errors, ...).

:func:`retry_after` extracts the server's requested delay (``Retry-After``
in seconds or as an HTTP-date, ``retry-after-ms`` / ``x-ms-retry-after-ms``,
Azure Resource Graph's ``x-ms-user-quota-resets-after`` (``hh:mm:ss``), and
gRPC ``RetryInfo`` details) when there is one.

No provider SDK is imported: the shapes are detected by duck typing
(``exc.response["Error"]["Code"]`` for botocore, ``exc.status_code`` /
``exc.response.headers`` for azure-core, ``exc.code`` / ``exc.details`` for
google-api-core, ``exc.code`` / ``exc.headers`` for urllib, ``exc.status``
for aiohttp), so this module works whichever extras are installed.
"""

from __future__ import annotations

import email.utils
import re
import time
from enum import Enum
from typing import Any, Iterable, Mapping

__all__ = [
    "AWS_THROTTLE_CODES",
    "AWS_TRANSIENT_CODES",
    "CircuitOpenError",
    "DeadlineExceededError",
    "ErrorKind",
    "ResilienceError",
    "RetryBudgetExhaustedError",
    "classify",
    "classify_strict",
    "describe_error",
    "error_code",
    "is_provider_answer",
    "is_throttle",
    "parse_retry_after",
    "retry_after",
    "status_code",
]


class ErrorKind(str, Enum):
    """How an error should be handled by the retry / rate-limit machinery."""

    THROTTLED = "throttled"
    TRANSIENT = "transient"
    FATAL = "fatal"


# The union of botocore's standard-mode throttling codes
# (botocore/retries/standard.py ThrottledRetryableChecker) plus codes seen in
# individual services. LimitExceededException is context dependent (it is
# also used for "too many resources" quotas), see _LIMIT_EXCEEDED_RATE_RE.
AWS_THROTTLE_CODES: frozenset[str] = frozenset(
    {
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
        "RateExceeded",
        "Rate exceeded",
        "ThrottlingError",
        "TooManyRequests",
    }
)

AWS_TRANSIENT_CODES: frozenset[str] = frozenset(
    {
        "RequestTimeout",
        "RequestTimeoutException",
        "TransactionInProgressException",
        "InternalError",
        "InternalFailure",
        "InternalServerError",
        "InternalServiceError",
        "InternalServiceException",
        "ServiceUnavailable",
        "ServiceUnavailableException",
        "ServiceFailure",
        "IDPCommunicationError",
    }
)

# Azure ARM / Resource Graph / Graph error codes signalling throttling
_AZURE_THROTTLE_CODES = frozenset(
    {
        "RateLimiting",
        "TooManyRequests",
        "SubscriptionRequestsThrottled",
        "TenantRequestsThrottled",
        "ResourceRequestsThrottled",
        "OperationRateLimitExceeded",
        "ThrottlingError",
    }
)
# A 429 that is a lock conflict, not a rate signal (Microsoft.Network)
_AZURE_TRANSIENT_429_CODES = frozenset({"RetryableErrorDueToAnotherOperation"})

# google.api_core.exceptions class names (matched along the MRO)
_GCP_THROTTLE_CLASSES = frozenset({"ResourceExhausted", "TooManyRequests"})
_GCP_TRANSIENT_CLASSES = frozenset(
    {
        "ServiceUnavailable",
        "DeadlineExceeded",
        "InternalServerError",
        "GatewayTimeout",
        "BadGateway",
        "Aborted",
        "Unknown",
    }
)
# botocore / urllib3 / aiohttp / httpx connection-level class names
_TRANSIENT_CLASSES = frozenset(
    {
        "EndpointConnectionError",
        "ConnectionClosedError",
        "ReadTimeoutError",
        "ConnectTimeoutError",
        "ProxyConnectionError",
        "HTTPClientError",
        "ServiceRequestError",  # azure-core: request never reached the service
        "ServiceResponseError",  # azure-core: connection dropped mid-response
        "ServiceRequestTimeoutError",
        "ServiceResponseTimeoutError",
        "ClientConnectionError",
        "ServerDisconnectedError",
        "ServerTimeoutError",
        "ClientOSError",
        "ConnectError",
        "ReadTimeout",
        "ConnectTimeout",
        "RemoteDisconnected",
        "IncompleteRead",
    }
)

_THROTTLE_STATUSES = frozenset({429})
# 503 is "slow down" on S3 and "overloaded" almost everywhere else: treat it
# as a rate signal so the adaptive limiter backs off.
_OVERLOAD_STATUSES = frozenset({503})
_TRANSIENT_STATUSES = frozenset({408, 500, 502, 504})

_THROTTLE_TEXT_RE = re.compile(
    r"(rate exceeded|throttl|too many requests|slow ?down|request limit exceeded|"
    r"resource_exhausted|quota exceeded|rate limit|ratelimiting|requests? (are|is) being throttled)",
    re.IGNORECASE,
)
_LIMIT_EXCEEDED_RATE_RE = re.compile(r"(rate|throttl|too many|per second|tps)", re.IGNORECASE)


class ResilienceError(Exception):
    """Base of the errors raised by :mod:`cloudg.resilience` itself."""

    #: Seconds after which trying again makes sense (None: unknown)
    retry_after: float | None = None

    def __init__(self, message: str, retry_after: float | None = None, scope: Any = None) -> None:
        super().__init__(message)
        self.retry_after = retry_after
        self.scope = scope
        # botocore-shaped so cloudg's existing error_code() helpers report it
        self.response = {"Error": {"Code": type(self).__name__, "Message": message}}


class CircuitOpenError(ResilienceError):
    """The circuit breaker for a scope is open: the call was not attempted."""


class DeadlineExceededError(ResilienceError):
    """The overall deadline for a call (including retries) ran out."""


class RetryBudgetExhaustedError(ResilienceError):
    """The per-run retry budget is spent: the call is not retried again."""


# ---------------------------------------------------------------------------
# Field extraction
# ---------------------------------------------------------------------------


def _mro_names(exc: BaseException) -> set[str]:
    return {cls.__name__ for cls in type(exc).__mro__}


def _aws_error(exc: BaseException) -> tuple[str | None, str | None, int | None]:
    """(code, message, http status) of a botocore ClientError-shaped error."""
    response = getattr(exc, "response", None)
    if not isinstance(response, Mapping):
        return None, None, None
    err = response.get("Error") or {}
    code = err.get("Code") if isinstance(err, Mapping) else None
    message = err.get("Message") if isinstance(err, Mapping) else None
    meta = response.get("ResponseMetadata") or {}
    status = meta.get("HTTPStatusCode") if isinstance(meta, Mapping) else None
    return (
        str(code) if code else None,
        str(message) if message else None,
        status if isinstance(status, int) else None,
    )


def error_code(exc: BaseException) -> str | None:
    """Provider error code of ``exc`` (AWS ``Error.Code``, Azure ``error.code``)."""
    code, _, _ = _aws_error(exc)
    if code:
        return code
    err = getattr(exc, "error", None)
    azure_code = getattr(err, "code", None)
    if isinstance(azure_code, str) and azure_code:
        return azure_code
    code_attr = getattr(exc, "error_code", None)
    if isinstance(code_attr, str) and code_attr:
        return code_attr
    return None


def status_code(exc: BaseException) -> int | None:
    """HTTP status of ``exc`` across SDK shapes (None when there is none)."""
    _, _, aws_status = _aws_error(exc)
    if aws_status is not None:
        return aws_status
    for attr in ("status_code", "status"):
        value = getattr(exc, attr, None)
        if isinstance(value, int) and 100 <= value < 600:
            return value
    response = getattr(exc, "response", None)
    if response is not None and not isinstance(response, Mapping):
        for attr in ("status_code", "status"):
            value = getattr(response, attr, None)
            if isinstance(value, int) and 100 <= value < 600:
                return value
    # google.api_core exceptions and urllib HTTPError keep the status in .code
    code = getattr(exc, "code", None)
    value = getattr(code, "value", code)  # http.HTTPStatus
    if isinstance(value, int) and not isinstance(value, bool) and 100 <= value < 600:
        return value
    return None


def _headers_of(exc: BaseException) -> Iterable[Any]:
    """Every header mapping attached to ``exc`` (most specific first)."""
    response = getattr(exc, "response", None)
    if isinstance(response, Mapping):
        meta = response.get("ResponseMetadata") or {}
        headers = meta.get("HTTPHeaders") if isinstance(meta, Mapping) else None
        if headers:
            yield headers
    elif response is not None:
        headers = getattr(response, "headers", None)
        if headers is not None:
            yield headers
    headers = getattr(exc, "headers", None)  # urllib HTTPError, aiohttp
    if headers is not None:
        yield headers


def _header(headers: Any, name: str) -> str | None:
    """Case-insensitive header lookup on dicts, Message objects and CaseInsensitiveDicts."""
    getter = getattr(headers, "get", None)
    if getter is None:
        return None
    for key in (name, name.lower(), name.title()):
        try:
            value = getter(key)
        except Exception:
            value = None
        if value is not None:
            return str(value)
    try:
        for key, value in headers.items():
            if str(key).lower() == name.lower():
                return str(value)
    except Exception:
        return None
    return None


def parse_retry_after(value: Any, now: float | None = None) -> float | None:
    """Seconds to wait from a ``Retry-After``-style value.

    Accepts delta-seconds (``"120"``, ``"1.5"``), an HTTP-date
    (``"Wed, 21 Oct 2026 07:28:00 GMT"``) and ``hh:mm:ss`` durations (Azure
    Resource Graph's ``x-ms-user-quota-resets-after``). Returns None for
    anything unparseable; negative values clamp to 0.
    """
    if value is None:
        return None
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return max(0.0, float(value))
    text = str(value).strip()
    if not text:
        return None
    try:
        return max(0.0, float(text))
    except ValueError:
        pass
    m = re.fullmatch(r"(?:(\d+)\.)?(\d{1,2}):(\d{2}):(\d{2}(?:\.\d+)?)", text)
    if m:
        days, hours, minutes, seconds = m.groups()
        return int(days or 0) * 86400 + int(hours) * 3600 + int(minutes) * 60 + float(seconds)
    try:
        parsed = email.utils.parsedate_to_datetime(text)
    except (TypeError, ValueError, IndexError):
        return None
    if parsed is None:
        return None
    current = time.time() if now is None else now
    return max(0.0, parsed.timestamp() - current)


def _grpc_retry_delay(exc: BaseException) -> float | None:
    """google.rpc.RetryInfo ``retry_delay`` from api_core exception details."""
    for detail in getattr(exc, "details", None) or ():
        delay = getattr(detail, "retry_delay", None)
        if delay is None:
            continue
        seconds = getattr(delay, "seconds", None)
        nanos = getattr(delay, "nanos", 0) or 0
        if isinstance(seconds, (int, float)):
            return max(0.0, float(seconds) + float(nanos) / 1e9)
        total = getattr(delay, "total_seconds", None)
        if callable(total):
            return max(0.0, float(total()))
    return None


def _causes(exc: BaseException, depth: int = 4) -> Iterable[BaseException]:
    """``exc`` then its wrapped causes (api_core RetryError.cause, __cause__)."""
    seen: set[int] = set()
    current: BaseException | None = exc
    for _ in range(depth):
        if current is None or id(current) in seen:
            return
        seen.add(id(current))
        yield current
        nxt = getattr(current, "cause", None)
        if not isinstance(nxt, BaseException):
            nxt = current.__cause__  # explicit "raise ... from" only
        current = nxt


def retry_after(exc: BaseException, now: float | None = None) -> float | None:
    """The server-requested delay attached to ``exc``, in seconds, if any."""
    if isinstance(exc, ResilienceError) and exc.retry_after is not None:
        return exc.retry_after
    for err in _causes(exc):
        for headers in _headers_of(err):
            for name in ("retry-after-ms", "x-ms-retry-after-ms"):
                raw = _header(headers, name)
                if raw is not None:
                    parsed = parse_retry_after(raw, now)
                    if parsed is not None:
                        return parsed / 1000.0
            raw = _header(headers, "Retry-After")
            if raw is not None:
                parsed = parse_retry_after(raw, now)
                if parsed is not None:
                    return parsed
            # Resource Graph: quota resets after hh:mm:ss
            remaining = _header(headers, "x-ms-user-quota-remaining")
            resets = _header(headers, "x-ms-user-quota-resets-after")
            if resets is not None and (remaining in (None, "0") or status_code(err) == 429):
                parsed = parse_retry_after(resets, now)
                if parsed is not None:
                    return parsed
        delay = _grpc_retry_delay(err)
        if delay is not None:
            return delay
    return None


# ---------------------------------------------------------------------------
# Classification
# ---------------------------------------------------------------------------


def _classify_code(code: str, message: str | None, exc: BaseException) -> ErrorKind | None:
    """Kind from a provider error code (None: the code alone does not say)."""
    if code in AWS_THROTTLE_CODES or code in _AZURE_THROTTLE_CODES:
        return ErrorKind.THROTTLED
    if code in _AZURE_TRANSIENT_429_CODES:
        return ErrorKind.TRANSIENT
    if code == "LimitExceededException":
        text = f"{message or ''} {exc}"
        return ErrorKind.THROTTLED if _LIMIT_EXCEEDED_RATE_RE.search(text) else ErrorKind.FATAL
    if code in AWS_TRANSIENT_CODES:
        return ErrorKind.TRANSIENT
    return None


def _classify_shape(exc: BaseException, status: int | None) -> ErrorKind | None:
    """Kind from the exception's class hierarchy and HTTP status."""
    names = _mro_names(exc)
    if names & _GCP_THROTTLE_CLASSES:
        return ErrorKind.THROTTLED
    if status in _THROTTLE_STATUSES or status in _OVERLOAD_STATUSES:
        return ErrorKind.THROTTLED
    if names & _GCP_TRANSIENT_CLASSES or status in _TRANSIENT_STATUSES:
        return ErrorKind.TRANSIENT
    if names & _TRANSIENT_CLASSES or isinstance(exc, (ConnectionError, TimeoutError)):
        return ErrorKind.TRANSIENT
    return None


def _classify_one(exc: BaseException, use_text: bool = True) -> ErrorKind | None:
    if isinstance(exc, (CircuitOpenError, RetryBudgetExhaustedError)):
        return ErrorKind.THROTTLED
    if isinstance(exc, DeadlineExceededError):
        return ErrorKind.TRANSIENT

    code, message, _ = _aws_error(exc)
    code = code or error_code(exc)
    status = status_code(exc)
    kind = _classify_code(code, message, exc) if code else None
    if kind is None:
        kind = _classify_shape(exc, status)
    if kind is None and (status is not None or code):
        # A real provider answer that is neither throttling nor transient
        throttled = use_text and _THROTTLE_TEXT_RE.search(f"{message or ''} {exc}")
        kind = ErrorKind.THROTTLED if throttled else ErrorKind.FATAL
    return kind


def classify_strict(exc: BaseException) -> ErrorKind | None:
    """Like :func:`classify`, but from error codes, exception classes and
    HTTP statuses only (no message text matching); None when none of them
    says anything."""
    for err in _causes(exc):
        kind = _classify_one(err, use_text=False)
        if kind is not None:
            return kind
    return None


def is_provider_answer(exc: BaseException) -> bool:
    """True when ``exc`` carries a provider HTTP status or error code, i.e. the
    request reached the service and it answered (as opposed to errors
    raised locally, including cloudg's own :class:`ResilienceError`)."""
    return any(
        not isinstance(err, ResilienceError) and (status_code(err) is not None or error_code(err))
        for err in _causes(exc)
    )


def classify(exc: BaseException) -> ErrorKind:
    """THROTTLED, TRANSIENT or FATAL for any SDK / HTTP exception."""
    for err in _causes(exc):
        kind = _classify_one(err)
        if kind is not None:
            return kind
    try:
        text = str(exc)
    except Exception:
        text = ""
    if _THROTTLE_TEXT_RE.search(text):
        return ErrorKind.THROTTLED
    return ErrorKind.FATAL


def is_throttle(exc: BaseException) -> bool:
    return classify(exc) is ErrorKind.THROTTLED


def describe_error(exc: BaseException) -> str:
    """``str(exc)``, prefixed with ``throttled:`` when it is a throttling error,
    so coverage records show why a service was skipped."""
    text = str(exc) or type(exc).__name__
    if classify(exc) is ErrorKind.THROTTLED and not text.lower().startswith("throttled"):
        return f"throttled: {text}"
    return text
