"""Retry decorator with exponential backoff and jitter.

Backwards-compatible shim: :func:`with_retry` keeps its public signature and
behaviour, and now also retries provider answers that
:func:`cloudg.resilience.classify_strict` recognises as throttling from
their error code, exception class or HTTP status (Azure 429s, GCP
ResourceExhausted, ...; never from message text alone), and never sleeps
less than the server's ``Retry-After``. cloudg's own resilience errors
(an open circuit, a spent retry budget, a missed deadline) are re-raised at
once. New code should use :mod:`cloudg.resilience`
(``call_with_resilience``), which adds shared adaptive rate limiting,
circuit breakers, retry budgets and telemetry.
"""

from __future__ import annotations

import asyncio
import logging
import random
from functools import wraps
from typing import Any, Callable, Type

# RetryPolicy, Scope and the call_with_resilience pair are re-exported for
# callers of cloudg.retry (listed in __all__)
from cloudg.resilience import (
    ErrorKind,
    ResilienceError,
    RetryPolicy,
    Scope,
    call_with_resilience,
    call_with_resilience_sync,
    classify,
    classify_strict,
    is_provider_answer,
    retry_after,
)

__all__ = [
    "AWS_RETRYABLE_CODES",
    "ErrorKind",
    "RETRYABLE_EXCEPTIONS",
    "RetryPolicy",
    "Scope",
    "call_with_resilience",
    "call_with_resilience_sync",
    "classify",
    "retry_after",
    "with_retry",
]

logger = logging.getLogger(__name__)

# System RNG: jitter is not cryptographic, but this also satisfies Bandit B311
_jitter_rng = random.SystemRandom()

# Default retryable exception types
RETRYABLE_EXCEPTIONS: tuple[Type[Exception], ...] = (
    ConnectionError,
    TimeoutError,
    OSError,
)

# AWS-specific retryable error codes
AWS_RETRYABLE_CODES = {
    "ThrottlingException",
    "TooManyRequestsException",
    "RequestLimitExceeded",
    "ProvisionedThroughputExceededException",
    "ServiceUnavailable",
    "InternalError",
}


def _is_retryable(
    exc: Exception, retry_exceptions: tuple[Type[Exception], ...], aws_codes: set[str]
) -> bool:
    """The retry decision of :func:`with_retry` for one error."""
    if isinstance(exc, ResilienceError):
        return False  # cloudg already decided: circuit open, budget spent, deadline
    if isinstance(exc, retry_exceptions):
        return True
    # AWS-specific error codes, from the response or (for wrapped errors) the text
    response = getattr(exc, "response", None)
    if isinstance(response, dict):
        if response.get("Error", {}).get("Code", "") in aws_codes:
            return True
    exc_str = str(exc)
    if any(code in exc_str for code in aws_codes):
        return True
    # Provider-aware throttling, only for real provider answers
    return is_provider_answer(exc) and classify_strict(exc) is ErrorKind.THROTTLED


def _backoff_delay(
    exc: Exception, attempt: int, base_delay: float, max_delay: float, backoff_factor: float
) -> float:
    """Seconds to wait before retry ``attempt`` of :func:`with_retry`."""
    # Exponential backoff with full jitter
    delay = min(max_delay, base_delay * (backoff_factor ** (attempt - 1)))
    jitter = _jitter_rng.uniform(0, delay)
    # Never retry sooner than the server asked (capped at max_delay)
    return max(jitter, min(retry_after(exc) or 0.0, max_delay))


def _retry_decorator(
    max_attempts: int,
    base_delay: float,
    max_delay: float,
    backoff_factor: float,
    retry_exceptions: tuple[Type[Exception], ...],
    aws_codes: set[str],
) -> Callable:
    """Build the decorator :func:`with_retry` returns."""

    def decorator(func: Callable) -> Callable:
        @wraps(func)
        async def wrapper(*args: Any, **kwargs: Any) -> Any:
            last_exception: Exception | None = None

            for attempt in range(1, max_attempts + 1):
                try:
                    return await func(*args, **kwargs)
                except Exception as exc:
                    last_exception = exc
                    if attempt == max_attempts or not _is_retryable(
                        exc, retry_exceptions, aws_codes
                    ):
                        raise

                    actual_delay = _backoff_delay(
                        exc, attempt, base_delay, max_delay, backoff_factor
                    )
                    logger.warning(
                        "Retry %d/%d for %s after %.1fs (error: %s)",
                        attempt,
                        max_attempts,
                        func.__name__,
                        actual_delay,
                        str(exc)[:200],
                    )
                    await asyncio.sleep(actual_delay)

            # Should not reach here, but just in case
            if last_exception:
                raise last_exception

        return wrapper

    return decorator


def with_retry(
    max_attempts: int = 5,
    base_delay: float = 1.0,
    max_delay: float = 60.0,
    backoff_factor: float = 2.0,
    retryable_exceptions: tuple[Type[Exception], ...] | None = None,
    retryable_aws_codes: set[str] | None = None,
) -> Callable:
    """Decorator for async functions with exponential backoff retry.

    Args:
        max_attempts: Maximum number of attempts (including initial).
        base_delay: Initial delay in seconds.
        max_delay: Maximum delay cap in seconds.
        backoff_factor: Multiplier for each retry delay.
        retryable_exceptions: Exception types to retry on.
        retryable_aws_codes: AWS error codes to retry on.

    Returns:
        Decorated async function.
    """
    return _retry_decorator(
        max_attempts,
        base_delay,
        max_delay,
        backoff_factor,
        retryable_exceptions or RETRYABLE_EXCEPTIONS,
        retryable_aws_codes or AWS_RETRYABLE_CODES,
    )
