"""Retry decorator with exponential backoff and jitter.

Backwards-compatible shim: :func:`with_retry` keeps its public signature and
behaviour, and now also retries anything :func:`cloudg.resilience.classify`
recognises as throttling / transient (Azure 429s, GCP ResourceExhausted,
botocore connection errors, ...) and never sleeps less than the server's
``Retry-After``. New code should use :mod:`cloudg.resilience`
(``call_with_resilience``), which adds shared adaptive rate limiting,
circuit breakers, retry budgets and telemetry.
"""

from __future__ import annotations

import asyncio
import logging
import random
from functools import wraps
from typing import Any, Callable, Type

from cloudg.resilience import (  # noqa: F401 (re-exported for callers of cloudg.retry)
    ErrorKind,
    RetryPolicy,
    Scope,
    call_with_resilience,
    call_with_resilience_sync,
    classify,
    retry_after,
)

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
    retry_exceptions = retryable_exceptions or RETRYABLE_EXCEPTIONS
    aws_codes = retryable_aws_codes or AWS_RETRYABLE_CODES

    def decorator(func: Callable) -> Callable:
        @wraps(func)
        async def wrapper(*args: Any, **kwargs: Any) -> Any:
            last_exception: Exception | None = None

            for attempt in range(1, max_attempts + 1):
                try:
                    return await func(*args, **kwargs)
                except Exception as exc:
                    last_exception = exc

                    # Check if this is a retryable exception
                    is_retryable = isinstance(exc, retry_exceptions)

                    # Check for AWS-specific error codes
                    if not is_retryable and hasattr(exc, "response"):
                        error_code = getattr(exc, "response", {}).get("Error", {}).get("Code", "")
                        is_retryable = error_code in aws_codes

                    # Also retry on botocore ClientError with retryable codes
                    if not is_retryable:
                        exc_str = str(exc)
                        is_retryable = any(code in exc_str for code in aws_codes)

                    # Provider-aware throttling / transient classification
                    if not is_retryable:
                        is_retryable = classify(exc) is not ErrorKind.FATAL

                    if not is_retryable or attempt == max_attempts:
                        raise

                    # Exponential backoff with full jitter
                    delay = min(max_delay, base_delay * (backoff_factor ** (attempt - 1)))
                    jitter = _jitter_rng.uniform(0, delay)
                    # Never retry sooner than the server asked (capped at max_delay)
                    actual_delay = max(jitter, min(retry_after(exc) or 0.0, max_delay))

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
