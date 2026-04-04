"""Retry decorator with exponential backoff and jitter."""

from __future__ import annotations

import asyncio
import logging
import random
from functools import wraps
from typing import Any, Callable, Type

logger = logging.getLogger(__name__)

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

                    if not is_retryable or attempt == max_attempts:
                        raise

                    # Exponential backoff with full jitter
                    delay = min(max_delay, base_delay * (backoff_factor ** (attempt - 1)))
                    jitter = random.uniform(0, delay)
                    actual_delay = jitter

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
