"""GCP integration: google-api-core Retry wired to the shared governor.

- :func:`gcp_retry` builds the ``google.api_core.retry.Retry`` used for
  every Cloud Asset Inventory call: it retries ``RESOURCE_EXHAUSTED`` (429),
  ``UNAVAILABLE``, ``DEADLINE_EXCEEDED`` and ``INTERNAL`` with exponential
  backoff (initial 1s, x2, capped at ``ratelimit.gcp.max_backoff_seconds``,
  overall ``deadline_seconds``) and reports every retried error to the
  governor (throttles cut the scope's rate; ``RetryInfo`` delays pause it).
- :func:`paced` wraps a paged result so a limiter token is taken before
  each further page is fetched (pages are fetched lazily while iterating),
  keeping org-wide listings under the per-minute quotas.
"""

from __future__ import annotations

import re
from typing import Any, Iterable, Iterator

from cloudg.resilience.errors import ErrorKind, RetryBudgetExhaustedError, classify, retry_after
from cloudg.resilience.governor import Governor, RetrySettings, get_governor
from cloudg.resilience.limiter import Scope

__all__ = ["RetryCounter", "gcp_retry", "gcp_scope", "operation_name", "paced"]


def operation_name(method: Any) -> str | None:
    """``list_assets`` -> ``ListAssets`` (the RPC name quotas are keyed by)."""
    name = getattr(method, "__name__", None) or getattr(
        getattr(method, "__func__", None), "__name__", None
    )
    if not name:
        return None
    return "".join(part.capitalize() for part in str(name).strip("_").split("_"))


def gcp_scope(parent: str | None, service: str = "cloudasset", method: Any = None) -> Scope:
    """Scope of a GCP API call on ``parent`` (``projects/x`` / ``organizations/1``)."""
    account = None
    if parent:
        m = re.match(r"(projects|organizations|folders)/([^/]+)", str(parent))
        account = f"{m.group(1)}/{m.group(2)}" if m else str(parent)
    op = operation_name(method) if method is not None and not isinstance(method, str) else method
    return Scope("gcp", account, None, service, op)


class RetryCounter:
    """Consecutive retries of one paged listing (reset by :func:`paced` on
    every page that arrives)."""

    __slots__ = ("count",)

    def __init__(self) -> None:
        self.count = 0


def _report_gcp_retry(
    exc: Exception,
    scope: Scope | None,
    gov: Governor,
    settings: RetrySettings,
    tally: RetryCounter,
) -> None:
    """``on_error`` body of :func:`gcp_retry`: report ``exc`` and spend a retry.

    Raises RetryBudgetExhaustedError (chained to ``exc``) once ``settings.max_retries``
    consecutive retries were made or the provider's retry budget is empty.
    """
    if scope is None:
        return
    kind = classify(exc)
    if kind is ErrorKind.THROTTLED:
        gov.on_throttle(scope, retry_after(exc), str(exc)[:300])
    elif kind is ErrorKind.TRANSIENT:
        gov.record_transient(scope, str(exc)[:300])
    if not gov.provider_enabled("gcp"):
        gov.record_retry(scope)
        return
    tally.count += 1
    if tally.count > settings.max_retries:
        raise RetryBudgetExhaustedError(
            f"{scope.operation}: {settings.max_retries} consecutive retries exhausted: "
            f"{str(exc)[:150]}",
            scope=scope,
        ) from exc
    if not gov.try_retry(scope, tally.count):
        raise RetryBudgetExhaustedError(
            f"retry budget of gcp exhausted; not retrying {scope.operation}: {str(exc)[:150]}",
            scope=scope,
        ) from exc
    gov.record_retry(scope)


def gcp_retry(
    scope: Scope | None = None,
    *,
    governor: Governor | None = None,
    initial: float = 1.0,
    multiplier: float = 2.0,
    counter: RetryCounter | None = None,
) -> Any:
    """An api_core Retry reporting to the governor (None without google-api-core).

    Besides api_core's time limit (``deadline_seconds``), each retry costs a
    token of the provider's retry budget (``retry_budget``) and at most
    ``max_retries`` consecutive retries are made (counted per page when a
    ``counter`` shared with :func:`paced` is given). Past either limit the
    ``on_error`` hook raises RetryBudgetExhaustedError (chained to the
    provider error), which ends api_core's retry loop.
    """
    try:
        from google.api_core import exceptions as gexc
        from google.api_core import retry as retries
    except ImportError:
        return None
    gov = governor or get_governor()
    settings = gov.retry_settings("gcp")
    tally = counter if counter is not None else RetryCounter()

    def on_error(exc: Exception) -> None:
        _report_gcp_retry(exc, scope, gov, settings, tally)

    return retries.Retry(
        predicate=retries.if_exception_type(
            gexc.ResourceExhausted,
            gexc.ServiceUnavailable,
            gexc.DeadlineExceeded,
            gexc.InternalServerError,
        ),
        initial=initial,
        maximum=settings.max_backoff,
        multiplier=multiplier,
        timeout=settings.deadline,
        on_error=on_error,
    )


def paced(
    items: Iterable[Any],
    scope: Scope,
    page_size: int | None,
    *,
    governor: Governor | None = None,
    counter: RetryCounter | None = None,
) -> Iterator[Any]:
    """Yield ``items``, taking a limiter token before each further page.

    Pagers fetch the next page when the previous one is exhausted, so a
    token is taken every ``page_size`` items, just before that fetch.
    Approximate when the server returns short pages (it never under-counts
    by more than one page per short page). Further pages are rate limited
    only: the breaker was checked once for the whole listing, so a listing
    that is a half-open breaker's probe is not rejected by its own breaker.
    """
    gov = governor or get_governor()
    iterator = iter(items)
    count = 0
    every = page_size if page_size and page_size > 0 else 0
    while True:
        if every and count and count % every == 0 and gov.provider_enabled("gcp"):
            gov.limiter.acquire_sync(scope)
            gov.record_call(scope)
        try:
            item = next(iterator)
        except StopIteration:
            return
        count += 1
        if counter is not None and every and (count - 1) % every == 0:
            counter.count = 0  # a page arrived: retries are counted per page
        yield item
