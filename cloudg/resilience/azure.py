"""Azure integration: azure-core retry settings plus a throttling policy.

:func:`azure_client_kwargs` returns keyword arguments for any azure-mgmt /
azure-core client constructor:

- ``retry_policy``: an azure-core RetryPolicy (which honours
  ``Retry-After`` on 429/503) with ``retry_total`` / ``retry_status`` =
  ``ratelimit.azure.max_retries`` (azure-core's default allows only 3
  status retries), ``retry_backoff_max`` = ``max_backoff_seconds`` and the
  total operation ``timeout`` = ``deadline_seconds``.
- ``per_retry_policies=[AzureThrottlePolicy]``: runs around *every* HTTP
  attempt (after the retry policy):

  - open circuits fail fast (``breaker_threshold`` /
    ``breaker_cooldown_seconds``);
  - each attempt takes a token from the shared limiter (subscription
    aggregate ``account_max_rps`` + resource-provider leaf; Resource Graph
    per user) and a slot of the subscription's concurrency bulkhead
    (``max_concurrency``), released on the response or the exception;
  - 429/503 responses cut the scope's rate and pause it for Retry-After;
  - every 429/503/408/500/502/504 response costs one token of the
    provider's retry budget (``retry_budget``); when it is spent the policy
    raises RetryBudgetExhaustedError, which ends azure-core's retry loop
    and is reported as throttling. The token is taken even on the last
    attempt, which azure-core would not retry;
  - the quota headers are read proactively: ``x-ms-user-quota-remaining:
    0`` (Resource Graph) pauses the resourcegraph scope for
    ``x-ms-user-quota-resets-after``, and a
    ``x-ms-ratelimit-remaining-subscription-reads`` below
    :data:`LOW_REMAINING_READS` pauses the subscription's aggregate bucket
    (every call of that subscription) for one second, before ARM starts
    returning 429.

:func:`build_azure_client` constructs a client with those kwargs and falls
back to a plain construction for clients (or test fakes) that reject them.
"""

from __future__ import annotations

import asyncio
import logging
import re
from typing import Any, Callable
from urllib.parse import urlsplit

from cloudg.resilience.errors import RetryBudgetExhaustedError, parse_retry_after
from cloudg.resilience.governor import Governor, get_governor
from cloudg.resilience.limiter import Scope, Slot

__all__ = [
    "azure_client_kwargs",
    "azure_scope",
    "azure_scope_of_error",
    "build_azure_client",
    "throttle_policy",
]

logger = logging.getLogger(__name__)

_SUB_RE = re.compile(r"/subscriptions/([0-9a-fA-F-]{36})", re.IGNORECASE)
_NS_RE = re.compile(r"/providers/Microsoft\.([A-Za-z0-9.]+)", re.IGNORECASE)

#: Below this many remaining subscription reads, ARM is about to throttle
LOW_REMAINING_READS = 25

_SLOT_KEY = "cloudg_bulkhead_slot"
_THROTTLE_STATUSES = frozenset({429, 503})
_TRANSIENT_STATUSES = frozenset({408, 500, 502, 504})
#: Longest limiter sleep on an event loop thread (the token is still taken), as for AWS
MAX_INLINE_WAIT = 1.0


def _on_loop_thread() -> bool:
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return False
    return True


def azure_scope(url: str | None, subscription_id: str | None = None) -> Scope:
    """Scope of an ARM request URL (subscription x resource-provider namespace).

    Resource Graph is scoped per user (no subscription), matching its quota.
    """
    path = urlsplit(str(url or "")).path
    namespaces = _NS_RE.findall(path)
    # Paths without a provider namespace (subscriptions, resource groups,
    # generic resource listing) are served by Microsoft.Resources.
    service = namespaces[-1].lower() if namespaces else "resources"
    if service == "resourcegraph":
        return Scope("azure", None, None, "resourcegraph")
    m = _SUB_RE.search(path)
    account = m.group(1).lower() if m else (subscription_id.lower() if subscription_id else None)
    return Scope("azure", account, None, service)


def azure_scope_of_error(exc: BaseException, subscription_id: str | None, fallback: str) -> Scope:
    """Scope of an azure-core HttpResponseError (from its request URL)."""
    response = getattr(exc, "response", None)
    request = getattr(response, "request", None)
    url = getattr(request, "url", None)
    if url:
        return azure_scope(str(url), subscription_id)
    return Scope("azure", subscription_id.lower() if subscription_id else None, None, fallback)


def _header(headers: Any, name: str) -> str | None:
    try:
        value = headers.get(name)
    except Exception:
        return None
    return None if value is None else str(value)


def _context_get(request: Any, key: str) -> Any:
    try:
        return request.context.get(key)
    except Exception:  # a request without a usable context carries nothing
        return None


def _status_hint(headers: Any) -> float | None:
    """Server-requested delay of a 429/503 (Retry-After, else the quota reset)."""
    hint = parse_retry_after(_header(headers, "Retry-After"))
    if hint is None:
        resets = _header(headers, "x-ms-user-quota-resets-after")
        hint = parse_retry_after(resets) if resets else None
    return hint


def _on_retryable_status(gov: Governor, scope: Scope, status: int, headers: Any) -> None:
    """Feedback for a 429/503 (throttling) or 408/5xx (transient) answer.

    azure-core's RetryPolicy retries these: each retry costs a token of the
    provider's retry budget; when it is spent, raising here ends the retry
    loop.
    """
    message = f"HTTP {status} from Azure {scope.service}"
    if status in _THROTTLE_STATUSES:
        gov.on_throttle(scope, _status_hint(headers), message)
    else:
        gov.record_transient(scope, message)
    if not gov.try_retry(scope):
        raise RetryBudgetExhaustedError(
            f"retry budget of azure exhausted; not retrying HTTP {status} from {scope.service}",
            scope=scope,
        )
    gov.record_retry(scope)


def _remaining_reads(headers: Any) -> int | None:
    reads = _header(headers, "x-ms-ratelimit-remaining-subscription-reads")
    if reads is None:
        return None
    try:
        return int(reads)
    except ValueError:
        return None


def _slow_down_from_quota_headers(gov: Governor, scope: Scope, headers: Any) -> None:
    """Proactive slow-down from the quota headers of a successful answer."""
    remaining = _header(headers, "x-ms-user-quota-remaining")
    if remaining is not None and remaining.strip() == "0":
        resets = parse_retry_after(_header(headers, "x-ms-user-quota-resets-after"))
        if resets:
            gov.limiter.pause(scope, resets)
    left = _remaining_reads(headers)
    if left is not None and left < LOW_REMAINING_READS and scope.account:
        # The ARM bucket is per subscription and refills ~25 tokens/s: pause
        # every call of the subscription (its aggregate bucket) for a second.
        gov.limiter.pause(scope, 1.0, level="account")


def _take_slot(gov: Governor, scope: Scope) -> Slot | None:
    """A slot of the subscription's bulkhead (None when none is free and
    waiting would block an event loop thread)."""
    bulkhead = gov.limiter.bulkhead(scope)
    if _on_loop_thread():
        # Never block an event loop thread: take a slot only if free
        return Slot(bulkhead) if bulkhead.try_acquire() else None
    bulkhead.acquire_sync()
    return Slot(bulkhead)


class _ThrottleHooks:
    """Per-attempt limiter / breaker / throttle feedback (see module docs).

    Independent of azure-core; :func:`_make_policy_class` mixes it into a
    ``SansIOHTTPPolicy`` when azure-core is installed.
    """

    def __init__(self, subscription_id: str | None, governor: Governor | None) -> None:
        super().__init__()
        self._subscription_id = subscription_id
        self._governor = governor

    @property
    def gov(self) -> Governor:
        return self._governor or get_governor()

    def on_request(self, request: Any) -> None:
        gov = self.gov
        if not gov.provider_enabled("azure"):
            return
        scope = azure_scope(getattr(request.http_request, "url", None), self._subscription_id)
        context = getattr(request, "context", None)
        try:
            context["cloudg_scope"] = scope
        except Exception:  # no usable context: limit the call, keep no state
            context = None
        gov.check(scope)
        gov.record_call(scope)
        gov.limiter.acquire_sync(scope, max_wait=MAX_INLINE_WAIT if _on_loop_thread() else None)
        slot = _take_slot(gov, scope)
        if slot is None:
            return
        try:
            context[_SLOT_KEY] = slot
        except Exception:  # nowhere to keep it until the response: give it back
            slot.release()

    @staticmethod
    def _release(request: Any) -> None:
        try:
            slot = request.context.pop(_SLOT_KEY, None)
        except Exception:  # a request without a usable context holds no slot
            slot = None
        if isinstance(slot, Slot):
            slot.release()

    def on_exception(self, request: Any) -> None:
        self._release(request)

    def on_response(self, request: Any, response: Any) -> None:
        self._release(request)
        scope = _context_get(request, "cloudg_scope")
        if not isinstance(scope, Scope):
            return
        http = getattr(response, "http_response", None)
        status = getattr(http, "status_code", 200) or 200
        headers = getattr(http, "headers", None) or {}
        if status in _THROTTLE_STATUSES or status in _TRANSIENT_STATUSES:
            _on_retryable_status(self.gov, scope, status, headers)
        elif status < 400:
            self.gov.on_success(scope)
            _slow_down_from_quota_headers(self.gov, scope, headers)


def _make_policy_class() -> type | None:
    try:
        from azure.core.pipeline.policies import SansIOHTTPPolicy
    except ImportError:
        return None

    class AzureThrottlePolicy(_ThrottleHooks, SansIOHTTPPolicy):  # type: ignore[misc,valid-type]
        """Per-attempt limiter / breaker / throttle feedback (see module docs)."""

    return AzureThrottlePolicy


_POLICY_CLASS: type | None = None
_POLICY_RESOLVED = False


def throttle_policy(subscription_id: str | None = None, governor: Governor | None = None) -> Any:
    """An AzureThrottlePolicy instance (None when azure-core is not installed)."""
    global _POLICY_CLASS, _POLICY_RESOLVED
    if not _POLICY_RESOLVED:
        _POLICY_CLASS = _make_policy_class()
        _POLICY_RESOLVED = True
    if _POLICY_CLASS is None:
        return None
    return _POLICY_CLASS(subscription_id, governor)


def azure_client_kwargs(
    subscription_id: str | None = None, *, governor: Governor | None = None
) -> dict[str, Any]:
    """Constructor kwargs adding cloudg's retry settings and throttling policy."""
    gov = governor or get_governor()
    if not gov.provider_enabled("azure"):
        return {}
    settings = gov.retry_settings("azure")
    retry = {
        "retry_total": settings.max_retries,
        "retry_status": settings.max_retries,
        "retry_backoff_max": max(1, int(settings.max_backoff)),
        "timeout": max(1, int(settings.deadline)),
    }
    try:
        from azure.core.pipeline.policies import RetryPolicy as AzureRetryPolicy
    except ImportError:
        return {}
    kwargs: dict[str, Any] = {"retry_policy": AzureRetryPolicy(**retry)}
    policy = throttle_policy(subscription_id, governor)
    if policy is not None:
        kwargs["per_retry_policies"] = [policy]
    return kwargs


def build_azure_client(
    cls: Callable[..., Any],
    *args: Any,
    subscription_id: str | None = None,
    governor: Governor | None = None,
    **kwargs: Any,
) -> Any:
    """``cls(*args, **kwargs)`` plus :func:`azure_client_kwargs`.

    Falls back to the plain construction when ``cls`` rejects the extra
    keyword arguments (old SDKs, test doubles).
    """
    extra = azure_client_kwargs(subscription_id, governor=governor)
    if extra:
        try:
            client = cls(*args, **kwargs, **extra)
            try:
                setattr(client, "_cloudg_throttle_policy", True)
            except (AttributeError, TypeError) as exc:  # __slots__ or frozen clients
                logger.debug("Could not mark %s as throttle-policy aware: %s", cls, exc)
            return client
        except TypeError as exc:
            logger.debug("%s rejected resilience kwargs (%s); building it plainly", cls, exc)
    return cls(*args, **kwargs)
