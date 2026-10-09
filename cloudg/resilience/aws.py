"""AWS integration: botocore event hooks feeding the shared governor.

:func:`install_aws_hooks` registers handlers on a boto3 / aioboto3
session's event emitter, so **every** client later created from that
session (``session.client("ec2")`` anywhere in the codebase, paginators
included) is covered without touching individual collectors:

- ``before-call``: fail fast when the circuit of the call's scope is open
  (per operation for EC2, per service otherwise), take a token from the
  shared adaptive limiter, then a slot of the account's concurrency
  bulkhead (``ratelimit.aws.max_concurrency``).
- ``needs-retry``: a throttled attempt cuts the scope's rate (AIMD) and
  honours Retry-After. Every retry botocore is about to make (throttled or
  transient) costs one token of the provider's retry budget
  (``ratelimit.aws.retry_budget``); when the budget is spent the hook
  raises RetryBudgetExhaustedError, which ends botocore's retry loop and
  is recorded as a throttled give-up. A throttled retry also waits for a
  fresh limiter token, on top of botocore's own backoff.
- ``after-call`` / ``after-call-error``: the bulkhead slot is released;
  success feeds additive recovery and closes breakers; a throttling error
  that survived botocore's retries counts toward the breaker and is
  recorded as "gave up" (stats + the collector task's
  :class:`~cloudg.resilience.stats.ThrottleLedger`, which turns its
  coverage PARTIAL). A slot whose call never reached these events (a
  cancelled task) is released when its request context is garbage
  collected.

Per-call deadlines stay botocore's job (``connect_timeout`` /
``read_timeout`` and its retry count); ``ratelimit.aws.deadline_seconds``
and ``ratelimit.aws.max_retries`` only apply to calls made through
:func:`cloudg.resilience.call_with_resilience`.

aiobotocore awaits coroutine handlers, so the async hooks never block the
event loop. Plain boto3 (used for STS / Organizations / Control Tower in
worker threads) gets blocking handlers; when such a call runs on an event
loop thread the limiter wait is capped at :data:`MAX_INLINE_WAIT` seconds.

botocore keeps doing the per-request retrying (mode / max_attempts from
``aws.retry_mode`` / ``aws.max_retries``): see :func:`botocore_retries`.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any

from cloudg.resilience.errors import (
    CircuitOpenError,
    ErrorKind,
    ResilienceError,
    RetryBudgetExhaustedError,
    classify,
    retry_after as server_retry_after,
)
from cloudg.resilience.governor import Governor, get_governor
from cloudg.resilience.limiter import Scope, Slot

try:
    from botocore.exceptions import ClientError as _ClientError
except ImportError:  # pragma: no cover - botocore is a core dependency
    _ClientError = None

__all__ = [
    "AWSCircuitOpenError",
    "AWSRetryBudgetExhaustedError",
    "MAX_INLINE_WAIT",
    "botocore_retries",
    "install_aws_hooks",
    "scope_for",
]

logger = logging.getLogger(__name__)

#: Max seconds a blocking boto3 call on an event loop thread waits for a token
MAX_INLINE_WAIT = 1.0

_SCOPE_KEY = "cloudg_scope"
_SLOT_KEY = "cloudg_bulkhead_slot"
_MARK = "_cloudg_resilience_hooks"


def _aws_flavour(base: type[ResilienceError]) -> type[ResilienceError]:
    """``base`` that is also a botocore ClientError (code ``Throttling``), so
    code calling instrumented clients inside ``except ClientError`` keeps
    working. Plain ``base`` when botocore is not importable."""
    if _ClientError is None:
        return base

    def __init__(
        self: Any, message: str, retry_after: float | None = None, scope: Any = None
    ) -> None:
        operation = getattr(scope, "operation", None) or "unknown"
        _ClientError.__init__(
            self, {"Error": {"Code": "Throttling", "Message": message}}, operation
        )
        self.retry_after = retry_after
        self.scope = scope

    doc = f"{base.__doc__} Also a botocore ClientError (code Throttling)."
    return type(f"AWS{base.__name__}", (base, _ClientError), {"__init__": __init__, "__doc__": doc})


#: CircuitOpenError raised by instrumented boto3 / aioboto3 clients
AWSCircuitOpenError = _aws_flavour(CircuitOpenError)
#: RetryBudgetExhaustedError raised by instrumented boto3 / aioboto3 clients
AWSRetryBudgetExhaustedError = _aws_flavour(RetryBudgetExhaustedError)


def botocore_retries(governor: Governor | None = None) -> dict[str, Any]:
    """``retries`` dict for botocore/aiobotocore Config from ``aws.retry_mode`` /
    ``aws.max_retries`` (defaults: adaptive mode, 10 retries after the first
    attempt; botocore reads ``max_attempts`` as the retry count)."""
    gov = governor or get_governor()
    return {"mode": gov.aws_retry_mode, "max_attempts": gov.aws_max_attempts}


class _ParsedError(Exception):
    """A botocore parsed error response, shaped for :func:`classify`."""

    def __init__(self, parsed: dict[str, Any]) -> None:
        err = parsed.get("Error") or {}
        super().__init__(f"{err.get('Code', '')}: {err.get('Message', '')}")
        self.response = parsed


def scope_for(model: Any, context: Any, account: str | None, default_region: str | None) -> Scope:
    """The Scope of a botocore operation call."""
    service = None
    operation = getattr(model, "name", None)
    service_model = getattr(model, "service_model", None)
    if service_model is not None:
        service = getattr(service_model, "service_name", None) or getattr(
            service_model, "endpoint_prefix", None
        )
    region = None
    if isinstance(context, dict):
        region = context.get("client_region")
    return Scope("aws", account or None, region or default_region, service, operation)


def _response_kind(response: Any, caught: BaseException | None) -> tuple[ErrorKind | None, Any]:
    """(kind, error) of a needs-retry attempt; kind None for a 2xx/3xx answer."""
    if caught is not None:
        return classify(caught), caught
    if not isinstance(response, (tuple, list)) or len(response) < 2:
        return None, None
    http, parsed = response[0], response[1]
    status = getattr(http, "status_code", 200) or 200
    if status < 300 or not isinstance(parsed, dict):
        return None, None
    err = _ParsedError(parsed)
    return classify(err), err


def _on_loop_thread() -> bool:
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return False
    return True


class _Hooks:
    def __init__(self, account: str | None, region: str | None, governor: Governor | None):
        self.account = account
        self.region = region
        self._governor = governor

    @property
    def gov(self) -> Governor:
        return self._governor or get_governor()

    def _scope(self, model: Any, context: Any) -> Scope | None:
        try:
            scope = scope_for(model, context, self.account, self.region)
        except Exception:  # pragma: no cover - defensive
            return None
        if isinstance(context, dict):
            context[_SCOPE_KEY] = scope
        return scope

    @staticmethod
    def _stored(request_dict: Any = None, context: Any = None) -> Scope | None:
        if context is None and isinstance(request_dict, dict):
            context = request_dict.get("context")
        if isinstance(context, dict):
            scope = context.get(_SCOPE_KEY)
            return scope if isinstance(scope, Scope) else None
        return None

    def _admit(self, model: Any, context: Any) -> Scope | None:
        gov = self.gov
        if not gov.provider_enabled("aws"):
            return None
        scope = self._scope(model, context)
        if scope is None:
            return None
        try:
            gov.check(scope)
        except CircuitOpenError as exc:  # propagates out of the API call
            raise AWSCircuitOpenError(str(exc), exc.retry_after, exc.scope) from None
        gov.record_call(scope)
        return scope

    def _feedback(
        self, response: Any, caught: Any, request_dict: Any
    ) -> tuple[Scope | None, ErrorKind | None, Any]:
        """Record a throttled / transient attempt; returns (scope, kind, error)."""
        scope = self._stored(request_dict=request_dict)
        if scope is None:
            return None, None, None
        kind, err = _response_kind(response, caught)
        if kind is ErrorKind.THROTTLED and err is not None:
            self.gov.on_throttle(scope, server_retry_after(err), str(err)[:300])
        elif kind is ErrorKind.TRANSIENT and err is not None:
            self.gov.record_transient(scope, str(err)[:300])
        return scope, kind, err

    def _retry_allowed(self, scope: Scope, kind: ErrorKind | None, err: Any, attempts: Any) -> bool:
        """True when botocore will retry and the retry budget allows it.

        Raises RetryBudgetExhaustedError (which stops botocore's retry loop
        and surfaces as a throttled failure) when the budget is spent.
        """
        if kind not in (ErrorKind.THROTTLED, ErrorKind.TRANSIENT) or not self._more_attempts(
            attempts
        ):
            return False
        if not self.gov.try_retry(scope, attempts):
            raise AWSRetryBudgetExhaustedError(
                f"retry budget of {scope.provider} exhausted; not retrying "
                f"{scope.operation}: {str(err)[:150]}",
                scope=scope,
            )
        self.gov.record_retry(scope)
        return True

    def _throttled_retry(
        self,
        response: Any = None,
        caught_exception: Any = None,
        attempts: Any = None,
        request_dict: Any = None,
        **_: Any,
    ) -> Scope | None:
        """needs-retry feedback shared by the sync and async hooks.

        Records the attempt's outcome and charges the retry budget; returns
        the scope when botocore will retry a throttled call (the retry then
        needs a limiter token), else None.
        """
        scope, kind, err = self._feedback(response, caught_exception, request_dict)
        if scope is None or not self._retry_allowed(scope, kind, err, attempts):
            return None
        return scope if kind is ErrorKind.THROTTLED else None

    @staticmethod
    def _release(context: Any) -> None:
        if isinstance(context, dict):
            slot = context.pop(_SLOT_KEY, None)
            if isinstance(slot, Slot):
                slot.release()

    def after_call(
        self, http_response: Any = None, parsed: Any = None, context: Any = None, **_: Any
    ) -> None:
        self._release(context)
        scope = self._stored(context=context)
        if scope is None:
            return
        status = getattr(http_response, "status_code", 200) or 200
        if status < 300:
            self.gov.on_success(scope)
        elif isinstance(parsed, dict):
            err = _ParsedError(parsed)
            self.gov.on_final_error(scope, err, f"{scope.operation} (retries exhausted)")

    def after_call_error(self, exception: Any = None, context: Any = None, **_: Any) -> None:
        self._release(context)
        scope = self._stored(context=context)
        if scope is not None and isinstance(exception, BaseException):
            self.gov.on_final_error(scope, exception, str(scope.operation))

    def _more_attempts(self, attempts: Any) -> bool:
        # botocore's retries.max_attempts counts retries after the first attempt
        return isinstance(attempts, int) and attempts <= self.gov.aws_max_attempts


class _AsyncHooks(_Hooks):
    async def before_call(self, model: Any = None, context: Any = None, **_: Any) -> None:
        scope = self._admit(model, context)
        if scope is not None:
            gov = self.gov
            await gov.limiter.acquire(scope)
            bulkhead = gov.limiter.bulkhead(scope)
            await bulkhead.acquire()
            if isinstance(context, dict):
                slot = context[_SLOT_KEY] = Slot(bulkhead)
                # after-call-error does not fire for a cancelled call
                slot.bind_to_current_task()
            else:  # pragma: no cover - botocore always passes a dict
                bulkhead.release()
        return None

    async def needs_retry(self, **kwargs: Any) -> None:
        scope = self._throttled_retry(**kwargs)
        if scope is not None:
            await self.gov.limiter.acquire(scope)  # the retry needs a token too
        return None


class _SyncHooks(_Hooks):
    def _acquire(self, scope: Scope) -> None:
        cap = MAX_INLINE_WAIT if _on_loop_thread() else None
        self.gov.limiter.acquire_sync(scope, max_wait=cap)

    def before_call(self, model: Any = None, context: Any = None, **_: Any) -> None:
        scope = self._admit(model, context)
        if scope is not None:
            self._acquire(scope)
            bulkhead = self.gov.limiter.bulkhead(scope)
            if _on_loop_thread():
                # Never block an event loop thread: take a slot only if free
                acquired = bulkhead.try_acquire()
            else:
                bulkhead.acquire_sync()
                acquired = True
            if acquired:
                if isinstance(context, dict):
                    context[_SLOT_KEY] = Slot(bulkhead)
                else:  # pragma: no cover - botocore always passes a dict
                    bulkhead.release()
        return None

    def needs_retry(self, **kwargs: Any) -> None:
        scope = self._throttled_retry(**kwargs)
        if scope is not None:
            self._acquire(scope)  # the retry needs a token too
        return None


def _botocore_session(session: Any) -> Any:
    """The botocore (or aiobotocore) session behind a boto3/aioboto3 session."""
    inner = getattr(session, "_session", None)
    if inner is not None and hasattr(inner, "register"):
        return inner
    return session if hasattr(session, "register") else None


def install_aws_hooks(
    session: Any,
    account_id: str | None = None,
    region: str | None = None,
    *,
    governor: Governor | None = None,
    default_config: Any = None,
) -> bool:
    """Wire a boto3 / aioboto3 session into the governor (idempotent).

    Clients created from ``session`` afterwards are rate limited, circuit
    broken and report throttling. ``default_config`` (a botocore/aiobotocore
    Config) becomes the session's default client config when it has none,
    so clients created without ``config=`` still get the configured retries.

    Returns:
        True when hooks were installed now, False when already present or
        the session has no event system (fakes in tests).
    """
    core = _botocore_session(session)
    if core is None or getattr(core, _MARK, False):
        return False
    asynchronous = type(core).__module__.startswith("aiobotocore")
    hooks: _Hooks = (
        _AsyncHooks(account_id, region, governor)
        if asynchronous
        else _SyncHooks(account_id, region, governor)
    )
    try:
        core.register("before-call", hooks.before_call, unique_id="cloudg-resilience-before-call")  # type: ignore[attr-defined]
        core.register("needs-retry", hooks.needs_retry, unique_id="cloudg-resilience-needs-retry")  # type: ignore[attr-defined]
        core.register("after-call", hooks.after_call, unique_id="cloudg-resilience-after-call")
        core.register(
            "after-call-error", hooks.after_call_error, unique_id="cloudg-resilience-after-error"
        )
        if default_config is not None:
            getter = getattr(core, "get_default_client_config", None)
            setter = getattr(core, "set_default_client_config", None)
            if setter is not None and (getter is None or getter() is None):
                setter(default_config)
        setattr(core, _MARK, True)
    except Exception as exc:  # never let instrumentation break auth/collection
        logger.debug("Could not install AWS resilience hooks: %s", exc)
        return False
    return True
