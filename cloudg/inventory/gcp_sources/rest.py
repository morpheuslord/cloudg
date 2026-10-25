"""Minimal REST client for the Google APIs Cloud Asset Inventory does not cover.

Built on google-auth's ``AuthorizedSession`` (requests), which the ``gcp``
extra already installs. The session is injectable, so tests hand in a fake
transport and never touch the network.

Every request goes through cloudg's resilience governor (rate limiter,
circuit breaker, retry budget) under the scope ``gcp / <parent> / <api>``,
and throttling (429) or unavailability (500, 502, 503, 504) is retried
with exponential backoff that honours ``Retry-After``.
"""

from __future__ import annotations

import logging
import time
from typing import Any, Callable

from cloudg.exceptions import CollectionError, CredentialError, ProviderSDKMissingError
from cloudg.resilience.gcp import gcp_scope
from cloudg.resilience.governor import get_governor

logger = logging.getLogger(__name__)

_RETRY_STATUSES = {429, 500, 502, 503, 504}
_DISABLED_REASONS = {"SERVICE_DISABLED", "accessNotConfigured", "API_DISABLED"}


class GCPApiError(CollectionError):
    """A Google API answered with an error status.

    Attributes:
        status_code: HTTP status.
        error_code: ``error.status`` (``PERMISSION_DENIED``, ``NOT_FOUND`` ...) or
            the first ``reason`` of the error details.
        url: Request URL without the query string.
    """

    def __init__(self, status_code: int, error_code: str | None, message: str, url: str) -> None:
        self.status_code = status_code
        self.error_code = error_code
        self.url = url
        self.reasons: set[str] = set()
        super().__init__(f"HTTP {status_code} {error_code or ''} from {url}: {message}".strip())

    @property
    def disabled(self) -> bool:
        """The API is not enabled in the project (the service is not in use)."""
        text = str(self)
        return bool(self.reasons & _DISABLED_REASONS) or (
            self.status_code == 403
            and ("has not been used in project" in text or "it is disabled" in text)
        )

    @property
    def not_found(self) -> bool:
        return self.status_code == 404

    @property
    def precondition(self) -> bool:
        """``FAILED_PRECONDITION``: the service exists but is not set up (not activated)."""
        return self.error_code == "FAILED_PRECONDITION" or (
            self.status_code == 400 and "not activated" in str(self).lower()
        )


def _error_from(resp: Any, url: str) -> GCPApiError:
    status = int(getattr(resp, "status_code", 0) or 0)
    code, message, reasons = None, "", set()
    try:
        body = resp.json()
    except Exception:
        body = None
    err = body.get("error") if isinstance(body, dict) else None
    if isinstance(err, dict):
        code = err.get("status") or None
        message = str(err.get("message") or "")
        for detail in err.get("details") or []:
            if isinstance(detail, dict) and detail.get("reason"):
                reasons.add(str(detail["reason"]))
        for e in err.get("errors") or []:
            if isinstance(e, dict) and e.get("reason"):
                reasons.add(str(e["reason"]))
    if not message:
        message = str(getattr(resp, "text", "") or "")[:300]
    exc = GCPApiError(status, code or (sorted(reasons)[0] if reasons else None), message[:300], url)
    exc.reasons = reasons
    return exc


def _service_of(url: str) -> str:
    host = url.split("://", 1)[-1].split("/", 1)[0]
    return host.split(".", 1)[0] or "googleapis"


def _parent_of(url: str) -> str | None:
    for marker in ("/projects/", "/organizations/", "/folders/"):
        if marker in url:
            rest = url.split(marker, 1)[1].split("/", 1)[0]
            return f"{marker.strip('/')}/{rest}"
    return None


class GCPRestClient:
    """GET / paged-list access to Google REST APIs.

    Args:
        credentials: google-auth credentials (used to build an
            ``AuthorizedSession`` when ``session`` is not given).
        session: Injected transport with ``get(url, params=..., timeout=...)``
            returning a ``requests``-like response (tests).
        timeout: Per-request timeout in seconds.
        max_retries: Retries of throttled / unavailable requests.
        sleep: Sleep function between retries (tests pass a no-op).
    """

    def __init__(
        self,
        credentials: Any = None,
        *,
        session: Any = None,
        timeout: float = 60.0,
        max_retries: int = 4,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self._credentials = credentials
        self._session = session
        self._timeout = timeout
        self._max_retries = max_retries
        self._sleep = sleep
        self.calls = 0

    def _get_session(self) -> Any:
        if self._session is None:
            try:
                from google.auth.transport.requests import AuthorizedSession
            except ImportError as exc:
                raise ProviderSDKMissingError("gcp", missing="google-auth[requests]") from exc
            self._session = AuthorizedSession(self._credentials)
        return self._session

    def get(self, url: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        """GET ``url`` and return the JSON body.

        Raises:
            CredentialError: 401 (the credentials were refused).
            GCPApiError: Any other error status after retries.
        """
        return self._request("get", url, params, None)

    def post(self, url: str, body: dict[str, Any] | None = None) -> dict[str, Any]:
        """POST a read-only RPC (``:getIamPolicy``) and return the JSON body."""
        return self._request("post", url, None, body or {})

    def _request(
        self, method: str, url: str, params: dict[str, Any] | None, body: dict[str, Any] | None
    ) -> dict[str, Any]:
        session = self._get_session()
        gov = get_governor()
        scope = gcp_scope(_parent_of(url), _service_of(url), f"rest.{method}")
        enabled = gov.provider_enabled("gcp")
        attempt = 0
        while True:
            if enabled:
                gov.check(scope)
                gov.limiter.acquire_sync(scope)
                gov.record_call(scope)
            self.calls += 1
            if method == "post":
                resp = session.post(url, json=body, timeout=self._timeout)
            else:
                resp = session.get(url, params=params or None, timeout=self._timeout)
            status = int(getattr(resp, "status_code", 0) or 0)
            if 200 <= status < 300:
                gov.on_success(scope)
                try:
                    body = resp.json()
                except ValueError:
                    body = {}
                return body if isinstance(body, dict) else {"items": body}
            if status == 401:
                raise CredentialError("gcp", f"request to {url} was refused (HTTP 401)")
            err = _error_from(resp, url)
            if (
                status in _RETRY_STATUSES
                and attempt < self._max_retries
                and gov.try_retry(scope, attempt + 1)
            ):
                attempt += 1
                retry_after = _retry_after(resp)
                if status == 429:
                    gov.on_throttle(scope, retry_after, str(err)[:150])
                else:
                    gov.record_transient(scope, str(err)[:150])
                self._sleep(retry_after if retry_after is not None else min(2**attempt * 0.5, 30.0))
                continue
            gov.on_final_error(scope, err, f"rest.{method}")
            raise err

    def list(
        self,
        url: str,
        key: str,
        params: dict[str, Any] | None = None,
        *,
        max_items: int | None = None,
        page_size: int | None = None,
        page_size_param: str = "pageSize",
    ) -> tuple[list[dict[str, Any]], bool]:
        """Every item of a paged list (``nextPageToken`` / ``pageToken``).

        Returns:
            (items, truncated): ``truncated`` is True when ``max_items`` cut the list.
        """
        items: list[dict[str, Any]] = []
        query = dict(params or {})
        if page_size:
            query[page_size_param] = page_size
        token = None
        for _ in range(10000):
            if token:
                query["pageToken"] = token
            body = self.get(url, query)
            page = body.get(key) or []
            for i, item in enumerate(page):
                items.append(item if isinstance(item, dict) else {"name": item})
                if max_items is not None and len(items) >= max_items:
                    return items, i < len(page) - 1 or bool(body.get("nextPageToken"))
            token = body.get("nextPageToken")
            if not token:
                break
        return items, False


def _retry_after(resp: Any) -> float | None:
    headers = getattr(resp, "headers", None) or {}
    value = headers.get("Retry-After") if hasattr(headers, "get") else None
    try:
        return min(float(value), 60.0) if value is not None else None
    except (TypeError, ValueError):
        return None


__all__ = ["GCPApiError", "GCPRestClient"]
