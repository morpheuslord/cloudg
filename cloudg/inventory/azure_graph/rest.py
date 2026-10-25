"""ARM, Microsoft Graph and data-plane REST reads for what Resource Graph misses.

Resource Graph returns tracked resources, but not most proxy (child)
resources (APIM APIs, Service Bus queues, DNS record sets, function
bindings, diagnostic settings, ...) and nothing from Entra ID. Those are
read with plain HTTPS GETs authenticated by the azure-identity credential
cloudg already holds, so no extra SDK is needed:

- :class:`AzureRestClient` pages through ``nextLink`` / ``@odata.nextLink``,
  only follows links on its own host, retries throttled (429 / 503)
  responses after ``Retry-After``, and paces every call through the shared
  rate limiter (``azure/<scope>/*/<service>`` buckets).
- :func:`default_arm_client_factory`, :func:`default_msgraph_client_factory`
  and :func:`default_dataplane_client_factory` build clients for
  ``management.azure.com``, ``graph.microsoft.com`` and per-service data
  planes. Collectors take them as injectable ``credential -> client``
  factories, so tests pass fakes and never touch the network.

Clients only issue ``GET`` (and ``POST`` for read-only ``list*`` actions
such as ``listClusterUserCredential``). Response bodies are returned as
dicts; secret values are never requested.
"""

from __future__ import annotations

import json
import logging
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Callable

from cloudg.exceptions import CredentialError
from cloudg.resilience.governor import get_governor
from cloudg.resilience.limiter import Scope

logger = logging.getLogger("cloudg.inventory.azure_graph")

ARM_ENDPOINT = "https://management.azure.com"
GRAPH_ENDPOINT = "https://graph.microsoft.com"
_ARM_SCOPE = f"{ARM_ENDPOINT}/.default"
_GRAPH_SCOPE = f"{GRAPH_ENDPOINT}/.default"
_RETRY_STATUSES = (429, 503)


class AzureRestError(Exception):
    """A REST call answered with an HTTP error status."""

    def __init__(self, status_code: int, url: str, message: str = "") -> None:
        self.status_code = status_code
        self.url = url
        super().__init__(f"HTTP {status_code} for {url.split('?', 1)[0]}: {message[:300]}")

    @property
    def forbidden(self) -> bool:
        return self.status_code in (401, 403)

    @property
    def not_applicable(self) -> bool:
        """404 / 400 / 405 / 409: the child kind does not exist for this parent or SKU."""
        return self.status_code in (400, 404, 405, 409)


def _retry_after(headers: Any) -> float | None:
    if headers is None:
        return None
    for key in ("Retry-After", "retry-after", "x-ms-retry-after-ms"):
        value = headers.get(key) if hasattr(headers, "get") else None
        if value is None:
            continue
        try:
            seconds = float(value)
        except (TypeError, ValueError):
            continue
        return seconds / 1000.0 if key.endswith("-ms") else seconds
    return None


class AzureRestClient:
    """Minimal paginated JSON REST client authenticated by a TokenCredential.

    Args:
        credential: azure-identity TokenCredential.
        base_url: ``https://host`` every relative path is joined to.
        scope: OAuth scope requested for the bearer token.
        service: Rate-limit bucket name (``arm``, ``msgraph``, ``dataplane``).
        timeout: Socket timeout of one call, in seconds.
        max_retries: Retries of throttled calls.
        sleep: Injectable sleep (tests).
    """

    def __init__(
        self,
        credential: Any,
        *,
        base_url: str = ARM_ENDPOINT,
        scope: str = _ARM_SCOPE,
        service: str = "arm",
        timeout: float = 30.0,
        max_retries: int = 4,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        if not base_url.startswith("https://"):
            raise ValueError("Azure REST base URL must be https")
        self._credential = credential
        self.base_url = base_url.rstrip("/")
        self._scope = scope
        self._timeout = timeout
        self._max_retries = max_retries
        self._sleep = sleep
        self._limit_scope = Scope("azure", None, None, service)
        self._token: str | None = None
        self._expires = 0.0
        self._lock = threading.Lock()

    # ── auth ──

    def _bearer(self) -> str:
        with self._lock:
            if self._token and time.time() < self._expires - 120:
                return self._token
            get_token = getattr(self._credential, "get_token", None)
            if not callable(get_token):
                raise CredentialError("azure", "the credential cannot issue access tokens")
            try:
                token = get_token(self._scope)
            except Exception as exc:
                raise CredentialError("azure", f"token for {self._scope} refused: {exc}") from exc
            self._token = str(getattr(token, "token", "") or "")
            self._expires = float(getattr(token, "expires_on", 0) or time.time() + 600)
            return self._token

    # ── transport ──

    def url(self, path: str, params: dict[str, Any] | None = None) -> str:
        url = path if path.startswith("https://") else self.base_url + "/" + path.lstrip("/")
        if params:
            sep = "&" if "?" in url else "?"
            url += sep + urllib.parse.urlencode({k: v for k, v in params.items() if v is not None})
        return url

    def _send(self, url: str, method: str, body: Any) -> dict[str, Any]:
        if not url.startswith(self.base_url + "/"):
            raise ValueError(f"refusing to call {url.split('?', 1)[0]}: not on {self.base_url}")
        data = None if body is None else json.dumps(body).encode("utf-8")
        headers = {"Authorization": f"Bearer {self._bearer()}", "Accept": "application/json"}
        if data is not None:
            headers["Content-Type"] = "application/json"
        req = urllib.request.Request(url, data=data, headers=headers, method=method)  # nosec B310
        with urllib.request.urlopen(req, timeout=self._timeout) as resp:  # nosec B310 - https only
            raw = resp.read()
        if not raw:
            return {}
        out = json.loads(raw.decode("utf-8"))
        return out if isinstance(out, dict) else {"value": out}

    def request(self, path: str, *, method: str = "GET", params=None, body=None) -> dict[str, Any]:
        """One call, paced and retried when throttled.

        Raises:
            AzureRestError: The service answered with an error status.
            CredentialError: No token could be obtained.
        """
        url = self.url(path, params)
        gov = get_governor()
        attempt = 0
        while True:
            if gov.provider_enabled("azure"):
                gov.check(self._limit_scope)
                gov.limiter.acquire_sync(self._limit_scope, sleep=self._sleep)
            try:
                result = self._send(url, method, body)
            except urllib.error.HTTPError as exc:
                text = ""
                try:
                    text = exc.read().decode("utf-8", "replace")
                except Exception:  # pragma: no cover - defensive
                    pass
                err = AzureRestError(exc.code, url, text)
                if exc.code in _RETRY_STATUSES and attempt < self._max_retries:
                    hint = _retry_after(exc.headers)
                    gov.on_throttle(self._limit_scope, hint, str(err)[:200])
                    attempt += 1
                    gov.record_retry(self._limit_scope)
                    self._sleep(min(max(hint or 0.0, 2.0**attempt), 60.0))
                    continue
                gov.on_final_error(self._limit_scope, err, "Azure REST call")
                raise err from None
            gov.on_success(self._limit_scope)
            return result

    def get(self, path: str, api_version: str | None = None, **params: Any) -> dict[str, Any]:
        if api_version:
            params["api-version"] = api_version
        return self.request(path, params=params or None)

    def post(self, path: str, api_version: str | None = None, body: Any = None) -> dict[str, Any]:
        params = {"api-version": api_version} if api_version else None
        return self.request(path, method="POST", params=params, body=body if body else {})

    def list(
        self,
        path: str,
        api_version: str | None = None,
        *,
        max_items: int = 5000,
        **params: Any,
    ) -> list[dict[str, Any]]:
        """Every item of a list endpoint (``value``), following next links on this host."""
        if api_version:
            params["api-version"] = api_version
        items: list[dict[str, Any]] = []
        url: str | None = self.url(path, params or None)
        pages = 0
        while url and pages < 500 and len(items) < max_items:
            pages += 1
            data = self.request(url)
            for item in data.get("value", []) or []:
                if isinstance(item, dict):
                    items.append(item)
            url = data.get("nextLink") or data.get("@odata.nextLink")
            if url and not str(url).startswith(self.base_url + "/"):
                break
        return items[:max_items]


def default_arm_client_factory(credential: Any) -> AzureRestClient:
    """REST client for Azure Resource Manager (``management.azure.com``)."""
    return AzureRestClient(credential, base_url=ARM_ENDPOINT, scope=_ARM_SCOPE, service="arm")


def default_msgraph_client_factory(credential: Any) -> AzureRestClient:
    """REST client for Microsoft Graph v1.0 (``graph.microsoft.com``)."""
    return AzureRestClient(
        credential, base_url=f"{GRAPH_ENDPOINT}", scope=_GRAPH_SCOPE, service="msgraph"
    )


def default_dataplane_client_factory(credential: Any, base_url: str, scope: str) -> AzureRestClient:
    """REST client for a service data plane (AI Search, Synapse dev endpoint, ...)."""
    return AzureRestClient(credential, base_url=base_url, scope=scope, service="dataplane")


__all__ = [
    "ARM_ENDPOINT",
    "GRAPH_ENDPOINT",
    "AzureRestClient",
    "AzureRestError",
    "default_arm_client_factory",
    "default_dataplane_client_factory",
    "default_msgraph_client_factory",
]
