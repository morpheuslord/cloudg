"""Fakes for the GCP REST sources: a requests-like session and responses."""

from __future__ import annotations

from typing import Any, Callable

from cloudg.inventory.gcp_sources import GCPRestClient


class FakeResponse:
    def __init__(self, status: int = 200, body: Any = None, headers: dict | None = None) -> None:
        self.status_code = status
        self._body = {} if body is None else body
        self.headers = headers or {}
        self.text = str(body)

    def json(self) -> Any:
        return self._body


def api_error(status: int, code: str, reason: str | None = None, message: str = "") -> FakeResponse:
    err: dict[str, Any] = {"code": status, "status": code, "message": message or code}
    if reason:
        err["details"] = [{"@type": "type.googleapis.com/google.rpc.ErrorInfo", "reason": reason}]
    return FakeResponse(status, {"error": err})


def disabled(service: str = "x.googleapis.com") -> FakeResponse:
    return api_error(
        403,
        "PERMISSION_DENIED",
        "SERVICE_DISABLED",
        f"{service} has not been used in project 111 before or it is disabled.",
    )


def denied() -> FakeResponse:
    return api_error(403, "PERMISSION_DENIED", "IAM_PERMISSION_DENIED", "caller lacks permission")


Route = Any  # dict body | FakeResponse | list of pages | callable(params) -> body


class FakeSession:
    """Serves GET / POST by exact URL (query ignored); unknown URLs answer 404.

    A route value is a JSON body, a :class:`FakeResponse`, a list of
    responses served in order (pagination, retries), or a callable taking
    the request params / JSON body.
    """

    def __init__(self, routes: dict[str, Route] | None = None) -> None:
        self.routes = dict(routes or {})
        self.calls: list[tuple[str, str, Any]] = []
        self._served: dict[str, int] = {}

    def _answer(self, method: str, url: str, payload: Any) -> FakeResponse:
        self.calls.append((method, url, payload))
        route = self.routes.get(url)
        if route is None:
            return api_error(404, "NOT_FOUND")
        if isinstance(route, list):
            i = self._served.get(url, 0)
            self._served[url] = i + 1
            route = route[min(i, len(route) - 1)]
        if callable(route):
            route = route(payload)
        return route if isinstance(route, FakeResponse) else FakeResponse(200, route)

    def get(self, url: str, params: Any = None, timeout: Any = None) -> FakeResponse:
        return self._answer("GET", url, params)

    def post(self, url: str, json: Any = None, timeout: Any = None) -> FakeResponse:
        return self._answer("POST", url, json)

    def urls(self, method: str = "GET") -> list[str]:
        return [u for m, u, _ in self.calls if m == method]


def rest_client(
    routes: dict[str, Route] | None = None, sleep: Callable[[float], None] | None = None
):
    session = FakeSession(routes)
    client = GCPRestClient(session=session, sleep=sleep or (lambda s: None))
    return client, session
