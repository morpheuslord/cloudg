"""The ARM / Microsoft Graph REST client used for Azure depth (no network)."""

from __future__ import annotations

import io
import json
import urllib.error
from types import SimpleNamespace

import pytest

from cloudg.exceptions import CredentialError
from cloudg.inventory.azure_graph import rest
from cloudg.inventory.azure_graph.rest import AzureRestClient, AzureRestError


class _Resp(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


class _Cred:
    def __init__(self):
        self.calls = 0

    def get_token(self, scope):
        self.calls += 1
        return SimpleNamespace(token=f"tok-{scope}", expires_on=9_999_999_999)


def _client(monkeypatch, pages, **kw):
    seen = []

    def fake_urlopen(req, timeout=None):
        seen.append(req)
        item = pages.pop(0)
        if isinstance(item, Exception):
            raise item
        return _Resp(json.dumps(item).encode())

    monkeypatch.setattr(rest.urllib.request, "urlopen", fake_urlopen)
    cred = _Cred()
    return AzureRestClient(cred, sleep=lambda s: None, **kw), seen, cred


def _http_error(code, headers=None):
    return urllib.error.HTTPError(
        "https://management.azure.com/x", code, "err", headers or {}, io.BytesIO(b"{}")
    )


def test_list_follows_next_links_on_the_same_host(monkeypatch):
    base = "https://management.azure.com"
    pages = [
        {"value": [{"id": "a"}], "nextLink": f"{base}/next?page=2"},
        {"value": [{"id": "b"}], "nextLink": "https://evil.example/steal"},
    ]
    client, seen, cred = _client(monkeypatch, pages)
    items = client.list("/subscriptions/s/providers/X/things", "2024-01-01")
    assert [i["id"] for i in items] == ["a", "b"]
    assert len(seen) == 2  # the foreign next link is never called
    assert seen[0].full_url.endswith("things?api-version=2024-01-01")
    assert seen[0].get_header("Authorization") == f"Bearer tok-{base}/.default"
    assert seen[0].get_method() == "GET"
    assert cred.calls == 1  # token cached across pages


def test_graph_odata_next_link(monkeypatch):
    base = "https://graph.microsoft.com"
    pages = [
        {"value": [{"id": "u1"}], "@odata.nextLink": f"{base}/v1.0/users?$skiptoken=x"},
        {"value": [{"id": "u2"}]},
    ]
    client, _seen, _ = _client(monkeypatch, pages, base_url=base, scope=f"{base}/.default")
    assert [u["id"] for u in client.list("/v1.0/users")] == ["u1", "u2"]


def test_throttled_calls_are_retried(monkeypatch):
    pages = [_http_error(429, {"Retry-After": "1"}), {"id": "obj"}]
    client, seen, _ = _client(monkeypatch, pages)
    assert client.get("/subscriptions/s/x", "2024-01-01") == {"id": "obj"}
    assert len(seen) == 2


def test_errors_and_refusals(monkeypatch):
    client, _seen, _ = _client(monkeypatch, [_http_error(403)])
    with pytest.raises(AzureRestError) as err:
        client.list("/subscriptions/s/x")
    assert err.value.forbidden and not err.value.not_applicable
    assert AzureRestError(404, "u").not_applicable
    with pytest.raises(ValueError):
        client.request("https://evil.example/x")
    with pytest.raises(CredentialError):
        AzureRestClient(object()).get("/subscriptions/s")
    with pytest.raises(ValueError):
        AzureRestClient(_Cred(), base_url="http://insecure")


def test_post_list_action(monkeypatch):
    client, seen, _ = _client(monkeypatch, [{"kubeconfigs": []}])
    assert client.post("/subscriptions/s/c/listClusterUserCredential", "2024-05-01") == {
        "kubeconfigs": []
    }
    assert seen[0].get_method() == "POST"
