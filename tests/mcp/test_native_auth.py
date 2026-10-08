"""Tests for caller identification (:mod:`cloudg.mcp.native.auth`)."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from cloudg.mcp.context import Principal
from cloudg.mcp.native.auth import (
    RequestInfo,
    TokenAuth,
    default_principal_resolver,
    parse_token_spec,
)


def test_parse_token_spec_variants(monkeypatch: pytest.MonkeyPatch) -> None:
    token, principal = parse_token_spec("s3cret:analyst,admin:ci-bot")
    assert token == "s3cret" and principal.id == "ci-bot"
    assert principal.roles == {"analyst", "admin", "default"}
    token, principal = parse_token_spec("plain")
    assert principal.roles == {"default"} and principal.id.startswith("token-")
    monkeypatch.setenv("CLOUDG_TEST_TOKEN", "from-env")
    token, principal = parse_token_spec("env:CLOUDG_TEST_TOKEN:viewer")
    assert token == "from-env" and principal.roles == {"viewer", "default"}
    token, principal = parse_token_spec("env:CLOUDG_TEST_TOKEN::bot")
    assert principal.roles == {"default"} and principal.id == "bot"
    monkeypatch.delenv("CLOUDG_TEST_TOKEN")
    with pytest.raises(ValueError):
        parse_token_spec("env:CLOUDG_TEST_TOKEN")
    with pytest.raises(ValueError):
        parse_token_spec(":role")


def test_tokens_may_contain_colons() -> None:
    token, principal = parse_token_spec("abc:def::")
    assert token == "abc:def" and principal.roles == {"default"}
    token, principal = parse_token_spec("a:b:c:analyst:svc")
    assert token == "a:b:c" and principal.roles == {"analyst", "default"}
    assert principal.id == "svc"
    auth = TokenAuth.from_specs(["x:y:z:auditor:"])
    assert auth.authenticate("Bearer x:y:z").roles == {"auditor", "default"}
    assert auth.authenticate("Bearer x") is None


def test_token_auth_lookup_and_headers() -> None:
    auth = TokenAuth({"t1": "a,b", "t2": Principal(id="p2", roles={"x"})})
    assert len(auth) == 2 and bool(auth)
    p = auth.authenticate("Bearer t1")
    assert p is not None and p.roles == {"a", "b", "default"}
    p.roles.add("mutated")  # returned principals are copies
    assert auth.lookup("t1").roles == {"a", "b", "default"}
    assert TokenAuth({"t3": ["r"]}).lookup("t3").roles == {"r", "default"}
    p2 = auth.authenticate("bearer   t2")
    assert p2.id == "p2" and p2.roles == {"x"}  # explicit principals are used as is
    assert auth.authenticate("Basic dDE=") is None
    assert auth.authenticate("Bearer nope") is None
    assert auth.authenticate(None) is None
    built = TokenAuth.from_specs(["k1:r1", "k2:r2:id2"])
    assert built.lookup("k2").id == "id2"
    with pytest.raises(ValueError):
        TokenAuth({"": "r"})


def test_default_resolver_order() -> None:
    explicit = Principal(id="explicit")
    assert default_principal_resolver(RequestInfo(transport="http", principal=explicit)) is explicit
    token = SimpleNamespace(client_id="client-9", scopes=["read", "write"])
    p = default_principal_resolver(RequestInfo(transport="http", access_token=token))
    assert p.id == "client-9" and {"read", "write", "default"} <= p.roles
    assert default_principal_resolver(RequestInfo(transport="stdio")).id == "local"
    assert default_principal_resolver(RequestInfo(transport="http")).id == "anonymous"
    info = RequestInfo(headers={"authorization": "Bearer abc"})
    assert info.bearer_token == "abc" and info.header("Authorization") == "Bearer abc"
