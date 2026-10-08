"""Tests for the ``cloudg mcp`` command group (:mod:`cloudg.mcp.cli`)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from click.testing import CliRunner

from cloudg.mcp.cli import client_config, mcp_group

REG = ["--registry", "tests.mcp._adapter_testkit:build_registry"]


@pytest.fixture(autouse=True)
def default_policy(monkeypatch: pytest.MonkeyPatch) -> None:
    """The CLI builds layers with the default policy profile; fall back to
    the permissive test policy while that profile is unavailable."""
    from cloudg.mcp.policy import Policy

    try:
        Policy.load(None)
    except Exception:
        from tests.mcp._adapter_testkit import _permissive_policy

        fallback = _permissive_policy()
        original = Policy.load.__func__  # type: ignore[attr-defined]

        def load(cls: Any, source: Any = None, **kw: Any) -> Any:
            return fallback if source is None else original(cls, source, **kw)

        monkeypatch.setattr(Policy, "load", classmethod(load))


def run(*args: str, input: str | None = None) -> Any:
    return CliRunner().invoke(mcp_group, list(args), input=input, catch_exceptions=False)


def test_tools_json_and_table() -> None:
    result = run("tools", "--json", *REG)
    assert result.exit_code == 0, result.output
    tools = json.loads(result.stdout)
    assert [t["name"] for t in tools][:3] == ["echo", "stats", "slow"]
    assert tools[0]["annotations"]["readOnlyHint"] is True

    result = run("tools", *REG)
    assert result.exit_code == 0
    assert "echo" in result.stdout and "read-only" in result.stdout

    admin = json.loads(run("tools", "--json", "--category", "admin", *REG).stdout)
    assert [t["name"] for t in admin] == ["touch"]


def test_layer_options() -> None:
    names = [t["name"] for t in json.loads(run("tools", "--json", "--read-only", *REG).stdout)]
    assert "touch" not in names and "echo" in names  # destructive tool dropped
    names = [t["name"] for t in json.loads(
        run("tools", "--json", "--prefix", "cg_", "--exclude-tool", "fail", *REG).stdout)]
    assert "cg_echo" in names and "cg_fail" not in names
    names = [t["name"] for t in json.loads(
        run("tools", "--json", "--include-category", "admin", *REG).stdout)]
    assert names == ["touch"]
    bad = CliRunner().invoke(mcp_group, ["tools", "--registry", "no.such.module:x"])
    assert bad.exit_code == 2


def test_resources_and_prompts() -> None:
    data = json.loads(run("resources", "--json", *REG).stdout)
    assert data["resources"][0]["uri"] == "test://info"
    assert data["resourceTemplates"][0]["uriTemplate"] == "test://items/{item_id}"
    assert "test://items/{item_id}" in run("resources", *REG).stdout
    prompts = json.loads(run("prompts", "--json", *REG).stdout)
    assert prompts[0]["name"] == "greet"
    assert "name*" in run("prompts", *REG).stdout


def test_call_and_read(tmp_path: Path) -> None:
    result = run("call", "echo", "--args", '{"text": "hi", "times": 2}', *REG)
    assert result.exit_code == 0 and json.loads(result.stdout) == {"text": "hihi"}
    raw = json.loads(run("call", "echo", "--args", '{"text": "x"}', "--raw", *REG).stdout)
    assert raw["isError"] is False and raw["structuredContent"] == {"text": "x"}
    args_file = tmp_path / "args.json"
    args_file.write_text('{"text": "file"}')
    assert json.loads(run("call", "echo", "--args", f"@{args_file}", *REG).stdout) == {
        "text": "file"}
    assert json.loads(run("call", "echo", "--args", "-", *REG,
                          input='{"text": "stdin"}').stdout) == {"text": "stdin"}

    failed = run("call", "fail", *REG)
    assert failed.exit_code == 1 and "boom" in failed.stdout
    unknown = CliRunner().invoke(mcp_group, ["call", "nope", *REG])
    assert unknown.exit_code == 1 and "Unknown tool" in unknown.output
    bad_json = CliRunner().invoke(mcp_group, ["call", "echo", "--args", "{nope", *REG])
    assert bad_json.exit_code == 2
    not_object = CliRunner().invoke(mcp_group, ["call", "echo", "--args", "[1]", *REG])
    assert not_object.exit_code == 2

    read = run("read", "test://items/gamma", *REG)
    assert read.exit_code == 0 and '"index": 2' in read.stdout
    missing = CliRunner().invoke(mcp_group, ["read", "test://items/nope", *REG])
    assert missing.exit_code == 1


def test_call_as_principal_with_roles() -> None:
    result = run("call", "echo", "--args", '{"text": "r"}', "--role", "analyst",
                 "--principal-id", "cli-user", *REG)
    assert result.exit_code == 0


def test_audit_log_option(tmp_path: Path) -> None:
    log = tmp_path / "audit.jsonl"
    run("call", "echo", "--args", '{"text": "secret"}', "--audit-log", str(log), *REG)
    line = json.loads(log.read_text().splitlines()[0])
    assert line["name"] == "echo" and "secret" not in log.read_text()


@pytest.mark.parametrize("client", ["claude-desktop", "claude-code", "cursor", "vscode"])
def test_config_snippets(client: str) -> None:
    stdio = json.loads(run("config", "--client", client, "--policy", "strict",
                           "--read-only", "--command", "cloudg-mcp serve").stdout)
    servers = stdio["servers" if client == "vscode" else "mcpServers"]
    entry = servers["cloudg"]
    assert entry["command"] == "cloudg-mcp"
    assert entry["args"] == ["serve", "--policy", "strict", "--read-only"]
    http = json.loads(run("config", "--client", client, "--transport", "http",
                          "--url", "http://127.0.0.1:9000/mcp",
                          "--token-env", "CLOUDG_TOKEN").stdout)
    entry = http["servers" if client == "vscode" else "mcpServers"]["cloudg"]
    text = json.dumps(entry)
    assert "http://127.0.0.1:9000/mcp" in text and "CLOUDG_TOKEN" in text


def test_client_config_defaults() -> None:
    cfg = client_config("claude-code", command=["python", "-m", "cloudg.mcp", "serve"])
    assert cfg["mcpServers"]["cloudg"]["type"] == "stdio"
    with pytest.raises(ValueError):
        client_config("emacs")


def test_serve_validates_auth_tokens() -> None:
    result = CliRunner().invoke(mcp_group, ["serve", "--transport", "http",
                                            "--auth-token", "env:CLOUDG_UNSET_VAR_X", *REG])
    assert result.exit_code == 2


def test_serve_refuses_unsupported_flavor_options() -> None:
    result = CliRunner().invoke(mcp_group, ["serve", "--transport", "http", "--flavor", "sdk",
                                            "--cors-origin", "https://a.example", *REG])
    assert result.exit_code == 2 and "native flavor" in result.output


def test_main_cli_keeps_stdout_machine_readable() -> None:
    from cloudg.cli import cli

    result = CliRunner().invoke(cli, ["mcp", "tools", "--json", *REG], catch_exceptions=False)
    assert result.exit_code == 0
    assert json.loads(result.stdout)[0]["name"] == "echo"  # banner went to stderr
    assert "cloud graphing" in result.stderr
    from cloudg.ui import console

    assert console.stderr is False  # restored for the other commands
