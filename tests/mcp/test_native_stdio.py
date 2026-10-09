"""stdio transport tests: a real subprocess speaking newline-delimited
JSON-RPC (raw, and through the official SDK client when installed), plus the
``python -m cloudg.mcp`` entry point."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[2]

# Serves the test registry over stdio with the given flavor (argv[1]).
SERVER_CODE = (
    "import sys; "
    "from tests.mcp._adapter_testkit import build_layer; "
    "from cloudg.mcp.server import serve; "
    "serve(build_layer(), 'stdio', flavor=sys.argv[1])"
)


def _sdk_major() -> int:
    try:
        import importlib.metadata as md

        return int(md.version("mcp").split(".")[0])
    except Exception:
        return 0


def run_raw(
    lines: list[Any], flavor: str = "native", timeout: float = 60
) -> tuple[list[dict[str, Any]], str, int]:
    payload = "".join((m if isinstance(m, str) else json.dumps(m)) + "\n" for m in lines)
    proc = subprocess.run(
        [sys.executable, "-c", SERVER_CODE, flavor],
        input=payload.encode(),
        capture_output=True,
        cwd=ROOT,
        timeout=timeout,
    )
    out_lines = [ln for ln in proc.stdout.decode().splitlines() if ln.strip()]
    return [json.loads(ln) for ln in out_lines], proc.stderr.decode(), proc.returncode


INIT = {
    "jsonrpc": "2.0",
    "id": 1,
    "method": "initialize",
    "params": {
        "protocolVersion": "2025-06-18",
        "capabilities": {},
        "clientInfo": {"name": "raw", "version": "1"},
    },
}
INITIALIZED = {"jsonrpc": "2.0", "method": "notifications/initialized"}


def test_raw_stdio_session_and_stdout_purity() -> None:
    messages, stderr, code = run_raw(
        [
            INIT,
            INITIALIZED,
            "this is not json",
            {
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/call",
                "params": {"name": "noisy", "arguments": {}},
            },
            {
                "jsonrpc": "2.0",
                "id": 3,
                "method": "tools/call",
                "params": {
                    "name": "slow",
                    "arguments": {"steps": 2},
                    "_meta": {"progressToken": 7},
                },
            },
            {"jsonrpc": "2.0", "id": 4, "method": "ping"},
        ]
    )
    assert code == 0
    # every stdout line is a JSON-RPC message; stray prints went to stderr
    assert all(m.get("jsonrpc") == "2.0" for m in messages)
    assert "NOISE from print()" in stderr and "NOISE from fd 1" in stderr
    by_id = {m["id"]: m for m in messages if "id" in m and m["id"] is not None}
    assert by_id[1]["result"]["protocolVersion"] == "2025-06-18"
    assert by_id[2]["result"]["structuredContent"] == {"noisy": True}
    assert by_id[3]["result"]["structuredContent"] == {"done": 2}
    assert by_id[4]["result"] == {}
    parse_errors = [m for m in messages if m.get("error", {}).get("code") == -32700]
    assert len(parse_errors) == 1 and parse_errors[0]["id"] is None
    progress = [m for m in messages if m.get("method") == "notifications/progress"]
    assert [p["params"]["progress"] for p in progress] == [1, 2]


@pytest.mark.parametrize("flavor", ["sdk", "fastmcp"])
def test_raw_stdio_framework_flavors_keep_stdout_clean(flavor: str) -> None:
    pytest.importorskip("mcp" if flavor == "sdk" else "fastmcp")
    messages, stderr, code = run_raw(
        [
            INIT,
            INITIALIZED,
            {
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/call",
                "params": {"name": "echo", "arguments": {"text": "x"}},
            },
            {"jsonrpc": "2.0", "id": 3, "method": "ping"},
        ],
        flavor=flavor,
    )
    assert code == 0, stderr
    assert all(m.get("jsonrpc") == "2.0" for m in messages)
    by_id = {m["id"]: m for m in messages if m.get("id") is not None}
    assert "result" in by_id[1]
    # the SDKs may drop responses still in flight when stdin hits EOF
    if 2 in by_id:
        assert by_id[2]["result"]["structuredContent"] == {"text": "x"}


def test_raw_stdio_cancellation_and_eof() -> None:
    messages, _, code = run_raw(
        [
            INIT,
            INITIALIZED,
            {
                "jsonrpc": "2.0",
                "id": "long",
                "method": "tools/call",
                "params": {"name": "sleepy", "arguments": {"seconds": 30}},
            },
            {
                "jsonrpc": "2.0",
                "method": "notifications/cancelled",
                "params": {"requestId": "long"},
            },
            {"jsonrpc": "2.0", "id": 5, "method": "ping"},
        ],
        timeout=30,
    )
    assert code == 0
    ids = [m.get("id") for m in messages]
    assert "long" not in ids and 5 in ids


@pytest.mark.filterwarnings("ignore")
@pytest.mark.parametrize("flavor", ["native", "sdk"])
@pytest.mark.parametrize("mode", ["legacy", "auto"])
async def test_sdk_client_over_stdio(flavor: str, mode: str) -> None:
    mcp = pytest.importorskip("mcp")
    if _sdk_major() < 2:
        pytest.skip("needs the mcp 2.x Client")
    params = mcp.StdioServerParameters(
        command=sys.executable, args=["-c", SERVER_CODE, flavor], cwd=str(ROOT)
    )
    async with mcp.Client(params, mode=mode) as client:
        assert client.protocol_version == ("2025-11-25" if mode == "legacy" else "2026-07-28")
        names = [t.name for t in (await client.list_tools()).tools]
        assert {"echo", "stats", "noisy"} <= set(names)
        noisy = await client.call_tool("noisy", {})
        assert noisy.structured_content == {"noisy": True}
        progress: list[float] = []

        async def on_progress(p: float, total: float | None, message: str | None) -> None:
            progress.append(p)

        slow = await client.call_tool("slow", {"steps": 3}, progress_callback=on_progress)
        assert slow.structured_content == {"done": 3} and progress == [1, 2, 3]
        bad = await client.call_tool("echo", {"text": "x", "times": 99})
        assert bad.is_error
        prompt = await client.get_prompt("greet", {"name": "Zed", "style": "formal"})
        assert prompt.messages[0].content.text == "Good day, Zed."


def test_module_entry_point_serves_custom_registry() -> None:
    from cloudg.mcp.policy import Policy

    try:
        Policy.load(None)
    except Exception as exc:  # the default profile ships with the privacy work
        pytest.skip(f"default policy not loadable yet: {exc}")
    payload = (
        json.dumps(INIT)
        + "\n"
        + json.dumps(INITIALIZED)
        + "\n"
        + json.dumps({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
        + "\n"
    )
    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "cloudg.mcp",
            "serve",
            "--flavor",
            "native",
            "--registry",
            "tests.mcp._adapter_testkit:build_registry",
        ],
        input=payload.encode(),
        capture_output=True,
        cwd=ROOT,
        timeout=60,
    )
    assert proc.returncode == 0, proc.stderr.decode()
    lines = [json.loads(ln) for ln in proc.stdout.decode().splitlines() if ln.strip()]
    tools = next(m for m in lines if m.get("id") == 2)["result"]["tools"]
    assert "echo" in [t["name"] for t in tools]


def test_cloudg_cli_banner_stays_off_stdout() -> None:
    from cloudg.mcp.policy import Policy

    try:
        Policy.load(None)
    except Exception as exc:
        pytest.skip(f"default policy not loadable yet: {exc}")
    payload = json.dumps(INIT) + "\n"
    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "cloudg.cli",
            "mcp",
            "serve",
            "--flavor",
            "native",
            "--registry",
            "tests.mcp._adapter_testkit:build_registry",
        ],
        input=payload.encode(),
        capture_output=True,
        cwd=ROOT,
        timeout=60,
    )
    stdout = proc.stdout.decode().strip().splitlines()
    assert stdout and all(json.loads(ln)["jsonrpc"] == "2.0" for ln in stdout)
    assert "cloud graphing" in proc.stderr.decode()  # the banner went to stderr
