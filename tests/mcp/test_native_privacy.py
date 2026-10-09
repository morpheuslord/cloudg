"""Privacy regressions seen end to end through the native server: every
string a call sends back (results, errors and their data, links, embedded
resources, progress and log notifications) leaves through the caller's
output pipeline, and real values restored from pseudonyms in the arguments
are never echoed back."""

from __future__ import annotations

import json
from typing import Any

import pytest

from cloudg.mcp.catalog import default_registry
from cloudg.mcp.context import Principal
from cloudg.mcp.core import (
    EmbeddedResource,
    InvalidArgumentsError,
    PromptArgument,
    PromptMessage,
    PromptResult,
    Sensitivity,
    TextContent,
    TextResourceContents,
)
from cloudg.mcp.layer import CloudGMCPLayer
from cloudg.mcp.native import NativeMCPServer

ACCOUNT = "111111111111"  # a real account id of the sample estate
REAL_NAME = "orders-db"
DATA = {"cloudg/data": {"account_id": ACCOUNT, "name": REAL_NAME}}


def _registry() -> Any:
    reg = default_registry()

    @reg.tool(category="test", sensitivity=Sensitivity.INTERNAL, read_only=True)
    def echo_error(ctx: Any, ref: str) -> dict:
        """Fail quoting the argument (as many lookups do)."""
        raise InvalidArgumentsError(f"Unknown thing '{ref}'", data={"value": ref})

    @reg.tool(category="test", sensitivity=Sensitivity.INTERNAL, read_only=True)
    async def noisy(ctx: Any) -> dict:
        """Progress, a log message and a link that all name real values."""
        await ctx.report_progress(1, 2, f"scanning arn:aws:rds:us-east-1:{ACCOUNT}:db:{REAL_NAME}")
        await ctx.log("info", {"account_id": ACCOUNT, "name": REAL_NAME})
        ctx.link(f"cloudg://assets/{REAL_NAME}", REAL_NAME, title=f"RDS {REAL_NAME}")
        return {"account_id": ACCOUNT, "name": REAL_NAME}

    @reg.resource_template(
        "cloudg://test/echo/{ref}", category="test", sensitivity=Sensitivity.INTERNAL
    )
    def echo_resource(ctx: Any, ref: str) -> dict:
        raise InvalidArgumentsError(f"Unknown '{ref}'", data={"value": ref})

    @reg.resource_template(
        "cloudg://test/crash/{ref}", category="test", sensitivity=Sensitivity.INTERNAL
    )
    def crash_resource(ctx: Any, ref: str) -> dict:
        raise ValueError(f"cannot read {ref}")

    @reg.resource("cloudg://test/marked", category="test", sensitivity=Sensitivity.INTERNAL)
    def marked_resource(ctx: Any) -> list:
        return [TextResourceContents("cloudg://test/marked", "", "application/json", dict(DATA))]

    @reg.prompt(
        category="test",
        sensitivity=Sensitivity.INTERNAL,
        arguments=[PromptArgument("ref", required=True)],
    )
    def echo_prompt(ctx: Any, ref: str) -> str:
        raise RuntimeError(f"prompt failed for {ref}")

    @reg.prompt(category="test", sensitivity=Sensitivity.INTERNAL)
    def marked_prompt(ctx: Any) -> PromptResult:
        block = {**DATA, "cloudg/render": "json-block", "keep": 1}
        embedded = TextResourceContents(
            f"cloudg://assets/{REAL_NAME}", "", "application/json", dict(DATA)
        )
        return PromptResult(
            [
                PromptMessage("user", TextContent("", meta=block)),
                PromptMessage("user", EmbeddedResource(embedded)),
            ]
        )

    return reg


class _Client:
    def __init__(self, layer: CloudGMCPLayer) -> None:
        self.session = NativeMCPServer(layer).create_session(
            transport="http", principal=Principal(id="mallory", roles={"default"})
        )
        self.notes: list[dict[str, Any]] = []
        self._id = 0

    async def _sink(self, message: dict[str, Any]) -> None:
        self.notes.append(message)

    async def req(self, method: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        self._id += 1
        msg = {"jsonrpc": "2.0", "id": self._id, "method": method, "params": params or {}}
        return await self.session.handle(msg, sink=self._sink)


@pytest.fixture
async def client(workspace: Any) -> _Client:
    c = _Client(CloudGMCPLayer(policy="strict", workspace=workspace, registry=_registry()))
    await c.req("initialize", {"protocolVersion": "2025-11-25", "capabilities": {}})
    await c.session.handle({"jsonrpc": "2.0", "method": "notifications/initialized"})
    return c


async def _pseudonym(client: _Client, real: str) -> str:
    res = await client.req("tools/call", {"name": "get_asset", "arguments": {"ref": real}})
    structured = res["result"]["structuredContent"]
    token = structured.get("asset", structured)["name"]
    assert token != real
    return token


async def test_errors_never_echo_restored_values(client: _Client) -> None:
    token = await _pseudonym(client, "web-1")
    res = await client.req("tools/call", {"name": "echo_error", "arguments": {"ref": token}})
    result = res["result"]
    assert result["isError"] and token in result["content"][0]["text"]
    assert "web-1" not in json.dumps(result)

    res = await client.req("resources/read", {"uri": f"cloudg://test/echo/{token}"})
    assert token in res["error"]["message"] and "web-1" not in json.dumps(res)

    # an unexpected handler exception: internal error, transformed text
    res = await client.req("resources/read", {"uri": f"cloudg://test/crash/{token}"})
    assert res["error"]["code"] == -32603
    assert "ValueError" in res["error"]["message"] and "web-1" not in json.dumps(res)

    res = await client.req("prompts/get", {"name": "echo_prompt", "arguments": {"ref": token}})
    assert res["error"]["code"] == -32603 and "web-1" not in json.dumps(res)


async def test_progress_log_and_links_use_the_output_pipeline(client: _Client) -> None:
    res = await client.req("tools/call", {"name": "noisy", "_meta": {"progressToken": "p1"}})
    methods = [n["method"] for n in client.notes]
    assert "notifications/progress" in methods and "notifications/message" in methods
    sent = json.dumps([client.notes, res])
    assert ACCOUNT not in sent and REAL_NAME not in sent
    link = next(c for c in res["result"]["content"] if c["type"] == "resource_link")
    token = res["result"]["structuredContent"]["name"]
    assert link["name"] == token and link["title"] == f"RDS {token}"


async def test_marked_structured_content_is_transformed_with_key_context(
    client: _Client,
) -> None:
    res = await client.req("prompts/get", {"name": "marked_prompt"})
    first, second = (m["content"] for m in res["result"]["messages"])
    assert first["text"].startswith("Context for this task (JSON):\n```json\n")
    assert first["text"].endswith("\n```")
    assert first["_meta"] == {"keep": 1}  # marker keys removed, the rest kept
    assert "_meta" not in second["resource"]
    assert REAL_NAME not in second["resource"]["uri"]
    assert ACCOUNT not in json.dumps(res) and REAL_NAME not in json.dumps(res)
    rendered = json.loads(second["resource"]["text"])
    assert set(rendered) == {"account_id", "name"}

    res = await client.req("resources/read", {"uri": "cloudg://test/marked"})
    content = res["result"]["contents"][0]
    assert "_meta" not in content and ACCOUNT not in content["text"]
    assert set(json.loads(content["text"])) == {"account_id", "name"}


async def test_percent_encoded_uri_resolves_to_the_denied_static_resource(
    workspace: Any,
) -> None:
    policy = {"extends": "standard", "deny_resources": ["cloudg://graph/d3"]}
    client = _Client(CloudGMCPLayer(policy=policy, workspace=workspace))
    await client.req("initialize", {"protocolVersion": "2025-11-25", "capabilities": {}})
    for uri in ("cloudg://graph/d3", "cloudg://graph/%64%33", "cloudg://graph/d%33"):
        res = await client.req("resources/read", {"uri": uri})
        assert "error" in res, uri
    res = await client.req("resources/read", {"uri": "cloudg://graph/cytoscape"})
    assert res["result"]["contents"][0]["uri"] == "cloudg://graph/cytoscape"


async def test_template_uri_is_matched_as_a_concrete_uri(workspace: Any) -> None:
    import inspect

    from cloudg.mcp.policy import Policy

    if "uri" not in inspect.signature(Policy.is_allowed).parameters:
        pytest.skip("this policy engine matches only the spec's own URI")
    policy = {"extends": "standard", "deny_resources": ["cloudg://assets/bastion*"]}
    client = _Client(CloudGMCPLayer(policy=policy, workspace=workspace))
    await client.req("initialize", {"protocolVersion": "2025-11-25", "capabilities": {}})
    for uri in ("cloudg://assets/bastion", "cloudg://assets/%62astion"):
        res = await client.req("resources/read", {"uri": uri})
        assert "error" in res, uri
    res = await client.req("resources/read", {"uri": "cloudg://assets/web-1"})
    assert "result" in res
