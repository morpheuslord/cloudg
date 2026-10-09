"""Small, self-contained registry used by the adapter / native-server / CLI
tests so they do not depend on the full cloudg catalog."""

from __future__ import annotations

import asyncio
from types import SimpleNamespace
from typing import Annotated, Any

from pydantic import Field

from cloudg.mcp.core import (
    Capability,
    PromptArgument,
    PromptMessage,
    PromptResult,
    Registry,
    Sensitivity,
    TextContent,
)
from cloudg.mcp.layer import CloudGMCPLayer

ITEMS = ["alpha", "beta", "gamma", "delta"]

STATS_SCHEMA = {
    "type": "object",
    "properties": {"count": {"type": "integer"}, "names": {"type": "array"}},
    "required": ["count"],
}


def build_registry() -> Registry:
    reg = Registry()

    @reg.tool(
        title="Echo",
        category="test",
        read_only=True,
        idempotent=True,
        open_world=False,
        sensitivity=Sensitivity.PUBLIC,
    )
    def echo(
        ctx,
        text: Annotated[str, Field(description="Text to echo")],
        times: Annotated[int, Field(ge=1, le=5)] = 1,
    ) -> dict:
        """Echo text back."""
        return {"text": text * times}

    @reg.tool(category="test", read_only=True, output_schema=STATS_SCHEMA)
    def stats(ctx) -> dict:
        """Count the test items."""
        return {"count": len(ITEMS), "names": list(ITEMS)}

    @reg.tool(category="test", idempotent=False)
    async def slow(ctx, steps: int = 3) -> dict:
        """Report progress and log while working."""
        for i in range(1, steps + 1):
            await ctx.report_progress(i, steps, f"step {i}")
            await ctx.log("info", {"step": i})
        return {"done": steps}

    @reg.tool(category="test")
    async def sleepy(ctx, seconds: float = 30.0) -> dict:
        """Sleep (used for cancellation tests)."""
        await asyncio.sleep(seconds)
        return {"slept": seconds}

    @reg.tool(category="test")
    def fail(ctx) -> dict:
        """Always fails."""
        raise ValueError("boom")

    @reg.tool(category="admin", capabilities=(Capability.WRITE_STATE,), destructive=True)
    def touch(ctx, uri: str = "test://info") -> dict:
        """Signal that a resource changed."""
        ctx.layer.notify_change("resource", uri)
        ctx.layer.notify_change("tools")
        return {"touched": uri}

    @reg.tool(category="test")
    def linked(ctx) -> dict:
        """Return a resource link alongside data."""
        ctx.link("test://items/alpha", "alpha", title="Alpha item")
        return {"ok": True}

    @reg.tool(category="test")
    def noisy(ctx) -> dict:
        """Write to stdout from a handler (must never corrupt the stdio stream)."""
        import os
        import sys

        print("NOISE from print()")
        sys.stdout.flush()
        os.write(1, b"NOISE from fd 1\n")
        return {"noisy": True}

    @reg.resource(
        "test://info", name="info", title="Info", category="test", sensitivity=Sensitivity.PUBLIC
    )
    def info(ctx) -> dict:
        """Static info resource."""
        return {"hello": "world"}

    def complete_items(ctx, partial: str) -> list[str]:
        return [i for i in ITEMS if i.startswith(partial)]

    @reg.resource_template(
        "test://items/{item_id}",
        name="item",
        title="Item",
        category="test",
        completions={"item_id": complete_items},
    )
    def item(ctx, item_id: str) -> dict:
        """One test item."""
        if item_id not in ITEMS:
            from cloudg.mcp.core import NotFoundError

            raise NotFoundError(f"No item {item_id}")
        return {"id": item_id, "index": ITEMS.index(item_id)}

    @reg.prompt(
        title="Greet",
        category="test",
        arguments=[
            PromptArgument("name", "Who to greet", required=True, completion=complete_items),
            PromptArgument("style", "formal|casual"),
        ],
    )
    def greet(ctx, name: str, style: str = "casual") -> PromptResult:
        """Greeting prompt."""
        text = f"Good day, {name}." if style == "formal" else f"Hi {name}!"
        return PromptResult([PromptMessage("user", TextContent(text))], "A greeting")

    return reg


def _permissive_policy() -> Any:
    """``None`` (the default profile) as the contract says; while the policy
    module is being written fall back to an empty dict policy."""
    from cloudg.mcp.policy import Policy

    for source in (None, {}):
        try:
            return Policy.load(source)
        except Exception:
            continue
    raise RuntimeError("cannot build a policy")


def build_layer(**kwargs: Any) -> CloudGMCPLayer:
    kwargs.setdefault("registry", build_registry())
    kwargs.setdefault("policy", _permissive_policy())
    kwargs.setdefault("workspace", SimpleNamespace(config=None))
    return CloudGMCPLayer(**kwargs)
