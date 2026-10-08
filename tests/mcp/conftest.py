"""Fixtures shared by every MCP layer test module.

- ``sample_dataset``: an in-memory :class:`~cloudg.mcp.state.Dataset` of
  the synthetic multi-cloud estate (see ``fixtures/sample_estate.py``).
- ``sample_paths``: the same estate written to ``tmp_path`` as
  ``inventory/inventory-map.json`` (+ organization, graph, findings.json)
  and ``report/findings.json``.
- ``workspace``: a :class:`Workspace` rooted at ``tmp_path`` with the
  estate loaded as dataset ``sample`` (active).
- ``layer``: ``CloudGMCPLayer(policy="open", workspace=workspace)``.
- ``call``: ``await call(name, **args)`` -> structured result, asserting
  the tool succeeded (``call.raw`` returns the ToolResult instead).
"""

from __future__ import annotations

from typing import Any

import pytest

from cloudg.config import CloudGConfig
from cloudg.mcp.state import Dataset, Workspace
from tests.mcp.fixtures import sample_estate


@pytest.fixture
def sample_dataset() -> Dataset:
    return Dataset(
        name="sample",
        assets=sample_estate.assets(),
        edges=sample_estate.edges(),
        findings=sample_estate.findings(),
        compliance=sample_estate.compliance(),
        coverage=sample_estate.coverage(),
        organization=sample_estate.organization(),
        unresolved_references=sample_estate.unresolved(),
        providers=["aws", "azure", "gcp"],
        source="inline",
        kind="inventory",
    )


@pytest.fixture
def sample_paths(tmp_path) -> dict[str, Any]:
    return sample_estate.write_estate(tmp_path)


@pytest.fixture
def workspace(tmp_path, sample_paths) -> Workspace:
    ws = Workspace(CloudGConfig(), allowed_roots=[tmp_path], output_dir=tmp_path / "out")
    ws.load(sample_paths["inventory_dir"], "sample")
    return ws


@pytest.fixture
def layer(workspace):
    from cloudg.mcp.layer import CloudGMCPLayer

    return CloudGMCPLayer(policy="open", workspace=workspace)


class _Caller:
    def __init__(self, layer: Any) -> None:
        self.layer = layer

    async def raw(self, tool: str, /, **args: Any):
        return await self.layer.call_tool(tool, args)

    async def __call__(self, tool: str, /, **args: Any) -> dict[str, Any]:
        res = await self.layer.call_tool(tool, args)
        assert not res.is_error, f"{tool} failed: {res.content[0].text if res.content else res}"
        assert res.structured is not None
        return res.structured

    async def error(self, tool: str, /, **args: Any) -> str:
        res = await self.layer.call_tool(tool, args)
        assert res.is_error, f"{tool} unexpectedly succeeded: {res.structured}"
        return res.content[0].text


@pytest.fixture
def call(layer) -> _Caller:
    return _Caller(layer)
