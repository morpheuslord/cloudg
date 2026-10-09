"""Construction options of :class:`~cloudg.mcp.layer.CloudGMCPLayer`.

``CloudGMCPLayer(config, policy=..., prefix=...)`` keeps accepting every
documented keyword argument; they are gathered into a :class:`LayerOptions`,
which can also be passed whole (``CloudGMCPLayer(options=LayerOptions(...))``).
"""

from __future__ import annotations

import dataclasses
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Callable, Iterable

from cloudg.mcp.core import Registry, ToolSpec

if TYPE_CHECKING:  # pragma: no cover
    from cloudg.mcp.policy import Policy
    from cloudg.mcp.state import Workspace

__all__ = ["LayerOptions", "filter_registry"]


@dataclass
class LayerOptions:
    """Every keyword argument of :class:`~cloudg.mcp.layer.CloudGMCPLayer`.

    Attributes:
        workspace: Shared state; created from ``config`` when omitted.
        policy: A :class:`~cloudg.mcp.policy.Policy`, a built-in profile name,
            a path to a YAML/JSON policy file, or a dict.
        registry: Primitives to expose. Defaults to the full cloudg catalog.
        include_categories / exclude_categories: Filter by category.
        include_tools / exclude_tools: Filter by tool name.
        prefix: Prepended to every tool and prompt name.
        middleware: Extra middleware, outermost first.
        default_timeout: Seconds before a tool call is cancelled.
        max_output_chars: Hard cap on the rendered text of one result.
        name / version / instructions: Server identity.
    """

    workspace: "Workspace | None" = None
    policy: "Policy | str | dict[str, Any] | None" = None
    registry: Registry | None = None
    include_categories: Iterable[str] | None = None
    exclude_categories: Iterable[str] | None = None
    include_tools: Iterable[str] | None = None
    exclude_tools: Iterable[str] | None = None
    prefix: str = ""
    middleware: Iterable[Callable[..., Any]] = ()
    default_timeout: float | None = 300.0
    max_output_chars: int = 200_000
    name: str = "cloudg"
    version: str | None = None
    instructions: str | None = None

    @classmethod
    def build(cls, options: "LayerOptions | None", kwargs: dict[str, Any]) -> "LayerOptions":
        """``options`` updated with ``kwargs``; unknown keywords raise
        :class:`TypeError` like a regular signature would."""
        known = {f.name for f in dataclasses.fields(cls)}
        unknown = sorted(set(kwargs) - known)
        if unknown:
            raise TypeError(
                f"CloudGMCPLayer() got unexpected keyword argument(s): {', '.join(unknown)}"
            )
        return dataclasses.replace(options or cls(), **kwargs)


def filter_registry(registry: Registry, opts: LayerOptions) -> Registry:
    """``registry`` restricted by the category / tool filters of ``opts``."""
    inc_c = set(opts.include_categories) if opts.include_categories else None
    exc_c = set(opts.exclude_categories or ())
    inc_t = set(opts.include_tools) if opts.include_tools else None
    exc_t = set(opts.exclude_tools or ())
    if not (inc_c or exc_c or inc_t or exc_t):
        return registry

    def keep(spec: Any) -> bool:
        if inc_c is not None and spec.category not in inc_c:
            return False
        if spec.category in exc_c:
            return False
        if isinstance(spec, ToolSpec):
            return (inc_t is None or spec.name in inc_t) and spec.name not in exc_t
        return True

    out = Registry()
    for spec in [
        *registry.tools.values(),
        *registry.resources.values(),
        *registry.templates.values(),
        *registry.prompts.values(),
    ]:
        if keep(spec):
            out.add(spec)
    return out
