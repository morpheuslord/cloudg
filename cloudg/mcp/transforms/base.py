"""Transform contracts.

A :class:`Transform` rewrites JSON-like data (``dict`` / ``list`` / ``str``
/ numbers / ``None``) either on its way out of the layer (redacting,
masking, pseudonymising, projecting, annotating or substituting values) or
on its way in. Input transforms reverse pseudonyms in tool arguments, so the
model can refer to an alias and the tool still resolves the real asset.

A :class:`Pipeline` is an ordered list of transforms. Policies
(:mod:`cloudg.mcp.policy`) assemble the pipeline for each primitive and
principal.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Iterable, Protocol, runtime_checkable

if TYPE_CHECKING:  # pragma: no cover
    from cloudg.mcp.context import Principal
    from cloudg.mcp.core import _BaseSpec
    from cloudg.mcp.transforms.vault import TokenVault


@dataclass
class TransformContext:
    """State shared by the transforms of one pipeline run."""

    principal: "Principal | None" = None
    spec: "_BaseSpec | None" = None
    kind: str = "tool"  # tool | resource | prompt
    direction: str = "output"  # output | input
    vault: "TokenVault | None" = None
    # Transforms record what they did here (counts per detector, fields
    # dropped, truncation...). The layer returns it under
    # ``_meta["cloudg/transforms"]`` so clients can tell data was altered.
    report: dict[str, Any] = field(default_factory=dict)

    def count(self, key: str, n: int = 1) -> None:
        self.report[key] = self.report.get(key, 0) + n


@runtime_checkable
class Transform(Protocol):
    """One data transformation step."""

    name: str

    def apply(self, value: Any, ctx: TransformContext) -> Any:
        """Return the transformed value. Must not mutate ``value``."""
        ...


class Pipeline:
    """Ordered sequence of transforms; itself a :class:`Transform`."""

    name = "pipeline"

    def __init__(self, transforms: Iterable[Transform] = ()) -> None:
        self.transforms: list[Transform] = list(transforms)

    def apply(self, value: Any, ctx: TransformContext) -> Any:
        for t in self.transforms:
            value = t.apply(value, ctx)
        return value

    def __bool__(self) -> bool:
        return bool(self.transforms)

    def __len__(self) -> int:
        return len(self.transforms)

    def __repr__(self) -> str:
        return f"Pipeline({[t.name for t in self.transforms]})"


IDENTITY = Pipeline()
