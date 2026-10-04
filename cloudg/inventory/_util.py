"""Small helpers shared by the inventory collectors and the linker."""

from __future__ import annotations

from typing import Any, Iterator


def image_repository(image: str) -> str:
    """Strip tag/digest from an image reference: repo URI used for linking."""
    ref = image.split("@", 1)[0]
    last = ref.rsplit("/", 1)[-1]
    if ":" in last:
        ref = ref[: len(ref) - len(last)] + last.split(":", 1)[0]
    return ref


def walk_strings(value: Any, max_depth: int = 12) -> Iterator[str]:
    """Every string inside a nested dict/list/tuple value, depth-limited."""
    stack: list[tuple[Any, int]] = [(value, 0)]
    while stack:
        item, depth = stack.pop()
        if depth > max_depth:
            continue
        if isinstance(item, str):
            yield item
        elif isinstance(item, dict):
            stack.extend((v, depth + 1) for v in reversed(list(item.values())))
        elif isinstance(item, (list, tuple)):
            stack.extend((v, depth + 1) for v in reversed(item))
