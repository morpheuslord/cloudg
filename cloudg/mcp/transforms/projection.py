"""Field projection and output shaping.

:class:`Projection` keeps results small and on-topic (data minimisation):

* ``include`` / ``exclude``: dotted-path globs. ``*`` matches one
  segment (a dict key or a list index), ``**`` any number of segments, and
  each segment is an ``fnmatch`` glob: ``assets.*.metadata.raw*``,
  ``**.tags``, ``findings.*.evidence``. With ``include`` only matching
  subtrees (and the containers leading to them) survive.
* ``allow_keys``: key-name globs allowed at any depth (others dropped);
  ``allow_keys_by_sensitivity`` picks the list by the primitive's
  sensitivity (``{"internal": ["id", "name", "*_count"]}``).
* ``max_depth``: deeper containers become ``"<dict: 12 keys>"`` /
  ``"<list: 40 items>"`` summaries.
* ``max_list``: long lists keep the first N items plus a
  ``"… 123 more items"`` marker.
* ``max_string``: long strings are cut with ``"… [+N chars]"``.
* ``drop_nulls`` / ``drop_empty`` remove ``None`` / empty values.
* ``max_chars`` is a size guard. When the rendered text (the layer's
  ``render_json``: indented JSON) exceeds the
  budget, list and string limits are tightened progressively (then depth)
  until it fits.

Path matching is incremental (an NFA over pattern positions carried down
the walk), so the cost is linear in the size of the data.
"""

from __future__ import annotations

import fnmatch
import re
from typing import Any, Iterable

from cloudg.mcp.core import render_json
from cloudg.mcp.transforms.base import TransformContext

_MISSING = object()
State = frozenset[tuple[int, int]]


class _Patterns:
    """Compiled dotted-path globs."""

    def __init__(self, patterns: Iterable[str]) -> None:
        self.raw = [p for p in patterns if p]
        self.segs: list[list[Any]] = []
        for p in self.raw:
            segs: list[Any] = []
            for s in p.split("."):
                if s == "**":
                    segs.append("**")
                elif s == "*":
                    segs.append("*")
                elif any(c in s for c in "*?["):
                    segs.append(re.compile(fnmatch.translate(s)))
                else:
                    segs.append(s)
            self.segs.append(segs)
        self._memo: dict[tuple[State, str], State] = {}
        self.initial: State = self._closure({(i, 0) for i in range(len(self.segs))})

    def __bool__(self) -> bool:
        return bool(self.segs)

    def _closure(self, states: set[tuple[int, int]]) -> State:
        """``**`` may match zero segments: add the positions after it."""
        out = set(states)
        stack = list(states)
        while stack:
            pi, pos = stack.pop()
            segs = self.segs[pi]
            if pos < len(segs) and segs[pos] == "**" and (pi, pos + 1) not in out:
                out.add((pi, pos + 1))
                stack.append((pi, pos + 1))
        return frozenset(out)

    def advance(self, states: State, seg: str) -> State:
        if not states:
            return states
        key = (states, seg)
        hit = self._memo.get(key)
        if hit is not None:
            return hit
        nxt: set[tuple[int, int]] = set()
        for pi, pos in states:
            segs = self.segs[pi]
            if pos >= len(segs):
                continue
            s = segs[pos]
            if s == "**":
                nxt.add((pi, pos))
            elif s == "*" or s == seg or (not isinstance(s, str) and s.match(seg)):
                nxt.add((pi, pos + 1))
        out = self._closure(nxt)
        if len(self._memo) > 20_000:
            self._memo.clear()
        self._memo[key] = out
        return out

    def complete(self, states: State) -> bool:
        return any(pos == len(self.segs[pi]) for pi, pos in states)


class Projection:
    """Shape output data. See the module docstring for the options."""

    name = "project"

    def __init__(
        self,
        *,
        include: Iterable[str] = (),
        exclude: Iterable[str] = (),
        allow_keys: Iterable[str] | None = None,
        allow_keys_by_sensitivity: dict[str, Iterable[str]] | None = None,
        max_depth: int | None = None,
        max_list: int | None = None,
        max_string: int | None = None,
        drop_nulls: bool = False,
        drop_empty: bool = False,
        max_chars: int | None = None,
        list_marker: bool = True,
        min_list: int = 1,
        min_string: int = 64,
    ) -> None:
        self.include = _Patterns(include)
        self.exclude = _Patterns(exclude)
        self.allow_keys = self._key_globs(allow_keys)
        self.allow_by_sensitivity = {
            str(k): self._key_globs(v) for k, v in (allow_keys_by_sensitivity or {}).items()
        }
        self.max_depth = max_depth
        self.max_list = max_list
        self.max_string = max_string
        self.drop_nulls = drop_nulls
        self.drop_empty = drop_empty
        self.max_chars = max_chars
        self.list_marker = list_marker
        self.min_list = max(0, min_list)
        self.min_string = max(8, min_string)

    @staticmethod
    def _key_globs(globs: Iterable[str] | None) -> re.Pattern[str] | None:
        if globs is None:
            return None
        pats = list(globs)
        return re.compile("|".join(f"(?:{fnmatch.translate(g)})" for g in pats) or r"(?!)")

    # ------------------------------------------------------------------

    def apply(self, value: Any, ctx: TransformContext) -> Any:
        allow = self.allow_keys
        spec = ctx.spec
        if spec is not None and self.allow_by_sensitivity:
            sens = getattr(getattr(spec, "sensitivity", None), "value", None)
            if sens in self.allow_by_sensitivity:
                allow = self.allow_by_sensitivity[sens]
        stats: dict[str, int] = {}
        limits = (self.max_depth, self.max_list, self.max_string)
        if isinstance(value, str):
            out: Any = self._shape_str(value, self.max_string, stats)
        else:
            out = self._run(value, allow, limits, stats)
        if self.max_chars:
            out = self._fit(value, out, allow, limits, stats, ctx)
        if stats:
            sec = ctx.report.setdefault("projection", {})
            for k, v in stats.items():
                if isinstance(v, int) and isinstance(sec.get(k), int):
                    sec[k] += v
                else:
                    sec[k] = v
        return out

    def _run(
        self, value: Any, allow: Any, limits: tuple[Any, Any, Any], stats: dict[str, int]
    ) -> Any:
        inc = self.include.initial if self.include else None
        exc = self.exclude.initial if self.exclude else None
        out = self._walk(value, inc, exc, 0, allow, limits, stats)
        if out is _MISSING:
            return {} if isinstance(value, dict) else ([] if isinstance(value, list) else None)
        return out

    # ------------------------------------------------------------------

    def _shape_str(self, s: str, max_string: int | None, stats: dict[str, int]) -> str:
        if max_string is not None and len(s) > max_string:
            stats["strings_truncated"] = stats.get("strings_truncated", 0) + 1
            return f"{s[:max_string]}… [+{len(s) - max_string} chars]"
        return s

    def _walk(
        self,
        v: Any,
        inc: State | None,
        exc: State | None,
        depth: int,
        allow: Any,
        limits: tuple[Any, Any, Any],
        stats: dict[str, int],
    ) -> Any:
        if exc is not None and exc and self.exclude.complete(exc):
            stats["excluded"] = stats.get("excluded", 0) + 1
            return _MISSING
        if inc is not None and self.include.complete(inc):
            inc = None  # whole subtree included
        max_depth, max_list, max_string = limits
        if isinstance(v, dict):
            if inc is not None and not inc:
                return _MISSING
            if max_depth is not None and depth >= max_depth and v:
                stats["depth_limited"] = stats.get("depth_limited", 0) + 1
                return f"<dict: {len(v)} keys>"
            out: dict[Any, Any] = {}
            for k, x in v.items():
                ks = str(k)
                if allow is not None and not allow.match(ks):
                    stats["keys_dropped"] = stats.get("keys_dropped", 0) + 1
                    continue
                child_inc = self.include.advance(inc, ks) if inc is not None else None
                if child_inc is not None and not child_inc:
                    continue
                child_exc = self.exclude.advance(exc, ks) if exc else exc
                res = self._walk(x, child_inc, child_exc, depth + 1, allow, limits, stats)
                if res is _MISSING:
                    continue
                if res is None and self.drop_nulls:
                    continue
                if self.drop_empty and res in ("", [], {}):
                    continue
                out[k] = res
            if inc is not None and not out:
                return _MISSING
            return out
        if isinstance(v, (list, tuple)):
            if inc is not None and not inc:
                return _MISSING
            if max_depth is not None and depth >= max_depth and v:
                stats["depth_limited"] = stats.get("depth_limited", 0) + 1
                return f"<list: {len(v)} items>"
            items = list(v)
            extra = 0
            if max_list is not None and len(items) > max_list:
                extra = len(items) - max_list
                items = items[:max_list]
                stats["lists_truncated"] = stats.get("lists_truncated", 0) + 1
            out_list = []
            for i, x in enumerate(items):
                si = str(i)
                child_inc = self.include.advance(inc, si) if inc is not None else None
                if child_inc is not None and not child_inc:
                    continue
                child_exc = self.exclude.advance(exc, si) if exc else exc
                res = self._walk(x, child_inc, child_exc, depth + 1, allow, limits, stats)
                if res is _MISSING:
                    continue
                if res is None and self.drop_nulls:
                    continue
                if self.drop_empty and res in ("", [], {}):
                    continue
                out_list.append(res)
            if inc is not None and not out_list:
                return _MISSING
            if extra and self.list_marker:
                out_list.append(f"… {extra} more items")
            return out_list
        # scalar
        if inc is not None:
            return _MISSING
        if isinstance(v, str):
            return self._shape_str(v, max_string, stats)
        return v

    # ------------------------------------------------------------------
    # Budget guard
    # ------------------------------------------------------------------

    @staticmethod
    def _size(v: Any) -> int:
        """Characters of the text the client receives: the layer renders
        structured results with :func:`cloudg.mcp.core.render_json`."""
        if isinstance(v, str):
            return len(v)
        try:
            return len(render_json(v))
        except (TypeError, ValueError):  # pragma: no cover
            return len(str(v))

    def _fit(
        self,
        original: Any,
        shaped: Any,
        allow: Any,
        limits: tuple[Any, Any, Any],
        stats: dict[str, int],
        ctx: TransformContext,
    ) -> Any:
        budget = int(self.max_chars or 0)
        size = self._size(shaped)
        if size <= budget:
            return shaped
        first = size
        if isinstance(original, str):
            out = original[: max(0, budget - 40)] + f"… [+{len(original) - budget + 40} chars]"
            stats["budget"] = {
                "max_chars": budget,
                "original_chars": first,  # type: ignore
                "final_chars": len(out),
            }
            return out
        depth, max_list, max_string = limits
        longest = _longest_list(original)
        cur_list = min(max_list or longest, longest)
        cur_str = max_string or 4000
        out = shaped
        for _ in range(24):
            ratio = budget / max(size, 1)
            cur_list = max(self.min_list, min(cur_list - 1, int(cur_list * ratio * 0.9)))
            if size > budget * 4 or cur_list <= self.min_list:
                cur_str = max(self.min_string, min(cur_str - 1, int(cur_str * max(ratio, 0.25))))
            if cur_list <= self.min_list and cur_str <= self.min_string:
                depth = max(1, (depth or _depth(original)) - 1)
            trial_stats: dict[str, int] = {}
            out = self._run(original, allow, (depth, cur_list, cur_str), trial_stats)
            size = self._size(out)
            if size <= budget or (depth == 1 and cur_list <= self.min_list):
                stats.update(trial_stats)
                break
        stats["budget"] = {  # type: ignore[assignment]
            "max_chars": budget,
            "original_chars": first,
            "final_chars": size,
            "max_list": cur_list,
            "max_string": cur_str,
            **({"max_depth": depth} if depth else {}),
        }
        if size > budget:
            ctx.report["truncated"] = True
        return out


def _longest_list(v: Any) -> int:
    best = 0
    stack = [v]
    while stack:
        x = stack.pop()
        if isinstance(x, dict):
            stack.extend(x.values())
        elif isinstance(x, (list, tuple)):
            best = max(best, len(x))
            stack.extend(x)
    return best


def _depth(v: Any) -> int:
    best = 0
    stack = [(v, 0)]
    while stack:
        x, d = stack.pop()
        if isinstance(x, dict):
            best = max(best, d + 1)
            stack.extend((y, d + 1) for y in x.values())
        elif isinstance(x, (list, tuple)):
            best = max(best, d + 1)
            stack.extend((y, d + 1) for y in x)
    return best
