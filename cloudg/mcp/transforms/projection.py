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
from dataclasses import dataclass, replace
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
        self._done: dict[State, bool] = {}
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
        hit = self._done.get(states)
        if hit is None:
            hit = any(pos == len(self.segs[pi]) for pi, pos in states)
            if len(self._done) > 20_000:
                self._done.clear()
            self._done[states] = hit
        return hit


@dataclass(frozen=True)
class ProjectionOptions:
    """Options of :class:`Projection` (see the module docstring)."""

    include: tuple[str, ...] = ()
    exclude: tuple[str, ...] = ()
    allow_keys: tuple[str, ...] | None = None
    allow_keys_by_sensitivity: dict[str, tuple[str, ...]] | None = None
    max_depth: int | None = None
    max_list: int | None = None
    max_string: int | None = None
    drop_nulls: bool = False
    drop_empty: bool = False
    max_chars: int | None = None
    list_marker: bool = True
    min_list: int = 1
    min_string: int = 64


Limits = tuple[Any, Any, Any]


class Projection:
    """Shape output data. See the module docstring for the options (keyword
    arguments, or one :class:`ProjectionOptions`)."""

    name = "project"

    def __init__(self, options: ProjectionOptions | None = None, **kwargs: Any) -> None:
        for k in ("include", "exclude", "allow_keys"):
            if kwargs.get(k) is not None:
                kwargs[k] = tuple(kwargs[k])
        opts = replace(options, **kwargs) if options is not None else ProjectionOptions(**kwargs)
        self.options = opts
        self.include = _Patterns(opts.include)
        self.exclude = _Patterns(opts.exclude)
        self.allow_keys = self._key_globs(opts.allow_keys)
        self.allow_by_sensitivity = {
            str(k): self._key_globs(v) for k, v in (opts.allow_keys_by_sensitivity or {}).items()
        }
        self.max_depth = opts.max_depth
        self.max_list = opts.max_list
        self.max_string = opts.max_string
        self.drop_nulls = opts.drop_nulls
        self.drop_empty = opts.drop_empty
        self.max_chars = opts.max_chars
        self.list_marker = opts.list_marker
        self.min_list = max(0, opts.min_list)
        self.min_string = max(8, opts.min_string)

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
        stats: dict[str, Any] = {}
        limits = (self.max_depth, self.max_list, self.max_string)
        if isinstance(value, str):
            out: Any = _shape_str(value, self.max_string, stats)
        else:
            out = self._run(value, allow, limits, stats)
        if self.max_chars:
            out = _Budget(self, allow, stats).fit(value, out, limits, ctx)
        if stats:
            sec = ctx.report.setdefault("projection", {})
            for k, v in stats.items():
                if isinstance(v, int) and isinstance(sec.get(k), int):
                    sec[k] += v
                else:
                    sec[k] = v
        return out

    def _run(self, value: Any, allow: Any, limits: Limits, stats: dict[str, Any]) -> Any:
        inc = self.include.initial if self.include else None
        exc = self.exclude.initial if self.exclude else None
        out = _Shaper(self, allow, limits, stats).walk(value, inc, exc, 0)
        if out is _MISSING:
            return {} if isinstance(value, dict) else ([] if isinstance(value, list) else None)
        return out

    # Kept for callers of the old private helper
    def _shape_str(self, s: str, max_string: int | None, stats: dict[str, Any]) -> str:
        return _shape_str(s, max_string, stats)

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


def _bump(stats: dict[str, Any], key: str) -> None:
    stats[key] = stats.get(key, 0) + 1


def _shape_str(s: str, max_string: int | None, stats: dict[str, Any]) -> str:
    if max_string is not None and len(s) > max_string:
        _bump(stats, "strings_truncated")
        return f"{s[:max_string]}… [+{len(s) - max_string} chars]"
    return s


class _Shaper:
    """One projection walk with fixed key allowlist and limits."""

    __slots__ = ("p", "allow", "max_depth", "max_list", "max_string", "stats")

    def __init__(self, p: Projection, allow: Any, limits: Limits, stats: dict[str, Any]) -> None:
        self.p = p
        self.allow = allow
        self.max_depth, self.max_list, self.max_string = limits
        self.stats = stats

    def walk(self, v: Any, inc: State | None, exc: State | None, depth: int) -> Any:
        p = self.p
        if exc and p.exclude.complete(exc):
            _bump(self.stats, "excluded")
            return _MISSING
        if inc is not None and p.include.complete(inc):
            inc = None  # whole subtree included
        if isinstance(v, (dict, list, tuple)):
            return self.container(v, inc, exc, depth)
        if inc is not None:
            return _MISSING
        if isinstance(v, str):
            return _shape_str(v, self.max_string, self.stats)
        return v

    def container(self, v: Any, inc: State | None, exc: State | None, depth: int) -> Any:
        if inc is not None and not inc:
            return _MISSING
        is_dict = isinstance(v, dict)
        if self.max_depth is not None and depth >= self.max_depth and v:
            _bump(self.stats, "depth_limited")
            return f"<dict: {len(v)} keys>" if is_dict else f"<list: {len(v)} items>"
        if is_dict:
            out: Any = self.walk_dict(v, inc, exc, depth)
        else:
            out = self.walk_list(v, inc, exc, depth)
        if inc is not None and not out:
            return _MISSING
        return out

    def child(self, x: Any, seg: str, inc: State | None, exc: State | None, depth: int) -> Any:
        """Shape one dict value / list item; ``_MISSING`` when it is left out."""
        p = self.p
        child_inc = p.include.advance(inc, seg) if inc is not None else None
        if child_inc is not None and not child_inc:
            return _MISSING
        child_exc = p.exclude.advance(exc, seg) if exc else exc
        res = self.walk(x, child_inc, child_exc, depth + 1)
        if (res is None and p.drop_nulls) or (p.drop_empty and res in ("", [], {})):
            return _MISSING
        return res

    def walk_dict(self, v: dict[Any, Any], inc: Any, exc: Any, depth: int) -> dict[Any, Any]:
        out: dict[Any, Any] = {}
        allow = self.allow
        for k, x in v.items():
            ks = str(k)
            if allow is not None and not allow.match(ks):
                _bump(self.stats, "keys_dropped")
                continue
            res = self.child(x, ks, inc, exc, depth)
            if res is not _MISSING:
                out[k] = res
        return out

    def walk_list(self, v: Any, inc: Any, exc: Any, depth: int) -> list[Any]:
        items = list(v)
        extra = 0
        if self.max_list is not None and len(items) > self.max_list:
            extra = len(items) - self.max_list
            items = items[: self.max_list]
            _bump(self.stats, "lists_truncated")
        out = []
        for i, x in enumerate(items):
            res = self.child(x, str(i), inc, exc, depth)
            if res is not _MISSING:
                out.append(res)
        if extra and self.p.list_marker and (inc is None or out):
            out.append(f"… {extra} more items")
        return out


class _Budget:
    """The ``max_chars`` size guard: tighten list / string limits (then
    depth) until the rendered result fits."""

    def __init__(self, p: Projection, allow: Any, stats: dict[str, Any]) -> None:
        self.p = p
        self.allow = allow
        self.stats = stats
        self.budget = int(p.max_chars or 0)

    def fit(self, original: Any, shaped: Any, limits: Limits, ctx: TransformContext) -> Any:
        size = Projection._size(shaped)
        if size <= self.budget:
            return shaped
        if isinstance(original, str):
            return self._fit_string(original, size)
        first = size
        out, size, final = self._tighten(original, size, limits)
        self.stats["budget"] = {
            "max_chars": self.budget,
            "original_chars": first,
            "final_chars": size,
            **final,
        }
        if size > self.budget:
            ctx.report["truncated"] = True
        return out

    def _fit_string(self, original: str, first: int) -> str:
        budget = self.budget
        out = original[: max(0, budget - 40)] + f"… [+{len(original) - budget + 40} chars]"
        self.stats["budget"] = {
            "max_chars": budget,
            "original_chars": first,
            "final_chars": len(out),
        }
        return out

    def _tighten(self, original: Any, size: int, limits: Limits) -> tuple[Any, int, dict]:
        p, budget = self.p, self.budget
        depth, max_list, max_string = limits
        longest = _longest_list(original)
        cur_list = min(max_list or longest, longest)
        cur_str = max_string or 4000
        out: Any = None
        for _ in range(24):
            ratio = budget / max(size, 1)
            cur_list = max(p.min_list, min(cur_list - 1, int(cur_list * ratio * 0.9)))
            if size > budget * 4 or cur_list <= p.min_list:
                cur_str = max(p.min_string, min(cur_str - 1, int(cur_str * max(ratio, 0.25))))
            if cur_list <= p.min_list and cur_str <= p.min_string:
                depth = max(1, (depth or _depth(original)) - 1)
            trial_stats: dict[str, Any] = {}
            out = p._run(original, self.allow, (depth, cur_list, cur_str), trial_stats)
            size = Projection._size(out)
            if size <= budget or (depth == 1 and cur_list <= p.min_list):
                self.stats.update(trial_stats)
                break
        final = {
            "max_list": cur_list,
            "max_string": cur_str,
            **({"max_depth": depth} if depth else {}),
        }
        return out, size, final


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
