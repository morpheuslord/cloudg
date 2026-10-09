"""Linear-time replacement of known values inside free text.

The vault reverses its tokens inside text, and the output side replaces
real values it already pseudonymised (exports, error messages). Both need
"find every known string in this text" without a regex alternation of
thousands of values and without backtracking patterns.

Text is cut into *runs* of identifier characters (one character class
with ``+``, so matching is linear). Each run is cut again at the
separators ``. : / @`` into parts. A candidate is any span of up to
``max_parts`` consecutive parts that starts and ends on a part boundary;
the longest known span starting at a part wins, left to right. A value
therefore matches only as a whole "word" (``web-1`` inside ``cmr:web-1``
or ``arn:...:web-1`` yes, inside ``web-10`` or ``my_web-1`` no), and the
cost per character is bounded by ``max_parts``.
"""

from __future__ import annotations

import re
from typing import Callable

_RUN_RE = re.compile(r"[A-Za-z0-9_\-.:/@%+#~]+")
_SEP_RE = re.compile(r"[.:/@]")

#: ``lookup(candidate) -> replacement or None``
Lookup = Callable[[str], "str | None"]
#: ``on_hit(original, replacement)``
OnHit = Callable[[str, str], None]


def _replace_run(
    run: str, lookup: Lookup, on_hit: OnHit | None, max_parts: int, max_len: int
) -> str:
    starts = [0]
    ends = []
    for m in _SEP_RE.finditer(run):
        ends.append(m.start())
        starts.append(m.end())
    ends.append(len(run))
    k = len(starts)
    out: list[str] = []
    pos = 0
    i = 0
    while i < k:
        hit_j = -1
        rep = None
        for j in range(min(k, i + max_parts) - 1, i - 1, -1):
            if ends[j] <= starts[i] or ends[j] - starts[i] > max_len:
                continue
            rep = lookup(run[starts[i] : ends[j]])
            if rep is not None:
                hit_j = j
                break
        if hit_j < 0:
            i += 1
            continue
        if on_hit is not None:
            on_hit(run[starts[i] : ends[hit_j]], rep)  # type: ignore[arg-type]
        out.append(run[pos : starts[i]])
        out.append(rep)  # type: ignore[arg-type]
        pos = ends[hit_j]
        i = hit_j + 1
    if not out:
        return run
    out.append(run[pos:])
    return "".join(out)


def replace_known(
    text: str,
    lookup: Lookup,
    *,
    on_hit: OnHit | None = None,
    max_parts: int = 16,
    max_len: int = 1024,
) -> str:
    """Replace every known value inside ``text`` (see the module docstring).
    ``on_hit`` is called with ``(found, replacement)`` for each replacement."""
    if not text:
        return text

    def sub(m: re.Match[str]) -> str:
        run = m.group(0)
        rep = lookup(run)
        if rep is not None:
            if on_hit is not None:
                on_hit(run, rep)
            return rep
        return _replace_run(run, lookup, on_hit, max_parts, max_len)

    return _RUN_RE.sub(sub, text)


__all__ = ["replace_known"]
