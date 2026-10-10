"""Line-by-line tracking of fenced code blocks in markdown sources."""

from __future__ import annotations

import re

FENCE_RE = re.compile(r"^\s{0,3}(`{3,}|~{3,})(.*)$")


class FenceTracker:
    """Follows ``` and ~~~ fences so callers can skip lines inside code.

    Feed every line in order; :meth:`feed` says whether that line belongs to a
    fenced block (the opening and closing fence lines included).
    """

    def __init__(self) -> None:
        self.fence: str | None = None

    def feed(self, line: str) -> bool:
        m = FENCE_RE.match(line)
        if self.fence is None:
            if m:
                self.fence = m.group(1)
            return m is not None
        if m and self._closes(m):
            self.fence = None
        return True

    def _closes(self, m: re.Match) -> bool:
        mark = m.group(1)
        return mark[0] == self.fence[0] and len(mark) >= len(self.fence) and not m.group(2).strip()
