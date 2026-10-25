"""Link rewriting for generated pages.

The docs/*.md references and CHANGELOG.md link to each other the way GitHub
resolves links: relative file paths and ``#anchors`` of the single-file
documents. On the site those documents are split into many pages, so every
link is pointed at the page that now holds its target. Links to repository
files that are not on the site go to GitHub.
"""

from __future__ import annotations

import posixpath
import re
from collections.abc import Callable

from gen.common import FENCE_RE, GITHUB

_PASS_THROUGH = ("http://", "https://", "mailto:", "data:", "//")
# [text](target) and [text](target "title"), not images' inner part
_LINK = re.compile(r"(\]\()([^)\s]+)((?:\s+\"[^\"]*\")?\))")
_CODE_SPAN = re.compile(r"(`+)(.+?)\1")


class LinkMap:
    """Where the targets of repository-relative links live on the site."""

    def __init__(self) -> None:
        # "docs/MCP.md" -> {GitHub anchor: (docs-dir uri, anchor on that page)}
        self.anchors: dict[str, dict[str, tuple[str, str]]] = {}
        # "docs/MCP.md" -> docs-dir uri of its overview page
        self.first_page: dict[str, str] = {}
        # other repository files with a page of their own: "CHANGELOG.md" -> "changelog.md"
        self.files: dict[str, str] = {}

    def resolver(self, source: str, page_uri: str) -> Callable[[str], str]:
        """A function rewriting hrefs found in ``source`` as it appears on ``page_uri``."""
        return lambda href: self.resolve(source, page_uri, href)

    def resolve(self, source: str, page_uri: str, href: str) -> str:
        if not href or href.startswith(_PASS_THROUGH):
            return href
        path, _, anchor = href.partition("#")
        if not path:
            target = source
        else:
            target = posixpath.normpath(posixpath.join(posixpath.dirname(source), path))
        if target.startswith("../"):
            return href
        found = self._uri_for(target, anchor)
        if found is None:
            return f"{GITHUB}/blob/main/{target}" + (f"#{anchor}" if anchor else "")
        uri, anchor = found
        if uri == page_uri:
            return f"#{anchor}" if anchor else "#"
        rel = posixpath.relpath(uri, posixpath.dirname(page_uri) or ".")
        return rel + (f"#{anchor}" if anchor else "")

    def _uri_for(self, target: str, anchor: str) -> tuple[str, str] | None:
        if target in self.anchors:
            if anchor and anchor in self.anchors[target]:
                return self.anchors[target][anchor]
            if anchor:
                return None  # unknown heading: GitHub still has the original
            return self.first_page[target], ""
        if target in self.files:
            return self.files[target], anchor
        return None


def rewrite(lines: list[str], resolve: Callable[[str], str]) -> list[str]:
    """Rewrite inline markdown links outside code fences and code spans."""
    out = []
    in_fence: str | None = None
    for line in lines:
        m = FENCE_RE.match(line)
        if in_fence is not None:
            if m and m.group(2)[0] == in_fence[0] and len(m.group(2)) >= len(in_fence):
                if not m.group(3).strip():
                    in_fence = None
            out.append(line)
            continue
        if m:
            in_fence = m.group(2)
            out.append(line)
            continue
        out.append(_rewrite_line(line, resolve))
    return out


def _rewrite_line(line: str, resolve: Callable[[str], str]) -> str:
    if "](" not in line:
        return line
    parts = []
    pos = 0
    for cm in _CODE_SPAN.finditer(line):
        parts.append(
            _LINK.sub(
                lambda m: m.group(1) + resolve(m.group(2)) + m.group(3), line[pos : cm.start()]
            )
        )
        parts.append(cm.group(0))
        pos = cm.end()
    parts.append(_LINK.sub(lambda m: m.group(1) + resolve(m.group(2)) + m.group(3), line[pos:]))
    return "".join(parts)
