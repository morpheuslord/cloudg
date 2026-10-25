"""Paths, URLs and small text helpers shared by the page generators."""

from __future__ import annotations

import os
import re
import unicodedata
from pathlib import Path

SITE = Path(__file__).resolve().parent.parent
REPO = SITE.parent
GITHUB = "https://github.com/morpheuslord/cloudg"

FENCE_RE = re.compile(r"^(\s*)(`{3,}|~{3,})(.*)$")
HEADING_RE = re.compile(r"^(#{1,6})\s+(.*?)\s*#*\s*$")
# "3. ", "4.2 ", "10.1. " in front of a numbered heading
NUM_PREFIX = re.compile(r"^\d[\d.]*\s+")


def source_ref() -> str:
    """Git ref that source links point at: the commit being built in CI, else main."""
    return os.environ.get("GITHUB_SHA") or "main"


def blob(path: str, line: int = 0, ref: str | None = None) -> str:
    url = f"{GITHUB}/blob/{ref or 'main'}/{path}"
    return url + (f"#L{line}" if line else "")


def version() -> str:
    m = re.search(r'^version\s*=\s*"([^"]+)"', (REPO / "pyproject.toml").read_text(), re.M)
    return m.group(1) if m else "0.0.0"


class FenceTracker:
    """Follows ``` and ~~~ fences so callers can skip lines inside code.

    :meth:`feed` says whether a line belongs to a fenced block, the opening
    and closing fence lines included.
    """

    def __init__(self) -> None:
        self.fence: str | None = None

    def feed(self, line: str) -> bool:
        m = FENCE_RE.match(line)
        if self.fence is None:
            if m:
                self.fence = m.group(2)
            return m is not None
        if m and m.group(2)[0] == self.fence[0] and len(m.group(2)) >= len(self.fence):
            if not m.group(3).strip():
                self.fence = None
        return True


def plain(md: str) -> str:
    """Heading text without inline markup, the way GitHub reads it for anchors."""
    md = re.sub(r"!?\[([^\]]*)\]\([^)]*\)", r"\1", md)
    md = re.sub(r"<[^>]+>", "", md)
    return md.replace("`", "").replace("**", "").strip()


def github_slug(text: str) -> str:
    """The anchor GitHub generates for a heading (before the -1, -2 suffixes)."""
    text = unicodedata.normalize("NFKC", text).strip().lower()
    text = re.sub(r"[^\w\- ]", "", text)
    return text.replace(" ", "-")


def page_slug(title: str) -> str:
    """URL segment for a split page: number prefix dropped, punctuation turned into hyphens."""
    title = NUM_PREFIX.sub("", plain(title)).lower()
    return re.sub(r"[^a-z0-9]+", "-", title).strip("-") or "section"


def with_id(heading_line: str, anchor: str) -> str:
    """Give a markdown heading an explicit id (attr_list)."""
    m = HEADING_RE.match(heading_line)
    if not m:
        return heading_line
    text = re.sub(r"\s*\{#[^}]*\}\s*$", "", m.group(2))
    return f"{m.group(1)} {text} {{ #{anchor} }}"


def first_sentence(md: str, limit: int = 160) -> str:
    """A short plain-text description from the first paragraph of ``md``."""
    for block in re.split(r"\n\s*\n", md):
        block = block.strip()
        if not block or block.startswith(("#", "```", "|", "<", "-", "*", ">", "!!!")):
            continue
        text = " ".join(plain(block).split())
        if len(text) <= limit:
            return text
        return text[: limit - 3].rsplit(" ", 1)[0] + "..."
    return ""


_LIST_ITEM = re.compile(r"^( *)([-*+]|\d+[.)]) +")


def normalise_markdown(text: str) -> str:
    """Adapt CommonMark-style source to Python-Markdown.

    The docs/*.md files are written for GitHub, where a nested list may be
    indented by two or three spaces and a table or list may follow a
    paragraph line directly. Python-Markdown needs four spaces per level and
    a blank line before those blocks, so both are added here. Code fences
    are left alone, except that a fence inside a list item moves with it.
    """
    out: list[str] = []
    stack: list[tuple[int, int]] = []  # (source content column, output content column)
    fence: str | None = None
    fence_shift = 0
    prev = ""
    for line in text.split("\n"):
        if fence is not None:
            fm = FENCE_RE.match(line)
            out.append(_shift(line, fence_shift))
            if fm and fm.group(2)[0] == fence[0] and len(fm.group(2)) >= len(fence):
                if not fm.group(3).strip():
                    fence = None
            prev = line
            continue
        if not line.strip():
            out.append(line)
            prev = line
            continue
        ind = len(line) - len(line.lstrip(" "))
        while stack and ind < stack[-1][0]:
            stack.pop()
        m = _LIST_ITEM.match(line)
        if m:
            new_ind = stack[-1][1] if stack else ind
            if stack and ind > stack[-1][0]:
                new_ind = stack[-1][1] + (ind - stack[-1][0])
            content_col = len(m.group(0))
            stack.append((content_col, new_ind + 4))
            if (
                not ind
                and prev.strip()
                and not _LIST_ITEM.match(prev)
                and not prev.startswith((" ", "|", "#", "<", ">"))
            ):
                out.append("")
            out.append(" " * new_ind + line.lstrip(" "))
        else:
            shift = (stack[-1][1] - stack[-1][0]) if stack else 0
            if line.lstrip().startswith("|") and prev.strip() and not prev.lstrip().startswith("|"):
                out.append("")
            out.append(_shift(line, shift))
            fm = FENCE_RE.match(line)
            if fm:
                fence, fence_shift = fm.group(2), shift
        prev = line
    return "\n".join(out)


def _shift(line: str, n: int) -> str:
    if n <= 0 or not line.strip():
        return line
    return " " * n + line
