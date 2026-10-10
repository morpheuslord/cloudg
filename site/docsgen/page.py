"""The page model and the small helpers the build steps share."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

SITE = Path(__file__).resolve().parent.parent
REPO = SITE.parent
GITHUB = "https://github.com/morpheuslord/cloudg"
PYPI = "https://pypi.org/project/cloudg/"

# "3. ", "4.2 ", "10.1. " in front of a numbered heading
NUM_PREFIX = re.compile(r"^\d[\d.]*\s+")


@dataclass
class Page:
    url: str  # "guides/quickstart"; "" for home
    title: str
    tab: str = ""
    group: str = ""
    kind: str = "guide"
    search_type: str = "Guides"
    source: str = ""  # repo-relative file the content comes from
    source_line: int = 0
    nav_title: str = ""
    in_sidebar: bool = True
    level: int = 1
    mono_title: bool = False
    # filled in by the renderers
    body: str = ""
    headings: list = field(default_factory=list)
    lede: str = ""
    meta: list = field(default_factory=list)
    since: str = ""
    crumbs: list = field(default_factory=list)
    extra: dict = field(default_factory=dict)
    toc_label: str = "On this page"
    # inputs for deferred rendering
    loader: object = None
    prev: Page | None = None
    next: Page | None = None
    description: str = ""


def page_slug(title: str) -> str:
    """URL segment for a split page: number prefix dropped, punctuation turned into hyphens."""
    title = NUM_PREFIX.sub("", title).lower()
    return re.sub(r"[^a-z0-9]+", "-", title).strip("-") or "section"


def truncate(text: str, n: int) -> str:
    text = " ".join(text.split())
    return text if len(text) <= n else text[: n - 1].rsplit(" ", 1)[0] + "…"


def line_of(path: Path, needle: str) -> int:
    """1-based number of the first line of ``path`` starting with ``needle``, or 0."""
    for i, line in enumerate(path.read_text().split("\n"), start=1):
        if line.startswith(needle):
            return i
    return 0
