"""Long docs/*.md references split into one page per section.

Every H2 becomes a page. An H2 section over ``SPLIT_H3_BYTES`` with at least
three H3s is split again, one page per H3. The heading anchors GitHub gives
the original file are mapped to the page that now holds each heading, so
links into the old single-file document keep working.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

from docsgen.fences import FenceTracker
from docsgen.md import github_slug
from docsgen.page import NUM_PREFIX, REPO, Page, page_slug

if TYPE_CHECKING:
    from docsgen.site import Site

SPLIT_H3_BYTES = 40_000
_HEADING_RE = re.compile(r"^(#{1,6})\s+(.*?)\s*#*\s*$")

# (level, text, line index)
HeadingLine = tuple[int, str, int]


def scan_headings(lines: list[str]) -> list[HeadingLine]:
    """ATX headings outside fenced code."""
    out = []
    fences = FenceTracker()
    for i, line in enumerate(lines):
        if fences.feed(line):
            continue
        m = _HEADING_RE.match(line)
        if m:
            out.append((len(m.group(1)), m.group(2), i))
    return out


def _bounds(heads: list[HeadingLine], end: int) -> list[tuple[HeadingLine, int]]:
    """Pair each heading with the line index where its section ends."""
    return [(h, heads[i + 1][2] if i + 1 < len(heads) else end) for i, h in enumerate(heads)]


def _needs_h3_split(body_lines: list[str], h3s: list[HeadingLine]) -> bool:
    return sum(len(x) + 1 for x in body_lines) > SPLIT_H3_BYTES and len(h3s) >= 3


class SplitDoc:
    """Discovers the pages of one split document for a nav group."""

    def __init__(self, site: Site, tab: str, group: dict):
        self.site = site
        self.tab = tab
        self.group = group
        self.name = (REPO / group["split"]).name
        self.prefix = group["prefix"]
        self.skip = set(group.get("skip", []))
        self.lines = (REPO / group["split"]).read_text().split("\n")
        self.heads = scan_headings(self.lines)
        self.search_type = "MCP" if tab == "mcp" else "Reference"
        self.pages: list[Page] = []
        self.slug_counts: dict[str, int] = {}
        # slugs taken by titles and skipped sections since the last page rendered
        self.pending: list[str] = []
        self.shared: dict[str, int] = {}

    # -- slugs and anchors -----------------------------------------------------

    def _unique(self, slug: str) -> str:
        """The anchor GitHub gives the n-th heading with this slug."""
        if slug in self.slug_counts:
            self.slug_counts[slug] += 1
            return f"{slug}-{self.slug_counts[slug]}"
        self.slug_counts[slug] = 0
        return slug

    def _consume(self, slug: str) -> str:
        """Take a slug the page renderer will not see, and remember it for that renderer."""
        self.pending.append(slug)
        return self._unique(slug)

    def _map(self, heading_text: str, url: str) -> None:
        anchor = self._unique(github_slug(self.site.plain(heading_text)))
        self.site.anchor_map[(self.name, anchor)] = url

    def _claim_title(self, page: Page, title: str) -> None:
        anchor = self._consume(github_slug(title))
        page.extra["title_anchor"] = anchor
        page.extra["pre_slugs"] = list(self.pending)
        self.pending.clear()
        self.site.anchor_map[(self.name, anchor)] = page.url

    # -- pages -----------------------------------------------------------------

    def _page(self, url: str, title: str, **kwargs) -> Page:
        page = Page(
            url,
            title,
            tab=self.tab,
            group=self.group["title"],
            search_type=self.search_type,
            source=self.group["split"],
            **kwargs,
        )
        self.pages.append(self.site.add(page))
        return page

    def discover(self) -> list[Page]:
        h2s = [h for h in self.heads if h[0] == 2]
        first_h2 = h2s[0][2] if h2s else len(self.lines)
        overview = self._overview(first_h2)
        for h, end in _bounds(h2s, len(self.lines)):
            self._section(overview, h, end)
        self._add_fragments()
        return self.pages

    def _overview(self, first_h2: int) -> Page:
        """Overview page from the text above the first H2."""
        h1 = next((h for h in self.heads if h[0] == 1), None)
        intro_start = h1[2] + 1 if h1 else 0
        title = self.site.plain(h1[1]) if h1 else self.group["title"]
        overview = self._page(self.prefix, title, kind="split-index", nav_title="Overview")
        overview.extra = {
            "doc": self.name,
            "md": "\n".join(self.lines[intro_start:first_h2]).strip(),
            "children": [],
            "pre_slugs": [],
            "shared_slugs": self.shared,
        }
        self.site.doc_first_page[self.name] = self.prefix
        # anchors for headings above the first H2 belong to the overview
        for _, txt, idx in self.heads:
            if idx >= first_h2:
                break
            self._map(txt, self.prefix)
        return overview

    def _section(self, overview: Page, h2: HeadingLine, end: int) -> None:
        start = h2[2]
        title = self.site.plain(h2[1])
        sec_heads = [h for h in self.heads if start <= h[2] < end]
        if title in self.skip:
            self._skip(sec_heads)
            return
        page = self._section_page(title)
        overview.extra["children"].append(page)
        self._claim_title(page, title)
        body_lines = self.lines[start + 1 : end]
        h3s = [h for h in sec_heads if h[0] == 3]
        if _needs_h3_split(body_lines, h3s):
            self._split_h3s(page, sec_heads, h3s, end)
            return
        page.extra.update(md="\n".join(body_lines), heading_base=-1)
        for h in sec_heads[1:]:
            self._map(h[1], page.url)

    def _skip(self, sec_heads: list[HeadingLine]) -> None:
        """A section left out of the site still takes its heading slugs."""
        for h in sec_heads:
            self._consume(github_slug(self.site.plain(h[1])))

    def _section_page(self, title: str) -> Page:
        """The page for one H2; a "4.2 " style number moves from the title to a kicker."""
        page = self._page(
            f"{self.prefix}/{page_slug(title)}", NUM_PREFIX.sub("", title), kind="split"
        )
        number = NUM_PREFIX.match(title)
        page.extra = {
            "doc": self.name,
            "number": number.group(0).strip() if number else "",
            "shared_slugs": self.shared,
        }
        return page

    def _split_h3s(self, page: Page, sec_heads: list, h3s: list, end: int) -> None:
        """One sub-page per H3; the text before the first H3 stays on ``page``."""
        first_h3 = h3s[0][2]
        md = "\n".join(self.lines[sec_heads[0][2] + 1 : first_h3])
        page.extra.update(md=md, children=[], heading_base=-1)
        for h in sec_heads:
            if h[2] < first_h3 and h[0] > 2:
                self._map(h[1], page.url)
        for h3, send in _bounds(h3s, end):
            self._sub_page(page, h3, send)

    def _sub_page(self, parent: Page, h3: HeadingLine, end: int) -> None:
        title = self.site.plain(h3[1])
        url = self._free_url(f"{parent.url}/{page_slug(title)}")
        sub = self._page(url, title, kind="split", in_sidebar=False, level=2)
        sub.extra = {
            "doc": self.name,
            "md": "\n".join(self.lines[h3[2] + 1 : end]),
            "heading_base": -2,
            "parent": parent,
            "shared_slugs": self.shared,
        }
        parent.extra["children"].append(sub)
        self._claim_title(sub, title)
        for h in self.heads:
            if h3[2] < h[2] < end:
                self._map(h[1], url)

    def _free_url(self, url: str) -> str:
        candidate, n = url, 2
        while candidate in self.site.by_url:
            candidate = f"{url}-{n}"
            n += 1
        return candidate

    def _add_fragments(self) -> None:
        """Store anchors with a fragment so links land on the heading itself."""
        anchor_map = self.site.anchor_map
        for key, url in list(anchor_map.items()):
            if key[0] == self.name and "#" not in url:
                anchor_map[key] = f"{url}#{key[1]}"
