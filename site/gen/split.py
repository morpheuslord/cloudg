"""Long docs/*.md references, split into one page per section.

Every H2 becomes a page. An H2 section over ``SPLIT_H3_BYTES`` with at
least three H3s becomes a folder: the text above its first H3 is the
folder's index page, and each H3 gets a page of its own. The text above the
first H2 is the overview page of the whole document.

Every heading keeps the anchor GitHub gives it in the original file
(``-1``, ``-2`` suffixes included), set as an explicit id, so links into
the single-file document and into the old site keep landing on the right
heading. :attr:`SplitDoc.anchors` records which page holds each anchor;
:mod:`gen.links` uses it to rewrite links.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from gen.common import (
    HEADING_RE,
    NUM_PREFIX,
    REPO,
    FenceTracker,
    first_sentence,
    github_slug,
    page_slug,
    plain,
    with_id,
)

SPLIT_H3_BYTES = 40_000


@dataclass
class Heading:
    level: int
    text: str
    line: int  # index into the document's lines
    anchor: str


@dataclass
class GenPage:
    """One generated page: where it goes, what it says, where it came from."""

    uri: str  # docs-dir path, "mcp/server/errors.md"
    title: str  # H1 text
    nav_title: str
    source: str  # repo-relative file the text comes from
    source_line: int = 0
    lines: list[str] = field(default_factory=list)  # markdown below the H1
    children: list[GenPage] = field(default_factory=list)
    title_anchor: str = ""
    kicker: str = ""
    description: str = ""


def scan_headings(lines: list[str]) -> list[Heading]:
    """ATX headings outside fenced code, each with its GitHub anchor."""
    out: list[Heading] = []
    counts: dict[str, int] = {}
    fences = FenceTracker()
    for i, line in enumerate(lines):
        if fences.feed(line):
            continue
        m = HEADING_RE.match(line)
        if not m:
            continue
        slug = github_slug(plain(m.group(2)))
        if slug in counts:
            counts[slug] += 1
            anchor = f"{slug}-{counts[slug]}"
        else:
            counts[slug] = 0
            anchor = slug
        out.append(Heading(len(m.group(1)), m.group(2), i, anchor))
    return out


class SplitDoc:
    """The pages of one split document."""

    def __init__(self, source: str, prefix: str, skip: list[str] | None = None):
        self.source = source  # "docs/MCP.md"
        self.name = source.rsplit("/", 1)[-1]
        self.prefix = prefix  # "mcp/server"
        self.skip = set(skip or [])
        self.lines = (REPO / source).read_text().split("\n")
        self.heads = scan_headings(self.lines)
        self.pages: list[GenPage] = []
        # GitHub anchor -> docs-dir path of the page holding it
        self.anchors: dict[str, str] = {}
        self.overview: GenPage | None = None
        self._uris: set[str] = set()

    # helpers

    def _within(self, start: int, end: int) -> list[Heading]:
        return [h for h in self.heads if start <= h.line < end]

    def _body(self, start: int, end: int, shift: int) -> list[str]:
        """Lines ``start:end`` with every heading moved up ``shift`` levels and given its id."""
        by_line = {h.line: h for h in self.heads}
        out = []
        for i in range(start, end):
            h = by_line.get(i)
            if h is None:
                out.append(self.lines[i])
                continue
            level = max(2, h.level - shift)
            out.append(with_id("#" * level + " " + h.text, h.anchor))
        return out

    def _claim(self, heads: list[Heading], uri: str) -> None:
        for h in heads:
            self.anchors[h.anchor] = uri

    def _free(self, uri: str) -> str:
        stem = uri[: -len(".md")]
        candidate, n = uri, 2
        while candidate in self._uris:
            candidate = f"{stem}-{n}.md"
            n += 1
        self._uris.add(candidate)
        return candidate

    def _page(self, uri: str, h: Heading | None, title: str, nav_title: str) -> GenPage:
        page = GenPage(
            uri=self._free(uri),
            title=title,
            nav_title=nav_title,
            source=self.source,
            source_line=(h.line + 1) if h else 1,
            title_anchor=h.anchor if h else "",
        )
        self.pages.append(page)
        return page

    # discovery

    def build(self) -> list[GenPage]:
        h2s = [h for h in self.heads if h.level == 2]
        first_h2 = h2s[0].line if h2s else len(self.lines)
        self._overview(first_h2)
        for i, h2 in enumerate(h2s):
            end = h2s[i + 1].line if i + 1 < len(h2s) else len(self.lines)
            self._section(h2, end)
        for p in self.pages:
            p.description = p.description or first_sentence("\n".join(p.lines))
        return self.pages

    def _overview(self, first_h2: int) -> None:
        h1 = next((h for h in self.heads if h.level == 1 and h.line < first_h2), None)
        start = h1.line + 1 if h1 else 0
        title = h1.text if h1 else self.name
        page = self._page(f"{self.prefix}/index.md", h1, title, "Overview")
        page.lines = self._body(start, first_h2, 0)
        self._claim(self._within(0, first_h2), page.uri)
        self.overview = page

    def _section(self, h2: Heading, end: int) -> None:
        heads = self._within(h2.line, end)
        title = plain(h2.text)
        if title in self.skip:
            self._claim(heads, self.overview.uri)
            return
        h3s = [h for h in heads if h.level == 3]
        size = sum(len(x) + 1 for x in self.lines[h2.line + 1 : end])
        folder = size > SPLIT_H3_BYTES and len(h3s) >= 3
        slug = page_slug(title)
        uri = f"{self.prefix}/{slug}/index.md" if folder else f"{self.prefix}/{slug}.md"
        clean = NUM_PREFIX.sub("", title)
        page = self._page(uri, h2, NUM_PREFIX.sub("", h2.text), clean)
        number = NUM_PREFIX.match(title)
        if number:
            page.kicker = f"Section {number.group(0).strip().rstrip('.')}"
        self.overview.children.append(page)
        if not folder:
            page.lines = self._body(h2.line + 1, end, 1)
            self._claim(heads, page.uri)
            return
        first_h3 = h3s[0].line
        page.lines = self._body(h2.line + 1, first_h3, 1)
        self._claim([h for h in heads if h.line < first_h3], page.uri)
        for i, h3 in enumerate(h3s):
            send = h3s[i + 1].line if i + 1 < len(h3s) else end
            sub_title = plain(h3.text)
            base = uri[: -len("index.md")]
            sub = self._page(f"{base}{page_slug(sub_title)}.md", h3, h3.text, sub_title)
            sub.kicker = clean
            sub.lines = self._body(h3.line + 1, send, 2)
            self._claim(self._within(h3.line, send), sub.uri)
            page.children.append(sub)

    # nav

    def nav(self) -> list:
        """MkDocs nav entries for the pages, nested the way the files are."""
        items: list = [{"Overview": self.overview.uri}]
        for page in self.overview.children:
            if page.children:
                items.append(
                    {page.nav_title: [page.uri] + [{c.nav_title: c.uri} for c in page.children]}
                )
            else:
                items.append({page.nav_title: page.uri})
        return items
