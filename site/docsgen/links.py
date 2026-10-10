"""URLs for site pages and repository files, and rewriting of links found in content."""

from __future__ import annotations

import posixpath
import re
from typing import Callable

from docsgen.page import GITHUB, Page

# hrefs that are left exactly as written
_PASS_THROUGH = ("http://", "https://", "mailto:", "data:", "//")


class LinksMixin:
    """Link building and checking for :class:`docsgen.site.Site`."""

    base: str
    git_ref: str
    by_url: dict[str, Page]
    anchor_map: dict[tuple[str, str], str]
    doc_first_page: dict[str, str]
    link_targets: list[tuple[str, str, str]]

    def href(self, url: str, anchor: str = "") -> str:
        path = self.base + (url.strip("/") + "/" if url.strip("/") else "")
        return path + (f"#{anchor}" if anchor else "")

    def asset(self, path: str) -> str:
        return self.base + path.lstrip("/")

    def blob(self, path: str, line: int = 0, ref: str | None = None) -> str:
        url = f"{GITHUB}/blob/{ref or 'main'}/{path}"
        return url + (f"#L{line}" if line else "")

    def edit_url(self, page: Page) -> str:
        if not page.source:
            return ""
        if page.source_line:
            return self.blob(page.source, page.source_line, self.git_ref)
        return f"{GITHUB}/edit/main/{page.source}"

    # -- link resolution -------------------------------------------------------

    def resolver(self, page: Page, doc: str | None = None) -> Callable[[str], str]:
        """Return a function that rewrites hrefs found on ``page``.

        ``doc`` is the basename of the docs/*.md file a split page comes from,
        so in-document ``#anchor`` links can follow the heading to its page.
        """
        return lambda href: self.resolve_href(page, doc, href)

    def resolve_href(self, page: Page, doc: str | None, href: str) -> str:
        if not href or href.startswith(_PASS_THROUGH):
            return href
        if href.startswith("/"):
            return self._resolve_site_path(page, href)
        if href.startswith("#"):
            return self._resolve_fragment(page, doc, href)
        return self._resolve_relative(page, href)

    def _resolve_site_path(self, page: Page, href: str) -> str:
        path, _, anchor = href.partition("#")
        url = path.strip("/")
        self.link_targets.append((page.url, url, anchor))
        return self.href(url, anchor)

    def _resolve_fragment(self, page: Page, doc: str | None, href: str) -> str:
        target = self.anchor_map.get((doc, href[1:])) if doc else None
        if not target:
            return href
        url, _, anchor = target.partition("#")
        if url == page.url:
            return "#" + anchor
        return self.href(url, anchor)

    def _resolve_relative(self, page: Page, href: str) -> str:
        """Relative file links from the docs/*.md sources."""
        path, _, anchor = href.partition("#")
        base_dir = posixpath.dirname(page.source) if page.source else "docs"
        target = posixpath.normpath(posixpath.join(base_dir, path))
        name = posixpath.basename(target)
        if name in self.doc_first_page and target.startswith("docs/"):
            return self._doc_link(name, anchor)
        if target == "CHANGELOG.md":
            return self.href("changelog", anchor)
        if target == "config.yaml":
            return self.href("reference/config/providers")
        if target.startswith(".."):
            return href
        return self.blob(target) + (f"#{anchor}" if anchor else "")

    def _doc_link(self, name: str, anchor: str) -> str:
        """Link into a split docs/*.md file: the page holding ``anchor``, else its overview."""
        if anchor and (name, anchor) in self.anchor_map:
            url, _, a = self.anchor_map[(name, anchor)].partition("#")
            return self.href(url, a)
        return self.href(self.doc_first_page[name], "")

    # -- checking --------------------------------------------------------------

    def check_links(self) -> list[str]:
        problems = []
        ids_cache: dict[str, set[str]] = {}
        for src, url, anchor in self.link_targets:
            where = src or "home"
            if url not in self.by_url:
                problems.append(f"{where}: link to missing page /{url}/")
                continue
            if anchor and anchor not in self._ids_on(url, ids_cache):
                problems.append(f"{where}: link to missing anchor /{url}/#{anchor}")
        return sorted(set(problems))

    def _ids_on(self, url: str, cache: dict[str, set[str]]) -> set[str]:
        if url not in cache:
            page = self.by_url[url]
            cache[url] = set(re.findall(r'id="([^"]+)"', page.body))
            cache[url].update(h.id for h in page.headings)
        return cache[url]
