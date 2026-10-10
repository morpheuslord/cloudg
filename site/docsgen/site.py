"""The site being built: pages, navigation and the Jinja environment.

The work is split by step: :mod:`docsgen.discover` creates the pages from
data/nav.yaml, :mod:`docsgen.render` fills in their HTML,
:mod:`docsgen.output` writes everything out and :mod:`docsgen.links` builds
and checks URLs.
"""

from __future__ import annotations

import os
import re

import yaml
from jinja2 import Environment, FileSystemLoader, select_autoescape
from markdown_it import MarkdownIt

from docsgen.discover import DiscoverMixin
from docsgen.icons import icon
from docsgen.links import LinksMixin
from docsgen.md import strip_tags
from docsgen.output import OutputMixin
from docsgen.page import REPO, SITE, Page
from docsgen.render import RenderMixin


def source_ref() -> str:
    """Git ref the "view source" links point at.

    In GitHub Actions that is the commit being built (``GITHUB_SHA``), so the
    line numbers match the code the pages were generated from. Local builds
    link to main.
    """
    return os.environ.get("GITHUB_SHA") or "main"


def _version() -> str:
    m = re.search(r'^version\s*=\s*"([^"]+)"', (REPO / "pyproject.toml").read_text(), re.M)
    return m.group(1) if m else "0.0.0"


class Site(DiscoverMixin, RenderMixin, OutputMixin, LinksMixin):
    def __init__(self, base: str, strict: bool):
        self.base = "/" + base.strip("/") + "/" if base.strip("/") else "/"
        self.strict = strict
        self.nav = yaml.safe_load((SITE / "data" / "nav.yaml").read_text())
        self.pages: list[Page] = []
        self.by_url: dict[str, Page] = {}
        self.tabs: list[dict] = []
        self.sidebars: dict[str, list[dict]] = {}
        # (doc basename, anchor) -> "url#anchor"
        self.anchor_map: dict[tuple[str, str], str] = {}
        self.doc_first_page: dict[str, str] = {}
        # (page url, target url, anchor) for every site-absolute link, checked at the end
        self.link_targets: list[tuple[str, str, str]] = []
        self.cli: dict = {}
        self.releases: list = []
        self.version = _version()
        self.git_ref = source_ref()
        self.env = Environment(
            loader=FileSystemLoader(str(SITE / "templates")),
            autoescape=select_autoescape(["html"]),
            trim_blocks=True,
            lstrip_blocks=True,
        )
        self.env.globals.update(icon=icon, site=self)
        self._plain_md = MarkdownIt("commonmark")

    def add(self, page: Page) -> Page:
        if page.url in self.by_url:
            raise SystemExit(f"duplicate page url: {page.url}")
        self.pages.append(page)
        self.by_url[page.url] = page
        return page

    def plain(self, md_inline: str) -> str:
        """Plain text of an inline markdown string (heading text without the markup)."""
        return strip_tags(self._plain_md.renderInline(md_inline)).strip()
