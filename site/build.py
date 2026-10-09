#!/usr/bin/env python3
"""Build the cloudg documentation site into site/dist.

    python site/build.py                 # build
    python site/build.py --serve         # build, then serve on http://127.0.0.1:8000/cloudg/
    python site/build.py --strict        # fail on broken internal links (used in CI)
    python site/build.py --base /        # build for serving at the domain root

See site/AUTHORING.md for the page format.
"""

from __future__ import annotations

import argparse
import functools
import http.server
import json
import os
import posixpath
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from html import escape
from pathlib import Path
from urllib.parse import urlsplit

SITE = Path(__file__).resolve().parent
REPO = SITE.parent
sys.path.insert(0, str(SITE))
sys.path.insert(0, str(REPO))

import yaml  # noqa: E402
from jinja2 import Environment, FileSystemLoader, select_autoescape  # noqa: E402
from markupsafe import Markup  # noqa: E402
from markdown_it import MarkdownIt  # noqa: E402

from docsgen import gen_api, gen_changelog, gen_cli, gen_config  # noqa: E402
from docsgen.highlight import render_code_block  # noqa: E402
from docsgen.icons import icon  # noqa: E402
from docsgen.md import Heading, Renderer, github_slug, render_inline, split_front_matter, strip_tags  # noqa: E402

GITHUB = "https://github.com/morpheuslord/cloudg"
PYPI = "https://pypi.org/project/cloudg/"
SPLIT_H3_BYTES = 40_000
_FENCE = re.compile(r"^\s{0,3}(`{3,}|~{3,})(.*)$")
_NUM_PREFIX = re.compile(r"^\d+(\.\d+)*\.?\s+")


# ---------------------------------------------------------------------------
# Page model
# ---------------------------------------------------------------------------


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
    prev: "Page | None" = None
    next: "Page | None" = None
    description: str = ""


class Site:
    def __init__(self, base: str, strict: bool):
        self.base = "/" + base.strip("/") + "/" if base.strip("/") else "/"
        self.strict = strict
        self.nav = yaml.safe_load((SITE / "data" / "nav.yaml").read_text())
        self.pages: list[Page] = []
        self.by_url: dict[str, Page] = {}
        self.tabs: list[dict] = []
        self.sidebars: dict[str, list[dict]] = {}
        self.anchor_map: dict[tuple[str, str], str] = {}  # (doc basename, anchor) -> url#anchor
        self.doc_first_page: dict[str, str] = {}
        self.broken: list[tuple[str, str]] = []
        self.version = self._version()
        self.git_ref = f"v{self.version}" if self._tag_exists(f"v{self.version}") else "main"
        self.env = Environment(
            loader=FileSystemLoader(str(SITE / "templates")),
            autoescape=select_autoescape(["html"]),
            trim_blocks=True,
            lstrip_blocks=True,
        )
        self.env.globals.update(icon=icon, site=self)
        self.env.filters["wbr"] = lambda text, sep: Markup(
            str(escape(text)).replace(str(escape(sep)), str(escape(sep)) + "<wbr>")
        )
        self._plain_md = MarkdownIt("commonmark")

    # -- helpers ---------------------------------------------------------------

    @staticmethod
    def _version() -> str:
        m = re.search(r'^version\s*=\s*"([^"]+)"', (REPO / "pyproject.toml").read_text(), re.M)
        return m.group(1) if m else "0.0.0"

    @staticmethod
    def _tag_exists(tag: str) -> bool:
        try:
            out = subprocess.run(["git", "-C", str(REPO), "tag", "--list", tag], capture_output=True, text=True)
            return out.stdout.strip() == tag
        except OSError:
            return False

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

    def add(self, page: Page) -> Page:
        if page.url in self.by_url:
            raise SystemExit(f"duplicate page url: {page.url}")
        self.pages.append(page)
        self.by_url[page.url] = page
        return page

    def plain(self, md_inline: str) -> str:
        return strip_tags(self._plain_md.renderInline(md_inline)).strip()

    # -- link resolution -------------------------------------------------------

    def resolver(self, page: Page, doc: str | None = None):
        """Return a function that rewrites hrefs found on ``page``."""

        def resolve(href: str) -> str:
            if not href or href.startswith(("http://", "https://", "mailto:", "data:")):
                return href
            if href.startswith("//"):
                return href
            if href.startswith("/"):
                path, _, anchor = href.partition("#")
                url = path.strip("/")
                self._check(page, url, anchor)
                return self.href(url, anchor)
            if href.startswith("#"):
                if doc:
                    target = self.anchor_map.get((doc, href[1:]))
                    if target:
                        url, _, anchor = target.partition("#")
                        if url == page.url:
                            return "#" + anchor if anchor else "#"
                        return self.href(url, anchor)
                return href
            # relative file links from the docs/*.md sources
            path, _, anchor = href.partition("#")
            base_dir = posixpath.dirname(page.source) if page.source else "docs"
            target = posixpath.normpath(posixpath.join(base_dir, path))
            name = posixpath.basename(target)
            if name in self.doc_first_page and target.startswith("docs/"):
                if anchor and (name, anchor) in self.anchor_map:
                    url, _, a = self.anchor_map[(name, anchor)].partition("#")
                    return self.href(url, a)
                return self.href(self.doc_first_page[name], "")
            if target == "CHANGELOG.md":
                return self.href("changelog", anchor)
            if target == "config.yaml":
                return self.href("reference/config/providers")
            if target.startswith(".."):
                return href
            return self.blob(target) + (f"#{anchor}" if anchor else "")

        return resolve

    def _check(self, page: Page, url: str, anchor: str) -> None:
        self.broken_candidates.append((page.url, url, anchor))

    broken_candidates: list = []

    # -- page discovery ----------------------------------------------------------

    def discover(self) -> None:
        self.broken_candidates = []
        home = self.add(Page("", "cloudg documentation", kind="home", search_type="Guides", in_sidebar=False))
        home.source = "site/templates/home.html"
        for tab in self.nav["tabs"]:
            self.tabs.append({"id": tab["id"], "label": tab["label"], "root": tab["root"]})
            groups = []
            for gi, group in enumerate(tab.get("groups", []), start=1):
                items = []
                if "split" in group:
                    items = self._discover_split(tab["id"], group)
                elif group.get("generated") == "config":
                    items = self._discover_config(tab["id"], group)
                else:
                    for item in group["items"]:
                        items.append(self._discover_item(tab["id"], group["title"], item))
                groups.append({"title": group["title"], "num": f"{gi:02d}", "pages": items})
            self.sidebars[tab["id"]] = groups
        self.add(
            Page("changelog", "Changelog", tab="changelog", kind="changelog", search_type="Changelog",
                 source="CHANGELOG.md", in_sidebar=False)
        )

    def _discover_item(self, tab: str, group: str, item: dict) -> Page:
        title = item["title"]
        if "generated" in item:
            page = Page(item["path"], title, tab=tab, group=group, kind=item["generated"])
            page.search_type = {"cli-index": "CLI", "api-index": "Python API"}.get(item["generated"], "Guides")
            return self.add(page)
        rel = item["page"]
        url = item.get("path", rel)
        file = SITE / "content" / f"{rel}.md"
        kind = {"cli": "cli", "api": "api", "mcp": "guide", "reference": "guide"}.get(tab, "guide")
        search_type = {"guides": "Guides", "cli": "CLI", "api": "Python API", "mcp": "MCP", "reference": "Reference"}[tab]
        page = Page(url, title, tab=tab, group=group, kind=kind, search_type=search_type,
                    source=str(file.relative_to(REPO)), nav_title=title)
        page.loader = file
        return self.add(page)

    def _discover_split(self, tab: str, group: dict) -> list[Page]:
        doc_path = REPO / group["split"]
        name = doc_path.name
        prefix = group["prefix"]
        skip = set(group.get("skip", []))
        text = doc_path.read_text()
        lines = text.split("\n")
        heads = _scan_headings(lines)
        h1 = next((h for h in heads if h[0] == 1), None)
        h2s = [h for h in heads if h[0] == 2]
        search_type = "MCP" if tab == "mcp" else "Reference"
        pages: list[Page] = []

        # Overview page from the text above the first H2
        first_h2 = h2s[0][2] if h2s else len(lines)
        intro_start = h1[2] + 1 if h1 else 0
        intro = "\n".join(lines[intro_start:first_h2]).strip()
        overview = Page(prefix, self.plain(h1[1]) if h1 else group["title"], tab=tab, group=group["title"],
                        kind="split-index", search_type=search_type, source=group["split"], nav_title="Overview")
        overview.extra = {"doc": name, "md": intro, "children": [], "pre_slugs": []}
        pages.append(self.add(overview))
        self.doc_first_page[name] = prefix

        slug_counts: dict[str, int] = {}
        pending: list[str] = []  # slugs consumed by titles and skipped sections before the next page renders

        def gh_unique(slug: str) -> str:
            if slug in slug_counts:
                slug_counts[slug] += 1
                return f"{slug}-{slug_counts[slug]}"
            slug_counts[slug] = 0
            return slug

        def consume(slug: str) -> str:
            s = gh_unique(slug)
            pending.append(slug)
            return s

        shared: dict[str, int] = {}
        overview.extra["shared_slugs"] = shared

        # anchors for headings above the first H2 belong to the overview
        for lvl, txt, idx in heads:
            if idx >= first_h2:
                break
            self.anchor_map[(name, gh_unique(github_slug(self.plain(txt))))] = prefix

        bounds = [(h, h2s[i + 1][2] if i + 1 < len(h2s) else len(lines)) for i, h in enumerate(h2s)]
        for (lvl, txt, start), end in bounds:
            title = self.plain(txt)
            sec_heads = [h for h in heads if start <= h[2] < end]
            if title in skip:
                for h in sec_heads:
                    consume(github_slug(self.plain(h[1])))
                continue
            slug = page_slug(title)
            url = f"{prefix}/{slug}"
            body_lines = lines[start + 1 : end]
            size = sum(len(x) + 1 for x in body_lines)
            h3s = [h for h in sec_heads if h[0] == 3]
            page = Page(url, _NUM_PREFIX.sub("", title), tab=tab, group=group["title"], kind="split",
                        search_type=search_type, source=group["split"], source_line=0)
            number = _NUM_PREFIX.match(title)
            page.extra = {"doc": name, "number": number.group(0).strip() if number else "", "shared_slugs": shared}
            self.add(page)
            pages.append(page)
            overview.extra["children"].append(page)
            title_anchor = consume(github_slug(title))
            page.extra["title_anchor"] = title_anchor
            page.extra["pre_slugs"] = list(pending)
            pending.clear()
            self.anchor_map[(name, title_anchor)] = url
            if size > SPLIT_H3_BYTES and len(h3s) >= 3:
                first_h3 = h3s[0][2]
                page.extra.update(md="\n".join(lines[start + 1 : first_h3]), children=[], heading_base=-1)
                for h in sec_heads:
                    if h[2] < first_h3 and h[0] > 2:
                        self.anchor_map[(name, gh_unique(github_slug(self.plain(h[1]))))] = url
                sub_bounds = [(h, h3s[i + 1][2] if i + 1 < len(h3s) else end) for i, h in enumerate(h3s)]
                for (_, stxt, sstart), send in sub_bounds:
                    stitle = self.plain(stxt)
                    sslug = page_slug(stitle)
                    surl = f"{url}/{sslug}"
                    n = 2
                    while surl in self.by_url:
                        surl = f"{url}/{sslug}-{n}"
                        n += 1
                    sub = Page(surl, stitle, tab=tab, group=group["title"], kind="split", search_type=search_type,
                               source=group["split"], in_sidebar=False, level=2)
                    sub.extra = {"doc": name, "md": "\n".join(lines[sstart + 1 : send]), "heading_base": -2,
                                 "parent": page, "shared_slugs": shared}
                    self.add(sub)
                    pages.append(sub)
                    page.extra["children"].append(sub)
                    sub_anchor = consume(github_slug(stitle))
                    sub.extra["title_anchor"] = sub_anchor
                    sub.extra["pre_slugs"] = list(pending)
                    pending.clear()
                    self.anchor_map[(name, sub_anchor)] = surl
                    for h in heads:
                        if sstart < h[2] < send:
                            self.anchor_map[(name, gh_unique(github_slug(self.plain(h[1]))))] = f"{surl}"
            else:
                page.extra.update(md="\n".join(body_lines), heading_base=-1)
                for h in sec_heads[1:]:
                    self.anchor_map[(name, gh_unique(github_slug(self.plain(h[1]))))] = url
        # store anchors with a fragment so links land on the heading itself
        for key, url in list(self.anchor_map.items()):
            if key[0] == name and "#" not in url:
                self.anchor_map[key] = f"{url}#{key[1]}"
        return pages

    def _discover_config(self, tab: str, group: dict) -> list[Page]:
        sections = gen_config.parse(REPO / "config.yaml")
        _merge_model_descriptions(sections)
        overrides = yaml.safe_load((SITE / "data" / "config-notes.yaml").read_text()) or {}
        pages = []
        for s in sections:
            for k in s.keys:
                note = overrides.get(f"{s.name}.{k.path}")
                if note:
                    k.description = note
            url = f"{group['prefix']}/{s.name}"
            page = Page(url, s.name, tab=tab, group=group["title"], kind="config", search_type="Config",
                        source="config.yaml", mono_title=True)
            page.extra = {"section": s, "intro": overrides.get(s.name, "")}
            pages.append(self.add(page))
        return pages

    # -- rendering -------------------------------------------------------------

    def render_all(self) -> None:
        cli = gen_cli.collect(REPO)
        self.cli = cli
        for page in self.pages:
            page.crumbs = self._crumbs(page)
            kind = page.kind
            if kind == "home":
                continue
            if kind in ("guide",):
                self._render_markdown_page(page)
            elif kind == "cli":
                self._render_cli_page(page, cli)
            elif kind == "api":
                self._render_api_page(page)
            elif kind in ("split", "split-index"):
                self._render_split_page(page)
            elif kind == "config":
                self._render_config_page(page)
            elif kind == "changelog":
                self._render_changelog(page)
            elif kind == "cli-index":
                self._render_cli_index(page, cli)
            elif kind == "api-index":
                self._render_api_index(page)
        self._link_prev_next()

    def _crumbs(self, page: Page) -> list[str]:
        tab = next((t["label"] for t in self.tabs if t["id"] == page.tab), "")
        out = [tab] if tab else []
        if page.group and page.group != tab:
            out.append(page.group)
        parent = page.extra.get("parent") if page.extra else None
        if parent:
            out.append(parent.title)
        return out

    def _load_md(self, page: Page) -> tuple[dict, str]:
        file: Path = page.loader  # type: ignore[assignment]
        if not file.exists():
            print(f"warning: missing content file {file.relative_to(REPO)}", file=sys.stderr)
            return {"title": page.title, "lede": "This page hasn't been written yet."}, ""
        return split_front_matter(file.read_text())

    def _apply_front(self, page: Page, meta: dict) -> None:
        res = self.resolver(page)
        if meta.get("title"):
            page.title = meta["title"]
        if meta.get("lede"):
            page.lede = render_inline(str(meta["lede"]), res)
            page.description = strip_tags(page.lede)
        if meta.get("description"):
            page.description = meta["description"]
        page.meta = [(label, render_inline(str(value), res)) for label, value in meta.get("meta", [])]
        page.since = str(meta.get("since", "")) or ""
        if meta.get("source"):
            page.source = meta["source"]

    def _render_markdown_page(self, page: Page) -> None:
        meta, body = self._load_md(page)
        self._apply_front(page, meta)
        r = Renderer(self.resolver(page)).render(body)
        page.body, page.headings = r.html, r.headings

    def _render_split_page(self, page: Page) -> None:
        doc = page.extra["doc"]
        md = page.extra.get("md", "")
        renderer = Renderer(self.resolver(page, doc), heading_base=page.extra.get("heading_base", -1),
                            slugs=page.extra.get("shared_slugs"))
        for slug in page.extra.get("pre_slugs", []):
            renderer.register(slug)
        r = renderer.render(md)
        body = r.html
        children = page.extra.get("children") or []
        if children:
            cards = "".join(
                f'<a class="link-card" href="{self.href(c.url)}"><span class="link-card-title">'
                f'{escape((c.extra.get("number", "") + " " if c.extra.get("number") else "") + c.title)}'
                f'{icon("arrow-right", 16)}</span><span class="link-card-desc">{escape(c.description)}</span></a>'
                for c in children
            )
            label = "Sections" if page.kind == "split-index" else "In this section"
            body += f'<h2 id="sections">{label}</h2><nav class="link-cards link-cards--dense">{cards}</nav>'
            r.headings.append(type(r.headings[0])(2, "sections", label, label) if r.headings else None)
            r.headings = [h for h in r.headings if h is not None]
            if not r.headings:
                    r.headings = [Heading(2, "sections", label, label)]
        page.body, page.headings = body, r.headings
        if not page.description:
            first = re.search(r"<p>(.*?)</p>", r.html, re.S)
            if first:
                page.description = _truncate(strip_tags(first.group(1)), 160)
        if page.kind == "split" and page.extra.get("number"):
            page.extra["kicker"] = f"Section {page.extra['number'].rstrip('.')}"

    def _render_cli_page(self, page: Page, cli: dict) -> None:
        meta, body = self._load_md(page)
        self._apply_front(page, meta)
        page.mono_title = bool(meta.get("command"))
        res = self.resolver(page)
        r = Renderer(res)
        parts = []
        command = meta.get("command")
        if command:
            cmd = cli.get(command)
            if cmd is None:
                raise SystemExit(f"{page.source}: unknown command {command!r}")
            page.title = f"cloudg {command}"
            if not page.lede:
                page.lede = escape(cmd.short_help)
            if cmd.source_file:
                page.source, page.source_line = cmd.source_file, cmd.source_line
            page.meta = page.meta or []
            if meta.get("intro"):
                parts.append(r.render(meta["intro"]).html)
            r.headings.append(Heading(2, "usage", "Usage", "Usage"))
            parts.append(
                f'<h2 id="usage" class="visually-hidden">Usage</h2><pre class="usage"><code>{escape(cmd.usage)}</code></pre>'
            )
            r.headings.append(Heading(2, "options", "Options", "Options"))
            parts.append(self.env.get_template("_options.html").render(cmd=cmd, page=page))
            page.extra["command"] = cmd
        parts.append(r.render(body).html)
        page.body, page.headings = "".join(parts), r.headings

    def _render_cli_index(self, page: Page, cli: dict) -> None:
        page.title = "CLI reference"
        page.lede = "Every <code>cloudg</code> command and the flags it takes. The tables are generated from the click definitions, so they match <code>--help</code>."
        page.source = "cloudg/cli.py"
        rows = []
        for group in self.sidebars["cli"][1:]:
            for p in group["pages"]:
                cmd_name = p.title.replace("cloudg ", "", 1) if p.title.startswith("cloudg ") else None
                cmd = cli.get(cmd_name) if cmd_name else None
                rows.append((group["title"], p, cmd))
        page.extra = {"rows": rows, "root": cli["__root__"]}
        page.headings = [Heading(2, "commands", "Commands", "Commands"), Heading(2, "global-options", "Global options", "Global options")]
        page.body = self.env.get_template("_cli_index.html").render(page=page)
        page.mono_title = False

    def _render_api_page(self, page: Page) -> None:
        meta, body = self._load_md(page)
        self._apply_front(page, meta)
        res = self.resolver(page)
        r = Renderer(res)
        objects = meta.get("object")
        parts = []
        if objects:
            paths = objects if isinstance(objects, list) else [objects]
            members = meta.get("members")
            loaded = []
            for p in paths:
                m = members.get(p) if isinstance(members, dict) else (members if len(paths) == 1 else None)
                try:
                    loaded.append(gen_api.load(p, REPO, m))
                except Exception as exc:  # noqa: BLE001
                    raise SystemExit(f"{page.source}: cannot load {p}: {exc}") from exc
            first = loaded[0]
            page.mono_title = len(loaded) == 1 and not meta.get("title")
            if page.mono_title:
                page.title = first.name
            if len(loaded) == 1:
                page.extra.update(kind_tag=first.kind, module=first.module, src=first)
            page.source, page.source_line = first.source_file, first.source_line
            if not page.lede and first.doc.summary:
                page.lede = render_inline(first.doc.summary, res)
            multi = len(loaded) > 1
            for obj in loaded:
                if multi:
                    r.headings.append(Heading(2, obj.name.lower(), obj.name, obj.name))
                else:
                    members_title = "Methods" if first.kind == "class" else "Members"
                    for title, hid in (("Fields", "fields"), ("Values", "values"), (members_title, "members")):
                        if (title == "Fields" and obj.fields) or (title == "Values" and obj.enum_values) or (
                            title == members_title and obj.members
                        ):
                            r.headings.append(Heading(2, hid, title, title))
                    for mem in obj.members:
                        r.headings.append(Heading(3, f"{obj.name}.{mem.name}", mem.name, mem.name))
                parts.append(
                    self.env.get_template("_api_object.html").render(
                        obj=obj, multi=multi, page=page, md=lambda t: Renderer(res).render(t).html,
                        inline=lambda t: render_inline(t, res), code=render_code_block,
                        blob=lambda line: self.blob(obj.source_file, line, self.git_ref),
                    )
                )
        rb = r.render(body)
        parts.append(rb.html)
        page.body, page.headings = "".join(parts), r.headings

    def _render_api_index(self, page: Page) -> None:
        page.title = "Python API"
        page.lede = (
            "cloudg is a library first. The CLI is a thin layer over <code>CloudGEngine</code>, so anything a command"
            " does you can do from Python, one phase at a time if you like."
        )
        page.source = "cloudg/__init__.py"
        groups = []
        for group in self.sidebars["api"][1:]:
            items = []
            for p in group["pages"]:
                items.append(p)
            groups.append((group["title"], items))
        page.extra = {"groups": groups}
        md_file = SITE / "content" / "api" / "index.md"
        intro_html = ""
        headings = []
        if md_file.exists():
            meta, body = split_front_matter(md_file.read_text())
            if meta.get("lede"):
                page.lede = render_inline(meta["lede"], self.resolver(page))
            rr = Renderer(self.resolver(page)).render(body)
            intro_html, headings = rr.html, rr.headings
        page.headings = headings + [Heading(2, "reference", "Reference", "Reference")]
        page.body = intro_html + self.env.get_template("_api_index.html").render(page=page)

    def _render_config_page(self, page: Page) -> None:
        s = page.extra["section"]
        res = self.resolver(page)
        page.title = s.name
        intro = page.extra.get("intro") or s.intro
        rest = ""
        if len(intro) > 240:
            first, sep, rest = intro.partition(". ")
            intro = first + ("." if sep else "")
        page.lede = render_inline(intro, res) if intro else ""
        page.description = strip_tags(page.lede)
        page.toc_label = "Sections"
        page.headings = [Heading(2, k.path, k.path, k.path) for k in s.keys if "." not in k.path]
        yaml_lines = _highlight_yaml_lines(s.lines)
        page.body = (f"<p>{render_inline(rest, res)}</p>" if rest else "") + self.env.get_template("_config.html").render(
            s=s, page=page, yaml_lines=yaml_lines, inline=lambda t: render_inline(t, res)
        )
        page.source_line = _line_of(REPO / "config.yaml", f"{s.name}:") if s.name != "general" else 0
        if page.source_line:
            page.source = "config.yaml"

    def _render_changelog(self, page: Page) -> None:
        head, releases = gen_changelog.parse(REPO / "CHANGELOG.md")
        res = self.resolver(page)
        page.lede = render_inline(head, res) if head else ""
        rendered = []
        for rel in releases:
            rr = Renderer(res, heading_base=1)
            intro = rr.render(rel.intro).html if rel.intro else ""
            blocks = [(label, Renderer(res, heading_base=1).render(text).html) for label, text in rel.blocks]
            rendered.append({"rel": rel, "intro": intro, "blocks": blocks})
        page.extra = {"releases": rendered}
        self.releases = releases
        page.headings = [Heading(2, r.anchor, r.version, r.version) for r in releases]

    def _link_prev_next(self) -> None:
        for tab, groups in self.sidebars.items():
            seq: list[Page] = []
            for g in groups:
                for p in g["pages"]:
                    seq.append(p)
            for i, p in enumerate(seq):
                p.prev = seq[i - 1] if i > 0 else None
                p.next = seq[i + 1] if i + 1 < len(seq) else None

    # -- output ----------------------------------------------------------------

    def write(self, out: Path) -> None:
        if out.exists():
            shutil.rmtree(out)
        out.mkdir(parents=True)
        shutil.copytree(SITE / "static", out / "static")
        for extra in ("viewer.html",):
            src = REPO / "docs" / extra
            if src.exists():
                shutil.copy2(src, out / extra)
        if (REPO / "docs" / "assets").is_dir():
            shutil.copytree(REPO / "docs" / "assets", out / "assets")
        stats = self._stats()
        redirects = {k: self.href(v.split("#")[0], v.partition("#")[2]) for k, v in self.nav["redirects"].items()}
        versions = self._versions()
        (out / "versions.json").write_text(json.dumps(versions, indent=2))
        for page in self.pages:
            tpl = {
                "home": "home.html",
                "changelog": "changelog.html",
            }.get(page.kind, "page.html")
            html = self.env.get_template(tpl).render(
                page=page, stats=stats, redirects=redirects, versions=versions,
                sidebar=self.sidebars.get(page.tab, []), tabs=self.tabs,
            )
            dest = out / page.url / "index.html" if page.url else out / "index.html"
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_text(html)
        nf = Page("404", "Page not found", kind="404", in_sidebar=False)
        (out / "404.html").write_text(
            self.env.get_template("404.html").render(page=nf, redirects=redirects, versions=versions, tabs=self.tabs,
                                                     sidebar=[])
        )
        (out / "search-index.json").write_text(json.dumps(self._search_index(), separators=(",", ":")))
        (out / ".nojekyll").write_text("")

    def _stats(self) -> dict:
        import glob

        controls = 0
        for f in glob.glob(str(REPO / "cloudg" / "rules" / "frameworks" / "*.yaml")):
            data = yaml.safe_load(Path(f).read_text()) or {}
            controls += len(data.get("controls") or [])
        try:
            from cloudg.schema.models import AssetType

            asset_types = len(AssetType)
        except Exception:  # noqa: BLE001
            asset_types = 0
        tools = 0
        try:
            from cloudg.mcp import default_registry

            tools = len(default_registry().tools())
        except Exception:  # noqa: BLE001
            pass
        data = yaml.safe_load((SITE / "data" / "stats.yaml").read_text())
        computed = {"controls": controls, "asset_types": asset_types, "mcp_tools": tools}
        out = []
        for item in data["stats"]:
            value = computed.get(item.get("compute", ""), 0) or item.get("value", 0)
            out.append({"value": f"{value:,}", "label": item["label"], "href": item.get("href", "")})
        return {"items": out, "commands": len([k for k, v in self.cli.items() if not v.group and k != "__root__"])}

    def _versions(self) -> list[dict]:
        out = []
        releases = getattr(self, "releases", [])
        for r in releases:
            if not re.match(r"^\d", r.version):
                continue
            latest = r.version == self.version
            out.append({
                "version": r.version,
                "date": r.date,
                "latest": latest,
                "url": self.href("") if latest else self.href("changelog", r.anchor),
            })
        out.append({"version": "main", "date": "unreleased", "latest": False, "url": f"{GITHUB}/tree/main"})
        return out

    def _search_index(self) -> list[dict]:
        entries = []
        for page in self.pages:
            if page.kind in ("home",):
                continue
            chunks = _sections(page.body, page.headings)
            title = page.title
            entries.append({
                "t": title, "u": self.href(page.url), "k": page.search_type, "h": "",
                "x": _truncate(strip_tags(page.lede) + " " + chunks[0][1] if chunks else strip_tags(page.lede), 600),
                "g": page.group, "m": int(page.mono_title),
            })
            for hid, text, htext in chunks[1:]:
                entries.append({
                    "t": title, "u": self.href(page.url, hid), "k": page.search_type, "h": htext,
                    "x": _truncate(text, 600), "g": page.group,
                    "m": int(page.mono_title or page.kind == "config"),
                })
            if page.kind == "config":
                s = page.extra["section"]
                for k in s.keys:
                    entries.append({
                        "t": f"{s.name}.{k.path}", "u": self.href(page.url, k.path), "k": "Config", "h": "",
                        "x": f"{k.type} · {k.default or 'none'} · {k.description}", "g": page.group, "m": 1,
                    })
        return entries

    def check_links(self) -> list[str]:
        problems = []
        ids_cache: dict[str, set[str]] = {}
        for src, url, anchor in self.broken_candidates:
            if url not in self.by_url:
                problems.append(f"{src or 'home'}: link to missing page /{url}/")
                continue
            if anchor:
                if url not in ids_cache:
                    ids_cache[url] = set(re.findall(r'id="([^"]+)"', self.by_url[url].body))
                    ids_cache[url].update(h.id for h in self.by_url[url].headings)
                if anchor not in ids_cache[url]:
                    problems.append(f"{src or 'home'}: link to missing anchor /{url}/#{anchor}")
        return sorted(set(problems))


# ---------------------------------------------------------------------------
# small utilities
# ---------------------------------------------------------------------------


def _scan_headings(lines: list[str]) -> list[tuple[int, str, int]]:
    out = []
    fence = None
    for i, line in enumerate(lines):
        fm = _FENCE.match(line)
        if fence is None and fm:
            fence = fm.group(1)
            continue
        if fence is not None:
            if fm and fm.group(1)[0] == fence[0] and len(fm.group(1)) >= len(fence) and not fm.group(2).strip():
                fence = None
            continue
        m = re.match(r"^(#{1,6})\s+(.*?)\s*#*\s*$", line)
        if m:
            out.append((len(m.group(1)), m.group(2), i))
    return out


def page_slug(title: str) -> str:
    """URL segment for a split page: number prefix dropped, punctuation turned into hyphens."""
    title = _NUM_PREFIX.sub("", title).lower()
    return re.sub(r"[^a-z0-9]+", "-", title).strip("-") or "section"


def _truncate(text: str, n: int) -> str:
    text = " ".join(text.split())
    return text if len(text) <= n else text[: n - 1].rsplit(" ", 1)[0] + "…"


def _sections(html: str, headings: list) -> list[tuple[str, str, str]]:
    """Split rendered HTML at h2/h3 ids into (id, text, heading) chunks."""
    ids = {h.id: h.text for h in headings if h.level in (2, 3)}
    html = re.sub(r'<a class="h-anchor"[^>]*>#</a>', "", html)
    parts = re.split(r'(<h[23] id="([^"]+)")', html)
    out = [("", strip_tags(parts[0]), "")]
    i = 1
    while i < len(parts):
        hid = parts[i + 1]
        content = parts[i + 2] if i + 2 < len(parts) else ""
        if hid in ids:
            text = strip_tags(re.sub(r"<pre.*?</pre>", " ", content, flags=re.S))
            out.append((hid, text, ids[hid]))
        else:
            prev = out[-1]
            out[-1] = (prev[0], prev[1] + " " + strip_tags(content), prev[2])
        i += 3
    return out


def _line_of(path: Path, needle: str) -> int:
    for i, line in enumerate(path.read_text().split("\n"), start=1):
        if line.startswith(needle):
            return i
    return 0


def _highlight_yaml_lines(lines: list[str]) -> list[str]:
    from docsgen.highlight import tokenize_lines

    toks = tokenize_lines("\n".join(lines) + "\n", "yaml")
    toks += [""] * (len(lines) - len(toks))
    return toks


def _merge_model_descriptions(sections) -> None:
    """Prefer pydantic Field descriptions from CloudGConfig; add keys the example file omits."""
    try:
        from cloudg.config import CloudGConfig
    except Exception:  # noqa: BLE001
        return

    def model_of(annotation):
        if hasattr(annotation, "model_fields"):
            return annotation
        for arg in getattr(annotation, "__args__", ()) or ():
            if hasattr(arg, "model_fields"):
                return arg
        return None

    for s in sections:
        top = CloudGConfig.model_fields.get(s.name)
        model = model_of(top.annotation) if top else None
        if s.name == "general":
            model = CloudGConfig
        if model is None:
            continue
        for k in s.keys:
            cur = model
            finfo = None
            for part in k.path.split("."):
                if cur is None or part not in cur.model_fields:
                    finfo = None
                    break
                finfo = cur.model_fields[part]
                cur = model_of(finfo.annotation)
            if finfo is not None and finfo.description:
                desc = finfo.description.strip()
                if not k.description or len(desc) > len(k.description):
                    k.description = desc
        known = {k.path for k in s.keys}
        for fname, finfo in model.model_fields.items():
            if s.name == "general" and model_of(finfo.annotation) is not None:
                continue
            if s.name == "general" and fname in ("providers",):
                continue
            if fname not in known and model_of(finfo.annotation) is None and not any(p.startswith(fname + ".") for p in known):
                if s.name == "general":
                    continue
                default = "" if finfo.default_factory else repr(finfo.default)
                if default in ("None",):
                    default = "null"
                s.keys.append(gen_config.Key(fname, gen_api._ann(finfo.annotation), default,
                                             (finfo.description or "") + " Not in the example file.", -1))


# ---------------------------------------------------------------------------
# entry point
# ---------------------------------------------------------------------------


def serve(out: Path, base: str, port: int) -> None:
    class Handler(http.server.SimpleHTTPRequestHandler):
        def end_headers(self):
            self.send_header("Cache-Control", "no-store")
            super().end_headers()

        def translate_path(self, path):  # noqa: D401
            parsed = urlsplit(path).path
            if base != "/" and parsed.startswith(base):
                parsed = "/" + parsed[len(base):]
            return str(out) + parsed

        def send_error(self, code, message=None, explain=None):
            if code == 404 and (out / "404.html").exists():
                body = (out / "404.html").read_bytes()
                self.send_response(404)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return
            super().send_error(code, message, explain)

    handler = functools.partial(Handler, directory=str(out))
    with http.server.ThreadingHTTPServer(("127.0.0.1", port), handler) as httpd:
        print(f"serving http://127.0.0.1:{port}{base}")
        httpd.serve_forever()


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--out", default=str(SITE / "dist"))
    ap.add_argument("--base", default=os.environ.get("DOCS_BASE", "/cloudg/"))
    ap.add_argument("--strict", action="store_true", help="exit non-zero on broken internal links")
    ap.add_argument("--serve", action="store_true")
    ap.add_argument("--port", type=int, default=8000)
    args = ap.parse_args()

    site = Site(args.base, args.strict)
    site.discover()
    site.render_all()
    out = Path(args.out)
    site.write(out)
    problems = site.check_links()
    for p in problems:
        print(f"link: {p}", file=sys.stderr)
    print(f"built {len(site.pages)} pages into {out} (base {site.base})")
    if problems and args.strict:
        return 1
    if args.serve:
        serve(out, site.base, args.port)
    return 0


if __name__ == "__main__":
    sys.exit(main())
