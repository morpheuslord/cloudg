"""Page rendering: turns each discovered page into body HTML, headings and metadata."""

from __future__ import annotations

import re
import sys
from html import escape
from pathlib import Path

from docsgen import gen_api, gen_changelog, gen_cli
from docsgen.highlight import render_code_block, tokenize_lines
from docsgen.icons import icon
from docsgen.md import Heading, Renderer, render_inline, split_front_matter, strip_tags
from docsgen.page import REPO, SITE, Page, line_of, truncate

CLI_INDEX_LEDE = (
    "Every <code>cloudg</code> command and the flags it takes. The tables are generated from"
    " the click definitions, so they match <code>--help</code>."
)
API_INDEX_LEDE = (
    "cloudg is a library first. The CLI is a thin layer over <code>CloudGEngine</code>, so"
    " anything a command does you can do from Python, one phase at a time if you like."
)


class RenderMixin:
    """Per-kind page renderers for :class:`docsgen.site.Site`."""

    def render_all(self) -> None:
        self.cli = gen_cli.collect(REPO)
        renderers = {
            "guide": self._render_markdown_page,
            "cli": self._render_cli_page,
            "api": self._render_api_page,
            "split": self._render_split_page,
            "split-index": self._render_split_page,
            "config": self._render_config_page,
            "changelog": self._render_changelog,
            "cli-index": self._render_cli_index,
            "api-index": self._render_api_index,
        }
        for page in self.pages:
            page.crumbs = self._crumbs(page)
            render = renderers.get(page.kind)
            if render:
                render(page)
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
        page.meta = [
            (label, render_inline(str(value), res)) for label, value in meta.get("meta", [])
        ]
        page.since = str(meta.get("since", "")) or ""
        if meta.get("source"):
            page.source = meta["source"]

    # -- guides and split documents ---------------------------------------------

    def _render_markdown_page(self, page: Page) -> None:
        meta, body = self._load_md(page)
        self._apply_front(page, meta)
        r = Renderer(self.resolver(page)).render(body)
        page.body, page.headings = r.html, r.headings

    def _render_split_page(self, page: Page) -> None:
        renderer = Renderer(
            self.resolver(page, page.extra["doc"]),
            heading_base=page.extra.get("heading_base", -1),
            slugs=page.extra.get("shared_slugs"),
        )
        for slug in page.extra.get("pre_slugs", []):
            renderer.register(slug)
        r = renderer.render(page.extra.get("md", ""))
        page.body, page.headings = r.html, r.headings
        children = page.extra.get("children") or []
        if children:
            self._append_section_cards(page, children)
        if not page.description:
            page.description = _first_paragraph(r.html)
        if page.kind == "split" and page.extra.get("number"):
            page.extra["kicker"] = f"Section {page.extra['number'].rstrip('.')}"

    def _append_section_cards(self, page: Page, children: list[Page]) -> None:
        cards = "".join(self._section_card(c) for c in children)
        label = "Sections" if page.kind == "split-index" else "In this section"
        page.body += (
            f'<h2 id="sections">{label}</h2><nav class="link-cards link-cards--dense">{cards}</nav>'
        )
        page.headings.append(Heading(2, "sections", label, label))

    def _section_card(self, child: Page) -> str:
        number = child.extra.get("number")
        title = f"{number} {child.title}" if number else child.title
        return (
            f'<a class="link-card" href="{self.href(child.url)}"><span class="link-card-title">'
            f"{escape(title)}{icon('arrow-right', 16)}</span>"
            f'<span class="link-card-desc">{escape(child.description)}</span></a>'
        )

    # -- CLI ---------------------------------------------------------------------

    def _render_cli_page(self, page: Page) -> None:
        meta, body = self._load_md(page)
        self._apply_front(page, meta)
        page.mono_title = bool(meta.get("command"))
        r = Renderer(self.resolver(page))
        parts = []
        if meta.get("command"):
            parts = self._render_command(page, meta, r)
        parts.append(r.render(body).html)
        page.body, page.headings = "".join(parts), r.headings

    def _render_command(self, page: Page, meta: dict, r: Renderer) -> list[str]:
        """Usage line and options table for the command named in the front matter."""
        command = meta["command"]
        cmd = self.cli.get(command)
        if cmd is None:
            raise SystemExit(f"{page.source}: unknown command {command!r}")
        page.title = f"cloudg {command}"
        if not page.lede:
            page.lede = escape(cmd.short_help)
        if cmd.source_file:
            page.source, page.source_line = cmd.source_file, cmd.source_line
        page.meta = page.meta or []
        parts = [r.render(meta["intro"]).html] if meta.get("intro") else []
        r.headings.append(Heading(2, "usage", "Usage", "Usage"))
        parts.append(
            '<h2 id="usage" class="visually-hidden">Usage</h2>'
            f'<pre class="usage"><code>{escape(cmd.usage)}</code></pre>'
        )
        r.headings.append(Heading(2, "options", "Options", "Options"))
        parts.append(self.env.get_template("_options.html").render(cmd=cmd, page=page))
        page.extra["command"] = cmd
        return parts

    def _render_cli_index(self, page: Page) -> None:
        page.title = "CLI reference"
        page.lede = CLI_INDEX_LEDE
        page.source = "cloudg/cli.py"
        rows = []
        for group in self.sidebars["cli"][1:]:
            for p in group["pages"]:
                cmd_name = (
                    p.title.replace("cloudg ", "", 1) if p.title.startswith("cloudg ") else None
                )
                rows.append((group["title"], p, self.cli.get(cmd_name) if cmd_name else None))
        page.extra = {"rows": rows, "root": self.cli["__root__"]}
        page.headings = [
            Heading(2, "commands", "Commands", "Commands"),
            Heading(2, "global-options", "Global options", "Global options"),
        ]
        page.body = self.env.get_template("_cli_index.html").render(page=page)
        page.mono_title = False

    # -- Python API --------------------------------------------------------------

    def _render_api_page(self, page: Page) -> None:
        meta, body = self._load_md(page)
        self._apply_front(page, meta)
        res = self.resolver(page)
        r = Renderer(res)
        parts = []
        if meta.get("object"):
            loaded = self._load_api_objects(page, meta)
            self._api_page_header(page, meta, loaded[0], len(loaded) == 1)
            multi = len(loaded) > 1
            for obj in loaded:
                r.headings.extend(_api_headings(obj, multi))
                parts.append(self._render_api_object(page, obj, multi, res))
        parts.append(r.render(body).html)
        page.body, page.headings = "".join(parts), r.headings

    def _load_api_objects(self, page: Page, meta: dict) -> list[gen_api.ApiObject]:
        objects = meta["object"]
        paths = objects if isinstance(objects, list) else [objects]
        members = meta.get("members")
        loaded = []
        for p in paths:
            if isinstance(members, dict):
                wanted = members.get(p)
            else:
                wanted = members if len(paths) == 1 else None
            try:
                loaded.append(gen_api.load(p, REPO, wanted))
            except Exception as exc:  # noqa: BLE001
                raise SystemExit(f"{page.source}: cannot load {p}: {exc}") from exc
        return loaded

    def _api_page_header(self, page: Page, meta: dict, first, single: bool) -> None:
        page.mono_title = single and not meta.get("title")
        if page.mono_title:
            page.title = first.name
        if single:
            page.extra.update(kind_tag=first.kind, module=first.module, src=first)
        page.source, page.source_line = first.source_file, first.source_line
        if not page.lede and first.doc.summary:
            page.lede = render_inline(first.doc.summary, self.resolver(page))

    def _render_api_object(self, page: Page, obj, multi: bool, res) -> str:
        return self.env.get_template("_api_object.html").render(
            obj=obj,
            multi=multi,
            page=page,
            md=lambda t: Renderer(res).render(t).html,
            inline=lambda t: render_inline(t, res),
            code=render_code_block,
            blob=lambda line: self.blob(obj.source_file, line, self.git_ref),
        )

    def _render_api_index(self, page: Page) -> None:
        page.title = "Python API"
        page.lede = API_INDEX_LEDE
        page.source = "cloudg/__init__.py"
        groups = [(group["title"], list(group["pages"])) for group in self.sidebars["api"][1:]]
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

    # -- config and changelog ----------------------------------------------------

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
        table = self.env.get_template("_config.html").render(
            s=s,
            page=page,
            yaml_lines=_highlight_yaml_lines(s.lines),
            inline=lambda t: render_inline(t, res),
        )
        page.body = (f"<p>{render_inline(rest, res)}</p>" if rest else "") + table
        if s.name != "general":
            page.source_line = line_of(REPO / "config.yaml", f"{s.name}:")
        if page.source_line:
            page.source = "config.yaml"

    def _render_changelog(self, page: Page) -> None:
        head, releases = gen_changelog.parse(REPO / "CHANGELOG.md")
        res = self.resolver(page)
        page.lede = render_inline(head, res) if head else ""
        page.extra = {"releases": [_render_release(rel, res) for rel in releases]}
        self.releases = releases
        page.headings = [Heading(2, r.anchor, r.version, r.version) for r in releases]

    def _link_prev_next(self) -> None:
        for groups in self.sidebars.values():
            seq = [p for g in groups for p in g["pages"]]
            for i, p in enumerate(seq):
                p.prev = seq[i - 1] if i > 0 else None
                p.next = seq[i + 1] if i + 1 < len(seq) else None


def _api_headings(obj: gen_api.ApiObject, multi: bool) -> list[Heading]:
    """TOC entries for one object on an API page."""
    if multi:
        return [Heading(2, obj.name.lower(), obj.name, obj.name)]
    members_title = "Methods" if obj.kind == "class" else "Members"
    sections = (
        ("Fields", "fields", obj.fields),
        ("Values", "values", obj.enum_values),
        (members_title, "members", obj.members),
    )
    out = [Heading(2, hid, title, title) for title, hid, items in sections if items]
    out += [Heading(3, f"{obj.name}.{m.name}", m.name, m.name) for m in obj.members]
    return out


def _render_release(rel, res) -> dict:
    intro = Renderer(res, heading_base=1).render(rel.intro).html if rel.intro else ""
    blocks = [
        (label, Renderer(res, heading_base=1).render(text).html) for label, text in rel.blocks
    ]
    return {"rel": rel, "intro": intro, "blocks": blocks}


def _first_paragraph(html: str) -> str:
    first = re.search(r"<p>(.*?)</p>", html, re.S)
    return truncate(strip_tags(first.group(1)), 160) if first else ""


def _highlight_yaml_lines(lines: list[str]) -> list[str]:
    toks = tokenize_lines("\n".join(lines) + "\n", "yaml")
    toks += [""] * (len(lines) - len(toks))
    return toks
