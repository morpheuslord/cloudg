"""Markdown to HTML with the site's extensions.

CommonMark and GFM tables come from markdown-it-py. On top of that:

- ``:::kind`` containers (callouts, steps, cells, links), parsed line by line
  before markdown-it sees the text, so they can nest and hold any markdown;
- fenced code rendered by :mod:`docsgen.highlight`, with consecutive ``tab=``
  fences merged into one tabbed block;
- ``mermaid`` fences turned into diagrams;
- GitHub-style heading anchors (overridable with ``{#id}``) collected for the TOC;
- link rewriting through a caller-supplied resolver.
"""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass, field
from html import escape, unescape
from typing import Callable

from markdown_it import MarkdownIt

from docsgen.fences import FenceTracker
from docsgen.highlight import parse_info, render_code_block, render_tab_group
from docsgen.icons import icon

_CONTAINER_OPEN = re.compile(r"^(:{3,})\s*([A-Za-z][\w-]*)\s*(.*?)\s*$")
_CONTAINER_CLOSE = re.compile(r"^(:{3,})\s*$")
_TAB_MARK = re.compile(r"<!--TAB:(\d+)-->")
_TAB_RUN = re.compile(r"(?:<!--TAB:\d+-->\s*)+")
_ID_SUFFIX = re.compile(r"\s*\{#([\w.\-:]+)\}\s*$")
_LINK_ITEM = re.compile(r"^\s*[-*]\s+\[([^\]]+)\]\(([^)]+)\)\s*(.*)$")

CALLOUTS = {
    "note": ("Note", "info"),
    "tip": ("Tip", "lightbulb"),
    "warning": ("Warning", "triangle-alert"),
    "danger": ("Danger", "octagon-alert"),
}


def github_slug(text: str) -> str:
    """The anchor GitHub generates for a heading."""
    text = unicodedata.normalize("NFKC", text).strip().lower()
    text = re.sub(r"[^\w\- ]", "", text)
    return text.replace(" ", "-")


@dataclass
class Heading:
    level: int
    id: str
    text: str
    html: str


@dataclass
class Rendered:
    html: str
    headings: list[Heading] = field(default_factory=list)


def strip_tags(html: str) -> str:
    return unescape(re.sub(r"<[^>]+>", "", html))


def _rule(method: Callable) -> Callable:
    """Wrap a bound method as a markdown-it render rule.

    markdown-it binds each rule to its renderer with ``__get__``. On
    Python 3.12 that re-binds a bound method to the renderer (3.13 keeps the
    original binding), so rules are plain functions that drop the renderer.
    """

    def rule(renderer, tokens, idx, options, env):  # noqa: ARG001
        return method(tokens, idx, options, env)

    return rule


class Renderer:
    """Renders one document. ``resolve_link(href) -> href`` rewrites links."""

    def __init__(
        self,
        resolve_link: Callable[[str], str] | None = None,
        heading_base: int = 0,
        slugs: dict[str, int] | None = None,
    ):
        self.resolve_link = resolve_link or (lambda h: h)
        self.heading_base = heading_base
        self.headings: list[Heading] = []
        # share one dict across the pages of a split document so duplicate
        # headings get the same -1, -2 suffixes GitHub gives them
        self._slugs: dict[str, int] = slugs if slugs is not None else {}
        self._tabs: list[tuple[str, str]] = []
        self.md = (
            MarkdownIt("commonmark", {"html": True, "typographer": False})
            .enable("table")
            .enable("strikethrough")
        )
        self.md.add_render_rule("fence", _rule(self._fence))
        self.md.add_render_rule("code_block", _rule(self._code_block))
        self.md.add_render_rule("heading_open", _rule(self._heading_open))
        self.md.add_render_rule("heading_close", _rule(self._heading_close))
        self._open_ids: list[str] = []
        self.md.add_render_rule(
            "table_open", lambda *a: '<div class="table-wrap"><table class="table">\n'
        )
        self.md.add_render_rule("table_close", lambda *a: "</table></div>\n")
        self.md.add_render_rule("link_open", _rule(self._link_open))
        self.md.add_render_rule("code_inline", _rule(self._code_inline))

    # -- markdown-it render rules -------------------------------------------------

    def _fence(self, tokens, idx, options, env):
        tok = tokens[idx]
        lang, attrs = parse_info(tok.info)
        if lang == "mermaid":
            cap = attrs.get("caption")
            figcap = f"<figcaption>{escape(cap)}</figcaption>" if cap else ""
            return (
                f'<figure class="diagram"><div class="diagram-body"><pre class="mermaid">{escape(tok.content)}</pre></div>'
                f"{figcap}</figure>\n"
            )
        if "tab" in attrs:
            self._tabs.append((tok.content, tok.info))
            return f"<!--TAB:{len(self._tabs) - 1}-->\n"
        return render_code_block(tok.content, tok.info) + "\n"

    def _code_block(self, tokens, idx, options, env):
        return render_code_block(tokens[idx].content, "text") + "\n"

    def _code_inline(self, tokens, idx, options, env):
        return f"<code>{escape(tokens[idx].content)}</code>"

    def _heading_open(self, tokens, idx, options, env):
        tok = tokens[idx]
        inline = tokens[idx + 1]
        level = max(1, min(int(tok.tag[1]) + self.heading_base, 6))
        custom = None
        if inline.children:
            last = inline.children[-1]
            if last.type == "text":
                m = _ID_SUFFIX.search(last.content)
                if m:
                    custom = m.group(1)
                    last.content = last.content[: m.start()]
        inner_html = self.md.renderer.renderInline(inline.children or [], options, env)
        text = strip_tags(inner_html).strip()
        hid = custom or self._unique(github_slug(text))
        self.headings.append(Heading(level, hid, text, inner_html))
        tok.tag = f"h{level}"
        tokens[idx + 2].tag = f"h{level}"
        self._open_ids.append(hid)
        return f'<h{level} id="{escape(hid)}">'

    def _heading_close(self, tokens, idx, options, env):
        hid = self._open_ids.pop() if self._open_ids else ""
        tag = tokens[idx].tag
        return f'<a class="h-anchor" href="#{escape(hid)}" aria-label="Link to this section">#</a></{tag}>\n'

    def register(self, slug: str) -> str:
        return self._unique(slug)

    def _unique(self, slug: str) -> str:
        if slug in self._slugs:
            self._slugs[slug] += 1
            return f"{slug}-{self._slugs[slug]}"
        self._slugs[slug] = 0
        return slug

    def _link_open(self, tokens, idx, options, env):
        tok = tokens[idx]
        href = tok.attrGet("href") or ""
        new = self.resolve_link(href)
        tok.attrSet("href", new)
        if new.startswith(("http://", "https://")):
            tok.attrSet("rel", "noopener")
        return self.md.renderer.renderToken(tokens, idx, options, env)

    # -- containers -----------------------------------------------------------------

    def render(self, text: str) -> Rendered:
        html = self._render_blocks(text)
        return Rendered(html=html, headings=self.headings)

    def _render_markdown(self, text: str) -> str:
        self._tabs = []
        html = self.md.render(text, {})
        if self._tabs:
            tabs = self._tabs

            def group(m: re.Match) -> str:
                ids = [int(i) for i in _TAB_MARK.findall(m.group(0))]
                return render_tab_group([tabs[i] for i in ids]) + "\n"

            html = _TAB_RUN.sub(group, html)
        return html

    def _render_blocks(self, text: str) -> str:
        """Split ``text`` into markdown runs and containers, render each."""
        lines = text.split("\n")
        out: list[str] = []
        buf: list[str] = []
        fences = FenceTracker()
        i = 0
        while i < len(lines):
            line = lines[i]
            om = None if fences.feed(line) else _CONTAINER_OPEN.match(line)
            if om:
                body, i = self._collect_container(lines, i + 1, len(om.group(1)))
                out.append(self._render_markdown("\n".join(buf)))
                buf = []
                out.append(self._container(om.group(2).lower(), om.group(3), body))
                continue
            buf.append(line)
            i += 1
        out.append(self._render_markdown("\n".join(buf)))
        return "".join(out)

    @staticmethod
    def _collect_container(lines: list[str], start: int, colons: int) -> tuple[str, int]:
        """Return the body of the container opened above ``start`` and the index after it."""
        depth = 0
        fences = FenceTracker()
        for i in range(start, len(lines)):
            if fences.feed(lines[i]):
                continue
            step = _container_step(lines[i], colons)
            if step < 0 and depth == 0:
                return "\n".join(lines[start:i]), i + 1
            depth += step
        return "\n".join(lines[start:]), max(start, len(lines))

    def _split_h3(self, body: str) -> tuple[str, list[tuple[str, str]]]:
        """Split a container body at ``###`` headings (outside fences)."""
        intro: list[str] = []
        items: list[tuple[str, list[str]]] = []
        fences = FenceTracker()
        for line in body.split("\n"):
            if not fences.feed(line) and line.startswith("### "):
                items.append((line[4:].strip(), []))
                continue
            (items[-1][1] if items else intro).append(line)
        return "\n".join(intro), [(t, "\n".join(b)) for t, b in items]

    def _inline(self, text: str) -> str:
        return self.md.renderInline(text)

    def _container(self, kind: str, arg: str, body: str) -> str:
        handler = _CONTAINERS.get(kind, Renderer._plain_container)
        return handler(self, kind, arg, body)

    def _callout(self, kind: str, arg: str, body: str) -> str:
        label, ico = CALLOUTS[kind]
        label = arg or label
        inner = self._render_blocks(body)
        return (
            f'<aside class="callout callout--{kind}" role="note">'
            f'<div class="callout-label">{icon(ico, 16)}<span>{escape(label)}</span></div>'
            f'<div class="callout-body">{inner}</div></aside>\n'
        )

    def _numbered(self, kind: str, arg: str, body: str) -> str:  # noqa: ARG002
        """``steps`` and ``cells`` containers: one numbered item per ``###`` heading."""
        intro, items = self._split_h3(body)
        parts = [self._render_blocks(intro)] if intro.strip() else []
        rows = "".join(
            self._numbered_item(kind, n, title, text)
            for n, (title, text) in enumerate(items, start=1)
        )
        if kind == "steps":
            parts.append(f'<ol class="steps">{rows}</ol>')
        else:
            parts.append(f'<div class="cells cells--{min(len(items), 4)}">{rows}</div>')
        return "".join(parts) + "\n"

    def _numbered_item(self, kind: str, n: int, title: str, text: str) -> str:
        hid = self._unique(github_slug(_ID_SUFFIX.sub("", title)))
        m = _ID_SUFFIX.search(title)
        if m:
            hid = m.group(1)
            title = title[: m.start()]
        title_html = self._inline(title)
        self.headings.append(
            Heading(3 + self.heading_base, hid, strip_tags(title_html), title_html)
        )
        inner = self._render_blocks(text)
        if kind == "steps":
            return (
                f'<li class="step"><div class="step-num" aria-hidden="true">{n}</div>'
                f'<div class="step-body"><h3 id="{escape(hid)}">{title_html}</h3>{inner}</div></li>'
            )
        return (
            f'<div class="cell"><div class="cell-num">{n:02d}</div>'
            f'<h4 id="{escape(hid)}">{title_html}</h4>{inner}</div>'
        )

    def _links(self, kind: str, arg: str, body: str) -> str:  # noqa: ARG002
        cards = []
        for line in body.split("\n"):
            m = _LINK_ITEM.match(line)
            if not m:
                continue
            title, href, desc = m.groups()
            href = self.resolve_link(href)
            cards.append(
                f'<a class="link-card" href="{escape(href)}"><span class="link-card-title">'
                f"{self._inline(title)}{icon('arrow-right', 16)}</span>"
                f'<span class="link-card-desc">{self._inline(desc)}</span></a>'
            )
        return f'<nav class="link-cards">{"".join(cards)}</nav>\n'

    def _plain_container(self, kind: str, arg: str, body: str) -> str:  # noqa: ARG002
        """Unknown container: render the body plainly."""
        return f'<div class="container-{escape(kind)}">{self._render_blocks(body)}</div>\n'


_CONTAINERS: dict[str, Callable[..., str]] = {
    **dict.fromkeys(CALLOUTS, Renderer._callout),
    "steps": Renderer._numbered,
    "cells": Renderer._numbered,
    "links": Renderer._links,
}


def _container_step(line: str, colons: int) -> int:
    """1 for a nested opener with ``colons`` colons, -1 for a matching closer, else 0."""
    om = _CONTAINER_OPEN.match(line)
    if om and len(om.group(1)) == colons:
        return 1
    cm = _CONTAINER_CLOSE.match(line)
    return -1 if cm and len(cm.group(1)) == colons else 0


def render_inline(text: str, resolve_link: Callable[[str], str] | None = None) -> str:
    return Renderer(resolve_link).md.renderInline(text or "")


def split_front_matter(text: str) -> tuple[dict, str]:
    import yaml

    if text.startswith("---\n"):
        end = text.find("\n---", 4)
        if end != -1:
            meta = yaml.safe_load(text[4:end]) or {}
            body = text[end + 4 :].lstrip("\n")
            return meta, body
    return {}, text
