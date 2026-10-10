"""Output: writes the rendered pages, static files, search index and version list."""

from __future__ import annotations

import json
import logging
import re
import shutil
from pathlib import Path

import yaml

from docsgen.md import strip_tags
from docsgen.page import GITHUB, REPO, SITE, Page, truncate

log = logging.getLogger(__name__)

# top-level pages with their own template; everything else uses page.html
_TEMPLATES = {"home": "home.html", "changelog": "changelog.html"}


class OutputMixin:
    """Writing the built site for :class:`docsgen.site.Site`."""

    def write(self, out: Path) -> None:
        self._copy_static(out)
        stats = self._stats()
        redirects = {
            k: self.href(v.split("#")[0], v.partition("#")[2])
            for k, v in self.nav["redirects"].items()
        }
        versions = self._versions()
        (out / "versions.json").write_text(json.dumps(versions, indent=2))
        common = {"redirects": redirects, "versions": versions, "tabs": self.tabs}
        for page in self.pages:
            html = self.env.get_template(_TEMPLATES.get(page.kind, "page.html")).render(
                page=page, stats=stats, sidebar=self.sidebars.get(page.tab, []), **common
            )
            dest = out / page.url / "index.html" if page.url else out / "index.html"
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_text(html)
        not_found = Page("404", "Page not found", kind="404", in_sidebar=False)
        (out / "404.html").write_text(
            self.env.get_template("404.html").render(page=not_found, sidebar=[], **common)
        )
        index = json.dumps(self._search_index(), separators=(",", ":"))
        (out / "search-index.json").write_text(index)
        (out / ".nojekyll").write_text("")

    @staticmethod
    def _copy_static(out: Path) -> None:
        if out.exists():
            shutil.rmtree(out)
        out.mkdir(parents=True)
        shutil.copytree(SITE / "static", out / "static")
        viewer = REPO / "docs" / "viewer.html"
        if viewer.exists():
            shutil.copy2(viewer, out / "viewer.html")
        if (REPO / "docs" / "assets").is_dir():
            shutil.copytree(REPO / "docs" / "assets", out / "assets")

    # -- home page numbers -------------------------------------------------------

    def _stats(self) -> dict:
        computed = {
            "controls": _count_controls(),
            "asset_types": _count_asset_types(),
            "mcp_tools": _count_mcp_tools(),
        }
        data = yaml.safe_load((SITE / "data" / "stats.yaml").read_text())
        items = []
        for item in data["stats"]:
            value = computed.get(item.get("compute", ""), 0) or item.get("value", 0)
            items.append(
                {"value": f"{value:,}", "label": item["label"], "href": item.get("href", "")}
            )
        commands = [k for k, v in self.cli.items() if not v.group and k != "__root__"]
        return {"items": items, "commands": len(commands)}

    def _versions(self) -> list[dict]:
        out = []
        for r in self.releases:
            if not re.match(r"^\d", r.version):
                continue
            latest = r.version == self.version
            out.append(
                {
                    "version": r.version,
                    "date": r.date,
                    "latest": latest,
                    "url": self.href("") if latest else self.href("changelog", r.anchor),
                }
            )
        out.append(
            {"version": "main", "date": "unreleased", "latest": False, "url": f"{GITHUB}/tree/main"}
        )
        return out

    # -- search ------------------------------------------------------------------

    def _search_index(self) -> list[dict]:
        entries = []
        for page in self.pages:
            if page.kind != "home":
                entries.extend(self._page_entries(page))
        return entries

    def _page_entries(self, page: Page) -> list[dict]:
        chunks = _sections(page.body, page.headings)
        lede = strip_tags(page.lede)
        entries = [
            {
                "t": page.title,
                "u": self.href(page.url),
                "k": page.search_type,
                "h": "",
                "x": truncate(lede + " " + chunks[0][1], 600),
                "g": page.group,
                "m": int(page.mono_title),
            }
        ]
        for hid, text, htext in chunks[1:]:
            entries.append(
                {
                    "t": page.title,
                    "u": self.href(page.url, hid),
                    "k": page.search_type,
                    "h": htext,
                    "x": truncate(text, 600),
                    "g": page.group,
                    "m": int(page.mono_title or page.kind == "config"),
                }
            )
        if page.kind == "config":
            entries.extend(self._config_entries(page))
        return entries

    def _config_entries(self, page: Page) -> list[dict]:
        s = page.extra["section"]
        return [
            {
                "t": f"{s.name}.{k.path}",
                "u": self.href(page.url, k.path),
                "k": "Config",
                "h": "",
                "x": f"{k.type} · {k.default or 'none'} · {k.description}",
                "g": page.group,
                "m": 1,
            }
            for k in s.keys
        ]


def _count_controls() -> int:
    controls = 0
    for f in sorted((REPO / "cloudg" / "rules" / "frameworks").glob("*.yaml")):
        data = yaml.safe_load(f.read_text()) or {}
        controls += len(data.get("controls") or [])
    return controls


def _count_asset_types() -> int:
    try:
        from cloudg.schema.models import AssetType
    except Exception:  # noqa: BLE001
        log.debug("cannot import AssetType; asset type count left at 0", exc_info=True)
        return 0
    return len(AssetType)


def _count_mcp_tools() -> int:
    try:
        from cloudg.mcp import default_registry

        return len(default_registry().tools)
    except Exception:  # noqa: BLE001
        log.debug("cannot list the MCP tools; tool count left at 0", exc_info=True)
        return 0


def _sections(html: str, headings: list) -> list[tuple[str, str, str]]:
    """Split rendered HTML at h2/h3 ids into (id, text, heading) chunks."""
    ids = {h.id: h.text for h in headings if h.level in (2, 3)}
    html = re.sub(r'<a class="h-anchor"[^>]*>#</a>', "", html)
    parts = re.split(r'(<h[23] id="([^"]+)")', html)
    out = [("", strip_tags(parts[0]), "")]
    for i in range(1, len(parts), 3):
        hid = parts[i + 1]
        content = parts[i + 2] if i + 2 < len(parts) else ""
        if hid in ids:
            text = strip_tags(re.sub(r"<pre.*?</pre>", " ", content, flags=re.S))
            out.append((hid, text, ids[hid]))
        else:
            prev = out[-1]
            out[-1] = (prev[0], prev[1] + " " + strip_tags(content), prev[2])
    return out
