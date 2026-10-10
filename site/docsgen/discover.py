"""Page discovery: walks data/nav.yaml and creates every page before anything renders."""

from __future__ import annotations

import yaml

from docsgen import gen_config
from docsgen.page import REPO, SITE, Page
from docsgen.split import SplitDoc

_GENERATED_SEARCH_TYPES = {"cli-index": "CLI", "api-index": "Python API"}
_TAB_KINDS = {"cli": "cli", "api": "api", "mcp": "guide", "reference": "guide"}
_TAB_SEARCH_TYPES = {
    "guides": "Guides",
    "cli": "CLI",
    "api": "Python API",
    "mcp": "MCP",
    "reference": "Reference",
}


class DiscoverMixin:
    """Nav walking for :class:`docsgen.site.Site`."""

    nav: dict
    tabs: list[dict]
    sidebars: dict[str, list[dict]]

    def discover(self) -> None:
        home = self.add(
            Page("", "cloudg documentation", kind="home", search_type="Guides", in_sidebar=False)
        )
        home.source = "site/templates/home.html"
        for tab in self.nav["tabs"]:
            self.tabs.append({"id": tab["id"], "label": tab["label"], "root": tab["root"]})
            self.sidebars[tab["id"]] = [
                {
                    "title": group["title"],
                    "num": f"{gi:02d}",
                    "pages": self._discover_group(tab["id"], group),
                }
                for gi, group in enumerate(tab.get("groups", []), start=1)
            ]
        self.add(
            Page(
                "changelog",
                "Changelog",
                tab="changelog",
                kind="changelog",
                search_type="Changelog",
                source="CHANGELOG.md",
                in_sidebar=False,
            )
        )

    def _discover_group(self, tab: str, group: dict) -> list[Page]:
        if "split" in group:
            return SplitDoc(self, tab, group).discover()
        if group.get("generated") == "config":
            return self._discover_config(tab, group)
        return [self._discover_item(tab, group["title"], item) for item in group["items"]]

    def _discover_item(self, tab: str, group: str, item: dict) -> Page:
        title = item["title"]
        if "generated" in item:
            page = Page(item["path"], title, tab=tab, group=group, kind=item["generated"])
            page.search_type = _GENERATED_SEARCH_TYPES.get(item["generated"], "Guides")
            return self.add(page)
        rel = item["page"]
        file = SITE / "content" / f"{rel}.md"
        page = Page(
            item.get("path", rel),
            title,
            tab=tab,
            group=group,
            kind=_TAB_KINDS.get(tab, "guide"),
            search_type=_TAB_SEARCH_TYPES[tab],
            source=str(file.relative_to(REPO)),
            nav_title=title,
        )
        page.loader = file
        return self.add(page)

    def _discover_config(self, tab: str, group: dict) -> list[Page]:
        sections = gen_config.parse(REPO / "config.yaml")
        gen_config.merge_model_descriptions(sections)
        notes_file = SITE / "data" / "config-notes.yaml"
        overrides = yaml.safe_load(notes_file.read_text()) or {}
        pages = []
        for s in sections:
            for k in s.keys:
                note = overrides.get(f"{s.name}.{k.path}")
                if note:
                    k.description = note
            page = Page(
                f"{group['prefix']}/{s.name}",
                s.name,
                tab=tab,
                group=group["title"],
                kind="config",
                search_type="Config",
                source="config.yaml",
                mono_title=True,
            )
            page.extra = {"section": s, "intro": overrides.get(s.name, "")}
            pages.append(self.add(page))
        return pages
