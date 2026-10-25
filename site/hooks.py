"""MkDocs hooks that generate the reference pages of the cloudg docs site.

Registered in mkdocs.yml under ``hooks:``. Nothing they produce is committed;
every build regenerates it from the sources:

- the docs/*.md references, split into one page per ``##`` section
  (:mod:`gen.split`), wherever the nav names one of them;
- the config.yaml reference, one page per top-level section
  (:mod:`gen.config_ref`), where the nav says ``config.yaml``;
- the changelog page, from CHANGELOG.md (:mod:`gen.changelog`);
- the "Usage" and "Options" sections of each CLI page and the command
  table of the CLI overview, from the click commands (:mod:`gen.cli`);
- a "source" link to GitHub on every object mkdocstrings renders;
- copies of the sample report, the offline viewer and docs/assets.

site/AUTHORING.md explains how to use them from a page.
"""

from __future__ import annotations

import inspect
import logging
import pkgutil
import posixpath
import re
import sys
from pathlib import Path

from mkdocs.plugins import event_priority
from mkdocs.structure.files import File, Files, InclusionLevel
from mkdocs.utils import get_relative_url

SITE = Path(__file__).resolve().parent
REPO = SITE.parent
if str(SITE) not in sys.path:
    sys.path.insert(0, str(SITE))
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

from gen import changelog, cli, config_ref  # noqa: E402
from gen.common import (  # noqa: E402
    GITHUB,
    blob,
    first_sentence,
    normalise_markdown,
    plain,
    source_ref,
    with_id,
)
from gen.links import LinkMap, rewrite  # noqa: E402
from gen.split import GenPage, SplitDoc  # noqa: E402

log = logging.getLogger("mkdocs.hooks.cloudg")

# docs/*.md file -> (URL prefix on the site, "##" sections left out)
SPLITS: dict[str, tuple[str, list[str]]] = {
    "docs/MCP.md": ("mcp/server", ["Contents"]),
    "docs/MCP_TOOLS.md": ("mcp/tools", ["Tool reference"]),
    "docs/MCP_PRIVACY.md": ("mcp/privacy", ["Contents"]),
    "docs/MCP_INTERNALS.md": ("mcp/internals", ["Contents"]),
    "docs/INVENTORY_REFERENCE.md": ("reference/inventory", ["Contents"]),
    "docs/INVENTORY_CATALOG.md": ("reference/catalog", ["Contents"]),
    "docs/INVENTORY_INTERNALS.md": ("reference/internals", ["Contents"]),
    "docs/RESILIENCE.md": ("reference/resilience", ["Contents"]),
}
CONFIG_PREFIX = "reference/config"
CHANGELOG_URI = "changelog.md"

# Files copied into the built site as they are: published path -> source
STATIC = {
    "sample-report.html": "site/static/sample-report.html",
    # the address the sample report had on the old site
    "static/sample-report.html": "site/static/sample-report.html",
    "viewer.html": "docs/viewer.html",
}

CLI_REFERENCE = "<!-- cloudg:cli-reference -->"
CLI_INDEX = "<!-- cloudg:cli-index -->"
STATS = "<!-- cloudg:stats -->"
# CLI pages whose options table also points at the auth flags page
_AUTH_COMMANDS = {"run", "collect", "scan", "map"}


class _State:
    generated: dict[str, str] = {}  # docs-dir uri -> markdown
    sources: dict[str, tuple[str, int]] = {}  # uri -> (repo file, line)
    commands: dict = {}
    cli_rows: list[tuple[str, str, str]] = []  # (group, title, uri)


S = _State()


# ---------------------------------------------------------------------------
# config: generate everything and expand the nav
# ---------------------------------------------------------------------------


def on_config(config, **kwargs):
    S.generated, S.sources = {}, {}
    links = LinkMap()
    docs: dict[str, SplitDoc] = {}
    for source, (prefix, skip) in SPLITS.items():
        doc = SplitDoc(source, prefix, skip)
        doc.build()
        docs[source] = doc
        links.anchors[source] = {a: (uri, a) for a, uri in doc.anchors.items()}
        links.first_page[source] = doc.overview.uri

    log_path = REPO / "CHANGELOG.md"
    links.anchors["CHANGELOG.md"] = {
        gh: (CHANGELOG_URI, site) for gh, site in changelog.anchors(log_path).items()
    }
    links.first_page["CHANGELOG.md"] = CHANGELOG_URI
    links.files["config.yaml"] = f"{CONFIG_PREFIX}/providers.md"

    for doc in docs.values():
        for page in doc.pages:
            _add(page.uri, _split_page(page, links), page.source, page.source_line)
    _add(CHANGELOG_URI, _changelog_page(links), "CHANGELOG.md", 1)
    config_pages = _config_pages()

    config["nav"] = _expand_nav(config["nav"], docs, config_pages)
    S.commands = cli.collect(REPO)

    release = changelog.latest(log_path)
    config["extra"]["release"] = release
    config["copyright"] = (
        f"cloudg {release} &middot; Copyright &copy; morpheuslord &middot; MIT License"
    )
    return config


def _add(uri: str, markdown: str, source: str, line: int) -> None:
    S.generated[uri] = markdown
    S.sources[uri] = (source, line)


def _front(description: str) -> list[str]:
    if not description:
        return []
    desc = description.replace('"', "'")
    return ["---", f'description: "{desc}"', "---", ""]


def _split_page(page: GenPage, links: LinkMap) -> str:
    body = rewrite(
        normalise_markdown("\n".join(page.lines)).split("\n"), links.resolver(page.source, page.uri)
    )
    out = _front(page.description)
    title = f"# {page.title}"
    out += [with_id(title, page.title_anchor) if page.title_anchor else title, ""]
    src = blob(page.source, page.source_line)
    kicker = f"{page.kicker} &middot; " if page.kicker else ""
    out += [f"{kicker}From [`{page.source}`]({src}) on GitHub", "{ .page-meta }", ""]
    out += body
    if page.children:
        out += _section_cards(page)
    return "\n".join(out).rstrip() + "\n"


def _section_cards(page: GenPage) -> list[str]:
    taken = set(re.findall(r"\{ #([^ }]+)", "\n".join(page.lines)))
    anchor = "sections" if "sections" not in taken else "page-sections"
    label = (
        "Sections" if page.uri.endswith("/index.md") and page.kicker == "" else "In this section"
    )
    out = [
        "",
        f"## {label} {{ #{anchor} }}",
        "",
        '<div class="grid cards link-cards" markdown>',
        "",
    ]
    base = posixpath.dirname(page.uri)
    for child in page.children:
        rel = posixpath.relpath(child.uri, base or ".")
        title = plain(child.title)
        if child.kicker and child.kicker.startswith("Section "):
            title = f"{child.kicker.removeprefix('Section ')}. {title}"
        out += [f"-   [**{title}**]({rel})", ""]
        if child.description:
            out += [f"    {child.description}", ""]
    return out + ["</div>", ""]


def _changelog_page(links: LinkMap) -> str:
    lines = changelog.page_lines(REPO / "CHANGELOG.md")
    lines = rewrite(
        normalise_markdown("\n".join(lines)).split("\n"),
        links.resolver("CHANGELOG.md", CHANGELOG_URI),
    )
    return "\n".join(_front("Notable changes in each cloudg release.") + lines).rstrip() + "\n"


def _config_pages() -> list[tuple[str, str]]:
    """(section name, uri) for every config.yaml section page, in file order."""
    out = []
    secs = config_ref.sections(REPO, SITE / "gen" / "config-notes.yaml")
    for s in secs:
        uri = f"{CONFIG_PREFIX}/{s.name}.md"
        md = config_ref.page_markdown(s, REPO, blob("config.yaml"), blob("cloudg/config.py"))
        desc = first_sentence(s.intro) if s.intro else f"The {s.name} keys of config.yaml."
        _add(uri, "\n".join(_front(desc)) + md, "config.yaml", 1)
        out.append((s.name, uri))
    return out


def _expand_nav(items, docs: dict[str, SplitDoc], config_pages):
    """Replace ``docs/X.md`` and ``config.yaml`` nav entries with their generated pages."""
    out = []
    for item in items:
        if isinstance(item, dict):
            ((title, value),) = item.items()
            if isinstance(value, list):
                out.append({title: _expand_nav(value, docs, config_pages)})
            elif value in docs:
                out.append({title: docs[value].nav()})
            elif value == "config.yaml":
                out.append({title: [{name: uri} for name, uri in config_pages]})
            else:
                out.append(item)
        else:
            out.append(item)
    return out


# ---------------------------------------------------------------------------
# files: add the generated pages and the static copies
# ---------------------------------------------------------------------------


# Runs before the plugins, so the redirects plugin sees the generated pages
@event_priority(50)
def on_files(files: Files, config, **kwargs):
    for uri, markdown in S.generated.items():
        existing = files.get_file_from_path(uri)
        if existing is not None:
            files.remove(existing)
        files.append(File.generated(config, uri, content=markdown))
    for dest, source in STATIC.items():
        path = REPO / source
        if not path.exists():
            log.warning("missing static file %s", source)
            continue
        files.append(_copy(config, dest, path))
    assets = REPO / "docs" / "assets"
    if assets.is_dir():
        for f in sorted(assets.iterdir()):
            if f.is_file():
                files.append(_copy(config, f"assets/{f.name}", f))
    return files


def _copy(config, dest: str, path: Path) -> File:
    f = File.generated(config, dest, abs_src_path=str(path))
    f.inclusion = InclusionLevel.NOT_IN_NAV
    return f


# ---------------------------------------------------------------------------
# nav and pages
# ---------------------------------------------------------------------------


def on_nav(nav, config, files, **kwargs):
    """Remember the CLI pages, in nav order, for the overview table."""
    S.cli_rows = []
    for item in nav.items:
        if getattr(item, "title", "") != "CLI":
            continue
        for group in item.children or []:
            for child in getattr(group, "children", None) or []:
                if getattr(child, "file", None) is not None:
                    S.cli_rows.append((group.title, child.title, child.file.src_uri))
    return nav


def on_page_markdown(markdown: str, page, config, files, **kwargs):
    if CLI_REFERENCE in markdown:
        markdown = markdown.replace(CLI_REFERENCE, _cli_reference(page))
    if CLI_INDEX in markdown:
        markdown = markdown.replace(CLI_INDEX, _cli_index(page))
    if STATS in markdown:
        markdown = markdown.replace(STATS, _stats(page, files))
    return markdown


def _stats(page, files) -> str:
    """The figures strip on the home page, counted from the code at build time."""
    import yaml

    controls = sum(
        len((yaml.safe_load(f.read_text()) or {}).get("controls") or [])
        for f in sorted((REPO / "cloudg" / "rules" / "frameworks").glob("*.yaml"))
    )
    from cloudg.mcp import default_registry
    from cloudg.schema.models import AssetType

    commands = [k for k, v in S.commands.items() if not v.group and k != "__root__"]

    def rel(uri: str) -> str:
        # raw HTML: MkDocs does not rewrite these links, so give the final URL
        return get_relative_url(files.get_file_from_path(uri).url, page.url)

    figures = [
        (f"{controls:,}", "compliance controls mapped", "guides/compliance.md"),
        (f"{len(AssetType):,}", "asset types catalogued", "reference/catalog/index.md"),
        (f"{len(default_registry().tools):,}", "MCP tools", "mcp/index.md"),
        (f"{len(commands):,}", "CLI commands", "cli/index.md"),
    ]
    cells = "".join(
        f'<a class="cg-stat" href="{rel(uri)}"><strong>{value}</strong><span>{label}</span></a>'
        for value, label, uri in figures
    )
    return f'<div class="cg-stats">{cells}</div>'


def _cli_reference(page) -> str:
    name = page.meta.get("command")
    cmd = S.commands.get(name or "")
    if cmd is None:
        raise SystemExit(f"{page.file.src_uri}: unknown command {name!r}")
    auth = None
    if name in _AUTH_COMMANDS and page.file.src_uri != "cli/auth-flags.md":
        auth = posixpath.relpath("cli/auth-flags.md", posixpath.dirname(page.file.src_uri))
    return cli.command_reference(cmd, blob(cmd.source_file, cmd.source_line, source_ref()), auth)


def _cli_index(page) -> str:
    rows = []
    base = posixpath.dirname(page.file.src_uri)
    for group, title, uri in S.cli_rows:
        if uri == page.file.src_uri:
            continue
        name = title.removeprefix("cloudg ") if title.startswith("cloudg ") else None
        cmd = S.commands.get(name) if name else None
        desc = cmd.short_help if cmd else ""
        rows.append((group, title, posixpath.relpath(uri, base or "."), desc))
    return cli.index_tables(rows, S.commands["__root__"])


def on_page_context(context, page, config, nav, **kwargs):
    """Generated pages are edited at their source, not in the docs directory."""
    src = S.sources.get(page.file.src_uri)
    if src is not None:
        page.edit_url = f"{GITHUB}/edit/main/{src[0]}"
    return context


# ---------------------------------------------------------------------------
# source links on API objects
# ---------------------------------------------------------------------------

_DOC_HEADING = re.compile(
    r'(<h(\d) id="(cloudg(?:\.[A-Za-z_]\w*)+)" class="doc doc-heading">)(.*?)(</h\2>)', re.S
)
_SOURCE_CACHE: dict[str, str] = {}


def _source_url(path: str) -> str:
    if path in _SOURCE_CACHE:
        return _SOURCE_CACHE[path]
    url = ""
    try:
        obj = pkgutil.resolve_name(path)
        if isinstance(obj, property):
            obj = obj.fget
        obj = inspect.unwrap(obj)
        if (
            inspect.isclass(obj)
            or inspect.isfunction(obj)
            or inspect.ismethod(obj)
            or inspect.ismodule(obj)
        ):
            file = Path(inspect.getsourcefile(obj) or "").resolve()
            line = 1 if inspect.ismodule(obj) else inspect.getsourcelines(obj)[1]
            url = blob(str(file.relative_to(REPO.resolve())), line, source_ref())
    except Exception:  # noqa: BLE001 - a missing link is not worth failing the build
        log.debug("no source link for %s", path, exc_info=True)
    _SOURCE_CACHE[path] = url
    return url


def on_page_content(html: str, page, config, files, **kwargs):
    if 'class="doc doc-heading"' not in html:
        return html

    def add_link(m: re.Match) -> str:
        url = _source_url(m.group(3))
        if not url:
            return m.group(0)
        link = (
            f'<a class="doc-source-link" href="{url}" title="View the source on GitHub"'
            ' rel="noopener">source</a>'
        )
        return m.group(1) + m.group(4) + link + m.group(5)

    return _DOC_HEADING.sub(add_link, html)
