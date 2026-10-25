# Writing pages for the cloudg docs site

The site at https://morpheuslord.github.io/cloudg/ is built with [MkDocs](https://www.mkdocs.org/) and the [Material theme](https://squidfunk.github.io/mkdocs-material/). It has three kinds of page:

- hand-written pages in `site/content/` (guides, examples, CLI prose, API prose);
- reference pages generated at build time from the code and the repository files: the CLI options tables (click commands), the API signatures and parameter tables (docstrings, through mkdocstrings), the `config.yaml` reference, the changelog, and the long `docs/*.md` references split into one page per section;
- static files copied as they are: the sample report, `docs/viewer.html` and `docs/assets/`.

Generated pages are never committed. `site/hooks.py` creates them on every build.

## Build and preview

The docs tools are a dependency group in `pyproject.toml`. Install them next to cloudg in a virtual environment:

```bash
python -m venv .venv
.venv/bin/pip install --upgrade "pip>=25.1"
.venv/bin/pip install -e . --group docs

.venv/bin/mkdocs serve -a 127.0.0.1:8807    # live preview on http://127.0.0.1:8807/cloudg/
.venv/bin/mkdocs build --strict             # what CI runs; writes site/dist
```

With uv: `uv pip install -e . --group docs`. `mkdocs build --strict` must finish with no warnings: a broken link, a missing anchor or a page left out of the nav fails the build in CI. Set `NO_MKDOCS_2_WARNING=1` and `DISABLE_MKDOCS_2_WARNING=true` to hide the banners some plugins print about the future of MkDocs.

## Layout

| Path | What it holds |
|---|---|
| `mkdocs.yml` | Site settings, theme, plugins, markdown extensions and the nav |
| `site/content/` | The docs directory: every hand-written page, plus `assets/` (logo, favicon, `extra.css`) |
| `site/overrides/main.html` | Theme override: the release banner at the top of every page |
| `site/hooks.py` | MkDocs hooks that generate the reference pages and copy the static files |
| `site/gen/` | The generators the hooks call: `cli.py`, `config_ref.py`, `changelog.py`, `split.py`, `links.py`, and `griffe_rst.py` for docstrings |
| `site/gen/config-notes.yaml` | Descriptions for `config.yaml` keys that have neither a comment in the file nor a `Field(description=...)` |
| `site/examples/` | Example scripts that pages include with snippets |
| `site/static/sample-report.html` | The sample report, built by `scripts/build_sample_report.py` |

## Style rules

- No em dashes anywhere, and no `--` or spaced en dash standing in for one. Use a comma, a colon, parentheses or two sentences.
- Straight quotes only. No emoji.
- Sentence-case headings.
- Run every page you write through the `/human` skill's scanner before committing it.
- Every code example must work as written against the current release. Check signatures in the source and run the Python ones when you can (the sample scanner output inlined in `tests/test_ingest.py` is handy for ingest examples). Prefer putting a longer example in `site/examples/` and including it, so the script on the page is a file you can run.

## Adding a page

1. Create the Markdown file under `site/content/`.
2. Add it to `nav:` in `mkdocs.yml`. A page that is not in the nav fails the strict build.
3. Link to other pages with relative paths to their Markdown files, for example `[cloudg map](../cli/map.md#usage)`. MkDocs checks every link and anchor and turns them into the right URLs. Never write site-absolute links (`/cloudg/...`).

A page starts with optional front matter, then the body:

```markdown
---
title: Inventory mapping          # optional: the nav title is used otherwise
description: One sentence for search engines and link previews.
---

`cloudg map` asks a different question from `cloudg run`: what exists, and how is it wired together?
{ .lede }

**Command** `cloudg map` &middot; **Providers** AWS, Azure, GCP
{ .page-meta }

## First section
```

The `{ .lede }` paragraph is the larger introduction under the title. The `{ .page-meta }` line is the strip of facts under it; end it with `**Last changed** [v0.6.1](../changelog.md#0.6.1)` when a page documents behaviour that changed in a release. The body never starts with an `#` heading: the title comes from the nav or the front matter.

## Markdown

The extensions are listed in `mkdocs.yml`. The ones pages use most:

### Headings and anchors

`##` and `###` feed the table of contents. Anchors are generated from the text the way GitHub does it; set one yourself with a trailing `{ #my-anchor }`. Never skip a level.

### Code blocks

````markdown
```python title="map_and_overlay.py" hl_lines="4-6"
from cloudg import CloudGConfig, CloudGEngine
...
```
````

- `title` shows as the file name above the block. Use a real file name for code people should save.
- `hl_lines` highlights lines: `hl_lines="3"`, `hl_lines="2 5-7"`.
- `bash` blocks hold commands only; `console` is for a captured session, with the `$` prompt written out and the output below it.
- Every block has a copy button. Annotations work too: put `# (1)!` at the end of a line and a numbered list after the block.

### Code from a file

`pymdownx.snippets` includes a file, so the code on the page is the script that was run. Paths are relative to `site/examples/` (then the repository root):

````markdown
```python title="strict_scanner.py"
--8<-- "errors/strict_scanner.py"
```
````

A missing file fails the build.

### Tabs

Tabs with the same label are linked across the whole site, so a reader who picks "Python" once sees Python everywhere.

````markdown
=== "CLI"

    ```bash
    cloudg map -p aws --regions all
    ```

=== "Python"

    ```python title="map.py"
    from cloudg import CloudGConfig, CloudGEngine
    ...
    ```
````

Use the labels `CLI`, `Python`, `Docker` for ways to do one thing, and `pip`, `uv`, `Docker` for installs. The content of a tab is indented by four spaces.

### Diagrams

A `mermaid` block renders as a diagram that follows the light and dark palette. A caption goes in a paragraph right after it:

````markdown
```mermaid
flowchart LR
  A[Collect] --> B[Graph] --> C[Scan] --> D[Normalise] --> E[Report]
```
What cloudg run does, phase by phase.
{ .diagram-caption }
````

Keep diagrams small enough to read on a laptop: up to about 12 nodes. Prefer `flowchart LR` or `TD`, `sequenceDiagram` for request flows and `stateDiagram-v2` for state machines. Don't set colours or `classDef` styles. Quote labels that contain punctuation: `A["cloudg map --org"]`.

### Admonitions

```markdown
!!! note
    The map doesn't depend on the scanners.

!!! warning "AWSControlTowerExecution has admin rights"
    Without `--org-role`, cloudg assumes that role in every member account.

??? tip "Collapsed until clicked"
    Use `???` for detail most readers can skip.
```

Kinds: `note`, `tip`, `warning`, `danger`, `example`, `info`.

### Steps, cells and link cards

Numbered steps are `###` headings inside a `steps` block; the numbers come from the stylesheet:

```markdown
<div class="steps" markdown>

### Install

...

### Authenticate

...

</div>
```

Two to four short items side by side are cards in a grid:

```markdown
<div class="grid cells" markdown>
<div class="card" markdown>

### Deep collectors

131 dedicated AWS collector tasks...

</div>
</div>
```

A list of links with a line of text each becomes a grid of cards:

```markdown
<div class="grid cards link-cards" markdown>

-   [**Inventory mapping**](../guides/inventory-mapping.md)

    What exists and how it is wired.

</div>
```

## Page kinds

### Guides and examples

Plain pages in `site/content/guides/` and `site/content/examples/`.

### CLI commands: `site/content/cli/<slug>.md`

The front matter names the command, and a marker says where the generated "Usage" and "Options" sections go:

```markdown
---
command: map            # or "mcp serve"
description: Builds the scanner-independent inventory map.
---

One paragraph on what the command is for.

<!-- cloudg:cli-reference -->

## How it works
...
```

The tables come from the click definitions in `cloudg/cli*.py`, so they match `--help`. `cli/index.md` uses `<!-- cloudg:cli-index -->` for the table of every command, in nav order. Typical sections after the options: `## Examples`, `## Output files`, `## Exit codes`, `## Notes`.

### Python API: `site/content/api/<slug>.md`

Prose and examples come first, then a `## Reference` section where mkdocstrings renders the objects from their docstrings:

```markdown
## Reference

::: cloudg.api.CloudGEngine
    options:
      members:
        - run_pipeline
        - map_inventory_sync
```

`members` picks and orders the members; `members: false` shows the object without them. The signatures, parameter, return and raises tables, and the "source" link to GitHub come from the code. Docstrings follow the Google style; `site/gen/griffe_rst.py` turns the reST roles (`:class:`, double backticks, `::` blocks) they still use into Markdown while the site is built, without changing the source.

### Generated reference pages

Three kinds of nav entry are replaced by generated pages in `site/hooks.py`:

- `docs/X.md`: the document is split into one page per `##` section under the prefix in `SPLITS`. A section over 40 KB with at least three `###` headings becomes a folder with one page per `###`. Every heading keeps the anchor GitHub gives it, so links into the single-file document keep working, and links between the documents are pointed at the page that now holds their target.
- `config.yaml`: one page per top-level section, from the comments in `config.yaml`, the `Field(description=...)` of the `CloudGConfig` models and `site/gen/config-notes.yaml`.
- `changelog.md`: `CHANGELOG.md`, with each release's anchor set to its version (`changelog/#0.6.1`).

To change what those pages say, edit their source (the `docs/*.md` file, `config.yaml`, the models or `CHANGELOG.md`). The "Edit" button on a generated page opens its source on GitHub.

### Sample report

`sample-report.md` embeds `site/static/sample-report.html`, which the hooks publish at `/cloudg/sample-report.html` (and at the old address, `/cloudg/static/sample-report.html`). Rebuild the file with `python scripts/build_sample_report.py`; the page needs no change.

## URLs

Every page keeps the address it had on the earlier site generator: `guides/quickstart.md` is served at `/cloudg/guides/quickstart/`, `cli/index.md` at `/cloudg/cli/`. Folder addresses without a page of their own (`/cloudg/guides/`, `/cloudg/reference/`) redirect through the `redirects` plugin; add an entry under `redirect_maps` in `mkdocs.yml` when a page moves.
