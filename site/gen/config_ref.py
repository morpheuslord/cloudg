"""config.yaml reference, read from the annotated example file itself.

Each key's description is its trailing comment, or failing that the comment
lines directly above it. The YAML text of each top-level section is kept
line by line so the page can show it next to the key table.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

import inspect
from typing import Any

import yaml


def _ann(a: Any) -> str:
    """A readable type name for a pydantic field annotation."""
    if a is inspect.Parameter.empty:
        return ""
    if isinstance(a, str):
        return a.strip("'\"")
    if isinstance(a, type):
        return a.__name__
    s = repr(a)
    return re.sub(r"\b(?:[a-z_][\w]*\.)+([A-Z]\w*)", r"\1", s).replace("typing.", "")


_KEY_RE = re.compile(r"^(\s*)(-\s+)?([\w.\-]+):(?:\s+(.*?))?\s*$")
_ITEM_RE = re.compile(r"^(\s*)-\s+(.*?)\s*$")
_RULE_RE = re.compile(r"^#\s*[─━═\-]{3,}")
_HEADER_RE = re.compile(r"^#\s*[─━═]{1,}\s*(.+?)\s*[─━═]*\s*$")


@dataclass
class Key:
    path: str  # relative to the section, e.g. "aws.retry_budget"; "" for the section root
    type: str
    default: str
    description: str
    line: int  # index into Section.lines


@dataclass
class Section:
    name: str
    title: str
    intro: str
    lines: list[str] = field(default_factory=list)
    keys: list[Key] = field(default_factory=list)


def _split_comment(value: str) -> tuple[str, str]:
    """Split ``value  # comment`` respecting quotes."""
    quote = None
    for i, ch in enumerate(value):
        if ch in "'\"":
            quote = None if quote == ch else (ch if quote is None else quote)
        elif ch == "#" and quote is None and (i == 0 or value[i - 1] in " \t"):
            return value[:i].strip(), value[i + 1 :].strip()
    return value.strip(), ""


def _is_code_comment(text: str) -> bool:
    """Commented-out YAML and linter pragmas are not descriptions."""
    return bool(
        text.startswith(("- ", "nosemgrep", "Uncomment", "#"))
        or re.match(r"^[\w.\-]+:\s", text + " ")
        and not re.match(r"^(e\.g\.|Note|Default|Options|Example)", text)
    )


def _clean(comment: str) -> str:
    comment = re.sub(r"\s*nosemgrep:.*$", "", comment)
    return comment.strip()


def _type_of(value: str) -> str:
    v = value.strip()
    if v in ("null", "~", ""):
        return "null"
    if v in ("true", "false"):
        return "bool"
    if re.fullmatch(r"-?\d+", v):
        return "int"
    if re.fullmatch(r"-?\d+\.\d*", v):
        return "float"
    if v.startswith("["):
        return "list"
    if v.startswith("{"):
        return "map"
    return "str"


class _Parser:
    """Reads config.yaml one line at a time into sections and keys."""

    def __init__(self) -> None:
        self.sections: list[Section] = []
        self.general = Section(
            "general",
            "General",
            "Settings at the top level of the file that apply to the whole run.",
        )
        self.pending: list[str] = []  # comment lines waiting for the key below them
        self.header = ""
        self.current: Section | None = None
        self.stack: list[tuple[int, str]] = []  # (indent, key) of the open parents
        self.last_key: Key | None = None
        self.list_items: list[str] = []

    def feed(self, line: str) -> None:
        stripped = line.strip()
        indent = len(line) - len(line.lstrip(" "))
        if not stripped:
            self._blank(line)
            return
        if stripped.startswith("#"):
            self._comment(line, stripped, indent)
            return
        km = _KEY_RE.match(line)
        if km and not km.group(2):
            self._key(line, km, indent)
            return
        im = _ITEM_RE.match(line)
        if im and self.current is not None:
            self._item(line, im)
        elif self.current is not None:
            self.current.lines.append(line)

    def finish(self) -> list[Section]:
        self._flush_list()
        for s in self.sections:
            while s.lines and not s.lines[-1].strip():
                s.lines.pop()
        if self.general.keys:
            self.sections.append(self.general)
        return self.sections

    def _flush_list(self) -> None:
        """Turn the ``- item`` lines collected under the last key into its default."""
        key = self.last_key
        if key is not None and self.list_items and key.type in ("map", "null"):
            key.type = "list"
            key.default = "[" + ", ".join(self.list_items) + "]"
        self.list_items = []

    def _blank(self, line: str) -> None:
        self.pending = []
        if self.current is not None and self.current is not self.general:
            self.current.lines.append(line)

    def _comment(self, line: str, stripped: str, indent: int) -> None:
        rule = _RULE_RE.match(stripped)
        hm = _HEADER_RE.match(stripped)
        if indent == 0 and (hm or rule):
            if hm and not rule:
                self.header = hm.group(1).strip("─━═ ")
            self.pending = []
            return
        text = stripped.lstrip("#").strip()
        if not _is_code_comment(text):
            self.pending.append(text)
        if self.current is not None and indent > 0:
            self.current.lines.append(line)

    def _key(self, line: str, km: re.Match, indent: int) -> None:
        value, comment = _split_comment(km.group(4) or "")
        comment = _clean(comment)
        if _is_code_comment(comment):
            comment = ""
        if indent == 0:
            self._top_key(line, km.group(3), value, comment)
        elif self.current is None:
            return
        else:
            self._nested_key(line, km.group(3), value, comment, indent)
        self.pending = []

    def _top_key(self, line: str, key: str, value: str, comment: str) -> None:
        self._flush_list()
        if value:  # top-level scalar
            general = self.general
            general.lines.append(line)
            description = comment or " ".join(self.pending)
            general.keys.append(
                Key(key, _type_of(value), value, description, len(general.lines) - 1)
            )
            self.current, self.stack, self.last_key = general, [], general.keys[-1]
            return
        self.current = Section(key, self.header or key, " ".join(self.pending))
        self.current.lines.append(line)
        self.sections.append(self.current)
        self.stack, self.header, self.last_key = [(0, key)], "", None

    def _nested_key(self, line: str, key: str, value: str, comment: str, indent: int) -> None:
        self._flush_list()
        while self.stack and self.stack[-1][0] >= indent:
            self.stack.pop()
        parents = self.stack if self.current is self.general else self.stack[1:]
        rel = ".".join([k for _, k in parents] + [key])
        section = self.current
        section.lines.append(line)
        typ = _type_of(value) if value else "map"
        description = comment or " ".join(self.pending)
        self.last_key = Key(rel, typ, value, description, len(section.lines) - 1)
        section.keys.append(self.last_key)
        self.stack.append((indent, key))

    def _item(self, line: str, im: re.Match) -> None:
        item, comment = _split_comment(im.group(2))
        self.current.lines.append(line)
        if self.last_key is not None and ":" not in item:
            self.list_items.append(item)
            if comment and not self.last_key.description:
                self.last_key.description = comment
        self.pending = []


def parse(path: Path) -> list[Section]:
    parser = _Parser()
    for line in path.read_text().split("\n"):
        parser.feed(line)
    return parser.finish()


# ---------------------------------------------------------------------------
# descriptions from the pydantic models
# ---------------------------------------------------------------------------


def _model_of(annotation):
    """The pydantic model an annotation refers to (directly or inside Optional/Union)."""
    if hasattr(annotation, "model_fields"):
        return annotation
    for arg in getattr(annotation, "__args__", ()) or ():
        if hasattr(arg, "model_fields"):
            return arg
    return None


def _field_info(model, path: str):
    """The FieldInfo for a dotted key path below ``model``, or None."""
    cur, finfo = model, None
    for part in path.split("."):
        if cur is None or part not in cur.model_fields:
            return None
        finfo = cur.model_fields[part]
        cur = _model_of(finfo.annotation)
    return finfo


def _apply_descriptions(section: Section, model) -> None:
    for k in section.keys:
        finfo = _field_info(model, k.path)
        if finfo is None or not finfo.description:
            continue
        desc = finfo.description.strip()
        if not k.description or len(desc) > len(k.description):
            k.description = desc


def _add_missing_keys(section: Section, model) -> None:
    """Add scalar model fields the example file leaves out."""
    known = {k.path for k in section.keys}
    for fname, finfo in model.model_fields.items():
        if fname in known or _model_of(finfo.annotation) is not None:
            continue
        if any(p.startswith(fname + ".") for p in known):
            continue
        default = "" if finfo.default_factory else repr(finfo.default)
        if default == "None":
            default = "null"
        description = (finfo.description or "") + " Not in the example file."
        section.keys.append(Key(fname, _ann(finfo.annotation), default, description, -1))


def merge_model_descriptions(sections: list[Section]) -> None:
    """Prefer pydantic Field descriptions from CloudGConfig; add keys the example file omits."""
    try:
        from cloudg.config import CloudGConfig
    except Exception:  # noqa: BLE001
        return
    for s in sections:
        if s.name == "general":
            # top-level keys: descriptions only, nothing added
            _apply_descriptions(s, CloudGConfig)
            continue
        top = CloudGConfig.model_fields.get(s.name)
        model = _model_of(top.annotation) if top else None
        if model is not None:
            _apply_descriptions(s, model)
            _add_missing_keys(s, model)


# ---------------------------------------------------------------------------
# markdown pages
# ---------------------------------------------------------------------------


def _cell(text: str) -> str:
    return text.replace("|", "\\|").replace("\n", " ").strip()


def _code(text: str) -> str:
    if not text:
        return ""
    if "|" in text:
        safe = text.replace("&", "&amp;").replace("<", "&lt;").replace("|", "&#124;")
        return f"<code>{safe}</code>"
    return f"`` {text} ``" if "`" in text else f"`{text}`"


def _line_of(path: Path, needle: str) -> int:
    for i, line in enumerate(path.read_text().split("\n"), start=1):
        if line.startswith(needle):
            return i
    return 0


def sections(repo: Path, notes_file: Path) -> list[Section]:
    """The config.yaml sections, with descriptions from the models and the notes file."""
    secs = parse(repo / "config.yaml")
    merge_model_descriptions(secs)
    notes = yaml.safe_load(notes_file.read_text()) or {}
    for s in secs:
        for k in s.keys:
            note = notes.get(f"{s.name}.{k.path}")
            if note:
                k.description = note
        if notes.get(s.name):
            s.intro = notes[s.name]
    return secs


def page_markdown(s: Section, repo: Path, config_url: str, model_url: str) -> str:
    """One reference page for a top-level section of config.yaml."""
    out = [f"# `{s.name}`", ""]
    intro = s.intro or ""
    rest = ""
    if len(intro) > 240:
        first, sep, rest = intro.partition(". ")
        intro = first + ("." if sep else "")
    if intro:
        out += [intro, "{ .lede }", ""]
    if rest:
        out += [rest, ""]
    out += ["## Keys", "", "| Key | Type | Default | Description |", "|---|---|---|---|"]
    for k in s.keys:
        key = f"[`{k.path}`](#{k.path}){{ #{k.path} .config-key }}"
        out.append(f"| {key} | {_code(k.type)} | {_code(k.default)} | {_cell(k.description)} |")
    line = _line_of(repo / "config.yaml", f"{s.name}:") if s.name != "general" else 0
    out += ["", "## In config.yaml", ""]
    if s.lines:
        title = "config.yaml" if s.name == "general" else f"config.yaml ({s.name})"
        out += [f'```yaml title="{title}"'] + s.lines + ["```", ""]
    link = config_url + (f"#L{line}" if line else "")
    out += [
        f"Read from the annotated example [`config.yaml`]({link}) and the `CloudGConfig`"
        f" models in [`cloudg/config.py`]({model_url}).",
        "{ .table-note }",
        "",
    ]
    return "\n".join(out)
