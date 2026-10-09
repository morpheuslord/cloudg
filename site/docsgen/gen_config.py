"""config.yaml reference, read from the annotated example file itself.

Each key's description is its trailing comment, or failing that the comment
lines directly above it. The YAML text of each top-level section is kept
line by line so the page can show it next to the key table.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

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


def parse(path: Path) -> list[Section]:
    raw = path.read_text().split("\n")
    sections: list[Section] = []
    general = Section("general", "General", "Settings at the top level of the file that apply to the whole run.")
    pending_comments: list[str] = []
    header = ""
    current: Section | None = None
    stack: list[tuple[int, str]] = []
    last_key: Key | None = None
    list_items: list[str] = []

    def flush_list() -> None:
        nonlocal list_items, last_key
        if last_key is not None and list_items and last_key.type in ("map", "null"):
            last_key.type = "list"
            last_key.default = "[" + ", ".join(list_items) + "]"
        list_items = []

    for line in raw:
        stripped = line.strip()
        indent = len(line) - len(line.lstrip(" "))
        if not stripped:
            pending_comments = []
            if current is not None and current is not general:
                current.lines.append(line)
            continue
        if stripped.startswith("#"):
            hm = _HEADER_RE.match(stripped)
            if indent == 0 and (hm or _RULE_RE.match(stripped)):
                if hm and not _RULE_RE.match(stripped):
                    header = hm.group(1).strip("─━═ ")
                pending_comments = []
                continue
            text = stripped.lstrip("#").strip()
            if not _is_code_comment(text):
                pending_comments.append(text)
            if current is not None and indent > 0:
                current.lines.append(line)
            continue

        km = _KEY_RE.match(line)
        if km and not km.group(2):
            key, rest = km.group(3), km.group(4) or ""
            value, comment = _split_comment(rest)
            comment = _clean(comment)
            if _is_code_comment(comment):
                comment = ""
            if indent == 0:
                flush_list()
                if value:  # top-level scalar
                    general.lines.append(line)
                    general.keys.append(Key(key, _type_of(value), value, comment or " ".join(pending_comments),
                                            len(general.lines) - 1))
                    current = general
                    stack = []
                    last_key = general.keys[-1]
                else:
                    current = Section(key, header or key, " ".join(pending_comments))
                    current.lines.append(line)
                    sections.append(current)
                    stack = [(0, key)]
                    header = ""
                    last_key = None
                pending_comments = []
                continue
            if current is None:
                continue
            flush_list()
            while stack and stack[-1][0] >= indent:
                stack.pop()
            parents = [k for _, k in stack[1:]] if current is not general else [k for _, k in stack]
            rel = ".".join(parents + [key])
            current.lines.append(line)
            typ = _type_of(value) if value else "map"
            k = Key(rel, typ, value if value else "", comment or " ".join(pending_comments), len(current.lines) - 1)
            current.keys.append(k)
            last_key = k
            stack.append((indent, key))
            pending_comments = []
            continue

        im = _ITEM_RE.match(line)
        if im and current is not None:
            item, comment = _split_comment(im.group(2))
            current.lines.append(line)
            if last_key is not None and ":" not in item:
                list_items.append(item)
                if comment and not last_key.description:
                    last_key.description = comment
            pending_comments = []
            continue
        if current is not None:
            current.lines.append(line)
    flush_list()

    for s in sections:
        while s.lines and not s.lines[-1].strip():
            s.lines.pop()
        # maps with only children: describe as such
        for k in s.keys:
            if k.type == "map" and not k.default:
                k.default = ""
    if general.keys:
        sections.append(general)
    return sections
