"""Griffe extension: the reST bits cloudg's Google-style docstrings use, as markdown.

The docstrings are read on GitHub and in ``help()`` as well as on the site,
so they keep their reST roles (``:class:`Finding```), double-backtick
literals and ``::`` literal blocks. mkdocstrings renders docstrings as
markdown, so this extension rewrites those three forms before rendering:
roles and double backticks become code spans, and a ``::`` block becomes a
fenced code block. The source is not changed.
"""

from __future__ import annotations

import re
from typing import Any

import griffe

_ROLE = re.compile(r":[\w]+(?::[\w]+)?:`~?\.?([^`]+)`")
_DOUBLE = re.compile(r"(?<!`)``([^`\n]+)``(?!`)")
_SECTION_NAMES = {"example", "examples", "note", "notes", "usage", "warning", "warnings", "tip"}


def _literal_blocks(text: str) -> str:
    """Turn ``Some text::`` plus an indented block into a fenced code block."""
    lines = text.split("\n")
    out: list[str] = []
    i = 0
    while i < len(lines):
        line = lines[i]
        if line.rstrip().endswith("::") and not line.strip().startswith(".."):
            head = line.rstrip()[:-1]  # "Some text::" -> "Some text:"
            if head.strip() == ":":
                head = ""
            elif head.strip().rstrip(":").lower() in _SECTION_NAMES:
                # "Example::" would read as a Google-style section header
                head = head.replace(head.strip(), f"**{head.strip().rstrip(':')}**")
            j = i + 1
            while j < len(lines) and not lines[j].strip():
                j += 1
            base = len(line) - len(line.lstrip())
            block = []
            while j < len(lines) and (
                not lines[j].strip() or len(lines[j]) - len(lines[j].lstrip()) > base
            ):
                block.append(lines[j])
                j += 1
            while block and not block[-1].strip():
                block.pop()
            if block:
                ind = min(len(b) - len(b.lstrip()) for b in block if b.strip())
                lang = (
                    "python"
                    if any(b.strip().startswith(("from ", "import ", ">>>")) for b in block)
                    else "text"
                )
                if head.strip():
                    out += [head, ""]
                out += (
                    [" " * base + f"```{lang}"]
                    + [" " * base + b[ind:] for b in block]
                    + [" " * base + "```", ""]
                )
                i = j
                continue
        out.append(line)
        i += 1
    return "\n".join(out)


_EXAMPLE_HEAD = re.compile(r"^(\s*)(Example|Examples|Usage):\s*$")


def _example_sections(text: str) -> str:
    """Fence the code of a Google-style ``Example:`` section that is not a doctest.

    ``>>>`` sessions are left to griffe, which renders them as code already.
    """
    lines = text.split("\n")
    out: list[str] = []
    i = 0
    while i < len(lines):
        m = _EXAMPLE_HEAD.match(lines[i])
        if not m:
            out.append(lines[i])
            i += 1
            continue
        base = len(m.group(1))
        j = i + 1
        block = []
        while j < len(lines) and (
            not lines[j].strip() or len(lines[j]) - len(lines[j].lstrip()) > base
        ):
            block.append(lines[j])
            j += 1
        code = [b for b in block if b.strip()]
        if not code or any(b.lstrip().startswith((">>>", "```")) for b in code):
            out.append(lines[i])
            i += 1
            continue
        ind = min(len(b) - len(b.lstrip()) for b in code)
        while block and not block[-1].strip():
            block.pop()
        while block and not block[0].strip():
            block.pop(0)
        lang = "bash" if code[0].lstrip().startswith(("cloudg ", "$ ")) else "python"
        pad = " " * ind
        out += [lines[i], f"{pad}```{lang}"] + block + [f"{pad}```", ""]
        i = j
    return "\n".join(out)


def to_markdown(text: str) -> str:
    text = _example_sections(text)
    text = _literal_blocks(text)
    text = _ROLE.sub(r"`\1`", text)
    return _DOUBLE.sub(r"`\1`", text)


class RstToMarkdown(griffe.Extension):
    """Rewrite each docstring once it is loaded."""

    def on_object(self, *, obj: griffe.Object, **kwargs: Any) -> None:  # noqa: ARG002
        if obj.docstring is not None:
            obj.docstring.value = to_markdown(obj.docstring.value)
