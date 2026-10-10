"""CHANGELOG.md split into releases and labelled blocks (Added, Changed, Fixed...)."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

_RELEASE_RE = re.compile(r"^##\s+(.+?)\s*$")
_VERSION_RE = re.compile(r"^(\d+\.\d+\.\d+)\s*(?:\((\d{4}-\d{2}-\d{2})\))?")
_LABEL_RE = re.compile(r"^([A-Z][A-Za-z ]{2,30}):\s*$")


@dataclass
class Release:
    title: str
    version: str
    date: str
    anchor: str
    intro: str
    blocks: list[tuple[str, str]] = field(default_factory=list)


def _split_blocks(lines: list[str]) -> tuple[str, list[tuple[str, str]]]:
    """Split a release body at ``Label:`` lines that sit outside code fences."""
    intro: list[str] = []
    blocks: list[tuple[str, list[str]]] = []
    fence = False
    for line in lines:
        if line.lstrip().startswith("```"):
            fence = not fence
        lm = _LABEL_RE.match(line) if not fence else None
        if lm:
            blocks.append((lm.group(1), []))
            continue
        (blocks[-1][1] if blocks else intro).append(line)
    return "\n".join(intro).strip(), [(k, "\n".join(v).strip()) for k, v in blocks]


def _release(part: str) -> Release:
    lines = part.rstrip().split("\n")
    title = _RELEASE_RE.match(lines[0]).group(1)
    intro, blocks = _split_blocks(lines[1:])
    m = _VERSION_RE.match(title)
    if m:
        return Release(title, m.group(1), m.group(2) or "", m.group(1), intro, blocks)
    anchor = re.sub(r"[^a-z0-9]+", "-", title.lower()).strip("-")
    return Release(title, title, "", anchor, intro, blocks)


def parse(path: Path) -> tuple[str, list[Release]]:
    parts = re.split(r"(?m)^(?=## )", path.read_text())
    head = re.sub(r"(?m)^#\s+.*$", "", parts[0]).strip()
    return head, [_release(part) for part in parts[1:]]
