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


def parse(path: Path) -> tuple[str, list[Release]]:
    text = path.read_text()
    parts = re.split(r"(?m)^(?=## )", text)
    head = parts[0]
    head = re.sub(r"(?m)^#\s+.*$", "", head).strip()
    releases: list[Release] = []
    for part in parts[1:]:
        lines = part.rstrip().split("\n")
        title = _RELEASE_RE.match(lines[0]).group(1)
        m = _VERSION_RE.match(title)
        version = m.group(1) if m else title
        date = (m.group(2) or "") if m else ""
        anchor = version if m else re.sub(r"[^a-z0-9]+", "-", title.lower()).strip("-")
        intro: list[str] = []
        blocks: list[tuple[str, list[str]]] = []
        fence = False
        for line in lines[1:]:
            if line.lstrip().startswith("```"):
                fence = not fence
            lm = _LABEL_RE.match(line) if not fence else None
            if lm:
                blocks.append((lm.group(1), []))
                continue
            (blocks[-1][1] if blocks else intro).append(line)
        releases.append(
            Release(title, version, date, anchor, "\n".join(intro).strip(), [(k, "\n".join(v).strip()) for k, v in blocks])
        )
    return head, releases
