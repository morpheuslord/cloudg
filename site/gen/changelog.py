"""CHANGELOG.md as a site page: one section per release, labelled blocks as headings."""

from __future__ import annotations

import re
from pathlib import Path

from gen.common import FenceTracker, github_slug, plain

_RELEASE_RE = re.compile(r"^##\s+(.+?)\s*$")
_VERSION_RE = re.compile(r"^(\d+\.\d+\.\d+)\s*(?:\((\d{4}-\d{2}-\d{2})\))?")
_LABEL_RE = re.compile(r"^([A-Z][A-Za-z ]{2,30}):\s*$")


def release_anchor(title: str) -> str:
    """``0.6.1`` for a version heading, a hyphenated slug otherwise (the old site's anchors)."""
    m = _VERSION_RE.match(title)
    if m:
        return m.group(1)
    return re.sub(r"[^a-z0-9]+", "-", title.lower()).strip("-")


def anchors(path: Path) -> dict[str, str]:
    """GitHub anchor of each release heading -> the anchor it has on the site."""
    out = {}
    for line in path.read_text().split("\n"):
        m = _RELEASE_RE.match(line)
        if m:
            out[github_slug(plain(m.group(1)))] = release_anchor(m.group(1))
            out[release_anchor(m.group(1))] = release_anchor(m.group(1))
    return out


def latest(path: Path) -> str:
    """The newest released version in CHANGELOG.md."""
    for line in path.read_text().split("\n"):
        m = _RELEASE_RE.match(line)
        if m and _VERSION_RE.match(m.group(1)):
            return _VERSION_RE.match(m.group(1)).group(1)
    return "0.0.0"


def page_lines(path: Path) -> list[str]:
    """CHANGELOG.md with release headings shortened to the version and labels as H3."""
    out: list[str] = []
    fences = FenceTracker()
    release = ""
    for line in path.read_text().split("\n"):
        if fences.feed(line):
            out.append(line)
            continue
        m = _RELEASE_RE.match(line)
        if m:
            title = m.group(1)
            release = release_anchor(title)
            vm = _VERSION_RE.match(title)
            if vm:
                out.append(f"## {vm.group(1)} {{ #{release} }}")
                if vm.group(2):
                    out += ["", f"Released {vm.group(2)}", "{ .release-date }"]
            else:
                out.append(f"## {title} {{ #{release} }}")
            continue
        lm = _LABEL_RE.match(line)
        if lm and release:
            label = lm.group(1)
            out.append(f"### {label} {{ #{release}-{github_slug(label)} }}")
            continue
        out.append(line)
    return out
