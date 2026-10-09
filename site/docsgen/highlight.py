"""Code blocks rendered as editor or terminal windows.

Pygments does the tokenising; the HTML is built here, one ``<span class="line">``
per source line, so line numbers, highlighted lines and terminal prompts can be
drawn with CSS and stay out of the copied text.
"""

from __future__ import annotations

import re
from html import escape

from pygments.lexers import get_lexer_by_name
from pygments.token import STANDARD_TYPES, Token
from pygments.util import ClassNotFound

from docsgen.icons import icon

TERMINAL_LANGS = {"bash", "sh", "shell", "zsh", "shell-session-commands"}
SESSION_LANGS = {"console", "shell-session"}
LANG_LABELS = {
    "python": "Python",
    "py": "Python",
    "yaml": "YAML",
    "yml": "YAML",
    "json": "JSON",
    "jsonc": "JSON",
    "toml": "TOML",
    "ini": "INI",
    "dockerfile": "Dockerfile",
    "docker": "Dockerfile",
    "text": "Text",
    "txt": "Text",
    "sparql": "SPARQL",
    "turtle": "Turtle",
    "ttl": "Turtle",
    "xml": "XML",
    "html": "HTML",
    "javascript": "JavaScript",
    "js": "JavaScript",
    "typescript": "TypeScript",
    "hcl": "HCL",
    "terraform": "HCL",
    "sql": "SQL",
    "powershell": "PowerShell",
    "ps1": "PowerShell",
    "diff": "Diff",
    "jsonl": "JSON Lines",
    "csv": "CSV",
}
_ATTR_RE = re.compile(r'(\w+)=("([^"]*)"|\'([^\']*)\'|(\S+))')


def parse_info(info: str) -> tuple[str, dict[str, str]]:
    """Split a fence info string into language and attributes.

    ``python title="a.py" hl="2-4"`` gives ``("python", {"title": "a.py", "hl": "2-4"})``.
    A bare ``{2-4}`` is accepted as ``hl`` too.
    """
    info = info.strip()
    if not info:
        return "", {}
    lang, _, rest = info.partition(" ")
    attrs: dict[str, str] = {}
    for m in _ATTR_RE.finditer(rest):
        attrs[m.group(1)] = next(g for g in (m.group(3), m.group(4), m.group(5)) if g is not None)
    brace = re.search(r"\{([\d,\-\s]+)\}", rest)
    if brace and "hl" not in attrs:
        attrs["hl"] = brace.group(1)
    return lang.lower(), attrs


def parse_ranges(spec: str) -> set[int]:
    out: set[int] = set()
    for part in spec.replace(" ", "").split(","):
        if not part:
            continue
        if "-" in part:
            a, b = part.split("-", 1)
            out.update(range(int(a), int(b) + 1))
        else:
            out.add(int(part))
    return out


def _css_class(ttype) -> str:
    while ttype not in STANDARD_TYPES and ttype is not Token:
        ttype = ttype.parent
    return STANDARD_TYPES.get(ttype, "")


def _lexer(lang: str):
    alias = {"jsonl": "json", "yml": "yaml", "docker": "dockerfile", "ttl": "turtle", "terraform": "hcl"}
    try:
        return get_lexer_by_name(alias.get(lang, lang) or "text", stripnl=False, ensurenl=False)
    except ClassNotFound:
        return get_lexer_by_name("text", stripnl=False, ensurenl=False)


def tokenize_lines(code: str, lang: str) -> list[str]:
    """Return one HTML string per source line."""
    lines: list[str] = [""]
    for ttype, value in _lexer(lang).get_tokens(code):
        cls = _css_class(ttype)
        parts = value.split("\n")
        for i, part in enumerate(parts):
            if i:
                lines.append("")
            if part:
                text = escape(part, quote=False)
                lines[-1] += f'<span class="{cls}">{text}</span>' if cls else text
    if lines and lines[-1] == "" and code.endswith("\n"):
        lines.pop()
    return lines


def _terminal_roles(raw_lines: list[str]) -> list[str]:
    roles = []
    continued = False
    in_heredoc: str | None = None
    for line in raw_lines:
        stripped = line.strip()
        if in_heredoc is not None:
            roles.append("out")
            if stripped == in_heredoc:
                in_heredoc = None
            continue
        if continued:
            roles.append("cont")
        elif not stripped:
            roles.append("blank")
        elif stripped.startswith("#"):
            roles.append("cmt")
        else:
            roles.append("cmd")
        m = re.search(r"<<-?\s*'?\"?(\w+)'?\"?\s*$", stripped)
        if m and roles[-1] in ("cmd", "cont"):
            in_heredoc = m.group(1)
        continued = stripped.endswith("\\") and roles[-1] != "cmt"
    return roles


def _session_roles(raw_lines: list[str]) -> list[tuple[str, str]]:
    """For console blocks: (role, line without prompt)."""
    out = []
    continued = False
    for line in raw_lines:
        if continued:
            out.append(("cont", line))
        elif line.startswith("$ "):
            out.append(("cmd", line[2:]))
        elif line.startswith("# ") and not out:
            out.append(("cmt", line))
        else:
            out.append(("out", line))
        continued = out[-1][0] in ("cmd", "cont") and line.rstrip().endswith("\\")
    return out


def code_bar_label(lang: str, attrs: dict[str, str]) -> tuple[str, str]:
    """Icon name and label shown in the editor bar."""
    if lang in TERMINAL_LANGS or lang in SESSION_LANGS:
        return "terminal", attrs.get("title", "Terminal")
    return "file-code", attrs.get("title", LANG_LABELS.get(lang, lang.upper() if lang else "Text"))


def render_code_body(code: str, lang: str, attrs: dict[str, str]) -> tuple[str, str]:
    """Render the ``<pre>`` for a block. Returns (variant, html)."""
    code = code.rstrip("\n") + "\n"
    hl = parse_ranges(attrs["hl"]) if attrs.get("hl") else set()
    if lang in SESSION_LANGS:
        variant = "terminal"
        rows = _session_roles(code.rstrip("\n").split("\n"))
        html_lines = []
        for role, text in rows:
            inner = tokenize_lines(text + "\n", "bash")[0] if role in ("cmd", "cont") else escape(text, quote=False)
            html_lines.append((role, inner))
    elif lang in TERMINAL_LANGS:
        variant = "terminal"
        raw = code.rstrip("\n").split("\n")
        roles = _terminal_roles(raw)
        toks = tokenize_lines(code, "bash")
        toks += [""] * (len(raw) - len(toks))
        html_lines = list(zip(roles, toks))
    else:
        variant = "editor"
        html_lines = [("", t) for t in tokenize_lines(code, lang)]
    out = []
    for n, (role, inner) in enumerate(html_lines, start=1):
        classes = ["line"]
        if role:
            classes.append(role)
        if n in hl:
            classes.append("hl")
        out.append(f'<span class="{" ".join(classes)}">{inner or " "}</span>')
    pre = f'<pre class="code-pre"><code class="lang-{escape(lang or "text")}">' + "\n".join(out) + "</code></pre>"
    return variant, pre


def render_code_block(code: str, info: str) -> str:
    lang, attrs = parse_info(info)
    variant, pre = render_code_body(code, lang, attrs)
    ico, label = code_bar_label(lang, attrs)
    lang_tag = LANG_LABELS.get(lang, lang) if lang and "title" in attrs and variant == "editor" else ""
    bar = (
        f'<div class="code-bar"><span class="code-file">{icon(ico, 14)}<span>{escape(label)}</span></span>'
        + (f'<span class="code-lang">{escape(lang_tag)}</span>' if lang_tag else "")
        + copy_button()
        + "</div>"
    )
    return f'<figure class="code code--{variant}" data-lang="{escape(lang)}">{bar}{pre}</figure>'


def copy_button() -> str:
    return (
        f'<button type="button" class="code-copy" data-copy>{icon("copy", 14, "i-copy")}{icon("check", 14, "i-check")}'
        '<span class="code-copy-label">Copy</span></button>'
    )


def render_tab_group(blocks: list[tuple[str, str]]) -> str:
    """Blocks are (code, info) pairs that all carry a ``tab`` attribute."""
    tabs, panes = [], []
    for i, (code, info) in enumerate(blocks):
        lang, attrs = parse_info(info)
        label = attrs.get("tab", f"Tab {i + 1}")
        variant, pre = render_code_body(code, lang, attrs)
        selected = "true" if i == 0 else "false"
        ico = icon("terminal", 14) if variant == "terminal" else ""
        tabs.append(
            f'<button type="button" role="tab" class="code-tab" aria-selected="{selected}" tabindex="{0 if i == 0 else -1}"'
            f' data-tab="{escape(label)}">{ico}{escape(label)}</button>'
        )
        sub = ""
        if "title" in attrs:
            sub_ico = "terminal" if variant == "terminal" else "file-code"
            sub = f'<div class="code-subbar">{icon(sub_ico, 13)}<span>{escape(attrs["title"])}</span></div>'
        hidden = "" if i == 0 else " hidden"
        panes.append(
            f'<div class="code-pane code--{variant}" role="tabpanel" data-tab="{escape(label)}"{hidden}>{sub}{pre}</div>'
        )
    return (
        '<figure class="code code--tabs">'
        f'<div class="code-bar code-tabs" role="tablist">{"".join(tabs)}{copy_button()}</div>'
        f'{"".join(panes)}</figure>'
    )
