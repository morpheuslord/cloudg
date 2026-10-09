"""Substitution transforms: aliases, regex rewrites, key renames, templates,
and the input-side :class:`Depseudonymizer`.

Output side (applied to results):

* :class:`AliasMap`: explicit value maps (``"123456789012" ->
  "prod-account"``), as whole values or embedded in text. Alias tables can
  be loaded from YAML / JSON files, optionally grouped by entity type.
* :class:`RegexReplace`: ``re.sub`` rules with back-references
  (``\\1`` / ``\\g<name>``), optionally limited to keys matching globs.
* :class:`KeyRename` renames dict keys anywhere in the payload.
* :class:`TemplateField` adds derived fields from templates
  (``"{name} in {region}"``) to every dict that has the referenced fields.
* :class:`Substitution` combines the four above in one configurable step.

Input side (applied to tool / prompt arguments, resource template
variables and completion context):

* :class:`Depseudonymizer` reverses vault tokens and aliases inside
  arguments, recursively (dicts, lists, plain strings such as URIs), and
  strips untrusted-content fences, so the model can pass back exactly what
  it saw and the handler receives real identifiers.
"""

from __future__ import annotations

import fnmatch
import json
import re
from pathlib import Path
from typing import Any, Iterable

from cloudg.mcp.transforms.base import TransformContext
from cloudg.mcp.transforms.textscan import replace_known

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _globs(patterns: Iterable[str] | None) -> re.Pattern[str] | None:
    pats = [str(p) for p in (patterns or ())]
    if not pats:
        return None
    return re.compile("|".join(f"(?:{fnmatch.translate(p)})" for p in pats))


def load_alias_file(path: str | Path) -> dict[str, Any]:
    """Load an alias table from YAML or JSON.

    Accepted shapes::

        aliases:                       # optional wrapper key
          aws_account_id:              # optional entity grouping
            "123456789012": prod-account
          "10.0.0.0/16": corp-vpc      # or flat value: alias
    """
    p = Path(path)
    text = p.read_text()
    if p.suffix.lower() == ".json":
        data = json.loads(text)
    else:
        import yaml

        data = yaml.safe_load(text) or {}
    if isinstance(data, dict) and "aliases" in data and isinstance(data["aliases"], dict):
        data = data["aliases"]
    if not isinstance(data, dict):
        raise ValueError(f"Alias file {p} must contain a mapping")
    return data


def flatten_aliases(table: dict[str, Any]) -> dict[str, str]:
    """``{entity: {real: alias}}`` or ``{real: alias}`` -> ``{real: alias}``."""
    out: dict[str, str] = {}
    for k, v in table.items():
        if isinstance(v, dict):
            out.update({str(a): str(b) for a, b in v.items()})
        else:
            out[str(k)] = str(v)
    return out


def _walk_strings(value: Any, fn: Any, key: str | None = None) -> Any:
    """Apply ``fn(text, key)`` to every string (values, not keys)."""
    if isinstance(value, str):
        return fn(value, key)
    if isinstance(value, dict):
        return {k: _walk_strings(v, fn, k if isinstance(k, str) else key) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_walk_strings(v, fn, key) for v in value]
    return value


# ---------------------------------------------------------------------------
# Output-side substitutions
# ---------------------------------------------------------------------------


class AliasMap:
    """Replace real values with operator-chosen aliases.

    Args:
        aliases: ``{real: alias}`` or ``{entity: {real: alias}}``.
        files: Alias files (YAML / JSON) merged in order.
        substring: Also replace occurrences inside longer strings (word
            bounded: ``123456789012`` inside an ARN is replaced, inside
            ``1234567890123`` it is not).
        case_sensitive: Match case exactly (default).
        pseudonym_aware: Also replace the vault's pseudonyms of the real
            values. Policies run aliases *after* redaction, so a pseudonymised
            account (alone or inside a pseudonymised ARN) still shows its
            alias, and the :class:`Depseudonymizer` maps the alias back.
    """

    name = "alias"

    def __init__(
        self,
        aliases: dict[str, Any] | None = None,
        *,
        files: Iterable[str | Path] = (),
        substring: bool = True,
        case_sensitive: bool = True,
        pseudonym_aware: bool = True,
    ) -> None:
        self.pseudonym_aware = pseudonym_aware
        table: dict[str, str] = {}
        for f in files:
            table.update(flatten_aliases(load_alias_file(f)))
        table.update(flatten_aliases(aliases or {}))
        self.aliases = table
        self.substring = substring
        self.case_sensitive = case_sensitive
        self._lookup = table if case_sensitive else {k.lower(): v for k, v in table.items()}
        self.reverse = {v: k for k, v in table.items()}
        self._rx = self._build(table.keys())
        self._rev_rx = self._build(self.reverse.keys())

    def _build(self, words: Iterable[str]) -> re.Pattern[str] | None:
        ws = sorted((w for w in words if w), key=len, reverse=True)
        if not ws:
            return None
        flags = 0 if self.case_sensitive else re.IGNORECASE
        body = "|".join(re.escape(w) for w in ws)
        return re.compile(rf"(?<![\w\-])(?:{body})(?![\w\-])", flags)

    def substitute(self, text: str) -> tuple[str, int]:
        key = text if self.case_sensitive else text.lower()
        if key in self._lookup:
            return self._lookup[key], 1
        if not self.substring or self._rx is None:
            return text, 0
        count = 0

        def sub(m: re.Match[str]) -> str:
            nonlocal count
            count += 1
            k = m.group(0) if self.case_sensitive else m.group(0).lower()
            return self._lookup[k]

        return self._rx.sub(sub, text), count

    def unsubstitute(
        self, text: str, pairs: list[tuple[str, str]] | None = None
    ) -> tuple[str, int]:
        """Aliases back to real values. ``pairs`` (optional) collects
        ``(real, alias)`` for each replacement."""
        if text in self.reverse:
            if pairs is not None:
                pairs.append((self.reverse[text], text))
            return self.reverse[text], 1
        if self._rev_rx is None:
            return text, 0
        count = 0

        def sub(m: re.Match[str]) -> str:
            nonlocal count
            alias = m.group(0)
            if alias in self.reverse:
                count += 1
                if pairs is not None:
                    pairs.append((self.reverse[alias], alias))
                return self.reverse[alias]
            return alias

        return self._rev_rx.sub(sub, text), count

    def _for_context(self, ctx: TransformContext) -> "AliasMap":
        """This map, extended with ``pseudonym -> alias`` entries for the
        caller's vault namespace."""
        vault = ctx.vault
        if not self.pseudonym_aware or vault is None:
            return self
        ns = vault.namespace_for(ctx.principal)
        extra = {
            tok: alias
            for real, alias in self.aliases.items()
            for tok in vault.tokens_for(real, namespace=ns)
        }
        if not extra:
            return self
        return AliasMap(
            {**self.aliases, **extra},
            substring=self.substring,
            case_sensitive=self.case_sensitive,
            pseudonym_aware=False,
        )

    def apply(self, value: Any, ctx: TransformContext) -> Any:
        if not self.aliases:
            return value
        amap = self._for_context(ctx)
        total = 0

        def fn(text: str, _key: str | None) -> str:
            nonlocal total
            out, n = amap.substitute(text)
            total += n
            return out

        out = _walk_strings(value, fn)
        if isinstance(value, dict):
            # Keys may be identifiers too (maps keyed by account / ARN)
            out = _rekey(out, lambda k: amap.substitute(k)[0])
        if total:
            ctx.count("aliased", total)
        return out


def _rekey(value: Any, fn: Any) -> Any:
    if isinstance(value, dict):
        return {(fn(k) if isinstance(k, str) else k): _rekey(v, fn) for k, v in value.items()}
    if isinstance(value, list):
        return [_rekey(v, fn) for v in value]
    return value


class RegexReplace:
    """``re.sub`` rules.

    ``rules`` items: ``{"pattern": ..., "replace": ..., "keys": [globs],
    "flags": "i", "count": 0}``. ``keys`` limits a rule to string values
    whose dict key matches one of the globs.
    """

    name = "regex_replace"

    def __init__(self, rules: Iterable[dict[str, Any]] = ()) -> None:
        self.rules: list[tuple[re.Pattern[str], str, re.Pattern[str] | None, int]] = []
        for r in rules:
            flags = 0
            for f in str(r.get("flags", "")):
                flags |= {"i": re.I, "m": re.M, "s": re.S, "x": re.X}.get(f.lower(), 0)
            repl = str(r.get("replace", r.get("replacement", "")))
            self.rules.append(
                (
                    re.compile(str(r["pattern"]), flags),
                    repl,
                    _globs(r.get("keys")),
                    int(r.get("count", 0)),
                )
            )

    def apply(self, value: Any, ctx: TransformContext) -> Any:
        if not self.rules:
            return value
        total = 0

        def fn(text: str, key: str | None) -> str:
            nonlocal total
            for rx, repl, keys, count in self.rules:
                if keys is not None and (key is None or not keys.match(key)):
                    continue
                text, n = rx.subn(repl, text, count=count)
                total += n
            return text

        out = _walk_strings(value, fn)
        if total:
            ctx.count("regex_replaced", total)
        return out


class KeyRename:
    """Rename dict keys anywhere in the payload (``{"account_id": "account"}``)."""

    name = "rename_keys"

    def __init__(self, renames: dict[str, str] | None = None) -> None:
        self.renames = dict(renames or {})

    def apply(self, value: Any, ctx: TransformContext) -> Any:
        if not self.renames:
            return value
        n = 0

        def walk(v: Any) -> Any:
            nonlocal n
            if isinstance(v, dict):
                out = {}
                for k, x in v.items():
                    nk = self.renames.get(k, k) if isinstance(k, str) else k
                    n += nk != k
                    out[nk] = walk(x)
                return out
            if isinstance(v, list):
                return [walk(x) for x in v]
            return v

        out = walk(value)
        if n:
            ctx.count("keys_renamed", n)
        return out


class _SafeDict(dict):
    def __missing__(self, key: str) -> str:
        raise KeyError(key)


class TemplateField:
    """Add derived string fields.

    ``templates`` items: ``{"target": "label", "template": "{name} in
    {region}", "overwrite": false}``. A template applies to every dict
    containing all the fields it references.
    """

    name = "template"
    _FIELD_RE = re.compile(r"{([A-Za-z_][A-Za-z0-9_]*)[^{}]*}")

    def __init__(self, templates: Iterable[dict[str, Any]] = ()) -> None:
        self.templates = []
        for t in templates:
            tmpl = str(t["template"])
            fields = frozenset(self._FIELD_RE.findall(tmpl))
            self.templates.append((str(t["target"]), tmpl, fields, bool(t.get("overwrite"))))

    def apply(self, value: Any, ctx: TransformContext) -> Any:
        if not self.templates:
            return value
        n = 0

        def walk(v: Any) -> Any:
            nonlocal n
            if isinstance(v, dict):
                out = {k: walk(x) for k, x in v.items()}
                for target, tmpl, fields, overwrite in self.templates:
                    if fields <= out.keys() and (overwrite or target not in out):
                        try:
                            out[target] = tmpl.format_map(_SafeDict(out))
                            n += 1
                        except (KeyError, ValueError, IndexError):
                            pass
                return out
            if isinstance(v, list):
                return [walk(x) for x in v]
            return v

        out = walk(value)
        if n:
            ctx.count("templated", n)
        return out


class Substitution:
    """Aliases -> regex rules -> key renames -> templates, as one step.

    Options: ``aliases`` (dict), ``alias_files`` (paths), ``substring``,
    ``case_sensitive``, ``regex`` (rules), ``rename`` (dict),
    ``templates`` (list).
    """

    name = "substitute"

    def __init__(
        self,
        *,
        aliases: dict[str, Any] | None = None,
        alias_files: Iterable[str | Path] = (),
        substring: bool = True,
        case_sensitive: bool = True,
        regex: Iterable[dict[str, Any]] = (),
        rename: dict[str, str] | None = None,
        templates: Iterable[dict[str, Any]] = (),
    ) -> None:
        self.alias_map = AliasMap(
            aliases, files=alias_files, substring=substring, case_sensitive=case_sensitive
        )
        self.steps: list[Any] = [
            self.alias_map,
            RegexReplace(regex),
            KeyRename(rename),
            TemplateField(templates),
        ]

    @property
    def alias_maps(self) -> list[AliasMap]:
        return [self.alias_map] if self.alias_map.aliases else []

    def apply(self, value: Any, ctx: TransformContext) -> Any:
        for step in self.steps:
            value = step.apply(value, ctx)
        return value


# ---------------------------------------------------------------------------
# Input side
# ---------------------------------------------------------------------------

#: Fence markers written by :class:`~cloudg.mcp.transforms.annotation.UntrustedTextGuard`.
FENCE_OPEN = "⟦untrusted⟧ "
FENCE_CLOSE = " ⟦/untrusted⟧"


def strip_fences(text: str) -> str:
    """Remove the untrusted-content fences, keeping the fenced text. A
    linear scan (no regex), so hostile input with many unmatched fence
    markers costs no more than one pass."""
    if "⟦" not in text:
        return text
    out: list[str] = []
    pos = 0
    while True:
        start = text.find(FENCE_OPEN, pos)
        if start < 0:
            break
        end = text.find(FENCE_CLOSE, start + len(FENCE_OPEN))
        if end < 0:
            break
        out.append(text[pos:start])
        out.append(text[start + len(FENCE_OPEN) : end])
        pos = end + len(FENCE_CLOSE)
    if not out:
        return text
    out.append(text[pos:])
    return "".join(out)


class Depseudonymizer:
    """Reverse pseudonyms and aliases in arguments (input direction).

    Works on dicts, lists and plain strings (resource URIs, completion
    values). Exact token matches are reversed first; otherwise every known
    token embedded in the text is replaced (``"show me 10.112.119.147"``).
    Only tokens the vault issued are reversed; unknown values pass
    through unchanged.
    """

    name = "depseudonymize"

    def __init__(
        self,
        vault: Any = None,
        *,
        aliases: Iterable[AliasMap] = (),
        strip_fences: bool = True,
        keys: bool = False,
    ) -> None:
        self.vault = vault
        self.aliases = list(aliases)
        self.strip_fences = strip_fences
        self.keys = keys

    def _reverse(self, text: str, run: "_ReverseRun") -> str:
        """Exact vault token first, then aliases, then tokens embedded in
        text (an aliased ARN ``arn:...:prod-payments:instance/i-<token>``
        needs both the alias and the token reversed)."""
        vault, ns, pairs = run.vault, run.ns, run.pairs
        if self.strip_fences:
            text = strip_fences(text)
        if vault is not None:
            real = vault.detokenize(text, namespace=ns)
            if real is not None:
                run.count += 1
                pairs.append((real, text))
                return strip_fences(real) if self.strip_fences else real
        for amap in self.aliases:
            text, n = amap.unsubstitute(text, pairs)
            run.count += n
        if vault is not None:
            text, n = vault.detokenize_text_count(text, namespace=ns, pairs=pairs)
            run.count += n
            if n and self.strip_fences:
                text = strip_fences(text)  # a pseudonymised value may have been fenced
        return text

    def apply(self, value: Any, ctx: TransformContext) -> Any:
        vault = ctx.vault if ctx.vault is not None else self.vault
        ns = vault.namespace_for(ctx.principal) if vault is not None else "global"
        run = _ReverseRun(vault, ns, ctx.restored)
        out = self._walk(value, run)
        if run.count:
            ctx.count("depseudonymized", run.count)
        return out

    def _walk(self, v: Any, run: "_ReverseRun") -> Any:
        if isinstance(v, str):
            return self._reverse(v, run)
        if isinstance(v, dict):
            return {
                (self._reverse(k, run) if self.keys and isinstance(k, str) else k): self._walk(
                    x, run
                )
                for k, x in v.items()
            }
        if isinstance(v, (list, tuple)):
            return [self._walk(x, run) for x in v]
        return v


class _ReverseRun:
    """State of one :meth:`Depseudonymizer.apply` call."""

    __slots__ = ("vault", "ns", "pairs", "count")

    def __init__(self, vault: Any, ns: str, pairs: list[tuple[str, str]]) -> None:
        self.vault = vault
        self.ns = ns
        self.pairs = pairs
        self.count = 0


# ---------------------------------------------------------------------------
# Re-pseudonymising restored values
# ---------------------------------------------------------------------------


def repseudonymize(value: Any, restored: Any) -> Any:
    """Put pseudonyms back into ``value`` for every real value restored by
    the input pipeline of the same call.

    ``restored`` is :attr:`TransformContext.restored` (a list of ``(real,
    token)`` pairs) or the input :class:`TransformContext` itself. Every
    string in ``value`` (dict keys included) has each restored real value
    replaced by its token wherever it appears as a whole word (see
    :mod:`cloudg.mcp.transforms.textscan`; values containing whitespace are
    replaced as plain substrings). A handler that echoes an argument in an
    error message ("Unknown severity 'web-1'") therefore cannot hand the
    caller the real value behind the pseudonym it sent. ``value`` is
    returned unchanged when nothing was restored."""
    pairs = getattr(restored, "restored", restored) or ()
    table: dict[str, str] = {}
    spaced: list[tuple[str, str]] = []
    for real, token in pairs:
        if not real or real == token or real in table:
            continue
        table[real] = token
        if any(c.isspace() for c in real):
            spaced.append((real, token))
    if not table:
        return value
    spaced.sort(key=lambda p: len(p[0]), reverse=True)

    def fix(text: str) -> str:
        hit = table.get(text)
        if hit is not None:
            return hit
        for real, token in spaced:
            text = text.replace(real, token)
        return replace_known(text, table.get)

    return _repseudo_walk(value, fix)


def _repseudo_walk(value: Any, fix: Any) -> Any:
    if isinstance(value, str):
        return fix(value)
    if isinstance(value, dict):
        return {
            (fix(k) if isinstance(k, str) else k): _repseudo_walk(v, fix) for k, v in value.items()
        }
    if isinstance(value, list):
        return [_repseudo_walk(v, fix) for v in value]
    if isinstance(value, tuple):
        return tuple(_repseudo_walk(v, fix) for v in value)
    return value
