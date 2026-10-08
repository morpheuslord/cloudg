"""Redaction transform: detect sensitive entities and apply a strategy.

:class:`Redactor` walks JSON-like data (dicts, lists, strings, scalars),
finds entities with the :mod:`~cloudg.mcp.transforms.detectors` registry
(inside strings, in dict keys, and as whole values under sensitive keys)
and replaces each according to a per-entity *strategy* (the Presidio
"operator" / Cloud DLP "transformation" concept):

=============== ==========================================================
strategy        effect
=============== ==========================================================
``redact``      ``[REDACTED:aws_secret_access_key]`` (template configurable)
``mask``        keep the first / last N characters: ``AKIA************MPLE``
``hash``        keyed HMAC-SHA256 short digest, stable per vault key:
                ``email:3f9a1c0b7d2e`` (irreversible, still joinable)
``pseudonymize``reversible, format-preserving token from the
                :class:`~cloudg.mcp.transforms.vault.TokenVault`
``generalize``  coarser value: IP -> ``/24``, timestamp -> date, email ->
                ``*@domain``, ARN -> ``arn:aws:ec2:us-east-1:*:instance/*``,
                numbers -> buckets
``drop``        remove the containing field / list element
``keep``        leave as is (default)
=============== ==========================================================

Strategies are resolved for a match by walking ``refined entity ->
parent entity -> detector entity -> detector name -> category ->
default``, so a policy can be as coarse (``secret: redact``) or as precise
(``public_ip: pseudonymize``, ``private_ip: keep``) as needed. Detectors
whose every possible entity resolves to ``keep`` are not even compiled.

The input is never mutated; counts land in ``ctx.report`` as
``report["redacted"]["password"] += 1`` etc.
"""

from __future__ import annotations

import ipaddress
import json
import re
from dataclasses import dataclass, field
from typing import Any, Iterable

from cloudg.mcp.transforms.base import TransformContext
from cloudg.mcp.transforms.detectors import (
    DEFAULT_REGISTRY,
    ENTITY_PARENTS,
    PERSON_TAG_PATTERN,
    TAG_CONTAINER_KEYS,
    Detector,
    DetectorRegistry,
    SHAPED_ENTITIES,
    KeyRule,
    normalize_key,
)

STRATEGIES = ("redact", "mask", "hash", "pseudonymize", "generalize", "drop", "keep")
_STRATEGY_ALIASES = {
    "pseudonymise": "pseudonymize", "tokenize": "pseudonymize", "tokenise": "pseudonymize",
    "generalise": "generalize", "remove": "drop", "replace": "redact", "none": "keep",
    "allow": "keep", "bucket": "generalize",
}
#: Report section per strategy.
_REPORT_KEY = {
    "redact": "redacted", "mask": "masked", "hash": "hashed", "pseudonymize": "pseudonymized",
    "generalize": "generalized", "drop": "dropped",
}
#: Default tag keys whose values are operational, not identifying.
DEFAULT_TAG_KEY_ALLOWLIST = frozenset({
    "env", "environment", "stage", "tier", "managed_by", "managedby", "terraform",
    "cost_center", "costcenter", "project_type", "application_tier", "criticality",
    "data_classification", "compliance", "backup", "patch_group",
})


class _Drop:
    """Sentinel: remove the containing field / element."""

    def __repr__(self) -> str:  # pragma: no cover
        return "<DROP>"


DROP = _Drop()


@dataclass(frozen=True)
class Strategy:
    kind: str
    options: dict[str, Any] = field(default_factory=dict)

    def __hash__(self) -> int:  # options are dicts; identity is fine for caching
        return hash((self.kind, id(self.options)))


KEEP = Strategy("keep")


def parse_strategy(spec: Any) -> Strategy:
    """``"redact"`` | ``{"strategy": "mask", "keep_last": 4}`` | Strategy."""
    if isinstance(spec, Strategy):
        return spec
    if spec is None or spec is False:
        return KEEP
    if spec is True:
        return Strategy("redact")
    if isinstance(spec, str):
        kind, opts = spec, {}
    elif isinstance(spec, dict):
        opts = dict(spec)
        kind = opts.pop("strategy", None) or opts.pop("type", None) or opts.pop("kind", "redact")
    else:
        raise ValueError(f"Invalid strategy {spec!r}")
    kind = _STRATEGY_ALIASES.get(str(kind).lower(), str(kind).lower())
    if kind not in STRATEGIES:
        raise ValueError(f"Unknown strategy {kind!r}; expected one of {', '.join(STRATEGIES)}")
    return Strategy(kind, opts)


def _chain(*names: str | None) -> tuple[str, ...]:
    out: list[str] = []
    for n in names:
        while n and n not in out:
            out.append(n)
            n = ENTITY_PARENTS.get(n)
    return tuple(out)


class Redactor:
    """Detect-and-transform pass over JSON-like data.

    Args:
        strategies: ``{entity | detector | category | "default": strategy}``.
        default: Strategy for anything not listed (``"keep"``).
        detectors: Detector registry (built-ins by default).
        custom_detectors: Extra detector dicts / :class:`Detector` objects.
        disabled_detectors: Detector names to switch off.
        key_rules: ``True`` (built-in key rules), ``False`` (none) or a
            list of rule names to keep.
        min_confidence: Ignore detector matches below this score.
        scan_keys: Also scan dict keys (maps keyed by ARN / account).
        tags: Treat ``tags`` / ``labels`` maps specially (tag values are
            entity ``tag_value``, people-ish keys ``person``).
        tag_key_allowlist: Tag keys whose values are never replaced
            wholesale (still scanned for embedded entities).
        skip_keys: Keys left untouched (``_meta``...).
        allow_pseudonymize: ``False`` turns every ``pseudonymize`` into
            ``keep`` (tool hint ``{"pseudonymize": false}``).
        redact_template / hash_template: Output formats.
        name_mentions: After pseudonymising names through key rules, also
            replace those names where they appear inside free text of the
            same payload (path summaries, descriptions).
    """

    name = "redact"

    def __init__(
        self,
        strategies: dict[str, Any] | None = None,
        *,
        default: Any = "keep",
        detectors: DetectorRegistry | None = None,
        custom_detectors: Iterable[dict[str, Any] | Detector] = (),
        disabled_detectors: Iterable[str] = (),
        key_rules: bool | Iterable[str] = True,
        extra_key_rules: Iterable[KeyRule | dict[str, Any]] = (),
        min_confidence: float = 0.0,
        scan_keys: bool = True,
        tags: bool = True,
        tag_key_allowlist: Iterable[str] | None = None,
        skip_keys: Iterable[str] = ("_meta", "_annotations", "cursor", "next_cursor"),
        allow_pseudonymize: bool = True,
        redact_template: str = "[REDACTED:{entity}]",
        hash_template: str = "{entity}:{digest}",
        cache_size: int = 200_000,
        vault: Any = None,
        name_mentions: bool = True,
    ) -> None:
        reg = detectors or DEFAULT_REGISTRY
        custom = list(custom_detectors)
        if custom:
            reg = reg.with_custom(custom)
        disabled = list(disabled_detectors)
        if disabled:
            reg = reg.disable(disabled)
        extra = [s if isinstance(s, KeyRule) else _key_rule_from_config(s)
                 for s in extra_key_rules]
        self.registry = reg
        self.strategies: dict[str, Strategy] = {
            str(k): parse_strategy(v) for k, v in (strategies or {}).items()
        }
        self.default = parse_strategy(self.strategies.pop("default", None) or default)
        self.min_confidence = float(min_confidence)
        self.scan_keys = scan_keys
        self.tags = tags
        self.tag_key_allowlist = frozenset(
            normalize_key(k)
            for k in (DEFAULT_TAG_KEY_ALLOWLIST if tag_key_allowlist is None else tag_key_allowlist)
        )
        self.skip_keys = frozenset(skip_keys)
        self.allow_pseudonymize = allow_pseudonymize
        self.redact_template = redact_template
        self.hash_template = hash_template
        self.cache_size = cache_size
        self.vault = vault
        self._resolved: dict[tuple[str, ...], Strategy] = {}
        self._str_cache: dict[tuple[Any, ...], tuple[Any, tuple[tuple[str, str], ...]]] = {}
        self._key_cache: dict[str, tuple[str, list[KeyRule]]] = {}
        self._full_cache: dict[str, bool] = {}
        self.name_mentions = name_mentions

        # Key rules that can do anything under this configuration
        if key_rules is True:
            rules = reg.key_rules
        elif key_rules is False:
            rules = []
        else:
            wanted = set(key_rules)
            rules = [r for r in reg.key_rules if r.name in wanted]
        rules = [*rules, *extra]
        self.key_rules = [r for r in rules if self._rule_strategy(r).kind != "keep"]
        self._person_rx = re.compile(PERSON_TAG_PATTERN)
        # Only compile detectors that can produce a non-keep outcome
        active = [d.name for d in reg.detectors if d.enabled and self._detector_active(d)]
        self.active_detectors = active
        self.scanner = reg.scanner(active)

    # ------------------------------------------------------------------
    # Strategy resolution
    # ------------------------------------------------------------------

    def resolve(self, chain: tuple[str, ...]) -> Strategy:
        s = self._resolved.get(chain)
        if s is None:
            s = self.default
            for key in chain:
                if key in self.strategies:
                    s = self.strategies[key]
                    break
            if s.kind == "pseudonymize" and not self.allow_pseudonymize:
                s = KEEP
            self._resolved[chain] = s
        return s

    def _detector_active(self, d: Detector) -> bool:
        if d.confidence < self.min_confidence:
            return False
        candidates = {d.entity} | {e for e, p in ENTITY_PARENTS.items() if p == d.entity}
        return any(
            self.resolve(_chain(e) + (d.entity, d.name, d.category)).kind != "keep"
            for e in candidates
        )

    def _rule_strategy(self, rule: KeyRule) -> Strategy:
        return self.resolve(_chain(rule.entity) + (rule.name, rule.category))

    @property
    def reversible(self) -> bool:
        """True when this redactor can emit vault tokens."""
        if not self.allow_pseudonymize:
            return False
        return self.default.kind == "pseudonymize" or any(
            s.kind == "pseudonymize" for s in self.strategies.values()
        )

    def describe(self) -> dict[str, Any]:
        return {
            "type": self.name,
            "default": self.default.kind,
            # a list, so entity names (secret, credential...) are values, not
            # keys the sensitive-key rule would redact
            "strategies": [
                {"applies_to": k, "strategy": v.kind, **({"options": v.options} if v.options
                                                          else {})}
                for k, v in self.strategies.items()
            ],
            "active_detectors": list(self.active_detectors),
            "key_rules": [r.name for r in self.key_rules],
            "min_confidence": self.min_confidence,
            "pseudonymize_allowed": self.allow_pseudonymize,
        }

    # ------------------------------------------------------------------
    # Apply
    # ------------------------------------------------------------------

    def apply(self, value: Any, ctx: TransformContext) -> Any:
        vault = ctx.vault if ctx.vault is not None else self.vault
        ns = vault.namespace_for(ctx.principal) if vault is not None else "global"
        run = _Run(self, ctx, vault, ns)
        out = run.walk(value, ())
        if run.issued and self.name_mentions and out is not DROP:
            out = run.name_pass(out)
        run.flush()
        if vault is not None and getattr(vault, "autosave", False):
            vault.maybe_autosave()
        if out is DROP:
            return None if not isinstance(value, str) else self.redact_template.format(
                entity="content"
            )
        return out

    # Replacement of one entity value ----------------------------------

    def replace(self, text: str, entity: str, strategy: Strategy, vault: Any, ns: str) -> Any:
        kind = strategy.kind
        opts = strategy.options
        if kind == "keep":
            return text
        if kind == "drop":
            return DROP
        if kind == "redact":
            tmpl = opts.get("text") or opts.get("template") or self.redact_template
            return tmpl.format(entity=entity, length=len(text))
        if kind == "mask":
            return _mask(text, opts)
        if kind == "hash":
            length = int(opts.get("length", 12))
            if vault is not None:
                digest = vault.hash_value(text, length=length, entity_type=entity)
            else:  # pragma: no cover (policies always provide a vault)
                import hashlib

                digest = hashlib.sha256(f"{entity}\x1f{text}".encode()).hexdigest()[:length]
            tmpl = opts.get("template") or self.hash_template
            return tmpl.format(entity=entity, digest=digest)
        if kind == "pseudonymize":
            if vault is None:
                return self.replace(text, entity, Strategy("hash", opts), vault, ns)
            return vault.tokenize(text, opts.get("as", entity), namespace=ns)
        if kind == "generalize":
            return generalize(text, entity, opts)
        raise ValueError(kind)  # pragma: no cover


_ENUM_KEYS: frozenset[str] | None = None
#: Entities whose real values are also replaced in free text of the same
#: payload (``"summary": "web-1 -> sg-app"``) once a key rule pseudonymised
#: them elsewhere.
_NO_MENTION_ENTITIES = frozenset({"sensitive_field", "tag_value", "person", "rag_chunk_id"})
_NAME_PASS_LIMIT = 5000
#: Keys whose values are vocabulary, never names (left alone by the mention pass).
_ENUMISH_KEYS = frozenset({
    "type", "asset_type", "resource_type", "provider", "region", "status", "severity",
    "predicate", "edge_type", "relationship", "kind", "chunk_type", "metric", "mode",
    "format", "category", "direction", "protocol", "max_severity", "severity_max",
    "relation_group", "feature_set", "env", "environment", "stage", "tier", "strategy",
    "applies_to", "entity", "entity_type", "decision",
})
_RAG_FIELD_RE = re.compile(r"^(Resource|Account|Tags): ?(.*)$")
_RAG_REL_RE = re.compile(r"^(\s+[\u2192\u2190] [A-Z0-9_]+: )(.+)$")
_RAG_MEMBER_RE = re.compile(r"^(\s+\u2022 )(.+?)( \([A-Z0-9_]+\))$")
_RAG_TRIPLE_RE = re.compile(r"^(\s+)(.+?) \u2192 ([A-Z0-9_]+) \u2192 (.+?)( \(.*\))?$")
_ASSET_TYPE_NAMES: frozenset[str] | None = None


def _asset_type_names() -> frozenset[str]:
    global _ASSET_TYPE_NAMES
    if _ASSET_TYPE_NAMES is None:
        try:
            from cloudg.schema.models import AssetType

            _ASSET_TYPE_NAMES = frozenset({t.value for t in AssetType} | {t.name for t in AssetType})
        except Exception:  # pragma: no cover
            _ASSET_TYPE_NAMES = frozenset()
    return _ASSET_TYPE_NAMES


def _enum_keys() -> frozenset[str]:
    """cloudg enum names (asset types, edge types, severities...). Used as
    dict keys in counts (``assets_by_type: {"SECRET": 3}``) they are labels,
    not secret-bearing field names."""
    global _ENUM_KEYS
    if _ENUM_KEYS is None:
        names: set[str] = set()
        try:
            from cloudg.schema import models

            for enum_name in ("AssetType", "EdgeType", "Severity", "CloudProvider",
                              "ComplianceStatus"):
                enum = getattr(models, enum_name, None)
                if enum is not None:
                    for member in enum:
                        names.add(member.name)
                        names.add(str(member.value))
        except Exception:  # pragma: no cover - schema always importable in cloudg
            pass
        _ENUM_KEYS = frozenset(n for n in names if n and n == n.upper())
    return _ENUM_KEYS


class _Run:
    """State of one :meth:`Redactor.apply` call."""

    __slots__ = ("r", "ctx", "vault", "ns", "counts", "cache_key", "issued")

    def __init__(self, r: Redactor, ctx: TransformContext, vault: Any, ns: str) -> None:
        self.r = r
        self.ctx = ctx
        self.vault = vault
        self.ns = ns
        self.counts: dict[tuple[str, str], int] = {}
        self.cache_key = (id(vault), ns)
        self.issued: dict[str, str] = {}

    def bump(self, kind: str, entity: str, n: int = 1) -> None:
        if kind == "keep":
            return
        key = (_REPORT_KEY[kind], entity)
        self.counts[key] = self.counts.get(key, 0) + n

    def flush(self) -> None:
        report = self.ctx.report
        for (section, entity), n in self.counts.items():
            sec = report.setdefault(section, {})
            sec[entity] = sec.get(entity, 0) + n

    # -- traversal -------------------------------------------------------

    def walk(self, value: Any, path: tuple[Any, ...]) -> Any:
        if isinstance(value, str):
            return self.scan_str(value)
        if isinstance(value, dict):
            return self.walk_dict(value)
        if isinstance(value, (list, tuple)):
            out = []
            for item in value:
                res = self.walk(item, path)
                if res is not DROP:
                    out.append(res)
            return out
        return value

    def norm(self, key: str) -> tuple[str, list[KeyRule]]:
        hit = self.r._key_cache.get(key)
        if hit is None:
            nk = normalize_key(key)
            rules = [rule for rule in self.r.key_rules if rule.matches(nk)]
            if rules and key in _enum_keys():
                # an enum label used as a key, e.g. {"SECRET": 3} in counts
                rules = [rule for rule in rules if rule.category != "secret"]
            hit = (nk, rules)
            if len(self.r._key_cache) > 50_000:
                self.r._key_cache.clear()
            self.r._key_cache[key] = hit
        return hit

    def walk_dict(self, value: dict[Any, Any]) -> dict[Any, Any]:
        r = self.r
        out: dict[Any, Any] = {}
        siblings: frozenset[str] | None = None
        for k, v in value.items():
            if k in r.skip_keys:
                out[k] = v
                continue
            if isinstance(k, str):
                nk, rules = self.norm(k)
                if r.scan_keys:
                    new_k = self.scan_str(k)
                    if new_k is DROP:
                        continue
                else:
                    new_k = k
            else:
                nk, rules, new_k = "", [], k
            rule = None
            for candidate in rules:
                if candidate.requires_sibling:
                    if siblings is None:
                        siblings = self.siblings(value)
                    if not (candidate.requires_sibling & siblings):
                        continue
                rule = candidate
                break
            if rule is not None:
                res = self.apply_rule(rule, v)
            elif r.tags and nk in TAG_CONTAINER_KEYS:
                res = self.walk_tags(v)
            else:
                res = self.walk(v, ())
            if res is DROP:
                continue
            out[new_k] = res
        return out

    def siblings(self, value: dict[Any, Any]) -> frozenset[str]:
        """Normalised keys of a dict, plus ``asset_type`` when its ``type``
        value is a cloudg asset type (``{"id", "name", "type": "EC2"}``)."""
        keys = {self.norm(str(x))[0] for x in value}
        t = value.get("type")
        if isinstance(t, str) and "asset_type" not in keys and t in _asset_type_names():
            keys.add("asset_type")
        return frozenset(keys)

    # -- key rules ---------------------------------------------------------

    def apply_rule(self, rule: KeyRule, value: Any) -> Any:
        if isinstance(value, str):
            if not value:
                return value
            if rule.entity == "rag_content":
                return self.rag_content(value)
            return self.rule_str(rule, value)
        strat = self.r._rule_strategy(rule)
        if isinstance(value, bool) or value is None:
            return value
        if isinstance(value, (int, float)):
            if rule.scalars:
                if strat.kind == "generalize":
                    return self.counted(strat, rule.entity, _bucket(value, strat.options))
                return self.rule_str(rule, str(value))
            return value
        if rule.subtree and isinstance(value, (dict, list, tuple)):
            if strat.kind == "drop":
                self.bump("drop", rule.entity)
                return DROP
            return self.walk_forced(value, rule.entity, strat)
        if rule.map_keys and isinstance(value, dict):
            out_map: dict[Any, Any] = {}
            for k, v in value.items():
                nk = self.rule_str(rule, k) if isinstance(k, str) and k else k
                if nk is DROP:
                    continue
                res = self.walk(v, ())
                if res is not DROP:
                    out_map[nk] = res
            return out_map
        if rule.defer and isinstance(value, (list, tuple)):
            out = []
            for item in value:
                res = self.apply_rule(rule, item) if isinstance(item, (str, list, tuple)) \
                    else self.walk(item, ())
                if res is not DROP:
                    out.append(res)
            return out
        return self.walk(value, ())

    def rule_str(self, rule: KeyRule, value: str) -> Any:
        """A string under a key rule: detectors first for ``defer`` rules,
        then the rule's (possibly shape-chosen) entity."""
        if rule.entity == "cloud_account" and " -> " in value:
            parts = [self.rule_str(rule, p) for p in value.split(" -> ")]
            if any(p is DROP for p in parts):
                return DROP
            return " -> ".join(str(p) for p in parts)
        if rule.defer and self.whole_entity(value):
            return self.scan_str(value)
        entity = rule.entity
        shaper = SHAPED_ENTITIES.get(entity)
        if shaper is not None:
            entity = shaper(value)
            strat = self.r.resolve(_chain(entity, rule.entity) + (rule.name, rule.category))
        else:
            strat = self.r._rule_strategy(rule)
        out = self.whole(value, entity, strat)
        if (strat.kind == "pseudonymize" and isinstance(out, str) and out != value
                and len(value) >= 3 and entity not in _NO_MENTION_ENTITIES):
            self.issued[value] = out
        return out

    def rag_content(self, text: str) -> str:
        """Entity / community / relation-group text of a RAG chunk: the
        structured lines (``Resource:``, ``Account:``, ``Tags:``, relation and
        member lines, triples) are pseudonymised field by field; any other
        line is scanned like free text."""
        rules = {r.name: r for r in self.r.key_rules}
        name_rule = rules.get("resource_name_key")
        acct_rule = rules.get("account_id_key")
        out_lines = []
        for line in text.split("\n"):
            m = _RAG_FIELD_RE.match(line)
            if m:
                label, val = m.group(1), m.group(2)
                if label == "Resource" and name_rule and val:
                    out_lines.append(f"Resource: {self.rule_str(name_rule, val)}")
                    continue
                if label == "Account" and acct_rule and val:
                    out_lines.append(f"Account: {self.rule_str(acct_rule, val)}")
                    continue
                if label == "Tags" and val.startswith("{"):
                    try:
                        tags = json.loads(val)
                    except ValueError:
                        tags = None
                    if isinstance(tags, dict):
                        out_lines.append(f"Tags: {json.dumps(self.walk_tags(tags))}")
                        continue
            m = _RAG_REL_RE.match(line)
            if m and name_rule:
                out_lines.append(f"{m.group(1)}{self.rule_str(name_rule, m.group(2))}")
                continue
            m = _RAG_MEMBER_RE.match(line)
            if m and name_rule:
                out_lines.append(f"{m.group(1)}{self.rule_str(name_rule, m.group(2))}"
                                 f"{m.group(3)}")
                continue
            m = _RAG_TRIPLE_RE.match(line)
            if m and name_rule:
                subj = self.rule_str(name_rule, m.group(2))
                obj = self.rule_str(name_rule, m.group(4))
                rest = self.scan_str(m.group(5)) if m.group(5) else ""
                out_lines.append(f"{m.group(1)}{subj} \u2192 {m.group(3)} \u2192 {obj}{rest}")
                continue
            res = self.scan_str(line)
            out_lines.append(line if res is DROP else str(res))
        return "\n".join(out_lines)

    def whole_entity(self, value: str) -> bool:
        """Does one active detector match the entire value? Its refined
        strategy then applies even when that is ``keep`` (``0.0.0.0/0``
        under ``source`` stays as is); inactive detectors (a bare UUID when
        ``uuid: keep``) do not count, so the rule's entity applies."""
        r = self.r
        hit = r._full_cache.get(value)
        if hit is None:
            hit = any(m.start == 0 and m.end == len(value)
                      for m in r.scanner.scan(value, r.min_confidence))
            if len(r._full_cache) > 100_000:
                r._full_cache.clear()
            r._full_cache[value] = hit
        return hit

    def name_pass(self, value: Any) -> Any:
        """Replace values pseudonymised through key rules where they appear
        elsewhere in the same payload: inside free text (strings with
        whitespace, ``->`` or commas), and as exact whole values (a one-node
        path summary). Tag values and enum-like keys (``type``, ``status``...)
        are left alone."""
        if not self.issued or len(self.issued) > _NAME_PASS_LIMIT:
            return value
        table = self.issued
        names = sorted(table, key=len, reverse=True)
        rx = re.compile(r"(?<![\w.\-/:@])(?:" + "|".join(re.escape(n) for n in names)
                        + r")(?![\w\-@]|\.\w)")
        count = 0

        def sub(m: re.Match[str]) -> str:
            nonlocal count
            count += 1
            return table[m.group(0)]

        def fix(text: str, key: str | None) -> str:
            if key is not None and key in _ENUMISH_KEYS:
                return text
            hit = table.get(text)
            if hit is not None:
                nonlocal count
                count += 1
                return hit
            if " " not in text and "," not in text and "->" not in text and "\n" not in text:
                return text
            return rx.sub(sub, text)

        def walk(v: Any, key: str | None) -> Any:
            if isinstance(v, str):
                return fix(v, key)
            if isinstance(v, dict):
                out = {}
                for k, v2 in v.items():
                    nk = self.norm(k)[0] if isinstance(k, str) else ""
                    if k in self.r.skip_keys or nk in TAG_CONTAINER_KEYS:
                        out[k] = v2
                    else:
                        out[k] = walk(v2, nk)
                return out
            if isinstance(v, list):
                return [walk(x, key) for x in v]
            return v

        out = walk(value, None)
        if count:
            self.bump("pseudonymize", "identifier_mention", count)
        return out

    def counted(self, strat: Strategy, entity: str, value: Any) -> Any:
        self.bump(strat.kind, entity)
        return value

    def walk_forced(self, value: Any, entity: str, strat: Strategy) -> Any:
        """Everything under a sensitive key is the entity."""
        if isinstance(value, str):
            return self.whole(value, entity, strat) if value else value
        if isinstance(value, dict):
            out = {}
            for k, v in value.items():
                res = self.walk_forced(v, entity, strat)
                if res is not DROP:
                    out[k] = res
            return out
        if isinstance(value, (list, tuple)):
            return [x for x in (self.walk_forced(v, entity, strat) for v in value) if x is not DROP]
        if isinstance(value, (int, float)) and not isinstance(value, bool):
            return self.whole(str(value), entity, strat)
        return value

    def whole(self, text: str, entity: str, strat: Strategy) -> Any:
        if strat.kind == "keep":
            return self.scan_str(text)
        out = self.r.replace(text, entity, strat, self.vault, self.ns)
        self.bump(strat.kind, entity)
        return out

    # -- tags ------------------------------------------------------------

    def tag_value(self, tag_key: Any, value: Any) -> Any:
        if not isinstance(value, str) or not value:
            return self.walk(value, ())
        nk = normalize_key(str(tag_key)) if tag_key is not None else ""
        if nk in self.r.tag_key_allowlist:
            return self.scan_str(value)
        entity = "person" if nk and self.r._person_rx.search(nk) else "tag_value"
        chain = ("person", "pii") if entity == "person" else ("tag_value", "free_text")
        strat = self.r.resolve(chain)
        if strat.kind == "keep":
            return self.scan_str(value)
        return self.whole(value, entity, strat)

    def walk_tags(self, value: Any) -> Any:
        if isinstance(value, dict):
            out = {}
            for k, v in value.items():
                new_k = self.scan_str(k) if isinstance(k, str) and self.r.scan_keys else k
                if new_k is DROP:
                    continue
                res = self.tag_value(k, v)
                if res is not DROP:
                    out[new_k] = res
            return out
        if isinstance(value, (list, tuple)):
            out_list = []
            for item in value:
                if isinstance(item, dict):
                    kk = next((k for k in item if str(k).lower() == "key"), None)
                    vk = next((k for k in item if str(k).lower() == "value"), None)
                    if kk is not None and vk is not None:
                        new_item = dict(item)
                        new_item[kk] = self.scan_str(item[kk]) if isinstance(item[kk], str) \
                            else item[kk]
                        res = self.tag_value(item[kk], item[vk])
                        if res is DROP:
                            continue
                        new_item[vk] = res
                        out_list.append(new_item)
                        continue
                res = self.walk(item, ())
                if res is not DROP:
                    out_list.append(res)
            return out_list
        return self.walk(value, ())

    # -- strings ---------------------------------------------------------

    def scan_str(self, text: str) -> Any:
        r = self.r
        scanner = r.scanner
        if len(text) < scanner.min_length or not scanner.detectors:
            return text
        ck = (self.cache_key, text)
        hit = r._str_cache.get(ck)
        if hit is not None:
            out, counts = hit
            for kind, entity in counts:
                self.bump(kind, entity)
            return out
        matches = scanner.scan(text, r.min_confidence)
        counts: list[tuple[str, str]] = []
        if not matches:
            out: Any = text
        else:
            pieces: list[str] = []
            pos = 0
            out = None
            for m in matches:
                strat = r.resolve(m.lookup_chain)
                if strat.kind == "keep":
                    continue
                rep = r.replace(m.text, m.entity, strat, self.vault, self.ns)
                counts.append((strat.kind, m.entity))
                if rep is DROP:
                    out = DROP
                    break
                pieces.append(text[pos : m.start])
                pieces.append(rep)
                pos = m.end
            if out is None:
                pieces.append(text[pos:])
                out = "".join(pieces) if counts else text
        if len(r._str_cache) >= r.cache_size:
            r._str_cache.clear()
        r._str_cache[ck] = (out, tuple(counts))
        for kind, entity in counts:
            self.bump(kind, entity)
        return out


# ---------------------------------------------------------------------------
# Strategy helpers
# ---------------------------------------------------------------------------


def _mask(text: str, opts: dict[str, Any]) -> str:
    char = str(opts.get("char", "*"))[:1] or "*"
    first = int(opts.get("keep_first", 0))
    last = int(opts.get("keep_last", 4))
    preserve = opts.get("preserve", "")  # characters left unmasked, e.g. "-.@"
    n = len(text)
    if first + last >= n:
        first, last = 0, 0 if n <= 4 else min(last, n // 4)
    body = "".join(c if c in preserve else char for c in text[first : n - last])
    out = text[:first] + body + (text[n - last :] if last else "")
    max_len = opts.get("max_length")
    if max_len and len(out) > int(max_len):
        out = out[: int(max_len)]
    return out


def _bucket(value: float, opts: dict[str, Any]) -> str:
    size = float(opts.get("bucket", opts.get("bucket_size", 10)))
    if size <= 0:
        return str(value)
    lo = (value // size) * size
    hi = lo + size
    fmt = (lambda x: str(int(x))) if size.is_integer() else (lambda x: f"{x:g}")
    return f"{fmt(lo)}-{fmt(hi)}"


_TS_GRANULARITY = {"year": 4, "month": 7, "day": 10, "date": 10, "hour": 13, "minute": 16}


def generalize(text: str, entity: str, opts: dict[str, Any] | None = None) -> str:
    """Coarsen one value (see the module docstring)."""
    opts = opts or {}
    root = entity
    while root in ENTITY_PARENTS:
        root = ENTITY_PARENTS[root]
    if root in ("ip_address", "cidr"):
        try:
            if "/" in text:
                net = ipaddress.ip_network(text, strict=False)
            else:
                net = ipaddress.ip_network(text)
            target = int(opts.get("ipv4_prefix" if net.version == 4 else "ipv6_prefix",
                                  24 if net.version == 4 else 48))
            if entity.startswith("special"):
                return text
            if net.prefixlen > target:
                net = net.supernet(new_prefix=target)
            return str(net)
        except ValueError:
            return f"<{entity}>"
    if root == "timestamp":
        return text[: _TS_GRANULARITY.get(str(opts.get("granularity", "day")), 10)]
    if root == "email":
        return "*@" + text.rpartition("@")[2]
    if root == "hostname":
        labels = text.split(".")
        keep = int(opts.get("keep_labels", 2))
        return "*." + ".".join(labels[-keep:]) if len(labels) > keep else text
    if root == "aws_arn":
        parts = text.split(":", 5)
        if len(parts) == 6:
            res = parts[5]
            typ = re.split(r"[/:]", res, maxsplit=1)
            res_out = f"{typ[0]}{res[len(typ[0])]}*" if len(typ) > 1 else "*"
            return ":".join(parts[:4] + ["*" if parts[4] else "", res_out])
    if root == "azure_resource_id":
        segs = text.split("/")
        out, prev, mode = [], "", ""
        for seg in segs:
            low = seg.lower()
            if prev in ("subscriptions", "resourcegroups", "tenants") or mode == "name":
                out.append("*")
                mode = "type" if mode == "name" else mode
            elif low == "providers":
                out.append(seg)
                mode = "namespace"
            elif mode == "namespace":
                out.append(seg)
                mode = "type"
            elif mode == "type":
                out.append(seg)
                mode = "name"
            else:
                out.append(seg)
            prev = low
        return "/".join(out)
    if root == "gcp_resource_name":
        m = re.match(r"^(//[^/]+/)?(.*)$", text, re.S)
        head, rest = ((m.group(1) or ""), m.group(2)) if m else ("", text)
        segs = rest.split("/")
        out = [
            s if i % 2 == 0 or segs[i - 1].lower() in ("zones", "regions", "locations") else "*"
            for i, s in enumerate(segs)
        ]
        return head + "/".join(out)
    if text.lstrip("-").replace(".", "", 1).isdigit() and "bucket" in opts:
        try:
            return _bucket(float(text), opts)
        except ValueError:  # pragma: no cover
            pass
    return f"<{entity}>"


def _key_rule_from_config(spec: dict[str, Any]) -> KeyRule:
    return KeyRule(
        name=str(spec["name"]),
        entity=str(spec.get("entity", spec["name"])),
        pattern=str(spec["pattern"]),
        category=str(spec.get("category", "secret")),
        exclude=spec.get("exclude"),
        requires_sibling=frozenset(spec.get("requires_sibling", ())),
        subtree=bool(spec.get("subtree", False)),
        scalars=bool(spec.get("scalars", False)),
        defer=bool(spec.get("defer", False)),
        map_keys=bool(spec.get("map_keys", False)),
        confidence=float(spec.get("confidence", 0.9)),
    )


class SecretArgumentGuard:
    """Input-side DLP: refuse (or scrub) secrets in tool arguments.

    Credentials must never travel through the model (MCP security best
    practice: "no token passthrough"; gateways such as Docker's
    ``--block-secrets`` do the same). Detects secret-category entities
    (private keys, passwords, API tokens, JWTs...) and values under
    sensitive argument names.

    Args:
        action: ``"reject"`` (raise :class:`~cloudg.mcp.core.InvalidArgumentsError`)
            or ``"redact"`` (replace and continue).
        categories: Detector categories treated as secrets.
        min_confidence: Ignore weaker detectors (the high-entropy
            heuristic scores 0.5 and is skipped by default).
    """

    name = "guard_secrets"

    def __init__(
        self,
        *,
        action: str = "reject",
        categories: Iterable[str] = ("secret",),
        min_confidence: float = 0.8,
        detectors: DetectorRegistry | None = None,
        custom_detectors: Iterable[dict[str, Any] | Detector] = (),
    ) -> None:
        if action not in ("reject", "redact"):
            raise ValueError("action must be 'reject' or 'redact'")
        self.action = action
        self.redactor = Redactor(
            {c: "redact" for c in categories},
            detectors=detectors,
            custom_detectors=custom_detectors,
            key_rules=["sensitive_key"],
            min_confidence=min_confidence,
            scan_keys=False,
            tags=False,
        )

    def apply(self, value: Any, ctx: TransformContext) -> Any:
        probe = TransformContext(principal=ctx.principal, spec=ctx.spec, kind=ctx.kind,
                                 direction=ctx.direction, vault=ctx.vault)
        out = self.redactor.apply(value, probe)
        found = sorted(probe.report.get("redacted", {}))
        if not found:
            return value
        if self.action == "reject":
            from cloudg.mcp.core import InvalidArgumentsError

            raise InvalidArgumentsError(
                "Arguments appear to contain secrets (" + ", ".join(found) + "); refusing to "
                "process them. Pass resource references, never credentials.",
                data={"entities": found},
            )
        sec = ctx.report.setdefault("redacted_arguments", {})
        for e, n in probe.report["redacted"].items():
            sec[e] = sec.get(e, 0) + n
        return out
