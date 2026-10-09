"""One pass of the :class:`~cloudg.mcp.transforms.redaction.Redactor` over
a value: traversal, key rules, tags, RAG chunk text, the name-mention pass
and string scanning. Kept apart from the redactor's configuration so each
piece stays small."""

from __future__ import annotations

import json
import logging
import re
from typing import TYPE_CHECKING, Any

from cloudg.mcp.transforms.base import TransformContext
from cloudg.mcp.transforms.builtin_rules import SHAPED_ENTITIES, TAG_CONTAINER_KEYS
from cloudg.mcp.transforms.entities import EntityMatch, KeyRule, normalize_key
from cloudg.mcp.transforms.strategies import DROP, REPORT_KEY, Strategy, _chain, bucket

if TYPE_CHECKING:  # pragma: no cover
    from cloudg.mcp.transforms.redaction import Redactor

logger = logging.getLogger("cloudg.mcp")

#: Entities whose real values are also replaced in free text of the same
#: payload (``"summary": "web-1 -> sg-app"``) once a key rule pseudonymised
#: them elsewhere.
_NO_MENTION_ENTITIES = frozenset({"sensitive_field", "tag_value", "person", "rag_chunk_id"})
_NAME_PASS_LIMIT = 5000
#: Keys whose values are vocabulary, never names (left alone by the mention pass).
_ENUMISH_KEYS = frozenset(
    {
        "type",
        "asset_type",
        "resource_type",
        "provider",
        "region",
        "status",
        "severity",
        "predicate",
        "edge_type",
        "relationship",
        "kind",
        "chunk_type",
        "metric",
        "mode",
        "format",
        "category",
        "direction",
        "protocol",
        "max_severity",
        "severity_max",
        "relation_group",
        "feature_set",
        "env",
        "environment",
        "stage",
        "tier",
        "strategy",
        "applies_to",
        "entity",
        "entity_type",
        "decision",
    }
)
_RAG_FIELD_RE = re.compile(r"^(Resource|Account|Tags): ?(.*)$")
_RAG_REL_RE = re.compile(r"^(\s+[→←] [A-Z0-9_]+: )(.+)$")
_RAG_PRED_RE = re.compile(r"[A-Z0-9_]+")
_ARROW = " → "

_ENUM_KEYS: frozenset[str] | None = None
_ASSET_TYPE_NAMES: frozenset[str] | None = None


def _asset_type_names() -> frozenset[str]:
    global _ASSET_TYPE_NAMES
    if _ASSET_TYPE_NAMES is None:
        try:
            from cloudg.schema.models import AssetType

            _ASSET_TYPE_NAMES = frozenset(
                {t.value for t in AssetType} | {t.name for t in AssetType}
            )
        except Exception:  # pragma: no cover
            logger.debug("asset types unavailable; asset-type sibling check off", exc_info=True)
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

            for enum_name in (
                "AssetType",
                "EdgeType",
                "Severity",
                "CloudProvider",
                "ComplianceStatus",
            ):
                for member in getattr(models, enum_name, None) or ():
                    names.add(member.name)
                    names.add(str(member.value))
        except Exception:  # pragma: no cover - schema always importable in cloudg
            logger.debug("cloudg enums unavailable; enum-key exemption off", exc_info=True)
        _ENUM_KEYS = frozenset(n for n in names if n and n == n.upper())
    return _ENUM_KEYS


def _split_member(line: str) -> tuple[str, str, str] | None:
    """``"  • name (TYPE)"`` -> ``("  • ", "name", " (TYPE)")``."""
    body = line.lstrip()
    indent = line[: len(line) - len(body)]
    if not indent or not body.startswith("• ") or not body.endswith(")"):
        return None
    rest = body[2:]
    cut = rest.rfind(" (")
    if cut < 1 or not _RAG_PRED_RE.fullmatch(rest[cut + 2 : -1]):
        return None
    return indent + "• ", rest[:cut], rest[cut:]


def _split_triple(line: str) -> tuple[str, str, str, str, str] | None:
    """``"  subj → PRED → obj (note)"`` -> its five parts (indent,
    subject, predicate, object, trailing note), parsed without a
    backtracking regex. The subject ends at the first arrow followed by a
    predicate and a second arrow; the note is an optional trailing
    parenthesised part."""
    body = line.lstrip()
    indent = line[: len(line) - len(body)]
    if not indent:
        return None
    pos = body.find(_ARROW, 1)
    while pos > 0:
        after = body[pos + len(_ARROW) :]
        pm = _RAG_PRED_RE.match(after)
        if pm and after[pm.end() :].startswith(_ARROW) and len(after) > pm.end() + len(_ARROW):
            obj = after[pm.end() + len(_ARROW) :]
            note = ""
            cut = obj.find(" (", 1) if obj.endswith(")") else -1
            if cut > 0:
                obj, note = obj[:cut], obj[cut:]
            return indent, body[:pos], pm.group(0), obj, note
        pos = body.find(_ARROW, pos + 1)
    return None


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
        key = (REPORT_KEY[kind], entity)
        self.counts[key] = self.counts.get(key, 0) + n

    def flush(self) -> None:
        report = self.ctx.report
        for (section, entity), n in self.counts.items():
            sec = report.setdefault(section, {})
            sec[entity] = sec.get(entity, 0) + n

    # -- traversal -------------------------------------------------------

    def walk(self, value: Any, _path: tuple[Any, ...] = ()) -> Any:
        if isinstance(value, str):
            return self.scan_str(value)
        if isinstance(value, dict):
            return self.walk_dict(value)
        if isinstance(value, (list, tuple)):
            return self.walk_items(value)
        return value

    def walk_items(self, items: Any) -> list[Any]:
        out = []
        for item in items:
            res = self.walk(item)
            if res is not DROP:
                out.append(res)
        return out

    def norm(self, key: str) -> tuple[str, list[KeyRule]]:
        """Normalised key and the key rules matching it (memoised per raw key)."""
        hit = self.r._key_cache.get(key)
        if hit is None:
            nk = normalize_key(key)
            rules = self.r._rules_for(nk)
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
        siblings: list[frozenset[str] | None] = [None]
        for k, v in value.items():
            if k in r.skip_keys:
                out[k] = v
                continue
            if isinstance(k, str):
                nk, rules = self.norm(k)
                new_k = self.scan_str(k) if r.scan_keys else k
                if new_k is DROP:
                    continue
            else:
                nk, rules, new_k = "", [], k
            rule = self.pick_rule(rules, value, siblings) if rules else None
            if rule is not None:
                res = self.apply_rule(rule, v)
            elif r.tags and nk in TAG_CONTAINER_KEYS:
                res = self.walk_tags(v)
            else:
                res = self.walk(v)
            if res is not DROP:
                out[new_k] = res
        return out

    def pick_rule(
        self, rules: list[KeyRule], value: dict[Any, Any], siblings: list[frozenset[str] | None]
    ) -> KeyRule | None:
        """First rule whose ``requires_sibling`` (if any) is met by ``value``.
        ``siblings`` is a one-slot cache shared by the keys of one dict."""
        for candidate in rules:
            if candidate.requires_sibling:
                if siblings[0] is None:
                    siblings[0] = self.siblings(value)
                if not (candidate.requires_sibling & siblings[0]):
                    continue
            return candidate
        return None

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
        if isinstance(value, bool) or value is None:
            return value
        if isinstance(value, (int, float)):
            return self.rule_number(rule, value)
        return self.rule_container(rule, value)

    def rule_number(self, rule: KeyRule, value: float) -> Any:
        if not rule.scalars:
            return value
        strat = self.r._rule_strategy(rule)
        if strat.kind == "generalize":
            return self.counted(strat, rule.entity, bucket(value, strat.options))
        return self.rule_str(rule, str(value))

    def rule_container(self, rule: KeyRule, value: Any) -> Any:
        is_seq = isinstance(value, (list, tuple))
        if rule.subtree and (is_seq or isinstance(value, dict)):
            strat = self.r._rule_strategy(rule)
            if strat.kind == "drop":
                self.bump("drop", rule.entity)
                return DROP
            return self.walk_forced(value, rule.entity, strat)
        if rule.map_keys and isinstance(value, dict):
            return self.rule_map_keys(rule, value)
        if rule.defer and is_seq:
            out = []
            for item in value:
                nested = isinstance(item, (str, list, tuple))
                res = self.apply_rule(rule, item) if nested else self.walk(item)
                if res is not DROP:
                    out.append(res)
            return out
        return self.walk(value)

    def rule_map_keys(self, rule: KeyRule, value: dict[Any, Any]) -> dict[Any, Any]:
        out_map: dict[Any, Any] = {}
        for k, v in value.items():
            nk = self.rule_str(rule, k) if isinstance(k, str) and k else k
            if nk is DROP:
                continue
            res = self.walk(v)
            if res is not DROP:
                out_map[nk] = res
        return out_map

    def rule_str(self, rule: KeyRule, value: str) -> Any:
        """A string under a key rule: detectors first for ``defer`` rules,
        then the rule's (possibly shape-chosen) entity."""
        if rule.entity == "cloud_account" and " -> " in value:
            parts = [self.rule_str(rule, p) for p in value.split(" -> ")]
            if any(p is DROP for p in parts):
                return DROP
            return " -> ".join(str(p) for p in parts)
        matches = None
        if rule.defer:
            whole, matches = self.whole_entity_scan(value)
            if whole:
                return self.scan_str(value, matches)
        entity = rule.entity
        shaper = SHAPED_ENTITIES.get(entity)
        if shaper is not None:
            entity = shaper(value)
            strat = self.r.resolve(_chain(entity, rule.entity) + (rule.name, rule.category))
        else:
            strat = self.r._rule_strategy(rule)
        out = self.whole(value, entity, strat, matches)
        if (
            strat.kind == "pseudonymize"
            and isinstance(out, str)
            and out != value
            and len(value) >= 3
            and entity not in _NO_MENTION_ENTITIES
        ):
            self.issued[value] = out
        return out

    def whole_entity_scan(self, value: str) -> tuple[bool, list[EntityMatch] | None]:
        """Does one active detector match the entire value? Its refined
        strategy then applies even when that is ``keep`` (``0.0.0.0/0`` under
        ``source`` stays as is); inactive detectors (a bare UUID when
        ``uuid: keep``) do not count, so the rule's entity applies. Also
        returns the detector matches when this call scanned the value, so
        :meth:`scan_str` does not scan it a second time (``None`` when the
        answer came from the cache)."""
        r = self.r
        hit = r._full_cache.get(value)
        if hit is not None:
            return hit, None
        matches = r.scanner.scan(value, r.min_confidence)
        whole = any(m.start == 0 and m.end == len(value) for m in matches)
        if len(r._full_cache) > 100_000:
            r._full_cache.clear()
        r._full_cache[value] = whole
        return whole, matches

    # -- RAG chunk text ----------------------------------------------------

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
            res = self.rag_field(line, name_rule, acct_rule)
            if res is None and name_rule is not None:
                res = self.rag_structured(line, name_rule)
            if res is None:
                scanned = self.scan_str(line)
                res = line if scanned is DROP else str(scanned)
            out_lines.append(res)
        return "\n".join(out_lines)

    def rag_field(self, line: str, name_rule: Any, acct_rule: Any) -> str | None:
        m = _RAG_FIELD_RE.match(line)
        if not m:
            return None
        label, val = m.group(1), m.group(2)
        if label == "Resource" and name_rule and val:
            return f"Resource: {self.rule_str(name_rule, val)}"
        if label == "Account" and acct_rule and val:
            return f"Account: {self.rule_str(acct_rule, val)}"
        if label == "Tags" and val.startswith("{"):
            try:
                tags = json.loads(val)
            except ValueError:
                return None
            if isinstance(tags, dict):
                return f"Tags: {json.dumps(self.walk_tags(tags))}"
        return None

    def rag_structured(self, line: str, name_rule: KeyRule) -> str | None:
        m = _RAG_REL_RE.match(line)
        if m:
            return f"{m.group(1)}{self.rule_str(name_rule, m.group(2))}"
        member = _split_member(line)
        if member is not None:
            head, name, tail = member
            return f"{head}{self.rule_str(name_rule, name)}{tail}"
        triple = _split_triple(line)
        if triple is not None:
            indent, subj, pred, obj, note = triple
            subj_out = self.rule_str(name_rule, subj)
            obj_out = self.rule_str(name_rule, obj)
            rest = self.scan_str(note) if note else ""
            return f"{indent}{subj_out}{_ARROW}{pred}{_ARROW}{obj_out}{rest}"
        return None

    # -- mentions ----------------------------------------------------------

    def name_pass(self, value: Any) -> Any:
        """Replace values pseudonymised through key rules where they appear
        elsewhere in the same payload (see :class:`_MentionPass`)."""
        if not self.issued or len(self.issued) > _NAME_PASS_LIMIT:
            return value
        mp = _MentionPass(self)
        out = mp.walk(value, None)
        if mp.count:
            self.bump("pseudonymize", "identifier_mention", mp.count)
        return out

    # -- forced / whole values ---------------------------------------------

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

    def whole(
        self, text: str, entity: str, strat: Strategy, matches: list[EntityMatch] | None = None
    ) -> Any:
        if strat.kind == "keep":
            return self.scan_str(text, matches)
        out = self.r.replace(text, entity, strat, self.vault, self.ns)
        self.bump(strat.kind, entity)
        return out

    # -- tags ------------------------------------------------------------

    def tag_value(self, tag_key: Any, value: Any) -> Any:
        if not isinstance(value, str) or not value:
            return self.walk(value)
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
                res = self.tag_item(item)
                if res is not DROP:
                    out_list.append(res)
            return out_list
        return self.walk(value)

    def tag_item(self, item: Any) -> Any:
        """One element of a ``[{"Key": ..., "Value": ...}]`` tag list."""
        if not isinstance(item, dict):
            return self.walk(item)
        kk = next((k for k in item if str(k).lower() == "key"), None)
        vk = next((k for k in item if str(k).lower() == "value"), None)
        if kk is None or vk is None:
            return self.walk(item)
        new_item = dict(item)
        new_item[kk] = self.scan_str(item[kk]) if isinstance(item[kk], str) else item[kk]
        res = self.tag_value(item[kk], item[vk])
        if res is DROP:
            return DROP
        new_item[vk] = res
        return new_item

    # -- strings ---------------------------------------------------------

    def scan_str(self, text: str, matches: list[EntityMatch] | None = None) -> Any:
        """Rewrite the entities found in ``text``. ``matches`` (from
        :meth:`whole_entity_scan`) saves a second scan of the same text."""
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
        if matches is None:
            matches = scanner.scan(text, r.min_confidence)
        out, counts = self.rewrite(text, matches)
        if len(r._str_cache) >= r.cache_size:
            r._str_cache.clear()
        r._str_cache[ck] = (out, tuple(counts))
        for kind, entity in counts:
            self.bump(kind, entity)
        return out

    def rewrite(self, text: str, matches: list[EntityMatch]) -> tuple[Any, list[tuple[str, str]]]:
        """Apply the strategy of each match; ``DROP`` if one says so."""
        r = self.r
        counts: list[tuple[str, str]] = []
        pieces: list[str] = []
        pos = 0
        for m in matches:
            strat = r.resolve(m.lookup_chain)
            if strat.kind == "keep":
                continue
            rep = r.replace(m.text, m.entity, strat, self.vault, self.ns)
            counts.append((strat.kind, m.entity))
            if rep is DROP:
                return DROP, counts
            pieces.append(text[pos : m.start])
            pieces.append(rep)
            pos = m.end
        if not counts:
            return text, counts
        pieces.append(text[pos:])
        return "".join(pieces), counts


class _MentionPass:
    """Replace values pseudonymised through key rules where they appear
    elsewhere in the same payload: inside free text (strings with
    whitespace, ``->`` or commas), and as exact whole values (a one-node
    path summary). Tag values and enum-like keys (``type``, ``status``...)
    are left alone."""

    def __init__(self, run: _Run) -> None:
        self.run = run
        self.table = run.issued
        names = sorted(self.table, key=len, reverse=True)
        self.rx = re.compile(
            r"(?<![\w.\-/:@])(?:" + "|".join(re.escape(n) for n in names) + r")(?![\w\-@]|\.\w)"
        )
        self.count = 0

    def _sub(self, m: re.Match[str]) -> str:
        self.count += 1
        return self.table[m.group(0)]

    def fix(self, text: str, key: str | None) -> str:
        if key is not None and key in _ENUMISH_KEYS:
            return text
        hit = self.table.get(text)
        if hit is not None:
            self.count += 1
            return hit
        if " " not in text and "," not in text and "->" not in text and "\n" not in text:
            return text
        return self.rx.sub(self._sub, text)

    def walk(self, v: Any, key: str | None) -> Any:
        if isinstance(v, str):
            return self.fix(v, key)
        if isinstance(v, dict):
            out = {}
            run = self.run
            for k, v2 in v.items():
                nk = run.norm(k)[0] if isinstance(k, str) else ""
                if k in run.r.skip_keys or nk in TAG_CONTAINER_KEYS:
                    out[k] = v2
                else:
                    out[k] = self.walk(v2, nk)
            return out
        if isinstance(v, list):
            return [self.walk(x, key) for x in v]
        return v
