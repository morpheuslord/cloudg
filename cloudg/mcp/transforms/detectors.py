"""Sensitive-entity detectors for the cloudg MCP privacy transforms.

The design follows the analyzer / anonymizer split used by Microsoft
Presidio and the infoType model of Google Cloud DLP: a *detector* only
finds spans of a given *entity type* (``aws_account_id``,
``private_key``, ``public_ip``...) with a confidence score; what happens to
a span (redact, mask, hash, pseudonymise, generalise, drop, keep) is
decided separately by the :class:`~cloudg.mcp.transforms.redaction.Redactor`
from the active policy.

Two kinds of detection exist:

* Content detectors (:class:`Detector`): a regular expression plus an
  optional validator, run over string values. A validator can reject a
  candidate (``False``) or refine its entity type by returning a string (the IP
  detectors return ``private_ip`` / ``public_ip`` / ``special_ip`` /
  ``private_cidr``...).
* Key rules (:class:`KeyRule`): the *field name* decides. Anything
  under ``password`` / ``client_secret`` / ``connection_string`` /
  ``user_data``... is a secret whatever it looks like; ``subscription_id``
  holds an Azure subscription GUID; ``tags`` hold free-form (possibly
  personal) values.

Performance matters (datasets have 50k+ assets): regexes are compiled once,
each detector carries cheap lowercase substring *hints* so its regex only
runs on strings that could match, and the redactor caches per-string
results.

Custom detectors can be declared in a policy::

    detectors:
      - name: employee_id
        entity: employee_id
        category: pii
        pattern: "\\bEMP-\\d{6}\\b"
        confidence: 0.9
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field, replace
from typing import Any, Iterable, Iterator

from cloudg.mcp.transforms.builtin_rules import (
    BUILTIN_DETECTORS,
    BUILTIN_KEY_RULES,
    PERSON_TAG_PATTERN,
    SAFE_KEY_PATTERN,
    SENSITIVE_KEY_PATTERN,
    SHAPED_ENTITIES,
    TAG_CONTAINER_KEYS,
)
from cloudg.mcp.transforms.entities import (
    CATEGORIES,
    ENTITY_PARENTS,
    Detector,
    EntityMatch,
    KeyRule,
    Validator,
    _secret_value,
    account_entity,
    classify_ip_text,
    ip_class,
    looks_like_secret,
    normalize_key,
    ref_entity,
    shannon_entropy,
)


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------


@dataclass
class CompiledScanner:
    """Scans strings with a fixed set of detectors.

    Python's ``re`` does not optimise large alternations, so instead of one
    combined regex each detector carries cheap lowercase substring
    *hints* (``"arn:"``, ``"@"``, ``"://"``...): a detector's regex only runs
    when one of its hints occurs in the string. Matches are then merged
    leftmost-first, earlier detectors winning ties, without overlaps.
    """

    detectors: list[Detector]
    singles: list[tuple[Detector, re.Pattern[str]]] = field(default_factory=list)
    min_length: int = 1
    _always: list[int] = field(default_factory=list)
    _hinted: list[tuple[int, tuple[frozenset[str], tuple[str, ...]]]] = field(default_factory=list)

    def __post_init__(self) -> None:
        for i, (det, _) in enumerate(self.singles):
            if det.hints:
                chars = frozenset(h for h in det.hints if len(h) == 1)
                multi = tuple(h for h in det.hints if len(h) > 1)
                self._hinted.append((i, (chars, multi)))
            else:
                self._always.append(i)

    def _select(self, text: str) -> list[int]:
        """Indexes of the detectors whose hints occur in ``text``, in
        priority order. One-character hints are tested against the set of
        characters of the text (one pass), longer ones as substrings."""
        if not self._hinted:
            return list(self._always)
        lower = text.lower()
        present = set(lower)
        selected = list(self._always)
        for i, (chars, multi) in self._hinted:
            if chars and not chars.isdisjoint(present):
                selected.append(i)
                continue
            for h in multi:
                if h in lower:
                    selected.append(i)
                    break
        if self._always and len(selected) > 1:
            selected.sort()
        return selected

    def _matches(
        self, prio: int, text: str, cands: list[tuple[int, int, int, EntityMatch]]
    ) -> None:
        """Append the validated matches of detector ``prio`` to ``cands``."""
        det, rx = self.singles[prio]
        g = det.group
        validator = det.validator
        for m in rx.finditer(text):
            start, end = (m.start(g), m.end(g)) if g else (m.start(), m.end())
            if start < 0:
                continue
            entity = det.entity
            if validator is not None:
                verdict = validator(text[start:end])
                if not verdict:
                    continue
                if isinstance(verdict, str):
                    entity = verdict
            em = EntityMatch(
                start, end, text[start:end], entity, det.name, det.category, det.confidence
            )
            cands.append((m.start(), prio, m.end(), em))

    def scan(self, text: str, min_confidence: float = 0.0) -> list[EntityMatch]:
        """Non-overlapping matches, left to right."""
        n = len(text)
        if n < self.min_length or not self.singles:
            return []
        cands: list[tuple[int, int, int, EntityMatch]] = []
        for prio in self._select(text):
            det = self.singles[prio][0]
            if n >= det.min_length and det.confidence >= min_confidence:
                self._matches(prio, text, cands)
        if len(cands) <= 1:
            return [c[3] for c in cands]
        cands.sort(key=lambda c: (c[0], c[1]))
        out: list[EntityMatch] = []
        consumed = 0
        for mstart, _prio, mend, em in cands:
            if mstart < consumed or em.start < consumed:
                continue
            out.append(em)
            consumed = max(mend, em.end)
        return out


class DetectorRegistry:
    """Named collection of :class:`Detector` and :class:`KeyRule`.

    ``DetectorRegistry.default()`` holds the built-ins; :meth:`with_custom`
    returns a copy extended with policy-declared detectors.
    """

    def __init__(
        self,
        detectors: Iterable[Detector] = (),
        key_rules: Iterable[KeyRule] = (),
    ) -> None:
        self._detectors: dict[str, Detector] = {}
        self._key_rules: dict[str, KeyRule] = {}
        for d in detectors:
            self.add(d)
        for r in key_rules:
            self.add_key_rule(r)
        self._scanners: dict[tuple[str, ...], CompiledScanner] = {}

    @classmethod
    def default(cls) -> "DetectorRegistry":
        return cls(BUILTIN_DETECTORS, BUILTIN_KEY_RULES)

    # -- mutation --------------------------------------------------------

    def add(self, detector: Detector, *, replace_existing: bool = True) -> None:
        if detector.name in self._detectors and not replace_existing:
            raise ValueError(f"Duplicate detector {detector.name!r}")
        re.compile(detector.pattern, detector.flags)  # fail fast on bad patterns
        self._detectors[detector.name] = detector
        self._scanners = {}

    def add_key_rule(self, rule: KeyRule) -> None:
        self._key_rules[rule.name] = rule

    def remove(self, name: str) -> None:
        self._detectors.pop(name, None)
        self._key_rules.pop(name, None)
        self._scanners = {}

    def copy(self) -> "DetectorRegistry":
        return DetectorRegistry(self._detectors.values(), self._key_rules.values())

    def with_custom(self, specs: Iterable[dict[str, Any] | Detector]) -> "DetectorRegistry":
        out = self.copy()
        for spec in specs:
            out.add(spec if isinstance(spec, Detector) else detector_from_config(spec))
        return out

    def disable(self, names: Iterable[str]) -> "DetectorRegistry":
        out = self.copy()
        for n in names:
            if n in out._detectors:
                out._detectors[n] = replace(out._detectors[n], enabled=False)
        return out

    # -- access ----------------------------------------------------------

    @property
    def detectors(self) -> list[Detector]:
        return list(self._detectors.values())

    @property
    def key_rules(self) -> list[KeyRule]:
        return list(self._key_rules.values())

    def get(self, name: str) -> Detector | None:
        return self._detectors.get(name)

    def __iter__(self) -> Iterator[Detector]:
        return iter(self._detectors.values())

    def __len__(self) -> int:
        return len(self._detectors)

    def entities(self) -> set[str]:
        out = {d.entity for d in self._detectors.values()}
        out |= {r.entity for r in self._key_rules.values()}
        return out | set(ENTITY_PARENTS)

    def scanner(self, names: Iterable[str] | None = None) -> CompiledScanner:
        """Compile (and cache) a combined scanner for the named detectors
        (all enabled ones when ``names`` is None)."""
        if names is None:
            selected = [d for d in self._detectors.values() if d.enabled]
        else:
            wanted = set(names)
            selected = [d for d in self._detectors.values() if d.name in wanted and d.enabled]
        key = tuple(d.name for d in selected)
        cached = self._scanners.get(key)
        if cached is not None:
            return cached
        scanner = CompiledScanner(
            detectors=selected,
            singles=[(d, d.compile()) for d in selected],
            min_length=min((d.min_length for d in selected), default=1),
        )
        self._scanners[key] = scanner
        return scanner

    def scan(self, text: str, min_confidence: float = 0.0) -> list[EntityMatch]:
        """Scan with every enabled detector."""
        return self.scanner().scan(text, min_confidence)

    def describe(self) -> list[dict[str, Any]]:
        out = [d.to_dict() for d in self._detectors.values()]
        out += [{"kind": "key_rule", **r.to_dict()} for r in self._key_rules.values()]
        return out


# ---------------------------------------------------------------------------
# Config -> Detector
# ---------------------------------------------------------------------------

_FLAG_NAMES = {
    "i": re.I,
    "ignorecase": re.I,
    "m": re.M,
    "multiline": re.M,
    "s": re.S,
    "dotall": re.S,
    "x": re.X,
    "verbose": re.X,
}


def make_validator(spec: Any) -> Validator | None:
    """Build a validator from a config value: ``"ip"``, ``"entropy"`` /
    ``"entropy:4.5"``, ``"secret"``, ``"not_placeholder"``, or a callable."""
    if spec is None or callable(spec):
        return spec
    name, _, arg = str(spec).partition(":")
    if name == "ip":
        return classify_ip_text
    if name == "entropy":
        threshold = float(arg or 4.0)
        return lambda s: shannon_entropy(s) >= threshold
    if name in ("secret", "not_placeholder"):
        return _secret_value
    if name == "high_entropy":
        threshold = float(arg or 4.0)
        return lambda s: looks_like_secret(s, threshold)
    raise ValueError(f"Unknown validator {spec!r}")


def detector_from_config(spec: dict[str, Any]) -> Detector:
    """Build a :class:`Detector` from a policy dict."""
    if "name" not in spec or "pattern" not in spec:
        raise ValueError("custom detectors need 'name' and 'pattern'")
    flags = 0
    raw_flags = spec.get("flags") or []
    if isinstance(raw_flags, str):
        raw_flags = (
            [raw_flags]
            if len(raw_flags) > 1 and raw_flags.lower() in _FLAG_NAMES
            else list(raw_flags)
        )
    for f in raw_flags:
        flags |= _FLAG_NAMES[str(f).lower()]
    if spec.get("ignore_case"):
        flags |= re.I
    return Detector(
        name=str(spec["name"]),
        entity=str(spec.get("entity") or spec["name"]),
        pattern=str(spec["pattern"]),
        category=str(spec.get("category", "identifier")),
        confidence=float(spec.get("confidence", 0.8)),
        flags=flags,
        validator=make_validator(spec.get("validator")),
        group=int(spec.get("group", 0)),
        description=str(spec.get("description", "")),
        enabled=bool(spec.get("enabled", True)),
        min_length=int(spec.get("min_length", 1)),
        hints=tuple(str(h).lower() for h in spec.get("hints", ())),
    )


DEFAULT_REGISTRY = DetectorRegistry.default()


__all__ = [
    "BUILTIN_DETECTORS",
    "BUILTIN_KEY_RULES",
    "CATEGORIES",
    "DEFAULT_REGISTRY",
    "ENTITY_PARENTS",
    "PERSON_TAG_PATTERN",
    "SAFE_KEY_PATTERN",
    "SENSITIVE_KEY_PATTERN",
    "SHAPED_ENTITIES",
    "TAG_CONTAINER_KEYS",
    "CompiledScanner",
    "Detector",
    "DetectorRegistry",
    "EntityMatch",
    "KeyRule",
    "Validator",
    "account_entity",
    "classify_ip_text",
    "detector_from_config",
    "ip_class",
    "looks_like_secret",
    "make_validator",
    "normalize_key",
    "ref_entity",
    "shannon_entropy",
]
