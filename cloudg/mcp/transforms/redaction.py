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

import json
import re
from dataclasses import dataclass, fields
from typing import Any, Iterable

from cloudg.mcp.transforms.base import TransformContext
from cloudg.mcp.transforms.builtin_rules import PERSON_TAG_PATTERN
from cloudg.mcp.transforms.detectors import DEFAULT_REGISTRY, DetectorRegistry
from cloudg.mcp.transforms.entities import ENTITY_PARENTS, Detector, KeyRule, normalize_key
from cloudg.mcp.transforms.redaction_run import _Run
from cloudg.mcp.transforms.strategies import (
    DROP,
    KEEP,
    STRATEGIES,
    Strategy,
    _chain,
    generalize,
    mask,
    parse_strategy,
)

#: Default tag keys whose values are operational, not identifying.
DEFAULT_TAG_KEY_ALLOWLIST = frozenset(
    {
        "env",
        "environment",
        "stage",
        "tier",
        "managed_by",
        "managedby",
        "terraform",
        "cost_center",
        "costcenter",
        "project_type",
        "application_tier",
        "criticality",
        "data_classification",
        "compliance",
        "backup",
        "patch_group",
    }
)


@dataclass(frozen=True)
class RedactorOptions:
    """Options of :class:`Redactor` other than ``strategies`` (see its
    docstring)."""

    default: Any = "keep"
    detectors: DetectorRegistry | None = None
    custom_detectors: tuple[Any, ...] = ()
    disabled_detectors: tuple[str, ...] = ()
    key_rules: Any = True
    extra_key_rules: tuple[Any, ...] = ()
    min_confidence: float = 0.0
    scan_keys: bool = True
    tags: bool = True
    tag_key_allowlist: tuple[str, ...] | None = None
    skip_keys: tuple[str, ...] = ("_meta", "_annotations", "cursor", "next_cursor")
    allow_pseudonymize: bool = True
    redact_template: str = "[REDACTED:{entity}]"
    hash_template: str = "{entity}:{digest}"
    cache_size: int = 200_000
    vault: Any = None
    name_mentions: bool = True
    structured_text: bool = True


_TUPLE_OPTIONS = frozenset(
    {"custom_detectors", "disabled_detectors", "extra_key_rules", "tag_key_allowlist", "skip_keys"}
)


def _redactor_options(options: dict[str, Any]) -> RedactorOptions:
    known = {f.name for f in fields(RedactorOptions)}
    unknown = sorted(set(options) - known)
    if unknown:
        raise TypeError(f"unexpected keyword argument(s): {', '.join(unknown)}")
    norm = {
        k: (tuple(v) if k in _TUPLE_OPTIONS and v is not None and not isinstance(v, str) else v)
        for k, v in options.items()
    }
    if isinstance(norm.get("key_rules"), (list, set, frozenset)):
        norm["key_rules"] = tuple(norm["key_rules"])
    return RedactorOptions(**norm)


class Redactor:
    """Detect-and-transform pass over JSON-like data.

    Args:
        strategies: ``{entity | detector | category | "default": strategy}``.

    Keyword options (see :class:`RedactorOptions`):
        default: Strategy for anything not listed (``"keep"``).
        detectors: Detector registry (built-ins by default).
        custom_detectors: Extra detector dicts / :class:`Detector` objects.
        disabled_detectors: Detector names to switch off.
        key_rules: ``True`` (built-in key rules), ``False`` (none) or a
            list of rule names to keep.
        extra_key_rules: Additional key rules (dicts or :class:`KeyRule`).
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
        structured_text: A top-level string that holds a JSON object or
            array is parsed, transformed like structured data (key rules
            apply) and serialised again; any other top-level text (GraphML,
            N-Triples, messages) additionally gets every real value the
            vault already pseudonymised replaced by its token.
    """

    name = "redact"

    def __init__(self, strategies: dict[str, Any] | None = None, **options: Any) -> None:
        opts = _redactor_options(options)
        self.options = opts
        reg = opts.detectors or DEFAULT_REGISTRY
        if opts.custom_detectors:
            reg = reg.with_custom(opts.custom_detectors)
        if opts.disabled_detectors:
            reg = reg.disable(opts.disabled_detectors)
        self.registry = reg
        self.strategies: dict[str, Strategy] = {
            str(k): parse_strategy(v) for k, v in (strategies or {}).items()
        }
        self.default = parse_strategy(self.strategies.pop("default", None) or opts.default)
        self.min_confidence = float(opts.min_confidence)
        self.scan_keys = opts.scan_keys
        self.tags = opts.tags
        allow = (
            DEFAULT_TAG_KEY_ALLOWLIST if opts.tag_key_allowlist is None else opts.tag_key_allowlist
        )
        self.tag_key_allowlist = frozenset(normalize_key(k) for k in allow)
        self.skip_keys = frozenset(opts.skip_keys)
        self.allow_pseudonymize = opts.allow_pseudonymize
        self.redact_template = opts.redact_template
        self.hash_template = opts.hash_template
        self.cache_size = opts.cache_size
        self.vault = opts.vault
        self.name_mentions = opts.name_mentions
        self.structured_text = opts.structured_text
        self._resolved: dict[tuple[str, ...], Strategy] = {}
        self._str_cache: dict[tuple[Any, ...], tuple[Any, tuple[tuple[str, str], ...]]] = {}
        self._key_cache: dict[str, tuple[str, list[KeyRule]]] = {}
        self._nkey_cache: dict[str, list[KeyRule]] = {}
        self._full_cache: dict[str, bool] = {}
        self.key_rules = self._active_key_rules(opts)
        self._person_rx = re.compile(PERSON_TAG_PATTERN)
        # Only compile detectors that can produce a non-keep outcome
        active = [d.name for d in reg.detectors if d.enabled and self._detector_active(d)]
        self.active_detectors = active
        self.scanner = reg.scanner(active)

    def _active_key_rules(self, opts: RedactorOptions) -> list[KeyRule]:
        """Key rules that can do anything under this configuration."""
        extra = [
            s if isinstance(s, KeyRule) else _key_rule_from_config(s) for s in opts.extra_key_rules
        ]
        if opts.key_rules is True:
            rules = self.registry.key_rules
        elif opts.key_rules is False:
            rules = []
        else:
            wanted = set(opts.key_rules)
            rules = [r for r in self.registry.key_rules if r.name in wanted]
        return [r for r in [*rules, *extra] if self._rule_strategy(r).kind != "keep"]

    def _rules_for(self, nkey: str) -> list[KeyRule]:
        """Key rules matching a normalised key (memoised: many raw keys
        normalise to the same one)."""
        hit = self._nkey_cache.get(nkey)
        if hit is None:
            hit = [rule for rule in self.key_rules if rule.matches(nkey)]
            if len(self._nkey_cache) > 50_000:
                self._nkey_cache.clear()
            self._nkey_cache[nkey] = hit
        return list(hit)

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
                {
                    "applies_to": k,
                    "strategy": v.kind,
                    **({"options": v.options} if v.options else {}),
                }
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
        if isinstance(value, str) and self.structured_text:
            out = self._apply_text(run, value)
        else:
            out = self._finish(run, run.walk(value))
        run.flush()
        if vault is not None and getattr(vault, "autosave", False):
            vault.maybe_autosave()
        if out is DROP:
            if not isinstance(value, str):
                return None
            return self.redact_template.format(entity="content")
        return out

    def _finish(self, run: _Run, out: Any) -> Any:
        if run.issued and self.name_mentions and out is not DROP:
            out = run.name_pass(out)
        return out

    def _apply_text(self, run: _Run, text: str) -> Any:
        """A top-level string: JSON is transformed as data, other text is
        scanned and then has known real values replaced (see
        ``structured_text``)."""
        parsed = _parse_json_text(text)
        if parsed is not None:
            out = self._finish(run, run.walk(parsed))
            if out is DROP:
                return DROP
            if "\n" in text:
                return json.dumps(out, indent=2, ensure_ascii=False, default=str)
            return json.dumps(out, ensure_ascii=False, default=str)
        out = run.scan_str(text)
        if out is DROP or run.vault is None or not self.reversible:
            return out
        replace_known = getattr(run.vault, "replace_known_values", None)
        if replace_known is None:
            return out
        out, n = replace_known(str(out), namespace=run.ns)
        if n:
            run.bump("pseudonymize", "identifier_mention", n)
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
            return mask(text, opts)
        if kind == "hash":
            return self._hash(text, entity, opts, vault)
        if kind == "pseudonymize":
            if vault is None:
                return self._hash(text, entity, opts, vault)
            return vault.tokenize(text, opts.get("as", entity), namespace=ns)
        if kind == "generalize":
            return generalize(text, entity, opts)
        raise ValueError(kind)  # pragma: no cover

    def _hash(self, text: str, entity: str, opts: dict[str, Any], vault: Any) -> str:
        length = int(opts.get("length", 12))
        if vault is not None:
            digest = vault.hash_value(text, length=length, entity_type=entity)
        else:  # pragma: no cover (policies always provide a vault)
            import hashlib

            digest = hashlib.sha256(f"{entity}\x1f{text}".encode()).hexdigest()[:length]
        tmpl = opts.get("template") or self.hash_template
        return tmpl.format(entity=entity, digest=digest)


def _parse_json_text(text: str) -> Any:
    """The JSON object / array held by ``text``, or ``None``."""
    head = text.lstrip()[:1]
    if head not in ("{", "["):
        return None
    try:
        parsed = json.loads(text)
    except ValueError:
        return None
    return parsed if isinstance(parsed, (dict, list)) else None


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
        probe = TransformContext(
            principal=ctx.principal,
            spec=ctx.spec,
            kind=ctx.kind,
            direction=ctx.direction,
            vault=ctx.vault,
        )
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


__all__ = [
    "DEFAULT_TAG_KEY_ALLOWLIST",
    "DROP",
    "KEEP",
    "STRATEGIES",
    "Redactor",
    "RedactorOptions",
    "SecretArgumentGuard",
    "Strategy",
    "generalize",
    "parse_strategy",
]
