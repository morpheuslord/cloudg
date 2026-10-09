"""Compiled access rules: glob lists, rule matching and the allow / deny
decision for one primitive (see :mod:`cloudg.mcp.policy`)."""

from __future__ import annotations

import fnmatch
import re
from typing import Any, Iterable
from urllib.parse import unquote

from cloudg.mcp.core import (
    SENSITIVITY_ORDER,
    Capability,
    PromptSpec,
    ResourceSpec,
    ResourceTemplateSpec,
    Sensitivity,
    ToolSpec,
)
from cloudg.mcp.policy.config import AccessRules, RuleConfig


class _Globs:
    """Glob list with ``!negation``; matches if any positive and no
    negative glob matches."""

    __slots__ = ("pos", "neg", "empty")

    def __init__(self, patterns: Iterable[str] | None) -> None:
        pats = [str(p) for p in (patterns or ())]
        pos = [p for p in pats if not p.startswith("!")]
        neg = [p[1:] for p in pats if p.startswith("!")]
        self.pos = re.compile("|".join(f"(?:{fnmatch.translate(p)})" for p in pos)) if pos else None
        self.neg = re.compile("|".join(f"(?:{fnmatch.translate(p)})" for p in neg)) if neg else None
        self.empty = not pats

    def match(self, *values: str | None) -> bool:
        if self.pos is None:
            return False
        vals = [v for v in values if v]
        if self.neg is not None and any(self.neg.match(v) for v in vals):
            return False
        return any(self.pos.match(v) for v in vals)


def spec_kind(spec: Any) -> str:
    if isinstance(spec, ToolSpec):
        return "tool"
    if isinstance(spec, ResourceTemplateSpec):
        return "resource_template"
    if isinstance(spec, ResourceSpec):
        return "resource"
    if isinstance(spec, PromptSpec):
        return "prompt"
    return str(getattr(spec, "kind", "tool"))


def _idents(spec: Any) -> tuple[str, ...]:
    out = [getattr(spec, "name", "") or ""]
    for attr in ("uri", "uri_template"):
        v = getattr(spec, attr, None)
        if v:
            out.insert(0, v)
    return tuple(out)


def idents_with_uri(spec: Any, uri: str | None) -> tuple[str, ...]:
    """The spec's identifiers plus a concrete requested URI, raw and
    percent-decoded (``cloudg://graph/%64%33`` is ``cloudg://graph/d3``), so
    URI globs in allow / deny lists also see what the client asked for."""
    base = _idents(spec)
    if not uri:
        return base
    extra = [u for u in dict.fromkeys((str(uri), unquote(str(uri)))) if u not in base]
    return (*base, *extra)


def _caps(spec: Any) -> set[Capability]:
    return {Capability(c) for c in (getattr(spec, "capabilities", None) or ())}


def _sens(spec: Any) -> Sensitivity:
    s = getattr(spec, "sensitivity", Sensitivity.CONFIDENTIAL)
    return Sensitivity(s)


class _CompiledAccess:
    def __init__(self, cfg: AccessRules) -> None:
        self.allow = {
            "tool": None if cfg.allow_tools is None else _Globs(cfg.allow_tools),
            "resource": None if cfg.allow_resources is None else _Globs(cfg.allow_resources),
            "prompt": None if cfg.allow_prompts is None else _Globs(cfg.allow_prompts),
        }
        self.deny = {
            "tool": _Globs(cfg.deny_tools),
            "resource": _Globs(cfg.deny_resources),
            "prompt": _Globs(cfg.deny_prompts),
        }
        self.allow_categories = (
            None if cfg.allow_categories is None else _Globs(cfg.allow_categories)
        )
        self.deny_categories = _Globs(cfg.deny_categories)
        self.allow_caps = {Capability(c) for c in cfg.allow_capabilities}
        self.deny_caps = {Capability(c) for c in cfg.deny_capabilities}
        self.max_sensitivity = cfg.max_sensitivity


def _kind_matches(kind: str, kinds: Iterable[str]) -> bool:
    """Rate-limit ``kinds`` filter: exact kind, and ``resource`` also covers
    ``resource_template``. Completions only match ``completion``."""
    ks = set(kinds)
    return kind in ks or (kind == "resource_template" and "resource" in ks)


def _list_kind(kind: str) -> str:
    """Which allow/deny list family applies to a spec kind."""
    if kind.startswith("resource"):
        return "resource"
    return kind if kind in ("tool", "prompt") else "tool"


class _Rule(_CompiledAccess):
    def __init__(self, cfg: RuleConfig, name: str) -> None:
        super().__init__(cfg)
        self.cfg = cfg
        self.name = name
        m = cfg.match
        self.roles = set(m.roles)
        self.principals = _Globs(m.principals) if m.principals else None
        self.names = _Globs(m.names) if m.names else None
        self.categories = _Globs(m.categories) if m.categories else None
        self.tags = set(m.tags)
        self.kinds = set(m.kinds)
        self.sensitivity = {Sensitivity(s) for s in m.sensitivity}
        self.capabilities = {Capability(c) for c in m.capabilities}
        self.spec_conditions = bool(
            self.names
            or self.categories
            or self.tags
            or self.kinds
            or self.sensitivity
            or self.capabilities
        )

    def _principal_matches(self, principal: Any) -> bool:
        if self.roles and "*" not in self.roles:
            if not (self.roles & set(getattr(principal, "roles", ()) or ())):
                return False
        if self.principals is None:
            return True
        return self.principals.match(str(getattr(principal, "id", "")))

    def _kind_ok(self, kind: str) -> bool:
        return not self.kinds or _kind_matches(kind, self.kinds)

    def _spec_matches(self, spec: Any, kind: str, idents: tuple[str, ...]) -> bool:
        if self.names is not None and not self.names.match(*idents):
            return False
        if self.categories is not None and not self.categories.match(getattr(spec, "category", "")):
            return False
        if self.tags and not (self.tags & set(getattr(spec, "tags", ()) or ())):
            return False
        if not self._kind_ok(kind):
            return False
        if self.sensitivity and _sens(spec) not in self.sensitivity:
            return False
        return not self.capabilities or bool(self.capabilities & _caps(spec))

    def applies(
        self, spec: Any, principal: Any, kind: str, idents: tuple[str, ...] | None = None
    ) -> bool:
        if not self._principal_matches(principal):
            return False
        if spec is None:
            return not self.spec_conditions
        return self._spec_matches(spec, kind, idents if idents is not None else _idents(spec))


class AccessDecision:
    """The allow / deny decision for one primitive, one caller and the
    rules that apply to them. ``decide()`` returns ``(allowed, reason)``."""

    __slots__ = ("base", "policy_name", "rules", "kind", "lk", "idents", "cat", "caps", "sens")

    def __init__(
        self, base: _CompiledAccess, policy_name: str, rules: list[_Rule], spec: Any, uri: Any
    ) -> None:
        self.base = base
        self.policy_name = policy_name
        self.rules = rules
        self.kind = spec_kind(spec)
        self.lk = _list_kind(self.kind)
        self.idents = idents_with_uri(spec, uri)
        self.cat = getattr(spec, "category", "") or ""
        self.caps = _caps(spec)
        self.sens = _sens(spec)

    def decide(self) -> tuple[bool, str]:
        reason = self._rule_denial() or self._sensitivity_denial()
        if reason is None and not self._granted():
            reason = self._base_denial()
        if reason is None:
            reason = self._capability_denial()
        return (False, reason) if reason is not None else (True, "")

    def _rule_denial(self) -> str | None:
        """Explicit ``deny_*`` in a matching rule always wins."""
        for r in self.rules:
            if r.deny[self.lk].match(*self.idents):
                return f"denied by rule '{r.name}'"
            if r.deny_categories.match(self.cat):
                return f"category '{self.cat}' denied by rule '{r.name}'"
            hit = self.caps & r.deny_caps
            if hit:
                first = sorted(c.value for c in hit)[0]
                return f"capability '{first}' denied by rule '{r.name}'"
        return None

    def _sensitivity_denial(self) -> str | None:
        """A rule ceiling replaces the policy ceiling (the highest wins)."""
        limits = [r.max_sensitivity for r in self.rules if r.max_sensitivity is not None]
        limit = (
            max(limits, key=lambda s: SENSITIVITY_ORDER[Sensitivity(s)])
            if limits
            else self.base.max_sensitivity
        )
        if limit is None:
            return None
        if SENSITIVITY_ORDER[self.sens] > SENSITIVITY_ORDER[Sensitivity(limit)]:
            allowed = Sensitivity(limit).value
            return f"sensitivity '{self.sens.value}' exceeds the allowed '{allowed}'"
        return None

    def _granted(self) -> bool:
        """A matching rule's ``allow_*`` overrides policy-level lists."""
        lk = self.lk
        return any(
            (r.allow[lk] is not None and r.allow[lk].match(*self.idents))
            or (r.allow_categories is not None and r.allow_categories.match(self.cat))
            for r in self.rules
        )

    def _base_denial(self) -> str | None:
        b, kind, name = self.base, self.kind, self.policy_name
        if b.deny[self.lk].match(*self.idents):
            return f"{kind} denied by policy '{name}'"
        if b.deny_categories.match(self.cat):
            return f"category '{self.cat}' denied by policy '{name}'"
        allow = b.allow[self.lk]
        if allow is not None and not allow.match(*self.idents):
            return f"{kind} not in the allow list of policy '{name}'"
        if b.allow_categories is not None and not b.allow_categories.match(self.cat):
            return f"category '{self.cat}' not allowed by policy '{name}'"
        return None

    def _capability_denial(self) -> str | None:
        for cap in sorted(self.caps, key=lambda c: c.value):
            if cap in self.base.deny_caps and not any(cap in r.allow_caps for r in self.rules):
                return f"capability '{cap.value}' is denied by policy '{self.policy_name}'"
        return None
