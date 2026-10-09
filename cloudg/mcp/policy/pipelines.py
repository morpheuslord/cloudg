"""Output and input transform pipelines of a policy (see
:mod:`cloudg.mcp.policy`)."""

from __future__ import annotations

import copy
import json
import secrets
import threading
from collections import OrderedDict
from typing import Any, Callable

from cloudg.mcp.policy.access import spec_kind
from cloudg.mcp.transforms import (
    IDENTITY,
    AliasMap,
    Depseudonymizer,
    Pipeline,
    Redactor,
    Substitution,
    TokenVault,
    UntrustedTextGuard,
    build_transform,
    canonical_transform_name,
    normalize_transform_spec,
)

_ALIAS_TYPES = ("alias", "substitute")
#: Entries kept by the throw-away preview vault before it starts over.
_PREVIEW_VAULT_LIMIT = 100_000


def _aliases_after_redaction(specs: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Aliases are presentation: move ``alias`` / ``substitute`` steps that
    precede the last ``redact`` step to just after it. Detection then sees
    real values (an aliased account inside an ARN would hide the ARN from
    its detector), and pseudonym-aware aliases still label pseudonymised
    values."""
    last = max((i for i, s in enumerate(specs) if s["type"] == "redact"), default=-1)
    if last < 0:
        return specs
    early = [s for s in specs[:last] if s["type"] in _ALIAS_TYPES]
    if not early:
        return specs
    rest = [s for s in specs if s not in early]
    pos = rest.index(specs[last]) + 1
    return rest[:pos] + early + rest[pos:]


def _deep_merge(a: dict[str, Any], b: dict[str, Any]) -> dict[str, Any]:
    out = dict(a)
    for k, v in b.items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = _deep_merge(out[k], v)
        else:
            out[k] = copy.deepcopy(v)
    return out


def _combine(specs: list[dict[str, Any]], extra: list[dict[str, Any]], mode: str) -> list:
    if mode == "replace":
        return extra
    if mode == "prepend":
        return extra + specs
    return specs + extra


def _apply_options(specs: list[dict[str, Any]], options: dict[str, Any]) -> None:
    """``transform_options`` keyed by transform type or id."""
    for s in specs:
        for key in (s["type"], s["id"]):
            over = options.get(key) or options.get(canonical_transform_name(key))
            if over:
                s["options"] = _deep_merge(s["options"], over)


def _skip_steps(specs: list[dict[str, Any]], hints: dict[str, Any]) -> list[dict[str, Any]]:
    skip = {canonical_transform_name(x) for x in hints.get("skip", ()) or ()}
    if "*" in skip or "all" in skip:
        return []
    if skip:
        return [s for s in specs if s["type"] not in skip and s["id"] not in skip]
    return specs


def _steps_of(specs: list[dict[str, Any]], kind: str) -> list[dict[str, Any]]:
    return [s for s in specs if s["type"] == kind]


def _apply_hints(specs: list[dict[str, Any]], hints: dict[str, Any]) -> list[dict[str, Any]]:
    """A primitive's ``transform_hints``: skip steps, forbid pseudonyms,
    tweak projection, add transforms."""
    specs = _skip_steps(specs, hints)
    if hints.get("pseudonymize") is False or hints.get("pseudonymise") is False:
        for s in _steps_of(specs, "redact"):
            s["options"]["allow_pseudonymize"] = False
    for k in ("project", "projection"):
        if isinstance(hints.get(k), dict):
            for s in _steps_of(specs, "project"):
                s["options"] = _deep_merge(s["options"], hints[k])
    for k in ("transforms", "extra"):
        specs.extend(normalize_transform_spec(extra) for extra in hints.get(k, ()) or ())
    return specs


def _reversal_sources(out: Pipeline) -> tuple[bool, list[AliasMap]]:
    """Whether the output pipeline can emit anything the input side must
    reverse (vault tokens, aliases, fences), and its alias maps."""
    aliases: list[AliasMap] = []
    wants = False
    for t in out.transforms:
        if isinstance(t, Redactor) and t.reversible:
            wants = True
        elif isinstance(t, Substitution) and t.alias_maps:
            aliases += t.alias_maps
        elif isinstance(t, AliasMap) and t.aliases:
            aliases.append(t)
        elif isinstance(t, UntrustedTextGuard) and t.on_suspicious == "fence":
            wants = True
    return wants or bool(aliases), aliases


class PipelineBuilder:
    """Mixin for :class:`~cloudg.mcp.policy.Policy` (needs ``config``,
    ``vault``, ``name``, ``_lock``, ``_built``, ``_pipelines``, ``_inputs``,
    ``matching_rules()``, ``_principal()`` and ``_roles_key()``)."""

    config: Any
    vault: TokenVault
    name: str
    _lock: threading.RLock
    _built: dict[str, Any]
    _pipelines: OrderedDict[Any, tuple[Any, Pipeline]]
    _inputs: OrderedDict[Any, tuple[Any, Pipeline]]
    _preview_vault: TokenVault | None = None

    # provided by Policy
    matching_rules: Callable[..., list[Any]]
    _principal: Callable[[Any], Any]
    _roles_key: Callable[[Any], tuple[Any, ...]]

    def _build(self, spec: dict[str, Any]) -> Any:
        key = json.dumps(spec, sort_keys=True, default=str)
        with self._lock:
            hit = self._built.get(key)
            if hit is None:
                hit = self._make(spec)
                if isinstance(hit, Redactor) and self.config.disabled_detectors:
                    spec2 = copy.deepcopy(spec)
                    spec2["options"].setdefault("disabled_detectors", [])
                    spec2["options"]["disabled_detectors"] += self.config.disabled_detectors
                    hit = self._make(spec2)
                self._built[key] = hit
            return hit

    def _make(self, spec: dict[str, Any]) -> Any:
        return build_transform(
            spec, vault=self.vault, custom_detectors=self.config.detectors, profile=self.name
        )

    def _hints(self, spec: Any, honor: bool) -> dict[str, Any]:
        hints = dict(getattr(spec, "transform_hints", None) or {})
        if honor:
            return hints
        # Only restrictive hints survive when relaxations are not honoured
        return {k: v for k, v in hints.items() if k in ("transforms", "extra")}

    def _output_specs(self, spec: Any, principal: Any) -> tuple[list[dict[str, Any]], dict]:
        specs = [normalize_transform_spec(s) for s in self.config.transforms]
        options = copy.deepcopy(self.config.transform_options)
        honor = self.config.honor_hints
        for r in self.matching_rules(spec, principal):
            extra = [normalize_transform_spec(s) for s in r.cfg.transforms]
            specs = _combine(specs, extra, r.cfg.transforms_mode)
            options = _deep_merge(options, r.cfg.transform_options)
            if r.cfg.honor_hints is not None:
                honor = r.cfg.honor_hints
        specs = _aliases_after_redaction(specs)
        _apply_options(specs, options)
        hints = self._hints(spec, honor)
        return _apply_hints(specs, hints), hints

    def _cached(self, cache: OrderedDict, key: Any, spec: Any) -> Pipeline | None:
        with self._lock:
            hit = cache.get(key)
            if hit is not None and hit[0] is spec:
                return hit[1]
        return None

    def _store(self, cache: OrderedDict, key: Any, spec: Any, pipeline: Pipeline) -> None:
        with self._lock:
            cache[key] = (spec, pipeline)
            if len(cache) > 4096:
                cache.popitem(last=False)

    def output_pipeline(self, spec: Any, principal: Any = None) -> Pipeline:
        """Transforms applied to everything ``spec`` returns to ``principal``."""
        principal = self._principal(principal)
        key = (id(spec), getattr(spec, "name", None), self._roles_key(principal))
        hit = self._cached(self._pipelines, key, spec)
        if hit is not None:
            return hit
        specs, _ = self._output_specs(spec, principal)
        pipeline = Pipeline([self._build(s) for s in specs]) if specs else IDENTITY
        self._store(self._pipelines, key, spec, pipeline)
        return pipeline

    def _input_specs(self, spec: Any, principal: Any) -> tuple[list[dict[str, Any]], dict]:
        honor = self.config.honor_hints
        specs = [normalize_transform_spec(s) for s in self.config.input_transforms]
        for r in self.matching_rules(spec, principal):
            specs += [normalize_transform_spec(s) for s in r.cfg.input_transforms]
            if r.cfg.honor_hints is not None:
                honor = r.cfg.honor_hints
        return specs, self._hints(spec, honor)

    def input_pipeline(self, spec: Any, principal: Any = None) -> Pipeline:
        """Transforms applied to arguments before the handler runs: secret
        guards, then reversal of pseudonyms / aliases / fences whenever the
        output pipeline can produce them."""
        principal = self._principal(principal)
        key = (id(spec), getattr(spec, "name", None), self._roles_key(principal))
        hit = self._cached(self._inputs, key, spec)
        if hit is not None:
            return hit
        specs, hints = self._input_specs(spec, principal)
        skip = {canonical_transform_name(x) for x in hints.get("skip_input", ()) or ()}
        if hints.get("input_guard") is False:
            skip.add("guard_secrets")
        transforms: list[Any] = [
            self._build(s) for s in specs if s["type"] not in skip and s["id"] not in skip
        ]
        wants, aliases = _reversal_sources(self.output_pipeline(spec, principal))
        if (
            wants
            and hints.get("depseudonymize", True) is not False
            and "depseudonymize" not in skip
        ):
            transforms.append(Depseudonymizer(self.vault, aliases=aliases, strip_fences=True))
        pipeline = Pipeline(transforms) if transforms else IDENTITY
        self._store(self._inputs, key, spec, pipeline)
        return pipeline

    def preview_vault(self) -> TokenVault:
        """A throw-away vault with a random key, used by :meth:`preview`.
        Previews are consistent with each other but never with real
        results, so ``preview_transform`` cannot confirm a guess ("does
        ``web-1`` become the pseudonym I saw?")."""
        with self._lock:
            pv = self._preview_vault
            if pv is None or len(pv) > _PREVIEW_VAULT_LIMIT:
                pv = TokenVault(secrets.token_bytes(32), scope=self.vault.scope, key_env=None)
                self._preview_vault = pv
            return pv

    def preview(self, value: Any, spec: Any = None, principal: Any = None) -> tuple[Any, dict]:
        """Run the output pipeline for ``spec`` (or the policy's generic
        pipeline) over ``value``; returns ``(transformed, report)``.
        Pseudonyms come from :meth:`preview_vault`, never the real vault."""
        from cloudg.mcp.transforms.base import TransformContext

        principal = self._principal(principal)
        pipeline = (
            self.output_pipeline(spec, principal)
            if spec is not None
            else self._generic_pipeline(principal)
        )
        ctx = TransformContext(
            principal=principal,
            spec=spec,
            kind=spec_kind(spec) if spec else "tool",
            direction="output",
            vault=self.preview_vault(),
        )
        return pipeline.apply(value, ctx), ctx.report

    def _generic_pipeline(self, principal: Any) -> Pipeline:
        """The pipeline for data not tied to one primitive (preview without a
        tool, privacy_status, list_detectors): assembled exactly like a
        tool's pipeline (rules, options, alias ordering), minus spec hints."""
        specs, _ = self._output_specs(None, principal)
        return Pipeline([self._build(s) for s in specs]) if specs else IDENTITY
