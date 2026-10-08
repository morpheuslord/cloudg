"""Access-control and data-transformation policy for the cloudg MCP layer.

A :class:`Policy` decides, for every tool / resource / template / prompt
and every caller (:class:`~cloudg.mcp.context.Principal`):

* Visibility and access: allow / deny lists (globs, ``!negation``) for
  tools, resources, prompts and categories, denied *capabilities*
  (``cloud_access``, ``exec``, ``write_fs``, ``reveal``...) and a maximum
  *sensitivity*; per-role and per-primitive rules refine them;
* Rate limits: token buckets per principal, tool, both, or global;
* Output transforms: an ordered pipeline (sanitise untrusted text,
  substitute, redact / pseudonymise, project, annotate) built per
  primitive and role, honouring ``ToolSpec.transform_hints``;
* Input transforms: refuse secrets in arguments and reverse
  pseudonyms / aliases / fences so tools receive real identifiers;
* Audit: decisions in a ring buffer and on the ``cloudg.mcp.audit``
  logger (reveals are always logged there).

Policies are YAML / JSON / dicts validated by pydantic. Built-in profiles
live in ``cloudg/mcp/policies/*.yaml`` (and are the single source of truth
for them):

``open``
    No transforms, nothing denied. For trusted local experiments.
``standard`` (default)
    Secrets (passwords, keys, tokens, JWTs, connection-string secrets,
    values under sensitive keys) are redacted, private keys
    dropped, credential IDs (``AKIA...``) masked; untrusted text is
    sanitised and suspected prompt injection fenced; ``raw_data`` dropped
    and output size-guarded; secrets in arguments are refused. Identifiers
    (accounts, ARNs, IPs) are kept so answers stay actionable. Reveal
    is denied except to the ``admin`` / ``privacy-admin`` roles.
``strict``
    Standard plus pseudonymisation of every identifier (accounts,
    ARNs, Azure / GCP IDs, resource names, IPs / CIDRs, hostnames, emails,
    tag values), credentials redacted, restricted-sensitivity primitives
    hidden, ``cloud_access`` / ``exec`` / ``write_fs`` / ``reveal`` denied,
    and a per-principal rate limit.
``read_only``
    Standard minus side effects: ``cloud_access``, ``exec``, ``write_fs``
    denied.
``airgapped``
    Standard with no outbound activity: ``cloud_access`` and ``exec``
    denied (local file export allowed).
``audit``
    Read-only plus a full decision audit trail and inline provenance.

A policy can ``extends:`` any profile or file. Merge semantics: scalars
override, mappings merge recursively, ``deny_*`` lists and ``detectors`` /
``rate_limits`` / ``rules`` accumulate, ``transforms`` replace (use
``transform_options`` to tweak inherited transforms by type or id).
Policy-level ``allow_capabilities`` removes capabilities from the inherited
deny list.

Selecting a policy: ``CloudGMCPLayer(policy=...)`` takes a :class:`Policy`,
a profile name, a path, or a dict; ``None`` uses ``$CLOUDG_MCP_POLICY`` or
``standard``.
"""

from __future__ import annotations

import atexit
import copy
import fnmatch
import hashlib
import json
import logging
import math
import os
import re
import threading
import time
import weakref
from collections import Counter, OrderedDict, deque
from pathlib import Path
from typing import Any, Iterable, Literal

from pydantic import BaseModel, ConfigDict, Field, SecretStr, ValidationError

from cloudg.mcp.core import (
    SENSITIVITY_ORDER,
    AccessDeniedError,
    Capability,
    PromptSpec,
    RateLimitedError,
    ResourceSpec,
    ResourceTemplateSpec,
    Sensitivity,
    ToolSpec,
)
from cloudg.mcp.transforms import (
    DEFAULT_REGISTRY,
    IDENTITY,
    AliasMap,
    Depseudonymizer,
    DetectorRegistry,
    Pipeline,
    Redactor,
    Substitution,
    TokenVault,
    UntrustedTextGuard,
    build_transform,
    canonical_transform_name,
    normalize_transform_spec,
)
from cloudg.mcp.transforms.vault import VAULT_KEY_ENV

logger = logging.getLogger("cloudg.mcp")
audit_logger = logging.getLogger("cloudg.mcp.audit")

POLICY_ENV = "CLOUDG_MCP_POLICY"
PROFILES_DIR = Path(__file__).parent / "policies"
DEFAULT_PROFILE = "standard"

TransformSpecT = str | dict[str, Any]

# ---------------------------------------------------------------------------
# Config models
# ---------------------------------------------------------------------------


class _Model(BaseModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True)


class RuleMatch(_Model):
    """Which callers and primitives a rule applies to. Empty = any."""

    roles: list[str] = Field(default_factory=list)
    principals: list[str] = Field(default_factory=list, description="Principal id globs")
    names: list[str] = Field(default_factory=list, description="Tool/prompt names or URI globs")
    categories: list[str] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)
    kinds: list[Literal["tool", "resource", "resource_template", "prompt"]] = Field(
        default_factory=list
    )
    sensitivity: list[Sensitivity] = Field(default_factory=list)
    capabilities: list[Capability] = Field(default_factory=list)


class RateLimitConfig(_Model):
    """Token bucket: ``rate`` calls per ``per``, bursting to ``burst``."""

    rate: float = Field(gt=0)
    per: Literal["second", "minute", "hour", "day"] = "minute"
    burst: int | None = Field(default=None, ge=1)
    scope: Literal["principal", "tool", "principal_tool", "global"] = "principal_tool"
    tools: list[str] = Field(default_factory=lambda: ["*"], description="Name / URI globs")
    kinds: list[str] = Field(default_factory=list)


class AccessRules(_Model):
    """Allow / deny lists shared by policies and rules.

    At policy level ``allow_*`` lists are allowlists (``None`` = all) and
    ``deny_*`` lists are default denials. In a rule, ``allow_*`` *grants*
    (overriding policy-level denials) and ``deny_*`` is an explicit deny
    that always wins.
    """

    allow_tools: list[str] | None = None
    deny_tools: list[str] = Field(default_factory=list)
    allow_resources: list[str] | None = None
    deny_resources: list[str] = Field(default_factory=list)
    allow_prompts: list[str] | None = None
    deny_prompts: list[str] = Field(default_factory=list)
    allow_categories: list[str] | None = None
    deny_categories: list[str] = Field(default_factory=list)
    allow_capabilities: list[Capability] = Field(default_factory=list)
    deny_capabilities: list[Capability] = Field(default_factory=list)
    max_sensitivity: Sensitivity | None = None


class RuleConfig(AccessRules):
    """A conditional refinement: access changes, extra transforms,
    transform option overrides and rate limits for matching calls."""

    name: str = ""
    description: str = ""
    match: RuleMatch = Field(default_factory=RuleMatch)
    transforms: list[TransformSpecT] = Field(default_factory=list)
    transforms_mode: Literal["append", "prepend", "replace"] = "append"
    transform_options: dict[str, dict[str, Any]] = Field(default_factory=dict)
    input_transforms: list[TransformSpecT] = Field(default_factory=list)
    rate_limits: list[RateLimitConfig] = Field(default_factory=list)
    honor_hints: bool | None = None


class VaultConfig(_Model):
    key: SecretStr | None = Field(default=None, description="Pseudonym HMAC key (keep secret)")
    key_env: str = VAULT_KEY_ENV
    scope: Literal["global", "principal"] = "global"
    ttl_seconds: float | None = Field(default=None, gt=0)
    path: str | None = None
    autosave: bool = False
    encrypt: bool = True


class PolicyConfig(AccessRules):
    """Top-level policy document."""

    name: str = "custom"
    description: str = ""
    extends: str | None = None
    hide_denied: bool = True
    honor_hints: bool = True
    audit: bool = False
    audit_size: int = Field(default=1000, ge=0)
    transforms: list[TransformSpecT] = Field(default_factory=list)
    input_transforms: list[TransformSpecT] = Field(default_factory=list)
    transform_options: dict[str, dict[str, Any]] = Field(default_factory=dict)
    detectors: list[dict[str, Any]] = Field(default_factory=list)
    disabled_detectors: list[str] = Field(default_factory=list)
    roles: dict[str, RuleConfig] = Field(default_factory=dict)
    rules: list[RuleConfig] = Field(default_factory=list)
    rate_limits: list[RateLimitConfig] = Field(default_factory=list)
    vault: VaultConfig = Field(default_factory=VaultConfig)


# ---------------------------------------------------------------------------
# Loading and merging
# ---------------------------------------------------------------------------


def available_profiles() -> list[str]:
    """Names of the packaged profiles (``cloudg/mcp/policies/*.yaml``)."""
    return sorted(p.stem for p in PROFILES_DIR.glob("*.yaml"))


def _profile_path(name: str) -> Path | None:
    for cand in {name, name.replace("-", "_"), name.replace("_", "-")}:
        p = PROFILES_DIR / f"{cand}.yaml"
        if p.is_file():
            return p
    return None


def _read_file(path: Path) -> dict[str, Any]:
    text = path.read_text()
    if path.suffix.lower() == ".json":
        data = json.loads(text)
    else:
        import yaml

        data = yaml.safe_load(text) or {}
    if isinstance(data, dict) and set(data) == {"policy"} and isinstance(data["policy"], dict):
        data = data["policy"]
    if not isinstance(data, dict):
        raise ValueError(f"Policy file {path} must contain a mapping")
    return data


def _union(a: list[Any], b: list[Any]) -> list[Any]:
    out = list(a)
    for x in b:
        if x not in out:
            out.append(x)
    return out


_ACCUMULATE = {"rules", "detectors", "rate_limits", "disabled_detectors"}


def merge_policy_dicts(base: dict[str, Any], child: dict[str, Any]) -> dict[str, Any]:
    """Merge a child policy dict over its parent (see module docstring)."""
    out = copy.deepcopy(base)
    for k, v in child.items():
        if k == "extends":
            continue
        cur = out.get(k)
        if k in _ACCUMULATE and isinstance(v, list):
            out[k] = list(cur or []) + list(v)
        elif k.startswith("deny_") and isinstance(v, list):
            out[k] = _union(list(cur or []), v)
        elif isinstance(v, dict) and isinstance(cur, dict):
            out[k] = merge_policy_dicts(cur, v)
        else:
            out[k] = copy.deepcopy(v)
    return out


def resolve_extends(
    data: dict[str, Any], *, base_dir: Path | None = None, _seen: tuple[str, ...] = ()
) -> dict[str, Any]:
    """Recursively apply ``extends`` (profile name or file path)."""
    parent_ref = data.get("extends")
    if not parent_ref:
        return dict(data)
    ref = str(parent_ref)
    if ref in _seen:
        raise ValueError(f"Policy 'extends' cycle: {' -> '.join((*_seen, ref))}")
    parent_path = _profile_path(ref)
    if parent_path is None:
        cand = Path(ref).expanduser()
        if not cand.is_absolute() and base_dir is not None:
            cand = base_dir / cand
        if not cand.is_file():
            raise ValueError(f"Unknown policy to extend: {ref!r} (profiles: "
                             f"{', '.join(available_profiles())})")
        parent_path = cand
    parent = resolve_extends(_read_file(parent_path), base_dir=parent_path.parent,
                             _seen=(*_seen, ref))
    merged = merge_policy_dicts(parent, data)
    parent_name = parent.get("name", ref)
    merged["_chain"] = [*parent.get("_chain", []), parent_name]
    if "name" not in data:
        merged["name"] = f"custom({parent_name})"
    return merged


_ALIAS_TYPES = ("alias", "substitute")


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


# ---------------------------------------------------------------------------
# Compiled helpers
# ---------------------------------------------------------------------------


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

    def applies(self, spec: Any, principal: Any, kind: str) -> bool:
        if self.roles and "*" not in self.roles:
            if not (self.roles & set(getattr(principal, "roles", ()) or ())):
                return False
        if self.principals is not None and not self.principals.match(
            str(getattr(principal, "id", ""))
        ):
            return False
        if spec is None:
            return not (self.names or self.categories or self.tags or self.kinds
                        or self.sensitivity or self.capabilities)
        if self.names is not None and not self.names.match(*_idents(spec)):
            return False
        if self.categories is not None and not self.categories.match(
            getattr(spec, "category", "")
        ):
            return False
        if self.tags and not (self.tags & set(getattr(spec, "tags", ()) or ())):
            return False
        if self.kinds and kind not in self.kinds and not (
            kind == "resource_template" and "resource" in self.kinds
        ):
            return False
        if self.sensitivity and _sens(spec) not in self.sensitivity:
            return False
        if self.capabilities and not (self.capabilities & _caps(spec)):
            return False
        return True


_EXIT_VAULTS: "weakref.WeakSet[TokenVault]" = weakref.WeakSet()
_EXIT_HOOKED = False


def _register_exit_save(vault: TokenVault) -> None:
    """Save vaults that have a path at interpreter exit (if they changed).
    Weak references: a vault that was garbage collected is skipped."""
    global _EXIT_HOOKED
    _EXIT_VAULTS.add(vault)
    if not _EXIT_HOOKED:
        atexit.register(_save_vaults_at_exit)
        _EXIT_HOOKED = True


def _save_vaults_at_exit() -> None:
    for vault in list(_EXIT_VAULTS):
        try:
            if vault.path is not None and vault.dirty:
                vault.save()
        except Exception:  # never fail interpreter shutdown
            logger.debug("vault save at exit failed", exc_info=True)


class _Bucket:
    __slots__ = ("tokens", "last")

    def __init__(self, tokens: float, now: float) -> None:
        self.tokens = tokens
        self.last = now


_PERIOD = {"second": 1.0, "minute": 60.0, "hour": 3600.0, "day": 86400.0}


# ---------------------------------------------------------------------------
# Policy
# ---------------------------------------------------------------------------


class Policy:
    """Compiled policy (see the module docstring).

    Args:
        config: :class:`PolicyConfig`, a dict (``extends`` resolved), or
            ``None`` for the default profile.
        vault: Share an existing :class:`TokenVault` (e.g. across layers);
            built from ``config.vault`` otherwise.
        source: Where the policy came from (shown by :meth:`describe`).
    """

    def __init__(
        self,
        config: PolicyConfig | dict[str, Any] | None = None,
        *,
        vault: TokenVault | None = None,
        source: str | None = None,
        base_dir: Path | None = None,
    ) -> None:
        chain: list[str] = []
        if config is None:
            path = _profile_path(DEFAULT_PROFILE)
            assert path is not None, "packaged standard profile missing"
            config = _read_file(path)
            source = source or f"profile:{DEFAULT_PROFILE}"
        if isinstance(config, PolicyConfig) and config.extends:
            # resolve the parent like a dict would be; only explicitly set
            # fields override it
            raw = config.model_dump(mode="python", exclude_unset=True)
            if config.vault.key is not None:
                raw.setdefault("vault", {})["key"] = config.vault.key.get_secret_value()
            config = raw
        if isinstance(config, dict):
            data = resolve_extends(config, base_dir=base_dir)
            chain = list(data.pop("_chain", []))
            try:
                config = PolicyConfig.model_validate(data)
            except ValidationError as exc:
                raise ValueError(f"Invalid policy: {exc}") from exc
        self.config: PolicyConfig = config
        self.name = config.name
        self.source = source
        self.extends_chain = chain
        vc = config.vault
        self.vault = vault if vault is not None else TokenVault(
            key=vc.key.get_secret_value() if vc.key else None,
            scope=vc.scope,
            ttl_seconds=vc.ttl_seconds,
            path=vc.path,
            autosave=vc.autosave,
            encrypt=vc.encrypt,
            key_env=vc.key_env,
        )
        if self.vault.path is not None:
            _register_exit_save(self.vault)
        self._base = _CompiledAccess(config)
        # Policy-level allow_capabilities un-deny inherited capabilities
        self._base.deny_caps -= self._base.allow_caps
        rules: list[_Rule] = []
        for role, body in config.roles.items():
            rc = body.model_copy(deep=True)
            rc.match = rc.match.model_copy(update={"roles": [role, *rc.match.roles]})
            rules.append(_Rule(rc, rc.name or f"role:{role}"))
        for i, rc in enumerate(config.rules):
            rules.append(_Rule(rc, rc.name or f"rule[{i}]"))
        self._rules = rules
        self._uses_principal_ids = any(r.principals is not None for r in rules)
        self._lock = threading.RLock()
        self._decisions: OrderedDict[Any, tuple[Any, tuple[bool, str]]] = OrderedDict()
        self._pipelines: OrderedDict[Any, tuple[Any, Pipeline]] = OrderedDict()
        self._inputs: OrderedDict[Any, tuple[Any, Pipeline]] = OrderedDict()
        self._built: dict[str, Any] = {}
        self._buckets: dict[tuple[Any, ...], _Bucket] = {}
        self._rl_globs: dict[int, _Globs] = {}
        self.audit_log: deque[dict[str, Any]] = deque(maxlen=config.audit_size)
        self.counters: Counter[str] = Counter()
        self.registry: DetectorRegistry = DEFAULT_REGISTRY
        if config.detectors or config.disabled_detectors:
            reg = DEFAULT_REGISTRY.with_custom(config.detectors)
            self.registry = reg.disable(config.disabled_detectors) \
                if config.disabled_detectors else reg
        # Validate transform specs eagerly so bad policies fail at load time
        for spec in [*config.transforms, *config.input_transforms]:
            self._build(normalize_transform_spec(spec))

    # ------------------------------------------------------------------
    # Construction
    # ------------------------------------------------------------------

    @classmethod
    def load(cls, source: Any = None, *, vault: TokenVault | None = None) -> "Policy":
        """``None`` (``$CLOUDG_MCP_POLICY`` or ``standard``), a
        :class:`Policy`, a :class:`PolicyConfig`, a dict, a profile name, a
        path to ``.yaml`` / ``.yml`` / ``.json``, or inline JSON."""
        if isinstance(source, Policy):
            return source
        if source is None:
            env = os.environ.get(POLICY_ENV, "").strip()
            if env:
                return cls.load(env, vault=vault)
            return cls.from_profile(DEFAULT_PROFILE, vault=vault)
        if isinstance(source, PolicyConfig):
            return cls(source, vault=vault, source="config")
        if isinstance(source, dict):
            return cls(source, vault=vault, source="dict")
        if isinstance(source, os.PathLike):
            return cls.from_file(source, vault=vault)
        if isinstance(source, str):
            s = source.strip()
            if s.startswith("{"):
                return cls(json.loads(s), vault=vault, source="json")
            if _profile_path(s) is not None:
                return cls.from_profile(s, vault=vault)
            p = Path(s).expanduser()
            if p.is_file() or p.suffix.lower() in (".yaml", ".yml", ".json"):
                return cls.from_file(p, vault=vault)
            raise ValueError(
                f"Unknown policy {source!r}: not a profile ({', '.join(available_profiles())}) "
                "or an existing file"
            )
        raise TypeError(f"Cannot load a policy from {type(source).__name__}")

    @classmethod
    def from_profile(cls, name: str, *, vault: TokenVault | None = None) -> "Policy":
        path = _profile_path(name)
        if path is None:
            raise ValueError(f"Unknown policy profile {name!r}; available: "
                             f"{', '.join(available_profiles())}")
        return cls(_read_file(path), vault=vault, source=f"profile:{path.stem}",
                   base_dir=path.parent)

    @classmethod
    def from_file(cls, path: str | os.PathLike[str], *, vault: TokenVault | None = None
                  ) -> "Policy":
        p = Path(path).expanduser()
        if not p.is_file():
            raise FileNotFoundError(f"Policy file not found: {p}")
        return cls(_read_file(p), vault=vault, source=str(p), base_dir=p.parent)

    @classmethod
    def from_dict(cls, data: dict[str, Any], *, vault: TokenVault | None = None) -> "Policy":
        return cls(data, vault=vault, source="dict")

    @classmethod
    def default(cls) -> "Policy":
        return cls.load(None)

    def derive(self, **overrides: Any) -> "Policy":
        """New policy = this one with ``overrides`` merged on top (same vault)."""
        data = self.config.model_dump(mode="python", exclude={"vault"})
        data["vault"] = self.config.vault.model_dump(mode="python")
        if self.config.vault.key:
            data["vault"]["key"] = self.config.vault.key.get_secret_value()
        derived = Policy(merge_policy_dicts(data, overrides), vault=self.vault,
                         source=f"derived:{self.name}")
        derived.extends_chain = [*self.extends_chain, self.name]
        return derived

    # ------------------------------------------------------------------
    # Access decisions
    # ------------------------------------------------------------------

    def _principal(self, principal: Any) -> Any:
        if principal is None:
            from cloudg.mcp.context import Principal

            return Principal()
        return principal

    def _roles_key(self, principal: Any) -> tuple[Any, ...]:
        roles = frozenset(getattr(principal, "roles", ()) or ())
        pid = getattr(principal, "id", None) if self._uses_principal_ids else None
        return (roles, pid)

    def matching_rules(self, spec: Any, principal: Any) -> list[_Rule]:
        kind = spec_kind(spec) if spec is not None else "tool"
        return [r for r in self._rules if r.applies(spec, principal, kind)]

    def decide(self, spec: Any, principal: Any = None) -> tuple[bool, str]:
        """``(allowed, reason)`` for ``principal`` using ``spec``."""
        principal = self._principal(principal)
        key = (id(spec), getattr(spec, "name", None), self._roles_key(principal))
        with self._lock:
            hit = self._decisions.get(key)
            if hit is not None and hit[0] is spec:
                return hit[1]
        res = self._decide(spec, principal)
        with self._lock:
            # the entry holds a reference to the spec, so its id() cannot be
            # recycled for a different spec while cached
            self._decisions[key] = (spec, res)
            if len(self._decisions) > 8192:
                self._decisions.popitem(last=False)
        return res

    def _decide(self, spec: Any, principal: Any) -> tuple[bool, str]:
        kind = spec_kind(spec)
        lk = _list_kind(kind)
        idents = _idents(spec)
        cat = getattr(spec, "category", "") or ""
        caps = _caps(spec)
        sens = _sens(spec)
        rules = self.matching_rules(spec, principal)
        for r in rules:
            if r.deny[lk].match(*idents):
                return False, f"denied by rule '{r.name}'"
            if r.deny_categories.match(cat):
                return False, f"category '{cat}' denied by rule '{r.name}'"
            hit = caps & r.deny_caps
            if hit:
                return False, (f"capability '{sorted(c.value for c in hit)[0]}' denied by rule "
                               f"'{r.name}'")
        limits = [r.max_sensitivity for r in rules if r.max_sensitivity is not None]
        limit = (max(limits, key=lambda s: SENSITIVITY_ORDER[Sensitivity(s)]) if limits
                 else self._base.max_sensitivity)
        if limit is not None and SENSITIVITY_ORDER[sens] > SENSITIVITY_ORDER[Sensitivity(limit)]:
            allowed = Sensitivity(limit).value
            return False, f"sensitivity '{sens.value}' exceeds the allowed '{allowed}'"
        granted = any(
            (r.allow[lk] is not None and r.allow[lk].match(*idents))
            or (r.allow_categories is not None and r.allow_categories.match(cat))
            for r in rules
        )
        if not granted:
            b = self._base
            if b.deny[lk].match(*idents):
                return False, f"{kind} denied by policy '{self.name}'"
            if b.deny_categories.match(cat):
                return False, f"category '{cat}' denied by policy '{self.name}'"
            allow = b.allow[lk]
            if allow is not None and not allow.match(*idents):
                return False, f"{kind} not in the allow list of policy '{self.name}'"
            if b.allow_categories is not None and not b.allow_categories.match(cat):
                return False, f"category '{cat}' not allowed by policy '{self.name}'"
        for cap in sorted(caps, key=lambda c: c.value):
            if cap in self._base.deny_caps and not any(cap in r.allow_caps for r in rules):
                return False, f"capability '{cap.value}' is denied by policy '{self.name}'"
        return True, ""

    def is_allowed(self, spec: Any, principal: Any = None) -> bool:
        """Visibility for list and call. With ``hide_denied: false``
        denied primitives stay listed (calls still fail)."""
        if not self.config.hide_denied:
            return True
        return self.decide(spec, principal)[0]

    def check_call(self, spec: Any, principal: Any, arguments: dict[str, Any] | None = None
                   ) -> None:
        """Raise :class:`AccessDeniedError` / :class:`RateLimitedError`."""
        principal = self._principal(principal)
        allowed, reason = self.decide(spec, principal)
        kind = spec_kind(spec)
        name = _idents(spec)[0]
        if arguments and "__completion__" in arguments:
            kind = "completion"
        if not allowed:
            self.counters["denied"] += 1
            self._audit("denied", kind, name, principal, arguments, reason)
            raise AccessDeniedError(
                f"Access to {kind} '{name}' denied: {reason}",
                data={"policy": self.name, "reason": reason},
            )
        try:
            self._rate_limit(spec, principal, kind, name)
        except RateLimitedError as exc:
            self.counters["rate_limited"] += 1
            self._audit("rate_limited", kind, name, principal, arguments, exc.message)
            raise
        self.counters["allowed"] += 1
        if Capability.REVEAL in _caps(spec):
            self.counters["reveal"] += 1
            audit_logger.warning(
                "REVEAL principal=%s roles=%s %s=%s args=%s policy=%s",
                getattr(principal, "id", "?"), sorted(getattr(principal, "roles", ()) or ()),
                kind, name, self._arg_fingerprint(arguments), self.name,
            )
            self._audit("allowed", kind, name, principal, arguments, "reveal", force=True)
        else:
            self._audit("allowed", kind, name, principal, arguments, "")

    # ------------------------------------------------------------------
    # Rate limiting
    # ------------------------------------------------------------------

    def _rate_limit(self, spec: Any, principal: Any, kind: str, name: str) -> None:
        limits = list(self.config.rate_limits)
        for r in self.matching_rules(spec, principal):
            limits.extend(r.cfg.rate_limits)
        if not limits:
            return
        idents = _idents(spec)
        pid = str(getattr(principal, "id", "anonymous"))
        now = time.monotonic()
        with self._lock:
            # Phase 1: refill and check every applicable bucket; phase 2:
            # take one token from each only when all of them allow the call,
            # so a rejection by a later bucket costs nothing in earlier ones.
            taken: list[_Bucket] = []
            for rl in limits:
                if rl.kinds and not _kind_matches(kind, rl.kinds):
                    continue
                globs = self._rl_globs.get(id(rl))
                if globs is None:
                    globs = self._rl_globs[id(rl)] = _Globs(rl.tools)
                if not globs.match(*idents):
                    continue
                scope_key: tuple[Any, ...] = {
                    "principal": (pid,),
                    "tool": (name,),
                    "principal_tool": (pid, name),
                    "global": (),
                }[rl.scope]
                key = (id(rl), *scope_key)
                capacity = float(rl.burst or max(1, math.ceil(rl.rate)))
                refill = rl.rate / _PERIOD[rl.per]
                b = self._buckets.get(key)
                if b is None:
                    b = self._buckets[key] = _Bucket(capacity, now)
                b.tokens = min(capacity, b.tokens + max(0.0, now - b.last) * refill)
                b.last = now
                if b.tokens < 1.0:
                    retry = (1.0 - b.tokens) / refill
                    raise RateLimitedError(
                        f"Rate limit exceeded for {kind} '{name}' ({rl.rate:g}/{rl.per}); "
                        f"retry in {retry:.1f}s",
                        data={"retry_after": round(retry, 2), "limit": f"{rl.rate:g}/{rl.per}",
                              "scope": rl.scope},
                    )
                taken.append(b)
            for b in taken:
                b.tokens -= 1.0

    def reset_rate_limits(self) -> None:
        with self._lock:
            self._buckets.clear()

    # ------------------------------------------------------------------
    # Audit
    # ------------------------------------------------------------------

    def _arg_fingerprint(self, arguments: dict[str, Any] | None) -> dict[str, str]:
        """Argument field names with keyed hashes of the values. The values
        themselves are never included."""
        out: dict[str, str] = {}
        for k, v in (arguments or {}).items():
            try:
                blob = json.dumps(v, sort_keys=True, default=str)
            except (TypeError, ValueError):
                blob = str(v)
            out[str(k)] = self.vault.hash_value(blob, length=12, entity_type="audit")
        return out

    def _audit(self, decision: str, kind: str, name: str, principal: Any,
               arguments: dict[str, Any] | None, reason: str, *, force: bool = False) -> None:
        if not (self.config.audit or force or decision != "allowed"):
            return
        entry = {
            "ts": time.time(),
            "decision": decision,
            "kind": kind,
            "name": name,
            "principal": str(getattr(principal, "id", "anonymous")),
            "roles": sorted(getattr(principal, "roles", ()) or ()),
            "arguments": self._arg_fingerprint(arguments),
            **({"reason": reason} if reason else {}),
        }
        with self._lock:
            if self.audit_log.maxlen != 0:
                self.audit_log.append(entry)
        if self.config.audit or decision != "allowed":
            audit_logger.info("%s %s %s principal=%s %s", decision, kind, name,
                              entry["principal"], reason)

    def record_rejection(self, spec: Any, principal: Any, arguments: dict[str, Any] | None,
                         exc: BaseException) -> None:
        """Called by the layer when the input pipeline refused a call that
        :meth:`check_call` had already allowed (secrets in arguments...).
        The matching "allowed" audit entry is amended to "rejected", or a
        new entry is added."""
        principal = self._principal(principal)
        kind = spec_kind(spec)
        name = _idents(spec)[0]
        reason = str(getattr(exc, "message", None) or exc)[:300]
        self.counters["rejected"] += 1
        fp = self._arg_fingerprint(arguments)
        pid = str(getattr(principal, "id", "anonymous"))
        with self._lock:
            for entry in reversed(self.audit_log):
                if (entry["decision"] == "allowed" and entry["name"] == name
                        and entry["principal"] == pid and entry["arguments"] == fp):
                    entry["decision"] = "rejected"
                    entry["reason"] = reason
                    break
            else:
                self._audit("rejected", kind, name, principal, arguments, reason, force=True)
                return
        audit_logger.info("rejected %s %s principal=%s %s", kind, name, pid, reason)

    def record_hidden(self, kind: str, name: str, principal: Any,
                      arguments: dict[str, Any] | None = None) -> None:
        """Called by the layer when a caller asks for a primitive that is
        unknown or hidden by this policy (it answers "not found")."""
        principal = self._principal(principal)
        self.counters["hidden"] += 1
        self._audit("not_found", str(kind), str(name)[:200], principal, arguments,
                    "unknown or hidden by policy", force=True)

    # ------------------------------------------------------------------
    # Vault persistence
    # ------------------------------------------------------------------

    def save_vault(self, path: str | os.PathLike[str] | None = None) -> Path | None:
        """Persist the pseudonym vault to ``path`` or ``vault.path`` from the
        config. Returns the file written, or ``None`` when no path is set.
        Servers call this at shutdown; an ``atexit`` hook does the same for
        vaults with a path."""
        if path is None and self.vault.path is None:
            return None
        return self.vault.save(path)

    # ------------------------------------------------------------------
    # Pipelines
    # ------------------------------------------------------------------

    def _build(self, spec: dict[str, Any]) -> Any:
        key = json.dumps(spec, sort_keys=True, default=str)
        with self._lock:
            hit = self._built.get(key)
            if hit is None:
                hit = build_transform(
                    spec,
                    vault=self.vault,
                    custom_detectors=self.config.detectors,
                    profile=self.name,
                )
                if isinstance(hit, Redactor) and self.config.disabled_detectors:
                    spec2 = copy.deepcopy(spec)
                    spec2["options"].setdefault("disabled_detectors", [])
                    spec2["options"]["disabled_detectors"] += self.config.disabled_detectors
                    hit = build_transform(spec2, vault=self.vault,
                                          custom_detectors=self.config.detectors,
                                          profile=self.name)
                self._built[key] = hit
            return hit

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
            if r.cfg.transforms_mode == "replace":
                specs = extra
            elif r.cfg.transforms_mode == "prepend":
                specs = extra + specs
            else:
                specs = specs + extra
            options = _deep_merge(options, r.cfg.transform_options)
            if r.cfg.honor_hints is not None:
                honor = r.cfg.honor_hints
        specs = _aliases_after_redaction(specs)
        for s in specs:
            for key in (s["type"], s["id"]):
                over = options.get(key) or options.get(canonical_transform_name(key))
                if over:
                    s["options"] = _deep_merge(s["options"], over)
        hints = self._hints(spec, honor)
        skip = {canonical_transform_name(x) for x in hints.get("skip", ()) or ()}
        if "*" in skip or "all" in skip:
            specs = []
        elif skip:
            specs = [s for s in specs if s["type"] not in skip and s["id"] not in skip]
        if hints.get("pseudonymize") is False or hints.get("pseudonymise") is False:
            for s in specs:
                if s["type"] == "redact":
                    s["options"]["allow_pseudonymize"] = False
        for k in ("project", "projection"):
            if isinstance(hints.get(k), dict):
                for s in specs:
                    if s["type"] == "project":
                        s["options"] = _deep_merge(s["options"], hints[k])
        for k in ("transforms", "extra"):
            for extra in hints.get(k, ()) or ():
                specs.append(normalize_transform_spec(extra))
        return specs, hints

    def output_pipeline(self, spec: Any, principal: Any = None) -> Pipeline:
        """Transforms applied to everything ``spec`` returns to ``principal``."""
        principal = self._principal(principal)
        key = (id(spec), getattr(spec, "name", None), self._roles_key(principal))
        with self._lock:
            hit = self._pipelines.get(key)
            if hit is not None and hit[0] is spec:
                return hit[1]
        specs, _ = self._output_specs(spec, principal)
        pipeline = Pipeline([self._build(s) for s in specs]) if specs else IDENTITY
        with self._lock:
            self._pipelines[key] = (spec, pipeline)
            if len(self._pipelines) > 4096:
                self._pipelines.popitem(last=False)
        return pipeline

    def input_pipeline(self, spec: Any, principal: Any = None) -> Pipeline:
        """Transforms applied to arguments before the handler runs: secret
        guards, then reversal of pseudonyms / aliases / fences whenever the
        output pipeline can produce them."""
        principal = self._principal(principal)
        key = (id(spec), getattr(spec, "name", None), self._roles_key(principal))
        with self._lock:
            hit = self._inputs.get(key)
            if hit is not None and hit[0] is spec:
                return hit[1]
        honor = self.config.honor_hints
        rules = self.matching_rules(spec, principal)
        specs = [normalize_transform_spec(s) for s in self.config.input_transforms]
        for r in rules:
            specs += [normalize_transform_spec(s) for s in r.cfg.input_transforms]
            if r.cfg.honor_hints is not None:
                honor = r.cfg.honor_hints
        hints = self._hints(spec, honor)
        skip = {canonical_transform_name(x) for x in hints.get("skip_input", ()) or ()}
        if hints.get("input_guard") is False:
            skip.add("guard_secrets")
        transforms: list[Any] = [self._build(s) for s in specs
                                 if s["type"] not in skip and s["id"] not in skip]
        out = self.output_pipeline(spec, principal)
        aliases: list[AliasMap] = []
        reversible = False
        fenced = False
        for t in out.transforms:
            if isinstance(t, Redactor) and t.reversible:
                reversible = True
            elif isinstance(t, Substitution) and t.alias_maps:
                aliases += t.alias_maps
            elif isinstance(t, AliasMap) and t.aliases:
                aliases.append(t)
            elif isinstance(t, UntrustedTextGuard) and t.on_suspicious == "fence":
                fenced = True
        wants = reversible or aliases or fenced
        if wants and hints.get("depseudonymize", True) is not False \
                and "depseudonymize" not in skip:
            transforms.append(Depseudonymizer(self.vault, aliases=aliases, strip_fences=True))
        pipeline = Pipeline(transforms) if transforms else IDENTITY
        with self._lock:
            self._inputs[key] = (spec, pipeline)
            if len(self._inputs) > 4096:
                self._inputs.popitem(last=False)
        return pipeline

    def preview(self, value: Any, spec: Any = None, principal: Any = None) -> tuple[Any, dict]:
        """Run the output pipeline for ``spec`` (or the policy's generic
        pipeline) over ``value``; returns ``(transformed, report)``."""
        from cloudg.mcp.transforms.base import TransformContext

        principal = self._principal(principal)
        pipeline = self.output_pipeline(spec, principal) if spec is not None else \
            self._generic_pipeline(principal)
        ctx = TransformContext(principal=principal, spec=spec, kind=spec_kind(spec) if spec
                               else "tool", direction="output", vault=self.vault)
        return pipeline.apply(value, ctx), ctx.report

    def _generic_pipeline(self, principal: Any) -> Pipeline:
        """The pipeline for data not tied to one primitive (preview without a
        tool, privacy_status, list_detectors): assembled exactly like a
        tool's pipeline (rules, options, alias ordering), minus spec hints."""
        specs, _ = self._output_specs(None, principal)
        return Pipeline([self._build(s) for s in specs]) if specs else IDENTITY

    # ------------------------------------------------------------------
    # Introspection
    # ------------------------------------------------------------------

    def detectors(self) -> DetectorRegistry:
        return self.registry

    def describe(self) -> dict[str, Any]:
        """Human / model readable summary. Never contains the vault key."""
        cfg = self.config
        doc = cfg.model_dump(mode="json", exclude={"vault"}, exclude_none=True)
        for k in ("transforms", "input_transforms"):
            doc[k] = [_scrub(normalize_transform_spec(s)) for s in getattr(cfg, k)]
        doc["transform_options"] = _scrub(doc.get("transform_options", {}))
        vault_cfg = cfg.vault.model_dump(mode="json", exclude={"key"})
        doc["vault"] = {**vault_cfg, **self.vault.stats(), "key_configured": cfg.vault.key
                        is not None}
        doc["loaded_from"] = self.source
        doc["extends_chain"] = self.extends_chain
        doc["effective_denied_capabilities"] = sorted(c.value for c in self._base.deny_caps)
        doc["counters"] = dict(self.counters)
        doc["available_profiles"] = available_profiles()
        return _strategy_lists(doc)

    def __repr__(self) -> str:
        return f"Policy(name={self.name!r}, source={self.source!r})"


_SECRET_OPTION = re.compile(r"(?i)(?:^|_)(?:key|secret|password|token)$")


def _scrub(value: Any) -> Any:
    """Hide secret-looking option values (``key: ...``) in descriptions;
    strategy tables (``strategies: {secret: redact}``) are left alone."""
    if isinstance(value, dict):
        return {k: (v if k == "strategies" else
                    "***" if isinstance(k, str) and _SECRET_OPTION.search(k)
                    and isinstance(v, str) else _scrub(v)) for k, v in value.items()}
    if isinstance(value, list):
        return [_scrub(v) for v in value]
    return value


def strategy_list(strategies: dict[str, Any]) -> list[dict[str, Any]]:
    """``{"secret": "redact", "credential": {"strategy": "mask", ...}}`` ->
    ``[{"applies_to": "secret", "strategy": "redact"}, ...]``. Descriptions use
    this shape so entity names such as ``secret`` / ``credential`` never
    appear as dict keys (the sensitive-key rule would redact them)."""
    out = []
    for target, spec in strategies.items():
        if isinstance(spec, dict):
            opts = {k: v for k, v in spec.items() if k not in ("strategy", "type", "kind")}
            kind = spec.get("strategy") or spec.get("type") or spec.get("kind") or "redact"
            item: dict[str, Any] = {"applies_to": target, "strategy": kind}
            if opts:
                item["options"] = opts
        else:
            item = {"applies_to": target, "strategy": spec}
        out.append(item)
    return out


def _strategy_lists(value: Any) -> Any:
    if isinstance(value, dict):
        return {k: (strategy_list(v) if k == "strategies" and isinstance(v, dict)
                    else _strategy_lists(v)) for k, v in value.items()}
    if isinstance(value, list):
        return [_strategy_lists(v) for v in value]
    return value


def policy_fingerprint(policy: Policy) -> str:
    """Stable short hash of the effective configuration (no secrets)."""
    blob = json.dumps(policy.config.model_dump(mode="json", exclude={"vault"}), sort_keys=True)
    return hashlib.sha256(blob.encode()).hexdigest()[:16]
