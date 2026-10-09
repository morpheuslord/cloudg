"""The compiled :class:`Policy` (see :mod:`cloudg.mcp.policy`)."""

from __future__ import annotations

import json
import os
import threading
from collections import Counter, OrderedDict, deque
from pathlib import Path
from typing import Any

from cloudg.mcp.core import AccessDeniedError, Capability, RateLimitedError
from cloudg.mcp.policy.access import (
    AccessDecision,
    _caps,
    _CompiledAccess,
    _idents,
    _Rule,
    idents_with_uri,
    spec_kind,
)
from cloudg.mcp.policy.audit import AuditTrail
from cloudg.mcp.policy.config import (
    DEFAULT_PROFILE,
    POLICY_ENV,
    PolicyConfig,
    _profile_path,
    _read_file,
    available_profiles,
    merge_policy_dicts,
    resolve_extends,
    validate_config,
)
from cloudg.mcp.policy.describe import describe_policy
from cloudg.mcp.policy.pipelines import PipelineBuilder
from cloudg.mcp.policy.ratelimit import RateLimiter
from cloudg.mcp.policy.vaults import _register_exit_save, vault_from_config
from cloudg.mcp.transforms import (
    DEFAULT_REGISTRY,
    DetectorRegistry,
    Pipeline,
    TokenVault,
    normalize_transform_spec,
)


def _resolve_config(
    config: PolicyConfig | dict[str, Any] | None, source: str | None, base_dir: Path | None
) -> tuple[PolicyConfig, str | None, list[str]]:
    """``(config, source, extends chain)`` from any accepted ``config``."""
    if config is None:
        path = _profile_path(DEFAULT_PROFILE)
        if path is None:
            raise RuntimeError(f"packaged {DEFAULT_PROFILE!r} policy profile is missing")
        config = _read_file(path)
        source = source or f"profile:{DEFAULT_PROFILE}"
    if isinstance(config, PolicyConfig) and config.extends:
        # resolve the parent like a dict would be; only explicitly set
        # fields override it
        raw = config.model_dump(mode="python", exclude_unset=True)
        if config.vault.key is not None:
            raw.setdefault("vault", {})["key"] = config.vault.key.get_secret_value()
        config = raw
    chain: list[str] = []
    if isinstance(config, dict):
        data = resolve_extends(config, base_dir=base_dir)
        chain = list(data.pop("_chain", []))
        config = validate_config(data)
    return config, source, chain


def _compile_rules(config: PolicyConfig) -> list[_Rule]:
    rules: list[_Rule] = []
    for role, body in config.roles.items():
        rc = body.model_copy(deep=True)
        rc.match = rc.match.model_copy(update={"roles": [role, *rc.match.roles]})
        rules.append(_Rule(rc, rc.name or f"role:{role}"))
    for i, rc in enumerate(config.rules):
        rules.append(_Rule(rc, rc.name or f"rule[{i}]"))
    return rules


class Policy(AuditTrail, PipelineBuilder):
    """Compiled policy (see the :mod:`cloudg.mcp.policy` docstring).

    Args:
        config: :class:`PolicyConfig`, a dict (``extends`` resolved), or
            ``None`` for the default profile.
        vault: Share an existing :class:`TokenVault` (e.g. across layers);
            built from ``config.vault`` otherwise.
        source: Where the policy came from (shown by :meth:`describe`).
        base_dir: Directory relative ``extends`` paths resolve against.
    """

    def __init__(
        self,
        config: PolicyConfig | dict[str, Any] | None = None,
        *,
        vault: TokenVault | None = None,
        source: str | None = None,
        base_dir: Path | None = None,
    ) -> None:
        config, source, chain = _resolve_config(config, source, base_dir)
        self.config: PolicyConfig = config
        self.name = config.name
        self.source = source
        self.extends_chain = chain
        self.vault = vault if vault is not None else vault_from_config(config.vault)
        if self.vault.path is not None:
            _register_exit_save(self.vault)
        self._base = _CompiledAccess(config)
        # Policy-level allow_capabilities un-deny inherited capabilities
        self._base.deny_caps -= self._base.allow_caps
        self._rules = _compile_rules(config)
        self._uses_principal_ids = any(r.principals is not None for r in self._rules)
        self._lock = threading.RLock()
        self._decisions: OrderedDict[Any, tuple[Any, tuple[bool, str]]] = OrderedDict()
        self._pipelines: OrderedDict[Any, tuple[Any, Pipeline]] = OrderedDict()
        self._inputs: OrderedDict[Any, tuple[Any, Pipeline]] = OrderedDict()
        self._built: dict[str, Any] = {}
        self._limiter = RateLimiter(self._lock)
        self.audit_log: deque[dict[str, Any]] = deque(maxlen=config.audit_size)
        self.counters: Counter[str] = Counter()
        self.registry: DetectorRegistry = self._registry(config)
        # Validate transform specs eagerly so bad policies fail at load time
        for spec in [*config.transforms, *config.input_transforms]:
            self._build(normalize_transform_spec(spec))

    @staticmethod
    def _registry(config: PolicyConfig) -> DetectorRegistry:
        if not (config.detectors or config.disabled_detectors):
            return DEFAULT_REGISTRY
        reg = DEFAULT_REGISTRY.with_custom(config.detectors)
        return reg.disable(config.disabled_detectors) if config.disabled_detectors else reg

    # ------------------------------------------------------------------
    # Construction
    # ------------------------------------------------------------------

    @classmethod
    def load(cls, source: Any = None, *, vault: TokenVault | None = None) -> Policy:
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
            return cls._load_str(source, vault)
        raise TypeError(f"Cannot load a policy from {type(source).__name__}")

    @classmethod
    def _load_str(cls, source: str, vault: TokenVault | None) -> Policy:
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

    @classmethod
    def from_profile(cls, name: str, *, vault: TokenVault | None = None) -> Policy:
        path = _profile_path(name)
        if path is None:
            raise ValueError(
                f"Unknown policy profile {name!r}; available: {', '.join(available_profiles())}"
            )
        return cls(
            _read_file(path), vault=vault, source=f"profile:{path.stem}", base_dir=path.parent
        )

    @classmethod
    def from_file(cls, path: str | os.PathLike[str], *, vault: TokenVault | None = None) -> Policy:
        p = Path(path).expanduser()
        if not p.is_file():
            raise FileNotFoundError(f"Policy file not found: {p}")
        return cls(_read_file(p), vault=vault, source=str(p), base_dir=p.parent)

    @classmethod
    def from_dict(cls, data: dict[str, Any], *, vault: TokenVault | None = None) -> Policy:
        return cls(data, vault=vault, source="dict")

    @classmethod
    def default(cls) -> Policy:
        return cls.load(None)

    def derive(self, **overrides: Any) -> Policy:
        """New policy = this one with ``overrides`` merged on top (same vault)."""
        data = self.config.model_dump(mode="python", exclude={"vault"})
        data["vault"] = self.config.vault.model_dump(mode="python")
        if self.config.vault.key:
            data["vault"]["key"] = self.config.vault.key.get_secret_value()
        derived = Policy(
            merge_policy_dicts(data, overrides), vault=self.vault, source=f"derived:{self.name}"
        )
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

    def matching_rules(self, spec: Any, principal: Any, *, uri: str | None = None) -> list[_Rule]:
        kind = spec_kind(spec) if spec is not None else "tool"
        idents = idents_with_uri(spec, uri) if spec is not None else None
        return [r for r in self._rules if r.applies(spec, principal, kind, idents)]

    def decide(
        self, spec: Any, principal: Any = None, *, uri: str | None = None
    ) -> tuple[bool, str]:
        """``(allowed, reason)`` for ``principal`` using ``spec``. ``uri`` is
        the concrete URI requested through a resource template (or a static
        resource); deny / allow globs and rule names are matched against it
        too, raw and percent-decoded."""
        principal = self._principal(principal)
        key = (id(spec), getattr(spec, "name", None), self._roles_key(principal), uri)
        with self._lock:
            hit = self._decisions.get(key)
            if hit is not None and hit[0] is spec:
                return hit[1]
        rules = self.matching_rules(spec, principal, uri=uri)
        res = AccessDecision(self._base, self.name, rules, spec, uri).decide()
        with self._lock:
            # the entry holds a reference to the spec, so its id() cannot be
            # recycled for a different spec while cached
            self._decisions[key] = (spec, res)
            if len(self._decisions) > 8192:
                self._decisions.popitem(last=False)
        return res

    def is_allowed(self, spec: Any, principal: Any = None, *, uri: str | None = None) -> bool:
        """Visibility for list and call. With ``hide_denied: false``
        denied primitives stay listed (calls still fail)."""
        if not self.config.hide_denied:
            return True
        return self.decide(spec, principal, uri=uri)[0]

    def check_call(
        self,
        spec: Any,
        principal: Any,
        arguments: dict[str, Any] | None = None,
        *,
        uri: str | None = None,
    ) -> None:
        """Raise :class:`AccessDeniedError` / :class:`RateLimitedError`."""
        principal = self._principal(principal)
        allowed, reason = self.decide(spec, principal, uri=uri)
        kind = spec_kind(spec)
        name = _idents(spec)[0]
        if arguments and "__completion__" in arguments:
            kind = "completion"
        if not allowed:
            self.counters["denied"] += 1
            self._audit(("denied", kind, name), principal, arguments, reason)
            raise AccessDeniedError(
                f"Access to {kind} '{name}' denied: {reason}",
                data={"policy": self.name, "reason": reason},
            )
        try:
            self._rate_limit(spec, principal, (kind, name), uri)
        except RateLimitedError as exc:
            self.counters["rate_limited"] += 1
            self._audit(("rate_limited", kind, name), principal, arguments, exc.message)
            raise
        self.counters["allowed"] += 1
        if Capability.REVEAL in _caps(spec):
            self.counters["reveal"] += 1
            self._log_reveal(principal, kind, name, arguments)
            self._audit(("allowed", kind, name), principal, arguments, "reveal", force=True)
        else:
            self._audit(("allowed", kind, name), principal, arguments, "")

    # ------------------------------------------------------------------
    # Rate limiting
    # ------------------------------------------------------------------

    def _rate_limit(
        self, spec: Any, principal: Any, call: tuple[str, str], uri: str | None = None
    ) -> None:
        limits = list(self.config.rate_limits)
        for r in self.matching_rules(spec, principal, uri=uri):
            limits.extend(r.cfg.rate_limits)
        if not limits:
            return
        kind, name = call
        pid = str(getattr(principal, "id", "anonymous"))
        self._limiter.take(limits, (kind, name, idents_with_uri(spec, uri)), pid)

    def reset_rate_limits(self) -> None:
        self._limiter.reset()

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
    # Introspection
    # ------------------------------------------------------------------

    def detectors(self) -> DetectorRegistry:
        return self.registry

    def describe(self) -> dict[str, Any]:
        """Human / model readable summary. Never contains the vault key."""
        return describe_policy(self)

    def __repr__(self) -> str:
        return f"Policy(name={self.name!r}, source={self.source!r})"
