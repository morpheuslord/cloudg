"""Policy documents: the pydantic models, the packaged profiles and the
``extends`` merge (see :mod:`cloudg.mcp.policy`)."""

from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, SecretStr, ValidationError

from cloudg.mcp.core import Capability, Sensitivity
from cloudg.mcp.transforms.vault import VAULT_KEY_ENV

POLICY_ENV = "CLOUDG_MCP_POLICY"
PROFILES_DIR = Path(__file__).resolve().parent.parent / "policies"
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
            raise ValueError(
                f"Unknown policy to extend: {ref!r} (profiles: {', '.join(available_profiles())})"
            )
        parent_path = cand
    parent = resolve_extends(
        _read_file(parent_path), base_dir=parent_path.parent, _seen=(*_seen, ref)
    )
    merged = merge_policy_dicts(parent, data)
    parent_name = parent.get("name", ref)
    merged["_chain"] = [*parent.get("_chain", []), parent_name]
    if "name" not in data:
        merged["name"] = f"custom({parent_name})"
    return merged


def validate_config(data: dict[str, Any]) -> PolicyConfig:
    """``PolicyConfig`` from a resolved dict. A validation error is re-raised
    as ``ValueError`` listing field paths and messages only: pydantic's own
    text includes the offending input, which could be the vault key."""
    try:
        return PolicyConfig.model_validate(data)
    except ValidationError as exc:
        problems = "; ".join(
            f"{'.'.join(str(p) for p in err.get('loc', ())) or 'policy'}: {err.get('msg', '')}"
            for err in exc.errors(include_url=False, include_input=False)
        )
        raise ValueError(f"Invalid policy: {problems}") from None
