"""Policy descriptions: ``Policy.describe()`` and the fingerprint (see
:mod:`cloudg.mcp.policy`). Nothing here ever includes the vault key."""

from __future__ import annotations

import hashlib
import json
import re
from typing import TYPE_CHECKING, Any

from cloudg.mcp.policy.config import available_profiles
from cloudg.mcp.transforms import normalize_transform_spec

if TYPE_CHECKING:  # pragma: no cover
    from cloudg.mcp.policy.engine import Policy


def describe_policy(policy: Policy) -> dict[str, Any]:
    """Human / model readable summary. Never contains the vault key."""
    cfg = policy.config
    doc = cfg.model_dump(mode="json", exclude={"vault"}, exclude_none=True)
    for k in ("transforms", "input_transforms"):
        doc[k] = [_scrub(normalize_transform_spec(s)) for s in getattr(cfg, k)]
    doc["transform_options"] = _scrub(doc.get("transform_options", {}))
    vault_cfg = cfg.vault.model_dump(mode="json", exclude={"key"})
    doc["vault"] = {
        **vault_cfg,
        **policy.vault.stats(),
        "key_configured": cfg.vault.key is not None,
    }
    doc["loaded_from"] = policy.source
    doc["extends_chain"] = policy.extends_chain
    doc["effective_denied_capabilities"] = sorted(c.value for c in policy._base.deny_caps)
    doc["counters"] = dict(policy.counters)
    doc["available_profiles"] = available_profiles()
    return _strategy_lists(doc)


_SECRET_OPTION = re.compile(r"(?i)(?:^|_)(?:key|secret|password|token)$")


def _scrub(value: Any) -> Any:
    """Hide secret-looking option values (``key: ...``) in descriptions;
    strategy tables (``strategies: {secret: redact}``) are left alone."""
    if isinstance(value, dict):
        return {
            k: (
                v
                if k == "strategies"
                else "***"
                if isinstance(k, str) and _SECRET_OPTION.search(k) and isinstance(v, str)
                else _scrub(v)
            )
            for k, v in value.items()
        }
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
        return {
            k: (
                strategy_list(v)
                if k == "strategies" and isinstance(v, dict)
                else _strategy_lists(v)
            )
            for k, v in value.items()
        }
    if isinstance(value, list):
        return [_strategy_lists(v) for v in value]
    return value


def policy_fingerprint(policy: Policy) -> str:
    """Stable short hash of the effective configuration (no secrets)."""
    blob = json.dumps(policy.config.model_dump(mode="json", exclude={"vault"}), sort_keys=True)
    return hashlib.sha256(blob.encode()).hexdigest()[:16]
