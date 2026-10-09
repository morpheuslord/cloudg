"""Privacy tools and resources: inspect the active policy, preview what it
does to data, list detectors, read the audit trail, and (for privileged
roles only) reverse pseudonyms.

=====================  =============  ==============================================
primitive              sensitivity    notes
=====================  =============  ==============================================
``privacy_status``     internal       active profile, denied capabilities, counts
``preview_transform``  internal       run the policy over sample JSON / text, with
                                      a throw-away vault (hidden by ``strict``)
``list_detectors``     public         detectors + the strategy each gets here
``privacy_audit_log``  restricted     recent access decisions (hashed arguments);
                                      only the caller's own entries unless it has
                                      the ``admin`` or ``privacy-admin`` role
``reveal_token``       restricted     needs ``Capability.REVEAL``; denied by
                                      ``standard`` except admin roles, always by
                                      ``strict``; every reveal is audited
``cloudg://policy``    internal       ``policy.describe()`` (never the vault key)
``cloudg://privacy/detectors``  public
=====================  =============  ==============================================

Handlers reach the policy through ``ctx.layer.policy``.
"""

from __future__ import annotations

import json
import logging
from typing import Annotated, Any

from pydantic import Field

from cloudg.mcp.core import Capability, Registry, Sensitivity
from cloudg.mcp.policy.audit import log_safe

CATEGORY = "privacy"
audit_logger = logging.getLogger("cloudg.mcp.audit")
#: Roles that may read every principal's audit entries.
AUDIT_ADMIN_ROLES = frozenset({"admin", "privacy-admin"})


def _policy(ctx: Any) -> Any:
    return ctx.layer.policy


def _redactor_for(policy: Any, principal: Any) -> Any:
    from cloudg.mcp.transforms import Redactor

    for t in policy._generic_pipeline(principal).transforms:
        if isinstance(t, Redactor):
            return t
    return None


def detector_table(
    policy: Any, principal: Any = None, category: str | None = None
) -> dict[str, Any]:
    """Detectors and key rules with the strategy the policy applies."""
    from cloudg.mcp.transforms.detectors import ENTITY_PARENTS
    from cloudg.mcp.transforms.redaction import _chain

    red = _redactor_for(policy, principal)
    rows = []
    for d in policy.detectors():
        if category and d.category != category:
            continue
        row = {
            "name": d.name,
            "entity": d.entity,
            "category": d.category,
            "confidence": d.confidence,
            "description": d.description,
            "enabled": d.enabled,
        }
        if red is not None:
            row["strategy"] = red.resolve(_chain(d.entity) + (d.name, d.category)).kind
            # a list, so entity names are values rather than keys that key
            # rules (account, name...) would act on
            refined = [
                {
                    "entity": e,
                    "strategy": red.resolve(_chain(e) + (d.entity, d.name, d.category)).kind,
                }
                for e, p in ENTITY_PARENTS.items()
                if p == d.entity
            ]
            if refined:
                row["refined"] = refined
            row["active"] = d.name in red.active_detectors
        rows.append(row)
    key_rules = []
    for r in policy.detectors().key_rules:
        if category and r.category != category:
            continue
        item = {
            "name": r.name,
            "entity": r.entity,
            "category": r.category,
            "key_pattern": r.pattern,
        }
        if red is not None:
            item["strategy"] = red._rule_strategy(r).kind
        key_rules.append(item)
    return {"policy": policy.name, "detectors": rows, "key_rules": key_rules}


# ---------------------------------------------------------------------------
# Handlers
# ---------------------------------------------------------------------------


def privacy_status(ctx: Any) -> dict[str, Any]:
    """Show the active privacy policy for the calling principal: profile,
    denied capabilities, sensitivity ceiling, what the output pipeline
    does (redaction / pseudonymisation / projection), pseudonym vault
    counts and access-decision counters. Identifiers in results may be
    pseudonyms: pass them back to tools unchanged."""
    policy = _policy(ctx)
    cfg = policy.config
    principal = ctx.principal
    pipeline = policy._generic_pipeline(principal)
    steps = []
    for t in pipeline.transforms:
        desc = t.describe() if hasattr(t, "describe") else {"type": t.name}
        steps.append(desc if isinstance(desc, dict) else {"type": t.name})
    vault = policy.vault.stats()
    return {
        "policy": policy.name,
        "description": cfg.description,
        "loaded_from": policy.source,
        "extends": policy.extends_chain,
        "principal": {"id": principal.id, "roles": sorted(principal.roles)},
        "max_sensitivity": cfg.max_sensitivity.value if cfg.max_sensitivity else None,
        "denied_capabilities": sorted(c.value for c in policy._base.deny_caps),
        "visible_tools": len(ctx.layer.list_tools(principal)),
        "output_pipeline": steps,
        "pseudonymisation": {
            "active": any(getattr(t, "reversible", False) for t in pipeline.transforms),
            "vault_scope": vault["scope"],
            "vault_entries": vault["entries"],
            "by_entity": vault["by_entity"],
            "key_source": vault["key_source"],
        },
        "audit_enabled": cfg.audit,
        "counters": dict(policy.counters),
    }


def preview_transform(
    ctx: Any,
    data: Annotated[
        Any,
        Field(description="JSON value (object / array / string) or text to transform"),
    ],
    tool: Annotated[
        str | None,
        Field(
            description="Preview with the pipeline of this tool (default: the policy's "
            "generic pipeline)"
        ),
    ] = None,
    parse_json: Annotated[
        bool, Field(description="Parse `data` as JSON when it is a JSON string")
    ] = True,
) -> dict[str, Any]:
    """Show how the active policy would transform some data for you:
    which values get redacted, masked, hashed, pseudonymised, projected
    or fenced as untrusted, plus the transform report. Pseudonyms in a
    preview come from a separate throw-away vault, so they never match the
    pseudonyms in real results; nothing is stored."""
    policy = _policy(ctx)
    spec = ctx.layer.get_tool(tool, ctx.principal) if tool else None
    value = data
    if parse_json and isinstance(data, str) and data.strip()[:1] in ("{", "["):
        try:
            value = json.loads(data)
        except ValueError:
            value = data
    transformed, report = policy.preview(value, spec, ctx.principal)
    return {
        "policy": policy.name,
        "tool": tool,
        "transformed": transformed,
        "report": report,
    }


def list_detectors(
    ctx: Any,
    category: Annotated[
        str | None,
        Field(
            description="Only this category: secret, credential, identifier, network, "
            "pii, temporal, free_text"
        ),
    ] = None,
) -> dict[str, Any]:
    """List the sensitive-entity detectors (content regexes and key-name
    rules) and the strategy the active policy applies to each
    (redact / mask / hash / pseudonymize / generalize / drop / keep)."""
    return detector_table(_policy(ctx), ctx.principal, category)


def privacy_audit_log(
    ctx: Any,
    limit: Annotated[int, Field(ge=1, le=1000, description="Most recent entries")] = 50,
    decision: Annotated[
        str | None, Field(description="Filter: allowed, denied or rate_limited")
    ] = None,
) -> dict[str, Any]:
    """Recent access decisions recorded by the policy (denials and
    rate-limit hits always; every call when the policy enables audit).
    Arguments appear as field names with keyed hashes, never values. Callers
    without the admin or privacy-admin role see only their own entries."""
    policy = _policy(ctx)
    principal = ctx.principal
    see_all = bool(AUDIT_ADMIN_ROLES & set(getattr(principal, "roles", ()) or ()))
    entries = list(policy.audit_log)
    if not see_all:
        pid = str(getattr(principal, "id", "anonymous"))
        entries = [e for e in entries if e.get("principal") == pid]
    if decision:
        entries = [e for e in entries if e.get("decision") == decision]
    return {
        "policy": policy.name,
        "audit_enabled": policy.config.audit,
        "scope": "all" if see_all else "own",
        "total": len(entries),
        "entries": entries[-limit:],
    }


def _alias_maps(ctx: Any, policy: Any) -> list[Any]:
    """Alias tables in the output pipelines of the tools the caller can
    see, i.e. the aliases that may appear in values they hold."""
    from cloudg.mcp.transforms.substitution import AliasMap, Substitution

    found: dict[int, Any] = {}
    for spec in ctx.layer.list_tools(ctx.principal):
        for t in policy.output_pipeline(spec, ctx.principal).transforms:
            maps = (
                t.alias_maps
                if isinstance(t, Substitution)
                else ([t] if isinstance(t, AliasMap) and t.aliases else [])
            )
            for m in maps:
                found.setdefault(id(m), m)
    return list(found.values())


def _log_reveal(ctx: Any, vault: Any, token: str, detail: str) -> None:
    """Audit one reveal: who, what kind, and a keyed hash of the input.
    Neither the pseudonym nor the revealed value is logged."""
    audit_logger.warning(
        "reveal_token principal=%s %s token_hash=%s",
        log_safe(ctx.principal.id),
        log_safe(detail),
        vault.hash_value(token, entity_type="audit"),
    )


def _reveal_aliased(ctx: Any, vault: Any, token: str, aliases: list[Any]) -> dict[str, Any]:
    """Aliased values (soc-analyst account names) wrap vault tokens:
    reverse aliases and tokens together, as tool inputs do."""
    from cloudg.mcp.transforms.base import TransformContext
    from cloudg.mcp.transforms.substitution import Depseudonymizer

    tctx = TransformContext(principal=ctx.principal, direction="input", vault=vault)
    real = Depseudonymizer(vault, aliases=aliases).apply(token, tctx)
    n = int(tctx.report.get("depseudonymized", 0))
    _log_reveal(ctx, vault, token, f"reversed={n}")
    return {"pseudonym": token, "found": n > 0, "value": real if n else None, "replaced": n}


def reveal_token(
    ctx: Any,
    token: Annotated[
        str,
        Field(
            description="A pseudonym (e.g. an account ID, ARN or IP from a result) or "
            "text containing pseudonyms",
            min_length=1,
            max_length=20000,
        ),
    ],
) -> dict[str, Any]:
    """Reverse pseudonymisation: return the real value behind a pseudonym
    (or replace every pseudonym inside a text). Privileged: it requires the
    `reveal` capability, and every call is audited."""
    policy = _policy(ctx)
    vault = policy.vault
    ns = vault.namespace_for(ctx.principal)
    entry = vault.entry(token, namespace=ns)
    if entry is None:
        aliases = _alias_maps(ctx, policy)
        if aliases:
            return _reveal_aliased(ctx, vault, token, aliases)
        text, n = vault.detokenize_text_count(token, namespace=ns)
        _log_reveal(ctx, vault, token, f"embedded_tokens={n}")
        return {"pseudonym": token, "found": n > 0, "value": text if n else None, "replaced": n}
    _log_reveal(ctx, vault, token, f"entity={entry['entity_type']}")
    return {
        "pseudonym": token,
        "found": True,
        "value": entry["value"],
        "entity_type": entry["entity_type"],
    }


def policy_resource(ctx: Any) -> dict[str, Any]:
    return _policy(ctx).describe()


def detectors_resource(ctx: Any) -> dict[str, Any]:
    return detector_table(_policy(ctx), ctx.principal)


# ---------------------------------------------------------------------------
# Registration
# ---------------------------------------------------------------------------

_READ = {"read_only": True, "open_world": False}

#: (handler, registration options) of every privacy tool.
_TOOLS: tuple[tuple[Any, dict[str, Any]], ...] = (
    (
        privacy_status,
        {
            "name": "privacy_status",
            "title": "Privacy policy status",
            "tags": ("privacy", "policy"),
            "sensitivity": Sensitivity.INTERNAL,
            "idempotent": True,
        },
    ),
    (
        preview_transform,
        {
            "name": "preview_transform",
            "title": "Preview privacy transforms",
            "tags": ("privacy", "policy"),
            "sensitivity": Sensitivity.INTERNAL,
            "idempotent": True,
            # The result is already transformed by the policy; do not
            # transform it again, and do not reverse pseudonyms in the sample.
            "transform_hints": {"skip": ["*"], "depseudonymize": False, "input_guard": False},
        },
    ),
    (
        list_detectors,
        {
            "name": "list_detectors",
            "title": "List sensitive-data detectors",
            "tags": ("privacy",),
            "sensitivity": Sensitivity.PUBLIC,
            "idempotent": True,
        },
    ),
    (
        privacy_audit_log,
        {
            "name": "privacy_audit_log",
            "title": "Privacy audit log",
            "tags": ("privacy", "audit"),
            "sensitivity": Sensitivity.RESTRICTED,
        },
    ),
    (
        reveal_token,
        {
            "name": "reveal_token",
            "title": "Reveal a pseudonym",
            "tags": ("privacy", "reveal"),
            "sensitivity": Sensitivity.RESTRICTED,
            "capabilities": (Capability.REVEAL,),
            "destructive": False,
            "idempotent": True,
            # Must see the token itself and return the real value untouched
            "transform_hints": {
                "pseudonymize": False,
                "depseudonymize": False,
                "input_guard": False,
                "skip": ["substitute", "alias"],
            },
        },
    ),
)

#: (handler, URI, registration options) of every privacy resource.
_RESOURCES: tuple[tuple[Any, str, dict[str, Any]], ...] = (
    (
        policy_resource,
        "cloudg://policy",
        {
            "name": "privacy_policy",
            "title": "Active privacy policy",
            "description": "The active access / transform policy (profiles, rules, transforms, "
            "rate limits, vault statistics; never the vault key).",
            "sensitivity": Sensitivity.INTERNAL,
        },
    ),
    (
        detectors_resource,
        "cloudg://privacy/detectors",
        {
            "name": "privacy_detectors",
            "title": "Sensitive-data detectors",
            "description": "Detectors and key rules with the strategy the policy applies to each.",
            "sensitivity": Sensitivity.PUBLIC,
        },
    ),
)


def register(registry: Registry) -> Registry:
    """Add the privacy tools and resources to ``registry``."""
    for fn, options in _TOOLS:
        registry.tool(category=CATEGORY, **_READ, **options)(fn)
    for fn, uri, options in _RESOURCES:
        registry.resource(uri, category=CATEGORY, **options)(fn)
    return registry


__all__ = ["AUDIT_ADMIN_ROLES", "CATEGORY", "detector_table", "register"]
