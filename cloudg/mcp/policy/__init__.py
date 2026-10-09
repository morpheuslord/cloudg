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

Roles come from the :class:`~cloudg.mcp.context.Principal`. Over HTTP with
OAuth, the granted token *scopes* become the principal's roles, so a token
carrying the scope ``admin`` or ``privacy-admin`` gets those roles (and, under
``standard``, the ``reveal`` capability). Issue such scopes only to people who
may see real identifiers.

Package layout: :mod:`.config` (documents, profiles, ``extends``),
:mod:`.access` (rule matching and allow / deny decisions), :mod:`.ratelimit`,
:mod:`.audit`, :mod:`.pipelines` (transform pipelines, previews),
:mod:`.describe` and :mod:`.engine` (:class:`Policy`). Everything public is
re-exported here.
"""

from __future__ import annotations

from cloudg.mcp.policy.access import (
    AccessDecision,
    _CompiledAccess,
    _Globs,
    _Rule,
    idents_with_uri,
    spec_kind,
)
from cloudg.mcp.policy.audit import AuditTrail, audit_logger, log_safe
from cloudg.mcp.policy.config import (
    DEFAULT_PROFILE,
    POLICY_ENV,
    PROFILES_DIR,
    AccessRules,
    PolicyConfig,
    RateLimitConfig,
    RuleConfig,
    RuleMatch,
    TransformSpecT,
    VaultConfig,
    available_profiles,
    merge_policy_dicts,
    resolve_extends,
)
from cloudg.mcp.policy.describe import policy_fingerprint, strategy_list
from cloudg.mcp.policy.engine import Policy
from cloudg.mcp.policy.pipelines import _aliases_after_redaction
from cloudg.mcp.policy.ratelimit import RateLimiter
from cloudg.mcp.policy.vaults import _save_vaults_at_exit

__all__ = [
    "DEFAULT_PROFILE",
    "POLICY_ENV",
    "PROFILES_DIR",
    "AccessDecision",
    "AccessRules",
    "AuditTrail",
    "Policy",
    "PolicyConfig",
    "RateLimitConfig",
    "RateLimiter",
    "RuleConfig",
    "RuleMatch",
    "TransformSpecT",
    "VaultConfig",
    "_CompiledAccess",
    "_Globs",
    "_Rule",
    "_aliases_after_redaction",
    "_save_vaults_at_exit",
    "audit_logger",
    "available_profiles",
    "idents_with_uri",
    "log_safe",
    "merge_policy_dicts",
    "policy_fingerprint",
    "resolve_extends",
    "spec_kind",
    "strategy_list",
]
