"""Data transformation for the cloudg MCP layer.

Transforms rewrite JSON-like data on its way out of the layer (redaction,
masking, hashing, pseudonymisation, generalisation, projection,
substitution, annotation, untrusted-text sanitising) and on its way in
(reversing pseudonyms and aliases in arguments, refusing secrets).

Policies (:mod:`cloudg.mcp.policy`) declare transforms by name::

    transforms:
      - sanitize
      - type: redact
        options:
          strategies: {secret: redact, aws_account_id: pseudonymize}
      - {type: project, options: {exclude: ["**.raw_data"], max_chars: 150000}}
      - annotate

and :func:`build_transform` turns each entry into a :class:`Transform`.
Custom transform types can be added with :func:`register_transform`.
"""

from __future__ import annotations

from typing import Any, Callable

from cloudg.mcp.transforms.annotation import (
    INJECTION_PATTERNS,
    UNTRUSTED_NOTICE,
    Annotator,
    AnnotatorOptions,
    GuardOptions,
    UntrustedTextGuard,
    strip_invisible,
)
from cloudg.mcp.transforms.base import IDENTITY, Pipeline, Transform, TransformContext
from cloudg.mcp.transforms.detectors import (
    BUILTIN_DETECTORS,
    BUILTIN_KEY_RULES,
    CATEGORIES,
    DEFAULT_REGISTRY,
    ENTITY_PARENTS,
    Detector,
    DetectorRegistry,
    EntityMatch,
    KeyRule,
    classify_ip_text,
    detector_from_config,
    normalize_key,
    shannon_entropy,
)
from cloudg.mcp.transforms.projection import Projection, ProjectionOptions
from cloudg.mcp.transforms.redaction import (
    DROP,
    STRATEGIES,
    Redactor,
    RedactorOptions,
    SecretArgumentGuard,
    Strategy,
    generalize,
    parse_strategy,
)
from cloudg.mcp.transforms.substitution import (
    FENCE_CLOSE,
    FENCE_OPEN,
    AliasMap,
    Depseudonymizer,
    repseudonymize,
    KeyRename,
    RegexReplace,
    Substitution,
    TemplateField,
    load_alias_file,
    strip_fences,
)
from cloudg.mcp.transforms.vault import VAULT_KEY_ENV, TokenVault

TransformFactory = Callable[..., Transform]

#: Canonical transform type -> factory (called with the options as kwargs).
TRANSFORM_TYPES: dict[str, TransformFactory] = {
    "redact": Redactor,
    "sanitize": UntrustedTextGuard,
    "project": Projection,
    "annotate": Annotator,
    "substitute": Substitution,
    "alias": AliasMap,
    "regex_replace": RegexReplace,
    "rename_keys": KeyRename,
    "template": TemplateField,
    "depseudonymize": Depseudonymizer,
    "guard_secrets": SecretArgumentGuard,
}

_ALIASES = {
    "redaction": "redact",
    "redactor": "redact",
    "dlp": "redact",
    "sanitise": "sanitize",
    "untrusted": "sanitize",
    "untrusted_text": "sanitize",
    "projection": "project",
    "shape": "project",
    "annotation": "annotate",
    "annotations": "annotate",
    "annotator": "annotate",
    "substitution": "substitute",
    "aliases": "alias",
    "rename": "rename_keys",
    "templates": "template",
    "depseudonymise": "depseudonymize",
    "depseudonymizer": "depseudonymize",
    "secret_guard": "guard_secrets",  # nosec B105 - transform name, not a credential
    "reject_secrets": "guard_secrets",  # nosec B105 - transform name, not a credential
}


def canonical_transform_name(name: str) -> str:
    """``"redaction"`` / ``"Projection"`` -> ``"redact"`` / ``"project"``."""
    n = str(name).strip().lower().replace("-", "_")
    return _ALIASES.get(n, n)


def register_transform(name: str, factory: TransformFactory) -> None:
    """Make ``factory(**options)`` available to policies as ``type: name``."""
    TRANSFORM_TYPES[canonical_transform_name(name)] = factory


def normalize_transform_spec(spec: Any) -> dict[str, Any]:
    """``"redact"`` | ``{"type": "redact", "options": {...}}`` |
    ``{"type": "redact", "strategies": {...}}`` -> canonical
    ``{"type", "id", "options"}`` dict."""
    if isinstance(spec, str):
        t = canonical_transform_name(spec)
        return {"type": t, "id": t, "options": {}}
    if not isinstance(spec, dict):
        raise ValueError(f"Invalid transform spec {spec!r}")
    d = dict(spec)
    t = d.pop("type", None) or d.pop("transform", None) or d.pop("name", None)
    if not t:
        raise ValueError(f"Transform spec needs a 'type': {spec!r}")
    t = canonical_transform_name(t)
    ident = str(d.pop("id", t))
    opts = dict(d.pop("options", None) or {})
    opts.update(d)  # inline options
    return {"type": t, "id": ident, "options": opts}


def build_transform(spec: Any, **context: Any) -> Transform:
    """Build a transform from a policy entry.

    ``context`` supplies policy-level values that some transforms accept:
    ``vault`` (redact / depseudonymize), ``custom_detectors`` (redact /
    guard_secrets), ``profile`` (annotate).
    """
    if not isinstance(spec, (str, dict)) and hasattr(spec, "apply"):
        return spec  # already a transform
    norm = normalize_transform_spec(spec)
    factory = TRANSFORM_TYPES.get(norm["type"])
    if factory is None:
        raise ValueError(
            f"Unknown transform type {norm['type']!r}; known: {', '.join(sorted(TRANSFORM_TYPES))}"
        )
    opts = dict(norm["options"])
    t = norm["type"]
    if t in ("redact", "guard_secrets") and context.get("custom_detectors"):
        opts["custom_detectors"] = [*context["custom_detectors"], *opts.get("custom_detectors", [])]
    if t in ("redact", "depseudonymize") and context.get("vault") is not None:
        opts.setdefault("vault", context["vault"])
    if t == "annotate" and context.get("profile"):
        opts.setdefault("profile", context["profile"])
    try:
        return factory(**opts)
    except TypeError as exc:
        raise ValueError(f"Bad options for transform {t!r}: {exc}") from exc


__all__ = [
    "AnnotatorOptions",
    "GuardOptions",
    "ProjectionOptions",
    "RedactorOptions",
    "repseudonymize",
    "AliasMap",
    "Annotator",
    "BUILTIN_DETECTORS",
    "BUILTIN_KEY_RULES",
    "CATEGORIES",
    "DEFAULT_REGISTRY",
    "DROP",
    "Depseudonymizer",
    "Detector",
    "DetectorRegistry",
    "ENTITY_PARENTS",
    "EntityMatch",
    "FENCE_CLOSE",
    "FENCE_OPEN",
    "IDENTITY",
    "INJECTION_PATTERNS",
    "KeyRename",
    "KeyRule",
    "Pipeline",
    "Projection",
    "Redactor",
    "RegexReplace",
    "STRATEGIES",
    "SecretArgumentGuard",
    "Strategy",
    "Substitution",
    "TRANSFORM_TYPES",
    "TemplateField",
    "TokenVault",
    "Transform",
    "TransformContext",
    "UNTRUSTED_NOTICE",
    "UntrustedTextGuard",
    "VAULT_KEY_ENV",
    "build_transform",
    "canonical_transform_name",
    "classify_ip_text",
    "detector_from_config",
    "generalize",
    "load_alias_file",
    "normalize_key",
    "normalize_transform_spec",
    "parse_strategy",
    "register_transform",
    "shannon_entropy",
    "strip_fences",
    "strip_invisible",
]
