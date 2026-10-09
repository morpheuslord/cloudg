"""Entity taxonomy, detector / key-rule types and validators for the
privacy transforms (see :mod:`cloudg.mcp.transforms.detectors`)."""

from __future__ import annotations

import functools
import ipaddress
import math
import re
from collections import Counter
from dataclasses import dataclass
from typing import Any, Callable

# ---------------------------------------------------------------------------
# Entity taxonomy
# ---------------------------------------------------------------------------

#: Categories group entity types so a policy can say "redact every secret"
#: instead of listing each secret detector.
CATEGORIES: dict[str, str] = {
    "secret": "Material that grants access on its own: keys, passwords, tokens",  # nosec B105 - category description
    "credential": "Credential identifiers (e.g. AWS access key IDs), not secret alone",
    "identifier": "Cloud tenant / resource identifiers: accounts, ARNs, resource IDs",
    "network": "IP addresses, CIDR ranges, hostnames, MAC addresses",
    "pii": "Personal data: email addresses, people named in tags",
    "temporal": "Timestamps",
    "free_text": "Free-form values copied from the cloud (tag values)",
}

#: Refined entity -> parent entity. The redactor resolves a strategy for a
#: match by walking ``entity -> parent -> detector entity -> detector name
#: -> category -> default``.
ENTITY_PARENTS: dict[str, str] = {
    "cloud_account": "aws_account_id",
    "private_ip": "ip_address",
    "public_ip": "ip_address",
    "special_ip": "ip_address",
    "private_cidr": "cidr",
    "public_cidr": "cidr",
    "special_cidr": "cidr",
    "aws_unique_id": "aws_access_key_id",
    "azure_tenant_id": "azure_subscription_id",
    "gcp_project_number": "gcp_project_id",
}

Validator = Callable[[str], "bool | str | None"]


@dataclass(frozen=True)
class Detector:
    """One content detector.

    Args:
        name: Unique detector name.
        entity: Entity type it reports (validators may refine it).
        pattern: Regular expression. Use *numbered* groups only; ``group``
            selects the span reported as the entity (``0`` = whole match),
            which lets context patterns such as ``password=(\\S+)`` report
            just the value.
        category: One of :data:`CATEGORIES` (free-form names are allowed).
        confidence: 0..1, compared against a redactor's ``min_confidence``.
        flags: ``re`` flags.
        validator: ``fn(text) -> bool | str | None``; ``False``/``None``
            rejects the candidate, a string refines the entity type.
        min_length: Strings shorter than this are not scanned by this
            detector (cheap pre-filter).
    """

    name: str
    entity: str
    pattern: str
    category: str = "identifier"
    confidence: float = 0.8
    flags: int = 0
    validator: Validator | None = None
    group: int = 0
    description: str = ""
    enabled: bool = True
    min_length: int = 1
    #: Lowercase substrings; the regex only runs if one occurs in the text
    #: (empty = always run). A cheap pre-filter, not part of the match.
    hints: tuple[str, ...] = ()

    def compile(self) -> re.Pattern[str]:
        return _compile(self.pattern, self.flags)

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "entity": self.entity,
            "category": self.category,
            "confidence": self.confidence,
            "description": self.description,
            "enabled": self.enabled,
            "pattern": self.pattern,
        }


@dataclass(frozen=True)
class EntityMatch:
    """A detected span inside a string."""

    start: int
    end: int
    text: str
    entity: str
    detector: str
    category: str
    confidence: float

    @property
    def lookup_chain(self) -> tuple[str, ...]:
        """Keys used to resolve the strategy for this match, most specific
        first."""
        chain = [self.entity]
        parent = ENTITY_PARENTS.get(self.entity)
        while parent and parent not in chain:
            chain.append(parent)
            parent = ENTITY_PARENTS.get(parent)
        for extra in (self.detector, self.category):
            if extra not in chain:
                chain.append(extra)
        return tuple(chain)


_cache_compile: dict[tuple[str, int], re.Pattern[str]] = {}


def _compile(pattern: str, flags: int = 0) -> re.Pattern[str]:
    key = (pattern, flags)
    rx = _cache_compile.get(key)
    if rx is None:
        rx = _cache_compile[key] = re.compile(pattern, flags)
    return rx


# ---------------------------------------------------------------------------
# Validators
# ---------------------------------------------------------------------------

_PRIVATE_V4 = [
    ipaddress.ip_network(n)
    for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10")
]
_PRIVATE_V6 = [ipaddress.ip_network("fc00::/7")]


def ip_class(addr: ipaddress.IPv4Address | ipaddress.IPv6Address) -> str:
    """``private`` (RFC 1918, CGNAT, IPv6 ULA), ``special`` (unspecified,
    loopback, link-local incl. the 169.254.169.254 metadata endpoint,
    multicast, broadcast, reserved) or ``public``."""
    if (
        addr.is_unspecified
        or addr.is_loopback
        or addr.is_link_local
        or addr.is_multicast
        or (addr.version == 4 and addr.is_reserved)
        or str(addr) == "255.255.255.255"
    ):
        return "special"
    nets = _PRIVATE_V4 if addr.version == 4 else _PRIVATE_V6
    if any(addr in n for n in nets):
        return "private"
    return "public"


@functools.lru_cache(maxsize=65536)
def classify_ip_text(text: str) -> str | None:
    """Validate an IP or CIDR string and return its refined entity
    (``private_ip`` / ``public_cidr`` / ...), or ``None`` if invalid."""
    try:
        if "/" in text:
            net = ipaddress.ip_network(text, strict=False)
            if net.prefixlen == 0:
                return "special_cidr"
            return f"{ip_class(net.network_address)}_cidr"
        addr = ipaddress.ip_address(text.split("%", 1)[0])
    except ValueError:
        return None
    return f"{ip_class(addr)}_ip"


def _ipv6_validator(text: str) -> str | None:
    """IPv6 candidates need real structure: ``"::"`` alone (C++ scopes,
    ``arn:...::``) is only accepted as the ``::/0`` route."""
    addr = text.split("/", 1)[0]
    groups = [g for g in addr.split(":") if g]
    if addr == "::":
        ok = "/" in text  # only the ::/0 route
    elif addr == "::1" or len(groups) >= 3:
        ok = True
    else:  # "fe80::1", "2600:1f18::/32" yes; "a::b", "foo::ba" no
        ok = len(groups) == 2 and ("/" in text or max(len(g) for g in groups) >= 3)
    if not ok:
        return None
    return classify_ip_text(text)


def shannon_entropy(text: str) -> float:
    """Bits of entropy per character."""
    if not text:
        return 0.0
    n = len(text)
    return -sum(c / n * math.log2(c / n) for c in Counter(text).values())


_HEX_RE = re.compile(r"^[0-9a-fA-F]+$")
_WORDISH_RE = re.compile(r"[a-z]{4,}")
_DIGIT_RE = re.compile(r"\d")


def _mixed_case(s: str) -> bool:
    """Has both a lowercase and an uppercase letter (fast path for ASCII)."""
    if s.isascii():
        return s.lower() != s and s.upper() != s
    return any(c.islower() for c in s) and any(c.isupper() for c in s)


def looks_like_secret(text: str, min_entropy: float = 4.0) -> bool:
    """Heuristic for opaque high-entropy tokens: long, mixed case + digits,
    not hex (hashes), not a path or slug made of words."""
    s = text.rstrip("=")
    if len(s) < 32 or _HEX_RE.match(s):
        return False
    if not _mixed_case(s) or not _DIGIT_RE.search(s):
        return False
    if len(_WORDISH_RE.findall(s)) >= 3:
        return False
    return shannon_entropy(s) >= min_entropy


_NOT_SECRET_VALUES = {
    "null",
    "none",
    "true",
    "false",
    "undefined",
    "redacted",
    "****",
    "******",
    "xxx",
    "changeme?",
    "<redacted>",
    "n/a",
    "na",
    "empty",
    "string",
    "required",
    "optional",
}


def _secret_value(text: str) -> bool:
    t = text.strip().strip("\"'").lower()
    if not t or t in _NOT_SECRET_VALUES or t.startswith(("[redacted", "${", "{{", "<")):
        return False
    return not set(t) <= {"*", "x", "#", "-", ".", ",", "\u2026"}


def _valid_account(text: str) -> bool:
    return len(set(text)) > 1  # 000000000000 / 111111111111 are placeholders


# ---------------------------------------------------------------------------
# Key rules
# ---------------------------------------------------------------------------


def normalize_key(key: str) -> str:
    """``SecretAccessKey`` / ``secret-access-key`` -> ``secret_access_key``."""
    return _NON_ALNUM.sub("_", _CAMEL.sub("_", key).lower()).strip("_")


_CAMEL = re.compile(r"(?<=[a-z0-9])(?=[A-Z])")
_NON_ALNUM = re.compile(r"[^a-z0-9]+")


@dataclass(frozen=True)
class KeyRule:
    """Treat whole values under matching keys as one entity.

    ``pattern`` is matched (``re.search``) against the *normalised* key
    (see :func:`normalize_key`); ``exclude`` vetoes a match.
    ``requires_sibling`` limits the rule to dicts that also contain one of
    the given (normalised) keys. That is how ``name`` counts as an identifier
    only inside asset-like objects, not in every catalog listing. ``subtree``
    applies the entity to every leaf string below the key (credentials
    objects); otherwise only scalar values are affected. ``defer`` lets the
    content detectors decide first: when the whole value is itself a detected
    entity (an ARN under ``source``, ``0.0.0.0/0`` under ``target``) it gets
    that entity's treatment, and the rule's entity applies only otherwise.
    ``map_keys`` applies the entity to the *keys* of a mapping under the key
    (``{"by_account_pair": {"111... -> 222...": 2}}``).
    """

    name: str
    entity: str
    pattern: str
    category: str = "secret"
    exclude: str | None = None
    requires_sibling: frozenset[str] = frozenset()
    subtree: bool = False
    scalars: bool = False  # also apply to int/float values
    confidence: float = 0.9
    defer: bool = False
    map_keys: bool = False

    def matches(self, nkey: str) -> bool:
        if not _compile(self.pattern).search(nkey):
            return False
        return not (self.exclude and _compile(self.exclude).search(nkey))

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "entity": self.entity,
            "category": self.category,
            "pattern": self.pattern,
            "requires_sibling": sorted(self.requires_sibling),
            "defer": self.defer,
        }


_GUID = r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
_GUID_RE = re.compile(rf"^{_GUID}$")
_GCP_PROJECT_RE = re.compile(r"^[a-z][a-z0-9\-]{4,28}[a-z0-9]$")


def account_entity(value: str) -> str:
    """Entity type of an account-like value, from its shape: 12 digits ->
    ``aws_account_id``, a GUID -> ``azure_subscription_id``, a GCP project id
    -> ``gcp_project_id``, other digits -> ``gcp_project_number``, anything
    else -> ``cloud_account``."""
    v = value.strip()
    if v.isdigit():
        return "aws_account_id" if len(v) == 12 else "gcp_project_number"
    if _GUID_RE.match(v):
        return "azure_subscription_id"
    if _GCP_PROJECT_RE.match(v):
        return "gcp_project_id"
    return "cloud_account"


_ORG_ID_RE = re.compile(r"^o-[a-z0-9]{2,32}$")
_OU_ID_RE = re.compile(r"^ou-[a-z0-9\-]{2,64}$")
_ROOT_ID_RE = re.compile(r"^r-[a-z0-9]{2,32}$")


def ref_entity(value: str) -> str:
    """Entity type of a reference (an ``id`` / ``ref`` / ``parent_id``
    value): 12 digits -> ``aws_account_id``, a GUID -> ``uuid`` (cloudg's own
    random asset ids), AWS Organizations ids -> ``aws_org_id`` /
    ``aws_ou_id`` / ``aws_root_id``, anything else -> ``resource_name`` (so
    the token equals the one the same value gets under ``name``)."""
    v = value.strip()
    if v.isdigit() and len(v) == 12:
        return "aws_account_id"
    if _GUID_RE.match(v):
        return "uuid"
    if _OU_ID_RE.match(v):
        return "aws_ou_id"
    if _ORG_ID_RE.match(v):
        return "aws_org_id"
    if _ROOT_ID_RE.match(v):
        return "aws_root_id"
    return "resource_name"
