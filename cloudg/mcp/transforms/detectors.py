"""Sensitive-entity detectors for the cloudg MCP privacy transforms.

The design follows the analyzer / anonymizer split used by Microsoft
Presidio and the infoType model of Google Cloud DLP: a *detector* only
finds spans of a given *entity type* (``aws_account_id``,
``private_key``, ``public_ip``...) with a confidence score; what happens to
a span (redact, mask, hash, pseudonymise, generalise, drop, keep) is
decided separately by the :class:`~cloudg.mcp.transforms.redaction.Redactor`
from the active policy.

Two kinds of detection exist:

* Content detectors (:class:`Detector`): a regular expression plus an
  optional validator, run over string values. A validator can reject a
  candidate (``False``) or refine its entity type by returning a string (the IP
  detectors return ``private_ip`` / ``public_ip`` / ``special_ip`` /
  ``private_cidr``...).
* Key rules (:class:`KeyRule`): the *field name* decides. Anything
  under ``password`` / ``client_secret`` / ``connection_string`` /
  ``user_data``... is a secret whatever it looks like; ``subscription_id``
  holds an Azure subscription GUID; ``tags`` hold free-form (possibly
  personal) values.

Performance matters (datasets have 50k+ assets): regexes are compiled once,
each detector carries cheap lowercase substring *hints* so its regex only
runs on strings that could match, and the redactor caches per-string
results.

Custom detectors can be declared in a policy::

    detectors:
      - name: employee_id
        entity: employee_id
        category: pii
        pattern: "\\bEMP-\\d{6}\\b"
        confidence: 0.9
"""

from __future__ import annotations

import ipaddress
import math
import re
from collections import Counter
from dataclasses import dataclass, field, replace
from typing import Any, Callable, Iterable, Iterator

# ---------------------------------------------------------------------------
# Entity taxonomy
# ---------------------------------------------------------------------------

#: Categories group entity types so a policy can say "redact every secret"
#: instead of listing each secret detector.
CATEGORIES: dict[str, str] = {
    "secret": "Material that grants access on its own: keys, passwords, tokens",
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


def looks_like_secret(text: str, min_entropy: float = 4.0) -> bool:
    """Heuristic for opaque high-entropy tokens: long, mixed case + digits,
    not hex (hashes), not a path or slug made of words."""
    s = text.rstrip("=")
    if len(s) < 32 or _HEX_RE.match(s):
        return False
    if not (any(c.islower() for c in s) and any(c.isupper() for c in s)):
        return False
    if not any(c.isdigit() for c in s):
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
# Built-in detectors (order = priority when spans start at the same place)
# ---------------------------------------------------------------------------

_OCTET = r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)"
_IPV4 = rf"{_OCTET}(?:\.{_OCTET}){{3}}"
_GUID = r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
_TLDS = (
    "com|net|org|io|dev|app|cloud|ai|co|biz|info|me|us|uk|de|fr|jp|in|au|ca|eu|nl|se|ch|"
    "es|it|br|sg|kr|cn|ru|internal|local|localdomain|lan|corp|intra|gov|edu|mil|tech|site"
)
_URL_STOP = r"[^\s\"'<>,;)\]}]"

BUILTIN_DETECTORS: tuple[Detector, ...] = (
    Detector(
        "cloudg_uri",
        "cloudg_uri",
        r"cloudg://(?:assets|datasets)/[^\s\"'<>,;)\]}]+",
        category="identifier",
        confidence=0.99,
        min_length=16,
        description="cloudg resource URIs naming an asset or dataset",
    ),
    # -- secrets ---------------------------------------------------------
    Detector(
        "private_key",
        "private_key",
        r"-----BEGIN[ A-Z0-9]*PRIVATE KEY(?: BLOCK)?-----[\s\S]*?"
        r"(?:-----END[ A-Z0-9]*PRIVATE KEY(?: BLOCK)?-----|\Z)",
        category="secret",
        confidence=1.0,
        min_length=30,
        description="PEM / OpenSSH / PGP private key blocks",
    ),
    Detector(
        "jwt",
        "jwt",
        r"\beyJ[A-Za-z0-9_\-]{5,}\.eyJ[A-Za-z0-9_\-]{5,}\.[A-Za-z0-9_\-]*",
        category="secret",
        confidence=0.95,
        min_length=20,
        description="JSON Web Tokens",
    ),
    Detector(
        "url_credentials",
        "password",
        r"\b[a-zA-Z][a-zA-Z0-9+.\-]{1,20}://[^\s:/@\"'<>]*:([^\s@/\"'<>]+)@",
        category="secret",
        confidence=0.95,
        group=1,
        min_length=10,
        validator=_secret_value,
        description="Password in the userinfo part of a URL",
    ),
    Detector(
        "url_userinfo",
        "url_username",
        r"\b[a-zA-Z][a-zA-Z0-9+.\-]{1,20}://([^\s:/@\"'<>]+)@",
        category="pii",
        confidence=0.9,
        group=1,
        min_length=8,
        description="User name in the userinfo part of a URL (no password)",
    ),
    Detector(
        "connection_string_secret",
        "password",
        r"(?i:(?:password|pwd|accountkey|sharedaccesskey|sharedsecret|clientsecret)\s*=\s*)"
        r"([^;\s\"']+)",
        category="secret",
        confidence=0.95,
        group=1,
        min_length=6,
        validator=_secret_value,
        description="Secret parts of key=value;... connection strings",
    ),
    Detector(
        "aws_secret_access_key",
        "aws_secret_access_key",
        r"(?i:aws.{0,20}?(?:secret|sk).{0,20}?[\"'\s:=]+)([A-Za-z0-9/+=]{40})(?![A-Za-z0-9/+=])",
        category="secret",
        confidence=0.95,
        group=1,
        min_length=40,
        description="AWS secret access keys next to an aws_secret_* label",
    ),
    Detector(
        "secret_assignment",
        "secret_value",
        r"(?i:\b(?:password|passwd|pwd|secret|client[_-]?secret|api[_-]?key|apikey|"
        r"access[_-]?token|auth[_-]?token|refresh[_-]?token|bearer|token|private[_-]?key|"
        r"secret[_-]?key|passphrase)\b[\"']?\s*[:=]\s*[\"']?)([^\s\"',;}{]{4,})",
        category="secret",
        confidence=0.85,
        group=1,
        min_length=8,
        validator=_secret_value,
        description="A password, token or API key assigned a value inside text",
    ),
    Detector(
        "authorization_header",
        "secret_value",
        r"(?i:\b(?:bearer|basic)\s+)([A-Za-z0-9\-._~+/]{16,}=*)",
        category="secret",
        confidence=0.9,
        group=1,
        min_length=20,
        description="HTTP Authorization header credentials",
    ),
    Detector(
        "github_token",
        "api_token",
        r"\b(?:gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{22,255})\b",
        category="secret",
        confidence=0.99,
        min_length=30,
    ),
    Detector(
        "slack_token",
        "api_token",
        r"\bxox[abposr]-[A-Za-z0-9\-]{10,}\b",
        category="secret",
        confidence=0.99,
        min_length=15,
    ),
    Detector(
        "google_api_key",
        "api_token",
        r"\bAIza[0-9A-Za-z_\-]{35}\b",
        category="secret",
        confidence=0.99,
        min_length=39,
    ),
    Detector(
        "stripe_key",
        "api_token",
        r"\b(?:sk|rk|pk)_(?:live|test)_[0-9A-Za-z]{16,}\b",
        category="secret",
        confidence=0.99,
        min_length=24,
    ),
    Detector(
        "azure_sas_signature",
        "secret_value",
        r"(?i:\bsig=)([A-Za-z0-9%+/=]{20,})",
        category="secret",
        confidence=0.95,
        group=1,
        min_length=24,
        description="Signature of an Azure shared access signature URL",
    ),
    Detector(
        "azure_storage_key",
        "secret_value",
        r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{86}==(?![A-Za-z0-9+/=])",
        category="secret",
        confidence=0.8,
        min_length=88,
        description="88-character base64 Azure storage account keys",
    ),
    # -- credentials / identifiers ----------------------------------------
    Detector(
        "aws_access_key_id",
        "aws_access_key_id",
        r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b",
        category="credential",
        confidence=0.99,
        min_length=20,
        description="AWS access key IDs (long-term AKIA, temporary ASIA)",
    ),
    Detector(
        "aws_unique_id",
        "aws_unique_id",
        r"\b(?:AIDA|AROA|AGPA|AIPA|ANPA|ANVA|APKA|ABIA|ACCA)[A-Z0-9]{16,17}\b",
        category="identifier",
        confidence=0.95,
        min_length=20,
        description="AWS IAM unique IDs (users, roles, groups...)",
    ),
    Detector(
        "aws_org_id",
        "aws_org_id",
        r"\bo-[a-z0-9]{10,32}\b",
        category="identifier",
        confidence=0.85,
        min_length=12,
        description="AWS Organizations organization ids",
    ),
    Detector(
        "aws_ou_id",
        "aws_ou_id",
        r"\bou-[a-z0-9]{4,32}-[a-z0-9]{8,32}\b",
        category="identifier",
        confidence=0.9,
        min_length=16,
        description="AWS Organizations organizational unit ids",
    ),
    Detector(
        "aws_root_id",
        "aws_root_id",
        r"(?<![\w\-])r-[a-z0-9]{4,32}\b(?!-)",
        category="identifier",
        confidence=0.7,
        min_length=6,
        description="AWS Organizations root ids",
    ),
    Detector(
        "cloudg_iri",
        "cloudg_iri",
        r"(?:\bcmr:|https://cloudg\.io/resource/)[^\s\"'<>,;)\]}]+",
        category="identifier",
        confidence=0.95,
        min_length=6,
        description="cloudg ontology resource IRIs (assets, tags) embedding identifiers",
    ),
    Detector(
        "aws_arn",
        "aws_arn",
        r"\barn:(?:aws|aws-cn|aws-us-gov|aws-iso(?:-[a-z])?):[a-zA-Z0-9\-]*:[a-z0-9\-]*:"
        rf"(?:\d{{12}}|aws)?:{_URL_STOP}+",
        category="identifier",
        confidence=0.99,
        min_length=12,
    ),
    Detector(
        "azure_resource_id",
        "azure_resource_id",
        rf"(?i:/subscriptions/{_GUID}(?:/[^\s/\"'<>,;?#]+)*)",
        category="identifier",
        confidence=0.99,
        min_length=50,
    ),
    Detector(
        "gcp_resource_name",
        "gcp_resource_name",
        r"//[a-z0-9\-]+\.googleapis\.com/(?:[^\s/\"'<>,;?#]+/?)+"
        r"|\b(?:projects|organizations|folders)/(?:[a-z][a-z0-9\-]{4,28}[a-z0-9]|\d{6,20})"
        r"(?:/[^\s/\"'<>,;?#]+)*",
        category="identifier",
        confidence=0.95,
        min_length=12,
        description="GCP full resource names (//svc.googleapis.com/...) and relative names",
    ),
    Detector(
        "azure_subscription_ref",
        "azure_subscription_id",
        rf"(?i:(?:subscription|tenant)[_ ]?id[\"']?\s*[:=]\s*[\"']?)({_GUID})",
        category="identifier",
        confidence=0.9,
        group=1,
        min_length=40,
    ),
    Detector(
        "email",
        "email",
        r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9](?:[A-Za-z0-9\-]*[A-Za-z0-9])?"
        r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9\-]*[A-Za-z0-9])?)*\.[A-Za-z]{2,24}\b",
        category="pii",
        confidence=0.95,
        min_length=6,
    ),
    # -- network ---------------------------------------------------------
    Detector(
        "ipv6",
        "ip_address",
        r"(?<![0-9A-Fa-f:.])(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}(?:/\d{1,3})?"
        r"(?![0-9A-Fa-f:])",
        category="network",
        confidence=0.9,
        validator=_ipv6_validator,
        min_length=2,
        description="IPv6 addresses and CIDRs (validated with ipaddress)",
    ),
    Detector(
        "ipv4",
        "ip_address",
        rf"(?<![\d.]){_IPV4}(?:/(?:3[0-2]|[12]?\d))?(?!\.?\d)",
        category="network",
        confidence=0.9,
        validator=classify_ip_text,
        min_length=7,
        description="IPv4 addresses and CIDRs (validated with ipaddress)",
    ),
    Detector(
        "mac_address",
        "mac_address",
        r"\b[0-9A-Fa-f]{2}(?:[:\-][0-9A-Fa-f]{2}){5}\b",
        category="network",
        confidence=0.8,
        min_length=17,
    ),
    Detector(
        "hostname",
        "hostname",
        rf"(?i:\b(?:[a-z0-9](?:[a-z0-9\-]{{0,61}}[a-z0-9])?\.)+(?:{_TLDS})\b)(?![\-.]?\w)",
        category="network",
        confidence=0.7,
        min_length=4,
        description="Fully-qualified DNS names with a common TLD",
    ),
    Detector(
        "aws_account_id",
        "aws_account_id",
        r"(?<![A-Za-z0-9_.\-/])\d{12}(?![A-Za-z0-9_\-]|\.\d)",
        category="identifier",
        confidence=0.7,
        validator=_valid_account,
        min_length=12,
        description="Bare 12-digit numbers (AWS account IDs)",
    ),
    # -- low-confidence / opt-in -----------------------------------------
    Detector(
        "timestamp",
        "timestamp",
        r"\b\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}(?::\d{2}(?:\.\d+)?)?(?:Z|[+\-]\d{2}:?\d{2})?",
        category="temporal",
        confidence=0.9,
        min_length=16,
    ),
    Detector(
        "uuid",
        "uuid",
        rf"\b{_GUID}\b",
        category="identifier",
        confidence=0.6,
        min_length=36,
        description="Generic UUIDs (opt in only: cloudg's own asset IDs are UUIDs)",
    ),
    Detector(
        "high_entropy_secret",
        "secret_value",
        r"(?<![A-Za-z0-9+/_\-])[A-Za-z0-9+/_\-]{32,}={0,2}(?![A-Za-z0-9+/=_\-])",
        category="secret",
        confidence=0.5,
        validator=looks_like_secret,
        min_length=32,
        description="Opaque high-entropy tokens (mixed case + digits, entropy >= 4 bits/char)",
    ),
)

_HINTS: dict[str, tuple[str, ...]] = {
    "private_key": ("private key",),
    "jwt": ("eyj",),
    "url_credentials": ("://",),
    "url_userinfo": ("://",),
    "cloudg_uri": ("cloudg://",),
    "aws_org_id": ("o-",),
    "aws_ou_id": ("ou-",),
    "aws_root_id": ("r-",),
    "cloudg_iri": ("cmr:", "cloudg.io/resource/"),
    "connection_string_secret": (
        "password",
        "pwd",
        "accountkey",
        "sharedaccesskey",
        "sharedsecret",
        "clientsecret",
    ),
    "aws_secret_access_key": ("aws",),
    "secret_assignment": ("pass", "pwd", "secret", "key", "token", "bearer"),
    "authorization_header": ("bearer", "basic"),
    "github_token": ("gh", "github_pat_"),
    "slack_token": ("xox",),
    "google_api_key": ("aiza",),
    "stripe_key": ("_live_", "_test_"),
    "azure_sas_signature": ("sig=",),
    "azure_storage_key": ("==",),
    "aws_access_key_id": ("akia", "asia"),
    "aws_unique_id": ("aida", "aroa", "agpa", "aipa", "anpa", "anva", "apka", "abia", "acca"),
    "aws_arn": ("arn:",),
    "azure_resource_id": ("/subscriptions/",),
    "gcp_resource_name": ("googleapis.com", "projects/", "organizations/", "folders/"),
    "azure_subscription_ref": ("subscription", "tenant"),
    "email": ("@",),
    "ipv6": (":",),
    "ipv4": (".",),
    "mac_address": (":", "-"),
    "hostname": (".",),
    "aws_account_id": ("0", "1", "2", "3", "4", "5", "6", "7", "8", "9"),
    "timestamp": ("-",),
    "uuid": ("-",),
}
BUILTIN_DETECTORS = tuple(replace(d, hints=_HINTS.get(d.name, ())) for d in BUILTIN_DETECTORS)

# ---------------------------------------------------------------------------
# Key rules
# ---------------------------------------------------------------------------


def normalize_key(key: str) -> str:
    """``SecretAccessKey`` / ``secret-access-key`` -> ``secret_access_key``."""
    return _NON_ALNUM.sub("_", _CAMEL.sub("_", key).lower()).strip("_")


_CAMEL = re.compile(r"(?<=[a-z0-9])(?=[A-Z])")
_NON_ALNUM = re.compile(r"[^a-z0-9]+")


SENSITIVE_KEY_PATTERN = (
    r"(?:^|_)(?:password|passwd|pwd|passphrase|secret|secrets|client_secret|api_key|apikey|"
    r"access_key|secret_key|secret_access_key|private_key|privatekey|token|tokens|"
    r"access_token|refresh_token|id_token|session_token|auth_token|bearer|credential|"
    r"credentials|authorization|auth|cookie|cookies|connection_string|connectionstring|"
    r"conn_str|sas_token|sas|signature|user_data|userdata|primary_key|secondary_key|"
    r"account_key|shared_key|master_key|admin_password|kubeconfig|pem)(?:$|_)"
)

#: Suffixes / prefixes that make a sensitive-looking key describe metadata
#: about the secret rather than the secret itself (``password_last_used``,
#: ``kms_key_id``, ``has_password``...).
SAFE_KEY_PATTERN = (
    r"(?:_(?:id|ids|arn|arns|name|names|type|types|state|status|usage|spec|enabled|"
    r"last_used|last_used_date|last_changed|last_rotated|age|length|count|policy|policies|"
    r"rotation\w*|expir\w*|created\w*|date|time|version|versions|present|required|set|"
    r"configured|manager|managers|source|format|algorithm|kind|ref|reference|location|uri|"
    r"url|endpoint|endpoints|header|scheme|method|mode|provider|issuer|audience|ttl|"
    r"lifetime|reset_required|exists|level|size|fingerprint|thumbprint|hint)$)"
    r"|^(?:has|is|num|require|requires|allow|allows|enable|enabled|use|uses|max|min)_"
)


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


#: Keys that mark a dict as describing a cloud asset (``name`` / ``id`` in it
#: are then identifiers). Generic keys such as ``type`` or ``kind`` are left
#: out on purpose: policy descriptions and dataset listings use them too.
_ASSET_SIBLINGS = frozenset(
    {"asset_type", "arn", "provider", "resource_type", "account_id", "region"}
)
#: Keys of AWS Organizations structures (accounts, OUs, the organization).
_ORG_SIBLINGS = frozenset(
    {
        "parent_id",
        "ou_path",
        "feature_set",
        "management_account_id",
        "ous",
        "joined_method",
        "master_account_id",
        "organization_id",
    }
)

BUILTIN_KEY_RULES: tuple[KeyRule, ...] = (
    KeyRule(
        "sensitive_key",
        "sensitive_field",
        SENSITIVE_KEY_PATTERN,
        category="secret",
        exclude=SAFE_KEY_PATTERN,
        subtree=True,
        scalars=True,
    ),
    KeyRule(
        "account_id_key",
        "cloud_account",
        r"(?:^|_)(?:account|accounts|account_id|account_ids|owner_id|owner_account_id)"
        r"(?:_affected)?$|^accounts?_affected$",
        category="identifier",
        defer=True,
    ),
    KeyRule(
        "account_map_key",
        "cloud_account",
        r"^(?:by_account(?:_pair|_region|_id)?|services_by_account(?:_region)?|"
        r"\w+_by_account|account_pairs)$",
        category="identifier",
        defer=True,
        map_keys=True,
    ),
    KeyRule(
        "org_id_key",
        "resource_ref",
        r"^(?:organization_id|organisation_id|org_id|root_id|ou_id|ou_ids|"
        r"parent_ou_id)$",
        category="identifier",
        defer=True,
    ),
    KeyRule(
        "subscription_key",
        "azure_subscription_id",
        r"^(?:azure_)?subscription(?:_id)?$",
        category="identifier",
        defer=True,
    ),
    KeyRule(
        "tenant_key",
        "azure_tenant_id",
        r"^(?:azure_)?tenant(?:_id)?$",
        category="identifier",
        defer=True,
    ),
    KeyRule(
        "gcp_project_key",
        "gcp_project_id",
        r"^(?:gcp_)?project(?:_id)?$",
        category="identifier",
        defer=True,
    ),
    KeyRule(
        "gcp_project_number_key",
        "gcp_project_number",
        r"^project_number$",
        category="identifier",
        scalars=True,
        defer=True,
    ),
    KeyRule(
        "resource_name_key",
        "resource_name",
        r"^(?:resource_name|display_name|bucket_name|function_name|instance_name|"
        r"cluster_name|db_name|database_name|computer_name|vm_name|role_name|user_name|"
        r"username|group_name|key_name|table_name|queue_name|topic_name|repository_name|"
        r"asset_name|source_name|target_name|resource_names|asset_names|account_name|"
        r"ou_name|ou_path|ou_names|org_name|organization_name|subject|object)$",
        category="identifier",
        defer=True,
    ),
    KeyRule(
        "resource_ref_key",
        "resource_ref",
        r"^(?:ref|refs|asset_ref|asset_refs|asset_id|asset_ids|resource_id|resource_ids|"
        r"resource|asset|source|target|source_id|target_id|source_ref|target_ref|"
        r"node|node_id|nodes|from|to|start|end|via|members|neighbors|neighbours|path|"
        r"parent_id|parent|parent_ids|child_id|child_ids|children|dependency_id|"
        r"dependency_ids|dependent_id|dependent_ids|subject_id|object_id|entry|entry_id|"
        r"exit|candidate|candidates)$",
        category="identifier",
        defer=True,
    ),
    KeyRule(
        "dataset_key",
        "dataset_name",
        r"^(?:dataset|dataset_name|datasets|active_dataset|base|base_dataset|"
        r"target_dataset)$",
        category="identifier",
        defer=True,
    ),
    KeyRule(
        "dataset_listing_name_key",
        "dataset_name",
        r"^name$",
        category="identifier",
        requires_sibling=frozenset({"loaded_at", "compliance_results"}),
        defer=True,
    ),
    KeyRule(
        "asset_name_key",
        "resource_name",
        r"^name$",
        category="identifier",
        requires_sibling=_ASSET_SIBLINGS,
        defer=True,
    ),
    KeyRule(
        "asset_id_key",
        "resource_ref",
        r"^id$",
        category="identifier",
        requires_sibling=_ASSET_SIBLINGS | _ORG_SIBLINGS,
        defer=True,
    ),
    KeyRule(
        "org_name_key",
        "resource_name",
        r"^name$",
        category="identifier",
        requires_sibling=_ORG_SIBLINGS,
        defer=True,
    ),
    KeyRule("rag_chunk_id_key", "rag_chunk_id", r"^(?:chunk_id|chunk_ids)$", category="identifier"),
    KeyRule(
        "rag_content_key",
        "rag_content",
        r"^content$",
        category="identifier",
        requires_sibling=frozenset({"chunk_type", "chunk_id"}),
    ),
    KeyRule(
        "hostname_key",
        "hostname",
        r"^(?:hostname|host_name|dns_name|fqdn|private_dns_name|public_dns_name|"
        r"domain_name|endpoint_address)$",
        category="network",
        defer=True,
    ),
)

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


#: Rule entities whose real entity is chosen per value.
SHAPED_ENTITIES = {"cloud_account": account_entity, "resource_ref": ref_entity}

#: Keys that hold tag / label maps (``{"Owner": "alice"}``) or lists of
#: ``{"Key": ..., "Value": ...}`` pairs.
TAG_CONTAINER_KEYS = frozenset(
    {"tags", "labels", "tag", "resource_tags", "user_labels", "tag_set", "tag_list"}
)
#: Tag keys whose values name a person.
PERSON_TAG_PATTERN = (
    r"(?:^|_)(?:owner|owners|created_by|createdby|creator|contact|email|maintainer|author|"
    r"requester|requested_by|user|team_lead|manager)(?:$|_)"
)


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------


@dataclass
class CompiledScanner:
    """Scans strings with a fixed set of detectors.

    Python's ``re`` does not optimise large alternations, so instead of one
    combined regex each detector carries cheap lowercase substring
    *hints* (``"arn:"``, ``"@"``, ``"://"``...): a detector's regex only runs
    when one of its hints occurs in the string. Matches are then merged
    leftmost-first, earlier detectors winning ties, without overlaps.
    """

    detectors: list[Detector]
    singles: list[tuple[Detector, re.Pattern[str]]] = field(default_factory=list)
    min_length: int = 1
    _always: list[int] = field(default_factory=list)
    _hinted: list[tuple[int, tuple[str, ...]]] = field(default_factory=list)

    def __post_init__(self) -> None:
        for i, (det, _) in enumerate(self.singles):
            if det.hints:
                self._hinted.append((i, det.hints))
            else:
                self._always.append(i)

    def scan(self, text: str, min_confidence: float = 0.0) -> list[EntityMatch]:
        """Non-overlapping matches, left to right."""
        n = len(text)
        if n < self.min_length or not self.singles:
            return []
        lower = text.lower() if self._hinted else text
        selected = list(self._always)
        for i, hints in self._hinted:
            for h in hints:
                if h in lower:
                    selected.append(i)
                    break
        if not selected:
            return []
        if len(selected) > 1:
            selected.sort()
        cands: list[tuple[int, int, int, EntityMatch]] = []
        singles = self.singles
        for prio in selected:
            det, rx = singles[prio]
            if n < det.min_length:
                continue
            g = det.group
            for m in rx.finditer(text):
                if g:
                    start, end = m.start(g), m.end(g)
                    if start < 0:
                        continue
                else:
                    start, end = m.start(), m.end()
                entity = det.entity
                if det.validator is not None:
                    verdict = det.validator(text[start:end])
                    if not verdict:
                        continue
                    if isinstance(verdict, str):
                        entity = verdict
                if det.confidence < min_confidence:
                    continue
                em = EntityMatch(
                    start, end, text[start:end], entity, det.name, det.category, det.confidence
                )
                cands.append((m.start(), prio, m.end(), em))
        if not cands:
            return []
        if len(cands) == 1:
            return [cands[0][3]]
        cands.sort(key=lambda c: (c[0], c[1]))
        out: list[EntityMatch] = []
        consumed = 0
        for mstart, _prio, mend, em in cands:
            if mstart < consumed or em.start < consumed:
                continue
            out.append(em)
            consumed = max(mend, em.end)
        return out


class DetectorRegistry:
    """Named collection of :class:`Detector` and :class:`KeyRule`.

    ``DetectorRegistry.default()`` holds the built-ins; :meth:`with_custom`
    returns a copy extended with policy-declared detectors.
    """

    def __init__(
        self,
        detectors: Iterable[Detector] = (),
        key_rules: Iterable[KeyRule] = (),
    ) -> None:
        self._detectors: dict[str, Detector] = {}
        self._key_rules: dict[str, KeyRule] = {}
        for d in detectors:
            self.add(d)
        for r in key_rules:
            self.add_key_rule(r)
        self._scanners: dict[tuple[str, ...], CompiledScanner] = {}

    @classmethod
    def default(cls) -> "DetectorRegistry":
        return cls(BUILTIN_DETECTORS, BUILTIN_KEY_RULES)

    # -- mutation --------------------------------------------------------

    def add(self, detector: Detector, *, replace_existing: bool = True) -> None:
        if detector.name in self._detectors and not replace_existing:
            raise ValueError(f"Duplicate detector {detector.name!r}")
        re.compile(detector.pattern, detector.flags)  # fail fast on bad patterns
        self._detectors[detector.name] = detector
        self._scanners = {}

    def add_key_rule(self, rule: KeyRule) -> None:
        self._key_rules[rule.name] = rule

    def remove(self, name: str) -> None:
        self._detectors.pop(name, None)
        self._key_rules.pop(name, None)
        self._scanners = {}

    def copy(self) -> "DetectorRegistry":
        return DetectorRegistry(self._detectors.values(), self._key_rules.values())

    def with_custom(self, specs: Iterable[dict[str, Any] | Detector]) -> "DetectorRegistry":
        out = self.copy()
        for spec in specs:
            out.add(spec if isinstance(spec, Detector) else detector_from_config(spec))
        return out

    def disable(self, names: Iterable[str]) -> "DetectorRegistry":
        out = self.copy()
        for n in names:
            if n in out._detectors:
                out._detectors[n] = replace(out._detectors[n], enabled=False)
        return out

    # -- access ----------------------------------------------------------

    @property
    def detectors(self) -> list[Detector]:
        return list(self._detectors.values())

    @property
    def key_rules(self) -> list[KeyRule]:
        return list(self._key_rules.values())

    def get(self, name: str) -> Detector | None:
        return self._detectors.get(name)

    def __iter__(self) -> Iterator[Detector]:
        return iter(self._detectors.values())

    def __len__(self) -> int:
        return len(self._detectors)

    def entities(self) -> set[str]:
        out = {d.entity for d in self._detectors.values()}
        out |= {r.entity for r in self._key_rules.values()}
        return out | set(ENTITY_PARENTS)

    def scanner(self, names: Iterable[str] | None = None) -> CompiledScanner:
        """Compile (and cache) a combined scanner for the named detectors
        (all enabled ones when ``names`` is None)."""
        if names is None:
            selected = [d for d in self._detectors.values() if d.enabled]
        else:
            wanted = set(names)
            selected = [d for d in self._detectors.values() if d.name in wanted and d.enabled]
        key = tuple(d.name for d in selected)
        cached = self._scanners.get(key)
        if cached is not None:
            return cached
        scanner = CompiledScanner(
            detectors=selected,
            singles=[(d, d.compile()) for d in selected],
            min_length=min((d.min_length for d in selected), default=1),
        )
        self._scanners[key] = scanner
        return scanner

    def scan(self, text: str, min_confidence: float = 0.0) -> list[EntityMatch]:
        """Scan with every enabled detector."""
        return self.scanner().scan(text, min_confidence)

    def describe(self) -> list[dict[str, Any]]:
        out = [d.to_dict() for d in self._detectors.values()]
        out += [{"kind": "key_rule", **r.to_dict()} for r in self._key_rules.values()]
        return out


# ---------------------------------------------------------------------------
# Config -> Detector
# ---------------------------------------------------------------------------

_FLAG_NAMES = {
    "i": re.I,
    "ignorecase": re.I,
    "m": re.M,
    "multiline": re.M,
    "s": re.S,
    "dotall": re.S,
    "x": re.X,
    "verbose": re.X,
}


def make_validator(spec: Any) -> Validator | None:
    """Build a validator from a config value: ``"ip"``, ``"entropy"`` /
    ``"entropy:4.5"``, ``"secret"``, ``"not_placeholder"``, or a callable."""
    if spec is None or callable(spec):
        return spec
    name, _, arg = str(spec).partition(":")
    if name == "ip":
        return classify_ip_text
    if name == "entropy":
        threshold = float(arg or 4.0)
        return lambda s: shannon_entropy(s) >= threshold
    if name in ("secret", "not_placeholder"):
        return _secret_value
    if name == "high_entropy":
        threshold = float(arg or 4.0)
        return lambda s: looks_like_secret(s, threshold)
    raise ValueError(f"Unknown validator {spec!r}")


def detector_from_config(spec: dict[str, Any]) -> Detector:
    """Build a :class:`Detector` from a policy dict."""
    if "name" not in spec or "pattern" not in spec:
        raise ValueError("custom detectors need 'name' and 'pattern'")
    flags = 0
    raw_flags = spec.get("flags") or []
    if isinstance(raw_flags, str):
        raw_flags = (
            [raw_flags]
            if len(raw_flags) > 1 and raw_flags.lower() in _FLAG_NAMES
            else list(raw_flags)
        )
    for f in raw_flags:
        flags |= _FLAG_NAMES[str(f).lower()]
    if spec.get("ignore_case"):
        flags |= re.I
    return Detector(
        name=str(spec["name"]),
        entity=str(spec.get("entity") or spec["name"]),
        pattern=str(spec["pattern"]),
        category=str(spec.get("category", "identifier")),
        confidence=float(spec.get("confidence", 0.8)),
        flags=flags,
        validator=make_validator(spec.get("validator")),
        group=int(spec.get("group", 0)),
        description=str(spec.get("description", "")),
        enabled=bool(spec.get("enabled", True)),
        min_length=int(spec.get("min_length", 1)),
        hints=tuple(str(h).lower() for h in spec.get("hints", ())),
    )


DEFAULT_REGISTRY = DetectorRegistry.default()
