"""Deterministic, reversible pseudonym vault.

The vault turns real identifiers into stable surrogate *tokens* and back,
the way Google Cloud DLP's deterministic crypto transformation and
Presidio's encrypt/decrypt operators do. A model can then work with an
account, ARN or IP it never sees and hand the surrogate back to a tool,
which resolves the real resource.

Properties:

* Deterministic: tokens are derived from ``HMAC-SHA256(key, namespace
  | entity type | value)``, so the same value always gets the same token
  for a given key (across calls, and across processes when the key is
  stable). Collisions are detected and resolved by re-deriving.
* Typed and format-preserving: a token looks like the thing it
  replaces, so downstream reasoning still works:

  ===================== ==========================================================
  entity                token
  ===================== ==========================================================
  aws_account_id        another 12-digit number
  aws_arn               ``arn:aws:ec2:us-east-1:<fake acct>:instance/i-<fake hex>``
  azure_resource_id     ``/subscriptions/<uuid v8>/resourceGroups/rg-.../providers/...``
  gcp_resource_name     ``//compute.googleapis.com/projects/proj-.../zones/.../instances/res-...``
  private IP / CIDR     prefix-preserving permutation *inside the same private
                        block* (10.x stays 10.x, hosts stay inside their subnet)
  public IPv4           ``198.18.0.0/15`` (RFC 2544 benchmarking range)
  public IPv6           ``2001:db8::/32`` (documentation range)
  special IPs           unchanged (``0.0.0.0/0``, loopback, 169.254.169.254...)
  email                 ``user-...@d-....example`` (GCP service accounts keep shape)
  hostname              unique labels replaced, cloud suffix kept
  names                 ``i-0abc...`` keeps its ``i-`` prefix, others ``res-...``
  ===================== ==========================================================

* Reversible through :meth:`TokenVault.detokenize` and
  :meth:`TokenVault.detokenize_text` (every known token inside free text).
* Namespaced: ``scope="principal"`` gives each caller its own
  namespace (different tokens, no cross-principal reversal); TTL expiry is
  optional.
* Persistable: :meth:`TokenVault.save` writes an authenticated,
  encrypted (HMAC-SHA256 counter-mode stream + HMAC tag) JSON file with
  ``0600`` permissions; reloading requires the same key.

The key comes from the policy, else ``$CLOUDG_MCP_VAULT_KEY``, else a
random per-process key (tokens then change between restarts). The key is
never exposed by :meth:`stats` / :meth:`describe`; only a short key id is.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import ipaddress
import json
import os
import re
import secrets
import tempfile
import threading
import time
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

VAULT_KEY_ENV = "CLOUDG_MCP_VAULT_KEY"
GLOBAL_NAMESPACE = "global"
_FILE_FORMAT = "cloudg-vault/1"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_PRIVATE_BLOCKS_V4 = [
    ipaddress.ip_network(n)
    for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10")
]
_PRIVATE_BLOCKS_V6 = [ipaddress.ip_network("fc00::/7")]
_PUBLIC_V4_POOL = ipaddress.ip_network("198.18.0.0/15")
_WIDE_V4_POOL = ipaddress.ip_network("240.0.0.0/4")
_PUBLIC_V6_POOL = ipaddress.ip_network("2001:db8::/32")

_AWS_ID_RE = re.compile(r"^([a-z]{1,12})-([0-9a-f]{8,40})$")
_DIRS = r"(?:east|west|north|south|central|northeast|northwest|southeast|southwest)"
_REGION_RE = re.compile(
    rf"^(?:[a-z]{{2}}(?:-gov|-iso[a-z]?)?-{_DIRS}-\d|[a-z]+-{_DIRS}\d+(?:-[a-z])?|"
    rf"{_DIRS}[a-z]*\d?)$"
)
_SERVICE_LABELS = frozenset(
    "elb rds s3 ec2 compute compute-1 execute-api es cache cloudfront lambda-url on aws dkr "
    "ecr eks sqs sns blob file queue table web dfs vault database privatelink cloudapp c iam "
    "run cloudfunctions appspot core windows net azure googleapis internal azurewebsites "
    "scm documents redis servicebus azurecr postgres mysql mariadb sql s3-website api "
    "amazonaws com org io".split()
)
_CLOUD_SUFFIXES = tuple(
    sorted(
        (
            "amazonaws.com",
            "amazonaws.com.cn",
            "cloudfront.net",
            "awsapps.com",
            "azurewebsites.net",
            "cloudapp.azure.com",
            "cloudapp.net",
            "windows.net",
            "azure.com",
            "azurecr.io",
            "azure-api.net",
            "azureedge.net",
            "googleapis.com",
            "appspot.com",
            "run.app",
            "cloudfunctions.net",
            "internal",
            "compute.internal",
            "ec2.internal",
            "gserviceaccount.com",
        ),
        key=len,
        reverse=True,
    )
)
_GSA_RE = re.compile(
    r"^(?P<local>[^@]+)@(?P<proj>[a-z][a-z0-9\-]{4,28}[a-z0-9])"
    r"\.iam\.gserviceaccount\.com$"
)
_GSA_NUM_RE = re.compile(
    r"^(?P<prefix>service-|)(?P<num>\d{6,20})(?P<rest>-compute|)"
    r"@(?P<domain>[a-z0-9.\-]*gserviceaccount\.com)$"
)

#: Shapes of tokens the vault can issue; used to find tokens in free text.
_SHAPE_RE = re.compile(
    r"(?P<email>[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,24})"
    r"|(?P<ip6>(?<![0-9A-Fa-f:])(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}(?:/\d{1,3})?"
    r"(?![0-9A-Fa-f:]))"
    r"|(?P<ip4>(?<![\d.])\d{1,3}(?:\.\d{1,3}){3}(?:/\d{1,2})?(?![\d]))"
    r"|(?P<guid>(?<![0-9A-Fa-f\-])[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-"
    r"[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}(?![0-9A-Fa-f\-]))"
    r"|(?P<mac>\b[0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5}\b)"
    r"|(?P<host>(?<![\w\-.])(?:[A-Za-z0-9\-]+\.)+[A-Za-z][A-Za-z0-9\-]*(?![\w\-]))"
    r"|(?P<akid>\b(?:AKIA|ASIA|AIDA|AROA|AGPA|AIPA|ANPA|ANVA|APKA|ABIA|ACCA)[A-Z2-7]{16,17}\b)"
    r"|(?P<pref>(?<![\w\-])[A-Za-z][A-Za-z0-9]{0,15}-[0-9a-f]{6,40}(?![\w\-]))"
    r"|(?P<digits>(?<![\w.\-])\d{6,20}(?![\w\-]))"
)
_ATOMIC_RE = re.compile(
    r"(?P<guid>(?<![0-9A-Fa-f\-])[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-"
    r"[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}(?![0-9A-Fa-f\-]))"
    r"|(?P<pref>(?<![A-Za-z0-9\-])[A-Za-z][A-Za-z0-9]{0,15}-[0-9a-f]{6,40}(?![A-Za-z0-9\-]))"
    r"|(?P<digits>(?<![A-Za-z0-9.\-])\d{6,20}(?![A-Za-z0-9\-]))"
)

#: Short prefixes for generic ``<prefix>-<hex>`` tokens.
_GENERIC_PREFIX = {
    "resource_name": "res",
    "dataset_name": "ds",
    "cloud_account": "acct",
    "url_username": "user",
    "azure_resource_group": "rg",
    "gcp_project_id": "proj",
    "tag_value": "tag",
    "person": "person",
    "hostname_label": "h",
    "email_domain": "d",
    "sensitive_field": "secret",
    "secret_value": "secret",
    "password": "secret",
    "api_token": "secret",
    "jwt": "secret",
    "private_key": "secret",
    "aws_secret_access_key": "secret",
}

_B32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"


def _resolve_key(key: bytes | str | None, key_env: str | None) -> tuple[bytes, str]:
    if key:
        return (key.encode() if isinstance(key, str) else bytes(key)), "config"
    env = os.environ.get(key_env or VAULT_KEY_ENV) if key_env is not False else None
    if env:
        return env.encode(), "env"
    return secrets.token_bytes(32), "random"


def _derive(key: bytes, label: str) -> bytes:
    return hmac.new(key, f"cloudg-mcp/{label}".encode(), hashlib.sha256).digest()


@dataclass
class _Entry:
    value: str
    entity: str
    namespace: str
    created: float
    last_used: float


# ---------------------------------------------------------------------------
# Vault
# ---------------------------------------------------------------------------


class TokenVault:
    """Bidirectional, HMAC-keyed pseudonym store.

    Args:
        key: Secret key (str or bytes). Defaults to ``$CLOUDG_MCP_VAULT_KEY``
            or a random per-process key.
        scope: ``"global"`` (one namespace) or ``"principal"`` (one
            namespace per caller, see :meth:`namespace_for`).
        ttl_seconds: Expire mappings unused for this long (``None`` = never).
        path: Optional file to load on start and :meth:`save` to.
        autosave: Save to ``path`` after every new mapping batch (via
            :meth:`maybe_autosave`; callers decide when).
        encrypt: Encrypt the persisted file (default) or write plain JSON.
    """

    def __init__(
        self,
        key: bytes | str | None = None,
        *,
        scope: str = "global",
        ttl_seconds: float | None = None,
        path: str | os.PathLike[str] | None = None,
        autosave: bool = False,
        encrypt: bool = True,
        key_env: str | None = VAULT_KEY_ENV,
    ) -> None:
        if scope not in ("global", "principal"):
            raise ValueError("scope must be 'global' or 'principal'")
        raw_key, self.key_source = _resolve_key(key, key_env)
        self._k_tok = _derive(raw_key, "tokenize")
        self._k_bit = _derive(raw_key, "prefix-preserving")[:32]
        self._k_hash = _derive(raw_key, "hash")
        self._k_enc = _derive(raw_key, "file-encryption")
        self._k_mac = _derive(raw_key, "file-mac")
        self.key_id = _derive(raw_key, "key-id").hex()[:12]
        self.scope = scope
        self.ttl_seconds = ttl_seconds
        self.path = Path(path) if path else None
        self.autosave = autosave
        self.encrypt = encrypt
        self._lock = threading.RLock()
        self._fwd: dict[tuple[str, str, str], str] = {}
        self._entities: set[str] = set()
        self._rev: dict[str, dict[str, _Entry]] = {}
        self._bits: dict[tuple[Any, ...], int] = {}
        self._counters: Counter[str] = Counter()
        self._dirty = False
        self._formatters: dict[str, Callable[[str, str, int], str]] = self._build_formatters()
        if self.path and self.path.exists():
            self.load(self.path)

    # ------------------------------------------------------------------
    # Namespaces
    # ------------------------------------------------------------------

    def namespace_for(self, principal: Any = None) -> str:
        """Namespace for a caller: always ``"global"`` in global scope,
        ``"p:<principal id>"`` in principal scope."""
        if self.scope == "global" or principal is None:
            return GLOBAL_NAMESPACE
        return f"p:{getattr(principal, 'id', principal)}"

    # ------------------------------------------------------------------
    # Tokenize / detokenize
    # ------------------------------------------------------------------

    def tokenize(
        self, value: str, entity_type: str = "generic", *, namespace: str | None = None
    ) -> str:
        """Return the stable token for ``value`` (creating it if needed).
        Values that should never be pseudonymised (``0.0.0.0/0``,
        loopback, ``*``) come back unchanged."""
        value = str(value)
        if not value:
            return value
        ns = namespace or GLOBAL_NAMESPACE
        key = (ns, entity_type, value)
        now = time.time()
        with self._lock:
            tok = self._fwd.get(key)
            if tok is not None:
                entry = self._rev.get(ns, {}).get(tok)
                if entry is not None and not self._expired(entry, now):
                    entry.last_used = now
                    self._counters["tokenize_hits"] += 1
                    return tok
            fmt = self._formatters.get(entity_type) or self._generic_for(entity_type)
            table = self._rev.setdefault(ns, {})
            tok = value
            for attempt in range(64):
                cand = (
                    fmt(value, ns, attempt)
                    if attempt < 48
                    else self._fmt_generic(value, ns, attempt, entity_type)
                )
                if cand == value:
                    return value  # not pseudonymised (special address, wildcard...)
                existing = table.get(cand)
                if existing is None or (existing.value == value and existing.entity == entity_type):
                    tok = cand
                    break
                self._counters["collisions"] += 1
            self._fwd[key] = tok
            self._entities.add(entity_type)
            table[tok] = _Entry(value, entity_type, ns, now, now)
            self._counters["tokenized"] += 1
            self._dirty = True
            return tok

    def tokens_for(self, value: str, *, namespace: str | None = None) -> list[str]:
        """Every token already issued for ``value`` (any entity type)."""
        ns = namespace or GLOBAL_NAMESPACE
        with self._lock:
            return [
                t
                for e in self._entities
                if (t := self._fwd.get((ns, e, value))) is not None and t != value
            ]

    def lookup(
        self, value: str, entity_type: str = "generic", *, namespace: str | None = None
    ) -> str | None:
        """Existing token for ``value`` or ``None`` (never creates one)."""
        with self._lock:
            return self._fwd.get((namespace or GLOBAL_NAMESPACE, entity_type, str(value)))

    def detokenize(self, token: str, *, namespace: str | None = None) -> str | None:
        """Real value behind ``token``, or ``None`` if unknown / expired."""
        ns = namespace or GLOBAL_NAMESPACE
        with self._lock:
            entry = self._rev.get(ns, {}).get(token)
            if entry is None:
                return None
            if self._expired(entry, time.time()):
                self._drop(ns, token, entry)
                return None
            self._counters["detokenized"] += 1
            return entry.value

    def entry(self, token: str, *, namespace: str | None = None) -> dict[str, Any] | None:
        """``{"value", "entity_type", "namespace", "created"}`` for a token."""
        with self._lock:
            e = self._rev.get(namespace or GLOBAL_NAMESPACE, {}).get(token)
            if e is None or self._expired(e, time.time()):
                return None
            return {
                "value": e.value,
                "entity_type": e.entity,
                "namespace": e.namespace,
                "created": e.created,
            }

    def is_token(self, value: str, *, namespace: str | None = None) -> bool:
        with self._lock:
            return value in self._rev.get(namespace or GLOBAL_NAMESPACE, {})

    def detokenize_text(self, text: str, *, namespace: str | None = None) -> str:
        """Replace every known token inside ``text`` with its real value."""
        return self.detokenize_text_count(text, namespace=namespace)[0]

    def detokenize_text_count(self, text: str, *, namespace: str | None = None) -> tuple[str, int]:
        ns = namespace or GLOBAL_NAMESPACE
        with self._lock:
            table = self._rev.get(ns)
            if not table or not isinstance(text, str) or not text:
                return text, 0
            exact = table.get(text)
            if exact is not None and not self._expired(exact, time.time()):
                return exact.value, 1
            count = 0

            def sub_atomic(m: re.Match[str]) -> str:
                nonlocal count
                e = table.get(m.group(0))
                if e is None:
                    return m.group(0)
                count += 1
                return e.value

            def sub(m: re.Match[str]) -> str:
                nonlocal count
                s = m.group(0)
                e = table.get(s)
                if e is not None:
                    count += 1
                    return e.value
                kind = m.lastgroup
                if kind in ("ip4", "ip6") and "/" in s:
                    addr, _, plen = s.partition("/")
                    e = table.get(addr)
                    if e is not None:
                        count += 1
                        return f"{e.value}/{plen}"
                    return s
                if kind in ("email", "host"):
                    return _ATOMIC_RE.sub(sub_atomic, s)
                return s

            out = _SHAPE_RE.sub(sub, text)
            if count:
                self._counters["detokenized"] += count
            return out, count

    # ------------------------------------------------------------------
    # Keyed hashing (the ``hash`` strategy)
    # ------------------------------------------------------------------

    def hash_value(self, value: str, *, length: int = 12, entity_type: str = "") -> str:
        """Keyed HMAC-SHA256 digest (hex, truncated). It is stable per key,
        irreversible, and not linkable without the key."""
        msg = f"{entity_type}\x1f{value}".encode()
        return hmac.new(self._k_hash, msg, hashlib.sha256).hexdigest()[: max(4, length)]

    # ------------------------------------------------------------------
    # Maintenance
    # ------------------------------------------------------------------

    def _expired(self, entry: _Entry, now: float) -> bool:
        return self.ttl_seconds is not None and now - entry.last_used > self.ttl_seconds

    def _drop(self, ns: str, token: str, entry: _Entry) -> None:
        self._rev.get(ns, {}).pop(token, None)
        self._fwd.pop((ns, entry.entity, entry.value), None)
        self._dirty = True

    def purge_expired(self) -> int:
        """Remove expired mappings; returns how many were dropped."""
        if self.ttl_seconds is None:
            return 0
        now = time.time()
        n = 0
        with self._lock:
            for ns, table in list(self._rev.items()):
                for tok, e in list(table.items()):
                    if self._expired(e, now):
                        self._drop(ns, tok, e)
                        n += 1
        return n

    def clear(self, namespace: str | None = None) -> None:
        with self._lock:
            if namespace is None:
                self._fwd.clear()
                self._rev.clear()
                self._bits.clear()
            else:
                for e in list(self._rev.pop(namespace, {}).values()):
                    self._fwd.pop((namespace, e.entity, e.value), None)
            self._dirty = True

    def __len__(self) -> int:
        with self._lock:
            return sum(len(t) for t in self._rev.values())

    def stats(self) -> dict[str, Any]:
        """Counts only, never values or key material."""
        with self._lock:
            by_entity: Counter[str] = Counter()
            for table in self._rev.values():
                for e in table.values():
                    by_entity[e.entity] += 1
            return {
                "entries": sum(by_entity.values()),
                "namespaces": len(self._rev),
                "by_entity": dict(sorted(by_entity.items())),
                "scope": self.scope,
                "ttl_seconds": self.ttl_seconds,
                "key_source": self.key_source,
                "key_id": self.key_id,
                "persist_path": str(self.path) if self.path else None,
                "counters": dict(self._counters),
            }

    describe = stats

    # ------------------------------------------------------------------
    # Export / import / persistence
    # ------------------------------------------------------------------

    def export(self, *, namespace: str | None = None) -> dict[str, Any]:
        """All mappings as plain JSON-able data. The output contains real
        values, so treat it as sensitive."""
        with self._lock:
            entries = [
                [e.namespace, e.entity, e.value, tok, e.created, e.last_used]
                for ns, table in self._rev.items()
                if namespace is None or ns == namespace
                for tok, e in table.items()
            ]
        return {"format": _FILE_FORMAT, "key_id": self.key_id, "entries": entries}

    def import_mappings(self, data: dict[str, Any], *, overwrite: bool = False) -> int:
        """Load mappings produced by :meth:`export`. Returns the number
        added. Mappings exported under a different key are accepted (the
        tokens are opaque strings) but new tokens will not match them."""
        n = 0
        with self._lock:
            for ns, entity, value, tok, created, last_used in data.get("entries", []):
                table = self._rev.setdefault(ns, {})
                if tok in table and not overwrite:
                    continue
                table[tok] = _Entry(value, entity, ns, float(created), float(last_used))
                self._fwd[(ns, entity, value)] = tok
                self._entities.add(entity)
                n += 1
            self._dirty = self._dirty or bool(n)
        return n

    import_ = import_mappings

    def save(self, path: str | os.PathLike[str] | None = None) -> Path:
        """Write the vault to ``path`` (default: the configured path) with
        ``0600`` permissions, atomically. Encrypted unless ``encrypt=False``."""
        target = Path(path) if path else self.path
        if target is None:
            raise ValueError("No vault path configured")
        payload = json.dumps(self.export(), separators=(",", ":")).encode()
        if self.encrypt:
            nonce = secrets.token_bytes(16)
            ct = self._xor_stream(payload, nonce)
            tag = hmac.new(self._k_mac, nonce + ct, hashlib.sha256).hexdigest()
            doc = {
                "format": _FILE_FORMAT,
                "encrypted": True,
                "key_id": self.key_id,
                "nonce": base64.b64encode(nonce).decode(),
                "data": base64.b64encode(ct).decode(),
                "tag": tag,
            }
            blob = json.dumps(doc).encode()
        else:
            blob = payload
        target.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(prefix=".vault-", dir=str(target.parent))
        try:
            os.chmod(tmp, 0o600)
            with os.fdopen(fd, "wb") as fh:
                fh.write(blob)
            os.replace(tmp, target)
        except BaseException:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise
        os.chmod(target, 0o600)
        self._dirty = False
        return target

    def load(self, path: str | os.PathLike[str]) -> int:
        """Load a file written by :meth:`save` (same key required for
        encrypted files). Returns the number of mappings added."""
        doc = json.loads(Path(path).read_text())
        if doc.get("encrypted"):
            nonce = base64.b64decode(doc["nonce"])
            ct = base64.b64decode(doc["data"])
            tag = hmac.new(self._k_mac, nonce + ct, hashlib.sha256).hexdigest()
            if not hmac.compare_digest(tag, str(doc.get("tag", ""))):
                raise ValueError("Vault file authentication failed (wrong key or tampered file)")
            doc = json.loads(self._xor_stream(ct, nonce))
        return self.import_mappings(doc)

    @property
    def dirty(self) -> bool:
        """Mappings changed since the last save / load."""
        return self._dirty

    def maybe_autosave(self) -> None:
        if self.autosave and self.path and self._dirty:
            self.save()

    def _xor_stream(self, data: bytes, nonce: bytes) -> bytes:
        blocks = []
        for i in range((len(data) + 31) // 32):
            blocks.append(
                hmac.new(self._k_enc, nonce + i.to_bytes(8, "big"), hashlib.sha256).digest()
            )
        ks = b"".join(blocks)[: len(data)]
        if not data:
            return b""
        return (int.from_bytes(data, "big") ^ int.from_bytes(ks, "big")).to_bytes(len(data), "big")

    # ------------------------------------------------------------------
    # Token formats
    # ------------------------------------------------------------------

    def _digest(self, ns: str, entity: str, value: str, attempt: int) -> bytes:
        msg = f"{ns}\x1f{entity}\x1f{attempt}\x1f{value}".encode()
        return hmac.new(self._k_tok, msg, hashlib.sha256).digest()

    def _hex(self, ns: str, entity: str, value: str, attempt: int, n: int) -> str:
        h = self._digest(ns, entity, value, attempt).hex()
        while len(h) < n:
            h += self._digest(ns, entity, value + h, attempt).hex()
        return h[:n]

    def _build_formatters(self) -> dict[str, Callable[[str, str, int], str]]:
        ip = self._fmt_ip
        f: dict[str, Callable[[str, str, int], str]] = {
            "aws_account_id": self._fmt_digits("aws_account_id"),
            "gcp_project_number": self._fmt_digits("gcp_project_number"),
            "number": self._fmt_digits("number"),
            "azure_subscription_id": self._fmt_uuid("azure_subscription_id"),
            "azure_tenant_id": self._fmt_uuid("azure_tenant_id"),
            "uuid": self._fmt_uuid("uuid"),
            "gcp_project_id": self._fmt_project,
            "resource_name": self._fmt_resource_name,
            "aws_resource_id": self._fmt_resource_name,
            "email": self._fmt_email,
            "hostname": self._fmt_hostname,
            "aws_arn": self._fmt_arn,
            "azure_resource_id": self._fmt_azure_id,
            "gcp_resource_name": self._fmt_gcp_name,
            "mac_address": self._fmt_mac,
            "aws_access_key_id": self._fmt_akid,
            "aws_unique_id": self._fmt_akid,
            "cloudg_uri": self._fmt_cloudg_uri,
            "cloudg_iri": self._fmt_cloudg_iri,
            "rag_chunk_id": self._fmt_chunk_id,
            "aws_org_id": self._fmt_org_id,
            "aws_ou_id": self._fmt_org_id,
            "aws_root_id": self._fmt_org_id,
        }
        for name in (
            "ip_address",
            "private_ip",
            "public_ip",
            "special_ip",
            "cidr",
            "private_cidr",
            "public_cidr",
            "special_cidr",
        ):
            f[name] = ip
        return f

    def _fmt_generic(self, value: str, ns: str, attempt: int, entity: str | None = None) -> str:
        entity = entity or "generic"
        prefix = _GENERIC_PREFIX.get(entity) or (re.sub(r"[^a-z0-9]", "", entity)[:10] or "tok")
        return f"{prefix}-{self._hex(ns, entity, value, attempt, 10)}"

    def _generic_for(self, entity: str) -> Callable[[str, str, int], str]:
        return lambda v, ns, a: self._fmt_generic(v, ns, a, entity)

    def _fmt_digits(self, entity: str) -> Callable[[str, str, int], str]:
        def fmt(value: str, ns: str, attempt: int) -> str:
            if not value.isdigit():
                return self._fmt_generic(value, ns, attempt, entity)
            n = len(value)
            num = int.from_bytes(self._digest(ns, entity, value, attempt), "big") % (10**n)
            out = str(num).zfill(n)
            if n > 1 and out[0] == "0" and value[0] != "0":
                out = str(1 + int(out[0:1]) % 9) + out[1:]
            return out

        return fmt

    def _fmt_uuid(self, entity: str) -> Callable[[str, str, int], str]:
        def fmt(value: str, ns: str, attempt: int) -> str:
            h = list(self._hex(ns, entity, value.lower(), attempt, 32))
            h[12] = "8"  # RFC 9562 UUIDv8 (vendor-specific): well-formed, clearly synthetic
            h[16] = "89ab"[int(h[16], 16) % 4]
            s = "".join(h)
            out = f"{s[:8]}-{s[8:12]}-{s[12:16]}-{s[16:20]}-{s[20:]}"
            return out.upper() if value.isupper() else out

        return fmt

    def _fmt_project(self, value: str, ns: str, attempt: int) -> str:
        if value.isdigit():
            return self._fmt_digits("gcp_project_number")(value, ns, attempt)
        return f"proj-{self._hex(ns, 'gcp_project_id', value, attempt, 8)}"

    def _fmt_resource_name(self, value: str, ns: str, attempt: int) -> str:
        if value in ("*", "") or value.startswith("$"):
            return value
        m = _AWS_ID_RE.match(value)
        if m:
            return f"{m.group(1)}-{self._hex(ns, 'resource_name', value, attempt, len(m.group(2)))}"
        return f"res-{self._hex(ns, 'resource_name', value, attempt, 10)}"

    def _sub(self, value: str, entity: str, ns: str) -> str:
        return self.tokenize(value, entity, namespace=ns)

    def _fmt_email(self, value: str, ns: str, attempt: int) -> str:
        m = _GSA_RE.match(value)
        if m:
            proj = self._sub(m.group("proj"), "gcp_project_id", ns)
            local = f"sa-{self._hex(ns, 'email', value, attempt, 8)}"
            return f"{local}@{proj}.iam.gserviceaccount.com"
        m = _GSA_NUM_RE.match(value)
        if m:
            num = self._sub(m.group("num"), "gcp_project_number", ns)
            if attempt:
                num = self._fmt_digits("gcp_project_number")(m.group("num") + "x", ns, attempt)
            return f"{m.group('prefix')}{num}{m.group('rest')}@{m.group('domain')}"
        local, _, domain = value.rpartition("@")
        dom = self._sub(domain.lower(), "email_domain", ns) + ".example" if domain else "example"
        return f"user-{self._hex(ns, 'email', value, attempt, 8)}@{dom}"

    def _fmt_hostname(self, value: str, ns: str, attempt: int) -> str:
        host = value.rstrip(".")
        lower = host.lower()
        suffix = next((s for s in _CLOUD_SUFFIXES if lower == s or lower.endswith("." + s)), None)
        if suffix is None:
            return f"host-{self._hex(ns, 'hostname', lower, attempt, 8)}.example"
        left = host[: len(host) - len(suffix)].rstrip(".")
        if not left:
            return value
        labels = left.split(".")
        out = []
        changed = False
        for label in labels:
            ll = label.lower()
            if ll in _SERVICE_LABELS or _REGION_RE.match(ll):
                out.append(label)
            else:
                salt = label if attempt == 0 else f"{label}#{attempt}"
                out.append(self._sub(salt, "hostname_label", ns))
                changed = True
        if not changed:
            return value
        return ".".join(out) + "." + host[len(host) - len(suffix) :]

    def _fmt_arn(self, value: str, ns: str, attempt: int) -> str:
        parts = value.split(":", 5)
        if len(parts) < 6 or parts[0] != "arn":
            return self._fmt_generic(value, ns, attempt, "aws_arn")
        _, partition, service, region, account, resource = parts
        if account.isdigit() and len(account) == 12:
            account = self._sub(account, "aws_account_id", ns)
        segs = re.split(r"([/:])", resource)
        values = segs[0::2]
        if service == "s3" or len(values) == 1:
            first_kept = False
        else:
            first_kept = True
        out = []
        for i, seg in enumerate(segs):
            if i % 2:  # separator
                out.append(seg)
                continue
            idx = i // 2
            if (
                (idx == 0 and first_kept)
                or seg in ("", "*")
                or seg.startswith("$")
                or (seg.isdigit() and len(seg) <= 4 and idx > 0)
            ):
                out.append(seg)
            else:
                out.append(self._sub(seg, "resource_name", ns))
        result = ":".join(["arn", partition, service, region, account, "".join(out)])
        if attempt:
            result += f"#{attempt}"
        return result

    def _fmt_azure_id(self, value: str, ns: str, attempt: int) -> str:
        segs = value.split("/")
        out: list[str] = []
        prev = ""
        mode = ""  # "" | "type" | "name"
        for seg in segs:
            low = seg.lower()
            if not seg:
                out.append(seg)
            elif prev == "subscriptions":
                out.append(self._sub(seg, "azure_subscription_id", ns))
            elif prev == "tenants":
                out.append(self._sub(seg, "azure_tenant_id", ns))
            elif prev == "resourcegroups":
                out.append(self._sub(seg, "azure_resource_group", ns))
            elif low == "providers":
                out.append(seg)
                mode = "namespace"
            elif mode == "namespace":
                out.append(seg)
                mode = "type"
            elif mode == "type":
                out.append(seg)
                mode = "name"
            elif mode == "name":
                out.append(self._sub(seg, "resource_name", ns))
                mode = "type"
            else:
                out.append(seg)
            prev = low if seg else prev
        result = "/".join(out)
        return result + (f"#{attempt}" if attempt else "")

    def _fmt_gcp_name(self, value: str, ns: str, attempt: int) -> str:
        head = ""
        rest = value
        m = re.match(r"^(//[^/]+/)(.*)$", value)
        if m:
            head, rest = m.group(1), m.group(2)
        segs = rest.split("/")
        out = []
        for i, seg in enumerate(segs):
            if i % 2 == 0 or not seg:
                out.append(seg)
                continue
            coll = segs[i - 1].lower()
            if coll in ("zones", "regions", "locations") or seg == "-":
                out.append(seg)
            elif coll == "projects":
                out.append(
                    self._sub(seg, "gcp_project_number" if seg.isdigit() else "gcp_project_id", ns)
                )
            elif coll in ("organizations", "folders", "billingaccounts") and seg.isdigit():
                out.append(self._sub(seg, "number", ns))
            else:
                out.append(self._sub(seg, "resource_name", ns))
        result = head + "/".join(out)
        return result + (f"#{attempt}" if attempt else "")

    def _ref_entity(self, ref: str) -> str:
        from cloudg.mcp.transforms.detectors import classify_ip_text

        if ref.startswith("arn:"):
            return "aws_arn"
        if ref.lower().startswith("/subscriptions/"):
            return "azure_resource_id"
        if ref.startswith("//") or ref.startswith("projects/"):
            return "gcp_resource_name"
        refined = classify_ip_text(ref)
        if refined:
            return refined
        return "resource_name"

    def _fmt_cloudg_uri(self, value: str, ns: str, attempt: int) -> str:
        """``cloudg://assets/<ref>[/neighbors|/findings]`` and
        ``cloudg://datasets/<name>/...``: only the reference is replaced,
        typed like the same value elsewhere (an ARN stays an ARN pseudonym,
        a name gets the same ``res-...`` token as under ``name``)."""
        m = re.match(r"^(cloudg://assets/)(.+?)(/neighbors|/findings|/)?$", value)
        if m:
            ref = m.group(2)
            tok = self._ref_token(ref, ns)
            if tok == ref:
                return value
            out = f"{m.group(1)}{tok}{m.group(3) or ''}"
        else:
            m = re.match(r"^(cloudg://datasets/)([^/]+)(/.*)?$", value)
            if not m:
                return value
            out = f"{m.group(1)}{self._sub(m.group(2), 'dataset_name', ns)}{m.group(3) or ''}"
        return out + (f"#{attempt}" if attempt else "")

    def _fmt_org_id(self, value: str, ns: str, attempt: int) -> str:
        """``o-``, ``ou-`` and ``r-`` ids keep their prefix; every other
        hyphen-separated part becomes random hex of the same length."""
        prefix, _, rest = value.partition("-")
        if not rest:
            return self._fmt_generic(value, ns, attempt, "aws_org_id")
        h = self._hex(ns, "aws_org_id", value, attempt, max(len(rest), 8) + 8)
        parts, pos = [], 0
        for part in rest.split("-"):
            n = max(len(part), 4)
            parts.append(h[pos : pos + n])
            pos += n
        return f"{prefix}-{'-'.join(parts)}"

    def _ref_token(self, ref: str, ns: str) -> str:
        from cloudg.mcp.transforms.detectors import ref_entity

        structured = self._ref_entity(ref)
        if structured != "resource_name":  # ARN, Azure id, GCP name, IP
            return self._sub(ref, structured, ns)
        entity = ref_entity(ref)
        if entity == "uuid":
            return ref  # cloudg's own random ids are kept
        return self._sub(ref, entity, ns)

    def _fmt_cloudg_iri(self, value: str, ns: str, attempt: int) -> str:
        """Ontology resource IRIs (``cmr:<asset id>``, ``cmr:tag_<key>_<value>``):
        the identifier part gets the same token the plain value gets
        elsewhere; finding and compliance IRIs are kept."""
        from cloudg.mcp.transforms.detectors import PERSON_TAG_PATTERN, normalize_key
        from cloudg.mcp.transforms.redaction import DEFAULT_TAG_KEY_ALLOWLIST

        prefix = "cmr:" if value.startswith("cmr:") else "https://cloudg.io/resource/"
        local = value[len(prefix) :]
        if not local or local.startswith(("finding_", "compliance_")):
            return value
        if local.startswith("tag_"):
            rest = local[4:]
            key = next(
                (
                    k
                    for k in sorted(DEFAULT_TAG_KEY_ALLOWLIST, key=len, reverse=True)
                    if rest.lower().startswith(k + "_")
                ),
                None,
            )
            if key is not None:
                return value
            tkey, sep, tval = rest.partition("_")
            if not sep or not tval:
                return f"{prefix}tag_{self._sub(rest, 'tag_value', ns)}"
            person = re.search(PERSON_TAG_PATTERN, normalize_key(tkey))
            tok = self._sub(tval, "person" if person else "tag_value", ns)
            out = f"{prefix}tag_{tkey}_{tok}"
        else:
            out = prefix + self._ref_token(local, ns)
            if out == value:
                return value
        return out + (f"#{attempt}" if attempt else "")

    def _fmt_chunk_id(self, value: str, ns: str, attempt: int) -> str:
        """RAG chunk ids: ``entity::<asset id>`` gets the asset id's token;
        ``community::`` / ``relation_group::`` ids are kept."""
        kind, sep, ref = value.partition("::")
        if not sep or kind != "entity" or not ref:
            return value
        tok = self._ref_token(ref, ns)
        if tok == ref:
            return value
        return f"{kind}::{tok}" + (f"#{attempt}" if attempt else "")

    def _fmt_mac(self, value: str, ns: str, attempt: int) -> str:
        sep = "-" if "-" in value else ":"
        b = bytearray(self._digest(ns, "mac_address", value.lower(), attempt)[:6])
        b[0] = (b[0] | 0x02) & 0xFE  # locally administered, unicast
        out = sep.join(f"{x:02x}" for x in b)
        return out.upper() if value.isupper() else out

    def _fmt_akid(self, value: str, ns: str, attempt: int) -> str:
        prefix = value[:4]
        d = self._digest(ns, "aws_access_key_id", value, attempt)
        return prefix + "".join(_B32[x % 32] for x in d[:16])

    # -- IPs -------------------------------------------------------------

    def _pp_bits(self, ns: str, block: str, host: int, hbits: int) -> int:
        """Prefix-preserving keyed permutation of the low ``hbits`` bits
        (Crypto-PAn style): output bit i = input bit i XOR PRF(prefix)."""
        out = 0
        cache = self._bits
        if len(cache) > 500_000:
            cache.clear()
        for i in range(hbits):
            shift = hbits - i
            prefix = host >> shift
            ck = (ns, block, i, prefix)
            flip = cache.get(ck)
            if flip is None:
                flip = (
                    hashlib.blake2b(
                        f"{ns}|{block}|{i}|{prefix}".encode(), key=self._k_bit, digest_size=1
                    ).digest()[0]
                    & 1
                )
                cache[ck] = flip
            out = (out << 1) | (((host >> (shift - 1)) & 1) ^ flip)
        return out

    def _fmt_ip(self, value: str, ns: str, attempt: int) -> str:
        from cloudg.mcp.transforms.detectors import ip_class

        try:
            if "/" in value:
                net = ipaddress.ip_network(value, strict=False)
                addr, plen = net.network_address, net.prefixlen
                host_part = ipaddress.ip_address(value.split("/", 1)[0])
                is_net = True
            else:
                addr = host_part = ipaddress.ip_address(value)
                plen = addr.max_prefixlen
                is_net = False
        except ValueError:
            return self._fmt_generic(value, ns, attempt, "ip_address")
        cls = ip_class(addr)
        if cls == "special" or (is_net and plen == 0):
            return value
        bits = addr.max_prefixlen
        cls_obj = ipaddress.IPv4Address if addr.version == 4 else ipaddress.IPv6Address
        if cls == "private":
            blocks = _PRIVATE_BLOCKS_V4 if addr.version == 4 else _PRIVATE_BLOCKS_V6
            block = next(b for b in blocks if addr in b)
            if plen <= block.prefixlen:
                return value
            hbits = bits - block.prefixlen
            mask = (1 << hbits) - 1
            src = int(host_part) & mask
            if attempt:  # collision fallback: non-prefix-preserving within block
                perm = int.from_bytes(self._digest(ns, "ip", value, attempt), "big") & mask
            else:
                perm = self._pp_bits(ns, str(block), src, hbits)
            fake = int(block.network_address) | perm
        else:
            pool = _PUBLIC_V4_POOL if addr.version == 4 else _PUBLIC_V6_POOL
            if plen < pool.prefixlen:
                if addr.version == 4 and plen >= _WIDE_V4_POOL.prefixlen:
                    pool = _WIDE_V4_POOL
                else:
                    return value
            hbits = bits - pool.prefixlen
            rnd = int.from_bytes(
                self._digest(ns, "ip", str(addr) if is_net else value, attempt), "big"
            )
            fake = int(pool.network_address) | (rnd & ((1 << hbits) - 1))
        if is_net:
            netmask = ((1 << bits) - 1) ^ ((1 << (bits - plen)) - 1)
            host_bits = int(host_part) & ~netmask & ((1 << bits) - 1)
            if host_bits and cls == "private" and not attempt:
                # "10.0.1.5/24" style interface address: keep host consistent
                return f"{cls_obj(fake)}/{plen}"
            return f"{cls_obj(fake & netmask)}/{plen}"
        return str(cls_obj(fake))
