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
import contextlib
import hashlib
import hmac
import json
import os
import secrets
import tempfile
import threading
import time
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

from cloudg.mcp.transforms.textscan import replace_known
from cloudg.mcp.transforms.vault_formats import TokenFormats

VAULT_KEY_ENV = "CLOUDG_MCP_VAULT_KEY"
GLOBAL_NAMESPACE = "global"
_FILE_FORMAT = "cloudg-vault/1"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _resolve_key(key: bytes | str | None, key_env: str | None) -> tuple[bytes, str]:
    if key:
        return (key.encode() if isinstance(key, str) else bytes(key)), "config"
    env = os.environ.get(key_env or VAULT_KEY_ENV) if key_env is not False else None
    if env:
        return env.encode(), "env"
    return secrets.token_bytes(32), "random"


def _derive(key: bytes, label: str) -> bytes:
    return hmac.new(key, f"cloudg-mcp/{label}".encode(), hashlib.sha256).digest()


def _atomic_write(target: Path, blob: bytes) -> None:
    """Write ``blob`` to ``target`` with ``0600`` permissions from the first
    byte (``mkstemp``), flushed to disk, then renamed over the target, so a
    reader never sees a partial file and a crash leaves the old one. New
    parent directories are created ``0700``."""
    target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd, tmp = tempfile.mkstemp(prefix=".vault-", dir=str(target.parent))
    try:
        os.chmod(tmp, 0o600)
        with os.fdopen(fd, "wb") as fh:
            fh.write(blob)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, target)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(tmp)
        raise
    os.chmod(target, 0o600)


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


class TokenVault(TokenFormats):
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
        self._known: dict[str, dict[str, str]] = {}
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
            self._remember(ns, value, tok)
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

    def detokenize_text_count(
        self,
        text: str,
        *,
        namespace: str | None = None,
        pairs: list[tuple[str, str]] | None = None,
    ) -> tuple[str, int]:
        """Like :meth:`detokenize_text`, also returning the number of tokens
        replaced. ``pairs`` (optional) collects ``(real, token)`` for each.

        Tokens are found with a linear scan over identifier-like runs (see
        :mod:`cloudg.mcp.transforms.textscan`), never with a backtracking
        regex, so hostile input cannot make this slow."""
        ns = namespace or GLOBAL_NAMESPACE
        with self._lock:
            table = self._rev.get(ns)
            if not table or not isinstance(text, str) or not text:
                return text, 0
            exact = table.get(text)
            if exact is not None and not self._expired(exact, time.time()):
                if pairs is not None:
                    pairs.append((exact.value, text))
                return exact.value, 1
            found: list[tuple[str, str]] = []

            def lookup(candidate: str) -> str | None:
                e = table.get(candidate)
                return None if e is None else e.value

            out = replace_known(text, lookup, on_hit=lambda tok, real: found.append((real, tok)))
            if found:
                self._counters["detokenized"] += len(found)
                if pairs is not None:
                    pairs.extend(found)
            return out, len(found)

    def replace_known_values(
        self,
        text: str,
        *,
        namespace: str | None = None,
        min_length: int = 3,
    ) -> tuple[str, int]:
        """Replace every real value this vault already pseudonymised (in
        ``namespace``) where it appears as a whole word inside ``text``,
        with its token. Used for text the redactor cannot parse (GraphML,
        N-Triples, Turtle, messages), so names and account ids seen
        elsewhere in the dataset get the same pseudonyms there."""
        ns = namespace or GLOBAL_NAMESPACE
        with self._lock:
            known = self._known.get(ns)
            if not known or not isinstance(text, str) or not text:
                return text, 0
            hits = [0]

            def lookup(candidate: str) -> str | None:
                if len(candidate) < min_length:
                    return None
                return known.get(candidate)

            def on_hit(_real: str, _tok: str) -> None:
                hits[0] += 1

            out = replace_known(text, lookup, on_hit=on_hit)
            return out, hits[0]

    def _remember(self, ns: str, value: str, tok: str) -> None:
        """Index ``value -> token`` for :meth:`replace_known_values` (the
        first token issued for a value wins)."""
        if tok != value:
            self._known.setdefault(ns, {}).setdefault(value, tok)

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
        known = self._known.get(ns)
        if known is not None and known.get(entry.value) == token:
            del known[entry.value]
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
                self._known.clear()
                self._bits.clear()
            else:
                self._known.pop(namespace, None)
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
                self._remember(ns, value, tok)
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
        with self._lock:  # a mapping added meanwhile must keep the vault dirty
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
            _atomic_write(target, blob)
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
