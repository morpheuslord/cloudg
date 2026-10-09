"""Decision audit trail of a policy: the ring buffer behind
``privacy_audit_log`` and the ``cloudg.mcp.audit`` logger.

Entries and log lines never hold argument values: arguments appear as field
names with keyed hashes, revealed values are never recorded, and the
variable part of an unknown resource URI is hashed too. Every client-chosen
string that reaches a log line has its control characters escaped, so a
name containing CR / LF cannot forge extra audit lines.
"""

from __future__ import annotations

import json
import logging
import threading
import time
from collections import Counter, deque
from typing import Any, Callable

audit_logger = logging.getLogger("cloudg.mcp.audit")

_CONTROL = {
    **{c: f"\\x{c:02x}" for c in range(0x20)},
    0x0A: "\\n",
    0x0D: "\\r",
    0x09: "\\t",
    0x7F: "\\x7f",
    0x85: "\\x85",
    0x2028: "\\u2028",
    0x2029: "\\u2029",
}


def log_safe(value: Any) -> str:
    """``value`` as one log-line-safe string (control characters escaped)."""
    return str(value).translate(_CONTROL)


class AuditTrail:
    """Mixin for :class:`~cloudg.mcp.policy.Policy`: needs ``config``,
    ``vault``, ``name``, ``_lock``, ``audit_log``, ``counters`` and
    ``_principal()``."""

    config: Any
    vault: Any
    name: str
    _lock: threading.RLock
    audit_log: deque[dict[str, Any]]
    counters: Counter[str]

    # provided by Policy
    _principal: Callable[[Any], Any]

    def _arg_fingerprint(self, arguments: dict[str, Any] | None) -> dict[str, str]:
        """Argument field names with keyed hashes of the values. The values
        themselves are never included."""
        out: dict[str, str] = {}
        for k, v in (arguments or {}).items():
            try:
                blob = json.dumps(v, sort_keys=True, default=str)
            except (TypeError, ValueError):
                blob = str(v)
            out[str(k)] = self.vault.hash_value(blob, length=12, entity_type="audit")
        return out

    def _audit(
        self,
        event: tuple[str, str, str],
        principal: Any,
        arguments: dict[str, Any] | None,
        reason: str,
        *,
        force: bool = False,
    ) -> None:
        """Record ``event = (decision, kind, name)``."""
        decision, kind, name = event
        if not (self.config.audit or force or decision != "allowed"):
            return
        entry = {
            "ts": time.time(),
            "decision": decision,
            "kind": kind,
            "name": name,
            "principal": str(getattr(principal, "id", "anonymous")),
            "roles": sorted(getattr(principal, "roles", ()) or ()),
            "arguments": self._arg_fingerprint(arguments),
            **({"reason": reason} if reason else {}),
        }
        with self._lock:
            if self.audit_log.maxlen != 0:
                self.audit_log.append(entry)
        if self.config.audit or decision != "allowed":
            audit_logger.info(
                "%s %s %s principal=%s %s",
                decision,
                log_safe(kind),
                log_safe(name),
                log_safe(entry["principal"]),
                log_safe(reason),
            )

    def _log_reveal(self, principal: Any, kind: str, name: str, arguments: Any) -> None:
        audit_logger.warning(
            "REVEAL principal=%s roles=%s %s=%s args=%s policy=%s",
            log_safe(getattr(principal, "id", "?")),
            log_safe(sorted(getattr(principal, "roles", ()) or ())),
            log_safe(kind),
            log_safe(name),
            self._arg_fingerprint(arguments),
            log_safe(self.name),
        )

    def record_rejection(
        self,
        spec: Any,
        principal: Any,
        arguments: dict[str, Any] | None,
        exc: BaseException,
    ) -> None:
        """Called by the layer when the input pipeline refused a call that
        :meth:`check_call` had already allowed (secrets in arguments...).
        The matching "allowed" audit entry is amended to "rejected", or a
        new entry is added."""
        from cloudg.mcp.policy.access import _idents, spec_kind

        principal = self._principal(principal)
        kind = spec_kind(spec)
        name = _idents(spec)[0]
        reason = str(getattr(exc, "message", None) or exc)[:300]
        self.counters["rejected"] += 1
        fp = self._arg_fingerprint(arguments)
        pid = str(getattr(principal, "id", "anonymous"))
        with self._lock:
            for entry in reversed(self.audit_log):
                if (
                    entry["decision"] == "allowed"
                    and entry["name"] == name
                    and entry["principal"] == pid
                    and entry["arguments"] == fp
                ):
                    entry["decision"] = "rejected"
                    entry["reason"] = reason
                    break
            else:
                self._audit(("rejected", kind, name), principal, arguments, reason, force=True)
                return
        audit_logger.info(
            "rejected %s %s principal=%s %s",
            log_safe(kind),
            log_safe(name),
            log_safe(pid),
            log_safe(reason),
        )

    def record_hidden(
        self,
        kind: str,
        name: str,
        principal: Any,
        arguments: dict[str, Any] | None = None,
    ) -> None:
        """Called by the layer when a caller asks for a primitive that is
        unknown or hidden by this policy (it answers "not found")."""
        principal = self._principal(principal)
        self.counters["hidden"] += 1
        self._audit(
            ("not_found", str(kind), self._probe_name(str(kind), str(name))),
            principal,
            arguments,
            "unknown or hidden by policy",
            force=True,
        )

    def _probe_name(self, kind: str, name: str) -> str:
        """The name to record for a probe. A resource URI keeps its scheme
        and first path segment; the rest may carry argument values
        (``cloudg://assets/<name>``) and is replaced by a keyed hash."""
        if kind == "resource" and "://" in name:
            scheme, _, rest = name.partition("://")
            head, sep, tail = rest.partition("/")
            if tail:
                digest = self.vault.hash_value(tail, length=12, entity_type="audit")
                name = f"{scheme}://{head}{sep}#{digest}"
        return name[:200]
