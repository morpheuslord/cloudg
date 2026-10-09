"""Redaction strategies: parsing, resolution chains and the value-level
operations (mask, bucket, generalise). See
:mod:`cloudg.mcp.transforms.redaction` for the strategy table."""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from typing import Any, Callable

from cloudg.mcp.transforms.entities import ENTITY_PARENTS

STRATEGIES = ("redact", "mask", "hash", "pseudonymize", "generalize", "drop", "keep")
_STRATEGY_ALIASES = {
    "pseudonymise": "pseudonymize",
    "tokenize": "pseudonymize",
    "tokenise": "pseudonymize",
    "generalise": "generalize",
    "remove": "drop",
    "replace": "redact",
    "none": "keep",
    "allow": "keep",
    "bucket": "generalize",
}
#: Report section per strategy.
REPORT_KEY = {
    "redact": "redacted",
    "mask": "masked",
    "hash": "hashed",
    "pseudonymize": "pseudonymized",
    "generalize": "generalized",
    "drop": "dropped",
}


class _Drop:
    """Sentinel: remove the containing field / element."""

    def __repr__(self) -> str:  # pragma: no cover
        return "<DROP>"


DROP = _Drop()


@dataclass(frozen=True)
class Strategy:
    kind: str
    options: dict[str, Any] = field(default_factory=dict)

    def __hash__(self) -> int:  # options are dicts; identity is fine for caching
        return hash((self.kind, id(self.options)))


KEEP = Strategy("keep")


def parse_strategy(spec: Any) -> Strategy:
    """``"redact"`` | ``{"strategy": "mask", "keep_last": 4}`` | Strategy."""
    if isinstance(spec, Strategy):
        return spec
    if spec is None or spec is False:
        return KEEP
    if spec is True:
        return Strategy("redact")
    if isinstance(spec, str):
        kind, opts = spec, {}
    elif isinstance(spec, dict):
        opts = dict(spec)
        kind = opts.pop("strategy", None) or opts.pop("type", None) or opts.pop("kind", "redact")
    else:
        raise ValueError(f"Invalid strategy {spec!r}")
    kind = _STRATEGY_ALIASES.get(str(kind).lower(), str(kind).lower())
    if kind not in STRATEGIES:
        raise ValueError(f"Unknown strategy {kind!r}; expected one of {', '.join(STRATEGIES)}")
    return Strategy(kind, opts)


def _chain(*names: str | None) -> tuple[str, ...]:
    """Entity names followed by their parents, without duplicates."""
    out: list[str] = []
    for n in names:
        while n and n not in out:
            out.append(n)
            n = ENTITY_PARENTS.get(n)
    return tuple(out)


def mask(text: str, opts: dict[str, Any]) -> str:
    char = str(opts.get("char", "*"))[:1] or "*"
    first = int(opts.get("keep_first", 0))
    last = int(opts.get("keep_last", 4))
    preserve = opts.get("preserve", "")  # characters left unmasked, e.g. "-.@"
    n = len(text)
    if first + last >= n:
        first, last = 0, 0 if n <= 4 else min(last, n // 4)
    body = "".join(c if c in preserve else char for c in text[first : n - last])
    out = text[:first] + body + (text[n - last :] if last else "")
    max_len = opts.get("max_length")
    if max_len and len(out) > int(max_len):
        out = out[: int(max_len)]
    return out


def bucket(value: float, opts: dict[str, Any]) -> str:
    size = float(opts.get("bucket", opts.get("bucket_size", 10)))
    if size <= 0:
        return str(value)
    lo = (value // size) * size
    hi = lo + size
    fmt = (lambda x: str(int(x))) if size.is_integer() else (lambda x: f"{x:g}")
    return f"{fmt(lo)}-{fmt(hi)}"


# ---------------------------------------------------------------------------
# generalize
# ---------------------------------------------------------------------------

_TS_GRANULARITY = {"year": 4, "month": 7, "day": 10, "date": 10, "hour": 13, "minute": 16}


def _gen_ip(text: str, entity: str, opts: dict[str, Any]) -> str:
    try:
        return _supernet(text, entity, opts)
    except ValueError:
        return f"<{entity}>"


def _supernet(text: str, entity: str, opts: dict[str, Any]) -> str:
    net = ipaddress.ip_network(text, strict=False) if "/" in text else ipaddress.ip_network(text)
    v4 = net.version == 4
    target = int(opts.get("ipv4_prefix" if v4 else "ipv6_prefix", 24 if v4 else 48))
    if entity.startswith("special"):
        return text
    if net.prefixlen > target:
        net = net.supernet(new_prefix=target)
    return str(net)


def _gen_timestamp(text: str, _entity: str, opts: dict[str, Any]) -> str:
    return text[: _TS_GRANULARITY.get(str(opts.get("granularity", "day")), 10)]


def _gen_email(text: str, _entity: str, _opts: dict[str, Any]) -> str:
    return "*@" + text.rpartition("@")[2]


def _gen_hostname(text: str, _entity: str, opts: dict[str, Any]) -> str:
    labels = text.split(".")
    keep = int(opts.get("keep_labels", 2))
    return "*." + ".".join(labels[-keep:]) if len(labels) > keep else text


def _gen_arn(text: str, _entity: str, _opts: dict[str, Any]) -> str | None:
    parts = text.split(":", 5)
    if len(parts) != 6:
        return None
    res = parts[5]
    typ = re.split(r"[/:]", res, maxsplit=1)
    res_out = f"{typ[0]}{res[len(typ[0])]}*" if len(typ) > 1 else "*"
    return ":".join(parts[:4] + ["*" if parts[4] else "", res_out])


def _gen_azure_id(text: str, _entity: str, _opts: dict[str, Any]) -> str:
    out, prev, mode = [], "", ""
    for seg in text.split("/"):
        low = seg.lower()
        if prev in ("subscriptions", "resourcegroups", "tenants") or mode == "name":
            out.append("*")
            mode = "type" if mode == "name" else mode
        else:
            out.append(seg)
            mode = {"namespace": "type", "type": "name"}.get(mode, mode)
            if low == "providers":
                mode = "namespace"
        prev = low
    return "/".join(out)


def _gen_gcp_name(text: str, _entity: str, _opts: dict[str, Any]) -> str:
    m = re.match(r"^(//[^/]+/)?(.*)$", text, re.S)
    head, rest = ((m.group(1) or ""), m.group(2)) if m else ("", text)
    segs = rest.split("/")
    out = [
        s if i % 2 == 0 or segs[i - 1].lower() in ("zones", "regions", "locations") else "*"
        for i, s in enumerate(segs)
    ]
    return head + "/".join(out)


_GENERALIZERS: dict[str, Callable[[str, str, dict[str, Any]], str | None]] = {
    "ip_address": _gen_ip,
    "cidr": _gen_ip,
    "timestamp": _gen_timestamp,
    "email": _gen_email,
    "hostname": _gen_hostname,
    "aws_arn": _gen_arn,
    "azure_resource_id": _gen_azure_id,
    "gcp_resource_name": _gen_gcp_name,
}


def generalize(text: str, entity: str, opts: dict[str, Any] | None = None) -> str:
    """Coarsen one value: IP -> ``/24``, timestamp -> date, email ->
    ``*@domain``, ARN -> ``arn:aws:ec2:us-east-1:*:instance/*``, numbers ->
    buckets, anything else -> ``<entity>``."""
    opts = opts or {}
    root = entity
    while root in ENTITY_PARENTS:
        root = ENTITY_PARENTS[root]
    fn = _GENERALIZERS.get(root)
    if fn is not None:
        out = fn(text, entity, opts)
        if out is not None:
            return out
    if text.lstrip("-").replace(".", "", 1).isdigit() and "bucket" in opts:
        try:
            return bucket(float(text), opts)
        except ValueError:  # pragma: no cover
            return f"<{entity}>"
    return f"<{entity}>"
