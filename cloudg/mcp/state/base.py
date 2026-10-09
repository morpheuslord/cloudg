"""Constants, errors and small helpers shared by the workspace modules."""

from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any, Callable, Iterable

from cloudg.mcp.core import NotFoundError
from cloudg.schema.models import Severity

INTERNET_NODES = ("0.0.0.0/0", "::/0")
SEVERITY_RANK = {
    Severity.CRITICAL.value: 4,
    Severity.HIGH.value: 3,
    Severity.MEDIUM.value: 2,
    Severity.LOW.value: 1,
    Severity.INFO.value: 0,
}
SCANNER_KINDS = ("prowler", "scoutsuite", "checkov", "trivy")
DATASET_KINDS = ("auto", "inventory", "report", "generic", *SCANNER_KINDS)
NAME_RE = re.compile(r"^[A-Za-z0-9_.\-]{1,64}$")


# ---------------------------------------------------------------------------
# Errors. Both are NotFoundError subclasses: raised from a tool handler the
# layer returns them as an isError result the model can read (message plus
# ``data``); raised from a resource handler they become a JSON-RPC
# "resource not found" error.
#
# Messages never repeat the reference the caller passed or the names of
# close matches: the input pipeline may have restored a pseudonym to its
# real value, and error text is only scanned as free text. The reference
# goes in ``data["value"]`` and suggestions go in ``data["suggestions"]`` as
# dicts, where the output pipeline sees each value with its key.
# ---------------------------------------------------------------------------


class NoDatasetError(NotFoundError):
    """No dataset is loaded / the named dataset does not exist."""


class ReferenceNotFoundError(NotFoundError):
    """An asset / finding / control reference matched nothing."""


def ref_tails(identifier: str) -> set[str]:
    """Short forms an asset can be referred to by, derived from its ARN or
    resource id: the resource part of an ARN (``function:api``,
    ``db:orders``, ``instance/i-0abc``), the last ``/`` segment
    (``i-0abc``) and the last ``:`` segment (``api``). Azure / GCP paths
    contribute their last ``/`` segment."""
    out: set[str] = set()
    if identifier.startswith("arn:"):
        parts = identifier.split(":", 5)
        if len(parts) == 6 and parts[5]:
            out.add(parts[5])
    slash = identifier.rsplit("/", 1)[-1]
    colon = identifier.rsplit(":", 1)[-1]
    for t in (slash, colon):
        if t and t != identifier:
            out.add(t)
    return out


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def count_by(items: Iterable[Any], key: Callable[[Any], str]) -> dict[str, int]:
    out: dict[str, int] = {}
    for it in items:
        k = key(it)
        out[k] = out.get(k, 0) + 1
    return dict(sorted(out.items(), key=lambda kv: -kv[1]))


def matches_note(count: int) -> str:
    """Sentence pointing at the suggestions carried in the error data."""
    if not count:
        return ""
    noun = "match" if count == 1 else "matches"
    return f" {count} close {noun}, see suggestions in the error data."
