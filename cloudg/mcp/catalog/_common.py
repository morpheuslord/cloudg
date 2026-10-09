"""Shared helpers for the catalog modules.

Conventions every catalog tool follows so an agent can rely on them:

- ``dataset`` argument: empty means the active dataset.
- Asset references (``ref``) accept the internal id, the ARN / cloud
  resource id, a unique name, or a unique ARN tail; misses come back as an
  error listing close matches.
- List tools are bounded: ``limit`` (default 50) plus an opaque ``cursor``;
  results carry ``total``, ``returned``, ``next_cursor`` and ``truncated``.
  A cursor is tied to the query and dataset version that produced it, so a
  stale cursor is rejected instead of silently returning the wrong page.
- Assets are summarised as compact "briefs" with a ``uri``
  (``cloudg://assets/{id}``) the client can read for full detail.
"""

from __future__ import annotations

import dataclasses
import difflib
import hashlib
import json
import re
from enum import Enum
from typing import Annotated, Any, Callable, Iterable, Sequence, TypeVar
from urllib.parse import quote

from pydantic import BaseModel, ConfigDict, Field

from cloudg.mcp.core import InvalidArgumentsError
from cloudg.mcp.state import SEVERITY_RANK, Dataset
from cloudg.schema.models import CloudAsset, Finding, NetworkEdge, Severity

T = TypeVar("T")
E = TypeVar("E", bound=Enum)
F = TypeVar("F", bound=Callable[..., Any])

#: Dataset summary keys every headline view (live run results, prompt
#: overviews) shows, in display order.
SUMMARY_CORE_KEYS = (
    "open_findings",
    "severity_breakdown",
    "accounts",
    "regions",
    "internet_exposed",
    "cross_account_edges",
)
DEFAULT_LIMIT = 50
MAX_LIMIT = 500


class Catalog:
    """Records tool / resource / prompt declarations made at import time
    and replays them onto a :class:`~cloudg.mcp.core.Registry`.

    Catalog modules declare their handlers as module-level functions with
    ``@CATALOG.tool(...)`` (same arguments as :meth:`Registry.tool`) and
    their ``register(reg)`` is just ``CATALOG.register(reg)``. Declaration
    order is registration order.
    """

    def __init__(self) -> None:
        self._specs: list[tuple[str, tuple[Any, ...], dict[str, Any], Callable[..., Any]]] = []

    def _record(self, kind: str, *args: Any, **kwargs: Any) -> Callable[[F], F]:
        def deco(fn: F) -> F:
            self._specs.append((kind, args, kwargs, fn))
            return fn

        return deco

    def tool(self, *args: Any, **kwargs: Any) -> Callable[[F], F]:
        return self._record("tool", *args, **kwargs)

    def resource(self, *args: Any, **kwargs: Any) -> Callable[[F], F]:
        return self._record("resource", *args, **kwargs)

    def resource_template(self, *args: Any, **kwargs: Any) -> Callable[[F], F]:
        return self._record("resource_template", *args, **kwargs)

    def prompt(self, *args: Any, **kwargs: Any) -> Callable[[F], F]:
        return self._record("prompt", *args, **kwargs)

    def register(self, reg: Any) -> None:
        for kind, args, kwargs, fn in self._specs:
            getattr(reg, kind)(*args, **kwargs)(fn)


DatasetArg = Annotated[
    str, Field(description="Dataset name (see list_datasets). Empty = the active dataset.")
]
RefArg = Annotated[
    str,
    Field(
        min_length=1,
        description="Asset reference: internal id, ARN / cloud resource id, unique name, "
        "or unique ARN tail (e.g. 'function:api' or 'i-0abc').",
    ),
]
Limit = Annotated[int, Field(ge=1, le=MAX_LIMIT, description="Maximum items to return.")]
Cursor = Annotated[
    str, Field(description="Opaque cursor from a previous call's next_cursor; empty = first page.")
]

ASSET_FIELDS = (
    "id",
    "name",
    "type",
    "provider",
    "region",
    "account_id",
    "arn",
    "internet_exposed",
    "open_findings",
    "max_severity",
    "tags",
    "uri",
)
FINDING_FIELDS = (
    "id",
    "title",
    "severity",
    "risk_score",
    "source_tool",
    "resource_id",
    "resource_arn",
    "asset_id",
    "asset_name",
    "compliance_frameworks",
    "is_suppressed",
    "cvss_score",
    "detected_at",
    "uri",
)


def ws_dataset(ctx: Any, dataset: str = "") -> Dataset:
    return ctx.workspace.get(dataset or None)


def asset_uri(asset_id: str) -> str:
    return "cloudg://assets/" + quote(asset_id, safe="")


def finding_uri(finding_id: str) -> str:
    return "cloudg://findings/" + quote(finding_id, safe="")


def max_severity(findings: Iterable[Finding]) -> str | None:
    best = None
    for f in findings:
        if best is None or SEVERITY_RANK[f.severity.value] > SEVERITY_RANK[best]:
            best = f.severity.value
    return best


def asset_brief(ds: Dataset, a: CloudAsset, *, tags: bool = False) -> dict[str, Any]:
    open_f = ds.open_findings(a.id)
    out: dict[str, Any] = {
        "id": a.id,
        "name": a.name,
        "type": a.asset_type.value,
        "provider": a.provider.value,
        "region": a.region,
        "account_id": a.account_id,
        "arn": a.arn,
        "internet_exposed": a.is_internet_exposed,
        "open_findings": len(open_f),
        "max_severity": max_severity(open_f),
        "uri": asset_uri(a.id),
    }
    if tags:
        out["tags"] = dict(a.tags)
    return out


def node_brief(ds: Dataset, node_id: str) -> dict[str, Any]:
    """Brief for a graph node: an asset, or a placeholder (CIDR / external)."""
    a = ds.by_id.get(node_id)
    if a is not None:
        return asset_brief(ds, a)
    data = ds.graph.nodes.get(node_id, {}) if node_id in ds.graph else {}
    return {
        "id": node_id,
        "name": data.get("name", node_id),
        "type": data.get("asset_type", "EXTERNAL"),
        "external": True,
    }


def edge_brief(ds: Dataset, e: NetworkEdge) -> dict[str, Any]:
    s, t = ds.by_id.get(e.source_id), ds.by_id.get(e.target_id)
    out: dict[str, Any] = {
        "id": e.id,
        "source": e.source_id,
        "source_name": s.name if s else e.source_id,
        "target": e.target_id,
        "target_name": t.name if t else e.target_id,
        "edge_type": e.edge_type.value,
        "relationship": e.relationship,
    }
    for k in ("port_range", "protocol", "cidr", "description"):
        v = getattr(e, k)
        if v:
            out[k] = v
    if e.ports:
        out["ports"] = e.ports[:20]
    if e.edge_type.value in ("SECURITY_GROUP_RULE", "NACL_RULE"):
        out["direction"] = e.direction
    if s and t and s.account_id and t.account_id and s.account_id != t.account_id:
        out["cross_account"] = True
    return out


def finding_brief(ds: Dataset, f: Finding) -> dict[str, Any]:
    aid = ds.finding_asset_id(f)
    a = ds.by_id.get(aid) if aid else None
    return {
        "id": f.id,
        "title": f.title,
        "severity": f.severity.value,
        "risk_score": f.risk_score,
        "source_tool": f.source_tool,
        "resource_id": f.resource_id,
        "resource_arn": f.resource_arn,
        "asset_id": a.id if a else None,
        "asset_name": a.name if a else None,
        "compliance_frameworks": list(f.compliance_frameworks),
        "is_suppressed": f.is_suppressed,
        "cvss_score": f.cvss_score,
        "detected_at": f.detected_at.isoformat() if f.detected_at else None,
        "uri": finding_uri(f.id),
    }


# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------


def parse_enum(value: str, enum: type[E], label: str) -> E:
    """Case-insensitive enum lookup with a helpful error."""
    v = (value or "").strip().upper().replace("-", "_").replace(" ", "_")
    for attr in ("value", "name"):
        for m in enum:
            if getattr(m, attr) == v:
                return m
    names = [m.value for m in enum]
    close = difflib.get_close_matches(v, names, n=3, cutoff=0.5)
    hint = f" Did you mean {', '.join(close)}?" if close else ""
    shown = ", ".join(names) if len(names) <= 30 else ", ".join(names[:30]) + ", ..."
    # The value itself goes in data, not in the text (see cloudg.mcp.state.base)
    raise InvalidArgumentsError(
        f"Unknown {label}.{hint} Valid values: {shown}",
        data={"value": value, "valid": names, "close_matches": close},
    )


def parse_enums(values: Sequence[str] | None, enum: type[E], label: str) -> set[E]:
    return {parse_enum(v, enum, label) for v in values or []}


def parse_severity(value: str) -> Severity:
    return parse_enum(value, Severity, "severity")


class ArgsFilter:
    """Base for the frozen dataclass filters the list tools build from
    their arguments (FindingFilter, AssetFilter)."""

    @classmethod
    def from_args(cls: type[T], args: dict[str, Any]) -> T:
        """Build from a tool's arguments (``locals()``): the matching keys."""
        names = (f.name for f in dataclasses.fields(cls))  # type: ignore[arg-type]
        return cls(**{name: args[name] for name in names if name in args})

    def key(self) -> dict[str, Any]:
        """The filter as a dict, for cursor fingerprints."""
        return dataclasses.asdict(self)  # type: ignore[call-overload]


def check_fields(fields: Sequence[str] | None, allowed: Sequence[str]) -> list[str] | None:
    if not fields:
        return None
    bad = [f for f in fields if f not in allowed]
    if bad:
        raise InvalidArgumentsError(
            f"Unknown field(s) {', '.join(bad)}. Valid fields: {', '.join(allowed)}"
        )
    out = list(dict.fromkeys(["id", *fields]))
    return out


def project(item: dict[str, Any], fields: list[str] | None) -> dict[str, Any]:
    if not fields:
        return item
    return {k: item.get(k) for k in fields}


# ---------------------------------------------------------------------------
# Pagination
# ---------------------------------------------------------------------------


def fingerprint(ds: Dataset | None, **params: Any) -> str:
    """Hash of the query and the dataset state a cursor belongs to: name,
    version and the per-load instance id, so a dataset replaced under the
    same name (version back to 0) rejects the old cursors."""
    raw = json.dumps(
        {
            "ds": ds.name if ds else None,
            "v": ds.version if ds else None,
            "i": getattr(ds, "instance_id", None) if ds else None,
            **params,
        },
        sort_keys=True,
        default=str,
    )
    return hashlib.sha256(raw.encode()).hexdigest()[:12]


def encode_cursor(offset: int, fp: str) -> str:
    # Short and punctuated on purpose: privacy policies redact long opaque
    # base64-looking tokens (and anything starting "eyJ") as secrets.
    return f"c{offset}.{fp}"


_CURSOR_RE = re.compile(r"^c(\d{1,9})\.([0-9a-f]{12})$")


def decode_cursor(cursor: str, fp: str) -> int:
    if not cursor:
        return 0
    m = _CURSOR_RE.match(cursor.strip())
    if not m:
        raise InvalidArgumentsError(
            "Invalid cursor. Pass the next_cursor value from the previous result unchanged, "
            "or omit cursor to start from the first page."
        )
    if m.group(2) != fp:
        raise InvalidArgumentsError(
            "Stale cursor: the query arguments or the dataset changed since it was issued. "
            "Repeat the call without cursor to start again."
        )
    return int(m.group(1))


def paginate(
    items: Sequence[T], limit: int, cursor: str, fp: str
) -> tuple[list[T], dict[str, Any]]:
    """Slice ``items``; returns (page, envelope fields)."""
    start = decode_cursor(cursor, fp)
    page = list(items[start : start + limit])
    end = start + len(page)
    more = end < len(items)
    return page, {
        "total": len(items),
        "offset": start,
        "returned": len(page),
        "next_cursor": encode_cursor(end, fp) if more else None,
        "truncated": more,
    }


def bounded(items: Sequence[T], limit: int) -> tuple[list[T], dict[str, Any]]:
    """First ``limit`` items plus total/truncated (no cursor)."""
    return list(items[:limit]), {
        "total": len(items),
        "returned": min(limit, len(items)),
        "truncated": len(items) > limit,
    }


# ---------------------------------------------------------------------------
# Output schemas (documented shapes; every field optional so that policy
# transforms such as projection / redaction never make results invalid)
# ---------------------------------------------------------------------------


class _Out(BaseModel):
    model_config = ConfigDict(extra="allow")


class AssetBriefOut(_Out):
    id: str | None = None
    name: str | None = None
    type: str | None = None
    provider: str | None = None
    region: str | None = None
    account_id: str | None = None
    arn: str | None = None
    internet_exposed: bool | None = None
    open_findings: int | None = None
    max_severity: str | None = None
    uri: str | None = None


class PageOut(_Out):
    dataset: str | None = None
    total: int | None = None
    offset: int | None = None
    returned: int | None = None
    next_cursor: str | None = None
    truncated: bool | None = None


class AssetPageOut(PageOut):
    items: list[AssetBriefOut] = Field(default_factory=list)


class EdgeOut(_Out):
    id: str | None = None
    source: str | None = None
    source_name: str | None = None
    target: str | None = None
    target_name: str | None = None
    edge_type: str | None = None
    relationship: str | None = None


class EdgePageOut(PageOut):
    items: list[EdgeOut] = Field(default_factory=list)


class FindingBriefOut(_Out):
    id: str | None = None
    title: str | None = None
    severity: str | None = None
    risk_score: float | None = None
    source_tool: str | None = None
    asset_id: str | None = None
    asset_name: str | None = None
    compliance_frameworks: list[str] | None = None
    is_suppressed: bool | None = None
    uri: str | None = None


class FindingPageOut(PageOut):
    items: list[FindingBriefOut] = Field(default_factory=list)


class AssetDetailOut(AssetBriefOut):
    tags: dict[str, str] | None = None
    relations: dict[str, Any] | None = None
    findings: list[FindingBriefOut] | None = None
    metadata_keys: list[str] | None = None


class NeighborsOut(_Out):
    dataset: str | None = None
    asset: AssetBriefOut | None = None
    nodes: list[AssetBriefOut] = Field(default_factory=list)
    edges: list[EdgeOut] = Field(default_factory=list)
    truncated: bool | None = None


class PathOut(_Out):
    length: int | None = None
    nodes: list[AssetBriefOut] = Field(default_factory=list)
    edge_types: list[str] = Field(default_factory=list)


class PathsOut(_Out):
    dataset: str | None = None
    paths: list[PathOut] = Field(default_factory=list)
    total_found: int | None = None
    truncated: bool | None = None


class DependencyOut(_Out):
    dataset: str | None = None
    asset: AssetBriefOut | None = None
    total: int | None = None
    items: list[dict[str, Any]] = Field(default_factory=list)
    truncated: bool | None = None


class SummaryOut(_Out):
    dataset: str | None = None
    total_assets: int | None = None
    total_edges: int | None = None
    total_findings: int | None = None
    open_findings: int | None = None
    severity_breakdown: dict[str, int] | None = None


class CountOut(_Out):
    dataset: str | None = None
    group_by: str | None = None
    total: int | None = None
    groups: dict[str, int] = Field(default_factory=dict)


class RiskOut(_Out):
    asset: AssetBriefOut | None = None
    score: float | None = None
    components: dict[str, Any] | None = None
    top_findings: list[FindingBriefOut] = Field(default_factory=list)


class TopRisksOut(_Out):
    dataset: str | None = None
    items: list[RiskOut] = Field(default_factory=list)
    total_candidates: int | None = None


class WorkspaceOut(_Out):
    active_dataset: str | None = None
    datasets: list[dict[str, Any]] = Field(default_factory=list)
    allowed_roots: list[str] | None = None
    output_dir: str | None = None


class DiffSectionOut(_Out):
    count: int | None = None
    items: list[dict[str, Any]] = Field(default_factory=list)
    truncated: bool | None = None


class DiffOut(_Out):
    base: str | None = None
    target: str | None = None
    assets: dict[str, Any] | None = None
    edges: dict[str, Any] | None = None
    findings: dict[str, Any] | None = None


class SparqlOut(_Out):
    dataset: str | None = None
    query_type: str | None = None
    rows: list[dict[str, Any]] = Field(default_factory=list)
    returned: int | None = None
    truncated: bool | None = None
    answer: bool | None = None


class ComplianceSummaryOut(_Out):
    dataset: str | None = None
    frameworks: list[dict[str, Any]] = Field(default_factory=list)


def schema(model: type[BaseModel]) -> dict[str, Any]:
    from cloudg.mcp.schema import output_schema_for

    return output_schema_for(model)
