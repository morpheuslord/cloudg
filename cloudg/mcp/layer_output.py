"""Output shaping for :class:`~cloudg.mcp.layer.CloudGMCPLayer`.

Everything a call sends back to the client (tool results, resource
contents, prompt messages, resource links, error messages and their
``data``, progress messages and log notifications) leaves through one
:class:`OutputScope`: the caller's output pipeline for that primitive, plus
re-pseudonymisation of the real values the call's *input* pipeline restored.

Why the second step: a pseudonym in the arguments is reversed to the real
value before the handler runs (``get_asset("res-759480a35a")`` resolves
``web-1``). A handler that echoes its argument (``"Unknown severity
'web-1'"``) would otherwise hand the real value back, and a bare name in
free text is not something the output detectors can recognise on their own.
The scope knows every ``(real, token)`` pair of the call and swaps the real
value back to its token in every outgoing string.
"""

from __future__ import annotations

import base64
import dataclasses
import json
import re
from typing import TYPE_CHECKING, Any, Iterable

from pydantic import BaseModel

from cloudg.mcp.core import (
    META_PREFIX,
    BlobResourceContents,
    EmbeddedResource,
    MCPLayerError,
    PromptMessage,
    PromptResult,
    ResourceLink,
    TextContent,
    TextResourceContents,
    ToolResult,
    render_json,
)
from cloudg.mcp.transforms.base import TransformContext

try:  # the transforms package's helper, when this cloudg has it
    from cloudg.mcp.transforms import repseudonymize as _shared_repseudonymize
except ImportError:  # pragma: no cover (older transforms package)
    _shared_repseudonymize = None

if TYPE_CHECKING:  # pragma: no cover
    from cloudg.mcp.context import Principal

__all__ = [
    "DATA_META_KEY",
    "RENDER_META_KEY",
    "OutputScope",
    "error_result",
    "jsonable",
    "restored_pairs",
    "shape_prompt",
    "shape_resource",
    "shape_tool_result",
    "transform_error",
    "transform_links",
]

#: ``_meta`` key of a TextContent / TextResourceContents whose text is
#: rendered from structured data: the layer transforms the data with key
#: context, then renders it (see :data:`RENDER_META_KEY`).
DATA_META_KEY = f"{META_PREFIX}data"
#: ``"json"`` (default, indented JSON) or ``"json-block"`` (a fenced JSON
#: block under a short heading, for prompt messages).
RENDER_META_KEY = f"{META_PREFIX}render"
_JSON_BLOCK_HEADING = "Context for this task (JSON):\n```json\n"
#: Restored values shorter than this are not swapped back (too ambiguous).
_MIN_RESTORED_LEN = 3
_TRUNCATED_NOTE = "\n... [truncated by cloudg mcp layer]"


def jsonable(value: Any) -> Any:
    """Convert handler output into JSON-compatible Python data."""
    if isinstance(value, BaseModel):
        return value.model_dump(mode="json", exclude={"raw_data"})
    if hasattr(value, "to_dict") and callable(value.to_dict):
        return jsonable(value.to_dict())
    if isinstance(value, dict):
        return {str(k): jsonable(v) for k, v in value.items()}
    if isinstance(value, (list, tuple, set, frozenset)):
        return [jsonable(v) for v in value]
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    if hasattr(value, "value") and isinstance(getattr(value, "value"), (str, int)):
        return value.value  # Enum
    if dataclasses.is_dataclass(value) and not isinstance(value, type):
        return jsonable(dataclasses.asdict(value))
    return str(value)


def merge_report(into: dict[str, Any], other: dict[str, Any]) -> None:
    for k, v in other.items():
        if isinstance(v, (int, float)) and isinstance(into.get(k), (int, float)):
            into[k] += v
        else:
            into.setdefault(k, v)


# ---------------------------------------------------------------------------
# Restored (real, token) pairs
# ---------------------------------------------------------------------------


def _pairs_from_report(report: Any) -> list[tuple[str, str]]:
    """Pairs a reversing input transform recorded (``report["restored"]``):
    a list of ``(real, token)`` pairs or ``{"real", "token"}`` dicts, or a
    ``{real: token}`` mapping."""
    raw = report.get("restored") if isinstance(report, dict) else None
    if isinstance(raw, dict):
        return [(str(k), str(v)) for k, v in raw.items()]
    out: list[tuple[str, str]] = []
    for item in raw or ():
        if isinstance(item, dict) and "real" in item and "token" in item:
            out.append((str(item["real"]), str(item["token"])))
        elif isinstance(item, (list, tuple)) and len(item) == 2:
            out.append((str(item[0]), str(item[1])))
    return out


def _diff_pairs(before: Any, after: Any, out: list[tuple[str, str]]) -> None:
    """Strings the input pipeline changed, as ``(restored, sent)`` pairs."""
    if isinstance(before, str) and isinstance(after, str):
        # fence stripping is not a pseudonym reversal
        if before != after and "⟦" not in before:
            out.append((after, before))
    elif isinstance(before, dict) and isinstance(after, dict):
        for key, value in before.items():
            if key in after:
                _diff_pairs(value, after[key], out)
    elif isinstance(before, (list, tuple)) and isinstance(after, (list, tuple)):
        for b, a in zip(before, after):
            _diff_pairs(b, a, out)


def restored_pairs(before: Any, after: Any, tctx: Any = None) -> list[tuple[str, str]]:
    """Every ``(real, token)`` pair the input pipeline of one call restored:
    the pairs its transforms recorded on ``tctx`` plus whole argument values
    it changed."""
    pairs: list[tuple[str, str]] = []
    if tctx is not None:
        pairs += _pairs_from_report(getattr(tctx, "report", None))
        extra = getattr(tctx, "restored", None)
        if extra:
            pairs += _pairs_from_report({"restored": extra})
    _diff_pairs(before, after, pairs)
    return pairs


# ---------------------------------------------------------------------------
# Scope
# ---------------------------------------------------------------------------


class OutputScope:
    """The output side of one call: ``spec``'s output pipeline for
    ``principal`` plus the call's restored values.

    ``scope(value)`` returns the transformed value; :meth:`apply` also
    returns the transform report.
    """

    def __init__(self, policy: Any, spec: Any, principal: "Principal", kind: str) -> None:
        self.policy = policy
        self.spec = spec
        self.principal = principal
        self.kind = kind
        self.pipeline = policy.output_pipeline(spec, principal)
        self._pairs: list[tuple[str, str]] = []
        self._swap: dict[str, str] = {}
        self._swap_re: re.Pattern[str] | None = None

    def __bool__(self) -> bool:
        return bool(self.pipeline)

    def add_restored(self, pairs: Iterable[tuple[str, str]]) -> None:
        """Remember real values the input pipeline restored; they are
        swapped back to their tokens in everything this scope emits."""
        for real, token in pairs:
            if len(real) >= _MIN_RESTORED_LEN and token and real != token:
                self._swap[real] = token
                self._pairs.append((real, token))
        if self._swap:
            alternatives = "|".join(re.escape(r) for r in sorted(self._swap, key=len, reverse=True))
            self._swap_re = re.compile(f"(?<![A-Za-z0-9])(?:{alternatives})(?![A-Za-z0-9])")

    def apply(self, value: Any) -> tuple[Any, dict[str, Any]]:
        if not self.pipeline:
            return value, {}
        tctx = TransformContext(
            principal=self.principal,
            spec=self.spec,
            kind=self.kind,
            direction="output",
            vault=self.policy.vault,
        )
        out = self.pipeline.apply(value, tctx)
        if self._pairs:
            out = self.repseudonymize(out)
        return out, tctx.report

    def repseudonymize(self, value: Any) -> Any:
        """``value`` with every restored real value replaced by its token."""
        if not self._pairs:
            return value
        if _shared_repseudonymize is not None:
            return _shared_repseudonymize(value, self._pairs)
        return self._reswap(value)

    def __call__(self, value: Any) -> Any:
        return self.apply(value)[0]

    def _reswap(self, value: Any) -> Any:
        if isinstance(value, str):
            rx = self._swap_re
            return rx.sub(lambda m: self._swap[m.group(0)], value) if rx else value
        if isinstance(value, dict):
            return {self._reswap(k): self._reswap(v) for k, v in value.items()}
        if isinstance(value, list):
            return [self._reswap(v) for v in value]
        return value


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


def transform_error(scope: OutputScope, exc: MCPLayerError) -> MCPLayerError:
    """Run an error's message and ``data`` through ``scope`` (in place)."""
    if not scope:
        return exc
    text, _ = scope.apply(exc.message)
    exc.message = str(text)
    exc.args = (exc.message,)
    if exc.data is not None:
        exc.data, _ = scope.apply(jsonable(exc.data))
    return exc


def wrap_handler_exception(scope: OutputScope, exc: Exception) -> MCPLayerError:
    """A transformed :class:`MCPLayerError` (internal error) for an
    unexpected handler exception; its text often quotes identifiers."""
    return transform_error(scope, MCPLayerError(f"{type(exc).__name__}: {exc}"))


def error_result(scope: OutputScope, message: str, code: Any, data: Any = None) -> ToolResult:
    text, _ = scope.apply(message)
    meta: dict[str, Any] = {f"{META_PREFIX}error_code": code}
    if data is not None:
        meta[f"{META_PREFIX}error_data"], _ = scope.apply(jsonable(data))
    return ToolResult(content=[TextContent(str(text))], is_error=True, meta=meta)


# ---------------------------------------------------------------------------
# Links, embedded resources and structured text
# ---------------------------------------------------------------------------


def _link_wire(link: ResourceLink) -> dict[str, Any]:
    return {
        "uri": link.uri,
        "name": link.name,
        "title": link.title,
        "description": link.description,
    }


def transform_links(
    scope: OutputScope, links: list[ResourceLink], context: Any = None
) -> list[ResourceLink]:
    """Transform resource links in the same pipeline run as ``context`` (the
    call's payload), so names the payload pseudonymises are pseudonymised
    in link names, titles and descriptions too."""
    if not links or not scope:
        return list(links)
    wires = [_link_wire(link) for link in links]
    combined, _ = scope.apply({"links": wires, "context": context})
    out = combined.get("links") if isinstance(combined, dict) else None
    if not isinstance(out, list) or len(out) != len(wires):
        out = [scope(w) for w in wires]  # a projection reshaped the run
    result = []
    for link, wire in zip(links, out):
        wire = wire if isinstance(wire, dict) else {}
        result.append(
            dataclasses.replace(
                link,
                uri=str(wire.get("uri", link.uri)),
                name=str(wire.get("name", link.name)),
                title=wire.get("title"),
                description=wire.get("description"),
            )
        )
    return result


def _render_data(scope: OutputScope, meta: dict[str, Any] | None) -> tuple[str, Any, dict] | None:
    """Text for content carrying its structured payload under
    :data:`DATA_META_KEY`: ``(text, remaining meta, report)``, or ``None``."""
    if not meta or DATA_META_KEY not in meta:
        return None
    rest = dict(meta)
    data = rest.pop(DATA_META_KEY)
    mode = rest.pop(RENDER_META_KEY, "json")
    transformed, report = scope.apply(jsonable(data))
    if mode == "json-block":
        body = json.dumps(transformed, indent=1, ensure_ascii=False, default=str)
        text = f"{_JSON_BLOCK_HEADING}{body}\n```"
    else:
        text = json.dumps(transformed, indent=2, ensure_ascii=False, default=str)
    return text, (rest or None), report


def _text_content(scope: OutputScope, c: TextContent, report: dict) -> TextContent:
    rendered = _render_data(scope, c.meta)
    if rendered is not None:
        text, meta, r = rendered
        merge_report(report, r)
        return TextContent(text, c.annotations, meta)
    text, r = scope.apply(c.text)
    merge_report(report, r)
    return TextContent(str(text), c.annotations, c.meta)


def _resource_contents(
    scope: OutputScope, res: TextResourceContents | BlobResourceContents, report: dict
) -> TextResourceContents | BlobResourceContents:
    uri = str(scope.apply({"uri": res.uri})[0].get("uri", res.uri)) if scope else res.uri
    if isinstance(res, BlobResourceContents):
        return BlobResourceContents(uri, res.blob, res.mime_type, res.meta)
    rendered = _render_data(scope, res.meta)
    if rendered is not None:
        text, meta, r = rendered
    else:
        text, r = scope.apply(res.text)
        meta = res.meta
    merge_report(report, r)
    return TextResourceContents(uri, str(text), res.mime_type, meta)


def _embedded(scope: OutputScope, c: EmbeddedResource, report: dict) -> EmbeddedResource:
    return EmbeddedResource(_resource_contents(scope, c.resource, report), c.annotations, c.meta)


def _content_block(scope: OutputScope, c: Any, report: dict, context: Any) -> Any:
    if isinstance(c, TextContent):
        return _text_content(scope, c, report)
    if isinstance(c, ResourceLink):
        return transform_links(scope, [c], context)[0]
    if isinstance(c, EmbeddedResource):
        return _embedded(scope, c, report)
    return c


# ---------------------------------------------------------------------------
# Tools, resources, prompts
# ---------------------------------------------------------------------------


def _shape_tool_object(scope: OutputScope, result: ToolResult) -> tuple[Any, dict]:
    """Transform a handler-built :class:`ToolResult` in place; returns the
    link context (its structured payload or texts) and the report."""
    report: dict[str, Any] = {}
    context = result.structured
    if result.structured is not None:
        result.structured, report = scope.apply(result.structured)
    if context is None:
        context = [c.text for c in result.content if isinstance(c, TextContent)]
    result.content = [_content_block(scope, c, report, context) for c in result.content]
    if result.meta:
        result.meta, r = scope.apply(result.meta)
        merge_report(report, r)
    return context, report


def shape_tool_result(
    scope: OutputScope, raw: Any, links: list[ResourceLink], max_chars: int
) -> tuple[ToolResult, dict[str, Any]]:
    """Normalise a tool handler's return value into a transformed
    :class:`ToolResult` and the transform report."""
    if isinstance(raw, ToolResult):
        result = raw
        context, report = _shape_tool_object(scope, result)
    else:
        data = jsonable(raw)
        context = data if isinstance(data, dict) else {"result": data}
        structured, report = scope.apply(context)
        text = render_json(structured)
        if len(text) > max_chars:
            report["truncated_chars"] = len(text) - max_chars
            text = text[:max_chars] + _TRUNCATED_NOTE
        result = ToolResult(content=[TextContent(text)], structured=structured)
    result.content.extend(transform_links(scope, links, context))
    return result, report


def shape_resource(
    scope: OutputScope, raw: Any, uri: str, mime: str | None
) -> list[TextResourceContents | BlobResourceContents]:
    """Normalise a resource handler's return value into transformed contents."""
    if (
        isinstance(raw, list)
        and raw
        and all(isinstance(x, (TextResourceContents, BlobResourceContents)) for x in raw)
    ):
        report: dict[str, Any] = {}
        return [_resource_item(scope, item, report) for item in raw]
    if isinstance(raw, bytes):
        return [BlobResourceContents(uri, base64.b64encode(raw).decode(), mime)]
    if isinstance(raw, str):
        text, report = scope.apply(raw)
        meta = {f"{META_PREFIX}transforms": report} if report else None
        return [TextResourceContents(uri, str(text), mime, meta)]
    data, report = scope.apply(jsonable(raw))
    meta = {f"{META_PREFIX}transforms": report} if report else None
    return [TextResourceContents(uri, render_json(data), mime or "application/json", meta)]


def _resource_item(
    scope: OutputScope, item: TextResourceContents | BlobResourceContents, report: dict
) -> TextResourceContents | BlobResourceContents:
    # Contents a handler built itself keep their own URI (the handler chose
    # it from the request); only the text / structured payload is shaped.
    if isinstance(item, BlobResourceContents):
        return item
    rendered = _render_data(scope, item.meta)
    if rendered is not None:
        text, meta, r = rendered
        merge_report(report, r)
        return TextResourceContents(item.uri, text, item.mime_type, meta)
    text, _ = scope.apply(item.text)
    return TextResourceContents(item.uri, str(text), item.mime_type, item.meta)


def shape_prompt(scope: OutputScope, raw: Any, description: str | None) -> PromptResult:
    """Normalise a prompt handler's return value into a transformed result."""
    if isinstance(raw, PromptResult):
        result = raw
    elif isinstance(raw, str):
        result = PromptResult([PromptMessage("user", TextContent(raw))], description)
    else:
        result = PromptResult(list(raw), description)
    report: dict[str, Any] = {}
    texts = [m.content.text for m in result.messages if isinstance(m.content, TextContent)]
    for m in result.messages:
        m.content = _content_block(scope, m.content, report, texts)
    return result
