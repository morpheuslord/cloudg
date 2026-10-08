"""JSON Schema generation and argument validation from handler signatures.

Handlers are plain Python functions whose first parameter is the
:class:`~cloudg.mcp.context.ToolContext` (named ``ctx``). The remaining
parameters become the tool's ``inputSchema``; describe them with
``typing.Annotated[..., pydantic.Field(description=...)]`` or plain
defaults::

    def find_assets(
        ctx,
        query: Annotated[str, Field(description="Substring match on name/ARN")] = "",
        limit: Annotated[int, Field(ge=1, le=500)] = 50,
    ) -> dict: ...
"""

from __future__ import annotations

import inspect
import typing
from typing import Any, Callable

from pydantic import BaseModel, ConfigDict, ValidationError, create_model

from cloudg.mcp.core import InvalidArgumentsError

_CTX_NAMES = {"ctx", "context"}
_MODEL_ATTR = "__cloudg_mcp_args_model__"


def _arguments_model(fn: Callable[..., Any]) -> type[BaseModel]:
    cached = getattr(fn, _MODEL_ATTR, None)
    if cached is not None:
        return cached

    sig = inspect.signature(fn)
    try:
        hints = typing.get_type_hints(fn, include_extras=True)
    except Exception:  # unresolved forward refs: fall back to Any
        hints = {}

    fields: dict[str, Any] = {}
    params = list(sig.parameters.values())
    if params and params[0].name in _CTX_NAMES:
        params = params[1:]
    for p in params:
        if p.kind in (p.VAR_POSITIONAL, p.VAR_KEYWORD):
            continue
        annotation = hints.get(p.name, Any)
        default = ... if p.default is inspect.Parameter.empty else p.default
        fields[p.name] = (annotation, default)

    model = create_model(  # type: ignore[call-overload]
        f"{fn.__name__}_arguments",
        __config__=ConfigDict(extra="forbid", arbitrary_types_allowed=True),
        **fields,
    )
    try:
        setattr(fn, _MODEL_ATTR, model)
    except (AttributeError, TypeError):  # builtins / bound methods
        pass
    return model


def _strip_titles(node: Any) -> Any:
    """Drop pydantic's auto-generated ``title`` keys; they add noise to
    the schema an LLM reads without telling it anything."""
    if isinstance(node, dict):
        return {
            k: _strip_titles(v)
            for k, v in node.items()
            if not (k == "title" and isinstance(v, str))
        }
    if isinstance(node, list):
        return [_strip_titles(v) for v in node]
    return node


def _inline_refs(schema: dict[str, Any]) -> dict[str, Any]:
    """Resolve local ``$ref``s into ``$defs`` inline; several MCP clients
    do not follow references. Recursive models keep their ``$ref``."""
    defs = schema.get("$defs", {})
    if not defs:
        return schema

    def resolve(node: Any, seen: frozenset[str]) -> Any:
        if isinstance(node, dict):
            ref = node.get("$ref")
            if isinstance(ref, str) and ref.startswith("#/$defs/"):
                key = ref.split("/")[-1]
                if key in defs and key not in seen:
                    merged = {**defs[key], **{k: v for k, v in node.items() if k != "$ref"}}
                    return resolve(merged, seen | {key})
                return node
            return {k: resolve(v, seen) for k, v in node.items() if k != "$defs"}
        if isinstance(node, list):
            return [resolve(v, seen) for v in node]
        return node

    out = resolve(schema, frozenset())
    if "$ref" in json_dumps(out):
        out["$defs"] = defs  # recursive model: keep the definitions
    return out


def json_dumps(value: Any) -> str:
    import json

    return json.dumps(value, default=str)


def input_schema_for(fn: Callable[..., Any]) -> dict[str, Any]:
    """JSON Schema (draft 2020-12 object) for ``fn``'s arguments."""
    schema = _arguments_model(fn).model_json_schema()
    schema = _inline_refs(_strip_titles(schema))
    schema.setdefault("type", "object")
    schema.setdefault("properties", {})
    schema["additionalProperties"] = False
    return schema


def validate_arguments(fn: Callable[..., Any], arguments: dict[str, Any] | None) -> dict[str, Any]:
    """Validate and coerce ``arguments`` against ``fn``'s signature.

    Raises:
        InvalidArgumentsError: with pydantic's error list as ``data``.
    """
    model = _arguments_model(fn)
    try:
        parsed = model.model_validate(arguments or {})
    except ValidationError as exc:
        errors = [
            {"loc": ".".join(str(x) for x in e["loc"]), "msg": e["msg"], "type": e["type"]}
            for e in exc.errors()
        ]
        summary = "; ".join(f"{e['loc'] or '<root>'}: {e['msg']}" for e in errors)
        raise InvalidArgumentsError(f"Invalid arguments: {summary}", data=errors) from None
    return {name: getattr(parsed, name) for name in model.model_fields}


def output_schema_for(model: type[BaseModel]) -> dict[str, Any]:
    """``outputSchema`` for a tool whose structured result is ``model``."""
    return _inline_refs(_strip_titles(model.model_json_schema()))
