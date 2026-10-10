"""Python API reference data, read from the live objects with ``inspect``."""

from __future__ import annotations

import dataclasses
import enum
import inspect
import pkgutil
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

_SECTION_RE = re.compile(
    r"^(Args|Arguments|Parameters|Params|Returns|Return|Yields|Raises|Example|Examples"
    r"|Note|Notes|Attributes|Usage)\s*:\s*$"
)
_ITEM_RE = re.compile(r"^(\*{0,2}[\w.\[\], |]+?)\s*(\([^)]*\))?\s*:\s*(.*)$")
# objects documented on the API pages: dotted identifiers inside the cloudg package
_API_PATH_RE = re.compile(r"^cloudg(?:\.[A-Za-z_][A-Za-z0-9_]*)+$")


@dataclass
class Param:
    name: str
    type: str
    default: str
    description: str = ""
    kind: str = ""


@dataclass
class Doc:
    summary: str = ""
    body: str = ""
    params: dict[str, str] = field(default_factory=dict)
    returns: str = ""
    raises: list[tuple[str, str]] = field(default_factory=list)
    examples: str = ""
    attributes: dict[str, str] = field(default_factory=dict)
    notes: str = ""


@dataclass
class Member:
    name: str
    kind: str  # method, async, property, classmethod, staticmethod, attribute
    signature: str
    returns: str
    doc: Doc
    params: list[Param]
    source_line: int = 0


@dataclass
class ApiObject:
    path: str
    name: str
    module: str
    kind: str  # class, function, module, enum, model, dataclass
    signature: str
    doc: Doc
    params: list[Param]
    returns: str
    members: list[Member] = field(default_factory=list)
    fields: list[Param] = field(default_factory=list)
    enum_values: list[tuple[str, str]] = field(default_factory=list)
    bases: list[str] = field(default_factory=list)
    source_file: str = ""
    source_line: int = 0


def rst_to_md(text: str) -> str:
    """Turn the reST bits docstrings use (``:func:`x```, double backticks) into markdown."""
    text = re.sub(r":[\w]+(?::[\w]+)?:`~?\.?([^`]+)`", r"`\1`", text)
    return re.sub(r"``([^`]+)``", r"`\1`", text)


def _split_sections(text: str) -> dict[str, list[str]]:
    """Group docstring lines under their Google-style section header ("" for the top)."""
    sections: dict[str, list[str]] = {"": []}
    current = ""
    for line in text.split("\n"):
        m = _SECTION_RE.match(line.strip()) if not line.startswith(" ") else None
        if m:
            current = m.group(1).lower()
            sections.setdefault(current, [])
            continue
        sections.setdefault(current, []).append(line)
    return sections


def _items(lines: list[str]) -> list[tuple[str, str]]:
    """``name (type): text`` entries, with continuation lines folded in."""
    out: list[tuple[str, str]] = []
    lines = inspect.cleandoc("\n".join(lines)).split("\n") if lines else []
    for line in lines:
        if not line.strip():
            continue
        m = _ITEM_RE.match(line) if not line.startswith(" ") else None
        if m:
            out.append((m.group(1).strip("* "), m.group(3).strip()))
        elif out:
            out[-1] = (out[-1][0], (out[-1][1] + " " + line.strip()).strip())
    return out


def _take(sections: dict[str, list[str]], keys: tuple[str, ...]) -> list[list[str]]:
    """Remove and return the sections named in ``keys``, in that order."""
    return [sections.pop(key) for key in keys if key in sections]


def _block(lines: list[str]) -> str:
    return inspect.cleandoc("\n".join(lines))


def parse_docstring(text: str | None) -> Doc:
    doc = Doc()
    if not text:
        return doc
    sections = _split_sections(rst_to_md(inspect.cleandoc(text)))
    main = "\n".join(sections.pop("", [])).strip()
    paras = re.split(r"\n\s*\n", main, maxsplit=1)
    doc.summary = " ".join(paras[0].split())
    doc.body = paras[1].strip() if len(paras) > 1 else ""
    for lines in _take(sections, ("args", "arguments", "parameters", "params")):
        doc.params.update(dict(_items(lines)))
    for lines in _take(sections, ("returns", "return", "yields")):
        doc.returns = " ".join(" ".join(lines).split())
    for lines in _take(sections, ("raises",)):
        doc.raises = _items(lines)
    for lines in _take(sections, ("attributes",)):
        doc.attributes = dict(_items(lines))
    for lines in _take(sections, ("example", "examples", "usage")):
        doc.examples = _block(lines)
    doc.notes = "\n\n".join(_block(lines) for lines in _take(sections, ("note", "notes")))
    return doc


def _ann(a: Any) -> str:
    if a is inspect.Parameter.empty or a is inspect.Signature.empty:
        return ""
    if isinstance(a, str):
        return a.strip("'\"")
    if isinstance(a, type):
        return a.__name__ if a.__module__ == "builtins" else a.__name__
    s = repr(a)
    return re.sub(r"\b(?:[a-z_][\w]*\.)+([A-Z]\w*)", r"\1", s).replace("typing.", "")


def _default(d: Any) -> str:
    if d is inspect.Parameter.empty:
        return ""
    if isinstance(d, enum.Enum):
        return f"{type(d).__name__}.{d.name}"
    r = repr(d)
    return r if len(r) <= 60 else r[:57] + "..."


def _params(sig: inspect.Signature | None, doc: Doc, skip_self: bool) -> list[Param]:
    if sig is None:
        return []
    out = []
    for i, (name, p) in enumerate(sig.parameters.items()):
        if skip_self and i == 0 and name in ("self", "cls"):
            continue
        prefix = "*" if p.kind is p.VAR_POSITIONAL else "**" if p.kind is p.VAR_KEYWORD else ""
        desc = doc.params.get(name) or doc.params.get(prefix + name) or ""
        out.append(Param(prefix + name, _ann(p.annotation), _default(p.default), desc, p.kind.name))
    return out


def _param_text(p: Param) -> str:
    s = p.name
    if p.type:
        s += f": {p.type}"
    if p.default:
        s += f" = {p.default}" if p.type else f"={p.default}"
    return s


def _has_var_positional(params: list[Param]) -> bool:
    return any(q.name.startswith("*") and not q.name.startswith("**") for q in params)


def format_signature(name: str, params: list[Param], returns: str, width: int = 88) -> str:
    pieces = []
    # a *args parameter already marks where the keyword-only ones start
    star_written = _has_var_positional(params)
    for p in params:
        if p.kind == "KEYWORD_ONLY" and not star_written:
            pieces.append("*")
            star_written = True
        pieces.append(_param_text(p))
    ret = f" -> {returns}" if returns else ""
    one = f"{name}({', '.join(pieces)}){ret}"
    if len(one) <= width:
        return one
    return f"{name}(\n" + "".join(f"    {p},\n" for p in pieces) + f"){ret}"


def _signature(obj: Any) -> inspect.Signature | None:
    try:
        return inspect.signature(obj)
    except (TypeError, ValueError):
        return None


def _source(obj: Any, repo: Path) -> tuple[str, int]:
    try:
        target = inspect.unwrap(obj)
        file = inspect.getsourcefile(target) or ""
        line = inspect.getsourcelines(target)[1]
        return str(Path(file).resolve().relative_to(repo.resolve())), line
    except (TypeError, OSError, ValueError):
        return "", 0


def _is_pydantic(cls: type) -> bool:
    return hasattr(cls, "model_fields") and hasattr(cls, "model_validate")


def _member(cls: type, name: str, repo: Path) -> Member | None:
    raw = inspect.getattr_static(cls, name, None)
    if raw is None:
        return None
    kind = "method"
    target: Any = raw
    if isinstance(raw, property):
        kind, target = "property", raw.fget
    elif isinstance(raw, classmethod):
        kind, target = "classmethod", raw.__func__
    elif isinstance(raw, staticmethod):
        kind, target = "staticmethod", raw.__func__
    elif inspect.iscoroutinefunction(raw):
        kind = "async"
    elif not callable(raw):
        return Member(name, "attribute", name, _ann(type(raw)), Doc(), [])
    doc = parse_docstring(inspect.getdoc(target))
    sig = _signature(target)
    params = _params(sig, doc, skip_self=kind in ("method", "async", "classmethod", "property"))
    returns = _ann(sig.return_annotation) if sig else ""
    if kind == "property":
        signature, params = name, []
    else:
        signature = format_signature(name, params, returns)
    _, line = _source(target, repo)
    return Member(name, kind, signature, returns, doc, params, line)


def _public_members(cls: type) -> list[str]:
    names = []
    base_names: set[str] = set()
    for base in cls.__mro__[1:]:
        if base.__module__.startswith(("pydantic", "builtins", "enum", "typing", "abc")):
            base_names.update(vars(base))
    for name, value in vars(cls).items():
        if name.startswith("_") or name in base_names:
            continue
        if callable(value) or isinstance(value, (property, classmethod, staticmethod)):
            names.append(name)
    return names


def _resolve(path: str) -> tuple[Any, str, str]:
    """Return (object, module name, attribute name) for a dotted ``cloudg.`` path.

    Only paths inside the cloudg package are accepted: the names come from the
    front matter of the content pages.
    """
    if not _API_PATH_RE.match(path):
        raise ValueError(f"not a cloudg object path: {path!r}")
    obj = pkgutil.resolve_name(path)
    module_name, _, attr = path.rpartition(".")
    if inspect.ismodule(obj):
        module_name = path
    return obj, module_name, attr


def _class_kind(cls: type) -> str:
    if issubclass(cls, enum.Enum):
        return "enum"
    if _is_pydantic(cls):
        return "model"
    if dataclasses.is_dataclass(cls):
        return "dataclass"
    return "class"


def _factory_default(factory: Any) -> str:
    name = getattr(factory, "__name__", "")
    return f"{name}()" if name and name != "<lambda>" else "generated"


def _model_field_default(finfo: Any) -> str:
    if finfo.is_required():
        return "required"
    if finfo.default_factory is not None:
        return _factory_default(finfo.default_factory)
    return _default(finfo.default)


def _dataclass_field_default(f: dataclasses.Field) -> str:
    if f.default is not dataclasses.MISSING:
        return _default(f.default)
    if f.default_factory is not dataclasses.MISSING:  # type: ignore[misc]
        return _factory_default(f.default_factory)
    return "required"


def _model_fields(cls: type, doc: Doc) -> list[Param]:
    return [
        Param(
            fname,
            _ann(finfo.annotation),
            _model_field_default(finfo),
            finfo.description or doc.attributes.get(fname, ""),
        )
        for fname, finfo in cls.model_fields.items()
    ]


def _dataclass_fields(cls: type, doc: Doc) -> list[Param]:
    return [
        Param(f.name, _ann(f.type), _dataclass_field_default(f), doc.attributes.get(f.name, ""))
        for f in dataclasses.fields(cls)
    ]


def _enum_values(cls: type) -> list[tuple[str, str]]:
    return [(m.name, repr(m.value)) for m in cls]


def _member_names(cls: type, kind: str, members: list[str] | None) -> list[str]:
    if members is not None:
        return members
    return [] if kind == "enum" else _public_members(cls)


def _fill_class(api: ApiObject, cls: type, repo: Path, members: list[str] | None) -> None:
    kind = _class_kind(cls)
    init_doc = parse_docstring(inspect.getdoc(cls.__init__)) if "__init__" in vars(cls) else Doc()
    doc = api.doc
    api.doc = Doc(**{**doc.__dict__, "params": {**init_doc.params, **doc.params}})
    api.name, api.kind, api.signature = cls.__name__, kind, cls.__name__
    if kind in ("class", "dataclass"):
        init_sig = _signature(cls)
        api.params = _params(init_sig, api.doc, skip_self=False) if init_sig else []
        api.signature = format_signature(cls.__name__, api.params, "")
    api.bases = [b.__name__ for b in cls.__bases__ if b is not object]
    if kind == "enum":
        api.enum_values = _enum_values(cls)
    fields_of = {"model": _model_fields, "dataclass": _dataclass_fields}.get(kind)
    if fields_of:
        api.fields = fields_of(cls, doc)
    for name in _member_names(cls, kind, members):
        m = _member(cls, name, repo)
        if m is not None:
            api.members.append(m)


def _fill_function(api: ApiObject, fn: Any) -> None:
    sig = _signature(fn)
    api.params = _params(sig, api.doc, skip_self=False)
    api.returns = _ann(sig.return_annotation) if sig else ""
    api.kind = "async" if inspect.iscoroutinefunction(fn) else "function"
    api.signature = format_signature(api.name, api.params, api.returns)


def load(path: str, repo: Path, members: list[str] | None = None) -> ApiObject:
    obj, module_name, attr = _resolve(path)
    file, line = _source(obj, repo)
    if inspect.ismodule(obj):
        doc = parse_docstring(obj.__doc__)
        return ApiObject(
            path, attr, module_name, "module", path, doc, [], "", source_file=file, source_line=1
        )
    real_module = getattr(obj, "__module__", module_name) or module_name
    doc = parse_docstring(inspect.getdoc(obj))
    api = ApiObject(
        path, attr, real_module, "function", attr, doc, [], "", source_file=file, source_line=line
    )
    if inspect.isclass(obj):
        _fill_class(api, obj, repo, members)
    else:
        _fill_function(api, obj)
    return api
