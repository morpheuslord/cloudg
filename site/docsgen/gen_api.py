"""Python API reference data, read from the live objects with ``inspect``."""

from __future__ import annotations

import dataclasses
import enum
import importlib
import inspect
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

_SECTION_RE = re.compile(
    r"^(Args|Arguments|Parameters|Params|Returns|Return|Yields|Raises|Example|Examples|Note|Notes|Attributes|Usage)\s*:\s*$"
)


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


def parse_docstring(text: str | None) -> Doc:
    doc = Doc()
    if not text:
        return doc
    text = rst_to_md(inspect.cleandoc(text))
    sections: dict[str, list[str]] = {"": []}
    current = ""
    for line in text.split("\n"):
        m = _SECTION_RE.match(line.strip()) if not line.startswith(" ") else None
        if m:
            current = m.group(1).lower()
            sections.setdefault(current, [])
            continue
        sections.setdefault(current, []).append(line)

    main = "\n".join(sections.pop("", [])).strip()
    paras = re.split(r"\n\s*\n", main, maxsplit=1)
    doc.summary = " ".join(paras[0].split())
    doc.body = paras[1].strip() if len(paras) > 1 else ""

    def items(lines: list[str]) -> list[tuple[str, str]]:
        out: list[tuple[str, str]] = []
        lines = inspect.cleandoc("\n".join(lines)).split("\n") if lines else []
        for line in lines:
            if not line.strip():
                continue
            m = re.match(r"^(\*{0,2}[\w.\[\], |]+?)\s*(\([^)]*\))?\s*:\s*(.*)$", line) if not line.startswith(" ") else None
            if m:
                out.append((m.group(1).strip("* "), m.group(3).strip()))
            elif out:
                out[-1] = (out[-1][0], (out[-1][1] + " " + line.strip()).strip())
        return out

    for key in ("args", "arguments", "parameters", "params"):
        if key in sections:
            doc.params.update(dict(items(sections.pop(key))))
    for key in ("returns", "return", "yields"):
        if key in sections:
            doc.returns = " ".join(" ".join(sections.pop(key)).split())
    if "raises" in sections:
        doc.raises = items(sections.pop("raises"))
    if "attributes" in sections:
        doc.attributes = dict(items(sections.pop("attributes")))
    for key in ("example", "examples", "usage"):
        if key in sections:
            doc.examples = inspect.cleandoc("\n".join(sections.pop(key)))
    notes = []
    for key in ("note", "notes"):
        if key in sections:
            notes.append(inspect.cleandoc("\n".join(sections.pop(key))))
    doc.notes = "\n\n".join(notes)
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


def format_signature(name: str, params: list[Param], returns: str, width: int = 88) -> str:
    pieces = []
    seen_kwonly = False
    for p in params:
        if p.kind == "KEYWORD_ONLY" and not seen_kwonly and not any(q.name.startswith("*") and not q.name.startswith("**") for q in params):
            pieces.append("*")
        if p.kind == "KEYWORD_ONLY":
            seen_kwonly = True
        s = p.name
        if p.type:
            s += f": {p.type}"
        if p.default:
            s += f" = {p.default}" if p.type else f"={p.default}"
        pieces.append(s)
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


def load(path: str, repo: Path, members: list[str] | None = None) -> ApiObject:
    module_name, _, attr = path.rpartition(".")
    try:
        module = importlib.import_module(path)
        obj, module_name, attr = module, path, path.rsplit(".", 1)[-1]
    except ImportError:
        module = importlib.import_module(module_name)
        obj = getattr(module, attr)
    real_module = getattr(obj, "__module__", module_name) or module_name
    file, line = _source(obj, repo)
    doc = parse_docstring(inspect.getdoc(obj) if not inspect.ismodule(obj) else obj.__doc__)

    if inspect.ismodule(obj):
        return ApiObject(path, attr, module_name, "module", path, doc, [], "", source_file=file, source_line=1)

    if inspect.isclass(obj):
        if issubclass(obj, enum.Enum):
            kind = "enum"
        elif _is_pydantic(obj):
            kind = "model"
        elif dataclasses.is_dataclass(obj):
            kind = "dataclass"
        else:
            kind = "class"
        init_sig = None
        if kind in ("class", "dataclass"):
            init_sig = _signature(obj)
        init_doc = parse_docstring(inspect.getdoc(obj.__init__)) if "__init__" in vars(obj) else Doc()
        merged = Doc(**{**doc.__dict__, "params": {**init_doc.params, **doc.params}})
        params = _params(init_sig, merged, skip_self=False) if init_sig else []
        signature = format_signature(obj.__name__, params, "") if kind in ("class", "dataclass") else obj.__name__
        bases = [b.__name__ for b in obj.__bases__ if b is not object]
        api = ApiObject(path, obj.__name__, real_module, kind, signature, merged, params, "", bases=bases,
                        source_file=file, source_line=line)
        if kind == "enum":
            api.enum_values = [(m.name, repr(m.value)) for m in obj]
        if kind == "model":
            for fname, finfo in obj.model_fields.items():
                ann = _ann(finfo.annotation)
                if finfo.is_required():
                    default = "required"
                elif finfo.default_factory is not None:
                    name = getattr(finfo.default_factory, "__name__", "")
                    default = f"{name}()" if name and name != "<lambda>" else "generated"
                else:
                    default = _default(finfo.default)
                desc = finfo.description or doc.attributes.get(fname, "")
                api.fields.append(Param(fname, ann, default, desc))
        elif kind == "dataclass":
            for f in dataclasses.fields(obj):
                if f.default is not dataclasses.MISSING:
                    default = _default(f.default)
                elif f.default_factory is not dataclasses.MISSING:  # type: ignore[misc]
                    name = getattr(f.default_factory, "__name__", "")
                    default = f"{name}()" if name and name != "<lambda>" else "generated"
                else:
                    default = "required"
                api.fields.append(Param(f.name, _ann(f.type), default, doc.attributes.get(f.name, "")))
        names = members if members is not None else _public_members(obj)
        if kind == "enum" and members is None:
            names = []
        for name in names:
            m = _member(obj, name, repo)
            if m is not None:
                api.members.append(m)
        return api

    # function
    sig = _signature(obj)
    params = _params(sig, doc, skip_self=False)
    returns = _ann(sig.return_annotation) if sig else ""
    kind = "async" if inspect.iscoroutinefunction(obj) else "function"
    signature = format_signature(attr, params, returns)
    return ApiObject(path, attr, real_module, kind, signature, doc, params, returns, source_file=file, source_line=line)
