"""CLI reference data, read from the click command tree in ``cloudg.cli``."""

from __future__ import annotations

import inspect
from dataclasses import dataclass, field
from pathlib import Path

import click


@dataclass
class Option:
    flags: str
    value: str
    default: str
    help: str
    required: bool = False
    multiple: bool = False
    envvar: str = ""
    is_argument: bool = False
    anchor: str = ""


@dataclass
class Command:
    path: str  # "map", "mcp serve"
    help: str
    short_help: str
    usage: str
    options: list[Option] = field(default_factory=list)
    source_file: str = ""
    source_line: int = 0
    group: bool = False


def _is_unset(value) -> bool:
    return (
        value is None
        or type(value).__name__ in ("Sentinel", "_Missing")
        or repr(value).startswith("Sentinel.")
    )


def _value_of(param: click.Parameter) -> str:
    t = param.type
    if isinstance(param, click.Option) and param.is_flag:
        return "flag"
    if isinstance(t, click.Choice):
        return "|".join(str(c) for c in t.choices)
    if getattr(param, "metavar", None):
        return param.metavar
    name = getattr(t, "name", "text")
    return {
        "text": "TEXT",
        "integer": "INT",
        "float": "FLOAT",
        "boolean": "BOOL",
        "file": "FILE",
        "path": "PATH",
        "filename": "FILE",
    }.get(name, name.upper())


def _flag_default(param: click.Option) -> str:
    default = param.default
    if not param.secondary_opts:
        return "on" if default is True else "off"
    if _is_unset(default):
        return "config"
    return param.opts[0] if default else param.secondary_opts[0]


def _default_of(param: click.Parameter) -> str:
    default = param.default
    if isinstance(param, click.Option) and param.is_flag:
        return _flag_default(param)
    if _is_unset(default):
        return "none"
    if isinstance(default, (tuple, list)):
        return ", ".join(str(d) for d in default) if default else "none"
    return str(default)


def _flags_of(param: click.Parameter) -> str:
    if isinstance(param, click.Argument):
        return param.human_readable_name
    opts = sorted(param.opts, key=lambda o: (o.startswith("--"), o))
    flags = ", ".join(opts)
    if getattr(param, "secondary_opts", None):
        flags += " / " + ", ".join(param.secondary_opts)
    return flags


def _usage(path: str, cmd: click.Command) -> str:
    parts = [f"cloudg {path}"]
    optional = False
    for p in cmd.params:
        if isinstance(p, click.Argument):
            continue
        if getattr(p, "hidden", False):
            continue
        if p.required:
            parts.append(f"{min(p.opts, key=len)} {(p.name or 'value').upper()}")
        else:
            optional = True
    if optional:
        parts.append("[OPTIONS]")
    for p in cmd.params:
        if isinstance(p, click.Argument):
            name = p.human_readable_name
            parts.append(name if p.required else f"[{name}]")
    return " ".join(parts)


def _source(cmd: click.Command) -> tuple[str, int]:
    fn = cmd.callback
    while fn is not None and hasattr(fn, "__wrapped__"):
        fn = fn.__wrapped__
    try:
        file = inspect.getsourcefile(fn)
        line = inspect.getsourcelines(fn)[1]
    except (TypeError, OSError):
        return "", 0
    return file or "", line


def _option(p: click.Parameter) -> Option:
    is_argument = isinstance(p, click.Argument)
    envvar = getattr(p, "envvar", None)
    anchor = p.opts[0] if is_argument else max(p.opts, key=len)
    return Option(
        flags=_flags_of(p),
        value=_value_of(p),
        default=_default_of(p),
        help=" ".join((getattr(p, "help", "") or "").split()),
        required=bool(p.required),
        multiple=bool(getattr(p, "multiple", False)),
        envvar=envvar if isinstance(envvar, str) else "",
        is_argument=is_argument,
        anchor=anchor.lstrip("-"),
    )


def _repo_source(cmd: click.Command, repo: Path) -> tuple[str, int]:
    """Source file of the command callback relative to ``repo``, and its line."""
    file, line = _source(cmd) if cmd.callback else ("", 0)
    if not file:
        return "", line
    try:
        return str(Path(file).resolve().relative_to(repo.resolve())), line
    except ValueError:
        return file, line


def _command(cmd: click.Command, path: str, repo: Path) -> Command:
    file, line = _repo_source(cmd, repo)
    return Command(
        path=path,
        help=inspect.cleandoc(cmd.help or ""),
        short_help=cmd.get_short_help_str(limit=200),
        usage=_usage(path, cmd),
        options=[_option(p) for p in cmd.params if not getattr(p, "hidden", False)],
        source_file=file,
        source_line=line,
        group=isinstance(cmd, click.Group),
    )


def _walk(cmd: click.Command, path: str, repo: Path, out: dict[str, Command]) -> None:
    if path:
        out[path] = _command(cmd, path, repo)
    if isinstance(cmd, click.Group):
        for name, sub in cmd.commands.items():
            _walk(sub, f"{path} {name}".strip(), repo, out)


def collect(repo: Path) -> dict[str, Command]:
    from cloudg.cli import cli

    out: dict[str, Command] = {}
    _walk(cli, "", repo, out)
    root_help = inspect.cleandoc(cli.help or "")
    out["__root__"] = Command(
        path="",
        help=root_help,
        short_help="",
        usage="cloudg [OPTIONS] COMMAND [ARGS]...",
        options=[
            Option(
                flags=_flags_of(p),
                value=_value_of(p),
                default=_default_of(p),
                help=" ".join((p.help or "").split()),
            )
            for p in cli.params
            if isinstance(p, click.Option)
        ],
    )
    return out
