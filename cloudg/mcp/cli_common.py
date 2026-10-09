"""Options and helpers shared by the ``cloudg mcp`` commands
(:mod:`cloudg.mcp.cli`): layer-shaping options, ``--registry`` loading,
principal options and output helpers."""

from __future__ import annotations

import json
import re
import sys
from typing import Any, Callable

import click

from cloudg.mcp.context import Principal

AUTH_TOKENS_ENV = "CLOUDG_MCP_AUTH_TOKENS"


# ---------------------------------------------------------------------------
# Shared options
# ---------------------------------------------------------------------------


def _layer_options(fn: Callable[..., Any]) -> Callable[..., Any]:
    """Options that shape the layer (shared by every command)."""
    options = [
        click.option(
            "-c",
            "--config",
            "config_path",
            default=None,
            help="cloudg config.yaml (defaults to the parent command's config).",
        ),
        click.option(
            "--policy",
            default=None,
            envvar="CLOUDG_MCP_POLICY",
            show_envvar=True,
            help="Policy profile name, or a YAML/JSON policy file.",
        ),
        click.option(
            "--dataset",
            "datasets",
            multiple=True,
            metavar="[NAME=]PATH",
            help="Preload a dataset (findings.json, inventory-map.json...). Repeatable.",
        ),
        click.option("--prefix", default="", help="Prefix for tool and prompt names."),
        click.option(
            "--include-category",
            "include_categories",
            multiple=True,
            help="Only expose these categories. Repeatable.",
        ),
        click.option(
            "--exclude-category",
            "exclude_categories",
            multiple=True,
            help="Hide these categories. Repeatable.",
        ),
        click.option(
            "--include-tool",
            "include_tools",
            multiple=True,
            help="Only expose these tools. Repeatable.",
        ),
        click.option(
            "--exclude-tool", "exclude_tools", multiple=True, help="Hide these tools. Repeatable."
        ),
        click.option(
            "--read-only",
            is_flag=True,
            help="Drop tools that write files, call cloud APIs, run scanners or are destructive.",
        ),
        click.option(
            "--audit-log",
            type=click.Path(dir_okay=False),
            default=None,
            envvar="CLOUDG_MCP_AUDIT_LOG",
            show_envvar=True,
            help="Append a JSONL audit trail (argument values are hashed).",
        ),
        click.option(
            "--timeout",
            type=float,
            default=300.0,
            show_default=True,
            help="Per-call timeout in seconds.",
        ),
        click.option(
            "--registry",
            "registry_ref",
            default=None,
            metavar="MODULE:ATTR",
            help="Serve a custom Registry (or a zero-argument factory returning one) "
            "instead of the built-in catalog.",
        ),
    ]
    for option in reversed(options):
        fn = option(fn)
    return fn


def _parent_config(ctx: click.Context) -> Any:
    root = ctx.find_root()
    obj = getattr(root, "obj", None)
    try:
        from cloudg.config import CloudGConfig

        return obj if isinstance(obj, CloudGConfig) else None
    except Exception:  # pragma: no cover
        return None


_DOTTED_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*")


def _parse_registry_ref(ref: str) -> tuple[str, list[str]]:
    """Split ``MODULE[:ATTR]`` after checking both are dotted Python
    identifiers (no relative imports, paths or expressions)."""
    module_name, _, attr = ref.partition(":")
    attr = attr or "default_registry"
    for part in (module_name, attr):
        if not _DOTTED_NAME.fullmatch(part):
            raise click.BadParameter(
                f"{ref!r} is not MODULE:ATTR with dotted Python names", param_hint="--registry"
            )
    if any(name.startswith("_") for name in attr.split(".")):
        raise click.BadParameter(
            f"{ref!r}: the attribute must be a public name", param_hint="--registry"
        )
    return module_name, attr.split(".")


def _load_registry(ref: str | None) -> Any:
    """Load ``--registry MODULE:ATTR``: a :class:`~cloudg.mcp.core.Registry`
    or a zero-argument factory returning one.

    This imports and runs operator code, exactly like ``python -m MODULE``
    would: the value comes from the command line or config of whoever starts
    the server, never from an MCP client. It is validated as a plain dotted
    module name and a public attribute path before anything is imported.
    """
    if not ref:
        return None
    import importlib

    from cloudg.mcp.core import Registry

    module_name, attrs = _parse_registry_ref(ref)
    try:
        # trusted operator input, validated by _parse_registry_ref above
        obj: Any = importlib.import_module(module_name)  # nosemgrep
        for part in attrs:
            obj = getattr(obj, part)
    except (ImportError, AttributeError) as exc:
        raise click.BadParameter(f"cannot import {ref!r}: {exc}", param_hint="--registry") from exc
    if not isinstance(obj, Registry) and callable(obj):
        obj = obj()
    if not isinstance(obj, Registry):
        raise click.BadParameter(
            f"{ref!r} is not a cloudg.mcp.core.Registry (or a factory returning one)",
            param_hint="--registry",
        )
    return obj


def _build_layer(ctx: click.Context, opts: dict[str, Any], **extra: Any) -> Any:
    from cloudg.mcp.server import create_layer_from_options

    registry = _load_registry(opts.get("registry_ref"))
    try:
        return create_layer_from_options(
            config=None if opts.get("config_path") else _parent_config(ctx),
            config_path=opts.get("config_path"),
            policy=opts.get("policy"),
            datasets=opts.get("datasets") or (),
            prefix=opts.get("prefix") or "",
            include_categories=opts.get("include_categories") or None,
            exclude_categories=opts.get("exclude_categories") or None,
            include_tools=opts.get("include_tools") or None,
            exclude_tools=opts.get("exclude_tools") or None,
            read_only=bool(opts.get("read_only")),
            audit_log=opts.get("audit_log"),
            default_timeout=opts.get("timeout"),
            registry=registry,
            **extra,
        )
    except (FileNotFoundError, ValueError) as exc:
        raise click.ClickException(str(exc)) from exc


def _principal(roles: tuple[str, ...], principal_id: str | None) -> Principal:
    if not roles and not principal_id:
        return Principal.local()
    return Principal(id=principal_id or "cli", roles=set(roles) or {"default"})


def _principal_options(fn: Callable[..., Any]) -> Callable[..., Any]:
    fn = click.option(
        "--role",
        "roles",
        multiple=True,
        help="Call as a principal with this role (repeatable; default: the local user).",
    )(fn)
    fn = click.option("--principal-id", default=None, help="Principal id to call as.")(fn)
    return fn


def _stdout_console() -> Any:
    from rich.console import Console

    try:
        tty = sys.stdout.isatty()
    except (AttributeError, ValueError):
        tty = False
    # piped / captured output: wide enough that URIs and names are not folded
    return Console(file=sys.stdout, soft_wrap=False, width=None if tty else 160)


def _setup_cli_logging(verbose: bool = False) -> None:
    from cloudg.mcp.server import _ensure_stderr_logging

    _ensure_stderr_logging("DEBUG" if verbose else "WARNING")


def _echo_json(data: Any) -> None:
    click.echo(json.dumps(data, indent=2, ensure_ascii=False, default=str))


def _first_line(text: str | None, width: int = 90) -> str:
    line = (text or "").strip().splitlines()[0] if (text or "").strip() else ""
    return line if len(line) <= width else line[: width - 1] + "…"
