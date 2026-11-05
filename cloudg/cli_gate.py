"""`cloudg gate`: fail a CI job on findings at or above a severity."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

import click
from rich.markup import escape

from cloudg import ui
from cloudg.gate import EXIT_GATE_FAILED, THRESHOLD_CHOICES, GateResult, evaluate_gate

_CONSOLE_TOP = 25


def _resolve_input(path: Path) -> Path:
    """``path``, or the findings.json inside it when it is a directory."""
    return path / "findings.json" if path.is_dir() else path


def _load(ctx: click.Context, input_path: Path) -> Any:
    from cloudg.cli_helpers import _load_report_input

    cfg = ctx.obj
    rules_dir = cfg.rulesets.rules_dir if cfg is not None else None
    if not input_path.exists():
        ui.error_panel("Input file not found", input_path)
        sys.exit(1)
    try:
        scan_result, _graph = _load_report_input(input_path, rules_dir=rules_dir)
    except (OSError, ValueError) as exc:
        ui.error_panel("Could not read the input", exc)
        sys.exit(1)
    return scan_result


def _show(gate: GateResult) -> None:
    ui.stats_table("Findings by severity", gate.counts)
    rows = [
        [f.title, f.severity.value, f.source_tool, f.resource_arn or f.resource_id]
        for f in gate.blocking[:_CONSOLE_TOP]
    ]
    if rows:
        ui.ranked_table("Blocking findings", ["Finding", "Severity", "Tool", "Resource"], rows)
    if gate.passed:
        ui.success(f"Gate passed (fail on {gate.fail_on}, {len(gate.blocking)} blocking)")
    else:
        ui.fail(f"Gate failed: {escape(gate.reason)}")


def _write_extras(
    scan_result: Any, gate: GateResult, sarif: str | None, summary: str | None
) -> None:
    if sarif:
        from cloudg.renderers.sarif import write_sarif

        ui.artifact("SARIF", write_sarif(scan_result, sarif))
    if summary:
        from cloudg.gate import summary_markdown

        with open(summary, "a", encoding="utf-8") as fh:
            fh.write(summary_markdown(gate))
        ui.artifact("Summary", summary)


@click.command()
@click.option(
    "-i",
    "--input",
    "input_file",
    default="./reports",
    show_default=True,
    help="findings.json (or the directory holding it) from `cloudg run` or `cloudg ingest`, "
    "or a raw-findings.json",
)
@click.option(
    "--fail-on",
    type=click.Choice(THRESHOLD_CHOICES, case_sensitive=False),
    default="high",
    show_default=True,
    help="Lowest severity that fails the gate; `never` only reports",
)
@click.option(
    "--max",
    "max_blocking",
    type=click.IntRange(min=0),
    default=0,
    show_default=True,
    help="Blocking findings tolerated before the gate fails",
)
@click.option(
    "--min-assets",
    type=click.IntRange(min=0),
    default=0,
    show_default=True,
    help="Fail when fewer assets were collected (catches runs whose credentials did not work)",
)
@click.option("--sarif", default=None, help="Also write the findings as SARIF 2.1.0 to this file")
@click.option(
    "--summary",
    default=None,
    help="Append a Markdown summary to this file (for example $GITHUB_STEP_SUMMARY)",
)
@click.option("--json", "as_json", is_flag=True, help="Print the verdict as JSON on stdout")
@click.pass_context
def gate(
    ctx: click.Context,
    input_file: str,
    fail_on: str,
    max_blocking: int,
    min_assets: int,
    sarif: str | None,
    summary: str | None,
    as_json: bool,
) -> None:
    """Fail a CI job on findings at or above a severity.

    Reads a findings.json, counts the findings at --fail-on or above
    (suppressed findings never count), and exits with status 4 when there
    are more than --max of them or fewer assets than --min-assets. Status 1
    means the input is missing or unreadable.

    \b
        cloudg gate -i reports --fail-on high
        cloudg gate -i reports --fail-on critical --min-assets 1 --sarif reports/cloudg.sarif
    """
    ui.section("Security Gate")
    input_path = _resolve_input(Path(input_file))
    scan_result = _load(ctx, input_path)
    verdict = evaluate_gate(scan_result, fail_on, max_blocking, min_assets)

    _show(verdict)
    _write_extras(scan_result, verdict, sarif, summary)
    if as_json:
        click.echo(json.dumps(verdict.to_dict(), indent=2))
    if not verdict.passed:
        ctx.exit(EXIT_GATE_FAILED)
