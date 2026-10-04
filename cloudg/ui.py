"""cloudg.ui — Rich-based terminal UI layer for the CloudG CLI.

Centralises every visual concern — theme, banner, phase headers, status
lines, tables, panels and progress displays — so the command logic in
``cli.py`` stays free of formatting details and the whole CLI renders
with one consistent look.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from rich import box
from rich.console import Console, Group
from rich.markup import escape
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
from rich.rule import Rule
from rich.table import Table
from rich.text import Text
from rich.theme import Theme

THEME = Theme(
    {
        "banner": "bold cyan",
        "tagline": "grey58",
        "accent": "cyan",
        "success": "green",
        "warning": "yellow",
        "error": "bold red",
        "muted": "grey58",
        "path": "cyan",
        "metric": "bold",
        "sev.critical": "bold white on red",
        "sev.high": "bold red",
        "sev.medium": "yellow",
        "sev.low": "cyan",
        "sev.info": "grey58",
    }
)

console = Console(theme=THEME)

_BANNER = r"""
      _                 _
  ___| | ___  _   _  __| | __ _
 / __| |/ _ \| | | |/ _` |/ _` |
| (__| | (_) | |_| | (_| | (_| |
 \___|_|\___/ \__,_|\__,_|\__, |
                          |___/
""".strip("\n")

_SEVERITY_STYLES = {
    "CRITICAL": "sev.critical",
    "HIGH": "sev.high",
    "MEDIUM": "sev.medium",
    "LOW": "sev.low",
    "INFO": "sev.info",
    "INFORMATIONAL": "sev.info",
}


def severity_style(severity: str) -> str:
    """Return the theme style name for a severity label."""
    return _SEVERITY_STYLES.get(severity.upper(), "metric")


# ─────────────────────────────────────────────────────────────────────
# Banner & headers
# ─────────────────────────────────────────────────────────────────────


def print_banner(version: str) -> None:
    """Print the cloudg banner panel with version tag."""
    art = Text(_BANNER, style="banner")
    tagline = Text("cloud graphing — map, graph and audit AWS / Azure / GCP", style="tagline")
    console.print(
        Panel(
            Group(art, Text(), tagline),
            box=box.ROUNDED,
            border_style="accent",
            subtitle=f"[muted]v{version}[/]",
            subtitle_align="right",
            expand=False,
            padding=(0, 3),
        )
    )


def section(title: str) -> None:
    """Top-level command header (e.g. 'Security Scan')."""
    console.print()
    console.print(Rule(f"[bold]{title}[/]", style="accent", align="center"))


def phase(title: str, note: str | None = None) -> None:
    """Pipeline phase header rendered as a left-aligned rule."""
    console.print()
    console.print(Rule(f"[bold accent]{title}[/]", style="muted", align="left"))
    if note:
        detail(note)


# ─────────────────────────────────────────────────────────────────────
# Status lines
# ─────────────────────────────────────────────────────────────────────


def success(message: str) -> None:
    console.print(f"  [success]✓[/] {message}")


def fail(message: str) -> None:
    console.print(f"  [error]✗[/] {message}")


def warn(message: str) -> None:
    console.print(f"  [warning]⚠[/] {message}")


def skip(message: str) -> None:
    console.print(f"  [muted]⊘ {message}[/]")


def detail(message: str) -> None:
    console.print(f"  [muted]{message}[/]")


def artifact(label: str, path: Any) -> None:
    """Report a produced output file."""
    console.print(f"  [success]✓[/] {label}: [path]{escape(str(path))}[/]")


def error_panel(title: str, exc: BaseException | str) -> None:
    """Prominent boxed error for fatal failures."""
    console.print(
        Panel(
            escape(str(exc)),
            title=f"[error]✗ {escape(title)}[/]",
            border_style="red",
            box=box.ROUNDED,
            expand=False,
        )
    )


# ─────────────────────────────────────────────────────────────────────
# Panels & tables
# ─────────────────────────────────────────────────────────────────────


def config_panel(title: str, pairs: Mapping[str, str]) -> None:
    """Key/value run-configuration panel."""
    grid = Table.grid(padding=(0, 2))
    grid.add_column(style="muted", justify="right")
    grid.add_column(style="metric")
    for key, value in pairs.items():
        grid.add_row(key, escape(str(value)))
    console.print(
        Panel(
            grid,
            title=f"[bold]{title}[/]",
            border_style="accent",
            box=box.ROUNDED,
            expand=False,
            padding=(0, 2),
        )
    )


def stats_table(title: str, rows: Mapping[str, Any]) -> None:
    """Simple metric/value summary table."""
    table = Table(
        title=title, box=box.ROUNDED, border_style="accent", header_style="bold", title_style="bold"
    )
    table.add_column("Metric", style="accent")
    table.add_column("Value", style="metric", justify="right")
    for metric, value in rows.items():
        table.add_row(metric, escape(str(value)))
    console.print(table)


def summary_table(summary: Mapping[str, Any]) -> None:
    """Pipeline summary with severity-coloured breakdown."""
    table = Table(
        title="Pipeline Summary",
        box=box.ROUNDED,
        border_style="accent",
        header_style="bold",
        title_style="bold",
    )
    table.add_column("Metric", style="accent")
    table.add_column("Value", justify="right")
    table.add_row("Assets", Text(str(summary["total_assets"]), style="metric"))
    table.add_row("Findings", Text(str(summary["total_findings"]), style="metric"))
    for sev, count in summary.get("severity_breakdown", {}).items():
        table.add_row(
            Text(f"  {sev}", style=severity_style(sev)), Text(str(count), style=severity_style(sev))
        )
    frameworks = ", ".join(summary.get("compliance_frameworks", [])) or "—"
    table.add_row("Frameworks", escape(frameworks))
    console.print(table)


def coverage_table(coverage_records: list[Any]) -> None:
    """Per-region collection coverage table."""
    table = Table(
        title="Collection Coverage",
        box=box.ROUNDED,
        border_style="accent",
        header_style="bold",
        title_style="bold",
    )
    table.add_column("Region", style="accent")
    table.add_column("Account", style="muted")
    table.add_column("Coverage", justify="right")
    table.add_column("Failures", style="error")
    for cov in coverage_records:
        data = cov.to_summary()
        pct = data["coverage_pct"]
        pct_style = "success" if pct >= 90 else "warning" if pct >= 50 else "error"
        failures = ", ".join(f["service"] for f in data["failures"]) or "—"
        table.add_row(
            data["region"] or "—",
            data["account_id"] or "—",
            Text(f"{pct}%", style=pct_style),
            escape(failures),
        )
    console.print(table)


# ─────────────────────────────────────────────────────────────────────
# Progress
# ─────────────────────────────────────────────────────────────────────


def scanner_progress() -> Progress:
    """Live spinner-per-task progress display for parallel scanners."""
    return Progress(
        SpinnerColumn(style="accent", finished_text=" "),
        TextColumn("[progress.description]{task.description}"),
        TimeElapsedColumn(),
        console=console,
    )


def task_done(progress: Progress, task_id: Any, message: str) -> None:
    """Mark a progress task finished with a success description."""
    progress.update(task_id, description=f"[success]✓[/] {message}", completed=1, total=1)


def task_failed(progress: Progress, task_id: Any, message: str) -> None:
    """Mark a progress task finished with a failure description."""
    progress.update(task_id, description=f"[error]✗[/] {message}", completed=1, total=1)


# ─────────────────────────────────────────────────────────────────────
# Inventory / dependency views
# ─────────────────────────────────────────────────────────────────────


def ranked_table(title: str, columns: list[str], rows: list[list[Any]]) -> None:
    """Generic ranked table (first column is the subject, the rest values)."""
    if not rows:
        return
    table = Table(
        title=title, box=box.ROUNDED, border_style="accent", header_style="bold", title_style="bold"
    )
    table.add_column(columns[0], style="accent", overflow="fold")
    for col in columns[1:]:
        table.add_column(col, style="metric", justify="right")
    for row in rows:
        table.add_row(*(escape(str(v)) for v in row))
    console.print(table)


def dependency_tree(view: Mapping[str, Any]) -> None:
    """Render a DependencyGraph.tree() view as two Rich trees."""
    from rich.tree import Tree

    asset = view["asset"]

    def label(node: Mapping[str, Any]) -> str:
        rel = node.get("relationship") or node.get("via", "")
        where = "/".join(x for x in (node.get("account_id"), node.get("region")) if x)
        return (
            f"[accent]{escape(str(node.get('name')))}[/] [muted]{node.get('type')}"
            f"{' · ' + escape(where) if where else ''}[/] [muted]({escape(str(rel))})[/]"
        )

    def grow(tree: Any, children: list[Mapping[str, Any]]) -> None:
        for child in children:
            grow(tree.add(label(child)), child.get("children", []))

    title = f"[bold]{escape(str(asset['name']))}[/] [muted]{asset['type']} {escape(str(asset.get('arn') or ''))}[/]"
    for key, heading in (("depends_on", "depends on"), ("dependents", "needed by (blast radius)")):
        if key in view:
            tree = Tree(f"{title} [accent]{heading}[/]")
            grow(tree, view[key])
            if not view[key]:
                tree.add("[muted]nothing[/]")
            console.print(tree)
