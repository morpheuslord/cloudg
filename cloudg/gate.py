"""Severity gate for CI pipelines.

`evaluate_gate` decides whether a scan result should fail a pipeline: it
counts the findings at or above a severity threshold, ignores suppressed
ones, and can also require a minimum number of collected assets (a run with
no assets usually means the credentials did not work). `cloudg gate` and
the GitHub Action are thin wrappers around it.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field

from cloudg.schema.models import Finding, ScanResult, Severity

# Exit status of `cloudg gate` when the gate fails. 1 stays "could not run"
# (missing or unreadable input) and 2 is click's usage error, so a pipeline
# can tell "the gate found something" from "the gate is broken".
EXIT_GATE_FAILED = 4

SEVERITY_ORDER: tuple[Severity, ...] = (
    Severity.INFO,
    Severity.LOW,
    Severity.MEDIUM,
    Severity.HIGH,
    Severity.CRITICAL,
)

THRESHOLD_CHOICES: tuple[str, ...] = ("critical", "high", "medium", "low", "info", "never")


def parse_threshold(value: str) -> Severity | None:
    """The severity named by ``value`` (any case), or None for ``never``.

    Raises:
        ValueError: ``value`` is not one of THRESHOLD_CHOICES.
    """
    name = value.strip().lower()
    if name not in THRESHOLD_CHOICES:
        raise ValueError(
            f"unknown severity threshold {value!r}, expected one of {THRESHOLD_CHOICES}"
        )
    return None if name == "never" else Severity(name.upper())


def _rank(severity: Severity) -> int:
    return SEVERITY_ORDER.index(severity)


@dataclass
class GateResult:
    """Outcome of one gate evaluation."""

    threshold: Severity | None
    max_blocking: int
    min_assets: int
    total_assets: int
    counts: dict[str, int]
    suppressed: int
    blocking: list[Finding] = field(default_factory=list)
    reason: str = ""

    @property
    def passed(self) -> bool:
        return not self.reason

    @property
    def total_findings(self) -> int:
        return sum(self.counts.values())

    @property
    def fail_on(self) -> str:
        return self.threshold.value if self.threshold else "NEVER"

    def to_dict(self) -> dict[str, object]:
        """JSON-ready summary, as `cloudg gate --json` prints it."""
        return {
            "passed": self.passed,
            "reason": self.reason,
            "fail_on": self.fail_on,
            "max": self.max_blocking,
            "blocking": len(self.blocking),
            "total_findings": self.total_findings,
            "suppressed": self.suppressed,
            "total_assets": self.total_assets,
            "min_assets": self.min_assets,
            "counts": self.counts,
        }


def evaluate_gate(
    result: ScanResult,
    fail_on: str = "high",
    max_blocking: int = 0,
    min_assets: int = 0,
) -> GateResult:
    """Apply the gate to ``result``.

    Args:
        result: A scan result, for example from `cloudg run` or
            `CloudGEngine.run()`, or restored from findings.json.
        fail_on: Lowest severity that blocks (``critical``, ``high``,
            ``medium``, ``low``, ``info``), or ``never`` to only report.
        max_blocking: How many blocking findings are tolerated.
        min_assets: Fail when fewer assets than this were collected.

    Returns:
        A GateResult; ``passed`` is False when either check failed, and
        ``reason`` says why. ``blocking`` is sorted worst first.
    """
    threshold = parse_threshold(fail_on)
    active = [f for f in result.findings if not f.is_suppressed]
    tally = Counter(f.severity for f in active)
    counts = {s.value: tally.get(s, 0) for s in reversed(SEVERITY_ORDER)}
    blocking: list[Finding] = []
    if threshold is not None:
        floor = _rank(threshold)
        blocking = [f for f in active if _rank(f.severity) >= floor]
        blocking.sort(key=lambda f: (-_rank(f.severity), -f.risk_score, f.title))

    gate = GateResult(
        threshold=threshold,
        max_blocking=max_blocking,
        min_assets=min_assets,
        total_assets=len(result.assets),
        counts=counts,
        suppressed=len(result.findings) - len(active),
        blocking=blocking,
    )
    gate.reason = _failure_reason(gate)
    return gate


def _failure_reason(gate: GateResult) -> str:
    if gate.total_assets < gate.min_assets:
        return f"only {gate.total_assets} asset(s) collected, expected at least {gate.min_assets}"
    if len(gate.blocking) > gate.max_blocking:
        return (
            f"{len(gate.blocking)} finding(s) at {gate.fail_on} or above, "
            f"{gate.max_blocking} allowed"
        )
    return ""


def summary_markdown(gate: GateResult, top: int = 10) -> str:
    """A Markdown summary for a CI job page (GitHub's $GITHUB_STEP_SUMMARY)."""
    verdict = "passed" if gate.passed else f"failed: {gate.reason}"
    lines = [
        "## cloudg security gate",
        "",
        f"**Result:** {verdict}",
        "",
        f"Fail on: `{gate.fail_on}`, allowed: {gate.max_blocking}, "
        f"assets: {gate.total_assets}, suppressed findings: {gate.suppressed}",
        "",
        "| Severity | Findings |",
        "|---|---|",
    ]
    lines += [f"| {sev} | {n} |" for sev, n in gate.counts.items()]
    if gate.blocking:
        lines += ["", f"### Blocking findings (worst {min(top, len(gate.blocking))})", ""]
        lines += ["| Severity | Finding | Resource | Tool |", "|---|---|---|---|"]
        for f in gate.blocking[:top]:
            target = f.resource_arn or f.resource_id
            lines.append(
                f"| {f.severity.value} | {_cell(f.title)} | {_cell(target)} | {_cell(f.source_tool)} |"
            )
    return "\n".join(lines) + "\n"


def _cell(text: str) -> str:
    """Text safe inside a Markdown table cell."""
    return text.replace("\\", "\\\\").replace("|", "\\|").replace("\n", " ")
