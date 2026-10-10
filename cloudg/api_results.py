"""Result objects of :class:`cloudg.api.CloudGEngine` and the collection
status checks the engine and the CLI share (re-exported by :mod:`cloudg.api`)."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from cloudg.coverage import CollectionCoverage
from cloudg.schema.models import (
    CloudAsset,
    Finding,
    NetworkEdge,
    ScanResult,
)


# ---------------------------------------------------------------------------
# Result dataclasses
# ---------------------------------------------------------------------------


@dataclass
class CollectionResult:
    """Output of the collection phase."""

    assets: list[CloudAsset] = field(default_factory=list)
    edges: list[NetworkEdge] = field(default_factory=list)
    coverage: list[CollectionCoverage] = field(default_factory=list)
    providers_scanned: list[str] = field(default_factory=list)
    regions_scanned: dict[str, list[str]] = field(default_factory=dict)
    duration_ms: int = 0


@dataclass
class AnalysisResult:
    """Output of the analysis phase (graph, ontology, RAG)."""

    graph_nodes: int = 0
    graph_edges: int = 0
    ontology_triples: int = 0
    ontology_path: Path | None = None
    rag_chunks_path: Path | None = None
    rag_chunk_count: int = 0
    terraform_paths: dict[str, Path] = field(default_factory=dict)
    attack_paths: list[Any] = field(default_factory=list)
    reachability_findings: list[Finding] = field(default_factory=list)


@dataclass
class PipelineResult:
    """Complete pipeline output: a single object for downstream consumption.

    This is the primary return type for `CloudGEngine.run_pipeline()`.
    Designed for easy serialisation and integration with larger systems.
    """

    # Core data
    assets: list[CloudAsset] = field(default_factory=list)
    edges: list[NetworkEdge] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    scan_result: ScanResult | None = None

    # Analysis outputs
    graph_nodes: int = 0
    graph_edges: int = 0
    ontology_triples: int = 0
    rag_chunks_path: Path | None = None
    terraform_paths: dict[str, Path] = field(default_factory=dict)
    attack_paths: list[Any] = field(default_factory=list)

    # Metadata
    providers_scanned: list[str] = field(default_factory=list)
    regions_scanned: dict[str, list[str]] = field(default_factory=dict)
    coverage: list[CollectionCoverage] = field(default_factory=list)
    report_paths: dict[str, Path] = field(default_factory=dict)
    duration_ms: int = 0
    errors: list[str] = field(default_factory=list)

    @property
    def total_assets(self) -> int:
        return len(self.assets)

    @property
    def total_findings(self) -> int:
        return len(self.findings)

    @property
    def severity_breakdown(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for f in self.findings:
            sev = f.severity.value
            counts[sev] = counts.get(sev, 0) + 1
        return counts

    def to_summary(self) -> dict[str, Any]:
        """Return a summary dict for downstream consumption."""
        return {
            "total_assets": self.total_assets,
            "total_findings": self.total_findings,
            "severity_breakdown": self.severity_breakdown,
            "providers_scanned": self.providers_scanned,
            "regions_scanned": self.regions_scanned,
            "graph_nodes": self.graph_nodes,
            "graph_edges": self.graph_edges,
            "ontology_triples": self.ontology_triples,
            "attack_paths_count": len(self.attack_paths),
            "duration_ms": self.duration_ms,
            "errors": self.errors,
        }


# ---------------------------------------------------------------------------
# Event hook types
# ---------------------------------------------------------------------------

# Callback signatures (all optional)
OnCollectionComplete = Callable[[CollectionResult], None]
OnScanComplete = Callable[[list[Finding]], None]
OnFinding = Callable[[Finding], None]
OnAnalysisComplete = Callable[[AnalysisResult], None]
OnPhaseStart = Callable[[str], None]  # phase name
OnError = Callable[[str, Exception], None]  # phase name, exception


def collection_failed(assets: list[Any], coverage: list[CollectionCoverage]) -> bool:
    """True when collection produced nothing because it failed.

    That is: no assets, and no collector reported success (an empty but
    readable account still has successful coverage records). The per-target
    records (``aws_full`` and the like) only count when they report SUCCESS:
    with no usable credentials every service fails on its own and the
    target record says PARTIAL, which is still a complete failure.
    """
    if assets:
        return False
    for cov in coverage:
        for svc in cov.services:
            status = svc.status.value
            if svc.service in _TARGET_RECORDS:
                if status == "SUCCESS":
                    return False
            elif status in ("SUCCESS", "PARTIAL"):
                return False
    return True


# Coverage records that mean a whole provider / account / region failed
# (not just one service inside it)
_TARGET_RECORDS = ("aws_full", "azure_full", "gcp_full", "sts_assume_role")


def failed_collection_targets(coverage: list[CollectionCoverage]) -> list[str]:
    """One line per provider, account or region whose collection failed as a
    whole, e.g. ``"aws 123456789012/eu-west-1: AccessDenied ..."``.

    A target also counts as failed when every one of its services failed,
    even though its own record says PARTIAL (what happens with no usable
    credentials). Single services that failed inside an otherwise collected
    target are left out; they are in the coverage records.
    """
    lines: list[str] = []
    for cov in coverage:
        lines.extend(_failed_target_lines(cov))
    return lines


def _failed_target_lines(cov: CollectionCoverage) -> list[str]:
    """Failure lines for one coverage record (see failed_collection_targets)."""
    where = _coverage_location(cov)
    targets, services = _split_target_records(cov)
    failed = [svc for svc in targets if svc.status.value == "FAILED"]
    if failed:
        return [f"{cov.provider} {where}: {svc.error or 'failed'}" for svc in failed]
    if not targets or not _all_failed(services):
        return []
    error = next((svc.error for svc in services if svc.error), "no detail")
    return [f"{cov.provider} {where}: every service failed ({error})"]


def _coverage_location(cov: CollectionCoverage) -> str:
    """``account/region`` of a coverage record, or ``all``."""
    parts = [x for x in (cov.account_id, cov.region) if x]
    return "/".join(parts) or "all"


def _split_target_records(cov: CollectionCoverage) -> tuple[list[Any], list[Any]]:
    """(per-target records such as aws_full, per-service records)."""
    targets: list[Any] = []
    services: list[Any] = []
    for svc in cov.services:
        (targets if svc.service in _TARGET_RECORDS else services).append(svc)
    return targets, services


def _all_failed(services: list[Any]) -> bool:
    """True for a non-empty list of service records that all FAILED."""
    return bool(services) and all(svc.status.value == "FAILED" for svc in services)
