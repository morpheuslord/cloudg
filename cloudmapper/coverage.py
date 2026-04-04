"""Collection coverage tracking — records which services succeeded/failed."""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class ServiceStatus(str, Enum):
    """Status of a service collection attempt."""

    SUCCESS = "SUCCESS"
    FAILED = "FAILED"
    PARTIAL = "PARTIAL"
    SKIPPED = "SKIPPED"


class ServiceCoverage(BaseModel):
    """Coverage record for a single service."""

    service: str
    status: ServiceStatus
    asset_count: int = 0
    error: str | None = None
    duration_ms: int | None = None


class CollectionCoverage(BaseModel):
    """Aggregate coverage for an entire collection run."""

    provider: str
    region: str | None = None
    account_id: str | None = None
    started_at: datetime = Field(default_factory=datetime.utcnow)
    completed_at: datetime | None = None
    services: list[ServiceCoverage] = Field(default_factory=list)

    @property
    def total_services(self) -> int:
        return len(self.services)

    @property
    def successful_services(self) -> int:
        return sum(1 for s in self.services if s.status == ServiceStatus.SUCCESS)

    @property
    def failed_services(self) -> int:
        return sum(1 for s in self.services if s.status == ServiceStatus.FAILED)

    @property
    def coverage_pct(self) -> float:
        if not self.services:
            return 0.0
        return round(self.successful_services / self.total_services * 100, 1)

    def record(
        self,
        service: str,
        status: ServiceStatus,
        asset_count: int = 0,
        error: str | None = None,
        duration_ms: int | None = None,
    ) -> None:
        """Record a service collection result."""
        self.services.append(
            ServiceCoverage(
                service=service,
                status=status,
                asset_count=asset_count,
                error=error,
                duration_ms=duration_ms,
            )
        )

    def to_summary(self) -> dict[str, Any]:
        """Return a summary dict for reporting."""
        return {
            "provider": self.provider,
            "region": self.region,
            "account_id": self.account_id,
            "total_services": self.total_services,
            "successful": self.successful_services,
            "failed": self.failed_services,
            "coverage_pct": self.coverage_pct,
            "failures": [
                {"service": s.service, "error": s.error}
                for s in self.services
                if s.status == ServiceStatus.FAILED
            ],
        }
