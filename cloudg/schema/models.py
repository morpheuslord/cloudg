"""Pydantic v2 schema models for cloud assets, findings, and relationships."""

from __future__ import annotations

import uuid
from datetime import datetime
from enum import Enum
from typing import Annotated, Any

from pydantic import BaseModel, ConfigDict, Field, computed_field


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class Severity(str, Enum):
    """Finding severity levels."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class CloudProvider(str, Enum):
    """Supported cloud providers."""

    AWS = "AWS"
    AZURE = "AZURE"
    GCP = "GCP"


class AssetType(str, Enum):
    """Normalised asset type taxonomy."""

    # Compute
    EC2 = "EC2"
    VIRTUAL_MACHINE = "VIRTUAL_MACHINE"
    GCE_INSTANCE = "GCE_INSTANCE"
    LAMBDA_FUNCTION = "LAMBDA_FUNCTION"
    CLOUD_FUNCTION = "CLOUD_FUNCTION"
    ECS_CLUSTER = "ECS_CLUSTER"
    EKS_CLUSTER = "EKS_CLUSTER"
    AKS_CLUSTER = "AKS_CLUSTER"
    GKE_CLUSTER = "GKE_CLUSTER"
    APP_SERVICE = "APP_SERVICE"

    # Networking
    VPC = "VPC"
    VNET = "VNET"
    SUBNET = "SUBNET"
    SECURITY_GROUP = "SECURITY_GROUP"
    NSG = "NSG"
    NACL = "NACL"
    ROUTE_TABLE = "ROUTE_TABLE"
    INTERNET_GATEWAY = "INTERNET_GATEWAY"
    NAT_GATEWAY = "NAT_GATEWAY"
    LOAD_BALANCER = "LOAD_BALANCER"
    CLOUDFRONT = "CLOUDFRONT"
    CDN = "CDN"
    TRANSIT_GATEWAY = "TRANSIT_GATEWAY"
    PEERING_CONNECTION = "PEERING_CONNECTION"
    ELASTIC_IP = "ELASTIC_IP"

    # Storage
    S3_BUCKET = "S3_BUCKET"
    BLOB_STORAGE = "BLOB_STORAGE"
    GCS_BUCKET = "GCS_BUCKET"
    EBS_VOLUME = "EBS_VOLUME"

    # Database
    RDS_INSTANCE = "RDS_INSTANCE"
    AURORA_CLUSTER = "AURORA_CLUSTER"
    AZURE_SQL = "AZURE_SQL"
    CLOUD_SQL = "CLOUD_SQL"
    DYNAMODB_TABLE = "DYNAMODB_TABLE"

    # IAM
    IAM_USER = "IAM_USER"
    IAM_ROLE = "IAM_ROLE"
    IAM_POLICY = "IAM_POLICY"
    IAM_GROUP = "IAM_GROUP"
    SERVICE_PRINCIPAL = "SERVICE_PRINCIPAL"

    # Secrets / Keys
    KMS_KEY = "KMS_KEY"
    SECRET = "SECRET"  # nosec B105 - asset type name, not a credential
    CERTIFICATE = "CERTIFICATE"
    KEY_VAULT = "KEY_VAULT"

    # Logging
    CLOUDTRAIL = "CLOUDTRAIL"
    FLOW_LOG = "FLOW_LOG"

    # Generic
    OTHER = "OTHER"


class EdgeType(str, Enum):
    """Relationship edge types."""

    SECURITY_GROUP_RULE = "SECURITY_GROUP_RULE"
    NACL_RULE = "NACL_RULE"
    ROUTE = "ROUTE"
    IAM_TRUST = "IAM_TRUST"
    IAM_POLICY_ATTACHMENT = "IAM_POLICY_ATTACHMENT"
    CONTAINS = "CONTAINS"  # VPC contains Subnet
    PEERING = "PEERING"
    LOAD_BALANCER_TARGET = "LOAD_BALANCER_TARGET"
    INTERNET_EXPOSED = "INTERNET_EXPOSED"


class ComplianceStatus(str, Enum):
    """Compliance check status."""

    PASS = "PASS"  # nosec B105 - compliance status label, not a credential
    FAIL = "FAIL"
    NOT_APPLICABLE = "NOT_APPLICABLE"
    MANUAL = "MANUAL"


# ---------------------------------------------------------------------------
# Helper types
# ---------------------------------------------------------------------------

NonEmptyStr = Annotated[str, Field(min_length=1)]


# ---------------------------------------------------------------------------
# Core Models
# ---------------------------------------------------------------------------


class CloudAsset(BaseModel):
    """Normalised cloud resource representation."""

    model_config = ConfigDict(extra="allow", populate_by_name=True)

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    arn: str | None = Field(default=None, description="Cloud-native resource identifier")
    name: str = Field(description="Human-readable resource name")
    asset_type: AssetType
    provider: CloudProvider
    region: str = Field(default="global")
    account_id: str | None = None
    tags: dict[str, str] = Field(default_factory=dict)
    metadata: dict[str, Any] = Field(default_factory=dict)
    raw_data: dict[str, Any] = Field(default_factory=dict, exclude=True)
    collected_at: datetime = Field(default_factory=datetime.utcnow)
    is_internet_exposed: bool = False

    @computed_field  # type: ignore[misc]
    @property
    def display_id(self) -> str:
        """Return the best identifier for display."""
        return self.arn or self.id


class NetworkEdge(BaseModel):
    """Directed edge representing a network relationship or access path."""

    model_config = ConfigDict(extra="allow")

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    source_id: str = Field(description="Source node ID")
    target_id: str = Field(description="Target node ID")
    edge_type: EdgeType
    ports: list[int] = Field(default_factory=list)
    port_range: str | None = None  # e.g. "80-443"
    protocol: str | None = None  # TCP, UDP, ICMP, ALL
    cidr: str | None = None  # e.g. "0.0.0.0/0"
    direction: str = "ingress"  # ingress | egress
    description: str | None = None


class Finding(BaseModel):
    """Normalised security or governance finding."""

    model_config = ConfigDict(extra="allow")

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    resource_id: str = Field(description="Internal asset ID")
    resource_arn: str | None = None
    severity: Severity
    title: str
    description: str
    evidence: str | None = None
    remediation: str | None = None
    source_tool: str = Field(description="Tool that produced this finding")
    source_finding_id: str | None = None
    compliance_frameworks: list[str] = Field(default_factory=list)
    cvss_score: float | None = Field(default=None, ge=0.0, le=10.0)
    detected_at: datetime = Field(default_factory=datetime.utcnow)
    is_suppressed: bool = False

    @computed_field  # type: ignore[misc]
    @property
    def risk_score(self) -> float:
        """Composite risk score (0-10) based on severity + CVSS."""
        severity_scores = {
            Severity.CRITICAL: 9.5,
            Severity.HIGH: 7.5,
            Severity.MEDIUM: 5.0,
            Severity.LOW: 2.5,
            Severity.INFO: 0.5,
        }
        base = severity_scores.get(self.severity, 5.0)
        if self.cvss_score is not None:
            return round((base + self.cvss_score) / 2, 1)
        return base


class ComplianceResult(BaseModel):
    """Mapping of a finding to a compliance framework control."""

    model_config = ConfigDict(extra="allow")

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    framework: str = Field(description="e.g. CIS, NIST-800-53, PCI-DSS, GDPR")
    control_id: str = Field(description="e.g. CIS-1.1, NIST-AC-2")
    control_title: str | None = None
    status: ComplianceStatus
    finding_ids: list[str] = Field(default_factory=list)
    resource_arn: str | None = None


class ScanResult(BaseModel):
    """Aggregate pipeline output container."""

    model_config = ConfigDict(extra="allow")

    scan_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    provider: CloudProvider | None = None
    account_id: str | None = None
    region: str | None = None
    started_at: datetime = Field(default_factory=datetime.utcnow)
    completed_at: datetime | None = None

    assets: list[CloudAsset] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    edges: list[NetworkEdge] = Field(default_factory=list)
    compliance: list[ComplianceResult] = Field(default_factory=list)

    @computed_field  # type: ignore[misc]
    @property
    def summary(self) -> dict[str, Any]:
        """Quick summary statistics."""
        severity_counts: dict[str, int] = {}
        for f in self.findings:
            severity_counts[f.severity.value] = severity_counts.get(f.severity.value, 0) + 1
        return {
            "total_assets": len(self.assets),
            "total_findings": len(self.findings),
            "total_edges": len(self.edges),
            "severity_breakdown": severity_counts,
            "compliance_frameworks": list({c.framework for c in self.compliance}),
        }
