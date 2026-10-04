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
    NETWORK_INTERFACE = "NETWORK_INTERFACE"

    # Storage
    S3_BUCKET = "S3_BUCKET"
    BLOB_STORAGE = "BLOB_STORAGE"
    GCS_BUCKET = "GCS_BUCKET"
    EBS_VOLUME = "EBS_VOLUME"
    ACCESS_POINT = "ACCESS_POINT"  # S3 (multi-region) access point, EFS access point

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
    SECRET = "SECRET"  # nosec B105 # nosemgrep -- asset type name, not a credential
    CERTIFICATE = "CERTIFICATE"
    KEY_VAULT = "KEY_VAULT"

    # Logging
    CLOUDTRAIL = "CLOUDTRAIL"
    FLOW_LOG = "FLOW_LOG"
    LOG_GROUP = "LOG_GROUP"

    # Containers / Kubernetes
    CONTAINER_REGISTRY = "CONTAINER_REGISTRY"  # ECR repository, ACR, Artifact Registry
    CONTAINER_SERVICE = "CONTAINER_SERVICE"  # ECS service, Azure Container App
    TASK_DEFINITION = "TASK_DEFINITION"  # ECS task definition
    NODE_GROUP = "NODE_GROUP"  # EKS nodegroup, AKS agent pool, GKE node pool
    FARGATE_PROFILE = "FARGATE_PROFILE"
    CLUSTER_ADDON = "CLUSTER_ADDON"
    K8S_NAMESPACE = "K8S_NAMESPACE"
    K8S_WORKLOAD = "K8S_WORKLOAD"  # Deployment, StatefulSet, DaemonSet, CronJob
    K8S_SERVICE = "K8S_SERVICE"
    K8S_INGRESS = "K8S_INGRESS"
    K8S_SERVICE_ACCOUNT = "K8S_SERVICE_ACCOUNT"

    # Compute fabric
    AUTOSCALING_GROUP = "AUTOSCALING_GROUP"
    LAUNCH_TEMPLATE = "LAUNCH_TEMPLATE"
    TARGET_GROUP = "TARGET_GROUP"
    API_GATEWAY = "API_GATEWAY"
    VPC_ENDPOINT = "VPC_ENDPOINT"
    INSTANCE_PROFILE = "INSTANCE_PROFILE"
    IDENTITY_PROVIDER = "IDENTITY_PROVIDER"

    # Integration / messaging
    MESSAGE_QUEUE = "MESSAGE_QUEUE"
    NOTIFICATION_TOPIC = "NOTIFICATION_TOPIC"
    EVENT_BUS = "EVENT_BUS"
    EVENT_RULE = "EVENT_RULE"
    STATE_MACHINE = "STATE_MACHINE"
    DATA_STREAM = "DATA_STREAM"

    # Data services
    CACHE_CLUSTER = "CACHE_CLUSTER"
    SEARCH_DOMAIN = "SEARCH_DOMAIN"
    DATA_WAREHOUSE = "DATA_WAREHOUSE"
    FILE_SYSTEM = "FILE_SYSTEM"

    # DNS / deployment
    DNS_ZONE = "DNS_ZONE"
    DNS_RECORD = "DNS_RECORD"
    IAC_STACK = "IAC_STACK"  # CloudFormation stack

    # Security services and scanners
    WAF_WEB_ACL = "WAF_WEB_ACL"
    NETWORK_FIREWALL = "NETWORK_FIREWALL"
    DDOS_PROTECTION = "DDOS_PROTECTION"
    THREAT_DETECTOR = "THREAT_DETECTOR"  # GuardDuty, Detective
    SECURITY_HUB = "SECURITY_HUB"
    VULNERABILITY_SCANNER = "VULNERABILITY_SCANNER"  # Inspector
    DATA_SECURITY_SCANNER = "DATA_SECURITY_SCANNER"  # Macie
    CONFIG_RECORDER = "CONFIG_RECORDER"
    ACCESS_ANALYZER = "ACCESS_ANALYZER"

    # Organization / governance
    ORGANIZATION = "ORGANIZATION"
    ORG_UNIT = "ORG_UNIT"
    CLOUD_ACCOUNT = "CLOUD_ACCOUNT"
    ORG_POLICY = "ORG_POLICY"  # SCP, RCP, tag/backup policy
    LANDING_ZONE = "LANDING_ZONE"
    GUARDRAIL = "GUARDRAIL"  # Control Tower control / baseline, policy assignment, perimeter
    RESOURCE_GROUP = "RESOURCE_GROUP"  # Azure resource group

    # Identity federation and access
    PERMISSION_SET = "PERMISSION_SET"  # IAM Identity Center
    IDENTITY_USER = "IDENTITY_USER"  # Identity Center / Entra / workforce user
    IDENTITY_GROUP = "IDENTITY_GROUP"
    ACCESS_KEY = "ACCESS_KEY"  # IAM access key, service account key
    USER_POOL = "USER_POOL"  # Cognito user pool, B2C
    IDENTITY_POOL = "IDENTITY_POOL"
    RESOURCE_SHARE = "RESOURCE_SHARE"  # AWS RAM

    # Deployment / provisioning
    STACK_SET = "STACK_SET"
    PROVISIONED_PRODUCT = "PROVISIONED_PRODUCT"  # Service Catalog / Account Factory
    PRODUCT_PORTFOLIO = "PRODUCT_PORTFOLIO"
    CI_PIPELINE = "CI_PIPELINE"
    BUILD_PROJECT = "BUILD_PROJECT"
    DEPLOYMENT_GROUP = "DEPLOYMENT_GROUP"

    # Images, snapshots, backups
    MACHINE_IMAGE = "MACHINE_IMAGE"
    SNAPSHOT = "SNAPSHOT"
    BACKUP_PLAN = "BACKUP_PLAN"
    BACKUP_VAULT = "BACKUP_VAULT"

    # Hybrid and edge networking
    VPN_CONNECTION = "VPN_CONNECTION"  # VPN connection / tunnel
    VPN_GATEWAY = "VPN_GATEWAY"  # VGW, Azure VNet gateway, GCP target VPN gateway
    CUSTOMER_GATEWAY = "CUSTOMER_GATEWAY"  # CGW, local network gateway, external VPN gateway
    DIRECT_CONNECT = "DIRECT_CONNECT"  # DX connection / VIF / gateway, ExpressRoute, Interconnect
    ROUTER = "ROUTER"  # GCP Cloud Router, Azure virtual hub router
    PREFIX_LIST = "PREFIX_LIST"
    ENDPOINT_SERVICE = (
        "ENDPOINT_SERVICE"  # PrivateLink service, private link service, PSC attachment
    )
    VPC_LINK = "VPC_LINK"
    CUSTOM_DOMAIN = "CUSTOM_DOMAIN"
    DNS_RESOLVER = "DNS_RESOLVER"
    GLOBAL_ACCELERATOR = "GLOBAL_ACCELERATOR"
    SERVICE_NETWORK = "SERVICE_NETWORK"  # VPC Lattice, Cloud WAN, NCC hub

    # Application integration and operations
    SCHEDULE = "SCHEDULE"
    EVENT_PIPE = "EVENT_PIPE"
    API_DESTINATION = "API_DESTINATION"
    ALARM = "ALARM"
    DELIVERY_STREAM = "DELIVERY_STREAM"  # Firehose
    LOG_SINK = "LOG_SINK"  # subscription filter, logging sink, diagnostic setting
    PARAMETER = "PARAMETER"  # SSM parameter, app configuration
    CAPACITY_PROVIDER = "CAPACITY_PROVIDER"
    SERVICE_REGISTRY = "SERVICE_REGISTRY"  # Cloud Map namespace / service
    EVENT_ARCHIVE = "EVENT_ARCHIVE"
    RUNBOOK = "RUNBOOK"  # SSM document, automation runbook
    SOURCE_CONNECTION = "SOURCE_CONNECTION"  # CodeConnections / CodeStar connection
    LB_LISTENER = "LB_LISTENER"
    AUTHORIZER = "AUTHORIZER"  # API Gateway authorizer
    EDGE_FUNCTION = "EDGE_FUNCTION"  # CloudFront Function, Lambda@Edge association

    # Platforms and data processing
    MESSAGE_BROKER = "MESSAGE_BROKER"  # MSK, Amazon MQ, Event Hubs Kafka, Managed Kafka
    BATCH_ENVIRONMENT = "BATCH_ENVIRONMENT"
    JOB_QUEUE = "JOB_QUEUE"
    JOB_DEFINITION = "JOB_DEFINITION"
    DATABASE_PROXY = "DATABASE_PROXY"
    DATA_CATALOG = "DATA_CATALOG"  # Glue database/catalog, Purview
    ETL_JOB = "ETL_JOB"  # Glue job/crawler, Data Factory pipeline, Dataflow
    BIG_DATA_CLUSTER = "BIG_DATA_CLUSTER"  # EMR, Dataproc, HDInsight, Databricks
    QUERY_WORKGROUP = "QUERY_WORKGROUP"  # Athena
    DATA_TRANSFER = "DATA_TRANSFER"  # DataSync task, Transfer Family server
    ML_WORKSPACE = "ML_WORKSPACE"  # SageMaker domain/notebook, Vertex workbench, AML workspace
    ML_ENDPOINT = "ML_ENDPOINT"
    ML_MODEL = "ML_MODEL"
    AI_AGENT = "AI_AGENT"  # Bedrock agent
    KNOWLEDGE_BASE = "KNOWLEDGE_BASE"
    AI_GUARDRAIL = "AI_GUARDRAIL"

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
    ATTACHED_TO = "ATTACHED_TO"  # ENI -> instance, SG -> resource, volume -> instance
    REFERENCES = "REFERENCES"  # generic cross-service dependency (role, key, origin)

    # Typed inventory relationships. Direction is always "source <verb> target".
    INVOKES = "INVOKES"  # event source / trigger -> consumer (S3 -> Lambda, rule -> target)
    USES_IMAGE = "USES_IMAGE"  # task definition / workload / function -> image repository
    ASSUMES_ROLE = "ASSUMES_ROLE"  # compute or service account -> IAM role it runs as
    GRANTS_ACCESS = "GRANTS_ACCESS"  # principal -> resource it was explicitly granted
    LOGS_TO = "LOGS_TO"  # trail / flow log / LB -> log destination
    PROTECTS = "PROTECTS"  # WAF / firewall / shield -> protected resource
    MONITORS = "MONITORS"  # security service or scanner -> monitored resource
    MANAGES = "MANAGES"  # stack / service / ASG / landing zone -> managed resource
    GOVERNS = "GOVERNS"  # org policy / control -> OU or account


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
    relationship: str | None = Field(
        default=None,
        description="Fine-grained semantic relation (an ontology RelationType name, e.g. TRIGGERED_BY)",
    )
    properties: dict[str, Any] = Field(
        default_factory=dict, description="Relation-specific detail (access policies, actions, ...)"
    )


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
