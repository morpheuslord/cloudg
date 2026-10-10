"""YAML-based configuration with Pydantic validation."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field, field_validator, model_validator

from cloudg.config_keys import _warn_unknown_keys_deep
from cloudg.config_ratelimit import (
    ProviderRateLimitConfig,
    RateLimitConfig,
    ServiceRateLimitConfig,
)

__all__ = [
    "AWSConfig",
    "AWSOrganizationConfig",
    "AzureConfig",
    "CloudGConfig",
    "GCPConfig",
    "GraphConfig",
    "InventoryConfig",
    "OntologyConfig",
    "ProviderRateLimitConfig",
    "RAGConfig",
    "RateLimitConfig",
    "ReportConfig",
    "RulesetConfig",
    "ScannerConfig",
    "ServiceRateLimitConfig",
    "TerraformConfig",
    "load_config",
]

logger = logging.getLogger(__name__)


class AWSOrganizationConfig(BaseModel):
    """AWS Organizations / Control Tower account discovery.

    When enabled, cloudg runs from the management account (or an
    Organizations delegated administrator), enumerates the OU tree and
    every member account, and fans collection out to each account by
    assuming ``role_name`` there. Control Tower is detected automatically:
    its landing zone, governed regions, shared accounts and enabled
    controls are mapped, and governed regions can drive the region list.
    """

    enabled: bool = Field(default=False, description="Discover and map every account in the org")
    role_name: str | None = Field(
        default=None,
        description="Role assumed in member accounts. Falls back to aws.role_name, then "
        "AWSControlTowerExecution. A dedicated read-only role (SecurityAudit + "
        "ViewOnlyAccess) deployed with a StackSet is recommended.",
    )
    include_ous: list[str] = Field(
        default_factory=list,
        description="Only accounts under these OUs (ID, ARN or name; nested OUs included)",
    )
    exclude_accounts: list[str] = Field(default_factory=list)
    include_management_account: bool = Field(default=True)
    include_suspended: bool = Field(default=False)
    use_governed_regions: bool = Field(
        default=True,
        description="With regions=['ALL'], scan only the Control Tower governed regions",
    )
    control_tower: bool = Field(default=True, description="Detect and map Control Tower")
    home_region: str | None = Field(
        default=None, description="Control Tower home region (auto-detected when unset)"
    )
    map_structure: bool = Field(
        default=True, description="Emit org, OU, account, SCP and control nodes on the map"
    )


class AWSConfig(BaseModel):
    """AWS-specific configuration.

    Auth priority: direct keys → OIDC web identity (role_arn +
    web_identity_token_file) → profile → default chain (env vars, EC2/ECS
    instance role, SSO cache). role_arn or accounts[]+role_name adds an
    STS AssumeRole hop on top, with optional external_id.
    """

    regions: list[str] = Field(default=["us-east-1"])
    accounts: list[str] = Field(
        default_factory=list, description="Account IDs for multi-account scanning"
    )
    access_key_id: str | None = Field(
        default=None, description="AWS access key ID (direct credential)"
    )
    secret_access_key: str | None = Field(
        default=None, description="AWS secret access key (direct credential)"
    )
    session_token: str | None = Field(
        default=None, description="AWS session token (for temporary credentials)"
    )
    profile: str | None = Field(
        default=None, description="AWS CLI profile name (fallback if no direct keys)"
    )
    role_name: str | None = Field(
        default=None,
        description="IAM role to assume in target accounts (optional, for cross-account)",
    )
    role_arn: str | None = Field(
        default=None,
        description="Full ARN of a role to assume (single-account AssumeRole or OIDC target)",
    )
    external_id: str | None = Field(
        default=None, description="ExternalId for AssumeRole (third-party auditor pattern)"
    )
    web_identity_token_file: str | None = Field(
        default=None,
        description="Path to an OIDC token file for AssumeRoleWithWebIdentity (GitHub Actions, EKS, GitLab CI)",
    )
    role_session_name: str = Field(
        default="cloudg-scan", description="STS session name for assumed roles"
    )
    max_retries: int = Field(default=10, ge=1, le=30)
    retry_mode: str = Field(default="adaptive", pattern="^(legacy|standard|adaptive)$")
    organization: AWSOrganizationConfig = Field(default_factory=AWSOrganizationConfig)


class AzureConfig(BaseModel):
    """Azure-specific configuration.

    Auth priority: workload identity federation (tenant_id + client_id +
    federated_token_file) → service principal secret → service principal
    certificate → managed identity → DefaultAzureCredential chain.
    """

    subscription_ids: list[str] = Field(default_factory=list)
    tenant_id: str | None = None
    client_id: str | None = Field(
        default=None, description="Service principal / workload identity application (client) ID"
    )
    client_secret: str | None = Field(default=None, description="Service principal client secret")
    certificate_path: str | None = Field(
        default=None, description="Path to a service principal certificate (PEM/PKCS12)"
    )
    federated_token_file: str | None = Field(
        default=None, description="Path to a federated OIDC token file (workload identity)"
    )
    use_managed_identity: bool = Field(
        default=False, description="Authenticate with the Azure managed identity of the host"
    )
    managed_identity_client_id: str | None = Field(
        default=None, description="Client ID of a user-assigned managed identity"
    )
    regions: list[str] = Field(
        default=["ALL"],
        description="Azure locations to scan. Use ['ALL'] for auto-discovery.",
    )
    all_subscriptions: bool = Field(
        default=True,
        description=(
            "When subscription_ids is empty, collect every Enabled subscription the "
            "credential can see (False: only the first one)"
        ),
    )
    map_management_groups: bool = Field(
        default=True,
        description="Map the management group / subscription / Azure Policy hierarchy (inventory)",
    )


# High-churn Cloud Asset Inventory types the GCP collector skips by default
# (GCPConfig.skip_asset_types; cloudg.collectors.gcp.DEFAULT_SKIP_ASSET_TYPES)
GCP_DEFAULT_SKIP_ASSET_TYPES: tuple[str, ...] = (
    "k8s.io/Pod",
    "k8s.io/Node",
    "k8s.io/Event",
    "events.k8s.io/Event",
    "k8s.io/Endpoints",
    "discovery.k8s.io/EndpointSlice",
    "apps.k8s.io/ReplicaSet",
    "apps.k8s.io/ControllerRevision",
    "run.googleapis.com/Revision",
    "cloudkms.googleapis.com/CryptoKeyVersion",
    "secretmanager.googleapis.com/SecretVersion",
    "serviceusage.googleapis.com/Service",
)


class GCPConfig(BaseModel):
    """GCP-specific configuration.

    Auth priority: credentials_file (service account key or workload
    identity federation config) → application default credentials
    (GOOGLE_APPLICATION_CREDENTIALS, gcloud, GCE/GKE metadata).
    impersonate_service_account adds an impersonation hop on top.
    """

    project_ids: list[str] = Field(default_factory=list)
    organization_id: str | None = None
    credentials_file: str | None = Field(
        default=None,
        description="Path to a service account key JSON or external_account (workload identity federation) JSON",
    )
    impersonate_service_account: str | None = Field(
        default=None, description="Service account email to impersonate"
    )
    regions: list[str] = Field(
        default=["ALL"],
        description="GCP regions to scan. Use ['ALL'] for auto-discovery.",
    )
    collection_scope: str = Field(
        default="auto",
        pattern="^(auto|organization|project)$",
        description="auto: one Cloud Asset Inventory listing at organizations/<organization_id> "
        "when organization_id is set (project_ids then filter it), else one per project. "
        "organization / project force either mode.",
    )
    skip_asset_types: list[str] = Field(
        default_factory=lambda: list(GCP_DEFAULT_SKIP_ASSET_TYPES),
        description="Cloud Asset Inventory types left out of the map (high-churn objects)",
    )
    asset_page_size: int = Field(default=1000, ge=1, le=1000)
    api_timeout_seconds: float = Field(default=600.0, ge=10.0)
    iam_policies: bool = Field(
        default=True, description="Map IAM policy bindings (principal -> resource access)"
    )
    map_hierarchy: bool = Field(
        default=True,
        description="With organization_id: map the organization, folders and projects",
    )
    org_policies: bool = Field(default=True, description="Map organization policies")
    vpc_service_controls: bool = Field(
        default=True, description="Map VPC Service Controls perimeters"
    )


class ScannerConfig(BaseModel):
    """Scanner selection and configuration."""

    enabled: list[str] = Field(default=["prowler", "scoutsuite", "checkov", "trivy", "iam"])
    prowler_extra_args: list[str] = Field(default_factory=list)
    scoutsuite_extra_args: list[str] = Field(default_factory=list)
    checkov_extra_args: list[str] = Field(default_factory=list)
    trivy_extra_args: list[str] = Field(default_factory=list)
    checkov_frameworks: list[str] = Field(
        default_factory=list,
        description="Checkov frameworks to scan. Empty = auto-detect all (recommended for cloud infra).",
    )
    trivy_images: list[str] = Field(default_factory=list)
    iac_directories: list[str] = Field(default_factory=list)
    timeout_seconds: int = Field(default=3600, ge=60)


class InventoryConfig(BaseModel):
    """Inventory mapping configuration (scanner-independent asset mapping)."""

    tagging_sweep: bool = Field(
        default=True,
        description="AWS: sweep the Resource Groups Tagging API (tagged resources only)",
    )
    cloud_control: bool = Field(
        default=True,
        description="AWS: list every resource type with a Cloud Control list handler, "
        "tagged or not, for services without a dedicated collector",
    )
    cloud_control_types: list[str] = Field(
        default_factory=list,
        description="Only these CloudFormation types or prefixes (e.g. AWS::SSM::, AWS::Glue::Job)",
    )
    cloud_control_exclude: list[str] = Field(default_factory=list)
    cloud_control_concurrency: int = Field(default=6, ge=1, le=32)
    link_references: bool = Field(
        default=True,
        description="Derive cross-service REFERENCES edges from asset metadata",
    )
    services: list[str] = Field(
        default=["all"],
        description="Service families or collector names to map: all, network, compute, "
        "containers, kubernetes, serverless, integration, data, storage, identity, security, "
        "dns, iac, logging",
    )
    exclude_services: list[str] = Field(default_factory=list)
    kubernetes: bool = Field(
        default=True,
        description="Read workloads, services, ingresses and service accounts from inside "
        "EKS clusters through the Kubernetes API (needs a cluster access entry)",
    )
    kubernetes_timeout: int = Field(default=10, ge=1, le=120)
    iam_resource_edges: bool = Field(
        default=True,
        description="Link IAM principals to the concrete resources their policies grant",
    )
    max_images_per_repository: int = Field(default=20, ge=0, le=1000)
    stack_resources: bool = Field(
        default=True, description="Link CloudFormation stacks to the resources they manage"
    )
    account_hierarchy: bool = Field(
        default=True,
        description="Add account nodes and account -> top-level resource containment",
    )


class GraphConfig(BaseModel):
    """Graph engine configuration."""

    persist_graphml: bool = Field(
        default=True,
        description="cloudg run writes the graph as topology.graphml",
    )
    max_nodes_warn: int = Field(
        default=10000,
        ge=0,
        description="cloudg run and CloudGEngine log a warning when they build a graph "
        "from more assets than this (0: never)",
    )
    compute_attack_paths: bool = Field(default=True)
    export_cytoscape: bool = Field(
        default=False,
        description="cloudg run also writes the graph as topology-cytoscape.json",
    )


class OntologyConfig(BaseModel):
    """Ontology engine configuration."""

    enabled: bool = Field(default=True)
    export_formats: list[str] = Field(default=["turtle", "json-ld"])
    include_raw_metadata: bool = Field(default=False)


class RAGConfig(BaseModel):
    """RAG export configuration."""

    enabled: bool = Field(default=True)
    chunk_strategy: str = Field(
        default="hybrid",
        pattern="^(entity|community|relation_group|hybrid)$",
        description="Chunk kinds written to rag_chunks.jsonl: entity, community, "
        "relation_group, or hybrid (all three)",
    )
    max_chunk_tokens: int = Field(
        default=2000,
        ge=100,
        description="Approximate size limit of one chunk's content, counted as 4 "
        "characters per token; longer lists are cut with an '... and N more' line",
    )


class TerraformConfig(BaseModel):
    """Terraform export configuration."""

    enabled: bool = Field(default=False)
    output_dir: str = Field(default="./reports/terraform")


REPORT_FORMATS: tuple[str, ...] = ("html", "json", "svg")


class ReportConfig(BaseModel):
    """Report generation configuration."""

    formats: list[str] = Field(
        default=["html", "json", "svg"],
        description="Reports written by cloudg run and by CloudGEngine.run_pipeline and "
        "run_from_reports: html, json, svg (svg needs collected assets, so "
        "run_from_reports skips it). cloudg report and cloudg ingest use --format.",
    )
    inline_js: bool = Field(
        default=True,
        description="Embed Chart.js and D3 in report.html so it works offline; false "
        "loads them from cdn.jsdelivr.net (smaller file, needs network access)",
    )
    output_dir: str = Field(
        default="./reports",
        description="Output directory of CloudGEngine methods called without "
        "output_dir, and the MCP workspace root. The CLI commands use -o "
        "(default ./reports).",
    )

    @field_validator("formats", mode="before")
    @classmethod
    def _known_formats(cls, value: Any) -> Any:
        """Lowercase the names and drop (with a warning) the unknown ones."""
        if isinstance(value, str):
            value = [value]
        if not isinstance(value, list):
            return value
        kept: list[str] = []
        for fmt in value:
            name = str(fmt).strip().lower()
            if name in REPORT_FORMATS:
                if name not in kept:
                    kept.append(name)
            else:
                logger.warning(
                    "Unknown report format %r in report.formats is ignored (known: %s)",
                    fmt,
                    ", ".join(REPORT_FORMATS),
                )
        return kept


def _default_rules_dir() -> str:
    """Packaged rules directory, falling back to ./rules for old layouts."""
    packaged = Path(__file__).parent / "rules"
    if packaged.is_dir():
        return str(packaged)
    return "./rules"


class RulesetConfig(BaseModel):
    """Compliance ruleset configuration."""

    rules_dir: str = Field(
        default_factory=_default_rules_dir,
        description="Directory containing YAML rulesets (null or unset: the rulesets "
        "shipped in the package)",
    )
    load_external: bool = Field(
        default=True,
        description="Load the YAML rulesets in rules_dir. false maps findings to "
        "compliance controls only from the scanners' own fields and the built-in "
        "fallback patterns. check_equivalence.yaml is loaded either way.",
    )

    @field_validator("rules_dir", mode="before")
    @classmethod
    def _null_rules_dir(cls, value: Any) -> Any:
        """``rules_dir: null`` (as in the documentation) means the packaged rules."""
        if value is None or (isinstance(value, str) and not value.strip()):
            return _default_rules_dir()
        return value


class CloudGConfig(BaseModel):
    """Root configuration model.

    Unknown keys, at the top level or in any section, are logged as
    warnings and ignored.
    """

    # Multi-provider support: list of providers to scan simultaneously
    providers: list[str] = Field(
        default=["aws"],
        description="Providers to scan: aws, azure, gcp. Use multiple for simultaneous scanning.",
    )
    # Backward-compat alias: a single provider string is auto-wrapped
    provider: str | None = Field(
        default=None,
        exclude=True,
        description="Deprecated: use 'providers' list. Kept for backward compat.",
    )
    aws: AWSConfig = Field(default_factory=AWSConfig)
    azure: AzureConfig = Field(default_factory=AzureConfig)
    gcp: GCPConfig = Field(default_factory=GCPConfig)
    scanners: ScannerConfig = Field(default_factory=ScannerConfig)
    inventory: InventoryConfig = Field(default_factory=InventoryConfig)
    graph: GraphConfig = Field(default_factory=GraphConfig)
    ontology: OntologyConfig = Field(default_factory=OntologyConfig)
    rag: RAGConfig = Field(default_factory=RAGConfig)
    terraform: TerraformConfig = Field(default_factory=TerraformConfig)
    report: ReportConfig = Field(default_factory=ReportConfig)
    rulesets: RulesetConfig = Field(default_factory=RulesetConfig)
    ratelimit: RateLimitConfig = Field(
        default_factory=RateLimitConfig,
        description="Throttling resilience: rate limits, retries, circuit breakers, live-run guard",
    )
    log_file: str | None = None
    verbose: bool = False
    concurrency_limit: int = Field(
        default=5,
        ge=1,
        le=50,
        description="Collection units the multi-provider collector (cloudg run, cloudg "
        "map, CloudGEngine.collect and map_inventory) runs at the same time, shared by "
        "all providers. A unit is one AWS account and region, one Azure subscription, "
        "or one GCP project or organization. API call rates are set in ratelimit.",
    )

    @model_validator(mode="before")
    @classmethod
    def _unknown_keys(cls, data: Any) -> Any:
        _warn_unknown_keys_deep(data, cls, "")
        return data

    def model_post_init(self, __context: Any) -> None:
        """Handle backward-compat: if 'provider' is set but 'providers' is default, migrate."""
        if self.provider is not None and self.providers == ["aws"]:
            self.providers = [self.provider]


def load_config(config_path: str | Path | None = None) -> CloudGConfig:
    """Load configuration from YAML file with Pydantic validation.

    Args:
        config_path: Path to config.yaml. If None, uses defaults.

    Returns:
        Validated CloudGConfig instance.
    """
    if config_path is None:
        logger.info("No config file specified, using defaults")
        return CloudGConfig()

    path = Path(config_path)
    if not path.exists():
        logger.warning("Config file %s not found, using defaults", path)
        return CloudGConfig()

    try:
        import yaml
    except ImportError:
        logger.warning("PyYAML not installed, using defaults. Install with: pip install pyyaml")
        return CloudGConfig()

    with open(path) as f:
        data: dict[str, Any] = yaml.safe_load(f) or {}

    config = CloudGConfig.model_validate(data)
    logger.info("Loaded config from %s", path)
    return config
