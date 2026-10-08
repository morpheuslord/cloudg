"""YAML-based configuration with Pydantic validation."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field, model_validator

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
        default_factory=lambda: [
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
        ],
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

    persist_graphml: bool = Field(default=True)
    max_nodes_warn: int = Field(default=10000)
    compute_attack_paths: bool = Field(default=True)
    export_cytoscape: bool = Field(default=False)


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
        description="Chunking strategy: entity, community, relation_group, or hybrid (all)",
    )
    max_chunk_tokens: int = Field(default=2000, ge=100)


class TerraformConfig(BaseModel):
    """Terraform export configuration."""

    enabled: bool = Field(default=False)
    output_dir: str = Field(default="./reports/terraform")


class ReportConfig(BaseModel):
    """Report generation configuration."""

    formats: list[str] = Field(default=["html", "json", "svg"])
    inline_js: bool = Field(
        default=True, description="Inline JS libraries for air-gapped environments"
    )
    output_dir: str = Field(default="./reports")


def _default_rules_dir() -> str:
    """Packaged rules directory, falling back to ./rules for old layouts."""
    packaged = Path(__file__).parent / "rules"
    if packaged.is_dir():
        return str(packaged)
    return "./rules"


class RulesetConfig(BaseModel):
    """External ruleset configuration."""

    rules_dir: str = Field(
        default_factory=_default_rules_dir,
        description="Directory containing YAML rulesets (defaults to the rulesets shipped in the package)",
    )
    load_external: bool = Field(default=True)


def _warn_unknown_keys(data: Any, model: type[BaseModel], path: str) -> None:
    """Log (not raise: CloudGConfig is public API) keys ``model`` does not define."""
    if not isinstance(data, dict):
        return
    for key in data:
        if key not in model.model_fields:
            logger.warning("Unknown config key %s.%s is ignored", path, key)


class ServiceRateLimitConfig(BaseModel):
    """Rate limit of one service (or ``service.Operation``) leaf bucket."""

    max_rps: float = Field(gt=0, description="Sustained requests per second")
    burst: float | None = Field(
        default=None, gt=0, description="Bucket capacity (default: 2 x max_rps)"
    )
    per_operation: bool | None = Field(
        default=None,
        description="One bucket (and circuit breaker) per API operation instead of per "
        "service (default: the built-in choice, true for AWS ec2)",
    )


class ProviderRateLimitConfig(BaseModel):
    """Throttling behaviour for one provider.

    Unset (None) limits fall back to cloudg's built-in per-provider and
    per-service defaults (documented with sources in
    ``cloudg/resilience/limiter.py``), which sit at or below each
    provider's published limits. Each description says which call paths
    the key affects: "AWS hooks" are the botocore event hooks on every
    boto3 / aioboto3 session cloudg builds, "Azure policy" is the
    per-attempt pipeline policy on every Azure SDK client cloudg builds,
    "GCP listings" are Cloud Asset Inventory calls, and
    "call_with_resilience" is the generic wrapper for embedders' own calls.
    """

    enabled: bool = Field(
        default=True, description="Rate limit / circuit-break this provider (all paths)"
    )
    max_rps: float | None = Field(
        default=None,
        gt=0,
        description="Default requests/s of a leaf bucket (account x region x service, or "
        "operation) on all paths (AWS 20, Azure 15, GCP 10)",
    )
    burst: float | None = Field(default=None, gt=0, description="Default leaf bucket capacity")
    account_max_rps: float | None = Field(
        default=None,
        gt=0,
        description="Aggregate requests/s per account / subscription / project, all paths "
        "(Azure 20; off for AWS and GCP)",
    )
    account_burst: float | None = Field(
        default=None, gt=0, description="Capacity of the account bucket (Azure 200)"
    )
    global_max_rps: float | None = Field(
        default=None,
        gt=0,
        description="Aggregate requests/s of the whole provider, all paths (off by default)",
    )
    global_burst: float | None = Field(
        default=None, gt=0, description="Capacity of the provider-wide bucket"
    )
    max_concurrency: int | None = Field(
        default=None,
        ge=1,
        le=1024,
        description="In-flight requests per account (bulkhead): AWS hooks and Azure policy per "
        "HTTP request, GCP per concurrent listing, call_with_resilience per call "
        "(AWS 128, Azure 16, GCP 16)",
    )
    adaptive: bool = Field(
        default=True,
        description="Halve a scope's rate when throttled, recover additively (AIMD), all paths",
    )
    min_rps: float | None = Field(
        default=None, gt=0, description="Floor the adaptive rate never drops below"
    )
    breaker_threshold: int = Field(
        default=5,
        ge=1,
        le=1000,
        description="Consecutive calls failing on throttling (after retries) that open the "
        "circuit of a scope (per operation where the bucket is per operation), all paths",
    )
    breaker_cooldown_seconds: float = Field(
        default=60.0,
        ge=0,
        description="Seconds an open circuit rejects calls before a probe, all paths",
    )
    max_retries: int = Field(
        default=8,
        ge=0,
        le=50,
        description="Retries of a throttled / transient call: Azure SDK retry_total and "
        "retry_status, GCP consecutive retries per page, call_with_resilience. Not used "
        "by the AWS hooks: botocore retries come from aws.max_retries",
    )
    max_backoff_seconds: float = Field(
        default=60.0,
        gt=0,
        description="Cap of one backoff sleep: Azure retry_backoff_max, GCP api_core Retry "
        "maximum, call_with_resilience. AWS: botocore's own backoff (not configurable here)",
    )
    deadline_seconds: float = Field(
        default=900.0,
        gt=0,
        description="Overall time budget of one call including retries: Azure RetryPolicy "
        "timeout, GCP api_core Retry timeout, call_with_resilience. AWS: botocore "
        "timeouts and aws.max_retries bound a call instead",
    )
    retry_budget: int = Field(
        default=500,
        ge=0,
        description="Retries the provider may make before cloudg stops retrying (each "
        "success refunds 0.1): AWS hooks, Azure policy, GCP listings, call_with_resilience",
    )
    services: dict[str, ServiceRateLimitConfig] = Field(
        default_factory=dict,
        description="Per-service overrides keyed by SDK service name (AWS: ec2, iam, ...; "
        "Azure: network, compute, resourcegraph, ...; GCP: cloudasset) or "
        "'<service>.<Operation>' (e.g. cloudasset.ListAssets)",
    )
    live_cooldown_seconds: float | None = Field(
        default=None,
        ge=0,
        description="Overrides ratelimit.live_cooldown_seconds for this provider "
        "(LiveOperationGuard only)",
    )


def _provider_ratelimit() -> ProviderRateLimitConfig:
    return ProviderRateLimitConfig()


class RateLimitConfig(BaseModel):
    """Cloud API throttling resilience (rate limits, retries, circuit breakers)
    and guard rails for live collections triggered on demand (MCP).

    Unknown keys are logged as warnings and ignored.
    """

    enabled: bool = Field(default=True, description="Master switch for every provider")
    aws: ProviderRateLimitConfig = Field(default_factory=_provider_ratelimit)
    azure: ProviderRateLimitConfig = Field(default_factory=_provider_ratelimit)
    gcp: ProviderRateLimitConfig = Field(default_factory=_provider_ratelimit)
    live_cooldown_seconds: float = Field(
        default=120.0,
        ge=0,
        description="Minimum seconds between two live collections of the same scope "
        "(LiveOperationGuard)",
    )
    live_max_concurrent: int = Field(
        default=1, ge=1, le=64, description="Concurrent live collections per scope"
    )
    live_max_concurrent_total: int = Field(
        default=2, ge=1, le=256, description="Concurrent live collections overall"
    )
    live_caller_max_operations: int = Field(
        default=0, ge=0, description="Live collections per caller per window (0 = unlimited)"
    )
    live_caller_window_seconds: float = Field(
        default=3600.0, gt=0, description="Window of live_caller_max_operations"
    )

    @model_validator(mode="before")
    @classmethod
    def _unknown_keys(cls, data: Any) -> Any:
        _warn_unknown_keys(data, cls, "ratelimit")
        if isinstance(data, dict):
            for provider in ("aws", "azure", "gcp"):
                pdata = data.get(provider)
                _warn_unknown_keys(pdata, ProviderRateLimitConfig, f"ratelimit.{provider}")
                services = pdata.get("services") if isinstance(pdata, dict) else None
                if isinstance(services, dict):
                    for name, sdata in services.items():
                        _warn_unknown_keys(
                            sdata,
                            ServiceRateLimitConfig,
                            f"ratelimit.{provider}.services.{name}",
                        )
        return data


class CloudGConfig(BaseModel):
    """Root configuration model."""

    # Multi-provider support: list of providers to scan simultaneously
    providers: list[str] = Field(
        default=["aws"],
        description="Providers to scan: aws, azure, gcp. Use multiple for simultaneous scanning.",
    )
    # Backward-compat alias — single provider string is auto-wrapped
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
    concurrency_limit: int = Field(default=5, ge=1, le=50, description="Max concurrent API calls")

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
