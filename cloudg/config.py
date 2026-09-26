"""YAML-based configuration with Pydantic validation."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)


class AWSConfig(BaseModel):
    """AWS-specific configuration.

    Auth priority: direct keys → OIDC web identity (role_arn +
    web_identity_token_file) → profile → default chain (env vars, EC2/ECS
    instance role, SSO cache). role_arn or accounts[]+role_name adds an
    STS AssumeRole hop on top, with optional external_id.
    """

    regions: list[str] = Field(default=["us-east-1"])
    accounts: list[str] = Field(default_factory=list, description="Account IDs for multi-account scanning")
    access_key_id: str | None = Field(default=None, description="AWS access key ID (direct credential)")
    secret_access_key: str | None = Field(default=None, description="AWS secret access key (direct credential)")
    session_token: str | None = Field(default=None, description="AWS session token (for temporary credentials)")
    profile: str | None = Field(default=None, description="AWS CLI profile name (fallback if no direct keys)")
    role_name: str | None = Field(default=None, description="IAM role to assume in target accounts (optional, for cross-account)")
    role_arn: str | None = Field(default=None, description="Full ARN of a role to assume (single-account AssumeRole or OIDC target)")
    external_id: str | None = Field(default=None, description="ExternalId for AssumeRole (third-party auditor pattern)")
    web_identity_token_file: str | None = Field(default=None, description="Path to an OIDC token file for AssumeRoleWithWebIdentity (GitHub Actions, EKS, GitLab CI)")
    role_session_name: str = Field(default="cloudg-scan", description="STS session name for assumed roles")
    max_retries: int = Field(default=10, ge=1, le=30)
    retry_mode: str = Field(default="adaptive", pattern="^(legacy|standard|adaptive)$")


class AzureConfig(BaseModel):
    """Azure-specific configuration.

    Auth priority: workload identity federation (tenant_id + client_id +
    federated_token_file) → service principal secret → service principal
    certificate → managed identity → DefaultAzureCredential chain.
    """

    subscription_ids: list[str] = Field(default_factory=list)
    tenant_id: str | None = None
    client_id: str | None = Field(default=None, description="Service principal / workload identity application (client) ID")
    client_secret: str | None = Field(default=None, description="Service principal client secret")
    certificate_path: str | None = Field(default=None, description="Path to a service principal certificate (PEM/PKCS12)")
    federated_token_file: str | None = Field(default=None, description="Path to a federated OIDC token file (workload identity)")
    use_managed_identity: bool = Field(default=False, description="Authenticate with the Azure managed identity of the host")
    managed_identity_client_id: str | None = Field(default=None, description="Client ID of a user-assigned managed identity")
    regions: list[str] = Field(
        default=["ALL"],
        description="Azure locations to scan. Use ['ALL'] for auto-discovery.",
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
    credentials_file: str | None = Field(default=None, description="Path to a service account key JSON or external_account (workload identity federation) JSON")
    impersonate_service_account: str | None = Field(default=None, description="Service account email to impersonate")
    regions: list[str] = Field(
        default=["ALL"],
        description="GCP regions to scan. Use ['ALL'] for auto-discovery.",
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
    inline_js: bool = Field(default=True, description="Inline JS libraries for air-gapped environments")
    output_dir: str = Field(default="./reports")


def _default_rules_dir() -> str:
    """Packaged rules directory, falling back to ./rules for old layouts."""
    packaged = Path(__file__).parent / "rules"
    if packaged.is_dir():
        return str(packaged)
    return "./rules"


class RulesetConfig(BaseModel):
    """External ruleset configuration."""

    rules_dir: str = Field(default_factory=_default_rules_dir, description="Directory containing YAML rulesets (defaults to the rulesets shipped in the package)")
    load_external: bool = Field(default=True)


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
    graph: GraphConfig = Field(default_factory=GraphConfig)
    ontology: OntologyConfig = Field(default_factory=OntologyConfig)
    rag: RAGConfig = Field(default_factory=RAGConfig)
    terraform: TerraformConfig = Field(default_factory=TerraformConfig)
    report: ReportConfig = Field(default_factory=ReportConfig)
    rulesets: RulesetConfig = Field(default_factory=RulesetConfig)
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
