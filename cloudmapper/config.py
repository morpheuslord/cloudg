"""YAML-based configuration with Pydantic validation."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)


class AWSConfig(BaseModel):
    """AWS-specific configuration."""

    regions: list[str] = Field(default=["us-east-1"])
    accounts: list[str] = Field(default_factory=list, description="Account IDs for multi-account scanning")
    access_key_id: str | None = Field(default=None, description="AWS access key ID (direct credential)")
    secret_access_key: str | None = Field(default=None, description="AWS secret access key (direct credential)")
    session_token: str | None = Field(default=None, description="AWS session token (for temporary credentials)")
    profile: str | None = Field(default=None, description="AWS CLI profile name (fallback if no direct keys)")
    role_name: str | None = Field(default=None, description="IAM role to assume in target accounts (optional, for cross-account)")
    max_retries: int = Field(default=10, ge=1, le=30)
    retry_mode: str = Field(default="adaptive", pattern="^(legacy|standard|adaptive)$")


class AzureConfig(BaseModel):
    """Azure-specific configuration."""

    subscription_ids: list[str] = Field(default_factory=list)
    tenant_id: str | None = None
    regions: list[str] = Field(
        default=["ALL"],
        description="Azure locations to scan. Use ['ALL'] for auto-discovery.",
    )


class GCPConfig(BaseModel):
    """GCP-specific configuration."""

    project_ids: list[str] = Field(default_factory=list)
    organization_id: str | None = None
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


class RulesetConfig(BaseModel):
    """External ruleset configuration."""

    rules_dir: str = Field(default="./rules", description="Directory containing YAML rulesets")
    load_external: bool = Field(default=True)


class CloudMapperConfig(BaseModel):
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


def load_config(config_path: str | Path | None = None) -> CloudMapperConfig:
    """Load configuration from YAML file with Pydantic validation.

    Args:
        config_path: Path to config.yaml. If None, uses defaults.

    Returns:
        Validated CloudMapperConfig instance.
    """
    if config_path is None:
        logger.info("No config file specified, using defaults")
        return CloudMapperConfig()

    path = Path(config_path)
    if not path.exists():
        logger.warning("Config file %s not found, using defaults", path)
        return CloudMapperConfig()

    try:
        import yaml
    except ImportError:
        logger.warning("PyYAML not installed, using defaults. Install with: pip install pyyaml")
        return CloudMapperConfig()

    with open(path) as f:
        data: dict[str, Any] = yaml.safe_load(f) or {}

    config = CloudMapperConfig.model_validate(data)
    logger.info("Loaded config from %s", path)
    return config
