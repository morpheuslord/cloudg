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
    role_name: str = Field(default="CloudMapperReadOnly", description="IAM role to assume in target accounts")
    profile: str | None = None
    max_retries: int = Field(default=10, ge=1, le=30)
    retry_mode: str = Field(default="adaptive", pattern="^(legacy|standard|adaptive)$")


class AzureConfig(BaseModel):
    """Azure-specific configuration."""

    subscription_ids: list[str] = Field(default_factory=list)
    tenant_id: str | None = None


class GCPConfig(BaseModel):
    """GCP-specific configuration."""

    project_ids: list[str] = Field(default_factory=list)
    organization_id: str | None = None


class ScannerConfig(BaseModel):
    """Scanner selection and configuration."""

    enabled: list[str] = Field(default=["prowler", "checkov"])
    prowler_extra_args: list[str] = Field(default_factory=list)
    checkov_frameworks: list[str] = Field(default=["terraform", "cloudformation"])
    trivy_images: list[str] = Field(default_factory=list)
    iac_directories: list[str] = Field(default_factory=list)
    timeout_seconds: int = Field(default=3600, ge=60)


class GraphConfig(BaseModel):
    """Graph engine configuration."""

    persist_graphml: bool = Field(default=True)
    max_nodes_warn: int = Field(default=10000)
    compute_attack_paths: bool = Field(default=True)
    export_cytoscape: bool = Field(default=False)


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

    provider: str = Field(default="aws", pattern="^(aws|azure|gcp)$")
    aws: AWSConfig = Field(default_factory=AWSConfig)
    azure: AzureConfig = Field(default_factory=AzureConfig)
    gcp: GCPConfig = Field(default_factory=GCPConfig)
    scanners: ScannerConfig = Field(default_factory=ScannerConfig)
    graph: GraphConfig = Field(default_factory=GraphConfig)
    report: ReportConfig = Field(default_factory=ReportConfig)
    rulesets: RulesetConfig = Field(default_factory=RulesetConfig)
    log_file: str | None = None
    verbose: bool = False
    concurrency_limit: int = Field(default=5, ge=1, le=50, description="Max concurrent API calls")


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
