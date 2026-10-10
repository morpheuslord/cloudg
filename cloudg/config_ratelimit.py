"""The ``ratelimit`` section of config.yaml (re-exported by :mod:`cloudg.config`)."""

from __future__ import annotations

from typing import Any, ClassVar

from pydantic import BaseModel, Field, model_validator

from cloudg.config_keys import _warn_unknown_keys


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

    # CloudGConfig leaves this section's keys to _unknown_keys below
    _checks_own_keys: ClassVar[bool] = True

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
    live_operation_timeout_seconds: float | None = Field(
        default=3600.0,
        gt=0,
        description="A live collection running longer is cancelled and its scopes freed "
        "(None: no limit)",
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
