"""Credential resolution for AWS, Azure, and GCP cloud providers.

Every provider supports several auth methods, resolved in a fixed priority
order so the same config works on a laptop, in CI, and on cloud compute.

AWS (build_aws_session):
    1. Direct access keys (access_key_id + secret_access_key [+ session_token])
    2. OIDC / web identity federation (role_arn + web_identity_token_file,
       e.g. GitHub Actions, GitLab CI, EKS service account tokens)
    3. Named CLI profile (includes SSO profiles)
    4. Default chain: env vars, EC2/ECS instance role (inherited role),
       container credentials, SSO cache
    Then, optionally on top of any of the above:
    5. STS AssumeRole into role_arn or accounts[]/role_name, with optional
       external_id (the standard third-party auditor pattern)

Azure (build_azure_credential):
    1. Workload identity federation (tenant_id + client_id +
       federated_token_file — AKS / GitHub OIDC)
    2. Service principal with client secret
    3. Service principal with client certificate
    4. Managed identity (system- or user-assigned — inherited identity)
    5. DefaultAzureCredential chain (env, CLI, PowerShell, managed identity)

GCP (build_gcp_credentials):
    1. Explicit credentials file: service account key JSON or a workload
       identity federation (external_account) config JSON
    2. Application Default Credentials: GOOGLE_APPLICATION_CREDENTIALS,
       gcloud user creds, or the GCE/GKE metadata server (inherited identity)
    Then, optionally on top of either:
    3. Service account impersonation (impersonate_service_account)
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from typing import Any

logger = logging.getLogger(__name__)

_GCP_SCOPES = ["https://www.googleapis.com/auth/cloud-platform"]


@dataclass
class AWSCredentials:
    """Resolved AWS credentials."""

    session: Any  # boto3.Session
    account_id: str | None = None
    region: str = "us-east-1"


@dataclass
class AzureCredentials:
    """Resolved Azure credentials."""

    credential: Any  # azure.identity credential object
    subscription_id: str
    tenant_id: str | None = None


@dataclass
class GCPCredentials:
    """Resolved GCP credentials."""

    credentials: Any  # google.auth.credentials.Credentials
    project_id: str


# ─────────────────────────────────────────────────────────────────────
# AWS
# ─────────────────────────────────────────────────────────────────────


def _aws_session_from_web_identity(
    boto3: Any,
    role_arn: str,
    token_file: str,
    session_name: str,
    region: str,
) -> Any:
    """2. OIDC / web identity federation."""
    logger.info("AWS auth: web identity federation into %s", role_arn)
    with open(token_file) as f:
        token = f.read().strip()
    sts = boto3.client("sts", region_name=region)
    try:
        resp = sts.assume_role_with_web_identity(
            RoleArn=role_arn,
            RoleSessionName=session_name,
            WebIdentityToken=token,
        )
    except Exception as exc:
        raise RuntimeError(f"AssumeRoleWithWebIdentity failed for {role_arn}: {exc}") from exc
    creds = resp["Credentials"]
    return boto3.Session(
        aws_access_key_id=creds["AccessKeyId"],
        aws_secret_access_key=creds["SecretAccessKey"],
        aws_session_token=creds["SessionToken"],
        region_name=region,
    )


def _aws_base_session(
    boto3: Any,
    cfg: Any,
    region: str,
    session_name: str,
    role_arn: str | None,
    token_file: str | None,
) -> tuple[Any, bool]:
    """Build the base session; returns (session, assumed_via_oidc)."""
    session_kwargs: dict[str, str] = {"region_name": region}

    if cfg.access_key_id and cfg.secret_access_key:
        # 1. Direct access keys
        session_kwargs["aws_access_key_id"] = cfg.access_key_id
        session_kwargs["aws_secret_access_key"] = cfg.secret_access_key
        if getattr(cfg, "session_token", None):
            session_kwargs["aws_session_token"] = cfg.session_token
        logger.info("AWS auth: direct access keys (region %s)", region)
        return boto3.Session(**session_kwargs), False

    if role_arn and token_file:
        # 2. OIDC / web identity federation
        return (
            _aws_session_from_web_identity(boto3, role_arn, token_file, session_name, region),
            True,
        )

    if getattr(cfg, "profile", None):
        # 3. Named profile (plain or SSO)
        session_kwargs["profile_name"] = cfg.profile
        logger.info("AWS auth: profile '%s' (region %s)", cfg.profile, region)
        return boto3.Session(**session_kwargs), False

    # 4. Default chain: env vars, instance/task role, SSO cache
    logger.info("AWS auth: default provider chain (region %s)", region)
    return boto3.Session(**session_kwargs), False


def _aws_assume_role(
    boto3: Any,
    session: Any,
    target_role: str,
    session_name: str,
    external_id: str | None,
    region: str,
) -> Any:
    """5. STS AssumeRole on top of the base credentials."""
    logger.info("AWS auth: assuming role %s", target_role)
    assume_kwargs: dict[str, Any] = {
        "RoleArn": target_role,
        "RoleSessionName": session_name,
        "DurationSeconds": 3600,
    }
    if external_id:
        assume_kwargs["ExternalId"] = external_id
    try:
        assumed = session.client("sts").assume_role(**assume_kwargs)
    except Exception as exc:
        raise RuntimeError(f"AssumeRole failed for {target_role}: {exc}") from exc
    creds = assumed["Credentials"]
    return boto3.Session(
        aws_access_key_id=creds["AccessKeyId"],
        aws_secret_access_key=creds["SecretAccessKey"],
        aws_session_token=creds["SessionToken"],
        region_name=region,
    )


def build_aws_session(
    cfg: Any,
    region: str,
    account_id: str | None = None,
) -> Any:
    """Build a boto3 Session from an AWSConfig, honouring all auth methods.

    Args:
        cfg: AWSConfig (or any object with the same credential fields).
        region: Target region for the session.
        account_id: Target account for cross-account AssumeRole via
            cfg.role_name (ignored when cfg.role_arn is set).

    Returns:
        boto3.Session ready for API calls.

    Raises:
        ImportError: If boto3 is not installed.
        RuntimeError: If a requested role assumption fails.
    """
    try:
        import boto3
    except ImportError as exc:
        raise ImportError(
            "boto3 is required for AWS. Install with: pip install cloudg[aws]"
        ) from exc

    session_name = getattr(cfg, "role_session_name", None) or "cloudg-scan"
    role_arn = getattr(cfg, "role_arn", None)
    token_file = getattr(cfg, "web_identity_token_file", None) or os.environ.get(
        "AWS_WEB_IDENTITY_TOKEN_FILE"
    )
    external_id = getattr(cfg, "external_id", None)

    session, assumed_via_oidc = _aws_base_session(
        boto3, cfg, region, session_name, role_arn, token_file
    )
    _instrument_aws_session(session, None, region)

    # 5. Optional role assumption on top of the base credentials
    target_role = _aws_target_role(cfg, role_arn, assumed_via_oidc, account_id)
    if target_role:
        session = _aws_assume_role(boto3, session, target_role, session_name, external_id, region)
        _instrument_aws_session(session, account_id, region)

    return session


def _aws_target_role(
    cfg: Any, role_arn: str | None, assumed_via_oidc: bool, account_id: str | None
) -> str | None:
    """The role to assume on top of the base session, if any.

    An explicit ``role_arn`` wins unless OIDC federation already assumed it;
    otherwise ``account_id`` plus ``cfg.role_name`` names a cross-account role.
    """
    if role_arn and not assumed_via_oidc:
        return role_arn
    if account_id and getattr(cfg, "role_name", None):
        return f"arn:aws:iam::{account_id}:role/{cfg.role_name}"
    return None


def _instrument_aws_session(session: Any, account_id: str | None, region: str) -> None:
    """Route the session's (STS, Organizations, Control Tower, ...) calls
    through cloudg's shared rate limiter / circuit breakers, with the
    configured botocore retries as the default client config."""
    try:
        from botocore.config import Config

        from cloudg.resilience.aws import botocore_retries, install_aws_hooks

        install_aws_hooks(
            session,
            account_id=account_id,
            region=region,
            default_config=Config(retries=botocore_retries()),
        )
    except Exception as exc:  # instrumentation must never break authentication
        logger.debug("AWS session instrumentation skipped: %s", exc)


# ─────────────────────────────────────────────────────────────────────
# Azure
# ─────────────────────────────────────────────────────────────────────


def build_azure_credential(cfg: Any) -> Any:
    """Build an azure.identity credential from an AzureConfig.

    Returns:
        A TokenCredential usable with all Azure mgmt SDK clients.

    Raises:
        ImportError: If azure-identity is not installed.
    """
    try:
        from azure import identity
    except ImportError as exc:
        raise ImportError(
            "azure-identity is required for Azure. Install with: pip install cloudg[azure]"
        ) from exc

    explicit = _azure_service_principal(identity, cfg)
    if explicit is not None:
        return explicit

    # 4. Managed identity (inherited from the VM / App Service / AKS node)
    if getattr(cfg, "use_managed_identity", False):
        mi_client_id = getattr(cfg, "managed_identity_client_id", None)
        logger.info(
            "Azure auth: managed identity (%s)",
            mi_client_id or "system-assigned",
        )
        if mi_client_id:
            return identity.ManagedIdentityCredential(client_id=mi_client_id)
        return identity.ManagedIdentityCredential()

    # 5. Default chain (env, managed identity, CLI, PowerShell)
    logger.info("Azure auth: DefaultAzureCredential chain")
    return identity.DefaultAzureCredential()


def _azure_setting(cfg: Any, name: str, env: str | None = None) -> Any:
    """``cfg.<name>``, else the environment variable ``env``."""
    value = getattr(cfg, name, None)
    if not value and env:
        value = os.environ.get(env)
    return value


def _azure_service_principal(identity: Any, cfg: Any) -> Any:
    """Workload identity, secret or certificate credential of the configured
    app registration (None when the settings for none of them are complete)."""
    tenant_id = _azure_setting(cfg, "tenant_id", "AZURE_TENANT_ID")
    client_id = _azure_setting(cfg, "client_id", "AZURE_CLIENT_ID")
    if not (tenant_id and client_id):
        return None
    client_secret = _azure_setting(cfg, "client_secret", "AZURE_CLIENT_SECRET")
    certificate_path = _azure_setting(cfg, "certificate_path")
    federated_token_file = _azure_setting(cfg, "federated_token_file", "AZURE_FEDERATED_TOKEN_FILE")

    # 1. Workload identity federation (AKS, GitHub Actions OIDC)
    if federated_token_file:
        logger.info("Azure auth: workload identity federation (client %s)", client_id)
        return identity.WorkloadIdentityCredential(
            tenant_id=tenant_id,
            client_id=client_id,
            token_file_path=federated_token_file,
        )

    # 2. Service principal with secret
    if client_secret:
        logger.info("Azure auth: service principal (client %s)", client_id)
        return identity.ClientSecretCredential(
            tenant_id=tenant_id,
            client_id=client_id,
            client_secret=client_secret,
        )

    # 3. Service principal with certificate
    if certificate_path:
        logger.info("Azure auth: service principal certificate (client %s)", client_id)
        return identity.CertificateCredential(
            tenant_id=tenant_id,
            client_id=client_id,
            certificate_path=certificate_path,
        )
    return None


# ─────────────────────────────────────────────────────────────────────
# GCP
# ─────────────────────────────────────────────────────────────────────


def build_gcp_credentials(cfg: Any) -> tuple[Any, str | None]:
    """Build google-auth credentials from a GCPConfig.

    Returns:
        (credentials, default_project_id) — project may be None when the
        auth method carries no project (e.g. impersonation).

    Raises:
        ImportError: If google-auth is not installed.
    """
    try:
        import google.auth
    except ImportError as exc:
        raise ImportError(
            "google-auth is required for GCP. Install with: pip install cloudg[gcp]"
        ) from exc

    credentials_file = getattr(cfg, "credentials_file", None) or os.environ.get(
        "GOOGLE_APPLICATION_CREDENTIALS"
    )

    if credentials_file and getattr(cfg, "credentials_file", None):
        # 1. Explicit file: service account key OR workload identity
        #    federation (external_account) config — load handles both.
        logger.info("GCP auth: file-based identity (%s)", credentials_file)
        credentials, project = google.auth.load_credentials_from_file(
            credentials_file, scopes=_GCP_SCOPES
        )
    else:
        # 2. Application Default Credentials (env var file, gcloud user
        #    credentials, or GCE/GKE metadata server)
        logger.info("GCP auth: application default credentials")
        credentials, project = google.auth.default(scopes=_GCP_SCOPES)

    # 3. Optional service account impersonation
    impersonate = getattr(cfg, "impersonate_service_account", None)
    if impersonate:
        from google.auth import impersonated_credentials

        logger.info("GCP auth: impersonating %s", impersonate)
        credentials = impersonated_credentials.Credentials(
            source_credentials=credentials,
            target_principal=impersonate,
            target_scopes=_GCP_SCOPES,
        )

    return credentials, project


# ─────────────────────────────────────────────────────────────────────
# Resolver (thin wrapper kept for the `collect` command and library use)
# ─────────────────────────────────────────────────────────────────────


class CredentialResolver:
    """Resolves cloud provider credentials across all supported auth methods.

    Thin convenience wrapper around build_aws_session /
    build_azure_credential / build_gcp_credentials that also resolves the
    account, subscription, or project the credentials belong to.
    """

    def resolve_aws(
        self,
        profile: str | None = None,
        region: str | None = None,
        config: Any = None,
    ) -> AWSCredentials:
        """Resolve AWS credentials.

        Args:
            profile: AWS profile name (defaults to AWS_PROFILE env var).
            region: AWS region (defaults to AWS_DEFAULT_REGION or us-east-1).
            config: Optional AWSConfig for the full range of auth methods
                (direct keys, OIDC, role assumption). Overrides `profile`.

        Returns:
            AWSCredentials with an active boto3 session.
        """
        region = region or os.environ.get("AWS_DEFAULT_REGION", "us-east-1")

        if config is not None:
            session = build_aws_session(config, region)
        else:
            from types import SimpleNamespace

            shim = SimpleNamespace(
                access_key_id=None,
                secret_access_key=None,
                session_token=None,
                profile=profile or os.environ.get("AWS_PROFILE"),
                role_arn=None,
                role_name=None,
                external_id=None,
                web_identity_token_file=None,
                role_session_name=None,
            )
            session = build_aws_session(shim, region)

        account_id = None
        try:
            identity = session.client("sts").get_caller_identity()
            account_id = identity.get("Account")
            logger.info("AWS identity resolved: account %s", account_id)
        except Exception:
            logger.warning("Could not resolve AWS account ID via STS")

        return AWSCredentials(session=session, account_id=account_id, region=region)

    def resolve_azure(
        self,
        subscription_id: str | None = None,
        tenant_id: str | None = None,
        config: Any = None,
    ) -> AzureCredentials:
        """Resolve Azure credentials.

        Args:
            subscription_id: Azure subscription (defaults to AZURE_SUBSCRIPTION_ID).
            tenant_id: Azure tenant (defaults to AZURE_TENANT_ID).
            config: Optional AzureConfig for service principal, workload
                identity, or managed identity auth.

        Returns:
            AzureCredentials with a TokenCredential instance.

        Raises:
            ValueError: If subscription_id cannot be determined.
        """
        subscription_id = subscription_id or os.environ.get("AZURE_SUBSCRIPTION_ID")
        tenant_id = tenant_id or os.environ.get("AZURE_TENANT_ID")

        if not subscription_id:
            raise ValueError(
                "Azure subscription ID is required. "
                "Set AZURE_SUBSCRIPTION_ID env var or pass subscription_id."
            )

        if config is not None:
            credential = build_azure_credential(config)
        else:
            from types import SimpleNamespace

            credential = build_azure_credential(SimpleNamespace(tenant_id=tenant_id))
        logger.info("Azure identity resolved: subscription %s", subscription_id)

        return AzureCredentials(
            credential=credential,
            subscription_id=subscription_id,
            tenant_id=tenant_id,
        )

    def resolve_gcp(
        self,
        project_id: str | None = None,
        config: Any = None,
    ) -> GCPCredentials:
        """Resolve GCP credentials.

        Args:
            project_id: GCP project (defaults to GOOGLE_CLOUD_PROJECT).
            config: Optional GCPConfig for key-file, federation, or
                impersonation auth.

        Returns:
            GCPCredentials with active credentials.

        Raises:
            ValueError: If project_id cannot be determined.
        """
        project_id = project_id or os.environ.get("GOOGLE_CLOUD_PROJECT")

        if config is not None:
            credentials, discovered_project = build_gcp_credentials(config)
        else:
            from types import SimpleNamespace

            credentials, discovered_project = build_gcp_credentials(SimpleNamespace())

        if not project_id:
            project_id = discovered_project

        if not project_id:
            raise ValueError(
                "GCP project ID is required. Set GOOGLE_CLOUD_PROJECT env var or pass project_id."
            )

        logger.info("GCP identity resolved: project %s", project_id)

        return GCPCredentials(credentials=credentials, project_id=project_id)
