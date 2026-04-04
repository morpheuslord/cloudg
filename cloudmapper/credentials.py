"""Credential resolution for AWS, Azure, and GCP cloud providers."""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class AWSCredentials:
    """Resolved AWS credentials."""

    session: Any  # boto3.Session
    account_id: str | None = None
    region: str = "us-east-1"


@dataclass
class AzureCredentials:
    """Resolved Azure credentials."""

    credential: Any  # azure.identity.DefaultAzureCredential
    subscription_id: str
    tenant_id: str | None = None


@dataclass
class GCPCredentials:
    """Resolved GCP credentials."""

    credentials: Any  # google.auth.credentials.Credentials
    project_id: str


class CredentialResolver:
    """Resolves cloud provider credentials from environment, profiles, or metadata.

    Supports:
    - AWS: boto3 Session via AWS_PROFILE, env vars, or instance metadata
    - Azure: DefaultAzureCredential chain
    - GCP: Application Default Credentials
    """

    def resolve_aws(
        self,
        profile: str | None = None,
        region: str | None = None,
    ) -> AWSCredentials:
        """Resolve AWS credentials via boto3 session.

        Args:
            profile: AWS profile name (defaults to AWS_PROFILE env var).
            region: AWS region (defaults to AWS_DEFAULT_REGION or us-east-1).

        Returns:
            AWSCredentials with an active boto3 session.

        Raises:
            ImportError: If boto3 is not installed.
            RuntimeError: If credentials cannot be resolved.
        """
        try:
            import boto3
        except ImportError as exc:
            raise ImportError(
                "boto3 is required for AWS. Install with: pip install boto3"
            ) from exc

        profile = profile or os.environ.get("AWS_PROFILE")
        region = region or os.environ.get("AWS_DEFAULT_REGION", "us-east-1")

        session_kwargs: dict[str, str] = {"region_name": region}
        if profile:
            session_kwargs["profile_name"] = profile

        session = boto3.Session(**session_kwargs)

        # Resolve account ID via STS
        account_id = None
        try:
            sts = session.client("sts")
            identity = sts.get_caller_identity()
            account_id = identity.get("Account")
            logger.info("AWS credentials resolved for account %s", account_id)
        except Exception:
            logger.warning("Could not resolve AWS account ID via STS")

        return AWSCredentials(session=session, account_id=account_id, region=region)

    def resolve_azure(
        self,
        subscription_id: str | None = None,
        tenant_id: str | None = None,
    ) -> AzureCredentials:
        """Resolve Azure credentials via DefaultAzureCredential.

        Args:
            subscription_id: Azure subscription (defaults to AZURE_SUBSCRIPTION_ID).
            tenant_id: Azure tenant (defaults to AZURE_TENANT_ID).

        Returns:
            AzureCredentials with a DefaultAzureCredential instance.

        Raises:
            ImportError: If azure-identity is not installed.
            ValueError: If subscription_id cannot be determined.
        """
        try:
            from azure.identity import DefaultAzureCredential
        except ImportError as exc:
            raise ImportError(
                "azure-identity is required for Azure. "
                "Install with: pip install azure-identity"
            ) from exc

        subscription_id = subscription_id or os.environ.get("AZURE_SUBSCRIPTION_ID")
        tenant_id = tenant_id or os.environ.get("AZURE_TENANT_ID")

        if not subscription_id:
            raise ValueError(
                "Azure subscription ID is required. "
                "Set AZURE_SUBSCRIPTION_ID env var or pass subscription_id."
            )

        credential = DefaultAzureCredential()
        logger.info("Azure credentials resolved for subscription %s", subscription_id)

        return AzureCredentials(
            credential=credential,
            subscription_id=subscription_id,
            tenant_id=tenant_id,
        )

    def resolve_gcp(
        self,
        project_id: str | None = None,
    ) -> GCPCredentials:
        """Resolve GCP credentials via Application Default Credentials.

        Args:
            project_id: GCP project (defaults to GOOGLE_CLOUD_PROJECT).

        Returns:
            GCPCredentials with ADC credentials.

        Raises:
            ImportError: If google-auth is not installed.
            ValueError: If project_id cannot be determined.
        """
        try:
            import google.auth
        except ImportError as exc:
            raise ImportError(
                "google-auth is required for GCP. "
                "Install with: pip install google-auth"
            ) from exc

        project_id = project_id or os.environ.get("GOOGLE_CLOUD_PROJECT")

        credentials, discovered_project = google.auth.default()

        if not project_id:
            project_id = discovered_project

        if not project_id:
            raise ValueError(
                "GCP project ID is required. "
                "Set GOOGLE_CLOUD_PROJECT env var or pass project_id."
            )

        logger.info("GCP credentials resolved for project %s", project_id)

        return GCPCredentials(credentials=credentials, project_id=project_id)
