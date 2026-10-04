"""Governance, access-sharing and data-protection services.

Who can reach what across accounts, and how data is protected and shared:

- IAM Identity Center: instance, permission sets (managed / customer-managed
  policies, inline policy presence, permissions boundary), provisioned
  accounts and account assignments; identity-store users, groups and
  memberships. Principals GRANTS_ACCESS the accounts they are assigned to
  and ASSUMES_ROLE the permission sets.
- AWS RAM resource shares (owned and received): principal -> share ->
  shared resource (GRANTS_ACCESS).
- Service Catalog portfolios and provisioned products (Control Tower
  Account Factory): product MANAGES the vended account and its stack.
- CloudFormation StackSets: MANAGES every stack instance and target account.
- IAM SAML providers, access keys (metadata only) and IAM Roles Anywhere.
- KMS (aliases, rotation, key policy and grant principals), Secrets
  Manager (rotation function, KMS, resource policy, replicas) and DynamoDB
  (KMS, streams, replicas, PITR, resource policy, Kinesis destinations):
  these override the shallow base collectors and keep their metadata keys.
- EBS snapshots, AMIs and manual RDS snapshots with their sharing
  permissions (public -> exposed, accounts -> GRANTS_ACCESS).
- S3 access points and Multi-Region Access Points.
- Cognito user pools (Lambda triggers, SMS role) and identity pools
  (authenticated / unauthenticated roles).

No secret material is ever collected: no secret or parameter values, no
access-key secrets, no stack parameters or template bodies, and no
identity-store e-mail addresses or phone numbers.

Each area lives in its own module; :class:`GovernanceCollectorsMixin`
composes them, so the KMS / Secrets Manager / DynamoDB overrides still sit
before ``AsyncAWSCollector`` in the deep collector's MRO.
"""

from __future__ import annotations

from typing import Any

from cloudg.inventory.aws_services.governance._common import (
    _ACCOUNT_RE,
    _COGNITO_TRIGGERS,
    _COGNITO_VERSIONED_TRIGGERS,
    _CT_ACCOUNT_FACTORY_PRODUCT,
    _MAX_ACCESS_KEY_USERS,
    _MAX_GRANTS,
    _MAX_IDENTITY_GROUPS,
    _MAX_IDENTITY_USERS,
    _MAX_IMAGES,
    _MAX_MEMBERSHIPS,
    _MAX_POLICY_PRINCIPALS,
    _MAX_POLICY_REFS,
    _MAX_PS_ACCOUNTS,
    _MAX_SNAPSHOTS,
    _MAX_STACK_INSTANCES,
    _SSO_FALLBACK_REGIONS,
    _SSO_ROLE_PATH,
    _STALE_KEY_DAYS,
    _age_days,
    _arn_account,
    _pab,
    _principal_target,
    _root,
    _ts,
    logger,
)
from cloudg.inventory.aws_services.governance.cognito import CognitoCollectorsMixin
from cloudg.inventory.aws_services.governance.data_protection import (
    DataProtectionCollectorsMixin,
)
from cloudg.inventory.aws_services.governance.iam_extras import IamExtrasCollectorsMixin
from cloudg.inventory.aws_services.governance.identity_center import (
    IdentityCenterCollectorsMixin,
)
from cloudg.inventory.aws_services.governance.ram import RamCollectorsMixin
from cloudg.inventory.aws_services.governance.s3_access_points import (
    S3AccessPointCollectorsMixin,
)
from cloudg.inventory.aws_services.governance.service_catalog import (
    ServiceCatalogCollectorsMixin,
)
from cloudg.inventory.aws_services.governance.sharing import SharingCollectorsMixin
from cloudg.inventory.aws_services.governance.stack_sets import StackSetsCollectorsMixin

# The helpers and limits stay importable from the original module path.
__all__ = [
    "GovernanceCollectorsMixin",
    "_ACCOUNT_RE",
    "_COGNITO_TRIGGERS",
    "_COGNITO_VERSIONED_TRIGGERS",
    "_CT_ACCOUNT_FACTORY_PRODUCT",
    "_MAX_ACCESS_KEY_USERS",
    "_MAX_GRANTS",
    "_MAX_IDENTITY_GROUPS",
    "_MAX_IDENTITY_USERS",
    "_MAX_IMAGES",
    "_MAX_MEMBERSHIPS",
    "_MAX_POLICY_PRINCIPALS",
    "_MAX_POLICY_REFS",
    "_MAX_PS_ACCOUNTS",
    "_MAX_SNAPSHOTS",
    "_MAX_STACK_INSTANCES",
    "_SSO_FALLBACK_REGIONS",
    "_SSO_ROLE_PATH",
    "_STALE_KEY_DAYS",
    "_age_days",
    "_arn_account",
    "_pab",
    "_principal_target",
    "_root",
    "_ts",
    "logger",
]


class GovernanceCollectorsMixin(
    IdentityCenterCollectorsMixin,
    IamExtrasCollectorsMixin,
    CognitoCollectorsMixin,
    RamCollectorsMixin,
    ServiceCatalogCollectorsMixin,
    StackSetsCollectorsMixin,
    DataProtectionCollectorsMixin,
    SharingCollectorsMixin,
    S3AccessPointCollectorsMixin,
):
    """Identity Center, RAM, Service Catalog, StackSets, data protection and
    sharing collectors."""

    def _governance_tasks(self) -> dict[str, tuple[Any, str, bool]]:
        """name -> (collector callable, service family, is_global)."""
        return {
            "identity_center": (self._collect_identity_center, "identity", True),
            "iam_saml_providers": (self._collect_iam_saml_providers, "identity", True),
            "iam_access_keys": (self._collect_iam_access_keys, "identity", True),
            "rolesanywhere": (self._collect_rolesanywhere, "identity", False),
            "cognito_user_pools": (self._collect_cognito_user_pools, "identity", False),
            "cognito_identity_pools": (self._collect_cognito_identity_pools, "identity", False),
            "ram_shares": (self._collect_ram_shares, "governance", False),
            "service_catalog": (self._collect_service_catalog, "governance", False),
            "stack_sets": (self._collect_stack_sets, "governance", False),
            "ebs_snapshots": (self._collect_ebs_snapshots, "storage", False),
            "machine_images": (self._collect_machine_images, "compute", False),
            "rds_snapshots": (self._collect_rds_snapshots, "data", False),
            "s3_access_points": (self._collect_s3_access_points, "storage", False),
            "s3_multi_region_access_points": (
                self._collect_s3_multi_region_access_points,
                "storage",
                True,
            ),
        }
